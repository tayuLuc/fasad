//! Релай SSE: кадр `data:` как единица разворота маркеров (SPEC §8, шаг 7c).
//!
//! # Задача
//!
//! Прокси отдаёт ответ модели клиенту тем же потоком, но развёрнутым: метки
//! `[PERSON_1_AAAA1111]` (или крипто-токены `[[F0#…]]`) обязаны стать
//! оригиналами до того, как байт ушёл клиенту. Проблема не в подмене, а в
//! границе: модель режет ответ на дельты где попало, и метку приносит разрезанной
//! между двумя `data:`-событиями. SPEC §8 утверждает, что «наивный replace по
//! чанку ломает обратимость», — этот модуль делает утверждение проверяемым: тест
//! `naive_replace_by_chunk_breaks_roundtrip` считает ровно то, что сломало бы, и
//! показывает, чем наш путь на том же входе выходит byte-exact.
//!
//! # Почему нельзя гонять сырые байты потока через `StreamRewriter`
//!
//! У разворота три границы, и третья в SPEC не названа:
//!
//! 1. метка разрезана между событиями → решает `VaultStream::push`: look-ahead
//!    `Grammar::window` плюс удержание оборванной UTF-8-последовательности;
//! 2. метку нельзя искать в **сырых** байтах SSE: между хвостом одной метки и
//!    началом другой вставляется `"}\n\ndata: {"choices":[…`, никакой конечный
//!    автомат по байтам её оттуда не соберёт, поэтому автомат кормится
//!    **декодированным содержимым** речевых полей, а кадр пересобирается;
//! 3. суррогатное имя — голое слово, не маркер: автомат его не видит вовсе, и
//!    разрезанное пополам слово не развернёт никакой `replace`. Отсюда удержание
//!    хвоста слова: имена восстанавливаются только на отрезке, который
//!    начинается и кончается границей слова
//!    ([`Vault::restore_surrogates_soft`]).
//!
//! # Что не разворачивается
//!
//! `choices[*].delta.tool_calls[*].function.arguments` — JSON аргументов
//! инструмента произвольной формы. Мы в него не лезем: правка неподвиального
//! чужого документа ломает вызов. Метки там остаются метками, то есть оригиналы
//! `ПДн` наружу не утекают, но round-trip в этом поле не обещается; счётчик
//! нерезолвленных маркеров это видно (`unresolved`, см. [`trailer`]).
//!
//! # Отклонение от WHATWG SSE, названное нарочно
//!
//! Кадр с несколькими `data:`-линиями по спецификации склеивается в одну
//! нагрузку через `\n`. Мы обрабатываем каждую линию отдельно: OpenAI-совместимый
//! контракт кладёт в `data:` ровно один JSON, а JSON не содержит сырых переводов
//! строки, поэтому «склейка» и «по линиям» на легальном входе неразличимы, а на
//! нелегальном по-линейная обработка хотя бы не превращает два события в одно.
//!
//! [`Vault::restore_surrogates_soft`]: crate::vault::Vault::restore_surrogates_soft

use std::collections::HashMap;

use guard_vault::VaultStream;
use serde_json::{Map, Value};

use crate::config::{Config, VaultMode};
use crate::vault::{Vault, VaultApiError};

/// Поля дельты, считающиеся речью и потому разворачиваемые.
///
/// `content` — канон `OpenAI`, `reasoning_content` — `thinking`-текст reasoning-
/// моделей, `refusal` — текст отказа. Список закрытый: расширять его «на всякий
/// случай» нельзя, потому что разворот непонятого поля = правка чужих данных.
pub(crate) const SPEECH_FIELDS: [&str; 3] = ["content", "reasoning_content", "refusal"];

/// Сентинел конца стрима в OpenAI-контракте.
const DONE: &[u8] = b"[DONE]";

/// Состояние одного `choices[i]`.
///
/// Дельты разных индексов идут перемешанно (при `n > 1`), метка не переезжает с
/// индекса на индекс, поэтому состояние не общее на поток.
struct State<'a> {
    stream: VaultStream<'a>,
    /// Хвост предыдущего куска, обрезанный на середине слова.
    word: Vec<u8>,
    /// Envelope последнего события индекса — шаблон синтетического флеш-кадра.
    template: Option<Value>,
}

/// Счётчики релая: то, что в не-потоковом ответе было бы полями тела.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Сколько маркеров и имён развёрнуто.
    pub substituted: usize,
    /// Сколько кадров не распарсилось и прошли дословно.
    pub malformed: usize,
    /// Был ли на хвосте незакрытый маркер.
    pub incomplete: bool,
}

/// Остановка релая с явной причиной: «поток битый» и «поток не влез» — разные
/// отказы, подменять один другим нельзя (AGENTS: ложь о причине отказа).
#[derive(Debug, Clone)]
pub enum RelayError {
    /// Между разделителями набралось больше `limit` байт: upstream либо врёт о
    /// формате, либо это не SSE. Буферизация бесконечного кадра = бесконечная
    /// память, поэтому стоп, а не «дожмём когда повезёт».
    FrameTooBig {
        /// Предел, байт.
        limit: usize,
    },
    /// Слот недоступен (режим 2 без `X-Session-ID`).
    Vault(VaultApiError),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooBig { limit } => {
                write!(f, "кадр SSE длиннее {limit} байт без разделителя")
            }
            Self::Vault(err) => write!(f, "хранилище отказало: {err}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Релай одного SSE-ответа.
pub struct Relay<'a> {
    vault: &'a Vault,
    /// Аргумент сессии для новых машин: `None` в режиме 3, id в режиме 2.
    session: Option<&'a str>,
    slot: String,
    /// Недопитанный хвост сырых байт: кадр ещё не закрыт пустой строкой.
    raw: Vec<u8>,
    states: HashMap<u32, State<'a>>,
    stats: Stats,
    limit: usize,
    restore_names: bool,
}

impl<'a> Relay<'a> {
    /// Новый релай. Грамматика и слот — те же, что у [`Vault::deanonymize`]
    /// (одна ветка «режим → грамматика» в [`Vault::stream`], двух в файле быть
    /// не может).
    ///
    /// # Errors
    ///
    /// [`RelayError::Vault`] — хранилище отказало на старте (режим 2 без
    /// заголовка сессии, переполнение реестра форм).
    pub fn new(
        vault: &'a Vault,
        session: Option<&'a str>,
        cfg: &Config,
    ) -> Result<Self, RelayError> {
        let slot = session.unwrap_or_default().to_owned();
        let stream = vault.stream(session).map_err(RelayError::Vault)?;
        let mut states = HashMap::new();
        states.insert(
            0_u32,
            State {
                stream,
                word: Vec::new(),
                template: None,
            },
        );
        Ok(Self {
            vault,
            session,
            slot,
            raw: Vec::new(),
            states,
            stats: Stats::default(),
            // Тот же потолок, что у тела запроса: ответ не обязан быть меньше
            // запроса, но и бесконечным не бывает.
            limit: cfg.max_body_bytes,
            restore_names: vault.mode() == VaultMode::Session,
        })
    }

    /// Счётчики на текущий момент.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Сколько маркеров прошло дословно по всем живым машинам.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.states.values().map(|s| s.stream.unresolved()).sum()
    }

    /// Скормить кусок байт ответа; готовые клиенту байты дописываются в `out`.
    ///
    /// # Errors
    ///
    /// [`RelayError::FrameTooBig`] — накопленный незакрытый кадр больше
    /// `max_body_bytes`; [`RelayError::Vault`] — хранилище отказало на развороте.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RelayError> {
        self.raw.extend_from_slice(chunk);
        if self.raw.len() > self.limit {
            return Err(RelayError::FrameTooBig { limit: self.limit });
        }
        while let Some(frame) = take_frame(&mut self.raw) {
            self.frame(&frame, out);
        }
        Ok(())
    }

    /// Конец потока: всё удержанное наружу (незакрытый кадр, маркер на хвосте,
    /// слово на хвосте).
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let rest = std::mem::take(&mut self.raw);
        if !rest.is_empty() {
            // Незакрытый кадр на EOF отдаём дословно и считаем битым: молча
            // выкинуть байты, полученные от модели, значит украсть у клиента её
            // ответ.
            self.stats.malformed += 1;
            out.extend_from_slice(&rest);
        }
        self.flush_all(out);
    }

    /// Один кадр (`…\n\n`) целиком.
    fn frame(&mut self, frame: &[u8], out: &mut Vec<u8>) {
        let (lines, has_data) = split_data(frame);
        if !has_data || !mentions_marker(&lines) {
            // Быстрый путь: пере-сериализация не нужна, байты идут дословно —
            // это и есть «прозрачность» прокси на 99 % кадров.
            out.extend_from_slice(frame);
            return;
        }
        let mut rebuilt: Vec<u8> = Vec::with_capacity(frame.len());
        let mut changed = false;
        for line in &lines {
            let Some(payload) = data_payload(line) else {
                rebuilt.extend_from_slice(line);
                rebuilt.extend_from_slice(b"\n");
                continue;
            };
            if payload == DONE {
                // Флеш удержанного ДО сентинела: клиент обязан увидеть весь текст
                // до `[DONE]`, иначе хвост ответа потерян для парсера.
                self.flush_all(out);
                rebuilt.extend_from_slice(line);
                rebuilt.extend_from_slice(b"\n");
                continue;
            }
            let Ok(mut value) = serde_json::from_slice::<Value>(payload) else {
                self.stats.malformed += 1;
                rebuilt.extend_from_slice(b"data: ");
                rebuilt.extend_from_slice(payload);
                rebuilt.extend_from_slice(b"\n");
                continue;
            };
            if self.rewrite_value(&mut value) {
                changed = true;
                let Ok(text) = serde_json::to_string(&value) else {
                    // Сериализация собственного Value не падает; если всё же —
                    // отдаём исходную нагрузку, а не пустоту.
                    rebuilt.extend_from_slice(b"data: ");
                    rebuilt.extend_from_slice(payload);
                    rebuilt.extend_from_slice(b"\n");
                    continue;
                };
                rebuilt.extend_from_slice(b"data: ");
                rebuilt.extend_from_slice(text.as_bytes());
                rebuilt.extend_from_slice(b"\n");
            } else {
                rebuilt.extend_from_slice(b"data: ");
                rebuilt.extend_from_slice(payload);
                rebuilt.extend_from_slice(b"\n");
            }
        }
        rebuilt.extend_from_slice(b"\n");
        if changed {
            out.extend_from_slice(&rebuilt);
        } else {
            out.extend_from_slice(frame);
        }
    }

    /// Развернуть речевые поля события. `true` — текст менялся.
    fn rewrite_value(&mut self, value: &mut Value) -> bool {
        // Снимок envelope до мутабельного заимствования: он нужен как шаблон
        // флеш-кадра, а `get_mut` уже держит `value`.
        let envelope = value.clone();
        let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) else {
            return false;
        };
        let mut touched = false;
        for ch in choices.iter_mut() {
            let Some(obj) = ch.as_object_mut() else {
                continue;
            };
            let index = obj
                .get("index")
                .and_then(Value::as_u64)
                .map_or(0, |i| u32::try_from(i).unwrap_or(0));
            let Some(delta) = obj.get_mut("delta").and_then(Value::as_object_mut) else {
                continue;
            };
            for field in SPEECH_FIELDS {
                // Речевое поле не-строкой — структура, которую наш ретранслятор
                // не видит: гарантию подмены для неё выполнить нельзя, и молчать
                // о ней значило бы врать в трейлере (`malformed=0` при живых
                // маркерах внутри массива). Считаем кадр непрослеживаемым; сами
                // байты идут транзитом — surrogate-метки не ПДн, утечки нет.
                // `null` не считается: провайдеры им пишут «в этом кадре текста
                // нет», и это штатная форма, а не невидимая структура.
                if !matches!(
                    delta.get(field),
                    None | Some(Value::Null | Value::String(_))
                ) {
                    self.stats.malformed += 1;
                }
                let Some(text) = delta.get(field).and_then(Value::as_str).map(str::to_owned) else {
                    continue;
                };
                if text.is_empty() {
                    continue;
                }
                let replaced = self.content(index, &text, &envelope);
                if replaced != text {
                    delta.insert(field.to_owned(), Value::String(replaced));
                    touched = true;
                }
            }
        }
        touched
    }

    /// Прогнать текст дельты через машину разворота + удержание слова.
    fn content(&mut self, index: u32, text: &str, envelope: &Value) -> String {
        if !self.states.contains_key(&index) {
            let Ok(stream) = self.vault.stream(self.session) else {
                return text.to_owned();
            };
            self.states.insert(
                index,
                State {
                    stream,
                    word: Vec::new(),
                    template: Some(envelope.clone()),
                },
            );
        }
        let Some(st) = self.states.get_mut(&index) else {
            return text.to_owned();
        };
        st.template = Some(envelope.clone());
        let mut fed: Vec<u8> = Vec::with_capacity(text.len() + st.word.len());
        fed.append(&mut st.word);
        let mut buf = Vec::with_capacity(text.len());
        let push = st.stream.push(text.as_bytes(), &mut buf);
        fed.extend_from_slice(&buf);
        self.stats.substituted += push.substituted;
        self.stats.incomplete |= push.incomplete;
        // Граница слова: хвост, обрезанный на середине слова, держится дальше.
        let cut = if self.restore_names {
            word_cut(&fed)
        } else {
            fed.len()
        };
        let ready = fed[..cut].to_vec();
        st.word = fed[cut..].to_vec();
        let Ok(mut out) = String::from_utf8(ready) else {
            // По построению недостижимо: машина отдаёт только целые символы.
            // Достижимо оно или нет — решать не нам, поэтому оригинальный текст
            // возвращается нетронутым, а не «почти правильный».
            self.stats.incomplete = true;
            return text.to_owned();
        };
        if self.restore_names {
            self.stats.substituted += self.vault.restore_surrogates_soft(&self.slot, &mut out);
        }
        out
    }

    /// Флеш всех индексов.
    fn flush_all(&mut self, out: &mut Vec<u8>) {
        let mut idxs: Vec<u32> = self.states.keys().copied().collect();
        // Порядок обхода `HashMap` не определён, а хвостовые кадры — часть
        // ответа клиента: два одинаковых запроса не должны различаться порядком.
        idxs.sort_unstable();
        for i in idxs {
            self.flush_state(i, out);
        }
    }

    /// Флеш одного индекса: `finish` машины + остаток слова, отдельным кадром.
    fn flush_state(&mut self, index: u32, out: &mut Vec<u8>) {
        let Some(mut st) = self.states.remove(&index) else {
            return;
        };
        let mut buf = Vec::new();
        let fin = st.stream.finish(&mut buf);
        self.stats.incomplete |= fin.incomplete;
        buf.append(&mut st.word);
        let mut text = String::from_utf8(buf).unwrap_or_else(|e| {
            self.stats.incomplete = true;
            String::from_utf8_lossy(e.as_bytes()).into_owned()
        });
        if self.restore_names {
            self.stats.substituted += self.vault.restore_surrogates_soft(&self.slot, &mut text);
        }
        if !text.is_empty() {
            let frame = synthetic(st.template.as_ref(), index, &text);
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(frame.as_bytes());
            out.extend_from_slice(b"\n\n");
        }
        // Машина после флеша чистая и обязана остаться: стрим формально ещё жив
        // (могут прийти новые дельты того же индекса).
        if let Ok(stream) = self.vault.stream(self.session) {
            self.states.insert(
                index,
                State {
                    stream,
                    word: Vec::new(),
                    template: None,
                },
            );
        }
    }
}

/// Комментарий-итог в конце потока.
///
/// В SSE заголовков после тела нет, поэтому счётчики деградации едут
/// SSE-комментарием: парсеры их игнорируют, человек и тест — нет.
#[must_use]
pub fn trailer(stats: Stats, unresolved: usize) -> Vec<u8> {
    format!(
        ": guard substituted={} unresolved={} malformed={} incomplete={}\n\n",
        stats.substituted, unresolved, stats.malformed, stats.incomplete
    )
    .into_bytes()
}

/// Кадр до пустой строки включительно; `None`, если кадр ещё не закрыт.
fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (at, sep) = find_delim(buf)?;
    Some(buf.drain(..at + sep).collect())
}

/// Ищем `\n\n` или `\r\n\r\n`: начало разделителя и его длина.
fn find_delim(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0_usize;
    while i < buf.len() {
        if buf[i] == b'\n' {
            if i + 1 < buf.len() && buf[i + 1] == b'\n' {
                return Some((i, 2));
            }
            if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
                return Some((i, 4));
            }
        } else if buf[i] == b'\r' && i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        i += 1;
    }
    None
}

/// Линии кадра без завершающего разделителя + есть ли среди них `data:`.
fn split_data(frame: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let body = frame
        .strip_suffix(b"\r\n\r\n")
        .or_else(|| frame.strip_suffix(b"\n\n"))
        .unwrap_or(frame);
    let mut lines = Vec::new();
    let mut has_data = false;
    for line in body.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line).to_vec();
        has_data |= data_payload(&line).is_some();
        lines.push(line);
    }
    (lines, has_data)
}

/// Нагрузка `data:` (необязательный один пробел после двоеточия, WHATWG §9.2.5).
fn data_payload(line: &[u8]) -> Option<&[u8]> {
    let rest = line.strip_prefix(b"data:")?;
    Some(rest.strip_prefix(b" ").unwrap_or(rest))
}

/// Есть ли хотя бы в одной линии начало маркера.
fn mentions_marker(lines: &[Vec<u8>]) -> bool {
    lines
        .iter()
        .any(|l| data_payload(l).is_some_and(|p| p.contains(&b'[')))
}

/// Индекс, до которого отрезок точно кончается границей слова.
fn word_cut(buf: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(buf) else {
        // Невалидный UTF-8 сюда не приходит (машина держит оборванные
        // последовательности сама), но на всякий случай держим всё: решить
        // позже дешевле, чем разрезать символ.
        return 0;
    };
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    // Хвостовое слово ищем с конца: пока идут letter/`_`, идём влево.
    while end > 0 {
        let c = char_before(text, end);
        if c.is_alphanumeric() || c == '_' {
            end -= c.len_utf8();
        } else {
            break;
        }
    }
    if end == bytes.len() || end == 0 {
        // Либо хвост не слово (резать нечего), либо слово тянется через весь
        // отрезок: держим всё до его конца, потому что начало слова мы не видали.
        return if end == 0 { 0 } else { bytes.len() };
    }
    end
}

/// Символ, заканчивающийся перед байтом `end`.
fn char_before(text: &str, end: usize) -> char {
    let b = text.as_bytes();
    let mut start = end - 1;
    while start > 0 && is_cont(b[start]) {
        start -= 1;
    }
    text[start..end].chars().next().unwrap_or('\u{fffd}')
}

/// Байт continuation UTF-8 (`10xx_xxxx`).
fn is_cont(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// Синтетический кадр флеша: тот же envelope, что у последнего события индекса,
/// только `delta.content` = удержанное, а `finish_reason` снят — он принадлежит
/// настоящему последнему кадру, а этот вставляется перед ним.
fn synthetic(template: Option<&Value>, index: u32, text: &str) -> String {
    let mut obj = Map::new();
    if let Value::Object(t) = template.unwrap_or(&Value::Null) {
        for (k, v) in t {
            if k != "choices" && k != "usage" {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    let mut delta = Map::new();
    delta.insert("content".to_owned(), Value::String(text.to_owned()));
    let mut choice = Map::new();
    choice.insert("index".to_owned(), Value::from(index));
    choice.insert("delta".to_owned(), Value::Object(delta));
    obj.insert(
        "choices".to_owned(),
        Value::Array(vec![Value::Object(choice)]),
    );
    serde_json::to_string(&Value::Object(obj)).unwrap_or_else(|_| String::from("{}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;
    use crate::schema::Schema;
    use crate::vault::SpanIn;

    /// Хвостовые кадры обязан определять вход, а не обход `HashMap`.
    ///
    /// Отказ ловится так: строим 64 релая с одной последовательностью вставок.
    /// Каждый новый `HashMap` в процессе получает свой сид хеширования, поэтому
    /// без сортировки хотя бы один прогон выдаёт хвосты не по возрастанию
    /// `index`. Детерминированность проверяем как равенство всех 64 порядков
    /// между собой и ожидаемому — иначе тест был бы flaky-зелёным.
    #[test]
    fn tail_frames_are_flushed_in_index_order() {
        const IDX: [u32; 3] = [7, 3, 1];
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let vault = Vault::startup(VaultMode::Session, crate::config::Mlock::BestEffort)
            .expect("хранилище в режиме 2 поднимается");
        let mut orders: Vec<Vec<u32>> = Vec::new();
        for n in 0..64_u32 {
            let session = format!("tail-{n}");
            let mut relay =
                Relay::new(&vault, Some(&session), &cfg).expect("релай в режиме 2 поднимается");
            let mut held_out = Vec::new();
            for i in IDX {
                let frame = format!(
                    "data: {{\"choices\":[{{\"index\":{i},\"delta\":{{\"content\":\"хвост{i}\"}}}}]}}\n\n"
                );
                relay
                    .push(frame.as_bytes(), &mut held_out)
                    .expect("кадр целый");
            }
            let echoed = String::from_utf8(held_out).expect("ASCII-оболочка");
            assert!(
                echoed.contains("\"content\":\"\""),
                "удержанное слово должно было оставить пустую дельту: {echoed}"
            );
            let mut out = Vec::new();
            relay.finish(&mut out);
            let text = String::from_utf8(out).expect("хвостовые кадры — UTF-8");
            let seen: Vec<u32> = text
                .lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .filter_map(|rest| serde_json::from_str::<Value>(rest).ok())
                .filter_map(|v| v["choices"][0]["index"].as_u64())
                .map(|i| u32::try_from(i).expect("индекс дельты маленький"))
                .collect();
            assert_eq!(
                seen.len(),
                IDX.len(),
                "по одному хвостовому кадру на индекс"
            );
            orders.push(seen);
        }
        let mut want = IDX;
        want.sort_unstable();
        let want = want.to_vec();
        assert!(
            orders.iter().all(|o| *o == want),
            "порядок хвостовых кадров не определён входом: {orders:?}"
        );
    }

    /// Дискриминатор SPEC §8: наивная замена по чанкам ломает разворот.
    ///
    /// Трём один и тот же поток дважды. Наивно: каждый чанк отдельно через
    /// `str::replace` — метка, разрезанная пополам границей чанка, не находится
    /// ни в одном из них, и разворота не происходит. Нашим релаем: те же
    /// границы реза, тот же вход — и исход побайтно совпадает с целым стримом.
    /// Без этого теста утверждение «наивный replace непригоден» оставалось бы
    /// декларацией, а не фактом.
    #[test]
    fn naive_replace_by_chunk_breaks_roundtrip() {
        let text = "Иванов Пётр Сергеевич, ИНН 2482014338";
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let vault = Vault::startup(VaultMode::Session, crate::config::Mlock::BestEffort)
            .expect("хранилище в режиме 2 поднимается");
        let needle = "Иванов Пётр Сергеевич";
        let start = text.find(needle).expect("подстрока есть в тестовом входе");
        let spans = vec![SpanIn {
            entity_type: "person_name".to_owned(),
            byte_start: start,
            byte_end: start + needle.len(),
        }];
        let anon = vault
            .anonymize(
                Some("naive"),
                text,
                &spans,
                &Schema::embedded().expect("канон валиден"),
            )
            .expect("анонимизация");
        let masked = anon.text.clone();
        let mstart = masked.find('[').expect("метка на месте");
        let mend = masked.find(']').expect("метка закрыта");
        let marker = masked[mstart..=mend].to_owned();
        assert!(
            marker.len() > 6 && marker.starts_with('[') && marker.ends_with(']'),
            "ожидался маркер вида `[КЛАСС_1_…]]`, получено {marker}"
        );
        let payload = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{masked}\"}}}}]}}\n\ndata: [DONE]\n\n"
        );
        // Резаем ровно посередине метки: открывающая скобка остаётся в левой
        // половинке, закрывающая — в правой, так что упрёк в многобайтовости
        // не отмажет.
        let marker_start = payload.find(&marker).expect("метка в стриме есть");
        let cut = marker_start + marker.len() / 2;
        let parts = [&payload[..cut], &payload[cut..]];
        assert!(
            parts[0].contains('[') && parts[1].contains(']'),
            "разрез не внутри метки: тест ничего не проверяет"
        );

        // Наивный путь: замена независимо по каждому чанку.
        let naive: String = parts
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk.as_bytes()).replace(&marker, needle))
            .collect();
        assert!(
            naive.contains('[') || naive.contains(']'),
            "наивный путь чудесным образом собрал метку — тест обесценен"
        );
        assert!(
            !naive.contains(text),
            "наивный разворот прошёл целиком, значит тест не дискриминирует"
        );

        // Наш путь: те же границы реза, побайтно совпадающий результат.
        let whole = run_relay(&vault, &cfg, payload.as_bytes(), &[]);
        let split = run_relay(&vault, &cfg, parts[0].as_bytes(), &[parts[1].as_bytes()]);
        assert_eq!(
            split, whole,
            "релай разошёлся с целым стримом на тех же границах"
        );
        assert!(
            whole.contains(needle) && !whole.contains(&marker),
            "разворот не случился и у релая: {whole}"
        );
    }

    /// Прогон стрима через `Relay`: один кусок целиком + остальные досылом.
    fn run_relay(vault: &Vault, cfg: &Config, first: &[u8], rest: &[&[u8]]) -> String {
        let mut relay = Relay::new(vault, Some("naive"), cfg).expect("релай поднимается");
        let mut out = Vec::new();
        relay
            .push(first, &mut out)
            .expect("первый кусок принимается");
        for chunk in rest {
            relay.push(chunk, &mut out).expect("кусок принимается");
        }
        relay.finish(&mut out);
        String::from_utf8(out).expect("оболочка — UTF-8")
    }

    /// Непрослеживаемое речевое поле: список частей вместо строки.
    ///
    /// Контракт стрима — текстовый, поэтому структура внутри `delta.content`
    /// для ретранслятора невидима, и молчать о ней значило бы врать в трейлере.
    /// Отдельно проверяем `null`: провайдеры им пишут «в этом кадре текста нет»,
    /// это штатная форма, а не невидимая структура.
    #[test]
    fn opaque_delta_field_counts_malformed() {
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let vault = Vault::startup(VaultMode::Session, crate::config::Mlock::BestEffort)
            .expect("хранилище в режиме 2 поднимается");
        let mut relay = Relay::new(&vault, Some("opaque"), &cfg).expect("релай поднимается");
        let marker = "[[F0#aaaaaaaa]]";
        let frame = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{marker}\"}}]}}}}]}}\n\n"
        );
        let mut out = Vec::new();
        relay
            .push(frame.as_bytes(), &mut out)
            .expect("кадр целый даже с невидимым полем");
        let text = String::from_utf8(out).expect("оболочка — UTF-8");
        assert!(
            text.contains(marker),
            "маркер обязан уйти транзитом целым: {text}"
        );
        assert_eq!(relay.stats().malformed, 1, "невидимое поле не посчитано");
        relay
            .push(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":null}}]}\n\n",
                &mut Vec::new(),
            )
            .expect("кадр целый");
        assert_eq!(
            relay.stats().malformed,
            1,
            "`null` — штатная форма, счётчик её не двигает"
        );
    }

    #[test]
    fn find_delim_handles_both_ending_styles() {
        assert_eq!(find_delim(b"a\n\nb"), Some((1, 2)));
        assert_eq!(find_delim(b"a\r\n\r\nb"), Some((1, 4)));
        assert_eq!(find_delim(b"a\nb"), None);
    }

    #[test]
    fn data_payload_tolerates_missing_space() {
        assert_eq!(data_payload(b"data: x"), Some(b"x".as_slice()));
        assert_eq!(data_payload(b"data:x"), Some(b"x".as_slice()));
        assert_eq!(data_payload(b"event: foo"), None);
    }

    #[test]
    fn word_cut_holds_unfinished_word() {
        assert_eq!(
            word_cut("Иван".as_bytes()),
            0,
            "весь отрезок — одно слово: держим целиком"
        );
        assert_eq!(word_cut("Иван ".as_bytes()), 9, "слово закрыто пробелом");
        assert_eq!(
            word_cut("привет мир".as_bytes()),
            13,
            "хвостовое «мир» держим (байты, не символы: кириллица по 2)"
        );
        assert_eq!(word_cut(b"!"), 1, "небуквенный хвост резать не надо");
    }

    #[test]
    fn split_data_reports_presence_of_data_line() {
        let (lines, has) = split_data(b"event: message\ndata: {}\n\n");
        assert!(has);
        assert_eq!(lines.len(), 2);
        let (_, has) = split_data(b": ping\n\n");
        assert!(!has, "комментарий не данные");
    }

    #[test]
    fn synthetic_frame_keeps_envelope_identity() {
        let tmpl: Value = serde_json::from_str(
            r#"{"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        )
        .unwrap();
        let s = synthetic(Some(&tmpl), 0, "хвост");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["model"], "m", "модель и id флеш-кадра наследуются");
        assert!(
            v["choices"][0].get("finish_reason").is_none(),
            "finish_reason снимается"
        );
        assert_eq!(v["choices"][0]["delta"]["content"], "хвост");
    }
}
