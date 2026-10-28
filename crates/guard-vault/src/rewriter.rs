//! Потоковая обратная подмена маркеров (SPEC §8, §10 шаг 5 атом B).
//!
//! LLM отвечает текстом, где вместо `ПДн` стоят маркеры. Демон отдаёт ответ наружу
//! и на этом пути разворачивает маркеры обратно в оригиналы. Ответ прилетает
//! SSE-чанками произвольной нарезки: маркер может быть разрезан по байту, в том
//! числе внутри многобайтового UTF-8-символа (SPEC §8: «токен `[PERSON_1]`
//! может прилететь нарезанным на 3 пакета»).
//!
//! Инварианты (SPEC §4/§8 + ТЗ шага 5):
//!
//! 1. Ни одного потерянного байта: конкатенация выдачи == вход, где
//!    распознанные маркеры заменены на оригиналы. Тесты сверяют это для
//!    перебора нарезок.
//! 2. Сомнение = пропуск дословно, а не ошибка всего ответа. Незакрытый маркер
//!    на EOF, тело вне алфавита, маркер без пары в словаре — текст выдаётся как
//!    есть, поверх ставится [`Push::incomplete`] / [`Finish::incomplete`].
//!    Обрывать стрим из-за одного хвоста значит потерять легальный текст;
//!    fail-closed здесь = «не подменять», а не «промолчать».
//! 3. Байты неразобранных маркеров наружу не просачиваются частично: кандидат
//!    буферится до решения (look-ahead = [`Grammar::window`]).
//! 4. Выдача не режется внутри UTF-8-последовательности: неполный хвост
//!    переедает в следующий вызов ([`Push::held`]).
//! 5. Подмена идёт строго по границам спана: байты вне маркера копируются байт
//!    в байт, без «улучшений» пробелов и регистра.
//!
//! Разбор байт-ориентированный, не по `chars()`: ASCII-префиксы грамматик
//! (`[` и `]]`) не могут быть порождены продолжением UTF-8-последовательности
//! (продолжающие байты ≥ 0x80), поэтому разрезанный посередине символ не
//! способен подделать открытие маркера — и наоборот, байт тела не может
//! accidentally склеиться с половинкой кириллической буквы.

#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use std::collections::VecDeque;

use crate::token;

/// Алфавит тела маркера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// base64url без паддинга: `A-Za-z0-9-_`.
    Base64Url,
    /// Человекочитаемая метка: `A-Z0-9_`.
    Label,
}

/// Грамматика маркера: префикс, суффикс, алфавит и потолок длины тела.
///
/// Сумма `prefix + max_body + suffix` — budget look-ahead: ровно столько байт
/// машина обязана удержать, чтобы решить, маркер это или нет.
#[derive(Debug, Clone, Copy)]
pub struct Grammar {
    /// Открывающая часть маркера.
    pub prefix: &'static [u8],
    /// Закрывающая часть маркера.
    pub suffix: &'static [u8],
    /// Алфавит тела.
    pub body: BodyKind,
    /// Максимум байт в теле.
    ///
    /// Ограничение грамматики: алфавит тела не должен пересекаться с первым
    /// байтом суффикса, иначе закрытие никогда не случится — тело сверяется
    /// приоритетнее суффикса (`StreamRewriter::step_body`).
    pub max_body: usize,
}

impl Grammar {
    /// Inline-токен формата F0: `[[F0#<base64url>]]`.
    ///
    /// Budget = [`token::MAX_MARKER_BYTES`] = 1594 байта, а не 32 из SPEC §8:
    /// §8 говорит о короткой метке `[PERSON_1]` (это [`Grammar::LABEL`]),
    /// тогда как stateless-токен несёт нонсу 24 Б + тег 16 Б + LZ4-блок. С
    /// потолком оригинала 128 Б это было 279 байт (272 символа base64url для
    /// промеренного максимума спана 109 Б); с потолком 1024 Б (#120) токен
    /// вырастает до 1587 символов, а окно — до 1594.
    ///
    /// Цена поднятия потолка ложится на **stateless-режим**: в нём маркер несёт
    /// оригинал в себе, поэтому (а) в выходном тексте словесный реестровый
    /// номер заменяется полторакилобайтным маркером вместо 279-байтного, и
    /// (б) look-ahead машины держит 1594 байта кандидата. В session-режиме
    /// (`FASAD_VAULT_MODE=2`) окно остаётся `Grammar::LABEL` = 34 Б — там
    /// ничего не меняется, и именно session-режим несёт обратный ход по
    /// реестру форм. Расхождение с §8 зафиксировано тестом
    /// `lookahead_budget_matches_grammar` и продублировано в рапорте по атому
    /// A/B; число окна пинится там же.
    pub const F0_INLINE: Self = Self {
        prefix: token::MARKER_PREFIX.as_bytes(),
        suffix: token::MARKER_SUFFIX.as_bytes(),
        body: BodyKind::Base64Url,
        max_body: token::MAX_TOKEN_B64_LEN,
    };

    /// Короткая типизированная метка `[CLIENT_PERSON_1]` (SPEC §2 каскад 3).
    ///
    /// Под эту грамматику справедлива цифра §8 «look-ahead до 32 байт»: тело
    /// ≤ 32 Б плюс скобки дают окно 34 Б.
    pub const LABEL: Self = Self {
        prefix: b"[",
        suffix: b"]",
        body: BodyKind::Label,
        max_body: 32,
    };

    /// Полный budget буфера: префикс + тело + суффикс.
    pub const fn window(&self) -> usize {
        self.prefix.len() + self.max_body + self.suffix.len()
    }

    /// Допустим ли байт в теле маркера.
    const fn accepts(&self, b: u8) -> bool {
        match self.body {
            BodyKind::Base64Url => b.is_ascii_alphanumeric() || b == b'-' || b == b'_',
            BodyKind::Label => b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_',
        }
    }
}

/// Что вернул [`MarkerResolver`] на распознанный маркер.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Подставить эти байты вместо маркера целиком.
    Substitute(Vec<u8>),
    /// Маркер распознан по грамматике, но оригинала нет (или ключ не тот) —
    /// выдать дословно и поднять флаг.
    Unknown,
}

/// Словарь «тело маркера → оригинал».
///
/// Реализации: сессионный кэш (атом C) для `[CLIENT_PERSON_1]`-формы,
/// крипто-контейнер (атом A) для `[[F0#…]]`-формы. `&mut`, потому что кэш
/// обновляет счётчики доступа и порядок вытеснения.
pub trait MarkerResolver {
    /// Разрешить тело маркера (байты между префиксом и суффиксом).
    fn resolve(&mut self, body: &[u8]) -> Resolution;
}

impl<F> MarkerResolver for F
where
    F: FnMut(&[u8]) -> Resolution,
{
    fn resolve(&mut self, body: &[u8]) -> Resolution {
        self(body)
    }
}

/// Обёртка над замыканием, позволяющая держать [`StreamRewriter`] в поле с
/// вытертым типом резолвера.
///
/// Нужно шагу 7c: SSE-релай в `guard-daemon` держит машину состояния в своей
/// структуре по одной на `choices[i]`, а замкнуть `VaultEngine` на счётчик
/// нерезолвленных маркеров в дженерике `R` без имени типа нельзя. Blanket-импл
/// ниже не конфликтует с `impl<F: FnMut…> MarkerResolver for F`: `FnResolver` —
/// наш тип, и `FnMut` для него не реализован ни здесь, ни где-либо ещё.
pub struct FnResolver<F>(pub F);

impl<F: FnMut(&[u8]) -> Resolution> MarkerResolver for FnResolver<F> {
    fn resolve(&mut self, body: &[u8]) -> Resolution {
        (self.0)(body)
    }
}

impl<F> core::fmt::Debug for FnResolver<F> {
    /// Резолвер — замыкание, замкнутое на кэш оригиналов: содержимое
    /// непечатаемо по контракту секретов (AGENTS §Инженерные инварианты:
    /// Debug-вывод только `[REDACTED]`), печатается только факт наличия.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FnResolver([REDACTED])")
    }
}

/// Машина подмены с резолвером «коробочное замыкание».
pub type DynStreamRewriter<'a> =
    StreamRewriter<FnResolver<Box<dyn FnMut(&[u8]) -> Resolution + 'a>>>;

/// Итог одного [`StreamRewriter::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Push {
    /// Сколько байт входа потреблено (всегда == длина чанка).
    pub consumed: usize,
    /// Сколько маркеров подменено ЭТИМ вызовом.
    pub substituted: usize,
    /// Есть незавершённый или нерезолвнутый маркер. Флаг липкий до `finish`.
    pub incomplete: bool,
    /// Сколько байт выдачи удержано из-за оборванной UTF-8-последовательности;
    /// следующий вызов допишет их первым.
    pub held: usize,
}

/// Итог [`StreamRewriter::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finish {
    /// Было ли на хвосте не распознано/не закрыто.
    pub incomplete: bool,
    /// Сколько байт вылито дословно.
    pub flushed: usize,
}

/// Состояние автомата.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Копируем в выдачу, высматриваем первый байт префикса.
    Scanning,
    /// Сверяем префикс, `k` байт уже совпало.
    Prefix,
    /// Внутри тела.
    Body,
    /// Суффикс начат, `k` байт уже совпало.
    Suffix,
}

/// Потоковая подмена маркеров.
pub struct StreamRewriter<R: MarkerResolver> {
    grammar: Grammar,
    resolver: R,
    phase: Phase,
    /// Кандидат: префикс + тело (+ начатый суффикс).
    cand: Vec<u8>,
    /// Сколько байт суффикса совпало.
    suffix_hit: usize,
    /// Очередь переигрывания: байты кандидата после ложного открытия. FIFO —
    /// порядок байтов исходного потока сохраняется (см. [`Self::mismatch`]).
    replay: VecDeque<u8>,
    incomplete: bool,
    total_substituted: usize,
    /// Хвост выдачи, зарезервированный из-за оборванного символа (≤ 3 байта).
    held: Vec<u8>,
}

impl<R: MarkerResolver> core::fmt::Debug for StreamRewriter<R> {
    /// Только метаданные машины: буферы `cand`/`replay`/`held` содержат байты
    /// оригинала `ПДн`, в выводе `Debug` они не попадают — наружу идут только
    /// длины (AGENTS §Инженерные инварианты: Debug-вывод только `[REDACTED]`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamRewriter")
            .field("grammar", &self.grammar)
            .field("resolver", &"[REDACTED]")
            .field("phase", &self.phase)
            .field("incomplete", &self.incomplete)
            .field("total_substituted", &self.total_substituted)
            .field("cand_len", &self.cand.len())
            .field("suffix_hit", &self.suffix_hit)
            .field("replay_len", &self.replay.len())
            .field("held_len", &self.held.len())
            .finish()
    }
}

impl<R: MarkerResolver> StreamRewriter<R> {
    /// Новая машина для грамматики.
    pub fn new(grammar: Grammar, resolver: R) -> Self {
        Self {
            grammar,
            resolver,
            phase: Phase::Scanning,
            cand: Vec::with_capacity(grammar.window()),
            suffix_hit: 0,
            replay: VecDeque::with_capacity(grammar.window()),
            incomplete: false,
            total_substituted: 0,
            held: Vec::with_capacity(4),
        }
    }

    /// Грамматика машины.
    pub fn grammar(&self) -> Grammar {
        self.grammar
    }

    /// Был ли в потоке хоть один нерезолвнутый/незакрытый маркер.
    pub fn is_incomplete(&self) -> bool {
        self.incomplete || self.phase != Phase::Scanning
    }

    /// Сколько маркеров подменено всего.
    pub fn substituted(&self) -> usize {
        self.total_substituted
    }

    /// Скормить кусок ответа; всё распознанное и дословное пишется в `out`.
    ///
    /// Метод не возвращает `Result` намеренно (см. инвариант 2).
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Push {
        let before = out.len();
        if !self.held.is_empty() {
            out.append(&mut self.held);
        }
        let sub_before = self.total_substituted;
        for &b in chunk {
            self.step(b, out);
            while let Some(r) = self.replay.pop_front() {
                self.step(r, out);
            }
        }
        self.hold_partial_utf8(out, before);
        Push {
            consumed: chunk.len(),
            substituted: self.total_substituted - sub_before,
            incomplete: self.is_incomplete(),
            held: self.held.len(),
        }
    }

    /// Конец потока: всё, что не закрылось, отдаём дословно и поднимаем флаг.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Finish {
        let before = out.len();
        out.append(&mut self.held);
        if self.phase != Phase::Scanning && !self.cand.is_empty() {
            // Незакрытый маркер на EOF: дословно, без подмены, с флагом.
            self.incomplete = true;
            out.extend_from_slice(&self.cand);
            self.reset_candidate();
        }
        Finish {
            incomplete: self.incomplete,
            flushed: out.len() - before,
        }
    }

    /// Удобство для не-потоковых вызовов: весь вход → вся выдача.
    ///
    /// Возвращает байты и флаг incomplete; ошибкой не является даже пустое
    /// разрешение маркера — текст проходит дословно.
    pub fn run_to_end(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(input.len());
        self.push(input, &mut out);
        let f = self.finish(&mut out);
        (out, f.incomplete)
    }

    /// Один байт автомата.
    fn step(&mut self, b: u8, out: &mut Vec<u8>) {
        match self.phase {
            Phase::Scanning => {
                if b == self.grammar.prefix[0] {
                    self.cand.clear();
                    self.cand.push(b);
                    self.suffix_hit = 0;
                    self.advance_prefix();
                } else {
                    out.push(b);
                }
            }
            Phase::Prefix => {
                if self.grammar.prefix[self.cand.len()] == b {
                    self.cand.push(b);
                    self.advance_prefix();
                } else {
                    self.mismatch(out, Some(b));
                }
            }
            Phase::Body => self.step_body(b, out),
            Phase::Suffix => {
                if self.grammar.suffix[self.suffix_hit] == b {
                    self.cand.push(b);
                    self.suffix_hit += 1;
                    if self.suffix_hit == self.grammar.suffix.len() {
                        self.close_marker(out);
                    }
                } else {
                    self.mismatch(out, Some(b));
                }
            }
        }
    }

    /// После совпадения байта префикса: переход в тело либо ещё сверяем.
    fn advance_prefix(&mut self) {
        if self.cand.len() == self.grammar.prefix.len() {
            self.phase = Phase::Body;
        } else {
            self.phase = Phase::Prefix;
        }
    }

    fn step_body(&mut self, b: u8, out: &mut Vec<u8>) {
        let body_len = self.cand.len() - self.grammar.prefix.len();
        if self.grammar.accepts(b) && body_len < self.grammar.max_body {
            self.cand.push(b);
            return;
        }
        if b == self.grammar.suffix[0] && body_len >= 1 {
            self.cand.push(b);
            self.suffix_hit = 1;
            self.phase = Phase::Suffix;
            if self.grammar.suffix.len() == 1 {
                self.close_marker(out);
            }
            return;
        }
        // Тело вне алфавита, пустое тело либо потолок длины — это не маркер.
        self.mismatch(out, Some(b));
    }

    /// Маркер закрыт: спрашиваем резолвер.
    fn close_marker(&mut self, out: &mut Vec<u8>) {
        let start = self.grammar.prefix.len();
        let end = self.cand.len() - self.grammar.suffix.len();
        let body = self.cand[start..end].to_vec();
        match self.resolver.resolve(&body) {
            Resolution::Substitute(repl) => {
                out.extend_from_slice(&repl);
                self.total_substituted += 1;
            }
            Resolution::Unknown => {
                self.incomplete = true;
                out.extend_from_slice(&self.cand);
            }
        }
        self.reset_candidate();
    }

    /// Кандидат не маркер: его первый байт — литерал, остальные переигрываются
    /// автоматом (в них могло начаться новое открытие), а следом — байт-триггер.
    ///
    /// Триггер обязан переигрываться, иначе он теряется: именно он чаще всего
    /// и есть начало нового открытия (`[[F0#…` для LABEL-грамматики).
    ///
    /// Переигрывание идёт в FIFO-очередь, а не рекурсивно: вложенный ложный
    /// вызов добавляет байты в хвост, поэтому порядок байтов исходного потока
    /// сохраняется всегда.
    fn mismatch(&mut self, out: &mut Vec<u8>, trigger: Option<u8>) {
        if self.cand.is_empty() {
            self.reset_candidate();
            if let Some(b) = trigger {
                self.step(b, out);
            }
            return;
        }
        // Первый байт кандидата — литерал; остаток и триггер переигрываются.
        out.push(self.cand[0]);
        // Триггер и остаток кандидата встают в ГОЛОВУ очереди: и то и другое
        // предшествует всему, что в очереди уже лежит (триггер либо из головы
        // очереди, либо это свежий байт входа при пустой очереди).
        if let Some(b) = trigger {
            self.replay.push_front(b);
        }
        for b in self.cand[1..].iter().rev().copied() {
            self.replay.push_front(b);
        }
        self.reset_candidate();
    }

    fn reset_candidate(&mut self) {
        self.cand.clear();
        self.suffix_hit = 0;
        self.phase = Phase::Scanning;
    }

    /// Не отдаём наружу оборванную UTF-8-последовательность: до трёх хвостовых
    /// байтов переедают в следующий вызов.
    ///
    /// Граница ищется только внутри байтов ЭТОГО вызова: то, что уже ушло
    /// вызывающему, не отзывается. Для валидного UTF-8-входа этого достаточно,
    /// потому что предыдущий вызов закончился на границе символа.
    fn hold_partial_utf8(&mut self, out: &mut Vec<u8>, from: usize) {
        let hold = partial_utf8_tail_len(out).min(out.len() - from);
        if hold > 0 {
            self.held.extend_from_slice(&out[out.len() - hold..]);
            out.truncate(out.len() - hold);
        }
    }
}

/// Сколько байт на хвосте `bytes` относятся к незавершённой UTF-8-последовательности.
///
/// 0 — хвост стоит на границе символа, его можно отдавать. Невалидный вход
/// (мусорные лиды, продолжения без лида) трактуется как «держать нечего»: мы не
/// валидатор и вешать на него буфер нельзя.
fn partial_utf8_tail_len(bytes: &[u8]) -> usize {
    let mut i = bytes.len();
    let mut cont = 0_usize;
    while i > 0 {
        i -= 1;
        let b = bytes[i];
        if b & 0x80 == 0 {
            return 0; // ASCII — граница сразу после него
        }
        if b & 0xC0 != 0x80 {
            // Лидер: сколько продолжений он требует.
            let need = match b {
                0xC2..=0xDF => 1,
                0xE0..=0xEF => 2,
                0xF0..=0xF4 => 3,
                _ => return 0,
            };
            return if cont < need { cont + 1 } else { 0 };
        }
        cont += 1;
        if cont > 3 {
            return 0;
        }
    }
    0
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::items_after_test_module
)] // паника в тесте = красный CI, это канал ответа; truncation в LCG намеренная
mod tests {
    use super::*;
    use crate::token::{KEY_LEN, MlockPolicy, SessionKey, VaultToken};
    use std::collections::BTreeMap;

    /// Словарь «тело → оригинал» для тестов FSM.
    #[derive(Default)]
    struct MapResolver {
        map: BTreeMap<Vec<u8>, Vec<u8>>,
        misses: usize,
    }

    impl MapResolver {
        fn new(entries: &[(&str, &str)]) -> Self {
            Self {
                map: entries
                    .iter()
                    .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                    .collect(),
                misses: 0,
            }
        }
    }

    /// Секрет-контракт `Debug` (AGENTS §Инженерные инварианты: Debug-вывод
    /// только `[REDACTED]`): отладочный вывод машины не содержит оригиналов,
    /// даже когда оригинал уже лежит в её буферах.
    ///
    /// Две посылки, пойманные возмущением (обе были ложно-зелёными до правки):
    ///
    /// 1. секрет обязан ОКАЗАТЬСЯ в буфере — `.field("cand", &self.cand)` при
    ///    пустом `cand` не красил ничего; здесь буферы наполняются руками, а
    ///    не упованием на то, что FSM их заполнит;
    /// 2. `Debug` над `Vec<u8>` = СПИСОК ЧИСЕЛ, поэтому подстрока секрета в
    ///    нём не ищется ни при какой утечке; реальная форма утечки — дамп
    ///    буфера как строки (`String::from_utf8_lossy`), на ней зуб и краснеет.
    #[test]
    fn debug_output_never_leaks_original_bytes() {
        let secret = "IVANOV PETR SERGEEVICH";
        let mut r = StreamRewriter::new(Grammar::LABEL, MapResolver::new(&[]));
        r.cand.extend_from_slice(secret.as_bytes());
        r.replay.extend(secret.as_bytes().iter().copied());
        r.held.extend_from_slice(secret.as_bytes());
        assert_eq!(r.cand.len(), secret.len(), "флагушка: секрет не в `cand`");
        let leaked = String::from_utf8_lossy(&r.cand);
        assert_eq!(
            leaked.as_ref(),
            secret,
            "флагушка: буфер не читается как строка"
        );
        let dbg = format!("{r:?}");
        assert!(
            !dbg.contains(leaked.as_ref()),
            "Debug сливает буфер кандидата как строку: {dbg}"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "Debug без маркера REDACTED: {dbg}"
        );
        assert!(
            dbg.contains("StreamRewriter"),
            "Debug потерял имя типа: {dbg}"
        );
        // Резолвер-замыкание — тоже секретный контур: печатается заглушка.
        let f = FnResolver(|_: &[u8]| Resolution::Unknown);
        assert_eq!(format!("{f:?}"), "FnResolver([REDACTED])");
    }

    impl MarkerResolver for MapResolver {
        fn resolve(&mut self, body: &[u8]) -> Resolution {
            if let Some(v) = self.map.get(body) {
                Resolution::Substitute(v.clone())
            } else {
                self.misses += 1;
                Resolution::Unknown
            }
        }
    }

    const NAMES: &[(&str, &str)] = &[
        ("CLIENT_PERSON_1", "Ушакова Кира Саввична"),
        ("VENDOR_ORG_2", "ООО Ромашка"),
        ("PERSON_9", "Ёлки-иголки"),
    ];

    fn rewriter() -> StreamRewriter<MapResolver> {
        StreamRewriter::new(Grammar::LABEL, MapResolver::new(NAMES))
    }

    /// Прогон по нарезке; возвращает выдачу и суммарный флаг.
    fn run(text: &str, split: &[(usize, usize)]) -> (String, bool) {
        let mut r = rewriter();
        let mut out = Vec::new();
        let mut incomplete = false;
        for &(a, b) in split {
            incomplete |= r.push(&text.as_bytes()[a..b], &mut out).incomplete;
        }
        incomplete |= r.finish(&mut out).incomplete;
        (
            String::from_utf8(out).unwrap_or_else(|e| panic!("выдача не UTF-8: {e}")),
            incomplete,
        )
    }

    /// Все способы нарезать текст длины `n` (2^(n-1) вариантов).
    fn all_splits(n: usize) -> Vec<Vec<(usize, usize)>> {
        let mut res = Vec::new();
        for mask in 0u64..(1_u64 << (n - 1)) {
            let mut cuts = vec![0usize];
            for i in 1..n {
                if mask & (1 << (i - 1)) != 0 {
                    cuts.push(i);
                }
            }
            cuts.push(n);
            res.push(cuts.windows(2).map(|w| (w[0], w[1])).collect());
        }
        res
    }

    /// Детерминированный LCG для выборочных нарезок.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn one_shot_substitutes_at_span_boundaries() {
        let text = "Клиент [CLIENT_PERSON_1], счёт открыт";
        let (out, incomplete) = run(text, &[(0, text.len())]);
        assert_eq!(out, "Клиент Ушакова Кира Саввична, счёт открыт");
        assert!(!incomplete);
    }

    /// Ядро атома B: ∀ способов нарезать один текст результат одинаков.
    /// Полный перебор — 2^(n-1) нарезок, поэтому текст короткий (13 Б: метка
    /// плюс двухбайтовая `ё` на конце, чтобы половина разрезов приходилась внутрь
    /// многобайтового символа).
    #[test]
    fn property_every_split_of_short_text_yields_same_output() {
        let text = "a[PERSON_9]ё";
        let bytes = text.as_bytes();
        assert_eq!(bytes.len(), 13, "проверь ожидание перед перебором");
        let (whole, _) = run(text, &[(0, bytes.len())]);
        assert_eq!(whole, "aЁлки-иголкиё"); // scan-lang:allow
        let mut checked = 0_usize;
        for split in all_splits(bytes.len()) {
            let (out, _) = run(text, &split);
            assert_eq!(out, whole, "нарезка {split:?} дала другой результат");
            checked += 1;
        }
        assert_eq!(
            checked,
            1 << (bytes.len() - 1),
            "перебран не весь куб нарезок"
        );
    }

    /// Тот же инвариант для текста с ДВУМЯ маркерами и ложным открытием.
    #[test]
    fn property_two_markers_and_false_open_survive_every_split() {
        let text = "[CLIENT_PERSON_1][x]";
        let bytes = text.as_bytes();
        let (whole, inc) = run(text, &[(0, bytes.len())]);
        assert_eq!(whole, "Ушакова Кира Саввична[x]");
        // Ложное открытие — не «сомнение»: `[x]` не может быть меткой по
        // алфавиту, значит ПДн здесь нет и флаг поднимать не за что.
        assert!(!inc, "ложное открытие подняло INCOMPLETE");
        let mut checked = 0_usize;
        for split in all_splits(bytes.len()) {
            let (out, _) = run(text, &split);
            assert_eq!(out, whole, "нарезка {split:?} разошлась");
            checked += 1;
        }
        assert_eq!(checked, 1 << (bytes.len() - 1));
    }

    /// Длинный текст: полный перебор невозможен (2^n), поэтому все срезы шагом
    /// 1..=4 байта + 300 псевдослучайных, включая разрезы внутри символов.
    #[test]
    fn property_long_text_with_strided_and_random_splits() {
        let text = "Договор №5 с [CLIENT_PERSON_1] от 18.10; адрес: ООО Ромашка, \
            ИНН [VENDOR_ORG_2], платёж [PERSON_9] прошёл.";
        let bytes = text.as_bytes();
        let (whole, _) = run(text, &[(0, bytes.len())]);
        assert!(whole.contains("Ушакова"), "подмены не случилось");
        for stride in 1..=4usize {
            let mut split = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let j = (i + stride).min(bytes.len());
                split.push((i, j));
                i = j;
            }
            let (out, _) = run(text, &split);
            assert_eq!(out, whole, "stride {stride} разошёлся");
        }
        let mut r = Lcg(0x853C_49E6_748F_EA9B);
        for _ in 0..300 {
            let mut cuts: Vec<usize> = (0..6).map(|_| (r.next() as usize) % bytes.len()).collect();
            cuts.extend([0, bytes.len()]);
            cuts.sort_unstable();
            cuts.dedup();
            let split: Vec<(usize, usize)> = cuts.windows(2).map(|w| (w[0], w[1])).collect();
            let (out, _) = run(text, &split);
            assert_eq!(out, whole, "случайная нарезка {cuts:?} разошлась");
        }
    }

    /// Маркер, разрезанный на три пакета внутри префикса и внутри тела.
    #[test]
    fn marker_split_across_three_packets() {
        let text = "а [CLIENT_PERSON_1] б";
        let b = text.as_bytes();
        let open = b.iter().position(|&x| x == b'[').expect("префикс есть");
        let splits = [
            vec![(0, open + 3), (open + 3, open + 9), (open + 9, b.len())],
            vec![(0, open + 1), (open + 1, open + 2), (open + 2, b.len())],
            vec![(0, b.len() - 1), (b.len() - 1, b.len())],
            vec![
                (0, open),
                (open, open + 5),
                (open + 5, open + 6),
                (open + 6, b.len()),
            ],
        ];
        for split in splits {
            let (out, _) = run(text, &split);
            assert_eq!(out, "а Ушакова Кира Саввична б", "нарезка {split:?}");
            assert!(!out.contains("CLIENT_PERSON"), "утёк осколок маркера");
        }
    }

    /// Незакрытый маркер на EOF: выдаём дословно, ставим INCOMPLETE, НЕ ошибку.
    #[test]
    fn unterminated_tail_passes_through_with_flag() {
        for text in ["Итого по [CLIENT_PERSON", "хвост [", "хвост [ABC"] {
            let (out, incomplete) = run(text, &[(0, text.len())]);
            assert_eq!(out, text, "текст обязан пройти дословно");
            assert!(incomplete, "флаг INCOMPLETE не поднят для {text:?}");
            let n = text.len();
            let split = vec![(0, n / 3), (n / 3, n / 2), (n / 2, n)];
            let (out2, inc2) = run(text, &split);
            assert_eq!(out2, text, "нарезка изменила дословный хвост");
            assert!(inc2, "флаг потерян при нарезке");
        }
    }

    /// Маркера нет в словаре: дословно + флаг, остальной текст цел.
    #[test]
    fn unknown_marker_passes_through_and_flags() {
        let text = "клиент [PERSON_42], счёт [CLIENT_PERSON_1]";
        let mut r = rewriter();
        let mut out = Vec::new();
        let p = r.push(text.as_bytes(), &mut out);
        let f = r.finish(&mut out);
        assert_eq!(
            String::from_utf8(out).expect("UTF-8"),
            "клиент [PERSON_42], счёт Ушакова Кира Саввична"
        );
        assert!(p.incomplete || f.incomplete, "INCOMPLETE не поднят");
        assert_eq!(r.substituted(), 1, "подменён ровно один маркер");
        assert_eq!(r.resolver.misses, 1);
    }

    /// Ложные открытия: `[` в тексте не обязан быть маркером, байты возвращаются
    /// все, до последнего.
    #[test]
    fn false_opens_are_returned_verbatim() {
        for text in [
            "a[b]",
            "[][]",
            "[[[[]]]]",
            "скобка [ не закрыта",
            "[_person_1] строчные буквы",
            "[АБВ] не ASCII",
            "100% [x]",
            "[[F0#",
            "[[ABC]]",
            "]]",
            "[",
            "[][",
            "[A]B[C]",
            "x[[[[[[[[[",
            "[[[[",
        ] {
            let (out, _) = run(text, &[(0, text.len())]);
            assert_eq!(out, text, "ложное открытие исказило {text:?}");
            let (out2, _) = run(text, &[(0, 1), (1, text.len())]);
            assert_eq!(out2, text, "ложное открытие исказило {text:?} в нарезке");
        }
    }

    /// Вложенность/соседство: метка сразу за меткой подменяется обе, а
    /// `[A]` внутри оставшегося текста не съедает соседа.
    #[test]
    fn adjacent_markers_are_each_substituted() {
        let text = "[PERSON_9][PERSON_9]";
        let mut r = rewriter();
        let (out, inc) = r.run_to_end(text.as_bytes());
        assert_eq!(
            String::from_utf8(out).expect("UTF-8"),
            "Ёлки-иголкиЁлки-иголки"
        );
        assert!(!inc);
        assert_eq!(r.substituted(), 2);
    }

    #[test]
    fn empty_and_boundary_inputs_are_noops() {
        let mut r = rewriter();
        let mut out = Vec::new();
        let p = r.push(b"", &mut out);
        assert_eq!(p.consumed, 0);
        assert!(!p.incomplete);
        let f = r.finish(&mut out);
        assert!(!f.incomplete);
        assert_eq!(out.len(), 0);
        // Висящая `[` на EOF обязана вернуться и поднять флаг.
        let mut r2 = rewriter();
        let mut out2 = Vec::new();
        r2.push(b"[", &mut out2);
        assert!(r2.finish(&mut out2).incomplete);
        assert_eq!(out2, b"[");
    }

    /// Выдача не режется внутри UTF-8: каждый чанк сам по себе валиден, склейка
    /// совпадает с монолитным прогоном.
    #[test]
    fn output_never_splits_a_utf8_sequence() {
        let text = "абвгдежзийкл [CLIENT_PERSON_1] mnoпрст"; // scan-lang:allow
        let bytes = text.as_bytes();
        let mut r = rewriter();
        let mut joined = Vec::new();
        let mut chunk = 1usize;
        let mut i = 0;
        while i < bytes.len() {
            let j = (i + chunk).min(bytes.len());
            let mut out = Vec::new();
            let p = r.push(&bytes[i..j], &mut out);
            assert!(
                out.is_empty() || std::str::from_utf8(&out).is_ok(),
                "чанк {i}..{j} выдал оборванный UTF-8: {out:?}",
            );
            assert_eq!(p.consumed, j - i);
            joined.extend_from_slice(&out);
            i = j;
            chunk = chunk % 5 + 1;
        }
        let mut tail = Vec::new();
        r.finish(&mut tail);
        joined.extend_from_slice(&tail);
        assert_eq!(
            String::from_utf8(joined).expect("склейка валидна"),
            "абвгдежзийкл Ушакова Кира Саввична mnoпрст" // scan-lang:allow
        );
        assert_eq!(r.held.len(), 0, "хвост не выплавлен после finish");
    }

    /// Разбор F0-маркера через крипту атома A: тело → токен → оригинал.
    fn decrypt_f0(key: &SessionKey, body: &[u8]) -> Resolution {
        std::str::from_utf8(body)
            .ok()
            .and_then(|s| VaultToken::from_base64url(s).ok())
            .and_then(|t| t.open_with(key, MlockPolicy::BestEffort).ok())
            .map_or(Resolution::Unknown, |plain| {
                Resolution::Substitute(plain.as_bytes().to_vec())
            })
    }

    /// F0-грамматика: реальный токен атома A проходит сквозь машину и
    /// разворачивается в оригинал, в том числе по одному байту за вызов.
    #[test]
    fn f0_inline_token_roundtrips_through_the_stream() {
        let key = SessionKey::new([0x77; KEY_LEN]);
        let original = "Ушакова Кира Саввична";
        let tok = VaultToken::seal_with(&key, original.as_bytes(), MlockPolicy::BestEffort)
            .expect("seal");
        let marker = tok.to_marker();
        assert!(
            marker.len() <= Grammar::F0_INLINE.window(),
            "маркер не в budget"
        );
        let text = format!("клиент {marker} платит");
        let decrypt = |body: &[u8]| decrypt_f0(&key, body);
        let expected = format!("клиент {original} платит");
        let mut one_shot = StreamRewriter::new(Grammar::F0_INLINE, decrypt);
        let (out, inc) = one_shot.run_to_end(text.as_bytes());
        assert!(!inc, "закрытый маркер не должен оставлять incomplete");
        assert_eq!(String::from_utf8(out).expect("UTF-8"), expected);
        assert_eq!(one_shot.substituted(), 1);
        // По одному байту за раз — тот же результат.
        let mut by_byte = StreamRewriter::new(Grammar::F0_INLINE, decrypt);
        let mut acc = Vec::new();
        for b in text.as_bytes() {
            by_byte.push(&[*b], &mut acc);
        }
        let mut tail = Vec::new();
        by_byte.finish(&mut tail);
        acc.extend_from_slice(&tail);
        assert_eq!(String::from_utf8(acc).expect("UTF-8"), expected);
    }

    /// F0-токен на произвольных срезах + битый токен проходит дословно.
    #[test]
    fn f0_token_survives_random_and_broken_splits() {
        let key = SessionKey::new([0x05; KEY_LEN]);
        let tok = VaultToken::seal_with(&key, "ИНН 7701234567".as_bytes(), MlockPolicy::BestEffort)
            .expect("seal");
        let text = format!("платёж {}", tok.to_marker());
        let bytes = text.as_bytes();
        let expected = "платёж ИНН 7701234567".to_string();
        let mk = || {
            let key = SessionKey::new([0x05; KEY_LEN]);
            StreamRewriter::new(Grammar::F0_INLINE, move |body: &[u8]| {
                decrypt_f0(&key, body)
            })
        };
        let (out, inc) = mk().run_to_end(bytes);
        assert_eq!(String::from_utf8(out).expect("UTF-8"), expected);
        assert!(!inc);
        let mut rand = Lcg(0x2545_F491_4F6C_DD1D);
        for _ in 0..200 {
            let mut cuts: Vec<usize> = (0..4)
                .map(|_| (rand.next() as usize) % bytes.len())
                .collect();
            cuts.extend([0, bytes.len()]);
            cuts.sort_unstable();
            cuts.dedup();
            let mut r = mk();
            let mut out = Vec::new();
            for w in cuts.windows(2) {
                r.push(&bytes[w[0]..w[1]], &mut out);
            }
            let _ = r.finish(&mut out);
            assert_eq!(
                String::from_utf8(out).expect("UTF-8"),
                expected,
                "срез {cuts:?} разошёлся"
            );
        }
        // Битый F0-маркер: дословно, с флагом, без паники. Портим ровно один
        // символ детерминированно: подмена «A» на «B» могла бы не попасть в
        // тег-зависимые байты, и тест стал бы флипающим.
        let mut b = text.as_bytes().to_vec();
        let last = b.len() - 3; // предпоследний символ тела, до закрывающих `]]`
        b[last] = if b[last] == b'B' { b'C' } else { b'B' };
        let broken = String::from_utf8(b).expect("маркер целиком ASCII, кроме обрамления");
        let (out, inc) = mk().run_to_end(broken.as_bytes());
        assert_eq!(String::from_utf8(out).expect("UTF-8"), broken);
        assert!(inc, "битый маркер обязан поднять флаг");
    }

    /// Budget look-ahead: F0-gram = ровно `MAX_MARKER_BYTES`, LABEL ≈ цифре 32
    /// из SPEC §8. Это тест, фиксирующий расхождение ТЗ/§8 числом.
    #[test]
    fn lookahead_budget_matches_grammar() {
        assert_eq!(Grammar::F0_INLINE.window(), token::MAX_MARKER_BYTES);
        // Окно = 5 (`[[F0#`) + 1587 (base64url худшего контейнера при потолке
        // 1024 Б, было 272 при 128 Б) + 2 (`]]`). Число пинится: потолок
        // переехал в #120, и молча разъехаться окно не должно.
        assert_eq!(Grammar::F0_INLINE.window(), 5 + 1587 + 2);
        assert_eq!(Grammar::LABEL.window(), 34);
        // Худший случай F0: тело длиной в потолок обязано распознаваться.
        let body = "A".repeat(Grammar::F0_INLINE.max_body);
        let text = format!("{}{body}{}", token::MARKER_PREFIX, token::MARKER_SUFFIX);
        let mut r = StreamRewriter::new(Grammar::F0_INLINE, |_: &[u8]| Resolution::Unknown);
        let (out, inc) = r.run_to_end(text.as_bytes());
        assert!(inc, "максимальный маркер не распознан как маркер");
        assert_eq!(
            out,
            text.as_bytes(),
            "нерезолвнутый маркер обязан пройти дословно"
        );
        assert!(
            r.cand.len() <= Grammar::F0_INLINE.window(),
            "окно раздулось"
        );
        // На байт длиннее потолка — уже не маркер, окно не растёт.
        let over = format!("{}{}}}", token::MARKER_PREFIX, "A".repeat(body.len() + 1));
        let mut r2 = StreamRewriter::new(Grammar::F0_INLINE, |_: &[u8]| Resolution::Unknown);
        let (out2, _) = r2.run_to_end(over.as_bytes());
        assert_eq!(out2, over.as_bytes());
    }

    /// Буфер кандидата ограничен сверху: гонка ложных открытий не раздувает
    /// память машины.
    #[test]
    fn candidate_buffer_stays_within_window() {
        let mut r = rewriter();
        let mut out = Vec::new();
        let junk = format!("[{}{}", "A".repeat(4096), "B".repeat(4096));
        for b in junk.as_bytes().chunks(64) {
            r.push(b, &mut out);
            assert!(r.cand.len() <= Grammar::LABEL.window());
            assert!(r.replay.len() <= Grammar::LABEL.window() * 2);
        }
        let _ = r.finish(&mut out);
        assert_eq!(out, junk.as_bytes(), "всё вернулось дословно");
    }

    /// Пустое тело (`[]`, `[[F0#]]`) подстановкой не считается.
    #[test]
    fn empty_body_is_never_a_marker() {
        let text = "[] и [[F0#]]";
        let mut r = rewriter();
        let (out, _) = r.run_to_end(text.as_bytes());
        assert_eq!(String::from_utf8(out).expect("UTF-8"), text);
        assert_eq!(r.substituted(), 0);
    }

    /// Подмена обязана возвращать ровно то, что дал резолвер, включая байты,
    /// не являющиеся UTF-8 (ответ наружу формирует вызывающий).
    #[test]
    fn resolver_output_is_passed_through_untouched() {
        let mut r = StreamRewriter::new(Grammar::LABEL, |_: &[u8]| {
            Resolution::Substitute(vec![0xF0, 0x9F, 0x98, 0x80])
        });
        let (out, inc) = r.run_to_end(b"a[X]b");
        assert_eq!(out, vec![b'a', 0xF0, 0x9F, 0x98, 0x80, b'b']);
        assert!(!inc);
    }

    /// Инварианты фазз-таргета `fuzz/fuzz_targets/f0_rewrite.rs`, измеримые в CI:
    /// на `Unknown`-резолвере произвольные байты (в том числе не-UTF-8 и приманки
    /// обеих грамматик) проходят дословно, а произвольная нарезка выдачу не меняет.
    /// Сам таргет CI не гоняет (`fuzz/README.md`), поэтому проверка живёт здесь.
    #[test]
    fn random_bytes_pass_verbatim_under_any_split() {
        let mut rand = Lcg(0x9E37_79B9_7F4A_7C15);
        for it in 0..4000 {
            let mut input: Vec<u8> = Vec::new();
            input.extend_from_slice(if it % 3 == 0 {
                b"[[F0#"
            } else if it % 3 == 1 {
                b"[CLIENT_PERSON_1]"
            } else {
                b"\xf0\x28\x8c"
            });
            let extra = 1 + (rand.next() as usize) % 48;
            for _ in 0..extra {
                input.push(rand.next() as u8);
            }
            input.extend_from_slice(b"]]");
            for g in [Grammar::LABEL, Grammar::F0_INLINE] {
                let (one, _) =
                    StreamRewriter::new(g, |_: &[u8]| Resolution::Unknown).run_to_end(&input);
                assert_eq!(one, input, "итерация {it}: реврайтер съел байты");
                let mut r = StreamRewriter::new(g, |_: &[u8]| Resolution::Unknown);
                let mut out = Vec::new();
                let mut rest = &input[..];
                while !rest.is_empty() {
                    let n = 1 + (rand.next() as usize) % rest.len();
                    let (a, b) = rest.split_at(n);
                    let _ = r.push(a, &mut out);
                    rest = b;
                }
                let _ = r.finish(&mut out);
                assert_eq!(out, one, "итерация {it}: нарезка изменила выдачу");
            }
        }
    }

    /// Второе свойство фазз-таргета: подмена тела его же байтами не раздувает
    /// выдачу (маркер длиннее тела минимум на обрамление) и не роняет автомат.
    #[test]
    fn substitution_never_grows_output() {
        let mut rand = Lcg(0xDEAD_BEEF_1234_5678);
        for it in 0..2000 {
            let mut input: Vec<u8> = Vec::new();
            let extra = 1 + (rand.next() as usize) % 64;
            for _ in 0..extra {
                input.push(rand.next() as u8);
            }
            let baits: [&[u8]; 4] = [b"[[F0#", b"[CLIENT_PERSON_1]", b"[A]]", b"[[F0#AAAA]]"];
            for (i, w) in baits.iter().enumerate() {
                if it % 4 == i {
                    input.extend_from_slice(w);
                }
            }
            for g in [Grammar::LABEL, Grammar::F0_INLINE] {
                let (out, _) = StreamRewriter::new(g, |b: &[u8]| {
                    if b.is_empty() {
                        Resolution::Unknown
                    } else {
                        Resolution::Substitute(b.to_vec())
                    }
                })
                .run_to_end(&input);
                assert!(
                    out.len() <= input.len(),
                    "итерация {it}: выдача {} длиннее входа {}",
                    out.len(),
                    input.len()
                );
            }
        }
    }
}
