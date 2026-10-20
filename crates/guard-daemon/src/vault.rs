//! Обратимое маскирование: `/v1/anonymize` и `/v1/deanonymize` (SPEC §3, §4, §8).
//!
//! # Два режима, оба из issue #56 п.3
//!
//! * [`VaultMode::Stateless`] (режим 3, дефолт): замена — аутентифицированный
//!   маркер `[[F0#base64url]]`, оригинал живёт внутри маркера. Сервер в покое
//!   хранит 0 байт пользовательских данных, `deanonymize` работает с любого
//!   перезапуска, пока задан `FASAD_VAULT_KEY`.
//! * [`VaultMode::Session`] (режим 2): замена — человекочитаемая метка
//!   `[КЛАСС_СЧЁТЧИК_NONCE]`, оригинал — в `SessionStore` с TTL SPEC §3 п.2.
//!   ФИО-спан при этом подменяется **гладким суррогатом** (SPEC §4), а не
//!   скобкой: «Ветрова Кира Саввична» вместо `[PERSON_NAME_1_9A31C2D4]`, и
//!   обратный ход держится в реестре форм этой сессии.
//!
//! # Почему метка с nonce
//!
//! `X-Session-ID` — строка, которую выбирает вызывающий: демон не имеет
//! аутентификации (мандаты клиента — SPEC §14, шаг 8). Метка вида `[INN_1]`
//! была бы приглашением: процесс, угадавший идентификатор чужой сессии,
//! подсовывает `[INN_1]` в текст и получает оригинал. Случайная 4-байтная
//! приставка на сессию делает такую подделку перебором 2³² вариантов, а
//! легитимному клиенту nonce приходит в самом ответе `anonymize`. Для
//! суррогатной формы та же защита не работает в принципе (пул имён открыт в
//! коде), поэтому обратный ход суррогатов ограничен рамками одной сессии и
//! честно задокументирован в README как свойство режима 2.
//!
//! # Что здесь fail-closed
//!
//! * Нерезолвнутый маркер (`[[F0#…]]`, которого мы не выпускали, или метка из
//!   другой сессии) = 422 и **ничего** в ответе: отдать текст с дыркой означало
//!   бы выдатьpartial-restore как полный.
//! * Хвостовой незакрытый маркер = 422: входящий текст обрезан на середине
//!   токена, а не «просто символы».
//! * Отказ `mlock` при `FASAD_MLOCK=strict`, отказ энтропии, переполненный пул
//!   буферов = 503, частичных подмен нет.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::http::StatusCode;
use guard_types::SecretString;
use guard_vault::cache::{Limits, StoreKey};
use guard_vault::{Gender, MorphTable, NameType, SpanParse};
use guard_vault::{Grammar, SessionKey, VaultEngine, VaultError, VaultToken};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{Mlock, VaultMode};
use crate::schema::Schema;

/// Потолок живых сессий в реестре: сверх — вытесняется старейшая вместе с её
/// кэшем (иначе `/v1/anonymize` был бы бесплатным способом раздвигать RSS).
const MAX_SESSIONS: usize = 256;

/// Потолок форм суррогатов на сессию: при 4 формы/ФИО это ~250 ФИО, больше
/// одному диалогу не нужно.
const MAX_FORMS_PER_SESSION: usize = 1024;

/// Длина случайной приставки метки, байт.
const NONCE_BYTES: usize = 4;

/// Ключевые слова ответа `anonymize` — операторы Presidio (`mask`/`replace`).
const OP_MASK: &str = "mask";
const OP_REPLACE: &str = "replace";

/// Один испанский фрагмент запроса `anonymize`.
///
/// Принимается дословно то, что отдал `/v1/analyze` (лишние поля игнорируются):
/// двухшаговый контракт §8 не должен требовать пересборки объекта на клиенте.
/// Байтовые координаты — канон (решение родителя по #56), символьные в запросе
/// не принимаются: они выводятся из байтовых, а не наоборот.
#[derive(Debug, Clone, Deserialize)]
pub struct SpanIn {
    /// Идентификатор класса (`entity_type` в ответе анализа).
    pub entity_type: String,
    /// Начало в байтах от начала `text`.
    pub byte_start: usize,
    /// Конец в байтах (не включительно).
    pub byte_end: usize,
}

/// Запрос `anonymize`.
#[derive(Debug, Clone, Deserialize)]
pub struct AnonymizeRequest {
    /// Исходный текст — оригиналы `ПДн`, поэтому `Zeroizing`: обнуляется при
    /// освобождении (в том числе при unwind обработчика) и не печатается в
    /// `Debug`.
    pub text: Zeroizing<String>,
    /// spans из предыдущего `/v1/analyze`.
    pub spans: Vec<SpanIn>,
}

/// Ответ `anonymize`: переписанный текст + опись подмен.
#[derive(Debug, Clone, Serialize)]
pub struct Anonymized {
    /// Текст с заменами. Оригиналов в нём нет по построению.
    pub text: String,
    /// Подмены в порядке появления в тексте.
    pub items: Vec<MaskItem>,
}

/// Одна подмена (форма `AnonymizerItem` Presidio + наши байтовые координаты).
#[derive(Debug, Clone, Serialize)]
pub struct MaskItem {
    /// Класс сущности.
    pub entity_type: String,
    /// Начало **исходного** спана в символах — те же semantics, что у
    /// `start` в `/v1/analyze` (контракт Presidio).
    pub start: usize,
    /// Конец **исходного** спана в символах.
    pub end: usize,
    /// Начало в байтах — канон (#56, решение родителя).
    pub byte_start: usize,
    /// Конец в байтах — канон.
    pub byte_end: usize,
    /// Чем заменили (метка, маркер или суррогат).
    pub replacement: String,
    /// Оператор: `mask` — токен, `replace` — гладкий суррогат.
    pub operator: &'static str,
}

/// Запрос `deanonymize`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeanonymizeRequest {
    /// Текст с маркерами/метками/суррогатами. Разворачивается в оригиналы, так
    /// что и он под `Zeroizing`.
    pub text: Zeroizing<String>,
}

/// Ответ `deanonymize`.
#[derive(Debug, Clone, Serialize)]
pub struct Deanonymized {
    /// Текст с возвращёнными оригиналами — самый чувствительный буфер демона.
    pub text: Zeroizing<String>,
    /// Сколько подмен развернуто.
    pub substituted: usize,
}

/// Отказ конвейера маскирования с готовым HTTP-отображением.
#[derive(Debug, Clone)]
pub enum VaultApiError {
    /// `spans[].entity_type` не знает схема.
    UnknownClass(String),
    /// Байтовая граница спана не совпала с границей символа или пусто.
    BadSpan {
        /// Начало.
        start: usize,
        /// Конец.
        end: usize,
    },
    /// Spans пересеклись: подмена первого сдвинула бы второй.
    OverlappingSpans,
    /// Режим 2 требует `X-Session-ID`.
    SessionRequired,
    /// Идентификатор сессии не в алфавите метки (`Grammar::LABEL` = `A-Z0-9_`).
    BadSessionId(String),
    /// Маркер распознан, но оригинал недоступен.
    Unresolved {
        /// Сколько маркеров не развернулось.
        count: usize,
    },
    /// Текст кончается незакрытым маркером: вход обрезан.
    IncompleteMarker,
    /// Оригинал спана не влезает в лимит кэша/токена.
    TooLong {
        /// Фактическая длина.
        len: usize,
        /// Лимит.
        max: usize,
    },
    /// Оригинал спана пуст: подмена на пустую строку позже выдала бы «спан есть,
    /// текста нет».
    EmptyOriginal,
    /// Хранилище отказало по причине, зависящей от сервера: `mlock` при
    /// `FASAD_MLOCK=strict`, отказ CSPRNG, переполнение пула буферов.
    Vault(VaultError),
}

impl std::fmt::Display for VaultApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownClass(c) => write!(f, "anonymize: класса {c:?} в схеме нет"),
            Self::BadSpan { start, end } => {
                write!(f, "span [{start}, {end}) не байтовая граница символов")
            }
            Self::OverlappingSpans => write!(f, "spans пересекаются"),
            Self::SessionRequired => write!(f, "режим 2 требует заголовок X-Session-ID"),
            Self::BadSessionId(s) => write!(
                f,
                "X-Session-ID {s:?}: допустимы ASCII-буквы, цифры, `.` `_` `-` и длина ≤ 64"
            ),
            Self::Unresolved { count } => write!(
                f,
                "не развернулось маркеров: {count} — отдаём отказ, а не partial-restore"
            ),
            Self::IncompleteMarker => write!(f, "текст обрывается на середине маркера"),
            Self::Vault(e) => write!(f, "хранилище: {e}"),
            Self::TooLong { len, max } => {
                write!(f, "оригинал спана {len} Б не влезает в лимит {max} Б")
            }
            Self::EmptyOriginal => write!(f, "пустой оригинал не маскируется"),
        }
    }
}

impl VaultApiError {
    /// Код причины для JSON-ответа.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownClass(_) | Self::BadSessionId(_) | Self::SessionRequired => "bad_request",
            Self::BadSpan { .. } | Self::OverlappingSpans => "bad_span",
            Self::Unresolved { .. } => "unresolved_token",
            Self::TooLong { .. } => "span_too_long",
            Self::EmptyOriginal => "empty_span",
            Self::IncompleteMarker => "incomplete_marker",
            Self::Vault(_) => "vault_error",
        }
    }

    /// Статус: клиентская ошибка → 4xx, отказ хранилища → 503 (fail-closed).
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadSessionId(_) | Self::SessionRequired => StatusCode::BAD_REQUEST,
            Self::Vault(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::UnknownClass(_)
            | Self::BadSpan { .. }
            | Self::OverlappingSpans
            | Self::Unresolved { .. }
            | Self::IncompleteMarker
            | Self::TooLong { .. }
            | Self::EmptyOriginal => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    /// Сообщение наружу. Для [`Self::Vault`] — только категория: варианты
    /// `VaultError` печатают длины и состояния пула, это безопасно, но имена
    /// внутренних модулей клиенту не нужны.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Vault(_) => "хранилище токенов отказало (fail-closed)".to_owned(),
            other => other.to_string(),
        }
    }
}

/// Причина, по которой демон не стартует с таким хранилищем.
#[derive(Debug, Clone)]
pub enum VaultStartup {
    /// `FASAD_VAULT_KEY` задан, но не является 64 hex-символами.
    BadKey(String),
    /// Системный CSPRNG отказал.
    Entropy,
}

impl std::fmt::Display for VaultStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey(len) => write!(
                f,
                "FASAD_VAULT_KEY должен быть 64 hex-символами (32 байта), получено {len:?}"
            ),
            Self::Entropy => write!(f, "системный генератор случайности отказал"),
        }
    }
}

/// Отпечаток источника ключа: сам ключ наружу не печатается никогда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `FASAD_VAULT_KEY`: обратимость переживает перезапуск.
    FromEnv,
    /// Случайный на старт: `deanonymize` работает до конца процесса.
    Ephemeral,
}

impl KeySource {
    /// Имя для стартового лога.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FromEnv => "env",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// Служебное состояние режима 2: nonce сессии, счётчик меток, формы суррогатов.
#[derive(Default)]
struct Session {
    nonce: String,
    seq: usize,
    forms: Vec<String>,
}

#[derive(Default)]
struct Registry {
    order: Vec<String>,
    sessions: HashMap<String, Box<Session>>,
}

/// Хранилище демона: движок + реестр сессий + политика залочкивания.
pub struct Vault {
    engine: VaultEngine,
    mode: VaultMode,
    mlock: Mlock,
    key_source: KeySource,
    registry: Mutex<Registry>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ключ печатается `[REDACTED]`, но и его не выводим: отпечаток режима
        // достаточен для логов.
        f.debug_struct("Vault")
            .field("mode", &self.mode)
            .field("mlock", &self.mlock)
            .field("key_source", &self.key_source)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Собрать хранилище из конфигурации процесса.
    ///
    /// Ключ: `FASAD_VAULT_KEY` (64 hex) либо свежий из CSPRNG. Временный ключ —
    /// осознанный дефолт: ключ в env читается соседями по `/proc` и попадает в
    /// дампы окружения systemd, а `deanonymize` после перезапуска с ним просто
    /// не обещается.
    ///
    /// # Errors
    ///
    /// [`VaultStartup::BadKey`] — значение переменной не hex нужной длины;
    /// [`VaultStartup::Entropy`] — CSPRNG отказал.
    pub fn startup(mode: VaultMode, mlock: Mlock) -> Result<Self, VaultStartup> {
        let (key, key_source) = match std::env::var("FASAD_VAULT_KEY") {
            Err(_) => (
                SessionKey::generate().map_err(|_| VaultStartup::Entropy)?,
                KeySource::Ephemeral,
            ),
            Ok(raw) => {
                let bytes = hex_key(&raw).ok_or_else(|| VaultStartup::BadKey(raw.clone()))?;
                (
                    SessionKey::try_from_slice(&bytes).map_err(|_| VaultStartup::BadKey(raw))?,
                    KeySource::FromEnv,
                )
            }
        };
        Ok(Self {
            engine: VaultEngine::new(key, Limits::SPEC_DEFAULT),
            mode,
            mlock,
            key_source,
            registry: Mutex::new(Registry::default()),
        })
    }

    /// Источник ключа для стартового лога.
    #[must_use]
    pub fn key_source(&self) -> KeySource {
        self.key_source
    }

    /// Режим, выставленный наружу.
    #[must_use]
    pub fn mode(&self) -> VaultMode {
        self.mode
    }

    /// Заменить spans обратимыми подменами.
    ///
    /// # Errors
    ///
    /// См. [`VaultApiError`]: чужой класс, не-граница символов, пересечение
    /// спанов, отсутствующая сессия в режиме 2, отказ хранилища.
    pub fn anonymize(
        &self,
        session: Option<&str>,
        text: &str,
        spans: &[SpanIn],
        schema: &Schema,
    ) -> Result<Anonymized, VaultApiError> {
        if self.mode == VaultMode::Session {
            self.session_slot(session)?;
        }
        let mut spans: Vec<&SpanIn> = spans.iter().collect();
        spans.sort_by_key(|s| (s.byte_start, s.byte_end));
        for pair in spans.windows(2) {
            if pair[0].byte_end > pair[1].byte_start {
                return Err(VaultApiError::OverlappingSpans);
            }
        }
        for s in &spans {
            if !schema.knows(s.entity_type.as_str()) {
                return Err(VaultApiError::UnknownClass(s.entity_type.clone()));
            }
            if s.byte_start >= s.byte_end
                || !text.is_char_boundary(s.byte_start)
                || !text.is_char_boundary(s.byte_end)
            {
                return Err(VaultApiError::BadSpan {
                    start: s.byte_start,
                    end: s.byte_end,
                });
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut items: Vec<MaskItem> = Vec::with_capacity(spans.len());
        let mut cursor = 0_usize;
        for s in &spans {
            let original = &text[s.byte_start..s.byte_end];
            let (replacement, operator) = self.substitute(session, original, &s.entity_type)?;
            items.push(MaskItem {
                entity_type: s.entity_type.clone(),
                // Символьные координаты исходного спана — те же semantics, что
                // у `/v1/analyze`; координаты в ответном тексте клиенту не нужны:
                // подмену там находит сама строка `replacement`.
                start: text[..s.byte_start].chars().count(),
                end: text[..s.byte_end].chars().count(),
                byte_start: s.byte_start,
                byte_end: s.byte_end,
                operator,
                replacement: replacement.clone(),
            });
            out.push_str(&text[cursor..s.byte_start]);
            out.push_str(&replacement);
            cursor = s.byte_end;
        }
        out.push_str(&text[cursor..]);
        Ok(Anonymized { text: out, items })
    }

    /// Развернуть подмены обратно.
    ///
    /// # Errors
    ///
    /// [`VaultApiError::Unresolved`] и [`VaultApiError::IncompleteMarker`] —
    /// частичный возврат не отдаётся никогда; [`VaultApiError::Vault`] — отказ
    /// движка.
    pub fn deanonymize(
        &self,
        session: Option<&str>,
        text: &str,
    ) -> Result<Deanonymized, VaultApiError> {
        let grammar = match self.mode {
            VaultMode::Stateless => Grammar::F0_INLINE,
            VaultMode::Session => {
                self.session_slot(session)?;
                Grammar::LABEL
            }
        };
        let outcome =
            self.engine
                .rewrite_stream(session.unwrap_or_default(), grammar, text.as_bytes());
        if outcome.unresolved > 0 {
            return Err(VaultApiError::Unresolved {
                count: outcome.unresolved,
            });
        }
        if outcome.incomplete {
            return Err(VaultApiError::IncompleteMarker);
        }
        let mut restored = String::from_utf8(outcome.bytes.clone())
            .map_err(|_| VaultApiError::Vault(VaultError::NotUtf8))?;
        let mut substituted = outcome.substituted;
        if self.mode == VaultMode::Session {
            let forms = {
                let guard = self.locked();
                guard
                    .sessions
                    .get(session.unwrap_or_default())
                    .map_or_else(Vec::new, |s| s.forms.clone())
            };
            substituted +=
                self.restore_surrogates(session.unwrap_or_default(), &mut restored, &forms);
        }
        Ok(Deanonymized {
            text: Zeroizing::new(restored),
            substituted,
        })
    }

    /// Забыть сессию целиком: кэш оригиналов, метки, формы суррогатов.
    pub fn invalidate(&self, session: &str) -> u64 {
        // moka: `iter()` (именно им идёт `invalidate_session`) видит записи
        // только после обслуживания очереди, поэтому свежую вставку без `sync`
        // мы бы «забыли» и вернули 0 удалённых при живой сессии.
        self.engine.store().sync();
        let dropped = self.engine.invalidate_session(session);
        let mut guard = self.locked();
        if guard.sessions.remove(session).is_some() && guard.order.len() <= MAX_SESSIONS + 1 {
            guard.order.retain(|s| s != session);
        }
        dropped
    }

    /// Метрики кэша для `/health`-подобной диагностики (без пользовательских
    /// данных: только счётчики).
    #[must_use]
    pub fn cache_entries(&self) -> u64 {
        self.engine.store().entry_count()
    }

    fn locked(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Проверить и зарегистрировать сессию, вернуть её nonce.
    fn session_slot(&self, session: Option<&str>) -> Result<(String, usize), VaultApiError> {
        let id = session.ok_or(VaultApiError::SessionRequired)?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(VaultApiError::BadSessionId(id.to_owned()));
        }
        let mut guard = self.locked();
        if !guard.sessions.contains_key(id) {
            if guard.order.len() >= MAX_SESSIONS {
                let doomed = guard.order.remove(0);
                guard.sessions.remove(&doomed);
                drop(guard);
                self.engine.invalidate_session(&doomed);
                guard = self.locked();
            }
            let nonce = match VaultToken::seal_with(
                self.engine.key(),
                id.as_bytes(),
                self.mlock.policy(),
            ) {
                Ok(tok) => hex_prefix(&tok.to_base64url(), NONCE_BYTES * 2),
                Err(e) => return Err(VaultApiError::Vault(e)),
            };
            guard.sessions.insert(
                id.to_owned(),
                Box::new(Session {
                    nonce,
                    seq: 0,
                    forms: Vec::new(),
                }),
            );
            guard.order.push(id.to_owned());
        }
        let s = guard
            .sessions
            .get(id)
            .ok_or(VaultApiError::SessionRequired)?;
        Ok((s.nonce.clone(), s.seq))
    }

    /// Следующая метка сессии: `{КЛАСС}_{seq}_{nonce}`.
    fn next_label(&self, session: &str, class: &str) -> Result<String, VaultApiError> {
        let mut guard = self.locked();
        let s = guard
            .sessions
            .get_mut(session)
            .ok_or(VaultApiError::SessionRequired)?;
        s.seq += 1;
        let label = format!("{}_{}_{}", class.to_ascii_uppercase(), s.seq, s.nonce);
        if label.len() > Grammar::LABEL.max_body {
            return Err(VaultApiError::TooLong {
                len: label.len(),
                max: Grammar::LABEL.max_body,
            });
        }
        Ok(label)
    }

    fn remember_form(&self, session: &str, form: &str) {
        let mut guard = self.locked();
        if let Some(s) = guard.sessions.get_mut(session) {
            if !s.forms.iter().any(|f| f == form) && s.forms.len() < MAX_FORMS_PER_SESSION {
                s.forms.push(form.to_owned());
            }
        }
    }

    /// Одна подмена: маркер, метка или суррогат — по режиму и классу.
    fn substitute(
        &self,
        session: Option<&str>,
        original: &str,
        class: &str,
    ) -> Result<(String, &'static str), VaultApiError> {
        if class == "person_name" && self.mode == VaultMode::Session {
            if let Some(srg) = self.surrogate_span(session.unwrap_or_default(), original) {
                return Ok((srg, OP_REPLACE));
            }
        }
        let sealed =
            VaultToken::seal_with(self.engine.key(), original.as_bytes(), self.mlock.policy())
                .map_err(VaultApiError::Vault)?;
        match self.mode {
            VaultMode::Stateless => Ok((sealed.to_marker(), OP_MASK)),
            VaultMode::Session => {
                // Метка: оригинал в кэше под `(session, label)`; сам токен в
                // текст не вставляем — читаемость важнее, а обратный ход есть.
                let label = self.next_label(session.unwrap_or_default(), class)?;
                self.engine
                    .store()
                    .insert(
                        &StoreKey::new(session.unwrap_or_default(), &label),
                        SecretString::new(original.to_owned()),
                    )
                    .map_err(store_err)?;
                Ok((format!("[{label}]"), OP_MASK))
            }
        }
    }

    /// Гладкая замена ФИО: пословно, с сохранением разделителей.
    ///
    /// Разбор даёт сам спан, а не слово: `parse_span` — единственный API,
    /// который из многословного ФИО вынимает согласованные род и падеж
    /// (по одному слову таблица даёт «Кира» как Nom|Gen|Acc, и любой наш выбор
    /// падежа был бы догадкой). Позиция токена в спане даёт тип: `lemmas`
    /// возвращаются в порядке [`NameType::ORDER`] (Фамилия Имя Отчество), и мы
    /// сопоставляем их с токенами по позиции.
    ///
    /// `None` — и вызывающий откатывается на метку — в трёх случаях: разбор
    /// неоднозначен или не найден, род пришлось бы угадывать, чисел токенов не
    /// совпало с числом лемм.
    fn surrogate_span(&self, session: &str, original: &str) -> Option<String> {
        let table = MorphTable::shipped()?;
        let (lemmas, case, gender) = match table.parse_span(original) {
            SpanParse::Unique {
                lemmas,
                case,
                gender,
            } => (lemmas, case, gender),
            SpanParse::LemmaUnique {
                lemmas,
                case,
                genders,
            } => {
                // Род не сошёлся: колонка `genders` у именных правил `f,m`,
                // и док модуля прямо отсылает шаг 6 проверять род по маске.
                // Маску даёт окончание первого токена — оно же флагман рода.
                let first = original.split_whitespace().next()?;
                let g = suffix_gender(first)?;
                if !genders.contains(&g) {
                    return None;
                }
                (lemmas, case, g)
            }
            SpanParse::Ambiguous(_) | SpanParse::NoMatch(_) => return None,
        };
        let tokens: Vec<&str> = original.split_whitespace().collect();
        if tokens.len() != lemmas.len() || tokens.len() > NameType::ORDER.len() {
            return None;
        }
        let mut out = String::with_capacity(original.len());
        let mut word = String::new();
        let mut forms: Vec<String> = Vec::new();
        let mut idx = 0_usize;
        for c in original.chars() {
            if c.is_alphabetic() {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                let srg = self.engine.surrogat_for_gender(
                    session,
                    &word,
                    case,
                    gender,
                    NameType::ORDER[idx],
                )?;
                forms.push(srg.form.clone());
                word.clear();
                out.push_str(&srg.form);
            }
            out.push(c);
            if c.is_whitespace() {
                idx += 1;
            }
        }
        if !word.is_empty() {
            let srg = self.engine.surrogat_for_gender(
                session,
                &word,
                case,
                gender,
                NameType::ORDER[idx],
            )?;
            forms.push(srg.form.clone());
            out.push_str(&srg.form);
        }
        if forms.len() != tokens.len() {
            return None;
        }
        for f in forms {
            self.remember_form(session, &f);
        }
        Some(out)
    }

    /// Обратный ход суррогатов: подставляем оригиналы по зарегистрированным
    /// формам, длинные имена раньше коротких (`Ветрова` ⊂ `Ветровой` не мешает).
    fn restore_surrogates(&self, session: &str, text: &mut String, forms: &[String]) -> usize {
        let mut n = 0_usize;
        let mut sorted: Vec<&String> = forms.iter().collect();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.len()));
        for form in sorted {
            let Some(orig) = self.engine.original_of_surrogat(session, form) else {
                continue;
            };
            if text.contains(form.as_str()) {
                *text = text.replace(form.as_str(), orig.as_str());
                n += 1;
            }
        }
        n
    }
}

/// Отпечаток маркера как hex-строка (первые `len` символов base64url,
/// приведённые к верхнему регистру алфавита метки).
fn hex_prefix(b64: &str, len: usize) -> String {
    b64.chars()
        .filter(char::is_ascii_alphanumeric)
        .take(len)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Род по окончанию — единственный источник рода для гладкой подмены.
///
/// Порядок проверок выбран так, чтобы ложный род был невозможен: сначала
/// отчества (`-ич`/`-евна`), потом женские фамильные и именные окончания, потом
/// мужские. Всё, что не подпало ни под одну ветку (несклоняемые «Шварценеггер»,
/// «Гете», имя «Александр» без суффиксного признака), возвращает `None` — и
/// спан уходит в метку, а не в угаданное имя.
#[must_use]
fn suffix_gender(word: &str) -> Option<Gender> {
    let w = word.trim_end_matches(['.', ',', ')', '»']).to_lowercase();
    let s = w.as_str();
    if s.ends_with("ич") || s.ends_with("уевич") || s.ends_with("ович") {
        return Some(Gender::Masc);
    }
    if s.ends_with("ична") || s.ends_with("евна") || s.ends_with("вна") || s.ends_with("чна")
    {
        return Some(Gender::Fem);
    }
    if s.ends_with("ова")
        || s.ends_with("ёва")
        || s.ends_with("ева")
        || s.ends_with("ина")
        || s.ends_with("ына")
        || s.ends_with("ская")
        || s.ends_with("цкая")
        || s.ends_with("али")
    {
        return Some(Gender::Fem);
    }
    // «Иванова» и «Кира»: женское окончание -а/-я после согласной.
    if s.ends_with('а') || s.ends_with('я') {
        return Some(Gender::Fem);
    }
    if s.ends_with('й')
        || s.ends_with("ь")
        || s.chars()
            .last()
            .is_some_and(|c| c.is_ascii() && c.is_ascii_alphabetic())
    {
        return Some(Gender::Masc);
    }
    None
}

/// 64 hex-символа → 32 байта; любое другое значение = `None`.
fn hex_key(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// [`StoreError`] в отказ API: обе ветки — про данные спана, не про сервер.
fn store_err(e: guard_vault::StoreError) -> VaultApiError {
    match e {
        guard_vault::StoreError::TooBig { len, max } => VaultApiError::TooLong { len, max },
        guard_vault::StoreError::Empty => VaultApiError::EmptyOriginal,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    fn vault(mode: VaultMode) -> Vault {
        Vault {
            engine: VaultEngine::new(
                SessionKey::new([0x5a; 32]),
                Limits::for_test(
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(600),
                ),
            ),
            mode,
            mlock: Mlock::BestEffort,
            key_source: KeySource::Ephemeral,
            registry: Mutex::new(Registry::default()),
        }
    }

    fn schema() -> Schema {
        Schema::embedded().expect("канон валиден")
    }

    fn span(class: &str, text: &str, needle: &str) -> SpanIn {
        let start = text.find(needle).expect("подстрока есть в тестовом входе");
        SpanIn {
            entity_type: class.to_owned(),
            byte_start: start,
            byte_end: start + needle.len(),
        }
    }

    #[test]
    fn hex_key_accepts_only_64_hex() {
        assert!(hex_key(&"aa".repeat(32)).is_some());
        assert!(hex_key(&"aa".repeat(31)).is_none());
        assert!(hex_key(&"zz".repeat(32)).is_none());
        assert!(hex_key("").is_none());
    }

    #[test]
    fn stateless_mode_emits_f0_markers_and_restores_them() {
        let v = vault(VaultMode::Stateless);
        let text = "Иванов Пётр Сергеевич, ИНН 2482014338";
        let spans = vec![
            span("person_name", text, "Иванов Пётр Сергеевич"),
            span("inn", text, "2482014338"),
        ];
        let anon = v
            .anonymize(None, text, &spans, &schema())
            .expect("анонимизация");
        assert!(
            !anon.text.contains("2482014338"),
            "оригинал протёк: {}",
            anon.text
        );
        assert!(
            !anon.text.contains("Иванов"),
            "оригинал протёк: {}",
            anon.text
        );
        assert_eq!(anon.items.len(), 2);
        assert!(anon.items.iter().all(|i| i.operator == OP_MASK));
        let back = v.deanonymize(None, &anon.text).expect("обратный ход");
        assert_eq!(back.text.as_str(), text);
        assert_eq!(back.substituted, 2);
    }

    #[test]
    fn session_mode_uses_labels_and_surrogates() {
        let v = vault(VaultMode::Session);
        let text = "Ушакова Кира Саввична, ИНН 2482014338";
        let spans = vec![
            span("person_name", text, "Ушакова Кира Саввична"),
            span("inn", text, "2482014338"),
        ];
        let anon = v
            .anonymize(Some("s1"), text, &spans, &schema())
            .expect("анонимизация");
        let names: Vec<&str> = anon
            .items
            .iter()
            .map(|i| i.operator)
            .filter(|op| *op == OP_REPLACE)
            .collect();
        assert_eq!(
            names.len(),
            1,
            "ФИО должно стать суррогатом: {:?}",
            anon.items
        );
        assert!(
            !anon.text.contains("Ушакова"),
            "оригинал ФИО протёк: {}",
            anon.text
        );
        assert!(
            anon.text.contains("ИНН [INN_"),
            "нет метки класса: {}",
            anon.text
        );
        let back = v.deanonymize(Some("s1"), &anon.text).expect("обратный ход");
        assert_eq!(back.text.as_str(), text, "суррогат + метка не развернулись");
    }

    #[test]
    fn forged_label_is_not_resolved_across_sessions() {
        let v = vault(VaultMode::Session);
        let text = "ИНН 2482014338";
        let anon = v
            .anonymize(
                Some("victim"),
                text,
                &[span("inn", text, "2482014338")],
                &schema(),
            )
            .expect("анонимизация");
        let leaked = format!("[INN_1_{}]", "0".repeat(NONCE_BYTES * 2));
        assert_ne!(anon.text, leaked, "метка стала предсказуемой");
        let err = v
            .deanonymize(Some("attacker"), &leaked)
            .expect_err("чужой предсказуемой метки разворачиваться не должно");
        assert!(
            matches!(err, VaultApiError::Unresolved { count: 1 }),
            "{err:?}"
        );
    }

    #[test]
    fn unresolved_f0_marker_is_422_and_no_partial_text() {
        let v = vault(VaultMode::Stateless);
        let err = v
            .deanonymize(None, "хвост [[F0#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]]")
            .expect_err("чужой маркер не разворачивается");
        assert!(
            matches!(err, VaultApiError::Unresolved { count: 1 }),
            "{err:?}"
        );
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err.code(), "unresolved_token");
        assert!(
            !err.message().contains("F0#"),
            "в сообщении нет фрагмента токена"
        );
    }

    #[test]
    fn truncated_marker_is_refused_as_incomplete() {
        let v = vault(VaultMode::Stateless);
        let text = "ИНН 2482014338";
        let anon = v
            .anonymize(None, text, &[span("inn", text, "2482014338")], &schema())
            .expect("анонимизация");
        let cut = anon.text.chars().take(12).collect::<String>();
        let err = v.deanonymize(None, &cut).expect_err("обрезанный маркер");
        assert!(
            matches!(
                err,
                VaultApiError::IncompleteMarker | VaultApiError::Unresolved { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn spans_are_validated_before_any_substitution() {
        let v = vault(VaultMode::Stateless);
        let text = "ИНН 2482014338";
        let s = span("inn", text, "2482014338");
        // Граница в середине символа: байт 1 — середина «И».
        let bad = SpanIn {
            byte_start: 1,
            byte_end: 5,
            ..s.clone()
        };
        let err = v
            .anonymize(None, text, &[bad], &schema())
            .expect_err("не граница");
        assert!(matches!(err, VaultApiError::BadSpan { .. }), "{err:?}");
        let err = v
            .anonymize(
                None,
                text,
                &[SpanIn {
                    entity_type: "snisl".to_owned(),
                    ..s.clone()
                }],
                &schema(),
            )
            .expect_err("-opечатка класса");
        assert!(
            matches!(err, VaultApiError::UnknownClass(ref c) if c == "snisl"),
            "{err:?}"
        );
        let err = v
            .anonymize(None, text, &[s.clone(), s.clone()], &schema())
            .expect_err("пересечение");
        assert!(matches!(err, VaultApiError::OverlappingSpans), "{err:?}");
    }

    #[test]
    fn session_mode_requires_a_session_id_and_validates_alphabet() {
        let v = vault(VaultMode::Session);
        let text = "ИНН 2482014338";
        let err = v
            .anonymize(None, text, &[span("inn", text, "2482014338")], &schema())
            .expect_err("режим 2 без сессии");
        assert!(matches!(err, VaultApiError::SessionRequired), "{err:?}");
        let err = v
            .anonymize(
                Some("сесси"),
                text,
                &[span("inn", text, "2482014338")],
                &schema(),
            )
            .expect_err("нелатинская сессия");
        assert!(matches!(err, VaultApiError::BadSessionId(_)), "{err:?}");
    }

    #[test]
    fn offsets_are_input_coordinates_not_output_ones() {
        // Два спана, и второй за первым: только так тест различает «координаты
        // в тексте запроса» и «координаты в ответе» — после первой подмены они
        // расходятся на длину маркера (~100 символов).
        let v = vault(VaultMode::Stateless);
        let text = "Иван ИНН 2482014338 оплатил, СНИЛС 657-077-154 21 выдан";
        let spans = [
            span("inn", text, "2482014338"),
            span("snils", text, "657-077-154 21"),
        ];
        let anon = v
            .anonymize(None, text, &spans, &schema())
            .expect("анонимизация");
        // Первичка: байты и символы сняты с `text`, а не вычислены кодом теста.
        assert_eq!((anon.items[0].byte_start, anon.items[0].byte_end), (16, 26));
        assert_eq!((anon.items[0].start, anon.items[0].end), (9, 19));
        assert_eq!((anon.items[1].byte_start, anon.items[1].byte_end), (54, 68));
        assert_eq!((anon.items[1].start, anon.items[1].end), (35, 49));
        assert!(
            anon.items[1].start < anon.items[0].end + 30,
            "координаты съехали в ответ: {}",
            anon.items[1].start
        );
        for (item, needle) in spans.iter().zip(["2482014338", "657-077-154 21"]) {
            let slice = &text.as_bytes()[item.byte_start..item.byte_end];
            assert_eq!(
                std::str::from_utf8(slice).expect("граница символов"),
                needle
            );
        }
    }

    #[test]
    fn invalidate_session_forgets_labels_and_surrogates() {
        let v = vault(VaultMode::Session);
        let text = "Ушакова Кира Саввична";
        let spans = vec![span("person_name", text, text)];
        let anon = v
            .anonymize(Some("s2"), text, &spans, &schema())
            .expect("анонимизация");
        // Три токена ФИО = три регистрации `SRG#<форма>` в кэше (промерено, не
        // угадано): teardown обязан снять все три.
        assert_eq!(v.invalidate("s2"), 3, "по одной метке на токен ФИО");
        // После teardown суррогаты проходят дословно: форма пула может встретиться
        // в тексте и сама по себе, а ошибаться на неё = врать про чужой вход.
        // Оригиналов это не открывает — кэш пуст, `substituted` = 0.
        let back = v
            .deanonymize(Some("s2"), &anon.text)
            .expect("не ошибка: чужая форма не является сломанным маркером");
        assert_eq!(back.substituted, 0);
        assert_eq!(back.text.as_str(), anon.text);
        assert!(!back.text.contains("Ушакова"), "протекло после teardown");
    }

    #[test]
    fn empty_span_list_returns_text_unchanged() {
        let v = vault(VaultMode::Stateless);
        let anon = v
            .anonymize(None, "ничего secrets", &[], &schema())
            .expect("пусто");
        assert_eq!(anon.text, "ничего secrets");
        assert!(anon.items.is_empty());
    }
}
