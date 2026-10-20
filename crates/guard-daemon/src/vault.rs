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
//! коде), поэтому обратный ход суррогатов ограничен рамками одной сессии.
//!
//! Раньше здесь стояло «и честно задокументирован в README как свойство режима
//! 2» — это была ложь: до правки B2/P8 второй оригинал молча перезаписывал
//! чужой слот (`let _ = store.insert(…)`), и `deanonymize` возвращал чужое имя
//! с `200 OK`. Слот по-прежнему закреплён за первичным писателем (движок), но
//! с шага 7а (#60) занятый слот больше не отказ запроса: имя уходит на
//! типизированную метку `[PERSON_NAME_n_nonce]` — она точна, не имеет коллизий
//! и обратима, а `422` ломал бы весь документ ради косметики. Пул расширен с
//! 4 до 128 лемм на корзину (промер: пар, упёршихся в отказ, 62.1 % → 1.7 % на
//! golden-v1), так что метка теперь редкость; счётчик [`Vault::
//! surrogate_fallbacks`] делает её видимой. Профиль риска — README §«Хранилище»,
//! п. 6.
//!
//! # Что здесь fail-closed
//!
//! * Нерезолвнутый маркер (`[[F0#…]]`, которого мы не выпускали, или метка из
//!   другой сессии) = 422 и **ничего** в ответе: отдать текст с дыркой означало
//!   бы выдать partial-restore как полный.
//! * Хвостовой незакрытый маркер = 422: входящий текст обрезан на середине
//!   токена, а не «просто символы».
//! * Отказ `mlock` при `FASAD_MLOCK=strict`, отказ энтропии, переполненный пул
//!   буферов = 503, частичных подмен нет.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::http::StatusCode;
use guard_types::SecretString;
use guard_vault::cache::{Limits, StoreKey};
use guard_vault::{Case, Gender, MorphTable, NameType, Restore, SpanParse, Surrogat};
use guard_vault::{Grammar, SessionKey, VaultEngine, VaultError, VaultStream, VaultToken};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{MAX_FORMS_PER_SESSION, Mlock, VaultMode};
use crate::schema::Schema;

/// Формы суррогатов, отложенные до конца запроса.
///
/// Счётчик ведётся на ходу (`push` до вставки), чтобы запрос, который заведомо
/// не влезает, не выделял бесконечный `Vec`: отказ наступает на первом лишнем
/// слове, а не после buffers на мегабайт тела. Дедупликация внутри запроса —
/// бесплатная и точная; относительно уже сохранённых форм она делается в
/// [`Vault::commit_forms`], поэтому оценка в `push` консервативна (может
/// отказать на строку раньше, чем кончится место, — в сторону отказа).
struct PendingForms {
    /// Уже сохранённые формы сессии на момент начала запроса.
    base: usize,
    /// Новые формы запроса: `(форма, поверхность токена-оригинала)`.
    /// Дедуплицированы внутри запроса, но владелец у формы тоже проверяется —
    /// см. [`PendingForms::push`] (B2/P8, пред-проверка до обращения к движку).
    items: Vec<(String, String)>,
}

impl PendingForms {
    fn new(base: usize) -> Self {
        Self {
            base,
            items: Vec::new(),
        }
    }

    /// Зарезервировать место под форму и положить её в пачку.
    ///
    /// `owner` — поверхность токена, из которого форма получена. Форма,
    /// повторно появившаяся в этом же запросе от ДРУГОГО токена, — это коллизия
    /// двух оригиналов в одном слоте: отказываем здесь, не доходя до движка,
    /// чтобы запрос «всё или ничего» не оставил в кэше движка записей от
    /// заведомо отвергнутого спана (B2/P8).
    fn push(&mut self, form: String, owner: &str) -> Result<Reserved, VaultApiError> {
        if let Some((_, prev)) = self.items.iter().find(|(f, _)| f == &form) {
            if prev != owner {
                return Ok(Reserved::TakenByOther);
            }
            return Ok(Reserved::SameOwner);
        }
        if self.base + self.items.len() >= MAX_FORMS_PER_SESSION {
            return Err(VaultApiError::TooManyForms {
                max: MAX_FORMS_PER_SESSION,
            });
        }
        self.items.push((form, owner.to_owned()));
        Ok(Reserved::Fresh)
    }
}

/// Потолок живых сессий в реестре: сверх — вытесняется старейшая вместе с её
/// кэшем (иначе `/v1/anonymize` был бы бесплатным способом раздвигать RSS).
const MAX_SESSIONS: usize = 256;

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
    /// Сколько суррогатных форм отвернуто при развороте (запись расходится со
    /// свидетельством выдачи, #60 п.3): в тексте остаются суррогаты, и клиент
    /// обязан видеть это числом (R7 ревью #70).
    pub restore_refused: usize,
}

/// Текст ответа, развёрнутый «мягко» (прокси, шаг 7c).
///
/// Отличие от [`Deanonymized`] — два счётчика деградации вместо отказа: нерезолвленный
/// маркер и незакрытый на хвосте маркер не валят ответ модели, но обязаны быть
/// видны вызывающему (и наружу, в `X-Guard-Unresolved`).
pub struct Restored {
    /// Текст с возвращёнными оригиналами (нерезолвленные маркеры — дословно).
    pub text: Zeroizing<String>,
    /// Сколько подмен развернуто.
    pub substituted: usize,
    /// Сколько маркеров прошло дословно: чужой/повреждённый токен или метка
    /// из другой сессии.
    pub unresolved: usize,
    /// На хвосте остался незакрытый маркер (поток оборван на середине метки).
    pub incomplete: bool,
    /// Сколько суррогатных форм отвернуто при развороте: их запись расходится со
    /// свидетельством выдачи (#60 п.3). Наружу — тем же числом, что и маркеры
    /// (заголовок `X-Guard-Unresolved`), молчать об этом нельзя (R7 ревью #70).
    pub restore_refused: usize,
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
    /// Форм суррогатов больше `MAX_FORMS_PER_SESSION`: отказ до первой подмены.
    TooManyForms {
        /// Потолок.
        max: usize,
    },
    /// Сессию вытеснили (FIFO по `MAX_SESSIONS`) между созданием слота и
    /// коммитом форм — гонка двух запросов, а не ошибка клиента в данных.
    SessionGone,
    /// Текст спана — уже замазанное нашим же механизмом: метка или текущий
    /// суррогат. Повторная анонимизация уничтожает раннюю связь (промер P6,
    /// и в режиме 3 — тоже), поэтому отказ, а не мутация.
    ReanonymizeSurrogate {
        /// Класс спана, на котором произошёл отказ.
        class: String,
    },
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
            Self::TooManyForms { max } => write!(
                f,
                "форм суррогатов больше {max}: отказ до первой подмены, а не partial-restore"
            ),
            Self::SessionGone => write!(f, "сессия вытеснена во время запроса"),
            Self::ReanonymizeSurrogate { class } => write!(
                f,
                "спан класса {class:?} — уже замазанный нашим же механизмом текст \
                 (метка или суррогат); повторная анонимизация запрещена"
            ),
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
            Self::TooManyForms { .. } => "too_many_forms",
            Self::SessionGone => "session_gone",
            Self::ReanonymizeSurrogate { .. } => "reanonymize_surrogate",
            Self::IncompleteMarker => "incomplete_marker",
            Self::Vault(_) => "vault_error",
        }
    }

    /// Статус: клиентская ошибка → 4xx, отказ хранилища → 503 (fail-closed).
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadSessionId(_) | Self::SessionRequired | Self::SessionGone => {
                StatusCode::BAD_REQUEST
            }
            Self::Vault(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::UnknownClass(_)
            | Self::BadSpan { .. }
            | Self::OverlappingSpans
            | Self::Unresolved { .. }
            | Self::IncompleteMarker
            | Self::TooLong { .. }
            | Self::TooManyForms { .. }
            | Self::ReanonymizeSurrogate { .. }
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
    /// Счётчик откатов суррогата на метку (#60): сколько имён не получили
    /// гладкую подмену из-за занятого слота. Деградация обязана быть видимой,
    /// а не тихой.
    surrogate_fallbacks: AtomicU64,
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
            surrogate_fallbacks: AtomicU64::new(0),
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
    /// спанов, отсутствующая сессия в режиме 2, повторная анонимизация своего
    /// же выхода, коллизия суррогатного слота, отказ хранилища.
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

        // P6: вход, равный нашей же подмене этой сессии, принимается отказом до
        // любой мутации. Причина не в гигиене протокола, а в ключах хранилища:
        // реверс-индекс `guard-vault` ищет оригинал по суррогату
        // (`StoreKey::new(session, "srg:" + form)`, lib.rs:300-303), поэтому
        // анонимизация собственного суррогата перезатирать будет уже не связь
        // «метка → оригинал», а связь «суррогат → оригинал» раннего прохода —
        // и `deanonymize` вернёт смесь чужой фамилии с настоящими именем и
        // отчеством как настоящие данные. Проверка по любому классу, не только
        // по `person_name`: класс дефекта — ключ хранилища, а не тип ПДн.
        for s in &spans {
            let piece = &text[s.byte_start..s.byte_end];
            // Грамматику проверяем в обоих режимах: `[[F0#…]]` из режима 3 —
            // тот же класс порчи, что и метка режима 2, только без сессии, за
            // которую можно зацепиться.
            if Self::has_marker(piece)
                || (self.mode == VaultMode::Session
                    && self.is_current_surrogate(session.unwrap_or_default(), piece))
            {
                return Err(VaultApiError::ReanonymizeSurrogate {
                    class: s.entity_type.clone(),
                });
            }
        }

        // Формы коммитятся пачкой после успешного прохода: до первой подмены
        // мутаций нет, значит `TooManyForms` — отказ всего запроса, а не
        // «одни имена запомнили, другие нет».
        let mut pending = PendingForms::new(self.forms_len(session));
        let mut out = String::with_capacity(text.len());
        let mut items: Vec<MaskItem> = Vec::with_capacity(spans.len());
        let mut cursor = 0_usize;
        for s in &spans {
            let original = &text[s.byte_start..s.byte_end];
            let (replacement, operator) =
                self.substitute(session, original, &s.entity_type, &mut pending)?;
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
        self.commit_forms(session, &pending)?;
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
        let (grammar, slot) = self.grammar_slot(session)?;
        let outcome = self.engine.rewrite_stream(&slot, grammar, text.as_bytes());
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
        let mut restore_refused = 0_usize;
        if self.mode == VaultMode::Session {
            let forms = {
                let guard = self.locked();
                guard
                    .sessions
                    .get(session.unwrap_or_default())
                    .map_or_else(Vec::new, |s| s.forms.clone())
            };
            let (n, refused) =
                self.restore_surrogates(session.unwrap_or_default(), &mut restored, &forms);
            substituted += n;
            restore_refused = refused;
        }
        Ok(Deanonymized {
            text: Zeroizing::new(restored),
            substituted,
            restore_refused,
        })
    }

    /// Формы суррогатов сессии (снимок под залоченным мьютексом).
    ///
    /// Вынесено из [`Self::deanonymize`] без изменения смысла: потоковый путь
    /// прокси (шаг 7c) обязан доставать тот же список, что и не-потоковый, иначе
    /// два канала начнут разно-восстанавливать ФИО.
    fn session_forms(&self, session: &str) -> Vec<String> {
        let guard = self.locked();
        guard
            .sessions
            .get(session)
            .map_or_else(Vec::new, |s| s.forms.clone())
    }

    /// Разворот для прокси: нерезолвленный маркер **не** валит ответ.
    ///
    /// [`Self::deanonymize`] отказывает на `Unresolved`/`IncompleteMarker`, и для
    /// `/v1/deanonymize` это правильно: клиент просит развернуть ровно то, что мы
    /// выдали. Прокси стоит между клиентом и LLM, и ответ модели важнее косметики
    /// разворота: тот же рулинг, что у отката суррогата на метку (#62,reviewer
    /// R3) — деградация наружу с числом, а не отказ whole-документа. Метка — не
    /// `ПДн`, поэтому пропуск маркера не утечка; но он обязан быть сочтён и
    /// показан заголовком `X-Guard-Unresolved`, иначе это ложь о причине
    /// (AGENTS §Инженерные инварианты, fail-closed в диагностике).
    ///
    /// Режим 2 дополнительно разворачивает суррогатные формы: для этого метода
    /// текст обязан быть целым (потоковый путь держит слово-границу сам, см.
    /// [`crate::sse`]).
    ///
    /// # Errors
    ///
    /// [`VaultApiError::BadRequest`] — режим 2 без заголовка сессии;
    /// [`VaultApiError::Vault`] — хранилище отказало (`NotUtf8` на развороте).
    pub fn deanonymize_soft(
        &self,
        session: Option<&str>,
        text: &str,
    ) -> Result<Restored, VaultApiError> {
        let (grammar, slot) = self.grammar_slot(session)?;
        let outcome = self.engine.rewrite_stream(&slot, grammar, text.as_bytes());
        let mut restored = String::from_utf8(outcome.bytes.clone())
            .map_err(|_| VaultApiError::Vault(VaultError::NotUtf8))?;
        let mut substituted = outcome.substituted;
        let mut restore_refused = 0_usize;
        if self.mode == VaultMode::Session {
            let forms = self.session_forms(session.unwrap_or_default());
            let (n, refused) =
                self.restore_surrogates(session.unwrap_or_default(), &mut restored, &forms);
            substituted += n;
            restore_refused = refused;
        }
        Ok(Restored {
            text: Zeroizing::new(restored),
            substituted,
            unresolved: outcome.unresolved,
            incomplete: outcome.incomplete,
            restore_refused,
        })
    }

    /// Потоковая машина разворота для SSE-релая (шаг 7c, SPEC §8).
    ///
    /// Грамматика выбирается по режиму хранилища — та же ветка, что у
    /// [`Self::deanonymize`], потому что две grammar-таблицы в одном файле
    /// расходятся неизбежно. Суррогатные формы этот объект НЕ разворачивает: он
    /// оперирует маркерами; слова восстанавливает вызывающий на границе слова
    /// ([`Self::restore_surrogates_soft`]).
    ///
    /// # Errors
    ///
    /// [`VaultApiError::BadRequest`] — режим 2 без заголовка сессии: без слота
    /// разворачивать нечем.
    pub fn stream(&self, session: Option<&str>) -> Result<VaultStream<'_>, VaultApiError> {
        let (grammar, slot) = self.grammar_slot(session)?;
        Ok(self.engine.stream(slot, grammar))
    }

    /// Одна ветка «режим → грамматика + слот» на весь файл.
    ///
    /// Возвращает ключ кэша, под которым лежат оригиналы: в режиме 3 сессии нет,
    /// и движок использует пустой слот (тот же `unwrap_or_default`, что и
    /// не-потоковый путь).
    fn grammar_slot(&self, session: Option<&str>) -> Result<(Grammar, String), VaultApiError> {
        match self.mode {
            VaultMode::Stateless => Ok((Grammar::F0_INLINE, String::new())),
            VaultMode::Session => {
                // Слот кэша — имя сессии из заголовка, а НЕ nonce: [`Self::session_slot`]
                // возвращает `(nonce, seq)`, и путаница этих двух стоит ровно «маркер
                // не развернулся» (промер: 6 тестов этого файла).
                self.session_slot(session)?;
                Ok((Grammar::LABEL, session.unwrap_or_default().to_owned()))
            }
        }
    }

    /// Разворот суррогатных форм на отрезке текста, ограниченном словами.
    ///
    /// Возвращает число восстановленных имён. Вызывать только на отрезке, который
    /// начинается и кончается границей слова: форма — один токен, и разрезанная
    /// посередине форма не восстановится никогда (см. `sse::Relay`, удержание
    /// хвоста слова).
    pub fn restore_surrogates_soft(&self, session: &str, text: &mut String) -> (usize, usize) {
        let forms = self.session_forms(session);
        self.restore_surrogates(session, text, &forms)
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

    /// Сколько ФИО за жизнь процесса ушло на метку вместо суррогата из-за занятого
    /// слота пула (#60). Метрика деградации: растёт — значит пул мал для профиля
    /// имён в этом документе, а не что демон сломался.
    #[must_use]
    pub fn surrogate_fallbacks(&self) -> u64 {
        self.surrogate_fallbacks.load(Ordering::Relaxed)
    }

    /// Сколько разворотов суррогата отказало, потому что форма в кэше указывает
    /// не на тот оригинал, что мы в неё подставляли (#60 п.3, метрика
    /// restoration-integrity).
    ///
    /// Растёт ровно в двух случаях: (1) в кэш под этим ключом написала запись не
    /// наш движок (ручная правка хранилища, регресс, будущий второй писатель), и
    /// (2) отказ на выдаче перестал работать, и чужая форма заняла занятый слот.
    /// Само по себе снятие записи (`idle`, evict, teardown) счётчика НЕ двигает:
    /// перенятый слот ловится на выдаче, и до разворота не доходит.
    ///
    /// Считает ПОПЫТКИ разворота, а не инциденты: два `deanonymize` одного и того
    /// же текста с расходящейся формой дадут +2. Ноль обязателен на любой чистой
    /// работе; ненулевой — сигнал, что писатель в кэше не один.
    ///
    /// В режиме 3 (`stateless`) счётчик нулевой по конструкции: там оригинал
    /// зашифрован внутри самого маркера, перенять нечего.
    #[must_use]
    pub fn unrestored_mismatch(&self) -> u64 {
        self.engine.restoration_mismatches()
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

    /// Текущий ли это выход демона для этой сессии: метка режима 2 по грамматике
    /// или суррогатное слово, которое хранилище знает как подмену.
    ///
    /// Ложный отказ возможен: настоящая фамилия клиента может совпасть с нашим
    /// суррогатом из этой же сессии. Отказ здесь дороже точности, чем тихая
    /// подмена данных, — см. комментарий в `anonymize`.
    fn is_current_surrogate(&self, session: &str, piece: &str) -> bool {
        // Маркер здесь уже проверен вызывающим (`has_marker`), остаются слова,
        // которые хранилище знает как подмену.
        // Ключ реверс-индекса — словоформа, а не ФИО целиком: «Тенина Агафья
        // Афанасьевна» целиком формой не является, но её первое слово является,
        // и перезатирание начинается именно с него.
        if self.engine.original_of_surrogat(session, piece).is_some() {
            return true;
        }
        piece
            .split_whitespace()
            .any(|w| self.engine.original_of_surrogat(session, w).is_some())
    }

    /// Содержит ли спан нашу же подмену маркерной грамматики: метку режима 2
    /// (`[КЛАСС_СЧЁТЧИК_NONCE]`, алфавит `Grammar::LABEL` = `A-Z0-9_`) или
    /// токен режима 3 (`[[F0#base64url]]`).
    ///
    /// Именно «содержит», а не «равна»: запрос замазать `ИНН [INN_1_X]` — это
    /// метка-в-метке, тот же класс порчи, что и суррогат-в-суррогате, и приходит
    /// он целиком как один спан. Для режима 3 промер той же пары раундов даёт
    /// `deanonymize` с `substituted: 1` и живым `[[F0#…]]` внутри «восстановленного»
    /// текста — тихий partial-restore, который мы не отдаём ни при какой ошибке.
    fn has_marker(piece: &str) -> bool {
        piece.contains("[[F0#")
            || piece.split('[').skip(1).any(|rest| {
                rest.split(']').next().is_some_and(|inner| {
                    !inner.is_empty() && inner.chars().all(Self::is_label_char)
                })
            })
    }

    fn is_label_char(c: char) -> bool {
        c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
    }

    /// Сколько форм уже лежит в сессии (0 вне режима 2).
    fn forms_len(&self, session: Option<&str>) -> usize {
        if self.mode != VaultMode::Session {
            return 0;
        }
        let guard = self.locked();
        guard
            .sessions
            .get(session.unwrap_or_default())
            .map_or(0, |s| s.forms.len())
    }

    /// Коммит форм одной критической секцией: либо все, либо ни одной.
    ///
    /// Проверка потолка здесь, а не только в [`PendingForms::push`], потому что
    /// между проходом по спанам и коммитом другой запрос мог вырастить сессию:
    /// молча выкинуть лишнее = тот самый fail-open, от которого мы ушли.
    fn commit_forms(
        &self,
        session: Option<&str>,
        pending: &PendingForms,
    ) -> Result<(), VaultApiError> {
        if pending.items.is_empty() {
            return Ok(());
        }
        let mut guard = self.locked();
        let Some(s) = guard.sessions.get_mut(session.unwrap_or_default()) else {
            return Err(VaultApiError::SessionGone);
        };
        let fresh: Vec<String> = pending
            .items
            .iter()
            .filter(|(f, _)| !s.forms.iter().any(|e| e == f))
            .map(|(f, _)| f.clone())
            .collect();
        if s.forms.len() + fresh.len() > MAX_FORMS_PER_SESSION {
            return Err(VaultApiError::TooManyForms {
                max: MAX_FORMS_PER_SESSION,
            });
        }
        s.forms.extend(fresh);
        Ok(())
    }

    /// Одна подмена: маркер, метка или суррогат — по режиму и классу.
    fn substitute(
        &self,
        session: Option<&str>,
        original: &str,
        class: &str,
        pending: &mut PendingForms,
    ) -> Result<(String, &'static str), VaultApiError> {
        if class == "person_name" && self.mode == VaultMode::Session {
            if let Some(srg) =
                self.surrogate_span(session.unwrap_or_default(), original, pending)?
            {
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
    fn surrogate_span(
        &self,
        session: &str,
        original: &str,
        pending: &mut PendingForms,
    ) -> Result<Option<String>, VaultApiError> {
        let Some((out, forms)) = self.surrogate_forms(session, original)? else {
            return Ok(None);
        };
        // Пачка атомарна по спану: хоть одна форма уже принадлежит ДРУГОМУ
        // оригиналу — весь спан уходит на метку, а не половина имени в суррогат и
        // половина в метку (`deanonymize` обязан вернуть исходник byte-exact).
        // Откат пачки — `truncate` до начала спана: в реестр не попадают формы,
        // которые не вошли в ответ.
        let mark = pending.items.len();
        for (f, owner) in forms {
            match pending.push(f, &owner) {
                Ok(Reserved::TakenByOther) => {
                    pending.items.truncate(mark);
                    self.surrogate_fallbacks.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                Ok(_) => {}
                Err(e) => {
                    pending.items.truncate(mark);
                    return Err(e);
                }
            }
        }
        Ok(Some(out))
    }

    /// Форма суррогата для одного токена — с политикой отказа шага 7а (#60).
    ///
    /// Коллизия слота больше НЕ ошибка запроса: имя уходит на типизированную
    /// метку (`Ok(None)` = «гладкой подмены не будет»), потому что метка точна,
    /// не имеет коллизий и полностью обратима. Отказ `422` на втором ФИО в
    /// сессии ломал бы весь документ ради косметики. Счётчик [`Self::
    /// surrogate_fallbacks`] видит, как часто пул не справляется.
    ///
    /// Ошибкой остаётся только отказ хранилища: без обратного индекса
    /// обратимость не гарантируется, и это настоящий `503`.
    fn srg(
        &self,
        session: &str,
        word: &str,
        case: Case,
        gender: Gender,
        ty: NameType,
    ) -> Result<Option<Surrogat>, VaultApiError> {
        match self
            .engine
            .surrogat_for_gender(session, word, case, gender, ty)
        {
            Ok(srg) => Ok(srg),
            Err(guard_vault::SurrogatError::Collision { .. }) => {
                self.surrogate_fallbacks.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
            Err(guard_vault::SurrogatError::Store(se)) => Err(store_err(se)),
        }
    }

    /// Суррогат по оригиналу, **без записи в реестр демона**: формы возвращаются
    /// вместе с текстом, а решение о capacities живёт снаружи (`PendingForms`).
    ///
    /// В кэше движка записи остаются и при отказе (слот занят — первый владелец
    /// не смещается, а запрос не выдал токен): реестр форм демона о такой записи
    /// не знает, `deanonymize` идёт по реестру — запись недостижима и снимается
    /// TTL или teardown. Осознанно не откатываем: откат требовал бы удалить чужую
    /// запись, то есть снова трогать чужой слот.
    fn surrogate_forms(
        &self,
        session: &str,
        original: &str,
    ) -> Result<Option<SurrogateOutcome>, VaultApiError> {
        let Some(table) = MorphTable::shipped() else {
            return Ok(None);
        };
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
                let Some(first) = original.split_whitespace().next() else {
                    return Ok(None);
                };
                let Some(g) = guard_vault::morph::suffix_gender(first) else {
                    return Ok(None);
                };
                if !genders.contains(&g) {
                    return Ok(None);
                }
                (lemmas, case, g)
            }
            SpanParse::Ambiguous(_) | SpanParse::NoMatch(_) => return Ok(None),
        };
        let tokens: Vec<&str> = original.split_whitespace().collect();
        if tokens.len() != lemmas.len() || tokens.len() > NameType::ORDER.len() {
            return Ok(None);
        }
        let mut out = String::with_capacity(original.len());
        let mut word = String::new();
        let mut forms: Vec<FormWithOwner> = Vec::new();
        let mut idx = 0_usize;
        for c in original.chars() {
            if c.is_alphabetic() {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                let Some(srg) = self.srg(session, &word, case, gender, NameType::ORDER[idx])?
                else {
                    return Ok(None);
                };
                forms.push((srg.form.clone(), word.clone()));
                word.clear();
                out.push_str(&srg.form);
            }
            out.push(c);
            if c.is_whitespace() {
                idx += 1;
            }
        }
        if !word.is_empty() {
            let Some(srg) = self.srg(session, &word, case, gender, NameType::ORDER[idx])? else {
                return Ok(None);
            };
            forms.push((srg.form.clone(), word.clone()));
            out.push_str(&srg.form);
        }
        if forms.len() != tokens.len() {
            return Ok(None);
        }
        Ok(Some((out, forms)))
    }

    /// Обратный ход суррогатов: подставляем оригиналы по зарегистрированным
    /// формам, длинные имена раньше коротких (`Ветрова` ⊂ `Ветровой` не мешает).
    ///
    /// Возвращает пару (развёрнуто, отвернуто). «Отвернуто» — только формы, чья
    /// запись расходится со свидетельством выдачи (#60 п.3): их мы не разворачиваем,
    /// и наружу это обязано выйти числом, а не тишиной (R7 ревью #70).
    fn restore_surrogates(
        &self,
        session: &str,
        text: &mut String,
        forms: &[String],
    ) -> (usize, usize) {
        let (mut n, mut refused) = (0_usize, 0_usize);
        let mut sorted: Vec<&String> = forms.iter().collect();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.len()));
        for form in sorted {
            match self.engine.try_restore(session, form) {
                // Формы без записи — косметика истёкшей сессии: не событие
                // целостности, в счётчик не идут.
                Restore::Absent => {}
                Restore::Diverged => refused += 1,
                Restore::Found(orig) => {
                    if text.contains(form.as_str()) {
                        *text = text.replace(form.as_str(), orig.as_str());
                        n += 1;
                    }
                }
            }
        }
        (n, refused)
    }
}

/// Суррогатный выход одного спана: подставленный текст и формы с поверхностями
/// токенов-оригиналов, из которых они выросли (владелец нужен пред-проверке
/// `PendingForms`, B2/P8).
type SurrogateOutcome = (String, Vec<FormWithOwner>);

/// Форма вместе с токеном-владельцем.
type FormWithOwner = (String, String);

/// Отпечаток маркера как hex-строка (первые `len` символов base64url,
/// приведённые к верхнему регистру алфавита метки).
fn hex_prefix(b64: &str, len: usize) -> String {
    b64.chars()
        .filter(char::is_ascii_alphanumeric)
        .take(len)
        .map(|c| c.to_ascii_uppercase())
        .collect()
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

/// Исход резервирования формы в пачке одного запроса.
#[derive(Debug, PartialEq, Eq)]
enum Reserved {
    /// Форма новая.
    Fresh,
    /// Эту же форму уже просил этот же оригинал — идемпотентно.
    SameOwner,
    /// Формой владеет ДРУГОЙ оригинал: спан уходит на метку (#60).
    TakenByOther,
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
            surrogate_fallbacks: AtomicU64::new(0),
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

    /// Имена, которые наша морф-таблица принимает как ФИО и которые не лежат в
    /// одной корзине пула (`pool_probe -- forms`: «Ушакова…» → Гудзовская /
    /// Гельфия / Хассановна, «Ветрова…» → Шашкина / Рагнета / Арабхановна —
    /// пересечений нет).
    const NAME_A: &str = "Ушакова Кира Саввична";

    /// Пара, промеренная `pool_probe -- forms`: обе фамилии падают на «Деденеву»
    /// при разных оригиналах («Родионова…» → Деденева/Люнгина/Феохарьевна,
    /// «Мельникова…» → Деденева/Рагиля/Люсиановна). На пуле в 128 лемм на корзину
    /// это единственный честный способ получить коллизию слота: совпадение
    /// отчеств коллизией не является (тот же оригинал токена — тот же владелец,
    /// `Reserved::SameOwner`), и «Ушакова…/Родионова Милана Саввична» с общей
    /// «Саввичной» разворачиваются оба. Литералы обязан обновлять тот, кто
    /// меняет артефакт пула: `data/morph/surrogates.tsv` закреплён тестом
    /// `pool::tests::pool_artifact_is_pinned`.
    const NAME_B: &str = "Ветрова Прасковья Афанасьевна";
    const NAME_CLASH_A: &str = "Родионова Аграфена Гордеевна";
    const NAME_CLASH_B: &str = "Мельникова Ульяна Тихоновна";

    fn seed_forms(v: &Vault, session: &str, n: usize) {
        let mut guard = v.locked();
        let s = guard.sessions.get_mut(session).expect("слот создан");
        s.forms = (0..n).map(|i| format!("Форма {i} Иванов")).collect();
    }

    #[test]
    fn forms_cap_refuses_request_before_first_substitution() {
        // Порог из `config::MAX_FORMS_PER_SESSION` должен быть отказом, а не
        // тихой потерей формы: потерянная форма = partial-restore на
        // `/v1/deanonymize` без ошибки, то есть fail-open на данных.
        let v = vault(VaultMode::Session);
        let inn = "ИНН 2482014338";
        v.anonymize(
            Some("cap"),
            inn,
            &[span("inn", inn, "2482014338")],
            &schema(),
        )
        .expect("слот создаётся первой же меткой");
        assert_eq!(v.forms_len(Some("cap")), 0, "метка формы не плодит");

        // 1. Добиваем сессию до ровно `max - 3` выдуманными формами и просим
        //    одно ФИО: трёх новых форм как раз хватает до потолка.
        let max = MAX_FORMS_PER_SESSION;
        seed_forms(&v, "cap", max - 3);
        let anon = v
            .anonymize(
                Some("cap"),
                NAME_A,
                &[span("person_name", NAME_A, NAME_A)],
                &schema(),
            )
            .expect("3 формы в остаток влезают");
        assert!(!anon.text.contains(NAME_A), "имя должно быть заменено");
        assert_eq!(v.forms_len(Some("cap")), max, "потолок достигнут точно");

        // 2. Запрос, которому не хватает одного слота, обязан быть отвергнут
        //    ЦЕЛИКОМ. Отдельная сессия на `max - 2`, потому что в `cap` имя из
        //    шага 1 уже стало суррогатом, и повтор его же просил бы отказ по
        //    другой причине (P6, `reanonymize_surrogate`).
        v.anonymize(
            Some("cap2"),
            inn,
            &[span("inn", inn, "2482014338")],
            &schema(),
        )
        .expect("слот");
        seed_forms(&v, "cap2", max - 2);
        let err = v
            .anonymize(
                Some("cap2"),
                NAME_A,
                &[span("person_name", NAME_A, NAME_A)],
                &schema(),
            )
            .expect_err("места нет");
        assert!(
            matches!(err, VaultApiError::TooManyForms { max: m } if m == max),
            "{err:?}"
        );
        assert_eq!(err.code(), "too_many_forms");
        assert_eq!(
            err.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "переполнение лимита — отказ клиента, а не 5xx"
        );
        // 3. И ничего не изменено: ни число форм, ни то, что сессия уже знала.
        assert_eq!(
            v.forms_len(Some("cap2")),
            max - 2,
            "отказ не мутирует реестр"
        );
    }

    /// P6: повторная анонимизация собственного выхода = отказ до первой
    /// подмены. Замеренная до правки порча: три раунда на одном имени давали
    /// `deanonymize` выдуманную смесь («Ветрова Кира Саввична») с `200 OK`.
    #[test]
    fn reanonymizing_own_output_is_refused_for_any_class() {
        let v = vault(VaultMode::Session);
        let inn = "ИНН 2482014338";
        let a = v
            .anonymize(
                Some("p6"),
                inn,
                &[span("inn", inn, "2482014338")],
                &schema(),
            )
            .expect("метка");
        let err = v
            .anonymize(
                Some("p6"),
                &a.text,
                &[span("inn", &a.text, &a.text)],
                &schema(),
            )
            .expect_err("метку повторно не мажут");
        assert!(
            matches!(err, VaultApiError::ReanonymizeSurrogate { .. }),
            "{err:?}"
        );
        assert_eq!(err.code(), "reanonymize_surrogate");
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Тот же отказ по классу ФИО и честный round-trip после него.
        let n = v
            .anonymize(
                Some("p6b"),
                NAME_A,
                &[span("person_name", NAME_A, NAME_A)],
                &schema(),
            )
            .expect("раунд 1");
        let err2 = v
            .anonymize(
                Some("p6b"),
                &n.text,
                &[span("person_name", &n.text, &n.text)],
                &schema(),
            )
            .expect_err("раунд 2 запрещён");
        assert!(
            matches!(err2, VaultApiError::ReanonymizeSurrogate { ref class } if class == "person_name"),
            "{err2:?}"
        );
        let back = v
            .deanonymize(Some("p6b"), &n.text)
            .expect("отказ ничего не перезатёр");
        assert_eq!(
            back.text.as_str(),
            NAME_A,
            "имя восстановлено точно, а не смесью"
        );
        assert_eq!(v.forms_len(Some("p6b")), 3, "отказ не мутирует реестр");

        // Проверка не должна стать отказом мазать всё подряд: настоящее имя,
        // не фигурировавшее в этой сессии как подмена, мажется как обычно.
        let other = v
            .anonymize(
                Some("p6c"),
                NAME_B,
                &[span("person_name", NAME_B, NAME_B)],
                &schema(),
            )
            .expect("свежее имя в свежей сессии — не наш суррогат");
        assert!(!other.text.contains(NAME_B));
    }

    /// Метрика `restoration-integrity` (#60 п.3) видна наружу без отладочного
    /// режима, а отказ разворота не отдаёт чужое имя.
    ///
    /// Состояние «кэш говорит одно, индекс — другое» строится напрямую через
    /// `store()`: так выглядит перенятый слот (запись истекла, форма досталась
    /// другому), и штатным путём его не получить — выдача на перенятую форму
    /// отказывает (`guard-vault::slot_retaken_after_record_died_is_refused_not_swallowed`).
    #[test]
    fn divergent_form_refuses_restore_and_shows_in_counter() {
        let v = vault(VaultMode::Session);
        let name = "Ушакова Кира Саввична";
        let n = v
            .anonymize(
                Some("p16"),
                name,
                &[span("person_name", name, name)],
                &schema(),
            )
            .expect("мазание");
        let forms = v.session_forms("p16");
        assert!(
            !forms.is_empty(),
            "тесту нужна гладкая подмена, а не метка: текст {text}",
            text = n.text
        );
        for f in &forms {
            v.engine
                .store()
                .insert(
                    &StoreKey::new("p16", &format!("SRG#{f}")),
                    SecretString::new("Ветрова Марселина Афанасьевна".to_owned()),
                )
                .expect("запись вручную");
        }
        let back = v
            .deanonymize(Some("p16"), &n.text)
            .expect("разворот не обязан валиться из-за расхождения");
        assert!(
            !back.text.contains("Ветрова"),
            "чужое имя на месте своего — это утечка, а не деградация: {out}",
            out = back.text.as_str()
        );
        assert!(
            back.text.contains(&forms[0]),
            "отказ обязан оставить неразвёрнутую форму, а не съесть её: {out}",
            out = back.text.as_str()
        );
        assert_eq!(
            v.unrestored_mismatch(),
            u64::try_from(forms.len()).expect("формы влезают в u64"),
            "сколько форм отвернулось — столько и в счётчике"
        );
        // R7 ревью #70: у события обязан быть след в самом запросе, а не только в
        // процессном счётчике, иначе молчание ответа выдаёт отказ разворота за
        // успешный разворот.
        assert_eq!(
            back.restore_refused,
            forms.len(),
            "число отвергнутых форм обязано приехать в ответе /v1/deanonymize"
        );
        let soft = v
            .deanonymize_soft(Some("p16"), n.text.as_str())
            .expect("мягкий путь не валится из-за расхождения");
        assert_eq!(
            soft.restore_refused,
            forms.len(),
            "мягкий путь (прокси) считает те же отвергнутые формы"
        );
        assert!(
            !soft.text.contains("Ветрова"),
            "мягкий путь тоже не имеет права подставить чужое имя"
        );
        assert_eq!(
            soft.unresolved, 0,
            "суррогатная форма — не маркер, в unresolved её нет"
        );
    }

    /// R1 ревью #62: коллизия на **втором** токене пачки. На golden-v1 при пуле
    /// 128 коллизий НЕ на первом токене нет вообще (`pool_probe -- probe`:
    /// Surname=6, Firstname=0, Midname=0 — все отказы на первом токене, и там
    /// откатывать нечего), поэтому пара синтетическая: `pool_probe -- forms`
    /// печатает её как два ФИО-триплета с одним общим именем «Рагиля» на втором
    /// токене — «Ушакова Люнгина Саввична» → `Гудзовская | Рагиля | Хассановна`
    /// и «Ветрова Марселина Афанасьевна» → `Шашкина | Рагиля | Арабхановна`
    /// (фамилии и отчества — другие слоты). Та же пара видна в `pool_probe --
    /// collide firstname f` строкой «слот Рагиля: Люнгина + Марселина», но
    /// `collide` печатает только группу ключей одного слота, без ФИО целиком, —
    /// литералы теста поэтому переписаны по `forms`. Этот тест держит «коллизия
    /// спана → весь спан
    /// меткой», но НЕ дискриминирует `truncate`: движок отвечает отказом до
    /// первой же пушки, и откатывать нечего. Дискриминирует соседний тест.
    #[test]
    fn collision_on_second_token_sends_whole_span_to_label() {
        let v = vault(VaultMode::Session);
        let first = "Ушакова Люнгина Саввична";
        let second = "Ветрова Марселина Афанасьевна";
        let a = v
            .anonymize(
                Some("r1"),
                first,
                &[span("person_name", first, first)],
                &schema(),
            )
            .expect("первое имя");
        assert!(
            !a.text.contains(first),
            "первое имя обязано быть суррогатом, а не меткой: {}",
            a.text
        );
        assert_eq!(v.forms_len(Some("r1")), 3, "три формы первого имени");
        let b = v
            .anonymize(
                Some("r1"),
                second,
                &[span("person_name", second, second)],
                &schema(),
            )
            .expect("второе имя — метка, не отказ");
        assert!(
            b.text.starts_with("[PERSON_NAME_"),
            "коллизия на втором токене: {}",
            b.text
        );
        assert_eq!(
            v.forms_len(Some("r1")),
            3,
            "откат пачки: ни одной формы второго имени в реестре не осталось"
        );
        assert_eq!(
            v.surrogate_fallbacks(),
            1,
            "деградация посчитана ровно один раз"
        );
        assert_eq!(
            v.deanonymize(Some("r1"), &a.text)
                .expect("разворот")
                .text
                .as_str(),
            first
        );
        assert_eq!(
            v.deanonymize(Some("r1"), &b.text)
                .expect("разворот")
                .text
                .as_str(),
            second
        );
    }

    /// Дискриминация `truncate` (R1 ревью #62): ветка живая, и ловит она
    /// расхождение пред-проверки батча с движком. `PendingForms` помнит владельца
    /// формы по **поверхности** токена, а движок — по **лемме**: один и тот же
    /// человек, написанный в двух спанах одного запроса с разной регистровой
    /// поверхностью имени («Кира» и «кира»), для движка один владелец (та же
    /// лемма КИРА → та же форма «Гельфия»), а для батча — второй оригинал той же
    /// формы. Отказ наступает на втором токене, первый («Шашкина») уже в пачке, и
    /// без `truncate` он уехал бы в `commit_forms` формой с невыданным токеном.
    ///
    /// Промер возмущением: `truncate` закомментирован — этот тест краснеет на
    /// `forms_len` (4 вместо 3), остальные 83 проходят. Литералы форм промерены
    /// `pool_probe -- forms`, регистр внутри спана — то, что реально приходит из
    /// OCR-потока, и спаны в запросе рисует клиент, а не наш сканер.
    #[test]
    fn batch_precheck_disagreement_rolls_the_partial_span_back() {
        let v = vault(VaultMode::Session);
        let one = "Ушакова Кира Саввична";
        let two = "Ветрова кира Саввична";
        let text = format!("{one} и {two}");
        let a = v
            .anonymize(
                Some("r2"),
                &text,
                &[
                    span("person_name", &text, one),
                    span("person_name", &text, two),
                ],
                &schema(),
            )
            .expect("запрос не отказывается: второй спан уходит на метку");
        assert_eq!(
            a.items.iter().filter(|i| i.operator == "replace").count(),
            1,
            "суррогат ровно один, второй спан — метка"
        );
        assert_eq!(
            v.forms_len(Some("r2")),
            3,
            "откат пачки: форма первого токена отвергнутого спана не влезла в реестр"
        );
        assert_eq!(v.surrogate_fallbacks(), 1, "деградация посчитана");
        let back = v
            .deanonymize(Some("r2"), &a.text)
            .expect("разворот обоих спанов");
        assert_eq!(back.text.as_str(), text, "byte-exact");
    }

    /// P4: атомарность отказа держится для **реестра форм**, но не для счётчика
    /// меток. Отказ берём из переполнения реестра (`too_many_forms`): с шага 7а
    /// коллизия слота отказом не является, и это единственный оставшийся путь
    /// отказаться по данным запроса после того, как метка уже выдана.
    /// Замер: `[INN_1_…]`, затем запрос «ИНН + ФИО», которому не хватает одного
    /// слота, даёт `422`, а следующая метка — `[INN_3_…]`: счётчик ушёл вперёд на
    /// провалившемся запросе. Это не дыра (номер метки — не секрет, плотность
    /// нумерации не обещана), и счётчик мы не откатываем: откат требовал бы
    /// трогать чужой слот. Тест держит ровно обещанное: отказ не двигает реестр
    /// форм и не даёт переиспользовать номер.
    #[test]
    fn refused_request_moves_only_the_label_counter() {
        let v = vault(VaultMode::Session);
        let max = MAX_FORMS_PER_SESSION;
        let a = v
            .anonymize(
                Some("p4"),
                "ИНН 2482014338",
                &[span("inn", "ИНН 2482014338", "2482014338")],
                &schema(),
            )
            .expect("метка");
        assert!(a.text.contains("[INN_1_"), "{:?}", a.text);
        let forms = v.forms_len(Some("p4"));
        seed_forms(&v, "p4", max - 2);
        let two = "ИНН 5001001000 и Родионова Милана Саввична";
        let err = v
            .anonymize(
                Some("p4"),
                two,
                &[
                    span("inn", two, "5001001000"),
                    span("person_name", two, "Родионова Милана Саввична"),
                ],
                &schema(),
            )
            .expect_err("ФИО не влезает в остаток реестра");
        assert!(
            matches!(err, VaultApiError::TooManyForms { max: m } if m == max),
            "{err:?}"
        );
        assert_eq!(
            v.forms_len(Some("p4")),
            max - 2,
            "отказ не мутирует реестр форм"
        );
        let next = v
            .anonymize(
                Some("p4"),
                "ИНН 6002002000",
                &[span("inn", "ИНН 6002002000", "6002002000")],
                &schema(),
            )
            .expect("метка после отказа")
            .text;
        assert!(
            next.contains("[INN_3_") || next.contains("[INN_2_"),
            "номер не переиспользуется, но плотность не обещана: {next}"
        );
        assert_eq!(v.forms_len(Some("p4")), max - 2, "реестр форм не тронут");
        let _ = forms;
    }

    /// P3: `invalidate` идёт «движок → реестр», путь запроса — «реестр, отпустить,
    /// движок». Тест держит этот порядок под конкуренцией: гонка двух потоков на
    /// одной сессии обязана давать только легальные ответы и не укладывать демон
    /// в клинч (мёртвая блокировка выглядела бы как висящий тест).
    #[test]
    fn invalidate_racing_anonymize_keeps_only_legal_outcomes() {
        let v = vault(VaultMode::Session);
        let inn = "ИНН 2482014338";
        let (codes, dropped) = std::thread::scope(|s| {
            let writer = s.spawn(|| {
                let mut out = Vec::new();
                for _ in 0..200 {
                    let r = v.anonymize(
                        Some("p3"),
                        inn,
                        &[span("inn", inn, "2482014338")],
                        &schema(),
                    );
                    out.push(match r {
                        Ok(_) => 200,
                        Err(e) => e.status().as_u16(),
                    });
                }
                out
            });
            let eraser = s.spawn(|| {
                let mut n = 0_u64;
                for _ in 0..200 {
                    n += v.invalidate("p3");
                }
                n
            });
            (
                writer.join().expect("поток запросов не паникует"),
                eraser.join().expect("поток invalidate не паникует"),
            )
        });
        let bad: Vec<u16> = codes
            .iter()
            .copied()
            .filter(|c| *c != 200 && *c != 400)
            .collect();
        assert!(
            bad.is_empty(),
            "гонка выдала нелегальные статусы: {bad:?} (400 = сессию стёрли между проверкой и вставкой)"
        );
        assert!(codes.contains(&200), "хоть один запрос прошёл");
        v.anonymize(
            Some("p3"),
            inn,
            &[span("inn", inn, "2482014338")],
            &schema(),
        )
        .expect("после гонки демон работает");
        // Поток `invalidate` дешевле потока запроса и мог весь пройти до первой
        // вставки — это не дефект, поэтому проверяем не сумму за гонку, а что
        // механизм не обескровлен: свежая запись находится.
        assert!(
            v.invalidate("p3") > 0 || dropped > 0,
            "invalidate перестал видеть записи сессии: {dropped}"
        );
    }

    /// B2/P8 c шага 7а (#60): второе ФИО, попавшее в занятый слот, не отказывает
    /// запросу и не смещает первого владельца — оно уходит на типизированную
    /// метку. Пара промерена `pool_probe -- forms` на закреплённом пуле: обе
    /// фамилии дают «Деденеву», то есть сталкиваются в корзине surname/fem.
    /// До правки #58 второй оригинал тихо перезаписывал
    /// чужой слот, на шаге 6 это стало `422`, с шага 7а — меткой.
    #[test]
    fn second_name_on_taken_slot_falls_back_to_label() {
        let v = vault(VaultMode::Session);
        let other = NAME_CLASH_B;
        let a = v
            .anonymize(
                Some("b2"),
                NAME_CLASH_A,
                &[span("person_name", NAME_CLASH_A, NAME_CLASH_A)],
                &schema(),
            )
            .expect("первое имя");
        let forms = v.forms_len(Some("b2"));
        assert_eq!(forms, 3, "три формы первого владельца в реестре");
        assert!(
            !a.text.contains(NAME_CLASH_A),
            "первое — суррогат: {}",
            a.text
        );
        let b = v
            .anonymize(
                Some("b2"),
                other,
                &[span("person_name", other, other)],
                &schema(),
            )
            .expect("второе имя не отказ, а метка");
        assert!(
            b.text.starts_with("[PERSON_NAME_"),
            "второе имя обязано стать меткой: {}",
            b.text
        );
        assert_eq!(
            v.forms_len(Some("b2")),
            forms,
            "отказ от слота форм не добавил"
        );
        assert_eq!(v.surrogate_fallbacks(), 1, "счётчик деградации");
        assert_eq!(
            v.deanonymize(Some("b2"), &a.text)
                .expect("разворот")
                .text
                .as_str(),
            NAME_CLASH_A,
            "вот здесь до правки появлялось чужое имя"
        );
        assert_eq!(
            v.deanonymize(Some("b2"), &b.text)
                .expect("разворот")
                .text
                .as_str(),
            other,
            "метка разворачивается точно так же, как суррогат"
        );
    }

    /// Два разных ФИО в ОДНОМ запросе, влезшие в один слот: первый получает
    /// суррогат, второй — метку, запрос в целом успешен (до шага 7а — `422` на
    /// весь документ). Реестр форм пополняется только первым именем.
    #[test]
    fn two_colliding_names_in_one_request_send_the_second_to_a_label() {
        let v = vault(VaultMode::Session);
        let text = format!("{NAME_CLASH_A} и {NAME_CLASH_B}");
        let spans = vec![
            span("person_name", &text, NAME_CLASH_A),
            span("person_name", &text, NAME_CLASH_B),
        ];
        let a = v
            .anonymize(Some("b2req"), &text, &spans, &schema())
            .expect("коллизия больше не отказ");
        assert_eq!(v.forms_len(Some("b2req")), 3, "формы только у первого");
        assert_eq!(
            v.surrogate_fallbacks(),
            1,
            "деградация обязана быть видна счётчику"
        );
        assert!(
            a.text.contains("[PERSON_NAME_"),
            "второе имя обязано стать меткой: {}",
            a.text
        );
        assert!(
            !a.text.contains(NAME_CLASH_A) && !a.text.contains(NAME_CLASH_B),
            "оригиналов в ответе нет: {}",
            a.text
        );
        let back = v
            .deanonymize(Some("b2req"), &a.text)
            .expect("разворот обоих имён");
        assert_eq!(back.text.as_str(), text, "byte-exact");
    }

    /// Белая коробка пред-проверки: `PendingForms` сам по себе помечает второй
    /// попытки занятия той же формы другим оригиналом. Через API эта ветка
    /// невидима (спан просто уходит на метку), поэтому проверка белая коробка.
    /// Литералы здесь произвольные: пула тест не касается, проверяется реестр
    /// пачки одного запроса.
    #[test]
    fn pending_forms_marks_second_owner_of_one_form_taken() {
        let mut p = PendingForms::new(0);
        assert_eq!(
            p.push("Тенина".to_owned(), "Ушакова").unwrap(),
            Reserved::Fresh,
            "первый владелец"
        );
        assert_eq!(
            p.push("Тенина".to_owned(), "Ушакова").unwrap(),
            Reserved::SameOwner,
            "тот же владелец идемпотентен"
        );
        assert_eq!(
            p.push("Тенина".to_owned(), "Родионова").unwrap(),
            Reserved::TakenByOther,
            "второй владелец того же слота"
        );
        assert_eq!(p.items.len(), 1, "отказ не резервирует место");
    }

    /// Тот же оригинал повторно — идемпотентен: слот принадлежит ему, отказывать
    /// не на чем (правки ради этого asserts и держится — иначе `422` посыпался бы
    /// на повторной отправке того же документа).
    #[test]
    fn same_name_twice_in_one_session_is_idempotent() {
        let v = vault(VaultMode::Session);
        let a = v
            .anonymize(
                Some("b2i"),
                NAME_A,
                &[span("person_name", NAME_A, NAME_A)],
                &schema(),
            )
            .expect("первый");
        let b = v
            .anonymize(
                Some("b2i"),
                NAME_A,
                &[span("person_name", NAME_A, NAME_A)],
                &schema(),
            )
            .expect("второй — тот же оригинал");
        assert_eq!(a.text, b.text, "та же форма, та же метка");
        assert_eq!(b.items[0].byte_start, a.items[0].byte_start);
    }

    /// Документ с двумя разными ФИО обязан и замаскироваться, и развернуться
    /// целиком. Был KNOWN-RED B2 из ревью #58: краснел на отказе второго имени.
    /// Зелёный с шага 7а (#60): второе имя — не отказ, а метка, оба разворачиваются.
    #[test]
    fn two_names_in_one_session_mask_and_restore() {
        let v = vault(VaultMode::Session);
        let text = "Ф.И.О. подряд: Родионова Аграфена Гордеевна и Мельникова Ульяна Тихоновна.";
        let spans = vec![
            span("person_name", text, "Родионова Аграфена Гордеевна"),
            span("person_name", text, "Мельникова Ульяна Тихоновна"),
        ];
        let a = v
            .anonymize(Some("b2doc"), text, &spans, &schema())
            .expect("оба имени обязаны замаскироваться");
        assert!(
            !a.text.contains("Родионова") && !a.text.contains("Мельникова"),
            "оригиналы не имели права остаться в тексте: {}",
            a.text
        );
        assert!(
            a.text.contains("[PERSON_NAME_"),
            "коллизия обязана была уйти на метку: {}",
            a.text
        );
        let back = v
            .deanonymize(Some("b2doc"), &a.text)
            .expect("оба обязаны развернуться");
        assert_eq!(back.text.as_str(), text, "разворот обязан быть byte-exact");
    }

    #[test]
    fn duplicate_forms_within_request_do_not_reserve_twice() {
        // 400 вхождений одного имени — это 3 формы, а не 1200: дедупликация
        // внутри запроса обязана быть, иначе лимит превратился бы в отказ на
        // безобидном тексте.
        let v = vault(VaultMode::Session);
        let inn = "ИНН 2482014338";
        v.anonymize(
            Some("dup"),
            inn,
            &[span("inn", inn, "2482014338")],
            &schema(),
        )
        .expect("слот");
        let text = format!("{NAME_A}, ");
        let unit = text.repeat(400);
        let needle_len = NAME_A.len();
        let spans: Vec<SpanIn> = (0..400)
            .map(|i| {
                let start = i * (needle_len + 2);
                SpanIn {
                    entity_type: "person_name".to_owned(),
                    byte_start: start,
                    byte_end: start + needle_len,
                }
            })
            .collect();
        v.anonymize(Some("dup"), &unit, &spans, &schema())
            .expect("400 одинаковых имён — три формы");
        assert_eq!(v.forms_len(Some("dup")), 3);
    }

    #[test]
    fn registry_evicts_oldest_session_and_forgets_its_labels() {
        // `MAX_SESSIONS` без теста = мёртвая константа: проверка, что FIFO
        // действительно вытесняет старейшую и вычищает за ней кэш оригиналов.
        let v = vault(VaultMode::Session);
        let inn = "ИНН 2482014338";
        let mut first_text = String::new();
        for i in 0..=MAX_SESSIONS {
            let id = format!("fifo{i}");
            let anon = v
                .anonymize(Some(&id), inn, &[span("inn", inn, "2482014338")], &schema())
                .expect("метка");
            if i == 0 {
                first_text = anon.text;
            }
        }
        {
            let guard = v.locked();
            assert_eq!(guard.sessions.len(), MAX_SESSIONS, "реестр не раздут");
            assert_eq!(guard.order.len(), MAX_SESSIONS);
            assert!(!guard.sessions.contains_key("fifo0"), "старейшая вытеснена");
            assert!(guard.sessions.contains_key("fifo256"), "новейшая жива");
        }
        let err = v
            .deanonymize(Some("fifo0"), &first_text)
            .expect_err("вытесненная сессия не разворачивается");
        assert!(
            matches!(err, VaultApiError::Unresolved { count: 1 }),
            "{err:?}"
        );
    }
}
