//! Конфигурация демона: env → тип, с fail-closed разбором.
//!
//! Шаг 6 (SPEC §10 п.6, issue #56). Файлового конфига на этом шаге нет: только
//! переменные окружения `FASAD_*` + встроенный канон схемы
//! (`config/schema.default.json`, атом E). Причина не лени, а граница шага:
//! редактор схемы и файл конфигурации — SPEC §10 п.8 (UI-песочница), а
//! тащить `toml`/`serde_yaml` в runtime-контур сейчас значило бы новую
//! зависимость без верификации по первичке (AGENTS §Дисциплина фактов п.2).
//!
//! # Почему разбор симметрично-строгий, а порт — нет
//!
//! Ошибка в бинде, пороге или схеме меняет **безопасность** (гард слушает не на
//! loopback, каскад режет порог ниже измеренного) — значит молча подставить
//! дефолт нельзя, [`ConfigError`] и старт валится. Порт — эргономика разработки:
//! `FASAD_PORT=abc` оставляет 8765 ([`port_from_value`]), и это поведение
//! зафиксировано тестами со шага 1; разница не случайна, она названа здесь,
//! чтобы следующий читатель не «унифицировал» её в обе стороны.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Порт по умолчанию; переопределяется `FASAD_PORT` (мусор = дефолт, см.
/// заголовок модуля).
pub const DEFAULT_PORT: u16 = 8765;

/// Бинд по умолчанию: loopback. Внешний интерфейс не допускается вовсе
/// (SPEC §1 п.6: гард — локальный демон, а не сетевой сервис).
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Потолок размера тела запроса. НЕ из SPEC: числа в §8 нет, это страховка от
/// неограниченного буфера в конвейере (ПДн-текст + 4 каскада над ним).
/// Правится `FASAD_MAX_BODY_BYTES`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Порог `τ_low` экстрактора: **0.20**, нижняя граница диапазона SPEC §2
/// (0.20–0.25, «FN фатален, FP дёшев»).
///
/// Это «дефолт по замеру шага 6» (#56 п.2), а не выбор по вкусу. Промер
/// `recall_golden` на golden-v1.1 (N=150 recall-строк, `--threads 8`,
/// замороженный порядок блока, HEAD 08c35c3, 20.10):
///
/// | τ | Decide overall | Wilson lower 95 % | Decide `snils` |
/// |---|----------------|---------------------|----------------|
/// | 0.20 | 94.74 | 91.50 | 51.72 |
/// | 0.25 | 92.98 | 89.41 | 37.93 |
///
/// Разница +1.76 п.п. overall и +13.79 п.п. на `snils` в пользу 0.20; обе τ
/// проходят HARD-гейт amendment'а (`docs/quant-policy.md` §3 п.2a), значит
/// выбор делает нижняя граница, а SPEC §2 прямо велит держать порог низко.
pub const DEFAULT_TAU_LOW: f64 = 0.20;

/// Порог `τ_high`: выше — без арбитра (SPEC §2 каскад 1).
pub const DEFAULT_TAU_HIGH: f64 = 0.80;

/// Нижняя граница серой зоны арбитража (SPEC §2 каскад 2; TODO из
/// `guard-onnx/src/lib.rs` п.4b-3 закрыт значением 0.22, промер — атом E).
pub const DEFAULT_GRAY_LO: f64 = 0.22;

/// Верхняя граница серой зоны арбитража.
pub const DEFAULT_GRAY_HI: f64 = 0.80;

/// Потоки ORT по умолчанию: 8 — значение, под которым снимались первичные
/// замеры parity/recall (`docs/quant-policy.md` §3 п.2b: дефолт 4 даёт ±1 tp на
/// Decide, т.е. метрика становится функцией от потока).
pub const DEFAULT_THREADS: usize = 8;

/// Бюджет латентности запроса, мс (SPEC §1: 80–300 мс). Превышение = ошибка
/// конвейера, а не «подожём»: middleware обязан ответить 5xx раньше, чем клиент
/// решит, что гард просто молчит (AGENTS §Инженерные инварианты, Fail-Closed).
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// Режимы хранилища, наружу которых выставляет `/v1/*` (SPEC §3, #56 п.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultMode {
    /// Режим 2: сессионный кэш оригиналов, маркеры `[КЛАСС_N]`
    /// (`Grammar::LABEL`), состояние живёт в `SessionStore`.
    Session,
    /// Режим 3: stateless-токен `[[F0#base64url]]` (`Grammar::F0_INLINE`),
    /// сервер в покое хранит 0 байт пользовательских данных.
    Stateless,
}

impl VaultMode {
    /// Разбор значения env: `2`/`session` → [`Self::Session`],
    /// `3`/`stateless` → [`Self::Stateless`].
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "2" | "session" => Some(Self::Session),
            "3" | "stateless" => Some(Self::Stateless),
            _ => None,
        }
    }

    /// Каноническое имя для `/health` и логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Stateless => "stateless",
        }
    }
}

/// Пороги конвейера одним блоком: их совместная согласованность важнее отдельных
/// значений (`low ≤ gray_lo < gray_hi ≤ high`), поэтому валидируются вместе.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// Порог извлечения (`τ_low`).
    pub tau_low: f64,
    /// Порог «высокой уверенности» (`τ_high`).
    pub tau_high: f64,
    /// Низ серой зоны арбитра.
    pub gray_lo: f64,
    /// Верх серой зоны арбитра.
    pub gray_hi: f64,
}

impl Thresholds {
    /// Значения по умолчанию (см. константы модуля).
    #[must_use]
    pub const fn default_working() -> Self {
        Self {
            tau_low: DEFAULT_TAU_LOW,
            tau_high: DEFAULT_TAU_HIGH,
            gray_lo: DEFAULT_GRAY_LO,
            gray_hi: DEFAULT_GRAY_HI,
        }
    }

    /// Сохранность порогов: все в `[0, 1]` и согласованы по каскаду.
    ///
    /// Инварианты (SPEC §2 каскады 1–2):
    ///
    /// 1. `tau_low ≤ tau_high` — иначе экстрактор ничего не принимает;
    /// 2. `gray_lo < gray_hi` — иначе арбитр зовётся на пустом множестве и
    ///    каскад 2 молча деградирует до каскада 1;
    /// 3. `gray_hi ≤ tau_high` — иначе возникает разрыв: спан с `p` между
    ///    `tau_high` и `gray_hi` принят «без арбитра», но при этом попадает в
    ///    серую зону; два решения против одного спана;
    /// 4. `tau_low < gray_hi` — иначе в серую зону не попадает ни один
    ///    извлечённый спан (вырождение каскада 2).
    ///
    /// Инверсии `gray_lo < tau_low` здесь **нет** намеренно: дефолт SPEC её и
    /// даёт (`τ_low = 0.25 > gray_lo = 0.22`), потому что SPEC держит
    /// `τ_low` независимым (диапазон 0.20–0.25, «FN фатален»), а нижняя граница
    /// серой зоны — отдельное число §2 каскад 2. Следствие лишь то, что нижняя
    /// часть зоны недостижима, а не противоречие.
    #[must_use]
    pub fn is_sane(&self) -> bool {
        let in_unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
        in_unit(self.tau_low)
            && in_unit(self.tau_high)
            && in_unit(self.gray_lo)
            && in_unit(self.gray_hi)
            && self.tau_low <= self.tau_high
            && self.gray_lo < self.gray_hi
            && self.gray_hi <= self.tau_high
            && self.tau_low < self.gray_hi
    }
}

/// Полная конфигурация демона, собранная из окружения.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Адрес прослушивания (всегда loopback, см. [`Config::bind`]).
    pub addr: SocketAddr,
    /// Потолок тела запроса, байт.
    pub max_body_bytes: usize,
    /// Бюджет латентности запроса, мс.
    pub timeout_ms: u64,
    /// Пороги конвейера.
    pub thresholds: Thresholds,
    /// Режим хранилища, выставленный наружу.
    pub vault_mode: VaultMode,
    /// Потоки ORT (`--threads` контракт замера).
    pub threads: usize,
    /// Каталог весов; `None` = каскады 1–2 не поднимаются, работает только
    /// детерминированный каскад 0 (деградация явная, см. `/health`).
    pub model_dir: Option<std::path::PathBuf>,
    /// Путь к файлу схемы классов (`FASAD_SCHEMA`); `None` = встроенный канон
    /// [`crate::schema::DEFAULT_SCHEMA_JSON`]. Override читается на старте и
    /// отказывает в старте, если испорчен — молча откатиться на дефолт значит
    /// игнорировать волю оператора.
    pub schema_path: Option<std::path::PathBuf>,
}

/// Причина, по которой конфигурация не собрана. Стартовый отказ — правильное
/// поведение: молча подменить безопасность-критичное значение дефолтом хуже,
/// чем не стартовать.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// `FASAD_BIND` не парсится как IP.
    BindUnparsable(String),
    /// Бинд не loopback: гард не сетевой сервис (SPEC §1 п.6).
    BindNotLoopback(IpAddr),
    /// Пороги вне `[0, 1]` или рассогласованы (см. [`Thresholds::is_sane`]).
    ThresholdsInsane(Thresholds),
    /// `FASAD_VAULT_MODE` не `2|3|session|stateless`.
    VaultModeUnknown(String),
    /// Числовое поле не парсится или нулевое.
    BadNumber {
        /// Имя переменной.
        var: &'static str,
        /// Что нашли.
        value: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindUnparsable(raw) => write!(f, "FASAD_BIND не является IP-адресом: {raw:?}"),
            Self::BindNotLoopback(ip) => {
                write!(
                    f,
                    "FASAD_BIND {ip} не loopback: демон не сетевой сервис (SPEC §1 п.6)"
                )
            }
            Self::ThresholdsInsane(t) => write!(
                f,
                "пороги рассогласованы: τ_low={} gray=[{}, {}] τ_high={} (нужно 0≤τ_low≤gray_lo<gray_hi≤τ_high≤1)",
                t.tau_low, t.gray_lo, t.gray_hi, t.tau_high
            ),
            Self::VaultModeUnknown(raw) => write!(
                f,
                "FASAD_VAULT_MODE {raw:?}: допустимо 2|3|session|stateless"
            ),
            Self::BadNumber { var, value } => {
                write!(f, "{var}={value:?}: не число или нуль")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Порт из значения env: мусор = дефолт (эргономика, не безопасность — см.
/// заголовок модуля).
#[must_use]
pub fn port_from_value(raw: Option<&str>) -> u16 {
    raw.and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT)
}

impl Config {
    /// Собрать из окружения процесса.
    ///
    /// # Errors
    ///
    /// Любой [`ConfigError`]: неверный бинд, рассогласованные пороги, неизвестный
    /// режим хранилища, непарсящееся/нулевое число.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Чистая часть: источник значений инжектится, чтобы тесты не трогали среду
    /// процесса (`set_var` в edition 2024 = unsafe + гонки параллельных тестов).
    ///
    /// # Errors
    ///
    /// См. [`Self::from_env`] — тот же контракт, источник значений инжектится.
    pub fn from_lookup<L>(mut lookup: L) -> Result<Self, ConfigError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        let addr = bind_from_value(
            lookup("FASAD_BIND").as_deref(),
            lookup("FASAD_PORT").as_deref(),
        )?;
        let thresholds = Thresholds {
            tau_low: float_or(&mut lookup, "FASAD_TAU_LOW", DEFAULT_TAU_LOW)?,
            tau_high: float_or(&mut lookup, "FASAD_TAU_HIGH", DEFAULT_TAU_HIGH)?,
            gray_lo: float_or(&mut lookup, "FASAD_GRAY_LO", DEFAULT_GRAY_LO)?,
            gray_hi: float_or(&mut lookup, "FASAD_GRAY_HI", DEFAULT_GRAY_HI)?,
        };
        if !thresholds.is_sane() {
            return Err(ConfigError::ThresholdsInsane(thresholds));
        }
        let vault_mode = match lookup("FASAD_VAULT_MODE").as_deref() {
            None => VaultMode::Stateless,
            Some(raw) => VaultMode::parse(raw)
                .ok_or_else(|| ConfigError::VaultModeUnknown(raw.to_owned()))?,
        };
        Ok(Self {
            addr,
            max_body_bytes: usize_or(&mut lookup, "FASAD_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?,
            timeout_ms: u64_or(&mut lookup, "FASAD_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)?,
            thresholds,
            vault_mode,
            threads: usize_or(&mut lookup, "FASAD_THREADS", DEFAULT_THREADS)?,
            model_dir: lookup("FASAD_MODEL_DIR").map(std::path::PathBuf::from),
            schema_path: lookup("FASAD_SCHEMA").map(std::path::PathBuf::from),
        })
    }

    /// Краткая строка статуса в `/health`: чем крутится конвейер. Секретов и
    /// пользовательских данных тут нет, но отпечаток конфигурации светим
    /// дозированно: `/health` ответа на аутентификацию не имеет.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        if self.model_dir.is_some() {
            "cascade-0+models"
        } else {
            "cascade-0-only"
        }
    }
}

/// Бинд из значения env; мусор = ошибка, не дефолт (см. заголовок модуля).
fn bind_from_value(raw: Option<&str>, port_raw: Option<&str>) -> Result<SocketAddr, ConfigError> {
    let ip = match raw {
        None | Some("") => DEFAULT_BIND,
        Some(s) => s
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::BindUnparsable(s.to_owned()))?,
    };
    if !ip.is_loopback() {
        return Err(ConfigError::BindNotLoopback(ip));
    }
    Ok(SocketAddr::new(ip, port_from_value(port_raw)))
}

fn float_or<L: FnMut(&'static str) -> Option<String>>(
    lookup: &mut L,
    var: &'static str,
    default: f64,
) -> Result<f64, ConfigError> {
    lookup(var).map_or(Ok(default), |raw| {
        raw.trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .ok_or(ConfigError::BadNumber { var, value: raw })
    })
}

fn usize_or<L: FnMut(&'static str) -> Option<String>>(
    lookup: &mut L,
    var: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    positive(lookup(var), var).unwrap_or(Ok(default))
}

fn u64_or<L: FnMut(&'static str) -> Option<String>>(
    lookup: &mut L,
    var: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    positive(lookup(var), var).unwrap_or(Ok(default))
}

fn positive<T>(raw: Option<String>, var: &'static str) -> Option<Result<T, ConfigError>>
where
    T: std::str::FromStr + PartialOrd + Default,
{
    raw.map(|value| {
        value
            .trim()
            .parse::<T>()
            .ok()
            .filter(|v| *v > T::default())
            .ok_or(ConfigError::BadNumber { var, value })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pairs(list: &[(&'static str, &'static str)]) -> HashMap<&'static str, String> {
        list.iter().map(|(k, v)| (*k, (*v).to_owned())).collect()
    }

    fn cfg_from(list: &[(&'static str, &'static str)]) -> Result<Config, ConfigError> {
        let map = pairs(list);
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_are_loopback_stateless_and_sane() {
        let cfg = cfg_from(&[]).expect("пустая среда = дефолты");
        assert_eq!(cfg.addr.port(), DEFAULT_PORT);
        assert!(cfg.addr.ip().is_loopback());
        assert_eq!(cfg.vault_mode, VaultMode::Stateless);
        assert_eq!(cfg.threads, DEFAULT_THREADS);
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert!(cfg.thresholds.is_sane());
        assert_eq!(cfg.model_dir, None);
        assert_eq!(cfg.schema_path, None);
        assert_eq!(cfg.stage(), "cascade-0-only");
    }

    #[test]
    fn non_loopback_bind_is_refused_not_defaulted() {
        let err = cfg_from(&[("FASAD_BIND", "0.0.0.0")]).unwrap_err();
        assert!(matches!(err, ConfigError::BindNotLoopback(_)), "{err:?}");
        let err = cfg_from(&[("FASAD_BIND", "не-айпи")]).unwrap_err();
        assert!(matches!(err, ConfigError::BindUnparsable(_)), "{err:?}");
        // В6 (::1) — тоже loopback и тоже принимается.
        let cfg = cfg_from(&[("FASAD_BIND", "::1")]).expect("IPv6 loopback валиден");
        assert!(cfg.addr.ip().is_loopback());
    }

    #[test]
    fn port_env_survives_and_garbage_falls_back() {
        let cfg = cfg_from(&[("FASAD_PORT", "9999")]).expect("порт читается");
        assert_eq!(cfg.addr.port(), 9999);
        let cfg = cfg_from(&[("FASAD_BIND", "127.0.0.1"), ("FASAD_PORT", "мусор")])
            .expect("порт по дефолту");
        assert_eq!(cfg.addr.port(), DEFAULT_PORT);
        assert_eq!(port_from_value(Some(" 1234 ")), 1234);
        assert_eq!(port_from_value(Some("70000")), DEFAULT_PORT);
        assert_eq!(port_from_value(None), DEFAULT_PORT);
    }

    #[test]
    fn insane_thresholds_are_refused_as_a_block() {
        // gray_lo > gray_hi: арбитр вызывался бы на пустом множестве.
        let err = cfg_from(&[("FASAD_GRAY_LO", "0.9"), ("FASAD_GRAY_HI", "0.5")]).unwrap_err();
        assert!(matches!(err, ConfigError::ThresholdsInsane(_)), "{err:?}");
        // τ_low выше τ_high: нечего ни принять, ни отдать арбитру.
        assert!(matches!(
            cfg_from(&[("FASAD_TAU_LOW", "0.9")]).unwrap_err(),
            ConfigError::ThresholdsInsane(_)
        ));
        // Вне [0,1].
        assert!(matches!(
            cfg_from(&[("FASAD_TAU_HIGH", "1.5")]).unwrap_err(),
            ConfigError::ThresholdsInsane(_)
        ));
        // NaN до in_unit вообще не доходит: float_or отбраковывает его как
        // непарсящееся значение — отказ с другим текстом, но тоже отказ.
        assert!(matches!(
            cfg_from(&[("FASAD_TAU_LOW", "nan")]).unwrap_err(),
            ConfigError::BadNumber { .. }
        ));
        // tau_low == tau_high (всё выговорено, ничего не остаётся арбитру) —
        // инвариант 4 (tau_low < gray_hi) при gray_hi = tau_high ловит это.
        assert!(matches!(
            cfg_from(&[("FASAD_TAU_LOW", "0.8"), ("FASAD_TAU_HIGH", "0.8")]).unwrap_err(),
            ConfigError::ThresholdsInsane(_)
        ));
    }

    #[test]
    fn working_tau_pair_from_amendment_is_accepted() {
        // docs/quant-policy.md §3 п.2a: HARD-гейт действует на рабочих τ ∈ {0.20, 0.25}.
        for tau in ["0.20", "0.25"] {
            let cfg = cfg_from(&[("FASAD_TAU_LOW", tau)]).expect("рабочее τ принимается");
            assert!((cfg.thresholds.tau_low - tau.parse::<f64>().unwrap()).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn vault_mode_accepts_numbers_and_words_and_rejects_rest() {
        assert_eq!(VaultMode::parse("2"), Some(VaultMode::Session));
        assert_eq!(VaultMode::parse(" session "), Some(VaultMode::Session));
        assert_eq!(VaultMode::parse("STATELESS"), Some(VaultMode::Stateless));
        assert_eq!(VaultMode::parse("1"), None);
        let err = cfg_from(&[("FASAD_VAULT_MODE", "1")]).unwrap_err();
        assert_eq!(err, ConfigError::VaultModeUnknown("1".to_owned()));
    }

    #[test]
    fn zero_and_garbage_numbers_are_errors_not_defaults() {
        // Нулевой потолок тела = «ничего не пропускать»; молча подставить дефолт
        // означало бы замаскировать опечатку в развёртывании.
        for (var, val) in [
            ("FASAD_MAX_BODY_BYTES", "0"),
            ("FASAD_THREADS", "abc"),
            ("FASAD_TIMEOUT_MS", "-1"),
        ] {
            let err = cfg_from(&[(var, val)]).unwrap_err();
            assert!(
                matches!(err, ConfigError::BadNumber { .. }),
                "{var}={val} → {err:?}"
            );
        }
    }

    #[test]
    fn schema_override_is_a_path_not_a_fallback() {
        let cfg =
            cfg_from(&[("FASAD_SCHEMA", "/etc/fasad/schema.json")]).expect("путь принимается");
        assert_eq!(
            cfg.schema_path.unwrap().to_string_lossy(),
            "/etc/fasad/schema.json"
        );
    }

    #[test]
    fn model_dir_switches_stage_label() {
        let cfg = cfg_from(&[("FASAD_MODEL_DIR", "/tmp/w")]).expect("дир весов");
        assert_eq!(cfg.stage(), "cascade-0+models");
        assert_eq!(cfg.model_dir.unwrap().to_string_lossy(), "/tmp/w");
    }

    #[test]
    fn display_names_the_variable_that_broke() {
        // Диагностическая строка — часть контракта: оператор читает её, а не код.
        let err = cfg_from(&[("FASAD_THREADS", "0")]).unwrap_err();
        assert!(err.to_string().contains("FASAD_THREADS"), "{err}");
        let err = cfg_from(&[("FASAD_BIND", "8.8.8.8")]).unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }
}
