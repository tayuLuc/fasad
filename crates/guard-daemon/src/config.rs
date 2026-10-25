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
use std::path::PathBuf;

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

/// Потолок форм суррогатов на одну сессию (режим 2), в формах.
///
/// Одна ФИО-подмена даёт до 4 форм, т.е. 1024 — это ~256 ФИО. Лимит достижим
/// в пределах одного запроса: то же `DEFAULT_MAX_BODY_BYTES` вмещает порядка
/// 20 000 спанов, значит формы кончаются раньше тела. Поэтому переполнение —
/// отказ `422 too_many_forms` до первой подмены (`Vault::anonymize`), а не
/// тихая потеря формы: второе превращает `/v1/deanonymize` в partial-restore
/// без ошибки, то есть в fail-open на данных.
///
/// Шаг 8 (UI + клиентские лимиты) вправе цифру пересмотреть: она одна, в
/// конфиге, а не размазана по коду.
pub const MAX_FORMS_PER_SESSION: usize = 1_024;

/// Дефолты `τ` — ре-экспорт из `guard_onnx::routing` (атом 7b, issue #60):
/// единственный источник чисел — lib, по которой мерит харнес
/// `recall_golden` (инвариант «меряем = гоняем»); таблица промера
/// 94.74@0.20 / 92.98@0.25 живёт в doc констант там. Дублировать литералы
/// в демоне запрещено. Здесь остаются только env-переопределения
/// `FASAD_TAU_LOW`/`FASAD_TAU_HIGH` и совместная проверка согласованности
/// [`Thresholds::is_sane`].
pub use guard_onnx::routing::{DEFAULT_TAU_HIGH, DEFAULT_TAU_LOW};

/// Нижняя граница серой зоны арбитража (SPEC §2 каскад 2; TODO из
/// `guard-onnx/src/lib.rs` п.4b-3 закрыт значением 0.22, промер — атом E).
pub const DEFAULT_GRAY_LO: f64 = 0.22;

/// Верхняя граница серой зоны арбитража.
pub const DEFAULT_GRAY_HI: f64 = 0.80;

/// Вес `α` смешивания `S = α·p1 + (1−α)·p2` (SPEC §2 каскад 2, серая зона).
///
/// Числа в SPEC нет — `α` **не калибрована**, это наше решение, а не цифра
/// транскрипта (AGENTS §Дисциплина фактов: число из SPEC без промера = `[claim]`).
/// Взят `0.5` = равновес арбитров: он симметричен, не требует веры в один из
/// каскадов и калибруется прогоном `#14` на golden-наборе, не правкой кода.
/// Ручка `FASAD_ARBITER_ALPHA` заведена ровно для этого промера.
pub const DEFAULT_ALPHA: f64 = 0.5;

/// Потоки ORT по умолчанию: 8 — значение, под которым снимались первичные
/// замеры parity/recall (`docs/quant-policy.md` §3 п.2b: дефолт 4 даёт ±1 tp на
/// Decide, т.е. метрика становится функцией от потока).
pub const DEFAULT_THREADS: usize = 8;

/// Бюджет латентности запроса, мс (SPEC §1: 80–300 мс). Превышение = ошибка
/// конвейера, а не «подожём»: middleware обязан ответить 5xx раньше, чем клиент
/// решит, что гард просто молчит (AGENTS §Инженерные инварианты, Fail-Closed).
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// Бюджет ожидания **входящего** тела, мс (`FASAD_READ_TIMEOUT_MS`).
///
/// Отличается от [`DEFAULT_TIMEOUT_MS`] направлением: тот — сколько мы держим
/// конвейер на один запрос, этот — сколько клиент имеет право молчать, дрипая
/// телом. Риск был зафиксирован в README §Fail-closed п.4 именно как «отдельная
/// ручка на таймаут входящего тела, НЕ `FASAD_TIMEOUT_MS`»; закрыт шагом 7c.
/// Капается по каждому куску тела, а не по телу целиком: медленно капающее тело
/// не обязан быть медленным целиком, но бесконечное удержание соединения —
/// отказ, и назван он `408 read_timeout`, а не 413 (ложь о причине = тот же
/// fail-open в диагностике).
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;

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

/// Политика залочкивания буферов с оригиналами (`FASAD_MLOCK`).
///
/// Дефолт — [`Self::Strict`] по AGENTS («все буферы с `ПДн`: `ZeroizeOnDrop` +
/// mlock/`VirtualLock`»). `BestEffort` — явный выбор оператора для окружений,
/// где залочить нечем: `RLIMIT_MEMLOCK` на CI-раннерах и Windows без
/// `SeLockMemoryPrivilege` (issue #55 пока не подписан, т.е. работоспособность
/// mlock на двух ОС документально не закрыта — см. README демона). Буфер при
/// этом всё равно обнуляется на drop, снимается только гарантия «не свопнётся».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mlock {
    /// Не залоченный буфер = отказ запроса (fail-closed).
    Strict,
    /// Незалоченный, но обнуляемый буфер допустим по явному решению оператора.
    BestEffort,
}

impl Mlock {
    /// Разбор значения env: `strict|1` → [`Self::Strict`],
    /// `best_effort|off` → [`Self::BestEffort`].
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "strict" | "1" | "on" => Some(Self::Strict),
            "best_effort" | "off" | "0" => Some(Self::BestEffort),
            _ => None,
        }
    }

    /// Каноническое имя для `/health` и логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::BestEffort => "best_effort",
        }
    }

    /// Политический выбор для [`guard_vault::MlockPolicy`].
    #[must_use]
    pub const fn policy(self) -> guard_vault::MlockPolicy {
        match self {
            Self::Strict => guard_vault::MlockPolicy::Strict,
            Self::BestEffort => guard_vault::MlockPolicy::BestEffort,
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
    /// Вес `α` смешивания скора в серой зоне (`FASAD_ARBITER_ALPHA`, SPEC §2).
    /// Лежит в [`Thresholds`] рядом с границами серой зоны намеренно: `α` без
    /// зоны бессмысленна, и валидируются они одним `is_sane`.
    pub alpha: f64,
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
            alpha: DEFAULT_ALPHA,
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
            // 5. `α` — вес, а не настройка «на глаз за пределами смысла»:
            //    вне `[0, 1]` смесь `α·p1+(1−α)·p2` перестаёт быть выпуклой и
            //    выдаёт скоры за пределами `[0, 1]`, которые контракт
            //    `AnnotatedSpan::new` отвергает уже в конвейере.
            && in_unit(self.alpha)
    }
}

/// Каталог конфигурации по первичке канона XDG (`$XDG_CONFIG_HOME`, дефолт
/// `$HOME/.config`) — unix и macOS одинаково.
///
/// macOS — НЕ `~/Library/Preferences`: канон, по которому живут переносимые
/// конфигурации, здесь именно XDG-форма, и она же резолвится на linux.
/// `dirs`-крейт в дереве нет (промер `cargo tree -i dirs` —
/// docs/dep-verify-crates.md §17), поэтому путь собирается чтением env из
/// `std`: второй правды о домашнем каталоге не появляется.
#[must_use]
pub fn config_dir_from_env<L>(mut lookup: L) -> Option<std::path::PathBuf>
where
    L: FnMut(&'static str) -> Option<String>,
{
    // XDG-канон: `$XDG_CONFIG_HOME/fasad` (сам XDG = уже «.config»),
    // дефолт-форма `$HOME/.config/fasad`.
    if let Some(xdg) = lookup("XDG_CONFIG_HOME")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        return Some(std::path::Path::new(&xdg).join("fasad"));
    }
    let home = lookup("HOME")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())?;
    Some(std::path::Path::new(&home).join(".config").join("fasad"))
}

/// Каталог конфигурации на Windows: `%APPDATA%\fasad` (roaming-профиль —
/// win-нэйтив без XDG-обходов; паритет `scripts/fetch-models.ps1`, который
/// пишет кеш весов в `%USERPROFILE%\.cache\fasad-models`).
#[must_use]
pub fn config_dir_from_appdata(appdata: Option<&str>) -> Option<std::path::PathBuf> {
    appdata
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|a| std::path::Path::new(a).join("fasad"))
}

/// Имя файла конфигурации: без `.toml`/`.cfg` — расширение приглашало бы
/// парсер, которого в дереве нет (формат = KV, см. [`parse_config_file`]).
pub const CONFIG_FILE_NAME: &str = "config";

/// Откуда взят путь файла конфигурации — семантика отсутствия файла РАЗНАЯ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathOrigin {
    /// Путь назван оператором в `FASAD_CONFIG`: файла нет = **отказ старта**
    /// ([`ConfigError::MissingExplicitPath`]) — опечатка в пути обязана быть
    /// названа (#185-контур), а не съедена молча.
    Explicit,
    /// Путь резолвнут из канона (`%APPDATA%`/`XDG_CONFIG_HOME`/`HOME`):
    /// файла нет = **дефолты** (у свежепоставленного пользователя файла нет,
    /// и отказывать ему — ломать README §Файл конфигурации: регресс
    /// fresh-install, ревью #224 блокер).
    Resolved,
}

/// Файл конфигурации: путь + происхождение (`None` = искать негде).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath {
    /// Сам путь.
    pub path: std::path::PathBuf,
    /// Явный (`FASAD_CONFIG`) или резолвнутый из канона.
    pub origin: ConfigPathOrigin,
}

impl ConfigPath {
    /// Путь, названный оператором в `FASAD_CONFIG` (файла нет = отказ).
    #[must_use]
    pub fn explicit(path: std::path::PathBuf) -> Self {
        Self {
            path,
            origin: ConfigPathOrigin::Explicit,
        }
    }

    /// Путь, резолвнутый из канона (файла нет = дефолты).
    #[must_use]
    pub fn resolved(path: std::path::PathBuf) -> Self {
        Self {
            path,
            origin: ConfigPathOrigin::Resolved,
        }
    }
}

/// Путь файла конфигурации, который будет прочитан.
///
/// Порядок: `FASAD_CONFIG` (явный = выигрывает всё; **пустой = unset**,
/// первичка env-контра: пустое env = «оператор ничего не сказал», а не
/// «путь-в-никуда») → win: `%APPDATA%\fasad` → unix/mac:
/// `$XDG_CONFIG_HOME/fasad`, если XDG задан, иначе `$HOME/.config/fasad`.
/// `None` = искать негде (ни явного пути, ни `HOME`/`APPDATA`/
/// `XDG_CONFIG_HOME`) = «файла нет» = env + дефолты.
#[must_use]
pub fn config_file_path<L>(mut lookup: L) -> Option<ConfigPath>
where
    L: FnMut(&'static str) -> Option<String>,
{
    config_file_path_from(&mut lookup)
}

/// [`config_file_path`] с `FnMut` (зовётся и из env-цепочки, и из тестов).
#[must_use]
pub fn config_file_path_from<L>(lookup: &mut L) -> Option<ConfigPath>
where
    L: FnMut(&'static str) -> Option<String>,
{
    if let Some(explicit) = lookup("FASAD_CONFIG")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        return Some(ConfigPath::explicit(std::path::PathBuf::from(explicit)));
    }
    let dir = if cfg!(windows) {
        config_dir_from_appdata(lookup("APPDATA").as_deref())
            .or_else(|| config_dir_from_env(&mut *lookup))
    } else {
        config_dir_from_env(&mut *lookup)
    };
    dir.map(|d| ConfigPath::resolved(d.join(CONFIG_FILE_NAME)))
}

/// Одна строка файла конфигурации, уже разобранная.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Ключ env-канона (`FASAD_PORT`).
    pub key: &'static str,
    /// Значение после trim (пустое = «override снят», см. [`Self::is_empty`]).
    pub value: String,
    /// 1-номер строки в файле: отказ обязан называть место, а не «что-то не так».
    pub line: usize,
}

impl FileEntry {
    /// Пустое значение = override снят, работает дефолт. Отказ — не пустое
    /// значение (оператор снял значение, а не вписал опечатку), а битая строка.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

/// Разобранный файл конфигурации (записи + предупреждения).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileConfig {
    /// Записи в порядке файла.
    pub entries: Vec<FileEntry>,
    /// Предупреждения о неизвестных ключах: их печатает `main` в stderr
    /// ([`ConfigError`] не возвращаются — warning не отказ), юнит меряет
    /// вектор (eprintln из lib тесту невидим, ложь-зелёная та же).
    pub warnings: Vec<String>,
}

impl FileConfig {
    /// Ни одной записи = файл эквивалентен отсутствию.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Значение ключа из файла (`None` = ключа нет). Пустое значение
    /// возвращается пустой строкой: решение «пустое = дефолт» принимает
    /// [`Config::from_lookup`] на общей для env и файла границе.
    #[must_use]
    pub fn value_of(&self, key: &'static str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Множество ключей, заданных файлом (для [`Config::source_of`]).
    #[must_use]
    pub fn keys(&self) -> Vec<&'static str> {
        self.entries.iter().map(|e| e.key).collect()
    }
}

/// Разбор файла конфигурации: KV-грамматика, единая точка отказов.
///
/// Грамматика (она же — README §Файл конфигурации):
///
/// 1. пустая строка и строка, начинающаяся с `#` после trim, = комментарий;
/// 2. `KEY=значение`: ровно одна `=` на строку, пробелы вокруг `=` и по краям
///    снимаются, CRLF снимается;
/// 3. секций, кавычек, переносов и escape-последовательностей нет: формат
///    намеренно = подмножество env-имён, чтобы разбор значений был общим;
/// 4. **неизвестный ключ = предупреждение**, не отказ: файл переживает релиз,
///    добавивший ключ (future-proof), а молчание о проигнорированной строке
///    запрещено — warning несёт номер строки;
/// 5. **ключ из [`FORBIDDEN_FILE_KEYS`] = отказ старта**
///    ([`ConfigError::FileKeyForbidden`]): предупреждение здесь означало бы
///    «секрет лёг на диск открытым текстом, а демон сделал вид, что не заметил»;
/// 6. **строка без `=` = отказ старта** ([`ConfigError::FileMalformed`]) с
///    номером строки: молча проигнорированная строка = «опечатка, конфигурация
///    не та»;
/// 7. значение бьётся тем же валидатором, что env ([`Config::from_lookup`]).
///
/// Файл читается ОДИН раз на старте ([`Config::load_config`]): hot-reload вне
/// контура #219 (монтаж весов и сокет = старт-время).
///
/// # Errors
///
/// [`ConfigError::FileMalformed`] — строка без `=`;
/// [`ConfigError::FileKeyForbidden`] — ключ вне белого списка.
pub fn parse_config_file(text: &str) -> Result<FileConfig, ConfigError> {
    let mut parsed = FileConfig::default();
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_end_matches('\r').trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line = idx + 1;
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(ConfigError::FileMalformed {
                line,
                text: trimmed.to_owned(),
            });
        };
        let key = key.trim();
        let value = value.trim().to_owned();
        // Запрет проверяется ПО ФОРМЕ ключа, до сверки с белым списком:
        // `FASAD_VAULT_KEY` = отказ, а не «неизвестный ключ» (секрет на диске
        // обязан быть назван, а не списан в игнор).
        if let Some(reason) = forbidden_file_key_reason(key) {
            return Err(ConfigError::FileKeyForbidden {
                key: key.to_owned(),
                line,
                reason,
            });
        }
        match allowed_key(key) {
            Some(canonical) => parsed.entries.push(FileEntry {
                key: canonical,
                value,
                line,
            }),
            None => parsed.warnings.push(format!(
                "файл конфигурации, строка {line}: неизвестный ключ {key} — игнорируется"
            )),
        }
    }
    Ok(parsed)
}

/// Причина, по которой ключу файл конфигурации закрыт (`None` = запрет не
/// назван). Каждый запрет — первичка инварианта, а не вкус:
///
/// - `FASAD_VAULT_KEY`: AGENTS §Инженерные инварианты «никаких секретов на
///   диске в открытом виде»; файл = пользовательский plaintext.
/// - `FASAD_BIND`: loopback-инвариант (SPEC §1 п.6) задаётся при запуске
///   (env/юнит), а не пользовательским файлом.
/// - `FASAD_TEST_CASCADE0` / `FASAD_TEST_TRAY_CONTOUR`: харнес-контур
///   (#192/#203); файл, задающий их, делал бы из релизного бинаря каскад-0
///   молча — ровно тот класс, который #185 убил стартовым отказом.
/// - `FASAD_CONFIG`: путь файла задаётся окружением; файл, описывающий сам
///   себя, = цикл.
/// - `FASAD_MLOCK`: политика залочки буферов `ПДн` = решение развёртывания
///   (rlimit/привилегии), его держат рядом с `FASAD_BIND` в env.
#[must_use]
pub fn forbidden_file_key_reason(key: &str) -> Option<&'static str> {
    match key {
        "FASAD_VAULT_KEY" => Some(
            "секрет шифрования ПДн в файле = открытый текст на диске (AGENTS: \
             никаких секретов в открытом виде); только env FASAD_VAULT_KEY",
        ),
        "FASAD_BIND" => Some(
            "адрес прослушивания = инвариант loopback (SPEC §1 п.6): только env \
             FASAD_BIND, не пользовательский файл",
        ),
        "FASAD_TEST_CASCADE0" | "FASAD_TEST_TRAY_CONTOUR" => Some(
            "флаг тестового контура: файл не имеет права делать из релизного \
             бинаря каскад-0-харнес; только env",
        ),
        "FASAD_CONFIG" => {
            Some("путь файла конфигурации задаётся окружением, сам файл его не задаёт")
        }
        "FASAD_MLOCK" => Some(
            "политика залочки буферов ПДн = решение развёртывания (rlimit, \
             привилегии); только env FASAD_MLOCK",
        ),
        _ => None,
    }
}

/// Ключ, которому файл конфигурации закрыт ЯВНО (не «неизвестный», а «нельзя»).
#[must_use]
pub fn is_forbidden_file_key(key: &str) -> bool {
    forbidden_file_key_reason(key).is_some()
}

/// Разрешённый ключ файла: имя, подпись для UI, право на UI-запись.
#[derive(Debug, Clone, Copy)]
pub struct FileKey {
    /// Имя env-канона: файл использует ровно его, второй грамматики имён нет.
    pub key: &'static str,
    /// Человекочитая подпись (UI, #219 atom-2).
    pub label: &'static str,
    /// Разрешена ли запись из UI (`POST /v1/config`). `false` = только файл/env.
    pub ui_editable: bool,
}

/// Реестр разрешённых ключей файла = подмножество env-канона (первичка
/// README §Переменные). Только то, что безопасно отдавать пользовательскому
/// файлу и странице «Настройки» (#219 atom-2, белый список issue §D).
///
/// **Перезапуск нужен у каждой строки**: значения применяются на старте
/// (монтаж весов, пороги, сокеты), hot-reload вне контура #219 — поле
/// `restart_required` в `/v1/config` поэтому константа `true`, а не флаг.
pub const FILE_ALLOWED_KEYS: &[FileKey] = &[
    FileKey {
        key: "FASAD_MODEL_DIR",
        label: "Каталог весов каскадов 1–2",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_PORT",
        label: "Порт (только loopback)",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_THREADS",
        label: "Потоки инференса",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_TIMEOUT_MS",
        label: "Бюджет конвейера, мс",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_READ_TIMEOUT_MS",
        label: "Бюджет тишины клиента, мс",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_MAX_BODY_BYTES",
        label: "Лимит тела запроса, байт",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_VAULT_MODE",
        label: "Режим хранилища (2|3|session|stateless)",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_GRAY_LO",
        label: "Низ серой зоны арбитра",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_GRAY_HI",
        label: "Верх серой зоны арбитра",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_TAU_LOW",
        label: "Порог извлечения τ_low",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_TAU_HIGH",
        label: "Порог уверенности τ_high",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_ARBITER_ALPHA",
        label: "Вес α смешивания арбитров",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_UPSTREAM_ALLOWLIST",
        label: "Разрешённые upstream (host[:port], через запятую)",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_PROXY_LOOPBACK_HTTP",
        label: "Разрешить http:// к loopback-upstream",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_HF_HOST",
        label: "Хост загрузки весов",
        ui_editable: true,
    },
    FileKey {
        key: "FASAD_SCHEMA",
        label: "Путь к своей схеме классов",
        // Только файл/env: редактор схемы = отдельный контур (SPEC §10 п.8);
        // #219 §«Не делаем»: «схема классов = UI».
        ui_editable: false,
    },
];

/// Каноническое имя разрешённого ключа (регистронезависимо: оператор пишет в
/// файле `fasad_port` и имеет в виду `FASAD_PORT`).
#[must_use]
pub fn allowed_key(key: &str) -> Option<&'static str> {
    FILE_ALLOWED_KEYS
        .iter()
        .find(|k| k.key.eq_ignore_ascii_case(key))
        .map(|k| k.key)
}

/// Ключ редактируется из UI (`POST /v1/config`, #219 atom-2).
#[must_use]
pub fn ui_editable_key(key: &str) -> bool {
    FILE_ALLOWED_KEYS
        .iter()
        .any(|k| k.ui_editable && k.key.eq_ignore_ascii_case(key))
}

/// Источник значения одной настройки (контент `GET /v1/config`, #219 atom-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    /// Значение взято из окружения процесса.
    Env,
    /// Значение взято из файла конфигурации.
    File,
    /// Значения нигде нет — работает дефолт.
    Default,
}

impl ValueSource {
    /// Каноническое имя для JSON-ответа `/v1/config`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
            Self::Default => "default",
        }
    }
}

/// Запись `GET /v1/config`: настройка, её эффективное значение, источник.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigView {
    /// Ключ env-канона.
    pub key: &'static str,
    /// Человекочитая подпись.
    pub label: &'static str,
    /// Эффективное значение env > файл > дефолт, в канонической строковой форме.
    pub value: String,
    /// Откуда оно взялось.
    pub source: ValueSource,
    /// Можно ли менять из UI (`POST /v1/config`).
    pub ui_editable: bool,
    /// Требуется перезапуск после записи (константа `true`, см.
    /// [`FILE_ALLOWED_KEYS`]).
    pub restart_required: bool,
}

/// Ключи, которые наружу значением НЕ отдаются никогда (секреты).
pub const SECRET_KEYS: &[&str] = &["FASAD_VAULT_KEY"];

/// Строка «задан/нет» для секрета: `GET /v1/config` обязан сказать «ключ есть»,
/// не показав ни одного байта ключа.
#[must_use]
pub fn secret_present(raw: Option<&str>) -> &'static str {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(_) => "задан",
        None => "нет",
    }
}

/// Результат загрузки конфигурации процесса (`main`-контур #219).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// Собранная конфигурация.
    pub config: Config,
    /// Путь файла, который искали (`None` = искать было негде).
    pub path: Option<std::path::PathBuf>,
    /// Предупреждения файла (неизвестные ключи): печатает `main` в stderr.
    pub warnings: Vec<String>,
    /// Файл существовал и дал хотя бы одну запись.
    pub file_used: bool,
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
    /// Политика залочкивания (`FASAD_MLOCK`), см. [`Mlock`].
    pub mlock: Mlock,
    /// Путь к файлу схемы классов (`FASAD_SCHEMA`); `None` = встроенный канон
    /// [`crate::schema::DEFAULT_SCHEMA_JSON`]. Override читается на старте и
    /// отказывает в старте, если испорчен — молча откатиться на дефолт значит
    /// игнорировать волю оператора.
    pub schema_path: Option<std::path::PathBuf>,
    /// Бюджет тишины между кусками входящего тела, мс
    /// (`FASAD_READ_TIMEOUT_MS`).
    pub read_timeout_ms: u64,
    /// Разрешённые upstream'ы прокси (`FASAD_UPSTREAM_ALLOWLIST`, SPEC §8:
    /// «никаких сетевых вызовов кроме явного `X-Upstream-URL`»). Пустой список
    /// — прокси выключен: каждый запрос на `/v1/chat/completions` получает 403
    /// `allowlist_empty`, потому что молча разрешить адрес из заголовка значит
    /// сделать из гарда open-recursive relay.
    pub upstream_allowlist: Vec<AllowedHost>,
    /// Ключи, заданные файлом конфигурации (#219): нужны `source_of` для
    /// `GET /v1/config`. `None` = конфигурация собрана без файла (харнеси,
    /// env-граница) — тогда «файл» как источник не заявляется.
    pub file_keys: Option<Vec<&'static str>>,
    /// Значения файла (ключ → значение) для потребителей ВНЕ полей `Config`
    /// (ревью #224 MAJOR-2: `FASAD_HF_HOST` живёт в `FetchConfig`, и витрина
    /// с fetch обязаны видеть файловое значение, иначе key в белом списке =
    /// мёртвый груз: GET врёт source, fetch потребляет env). `None` = конфиг
    /// собран без файла (харнеси/env-граница).
    pub file_values: Option<std::collections::BTreeMap<&'static str, String>>,
    /// Разрешить `http://` к loopback-upstream (`FASAD_PROXY_LOOPBACK_HTTP`).
    /// Исключительно тестовая аффорданс: TLS-терминация на тестовом эхо-сервере означал бы либо самоподписанные сертификаты в тесте, либо отказ
    /// тестировать прокси вовсе. Даже включённый флаг не выпускает трафик за
    /// пределы машины (см. [`Config::loopback_http_permitted`]).
    pub proxy_loopback_http: bool,
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
    /// `FASAD_MLOCK` не `strict|best_effort` (в том числе `relaxed`: мягкого
    /// mlock не бывает, есть явный отказ от гарантии).
    MlockUnknown(String),
    /// Числовое поле не парсится или нулевое.
    BadNumber {
        /// Имя переменной.
        var: &'static str,
        /// Что нашли.
        value: String,
    },
    /// `FASAD_UPSTREAM_ALLOWLIST`: элемент не является `host[:port]`. Отказ на
    /// старте, а не на запросе: молча проигнорированный элемент списка — это
    /// дырка, о которой оператор не знает.
    BadAllowlist {
        /// Имя переменной.
        var: &'static str,
        /// Что нашли.
        value: String,
    },
    /// Булево поле не `0|1|true|false|on|off`.
    BadBool {
        /// Имя переменной.
        var: &'static str,
        /// Что нашли.
        value: String,
    },
    /// Файл конфигурации: строка без `=` ([`parse_config_file`], п.6). Номер
    /// строки обязателен: «битый конфиг» без места = оператор идёт смотреть
    /// весь файл глазами.
    FileMalformed {
        /// 1-номер строки.
        line: usize,
        /// Содержимое строки (файл конфигурации = пользовательский текст, `ПДн`
        /// в нём быть не должно; ключ и значение печатаются как есть).
        text: String,
    },
    /// Файл конфигурации задал ключ, которому там закрыто (`FASAD_VAULT_KEY`,
    /// `FASAD_BIND`, харнес-флаги) — причина в тексте отказа
    /// ([`forbidden_file_key_reason`]).
    FileKeyForbidden {
        /// Ключ как его написали.
        key: String,
        /// 1-номер строки.
        line: usize,
        /// Причина запрета (первичка инварианта, см. `forbidden_file_key_reason`).
        reason: &'static str,
    },
    /// Значение ключа отвергнуто его собственным валидатором (`POST
    /// /v1/config` #224: текст = первичка причины, а не шаблон «не число»:
    /// `FASAD_PORT` называет диапазон, `FASAD_HF_HOST` — класс отказа fetch-парсера).
    BadValue {
        /// Имя переменной (env-канон).
        var: &'static str,
        /// Причина (готовый человекочитаемый текст).
        reason: String,
    },
    /// Явный `FASAD_CONFIG` указывает на несуществующий файл. Отказ, а не
    /// дефолты: опечатка в пути = «демон работает не так, как просили», и
    /// молчать об этом нельзя (#185-контур).
    MissingExplicitPath {
        /// Путь.
        path: String,
        /// Что сказал `std::fs`.
        reason: String,
    },
    /// Файл конфигурации есть, но не читается (права, каталог вместо файла,
    /// не-UTF-8). Отказ, а не дефолты: тот же контур, что у `FASAD_SCHEMA`.
    FileUnreadable {
        /// Путь.
        path: String,
        /// Что сказал `std::fs`.
        reason: String,
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
            Self::MlockUnknown(raw) => {
                write!(f, "FASAD_MLOCK={raw:?}: ожидается strict|best_effort")
            }
            Self::VaultModeUnknown(raw) => write!(
                f,
                "FASAD_VAULT_MODE {raw:?}: допустимо 2|3|session|stateless"
            ),
            Self::BadNumber { var, value } => {
                write!(f, "{var}={value:?}: не число или нуль")
            }
            Self::BadAllowlist { var, value } => {
                write!(f, "{var}: элемент не формата `host[:port]` — {value:?}")
            }
            Self::BadBool { var, value } => {
                write!(f, "{var}={value:?}: допустимо 0|1|true|false|on|off")
            }
            Self::FileMalformed { line, text } => {
                write!(f, "файл конфигурации, строка {line}: нет `=` — {text:?}")
            }
            Self::FileKeyForbidden { key, line, reason } => {
                write!(
                    f,
                    "файл конфигурации, строка {line}: ключ {key} запрещён: {reason}"
                )
            }
            Self::MissingExplicitPath { path, reason } => {
                // Одна строка без переносов: док-формат `\` склеивал текст с
                // простынёю литеральных пробелов (ревью #224 MINOR), а
                // оператор читает именно эту строку.
                write!(
                    f,
                    "FASAD_CONFIG указывает на {path:?}, а файла нет ({reason}): опечатка в пути, а не «конфига нет»"
                )
            }
            Self::BadValue { var, reason } => {
                write!(f, "{var}: {reason}")
            }
            Self::FileUnreadable { path, reason } => {
                write!(f, "файл конфигурации {path:?} не читается: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Дефолтный каталог весов: кеш-контракт `scripts/fetch-models.sh:24`
/// (`$HOME/.cache/fasad-models`) и раскладка `cascades::onnx::OnnxMount::load`
/// (#192 требование A: «двойной клик → браузер, ноль консоли»).
///
/// Контур разрешённости (#192): при `FASAD_MODEL_DIR` unset каталог =
/// `$HOME/.cache/fasad-models`; при `HOME` unset (win cmd без `USERPROFILE`
/// попадается) — `None`, т.е. прежнее поведение отказа старта с текстом
/// (`cascades::startup`, рюлинг #185: смонтировать нечем = старт red, не
/// молчание). Явный `FASAD_MODEL_DIR` жив как override: дефолт подставляется
/// ТОЛЬКО на unset/пустое, и только на env-границе `from_env` (не в чистой
/// `from_lookup` — харнеси `from_lookup(|_| None)` остаются cascade-0).
pub const DEFAULT_MODEL_DIR_SUFFIX: &str = ".cache/fasad-models";

/// Значение дефолтного пути по `HOME` (unix; Git-Bash-win = `%USERPROFILE%`
/// под bash; ps1 #190 пишет в `$env:USERPROFILE\.cache\fasad-models` — тот же
/// путь, win-нэйтив) + суффикс. Только home, без `xdg`-обходов: скриптовый
/// контракт должен читаться в две секунды. `None` на пустом/отсутствующем
/// `HOME` — не краш, а прежнее поведение отказа старта с текстом (#185).
#[must_use]
pub fn default_model_dir_from_home(home: Option<&str>) -> Option<std::path::PathBuf> {
    home.map(str::trim)
        .filter(|h| !h.is_empty())
        .map(|h| std::path::Path::new(h).join(DEFAULT_MODEL_DIR_SUFFIX))
}

/// Порт из значения env: мусор = дефолт (эргономика, не безопасность — см.
/// заголовок модуля).
#[must_use]
pub fn port_from_value(raw: Option<&str>) -> u16 {
    raw.and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Строгий порт (контур ЗАПИСИ #224): `Ok(None)` = unset (дефолт), `Ok(p)` =
/// валидный порт, `Err` = мусор/привилегированный.
///
/// Диапазон = `0` ∪ `1024..=65535`:
/// - `0` легален и НУЖЕН: контракт «дай свободный порт» (README, баннер
///   `local_addr`), на нём ездят харнеси `wire_e2e`/`ui_sandbox`,
///   `verify-bundle.sh` и `measure-rss.sh` — отсечь его = валить харнеси;
/// - `1..=1023` = привилегированные (bind под обычным пользователем =
///   `PermissionDenied` rc=1 без внятного текста, #224 MINOR): отказ с
///   диапазоном в тексте; root-сценарий = env (юнит systemd), не UI-запись;
/// - мусор (`abc`, `8.5`, `65536`) = отказ (запись обязана отвергать ДО
///   записи, тихий фолбэк `port_from_value` = эргономика env-запуска, к
///   записи неприменима).
///
/// Единый валидатор env-файлового и POST-контуров (ревью #224: вызывается и
/// здесь, и в `validate_value` — расхождение «валидатор записи vs валидатор
/// чтения» порождает файл, на котором демон не стартует).
pub(crate) fn port_strict(raw: &str) -> Result<u16, ConfigError> {
    let port = raw
        .trim()
        .parse::<u16>()
        .map_err(|_| ConfigError::BadValue {
            var: "FASAD_PORT",
            reason: format!("{raw:?}: нужен порт 0 или 1024..=65535"),
        })?;
    if port > 0 && port < 1024 {
        return Err(ConfigError::BadValue {
            var: "FASAD_PORT",
            reason: format!(
                "порт {port} привилегированный (<1024): bind требует root; диапазон 0, 1024..=65535"
            ),
        });
    }
    Ok(port)
}

/// Порт контура ЗАПИСИ (#224 POST /v1/config, UI): `0` вне диапазона.
///
/// Почему границы различаются, а разбор — один ([`port_strict`]):
/// `FASAD_PORT=0` = «дай свободный порт» — контракт харнесей
/// (`wire_e2e`/`ui_sandbox` поднимают демон на нулевом порте и читают адрес
/// из баннера) и скриптов (`verify-bundle.sh`, `measure-rss.sh`); человеку из
/// формы «Настройки» нулевой порт не нужен (баннер «listening on :52143» =
/// сюрприз), а «свой свободный» он получает пустым полем = дефолт 8765.
pub(crate) fn port_strict_for_write(raw: &str) -> Result<u16, ConfigError> {
    let port = port_strict(raw)?;
    if port == 0 {
        return Err(ConfigError::BadValue {
            var: "FASAD_PORT",
            reason:
                "0 = «случайный порт» (контур харнесей/скриптов, env); из UI выберите 1024..=65535"
                    .to_owned(),
        });
    }
    Ok(port)
}

/// Env-граница с подстановками дефолта #192/#198 (вынесена из тела
/// [`Config::from_env`] без изменений, чтобы файловый слой #219 надстраивал над
/// ней цепочку env > файл > дефолт, не переписывая их).
pub(crate) fn env_boundary_lookup() -> impl FnMut(&'static str) -> Option<String> {
    |var: &'static str| {
        let v = std::env::var(var).ok();
        // #192 требование A: при unset/пустом `FASAD_MODEL_DIR` дефолт =
        // кеш-контракт `~/.cache/fasad-models` (double-click UX). Здесь, в
        // env-границе, а НЕ в чистой `from_lookup`: харнесы
        // `from_lookup(|_| None)` обязаны оставаться cascade-0-контуром
        // (тот же контракт, что тестовый `env_remove` в ui_sandbox/wire_e2e),
        // а живая env-машина оператора получает дефолт.
        //
        // Исключение для ТЕСТОВОГО КОНТУРА: `FASAD_TEST_CASCADE0=1` (Ставит
        // `Daemon::start` в ui_sandbox/wire_e2e) отключает подстановку —
        // каскад-0-бинарь с резолвнутым дефолтом падал бы
        // `BuiltWithoutInference` (дефолт = Some!), и тесты UI/pad-контура
        // краснели бы на машине с HOME. Машине оператора переменная не
        // нужна: она на пути без неё.
        // Симметрия харнеса (ревью #203 §2.1): `FASAD_TEST_CASCADE0` =
        // «харнес cascade-0», он отключает ОБЕ подстановки дефолта —
        // базовую #192 и #198-ветку смонтированного дефолта. На
        // трей-мишени с флагом был живой ALIVE-контур `models-pending`
        // (third outcome: stage харнесу врал, flag документирован как
        // cascade-0-харнес); теперь флаг на любой мишени = каскад-0
        // семантика (feature-off легально, full-бинарь = честный
        // `BuiltWithoutInference` текстом «бинарь без орт-контура», не
        // pending-ложью). Зубы (env-граница читает процесс-среде, юнит
        // = живой бинарь, первичка #192-контур): live-нога wire_e2e
        // `pending_flag_on_tray_contour_keeps_the_cascade0_harness`
        // (флаг+мишень+tmp-пустой HOME = cascade-0-only харнес, НЕ
        // pending) и харнес-дискриминатор `Daemon::start`
        // (`env_remove FASAD_TEST_TRAY_CONTOUR` = прогон с весами цел,
        // ревью #203 §2.1-провен 28/4 → 32/0).
        match var {
            "FASAD_MODEL_DIR" if std::env::var("FASAD_TEST_CASCADE0").is_ok() => {
                // Харнес cascade-0 с ЯВНО названным каталогом обязан
                // сохранить путь (feature-off = зуб `BuiltWithoutInference`
                // «бинарь без орт при названных весах», ZUB В verify-bundle):
                // подстановка дефолта здесь = stage-ложь харнеса.
                let explicit = v.filter(|x| !x.trim().is_empty());
                if explicit.is_some() {
                    return explicit;
                }
                // Симметрия (ревью #203 §2.1) ТОЛЬКО на трей-мишени
                // (compile-time cfg! + env-симуляция контура #198): трей
                // с флагом + смонтированным HOME-дефолтом (5/5) =
                // Some(каталог) = mounted-смысл (#198-зуб layout),
                // pending не заводится. На headless-мишени флаг = чистый
                // None = прежняя каскад-0-семантика харнеса wire_e2e
                // (#192): HOME=кеш оператора на feature-off давал Some =
                // `BuiltWithoutInference` = харнес красный (провен этого
                // прогона: stateless_roundtrip).
                let tray = cfg!(all(
                    feature = "tray",
                    any(target_os = "windows", target_os = "macos")
                )) || std::env::var("FASAD_TEST_TRAY_CONTOUR").is_ok();
                let resolved = std::env::var("HOME")
                    .ok()
                    .as_deref()
                    .and_then(|h| default_model_dir_from_home(Some(h)));
                if tray && crate::cascades::harness_dir_fully_mounted(&resolved) {
                    return resolved.map(|p| p.display().to_string());
                }
                None
            }
            // #198: симметричный ЗУБ — трей desktop-доставки (win/mac,
            // feature `tray`) с РЕЗОЛВНУТЫМ HOME-дефолтом, где раскладка
            // 5/5 СМОНТИРОВАНА, обязан стартовать МОНТИРОВАННЫМ
            // (model_dir=Some → mount → cascade-0+models). Ветка живёт
            // ВЫШЕ базовой (#192) именно потому, что match берёт первую
            // совпавшую ветку: смонтированный дефолт = Some(dir), пустой
            // дефолт = НЕ эта ветка (guard `layout_complete` ложный) →
            // базовая #192 = Some(default-dir) → `startup` Load-отказ →
            // pending-решётка main (#198 core). На feature-off/иной
            // мишени guard ложный всегда (cfg! константа) = прежнее
            // поведение (#185/#192 контуры целы; юниты:
            // `default_model_dir_from_home_*` (форма резолва),
            // `weights::tests::layout_complete_*` (5/5 против пустого),
            // `cascades::tests::pending_gate_is_tray_only_and_model_failures_only`
            // (решётка main на Load/ModelsNotConfigured),
            // `pending_flag_on_tray_contour_keeps_the_cascade0_harness`
            // (wire_e2e, live-флаг) + харнес-`env_remove` (ревью #203
            // §2.2: прежняя ссылка на несуществующий юнит).
            "FASAD_MODEL_DIR"
                if v.as_deref().is_none_or(|x| x.trim().is_empty())
                    && cfg!(all(
                        feature = "tray",
                        any(target_os = "windows", target_os = "macos")
                    ))
                    && std::env::var("FASAD_TEST_CASCADE0").is_err() =>
            {
                std::env::var("HOME").ok().as_deref().and_then(|h| {
                    default_model_dir_from_home(Some(h)).and_then(|p| {
                        crate::weights::layout_complete(&p).then(|| p.display().to_string())
                    })
                })
            }
            "FASAD_MODEL_DIR" => v.filter(|s| !s.trim().is_empty()).or_else(|| {
                std::env::var("HOME").ok().as_deref().and_then(|h| {
                    default_model_dir_from_home(Some(h)).map(|p| p.display().to_string())
                })
            }),
            _ => v,
        }
    }
}

impl Config {
    /// Собрать конфигурацию процесса: env > файл > дефолт, с предупреждениями
    /// файла. Граница запуска — её зовёт `main` (#219 atom-1).
    ///
    /// # Errors
    ///
    /// Любой [`ConfigError`]: `FASAD_CONFIG` указывает в никуда, файл битый,
    /// в файле запрещённый ключ, либо то, чем отказывает env-контур.
    pub fn load_config() -> Result<LoadedConfig, ConfigError> {
        let found = config_file_path(|k| std::env::var(k).ok());
        Self::load_config_at(found.as_ref())
    }

    /// [`Self::load_config`] с уже названным путём и его происхождением
    /// (путь — аргумент, не поиск: `main` и тесты зовут одну функцию).
    ///
    /// Семантика отсутствия файла РАЗНАЯ по происхождению пути (ревью #224
    /// блокер: неразличение = «свежая установка не стартует»):
    ///
    /// - [`ConfigPathOrigin::Resolved`] (путь из `HOME`/`XDG`/`APPDATA`):
    ///   файла нет = **дефолты** — у свежепоставленного пользователя файла
    ///   нет, отказывать ему = ломать README §Файл конфигурации;
    /// - [`ConfigPathOrigin::Explicit`] (путь из `FASAD_CONFIG`): файла нет =
    ///   [`ConfigError::MissingExplicitPath`] — опечатка в пути обязана быть
    ///   названа, а не съедена молча (fail-closed, #185-контур).
    ///
    /// # Errors
    ///
    /// См. [`Self::load_config`].
    pub fn load_config_at(found: Option<&ConfigPath>) -> Result<LoadedConfig, ConfigError> {
        let file = match found {
            None => FileConfig::default(),
            Some(found) => match std::fs::read_to_string(&found.path) {
                Ok(text) => parse_config_file(&text)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if found.origin == ConfigPathOrigin::Resolved {
                        // Канонический путь, файла нет = дефолты (fresh-install).
                        FileConfig::default()
                    } else {
                        return Err(ConfigError::MissingExplicitPath {
                            path: found.path.display().to_string(),
                            reason: e.to_string(),
                        });
                    }
                }
                Err(e) => {
                    return Err(ConfigError::FileUnreadable {
                        path: found.path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            },
        };
        Self::from_file_aware(&file, found.map(|f| f.path.as_path()))
    }

    /// Цепочка env > файл > дефолт поверх уже разобранного файла.
    ///
    /// env обязан быть НЕПУСТЫМ, чтобы победить файл: `FASAD_PORT=` (пустой
    /// env) = «оператор ничего не сказал», и молча затереть значение файла
    /// пустой строкой = «ложь о причине отказа» на уровне диагностики.
    /// Значение из файла при этом идёт в `from_lookup` как есть, включая
    /// пустое: «пустое = дефолт» решает единый валидатор, а не два места.
    ///
    /// # Errors
    ///
    /// См. [`Self::from_lookup`].
    pub fn from_file_aware(
        file: &FileConfig,
        path: Option<&std::path::Path>,
    ) -> Result<LoadedConfig, ConfigError> {
        Self::from_file_aware_with_lookup(file, |k| std::env::var(k).ok(), path.map(PathBuf::from))
    }

    /// Тело [`Self::from_file_aware`] с инжектируемым env-слоем (зуб
    /// `fresh_install_without_config_file_loads_defaults` прогоняет
    /// продуктивную цепочку без среды процесса).
    ///
    /// # Errors
    ///
    /// См. [`Self::from_lookup`].
    fn from_file_aware_with_lookup<L>(
        file: &FileConfig,
        mut env: L,
        path: Option<PathBuf>,
    ) -> Result<LoadedConfig, ConfigError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        let cfg = Self::from_file_aware_with(|k| match env(k) {
            Some(v) if !v.trim().is_empty() => Some(v),
            _ => file.value_of(k).map(str::to_owned),
        })?
        .with_file_origin(file);
        Ok(LoadedConfig {
            config: cfg,
            // Путь возвращается ВСЕГДА, когда он назван (даже пустого файла):
            // POST /v1/config пишет в ТОТ ЖЕ файл, который искали на старте;
            // «файла нет» ≠ «пути нет» (свежепоставленный пользователь = путь
            // есть, файла ещё нет, и писать куда — известно).
            path,
            warnings: file.warnings.clone(),
            file_used: !file.is_empty(),
        })
    }

    /// Чистый контур цепочки: источник значений инжектится (тесты приоритета
    /// env > файл > дефолт не трогают среду процесса — `set_var` в edition
    /// 2024 = unsafe + гонка параллельных тестов, тот же контракт, что у
    /// [`Self::from_lookup`]).
    ///
    /// # Errors
    ///
    /// См. [`Self::from_lookup`].
    pub fn from_file_aware_with<L>(mut lookup: L) -> Result<Self, ConfigError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        Self::from_lookup(&mut |k| {
            lookup(k)
                .map(|v| v.trim().to_owned())
                // Пустое значение = «ключа нет» = дефолт (тот же контракт,
                // что у env-контура для `FASAD_MODEL_DIR`/`FASAD_BIND`).
                // Нормализация живёт на ГРАНИЦЕ слоя, а не в `from_lookup`:
                // числовые валидаторы обязаны краснеть на `FASAD_THREADS=` в
                // env (зуб `zero_and_garbage_numbers_are_errors_not_defaults`),
                // и молча простить им пустоту = ослабить существующий контракт.
                .filter(|v| !v.is_empty())
        })
    }

    /// Продуктивная граница с инжектируемым env-lookup: ровно то, что зовёт
    /// `main` ([`Self::load_config`]), но lookup = аргумент (среда процесса
    /// не трогается: `set_var` в edition 2024 = unsafe + гонка тестов).
    ///
    /// Путь резолвится ВНУТРИ функции (из того же lookup), поэтому зуб
    /// `fresh_install_without_config_file_loads_defaults` мерит именно
    /// продуктовый код, а не модель границы.
    ///
    /// # Errors
    ///
    /// См. [`Self::load_config`].
    pub fn load_config_from_env<L>(lookup: &mut L) -> Result<LoadedConfig, ConfigError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        let found = config_file_path_from(lookup);
        let file = match found.as_ref() {
            None => FileConfig::default(),
            Some(found) => match std::fs::read_to_string(&found.path) {
                Ok(text) => parse_config_file(&text)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if found.origin == ConfigPathOrigin::Resolved {
                        FileConfig::default()
                    } else {
                        return Err(ConfigError::MissingExplicitPath {
                            path: found.path.display().to_string(),
                            reason: e.to_string(),
                        });
                    }
                }
                Err(e) => {
                    return Err(ConfigError::FileUnreadable {
                        path: found.path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            },
        };
        let path = found.map(|f| f.path);
        Self::from_file_aware_with_lookup(&file, lookup, path)
    }

    /// Чистая часть цепочки (контракт для тестов): источник значений
    /// инжектится, порядок «env важнее файла» задаёт вызывающий closure.
    ///
    /// Разбор значений = [`Self::from_lookup`], т.е. env и файл проходят через
    /// одни и те же валидаторы: второй грамматики нет.
    ///
    /// # Errors
    ///
    /// См. [`Self::from_lookup`].
    pub fn from_sources<L>(lookup: L) -> Result<Self, ConfigError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        Self::from_lookup(lookup)
    }

    /// Тот же разбор, что [`Self::from_lookup`], с env-границей #192/#198:
    /// при unset/пустом `FASAD_MODEL_DIR` подставляется дефолт по `HOME`.
    ///
    /// Файлового слоя здесь НЕТ: это чистая env-граница, её зовут харнеси
    /// (`tray_live`) и тесты; продуктовый путь запуска — [`Self::load_config`].
    ///
    /// # Errors
    ///
    /// Любой [`ConfigError`]: неверный бинд, рассогласованные пороги,
    /// неизвестный режим хранилища, непарсящееся/нулевое число.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(env_boundary_lookup())
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
        // #192 (тесты): `FASAD_MODEL_DIR` из чистого lookup (тесты-харнесы,
        // `from_lookup(|_| None)`) = cascade-0-контур, КАК ДО #192: дефолт по
        // HOME подставляет `from_env` (нижняя граница), а не чистая функция.
        // Иначе каждый харнес `from_lookup(|_| None)` получил бы stage
        // `cascade-0+models` и `BuiltWithoutInference` — молчаливая смена
        // семантики тестового контура.
        let model_dir = lookup("FASAD_MODEL_DIR")
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from);
        let addr = bind_from_value(
            lookup("FASAD_BIND").as_deref(),
            lookup("FASAD_PORT").as_deref(),
        )?;
        let thresholds = Thresholds {
            tau_low: float_or(&mut lookup, "FASAD_TAU_LOW", DEFAULT_TAU_LOW)?,
            tau_high: float_or(&mut lookup, "FASAD_TAU_HIGH", DEFAULT_TAU_HIGH)?,
            gray_lo: float_or(&mut lookup, "FASAD_GRAY_LO", DEFAULT_GRAY_LO)?,
            gray_hi: float_or(&mut lookup, "FASAD_GRAY_HI", DEFAULT_GRAY_HI)?,
            alpha: float_or(&mut lookup, "FASAD_ARBITER_ALPHA", DEFAULT_ALPHA)?,
        };
        if !thresholds.is_sane() {
            return Err(ConfigError::ThresholdsInsane(thresholds));
        }
        let vault_mode = match lookup("FASAD_VAULT_MODE").as_deref() {
            None => VaultMode::Stateless,
            Some(raw) => VaultMode::parse(raw)
                .ok_or_else(|| ConfigError::VaultModeUnknown(raw.to_owned()))?,
        };
        let mlock = match lookup("FASAD_MLOCK").as_deref() {
            None => Mlock::Strict,
            Some(raw) => {
                Mlock::parse(raw).ok_or_else(|| ConfigError::MlockUnknown(raw.to_owned()))?
            }
        };
        Ok(Self {
            mlock,
            addr,
            max_body_bytes: usize_or(&mut lookup, "FASAD_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?,
            timeout_ms: u64_or(&mut lookup, "FASAD_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)?,
            thresholds,
            vault_mode,
            threads: usize_or(&mut lookup, "FASAD_THREADS", DEFAULT_THREADS)?,
            model_dir,
            schema_path: lookup("FASAD_SCHEMA").map(std::path::PathBuf::from),
            read_timeout_ms: u64_or(
                &mut lookup,
                "FASAD_READ_TIMEOUT_MS",
                DEFAULT_READ_TIMEOUT_MS,
            )?,
            upstream_allowlist: parse_allowlist(lookup("FASAD_UPSTREAM_ALLOWLIST").as_deref())?,
            proxy_loopback_http: bool_or(&mut lookup, "FASAD_PROXY_LOOPBACK_HTTP", false)?,
            // Срез ключей файла ставит `with_file_origin` на границе загрузки;
            // чистый lookup (харнеси) = None, «источник = файл» он заявлять не
            // обязан и не может.
            file_keys: None,
            file_values: None,
        })
    }

    /// Запомнить, какие ключи и значения дал файл (нужно для
    /// [`Self::source_of`] и file-aware потребителей вне полей `Config`).
    #[must_use]
    pub fn with_file_origin(mut self, file: &FileConfig) -> Self {
        self.file_keys = Some(file.keys());
        self.file_values = Some(
            file.entries
                .iter()
                .map(|e| (e.key, e.value.clone()))
                .collect(),
        );
        self
    }

    /// Разрешённые ключи с эффективными значениями и источниками — контент
    /// `GET /v1/config` (#219 atom-2).
    ///
    /// Значения берутся из собранной конфигурации, а НЕ из строки источника:
    /// «эффективное» = тем же числом крутится демон (порт из `addr`), и в
    /// канонической форме (мусор в `FASAD_PORT` даёт дефолт, и показывать
    /// надо 8765, а не `abc`).
    ///
    /// Секретов в ответе нет по построению: таблица = [`FILE_ALLOWED_KEYS`],
    /// в ней нет ни `FASAD_VAULT_KEY`, ни `FASAD_BIND`
    /// ([`forbidden_file_key_reason`]), и юнит-зуб
    /// `config_view_carries_no_secrets` меряет это по строке, а не по списку.
    #[must_use]
    pub fn view(&self) -> Vec<ConfigView> {
        FILE_ALLOWED_KEYS
            .iter()
            .map(|k| ConfigView {
                key: k.key,
                label: k.label,
                value: self.effective_value(k.key),
                source: self.source_of(k.key),
                ui_editable: k.ui_editable,
                restart_required: true,
            })
            .collect()
    }

    /// Эффективное значение ключа в канонической строковой форме.
    ///
    /// Только [`FILE_ALLOWED_KEYS`]: у ключа вне реестра нет «эффективного
    /// значения», которое мы готовы показать наружу.
    #[must_use]
    pub fn effective_value(&self, key: &'static str) -> String {
        match key {
            "FASAD_MODEL_DIR" => self
                .model_dir
                .as_ref()
                .map_or_else(String::new, |p| p.display().to_string()),
            "FASAD_PORT" => self.addr.port().to_string(),
            "FASAD_THREADS" => self.threads.to_string(),
            "FASAD_TIMEOUT_MS" => self.timeout_ms.to_string(),
            "FASAD_READ_TIMEOUT_MS" => self.read_timeout_ms.to_string(),
            "FASAD_MAX_BODY_BYTES" => self.max_body_bytes.to_string(),
            "FASAD_VAULT_MODE" => self.vault_mode.as_str().to_owned(),
            "FASAD_GRAY_LO" => self.thresholds.gray_lo.to_string(),
            "FASAD_GRAY_HI" => self.thresholds.gray_hi.to_string(),
            "FASAD_TAU_LOW" => self.thresholds.tau_low.to_string(),
            "FASAD_TAU_HIGH" => self.thresholds.tau_high.to_string(),
            "FASAD_ARBITER_ALPHA" => self.thresholds.alpha.to_string(),
            "FASAD_UPSTREAM_ALLOWLIST" => self
                .upstream_allowlist
                .iter()
                .map(|h| match h.port {
                    Some(p) => format!("{}:{p}", h.host),
                    None => h.host.clone(),
                })
                .collect::<Vec<_>>()
                .join(","),
            "FASAD_PROXY_LOOPBACK_HTTP" => {
                (if self.proxy_loopback_http { "1" } else { "0" }).to_owned()
            }
            "FASAD_SCHEMA" => self
                .schema_path
                .as_ref()
                .map_or_else(String::new, |p| p.display().to_string()),
            // `FASAD_HF_HOST` живёт вне полей `Config` (собирает его
            // `FetchConfig`, #192; file-aware с #224 MAJOR-2): canonical
            // значение = канонический дефолт, `http.rs` перекрывает его
            // реальным `FetchConfig::host_display` — одной правдой.
            "FASAD_HF_HOST" => crate::weights::DEFAULT_HF_HOST.to_owned(),
            // Ключей, не перечисленных выше, в реестре нет.
            _ => String::new(),
        }
    }

    /// Откуда взялось значение: env победил файл, файл победил дефолт.
    ///
    /// Env читается живьём, файл — по сохранённому срезу ключей
    /// ([`Self::with_file_origin`]): файл читается один раз на старте, и его
    /// содержимое на момент запроса показывать нельзя (ответ обязан быть
    /// про то, чем демон крутится).
    #[must_use]
    pub fn source_of(&self, key: &'static str) -> ValueSource {
        self.source_of_with(key, &mut |k| std::env::var(k).ok())
    }

    /// [`Self::source_of`] с инжектируемым env (тесты приоритета не трогают
    /// среду процесса).
    #[must_use]
    pub fn source_of_with<L>(&self, key: &'static str, env: &mut L) -> ValueSource
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        if env(key).is_some_and(|v| !v.trim().is_empty()) {
            return ValueSource::Env;
        }
        if self
            .file_keys
            .as_ref()
            .is_some_and(|keys| keys.contains(&key))
        {
            return ValueSource::File;
        }
        ValueSource::Default
    }

    /// Значение ключа из файла конфигурации (`None` = файла нет / ключа нет).
    /// Пустое значение = пустая строка: решение «пусто = не источник»
    /// принимает вызывающий (тот же контракт, что у цепочки).
    #[must_use]
    pub fn file_value(&self, key: &'static str) -> Option<&str> {
        self.file_values
            .as_ref()
            .and_then(|m| m.get(key))
            .map(String::as_str)
    }

    /// Значение булева env-флага для потребителей ВНЕ цепочки `Config`
    /// (ревью #224 MAJOR-2: валидатор `FASAD_HF_HOST` обязан знать про
    /// loopback-аффорданс, а лезть в `std::env::var` из `fetch` = вторая
    /// правда об источнике; источник один: env (непустой) > файл > дефолт,
    /// та же нормализация, что у цепочки загрузки).
    ///
    /// Разбор грамматики = [`bool_or`] (тот же, что у env-контура).
    ///
    /// # Errors
    ///
    /// [`ConfigError::BadBool`] — значение не разобрано (на этом пути оно
    /// уже прошло полный `from_lookup` на старте, отказ здесь = сигнал о
    /// расхождении контуров, не рабочий сценарий).
    pub fn bool_flag(&self, key: &'static str, default: bool) -> Result<bool, ConfigError> {
        let value = self.string_value(key).ok_or(ConfigError::BadBool {
            var: key,
            value: "<нет значения>".to_owned(),
        })?;
        bool_or(&mut move |_| Some(value.clone()), key, default)
    }

    /// Эффективное строковое значение ключа: env (непустой) > файл > `None`.
    /// Для потребителей, чьё поле живёт вне `Config` (`FASAD_HF_HOST` →
    /// `FetchConfig`, #224).
    #[must_use]
    pub fn string_value(&self, key: &'static str) -> Option<String> {
        match std::env::var(key) {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => self
                .file_value(key)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
        }
        // env читается ЖИВЬЁМ: `Config::proxy_loopback_http` = срез старта, и
        // «харнес включил флаг env после сборки Config» — рабочий контур
        // тестов; файловый флаг = срез (файл читается один раз на старте).
    }

    /// Разрешает ли конфигурация `http://` к upstream (только loopback-адреса).
    ///
    /// Название — вопрос, а не поле: сам флаг ничего не разрешает без проверки
    /// адреса, и путать «включено» с «можно наружу» нельзя.
    #[must_use]
    pub const fn loopback_http_permitted(&self) -> bool {
        self.proxy_loopback_http
    }

    /// Краткая строка статуса в `/health`: чем крутится конвейер. Секретов и
    /// пользовательских данных тут нет, но отпечаток конфигурации светим
    /// дозированно: `/health` ответа на аутентификацию не имеет.
    ///
    /// С шага 9A (`#14A`) метка обязана быть **правдой про собранный бинарь**,
    /// а не про намерение оператора: `cascade-0+models` означает, что каскады
    /// 1–2 реально примонтированы ([`crate::cascades`]). Это держится не
    /// вежливостью, а стартовым отказом: `model_dir` задан, а бинарь собран без
    /// `ort-inference` (или веса не загрузились) — демон не поднимается вовсе
    /// ([`crate::cascades::startup`]), потому что молчаливая деградация до
    /// каскада 0 при обещанных весах = fail-open на recall.
    ///
    /// Рюлинг #185 (22.10) закрыл и обратную сторону: full-бинарь (фича
    /// `ort-inference`) без `model_dir` тоже не стартует
    /// (`CascadeFailure::ModelsNotConfigured`) — `cascade-0-only` в релизном
    /// контуре недостижим, каскад-0 = харнес/тесты, не продакшн.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        if self.model_dir.is_some() {
            "cascade-0+models"
        } else {
            "cascade-0-only"
        }
    }
}

/// Элемент `FASAD_UPSTREAM_ALLOWLIST`: хост с необязательным портом.
///
/// Храним авторити разобранной, а не строкой: сравнение с URL обязано быть
/// точным по порту (`evil.com:443` ≠ `evil.com:8080`), а разбор на старте даёт
/// честный отказ на мусоре вместо молча проигнорированного элемента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedHost {
    /// Хост в нижнем регистре, как в URL.
    pub host: String,
    /// Порт; `None` = порт по умолчанию для схемы запроса.
    pub port: Option<u16>,
}

impl AllowedHost {
    /// Разбор одного элемента списка. Отказ на схеме, пути, учётных данных,
    /// пробелах и пустом хосте: всё это признаки того, что в env вписали URL
    /// целиком, а не авторити. Причину не возвращаем: `ConfigError::BadAllowlist`
    /// назовёт элемент целиком, оператору этого хватает.
    ///
    /// Квадратные скобки IPv6-литерала снимаются: [`crate::proxy::Upstream`]
    /// держит хост без них, и `https://[::1]:9` должен совпасть с записью
    /// `[::1]:9`, а не отвергнуться молча.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() || s.contains('/') || s.contains('@') || s.contains(char::is_whitespace) {
            return None;
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => {
                let Ok(port) = p.parse::<u16>() else {
                    return None;
                };
                if port == 0 {
                    return None;
                }
                (h, Some(port))
            }
            None => (s, None),
        };
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Совпадает ли авторити запроса с этим элементом.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.host.eq_ignore_ascii_case(host) && self.port.is_none_or(|p| p == port)
    }
}

/// Список из env: пусто/нет переменной = пустой список (прокси выключен),
/// любой мусорный элемент = отказ стартовать.
fn parse_allowlist(raw: Option<&str>) -> Result<Vec<AllowedHost>, ConfigError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    s.split(',')
        .map(|entry| {
            AllowedHost::parse(entry).ok_or_else(|| ConfigError::BadAllowlist {
                var: "FASAD_UPSTREAM_ALLOWLIST",
                value: entry.to_owned(),
            })
        })
        .collect()
}

/// Булево из env со строгой грамматикой; мусор = ошибка, не дефолт.
fn bool_or<L: FnMut(&'static str) -> Option<String>>(
    lookup: &mut L,
    var: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    let Some(raw) = lookup(var) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" => Ok(false),
        "1" | "true" | "on" => Ok(true),
        _ => Err(ConfigError::BadBool { var, value: raw }),
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

/// Запись ключа в файл конфигурации (UI-контур `POST /v1/config`, #220).
///
/// Контур записи:
///
/// 1. **Белый список**: ключ вне [`FILE_ALLOWED_KEYS`] = отказ
///    ([`ConfigError::FileKeyForbidden`]), ключ из списка запретов
///    ([`forbidden_file_key_reason`]) = отказ с причиной. Запись НЕ умеет
///    создавать ключей, которых файл читать не вправе, — «UI предложил, UI
///    записал» без белого списка = дыра.
/// 2. **Валидация ДО записи**: значение проходит те же валидаторы, что env и
///    файл на старте ([`validate_value`]) — в файл не попадает то, на чём
///    демон откажется стартовать.
/// 3. **Атомарность**: `.part` + `rename` (паритет `fetch.rs:369-470` и
///    `scripts/fetch-models.sh`), файл перезаписывается целиком из
///    прочитанного + новой пары: partial-write = битый конфиг = отказ старта,
///    и чинится он только вручную.
/// 4. **Каталог создаётся** (`create_dir_all`): UI-первый запуск не имеет
///    права требовать от оператора `mkdir`.
///
/// Формат записи = канон: ключ env-канона, `KEY=значение`, комментарии
/// существующих строк сохраняются (перезапись построчно). CRLF: парсер
/// читает оба (`trim_end` `\r`), запись пишет канонический LF (решение #224
/// MINOR, названо намеренно: mixed EOL в одном файле = сюрприз для правки
/// руками, а перевод всех строк в CRLF под win-редактор не стоит того:
/// читатель = наш парсер, он не чувствителен).
///
/// # Errors
///
/// [`ConfigError::FileKeyForbidden`] / [`ConfigError::FileMalformed`]
/// (значение не проходит валидатор) / [`ConfigError::FileUnreadable`]
/// (fs-отказ чтения/записи).
pub fn write_config_value(
    path: &std::path::Path,
    key: &str,
    value: &str,
    effective: &Config,
) -> Result<(), ConfigError> {
    let Some(canonical) = allowed_key(key) else {
        return Err(ConfigError::FileKeyForbidden {
            key: key.to_owned(),
            line: 0,
            reason: "ключа нет в белом списке конфигурации (он не читается \
                     демоном из файла — записывать его бессмысленно; список — \
                     README §Файл конфигурации)",
        });
    };
    if let Some(reason) = forbidden_file_key_reason(canonical) {
        return Err(ConfigError::FileKeyForbidden {
            key: canonical.to_owned(),
            line: 0,
            reason,
        });
    }
    // Проверка до записи, а не после: «UI принял, демон не стартовал» =
    // разрыв контракта, а 422 с текстом валидатора = «исправь поле».
    // Инвариант порогов мерится против ЭФФЕКТИВНЫХ значений (вызывающий
    // знает их: он держит живой `Config`).
    let value = value.trim();
    validate_value(
        canonical,
        value,
        &effective.thresholds,
        effective.proxy_loopback_http,
    )?;
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(ConfigError::FileUnreadable {
                path: path.display().to_string(),
                reason: e.to_string(),
            });
        }
    };
    let rendered = format!("{canonical}={value}\n");
    let mut out = String::new();
    let mut replaced = false;
    for raw in existing.lines() {
        let trimmed = raw.trim_end_matches('\r').trim();
        let is_same = trimmed
            .split_once('=')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(canonical));
        if is_same {
            if !replaced {
                out.push_str(&rendered);
                replaced = true;
            }
            continue; // дубликаты схлопываются: один ключ = одна строка
        }
        out.push_str(raw.trim_end_matches('\r'));
        out.push('\n');
    }
    if !replaced {
        if !existing.is_empty() && !existing.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&rendered);
    }
    write_atomic(path, &out)?;
    Ok(())
}

/// `.part` + `rename` (паритет fetch-контура, см. [`write_config_value`]).
///
/// Отдельная функция: у файла конфигурации и у весов один и тот же контракт
/// «не оставляем полфайла», и реализация обязана быть одна.
fn write_atomic(path: &std::path::Path, text: &str) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::FileUnreadable {
            path: parent.display().to_string(),
            reason: format!("создать каталог: {e}"),
        })?;
    }
    // Имя = `config.part` (файл конфигурации без расширения: `with_extension`
    // на нём молча переписал бы имя, зуб #224 MINOR мерит факт `.part`-имени
    // через суффикс file-name, как `fetch.rs:369` мерит его на named-файлах).
    let tmp = path.with_file_name(format!(
        "{}.part",
        path.file_name()
            .map_or("config", |n| n.to_str().unwrap_or("config"))
    ));
    std::fs::write(&tmp, text).map_err(|e| ConfigError::FileUnreadable {
        path: tmp.display().to_string(),
        reason: format!("записать .part: {e}"),
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        std::fs::remove_file(&tmp).ok();
        ConfigError::FileUnreadable {
            path: path.display().to_string(),
            reason: format!("rename: {e}"),
        }
    })
}

/// Валидатор ОДНОГО значения: та же грамматика, что у env-контура
/// ([`Config::from_lookup`]), вызванная изолированно (для `POST /v1/config`
/// значение обязано быть отвергнуто ДО записи, а не на следующем старте:
/// «UI принял, демон не стартовал» = разрыв контракта).
///
/// Пороги проверяются против ЭФФЕКТИВНЫХ значений остальных порогов
/// (`effective`), а не против дефолтов: запись `FASAD_GRAY_HI=0.1` при живом
/// `gray_lo = 0.22` обязана быть 422 с текстом инварианта, иначе файл
/// configuration уедет в состояние «сохранил — демон не стартует», а это
/// ровно то, от чего #185 защищает стартовым отказом (#219 §D, fail-closed).
///
/// Пустое значение разрешено любому ключу: «override снят», работает дефолт.
///
/// # Errors
///
/// Те же варианты, чем отказывает env-разбор: [`ConfigError::BadNumber`],
/// [`ConfigError::VaultModeUnknown`], [`ConfigError::BadBool`],
/// [`ConfigError::BadAllowlist`], [`ConfigError::ThresholdsInsane`];
/// [`ConfigError::FileKeyForbidden`] — ключ вне реестра (запрещённый ключ
/// отсекается раньше, в [`write_config_value`], с его собственной причиной).
pub fn validate_value(
    key: &'static str,
    raw: &str,
    effective: &Thresholds,
    proxy_loopback_http: bool,
) -> Result<(), ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        // Снятие override: валидаторов не проходит «пусто», пустое значение
        // трактуется как «ключа нет» (тот же контракт, что у env-контура).
        return Ok(());
    }
    let given = |k: &'static str| (k == key).then(|| raw.to_owned());
    if is_threshold_key(key) {
        let merged = Thresholds {
            tau_low: merge_f64(key, raw, "FASAD_TAU_LOW", effective.tau_low)?,
            tau_high: merge_f64(key, raw, "FASAD_TAU_HIGH", effective.tau_high)?,
            gray_lo: merge_f64(key, raw, "FASAD_GRAY_LO", effective.gray_lo)?,
            gray_hi: merge_f64(key, raw, "FASAD_GRAY_HI", effective.gray_hi)?,
            alpha: merge_f64(key, raw, "FASAD_ARBITER_ALPHA", effective.alpha)?,
        };
        if !merged.is_sane() {
            return Err(ConfigError::ThresholdsInsane(merged));
        }
    }
    // Syntax-контур: тот же `from_lookup`, что читает env, с одним
    // подставленным значением. Пороги НЕ подставляются: их совместный
    // `is_sane` уже проверен веткой выше против ЭФФЕКТИВНЫХ значений, а
    // изолированный разбор с «новое + дефолты» дал бы ложный отказ на
    // легальной паре (дефолт SPEC `τ_low = 0.20 > gray_lo = 0.22` и есть
    // такое «рассогласование», см. док `Thresholds::is_sane`).
    if is_threshold_key(key) {
        return Ok(());
    }
    // PORT = ЯВНЫЙ парсер, без тихого фолбэка `port_from_value` (ревью #224
    // MAJOR-1): env-контур прощает `FASAD_PORT=abc` (эргономика запуска,
    // задокументирована в заголовке модуля), а запись через UI прощать не
    // вправе: 200 + фолбэк на 8765 = «UI принял, демон слушает не то» —
    // двойная ложь (значение в GET и реальность). Диапазон привилегированных
    // портов (1..1023) = 422 текстом: bind дал бы `PermissionDenied` rc=1 без
    // внятного объяснения (#224 MINOR); root-сценарий = env, не UI-файл.
    if key == "FASAD_PORT" {
        let _ = port_strict_for_write(raw)?;
        return Ok(());
    }
    // HF_HOST = тот же парсер, что у живого fetch-контура (ревью #224
    // MAJOR-2): он НЕ поле `Config`, и прогонять его через `from_lookup`
    // бессмысленно (ключ туда не входит).
    if key == "FASAD_HF_HOST" {
        // Аффорданс loopback-http = ЭФФЕКТИВНЫЙ флаг контура (env > файл):
        // вызывающий (`POST /v1/config`) держит живой `Config` и передаёт его.
        return crate::fetch::FetchConfig::validate_host(raw, proxy_loopback_http).map_err(|e| {
            // Класс отказа fetch'а переносится текстом: POST отдаёт 422 с
            // той же формулировкой, что дала бы загрузка (единая первичка
            // причины).
            ConfigError::BadValue {
                var: "FASAD_HF_HOST",
                reason: e.display_safe(),
            }
        });
    }
    Config::from_lookup(given).map(|_| ())
}

/// Эффективное значение порога по ключу (`None` = не порог).
#[must_use]
pub fn effective_threshold(t: &Thresholds, key: &str) -> Option<f64> {
    match key {
        "FASAD_TAU_LOW" => Some(t.tau_low),
        "FASAD_TAU_HIGH" => Some(t.tau_high),
        "FASAD_GRAY_LO" => Some(t.gray_lo),
        "FASAD_GRAY_HI" => Some(t.gray_hi),
        "FASAD_ARBITER_ALPHA" => Some(t.alpha),
        _ => None,
    }
}

/// Ключ порога (проверяется блоком, инвариант совместный).
#[must_use]
pub fn is_threshold_key(key: &'static str) -> bool {
    matches!(
        key,
        "FASAD_TAU_LOW"
            | "FASAD_TAU_HIGH"
            | "FASAD_GRAY_LO"
            | "FASAD_GRAY_HI"
            | "FASAD_ARBITER_ALPHA"
    )
}

/// Наше значение (если ключ = этот) или эффективное, с разбор-валидацией.
fn merge_f64(
    key: &'static str,
    raw: &str,
    want: &'static str,
    effective: f64,
) -> Result<f64, ConfigError> {
    if key != want {
        return Ok(effective);
    }
    raw.trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .ok_or(ConfigError::BadNumber {
            var: want,
            value: raw.to_owned(),
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

    // ── #219 atom-1: файл конфигурации ─────────────────────────────────────

    /// KV-грамматика: комментарии, пустые строки, trim, CRLF, регистр ключа.
    #[test]
    fn config_file_parses_kv_grammar() {
        let f = parse_config_file("# комментарий\n\r\n  FASAD_PORT = 9311 \r\nFASAD_THREADS=4\n")
            .expect("грамматика принимается");
        assert_eq!(f.entries.len(), 2);
        assert_eq!(f.value_of("FASAD_PORT"), Some("9311"));
        assert_eq!(f.value_of("FASAD_THREADS"), Some("4"));
        assert!(f.warnings.is_empty(), "{:?}", f.warnings);
        // Регистр ключа = регистронезависимый канон (опечатка «fasad_port»).
        let f = parse_config_file("fasad_port=1234").expect("регистр не важен");
        assert_eq!(f.value_of("FASAD_PORT"), Some("1234"));
    }

    #[test]
    fn config_file_empty_is_default_equivalent() {
        let f = parse_config_file("# только комментарий\n\n").expect("пустой файл не отказ");
        assert!(f.is_empty());
        assert_eq!(f.value_of("FASAD_PORT"), None);
    }

    /// Неизвестный ключ = предупреждение (future-proof: файл переживает релиз
    /// с новым ключом), а НЕ отказ; warning обязан называть номер строки.
    #[test]
    fn unknown_key_warns_with_line_number_and_does_not_refuse() {
        let f = parse_config_file("FASAD_PORT=9311\nFASAD_BUDUSCHEE=1\n")
            .expect("неизвестный ключ не отказ");
        assert_eq!(f.entries.len(), 1);
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("строка 2"), "{}", f.warnings[0]);
        assert!(
            f.warnings[0].contains("FASAD_BUDUSCHEE"),
            "{}",
            f.warnings[0]
        );
    }

    /// Строка без `=` = отказ с номером строки (молча проигнорированная
    /// строка = «опечатка, конфигурация не та»).
    #[test]
    fn malformed_line_refuses_with_line_number() {
        let err = parse_config_file("FASAD_PORT=9311\nэто не пара\n")
            .expect_err("строка без `=` = отказ");
        assert!(
            matches!(&err, ConfigError::FileMalformed { line: 2, .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("строка 2"), "{err}");
    }

    /// Секрет в файле = ОТКАЗ старта текстом «только env» (AGENTS: никаких
    /// секретов в открытом виде), не предупреждение.
    #[test]
    fn vault_key_in_file_refuses_startup_with_env_only_text() {
        let err = parse_config_file(
            "FASAD_VAULT_KEY=0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .expect_err("секрет в файле = отказ");
        assert!(
            matches!(&err, ConfigError::FileKeyForbidden { key, .. } if key == "FASAD_VAULT_KEY"),
            "{err:?}"
        );
        let text = err.to_string();
        assert!(text.contains("FASAD_VAULT_KEY"), "{text}");
        assert!(text.contains("env"), "текст обязан называть канал: {text}");
    }

    /// BIND в файле = отказ: loopback-инвариант живёт в env/юните, не в
    /// пользовательском файле.
    #[test]
    fn bind_in_file_is_refused() {
        let err = parse_config_file("FASAD_BIND=0.0.0.0\n").expect_err("бинд = env-only");
        assert!(
            matches!(&err, ConfigError::FileKeyForbidden { key, .. } if key == "FASAD_BIND"),
            "{err:?}"
        );
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    /// Харнес-флаги и `FASAD_MLOCK` тоже env-only: файл не имеет права
    /// делать из релизного бинаря каскад-0-харнес (класс #185).
    #[test]
    fn harness_flags_and_mlock_are_env_only() {
        for key in [
            "FASAD_TEST_CASCADE0",
            "FASAD_TEST_TRAY_CONTOUR",
            "FASAD_MLOCK",
            "FASAD_CONFIG",
        ] {
            let err = parse_config_file(&format!("{key}=1\n")).expect_err("{key} = env-only");
            assert!(
                matches!(err, ConfigError::FileKeyForbidden { .. }),
                "{key}: {err:?}"
            );
        }
    }

    /// Приоритет env > файл > дефолт — решётка на чистой границе
    /// `from_file_aware` (env процесса тут не трогается: тесты параллельны).
    #[test]
    fn precedence_env_beats_file_beats_default() {
        // Цепочка = env > файл > дефолт; env-слой инжектится (среда процесса
        // не трогается: `set_var` в edition 2024 = unsafe + гонка тестов).
        fn chain(env: Option<&'static str>, file: &FileConfig) -> Config {
            Config::from_file_aware_with(|k| {
                // Тот же слой, что ставит `from_file_aware` поверх env:
                // пустое (после trim) env-значение = «оператор ничего не
                // сказал», не «значение-мусор».
                match k {
                    "FASAD_PORT" => env
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .or_else(|| file.value_of(k).map(str::to_owned)),
                    _ => file.value_of(k).map(str::to_owned),
                }
            })
            .expect("цепочка собирается")
        }
        let f = parse_config_file("FASAD_PORT=9311\nFASAD_THREADS=4\n").expect("парсится");
        let from_file = chain(None, &f);
        assert_eq!(from_file.addr.port(), 9311, "файл бьёт дефолт");
        assert_eq!(from_file.threads, 4);
        assert_eq!(chain(Some("9400"), &f).addr.port(), 9400, "env бьёт файл");
        assert_eq!(
            chain(Some("9400"), &f).threads,
            4,
            "ключ, не тронутый env, берётся из файла"
        );
        assert_eq!(
            chain(Some(" "), &f).addr.port(),
            9311,
            "пробельный env = не источник (trim)"
        );
        // Ключа ни в env, ни в файле = дефолт.
        assert_eq!(chain(None, &f).timeout_ms, DEFAULT_TIMEOUT_MS);
    }

    /// Пустое значение в файле = дефолт («override снят»), не отказ.
    #[test]
    fn empty_value_in_file_means_default() {
        let f = parse_config_file("FASAD_THREADS=\n").expect("пустое значение легально");
        assert_eq!(f.value_of("FASAD_THREADS"), Some(""));
        let bare = Config::from_file_aware_with(|_| None).expect("дефолт-контур без файла");
        assert_eq!(bare.threads, DEFAULT_THREADS);
        let with_empty = Config::from_file_aware_with(|k| f.value_of(k).map(str::to_owned))
            .expect("пустое = дефолт");
        assert_eq!(with_empty.threads, DEFAULT_THREADS);
    }

    /// Битое значение в файле = отказ старта ТЕКСТОМ валидатора env-контура
    /// (единая точка разбора: второй грамматики отказов нет).
    #[test]
    fn broken_value_in_file_refuses_with_env_validator_text() {
        let f = parse_config_file("FASAD_THREADS=abc\n").expect("синтаксис строки ок");
        let err = Config::from_file_aware_with(|k| f.value_of(k).map(str::to_owned))
            .expect_err("битое число = отказ");
        assert!(matches!(err, ConfigError::BadNumber { .. }), "{err:?}");
        assert!(err.to_string().contains("FASAD_THREADS"), "{err}");
    }

    /// Инвариант порогов действует и для файла (общая проверка, §D).
    #[test]
    fn file_thresholds_are_validated_as_a_block() {
        let f = parse_config_file("FASAD_GRAY_LO=0.9\nFASAD_GRAY_HI=0.5\n").expect("синтаксис ок");
        let err = Config::from_file_aware_with(|k| f.value_of(k).map(str::to_owned))
            .expect_err("рассогласование = отказ");
        assert!(matches!(err, ConfigError::ThresholdsInsane(_)), "{err:?}");
    }

    /// Путь: `FASAD_CONFIG` выигрывает всё; win = `%APPDATA%\fasad\config`;
    /// unix/mac = `$XDG_CONFIG_HOME/fasad/config`, дефолт `$HOME/.config/fasad/config`.
    #[test]
    fn config_path_resolution_follows_platform_canon() {
        let explicit = config_file_path_from(&mut |k| match k {
            "FASAD_CONFIG" => Some("/tmp/mine".to_owned()),
            "HOME" => Some("/home/op".to_owned()),
            _ => None,
        });
        let explicit = explicit.expect("явный путь");
        assert_eq!(explicit.path.to_string_lossy(), "/tmp/mine");
        assert_eq!(explicit.origin, ConfigPathOrigin::Explicit);
        // Пустой `FASAD_CONFIG` = UNSET (первичка env-контра: пустое env =
        // «оператор ничего не сказал», не «путь-в-никуда»): резолвим канон.
        let empty = config_file_path_from(&mut |k| match k {
            "FASAD_CONFIG" => Some("   ".to_owned()),
            "HOME" => Some("/home/op".to_owned()),
            _ => None,
        })
        .expect("пустой FASAD_CONFIG = канон-резолв, не отказ");
        assert_eq!(empty.origin, ConfigPathOrigin::Resolved);
        assert_eq!(
            empty.path,
            config_dir_from_env(&mut |k| match k {
                "HOME" => Some("/home/op".to_owned()),
                _ => None,
            })
            .expect("дом есть")
            .join(CONFIG_FILE_NAME)
        );

        // XDG задан = сам XDG = каталог конфигурации (без .config).
        let p = config_file_path_from(&mut |k| match k {
            "XDG_CONFIG_HOME" => Some("/xdg".to_owned()),
            "HOME" => Some("/home/op".to_owned()),
            _ => None,
        })
        .expect("XDG даёт путь");
        assert_eq!(
            p.path,
            std::path::Path::new("/xdg")
                .join("fasad")
                .join(CONFIG_FILE_NAME)
        );
        assert_eq!(p.origin, ConfigPathOrigin::Resolved);

        // Дефолт = $HOME/.config/fasad/config (НЕ ~/Library/Preferences на mac).
        let p = config_file_path_from(&mut |k| match k {
            "HOME" => Some("/home/op".to_owned()),
            _ => None,
        })
        .expect("HOME даёт путь");
        assert_eq!(
            p.path,
            std::path::Path::new("/home/op")
                .join(".config")
                .join("fasad")
                .join(CONFIG_FILE_NAME)
        );

        // Windows-ветка: %APPDATA%\fasad\config (чистая функция, проверяется на любой ОС).
        assert_eq!(
            config_dir_from_appdata(Some("C:\\Users\\op\\AppData\\Roaming")).unwrap(),
            std::path::Path::new("C:\\Users\\op\\AppData\\Roaming").join("fasad")
        );
        assert_eq!(config_dir_from_appdata(Some("   ")), None);
        // Ничего нет = искать негде (не паника, не «.»).
        assert!(config_file_path_from(&mut |_| None).is_none());
    }

    /// Явный `FASAD_CONFIG` в несуществующий файл = отказ старта с путём
    /// (#185-контур: опечатка в пути обязана быть названа); дефолтного пути
    /// отсутствие файла не касается.
    #[test]
    fn explicit_missing_path_refuses_absent_default_does_not() {
        let missing = ConfigPath {
            path: std::path::Path::new("/nonexistent-fasad-config-219/config").to_owned(),
            origin: ConfigPathOrigin::Explicit,
        };
        let err = Config::load_config_at(Some(&missing)).expect_err("явный путь = отказ");
        assert!(
            matches!(err, ConfigError::MissingExplicitPath { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("FASAD_CONFIG"), "{err}");
        // Тот ПУТЬ, помеченный Resolved (канон-резолв), = дефолты: ровно та
        // ветка, на которой fresh-install краснел ревью-блокером #224.
        let resolved = ConfigPath {
            path: missing.path.clone(),
            origin: ConfigPathOrigin::Resolved,
        };
        let loaded = Config::load_config_at(Some(&resolved)).expect("резолвнутый = дефолты");
        assert!(!loaded.file_used);
        assert_eq!(loaded.config.addr.port(), DEFAULT_PORT);
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        let loaded = Config::load_config_at(None).expect("без пути = дефолты");
        assert!(!loaded.file_used);
    }

    /// ЗУБ БЛОКЕРА #224 (регресс fresh-install): продуктивная граница
    /// `Config::load_config()` на машине БЕЗ файла конфигурации обязана
    /// стартовать дефолтами, а не отказывать «`FASAD_CONFIG` указывает…».
    ///
    /// (Док-текст в бэктиках: `clippy::doc_markdown` красит голые ALL_CAPS-имена.)
    ///
    /// Моделируется процесс-окружение: игла `Config::load_config_from_env`
    /// (= то, что вызывает `main`, только lookup инжектится). Ключевое:
    /// путь резолвится ЗДЕСЬ, внутри функции, а не передаётся готовым — зуб
    /// ловит именно путаницу `Some(resolved)` → `NotFound` → отказ, а не её
    /// модель. env-контур при lookup="нет ничего" = дефолты (харнес-семантика
    /// `from_lookup(|_| None)`, без HOME-подстановок).
    /// Уникальный tmp-путь юнита: `cargo test --lib` = ОДИН процесс, тесты в
    /// потоках, `std::process::id()` НЕ уникален на поток → два юнита с одним
    /// PID-суффиксом пишут в один каталог (win-контра #224: имя-гонка tmp =
    /// ECONNREFUSED/RST-окна на CI). Суффикс = PID + счётчик + наносекунды.
    fn unique_tmp_dir(prefix: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir();
        for _ in 0..128 {
            let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or_default();
            let dir = root.join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("unique_tmp_dir({prefix}): {e}"),
            }
        }
        panic!("unique_tmp_dir: 128 коллизий имени {prefix}");
    }

    #[test]
    fn fresh_install_without_config_file_loads_defaults() {
        // 1) ни FASAD_CONFIG, ни HOME/XDG: искать негде = дефолты.
        let loaded = Config::load_config_from_env(&mut |_| None).expect("чистая среда = дефолты");
        assert!(!loaded.file_used);
        assert_eq!(loaded.config.addr.port(), DEFAULT_PORT);

        // 2) HOME = tempdir БЕЗ файла (свежая установка): резолв даёт путь,
        //    файла нет = дефолты, НЕ отказ. Это и был блокер.
        let dir = unique_tmp_dir("fasad-fresh-224");
        std::fs::create_dir_all(&dir).expect("каталог HOME");
        let home = dir.to_string_lossy().to_string();
        let loaded = Config::load_config_from_env(&mut |k| match k {
            "HOME" => Some(home.clone()),
            _ => None,
        })
        .expect("свежая установка без файла стартует дефолтами");
        assert!(!loaded.file_used, "файла нет — источника нет");
        assert_eq!(loaded.config.addr.port(), DEFAULT_PORT);
        // Путь в ответе есть (UI «куда писать» обязан его знать).
        assert!(loaded.path.is_some(), "резолвнутый путь обязан вернуться");

        // 3) HOME = tempdir С валидным файлом по каноническому пути: значения
        //    применяются, source = file (продуктивный путь fresh-install
        //    после «сохрани через UI, перезапусти»).
        let cfgdir = dir.join(".config").join("fasad");
        std::fs::create_dir_all(&cfgdir).expect("каталог конфига");
        std::fs::write(cfgdir.join(CONFIG_FILE_NAME), "FASAD_PORT=9316\n").expect("файл");
        let home = dir.to_string_lossy().to_string();
        let loaded = Config::load_config_from_env(&mut |k| match k {
            "HOME" => Some(home.clone()),
            _ => None,
        })
        .expect("файл по каноническому пути читается");
        assert!(loaded.file_used);
        assert_eq!(loaded.config.addr.port(), 9316);
        assert_eq!(loaded.config.source_of("FASAD_PORT"), ValueSource::File);

        // 4) явный FASAD_CONFIG в никуда = ОТКАЗ (контраст с ногой 2:
        //    различает происхождение пути, а не факт отсутствия файла).
        let err = Config::load_config_from_env(&mut |k| match k {
            "FASAD_CONFIG" => Some(format!(
                "/nonexistent-fasad-224-{}/config",
                std::process::id()
            )),
            _ => None,
        })
        .expect_err("явный путь в никуда = отказ");
        assert!(
            matches!(err, ConfigError::MissingExplicitPath { .. }),
            "{err:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Живой файл через tempdir (игла HOME/APPDATA = tempdir, не каталог
    /// оператора): чтение + приоритет + предупреждения.
    #[test]
    fn load_config_at_reads_tempdir_file() {
        let dir = unique_tmp_dir("fasad-cfg-219");
        std::fs::create_dir_all(&dir).expect("каталог");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&path, "FASAD_PORT=9311\nFASAD_CHEZ_BUDUSCHEE=x\n").expect("запись");
        let found = ConfigPath {
            path: path.clone(),
            origin: ConfigPathOrigin::Explicit,
        };
        let loaded = Config::load_config_at(Some(&found)).expect("читается");
        assert!(loaded.file_used);
        assert_eq!(loaded.config.addr.port(), 9311);
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("FASAD_CHEZ_BUDUSCHEE"));
        // Источник = файл (для `GET /v1/config`).
        assert_eq!(
            loaded.config.source_of("FASAD_PORT"),
            ValueSource::File,
            "ключ из файла обязан быть помечен file"
        );
        assert_eq!(
            loaded.config.source_of("FASAD_THREADS"),
            ValueSource::Default,
            "не заданный нигде = default"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Таблица-реестр: каждый разрешённый ключ файла = существующая env-ручка,
    /// и ни один секрет/бинд в реестре не сидит.
    #[test]
    fn registry_is_env_canon_and_carries_no_secrets() {
        // #224 MINOR: контракт = ТОЧНОЕ число (16), а не «>= 15»: реестр —
        // публичный контракт UI/README, молчаливое расхождение = ложь таблицы.
        assert_eq!(
            FILE_ALLOWED_KEYS.len(),
            16,
            "реестр ключей изменился: синхронизируй README §Файл конфигурации, docs/release.md §Запуск и CFG_NUMERIC в ui/app.js"
        );
        for k in FILE_ALLOWED_KEYS {
            assert!(k.key.starts_with("FASAD_"), "{}", k.key);
            assert!(
                !is_forbidden_file_key(k.key),
                "{} засветился в двух списках",
                k.key
            );
        }
        for secret in SECRET_KEYS {
            assert!(
                FILE_ALLOWED_KEYS.iter().all(|k| k.key != *secret),
                "секрет {secret} в белом списке = утечка через /v1/config"
            );
        }
    }

    /// `Config::view` (GET /v1/config): эффективные значения, источников,
    /// секретов в строках нет.
    #[test]
    fn config_view_carries_no_secrets() {
        let cfg = Config::from_lookup(|_| None).expect("дефолты");
        let view = cfg.view();
        assert_eq!(view.len(), FILE_ALLOWED_KEYS.len());
        let rendered = view
            .iter()
            .map(|v| format!("{}={} ({})", v.key, v.value, v.source.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.contains("VAULT_KEY"), "{rendered}");
        assert!(!rendered.contains("FASAD_BIND"), "{rendered}");
        assert!(rendered.contains("FASAD_PORT=8765 (default)"), "{rendered}");
    }

    /// Запись значения: атомарность (.part+rename), белый список, сохранение
    /// комментариев, схлопывание дубликата, отказ секрету и мусорному значению.
    #[test]
    fn write_config_value_writes_atomically_and_validates() {
        fn base_cfg() -> Config {
            Config::from_lookup(|_| None).expect("дефолты")
        }
        let dir = unique_tmp_dir("fasad-cfg-write-219");
        std::fs::create_dir_all(&dir).expect("каталог");
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&path, "# мой конфиг\nFASAD_PORT=9311\n").expect("база");
        write_config_value(&path, "FASAD_THREADS", "3", &base_cfg()).expect("запись");
        write_config_value(&path, "FASAD_PORT", "9400", &base_cfg()).expect("перезапись");
        let text = std::fs::read_to_string(&path).expect("файл");
        assert!(
            text.contains("# мой конфиг"),
            "комментарий обязан выжить: {text}"
        );
        assert_eq!(
            text.matches("FASAD_PORT=").count(),
            1,
            "дубликат схлопнулся: {text}"
        );
        assert!(text.contains("FASAD_PORT=9400"), "{text}");
        assert!(text.contains("FASAD_THREADS=3"), "{text}");
        assert!(
            !dir.join("config.part").exists(),
            ".part обязан исчезнуть после rename"
        );
        // Мусорное значение = отказ ДО записи (файл не испорчен).
        assert!(write_config_value(&path, "FASAD_THREADS", "abc", &base_cfg()).is_err());
        let after = std::fs::read_to_string(&path).expect("файл жив");
        assert_eq!(after, text, "отказ не трогает файл");
        // Секрет = отказ; ключ вне списка = отказ.
        assert!(write_config_value(&path, "FASAD_VAULT_KEY", "aa", &base_cfg()).is_err());
        assert!(write_config_value(&path, "FASAD_BUDUSCHEE", "1", &base_cfg()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Инвариант порогов при записи: 422-контур (#219 §D) меряется против
    /// ЭФФЕКТИВНЫХ значений, а не дефолтов.
    #[test]
    fn validate_value_checks_thresholds_against_effective() {
        let sane = Thresholds::default_working();
        // Дефолт SPEC = `τ_low 0.20 > gray_lo 0.22`?? нет: τ_high = 0.80,
        // поэтому gray_hi = 0.9 ЛОМАЕТ инвариант `gray_hi ≤ tau_high` —
        // отказ здесь и есть правильный (зуб «инвариант красен» ниже).
        assert!(matches!(
            validate_value("FASAD_GRAY_HI", "0.9", &sane, false).expect_err("gray_hi > tau_high"),
            ConfigError::ThresholdsInsane(_)
        ));
        // Согласованная пара (gray_hi 0.75 ≤ tau_high 0.80) проходит.
        assert!(validate_value("FASAD_GRAY_HI", "0.75", &sane, false).is_ok());
        // gray_lo поднят выше будущего gray_hi: инвариант `lo < hi` краснеет.
        // Пороги подняты ПАРОЙ согласованно (τ_high = 0.95), иначе красным
        // окажется уже инвариант `gray_hi ≤ tau_high`, а не проверяемый.
        let raised = Thresholds {
            gray_lo: 0.9,
            tau_high: 0.95,
            ..Thresholds::default_working()
        };
        let err =
            validate_value("FASAD_GRAY_HI", "0.5", &raised, false).expect_err("инвариант красен");
        assert!(matches!(err, ConfigError::ThresholdsInsane(_)), "{err:?}");
        // syntax = тот же валидатор, что env.
        assert!(matches!(
            validate_value("FASAD_TIMEOUT_MS", "abc", &sane, false).expect_err("не число"),
            ConfigError::BadNumber { .. }
        ));
        assert!(matches!(
            validate_value("FASAD_VAULT_MODE", "17", &sane, false).expect_err("режима нет"),
            ConfigError::VaultModeUnknown(_)
        ));
        assert!(matches!(
            validate_value("FASAD_UPSTREAM_ALLOWLIST", "http://evil/", &sane, false)
                .expect_err("URL не авторити"),
            ConfigError::BadAllowlist { .. }
        ));
        // Снятие override = легально для любого ключа.
        assert!(validate_value("FASAD_PORT", "", &sane, false).is_ok());
    }

    /// #224 MAJOR-1: POST-валидатор PORT = явный парсер, тихого фолбэка
    /// `port_from_value` (эргономика env-запуска) в контуре записи НЕТ:
    /// 200 + фолбэк = «UI принял, демон слушает не то».
    #[test]
    fn validate_port_has_no_silent_fallback() {
        let sane = Thresholds::default_working();
        for bad in ["abc", "-1", "65536", "99999", "1", "1023", "8.5", ""] {
            // "" = снятие override (легально), проверяется отдельно ниже.
            if bad.is_empty() {
                assert!(validate_value("FASAD_PORT", bad, &sane, false).is_ok());
                continue;
            }
            let err = validate_value("FASAD_PORT", bad, &sane, false)
                .expect_err("мусорный/привилегированный порт = отказ ДО записи");
            assert!(
                matches!(
                    err,
                    ConfigError::BadValue {
                        var: "FASAD_PORT",
                        ..
                    }
                ),
                "{bad}: {err:?}"
            );
            assert!(
                err.to_string().contains("1024"),
                "текст обязан назвать диапазон: {err}"
            );
        }
        assert!(validate_value("FASAD_PORT", "1024", &sane, false).is_ok());
        assert!(validate_value("FASAD_PORT", "65535", &sane, false).is_ok());
        assert!(
            validate_value("FASAD_PORT", " 9311 ", &sane, false).is_ok(),
            "trim"
        );
        // #224 передача (первичка харнесей): `FASAD_PORT=0` = «дай свободный
        // порт» — контракт `wire_e2e`/`ui_sandbox` (стартуют на 0 и читают
        // адрес из баннера), `verify-bundle.sh`, `measure-rss.sh`.
        // env/файловый контур: 0 ЛЕГАЛЕН (иначе харнеси валит сам валидатор).
        assert_eq!(port_strict("0").expect("0 легален в env/файле"), 0);
        // Контур записи (POST/UI): 0 вне диапазона — случайный порт человеку
        // не нужен («listening on :52143» = сюрприз), boundary названа в доке.
        let err = validate_value("FASAD_PORT", "0", &sane, false)
            .expect_err("POST 0 = отказ (случайный порт = харнес-контур)");
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    var: "FASAD_PORT",
                    ..
                }
            ),
            "{err:?}"
        );
        // Живой env-контур на 0: bindFrom = addr :0 (харнес-семантика).
        let cfg = cfg_from(&[("FASAD_PORT", "0")]).expect("0 читается env-контуром");
        assert_eq!(cfg.addr.port(), 0);
    }

    /// #224 MAJOR-2: `FASAD_HF_HOST` валидируется ПАРСЕРОМ fetch-контура (единая
    /// точка), а файловое значение потребляется `FetchConfig::from_config`
    /// (env > файл) — ключ не мертвый груз.
    #[test]
    fn validate_hf_host_uses_fetch_parser_and_file_is_consumed() {
        let sane = Thresholds::default_working();
        assert!(
            validate_value(
                "FASAD_HF_HOST",
                "https://my-mirror.example.test",
                &sane,
                false
            )
            .is_ok()
        );
        for bad in [
            "garbage-not-a-url",
            "ftp://files.example.test",
            "not a url at all",
            "https://user@evil.example",
        ] {
            let err = validate_value("FASAD_HF_HOST", bad, &sane, false)
                .expect_err("парсер fetch красен");
            assert!(
                matches!(
                    err,
                    ConfigError::BadValue {
                        var: "FASAD_HF_HOST",
                        ..
                    }
                ),
                "{bad}: {err:?}"
            );
        }
        // Файловое значение читается fetch-контуром (env > файл > дефолт):
        let f = parse_config_file("FASAD_HF_HOST=https://from-file.example.test\n").expect("парс");
        let cfg = Config::from_file_aware_with(|_| None).expect("без env");
        let cfg = cfg.with_file_origin(&f);
        let fc =
            crate::fetch::FetchConfig::from_lookup(&cfg, &|k| cfg.file_value(k).map(str::to_owned))
                .expect("файловый хост разбирается");
        assert_eq!(fc.host_display(), "https://from-file.example.test");
        // env побеждает файл.
        let fc = crate::fetch::FetchConfig::from_lookup(&cfg, &|k| {
            (k == "FASAD_HF_HOST")
                .then(|| "https://from-env.example.test".to_owned())
                .or_else(|| cfg.file_value(k).map(str::to_owned))
        })
        .expect("env-хост");
        assert_eq!(fc.host_display(), "https://from-env.example.test");
        // `source_of` честен на файловом значении (витрина не врет парой).
        assert_eq!(
            cfg.source_of_with("FASAD_HF_HOST", &mut |_| None),
            ValueSource::File
        );
    }
}
