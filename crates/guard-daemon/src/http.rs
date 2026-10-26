//! HTTP-слой: роутеры §8 + заголовки `X-Guard-*`.
//!
//! Шаги 1–5 держали здесь только `/health`. Шаг 6 добавляет `/v1/analyze`
//! (атом B) и `/v1/anonymize|deanonymize` (атом C); fail-closed middleware —
//! атом D.
//!
//! # Что здесь fail-closed
//!
//! 1. Тело больше `FASAD_MAX_BODY_BYTES` отсекается слоем до разбора (413), а не
//!    «читаем, что дали».
//! 2. Ошибка разбора JSON отдаётся **без эха входа**: сообщения `serde_json`
//!    цитируют фрагменты тела, а тело — потенциальные `ПДн`. Клиент получает код и
//!    категорию причины.
//! 3. Любая внутренняя ошибка конвейера → 5xx, ответ без частичных спанов.
//!    Пустой список при 200 означает «анализ прошёл и `ПДн` нет», поэтому он
//!    допустим только на успешном пути (AGENTS: никогда fail-open).

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};

use crate::Health;
use crate::config::Config;
use crate::pipeline::{self, Analysis, AnalyzeError, AnalyzeRequest, Policy};
use crate::schema::Schema;
use crate::vault::{AnonymizeRequest, DeanonymizeRequest, Vault, VaultApiError};

/// Имя входного заголовка политики (SPEC §8).
pub const HEADER_POLICY: HeaderName = HeaderName::from_static("x-guard-policy");

/// Идентификатор сессии (`X-Session-ID`, SPEC §8). Для режима 3 не требуется.
pub const HEADER_SESSION: HeaderName = HeaderName::from_static("x-session-id");

/// Выходные заголовки `X-Guard-*`.
///
/// SPEC §8 определяет из выходов только Count / Max-Risk / Latency; `Stage`,
/// `Policy-Applied` и `Score-Threshold` — наши расширения вне спецификации
/// (входной `X-Guard-Policy` §8 не переиспользуется: он про запрос). Имена —
/// контракт, таблица в `docs/daemon-scope.md` сверяется с этим кодом тестом
/// [`header_table_in_docs_matches_emitted_names`].
pub(crate) mod h {
    use axum::http::HeaderName;

    pub const COUNT: HeaderName = HeaderName::from_static("x-guard-redacted-count");
    pub const MAX_RISK: HeaderName = HeaderName::from_static("x-guard-max-risk");
    pub const LATENCY: HeaderName = HeaderName::from_static("x-guard-latency-ms");
    pub const STAGE: HeaderName = HeaderName::from_static("x-guard-stage");
    /// Лег каскада 2 на запросе (`ok`/`skipped`/`absent`): стадия описывает
    /// монтаж, этот заголовок — что вердикты были. Деградация обязана быть
    /// видна оператору per-request, а не тонуть в общем `cascade-0+models`.
    pub const CASCADE2: HeaderName = HeaderName::from_static("x-guard-cascade2");
    pub const POLICY: HeaderName = HeaderName::from_static("x-guard-policy-applied");
    pub const THRESHOLD: HeaderName = HeaderName::from_static("x-guard-score-threshold");
    /// Сколько маркеров не удалось развернуть (прокси, §8 шаг 7c): absent при
    /// нуле, потому что ноль — это «развернулось всё», а не «мы не знали».
    pub const UNRESOLVED: HeaderName = HeaderName::from_static("x-guard-unresolved");
    /// Тело ответа upstream не разобрано как JSON: разворота не было, и маркеры
    /// ушли к клиенту дословно. `1` — и только при отказе: отсутствие заголовка
    /// означает «развернулось», а не «мы не посмотрели».
    pub const MALFORMED: HeaderName = HeaderName::from_static("x-guard-malformed");
}

/// Состояние демона: конфиг + схема, читаемые каждым запросом.
///
/// `Arc` внутри, чтобы `Clone` у роутера не копировал схему: на шаге 6 это
/// копейки, но `PUT /v1/schema` (шаг 8) подменит её целиком, и гонка
/// копирования стала бы видимой в ответах.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

/// Внутреннее состояние за `Arc`: видно крейту (модуль `tray` держит общий
/// `Arc` через [`AppState::inner_arc`], #128), поля остаются приватными
/// модуля `http`.
pub struct Inner {
    cfg: Config,
    schema: Schema,
    health: Health,
    vault: Vault,
    client: crate::proxy::Client,
    /// Конфиг загрузки весов (#192), собранный на старте: `FASAD_HF_HOST`
    /// резолвится при старте, не на запросе (env «при старте», решения #192).
    /// `Err` хранится, а не роняет старт: плохой `FASAD_HF_HOST` ломает
    /// кнопку, а не демон (`/health` остаётся жив, отказ — кодом endpoint).
    fetch: Result<crate::fetch::FetchConfig, crate::fetch::FetchError>,
    /// Старт В РЕЖИМЕ ОЖИДАНИЯ (#198): трей-бинарь без весов поднял HTTP,
    /// каскадов нет. #316: это НАЧАЛЬНОЕ состояние доставки, а не приговор:
    /// горячий монтаж (`cascades::live_mount` = swap + атомарный флаг)
    /// снимает режим на лету, «перезапусти» = заменяющее (оператор-требование
    /// #316). Живое чтение — [`AppState::pending`]; юнит-роутеры живут с
    /// флагом `false` и фейковым mount, провайдер отказа = один на четыре
    /// маршрута (analyze/anonymize/deanonymize/chat).
    start_pending: bool,
}

impl Inner {
    /// Хранилище для держателя общего `Arc` (модуль `tray`, #128): те же
    /// счётчики, что читает `health_handler`, — один объект, расхождения
    /// tooltip ↔ `/health` не существует по построению.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }
}

impl AppState {
    /// Собрать состояние из уже проверенных конфига и схемы.
    ///
    /// Оба параметра пришли из `Config::from_env` / `Schema::from_config`, т.е.
    /// отказ старта уже случился бы раньше — здесь инвариант, а не валидация.
    #[must_use]
    pub fn new(cfg: Config, schema: Schema, health: Health, vault: Vault) -> Self {
        Self::with_pending(cfg, schema, health, vault, false)
    }

    /// [`new`](Self::new) + флаг ожидающего старта (#198, ставит `main`
    /// трей-контура при отказе модельного пути: UI живёт, модельный отказ =
    /// 503 `models_pending`, а не 200-обман каскадом 0).
    #[must_use]
    pub fn with_pending(
        cfg: Config,
        schema: Schema,
        health: Health,
        vault: Vault,
        pending: bool,
    ) -> Self {
        let client = crate::proxy::Client::new(&cfg);
        let fetch = crate::fetch::FetchConfig::from_config(&cfg);
        Self {
            inner: Arc::new(Inner {
                cfg,
                schema,
                health,
                vault,
                client,
                fetch,
                start_pending: pending,
            }),
        }
    }

    /// Конфиг (пороги, лимит тела, режим vault).
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    /// Рабочая схема классов.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.inner.schema
    }

    /// Ответ `/health`.
    #[must_use]
    pub fn health(&self) -> Health {
        self.inner.health.clone()
    }

    /// Ожидающий старт (#198) В ЖИВОМ ЧТЕНИИ (#316): true = веса ещё не
    /// примонтированы (model-маршруты = 503 `models_pending`). Флаг =
    /// стартовое «режим доставки» И НЕ смонтированность сейчас
    /// (`cascades::mounted_live`): hot-mount swap переводит все четыре
    /// маршрута с 503 на 200 без единого перезапуска.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.inner.start_pending && !crate::cascades::mounted_live()
    }

    /// Отказ модельного контура (#198): единый провайдер для четырёх
    /// маршрутов, которые требуют каскадов (analyze/anonymize/deanonymize/
    /// proxy). `None` = контур готов; `Some` = 503 со своим кодом — не
    /// молчание и не каскад-0-обман (fail-closed: без весов анализ =
    /// отказ, а не частичная защита).
    #[must_use]
    pub fn model_refusal(&self) -> Option<ApiError> {
        self.pending().then(|| {
            ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "models_pending",
                "модельный контур не смонтирован: веса не скачаны (UI: «Скачать веса» — \
                 каскады подхватятся на лету, #316)",
            )
        })
    }

    /// Живой stage (#316): старт-строка, а на desktop-контуре ожидавшего
    /// старта — `cascade-0+models` сразу после hot-mount. Один источник для
    /// `/health`, `X-Guard-Stage`, `/v1/status` (tray читает `status_of` =
    /// тот же). Не «каскад-0 под вывеской»: `mounted_live`=true = смонтировано
    /// по-настоящему (fail-closed #185 цел: флаг ставит только успешный
    /// `OnnxMount::load`).
    #[must_use]
    pub fn live_stage(&self) -> &'static str {
        if self.inner.start_pending && crate::cascades::mounted_live() {
            crate::cascades::STAGE_MOUNTED
        } else {
            self.inner.health.stage
        }
    }

    /// Живой `Health` (#316): stage = live-чтение; поля копируемые дешёво
    /// (`&'static str`), «`health()` = cheap» контракта держится.
    #[must_use]
    pub fn live_health(&self) -> crate::Health {
        crate::Health {
            version: self.inner.health.version,
            stage: self.live_stage(),
            mode: self.inner.health.mode,
        }
    }

    /// Хранилище обратимых подмен.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.inner.vault
    }

    /// #318 (debug-харнес): состояние с ЯВНЫМ `start_pending` для трей-контры
    /// `stage_reader` (прод-путь = `with_pending`, этот = конструктор тестов).
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    #[allow(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::must_use_candidate
    )] // тестовая фабрика (panic = красный CI)
    pub fn harness_pending(stage: &'static str) -> Self {
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let health = crate::Health {
            version: env!("CARGO_PKG_VERSION"),
            stage,
            mode: cfg.vault_mode.as_str(),
        };
        let vault = crate::vault::Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище");
        Self::with_pending(
            cfg,
            crate::schema::Schema::embedded().expect("канон"),
            health,
            vault,
            true,
        )
    }

    /// Общее владение состоянием роутера — для **главного потока трея** (#128
    /// фаза 2).
    ///
    /// Отдаётся весь `Arc<Inner>`, а не второй `Arc<Vault>`: трей читает те же
    /// счётчики, что `/health` (`vault()`), и обязан видеть тот же объект —
    /// две копии сошлись бы враньём в tooltip. Публичного `Arc`-доступа к
    /// роутеру это не открывает: поле `inner` приватно, accessor `pub(crate)`.
    ///
    /// #318: трей строит ЗАМЫКАНИЕ живого stage над этим `Arc` (замыкает
    /// `AppState::live_stage`-выражение), поэтому tooltip/иконка = тот же
    /// атом `MOUNT_LIVE`, что `/health` (#316): hot-mount = трей-строка
    /// flip-ается на следующем тике, статика старта в вине не остаётся.
    #[must_use]
    pub fn inner_arc(&self) -> Arc<Inner> {
        Arc::clone(&self.inner)
    }

    /// Живой stage ЗАМЫКАНИЕМ для трея (#318): трей-контур (win/mac, §16)
    /// не видит `AppState` (главный поток = `Arc<Inner>`), но обязан читать
    /// stage ЖИВО, иначе после hot-mount #316 tooltip врёт «models-pending»
    /// при смонтированных каскадах (#226-контра видимости). Фолбэк =
    /// статика `base` (харнеси/контуры без ожидающего старта: live = base).
    #[must_use]
    pub fn stage_reader(&self) -> crate::StageFn {
        let st = self.clone();
        std::sync::Arc::new(move || st.live_stage())
    }

    /// #318 (debug-харнес): тот же reader для `Arc<Inner>` (трей-тесты
    /// держат `Arc<Inner>`, как прод-`main`).
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    #[allow(clippy::must_use_candidate)]
    pub fn stage_reader_of(inner: &std::sync::Arc<Inner>) -> crate::StageFn {
        let inner = std::sync::Arc::clone(inner);
        std::sync::Arc::new(move || {
            if inner.start_pending && crate::cascades::mounted_live() {
                crate::cascades::STAGE_MOUNTED
            } else {
                inner.health.stage
            }
        })
    }

    /// Пул клиентов прокси (`/v1/chat/completions`).
    #[must_use]
    pub fn client(&self) -> &crate::proxy::Client {
        &self.inner.client
    }

    /// Конфиг загрузки весов (#192): копия `Result`. `Ok` = endpoints
    /// работают; `Err` несёт класс отказа (плохой `FASAD_HF_HOST`);
    /// отсутствие каталога (`dir: None`) = случай HOME-unset-машины,
    /// endpoint отвечает отдельным классом.
    ///
    /// # Errors
    ///
    /// [`crate::fetch::FetchError`] класса `host_denied` (плохой
    /// `FASAD_HF_HOST`): витрина и `/v1/models/fetch` отвечают им как 503,
    /// старт демона — нет.
    pub fn fetch_config(&self) -> Result<crate::fetch::FetchConfig, crate::fetch::FetchError> {
        self.inner.fetch.clone()
    }

    /// Снимок состояния загрузки для `GET /v1/status` (слот процесс-global,
    /// тот же, в который пишет `spawn_blocking`).
    pub fn fetch_state(&self) -> crate::weights::FetchState {
        crate::weights::fetch_slot()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Собирает корневой роутер демона.
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)] // axum-роутер: отказ = ответ, не Result
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/analyze", post(analyze_handler))
        .route("/v1/anonymize", post(anonymize_handler))
        .route("/v1/deanonymize", post(deanonymize_handler))
        .route("/v1/chat/completions", post(crate::proxy::handle))
        .route("/v1/sessions/{id}", delete(invalidate_handler))
        // #192 UX первого запуска: статус весов + загрузка по клику.
        // `GET /v1/status` — как `/health`: loopback-контур, auth-none, ПДн
        // в ответе нет по построению (layout-имена, размеры, revision,
        // относительные пути — домашнего пути нет).
        .route("/v1/status", get(status_handler))
        .route("/v1/models/fetch", post(fetch_models_handler))
        // #219/#220: страница «Настройки». GET = read-only список
        // РАЗРЕШЁННЫХ ключей с эффективными значениями и источниками; POST =
        // запись в файл конфигурации (белый список, валидаторы env-контура,
        // атомарная запись). Секретов в GET нет по построению таблицы
        // (`FILE_ALLOWED_KEYS` не содержит VAULT_KEY/BIND), путь файла =
        // пользовательский путь (не ПДн), loopback-контур = тот же, что
        // `/v1/status` (#192 прецедент: витрина первого запуска).
        .route("/v1/config", get(config_handler).post(config_write_handler))
        .merge(crate::ui::router())
        .with_state(state)
}

/// Ответ `/health` с счётчиками деградации хранилища.
///
/// Статика [`Health`] лежит на верхнем уровне, как лежала: добавляется только
/// объект `vault`. Счётчики здесь, а не в отладочном режиме, потому что обе
/// метрики молчат по отдельности: `surrogate_fallbacks` растёт, когда пул мал,
/// `unrestored_mismatch` — когда разворот отказал по расхождению с
/// реверс-индексом. Оператор обязан видеть это до разбора логов.
#[derive(Debug, serde::Serialize)]
struct HealthReply {
    #[serde(flatten)]
    health: Health,
    vault: VaultCounters,
}

#[derive(Debug, serde::Serialize)]
struct VaultCounters {
    /// ФИО, ушедших на метку вместо суррогата из-за занятого слота.
    surrogate_fallbacks: u64,
    /// Разворотов, отказавших по расхождению формы с реверс-индексом.
    unrestored_mismatch: u64,
}

async fn health_handler(State(st): State<AppState>) -> axum::Json<HealthReply> {
    // Ответ осознанно не содержит никаких пользовательских данных (§1 п.6:
    // весь разбор завершается на 127.0.0.1 до первой сокет-операции).
    let vault = st.vault();
    axum::Json(HealthReply {
        // #316: stage = живое чтение (hot-mount = stage без перезапуска).
        health: st.live_health(),
        vault: VaultCounters {
            surrogate_fallbacks: vault.surrogate_fallbacks(),
            unrestored_mismatch: vault.unrestored_mismatch(),
        },
    })
}

// ── #219/#220: страница «Настройки» (GET/POST /v1/config) ──────────────────

/// Путь файла конфигурации, который прочитал демон (`main`, #220).
///
/// Слот процесс-global по той же причине, что `weights::fetch_slot`: POST
/// обязан писать ТОТ ЖЕ файл, который был прочитан на старте, а не резолвить
/// путь повторно на запросе — `FASAD_CONFIG` процесса неизменен с момента
/// старта, и вторая правда о пути (резолв на запросе) дала бы «пишем не туда,
/// где читали». `None` = резолв на старте не дал пути (ни `FASAD_CONFIG`, ни
/// `HOME`/`APPDATA`/`XDG_CONFIG_HOME`): POST отвечает классом, а не пишет в
/// пустой путь.
static CONFIG_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Записать путь (вызывает `main` один раз, до подъёма сокета).
pub fn set_config_path(path: Option<std::path::PathBuf>) {
    let mut slot = CONFIG_PATH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = path;
}

/// Текущий путь файла конфигурации (для ответов и юнитов).
#[must_use]
pub fn config_path() -> Option<std::path::PathBuf> {
    CONFIG_PATH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Одна строка `GET /v1/config`.
#[derive(Debug, serde::Serialize)]
struct ConfigRow {
    key: &'static str,
    label: &'static str,
    value: String,
    source: &'static str,
    ui_editable: bool,
    restart_required: bool,
}

/// Ответ `GET /v1/config` (#220).
#[derive(Debug, serde::Serialize)]
struct ConfigReply {
    #[serde(flatten)]
    health: Health,
    /// Путь файла конфигурации (tilde-форма, как витрина весов) + существует ли.
    file: ConfigFileInfo,
    /// Разрешённые ключи с эффективными значениями. Секретов здесь нет по
    /// построению таблицы (док у [`crate::config::Config::view`]).
    entries: Vec<ConfigRow>,
    /// `FASAD_VAULT_KEY` = «задан/нет», значение НЕ отдаётся (#220: секрет
    /// показывается фактом наличия, не байтами).
    vault_key: &'static str,
    /// Бинд: read-only (только env, инвариант loopback).
    bind: String,
    /// Потоки/режим — то, что витрина показывает крупно.
    threads: usize,
    mode: &'static str,
}

#[derive(Debug, serde::Serialize)]
struct ConfigFileInfo {
    path: String,
    exists: bool,
}

fn config_reply_of(st: &AppState) -> axum::Json<ConfigReply> {
    let cfg = st.config();
    let path = config_path();
    let file = ConfigFileInfo {
        path: path.as_deref().map_or_else(
            || "не определён (задай FASAD_CONFIG или HOME)".to_owned(),
            tilde_dir,
        ),
        exists: path.as_deref().is_some_and(std::path::Path::exists),
    };
    let entries = cfg
        .view()
        .into_iter()
        .map(|v| ConfigRow {
            key: v.key,
            label: v.label,
            // Хост загрузки весов живёт в `FetchConfig` (#192), не в `Config`:
            // пустую строку из `effective_value` подменяем его значением —
            // одной правдой, а не двумя.
            value: if v.key == "FASAD_HF_HOST" {
                st.fetch_config()
                    .map(|fc| fc.host_display())
                    .unwrap_or_default()
            } else {
                v.value
            },
            // Источник = тот же контур, что и значение: env (живьём, с
            // нормализацией trim) > файл (`file_keys`) > дефолт. Ревью #224
            // MAJOR-2: GET не имеет права врать парой «значение из env,
            // source=file».
            source: effective_source(v.key, v.source),
            ui_editable: v.ui_editable,
            restart_required: v.restart_required,
        })
        .collect();
    axum::Json(ConfigReply {
        health: st.live_health(),
        file,
        entries,
        vault_key: crate::config::secret_present(std::env::var("FASAD_VAULT_KEY").ok().as_deref()),
        bind: cfg.addr.to_string(),
        threads: cfg.threads,
        mode: cfg.vault_mode.as_str(),
    })
}

async fn config_handler(State(st): State<AppState>) -> axum::Json<ConfigReply> {
    config_reply_of(&st)
}

/// Источник значения для витрины: env с НЕПУСТЫМ значением побеждает всё
/// (та же нормализация, что у цепочки загрузки), иначе — сохранённый источник
/// сборки (`Config::source_of` уже честно развёл file/default по срезу файла).
fn effective_source(key: &'static str, stored: crate::config::ValueSource) -> &'static str {
    use crate::config::ValueSource;
    let src = match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => ValueSource::Env,
        _ => stored,
    };
    src.as_str()
}

/// Тело `POST /v1/config`: `{ключ, значение}` (#220).
#[derive(Debug, serde::Deserialize)]
struct ConfigWriteRequest {
    key: String,
    value: String,
}

/// Ответ `POST /v1/config`: запись применится только после перезапуска.
#[derive(Debug, serde::Serialize)]
struct ConfigWriteReply {
    ok: bool,
    key: String,
    value: String,
    path: String,
    restart_required: bool,
    message: String,
}

async fn config_write_handler(
    State(st): State<AppState>,
    body: axum::body::Bytes,
) -> Result<axum::Json<ConfigWriteReply>, ApiError> {
    let req: ConfigWriteRequest = serde_json::from_slice(&body).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            &format!("ожидается JSON c полями key/value: {e}"),
        )
    })?;
    // Белый список + запрет секретов — на входе, ДО валидатора: отказ обязан
    // называть причину «ключ не записывается из UI», а не «значение плохое».
    if crate::config::is_forbidden_file_key(&req.key) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "key_forbidden",
            &format!(
                "ключ {} запрещён к записи: {}",
                req.key,
                crate::config::forbidden_file_key_reason(&req.key)
                    .unwrap_or("см. README §Файл конфигурации")
            ),
        ));
    }
    if !crate::config::ui_editable_key(&req.key) {
        let known = crate::config::allowed_key(&req.key).is_some();
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            if known {
                "key_read_only"
            } else {
                "key_unknown"
            },
            &format!(
                "ключ {} не редактируется из UI ({})",
                req.key,
                if known {
                    "только файл/env"
                } else {
                    "нет в белом списке"
                }
            ),
        ));
    }
    // Значение валидируется против ЭФФЕКТИВНЫХ порогов живого демона:
    // «gray_hi=0.1 при gray_lo=0.22» = 422 с текстом инварианта, а не файл,
    // на котором демон не стартует (#219 §D).
    let canonical = crate::config::allowed_key(&req.key)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "key_unknown", "ключ не разобран"))?;
    let cfg = st.config();
    crate::config::validate_value(
        canonical,
        &req.value,
        &cfg.thresholds,
        cfg.proxy_loopback_http,
    )
    .map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_value",
            &e.to_string(),
        )
    })?;
    let path = config_path().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "config_path_unknown",
            "путь файла конфигурации не определён (ни FASAD_CONFIG, ни HOME/APPDATA/XDG): \
             запиши FASAD_CONFIG=<путь> при запуске",
        )
    })?;
    crate::config::write_config_value(&path, canonical, &req.value, cfg).map_err(|e| match e {
        crate::config::ConfigError::FileKeyForbidden { .. } => {
            ApiError::new(StatusCode::FORBIDDEN, "key_forbidden", &e.to_string())
        }
        crate::config::ConfigError::FileUnreadable { .. } => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_write_failed",
            &e.to_string(),
        ),
        other => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_value",
            &other.to_string(),
        ),
    })?;
    Ok(axum::Json(ConfigWriteReply {
        ok: true,
        key: canonical.to_owned(),
        value: req.value.trim().to_owned(),
        path: tilde_dir(&path),
        restart_required: true,
        // hot-reload вне контура #219 (монтаж/сокет = старт-время): ответ
        // обязан говорить это, а не «сохранено» (тогда «не применилось» =
        // ложь интерфейса).
        message: "сохранено; требуется перезапуск демона".to_owned(),
    }))
}

// ── #192: статус весов + загрузка по клику ─────────────────────────────────

/// Ответ `GET /v1/status`: витрина первого запуска (ТЗ #192 B).
#[derive(Debug, serde::Serialize)]
struct StatusReply {
    #[serde(flatten)]
    health: Health,
    vault: VaultCounters,
    weights: WeightsStatus,
    fetch: crate::weights::FetchState,
    mount: MountStatus,
    model: ModelInfo,
}

/// Горячий монтаж (#316): `live` = каскады 1–2 работают СЕЙЧАС;
/// `last_error` = причина последней неудачи (UI = «веса повреждены,
/// перескачай» = #198-класс, pending честный, HTTP жив).
#[derive(Debug, serde::Serialize)]
struct MountStatus {
    live: bool,
    last_error: Option<String>,
}

/// Каталог + раскладка. `dir` — РАЗРЕШЁННЫЙ путь (env или дефолт #192);
/// наружу отдаётся относительная форма (`~`-префикс): домашний путь — не
/// секрет на loopback-демоне, но `/health`-контур «секретов не светим»
/// распространяется и сюда (AGENTS: Debug-вывод только `[REDACTED]`-класс).
#[derive(Debug, serde::Serialize)]
struct WeightsStatus {
    /// Раскрытый каталог весов (tilde-форма).
    dir: String,
    /// Путь взят из дефолта (env `FASAD_MODEL_DIR` unset) — UI рисует
    /// «по умолчанию».
    default: bool,
    /// Пять файлов layout: присутствие + размер против манифеста.
    present: Vec<crate::weights::WeightFile>,
}

/// Витрина модели: из **вшитого** манифеста (оффлайн-источник, ТЗ #192 B).
#[derive(Debug, serde::Serialize)]
struct ModelInfo {
    lockr_revision: Option<String>,
    arbiter_revision: Option<String>,
    /// Число записей манифеста (0 = манифест вшитый испорчен; UI обязан это
    /// показать, а не молчать — ложь о причине отказа).
    manifest_records: usize,
}

fn tilde_dir(p: &std::path::Path) -> String {
    // Только для витрины: `C:\Users\alex\...` → `~\...`.
    // #264: единая точка домашнего каталога (`HOME` → `USERPROFILE`).
    crate::config::default_home_dir(|k| std::env::var(k).ok())
        .and_then(|h| h.to_str().map(str::to_owned))
        .and_then(|h| {
            p.strip_prefix(&h)
                .ok()
                .map(|r| format!("~{}{}", std::path::MAIN_SEPARATOR, r.display()))
        })
        .unwrap_or_else(|| p.display().to_string())
}

async fn status_handler(State(st): State<AppState>) -> axum::Json<StatusReply> {
    status_reply_of(&st)
}

/// Тело `GET /v1/status` — свободная функция (юнит-зуб #198 монтирует
/// `AppState` с `pending=true` и требует витрину СВОЕЙ stage-строкой, не
/// `cfg.stage()`: харнеси (`from_lookup`) живут stage-семантикой cascade-0,
/// ожидающий старт = отдельная строка).
fn status_reply_of(st: &AppState) -> axum::Json<StatusReply> {
    let cfg = st.config();
    let vault = st.vault();
    let entries = crate::weights::embedded_entries();
    // model_dir = Some на весь runtime после #192-дефолта (кроме HOME-unset);
    // витрина обязана жить и там: fallback на дефолт от HOME напрямую.
    // Тот же резолв, что у `FetchConfig`: env-граница + fallback (витрина
    // обязана показывать тот путь, в который пишет кнопка, а не другой).
    let dir = st
        .fetch_config()
        .ok()
        .and_then(|fc| fc.dir.clone())
        .or_else(|| cfg.model_dir.clone());
    let (dir_s, default) = match dir.as_deref() {
        Some(d) => {
            let is_default = match std::env::var("FASAD_MODEL_DIR") {
                Ok(v) => v.trim().is_empty(),
                Err(_) => true,
            };
            (tilde_dir(d), is_default)
        }
        // HOME недоступен и env нет: витрина честная — путь неизвестен.
        None => (String::new(), false),
    };
    let present = dir
        .as_deref()
        .map(|d| crate::weights::scan(d, &entries))
        .unwrap_or_default();
    let lockr = crate::weights::entry_by_role(&entries, crate::weights::ROLE_LOCKR_MODEL)
        .map(|e| e.revision.clone());
    let arb = crate::weights::entry_by_role(&entries, crate::weights::ROLE_ARB_WEIGHTS)
        .map(|e| e.revision.clone());
    axum::Json(StatusReply {
        // #316: stage = живое чтение (hot-mount = смена stage без перезапуска).
        health: st.live_health(),
        vault: VaultCounters {
            surrogate_fallbacks: vault.surrogate_fallbacks(),
            unrestored_mismatch: vault.unrestored_mismatch(),
        },
        weights: WeightsStatus {
            dir: dir_s,
            default,
            present,
        },
        fetch: st.fetch_state(),
        mount: MountStatus {
            live: crate::cascades::mounted_live(),
            last_error: crate::cascades::mount_last_error(),
        },
        model: ModelInfo {
            lockr_revision: lockr,
            arbiter_revision: arb,
            manifest_records: entries.len(),
        },
    })
}

/// `POST /v1/models/fetch` — запуск фоновой загрузки весов (#192).
///
/// Тело запроса не читается (инъекций из него не собирается). Один job на
/// процесс: повторный клик во время `running` = 409 `fetch_running` (не
/// «приму и сделаю дважды»). Прогресс — поллом `GET /v1/status`.
async fn fetch_models_handler(State(st): State<AppState>) -> Response {
    let entries = crate::weights::embedded_entries();
    if entries.is_empty() {
        // Манифест вшитый испорчен = качать нечего и некуда: отказ классом,
        // не молчание.
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "manifest_unparsable",
            "вшитый манифест весов не разобран (сборка испорчена)",
        )
        .into_response();
    }
    let fc = match st.fetch_config() {
        Ok(fc) => fc,
        Err(e) => {
            return ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                e.code(),
                &format!("загрузка не настраивается: {}", e.display_safe()),
            )
            .into_response();
        }
    };
    if fc.dir.is_none() {
        // HOME-unset-машина: класс отдельный, не io-ошибка на пустом пути.
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::fetch::E_NO_DIR,
            "каталог весов не определён (FASAD_MODEL_DIR unset и HOME недоступен)",
        )
        .into_response();
    }
    // Занято? (один job) — до постановки: 409, а не «accepted, второй промолчит».
    if crate::weights::fetch_busy() {
        return ApiError::new(
            StatusCode::CONFLICT,
            "fetch_running",
            "загрузка уже идёт (GET /v1/status.fetch)",
        )
        .into_response();
    }
    crate::weights::set_fetch_state(crate::weights::FetchState::Running {
        index: 0,
        total: crate::weights::layout().len(),
        progress: crate::weights::Progress {
            file: crate::weights::layout()[0],
            bytes_done: 0,
            bytes_total: 0,
            phase: crate::weights::Phase::Download,
        },
    });
    // #316: детерминированный триггер горячего монтажа = УСПЕХ fetch (не
    // poll-only): после Done-состояния, ОФОШНУВ пул-тред (ORT-load 2–3 с =
    // НЕ HTTP-тред), live_mount из того же каталога, что скачали. Кнопка
    // «Скачать веса» = кончается качание = монтирование; poll-поток = страховка
    // для ВНЕШНЕЙ докачки (cli/scp). Idempotency = `live_mount` (второй =
    // NOOP при mounted_live; после Load-отказа poll-контур не перетриггерит).
    let mount_cfg = st.config().clone();
    let mount_dir = fc.dir.clone();
    let spawn = tokio::task::spawn_blocking(move || {
        crate::fetch::run_fetch(fc, entries);
        let done = crate::weights::fetch_slot()
            .lock()
            .is_ok_and(|g| matches!(*g, crate::weights::FetchState::Done { .. }));
        // Fail-closed: неудача = причина в `mount_last_error` (UI
        // «перескачай»), слот не тронут, HTTP жив (#198-решётка).
        if done
            && let Some(dir) = mount_dir
            && let Err(e) = crate::cascades::live_mount(&mount_cfg, &dir)
        {
            eprintln!("fasad: hot-mount после докачки не сложился ({e}) (#316)");
        }
    });
    if spawn.is_finished() {
        // Пул задач лёг мгновенно (дерьмо-машина): честный отказ, не «running
        // навсегда». Нормальный путь — is_finished() == false на возврате.
        let _ = spawn.await;
        crate::weights::set_fetch_state(crate::weights::FetchState::Failed {
            file: String::new(),
            error: "spawn_blocking: пул задач недоступен".to_owned(),
        });
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "fetch_spawn_failed",
            "фоновый поток загрузки не поднят",
        )
        .into_response();
    }
    (
        StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({
            "started": true,
            "files": crate::weights::layout().len(),
            "poll": "/v1/status"
        })),
    )
        .into_response()
}

async fn analyze_handler(State(st): State<AppState>, req: Request) -> Response {
    let (headers, body) = match read_body(st.clone(), req).await {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    guarded(move || {
        // #198: ожидающий старт = отказ модельных маршрутов своим кодом.
        // Каскад-0 на pending НЕ выпускается: релизный контур без весов,
        // объявленный «защищённым», = тихая деградация (#185), а не продукт.
        if let Some(refusal) = st.model_refusal() {
            return Err(refusal);
        }
        let req: AnalyzeRequest = json_body(&body)?;
        let policy = parse_policy(&headers)?;
        let res = pipeline::analyze(&req, st.schema(), st.config(), policy)
            .map_err(ApiError::from_analysis)?;
        Ok(analysis_response(&res))
    })
}

/// Обёртка «паника обработчика = отказ, а не пропускаем запрос».
///
/// Инвариант SPEC: `panic = "unwind"` — паника одного запроса не валит демон.
/// Без обёртки unwind означает «соединение разорвано», и клиент получает
/// оборванный ответ вместо 5xx; обёртка превращает панику в `503
/// internal_panic` с пустым телом: в паническом сообщении может быть фрагмент
/// входа, а вход — `ПДн`.
pub(crate) fn guarded(f: impl FnOnce() -> Result<Response, ApiError>) -> Response {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => err.into_response(),
        Err(_) => ApiError::panic().into_response(),
    }
}

/// Заголовки SPEC §8 одним местом: счётчик, латентность, стадия каскада.
///
/// Значения пишутся только фактические: absent лучше фиктивного нуля, поэтому
/// недостижимый `HeaderValue` (значение не влезает в 8 КБ заголовка) просто
/// не добавляет заголовок, а не врёт.
fn guard_headers(
    map: &mut HeaderMap,
    count: impl std::fmt::Display,
    latency_ms: u128,
    stage: &str,
) {
    insert(map, h::COUNT, count);
    insert(map, h::LATENCY, latency_ms);
    insert(map, h::STAGE, stage);
}

/// Чтение тела с нашим лимитом и нашим же ответом на переполнение.
///
/// Экстрактор `Bytes` + слой `DefaultBodyLimit` дают 413 с текстом axum
/// («Failed to buffer the request body…»), т.е. вне нашего контрактного
/// конверта `{"error":{…}}`: клиент, который различает 4xx по `code`, на
/// переполнении тела слепнет. Поэтому тело читается здесь, а лимит берётся из
/// конфига; `Content-Length` при этом не доверен — считается фактически
/// прочитанное (заголовок можно соврать).
///
/// Свой счётчик нужен и по второй причине: `axum_core::Error` — прозрачная
/// обёртка над `BoxError`, `is_length_limit()` в 0.5.6 нет (промер исходника
/// crate), т.е. через `to_bytes` «слишком длинно» неотличимо от «поток
/// оборвался посередине». Врать о причине — тот же fail-open, только в
/// диагностике, поэтому перелив лимита даёт 413 `body_too_large`, а битый
/// фрейм — 400 `bad_body`. Остаток тела не дочитываем: hyper закроет соединение
/// после ответа, а клиенту наше решение о его теле не сообщаем.
pub(crate) async fn read_body(
    st: AppState,
    req: Request,
) -> Result<(HeaderMap, axum::body::Bytes), ApiError> {
    use http_body_util::BodyExt as _;
    let limit = st.config().max_body_bytes;
    let idle = Duration::from_millis(st.config().read_timeout_ms);
    let (parts, mut body) = req.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // Тишина между кусками дольше бюджета = `408 read_timeout`, а не 413:
        // перелив и молчание — разные отказы, и клиент по коду выбирает, что
        // чинить (первое — тело, второе — скорость отправки).
        let Ok(next) = tokio::time::timeout(idle, body.frame()).await else {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "read_timeout",
                "клиент молчал дольше FASAD_READ_TIMEOUT_MS",
            ));
        };
        match next {
            None => break,
            Some(Err(_)) => {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_body",
                    "тело пришло битым фреймом или оборвалось",
                ));
            }
            Some(Ok(frame)) => {
                // Трейлеры контракту тела не нужны: `into_data` ошибается именно
                // на них, и это единственный ожидаемый ошибочный ход.
                if let Ok(data) = frame.into_data() {
                    if buf.len() + data.len() > limit {
                        return Err(ApiError::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "body_too_large",
                            "тело больше FASAD_MAX_BODY_BYTES",
                        ));
                    }
                    buf.extend_from_slice(&data);
                }
            }
        }
    }
    Ok((parts.headers, buf.into()))
}

/// Разбор JSON-тела руками (не экстрактором `Json`): rejection-сообщения axum
/// и `serde_json` пересказывают вход, а вход — потенциальные `ПДн`.
pub(crate) fn json_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "тело не является ожидаемым JSON-объектом",
        )
    })
}

/// Роутер с тестовым зондом: `/__probe_panic` паникует внутри того же
/// `guarded`, через который завёрнуты все четыре рабочих обработчика. Отдельная
/// функция, а не правка `router`, чтобы продакшн-роутер не знал про тесты.
#[cfg(test)]
pub fn router_with_panic_probe(state: AppState) -> Router {
    router(state).route("/__probe_panic", get(probe_panic))
}

#[cfg(test)]
async fn probe_panic() -> Response {
    guarded(|| panic!("СЕКРЕТ-ПДН-МАРКЕР из обработчика"))
}

/// `POST /v1/anonymize`: принимает опись спанов от `/v1/analyze` (или свою) и
/// возвращает переписанный текст. Счётчик подмен = `X-Guard-Redacted-Count`.
async fn anonymize_handler(State(st): State<AppState>, req: Request) -> Response {
    let (headers, body) = match read_body(st.clone(), req).await {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    let started = Instant::now();
    guarded(move || {
        let req: AnonymizeRequest = json_body(&body)?;
        if let Some(refusal) = st.model_refusal() {
            return Err(refusal);
        }
        let session = session_of(&headers)?;
        let anon = st
            .vault()
            .anonymize(session, &req.text, &req.spans, st.schema())
            .map_err(|ref err| ApiError::from_vault(err))?;
        let count = anon.items.len();
        let stage = st.live_stage(); // #316 live
        let mut resp = axum::Json(anon).into_response();
        guard_headers(
            resp.headers_mut(),
            count,
            started.elapsed().as_millis(),
            stage,
        );
        Ok(resp)
    })
}

/// `POST /v1/deanonymize`: обратный ход.
///
/// `X-Guard-Redacted-Count` на этом роуте равен `substituted` из тела — число
/// развёрнутых токенов. Смысл заголовка по §8 («сколько `ПДн` замазано») тут не
/// переворачивается: он просто не про подмену, а единая сетка `X-Guard-*` на
/// четырёх маршрутах того стоит (клиент читает заголовок на любом 2xx, не
/// разбирая маршрут). Убрать заголовок здесь было бы хуже: отсутствие клиенты
/// приравнивают к нулю, а ноль на deanonymize означал бы «не развернулось
/// ничего». Точные значения по роутам — README, §«Заголовки SPEC §8».
/// Промер живым сокетом этой сессии: `x-guard-redacted-count: 2` при
/// `substituted: 2`.
async fn deanonymize_handler(State(st): State<AppState>, req: Request) -> Response {
    let (headers, body) = match read_body(st.clone(), req).await {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    let started = Instant::now();
    guarded(move || {
        if let Some(refusal) = st.model_refusal() {
            return Err(refusal);
        }
        let req: DeanonymizeRequest = json_body(&body)?;
        let session = session_of(&headers)?;
        let done = st
            .vault()
            .deanonymize(session, &req.text)
            .map_err(|ref err| ApiError::from_vault(err))?;
        let count = done.substituted;
        let stage = st.live_stage(); // #316 live
        let mut resp = axum::Json(done).into_response();
        guard_headers(
            resp.headers_mut(),
            count,
            started.elapsed().as_millis(),
            stage,
        );
        Ok(resp)
    })
}

/// `DELETE /v1/sessions/{id}` — teardown: кэш оригиналов и реестр форм.
async fn invalidate_handler(
    State(st): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let started = Instant::now();
    guarded(move || {
        let dropped = st.vault().invalidate(&id);
        let stage = st.live_stage(); // #316 live
        let mut resp = (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "deleted": dropped })),
        )
            .into_response();
        guard_headers(
            resp.headers_mut(),
            dropped,
            started.elapsed().as_millis(),
            stage,
        );
        Ok(resp)
    })
}

/// `X-Session-ID` из заголовков: отсутствие (или пустое значение) = `None`,
/// а непечатаемое значение = `Err`.
///
/// Различать обязаны: отвечать «заголовка нет» клиенту, который его прислал,
/// значит соврать о причине отказа. Само значение наружу не цитируется —
/// непечатаемые байты в сообщении были бы каналом в логи потребителя.
pub(crate) fn session_of(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    match headers.get(HEADER_SESSION) {
        None => Ok(None),
        Some(raw) => raw
            .to_str()
            .map(|v| (!v.is_empty()).then_some(v))
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "X-Session-ID не является печатаемым ASCII",
                )
            }),
    }
}

/// Разбор `X-Guard-Policy`: отсутствие = `mask` (дефолт SPEC §8), неизвестное
/// значение = 400, а не тихий откат к дефолту.
pub(crate) fn parse_policy(headers: &HeaderMap) -> Result<Policy, ApiError> {
    match headers.get(HEADER_POLICY) {
        None => Ok(Policy::Mask),
        Some(raw) => raw
            .to_str()
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_policy",
                    "X-Guard-Policy содержит непечатаемые байты",
                )
            })
            .and_then(|v| Policy::parse(v).map_err(ApiError::from_analysis)),
    }
}

/// 200 + спаны + счётчики `X-Guard-*` (SPEC §8).
fn analysis_response(res: &Analysis) -> Response {
    let mut out = axum::Json(&res.spans).into_response();
    {
        let hs = out.headers_mut();
        insert(hs, h::COUNT, res.spans.len());
        insert(hs, h::MAX_RISK, res.max_risk);
        insert(hs, h::LATENCY, res.latency_ms);
        insert(hs, h::STAGE, res.stage);
        insert(hs, h::CASCADE2, res.cascade2);
        insert(hs, h::POLICY, res.policy.as_str());
        insert(hs, h::THRESHOLD, res.threshold);
    }
    out
}

/// Вставка заголовка.
///
/// Значения — числа и статические строки, `HeaderValue::from_*` на них не
/// отказывает; отказ означал бы баг форматирования, и мы оставляем заголовок
/// отсутствующим (клиент обязан счесть отсутствие счётчика ошибкой, README), а
/// не подменяем его нулём: ноль — это утверждение «`ПДн` не найдено».
pub(crate) fn insert<T: std::fmt::Display>(map: &mut HeaderMap, name: HeaderName, value: T) {
    if let Ok(hv) = HeaderValue::from_str(&value.to_string()) {
        map.append(name, hv);
    }
}

/// Ошибка HTTP-ответа: статус + машинный код + объяснение без фрагментов входа.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP-статус.
    status: StatusCode,
    /// Машинный код (`bad_json`, `unknown_entity`, …).
    code: &'static str,
    /// Пояснение; пользовательских данных не содержит по построению.
    message: String,
}

impl ApiError {
    /// Сообщение паники: одно на все места, потому что «обработчик паниковал»
    /// — это факт об обработчике, а не о запросе, и варьировать его нечем.
    pub(crate) const PANIC_MESSAGE: &'static str =
        "обработчик паниковал; запрос отклонён (fail-closed)";

    /// `503 internal_panic`: тот же ответ, что даёт [`guarded`].
    #[must_use]
    pub(crate) fn panic() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal_panic",
            Self::PANIC_MESSAGE,
        )
    }

    pub(crate) fn new(status: StatusCode, code: &'static str, message: &str) -> Self {
        Self {
            status,
            code,
            message: message.to_owned(),
        }
    }

    /// Отвергнутый запрос ≠ сбой конвейера: 4xx на клиентские ошибки, 500 —
    /// только на нарушение нашего собственного контракта скора.
    pub(crate) fn from_analysis(e: AnalyzeError) -> Self {
        match e {
            AnalyzeError::UnknownPolicy(p) => Self::new(
                StatusCode::BAD_REQUEST,
                "bad_policy",
                &format!(
                    "X-Guard-Policy: неизвестное значение {p:?} (ожидается mask|block|audit_only)"
                ),
            ),
            AnalyzeError::UnknownEntity(c) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown_entity",
                &format!("entities: класса {c:?} в схеме нет"),
            ),
            AnalyzeError::BadThreshold(t) => Self::new(
                StatusCode::BAD_REQUEST,
                "bad_threshold",
                &format!("score_threshold {t} вне [0, 1]"),
            ),
            AnalyzeError::Score(s) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "score_contract",
                &format!("внутреннее нарушение контракта скора: {s:?}"),
            ),
            // Шаг 9A (#14A): сбой модельного каскада при выставленном
            // `model_dir`. 502, а не 4xx и не 200 с пустым списком: запрос не
            // был отвергнут по своей форме, и «ПДн не нашли» при сломанной
            // модели было бы fail-open на маскировании (AGENTS, Fail-Closed).
            // Единственный правленный hunk этого файла в данном PR — роутер
            // (#75) здесь не тронут.
            AnalyzeError::Cascade(c) => Self::new(
                StatusCode::BAD_GATEWAY,
                "cascade_unavailable",
                &format!("конвейер не смог досчитать каскады: {c}"),
            ),
        }
    }
}

impl ApiError {
    /// Отказ слоя маскирования: статус и код приходят вместе с ошибкой, чтобы
    /// карта «что клиентская ошибка, что сбой сервера» жила в одном месте
    /// (`VaultApiError::status`), а не расползалась по обработчикам.
    pub(crate) fn from_vault(e: &VaultApiError) -> Self {
        Self {
            status: e.status(),
            code: e.code(),
            message: e.message(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Серверный отказ оставляет след в stderr с ПРИЧИНОЙ, а не фактом
        // отказа: оператор, разбирающий 503 в логе, должен видеть то же, что
        // видит клиент (ревью #118 B2 — «ложь о причине» лечится в одном месте,
        // через который проходят все отказы). ПДн в строке нет по построению
        // поля `message` (см. его док-строку); `span_too_long` несёт метрики
        // `len`/`max`. Конвенция префикса — `fasad:` (см. cascades.rs).
        if self.status.is_server_error() {
            eprintln!(
                "fasad: отказ {} code={} detail={}",
                self.status.as_u16(),
                self.code,
                self.message
            );
        }
        let body = serde_json::json!({
            "error": {"code": self.code, "message": self.message},
        });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Харнес-конструктор `Arc<Inner>` для трей-тестов (#318): трей читает тот же
/// объект, что роутер, а поле `inner` приватно. Тестовая фабрика (panic =
/// красный CI), debug-only; `-D clippy::expect_used` обходит
/// тестово-харнесной блок (тот же канал, что `#![allow(expect_used)]` в
/// интеграционных файлах).
#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(
    clippy::expect_used,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]
pub fn new_tray_harness_state() -> std::sync::Arc<Inner> {
    let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
    let stage = cfg.stage();
    let health = crate::Health {
        version: env!("CARGO_PKG_VERSION"),
        stage,
        mode: cfg.vault_mode.as_str(),
    };
    let vault = crate::vault::Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище");
    AppState::new(
        cfg,
        crate::schema::Schema::embedded().expect("канон"),
        health,
        vault,
    )
    .inner_arc()
}

#[cfg(test)]
// в тестах паника = красный CI, это канал ответа
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// P1: таблица заголовков в доке обязана совпадать с тем, что мы реально
    /// отправляем. До правки две строки доки называли `X-Guard-Policy` и
    /// `X-Guard-Threshold` — имён, которых в коде нет: SPEC §8 определяет
    /// `X-Guard-Policy` как **входной** заголовок, а выходов с такими именами
    /// не задаёт вовсе. Правка пошла по доке, константы не тронуты.
    /// Значения заголовков из таблицы `daemon-scope.md` против того, что
    /// печатает код. Имена без значений — тест-пара, слепая к тому, что
    /// реально читает оператор (#87 review).
    fn assert_documented_values(doc: &str) {
        // Имена — половина контракта. Значения оператор читает из тех же
        // строк таблицы, поэтому сверяются и они: тест-пара имён к значениям
        // слеп (код мог печатать что угодно, и сетка бы «сошлась») — #87 review.
        let stage_row = doc
            .lines()
            .find(|l| l.starts_with("| `X-Guard-Stage`"))
            .expect("строка stage в таблице");
        for v in ["cascade-0-only", crate::cascades::STAGE_MOUNTED] {
            assert!(
                stage_row.contains(v),
                "значение `{v}` печатается кодом, но не описано в сетке: {stage_row}"
            );
        }
        let c2_row = doc
            .lines()
            .find(|l| l.starts_with("| `X-Guard-Cascade2`"))
            .expect("строка cascade2 в таблице");
        for v in [
            crate::cascades::Cascade2::Absent,
            crate::cascades::Cascade2::Ok,
            crate::cascades::Cascade2::Skipped,
        ] {
            assert!(
                c2_row.contains(v.as_header()),
                "значение `{}` печатается кодом, но не описано в сетке: {c2_row}",
                v.as_header()
            );
        }
    }

    #[test]
    fn header_table_in_docs_matches_emitted_names() {
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/daemon-scope.md"
        ))
        .expect("док с таблицей заголовков читается");
        let emitted = [
            &h::COUNT,
            &h::MAX_RISK,
            &h::LATENCY,
            &h::STAGE,
            &h::CASCADE2,
            &h::POLICY,
            &h::THRESHOLD,
            &h::UNRESOLVED,
            &h::MALFORMED,
        ];
        let mut allowed: Vec<String> = emitted
            .iter()
            .map(|n| n.as_str().to_ascii_uppercase())
            .collect();
        allowed.push(HEADER_SESSION.as_str().to_ascii_uppercase());
        allowed.push("X-UPSTREAM-URL".to_owned());
        let mut seen: Vec<String> = Vec::new();
        for line in doc.lines().filter(|l| l.starts_with("| `X-")) {
            let name = line.split('`').nth(1).expect("имя в бэктиках");
            let up = name.to_ascii_uppercase();
            assert!(
                allowed.contains(&up),
                "док обещает «{name}», а такого заголовка мы не отправляем"
            );
            seen.push(up);
        }
        assert_eq!(
            seen.len(),
            11,
            "строки таблицы разъехались с кодом: {seen:?}"
        );
        for e in &emitted {
            assert!(
                seen.contains(&e.as_str().to_ascii_uppercase()),
                "код отправляет «{}», а док о нём молчит",
                e.as_str()
            );
        }

        assert_documented_values(&doc);

        // SPEC §8 обязан называть всю эмиссию, а не три имени из транскрипта:
        // расхождение сетки §8 — это обещание клиенту, которое мы не отправляем.
        let spec =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/SPEC.md"))
                .expect("SPEC читается");
        let section = spec
            .split(
                "
## ",
            )
            .find(|s| s.starts_with("8."))
            .expect("раздел 8 в SPEC есть");
        let mut grid: Vec<String> = Vec::new();
        for line in section.lines().filter(|l| l.starts_with("- `X-")) {
            grid.push(
                line.split('`')
                    .nth(1)
                    .expect("имя заголовка в бэктиках")
                    .to_ascii_uppercase(),
            );
        }
        assert_eq!(
            grid.len(),
            emitted.len(),
            "сетка SPEC §8 разъехалась с эмиссией: {grid:?}"
        );
        for g in &grid {
            assert!(
                allowed.contains(g),
                "SPEC §8 обещает «{g}», а такого заголовка мы не отправляем"
            );
        }
        for e in &emitted {
            assert!(
                grid.contains(&e.as_str().to_ascii_uppercase()),
                "код отправляет «{}», а SPEC §8 о нём молчит",
                e.as_str()
            );
        }
    }

    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn state() -> AppState {
        state_with(Config::from_lookup(|_| None).expect("дефолты sane"))
    }

    fn state_with(cfg: Config) -> AppState {
        let stage = cfg.stage();
        let health = Health {
            version: env!("CARGO_PKG_VERSION"),
            stage,
            mode: cfg.vault_mode.as_str(),
        };
        let vault = Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище поднимается");
        AppState::new(
            cfg,
            Schema::embedded().expect("канон валиден"),
            health,
            vault,
        )
    }

    /// #198: ожидающий старт = 503 `models_pending` на модельных маршрутах,
    /// а не 200-обман каскадом 0 и не 500. Pending-состояние собирается
    /// конструктором (тот же путь, что `main` трей-контура), stage =
    /// `models-pending`: зуб дискриминирует и ложь stage (cascade-0-only на
    /// релизном бинаре, #185), и fail-open конвейера.
    #[tokio::test]
    async fn pending_mode_refuses_model_routes_with_own_code() {
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let health = Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: crate::cascades::STAGE_PENDING,
            mode: cfg.vault_mode.as_str(),
        };
        let vault = Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище");
        let st = AppState::with_pending(
            cfg,
            Schema::embedded().expect("канон валиден"),
            health,
            vault,
            true,
        );
        let app = router(st.clone());

        let r = app
            .clone()
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, None))
            .await
            .expect("анализ идёт");
        assert_eq!(r.status(), 503, "analyze в pending = 503");
        let j = json_of(r).await;
        assert_eq!(j["error"]["code"], "models_pending", "{j}");

        // health/status = живые витрины ожидающего режима (UI обязан их
        // читать, чтобы показать карточку весов).
        let r = app
            .clone()
            .oneshot(
                Request::get("/health")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("health идёт");
        assert_eq!(r.status(), 200);
        let j = json_of(r).await;
        assert_eq!(j["stage"], crate::cascades::STAGE_PENDING);
        assert_ne!(j["stage"], "cascade-0-only", "stage не обязан лгать #185");

        let r = app
            .oneshot(
                Request::get("/v1/status")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("status идёт");
        assert_eq!(r.status(), 200, "витрина веса живёт в pending");
    }

    /// #316 ГЛАВНЫЙ ЗУБ (unit, мок-слот): горячий монтаж на живом роутере
    /// без единого перезапуска = тот же `AppState`: 503 `models_pending` →
    /// (swap = `install_test_live_mount(Some)`) → analyze 200, stage
    /// `cascade-0+models` в `/health` И в заголовке `X-Guard-Stage`,
    /// `mount.live=true` в `/v1/status`. Мок-слот = prod-форма `live_mount`
    /// (unit-CI без весов; prod-swap = `cascades::live_mount`, CI-полка
    /// `hot_mount_live` = живой монтажный контур).
    #[tokio::test]
    async fn hot_mount_flips_503_to_200_without_restart() {
        let _g = crate::cascades::live_mount_lock().await;
        crate::cascades::reset_test_live_mount();
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let health = Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: crate::cascades::STAGE_PENDING,
            mode: cfg.vault_mode.as_str(),
        };
        let vault = Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище");
        let st =
            AppState::with_pending(cfg, Schema::embedded().expect("канон"), health, vault, true);
        let app = router(st.clone());

        let r = app
            .clone()
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, None))
            .await
            .expect("анализ идёт");
        assert_eq!(r.status(), 503, "до монтажа = pending 503");

        crate::cascades::install_test_live_mount(Some(std::sync::Arc::new(Cascade0OnlyStub)), None);

        let r = app
            .clone()
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, None))
            .await
            .expect("анализ идёт");
        assert_eq!(
            r.status(),
            200,
            "swap без рестарта = 200 (оператор-требование #316: «перезапусти» = НЕ канает)"
        );
        let stage = r
            .headers()
            .get(h::STAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert_eq!(
            stage,
            crate::cascades::STAGE_MOUNTED,
            "X-Guard-Stage = live после swaps (первичка #314: заголовок = live)"
        );

        let r = app
            .clone()
            .oneshot(
                Request::get("/health")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("health идёт");
        let j = json_of(r).await;
        assert_eq!(
            j["stage"],
            crate::cascades::STAGE_MOUNTED,
            "/health stage = live (#316: stage без перезапуска)"
        );

        let r = app
            .oneshot(
                Request::get("/v1/status")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("status идёт");
        let j = json_of(r).await;
        assert_eq!(j["mount"]["live"], true, "/v1/status mount.live = live");

        crate::cascades::reset_test_live_mount();
    }

    /// #316 отказ живого монтажа = pending ЧЕСТНЫЙ: swap с причиной (битые
    /// веса) = 503 остаётся, причина видна витрине (UI «перескачай»), stage
    /// не лжёт (#185 fail-closed: каскад-0 под вывеской cascade-0+models).
    #[tokio::test]
    async fn failed_live_mount_keeps_honest_pending() {
        let _g = crate::cascades::live_mount_lock().await;
        crate::cascades::reset_test_live_mount();
        let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
        let health = Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: crate::cascades::STAGE_PENDING,
            mode: cfg.vault_mode.as_str(),
        };
        let vault = Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище");
        let st =
            AppState::with_pending(cfg, Schema::embedded().expect("канон"), health, vault, true);
        crate::cascades::install_test_live_mount(None, Some("нет файла model.onnx"));
        let app = router(st.clone());
        let r = app
            .clone()
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, None))
            .await
            .expect("анализ идёт");
        assert_eq!(r.status(), 503, "отказ монтажа ≠ выпуск конвейера (#185)");
        let r = app
            .oneshot(
                Request::get("/v1/status")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("status идёт");
        let j = json_of(r).await;
        assert_eq!(j["mount"]["live"], false, "live = false при отказе");
        assert!(
            j["mount"]["last_error"]
                .as_str()
                .is_some_and(|e| e.contains("model.onnx")),
            "причина доходит до UI: {j}"
        );
        crate::cascades::reset_test_live_mount();
    }

    /// Дискриминатор конструктора: обычный роутер (pending=false) НЕ даёт
    /// `models_pending` (else-ветка флага = зелёный путь прежний).
    #[tokio::test]
    async fn mounted_mode_has_no_models_pending() {
        let r = router(state())
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, None))
            .await
            .expect("анализ идёт");
        let j = json_of(r).await;
        assert_ne!(
            j["error"]["code"],
            serde_json::json!("models_pending"),
            "{j}"
        );
    }

    /// Мок каскадов 1–2 для live-зуба (unit-CI без весов).
    struct Cascade0OnlyStub;
    impl crate::cascades::Cascade12 for Cascade0OnlyStub {
        fn model_spans(
            &self,
            _text: &str,
            _schema: &Schema,
            _plan: &crate::cascades::Plan,
        ) -> Result<crate::cascades::Outcome, crate::cascades::CascadeFailure> {
            Ok(crate::cascades::Outcome {
                spans: Vec::new(),
                cascade2: crate::cascades::Cascade2::Ok,
                p2: Vec::new(),
            })
        }
    }

    fn analyze_req(body: &str, policy: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/v1/analyze")
            .header("content-type", "application/json");
        if let Some(p) = policy {
            b = b.header(HEADER_POLICY.as_str(), p);
        }
        b.body(Body::from(body.to_owned()))
            .expect("запрос строится")
    }

    async fn json_of(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("тело читается");
        serde_json::from_slice(&bytes).expect("валидный JSON")
    }

    #[tokio::test]
    async fn health_reports_stage_and_mode() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;
        assert_eq!(v["stage"], "cascade-0-only");
        assert_eq!(v["mode"], "stateless");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        // Счётчики деградации хранилища — часть контракта `/health` (#60 п.3):
        // без них метрика живёт только в тестах, а это не «видно оператору».
        assert_eq!(
            v["vault"]["surrogate_fallbacks"], 0,
            "свежее хранилище чисто"
        );
        assert_eq!(
            v["vault"]["unrestored_mismatch"], 0,
            "расхождений ещё не было"
        );
    }

    #[tokio::test]
    async fn analyze_finds_inn_and_sets_guard_headers() {
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(
                r#"{"text":"Иван ИНН 2482014338 оплатил"}"#,
                None,
            ))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(h::COUNT).expect("счётчик есть"), "1");
        assert_eq!(
            resp.headers().get(h::STAGE).expect("stage"),
            "cascade-0-only"
        );
        assert_eq!(
            resp.headers().get(h::POLICY).expect("политика"),
            "mask",
            "отсутствие заголовка = дефолт mask"
        );
        assert!(
            resp.headers()
                .get(h::MAX_RISK)
                .expect("риск")
                .to_str()
                .expect("печатаемо")
                .starts_with('1')
        );
        assert!(
            resp.headers().get(h::LATENCY).is_some(),
            "латентность обязательна"
        );
        let v = json_of(resp).await;
        let span = v
            .as_array()
            .expect("массив спанов")
            .first()
            .expect("один спан")
            .clone();
        assert_eq!(span["entity_type"], "inn");
        assert_eq!(span["class"], "inn");
        assert_eq!(span["verdict"], "mask_surrogate");
        assert_eq!(span["validator"], "inn10");
        assert_eq!(span["score"], 1.0);
    }

    /// #234 сквозь wire-контур: каркасный 0.95 = отдельный спан с
    /// `source: frame_invalid_checksum`, `validator: frame_invalid`,
    /// `score: 0.95` (UI-таблица «Валидатор» читается), валидный номер
    /// рядом = 1.0 без понижения.
    #[tokio::test]
    async fn analyze_frame_invalid_carries_score_and_validator() {
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(
                r#"{"text":"СНИЛС 112-233-455 95 и 384-051-346 70"}"#,
                None,
            ))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;
        let spans = v.as_array().expect("массив спанов");
        assert_eq!(spans.len(), 2, "{v}");
        let frame = &spans[0];
        assert_eq!(frame["source"], "frame_invalid_checksum");
        assert_eq!(frame["validator"], "frame_invalid");
        assert_eq!(frame["score"], 0.95);
        assert_eq!(spans[1]["validator"], "snils");
        assert_eq!(spans[1]["score"], 1.0, "валидный = вето без понижения");
    }

    #[tokio::test]
    async fn policy_header_changes_verdicts_and_is_echoed() {
        for (raw, verdict) in [
            ("block", "block_request"),
            ("audit_only", "keep_public"),
            ("mask", "mask_surrogate"),
        ] {
            let app = router(state());
            let resp = app
                .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, Some(raw)))
                .await
                .expect("обработчик не падает");
            assert_eq!(resp.status(), StatusCode::OK, "{raw}");
            assert_eq!(resp.headers().get(h::POLICY).expect("эхо"), raw, "{raw}");
            let v = json_of(resp).await;
            assert_eq!(v[0]["verdict"].clone(), verdict, "{raw}");
        }
    }

    #[tokio::test]
    async fn unknown_policy_is_400_not_silent_default() {
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(r#"{"text":"ИНН 2482014338"}"#, Some("blockl")))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = json_of(resp).await;
        assert_eq!(v["error"]["code"], "bad_policy");
    }

    #[tokio::test]
    async fn unknown_entity_filter_is_422() {
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(
                r#"{"text":"ИНН 2482014338","entities":["sni1s"]}"#,
                None,
            ))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = json_of(resp).await;
        assert_eq!(v["error"]["code"], "unknown_entity");
    }

    #[tokio::test]
    async fn malformed_body_is_400_without_echoing_input() {
        // Ошибка не должна процитировать ПДн из тела (AGENTS: никакого
        // содержимого в логах и сообщениях об ошибках).
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(r#"{"текст":"СЕКРЕТ-ПДН-МАРКЕР"}"#, None))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = json_of(resp).await;
        assert_eq!(v["error"]["code"], "bad_json");
        let dumped = v.to_string();
        assert!(
            !dumped.contains("СЕКРЕТ-ПДН-МАРКЕР"),
            "ответ об ошибке процитировал вход: {dumped}"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_413_in_our_envelope() {
        let mut cfg =
            Config::from_lookup(|k| (k == "FASAD_MAX_BODY_BYTES").then(|| "64".to_owned()))
                .expect("64 байта принимаются");
        cfg.max_body_bytes = 64;
        let app = router(state_with(cfg));
        let big = format!(r#"{{"text":"{}"}}"#, "ИНН 2482014338 ".repeat(20));
        let resp = app
            .oneshot(analyze_req(&big, None))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // Конверт обязателен: текст axum про «Failed to buffer» не разбирается
        // машиной, а клиент различает 4xx по полю `code`.
        let v = json_of(resp).await;
        assert_eq!(v["error"]["code"], "body_too_large");
        assert!(
            !v["error"]["message"]
                .as_str()
                .expect("сообщение")
                .contains("ИНН 2482014338")
        );
    }

    #[tokio::test]
    async fn empty_spans_is_200_with_zero_counter() {
        let app = router(state());
        let resp = app
            .oneshot(analyze_req(r#"{"text":"просто текст без номеров"}"#, None))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(h::COUNT).expect("счётчик"), "0");
        let v = json_of(resp).await;
        assert_eq!(v.as_array().expect("массив").len(), 0);
    }

    #[tokio::test]
    async fn panic_in_handler_becomes_503_and_does_not_echo_the_payload() {
        // Паника с текстом, похожим на вход: хук по умолчанию печатает сообщение,
        // обёртка обязана не отдавать его наружу.
        let resp = guarded(|| panic!("СЕКРЕТ-ПДН-МАРКЕР в сообщении"));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("тело читается");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("СЕКРЕТ-ПДН-МАРКЕР"),
            "тело цитирует панику: {body}"
        );
        assert!(
            body.contains("internal_panic"),
            "нет машинного кода: {body}"
        );
    }

    #[tokio::test]
    async fn panicking_handler_answers_503_through_the_router() {
        // Доказательство, что обёртка стоит на маршруте, а не только юнит-тестом
        // самой функции: запрос проходит через `router`, обработчик паникует.
        let app = router_with_panic_probe(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/__probe_panic")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("роутер отвечает, а не рвёт соединение");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .expect("тело читается");
        let body = String::from_utf8_lossy(&bytes);
        assert!(!body.contains("СЕКРЕТ"), "ответ цитирует панику: {body}");
        assert!(body.contains("internal_panic"), "нет кода: {body}");
    }

    #[tokio::test]
    async fn success_path_of_guarded_is_transparent() {
        // Парная проверка: обёртка не проглатывает обычные `Err` и `Ok`.
        let ok = guarded(|| Ok(StatusCode::OK.into_response()));
        assert_eq!(ok.status(), StatusCode::OK);
        let err = guarded(|| {
            Err(ApiError::new(
                StatusCode::IM_A_TEAPOT,
                "bad_json",
                "нет входа",
            ))
        });
        assert_eq!(err.status(), StatusCode::IM_A_TEAPOT);
    }

    #[test]
    fn vault_request_debug_redacts_the_text_too() {
        let body = r#"{"text":"СНИЛС 65707715421","spans":[]}"#;
        let req: AnonymizeRequest = serde_json::from_str(body).expect("тело разобрано");
        let line = format!("{req:?}");
        assert!(!line.contains("65707715421"), "Debug печати вход: {line}");
    }

    fn cfg_with(pairs: &[(&'static str, &'static str)]) -> Config {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| owned.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
            .expect("конфиг из тестовых пар")
    }

    fn post_req(uri: &str, body: &str, session: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(s) = session {
            b = b.header(HEADER_SESSION.as_str(), s);
        }
        b.body(Body::from(body.to_owned()))
            .expect("запрос строится")
    }

    /// Тело `anonymize` с координатами, снятыми с подстрок, а не «на глаз»:
    /// байтовый оффсет в кириллице угадать нельзя, и тест на угаданном оффсете
    /// проверял бы арифметику теста, а не демон.
    fn anon_body(text: &str, needles: &[(&str, &str)]) -> String {
        let spans: Vec<String> = needles
            .iter()
            .map(|(class, needle)| {
                let start = text
                    .find(needle)
                    .unwrap_or_else(|| panic!("нет {needle:?} в тексте"));
                format!(
                    r#"{{"entity_type":"{class}","byte_start":{},"byte_end":{}}}"#,
                    start,
                    start + needle.len()
                )
            })
            .collect();
        format!(
            r#"{{"text":{},"spans":[{}]}}"#,
            serde_json::to_string(text).expect("текст сериализуется"),
            spans.join(",")
        )
    }

    #[tokio::test]
    async fn anonymize_then_deanonymize_roundtrip_over_http() {
        let st = state();
        let app = router(st.clone());
        let body = anon_body(
            "Иванов Пётр Сергеевич, ИНН 2482014338",
            &[
                ("person_name", "Иванов Пётр Сергеевич"),
                ("inn", "2482014338"),
            ],
        );
        let resp = app
            .oneshot(post_req("/v1/anonymize", &body, None))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(h::COUNT).expect("счётчик"), "2");
        let v = json_of(resp).await;
        let masked = v["text"].as_str().expect("текст маскирования").to_owned();
        assert!(
            !masked.contains("Иванов"),
            "оригинал протёк в ответ: {masked}"
        );
        assert!(!masked.contains("2482014338"), "оригинал протёк: {masked}");
        assert_eq!(v["items"][0]["operator"], "mask", "режим 3 = маркеры");

        // Второй `router` поверх того же `AppState`: `Arc<Inner>` общий, поэтому
        // ключ и кэш те же — ровно как у живого демона на одном процессе.
        let app = router(st.clone());
        let req_body = format!(r#"{{"text":"{masked}"}}"#);
        let resp = app
            .oneshot(post_req("/v1/deanonymize", &req_body, None))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let back = json_of(resp).await;
        assert_eq!(back["text"], "Иванов Пётр Сергеевич, ИНН 2482014338");
        assert_eq!(back["substituted"], 2);
    }

    #[tokio::test]
    async fn session_mode_roundtrips_surrogates_and_labels() {
        let st = state_with(cfg_with(&[("FASAD_VAULT_MODE", "session")]));
        let app = router(st.clone());
        let body = anon_body(
            "Ушакова Кира Саввична, ИНН 2482014338",
            &[
                ("person_name", "Ушакова Кира Саввична"),
                ("inn", "2482014338"),
            ],
        );
        let resp = app
            .oneshot(post_req("/v1/anonymize", &body, Some("http-s1")))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;
        let masked = v["text"].as_str().expect("текст").to_owned();
        assert!(masked.contains("[INN_"), "нет метки класса: {masked}");
        assert_eq!(
            v["items"][0]["operator"], "replace",
            "ФИО в режиме 2 = гладкий суррогат: {masked}"
        );
        assert!(!masked.contains("Ушакова"), "протёк: {masked}");

        let app = router(st.clone());
        let req_body = format!(r#"{{"text":"{masked}"}}"#);
        let resp = app
            .oneshot(post_req("/v1/deanonymize", &req_body, Some("http-s1")))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let back = json_of(resp).await;
        assert_eq!(back["text"], "Ушакова Кира Саввична, ИНН 2482014338");
    }

    #[tokio::test]
    async fn session_mode_without_session_header_is_400() {
        let app = router(state_with(cfg_with(&[("FASAD_VAULT_MODE", "session")])));
        let resp = app
            .oneshot(post_req(
                "/v1/anonymize",
                &anon_body("ИНН 2482014338", &[("inn", "2482014338")]),
                None,
            ))
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_of(resp).await["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn anonymize_rejects_unknown_class_with_422() {
        let app = router(state());
        let resp = app
            .oneshot(post_req(
                "/v1/anonymize",
                r#"{"text":"ИНН 2482014338","spans":[{"entity_type":"snisl","byte_start":4,"byte_end":14}]}"#,
                None,
            ))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json_of(resp).await["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn deanonymize_of_forged_marker_is_422_without_partial_text() {
        let app = router(state());
        let resp = app
            .oneshot(post_req(
                "/v1/deanonymize",
                r#"{"text":"данные [[F0#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]] тут"}"#,
                None,
            ))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = json_of(resp).await;
        assert_eq!(v["error"]["code"], "unresolved_token");
        // Частичный возврат = «текст похож на расшифрованный, но им не является».
        assert!(v.get("text").is_none(), "ответ содержит тело: {v}");
    }

    #[tokio::test]
    async fn delete_session_reports_dropped_labels() {
        let st = state_with(cfg_with(&[("FASAD_VAULT_MODE", "session")]));
        let app = router(st.clone());
        let resp = app
            .oneshot(post_req(
                "/v1/anonymize",
                &anon_body("ИНН 2482014338", &[("inn", "2482014338")]),
                Some("http-s2"),
            ))
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = json_of(resp).await;

        let app = router(st.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/sessions/http-s2")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("не падает");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(h::COUNT).expect("счётчик"), "1");
        assert_eq!(json_of(resp).await["deleted"], 1);
    }

    #[tokio::test]
    async fn unknown_route_is_404_not_500() {
        // Fail-closed на уровне роутера: ничего не проксируем «автоматом».
        // `/v1/chat/completions` с шага 7c — маршрут настоящий, поэтому зондом
        // служит имя, которого нет ни в одном роутере.
        let app = router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions/legacy")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn proxy_is_off_until_the_allowlist_says_otherwise() {
        // Дефолтный конфиг теста — пустой список: прокси обязан отвечать
        // `403 allowlist_empty`, а не «пробуем куда просили» и не 404.
        let app = router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(
                        "x-upstream-url",
                        "https://api.openai.com/v1/chat/completions",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#,
                    ))
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn proxy_without_upstream_header_is_400_not_403() {
        // Причина отказа называется та, что есть: заголовка нет — это 400
        // `missing_upstream`, а не отговорка про список.
        let app = router(state_with(
            Config::from_lookup(|k| {
                (k == "FASAD_UPSTREAM_ALLOWLIST").then(|| "api.openai.com".to_owned())
            })
            .expect("конфиг"),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"model":"m","messages":[]}"#))
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_on_analyze_is_405() {
        let app = router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/analyze")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
