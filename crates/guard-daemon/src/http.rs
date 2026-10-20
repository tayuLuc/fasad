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
use std::time::Instant;

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

/// Выходные заголовки `X-Guard-*` (SPEC §8).
mod h {
    use axum::http::HeaderName;

    pub const COUNT: HeaderName = HeaderName::from_static("x-guard-redacted-count");
    pub const MAX_RISK: HeaderName = HeaderName::from_static("x-guard-max-risk");
    pub const LATENCY: HeaderName = HeaderName::from_static("x-guard-latency-ms");
    pub const STAGE: HeaderName = HeaderName::from_static("x-guard-stage");
    pub const POLICY: HeaderName = HeaderName::from_static("x-guard-policy-applied");
    pub const THRESHOLD: HeaderName = HeaderName::from_static("x-guard-score-threshold");
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

struct Inner {
    cfg: Config,
    schema: Schema,
    health: Health,
    vault: Vault,
}

impl AppState {
    /// Собрать состояние из уже проверенных конфига и схемы.
    ///
    /// Оба параметра пришли из `Config::from_env` / `Schema::from_config`, т.е.
    /// отказ старта уже случился бы раньше — здесь инвариант, а не валидация.
    #[must_use]
    pub fn new(cfg: Config, schema: Schema, health: Health, vault: Vault) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg,
                schema,
                health,
                vault,
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

    /// Хранилище обратимых подмен.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.inner.vault
    }
}

/// Собирает корневой роутер демона.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/analyze", post(analyze_handler))
        .route("/v1/anonymize", post(anonymize_handler))
        .route("/v1/deanonymize", post(deanonymize_handler))
        .route("/v1/sessions/{id}", delete(invalidate_handler))
        .with_state(state)
}

async fn health_handler(State(st): State<AppState>) -> axum::Json<Health> {
    // Ответ осознанно не содержит никаких пользовательских данных (§1 п.6:
    // весь разбор завершается на 127.0.0.1 до первой сокет-операции).
    axum::Json(st.health())
}

async fn analyze_handler(State(st): State<AppState>, req: Request) -> Response {
    let (headers, body) = match read_body(st.clone(), req).await {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    guarded(move || {
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
fn guarded(f: impl FnOnce() -> Result<Response, ApiError>) -> Response {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => err.into_response(),
        Err(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal_panic",
            "обработчик паниковал; запрос отклонён (fail-closed)",
        )
        .into_response(),
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
async fn read_body(st: AppState, req: Request) -> Result<(HeaderMap, axum::body::Bytes), ApiError> {
    use http_body_util::BodyExt as _;
    let limit = st.config().max_body_bytes;
    let (parts, mut body) = req.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
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
fn json_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
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
        let session = session_of(&headers)?;
        let anon = st
            .vault()
            .anonymize(session, &req.text, &req.spans, st.schema())
            .map_err(|ref err| ApiError::from_vault(err))?;
        let count = anon.items.len();
        let stage = st.health().stage;
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
        let req: DeanonymizeRequest = json_body(&body)?;
        let session = session_of(&headers)?;
        let done = st
            .vault()
            .deanonymize(session, &req.text)
            .map_err(|ref err| ApiError::from_vault(err))?;
        let count = done.substituted;
        let stage = st.health().stage;
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
        let stage = st.health().stage;
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
fn session_of(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
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
fn parse_policy(headers: &HeaderMap) -> Result<Policy, ApiError> {
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
fn insert<T: std::fmt::Display>(map: &mut HeaderMap, name: HeaderName, value: T) {
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
    fn new(status: StatusCode, code: &'static str, message: &str) -> Self {
        Self {
            status,
            code,
            message: message.to_owned(),
        }
    }

    /// Отвергнутый запрос ≠ сбой конвейера: 4xx на клиентские ошибки, 500 —
    /// только на нарушение нашего собственного контракта скора.
    fn from_analysis(e: AnalyzeError) -> Self {
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
        }
    }
}

impl ApiError {
    /// Отказ слоя маскирования: статус и код приходят вместе с ошибкой, чтобы
    /// карта «что клиентская ошибка, что сбой сервера» жила в одном месте
    /// (`VaultApiError::status`), а не расползалась по обработчикам.
    fn from_vault(e: &VaultApiError) -> Self {
        Self {
            status: e.status(),
            code: e.code(),
            message: e.message(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {"code": self.code, "message": self.message},
        });
        (self.status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
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
        // Fail-closed на уровне роутера: ничего не проксируем «автоматом»
        // (шаг 7 поднимет /v1/chat/completions, и только когда поднимет).
        let app = router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .body(Body::empty())
                    .expect("запрос строится"),
            )
            .await
            .expect("обработчик не падает");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
