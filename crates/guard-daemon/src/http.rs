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

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::Health;
use crate::config::Config;
use crate::pipeline::{self, Analysis, AnalyzeError, AnalyzeRequest, Policy};
use crate::schema::Schema;

/// Имя входного заголовка политики (SPEC §8).
pub const HEADER_POLICY: HeaderName = HeaderName::from_static("x-guard-policy");

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
}

impl AppState {
    /// Собрать состояние из уже проверенных конфига и схемы.
    ///
    /// Оба параметра пришли из `Config::from_env` / `Schema::from_config`, т.е.
    /// отказ старта уже случился бы раньше — здесь инвариант, а не валидация.
    #[must_use]
    pub fn new(cfg: Config, schema: Schema, health: Health) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg,
                schema,
                health,
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
}

/// Собирает корневой роутер демона.
pub fn router(state: AppState) -> Router {
    let limit = state.config().max_body_bytes;
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/analyze", post(analyze_handler))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn health_handler(State(st): State<AppState>) -> axum::Json<Health> {
    // Ответ осознанно не содержит никаких пользовательских данных (§1 п.6:
    // весь разбор завершается на 127.0.0.1 до первой сокет-операции).
    axum::Json(st.health())
}

async fn analyze_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let policy = match parse_policy(&headers) {
        Ok(policy) => policy,
        Err(err) => return err.into_response(),
    };
    // Разбор руками (не экстрактором `Json`): rejection-сообщения axum
    // пересказывают вход, а вход — ПДн.
    let req: AnalyzeRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_json",
                "тело — не JSON вида {\"text\": \"…\"}",
            )
            .into_response();
        }
    };
    match pipeline::analyze(&req, st.schema(), st.config(), policy) {
        Ok(res) => analysis_response(&res),
        Err(err) => ApiError::from_analysis(err).into_response(),
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
        AppState::new(cfg, Schema::embedded().expect("канон валиден"), health)
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
    async fn oversized_body_is_413_before_parsing() {
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
