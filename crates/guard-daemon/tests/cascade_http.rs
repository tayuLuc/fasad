//! Каскады 1–2 в HTTP-контуре: 502 вместо fail-open и честный `X-Guard-Stage`.
//!
//! Отдельный бинарь интеграционных тестов, а не правка `src/http.rs`: у того
//! файла владелец — атом #75 (UI+роутер), и единственное изменение в нём в
//! этом PR — одна ветка в `ApiError::from_analysis`. Здесь проверяется ровно
//! то, что видно клиенту: код ответа, тело и заголовки стадии.
//!
//! Модельный путь подменяется фейком ([`install_test_mount`]): слот движка —
//! процесс-global (на старте демона пишется один раз), поэтому **тесты этого
//! файла сериализованы** [`MOUNT_LOCK`]: параллельные тесты в одном процессе
//! иначе затирают mount друг друга (промерено до сериализации: 502-тест
//! получал 200, читая чистый слот соседа). Реальные веса проверяются
//! `tests/cascade_parity.rs` под фичей `ort-inference`.

#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
#![allow(clippy::type_complexity)] // ключи сравнения спанов — кортежи, и они читамее в тесте

use std::sync::Arc;

use axum::body::Body as AxumBody;
use axum::http::{HeaderMap, Request, StatusCode};
use guard_daemon::Health;
use guard_daemon::cascades::{
    Cascade12, CascadeFailure, ModelSpan, Outcome, Plan, install_test_mount,
};
use guard_daemon::config::Config;
use guard_daemon::http::{AppState, HEADER_POLICY, router};
use guard_daemon::schema::Schema;
use guard_daemon::vault::Vault;
use guard_types::DetectionSource;
use tower::ServiceExt as _;

const SECRET_MARK: &str = "СЕКРЕТ-ПДН-МАРКЕР";

/// Сериализация тестов, трогающих глобальный слот движка. `tokio::sync::Mutex`:
/// обычный `std`-мьютекс через `.await` держать нельзя (`await_holding_lock`),
/// а держать его надо на всё время запроса — иначе соседний тест снимет mount
/// в середине нашего.
static MOUNT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn mount_exclusive() -> tokio::sync::MutexGuard<'static, ()> {
    MOUNT_LOCK.lock().await
}

/// Фейк модельного пути: детерминированный, без весов и без `ort`.
struct Fake {
    spans: Vec<ModelSpan>,
    fail: Option<CascadeFailure>,
    /// Что фейк сообщает о леве каскада 2 (`X-Guard-Cascade2`).
    cascade2: &'static str,
}

impl Cascade12 for Fake {
    fn model_spans(
        &self,
        _text: &str,
        _schema: &Schema,
        _plan: &Plan,
    ) -> Result<Outcome, CascadeFailure> {
        match &self.fail {
            Some(f) => Err(f.clone()),
            None => Ok(Outcome {
                spans: self.spans.clone(),
                cascade2: match self.cascade2 {
                    "skipped" => guard_daemon::cascades::Cascade2::Skipped,
                    "absent" => guard_daemon::cascades::Cascade2::Absent,
                    _ => guard_daemon::cascades::Cascade2::Ok,
                },
                // #238: фейк отвечает p2 по person_name = 1.0 (арбитраж
                // «есть человек»): транслит-кандидаты живут и маскируются.
                p2: vec![("person_name".to_owned(), 1.0)],
            }),
        }
    }
}

fn state() -> AppState {
    state_with(Config::from_lookup(|_| None).expect("дефолты sane"))
}

fn state_with(cfg: Config) -> AppState {
    let health = Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: cfg.stage(),
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

/// Текст с валидным ИНН (каскад 0) и фамилией, которую каскад 0 не видит.
const TEXT: &str = "Иванов Пётр ИНН 2482014338 оплатил";

fn name_span() -> ModelSpan {
    let start = TEXT.find("Иванов").expect("подстрока есть");
    ModelSpan {
        byte_start: start,
        byte_end: start + "Иванов".len(),
        class: "person_name".to_owned(),
        score: 0.9,
        p1: 0.9,
        source: DetectionSource::GlinerExtractor,
    }
}

/// #198 интеграция pending-режима на ПОЛНОМ роутере: analyze=503 своим
/// кодом, anonymize/deanonymize = те же 503 (конвейер без первого шага не
/// существует), `/v1/status` = витрина веса (200, карточка «Скачать веса»),
/// `/health` stage = `models-pending`. Дискриминатор: red = fail-open
/// конвейера на pending (200-обман каскадом 0, #185) ИЛИ мёртвая витрина
/// (UI-кнопка недостижима = ровно дефект #198, который чинится).
#[tokio::test]
async fn pending_mode_refuses_pipeline_and_keeps_the_weights_card() {
    let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
    let health = guard_daemon::Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: guard_daemon::cascades::STAGE_PENDING,
        mode: cfg.vault_mode.as_str(),
    };
    let vault = guard_daemon::vault::Vault::startup(cfg.vault_mode, cfg.mlock)
        .expect("хранилище поднимается");
    let st = AppState::with_pending(
        cfg,
        guard_daemon::schema::Schema::embedded().expect("канон валиден"),
        health,
        vault,
        true,
    );
    let app = router(st);

    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/analyze")
                .header("content-type", "application/json")
                .body(AxumBody::from(r#"{"text":"ИНН 2482014338"}"#.to_owned()))
                .expect("запрос строится"),
        )
        .await
        .expect("роутер отвечает");
    let (status, _, json) = json_of(r).await;
    assert_eq!(status, 503, "analyze в pending = 503");
    assert_eq!(json["error"]["code"], "models_pending");

    for (uri, body) in [
        (
            "/v1/anonymize",
            r#"{"text":"ИНН 2482014338","spans":[]}"#.to_owned(),
        ),
        (
            "/v1/deanonymize",
            r#"{"text":"[Телефон:12345678901]"}"#.to_owned(),
        ),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("x-session-id", "s198")
                    .body(AxumBody::from(body))
                    .expect("запрос строится"),
            )
            .await
            .expect("роутер отвечает");
        let (status, _, json) = json_of(r).await;
        assert_eq!(
            status, 503,
            "{uri} в pending = 503 (конвейер без 1-го шага)"
        );
        assert_eq!(json["error"]["code"], "models_pending", "{uri}");
    }

    // Витрина живёт: UI-кнопка #198 обязана быть достижимой в pending.
    let r = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/status")
                .body(AxumBody::empty())
                .expect("запрос строится"),
        )
        .await
        .expect("роутер отвечает");
    let (status, _, json) = json_of(r).await;
    assert_eq!(status, 200, "витрина веса = 200 в pending");
    assert_eq!(json["stage"], guard_daemon::cascades::STAGE_PENDING);
    assert!(
        json["weights"].is_object(),
        "карточка весов пропала из витрины: {json}"
    );
}

async fn analyze(body: &str) -> axum::http::Response<AxumBody> {
    router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/analyze")
                .header("content-type", "application/json")
                .header(HEADER_POLICY.as_str(), "audit_only")
                .body(AxumBody::from(body.to_owned()))
                .expect("запрос строится"),
        )
        .await
        .expect("обработчик не падает")
}

fn header(map: &HeaderMap, name: &str) -> Option<String> {
    map.get(name)
        .map(|v| v.to_str().expect("заголовок ASCII").to_owned())
}

async fn json_of(
    resp: axum::http::Response<AxumBody>,
) -> (StatusCode, HeaderMap, serde_json::Value) {
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .expect("тело читается");
    let json = serde_json::from_slice(&bytes).expect("валидный JSON");
    (parts.status, parts.headers, json)
}

/// Ответ `/v1/analyze` — голый массив спанов (контракт SPEC §8, не обёртка).
fn spans_of(v: &serde_json::Value) -> Vec<&serde_json::Value> {
    v.as_array().expect("массив спанов").iter().collect()
}

/// Классы спанов из ответа `/v1/analyze`.
fn classes(v: &serde_json::Value) -> Vec<String> {
    spans_of(v)
        .into_iter()
        .map(|s| s["entity_type"].as_str().expect("класс строкой").to_owned())
        .collect()
}

/// Первый спан данного класса.
fn span_of<'a>(v: &'a serde_json::Value, class: &str) -> &'a serde_json::Value {
    spans_of(v)
        .into_iter()
        .find(|s| s["entity_type"] == class)
        .unwrap_or_else(|| panic!("спана {class} нет в ответе"))
}

/// #238 wire-контра: транслит-кандидат доезжает до HTTP-ответа (фейк
/// отвечает `p2=1.0` по `person_name`; S = 0.5·0.22+0.5·1.0 = 0.61,
/// source = арбитр). Класс, скор, авторство = контракт клиента.
#[tokio::test]
async fn analyze_translit_candidate_reaches_the_answer() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: Vec::new(),
        fail: None,
        cascade2: "ok",
    })));
    let body = r#"{"text":"Contract: Ushakov Petr Sergeevich, Moscow Region"}"#;
    let (status, _h, v) = json_of(analyze(body).await).await;
    install_test_mount(None);
    assert_eq!(status, StatusCode::OK);
    let name = span_of(&v, "person_name");
    assert_eq!(name["source"], "gliner_decide_arbitrator");
    let score = name["score"].as_f64().expect("скор числом");
    assert!(
        (score - 0.61).abs() < 1e-12,
        "blend(0.22, 1.0, 0.5) = 0.61, получено {score}"
    );
    assert_eq!(
        name["entity_type"], "person_name",
        "класс = схема, не выдумка эвристики"
    );
}

/// #238: без живого арбитра (лег `Cascade2::Skipped`) транслит-спан НЕ
/// появляется, хотя фейк приносит p2-вектор: контур читает Cascade2 —
/// Skipped = арбитража не было = кандидату негде жить. cascade-0-only
/// витрина FN остаётся FN на любой стадии без Decide.
#[tokio::test]
async fn analyze_translit_silent_without_arbiter() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: Vec::new(),
        fail: None,
        cascade2: "skipped",
    })));
    let body = r#"{"text":"Contract: Ushakov Petr Sergeevich, Moscow Region"}"#;
    let (status, _h, v) = json_of(analyze(body).await).await;
    install_test_mount(None);
    assert_eq!(status, StatusCode::OK);
    assert!(
        classes(&v).is_empty(),
        "Skipped = кандидату неоткуда брать p2: {v:?}"
    );
}

#[tokio::test]
async fn mounted_cascade_spans_reach_the_http_answer() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: vec![name_span()],
        fail: None,
        cascade2: "ok",
    })));
    let (status, headers, v) = json_of(analyze(&format!(r#"{{"text":"{TEXT}"}}"#)).await).await;
    install_test_mount(None);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "x-guard-stage").as_deref(),
        Some("cascade-0+models"),
        "стадия в заголовке = примонтированный путь (SPEC §8)"
    );
    assert_eq!(
        header(&headers, "x-guard-cascade2").as_deref(),
        Some("ok"),
        "штатный лег каскада 2 различим на ответе"
    );
    let cls = classes(&v);
    assert!(
        cls.contains(&"person_name".to_owned()),
        "ФИО из каскада 1 дошло до клиента: {cls:?}"
    );
    assert!(cls.contains(&"inn".to_owned()), "каскад 0 остался: {cls:?}");
    let name = span_of(&v, "person_name");
    assert_eq!(name["source"], "gliner_extractor");
    assert_eq!(
        name["validator"],
        serde_json::Value::Null,
        "у модельного спана нет детерминированного валидатора — клиент это видит"
    );
    let inn = span_of(&v, "inn");
    assert_eq!(
        inn["score"].as_f64(),
        Some(1.0),
        "вето чексуммы не понижено соседством модели"
    );
}

/// Деградация каскада 2 на входе (`№` против контракта склейки, #88) обязана
/// быть видна оператору на ОТВЕТЕ: `X-Guard-Stage` при этом остаётся
/// `cascade-0+models` (монтаж-то есть), и без отдельного сигнала запрос
/// выглядел бы штатным (#87 review: «молчание нельзя»).
#[tokio::test]
async fn skipped_cascade2_leg_is_visible_on_the_wire() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: vec![name_span()],
        fail: None,
        cascade2: "skipped",
    })));
    let (status, headers, v) = json_of(analyze(&format!(r#"{{"text":"{TEXT}"}}"#)).await).await;
    install_test_mount(None);
    assert_eq!(status, StatusCode::OK, "деградация легов ≠ отказ запроса");
    assert_eq!(
        header(&headers, "x-guard-cascade2").as_deref(),
        Some("skipped"),
        "лег пропущен, и клиент обязан это читать"
    );
    assert_eq!(
        header(&headers, "x-guard-stage").as_deref(),
        Some("cascade-0+models"),
        "стадия про монтаж, сигнал про вердикты — это разные заголовки"
    );
    assert!(
        classes(&v).contains(&"person_name".to_owned()),
        "на деградации спан не теряется: {v}"
    );
}

#[tokio::test]
async fn cascade_failure_is_502_and_leaks_no_request_text() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: Vec::new(),
        fail: Some(CascadeFailure::Timeout {
            budget_ms: 3000,
            stage: "inference",
        }),
        cascade2: "ok",
    })));
    let resp = analyze(&format!(r#"{{"text":"{SECRET_MARK} ИНН 2482014338"}}"#)).await;
    install_test_mount(None);
    let (status, _, v) = json_of(resp).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "сбой каскада = отказ конвейера, а не «ПДн не нашли» (fail-closed)"
    );
    assert_eq!(v["error"]["code"], "cascade_unavailable");
    let raw = serde_json::to_string(&v).expect("сериализуется");
    assert!(
        !raw.contains(SECRET_MARK) && !raw.contains("2482014338"),
        "причина обязана называть стадию и бюджет, но не текст запроса: {raw}"
    );
    assert!(
        raw.contains("3000"),
        "в причине должен быть бюджет — иначе оператор не поймёт, что крутить: {raw}"
    );
}

/// Контроль дискриминатора: без примонтированного пути тот же запрос green.
/// Без этой пары «502» не доказывает, что причина — каскад, а не тест.
#[tokio::test]
async fn without_mount_same_request_is_200() {
    let _guard = mount_exclusive().await;
    install_test_mount(None);
    let (status, headers, v) = json_of(analyze(&format!(r#"{{"text":"{TEXT}"}}"#)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "x-guard-stage").as_deref(),
        Some("cascade-0-only"),
        "без движка стадия не обязана притворяться смонтированной"
    );
    assert_eq!(
        header(&headers, "x-guard-cascade2").as_deref(),
        Some("absent"),
        "каскада 2 в процессе нет — сигнал обязан быть явным, а не пустым"
    );
    assert_eq!(
        classes(&v),
        vec!["inn".to_owned()],
        "каскад 0 один: ФИО не находится — это и есть дыра #14A"
    );
}

#[tokio::test]
async fn proxy_path_carries_the_same_failure_before_dialing() {
    let _guard = mount_exclusive().await;
    install_test_mount(Some(Arc::new(Fake {
        spans: Vec::new(),
        fail: Some(CascadeFailure::Dead),
        cascade2: "ok",
    })));
    // Allowlist тот же, что в http-тестах (`api.openai.com`): dialing происходит
    // ПОСЛЕ маскирования, а маскирование обязано упасть раньше — тест не
    // касается сети ровно по той же причине, по какой её не касается прокси.
    let cfg = Config::from_lookup(|k| {
        (k == "FASAD_UPSTREAM_ALLOWLIST").then(|| "api.openai.com".to_owned())
    })
    .expect("конфиг с allowlist");
    let app = router(state_with(cfg));
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{SECRET_MARK} ИНН 2482014338"}}]}}"#
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header(HEADER_POLICY.as_str(), "block")
                .header(
                    "x-upstream-url",
                    "https://api.openai.com/v1/chat/completions",
                )
                .body(AxumBody::from(body.into_bytes()))
                .expect("запрос строится"),
        )
        .await
        .expect("обработчик не падает");
    install_test_mount(None);
    let (status, _, v) = json_of(resp).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "каскад мёртв — запрос к апстриму не уходит"
    );
    assert_eq!(
        v["error"]["code"], "cascade_unavailable",
        "причина — конвейер, а не апстрим: {v}"
    );
}
