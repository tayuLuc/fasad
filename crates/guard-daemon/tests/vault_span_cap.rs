//! Потолок спана (1024 Б) на словесных реестровых номерах: HTTP-контракт.
//!
//! **Контракт ПОСЛЕ #120** (док переименован с «контракт до решения #120»;
//! сам тест не удалён — он про `> MAX` и про причину отказа, и эти ноги живы
//! при любом потолке).
//!
//! Файл пинит поведение атома #118 (числительные словами) + #120 (потолок
//! поднят 128 → 1024 Б, решение оператора). Смысл #120 ровно в том, что
//! round-trip словесного реестрового номера обязан жить: до поднятия потолка
//! слой находил фразу, маскирование отказывало навсегда (`503 span_too_long`),
//! и прокси блокировал те самые запросы, ради которых слой написан. Теперь
//! фикстуры 170–336 Б проходят `analyze → anonymize → deanonymize` побайтово.
//!
//! Потолок из первички: `MAX_ORIGINAL_BYTES` (`crates/guard-vault/src/token.rs`),
//! пинится и в тесте, и в доке (`docs/daemon-scope.md` п.4, `docs/SPEC.md` §4,
//! README демона).
//!
//! Промер 21.10 (байты фраз из тестов `cascade0::spelled_*`, кириллица = 2 Б):
//! ИНН-10 170 Б, СНИЛС 185 Б, ИНН-12 223 Б, ОГРН 229 Б, ОГРНИП 258 Б, карта
//! 280 Б; максимум фразы, достижимый словарём `numwords` для 15-значного
//! класса, 336 Б. Все они лежат под 1024 Б — «класс адреса 212 Б» (#118 B1)
//! закрыт: за потолком остаётся только синтетический спан > 1024 Б, и для него
//! отказ обязан называть причину (`503 span_too_long len=<n> max=1024`).
//!
//! Проверяется ровно то, что видит клиент, по протоколу реального клиента:
//! `/v1/analyze` → опись спанов → `/v1/anonymize` (+ `/v1/deanonymize` на ноге
//! round-trip). Ноги (реестр ложно-зелёных, «print-only landing test»:
//! проверяются и выход, и состояние):
//!
//! 1. над потолком — отказ есть (503), причина названа (`span_too_long`,
//!    `len`/`max`), и это НЕ «хранилище токенов отказало» (ревью #118 B2),
//!    оригинал в ответ не попадает (fail-closed);
//! 2. словесный номер 170–280 Б (был за потолком 128) — 200, маркер на месте,
//!    оригинала в masked-тексте нет, **обратный ход побайтовый** (session);
//! 3. «пять миллиардов» 29 Б — класс мелочи под любым потолком: 200 + маркер,
//!    нога цела (промер 21.10: она была живой и до #120).
//!
//! Каскады 1–2 не монтируются: дефолтный `Config` без `FASAD_MODEL_DIR` =
//! стадия cascade-0-only, глобальный слот движка файл не трогает, поэтому
//! сериализация через `MOUNT_LOCK` (как в `cascade_http.rs`) не нужна.

#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа

use axum::body::Body as AxumBody;
use axum::http::{Request, StatusCode};
use guard_daemon::config::{Config, VaultMode};
use guard_daemon::http::{AppState, router};
use guard_daemon::schema::Schema;
use guard_daemon::vault::Vault;
use tower::ServiceExt as _;

/// Потолок из первички: `MAX_ORIGINAL_BYTES`, пинится и в тесте, и в доке.
const CAP: usize = guard_vault::token::MAX_ORIGINAL_BYTES;

/// ИНН-12 словами (golden 825082492964), та же фикстура, что в
/// `cascade0::spelled_inn12_fires_with_the_phrase_as_span`. 223 Б: до #120 —
/// за потолком (вечный 503), после — маскируется и разворачивается.
const INN12_WORDS: &str = concat!(
    "восемьсот двадцать пять миллиардов восемьдесят два миллиона ",
    "четыреста девяносто две тысячи девятьсот шестьдесят четыре"
);

/// «пять миллиардов» = 5000000000: проходит валидатор ИНН-10 и влезает в
/// любой из потолков (задокументированный компромисс круглых количеств,
/// `spelled_round_billion_is_the_documented_tradeoff`).
const ROUND_BILLION: &str = "пять миллиардов";

/// Состояние с выбранным режимом хранилища: `FASAD_VAULT_MODE` инжектится
/// через `from_lookup` (тот же контракт, что у `Config::from_env`, без `set_var`).
fn state(mode: VaultMode) -> AppState {
    let cfg = Config::from_lookup(|k| (k == "FASAD_VAULT_MODE").then(|| mode.as_str().to_owned()))
        .expect("дефолты sane");
    assert_eq!(cfg.vault_mode, mode, "режим обязан примениться");
    let health = guard_daemon::Health {
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

async fn post_req(
    st: AppState,
    path: &str,
    body: String,
    session: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(s) = session {
        b = b.header("x-session-id", s);
    }
    let resp = router(st)
        .oneshot(b.body(AxumBody::from(body)).expect("запрос строится"))
        .await
        .expect("обработчик не падает");
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .expect("тело читается");
    (
        parts.status,
        serde_json::from_slice(&bytes).expect("ответ — JSON"),
    )
}

async fn post(path: &str, body: String) -> (StatusCode, serde_json::Value) {
    post_req(state(VaultMode::Stateless), path, body, None).await
}

/// Спаны ответом `/v1/analyze` (голый массив, `RecognizerResult`-форма
/// Presidio) в виде, который пересылают в `/v1/anonymize`.
async fn analyze_spans(text: &str) -> Vec<(String, usize, usize)> {
    let (status, v) = post("/v1/analyze", format!(r#"{{"text":"{text}"}}"#)).await;
    assert_eq!(status, StatusCode::OK, "анализ обязан пройти: {v}");
    v.as_array()
        .expect("analyze отдаёт массив спанов")
        .iter()
        .map(|s| {
            (
                s["entity_type"].as_str().expect("класс").to_owned(),
                usize::try_from(s["byte_start"].as_u64().expect("байт начала"))
                    .expect("оффсет влезает в usize"),
                usize::try_from(s["byte_end"].as_u64().expect("байт конца"))
                    .expect("оффсет влезает в usize"),
            )
        })
        .collect()
}

async fn anonymize_at(
    st: &AppState,
    text: &str,
    spans: &[(String, usize, usize)],
    session: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let items: Vec<String> = spans
        .iter()
        .map(|(ty, b, e)| format!(r#"{{"entity_type":"{ty}","byte_start":{b},"byte_end":{e}}}"#))
        .collect();
    post_req(
        st.clone(),
        "/v1/anonymize",
        format!(r#"{{"text":"{text}","spans":[{}]}}"#, items.join(",")),
        session,
    )
    .await
}

/// Дефолтный (stateless) `/v1/anonymize`: та же цепочка, что у клиента по умолчанию.
async fn anonymize(
    text: &str,
    spans: &[(String, usize, usize)],
) -> (StatusCode, serde_json::Value) {
    anonymize_at(&state(VaultMode::Stateless), text, spans, None).await
}

/// Класс `inn` среди спанов ответа.
fn inn_span(spans: &[(String, usize, usize)]) -> (usize, usize) {
    spans
        .iter()
        .find(|(ty, _, _)| ty == "inn")
        .map(|&(_, b, e)| (b, e))
        .expect("каскад 0 нашёл словесный ИНН")
}

/// Пин потолка: тест краснеет, если `MAX_ORIGINAL_BYTES` уедет молча — тот же
/// класс дефекта, из-за которого #118 жил с вечным 503 (док и константа
/// разъехались бы без этой проверки).
#[test]
fn cap_is_the_documented_1024() {
    assert_eq!(CAP, 1024, "потолок #120: 128 → 1024, пин в доке и в тесте");
    assert!(
        INN12_WORDS.len() < CAP,
        "фикстура словесного номера обязана быть ПОД новым потолком: {} Б",
        INN12_WORDS.len()
    );
    assert!(
        INN12_WORDS.len() > 128,
        "и ЗА прежним: смысл #120 в том, что 223 Б теперь маскируются"
    );
}

#[tokio::test]
async fn spelled_registry_number_under_the_cap_round_trips_byte_exact() {
    // Смысл #120: round-trip словесного ИНН-12 (223 Б) жив. До поднятия
    // потолка этот вход давал 503 и до апстрима не доходил.
    assert_eq!(
        INN12_WORDS.len(),
        223,
        "промер 21.10: фикстура 223 Б (пин против изменения фразы)"
    );
    let text = format!("ИНН контрагента: {INN12_WORDS}, просим проверить");
    let spans = analyze_spans(&text).await;
    let (b, e) = inn_span(&spans);
    assert_eq!(&text[b..e], INN12_WORDS, "спан — на всю фразу словами");
    assert!(
        e - b < CAP,
        "после #120 фикстура обязана быть под потолком: {} Б",
        e - b
    );

    // session-режим: обратный ход обязан вернуть исходные байты.
    let st = state(VaultMode::Session);
    let (status, body) = anonymize_at(&st, &text, &spans, Some("cap120")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "словесный реестровый номер 223 Б маскируется (смысл #120): {body}"
    );
    let masked = body["text"].as_str().expect("текст с подменой");
    assert!(
        !masked.contains(INN12_WORDS),
        "оригинал протёк в masked-текст: {masked}"
    );
    assert!(masked.contains('['), "подмены-метки нет: {masked}");

    let req = format!(
        r#"{{"text":{}}}"#,
        serde_json::to_string(masked).expect("json строка")
    );
    let (status, back) = post_req(st, "/v1/deanonymize", req, Some("cap120")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "обратный ход обязан состояться: {back}"
    );
    assert_eq!(
        back["text"].as_str().expect("восстановленный текст"),
        text,
        "round-trip не побайтовый — смысл #120 не выполнен"
    );
}

#[tokio::test]
async fn span_over_the_cap_is_refused_with_its_reason() {
    // Контракт B2 (ревью #118) переписан под новый потолок: за 1024 Б остаётся
    // отказ, и он обязан называть причину. Фикстура синтетическая —
    // достижимого словарём `numwords` словесного номера за 1024 Б нет (промер:
    // максимум фразы для 15-значного класса 336 Б).
    //
    // Фикстура = ровно `CAP + 1` Б = 1025: 512 знаков «о» (2 Б/знак, кириллица)
    // дают 1024 Б, плюс один ASCII-знак. Ассертом длины это проверяется прямым
    // промером, а не арифметикой: две первые итерации фикстуры дали 2049 и
    // 1023 Б и покраснели именно здесь (реестр ложно-зелёных, «oracle-ceiling»).
    //
    // Проверка границы на уровне контейнера («1024 проходит / 1025 отказывает»)
    // живёт в `guard-vault`: `cap_boundary_is_1024_exact_and_plus_one_is_refused`.
    // Здесь важен HTTP-контур: статус, код, причина в детали, молчание об
    // оригинале.
    let words = ["о".repeat(CAP / 2), "a".to_owned()].concat();
    assert_eq!(
        words.len(),
        CAP + 1,
        "фикстура обязана быть ровно на байт за потолком"
    );
    let text = format!("ИНН контрагента: {words}, просим проверить");
    let b = text.find(&words).expect("фикстура в тексте");
    let spans = vec![("inn".to_owned(), b, b + words.len())];

    let (status, body) = anonymize(&text, &spans).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "спан за потолком не маскируется и не уходит наружу (fail-closed): {body}"
    );
    let err = &body["error"];
    assert_eq!(
        err["code"], "span_too_long",
        "код называет причину, а не «vault_error» вслепую (ревью #118 B2)"
    );
    let msg = err["message"].as_str().expect("сообщение строкой");
    assert_eq!(
        msg,
        format!("vault:span_too_long len={} max={CAP}", words.len()),
        "деталь обязана нести фактические числа спана (число лимита — авто из константы)"
    );
    assert!(
        msg.contains(&format!("max={CAP}")),
        "число лимита в детали обязано следовать константе: {msg}"
    );
    assert!(
        !msg.contains("хранилище токенов отказало"),
        "подставная причина недопустима: {msg}"
    );
    assert!(
        !body.to_string().contains(&words),
        "отказ не проталкивает оригинал в ответ"
    );
}

#[tokio::test]
async fn spelled_phrase_under_the_cap_masks_normally() {
    // Третья нога (класс мелочи, 29 Б): отказ выше — про потолок, а не про то,
    // что слой словесных номеров мёртв. Та же цепочка analyze → anonymize,
    // тот же класс `inn`.
    let text = format!("Ожидаемая выручка: {ROUND_BILLION} рублей");
    assert!(
        ROUND_BILLION.len() < CAP,
        "фикстура обязана быть под потолком: {} Б",
        ROUND_BILLION.len()
    );
    let spans = analyze_spans(&text).await;
    let (b, e) = inn_span(&spans);
    assert_eq!(&text[b..e], ROUND_BILLION, "спан — на фразу словами");

    let (status, body) = anonymize(&text, &spans).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "под потолком маскирование живое: {body}"
    );
    let masked = body["text"].as_str().expect("текст с подменой");
    assert!(
        masked.contains("[[F0#"),
        "режим по умолчанию stateless → маркер `[[F0#…]]`: {masked}"
    );
    assert!(
        !masked.contains(ROUND_BILLION),
        "оригинал протёк в ответ: {masked}"
    );
}
