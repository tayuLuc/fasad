//! Потолок спана (128 Б) на словесных реестровых номерах: HTTP-контракт.
//!
//! **Контракт до решения #120.** Файл пинит ТЕКУЩЕЕ поведение атома #118
//! (числительные словами), а не желаемое: слой находит словесный ИНН/ОГРН/
//! карту, но найденная фраза словами длиннее `MAX_ORIGINAL_BYTES` = 128 Б
//! (`guard-vault/src/token.rs:53`), и маскирование отказывает. Выбор между
//! чанковым sealing, необратимой меткой и поднятием потолка вынесен в issue
//! #120 и здесь НЕ реализуется. Если #120 решит в пользу чанков — эти тесты
//! правятся осознанно одним атомом, молча под новый код они не поедут.
//!
//! Промер 21.10 (байты фраз из тестов `cascade0::spelled_*`, кириллица = 2 Б):
//! ИНН-10 170 Б, ИНН-12 223 Б, СНИЛС 185 Б, ОГРН 229 Б, ОГРНИП 258 Б,
//! карта 280 Б — все выше потолка; «пять миллиардов» 29 Б — ниже. То есть
//! потолок ловит не редкий вход, а почти любой словесный реестровый номер.
//!
//! Проверяется ровно то, что видит клиент, по протоколу реального клиента:
//! `/v1/analyze` → опись спанов → `/v1/anonymize`. Два Legs (реестр
//! ложно-зелёных, «print-only landing test»):
//!
//! 1. над потолком — отказ есть (503), причина названа (`span_too_long`,
//!    `len`/`max`), и это НЕ «хранилище токенов отказало» (ревью #118 B2),
//!    оригинал в ответ не попадает (fail-closed);
//! 2. под потолком — 200, маркер на месте, оригинала в тексте нет: отказ
//!    выше — это потолок, а не «слой словесных номеров не работает».
//!
//! Каскады 1–2 не монтируются: дефолтный `Config` без `FASAD_MODEL_DIR` =
//! стадия cascade-0-only, глобальный слот движка файл не трогает, поэтому
//! сериализация через `MOUNT_LOCK` (как в `cascade_http.rs`) не нужна.

#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа

use axum::body::Body as AxumBody;
use axum::http::{Request, StatusCode};
use guard_daemon::config::Config;
use guard_daemon::http::{AppState, router};
use guard_daemon::schema::Schema;
use guard_daemon::vault::Vault;
use tower::ServiceExt as _;

/// Потолок из первички: `MAX_ORIGINAL_BYTES`, пинится и в тесте, и в доке.
const CAP: usize = guard_vault::token::MAX_ORIGINAL_BYTES;

/// ИНН-12 словами (golden 825082492964), та же фикстура, что в
/// `cascade0::spelled_inn12_fires_with_the_phrase_as_span`.
const INN12_WORDS: &str = concat!(
    "восемьсот двадцать пять миллиардов восемьдесят два миллиона ",
    "четыреста девяносто две тысячи девятьсот шестьдесят четыре"
);

/// «пять миллиардов» = 5000000000: проходит валидатор ИНН-10 и влезает в
/// потолок (задокументированный компромисс круглых количеств,
/// `spelled_round_billion_is_the_documented_tradeoff`).
const ROUND_BILLION: &str = "пять миллиардов";

fn state() -> AppState {
    let cfg = Config::from_lookup(|_| None).expect("дефолты sane");
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

async fn post(path: &str, body: String) -> (StatusCode, serde_json::Value) {
    let resp = router(state())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(AxumBody::from(body))
                .expect("запрос строится"),
        )
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

async fn anonymize(
    text: &str,
    spans: &[(String, usize, usize)],
) -> (StatusCode, serde_json::Value) {
    let items: Vec<String> = spans
        .iter()
        .map(|(ty, b, e)| format!(r#"{{"entity_type":"{ty}","byte_start":{b},"byte_end":{e}}}"#))
        .collect();
    post(
        "/v1/anonymize",
        format!(r#"{{"text":"{text}","spans":[{}]}}"#, items.join(",")),
    )
    .await
}

/// Класс `inn` среди спанов ответа.
fn inn_span(spans: &[(String, usize, usize)]) -> (usize, usize) {
    spans
        .iter()
        .find(|(ty, _, _)| ty == "inn")
        .map(|&(_, b, e)| (b, e))
        .expect("каскад 0 нашёл словесный ИНН")
}

#[tokio::test]
async fn spelled_registry_number_over_the_cap_is_refused_with_its_reason() {
    // Контракт до решения #120: находка есть, маскирования нет, отказ говорит почему.
    let text = format!("ИНН контрагента: {INN12_WORDS}, просим проверить");
    assert_eq!(
        INN12_WORDS.len(),
        223,
        "промер 21.10: фикстура 223 Б (пин против изменения фразы)"
    );
    let spans = analyze_spans(&text).await;
    let (b, e) = inn_span(&spans);
    let span_bytes = e - b;
    assert!(
        span_bytes > CAP,
        "фикстура обязана быть за потолком: {span_bytes} Б против {CAP} Б"
    );

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
        format!("vault:span_too_long len={span_bytes} max={CAP}"),
        "деталь обязана нести фактические числа спана"
    );
    assert!(
        !msg.contains("хранилище токенов отказало"),
        "подставная причина недопустима: {msg}"
    );
    assert!(
        !body.to_string().contains(INN12_WORDS),
        "отказ не проталкивает оригинал в ответ"
    );
}

#[tokio::test]
async fn spelled_phrase_under_the_cap_masks_normally() {
    // Вторая нога: отказ выше — про потолок, а не про то, что слой словесных
    // номеров мёртв. Та же цепочка analyze → anonymize, тот же класс `inn`.
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
