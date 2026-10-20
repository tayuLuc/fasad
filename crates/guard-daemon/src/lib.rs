//! Стендэлон-демон fasad (SPEC §6, §8).
//!
//! Шаг 1 (SPEC §10 п.1) дал каркас + `/health`; шаг 6 (SPEC §10 п.6, issue #56)
//! добавляет конфигурацию ([`config`]), конвейер `/v1/analyze` и пару
//! `/v1/anonymize|deanonymize` поверх `guard-vault`. UI (`/ui`) и прокси
//! `/v1/chat/completions` остаются за шагами 7–8: сеть наружу на этом шаге не
//! появляется вовсе (#56 п.5), и это не обещание «на глаз»: HTTP-клиент убран из
//! манифеста, а `just net-audit` (внутри `just check`) краснеет, если в crate
//! вернётся клиентский путь или исходящий `connect`. Список запрещённых имён
//! живёт в самом гейте и в тесте `daemon_manifest_has_no_http_client`.
//!
//! Fail-closed на этом шаге означает три вещи: паника обработчика становится
//! 503 `internal_panic` без цитаты из входа (`http::guarded`), хранилище
//! (`mlock`, CSPRNG, переполнение пула) даёт 503, а не «пустой ответ как будто
//! `ПДн` нет», и буферы с оригиналами обнуляются на `Drop` (`Zeroizing`).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used)]

pub mod cascade0;
pub mod config;
pub mod http;
pub mod pipeline;
pub mod schema;
pub mod vault;

/// Ответ `/health`: чем крутится демон и что в нём реально включено.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Health {
    /// Версия демона (= workspace version).
    pub version: &'static str,
    /// Собранный контур конвейера: `"cascade-0-only"` без весов, `"cascade-0+models"`
    /// с каталогом весов ([`config::Config::stage`]). Молчаливая деградация
    /// каскадов наружу не прячется: это первое, что смотрит оператор.
    pub stage: &'static str,
    /// Выставленный наружу режим хранилища (`"session"` / `"stateless"`,
    /// SPEC §3 режимы 2 и 3, #56 п.3).
    pub mode: &'static str,
}
