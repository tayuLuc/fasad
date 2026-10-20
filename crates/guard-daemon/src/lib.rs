//! Стендэлон-демон fasad (SPEC §6, §8).
//!
//! Шаг 1 (SPEC §10 п.1) дал каркас + `/health`; шаг 6 (SPEC §10 п.6, issue #56)
//! добавляет конфигурацию ([`config`]), конвейер `/v1/analyze` и пару
//! `/v1/anonymize|deanonymize` поверх `guard-vault`. UI (`/ui`) и прокси
//! `/v1/chat/completions` остаются за шагами 7–8: сеть наружу на этом шаге не
//! появляется вовсе (#56 п.5).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used)]

pub mod config;
pub mod http;
pub mod schema;

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
