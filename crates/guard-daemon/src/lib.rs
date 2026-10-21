//! Стендэлон-демон fasad (SPEC §6, §8).
//!
//! Шаг 1 (SPEC §10 п.1) дал каркас + `/health`; шаг 6 (SPEC §10 п.6, issue #56)
//! добавил конфигурацию ([`config`]), конвейер `/v1/analyze` и пару
//! `/v1/anonymize|deanonymize` поверх `guard-vault`; шаг 7c ([`proxy`], SPEC §10
//! п.7) — прокси `/v1/chat/completions`, то есть первое исходящее соединение.
//! UI (`/ui`) остаётся за шагом 8.
//!
//! Сеть наружу по-прежнему не свободная, а разрешённая точечно: единственный
//! исходящий путь — [`proxy`], адрес только из `X-Upstream-URL` и только из
//! `FASAD_UPSTREAM_ALLOWLIST`, TLS обязателен (кроме loopback-исключения для
//! тестов), редиректы не сопровождаются. Гейт `just net-audit` (внутри
//! `just check`) с шага 7c проверяет не «клиента нет», а «клиент ровно один и
//! это `src/proxy.rs`»: запрещённые имена ищутся во всех модулях, кроме одного
//! санкционированного.
//!
//! Fail-closed на этом шаге означает три вещи: паника обработчика становится
//! 503 `internal_panic` без цитаты из входа (`http::guarded`), хранилище
//! (`mlock`, CSPRNG, переполнение пула) даёт 503, а не «пустой ответ как будто
//! `ПДн` нет», и буферы с оригиналами обнуляются на `Drop` (`Zeroizing`).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used)]

pub mod cascade0;
pub mod cascades;
pub mod config;
pub mod http;
pub mod pipeline;
pub mod proxy;
pub mod schema;
pub mod sse;
pub mod ui;
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
