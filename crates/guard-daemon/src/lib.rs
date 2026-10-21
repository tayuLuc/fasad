//! Стендэлон-демон fasad (SPEC §6, §8).
//!
//! Шаг 1 (SPEC §10 п.1) дал каркас + `/health`; шаг 6 (SPEC §10 п.6, issue #56)
//! добавил конфигурацию ([`config`]), конвейер `/v1/analyze` и пару
//! `/v1/anonymize|deanonymize` поверх `guard-vault`; шаг 7c ([`proxy`], SPEC §10
//! п.7) — прокси `/v1/chat/completions`, то есть первое исходящее соединение;
//! шаг 8 ([`ui`], SPEC §10 п.8, issue #75) — вшитая в бинарник песочница `/ui`;
//! шаги 9A/9B (issue #14A, PR #87) — каскады 1–2 внутри продуктового конвейера
//! ([`cascades`]).
//!
//! Модульный состав (перечень = `pub mod` ниже, по заголовкам самих модулей):
//! [`config`] — env → тип с fail-closed разбором; [`schema`] — канон классов
//! `ПДн` с валидаторами; [`cascade0`] — каскад 0: кандидаты → чексуммы схемы →
//! классы на координатах оригинала; [`numwords`] — числительные словами → цифры,
//! дополнение каскада 0 (issue #51 п.2); [`cascades`] — каскады 1–2 поверх него,
//! живущие только под фичей `ort-inference`; [`pipeline`] — конвейер `/v1/analyze` над
//! всем этим; [`vault`] — обратимое маскирование (`/v1/anonymize|deanonymize`);
//! [`http`] — роутеры §8, сетка `X-Guard-*` и fail-closed middleware; [`sse`] —
//! релай кадров ответа прокси; [`proxy`] — единственный исходящий наружу путь;
//! [`ui`] — статика песочницы, зашитая в бинарник.
//!
//! Сеть наружу по-прежнему не свободная, а разрешённая точечно: единственный
//! исходящий путь — [`proxy`], адрес только из `X-Upstream-URL` и только из
//! `FASAD_UPSTREAM_ALLOWLIST`, TLS обязателен (кроме loopback-исключения для
//! тестов), редиректы не сопровождаются. Гейт `just net-audit` (внутри
//! `just check`) с шага 7c проверяет не «клиента нет», а «клиент ровно один и
//! это `src/proxy.rs`»: запрещённые имена ищутся во всех модулях, кроме одного
//! санкционированного.
//!
//! Fail-closed в демоне означает три вещи: паника обработчика становится
//! 503 `internal_panic` без цитаты из входа (`http::guarded`), хранилище
//! (`mlock`, CSPRNG, переполнение пула) даёт 503, а не «пустой ответ как будто
//! `ПДн` нет», и буферы с оригиналами обнуляются на `Drop` (`Zeroizing`).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used)]

pub mod cascade0;
pub mod cascades;
pub mod config;
pub mod http;
pub mod numwords;
pub mod pipeline;
pub mod proxy;
pub mod schema;
pub mod sse;
// Иконка трея win/mac (#128 фаза 2): модуль целиком под cfg фичи + ОС-мишени;
// на linux фича недоступна (compile_error крейта — см. заголовок [`tray`]).
#[cfg(all(feature = "tray", any(target_os = "windows", target_os = "macos")))]
pub mod tray;
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
