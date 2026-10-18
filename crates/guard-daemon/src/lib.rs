//! Стендэлон-демон fasad (SPEC §6, §8).
//!
//! Шаг 1 (SPEC §10 п.1): только каркас + `/health`, чтобы CI-матрица обеих ОС
//! собирала и гоняла живой бинарь. Роуты §8, fail-closed middleware и UI
//! добавляются на шагах 6–8.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used)]

pub mod http;

/// Ответ `/health`: демон жив, конвейер ещё не собран.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Health {
    /// Версия демона (= workspace version).
    pub version: &'static str,
    /// Статус каркаса: на шаге 1 всегда `"scaffold"` — детекторы/модели не
    /// загружены, проксировать нечего (fail-closed по отсутствию функционала,
    /// а не по ошибке).
    pub stage: &'static str,
}
