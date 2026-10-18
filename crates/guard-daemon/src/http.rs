//! HTTP-слой: роутеры §8 + fail-closed middleware.
//!
//! На шаге 1 здесь только `/health`. Остальные контракты (§8:
//! `/v1/chat/completions`, `/v1/analyze`, `/v1/anonymize|deanonymize`,
//! `DELETE /v1/sessions/{id}`, `PUT /v1/schema`, `GET /ui`) собираются на шаге 6
//! вместе с fail-closed middleware: ошибка/таймаут детектора = запрос наружу не
//! уходит, никогда fail-open (AGENTS §Инженерные инварианты).

use axum::Router;
use axum::extract::State;
use axum::routing::get;

use crate::Health;

/// Собирает корневой роутер демона.
///
/// `Router` сам помечен `#[must_use]` — повторный атрибут не нужен.
pub fn router(health: Health) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .with_state(health)
}

async fn health_handler(State(health): State<Health>) -> axum::Json<Health> {
    // Ответ осознанно не содержит никаких пользовательских данных (§1 п.6:
    // весь разбор завершается на 127.0.0.1 до первой сокет-операции).
    axum::Json(health)
}

/// Каркас заголовков `X-Guard-*` (§8). На шаге 1 возвращает пустой набор:
/// счётчики маскирования появятся вместе с пайплайном (шаг 6), а не раньше.
#[must_use]
pub fn guard_headers() -> axum::http::HeaderMap {
    axum::http::HeaderMap::new()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn health_returns_200_with_scaffold_stage() {
        let app = router(crate::Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: "scaffold",
        });
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
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("тело читается");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("валидный JSON");
        assert_eq!(v["stage"], "scaffold");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn unknown_route_is_404_not_500() {
        // Fail-closed на уровне роутера: ничего не проксируем «автоматом».
        let app = router(crate::Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: "scaffold",
        });
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
}
