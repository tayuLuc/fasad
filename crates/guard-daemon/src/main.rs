//! Точка входа демона `fasad`.
//!
//! Шаг 1: слушает 127.0.0.1 (SPEC §1 п.6: никаких сетевых вызовов, кроме явного
//! `X-Upstream-URL`, и старт только на loopback) и отдаёт `/health`.
//! Конфиг-файл, tray и rust-embed UI — шаги 6/8.

#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use guard_daemon::Health;

/// Порт по умолчанию; переопределяется `FASAD_PORT` (значение не распарсится —
/// дефолт, молча: это эргономика разработки, не контракт безопасности).
const DEFAULT_PORT: u16 = 8765;

fn port_from_env() -> u16 {
    port_from_value(std::env::var("FASAD_PORT").ok().as_deref())
}

/// Чистая часть разбора: значение env → порт; мусор = дефолт.
/// Вынесена из [`port_from_env`], чтобы тестировать без мутации среды процесса.
fn port_from_value(raw: Option<&str>) -> u16 {
    raw.and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Loopback обязателен: гард не сетевой сервис (SPEC §1 п.6).
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_from_env());

    let app = guard_daemon::http::router(Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: "scaffold",
    });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(
        "fasad {} scaffold, listening on http://{addr}/health",
        env!("CARGO_PKG_VERSION")
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    /// Порт из env: только читатель, без мутаций среды — `set_var` в тестах требовал бы
    /// unsafe (edition 2024) и конфликтовал бы с параллельными тестами.
    #[test]
    fn default_port_is_a_dozen_four_k() {
        assert_eq!(DEFAULT_PORT, 8765);
        assert_eq!(port_from_value(Some("9999")), 9999);
        assert_eq!(port_from_value(Some(" 1234 ")), 1234);
    }

    #[test]
    fn port_garbage_falls_back_to_default() {
        assert_eq!(port_from_value(Some("abc")), DEFAULT_PORT);
        assert_eq!(port_from_value(Some("70000")), DEFAULT_PORT);
        assert_eq!(port_from_value(Some("")), DEFAULT_PORT);
        assert_eq!(port_from_value(None), DEFAULT_PORT);
    }
}
