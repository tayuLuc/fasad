//! Точка входа демона `fasad`.
//!
//! Шаг 1: слушает 127.0.0.1 (SPEC §1 п.6: никаких сетевых вызовов, кроме явного
//! `X-Upstream-URL`, и старт только на loopback) и отдаёт `/health`.
//! Конфиг-файл, tray и rust-embed UI — шаги 6/8.

#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]

use guard_daemon::Health;
use guard_daemon::config::{Config, ConfigError};

/// Код выхода при отклонённой конфигурации: отдельный от сетевых ошибок, чтобы
/// systemd/докер видели «неверный конфиг» как неверный конфиг, а не как порт
/// занят (перезапуск с backoff тут бессмыслен и маскирует опечатку).
const EXIT_BAD_CONFIG: i32 = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => fail_closed_config(&e),
    };

    // Loopback обязателен и проверен на разборе: гард не сетевой сервис
    // (SPEC §1 п.6), и `0.0.0.0` сюда протаскивается только через эту стену.
    let app = guard_daemon::http::router(Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: cfg.stage(),
        mode: cfg.vault_mode.as_str(),
    });

    let listener = tokio::net::TcpListener::bind(cfg.addr).await?;
    println!(
        "fasad {} {}, listening on http://{}/health",
        env!("CARGO_PKG_VERSION"),
        cfg.stage(),
        cfg.addr
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// Отказ по конфигу: напечатать причину и выйти, не поднимая сокет.
///
/// Вынесено в `-> !`, чтобы поток управления был явен для компилятора, а не
/// через `unwrap_or_else(|e| todo!())`.
fn fail_closed_config(err: &ConfigError) -> ! {
    eprintln!("fasad: конфигурация отклонена, сокет не поднимается: {err}");
    std::process::exit(EXIT_BAD_CONFIG);
}
