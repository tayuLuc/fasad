//! Точка входа демона `fasad`.
//!
//! Шаг 6: слушает 127.0.0.1 (SPEC §1 п.6: никаких сетевых вызовов, кроме явного
//! `X-Upstream-URL`, и старт только на loopback), поднимает `/health` и
//! `/v1/analyze`; конфиг из `FASAD_*`-переменных, схема из встроенного канона
//! (или `FASAD_SCHEMA`). Tray и UI — шаги 8+.

#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]

use guard_daemon::Health;
use guard_daemon::config::Config;
use guard_daemon::http::AppState;
use guard_daemon::schema::Schema;

/// Код выхода при отклонённой конфигурации: отдельный от сетевых ошибок, чтобы
/// systemd/докер видели «неверный конфиг» как неверный конфиг, а не как порт
/// занят (перезапуск с backoff тут бессмыслен и маскирует опечатку).
const EXIT_BAD_CONFIG: i32 = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => refuse_startup(&e),
    };

    // Схема проверяется до подъёма сокета: частично применимая схема хуже
    // отсутствующей, а `/health` с 200 на испорченном каноне ввёл бы оператора
    // в заблуждение (fail-closed, AGENTS §Инженерные инварианты).
    let schema = match Schema::from_config(cfg.schema_path.as_deref()) {
        Ok(schema) => schema,
        Err(e) => refuse_startup(&e),
    };

    // Loopback обязателен и проверен на разборе: гард не сетевой сервис
    // (SPEC §1 п.6), и `0.0.0.0` сюда протаскивается только через эту стену.
    let health = Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: cfg.stage(),
        mode: cfg.vault_mode.as_str(),
    };
    let classes = schema.classes.len();
    let app = guard_daemon::http::router(AppState::new(cfg.clone(), schema, health));

    let listener = tokio::net::TcpListener::bind(cfg.addr).await?;
    println!(
        "fasad {} {}, listening on http://{}/health (классов схемы: {})",
        env!("CARGO_PKG_VERSION"),
        cfg.stage(),
        cfg.addr,
        classes
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// Отказ на старте (конфиг или схема): причина в stderr, сокет не поднимается.
///
/// Вынесено в `-> !`, чтобы поток управления был явен для компилятора, а не
/// через `unwrap_or_else(|e| todo!())`.
fn refuse_startup(err: &dyn std::fmt::Display) -> ! {
    eprintln!("fasad: старт невозможен: {err}");
    std::process::exit(EXIT_BAD_CONFIG);
}
