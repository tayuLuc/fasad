//! Точка входа демона `fasad`.
//!
//! Шаг 6: слушает 127.0.0.1 (SPEC §1 п.6: никаких сетевых вызовов, кроме явного
//! `X-Upstream-URL`, и старт только на loopback), поднимает `/health`,
//! `/v1/analyze`, `/v1/anonymize`, `/v1/deanonymize`, `/v1/sessions/{id}`;
//! конфиг из `FASAD_*`-переменных, схема из встроенного канона (или
//! `FASAD_SCHEMA`). Tray и UI — шаги 8+.
//!
//! Хук паники ставится до первого сокета: дефолтный хук печатает сообщение
//! паники, а сообщение сторонней библиотеки могут собирать из аргументов, т.е.
//! из текста запроса (`ПДн`). Печатается только место в коде.

#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]

use guard_daemon::Health;
use guard_daemon::config::Config;
use guard_daemon::http::AppState;
use guard_daemon::schema::Schema;
use guard_daemon::vault::Vault;

/// Хук паники: место в коде без сообщения.
///
/// Обработчики завёрнуты в `http::guarded` и превращают панику в 503, но сообщение в stderr пишет хук, а не обёртка —
/// поэтому хук ставится здесь, до бинда.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "неизвестно".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        eprintln!("fasad: паника в {loc} (сообщение скрыто: в нём может быть вход запроса)");
    }));
}

/// Код выхода при отклонённой конфигурации: отдельный от сетевых ошибок, чтобы
/// systemd/докер видели «неверный конфиг» как неверный конфиг, а не как порт
/// занят (перезапуск с backoff тут бессмыслен и маскирует опечатку).
const EXIT_BAD_CONFIG: i32 = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    install_panic_hook();
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
    // Хранилище поднимается до сокета по той же причине, что и схема: режим 2/3
    // без ключа и без залочкированной памяти обслуживать нельзя, а отказ после
    // bind выглядит как «демон живой, но ничего не работает».
    let vault = match Vault::startup(cfg.vault_mode, cfg.mlock) {
        Ok(vault) => vault,
        Err(e) => refuse_startup(&e),
    };
    let vault_key_source = vault.key_source().as_str();
    let classes = schema.classes.len();
    let app = guard_daemon::http::router(AppState::new(cfg.clone(), schema, health, vault));

    let listener = tokio::net::TcpListener::bind(cfg.addr).await?;
    // Порт в баннере — фактически занятый, а не запрошенный: `FASAD_PORT=0`
    // означает «дай свободный», и без `local_addr` оператор (и e2e-тест
    // `tests/wire_e2e.rs`, который поднимает этот бинарь) увидел бы в баннере
    // ноль и не узнал, куда стучаться.
    let addr = listener.local_addr()?;
    println!(
        "fasad {} {}, listening on http://{}/health (классов схемы: {}, vault: {}/{}, ключ: {})",
        env!("CARGO_PKG_VERSION"),
        cfg.stage(),
        addr,
        classes,
        cfg.vault_mode.as_str(),
        cfg.mlock.as_str(),
        vault_key_source,
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
