//! Живой GUI-интеграл трея (#128 фаза 2) — **только под фичей `tray`**.
//!
//! Юниты `src/tray.rs` меряют логику (формат tooltip, RGBA, построение
//! open-команды, quit-флаг); этот тест меряет то, что без оконной сессии не
//! измеряется: `TrayIcon::build()` поднимает status-item, цикл крутится, Quit
//! сворачивает процесс. На CI-раннерах он НЕ запускается (`#[ignore]`;
//! headless-раннер без окна = гарантированный отказ не продукта, а теста),
//! прогон — руками на машине оператора:
//!
//! ```text
//! cargo test -p guard-daemon --features tray --test tray_live -- --ignored --nocapture
//! ```
//!
//! Ручной прогон: в меню-баре появляется зелёный квадрат; клик открывает
//! `http://127.0.0.1:<порт>/ui` в браузере; меню → «Выход (graceful)»
//! завершает процесс (порт освобождается).
//!
//! #244 win-полка (тот же прогон на win-машине оператора): иконка в лотке
//! (при «скрыто» — в свёрнутой области ▲), tooltip тикает, клик открывает
//! UI, меню = адрес/открыть/выход, «Выход» = graceful;
//! `%APPDATA%\fasad\fasad-tray.log` = след startup-текстов; второй запуск
//! при живом первом = bind-отказ **окном** (rc=2, не тихая смерть #244);
//! отказ иконки = окно «трей не поднялся» + лог (UI жив).
//!
//! #263 mac-полка (тот же прогон на машине оператора, mac): лог-контур =
//! `<config-root>/fasad-tray.log` (`$XDG_CONFIG_HOME/fasad`/
//! `$HOME/.config/fasad`): запуск из Terminal = stderr + файл; тихий запуск
//! (Finder-двойной-клик без терминала) = файл = единственный след
//! startup/refuse-текстов (win-полка, зеркало).

#![cfg(all(feature = "tray", any(target_os = "windows", target_os = "macos")))]
#![allow(clippy::unwrap_used, clippy::expect_used)] // тестовый файл: паника = отказ теста

use std::sync::Arc;

#[test]
#[ignore = "требует GUI-сессии (status-item, браузер): ручной промер на машине оператора, см. док модуля"]
fn tray_lives_and_quit_ends_it() {
    // Тот же `Arc<Inner>`, что живёт в боевом демоне: трей обязан читать
    // счётчики состояния роутера, а не отдельный `Vault` (иначе тест мерил бы
    // объект, которого в продукте нет).
    let cfg = guard_daemon::config::Config::from_env().expect("конфиг по умолчанию");
    let vault = guard_daemon::vault::Vault::startup(cfg.vault_mode, cfg.mlock)
        .expect("хранилище поднимается");
    let schema = guard_daemon::schema::Schema::from_config(None).expect("канон схемы");
    let health = guard_daemon::Health {
        version: "test",
        stage: "cascade-0-only",
        mode: cfg.vault_mode.as_str(),
    };
    let state = Arc::new(guard_daemon::http::AppState::new(cfg, schema, health, vault).inner_arc());
    let shutdown = guard_daemon::tray::Shutdown::new();
    // Порт 0: «дай свободный» — контракт `FASAD_PORT=0` из config.rs.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback-порт");
    let port = listener.local_addr().expect("адрес").port();
    drop(listener);

    // Тред-симуляция клика Quit через 3 с: цикл трея обязан выйти по флагу за
    // свой шаг (2 с) + буфер.
    {
        let sd = shutdown.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            sd.trigger();
        });
    }
    // Главный поток = цикл трея (требование крейта, docs модуля `tray`).
    guard_daemon::tray::run(
        &state,
        guard_daemon::static_stage("cascade-0-only"),
        port,
        &shutdown,
    );
    assert!(shutdown.triggered(), "цикл вышел по quit-флагу");
    assert!(
        guard_daemon::tray::OPEN_CLICKS.load(std::sync::atomic::Ordering::Relaxed) == 0,
        "клик по иконке в автотесте не было — копка пуста"
    );
}
