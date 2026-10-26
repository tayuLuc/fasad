//! #318-полка: трей-строка = ЖИВОЕ чтение на смонтированном контуре.
//!
//! Из ревью #317: `main` клал `tray_stage` СТАТИКОЙ в `tray::run` → после
//! hot-mount #316 `/health` = `cascade-0+models`, а трей (tooltip/иконка) =
//! «… / models-pending» = враньё клиент-видимой витрины (#226-контра).
//! Чин = `AppState::stage_reader()` (замыкание на `live_stage` = атом
//! `MOUNT_LIVE`, #316) → `StatusInfo::snapshot` читает stage КАЖДЫЙ ТИК.
//!
//! Контур legs (первичка #316-полки):
//! - **linux = ∅** (docs/dep-verify-crates.md §16: `tray`-фича не
//!   компилируется: `compile_error` у tray-icon без libappindicator; CI
//!   «красная строка linux» это и фиксирует) — зуб не может быть ubuntu-ного;
//! - **mac = CI-лег** (macos-14, `--features tray,ort-inference`, веса =
//!   CI-fetch шаг #255-паттерн): НО = stdout-полка (lesson #240:
//!   GUI-иконка/tooltip = `NSStatusBar` = за пределами headless-раннера,
//!   живой GUI-контур = операторский приёмник #313-семьи; ЗУБ = строка в
//!   stdout: `TRAYSTAGE|pending→mounted` = та же пара (reader, snapshot),
//!   что крутит `run`-цикл);
//! - **win = CI-msvc compile-контра** (`just tray-check` = clippy/check
//!   `--features tray` на windows-2022, ci.yml-шаг = первичка; GUI runtime
//!   = операторский приёмник #313, не автотест).
//!
//! Unit-контра (headless, любая ОС): `snapshot_reads_stage_live_on_every_tick`
//! + `stage_reader_of_state_follows_the_live_atom` (tray.rs).
//!
//! Локальный промер = runtime-read каталога весов (монтаж = 2–3 с, без
//! сборки/скачивания; slot-контра 22.10), ПЕРВОЕ число: 3.1 с на машине
//! оператора, threads=2 (`live_mount`-промер #316 = 2.6 с mac-CI).
//! Полка = то же утверждение на CI-ядре: строка `TRAYSTAGE|…` в логе.
//!
//! Без весов = `SKIP|…` + падение при `FASAD_REQUIRE_MODELS` (#87-паттерн).
#![cfg(all(
    feature = "tray",
    feature = "ort-inference",
    any(target_os = "windows", target_os = "macos")
))]
#![allow(clippy::unwrap_used, clippy::expect_used)] // паника = красный CI = канал ответа

use std::path::PathBuf;

use guard_daemon::cascades;
use guard_daemon::config::Config;
use guard_daemon::http::AppState;
use guard_daemon::schema::Schema;

fn model_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FASAD_MODEL_DIR") {
        let p = PathBuf::from(dir);
        return p.is_dir().then_some(p);
    }
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".cache/fasad-models");
    cache.is_dir().then_some(cache)
}

#[test]
fn tray_stage_line_flips_with_hot_mount() {
    let Some(dir) = model_dir() else {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а весов нет — #318-полка не смонтирована"
        );
        eprintln!("SKIP|tray_stage_live|нет каталога весов");
        return;
    };
    let dir_s = dir.display().to_string();
    let cfg = Config::from_lookup(|k| match k {
        "FASAD_MODEL_DIR" => Some(dir_s.clone()),
        "FASAD_THREADS" => Some("2".to_owned()),
        _ => None,
    })
    .expect("конфиг с весами sane");

    // Прод-форма вызова (main): состояние ожидавшего старта (desktop-контра
    // #198) + `stage_reader()` + `StatusInfo::snapshot` = тот же путь, что
    // каждый тик `run`-цикла.
    let st = AppState::with_pending(
        cfg.clone(),
        Schema::embedded().expect("канон"),
        guard_daemon::Health {
            version: env!("CARGO_PKG_VERSION"),
            stage: cascades::STAGE_PENDING,
            mode: cfg.vault_mode.as_str(),
        },
        guard_daemon::vault::Vault::startup(cfg.vault_mode, cfg.mlock).expect("хранилище"),
        true,
    );
    let reader = st.stage_reader();
    let inner = st.inner_arc();
    let s1 = guard_daemon::tray::StatusInfo::snapshot(&inner, &reader, 8765);
    assert_eq!(
        s1.stage,
        cascades::STAGE_PENDING,
        "до монтажа = честный pending"
    );

    cascades::live_mount(&cfg, &dir).expect("живой монтаж на CI-весах");
    let s2 = guard_daemon::tray::StatusInfo::snapshot(&inner, &reader, 8765);
    println!("TRAYSTAGE|{}->{}", s1.stage, s2.stage);
    assert_eq!(
        s2.stage,
        cascades::STAGE_MOUNTED,
        "трей-строка после hot-mount = live (статика старта = враньё #226)"
    );
    assert!(
        s2.tooltip()
            .ends_with(&format!("/ {}", cascades::STAGE_MOUNTED)),
        "tooltip = контракт #226 (видимая строка): {:?}",
        s2.tooltip()
    );
    cascades::install_test_live_mount(None, None);
}
