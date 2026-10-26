//! #316-полка: горячий монтаж каскадов 1–2 = ЖИВОЙ контур на весах.
//!
//! Unit-контур (`cascades::tests::live_mount_…`, `http::tests::hot_mount_…`)
//! закрыл контракт свопа на мок-слоте. Цена live-факта «смонтированный
//! `OnnxMount` отвечает конвейеру» = промер на настоящих весах = CI
//! `ort-build` (#255/#109-прецедент: шаг fetch-models + `FASAD_REQUIRE_MODELS`
//! = провен монтирования, молчаливого SKIP нет, lesson #237).
//!
//! ЗУБ (оператор-требование #316: «перезапусти» = НЕ канает): в ЖИВОМ
//! процессе — монтаж без рестарта = `live_mount` swap + `analyze`:
//! 1. pending-контра: `mounted_live` = false, `live_stage` = pending-строка;
//! 2. swap на живом процессе (процесс НЕ перезапускался) = `Ok`;
//! 3. `mounted_live` = true, stage = `cascade-0+models` = `/health`-контра;
//! 4. `pipeline::analyze` = Ok с живыми спанами (конвейер выпущен МОНТАЖОМ);
//! 5. идемпотентность: второй `live_mount` = NOOP `Ok` (RSS-бюджет 1843 MiB:
//!    второй сессии ORT нет, docs/model-audit).
//!
//! RSS-дисциплина (#232): пики = артефакт строками `HOTMOUNT|…`, не пин.
//! Без весов = `SKIP|…` + падение при `FASAD_REQUIRE_MODELS`.

#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = канал ответа

use std::path::PathBuf;
use std::time::Instant;

use guard_daemon::cascades;
use guard_daemon::config::Config;
use guard_daemon::pipeline::{AnalyzeRequest, Policy, analyze};
use guard_daemon::schema::Schema;
use zeroize::Zeroizing;

const GOLDEN: &str = include_str!("../../../data/golden/golden-v1.jsonl");

fn model_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FASAD_MODEL_DIR") {
        let p = PathBuf::from(dir);
        return p.is_dir().then_some(p);
    }
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".cache/fasad-models");
    cache.is_dir().then_some(cache)
}

fn cfg_with(dir: &std::path::Path) -> Config {
    let dir_s = dir.display().to_string();
    Config::from_lookup(|k| match k {
        "FASAD_MODEL_DIR" => Some(dir_s.clone()),
        "FASAD_THREADS" => Some("2".to_owned()),
        _ => None,
    })
    .expect("конфиг с весами sane")
}

#[test]
fn hot_mount_swaps_a_live_process_and_the_pipeline_answers() {
    let Some(dir) = model_dir() else {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а весов нет — #316-полка не смонтирована"
        );
        eprintln!("SKIP|hot_mount_live|нет каталога весов (FASAD_MODEL_DIR/~/.cache/fasad-models)");
        return;
    };
    assert!(
        guard_daemon::weights::layout_complete(&dir),
        "полка = настоящий layout 5/5 (CI-fetch), фейк-контра unit-слоя здесь не нужна"
    );
    let cfg = cfg_with(&dir);
    let schema = Schema::embedded().expect("канон");

    // (1) КОНТРА ПЕРЕМЕННОЙ СРЕДЫ процесса: этот тестовый процесс = чистый
    // лист (файл-контейнер: свой бинарь, `startup` не звался).
    assert!(
        !cascades::mounted_live(),
        "чистый процесс = не live (флаг процесса, а не конфига)"
    );
    let health_stage_pending = cascades::STAGE_PENDING;
    println!("HOTMOUNT|pre|pending|{health_stage_pending}");

    // (2) SSWAP на живом процессе: `live_mount` = prod-функция (не debug-
    // подмена): `OnnxMount::load` (ORT-сессии, 2–3 с) + `*mount_slot() =
    // Some` + флаг. Рестарта процесса НЕТ = утверждение теста.
    let t = Instant::now();
    cascades::live_mount(&cfg, &dir)
        .expect("живой монтаж на смонтированном каталоге обязан удасться");
    let mount_ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);

    // (3) live-флаг + stage-контра `/health` (тот же атом читает http).
    assert!(
        cascades::mounted_live(),
        "#316: swap без рестарта поднял live"
    );
    assert_eq!(cascades::mount_last_error(), None, "успех очищает причину");
    println!(
        "HOTMOUNT|swap|ok|mount_ms|{mount_ms}|stage|{}",
        cascades::STAGE_MOUNTED
    );

    // (4) КОНВЕЙЕР ОТВЕЧАЕТ: живой analyze на freshly-mounted движке =
    // 200-класс (первичка #316: конвейер выпущен монтажом; fail-closed снят
    // не обнулением — до swap `analyze_with(mount: None)` = каскад-0, после
    // = cascade-0+models). Зуб =Ok + non-empty spans на golden-входе.
    let row = GOLDEN
        .lines()
        .find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["text"].as_str().map(str::to_owned))
        })
        .expect("golden-строка с ФИО");
    let req = AnalyzeRequest {
        text: Zeroizing::new(row.clone()),
        entities: None,
        score_threshold: None,
    };
    let t = Instant::now();
    let a = analyze(&req, &schema, &cfg, Policy::Mask).expect("живой конвейер после монтажа");
    let an_ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    println!(
        "HOTMOUNT|analyze|ok|ms|{an_ms}|spans|{}|cascade2|{}",
        a.spans.len(),
        a.cascade2
    );
    assert!(
        !a.spans.is_empty(),
        "golden-вход без спанов = контур мёртв (lesson ложно-зелёных)"
    );

    // (5) Идемпотентность: второй live_mount = NOOP Ok (нет второй сессии
    // ORT = RSS-бюджет; poll+fetch-триггер бьют повторно по построению).
    cascades::live_mount(&cfg, &dir).expect("второй live_mount = NOOP Ok");
    assert!(cascades::mounted_live(), "NOOP не роняет live");
    println!("HOTMOUNT|second|noop");
}

/// Фейк-полка (без весов, unit-контра этой же ноги): `layout_complete` на
/// фейк-файлах НЕ равна «4096-байтовый файлик прошёл»: гейт = РАЗМЕР vs
/// манифест (первичка ТЗ #316). Полка живого flip = выше (орт-нога); эта
/// решётка = предикат триггера poll, CI-leg `ort-build` (этот же файл).
#[test]
fn shelf_invariant_layout_gate_is_size_not_existence() {
    let dir = std::env::temp_dir().join(format!("fasad316-lay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmp создаётся");
    assert!(
        !guard_daemon::weights::layout_complete(&dir),
        "пусто = не готово"
    );
    // 4096-фейки (существование без размера) = НЕ проходят.
    for rel in guard_daemon::weights::layout() {
        let p = guard_daemon::weights::layout_path(&dir, rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&p, vec![0u8; 4096]).expect("фейк пишется");
    }
    assert!(
        !guard_daemon::weights::layout_complete(&dir),
        "size-гейт манифеста сломан: 4096-фейки прошлись (полка живого flip = \
         CI-fetch, fake-weights = unit-контра `mount_poll_decision`)"
    );
    // Точные размеры = готово.
    let entries = guard_daemon::weights::embedded_entries();
    for rel in guard_daemon::weights::layout() {
        let role = guard_daemon::weights::role_for(rel).expect("роль раскладки");
        let e = guard_daemon::weights::entry_by_role(&entries, role).expect("роль в манифесте");
        let p = guard_daemon::weights::layout_path(&dir, rel);
        let n = usize::try_from(e.size_bytes).expect("размер манифеста влезает в usize");
        std::fs::write(&p, vec![0u8; n]).expect("файл точного размера");
    }
    assert!(
        guard_daemon::weights::layout_complete(&dir),
        "5/5 точных размеров = готово (тот же предикат, что крутит poll)"
    );
    std::fs::remove_dir_all(&dir).ok();
}
