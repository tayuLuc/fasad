//! Красный дискриминатор fail-closed на битом весе (#14A).
//!
//! Что проверяется и почему это красный дискриминатор, а не галочка:
//!
//! 1. **Битый `.onnx` = отказ старта, а не «cascade-0-only под вывеской
//!    cascade-0+models».** Утверждение `matches!(startup(&cfg), Err(Load(_)))`
//!    краснеет ровно на том коде, который reintroduce-ил бы fail-open: на
//!    `Ok(())` (промолчали и подняли каскад 0) и на `panic!` (уронили демон).
//!    Контроль «пустой каталог → та же причина» не даёт подменить отказ
//!    успехом: у отказа есть имя отсутствующего файла.
//! 2. **Причина называется по имени файла.** AGENTS «отказ обязан называть
//!    истинную причину»: «не могу стартовать» без пути гоняет оператора искать
//!    проблему вслепую.
//! 3. Тест под `#![cfg(feature = "ort-inference")]`: в CI (фичи нет) он не
//!    собирается, а отказ без фичи проверяется юнит-тестом
//!    `cascades::tests::startup_without_inference_is_refused_when_models_are_configured`,
//!    который в CI идёт всегда.
//!
//! Тесту нужен настоящий `tokenizer.json` (иначе отказ наступает раньше, чем
//! мы дошли до битого графа): он берётся из кэша весов; нет кэша — печатаем
//! `SKIP|<причина>` и выходим зелёными. Молчаливый пропуск = ложно-зелёная
//! проверка, поэтому строка SKIP обязательна.

#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_daemon::cascades::{CascadeFailure, startup};
use guard_daemon::config::Config;

/// Раскладка каталога весов (совпадает с `scripts/fetch-models.sh`).
const LOCKR_ONNX: &str = "lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx";
const LOCKR_TOK: &str = "lockR/rubert-base-pii-ner-onnx/tokenizer.json";
const DECIDE_ONNX: &str = "onnx-community/GLiNER2.5-Decide-ONNX/onnx/model_q4f16.onnx";
const DECIDE_TOK: &str = "onnx-community/GLiNER2.5-Decide-ONNX/tokenizer.json";

/// Временный каталог весов; убирается в `Drop`, чтобы тест не оставлял мусора
/// на диске оператора (на машине 95 % занято — это не гигиена, а необходимость).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("часы не в прошлом")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fasad-cascade-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("временный каталог создаётся");
        Self(path)
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let full = self.0.join(rel);
        std::fs::create_dir_all(full.parent().expect("есть родитель")).expect("каталог весов");
        std::fs::write(&full, bytes).expect("файл пишется");
    }

    fn copy_from(&self, rel: &str, src: &Path) {
        let bytes = std::fs::read(src).expect("токенизатор читается");
        self.write(rel, &bytes);
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Флаг «веса обязательны»: пропуск под ним = падение (см. модуль-док
/// `cascade_parity.rs`: молчаливый `SKIP` делает счётчик зелёных тестов
/// слепым к разнице между прогоном и пропуском).
fn require_models(what: &str) {
    assert!(
        std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
        "FASAD_REQUIRE_MODELS установлен, а весов нет ({what}) — пропуск запрещён"
    );
}

fn cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FASAD_MODEL_DIR") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".cache/fasad-models");
    cache.is_dir().then_some(cache)
}

fn cfg_with(dir: &Path) -> Config {
    let dir_s = dir.display().to_string();
    Config::from_lookup(|k| match k {
        "FASAD_MODEL_DIR" => Some(dir_s.clone()),
        "FASAD_THREADS" => Some("2".to_owned()),
        _ => None,
    })
    .expect("конфиг с model_dir sane")
}

#[test]
fn broken_onnx_refuses_startup_with_the_name_of_the_broken_file() {
    let Some(cache) = cache_dir() else {
        require_models("проверку fail-closed на битой модели");
        eprintln!("SKIP|cascade_failclosed|нет кэша весов (токенизатор неоткуда взять)");
        return;
    };
    let tmp = TempDir::new("broken");
    // Битый граф: валидный путь, невалидное содержимое. Токенизаторы живые —
    // иначе отказ наступит на них и не проверит путь загрузки сессии.
    tmp.write(LOCKR_ONNX, b"NOT-ONNX-GRAPH");
    tmp.write(DECIDE_ONNX, b"NOT-ONNX-GRAPH");
    tmp.copy_from(LOCKR_TOK, &cache.join(LOCKR_TOK));
    tmp.copy_from(DECIDE_TOK, &cache.join(DECIDE_TOK));

    let res = startup(&cfg_with(&tmp.0));
    let Err(CascadeFailure::Load(reason)) = res else {
        panic!(
            "битый вес обязан отказывать старт с причиной Load, получено {res:?} — \
             это ровно тот fail-open, который запрещён (молчаливый cascade-0-only)"
        );
    };
    assert!(
        reason.contains("model.optimized.fp16.onnx") || reason.contains("model_q4f16.onnx"),
        "в причине обязан быть путь битого файла, иначе оператор чинит вслепую: {reason}"
    );
    assert!(
        !reason.contains("СЕКРЕТ") && reason.len() < 4096,
        "причина старта — это диагностика, а не дамп: {reason}"
    );
}

#[test]
fn empty_model_dir_names_the_missing_file() {
    let tmp = TempDir::new("empty");
    let res = startup(&cfg_with(&tmp.0));
    let Err(CascadeFailure::Load(reason)) = res else {
        panic!("пустой каталог весов обязан отказывать старт: {res:?}");
    };
    assert!(
        reason.contains("lockR"),
        "первое отсутствующее звено — lockR: {reason}"
    );
}

/// Бюджет загрузки — не «сколько попросит оператор»: верхняя граница = 1.5 ×
/// константы (180 с на 120 с), а не «на порядок больше». Запас 7.5× (900 с)
/// тест превращал в тавтологию: он бы пропустил и 10-минутное ожидание, после
/// которого старт демона всё равно мёртв для оператора.
#[test]
fn startup_load_budget_is_bounded() {
    let budget = guard_daemon::cascades::startup_load_budget_ms();
    assert!(
        budget > 0 && budget <= 180_000,
        "бюджет старта {budget} мс вне разумных границ"
    );
}
