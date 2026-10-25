//! #238-полка: транслит-ФИО = живой контур на НАСТОЯЩЕЙ модели.
//!
//! Контур: unit-зубы #239 (7 в pipeline) закрыли арифметику blend/дроп на
//!FakeMount-овской p2. Живая p2 (row-level вероятность `person_name` у
//! Decide-арбитра) = только веса + ort = только CI (`ort-build` job: линковка
//! доказана, += шаг весов `scripts/fetch-models.sh` = рецепт release.yml
//! `dist`-mac). Файл под `#![cfg(feature = "ort-inference")]` = собирается
//! только там, где линкуется (контра #204).
//!
//! Дисциплина чисел (lesson #232 «pin = measurement»):
//! - ЗУБ = СРАВНЕНИЕ живой p2: транслит-ФИО «Ushakov Petr Sergeevich» обязан
//!   получать у арбитра person_name-вероятность СТРОГО выше, чем компани-бейт
//!   «Gazprom Neft» (тот же формат Capitalized Capitalized, реестр-контекст,
//!   не-ФИО). Абсолютные p2 = артефакт раннера, печатаются строкой
//!   `TRANSLIT_LIVE|…` (первый промер = число в PR-комменте, не пин).
//! - ЗУБ = КОНТРА #238 (инвариант стабильности `α·gray_lo < τ_low` =
//!   unit-контур, живёт без весов — здесь он повторён для полноты: стабильная
//!   связка = кандидат серой зоны доживает до маскировки, S = blend(0.5·0.22 +
//!   0.5·p2) ≥ 0.20 при p2 > 0.18; p2 ниже = candidate отфильтрован арбитром
//!   = ровно контракт «эвристика не вето»).
//! - Пропуск без весов = `SKIP|…`-строка + `FASAD_REQUIRE_MODELS` = падение
//!   (#87/#237-паттерн: молчаливого зелёного про пропуска нет; CI-шаг ставит
//!   REQUIRE, провен монтирования = красный при кеше без весов).
#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа

use std::path::PathBuf;

use guard_daemon::cascades::{Plan, startup};
use guard_daemon::config::{Config, Thresholds};
use guard_daemon::pipeline::{AnalyzeRequest, Policy, analyze};
use guard_daemon::schema::Schema;
use guard_detectors::translit::name_runs;
use zeroize::Zeroizing;

/// Векторы полки (тот же реестр-формат, что golden g0271 и юнит-таблица
/// `translit_name_runs_table`; формально кандидатны оба = эвристика
///Capitalized-окна не различает FIO/компани, различает арбитр).
const USHAKOV: &str = "Контрагент: Ushakov Petr Sergeevich, ИНН 7707083893";
const GAZPROM: &str = "Контрагент: Gazprom Neft, ИНН 773610727370";

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
        // CI-бюджет = 2 потока (тот же рычаг, что ruling 21.10 локально;
        // раннер платит своими ядрами, но таймаут-бюджет job = 30 мин).
        "FASAD_THREADS" => Some("2".to_owned()),
        "FASAD_TIMEOUT_MS" => Some("30000".to_owned()),
        _ => None,
    })
    .expect("конфиг с весами sane")
}

/// Контра #238 = unit-уровень (без весов): стабильность связки порогов.
/// Живёт в этом файле как «полка целиком»: файл собирается только под
/// ort-контуром, где и решает задачу.
#[test]
fn shelf_invariant_translit_stable_on_defaults() {
    let t = Thresholds::default_working();
    assert!(
        t.translit_stable(),
        "связка дефолтов стабильна (0.5·0.22 < 0.20)"
    );
    // blend-арифметика полки (юниты #239 дублируют в pipeline-контуре):
    // p1 = gray_lo, S = α·p1+(1−α)·p2 ≥ τ_low ⇔ p2 ≥ 0.18 (ровно граница
    // фильтра арбитра = кандидат не вето).
    let plan = Plan::from_config(&Config::from_lookup(|_| None).expect("default"), t.tau_low);
    let s_low = guard_daemon::cascades::blend(plan.gray_lo, 0.18, plan.alpha);
    let s_hi = guard_daemon::cascades::blend(plan.gray_lo, 0.9, plan.alpha);
    assert!(s_low + 1e-12 >= t.tau_low && s_hi > s_low);
}

#[test]
fn translit_live_ushakov_beats_gazprom() {
    let Some(dir) = model_dir() else {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а весов нет — транслит-полка не смонтирована"
        );
        eprintln!("SKIP|translit_live|нет каталога весов (FASAD_MODEL_DIR/~/.cache/fasad-models)");
        return;
    };
    let cfg = cfg_with(&dir);
    if let Err(e) = startup(&cfg) {
        panic!("веса есть ({dir:?}), а старт каскадов отказал: {e}");
    }
    let schema = Schema::embedded().expect("канон");
    // Формальная кандидатность обеих строк (эвристика = внешний контур):
    let u = name_runs(USHAKOV);
    let g = name_runs(GAZPROM);
    assert!(
        !u.is_empty() && !g.is_empty(),
        "обе строки = кандидаты формы"
    );

    let mut p2 = Vec::new();
    let mut scored = Vec::new();
    for text in [USHAKOV, GAZPROM] {
        let req = AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: None,
            score_threshold: None,
        };
        let a = analyze(&req, &schema, &cfg, Policy::Mask).expect("ок");
        let person = a
            .spans
            .iter()
            .find(|s| s.class == "person_name")
            .map(|s| s.score);
        scored.push((text, person));
        p2.push(person);
    }
    // p2-артефакт раннера = печатается (первый промер = число PR-коммента).
    println!("TRANSLIT_LIVE|ushakov_person_score|{:?}", scored[0].1);
    println!("TRANSLIT_LIVE|gazprom_person_score|{:?}", scored[1].1);

    // ЗУБ-сравнение (инвариант, не хрупкий пин): живой человек-формат
    // обязан получать у контура СТРОГО больше, чем компани-бейт. Сравниваем
    // итоговые person_name-скоры ответа: у ushakov = blend с живой p2
    // (0.5·0.22 + 0.5·p2), у gazprom = nil (дроп фильтром) или ниже.
    let (u_s, g_s) = (scored[0].1, scored[1].1);
    match (u_s, g_s) {
        (Some(u), g) => {
            assert!(u >= cfg.thresholds.tau_low - 1e-12, "ushakov дожил: {u}");
            assert!(
                g.is_none_or(|g| u > g + 1e-9),
                "сравнение: ushakov {u} > gazprom {g:?}"
            );
        }
        (None, _) => panic!(
            "полка мертва: живой контур не оставил person_name-кандидата на \
             «Ushakov Petr Sergeevich» при стабильной связке порогов: {scored:?}"
        ),
    }
}
