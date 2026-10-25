//! Парность продукта харнесу на реальном весе (`ort-inference`, локально).
//!
//! Что именно равняется. Харнес `recall_golden` (мера 92.46 % из отчёта #80)
//! считает каскад 1 так: `LockrExtractor` → гейт `RoutingCfg::single(τ)` →
//! маппинг тегов по схеме → объединение с каскадом 0. Продукт обязан выдавать
//! **тот же набор спанов на том же тексте**, иначе метрика recall описывает не
//! продукт, а склейку скриптов (инвариант 7b «меряем = гоняем»).
//!
//! Оракул — не second implementation на Python, а те же ноги конвейера,
//! вызванные напрямую: `cascade0::scan` + `engine().model_spans` +
//! `cascades::merge_disjoint` + `RoutingCfg`. Сравнивается с
//! [`pipeline::analyze`] — то есть с путём, у которого сверху добавлены
//! HTTP-контракт, фильтр классов и контракт скора. Расхождение = баг монтажа
//! (потерянный спан, съехавший порог, кривое слияние), а не баг модели.
//!
//! Второй блок — дифф «до/после» на тех же строках: он и есть артефакт отчёта
//! (#14A: продукт должен начать видеть то, что харнес мерил без него).
//!
//! # Пропуск без весов
//!
//! Тест требует весов (`~/.cache/fasad-models`, `scripts/fetch-models.sh`) и
//! `libonnxruntime` в `DYLD_LIBRARY_PATH`/`ORT_LIB_PATH`. В CI весов нет:
//! файл под `#![cfg(feature = "ort-inference")]`, и в CI он не собирается.
//! Локально при отсутствии весов тест печатает `SKIP|<причина>` и выходит
//! (под `FASAD_REQUIRE_MODELS=1` тот же путь — падение, см. [`require_models`])
//! зелёным: молчаливый пропуск без строки SKIP был бы ложно-зелёной проверкой.

#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
#![allow(clippy::type_complexity)] // ключи сравнения спанов — кортежи, и они читамее в тесте

use std::path::{Path, PathBuf};

use guard_daemon::cascade0;
use guard_daemon::cascades::{Plan, engine, merge_disjoint, startup};
use guard_daemon::config::Config;
use guard_daemon::pipeline::{AnalyzeRequest, Policy, analyze, analyze_with};
use guard_daemon::schema::Schema;
use guard_onnx::routing::{RoutingCfg, ScoredSpan, route_spans};
use guard_types::NewtypeId as _;
use zeroize::Zeroizing;

const GOLDEN: &str = include_str!("../../../data/golden/golden-v1.jsonl");

/// τ сетки харнеса, на которой смонтирован продукт (0.20 = `DEFAULT_TAU_LOW`).
const TAU: f64 = guard_onnx::routing::DEFAULT_TAU_LOW;

/// Классы, которые каскад 0 не находит никогда: ради них и затевался #14A.
/// #222: email закрыт форматным валидатором addr-spec, phone/passport —
/// структурным вето #200-A2: в model-only контуре промера остались чистые
/// модельные классы (реестр = `validators` схемы, зуб
/// `model_only_registry_matches_schema`).
const MODEL_ONLY: [&str; 2] = ["person_name", "address"];

/// Флаг «веса обязательны»: на гейт-машине пропуск = падение, а не зелёный.
///
/// Причина (ревью #87): без флага `SKIP|…` печатается в stderr, тест
/// возвращается `Ok(())` и счётчик «N passed» не различает прогон и пропуск —
/// ровно тот класс ложно-зелёного, когда гейт выглядит пройденным на машине,
/// где он ничего не мерил.
fn require_models(what: &str) {
    assert!(
        std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
        "FASAD_REQUIRE_MODELS установлен, а весов нет ({what}) — пропуск запрещён"
    );
}

fn model_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FASAD_MODEL_DIR") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
        return None;
    }
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".cache/fasad-models");
    cache.is_dir().then_some(cache)
}

fn cfg_with(dir: &Path) -> Config {
    let dir_s = dir.display().to_string();
    Config::from_lookup(|k| match k {
        "FASAD_MODEL_DIR" => Some(dir_s.clone()),
        // Рюлинг 21.10: ноут оператора не нагружать — 2 потока инференса.
        "FASAD_THREADS" => Some("2".to_owned()),
        // Первый прогон после загрузки греет кэш аллокатора; 30 с на запрос —
        // промеренный бюджет локального прогона, не продуктовый (дефолт 3 с).
        "FASAD_TIMEOUT_MS" => Some("30000".to_owned()),
        _ => None,
    })
    .expect("конфиг с весами sane")
}

#[derive(Debug)]
struct Row {
    id: String,
    text: String,
    gold: Vec<(String, usize, usize)>,
}

fn rows() -> Vec<Row> {
    GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).expect("golden-строка JSON");
            let gold = v["spans"]
                .as_array()
                .expect("spans массив")
                .iter()
                .map(|s| {
                    (
                        s["category"].as_str().expect("category").to_owned(),
                        usize::try_from(s["start_byte"].as_u64().expect("start_byte"))
                            .expect("офсет golden-строки влезает в usize"),
                        usize::try_from(s["end_byte"].as_u64().expect("end_byte"))
                            .expect("офсет golden-строки влезает в usize"),
                    )
                })
                .collect();
            Row {
                id: v["id"].as_str().expect("id").to_owned(),
                text: v["text"].as_str().expect("text").to_owned(),
                gold,
            }
        })
        .collect()
}

/// Реестр MODEL_ONLY = первичка схемы: класс без детерминированного
/// валидатора = ровно он (зуб не даёт реестру отстать от схемы: email
/// закрыт #222, phone/passport — #200-A2; iban = чексумма, НЕ model-only).
#[test]
fn model_only_registry_matches_schema() {
    let schema = guard_daemon::schema::Schema::embedded().expect("канон валиден");
    for c in &schema.classes {
        let model_only = MODEL_ONLY.contains(&c.id.as_str());
        assert_eq!(
            c.validators.is_empty() && c.model,
            model_only,
            "класс {} (validators={:?}, model={}) разошёлся с реестром MODEL_ONLY",
            c.id,
            c.validators,
            c.model
        );
    }
}

/// Три строки промера: с золотым спаном model-only класса и короткие, чтобы не
/// упираться в окно 256 токенов (оно — issue #14B, не этот тест).
fn pick_rows(all: &[Row]) -> Vec<&Row> {
    let mut out: Vec<&Row> = Vec::new();
    for r in all {
        if out.len() == 3 {
            break;
        }
        if r.text.chars().count() > 200 {
            continue;
        }
        if !r
            .gold
            .iter()
            .any(|(c, _, _)| MODEL_ONLY.contains(&c.as_str()))
        {
            continue;
        }
        out.push(r);
    }
    out
}

/// Класс+координаты спана: то, чем меряется парность (скор в сравнении не
/// участвует осознанно: он сравненный f64, а набор спанов — контракт).
type Key = (String, usize, usize);

fn keys_from_analysis(a: &guard_daemon::pipeline::Analysis) -> Vec<Key> {
    let mut v: Vec<Key> = a
        .spans
        .iter()
        .map(|s| (s.entity_type.clone(), s.byte_start, s.byte_end))
        .collect();
    v.sort();
    v
}

/// Кандидаты харнес-композиции на одном тексте: каскад 0 (все хиты) + каскад 1
/// (все спаны `p1 ≥ τ`, гейт `RoutingCfg`), без снятия пересечений.
///
/// Это ровно то, из чего `tools/metrics/union_recall.py` считает «strict»-меру
/// каскада 0 ∨ 1: харнес ничего не сливает, он зачитывает кредит золотому
/// спану при любом пересечении.
fn harness_list(text: &str, schema: &Schema, cfg: &Config) -> Vec<(Key, bool, f64)> {
    let plan = Plan::from_config(cfg, TAU);
    let routing = RoutingCfg::single(TAU);
    let mut out: Vec<(Key, bool, f64)> = cascade0::scan(text, schema)
        .into_iter()
        .map(|h| {
            (
                (h.class.as_str().to_owned(), h.span.start, h.span.end),
                true,
                h.score(),
            )
        })
        .collect();
    let mounted = engine().expect("тест стартует движок сам");
    for m in mounted
        .model_spans(text, schema, &plan)
        .expect("каскад 1 на короткой golden-строке обязан отработать")
        .spans
    {
        // Гейт каскада 1 меряется тем же lib-`RoutingCfg`, что и в продукте;
        // в харнесе он стоит в цикле `if !route(sp.score).extracted() { continue }`.
        if routing.route(m.score).extracted() {
            out.push(((m.class, m.byte_start, m.byte_end), false, m.score));
        }
    }
    out
}

/// Оракул: та же композиция, приведённая к непересекающемуся покрытию
/// (слияние каскада 3 + пороговый гейт) — то, что обязан выдать продукт.
fn oracle(text: &str, schema: &Schema, cfg: &Config) -> Vec<Key> {
    let cand = harness_list(text, schema, cfg);
    let tuples: Vec<(usize, usize, f64, bool)> = cand
        .iter()
        .map(|((_, s, e), det, score)| (*s, *e, *score, *det))
        .collect();
    let routing = RoutingCfg::single(TAU);
    let mut keys = Vec::new();
    for i in merge_disjoint(&tuples) {
        let class = cand[i].0.0.clone();
        let scored = [ScoredSpan {
            class: &class,
            score: tuples[i].2,
            validator: cand[i].1,
        }];
        let routed = route_spans(&routing, &scored);
        if routed.first().is_some_and(|r| r.route.extracted()) {
            keys.push(cand[i].0.clone());
        }
    }
    keys.sort();
    keys
}

/// Число золотых спанов класса, пересечённых данным списком (мера харнеса:
/// пересечение = зачтено, `tools/metrics/union_recall.py`).
fn gold_hits(list: &[(Key, bool, f64)], gold: &[(String, usize, usize)], class: &str) -> usize {
    gold.iter()
        .filter(|(gc, gs, ge)| {
            gc == class
                && list
                    .iter()
                    .any(|((c, s, e), _, _)| c == class && s < ge && e > gs)
        })
        .count()
}

/// Число золотых спанов класса, пересечённых списком ключей продукта.
fn gold_hits_keys(list: &[Key], gold: &[(String, usize, usize)], class: &str) -> usize {
    gold_hits(
        &list
            .iter()
            .map(|k| (k.clone(), false, 1.0))
            .collect::<Vec<_>>(),
        gold,
        class,
    )
}

fn gold_count(gold: &[(String, usize, usize)], class: &str) -> usize {
    gold.iter().filter(|(c, _, _)| c == class).count()
}

#[test]
fn product_path_matches_the_harness_composition() {
    let Some(dir) = model_dir() else {
        require_models("парность каскадов");
        eprintln!(
            "SKIP|cascade_parity|нет каталога весов (FASAD_MODEL_DIR/`~/.cache/fasad-models`)"
        );
        return;
    };
    let cfg = cfg_with(&dir);
    if let Err(e) = startup(&cfg) {
        panic!("веса есть ({dir:?}), а старт каскадов отказал: {e}");
    }
    let schema = Schema::embedded().expect("канон");
    let all = rows();
    let picked = pick_rows(&all);
    assert_eq!(
        picked.len(),
        3,
        "golden-набор обязан дать 3 подходящие строки"
    );

    let mut total_new = 0_usize;
    for row in picked {
        let req = AnalyzeRequest {
            text: Zeroizing::new(row.text.clone()),
            entities: None,
            score_threshold: None,
        };
        let cfg_plain = Config::from_lookup(|_| None).expect("дефолты sane");
        // «До»: ровно то, что продукт отвечал до #14A (каскад 0).
        let before = analyze_with(&req, &schema, &cfg_plain, Policy::AuditOnly, None)
            .expect("каскад 0 работает");
        // «После»: продуктовый путь с примонтированными каскадами 1–2.
        let after = analyze(&req, &schema, &cfg, Policy::AuditOnly).expect("каскады работают");
        assert_eq!(
            after.stage, "cascade-0+models",
            "строка {}: стадия обязана отражать монтаж",
            row.id
        );
        let harness = harness_list(&row.text, &schema, &cfg);
        let oracle_keys = oracle(&row.text, &schema, &cfg);
        let a = keys_from_analysis(&after);
        let b = keys_from_analysis(&before);
        // Парность по мере харнеса: product зачитывает золоту не хуже, чем
        // строгая union-мера харнеса на том же тексте. Продукт обязан уметь
        // всё, что мерил харнес, — и ни классом меньше.
        let mut classes: Vec<&str> = row.gold.iter().map(|(c, _, _)| c.as_str()).collect();
        classes.sort_unstable();
        classes.dedup();
        for cls in classes {
            let n = gold_count(&row.gold, cls);
            let h = gold_hits(&harness, &row.gold, cls);
            let pr = gold_hits_keys(&a, &row.gold, cls);
            println!("RECALL|{}|{cls}|gold|{n}|harness|{h}|product|{pr}", row.id);
            assert!(
                pr >= h,
                "строка {row_id} класс {cls}: продукт зачитал {pr} золотых спанов, \
                 харнес на тех же ногах — {h}: монтаж проецирует union в покрытие \
                 и теряет кредит",
                row_id = row.id
            );
        }

        // Артефакт отчёта: дифф до/после по строке.
        let added: Vec<&Key> = a.iter().filter(|k| !b.contains(k)).collect();
        let lost: Vec<&Key> = b.iter().filter(|k| !a.contains(k)).collect();
        total_new += added.len();
        println!(
            "PARITY|row={}|before={:?}|after={:?}|added={added:?}|lost={lost:?}|oracle_eq={}",
            row.id,
            b,
            a,
            a == oracle_keys,
        );
        for (cls, s, e) in &a {
            let gold = row
                .gold
                .iter()
                .any(|(gc, gs, ge)| gc == cls && s < ge && e > gs);
            println!(
                "SPAN|{}|{}|{cls}|{s}..{e}",
                row.id,
                if gold { "gold" } else { "fp" }
            );
        }
        assert_eq!(
            a, oracle_keys,
            "строка {}: продукт разошёлся с харнес-композицией (7b)",
            row.id
        );
        assert!(
            lost.is_empty(),
            "строка {}: монтаж отнял у продукта спан каскада 0 {lost:?}",
            row.id
        );
        assert!(
            !added.is_empty(),
            "строка {}: каскады 1–2 не добавили ничего там, где золото есть — \
             значит монтаж не видит того, что мерил харнес",
            row.id
        );
    }
    assert!(
        total_new > 0,
        "на трёх строках каскады 1–2 не добавили ни одного спана"
    );
    println!("PARITY|verdict|product_eq_harness|rows|3|new_spans|{total_new}");
}

/// Полный промер покрытия продукта на golden (артефакт для отчёта, не гейт).
///
/// Зачем он отдельным `#[ignore]`: 185 строк × инференс = ~12 минут на
/// `FASAD_THREADS=2` (рюлинг 21.10), и в CI он не помещается (весов там нет).
/// Он отвечает на вопрос, на который §5.1 `docs/golden-report.md` ответить не
/// может: харнес мерит стадии по отдельности (`c0`/`lockr`/`decide`/`union`/
/// `strict`), а здесь меряется **выход продукта** — тот набор спанов, который
/// уйдёт в маскирование, и меряется двумя способами:
///
/// 1. `overlap` — пересечение с золотом (мера харнеса `union`),
/// 2. `exact` — байт-в-байт по координатам (гейт-мера рюлинга #77).
///
/// Разрыв между ними и есть #41: `lockR` даёт координаты, и если его граница
/// не совпала с золотом байт-в-байт, продукт маскирует не то окно, что размечено.
#[test]
#[ignore = "полный golden-промер (~12 мин, нужны веса): cargo test -p guard-daemon --features ort-inference -- --ignored"]
fn product_coverage_on_the_whole_golden() {
    let Some(dir) = model_dir() else {
        require_models("промер покрытия");
        eprintln!(
            "SKIP|cascade_parity|нет каталога весов (FASAD_MODEL_DIR/`~/.cache/fasad-models`)"
        );
        return;
    };
    let cfg = cfg_with(&dir);
    startup(&cfg).expect("веса есть — старт каскадов обязан пройти");
    let schema = Schema::embedded().expect("канон");
    let all = rows();
    let picked: Vec<&Row> = all
        .iter()
        .filter(|r| r.text.chars().count() <= 200)
        .collect();
    println!("COVER|rows|{}|of|{}", picked.len(), all.len());

    let mut gold: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_overlap: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut by_exact: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut fp = 0_usize;
    let mut spans_out = 0_usize;

    for (i, row) in picked.iter().enumerate() {
        let req = AnalyzeRequest {
            text: Zeroizing::new(row.text.clone()),
            entities: None,
            score_threshold: None,
        };
        let after = analyze(&req, &schema, &cfg, Policy::AuditOnly)
            .unwrap_or_else(|e| panic!("строка {} ({i}/{}): продукт отказал: {e}", row.id, i + 1));
        let got = keys_from_analysis(&after);
        spans_out += got.len();
        for (cls, gs, ge) in &row.gold {
            *gold.entry(cls.clone()).or_default() += 1;
            if got.iter().any(|(c, s, e)| c == cls && s < ge && e > gs) {
                *by_overlap.entry(cls.clone()).or_default() += 1;
            }
            if got.iter().any(|(c, s, e)| c == cls && s == gs && e == ge) {
                *by_exact.entry(cls.clone()).or_default() += 1;
            }
        }
        fp += got
            .iter()
            .filter(|(c, s, e)| {
                !row.gold
                    .iter()
                    .any(|(gc, gs, ge)| gc == c && s < ge && e > gs)
            })
            .count();
        if (i + 1) % 25 == 0 {
            println!("COVER|progress|{}", i + 1);
        }
    }
    let total_gold: usize = gold.values().sum();
    let total_ov: usize = by_overlap.values().sum();
    let total_ex: usize = by_exact.values().sum();
    for cls in gold.keys() {
        println!(
            "COVER|class|{cls}|gold|{}|overlap|{}|exact|{}",
            gold[cls],
            by_overlap.get(cls).copied().unwrap_or(0),
            by_exact.get(cls).copied().unwrap_or(0),
        );
    }
    println!(
        "COVER|total|gold|{total_gold}|overlap|{total_ov}|exact|{total_ex}|spans_out|{spans_out}|fp|{fp}"
    );
    assert!(
        total_ov > 0,
        "продукт не накрыл ни одного золотого спана на полном golden"
    );
}
