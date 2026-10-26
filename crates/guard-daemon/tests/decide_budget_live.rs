//! #109-полка: пер-чанковый бюджет Decide = ЖИВОЙ контур на НАСТОЯЩИХ весах.
//!
//! Unit-стенд (`arbitrate::tests::budget_…` в guard-onnx, `decide_budget_…`
//! в cascades) закрыл арифметику хука на фейках. Цена одного Decide-чанка
//! 4.5–8.6 с (audit §I1 п.3, threads=2) = факт ЖИВОГО графа: фальсифицировать
//! «хук не сработал на смонтированном пути» может только промер на весах =
//! CI `ort-build` (#255-прецедент: шаг fetch-models + `FASAD_REQUIRE_MODELS` =
//! провен монтирования, молчаливого SKIP нет).
//!
//! Дисциплина чисел (lesson #232/#238): абсолютные латентности = АРТЕФАКТ
//! раннера, печатаются строками `CHUNK_BUDGET|…` (первый промер = число в
//! PR-комменте, не пин). ЗУБ = инварианты, не хрупкие пины:
//!
//! 1. **Deadline-контра:** отказ от бюджета приходит ЗА бюджет с маржой
//!    (queue-recv = бюджет, воркер отвечает после чанка, влезавшего в бюджет
//!    → верхняя граница ~2×бюджет). «24 × 4.5 с = 100+ с при бюджете 3 с»
//!    (первичка #109) на этом зубе красный по построению.
//! 2. **Fail-closed (#185-инвариант):** исход = `Cascade(Timeout{decide})`
//!    (502-класс), причина называет стадию и бюджет; PII запроса в причине нет.
//! 3. **Контроль живости КОНТУРА:** короткий вход проходит с `cascade2: ok`
//!    = Decide на этом раннере живой.
//! 4. **Контроль живости ВХОДА (lesson прогона 40251111755):** длинный вход
//!    с БОЛЬШИМ бюджетом обязан дать `cascade2: ok` = на нём Decide реально
//!    ЗВОНЯТСЯ. Первый промер полки поймал ровно это: Ushakov-фикстура #238
//!    дала 200 за 280–3231 мс при бюджете 4500 = short-circuit (серой зоны у
//!    живого lockR на транслите НЕТ, Decide не звонился): «прошёл бюджет»
//!    без этой проверки = ложно-зелёный тест мёртвого контура (реестр
//!    ложно-зелёных, «function covered ≠ called on the request path»).
//!    Фикстура = golden-строки с адресом (read-only, `data/golden/` НЕ
//!    правится: #109 = runtime-контур, метрики не трогаем): адресные спаны
//!    живого lockR ниже 0.8 (промер §I1: минимум НЕ адресного класса =
//!    0.8022), `address` = контекстно-зависимый класс схемы → серая зона
//!    `[0.22; 0.80)` = законный зов Decide; повтор строк = несколько
//!    Decide-чанков (окно state 456 токенов ≈ 1.6–2.1 КБ текста).
//!
//! Порядок = БЮДЖЕТ ДО `startup`: бюджет печатается в `Job` из
//! `OnnxMount::load` (`cfg.timeout_ms`) ⇒ на процесс ОДИН монтаж с ОДНИМ
//! бюджетом (второй `startup` красен по ort-контракту «only one environment
//! per process», промер run 40253494121): короткий контроль и бюджетный зуб
//! живут на одном `BUDGET_MS`.
//! Без весов = `SKIP|…`-строка + падение при `FASAD_REQUIRE_MODELS`
//! (#87/#237-паттерн).

#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа

use std::path::PathBuf;
use std::time::Instant;

use guard_daemon::cascades::{Cascade2, CascadeFailure, startup};
use guard_daemon::config::Config;
use guard_daemon::pipeline::{AnalyzeError, AnalyzeRequest, Policy, analyze};
use guard_daemon::schema::Schema;
use zeroize::Zeroizing;

/// Бюджет полки (единственный монтаж на процесс), мс. Меньше ОДНОГО живого
/// Decide-чанка (4.5–8.6 с, §I1 п.3) и больше lockR-фазы + одного короткого
/// прогона: короткий серый вход успевает (витрина 285–427 мс + Decide-чанк
/// влезает в бюджет первого чанка — budget-хук проверяет ПЕРЕД чанком, при
/// spent=0), длинный — упёрся в хук на втором чанке Decide.
///
/// ОДИН монтаж = контракт ort: `ort::init: only one environment is allowed
/// per process` (промер run 40253494121: второй `startup` красен = Load) —
/// бюджеты на один процесс не меняются, только константа.
const BUDGET_MS: u64 = 4_500;

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

/// Конфиг полки: веса + threads=2 (#255-прецедент) + БЮДЖЕТ = параметр.
fn cfg_with(dir: &std::path::Path, timeout_ms: u64) -> Config {
    let dir_s = dir.display().to_string();
    let budget = timeout_ms.to_string();
    Config::from_lookup(|k| match k {
        "FASAD_MODEL_DIR" => Some(dir_s.clone()),
        "FASAD_THREADS" => Some("2".to_owned()),
        "FASAD_TIMEOUT_MS" => Some(budget.clone()),
        _ => None,
    })
    .expect("конфиг с весами sane")
}

fn req(text: &str) -> AnalyzeRequest {
    AnalyzeRequest {
        text: Zeroizing::new(text.to_owned()),
        entities: None,
        score_threshold: None,
    }
}

/// Золотые строки С АДРЕСОМ БЕЗ `№` (тексты read-only). `№` = [UNK] в
/// словаре Spiber (первичка #88, инвентарь 4b-3C) ⇒ на входе с `№` Decide
/// деградирует в `Skipped` (splice-контракт) и до чанкового бюджета не
/// доходит — lesson второго промера (run 40252828912: `skipped` на
/// коротком входе = контроль живости красный, и это правильная краснота:
/// фикстура обязана ЗВАТЬ арбитр, а не деградировать его).
fn address_rows() -> Vec<String> {
    GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| l.contains("\"address\"") && !l.contains('№'))
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["text"].as_str().map(str::to_owned))
        })
        .collect()
}

/// Фикстура = адресные golden-строки, повторённые до `min_bytes`.
fn grey_fixture(min_bytes: usize) -> String {
    let rows = address_rows();
    assert!(!rows.is_empty(), "golden с адресом обязана быть");
    let mut text = String::new();
    let mut i = 0usize;
    while text.len() < min_bytes {
        text.push_str(&rows[i % rows.len()]);
        text.push('\n');
        i += 1;
    }
    text
}

fn mount(dir: &std::path::Path, budget_ms: u64) -> Config {
    let cfg = cfg_with(dir, budget_ms);
    if let Err(e) = startup(&cfg) {
        panic!("startup с бюджетом {budget_ms} отказал: {e}");
    }
    cfg
}

#[test]
fn decide_budget_stops_before_the_next_chunk() {
    let Some(dir) = model_dir() else {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а весов нет — #109-полка не смонтирована"
        );
        eprintln!(
            "SKIP|decide_budget_live|нет каталога весов (FASAD_MODEL_DIR/~/.cache/fasad-models)"
        );
        return;
    };
    let schema = Schema::embedded().expect("канон");
    let cfg = mount(&dir, BUDGET_MS);

    // (3) КОНТРОЛЬ ЖИВОСТИ КОНТУРА: короткий серый вход на бюджете полки =
    // Ok + cascade2 ok. Короткий = один чанк каждого каскада: lockR ~0.3 с +
    // Decide ~4.5–8.6 с укладывается в 4500 на быстрых ядрах раннера (первый
    // чанк стартует при spent=0 всегда; проверка — перед ВТОРЫМ). `skipped`
    // красен (lesson 40253494121: `№` в фикстуре деградировал арбитра ДО
    // бюджета), short-circuit красен (lesson 40251111755: транслит-фикстура
    // не звала Decide).
    let text_short = grey_fixture(1);
    let t = Instant::now();
    let short = analyze(&req(&text_short), &schema, &cfg, Policy::Mask);
    let short_ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    match &short {
        Ok(a) => println!("CHUNK_BUDGET|short|ok|{short_ms}|cascade2|{}", a.cascade2),
        Err(e) => println!("CHUNK_BUDGET|short|err|{short_ms}|{e}"),
    }
    let a = short.expect("контроль: короткий серый вход обязан проходить при бюджете полки");
    assert_eq!(
        a.cascade2,
        Cascade2::Ok.as_header(),
        "Decide на этом раннере не звонился (short-circuit или деградация \
         контракта склейки) = бюджет-зуб проверял бы мёртвый контур"
    );

    // (1)+(2) БЮДЖЕТНЫЙ ЗУБ: длинная фикстура при том же бюджете.
    // (4) контроль живости ВХОДА = сам исход: Timeout{stage: decide}
    // ДОКАЗЫВАЕТ, что Decide на фикстуре звонился (short-circuit дал бы 200,
    // lockR-хук дал бы stage=lockR) — отдельный полный прогон не нужен, а
    // ort-контра «один Environment на процесс» (промер 40253494121) его и
    // запрещает без второго бюджета-монтажа.
    let text = grey_fixture(5_000);
    let t = Instant::now();
    let r = analyze(&req(&text), &schema, &cfg, Policy::Mask);
    let ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    match r {
        Err(AnalyzeError::Cascade(CascadeFailure::Timeout {
            budget_ms: b,
            stage,
        })) => {
            println!(
                "CHUNK_BUDGET|decide|timeout|{ms}|budget|{b}|stage|{stage}|short_ms|{short_ms}"
            );
            assert_eq!(b, BUDGET_MS, "отказ обязан назвать бюджет вызывающего");
            assert_eq!(
                stage, "decide",
                "стадия отказа = каскад 2 (lockR-хук #84 = другой зуб): {stage}"
            );
            // Deadline-контра (не вечный прогон): outer recv_timeout = бюджет
            // срабатывает НЕ ПОЗЖЕ бюджета; inner-ответ даёт верхнюю границу
            // ~2×бюджет + планирование раннера.
            assert!(
                ms <= i64::try_from(BUDGET_MS * 2 + 2_000).unwrap_or(i64::MAX),
                "отказ от бюджета за {ms} мс при бюджете {BUDGET_MS}: хук не работал \
                 — прогнали чанки досрочно (первичка #109: 24×4.5 с)"
            );
            // Инкрементальной отдачи нет: Timeout = запрос не обслуживан,
            // а не «маска по первым чанкам» (политика частичного ответа =
            // операторский выбор #110, здесь её нет намеренно).
            let reason = format!("{r:?}");
            assert!(
                !reason.contains("Ушакова") && !reason.contains("825082492964"),
                "причина отказа протекла текстом запроса: {reason}"
            );
        }
        Ok(a) => panic!(
            "бюджет {BUDGET_MS} мс выпустил 200 (spans={}, latency={ms}, cascade2={}) \
             = #109 НЕ закрыт: досчитали молча",
            a.spans.len(),
            a.cascade2
        ),
        Err(e) => panic!("ожидался Timeout{{decide}}, получен: {e}"),
    }
}

/// Unit-контра полки (без весов; живёт в CI этой же ort-ноги): геометрия
/// хука на табличной сетке = та же, что в `arbitrate::tests::budget_…`;
/// здесь повторяется как контракт ПОЛКИ (файл = стенд целиком, паттерн
/// `translit_live::shelf_invariant_…`).
#[test]
fn shelf_invariant_budget_never_starts_an_unaffordable_chunk() {
    // (чанки, цена, бюджет, стартапов) — сетка ТЗ #109.
    let cases: [(usize, u64, u64, usize); 4] = [
        (24, 4_500, 3_000, 1),
        (4, 200, 500, 3),
        (3, 200, 500, 3),
        (1, 4_500, 5_000, 1),
    ];
    for (chunks, chunk_ms, budget_ms, want) in cases {
        let mut runs = 0usize;
        for i in 0..chunks {
            let spent = u64::try_from(i).unwrap_or(u64::MAX) * chunk_ms;
            if spent > budget_ms {
                break;
            }
            runs += 1;
        }
        assert_eq!(runs, want, "{chunks}×{chunk_ms} при бюджете {budget_ms}");
    }
}
