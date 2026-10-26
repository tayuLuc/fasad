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
//!    (queue-recv = бюджет, воркер отвечает после чанка → маржа = один чанк,
//!    влезавший в бюджет). «24 × 4.5 с = 100+ с при бюджете 3 с» (первичка
//!    #109) на этом зубе красный по построению.
//! 2. **Fail-closed (#185-инвариант):** исход = 502-класс `Cascade(Timeout)`,
//!    причина называет стадию `decide` и бюджет; маска НЕ выдана; PII из
//!    тела запроса в причину не просочилась.
//! 3. **Контроль живости контура** (реестр ложно-зелёных, «function covered
//!    ≠ called on the request path»): на ТОМ ЖЕ конфиге короткий серый вход
//!    обязан завершаться `Cascade2::Ok` = Decide на этом раннере живой.
//!    Без контроля зелёный «таймаут» мог бы значить «Decide вообще не
//!    работает», а не «бюджет сработал».
//!
//! Порядок = БЮДЖЕТ ДО `startup`: бюджет запроса печатается в `Job` из
//! `OnnxMount::load` (`cfg.timeout_ms`), mounted-контур гоняется через
//! `analyze`/глобальный слот — `startup` с малым бюджетом ставится ОДИН раз
//! и им же обслуживаются обе проверки (дешёвая даёт Ok, дорогая — Timeout).
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

/// Бюджет смонтированного монтаже этой полки, мс. Меньше ОДНОГО живого
/// Decide-чанка (4.5–8.6 с, §I1 п.3) и больше lockR-фазы 5 КБ (~1.5 с при
/// 329–373 мс/чанк, §I1 п.3) + короткого прогона: значит короткий серый
/// вход успевает дойти до Decide и вернуть Ok, а длинный — упёрся в хук
/// между чанками Decide.
const BUDGET_MS: u64 = 4_500;

/// Серый якорь (тот же, что `translit_live`: формальный кандидат `person_name`
/// по эвристике #238 → спан серой зоны → Decide зовётся).
const GREY: &str = "Контрагент: Ushakov Petr Sergeevich, ИНН 7707083893\n";

/// Чанки Decide ≈ 456 токенов state ≈ 1.6–2.1 КБ текста (промер §W2.6):
/// ~5 КБ = НЕСКОЛЬКО чанков Decide.
const PAD_SENTENCE: &str = "Отдел кадров уведомляет о плановой сверке документов. ";
const TARGET_BYTES: usize = 5_000;

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

/// Текст: серый якорь + детерминированная pad-набивка до `TARGET_BYTES`.
fn long_grey_text() -> String {
    let mut text = String::from(GREY);
    while text.len() < TARGET_BYTES {
        text.push_str(PAD_SENTENCE);
    }
    text
}

fn req(text: &str) -> AnalyzeRequest {
    AnalyzeRequest {
        text: Zeroizing::new(text.to_owned()),
        entities: None,
        score_threshold: None,
    }
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
    let cfg = cfg_with(&dir, BUDGET_MS);
    if let Err(e) = startup(&cfg) {
        panic!("веса есть ({dir:?}), а старт каскадов отказал: {e}");
    }

    // (3) КОНТРОЛЬ ЖИВОСТИ: короткий серый вход на ТОМ ЖЕ бюджете проходит
    // весь конвейер с каскадом 2 = Decide на этом раннере зовётся и живой.
    let t = Instant::now();
    let short = analyze(&req(GREY), &schema, &cfg, Policy::Mask);
    let short_ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    match &short {
        Ok(a) => println!("CHUNK_BUDGET|short|ok|{short_ms}|cascade2|{}", a.cascade2),
        Err(e) => println!("CHUNK_BUDGET|short|err|{short_ms}|{e}"),
    }
    let a = short.expect("контроль: короткий серый вход обязан проходить при бюджете полки");
    assert_eq!(
        a.cascade2,
        Cascade2::Ok.as_header(),
        "контроль живости: каскад 2 обязан зваться (иначе бюджет-зуб зелёный вручил бы \
         контрольная точка мёртвого контура = реестр ложно-зелёных)"
    );

    // (1)+(2) БЮДЖЕТНЫЙ ЗУБ: длинный вход при бюджете < одного Decide-чанка.
    let text = long_grey_text();
    let t = Instant::now();
    let r = analyze(&req(&text), &schema, &cfg, Policy::Mask);
    let ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    match r {
        Err(AnalyzeError::Cascade(CascadeFailure::Timeout {
            budget_ms: b,
            stage,
        })) => {
            println!("CHUNK_BUDGET|decide|timeout|{ms}|budget|{b}|stage|{stage}");
            assert_eq!(b, BUDGET_MS, "отказ обязан назвать бюджет вызывающего");
            assert_eq!(stage, "decide", "стадия отказа = каскад 2, не lockR");
            // Deadline-контра (не вечный прогон): outer recv_timeout = бюджет
            // срабатывает НЕ ПОЗЖЕ бюджета; inner-ответ (воркер отвечает
            // сразу после чанка, влезавшего в бюджет) даёт верхнюю границу
            // ~2×бюджет. 20 % на планирование/нагрузку раннера.
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
                reason.contains("decide"),
                "стадия в причине отказа: {reason}"
            );
            assert!(
                !text.contains("Ushakov") || !reason.contains("Ushakov"),
                "причина отказа протекла текстом запроса: {reason}"
            );
            println!("CHUNK_BUDGET|text_bytes|{}|short_ms|{short_ms}", text.len());
        }
        Ok(a) => panic!(
            "бюджет {BUDGET_MS} мс выпустил 200 с замаскированным ответом \
             (spans={}, latency={ms}) = #109 НЕ закрыт: досчитали молча",
            a.spans.len()
        ),
        Err(e) => panic!("ожидался Timeout{{decide}}, получен: {e}"),
    }
}

/// Unit-контра полки (без весов, живёт в CI любой ноги этой же файловой
/// полки): геометрия хука на табличной сетке = та же, что в
/// `arbitrate::tests::budget_…`; здесь повторяется как контракт ПОЛКИ
/// (файл = стенд целиком, паттерн `translit_live::shelf_invariant_…`).
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
