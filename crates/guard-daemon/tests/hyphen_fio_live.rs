//! #160 PR-B полка: дефисное ФИО = живой контур каскада 1 на НАСТОЯЩЕЙ модели.
//!
//! Контур: первичка issue #160 (промер 27.10) закрыла BPE-механику #222 как
//! непереносимую (Decide-Unigram: hyphen = отдельный токен, 0 UNK) и сама же
//! оговаривала: «первичка g0133-поведения модели не мерял локально — живые
//! ort-промеры = CI/полка». Промер PR-B (paired, lockR fp16 @ea7610b2,
//! threads=2, thr=0.20, 28.10): на ЭТОЙ модели row-level FN на фикстурах
//! v1.12 НЕ подтвердился — g0284/g0285 дают person_name-хит и на raw-входе
//! (скобка `Иванов-Иванов` РЕЗАНА на границе дефиса: `50..62` + `63..75`,
//! дыра на байте дефиса; пересечение-оракул row-level = тот же HIT).
//! Defer-контра v1.12 = union-гейт, канонизатор её не двигал.
//!
//! Чин, который монит THIS PR = канон дефисного склеивания на входе lockR
//! (`guard_onnx::extract::canonicalize_lockr_input`, #88-паттерн: 1Б→1Б,
//! координаты не двигаются). Что он делает на живом графе (первичка промера):
//! канон `Иванов Иванов` даёт РОВНО те же спаны, что raw `Иванов-Иванов`
//! (wordpiece-склейка `##иванов` через пробел в rubert жива ⇒ канон
//! невидим модели, а скобка остаётся резаной у обоих входов). Что он чинит:
//! span-геометрию каскада 1 для будущего PR-C (дефис-хвост окна `Петрова-`
//! по промеру #160 — контур эвристики, не lockR); канон нормализует вход
//! каскада 1, не изменяя вердикт — это и есть его контракт (safe-no-op
//! evidence + preparation, честная формулировка PR-B).
//!
//! Дисциплина чисел (lesson #232 «pin = measurement»):
//! - ЗУБ 1 = recall-контра v1.12: дефисные ФИО (g0284/g0285) закрыты
//!   `person_name` на живом графе (оракул = пересечение байтовых интервалов +
//!   равенство класса + порог, тот же, что `recall_golden`).
//! - ЗУБ 2 = FP-контра v1.12: гео-дефисы (g0286–g0288) НЕ получают
//!   person_name-спана, перекрывающего гео (канон склеивает `Санкт
//!   Петербург`; накрасит rubert = FP-фабрика, канон откатывать).
//! - ЗУБ 3 (perturbation live, law «green = not evidence until proven live»)
//!   = PAIRED raw-vs-canon (рычаг `extract_with(raw)` — явный аргумент, НЕ
//!   env): golden-хит-множество raw = канон на каждой recall-фикстуре
//!   (координатная невидимость канона на живом графе), и raw-скобка первой
//!   дефисной фамилии g0284 = ≥2 спана (дискриминатор: зуб КРАСНЕЕТ, если
//!   модель начнёт склеивать сама — первичка промера устарела, полка требует
//!   переоценки).
//! - Пропуск без весов = `SKIP|…`-строка + `FASAD_REQUIRE_MODELS` = падение
//!   (#87/#237-паттерн: молчаливого зелёного про пропуска нет).
//!
//! Ort-контракт «one environment per process» (промер `decide_budget_live`,
//! run 40253494121): все legs в ОДНОМ тесте с ОДНИМ монтажом; CI-шаг и
//! `--test-threads=1` гарантируют последовательность.
#![cfg(feature = "ort-inference")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
#![allow(clippy::too_many_lines)] // полка = промер: legs одного эксперимента читнее в одном теле

use std::path::PathBuf;

use guard_onnx::extract::{ExtractSpan, LockrExtractor, canonicalize_lockr_input};
use guard_onnx::routing::DEFAULT_TAU_LOW;

/// Векторы = golden v1.12 (#160): тексты и золотые байтовые диапазоны дословно
/// из `data/golden/golden-v1.jsonl` (канон 1Б→1Б координат не двигает —
/// оффлайн-зуб ниже). Флаг = recall-FIO (true) / negative-бейт гео (false).
const ROWS: [(&str, &str, usize, usize, bool); 5] = [
    (
        "g0284",
        "Кредитный договор: заёмщик Иванов-Иванов Иван Петрович, ИНН 7710140614, телефон +7 916 1002030.",
        50,
        101,
        true,
    ),
    (
        "g0285",
        "Акт выполненных работ: подрядчик Петрова-Водкина Анна Сергеевна, СНИЛС 112-233-455 95 (проверка формы дефисного ФИО).",
        61,
        118,
        true,
    ),
    (
        "g0286",
        "Отгрузка со склада: Санкт-Петербург, Невский проспект 1953 год выпуска партии.",
        36,
        65,
        false,
    ),
    (
        "g0287",
        "Маршрут доставки: Усть-Илимск, Иркутская область, партия № 5 принята складом.",
        33,
        54,
        false,
    ),
    (
        "g0288",
        "Экспедиция: Ростов-на-Дону, таможня оформила декларацию грузополучателя.",
        22,
        48,
        false,
    ),
];

fn model_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FASAD_MODEL_DIR") {
        let p = PathBuf::from(dir);
        return p.is_dir().then_some(p);
    }
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".cache/fasad-models");
    cache.is_dir().then_some(cache)
}

fn load_lockr(dir: &std::path::Path) -> LockrExtractor {
    let env = guard_onnx::extract::environment().expect("ort env");
    let ldir = dir.join("lockR/rubert-base-pii-ner-onnx");
    LockrExtractor::load(
        &env,
        &ldir.join("model.optimized.fp16.onnx"),
        &ldir.join("tokenizer.json"),
        // Рюлинг 21.10 по аналогии с cfg_with CI-полок: бюджет полки = 2 потока.
        2,
    )
    .expect("LockrExtractor::load (lockR fp16)")
}

/// person_name-спан над порогом, пересекающий [gs, ge) (оракул хита =
/// пересечение байтовых интервалов + равенство класса, тот же, что
/// `recall_golden`).
fn person_hit(spans: &[ExtractSpan], gs: usize, ge: usize) -> bool {
    spans.iter().any(|sp| {
        sp.class == Some("person_name")
            && sp.byte_start < ge
            && sp.byte_end > gs
            && sp.score >= DEFAULT_TAU_LOW
    })
}

fn person_spans(spans: &[ExtractSpan]) -> Vec<(usize, usize)> {
    spans
        .iter()
        .filter(|sp| sp.class == Some("person_name") && sp.score >= DEFAULT_TAU_LOW)
        .map(|sp| (sp.byte_start, sp.byte_end))
        .collect()
}

/// Оффлайн-зуб (без весов, гоняется всегда): канон 1Б→1Б байт-сохраняющ на
/// golden-векторах промёра — length-инвариант на каждой строке таблицы; на
/// нём держится геометрия живого зуба (золотые координаты не двигаются).
#[test]
fn canon_is_byte_preserving_on_golden_vectors() {
    for (id, text, gs, ge, _) in ROWS {
        let canon = canonicalize_lockr_input(text);
        assert_eq!(canon.len(), text.len(), "{id}: байтовая длина поехала");
        assert!(
            canon.is_char_boundary(canon.len()),
            "{id}: канон не на char-границе"
        );
        assert!(
            text.is_char_boundary(gs) && text.is_char_boundary(ge),
            "{id}: золотой спан не на char-границе (первичка golden)"
        );
        if text.contains('-') {
            assert!(
                matches!(canon, std::borrow::Cow::Owned(_)),
                "{id}: дефис есть, а канон заимствованный"
            );
            assert!(!canon.contains('-'), "{id}: дефис выжил в каноне");
        }
    }
}

/// Живая полка: все legs в одном тесте (ort-контракт «one environment per
/// process», промер `decide_budget_live`) + `--test-threads=1` в CI-шаге.
#[test]
fn hyphen_fio_live_paired_raw_vs_canon() {
    let Some(dir) = model_dir() else {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а весов нет — #160-полка не смонтирована"
        );
        eprintln!(
            "SKIP|hyphen_fio_live|нет каталога весов (FASAD_MODEL_DIR/~/.cache/fasad-models)"
        );
        return;
    };
    let mut lockr = load_lockr(&dir);

    let mut fn_rows = 0u32;
    let mut fp_baits = 0u32;
    let mut parity_breaks = 0u32;
    let mut raw_first_name_spans = 0usize;
    for (id, text, gs, ge, is_fio) in ROWS {
        let raw = lockr
            .extract_with(text, false)
            .unwrap_or_else(|e| panic!("{id}: raw extract: {e}"));
        let canon = lockr
            .extract(text)
            .unwrap_or_else(|e| panic!("{id}: canon extract: {e}"));
        // Артефакт промера = оба набора спанов (lesson #232: числа в
        // PR-комменте, не пин).
        for (leg, ex) in [("raw", &raw), ("canon", &canon)] {
            for sp in &ex.spans {
                println!(
                    "HYPHENLIVE|{id}|{leg}|{}|{}..{}|{:.4}",
                    sp.class.map_or(sp.tag.as_str(), |c| c),
                    sp.byte_start,
                    sp.byte_end,
                    sp.score
                );
            }
        }
        let hit_raw = person_hit(&raw.spans, gs, ge);
        let hit_canon = person_hit(&canon.spans, gs, ge);
        println!("HYPHENLIVE|{id}|person_hit_raw|{hit_raw}|person_hit_canon|{hit_canon}");
        if is_fio {
            fn_rows += u32::from(!hit_canon);
            // ЗУБ-3a (координатная невидимость канона): golden-хит raw =
            // канон на каждой recall-фикстуре (1Б→1Б-свойство на живом
            // графе; расхождение = канон сдвинул координаты/вердикт).
            parity_breaks += u32::from(hit_raw != hit_canon);
            // ЗУБ-3b (дискриминатор): скобка первой дефисной фамилии на raw
            // (окно 50..76 у g0284) = резаная, ≥2 спана (первичка
            // paired-промера 28.10).
            if id == "g0284" {
                raw_first_name_spans = person_spans(&raw.spans)
                    .iter()
                    .filter(|(a, b)| *a >= gs && *b <= 76)
                    .count();
                println!("HYPHENLIVE|g0284|first_name_spans_raw|{raw_first_name_spans}");
                println!("HYPHENLIVE|g0284|spans_raw|{:?}", person_spans(&raw.spans));
                println!(
                    "HYPHENLIVE|g0284|spans_canon|{:?}",
                    person_spans(&canon.spans)
                );
            }
        } else {
            fp_baits += u32::from(hit_canon);
        }
    }
    println!(
        "HYPHENLIVE|verdict|fn_rows|{fn_rows}|fp_baits|{fp_baits}|parity_breaks|{parity_breaks}|raw_first_name_spans|{raw_first_name_spans}"
    );

    // ЗУБ 1 (recall-контра v1.12): обе фикстуры дефисного ФИО закрыты
    // person_name на живом графе. Промер PR-B: row-level FN НЕ подтверждён
    // (первичка issue оговаривала «поведения модели не мерял локально»);
    // контра = регресс-страж: краснеет, если канон/модель проедают recall.
    assert_eq!(
        fn_rows, 0,
        "дефисные ФИО не закрыты person_name: {fn_rows} recall-фикстур без хита"
    );
    // ЗУБ 2 (FP-контра v1.12): гео-бейты не накраслены person_name каноном.
    assert_eq!(
        fp_baits, 0,
        "FP-фабрика: канон lockR накрасил person_name на гео-бейтах ({fp_baits}) — откат канона"
    );
    // ЗУБ 3a: raw↔canon parity golden-хитов = канон невидим по координатам.
    assert_eq!(
        parity_breaks, 0,
        "канон сдвинул golden-хит ({parity_breaks} расждений raw↔canon) — 1Б→1Б-инвариант нарушен на живом графе"
    );
    // ЗУБ 3b: живость дискриминатора (первичка промера 28.10 = резаная
    // raw-скобка). Красный = модель начала склеивать сама ⇒ первичка
    // устарела, направление чина (PR-C span-контур) требует переоценки.
    assert!(
        raw_first_name_spans >= 2,
        "raw-скобка первой дефисной фамилии g0284 не резана ({raw_first_name_spans} спан(ов) в 50..76): первичка paired-промера 28.10 опровергнута живой моделью — канон lockR под вопросом, полка требует переоценки"
    );
}
