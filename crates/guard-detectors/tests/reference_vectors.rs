//! B5 (issue #14): табличные эталоны чексумм/форматов вынесены в данные —
//! `data/golden/reference-vectors.tsv`, перенесён дословно из таблиц
//! `docs/dep-verify-algorithms.md` §1–§7. Тест читает TSV из дерева репозитория
//! и прогоняет его через `guard_detectors::checksums::*`.
//!
//! Дисциплина (AGENTS §Дисциплина фактов п.3): ожидаемый статус берётся **из
//! таблицы первички**, никогда не вычисляется проверяемой функцией.
//!
//! Конвенции TSV (шапка `#` — комментарий):
//! - `family`   — класс-проверка (`inn10`/`inn12`/`snils`/`ogrn13`/`ogrnip15`/
//!   `card`/`iban`/`bik`/`account`/`bik_account`);
//! - `input`    — значение; для `bik_account` — пара `БИК:СЧЁТ`;
//! - `expected` — `valid` | `invalid` | `none` («none» = строка не относится к
//!   классу: чужая длина/не-цифры → `Option::None`, соглашение модуля checksums);
//! - `section`  — ссылка на § первички;
//! - `note`     — комментарий документа;
//! - `contradiction` — `yes`: строка участвует в зафиксированном противоречии
//!   первички (§2 `383391302210`, §3 колонка S, §4 колонка расчёта, §7
//!   разряды `БИК[1:3]==счёт[6:8]`). Такие строки **скипаются** в прогоне —
//!   соответствующие `#[ignore]`-тесты в `checksums.rs` живы до закрытия
//!   issue #14; статус в `note` остаётся подтверждённым документом.
//!
//! Самопроверка «формула == таблица» остаётся в unit-тестах `checksums.rs` —
//! этот файл добавляет промер «TSV == таблица первички == модуль».

use std::collections::BTreeMap;
use std::path::PathBuf;

use guard_detectors::checksums;

/// Репозиторий от корня крейта: `crates/guard-detectors` → `../..`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vectors_path() -> PathBuf {
    repo_root().join("data/golden/reference-vectors.tsv")
}

#[derive(Debug)]
struct Vector {
    lineno: usize,
    family: String,
    input: String,
    expected: String,
    section: String,
    contradiction: bool,
}

fn parse_tsv() -> Vec<Vector> {
    let path = vectors_path();
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("читаем {}: {e}", path.display()));
    let mut out = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols[0] == "family" {
            // строка заголовка
            assert_eq!(cols.len(), 6, "строка {lineno}: шапка не из 6 колонок");
            continue;
        }
        assert_eq!(
            cols.len(),
            6,
            "строка {lineno}: колонки разделены TAB, ровно 6 (family, input, expected, section, note, contradiction)"
        );
        assert!(
            matches!(cols[2], "valid" | "invalid" | "none"),
            "строка {lineno}: expected={:?} вне enum valid|invalid|none",
            cols[2]
        );
        assert!(
            cols[3].starts_with('§'),
            "строка {lineno}: section {:?} обязан ссылаться на § первички",
            cols[3]
        );
        assert!(
            matches!(cols[5], "yes" | "no"),
            "строка {lineno}: contradiction={:?} вне enum yes|no",
            cols[5]
        );
        out.push(Vector {
            lineno: lineno + 1,
            family: cols[0].to_owned(),
            input: cols[1].to_owned(),
            expected: cols[2].to_owned(),
            section: cols[3].to_owned(),
            contradiction: cols[5] == "yes",
        });
    }
    out
}

/// Прогон строки TSV через `checksums::*`. Внешний `Option` отделяет
/// «семейство тесту неизвестно» (защита от опечатки в TSV → паника теста) от
/// валидного ответа модуля; внутренний — соглашение `Option<bool>` модуля
/// checksums (`None` = не наш класс).
#[allow(
    clippy::option_option,
    reason = "два разных None: неизвестное family vs не-класс"
)]
fn run_through_module(v: &Vector) -> Option<Option<bool>> {
    let inp = v.input.as_bytes();
    match v.family.as_str() {
        "inn10" => Some(checksums::inn10(inp)),
        "inn12" => Some(checksums::inn12(inp)),
        "snils" => Some(checksums::snils(inp)),
        "ogrn13" => Some(checksums::ogrn13(inp)),
        "ogrnip15" => Some(checksums::ogrnip15(inp)),
        "card" => Some(checksums::luhn(inp)),
        "iban" => Some(checksums::iban(inp)),
        "bik" => Some(checksums::bik_format(inp)),
        "account" => Some(checksums::bank_account_format(inp)),
        "bik_account" => {
            let (bik, acc) = v.input.split_once(':')?;
            Some(checksums::bik_account_cross(bik.as_bytes(), acc.as_bytes()))
        }
        _ => None,
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "гейт-тест B5: промер-счётчики в одном проходе"
)]
fn reference_vectors_tsv_matches_checksums() {
    let vectors = parse_tsv();
    assert!(!vectors.is_empty(), "TSV пуст");

    let mut total = 0usize;
    let mut checked = 0usize;
    let mut skipped = 0usize;
    let mut per_family: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &vectors {
        total += 1;
        *per_family.entry(v.family.as_str()).or_default() += 1;
        if v.contradiction {
            skipped += 1;
            continue;
        }
        let Some(res) = run_through_module(v) else {
            panic!(
                "строка {}: неизвестное family {:?} (TSV мёртв — правь match в тесте)",
                v.lineno, v.family
            );
        };
        let want = match v.expected.as_str() {
            "valid" => Some(true),
            "invalid" => Some(false),
            "none" => None,
            _ => unreachable!("enum проверен в парсере"),
        };
        assert_eq!(
            res, want,
            "строка {}: {} {} — таблица {} ждёт {:?}, модуль даёт {:?}",
            v.lineno, v.family, v.input, v.section, want, res
        );
        checked += 1;
    }
    // Каждая противоречивая строка обязана быть помечена — иначе счётчик
    // скипа молча осядет и #14 закроется с дырой. Ожидаемый минимум —
    // фактический промер TSV этого захода: 6 строк (§2 ×1, §3 ×2, §5 ×1,
    // §7 ×2; см. print ниже). §3 двойка: SNIKS-контрпримеры доки —
    // 8/9-значная контр-пара НЕ считается (правило S10/S11 не в TSV), см.
    // snils_triple_rule_vector_contradiction в #[ignore]-модуле checksums
    // (ignore без TSV-строки — отсюда «6 ignore» ≠ «6 TSV-contradiction
    // один-в-один»: три ×3-й ignore без строки; нит ревью PR#24 N3).
    //
    // Было 8: две §4-строки (`5060049620796`, `4090342700154`) сняты с
    // contradiction в задаче #27 — их «противоречие» оказалось дефектом колонки
    // «расчёт» нашей таблицы (перебор moduli 2..2000 × 15 конвенций не дал
    // пересечения ни с каким альтернативным алгоритмом), а не расхождением
    // первички. Колонка исправлена по независимому пересчёту, статусы НЕВАЛИДН
    // подтверждены структурным ветом п.7 165н + mod-11 → строки прогоняются.
    assert!(
        skipped >= 6,
        "ожидались ≥6 contradiction=yes строк (§2 ×1, §3 ×2, §5 ×1, §7 ×2), скипнуто {skipped}"
    );
    println!(
        "B5 reference-vectors.tsv: всего {total}, проверено {checked}, скипнуто contradiction=yes {skipped}"
    );
    for (f, n) in &per_family {
        println!("  family {f}: {n}");
    }
}

/// B3 для данных: TSV существует, парсится, каждая строка ссылается на §, в
/// families покрыты все семь таблиц документа (§1–§7).
#[test]
fn reference_vectors_tsv_family_coverage() {
    let vectors = parse_tsv();
    for f in [
        "inn10",
        "inn12",
        "snils",
        "ogrn13",
        "ogrnip15",
        "card",
        "iban",
        "bik",
        "account",
        "bik_account",
    ] {
        assert!(
            vectors.iter().any(|v| v.family == f),
            "в TSV нет ни одной строки family={f} (таблица первички не перенесена)"
        );
    }
    // каждая таблица первички содержит и ВАЛИДН, и НЕВАЛИДН/None-строки —
    // иначе перенесён половину таблицы
    for f in [
        "inn10", "inn12", "snils", "ogrn13", "ogrnip15", "card", "iban", "bik", "account",
    ] {
        let has_valid = vectors
            .iter()
            .any(|v| v.family == f && v.expected == "valid");
        let has_neg = vectors
            .iter()
            .any(|v| v.family == f && v.expected != "valid");
        assert!(
            has_valid && has_neg,
            "family {f}: только одна половина таблицы (§ — обе обязательны)"
        );
    }
}
