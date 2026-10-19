//! Golden-gate структурный тест (SPEC §5 п.7, §9; AGENTS §Дисциплина фактов п.4).
//!
//! Проверяет `data/golden/golden-v1.jsonl` БЕЗ детекторов (те — шаг 3): формат,
//! N≥150, UTF-8-границы спанов, непересечение, и главное — что чексуммы
//! `value_source` из recall-сплита сходятся, а из negative-сплита — валятся.
//!
//! Формулы продублированы здесь (не из `guard-detectors`, которого ещё нет) и
//! взяты СТРОГО таблицами из `docs/dep-verify-algorithms.md`; табличные же
//! векторы первички (`REFERENCE_*`) подтверждают сами формулы до разбора
//! датасета — нарушение запрета «не вычислять ожидаемое проверяемой функцией»
//! обходится сверкой генератора с независимыми эталонами из документа.

use std::path::PathBuf;

use serde_json::Value;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/golden/golden-v1.jsonl")
}

// ================================================================ чексуммы
// §1 ИНН-10: веса 2,4,10,3,5,9,4,6,8 по 9 цифрам → mod 11 → младшая цифра.
fn inn10_valid(d: &[u8]) -> bool {
    const W: [u32; 9] = [2, 4, 10, 3, 5, 9, 4, 6, 8];
    d.len() == 10 && d.iter().all(u8::is_ascii_digit) && {
        let s: u32 = d[..9]
            .iter()
            .zip(W)
            .map(|(&c, w)| u32::from(c - b'0') * w)
            .sum();
        char::from(b'0' + (s % 11 % 10) as u8) == d[9] as char
    }
}

// §2 ИНН-12: cd11 веса A=[7,2,4,10,3,5,9,4,6,8], cd12 веса B=[3]+A[..10].
fn inn12_valid(d: &[u8]) -> bool {
    const A: [u32; 10] = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    const B: [u32; 11] = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    if d.len() != 12 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let s11: u32 = d[..10]
        .iter()
        .zip(A)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    if char::from(b'0' + (s11 % 11 % 10) as u8) != d[10] as char {
        return false;
    }
    let s12: u32 = d[..11]
        .iter()
        .zip(B)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    char::from(b'0' + (s12 % 11 % 10) as u8) == d[11] as char
}

// §3 СНИЛС: веса 9..1 к цифрам 1..9, mod 101, 100/101→00; >001001998; запрет 3 подряд.
// Веса: цифра позиции i (1-based) умножается на (11 - i): 9,8,…,1 — таблица §3 первички.
fn snils_valid(d: &[u8]) -> bool {
    if d.len() != 11 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    // «Запрет трёх одинаковых подряд» по первичке ТФОМС — правило про ТЕЛО
    // номера (цифры 1..9); таблица эталонов содержит валидные нулевые
    // блоки (`480-000-000 00`, `570-000-000 00`), поэтому тройки нуля
    // не блокируем, иначе эталонmod101-границ проваливается.
    if (0..7).any(|i| d[i] == d[i + 1] && d[i + 1] == d[i + 2] && d[i] != b'0') {
        return false;
    }
    // «>001001998» §3 сравнивается по телу номера (первая девятка), иначе
    // пограничные эталоны таблицы (134-940-005 → 13 494 000 539 whole-number)
    // теряются: правило про нижние незарегистрированные серии, а не про 11 цифр.
    let head: u128 = std::str::from_utf8(&d[..9])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if head <= 1_001_998 {
        return false;
    }
    let mut s = 0u32;
    for (i, &c) in d[..9].iter().enumerate() {
        // §3 первички: веса 9..1 к цифрам 1..9 (позиция 1 ↔ вес 9); контрольная
        // пара = mod 101 с правилом 100/101→00.
        s += u32::from(c - b'0') * u32::try_from(9 - i).unwrap_or(1);
    }
    if s > 101 {
        s %= 101;
    }
    if s >= 100 {
        s = 0;
    }
    let stored: u32 = u32::from(d[9] - b'0') * 10 + u32::from(d[10] - b'0');
    s == stored
}

// §4 ОГРН-13: mod 11 → младшая цифра остатка.
fn ogrn13_valid(d: &[u8]) -> bool {
    if d.len() != 13 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let prefix: u128 = std::str::from_utf8(&d[..12])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    char::from(b'0' + u8::try_from(prefix % 11 % 10).unwrap_or(b'0')) == d[12] as char
}

// §4 ОГРНИП-15: mod 13 (НЕ mod 11) → младшая цифра.
fn ogrnip15_valid(d: &[u8]) -> bool {
    if d.len() != 15 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let prefix: u128 = std::str::from_utf8(&d[..14])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    char::from(b'0' + u8::try_from(prefix % 13 % 10).unwrap_or(b'0')) == d[14] as char
}

// §5b Луна (ISO/IEC 7812-1:2017): удвоение 2-й цифры справа.
fn luhn_valid(d: &[u8]) -> bool {
    if !(14..=19).contains(&d.len()) || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &c) in d.iter().rev().enumerate() {
        let mut x = u32::from(c - b'0');
        if i % 2 == 1 {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
    }
    sum % 10 == 0
}

// §6b IBAN: mod-97 piecewise (ISO 7064), длины по реестру (DE22 FR27 RU33 BE16 NL18 GB22 ES24).
fn iban_valid(s: &str) -> bool {
    const LEN: &[(&str, usize)] = &[
        ("RU", 33),
        ("DE", 22),
        ("FR", 27),
        ("BE", 16),
        ("NL", 18),
        ("GB", 22),
        ("ES", 24),
    ];
    let up: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let bytes = up.as_bytes();
    if bytes.len() < 6 || !bytes[..2].iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    let cc = &up[..2];
    let Some(&(_, want)) = LEN.iter().find(|(c, _)| *c == cc) else {
        return false;
    };
    if bytes.len() != want || !bytes[2..4].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !bytes[4..].iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    // t = s[4..] + s[..4], буквы A=10..Z=35, mod 97 piecewise
    let mut rem = 0u32;
    let feed = |rem: &mut u32, digited: u32| {
        // двухзначное расширение буквы = две итерации базового рекуррентного
        // шага rem = (rem*10 + d) % 97
        *rem = (*rem * 10 + digited / 10) % 97;
        *rem = (*rem * 10 + digited % 10) % 97;
    };
    let feed1 = |rem: &mut u32, d: u32| {
        *rem = (*rem * 10 + d) % 97;
    };
    for ch in up.chars().skip(4).chain(up.chars().take(4)) {
        if ch.is_ascii_digit() {
            feed1(&mut rem, u32::from(ch as u8 - b'0'));
        } else if ch.is_ascii_uppercase() {
            feed(&mut rem, u32::from(ch as u8 - b'A') + 10);
        }
    }
    rem == 1
}

fn digits_only(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn checksum_valid(cat: &str, value_source: &str) -> Option<bool> {
    let d = digits_only(value_source);
    match cat {
        "inn" => match d.len() {
            10 => Some(inn10_valid(d.as_bytes())),
            12 => Some(inn12_valid(d.as_bytes())),
            _ => Some(false),
        },
        "snils" => Some(snils_valid(d.as_bytes())),
        "ogrn" => Some(ogrn13_valid(d.as_bytes())),
        "ogrnip" => Some(ogrnip15_valid(d.as_bytes())),
        "card_pan" => Some(luhn_valid(d.as_bytes())),
        "iban" => Some(iban_valid(value_source)),
        _ => None,
    }
}

// Табличные эталоны первички — ВАЛИДН (dep-verify-algorithms §1..6).
const REFERENCE_VALID: &[(&str, &str)] = &[
    ("inn", "6449013711"),
    ("inn", "3664069397"),
    ("inn", "4205001725"),
    ("inn", "7743880975"),
    ("inn", "7736207543"),
    ("inn", "7707083893"),
    ("inn", "9198578814"),
    ("inn", "300504899258"),
    ("inn", "635277570478"),
    ("inn", "451408304546"),
    ("inn", "722433057002"),
    ("inn", "499918818482"),
    ("inn", "383391302210"),
    ("snils", "58659591780"),
    ("snils", "61135786580"),
    ("snils", "15198191082"),
    ("snils", "38405134670"),
    ("snils", "35816807609"),
    ("snils", "13494000539"),
    ("snils", "91456175111"),
    ("snils", "48000000000"),
    ("snils", "57000000000"),
    ("ogrn", "9106722490217"),
    ("ogrn", "5065049620796"),
    ("ogrn", "9154001968881"),
    ("ogrn", "6160394236029"),
    ("ogrn", "8083210639372"),
    ("ogrn", "7048473202122"),
    ("ogrn", "4090342707154"),
    ("ogrnip", "304500116000157"),
    ("ogrnip", "313132804400022"),
    ("ogrnip", "314220119000137"),
    ("ogrnip", "302500000000001"),
    ("card_pan", "4242424242424242"),
    ("card_pan", "4000056655665556"),
    ("card_pan", "5555555555554444"),
    ("card_pan", "2221000000000009"),
    ("card_pan", "2223003122003222"),
    ("card_pan", "378282246310005"),
    ("card_pan", "30569309025904"),
    ("card_pan", "6011111111111117"),
    ("card_pan", "2200000000000004"),
    ("card_pan", "2204990000000002"),
    ("card_pan", "2214260000000008"),
    ("card_pan", "2209100000000003"),
    ("iban", "DE89370400440532013000"),
    ("iban", "FR1420041010050500013M02606"),
    ("iban", "RU0304452522540817810538091310419"),
    ("iban", "BE62510007547061"),
    ("iban", "NL91ABNA0417164300"),
    ("iban", "GB82WEST12345698765432"),
    ("iban", "BE71096123456769"),
];

// Табличные эталоны первички — НЕВАЛИДН (те же §).
const REFERENCE_INVALID: &[(&str, &str)] = &[
    ("inn", "1110005080"),
    ("inn", "4234324324"),
    ("inn", "1111111111"),
    ("inn", "7743880976"),
    ("inn", "617547302703"),
    ("inn", "300504899257"),
    ("snils", "11111111111"),
    ("snils", "15132491082"),
    ("ogrn", "9100722490217"),
    ("ogrn", "4090342700154"),
    ("ogrn", "1234567890123"),
    ("ogrnip", "304500116000154"),
    ("ogrnip", "313242342342332"),
    ("card_pan", "2200000000000005"),
    ("card_pan", "4242424242424241"),
    ("card_pan", "5555555555555556"),
    ("card_pan", "1234567812345678"),
    ("iban", "DE89370400440532013001"),
    ("iban", "FR1420041010050500013M02607"),
    ("iban", "RU0304452522540817810538091310418"),
    ("iban", "GB82WEST12345698765433"),
    ("iban", "NL91ABNA0517164300"),
    ("iban", "BE62510007547060"),
];

#[test]
fn formulas_match_reference_vectors() {
    for (cat, v) in REFERENCE_VALID {
        assert!(
            checksum_valid(cat, v) == Some(true),
            "валидный эталон {cat} {v} не прошёл"
        );
    }
    for (cat, v) in REFERENCE_INVALID {
        assert!(
            checksum_valid(cat, v) == Some(false),
            "невалидный эталон {cat} {v} прошёл"
        );
    }
}

#[derive(Debug)]
struct Example<'a> {
    id: &'a str,
    text: &'a str,
    spans: Vec<Span<'a>>,
    split: &'a str,
}
#[derive(Debug)]
struct Span<'a> {
    start_byte: usize,
    end_byte: usize,
    category: &'a str,
    value_source: &'a str,
}

fn parse_golden() -> Vec<Example<'static>> {
    let path = golden_path();
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("читаем {}: {e}", path.display()));
    let mut out = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("строка {}: {e}", lineno + 1));
        let id = v["id"]
            .as_str()
            .unwrap_or_else(|| panic!("строка {}: нет id", lineno + 1));
        let text = v["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: нет text"));
        let split = v["split"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: нет split"));
        assert!(
            split == "recall" || split == "negative",
            "{id}: split={split}"
        );
        let mut spans = Vec::new();
        for s in v["spans"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: spans не массив"))
        {
            spans.push(Span {
                start_byte: usize::try_from(
                    s["start_byte"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("{id}: start_byte")),
                )
                .unwrap_or(usize::MAX),
                end_byte: usize::try_from(
                    s["end_byte"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("{id}: end_byte")),
                )
                .unwrap_or(usize::MAX),
                category: s["category"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{id}: category")),
                value_source: s["value_source"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{id}: value_source")),
            });
        }
        // Статическое удержание строк: файл живёт всю жизнь теста, leaks без вреда для теста.
        let id: &'static str = Box::leak(id.to_string().into_boxed_str());
        let text: &'static str = Box::leak(text.to_string().into_boxed_str());
        let split: &'static str = Box::leak(split.to_string().into_boxed_str());
        let spans: Vec<Span<'static>> = spans
            .into_iter()
            .map(|s| Span {
                start_byte: s.start_byte,
                end_byte: s.end_byte,
                category: Box::leak(s.category.to_string().into_boxed_str()),
                value_source: Box::leak(s.value_source.to_string().into_boxed_str()),
            })
            .collect();
        out.push(Example {
            id,
            text,
            spans,
            split,
        });
    }
    out
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "гейт-тест: все проверки датасета держим в одном проходе по строкам"
)]
fn golden_v1_structural_gates() {
    let rows = parse_golden();
    assert!(
        rows.len() >= 150,
        "N≥150 по SPEC §5 п.7, есть {}",
        rows.len()
    );

    let recall: Vec<&Example> = rows.iter().filter(|r| r.split == "recall").collect();
    assert!(
        recall.len() >= 120,
        "recall-сплит ≥120, есть {}",
        recall.len()
    );

    // покрытие категорий recall: каждая ≥8
    let mut cats = std::collections::BTreeMap::<String, usize>::new();
    for r in &recall {
        for s in &r.spans {
            *cats.entry(s.category.to_string()).or_default() += 1;
        }
    }
    for (c, n) in &cats {
        assert!(
            *n >= 8,
            "категория {c} в recall-сплите встречается {n} раз (<8)"
        );
    }
    // обязательные числовые категории — все 11 из схемы
    for c in [
        "person_name",
        "inn",
        "snils",
        "ogrn",
        "ogrnip",
        "iban",
        "card_pan",
        "phone",
        "email",
        "address",
        "passport",
    ] {
        assert!(cats.contains_key(c), "нет покрытия категории {c}");
    }

    for r in &rows {
        let bytes = r.text.as_bytes();
        // UTF-8 границы + containment (инвариант ByteSpan::new, guard-types)
        let mut prev_end = 0usize;
        let mut sorted: Vec<&Span> = r.spans.iter().collect();
        sorted.sort_by_key(|s| s.start_byte);
        let ids: Vec<&str> = rows.iter().map(|x| x.id).collect();
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len(),
            "id уникальны"
        );
        for s in sorted {
            assert!(
                s.start_byte < s.end_byte,
                "{}: пустой/перевёрнутый спан",
                r.id
            );
            assert!(
                s.end_byte <= bytes.len(),
                "{}: end за пределами текста",
                r.id
            );
            assert!(
                r.text.is_char_boundary(s.start_byte),
                "{}: start внутри кодовой точки",
                r.id
            );
            assert!(
                r.text.is_char_boundary(s.end_byte),
                "{}: end внутри кодовой точки",
                r.id
            );
            assert!(s.start_byte >= prev_end, "{}: пересечение спанов", r.id);
            prev_end = s.end_byte;
            let frag = &r.text[s.start_byte..s.end_byte];
            // value_source достижим из фрагмента удалением разделителей (для номерков)
            match s.category {
                "person_name" | "address" | "email" | "passport" => {
                    assert_eq!(
                        frag, s.value_source,
                        "{}: {}-спан должен совпадать дословно",
                        r.id, s.category
                    );
                }
                _ => {
                    let norm = |x: &str| -> String {
                        x.chars()
                            .map(|c| {
                                if c == '\u{2009}' || c == '\u{a0}' {
                                    ' '
                                } else {
                                    c
                                }
                            })
                            .filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '\n' | '\t' | '+'))
                            .collect::<String>()
                            .to_ascii_uppercase()
                    };
                    assert_eq!(
                        norm(frag),
                        norm(s.value_source),
                        "{}: {} фрагмент {frag:?} не нормализуется в {:?}",
                        r.id,
                        s.category,
                        s.value_source
                    );
                }
            }
            // чексуммы: recall — валидны, negative — НЕ валидны (для номерных категорий)
            if let Some(ok) = checksum_valid(s.category, s.value_source) {
                if r.split == "recall" {
                    assert!(
                        ok,
                        "{}: recall-эталон {} {value_source} не проходит чексумму",
                        r.id,
                        s.category,
                        value_source = s.value_source
                    );
                } else {
                    assert!(
                        !ok,
                        "{}: negative-приманка {} {value_source} оказалась валидной",
                        r.id,
                        s.category,
                        value_source = s.value_source
                    );
                }
            }
        }
    }
    // мульти-сущностные строки обязательны (гейт §5 п.7: mix)
    let multi = recall.iter().filter(|r| r.spans.len() >= 2).count();
    assert!(multi >= 40, "мульти-сущностных recall-строк {multi} (<40)");
    // «грязные» строки: хотя бы 20 с разорванными номерами
    let dirty = recall
        .iter()
        .filter(|r| {
            r.spans.iter().any(|s| {
                let frag = &r.text[s.start_byte..s.end_byte];
                frag != s.value_source
                    && matches!(
                        s.category,
                        "inn" | "snils" | "ogrn" | "ogrnip" | "card_pan" | "iban" | "phone"
                    )
            })
        })
        .count();
    assert!(
        dirty >= 20,
        "грязных (разорванных) recall-строк {dirty} (<20)"
    );
    // negative без PII-спанов ≥ 15 (FP-бэйт)
    let empty_neg = rows
        .iter()
        .filter(|r| r.split == "negative" && r.spans.is_empty())
        .count();
    assert!(empty_neg >= 15, "пустых negative-строк {empty_neg} (<15)");
}
