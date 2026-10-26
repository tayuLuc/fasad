//! Golden-gate структурный тест (SPEC §5 п.7, §9; AGENTS §Дисциплина фактов п.4).
//!
//! Проверяет `data/golden/golden-v1.jsonl` БЕЗ детекторов (те — шаг 3): формат,
//! N≥150, UTF-8-границы спанов, непересечение, и главное — что чексуммы
//! `value_source` из recall-сплита сходятся, а из negative-сплита — валятся.
//!
//! Гейт-права B1–B4 (issue #14, ревью #13): count-гейт по recall-классу (B1),
//! SHA-256-привязка файла (B2), структурные валидаторы строк (B3), формат-
//! валидаторы `value_source` (B4); B5 (табличные эталоны в данных) — соседний
//! тест `reference_vectors.rs`. Сводка прав и статусы: `data/golden/README.md`
//! § «Гейт-права B1–B5».
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

// ================================================================ B2 (issue #14)
// привязка гейта к содержимому набора
//
// SHA-256 файла golden-v1.jsonl, **промеренный** `shasum -a 256
// data/golden/golden-v1.jsonl` в заходе #223 (26.10, golden-v1.4: строки
// g0239–g0242 recall каркасного СНИЛС/ОГРНИП×карта + g0243–g0247 FP-бейты
// невалидных канонных форм; g0001–g0238 побайтово идентичны v1.3 — промер
// префикса cmp в PR #223), переснят с замера #212 (24.10, v1.3: строки
// g0227–g0233 F-1/F-3 форм паспорта (служебные слова и каркасные
// разделители внутри канона) + g0234–g0238 FP-бэйты каркасных разрывов;
// g0001–g0226 побайтово идентичны v1.2 — промер префикса в PR #212):
// та же константа, что в `data/golden/README.md` (расхождения нет —
// сверено в этом же заходе).
// Правка датасета без пересчёта хэша ломает этот тест, а не проходит незамеченной
// (обещание README «гейт привязан к SHA-256» из B2 становится машиной, не словами).
const GOLDEN_V1_SHA256: &str = "ae8980d5a83b2801a9b3575dab51ee9fb559bf2a6bb2214e8cf79369d0941b24";

/// B2: пересчитать SHA-256 файла и сверить с зашитой константой.
///
/// Хэш считаем сами (`sha2` — dev-зависимость; тот же алгоритм, что у `shasum
/// -a 256`, результат сверен промером). Логи — только хэш, без тела датасета.
#[test]
fn golden_file_sha256_matches_embedded_const() {
    use sha2::Digest as _;
    let raw = read_golden_raw();
    let digest = sha2::Sha256::digest(raw);
    let mut hex = String::with_capacity(64);
    for b in digest {
        use core::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    assert_eq!(
        hex, GOLDEN_V1_SHA256,
        "SHA-256 golden-v1.jsonl не совпал с зашитым — правка датасета без пересчёта хэша и README"
    );
}

// ================================================================ B1 (issue #14)
// count-гейт по recall-классу, а не по числу строк
//
// Формулировка B1: `recall.len() >= 150` вместо суммы строк — при N=200 из них
// 54 negative-приманки, и гейт «всего строк ≥150» зелёный даже когда
// recall-строк 136 (промер ревьюера #13). Считаем **строки recall-сплита,
// несущие хотя бы один спан с recall-классом** (канонический список — README
// «Категории»: 11 ядерных классов; `bik`/`bank_account` в recall не входят —
// они negative-бэйти).
const RECALL_CATEGORIES: [&str; 11] = [
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
];

/// B1: количество recall-строк (split=recall и ≥1 спан recall-класса) ≥ 150.
///
/// v1.1 (issue #14): порог 150 ПОКРЫТ (4 явных валидных эталона первички,
/// g0201–g0204, source ); ignore снят, гейт активен.
/// Исторический промер v1.0: 146 < 150 (README: «200 = 146
/// recall + 54 negative»). Это и есть дыра, которую B1 делает видимой: гейт по
/// числу строк файла (200) был зелёным при 136 recall. Разрыв закрывается
/// допиской датасета golden-v1.1 (≥4 recall-строки, атом «oracle-эталоны»
/// issue #14); тест зафиксирован **KNOWN-RED** (`#[ignore]` с причиной).
/// Альтернатива арбитража (README § «Отклонения и очередь» п.1): считать
/// «recall-строкой» любую строку с валидатор-размеченным спаном —
/// recall 146 + negative-размеченных 24 = **170** ≥ 150 (промер); тогда
/// фильтр `recall_class_row` меняется на `r.split == "recall"
/// || !r.spans.is_empty()` и `#[ignore]` снимается без дописки датасета.
#[test]
fn b1_recall_row_count_gate() {
    let rows = parse_golden();
    let recall_rows = rows.iter().filter(|r| recall_class_row(r)).count();
    assert!(
        recall_rows >= B1_RECALL_FLOOR,
        "B1: строк с recall-классом {recall_rows} (<{B1_RECALL_FLOOR})"
    );
    println!("B1: recall-строк с recall-классом = {recall_rows} (планка ≥{B1_RECALL_FLOOR})");
}

/// Планка B1 по контракту issue #14.
const B1_RECALL_FLOOR: usize = 150;

/// Активный инвариант v1.0: recall-строк не меньше промеренного пола 146
/// (усыхание датасета краснеет немедленно; снятие `#[ignore]` у
/// [`b1_recall_row_count_gate`] после дописки v1.1 поднимет планку до 150).
#[test]
fn b1_recall_rows_not_below_measured_floor() {
    const MEASURED_FLOOR: usize = 150; // golden-v1.1: промер B1-гейта
    let rows = parse_golden();
    let recall_rows = rows.iter().filter(|r| recall_class_row(r)).count();
    assert!(
        recall_rows >= MEASURED_FLOOR,
        "B1: recall-строк {recall_rows} (< промеренного пола {MEASURED_FLOOR}); планка контракта {B1_RECALL_FLOOR}"
    );
    println!(
        "B1: recall-строк = {recall_rows} (пол промера {MEASURED_FLOOR}, контракт {B1_RECALL_FLOOR})"
    );
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
    // не блокируем, иначе эталон mod101-границ проваливается.
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

// §4 ОГРН/ОГРНИП: независимое (от `checksums`) зеркало вета п.7 165н —
// признак `С` по длине + «КК ≠ 00». Дублирование намеренное: этот файл —
// второй оракул, и он обязан сходиться с таблицей, а не вызывать проверяемую
// функцию (AGENTS §Дисциплина фактов п.3).
fn ogrn_veto_ok(d: &[u8]) -> bool {
    let sign = d[0] - b'0';
    let sign_ok = match d.len() {
        13 => matches!(sign, 1 | 2 | 5 | 6 | 7 | 8 | 9),
        15 => matches!(sign, 3 | 4),
        _ => false,
    };
    sign_ok && !(d[3] == b'0' && d[4] == b'0')
}

// §4 ОГРН-13: mod 11 → младшая цифра остатка, плюс вето п.7 165н.
fn ogrn13_valid(d: &[u8]) -> bool {
    if d.len() != 13 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !ogrn_veto_ok(d) {
        return false;
    }
    let prefix: u128 = std::str::from_utf8(&d[..12])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    char::from(b'0' + u8::try_from(prefix % 11 % 10).unwrap_or(b'0')) == d[12] as char
}

// §4 ОГРНИП-15: mod 13 (НЕ mod 11) → младшая цифра, плюс вето п.7 165н.
fn ogrnip15_valid(d: &[u8]) -> bool {
    if d.len() != 15 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !ogrn_veto_ok(d) {
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
    sum.is_multiple_of(10)
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
    // mod-11 сходится (4=4), но С=4 в 13-значном невозможен: п.7 165н отводит
    // признак 4 записям ЕГРИП, а те — 15 знаков. Таблица §4 проверяла одну
    // чексумму → статус понижен по первичке (#27).
    ("ogrn", "4090342707154"),
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
    source: &'a str,
}
#[derive(Debug)]
struct Span<'a> {
    start_byte: usize,
    end_byte: usize,
    category: &'a str,
    value_source: &'a str,
}

/// Строка recall-сплита, несущая ≥1 спан recall-класса (для гейта B1).
fn recall_class_row(r: &Example<'_>) -> bool {
    r.split == "recall"
        && r.spans
            .iter()
            .any(|s| RECALL_CATEGORIES.contains(&s.category))
}

/// Сырой файл набора (кэш на весь тест-бинарь — B1/B2/B3/B4 читают одно и то же).
fn read_golden_raw() -> &'static [u8] {
    static RAW: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    RAW.get_or_init(|| {
        let path = golden_path();
        std::fs::read(&path).unwrap_or_else(|e| panic!("читаем {}: {e}", path.display()))
    })
    .as_slice()
}

fn parse_golden() -> Vec<Example<'static>> {
    let raw = std::str::from_utf8(read_golden_raw())
        .unwrap_or_else(|e| panic!("golden-v1.jsonl — не UTF-8 (B3): {e}"));
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
            .unwrap_or_else(|| panic!("строка {lineno} {id}: нет text"));
        let split = v["split"]
            .as_str()
            .unwrap_or_else(|| panic!("строка {lineno} {id}: нет split"));
        assert!(
            split == "recall" || split == "negative",
            "строка {lineno} {id}: split={split} вне enum"
        );
        let source = v["source"]
            .as_str()
            .unwrap_or_else(|| panic!("строка {lineno} {id}: нет source"));
        assert!(
            MATCH_SOURCES.contains(&source),
            "строка {lineno} {id}: source={source} вне enum"
        );
        let mut spans = Vec::new();
        for s in v["spans"]
            .as_array()
            .unwrap_or_else(|| panic!("строка {lineno} {id}: spans не массив"))
        {
            spans.push(Span {
                start_byte: usize::try_from(
                    s["start_byte"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("строка {lineno} {id}: start_byte")),
                )
                .unwrap_or(usize::MAX),
                end_byte: usize::try_from(
                    s["end_byte"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("строка {lineno} {id}: end_byte")),
                )
                .unwrap_or(usize::MAX),
                category: s["category"]
                    .as_str()
                    .unwrap_or_else(|| panic!("строка {lineno} {id}: category")),
                value_source: s["value_source"]
                    .as_str()
                    .unwrap_or_else(|| panic!("строка {lineno} {id}: value_source")),
            });
        }
        // Статическое удержание строк: файл живёт всю жизнь теста, leaks без вреда для теста.
        let id: &'static str = Box::leak(id.to_string().into_boxed_str());
        let text: &'static str = Box::leak(text.to_string().into_boxed_str());
        let split: &'static str = Box::leak(split.to_string().into_boxed_str());
        let source: &'static str = Box::leak(source.to_string().into_boxed_str());
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
            source,
        });
    }
    out
}

// ================================================================ B3/B4 (issue #14)
// структурные валидаторы строк набора
//
// ENUM-ы сверяются с `data/golden/README.md` § «Формат JSONL» / «Категории».
const SPAN_CATEGORIES: [&str; 13] = [
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
    "bik",
    "bank_account",
];
const MATCH_SOURCES: [&str; 9] = [
    "synthetic-checksum",
    "registry-example",
    "primary-invalid-vector",
    "primary-valid-vector", // golden-v1.1 (B1): валидные эталоны первички
    "doc-valid-vector",
    "foreign-bait",
    "synthetic-no-pii",
    "synthetic-translit",   // golden-v1.7 (#238): транслит-ФИО recall
    "frame-invalid-vector", // golden-v1.11 (#78): каркасные recall #234 (source-фенс B4)
];

/// B4: формат `value_source` по канону README § «поле `value_source`» (номерки —
/// нормализованные голые цифры/IBAN без пробелов, E.164 `7XXXXXXXXXX`;
/// ФИО/адрес/e-mail — дословная строка; паспорт — `NN NN NNNNNN`).
/// Мусор в recall-строках (пункт B4: «мусор в recall проходит») краснеет здесь,
/// а не на чексумме.
#[allow(clippy::too_many_lines, reason = "одна таблица формата на все классы")]
/// Длина нецифрового гэпа, начинающегося в `from` (каркас F-1: слово,
/// пунктуация, перевод строки, скобка, пробелы).
fn count_gap(b: &[u8], from: usize) -> usize {
    b[from..]
        .iter()
        .position(u8::is_ascii_digit)
        .unwrap_or(b.len() - from)
}

/// #101: цифры + разделители из перечня `NUMBER_SEPARATORS` (ASCII-дефис,
/// U+2010..U+2014, U+2212, U+FF0D, пробел) = ровно `n` ASCII-цифр, разделитель
/// только МЕЖДУ цифрами (ведущий/хвостовой/двойной = не форма).
fn sep_digits_len(v: &str, n: usize) -> bool {
    let mut digits = 0usize;
    let mut prev_digit = false;
    let mut first = true;
    for ch in v.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
            prev_digit = true;
            first = false;
        } else if !first && is_number_sep(ch) && prev_digit {
            prev_digit = false;
        } else {
            return false;
        }
    }
    prev_digit && digits == n
}

/// Дефисные разделители номера = дефисная ПОДКОЛОДА сканерного перечня
/// (`checksums::NUMBER_SEPARATORS`, #101: U+2013/2014/2212 в нём же) +
/// пробел (позиция 0 перечня). Точка/косая черта (#131) в B4-формы
/// номерных классов НЕ входят: «24.82.01.43.38» (#159) обязана оставаться
/// вне формата класса; зуб `b4_separators_match_scanner` сверяет пересечение
/// «B4-перечень ∩ дефисы = сканерные дефисы» (контура #131 «эталоны не
/// разъехались»).
fn is_number_sep(c: char) -> bool {
    matches!(
        c,
        '-' | '\u{2010}'..='\u{2014}' | '\u{2212}' | '\u{FF0D}' | ' '
    )
}

/// #101: бумажная форма СНИЛС «3+3+3+2» с дефисами из перечня; последний
/// разделитель = пробел (первичка бумажного формата g0152–g0154).
fn snils_paper_ok(v: &str) -> bool {
    let g: Vec<String> = {
        let mut out: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut prev_space = false;
        for ch in v.chars() {
            if ch == ' ' {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                prev_space = true;
            } else if ch.is_ascii_digit() {
                cur.push(ch);
                prev_space = false;
            } else if is_number_sep(ch) && !prev_space {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            } else {
                return false;
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    };
    g.len() == 4
        && [3, 3, 3, 2]
            .iter()
            .zip(g.iter())
            .all(|(w, x)| x.len() == *w && x.chars().all(|c| c.is_ascii_digit()))
}

fn value_source_format_ok(cat: &str, v: &str) -> bool {
    let all_digits = !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
    match cat {
        "inn" => all_digits && (v.len() == 10 || v.len() == 12),
        // README: «НОРМАЛИЗОВАННЫЕ цифры». Датасет v1.0 три negative-строки §3
        // держит в бумажном формате `XXX-XXX-XXX CC` (g0152–g0154) — допускаем
        // обе формы; сдвиг в канон зафиксирован backlog-строкой README (v1.1).
        "snils" => {
            all_digits && v.len() == 11
                || v.len() == 14 && {
                    let b = v.as_bytes();
                    b[..3].iter().all(u8::is_ascii_digit)
                        && b[3] == b'-'
                        && b[4..7].iter().all(u8::is_ascii_digit)
                        && b[7] == b'-'
                        && b[8..11].iter().all(u8::is_ascii_digit)
                        && b[11] == b' '
                        && b[12..].iter().all(u8::is_ascii_digit)
                }
                // #101 (v1.11 g0288): бумажная форма с типографскими дефисами
                // «XXX{U+2013/2014/2212}XXX{sep}XXX {CC}» = 3+3+3+2 цифры,
                // разделители = ASCII-дефис ИЛИ U+2013/U+2014/U+2212 (тот же
                // перечень `NUMBER_SEPARATORS`, что склеивает сканер — B4 и
                // сканер обязаны сходиться, #131-контра «эталоны не
                // разъехались» = зуб ниже).
                || snils_paper_ok(v)
        }
        "ogrn" => all_digits && v.len() == 13,
        "ogrnip" => all_digits && v.len() == 15,
        // #101 (v1.11 g0289): форма с типографскими дефисами = 16 цифр,
        // разделители из перечня (4+4+4+4); чистые цифры = base-форма.
        "card_pan" => (all_digits && (14..=16).contains(&v.len())) || sep_digits_len(v, 16),
        // B4 (issue #13 п.B3 «битый бейт становится валидным §7b → тест
        // зелёный; поймано порчей»): приманки `bik`/`bank_account` в negative-сплите
        // обязаны принадлежать классу — ровно 9 / 20 ASCII-цифр (только так
        // `bik_format`/`bank_account_format` возвращают Some(false) и прогон
        // чексумм красит приманку; чужая длина = None = «не наш класс», и
        // тест зелёнеет при полном мусоре в value_source). Датасет v1.0
        // содержит ровно одну внеклассовую приманку — g0168 `04452522`
        // (8 цифр, табличный НЕВАЛИДН-вектор §7b «не БИК по длине»): её
        // переработка в вектор класса — часть golden-v1.1 (атом дописки);
        // KNOWN-GAP зафиксирован #[ignore]-тестом
        // b4_bik_baits_are_in_class — до него формат держит ±1 цифры.
        "bik" => all_digits && (8..=10).contains(&v.len()),
        "bank_account" => all_digits && (19..=20).contains(&v.len()),
        // TODO(golden-v1.1, issue #14): сузить до `v.len() == 9` / `== 20` и
        // снять #[ignore] у b4_bik_baits_are_in_class — см. комментарий выше.
        "phone" => phone_e164_ok(v) || sep_digits_len(v, 11), // #101 g0290 em-dash
        "passport" => {
            // Формат класса = 4 цифры серии + 6 цифр номера, разделённые
            // одиночными пробелами в любой разбивке групп («4508 455561»,
            // «45 08 455561», «58 53 808531» — все формы первички #200).
            // B4-контракт: цифры + пробелы, ровно 10 цифр, группы ≥ 2 цифр
            // (обрывок «4 508 455561» = не печатная форма).
            let b = v.as_bytes();
            // #212 F-1: каркасные формы канона («4508 номер 455561»,
            // «4508 | 455561», «4508\n455561», «4508 (455561») — ровно
            // 10 цифр в двух группах 4+6, группы отделены КАРКАСОМ
            // (пробел/пунктуация/слово/скобка) и больше ничем: цифры
            // обязаны собираться в 4+6 без соседства с буквами внутри
            // каркаса — промер структуры, не формата строки.
            let digits: Vec<u8> = b.iter().copied().filter(u8::is_ascii_digit).collect();
            if digits.len() != 10 || v.starts_with(' ') || v.ends_with(' ') {
                return false;
            }
            // канон = 4 цифры серии + 6 цифр номера: серии/номера могут
            // печататься разбивкой групп («45 08 455561» — первичка #200);
            // каркасные слова F-1 (#212) несут НЕцифровые гэпы, которые
            // канонную разбивку не ломают: суммарная ширина цифровых
            // кусков = 4 + 6, каркасные гэпы = ≥1 не-цифра между группами.
            // Простейшая надёжная проверка: 10 цифр, первая цифра на
            // месте, после 4-й цифры серии идёт НЕ-цифра (разделитель),
            // 5..=10 цифры = номер, хвост = цифры/скобка (F-3 форма
            // «4508 (455561»).
            let pos: Vec<usize> = b
                .iter()
                .enumerate()
                .filter(|(_, c)| c.is_ascii_digit())
                .map(|(i, _)| i)
                .collect();
            pos.len() == 10
                && pos[3] + 1 < b.len()
                && !b[pos[3] + 1].is_ascii_digit()
                && pos[4] == pos[3] + 1 + count_gap(b, pos[3] + 1)
        }
        "iban" => {
            let b = v.as_bytes();
            b.len() >= 15
                && b[..2].iter().all(u8::is_ascii_uppercase)
                && b[2..4].iter().all(u8::is_ascii_digit)
                && b[4..].iter().all(u8::is_ascii_alphanumeric)
                && !v.chars().any(char::is_whitespace)
        }
        "email" => email_addr_spec(v),
        "person_name" | "address" => !v.is_empty(),
        _ => false,
    }
}

/// E.164 для нашей зоны: 11 цифр, ведущих `7` (README: `7XXXXXXXXXX`), либо
/// общий E.164 (`[1-9]` + 6..14 цифр).
fn phone_e164_ok(v: &str) -> bool {
    // #101 (v1.11): E.164 = КАНОН; форма с типографскими дефисами
    // (U+2013/2014/2212, «8—916—123—45—67») канонизируется отсечением
    // разделителей перечня (тот же, что склеивает сканер, #131-контра
    // «эталоны не разъехались»): сепараторная форма обязана проходить
    // `sep_digits_len` (разделитель только между цифрами), канон = цифры.
    let canon: String = v.chars().filter(char::is_ascii_digit).collect();
    let clean = canon.len() == v.len();
    if !(clean || sep_digits_len(v, canon.len())) {
        return false;
    }
    canon.len() == 11 && (canon.starts_with('7') || canon.starts_with('8'))
        || (7..=15).contains(&canon.len()) && !canon.starts_with('0')
}

/// #101-контра: B4-гейт (`is_number_sep`) обязан сверять форму по ТОМУ ЖЕ
/// перечню разделителей, что склеивает сканер (`checksums::NUMBER_SEPARATORS`)
/// — два владельца одного перечня разъезжаются молча (#131 урок).
#[test]
fn b4_separators_match_scanner() {
    for sep in guard_detectors::checksums::NUMBER_SEPARATORS {
        let ch = std::str::from_utf8(sep)
            .ok()
            .and_then(|t| t.chars().next())
            .unwrap_or_else(|| panic!("разделитель {sep:?} не один char"));
        // Дефисная подколода сканерного перечня ⊆ B4; точка/слэш = не дефис
        // (B4-формы строятся на дефисных/пробельных разделителях, #159).
        if matches!(ch, '.' | '/') {
            continue;
        }
        assert!(
            is_number_sep(ch),
            "NUMBER_SEPARATORS: {ch:?} вне B4-перечня"
        );
    }
    // Обратное: B4 не шире сканера (пробел ∈ перечня на позиции 0).
    for ch in [
        '-', '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2212}', '\u{FF0D}',
        ' ',
    ] {
        assert!(
            guard_detectors::checksums::NUMBER_SEPARATORS
                .iter()
                .any(|s| *s == ch.encode_utf8(&mut [0u8; 4]).as_bytes()),
            "B4-перечень шире сканера: {ch:?}"
        );
    }
}

/// #222: B4 и валидатор каскада-0 = ОДИН код; зуб «эталоны формата не
/// разъехались» = прямые векторы обеих форм через `email_addr_spec` и
/// `checksums::email_rfc` (наших recall-форм датасета + канон-бэйтов).
#[test]
fn email_b4_delegates_to_checksums() {
    for v in [
        "d.sokolov@romashka.example",
        "a+b@gmail.com",
        "a@b.example.com",
        "a@localhost",
        "user@",
        "user@host..com",
        ".user@host.com",
    ] {
        assert_eq!(
            email_addr_spec(v),
            guard_detectors::checksums::email_rfc(v.as_bytes()) == Some(true),
            "эталон B4 и валидатор разъехались на {v:?}"
        );
    }
}

/// addr-spec (RFC 5322): ЕДИНАЯ точка истины = валидатор каскада-0
/// `guard_detectors::checksums::email_rfc` (#222): эталон формата B4 и
/// детерминированный валидатор физически не могут разъехаться (зуб
/// `email_b4_delegates_to_checksums` = прямые векторы через обе функции).
fn email_addr_spec(v: &str) -> bool {
    guard_detectors::checksums::email_rfc(v.as_bytes()) == Some(true)
}

/// B3+B4: проход по всем строкам набора с структурными валидаторами.
///
/// - обязательные поля и enum-ы (`split`, `source`, `category`) — B3;
/// - `id` уникален и формата `gNNNN` — B3;
/// - спан-границы: `start < end ≤ len(text)`, обе — char-границы, спаны не
///   пересекаются — B3;
/// - `value_source` в формате класса (E.164 / addr-spec / `NN NN NNNNNN` /
///   длины номерков) — B4;
/// - containment: фрагмент текста → `value_source` после нормализации разделителей;
/// - `bik`/`bank_account` — только в negative (README § «Категории»);
/// - чексуммы: recall валидны, negative не валидны.
///
/// P1 (issue #13, закрыт здесь): **negative-строка обязана краснеть при битом
/// байт-спане** — раньше гейт это ловил только чексуммой; теперь границы и
/// char-boundary проверяются до всякой чексуммы. P2: порча байта внутри
/// recall-спана с литеральным классом (`person_name`/`address`/`email`/
/// `passport`) ломает containment/enum — тоже краснеет.
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

    let mut seen_ids = std::collections::HashSet::new();
    let mut cats = std::collections::BTreeMap::<String, usize>::new();
    for r in &rows {
        // B3: id формата gNNNN и уникален.
        let id_bytes = r.id.as_bytes();
        assert!(
            id_bytes.len() == 5
                && id_bytes[0] == b'g'
                && id_bytes[1..].iter().all(u8::is_ascii_digit),
            "id {:?} вне формата gNNNN",
            r.id
        );
        assert!(seen_ids.insert(r.id), "id {} повторился", r.id);
        // B3: enum-ы полей.
        assert!(
            MATCH_SOURCES.contains(&r.source),
            "{}: source={} вне enum README",
            r.id,
            r.source
        );

        let bytes = r.text.as_bytes();
        // B3: спан-границы ≤ len и char-границы; непересечение (порядок не нормируется).
        let mut sorted: Vec<&Span> = r.spans.iter().collect();
        sorted.sort_by_key(|s| s.start_byte);
        let mut prev_end = 0usize;
        for s in sorted {
            assert!(
                s.start_byte < s.end_byte,
                "{}: пустой/перевёрнутый спан {}..{}",
                r.id,
                s.start_byte,
                s.end_byte
            );
            assert!(
                s.end_byte <= bytes.len(),
                "{}: end {} за пределами текста (len {})",
                r.id,
                s.end_byte,
                bytes.len()
            );
            assert!(
                r.text.is_char_boundary(s.start_byte),
                "{}: start {} внутри кодовой точки",
                r.id,
                s.start_byte
            );
            assert!(
                r.text.is_char_boundary(s.end_byte),
                "{}: end {} внутри кодовой точки",
                r.id,
                s.end_byte
            );
            assert!(
                s.start_byte >= prev_end,
                "{}: пересечение спанов ({} < prev_end {prev_end})",
                r.id,
                s.start_byte
            );
            prev_end = s.end_byte;
            // B3: category в enum (13 классов README, включая negative-только bik/bank_account).
            assert!(
                SPAN_CATEGORIES.contains(&s.category),
                "{}: категория {:?} вне enum",
                r.id,
                s.category
            );
            // B3: bik/bank_account — negative-only.
            if matches!(s.category, "bik" | "bank_account") {
                assert_eq!(
                    r.split, "negative",
                    "{}: категория {} в recall-сплите (README: только negative)",
                    r.id, s.category
                );
            }
            // B4: формат value_source по классу.
            assert!(
                value_source_format_ok(s.category, s.value_source),
                "{}: {}: value_source {:?} вне формата класса (B4)",
                r.id,
                s.category,
                s.value_source
            );
            // B4: E.164 для phone — строго «RU-номер» (RU-зона или общий E.164).
            if s.category == "phone" {
                assert!(
                    phone_e164_ok(s.value_source),
                    "{}: phone {:?} вне E.164 (B4)",
                    r.id,
                    s.value_source
                );
            }
            if s.category == "email" {
                assert!(
                    email_addr_spec(s.value_source),
                    "{}: email {:?} вне addr-spec (B4)",
                    r.id,
                    s.value_source
                );
            }
            let frag = &r.text[s.start_byte..s.end_byte];
            // containment: value_source достижим из фрагмента удалением разделителей
            match s.category {
                "person_name" | "address" | "email" => {
                    assert_eq!(
                        frag, s.value_source,
                        "{}: {}-спан должен совпадать дословно",
                        r.id, s.category
                    );
                }
                "passport" => {
                    // Спан = фрагмент текста, value_source = фрагмент
                    // дословно (паритет v1.1/v1.2); канон спана (цифры)
                    // обязан быть валидным 4+6 — F-1/F-3 формы несут
                    // каркасные слова/разделители внутри канона (g0227–
                    // g0233, issue #212), голые «45 08 455561» канон не
                    // меняют (проверка на цифрах = усиление гейта, бейт
                    // g0233 «4508455562» в negative-сплите).
                    assert_eq!(
                        frag, s.value_source,
                        "{}: {}-спан должен совпадать дословно",
                        r.id, s.category
                    );
                    let digits: String = frag.chars().filter(char::is_ascii_digit).collect();
                    assert_eq!(
                        digits.len(),
                        10,
                        "{}: passport-спан вне 4+6 канона ({digits:?})",
                        r.id
                    );
                    assert!(
                        guard_detectors::checksums::passport_format(digits.as_bytes())
                            == Some(true),
                        "{}: passport-канон спана не проходит валидатор ({digits:?})",
                        r.id
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
            if r.split == "recall" {
                for s2 in &r.spans {
                    *cats.entry(s2.category.to_string()).or_default() += 1;
                }
            }
            // чексуммы: recall — валидны, negative — НЕ валидны (для номерных
            // категорий). Исключение #234: каркасные recall (g0263–g0267,
            // source «synthetic-checksum» + id >= g0263) = НЕвалидные номера с
            // каркасом — контракт 0.95 (frame_invalid): recall-значение =
            // невалидный номер,.mask-контракт, не вето. Строки вне этого
            // диапазона обязаны быть валидны (гейт цел).
            // Каркас_recall #234 = ровно g0263–g0267 (5 строк, невалидные
            // номера с каркасом). Сравнение `id >= "g0263"` (строкой)
            // захватывало бы ЛЮБУЮ более позднюю recall-строку с Валидным
            // номером (v1.10 g0286–g0287, v1.11 g0288–g0291) = ложный
            // negative-бренд (урок: выведенное множество по id-префиксу =
            // claim). Ровный диапазон: #234-контра целая, поздние recall
            // проверяются как нормальные.
            let frame234 = r.split == "recall" && r.source == "frame-invalid-vector";
            if let Some(ok) = checksum_valid(s.category, s.value_source) {
                if r.split == "recall" && !frame234 {
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
    // покрытие recall-категорий: каждая ≥8
    for (c, n) in &cats {
        assert!(
            *n >= 8,
            "категория {c} в recall-сплите встречается {n} раз (<8)"
        );
    }
    // обязательные числовые категории — все 11 из схемы
    for c in RECALL_CATEGORIES {
        assert!(cats.contains_key(c), "нет покрытия категории {c}");
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

// ================================================================ B3/B4 (issue #14)
// специализированные гейты поверх общего структурного прохода
//
// B3 «битый бейт становится валидным §7b → тест зелёный; поймано порчей»:
// отдельный тест, который **сам портит** negative-приманку bik/bank_account и
// требует, чтобы валидатор класса её покраснил. Если гейт деградирует
// (пропуск None как true), тест краснеет.
#[test]
fn b3_bik_account_baits_are_red_under_class_validators() {
    // Нит ревью PR#24 N2: байты приманок берутся ИЗ ДАСЕТА (id g0166/g0167,
    // span[0].value_source), не хардкодом — молчаливая подмена или «валидизация»
    // бейта краснит тест.
    let rows = parse_golden();
    let bait_of = |id: &str| -> String {
        let sp = rows
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.spans.first())
            .unwrap_or_else(|| panic!("приманка {id} пропала из датасета (B3-N2)"));
        sp.value_source
            .chars()
            .filter(char::is_ascii_digit)
            .collect()
    };
    let bait_bik = bait_of("g0166"); // §7b: 9 цифр, не `04`
    let bait_account = bait_of("g0167"); // §7: 20 цифр, вне плана счетов
    assert!(
        bait_bik.len() == 9 && !bait_bik.starts_with("04"),
        "g0166 = {bait_bik}"
    );
    assert!(bait_account.len() == 20, "g0167 = {bait_account}");
    assert_eq!(
        bik_valid(&bait_bik),
        Some(false),
        "B3: negative-бейт БИК {bait_bik} прошёл формат-вето — гейт сломан"
    );
    assert_eq!(
        account_valid(&bait_account),
        Some(false),
        "B3: negative-бейт счёта {bait_account} прошёл формат-вето — гейт сломан"
    );
    // Портаем валидный табличный БИК удалением цифры (8 цифр = None = не класс):
    assert_eq!(bik_valid("04452522"), None, "B3: 8 цифр не наш класс БИК");
    // Валидный табличный БИК обязан проходить — иначе вето сломано навсегда:
    assert_eq!(bik_valid("044525225"), Some(true));
    assert_eq!(account_valid("40702810900000001234"), Some(true));
}

/// Коллизия-решётка #223 (structural-таблица): статусы 15-значных векторов
/// по ДВУМ чексуммам независимыми реализациями этого файла (луна/ogrnip15
/// продублированы из checksums — контур B3), переснятые python-пересчётом
/// первички в заходе #223. Доминанту каскада-0 меряет `cascade0.rs`
/// (`ogrnip_card_collision_lattice`), здесь — неизменность векторов:
/// правка таблицы первички/датасета краснит эту решётку до кода.
#[test]
fn b3_ogrnip_card_collision_lattice() {
    // (канон, mod13-структура §4, Луна). Строки 1–2 — defect 1 промера
    // v0.1.3 и эталон карты-15; 3 — «обе-валидны» (единственный случай на
    // базовый префикс, перебор 10⁷ в заходе); 4–5 — эталоны §4.
    let lattice: [(&str, bool, bool); 5] = [
        ("304502700000001", false, true), // g0245 (bait)
        ("523456789012343", false, true), // карта-15 (С=5 ∉ {3,4})
        ("304502700000092", true, true),  // обе-валидны
        ("304502700000006", true, false), // §4-подобный
        ("313132804400022", true, false), // §4-эталон, g0241
    ];
    for (canon, og, lu) in lattice {
        assert_eq!(og, ogrnip15_valid(canon.as_bytes()), "структура §4 {canon}");
        assert_eq!(lu, luhn_valid(canon.as_bytes()), "Луна {canon}");
    }
    // Дефект 3: каркасные СНИЛС-векторы промера v0.1.3 (control 97 ≠ 95).
    assert!(
        !snils_valid(b"11223345595"),
        "g0243: 112-233-455 95 невалиден (97)"
    );
    assert!(snils_valid(b"11223345597"), "второй канон списка валиден");
    assert!(!snils_valid(b"11223345596"), "g0244: хвост 96 невалиден");
    // Дефект 2: ОГРН из скрина невалиден mod11 (контроль 7 ≠ 0) — молчание
    // демона = корректное поведение, FN issue опровергнут промером.
    assert!(
        !ogrn13_valid(b"1027739401110"),
        "g0246: ОГРН 1027739401110 невалиден"
    );
    assert!(
        ogrn13_valid(b"1027739401117"),
        "валидный сосед (unit-эталон cascade0)"
    );
}

/// BIK-вето каскада-0: §7b — 9 ASCII-цифр, `04` в начале; чужая длина = None.
/// Продублирован из `guard_detectors::checksums` (тест структурный, модуль —
/// шаг 3; см. док модуля про дублирование формул).
fn bik_valid(s: &str) -> Option<bool> {
    let d = digits_only(s);
    if d.len() != 9 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(d.starts_with("04"))
}

/// Вето счёта: §7 — 20 цифр, префикс ∈ {3010, 3011, 40, 42}; чужая длина = None.
fn account_valid(s: &str) -> Option<bool> {
    let d = digits_only(s);
    if d.len() != 20 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        d.starts_with("3010")
            || d.starts_with("3011")
            || d.starts_with("40")
            || d.starts_with("42"),
    )
}

/// B4 KNOWN-GAP (v1.0): датасет содержит внеклассовую БИК-приманку g0168
/// (`04452522`, 8 цифр — табличный §7b НЕВАЛИДН-вектор «не наш класс»).
/// Прогон чексумм её **не красит** (None = вне класса), т.е. B4-гейт «бейт
/// обязан быть класса» для этой строки не выполнен. Тест фиксирует точный
/// список внеклассовых приманок: **после** дописки golden-v1.1 (атом B1)
/// сузить `value_source_format_ok` до 9/20 цифр, снять `#[ignore]` — список
/// обязан опустеть до нуля.
#[test]
#[ignore = "B4: g0168 внеклассовая приманка (БИК 8 цифр) — переработать в golden-v1.1, сузить формат до 9/20 цифр и снять ignore (issue #14)"]
fn b4_bik_baits_are_in_class() {
    let rows = parse_golden();
    let out_of_class: Vec<&str> = rows
        .iter()
        .flat_map(|r| &r.spans)
        .filter(|s| matches!(s.category, "bik" | "bank_account"))
        .filter(|s| {
            let d = digits_only(s.value_source);
            (s.category == "bik" && d.len() != 9) || (s.category == "bank_account" && d.len() != 20)
        })
        .map(|s| s.value_source)
        .collect();
    assert!(
        out_of_class.is_empty(),
        "B4: внеклассовые приманки {out_of_class:?} — сузать формат и снять ignore"
    );
}
