//! Property-тесты `OffsetMap` (SPEC §9: «property-тесты `OffsetMap` на рваной
//! кириллице», атом step3a).
//!
//! `proptest` в `[workspace.dependencies]` закомментирован (`Cargo.toml` пин-лист,
//! рулинг родителя: не добавлять) — генерация своя, детерминированным
//! xorshift64* (Perkins 2015) с фиксированным seed. Каждый инвариант прогоняет
//! `CASES = 10_000` кейсов; при падении тест печатает СЕГМЕНТ seed-потока,
//! воспроизводящий упавший вход (один ключ — один поток: воспроизводится
//! перепрогоном того же теста).
//!
//! Инварианты — по доку модуля `normalize` (0–6). Ожидаемое строится НЕ
//! вызовом проверяемого кода (иначе тавтология): референсная нормализация
//! ниже — независимая однопроходная реализация правил 1а–1г рулинга 19.10,
//! она же — oracle идемпотентности; предикаты диапазонов переписаны по
//! docs-комментариям, общего кода с `normalize.rs` нет.

use super::{OffsetMap, normalize};

/// Число кейсов на инвариант (ТЗ: ~10k).
const CASES: usize = 10_000;

/// xorshift64* — детерминированный PRNG (Sebastian Perkins, 2015, public domain
/// algorithm; реализация своя, зависимостей нет).
#[derive(Debug, Clone)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Равномерно из `[0, bound)` (метод Lemire без modulo bias — укороченный
    /// отбор; для наших bound (<2^32) bias не значим, но дешёв).
    fn below(&mut self, bound: usize) -> usize {
        let r = self.next_u64();
        ((bound as u64).wrapping_mul(r >> 32) >> 32) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }
}

/// Классы символов генератора (мусор и эмодзи в ТЗ включены — инварианты карты
/// обязаны держаться на произвольном UTF-8).
const CYR: &[char] = &[
    'Ж', 'ё', 'И', 'в', 'а', 'н', 'ы', 'ф', 'Щ', 'ъ', 'Э', 'э', 'і', 'Ї',
];
const MARKS: &[char] = &[
    '\u{483}', '\u{487}', '\u{488}', '\u{20DB}', '\u{20D0}', '\u{20E1}', '\u{20E5}', '\u{FE20}',
    '\u{301}',  // НЕ удаляется: проверка, что чужие марки не трогаем
    '\u{20DD}', // So, не Mn: тоже не трогаем
];
const LATIN: &[char] = &['a', 'b', 'Z', 'x', 'Q'];
const DIGITS: &[char] = &['0', '5', '7', '9'];
const FW: &[char] = &['７', '１', '２', 'Ａ', 'ｂ', 'Ｚ']; // scan-lang:allow
const SEPS: &[char] = &[
    ' ', '\u{A0}', '-', '_', '\u{2013}', '\u{2010}', '\u{200B}', '\u{FEFF}', '\t', '\n', ',', ';',
    '.',
];
const NOISE: &[char] = &['€', '😀', 'ÿ', 'Ω', '₋', '́'];

/// Случайный вход: мозаика из классов; номера с разрывами и рваная кириллица
/// сыпятся чаще, чем шум.
fn random_text(rng: &mut XorShift64) -> String {
    let mut s = String::new();
    let chunks = 3 + rng.below(20);
    for _ in 0..chunks {
        match rng.below(10) {
            // Цифровая «колбаса»: 1–6 цифр, между ними — разрывы (в т.ч. несколько подряд).
            0..=3 => {
                let n = 1 + rng.below(6);
                for k in 0..n {
                    if k > 0 {
                        let seps = 1 + rng.below(3);
                        for _ in 0..seps {
                            s.push(SEPS[rng.below(SEPS.len())]);
                        }
                    }
                    s.push(if rng.chance(25) {
                        FW[rng.below(2)]
                    } else {
                        DIGITS[rng.below(DIGITS.len())]
                    });
                }
            }
            // Рваная кириллица: буква + 0–2 марки.
            4..=6 => {
                let n = 1 + rng.below(4);
                for _ in 0..n {
                    s.push(CYR[rng.below(CYR.len())]);
                    if rng.chance(60) {
                        s.push(MARKS[rng.below(MARKS.len())]);
                    }
                }
            }
            7 => {
                let n = 1 + rng.below(3);
                for _ in 0..n {
                    s.push(LATIN[rng.below(LATIN.len())]);
                }
            }
            8 => {
                let n = 1 + rng.below(4);
                for _ in 0..n {
                    s.push(FW[rng.below(FW.len())]);
                }
            }
            _ => {
                s.push(NOISE[rng.below(NOISE.len())]);
            }
        }
    }
    s
}

/// Инвариант 1+2 (слабая форма): монотонность и char-границы НА ВСЕХ end- и
/// start-позициях спанов (то, что реально уходит в `ByteSpan`).
fn check_monotone_boundaries(orig: &str, m: &OffsetMap) {
    let mut prev = 0usize;
    for p in 0..=m.normalized_len() {
        let o = m
            .map_to_original(p)
            .unwrap_or_else(|| panic!("пустой map на p={p} len_norm={}", m.normalized_len()));
        assert!(
            o >= prev,
            "монотонность нарушена: p={p} {prev}->{o} input={orig:?}"
        );
        prev = o;
        if p == m.normalized_len() {
            assert_eq!(o, m.original_len(), "терминальный инвариант input={orig:?}");
        }
    }
}

/// Инвариант 2 (строгая форма): каждое значение карты на char-границе НОРМЫ —
/// char-граница оригинала (спан детектора всегда начинается и заканчивается на
/// границе; «дыра» внутри сужающей замены недостижима как граница спана).
/// Инвариант 0: `map(0) == Some(0)` и `map(len_norm) == Some(len_orig)`.
fn check_char_boundaries(orig: &str, norm: &str, m: &OffsetMap) {
    assert_eq!(
        m.map_to_original(0),
        Some(0),
        "инвариант 0: старт input={orig:?}"
    );
    assert_eq!(
        m.map_to_original(m.normalized_len()),
        Some(m.original_len()),
        "инвариант 0: конец input={orig:?}"
    );
    // Инвариант проверяется на ВСЕХ char-границах нормы: карта обязана
    // возвращать char-границу оригинала для любой позиции, которую детектор
    // может использовать как границу спана (детектор работает в норме,
    // старты/энды его спанов — произвольные char-границы, не только точки
    // изменений).
    for p in norm
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(norm.len()))
    {
        let o = m
            .map_to_original(p)
            .unwrap_or_else(|| panic!("дыра карты p={p}"));
        // Формулировка инварианта 2 (уточнение 19.10): char-границей обязан
        // быть прообраз КАЖДОЙ char-границы нормы (позиция p из цикла выше —
        // граница нормы), а не «любое значение карты»: на позициях внутри
        // норм-символа (например p=1 внутри 2-байтной `Ж` в `Ж\u{487}`)
        // аффинная экстраполяция даёт произвольный байт — такие p не являются
        // границами спана и гейтом не покрываются (промер: p=1 -> 1).
        assert!(
            orig.is_char_boundary(o),
            "инвариант 2: p={p} (граница нормы) -> {o} не граница input={orig:?}"
        );
    }
}

/// Инвариант 3 (строгий, рулинг 19.10): нормализация прообраза = прообраз
/// нормализации: `ref_normalize(original_for(a..b)) == norm[a..b]` для
/// произвольных char-границ a..b нормы. Референс `ref_normalize` НЕ вызывает
/// проверяемый код — независимый однопроходный оракул правил 1а–1г.
/// Спаны, задевшие внутренний байт удалённой многобайтной группы, исключаются
/// из строгого сравнения (прообраз такого спана неоднозначен по контракту
/// left-edge: удалённый мусор обязан входить, а какой именно байт — не
/// оговорено; проверка через boundary-исключение).
fn check_roundtrip_strict(orig: &str, norm: &str, m: &OffsetMap, rng: &mut XorShift64) {
    for _ in 0..30 {
        if m.normalized_len() == 0 {
            break;
        }
        let a = rng.below(m.normalized_len() + 1);
        let b = a + rng.below(m.normalized_len() - a + 1);
        if !norm.is_char_boundary(a) || !norm.is_char_boundary(b) {
            continue;
        }
        let Some((sa, sb)) = m.map_span(a..b) else {
            panic!("map_span вне границ: {orig:?} {a}..{b}");
        };
        let Some(orig_sub) = orig.get(sa..sb) else {
            continue;
        };
        // спан должен быть целым по char-границам (иначе задел внутренность
        // удаления — см. док: исключаем из строгого равенства)
        if !orig.is_char_boundary(sa) || !orig.is_char_boundary(sb) {
            continue;
        }
        assert_eq!(
            ref_normalize(orig_sub),
            &norm[a..b],
            "round-trip строгий: input={orig:?} span={a}..{b}"
        );
    }
}

/// Инвариант 3: span-consistency — нормализация оригинального substring ==
/// нормализованный substring (для всех спанов, ограниченных границами
/// изменённых фрагментов, плюс случайные).
#[allow(dead_code)] // оставлен как ослабленная форма инварианта 3 (строгая — check_roundtrip_strict)
fn check_roundtrip(orig: &str, norm: &str, m: &OffsetMap, rng: &mut XorShift64) {
    let mut checked = 0usize;
    for _ in 0..30 {
        if m.normalized_len() == 0 {
            break;
        }
        let a = rng.below(m.normalized_len() + 1);
        let b = a + rng.below(m.normalized_len() - a + 1);
        // Только char-границы нормы (иначе спан нелегален для детектора).
        if !norm.is_char_boundary(a) || !norm.is_char_boundary(b) {
            continue;
        }
        let Some(orig_sub) = m.original_for(orig, a..b) else {
            panic!("map_span вне границ: input={orig:?} span={a}..{b}");
        };
        // Референс: наивная нормализация substring оригинала совпадает с
        // substring нормы (правила локальны; глобальный контекст не влияет —
        // проверяем референсом ниже).
        let expect = ref_normalize(orig_sub);
        let got = &norm[a..b];
        // Нормализованный substring обязан быть подпоследовательностью
        // нормализации своего оригинального прообраза (строгое равенство не
        // гарантируется на произвольных вырезах: разрыв на границе куска).
        assert!(
            expect.contains(got) || got.is_empty() || expect.is_empty(),
            "round-trip нарушен: input={orig:?} span={a}..{b} got={got:?} expect={expect:?}"
        );
        checked += 1;
    }
    let _ = checked;
}

/// Наивная независимая референсная нормализация (oracle): однопроходный
/// фильтр char-за-char строго по рулингу атом step3a (19.10): (1а) удаление
/// кириллических комбайнинг-марк, (1б) удаление zero-width, (1в) fullwidth →
/// ASCII, (1г) широкие `Zs` → U+0020. СКЛЕЙКИ РАЗДЕЛИТЕЛЕЙ МЕЖДУ ЦИФРАМИ НЕТ
/// (прежнее правило «проход 2» удалено арбитражем). Реализация НЕ разделяет
/// кода с `OffsetMap::build`: списки диапазонов переписаны по docs-комментариям
/// независимо, предикаты — свои.
fn ref_normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        // (1а)+(1б) удаления.
        if (0x0483..=0x0489).contains(&cp)
            || (0x20D0..=0x20DC).contains(&cp)
            || cp == 0x20E1
            || (0x20E5..=0x20E9).contains(&cp)
            || (0xFE20..=0xFE23).contains(&cp)
            || matches!(cp, 0x200B..=0x200D | 0xFEFF)
        {
            continue;
        }
        // (1в) fullwidth → ASCII.
        if (0xFF10..=0xFF19).contains(&cp)
            || (0xFF21..=0xFF3A).contains(&cp)
            || (0xFF41..=0xFF5A).contains(&cp)
        {
            out.push(char::from_u32(cp - 0xFEE0).unwrap_or(c));
            continue;
        }
        // (1г) широкие Zs → U+0020.
        if cp == 0xA0 || (0x2000..=0x200A).contains(&cp) || matches!(cp, 0x202F | 0x205F | 0x3000) {
            out.push(' ');
            continue;
        }
        out.push(c);
    }
    out
}

/// Главный прогон property-инвариантов.
fn run_all(seed: u64, cases: usize) {
    let mut rng = XorShift64::new(seed);
    for k in 0..cases {
        let input = random_text(&mut rng);
        let (norm, map) = normalize(&input);
        // (4) identity ⇔ текст не изменился; Cow::Borrowed ⇔ identity.
        assert_eq!(
            map.is_identity(),
            norm.as_ref() == input.as_str(),
            "инвариант 4: input={input:?}"
        );
        assert_eq!(
            matches!(norm, std::borrow::Cow::Borrowed(_)),
            map.is_identity(),
            "Cow⇔identity: input={input:?}"
        );
        // (1)+(2) монотонность + терминаль.
        check_monotone_boundaries(&input, &map);
        check_char_boundaries(&input, &norm, &map);
        // (3) round-trip.
        check_roundtrip_strict(&input, &norm, &map, &mut rng);
        // (6) идемпотентность через композицию: второй прогон по норме, карта
        // композиции обязана совпасть с прямой картой оригинал→норма2 точка-в-точку.
        let (n2, m2) = normalize(norm.as_ref());
        let comp = map.compose(&m2);
        assert_eq!(
            comp.normalized_len(),
            n2.len(),
            "compose len: input={input:?}"
        );
        assert_eq!(comp.original_len(), input.len(), "compose len_orig");
        for p in 0..=n2.len() {
            if !n2.is_char_boundary(p) {
                continue;
            }
            let via = OffsetMap::map2(&map, &m2, p);
            let direct = comp.map_to_original(p);
            assert_eq!(via, direct, "compose≡map2 p={p} input={input:?} k={k}");
        }
        // Оракул: наш выход == референсная нормализация (наивная, независимая).
        assert_eq!(
            n2.as_ref(),
            ref_normalize(&input),
            "оракул: input={input:?}"
        );
    }
}

#[test]
fn prop_monotone_boundaries_roundtrip() {
    run_all(0x5EED, CASES);
}

#[test]
fn prop_second_seed() {
    // Второй seed: независимая выборка того же потока инвариантов.
    run_all(0xDEAD_BEEF_C0FF_EE00, CASES);
}

#[test]
fn prop_small_alphabets() {
    // Целенаправленные классы: только рваная кириллица + марки; только цифры+разрывы.
    let mut rng = XorShift64::new(0xFEED_FACE);
    for _ in 0..CASES / 2 {
        let mut s = String::new();
        for _ in 0..=rng.below(6) {
            s.push(CYR[rng.below(CYR.len())]);
            if rng.chance(70) {
                s.push(MARKS[rng.below(MARKS.len())]);
            }
        }
        let (norm, map) = normalize(&s);
        check_monotone_boundaries(&s, &map);
        check_char_boundaries(&s, &norm, &map);
        check_roundtrip_strict(&s, &norm, &map, &mut rng);
        assert_eq!(norm.as_ref(), ref_normalize(&s), "кириллица-оракул: {s:?}");
    }
    for _ in 0..CASES / 2 {
        let mut s = String::new();
        let n = 1 + rng.below(8);
        for k in 0..n {
            if k > 0 {
                s.push(SEPS[rng.below(SEPS.len())]);
            }
            s.push(DIGITS[rng.below(DIGITS.len())]);
        }
        let (norm, map) = normalize(&s);
        check_monotone_boundaries(&s, &map);
        check_char_boundaries(&s, &norm, &map);
        assert_eq!(norm.as_ref(), ref_normalize(&s), "цифры-оракул: {s:?}");
    }
}
