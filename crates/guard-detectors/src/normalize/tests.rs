//! Юнит-тесты нормализатора (атом step3a; property-тесты PRNG — `proptests.rs`).
//!
//! Ожидания — из спецификации и промера векторов ВНЕШНЕЙ первичкой (Python
//! `str.encode()` в сессии прогона, не проверяемой функцией; AGENTS
//! §Дисциплина фактов п.3). Падающий assert = зарегистрированный дефект
//! реализации; под фактическое поведение не подгоняем.
//!
//! РУЛИНГ атома step3a (19.10, зафиксирован в доке `normalize.rs`): нормализатор
//! НЕ схлопывает разделители между цифрами (`1- 23` → `1- 23`); толерантность к
//! разрывам — обязанность regex-слоя детектора. Правила: (1) удаление
//! кириллических комбайнинг-марк; (2) удаление zero-width кодов в любой позиции
//! (ZWSP/ZWNJ/ZWJ/BOM); (3) fullwidth-цифры/латиница → ASCII, NBSP/широкие Zs →
//! U+0020 (NFKC-класс); остальное — identity.
//!
//! Семантика карты (инвариант 2): точка перелома — на ГРАНИЦЕ изменённого
//! фрагмента; `map_to_original` обязан возвращать char-границы оригинала для
//! ЛЮБОЙ позиции нормы, включая внутреннюю. Для равноширинных замен (NBSP →
//! пробел) это недостижимо в середине байта (U+00A0 = 2 байта, `' '` = 1):
//! внутренняя позиция такой замены — вне char-границы оригинала по самой
//! природе сужающей замены; тесты ниже фиксируют это разрешённым списком.

use super::*;

/// Инварианты 4+5: пустой вход → пустая карта, identity, `Cow::Borrowed`,
/// `map_to_original` вне диапазона → `None`, без паник.
#[test]
fn identity_empty() {
    let (norm, map) = normalize("");
    assert_eq!(norm.as_ref(), "");
    assert!(map.is_identity());
    assert_eq!(map.normalized_len(), 0);
    assert_eq!(map.original_len(), 0);
    assert_eq!(map.map_to_original(0), Some(0));
    assert_eq!(map.map_to_original(1), None);
    // Ни одного правила — Cow заимствует вход.
    assert!(matches!(norm, Cow::Borrowed(_)));
}

/// Кейс SPEC §9 «рваная кириллица»: `Ж` (U+0416 = D0 96, 2 байта) + U+0487
/// (COMBINING CYRILLIC POKRYTIE = D2 87, 2 байта, Mn) → `Ж`; оригинал 4 байта,
/// норма 2.
#[test]
fn rvanaya_kyrillica() {
    let src = "Ж\u{487}";
    assert_eq!(src.len(), 4, "промер: Ж=D096 (2) + U+0487=D287 (2)");
    let (norm, map) = normalize(src);
    assert_eq!(norm.as_ref(), "Ж");
    assert!(!map.is_identity(), "правило сработало — карта нетождественна");
    assert_eq!(map.normalized_len(), 2);
    assert_eq!(map.original_len(), 4);
    assert_eq!(map.map_to_original(0), Some(0));
    // Терминальный инвариант: конец нормы → конец оригинала (марка внутри).
    assert_eq!(map.map_to_original(2), Some(4));
    // Round-trip: спан всей нормы → весь оригинал, включая съеденную марку.
    assert_eq!(map.original_for(src, 0..2), Some("Ж\u{487}"));
    // Инвариант 2: середина марки (байт 3) НЕ возвращается картой — позиция
    // нормы 1 (середина Ж) обязана маппиться на char-границу (0 или 2),
    // удалённая марка целиком лежит в «невозвратной» зоне.
    assert!(!src.is_char_boundary(3));
    assert!(
        src.is_char_boundary(map.map_to_original(1).unwrap_or(usize::MAX)),
        "инвариант 2: карта вывела на не-границу"
    );
    // Марка в середине слова: «Иван\u{487}» → «Иван», спан всей нормы = весь оригинал.
    let src2 = "\u{418}\u{432}\u{430}\u{43D}\u{487}"; // Иван + Pokrytie
    let (norm2, map2) = normalize(src2);
    assert_eq!(norm2.as_ref(), "\u{418}\u{432}\u{430}\u{43D}");
    assert_eq!(map2.original_for(src2, 0..norm2.len()), Some(src2));
    // U+0483…U+0489 удаляются; U+048A (So, НЕ Mn) остаётся — промер UCD 16.0
    // категории вне дерева (Python unicodedata в сессии).
    let src3 = "\u{410}\u{483}\u{489}\u{48A}";
    let (n3, m3) = normalize(src3);
    assert_eq!(n3.as_ref(), "\u{410}\u{48A}");
    assert_eq!(m3.original_for(src3, 0..n3.len()), Some(src3));
    // Чужие марки не трогаем: U+0301 (острая, латинская зона) и U+20DD (So).
    let (n4, m4) = normalize("12\u{301}x\u{20DD}");
    assert_eq!(n4.as_ref(), "12\u{301}x\u{20DD}");
    assert!(m4.is_identity());
}

/// Правило 2 (рулинг атома): РАЗДЕЛИТЕЛИ МЕЖДУ ЦИФРАМИ НЕ СХЛОПЫВАЮТСЯ
/// (`1- 23` → `1- 23`); срабатывают только удаления zero-width и правила
/// замены. Байтовые промеры — Python `str.encode()`, этот заход.
#[test]
fn tsifry_razryvy() {
    let src = "77 01\u{A0}23-45\u{200B}67_89";
    assert_eq!(src.len(), 20, "промер: 12 цифр + 1 + 2 + 1 + 3 + 1");
    let (norm, map) = normalize(src);
    // NBSP → пробел (NFKC-класс), ZWSP удалён, всё остальное на месте.
    assert_eq!(norm.as_ref(), "77 01 23-4567_89");
    assert_eq!(map.normalized_len(), 16);
    assert_eq!(map.original_len(), 20);
    // Round-trip всей нормы — весь оригинал (съеденные/заменённые внутри).
    assert_eq!(map.original_for(src, 0..16), Some(src));
    // Дефис/подчёркивание между цифрами остаются: `1-2` identity.
    let (n2, m2) = normalize("1-2");
    assert_eq!(n2.as_ref(), "1-2");
    assert!(m2.is_identity());
    // Zero-width удаляются в любой позиции. `1\u{200B}\u{200C}2`: 1+3+3+1 = 8
    // байт → `12`; вся норма → весь оригинал.
    let (n3, m3) = normalize("1\u{200B}\u{200C}2");
    assert_eq!(n3.as_ref(), "12");
    assert!(!m3.is_identity());
    assert_eq!(m3.map_span(0..2), Some((0, 8)));
    // `abc\u{FEFF}def` (9 → 6): «abc» до BOM остаётся на 0..3, «def» сдвигается
    // на 6..9.
    let (n4, m4) = normalize("abc\u{FEFF}def");
    assert_eq!(n4.as_ref(), "abcdef");
    assert_eq!(m4.map_span(0..3), Some((0, 3)));
    assert_eq!(m4.map_span(3..6), Some((6, 9)));
    // NBSP между цифрами → обычный пробел (не удаление!): `1\u{A0}2` → `1 2`,
    // промер: 1 + NBSP(2) + 1 = 4 байта оригинала.
    let (n5, m5) = normalize("1\u{A0}2");
    assert_eq!(n5.as_ref(), "1 2");
    assert_eq!(m5.map_span(0..3), Some((0, 4)));
    // Идемпотентность текста: без склейки второй прогон ничего не находит.
    let (a1, ma) = normalize("1- 23");
    assert_eq!(a1.as_ref(), "1- 23");
    assert!(ma.is_identity());
}

/// Правило 3: fullwidth-цифры/латиница → ASCII (сдвиг 0xFEE0), NBSP/`Zs` →
/// пробел. `７７07083898 Ａｂ` (21 байт) → `7707083898 Ab` (13 байт).
#[test]
fn fullwidth() {
    let src = "\u{FF17}\u{FF17}07083898 \u{FF21}\u{FF42}"; // «７７07083898 Ａｂ»
    assert_eq!(src.len(), 21, "промер: 2×3 + 8 + 1 + 2×3");
    let (norm, map) = normalize(src);
    assert_eq!(norm.as_ref(), "7707083898 Ab");
    assert_eq!(map.normalized_len(), 13);
    assert_eq!(map.map_to_original(0), Some(0));
    assert_eq!(map.map_to_original(13), Some(21));
    // Round-trip всей нормы — весь оригинал.
    assert_eq!(map.original_for(src, 0..13), Some(src));
    // Разделитель НЕ схлопывается: `７ 7` → `7 7` (5→3 байта: 3+1+1 → 1+1+1).
    let (n2, m2) = normalize("\u{FF17} 7");
    assert_eq!(n2.as_ref(), "7 7");
    assert_eq!(n2.len(), 3);
    assert_eq!(m2.map_span(0..3), Some((0, 5)));
    // U+3000 (полноширинный пробел) → U+0020 (3→1 байт).
    let (n3, m3) = normalize("1\u{3000}2");
    assert_eq!(n3.as_ref(), "1 2");
    assert_eq!(m3.map_span(0..3), Some((0, 5)));
}

/// Инвариант 6: идемпотентность через композицию карт. Текстовая идемпотентность
/// строга (правила поточечные), второй прогон — identity; `compose` обязан
/// совпасть с первой картой точка-в-точку; `map2` = последовательный вызов.
#[test]
fn idepotentnost_cherez_map() {
    let (n1, m1) = normalize("１- 2\u{487}"); // fw-цифра, пробелы, кирилл. марка
    assert_eq!(n1.as_ref(), "1- 2");
    assert!(!m1.is_identity());
    let (n2, m2) = normalize(n1.as_ref());
    assert_eq!(n2.as_ref(), "1- 2");
    assert!(m2.is_identity(), "второй прогон по норме обязан быть identity");
    assert_eq!(
        OffsetMap::map2(&m1, &m2, 4),
        m1.map_to_original(4),
        "инвариант 6: map2 = последовательный вызов"
    );
    // Промер первичкой: `１- 2\u{487}` = 3+1+1+1+2 = 8 байт;
    // норма `1- 2` = 4; конец нормы → конец оригинала = 8.
    assert_eq!(OffsetMap::map2(&m1, &m2, 4), Some(8), "конец → конец оригинала");
    // Композиция-объект с identity: len-пара и отображение сохраняются.
    let c = m1.compose(&m2);
    assert_eq!(c.normalized_len(), m1.normalized_len());
    assert_eq!(c.original_len(), m1.original_len());
    for p in 0..=m1.normalized_len() {
        assert_eq!(c.map_to_original(p), m1.map_to_original(p), "p={p}");
    }
    // Композиция двух нетождественных прогонов: `a７\u{200b}b` → `a7b`
    // (промер: 1+3+3+1 = 8 байт).
    let (x1, mx) = normalize("a\u{FF17}\u{200B}b");
    assert_eq!(x1.as_ref(), "a7b");
    let (x2, mxx) = normalize(x1.as_ref());
    assert!(x2.as_ref() == "a7b" && mxx.is_identity());
    assert_eq!(OffsetMap::map2(&mx, &mxx, 3), Some(8));
    assert_eq!(mx.compose(&mxx).map_to_original(3), Some(8));
}
