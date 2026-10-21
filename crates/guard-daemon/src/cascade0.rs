//! Каскад 0 демона: кандидаты → чексуммы схемы → классы на координатах оригинала.
//!
//! Здесь конвейер встречается с `guard-detectors`: модуль **не** переизобретает
//! арифметику проверок (она в `checksums`, эталоны —
//! `data/golden/reference-vectors.tsv`, первичка `docs/dep-verify-algorithms.md`
//! §1–§7), а решает три вещи, которых в детекторах нет:
//!
//! 1. где в тексте вообще искать номер (сканер максимальных прогонов);
//! 2. какие классы схемы этот прогон касается (таблица длин на валидатор);
//! 3. как координаты из нормализованного текста вернуть в оригинал
//!    ([`normalize::OffsetMap`], SPEC §6).
//!
//! # Разделители внутри номерка (закрыто шагом 9, issue #51)
//!
//! `378-312-074 87` — это СНИЛС, и finding-промер (`docs/golden-report.md` §6.2)
//! показал, что на расщеплённых номерах каскад 0 теряет 28 СНИЛС из 29, 15 карт
//! из 15 и 18 IBAN из 21: чексумма требует compact-вид, а в тексте номер
//! напечатан группами.
//!
//! Разделители терпит **детектор**, не нормализатор — по рулингу атома step3a
//! (`guard-detectors/src/normalize.rs`, «Склейки разрывов между цифрами НЕТ»):
//! схлопывание в нормализаторе рождает ложные ИНН/СНИЛС внутри фраз («в 12 часов
//! и 34 минуты» → `1234`) и сдвигает координаты. Здесь же сканер строит окна из
//! групп цифр ([`num_runs`]), валидатор получает канон (группы склеены), а спан
//! остаётся на оригинале: координаты покрывают весь форматированный номер,
//! вместе с разделителями — маскировать надо то, что нашли, а не то, что удобно.
//!
//! Окно обязано быть из **соседних** групп и ограничено по форме: не более
//! [`MAX_WINDOW_GROUPS`] групп и не более [`MAX_GROUP_DIGITS`] цифр в группе.
//! Без этих рамок «1000000000 2000000000» склеилось бы в 20-значный счёт, а
//! «2024 0115 1230 4567» — в карту. Печатные формы номеров, которые мерялись
//! (СНИЛС 3-3-3-2, PAN 4-4-4-4, IBAN группами по 4), в рамки укладываются.
//!
//! IBAN — отдельный сканер ([`iban_tokens`]): у него группы печатаются по 4
//! символа, а у реестровых форм хвост идёт сплошняком (`RU19 0445252254082…`),
//! поэтому группа для него не ограничивается; рамку держат длина и маска страны
//! из реестра плюс mod-97.
//!
//! # Почему окно обязано быть изолированным
//!
//! Прогон цифр, прижатый к латинской букве или цифре (`sha256=7785240858…`),
//! номером не считается: буквенно-цифровая склейка — это хэш/артикул/трек-ид, а
//! не ИНН. Цена правила асимметрична: ложная чексумма даёт вето весом 1.0,
//! которое каскады 1–2 не переспорят (SPEC §2), т.е. masking чужого текста.
//! Кириллица соседом не считается — «ИНН7785240858» без пробела типична для
//! русских документов, а хэшей кириллицей не пишут.

use guard_detectors::checksums;
use guard_detectors::normalize;
use guard_types::{ByteSpan, ClassId, DetectionSource, NewtypeId};

use crate::schema::{KNOWN_VALIDATORS, Schema};

/// Что валидатор требует от окна.
#[derive(Debug, Clone, Copy)]
struct Spec {
    /// Имя валидатора — оно же в [`KNOWN_VALIDATORS`].
    name: &'static str,
    /// Минимальная длина окна в байтах нормы.
    min: usize,
    /// Максимальная длина окна в байтах нормы.
    max: usize,
    /// Кто нашёл (SPEC §2: чексумма РФ vs ЕС).
    source: DetectionSource,
}

/// Таблица длин по именам валидаторов.
///
/// Диапазоны взяты из доков самих функций `checksums.rs`: «`None` — не N
/// ASCII-цифр» у `inn10`/`inn12`/`snils`/`ogrn13`/`ogrnip15` (ровно N), у `luhn`
/// — «не 12..19 ASCII-цифр», у `bank_account_format` — «не 20 ASCII-цифр»;
/// `bik_format` — БИК 9 цифр (§7 той же первички); IBAN — 15..=34 (ISO 13616).
/// `bik_account_cross` в оконном сканере не участвует: это проверка ПАРЫ
/// «БИК + счёт», ей нужен два уже найденных окна (атом B, `cross_checks`).
const DIGIT_SPECS: &[Spec] = &[
    Spec {
        name: "inn10",
        min: 10,
        max: 10,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "inn12",
        min: 12,
        max: 12,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "snils",
        min: 11,
        max: 11,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "ogrn13",
        min: 13,
        max: 13,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "ogrnip15",
        min: 15,
        max: 15,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "luhn",
        min: 12,
        max: 19,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "bik_format",
        min: 9,
        max: 9,
        source: DetectionSource::ChecksumRf,
    },
    Spec {
        name: "bank_account_format",
        min: 20,
        max: 20,
        source: DetectionSource::ChecksumRf,
    },
];

/// IBAN — отдельной константой: окно у него не цифровое (2 буквы, затем 2 цифры
/// и дальше альфанумерики, ISO 13616-1 §2.1). Держать его в срезе цифровых спек
/// значило бы заводить поиск с `expect` на ветку, которая «никогда не пустая».
const IBAN_SPEC: Spec = Spec {
    name: "iban",
    min: 15,
    max: 34,
    source: DetectionSource::ChecksumEu,
};

/// Вызов валидатора по имени — единственное место, где имя из схемы становится
/// вызовом. Неизвестное имя = `None` (схема обязана отвергнуть его на старте,
/// [`crate::schema::SchemaError::UnknownValidator`]).
fn call_validator(name: &str, input: &[u8]) -> Option<bool> {
    match name {
        "inn10" => checksums::inn10(input),
        "inn12" => checksums::inn12(input),
        "snils" => checksums::snils(input),
        "ogrn13" => checksums::ogrn13(input),
        "ogrnip15" => checksums::ogrnip15(input),
        "luhn" => checksums::luhn(input),
        "iban" => checksums::iban(input),
        "bik_format" => checksums::bik_format(input),
        "bank_account_format" => checksums::bank_account_format(input),
        _ => None,
    }
}

/// Подтверждённый валидатором класс на координатах оригинала.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Спан в исходном тексте (байты + символы; инвариант UTF-8 проверен
    /// конструктором [`ByteSpan::new`] внутри карты).
    pub span: ByteSpan,
    /// Класс схемы.
    pub class: ClassId,
    /// Имя подтвердившего валидатора — для `X-Guard-*` и отладки политик.
    pub validator: &'static str,
    /// Кто нашёл.
    pub source: DetectionSource,
}

impl Hit {
    /// Вес детерминированного вето: 1.0 (SPEC §2 каскад 0,
    /// [`DetectionSource::DeterministicW`]).
    #[must_use]
    pub const fn score(&self) -> f64 {
        DetectionSource::DeterministicW
    }
}

/// Прогон каскада 0: нормализация → окна → валидаторы схемы → хиты.
///
/// Хиты отсортированы по `(start, end, class)`: `/v1/analyze` обязан отдавать
/// стабильный JSON на стабильном входе, а перекрывающиеся классы (13 цифр =
/// ОГРН и PAN по Луне одновременно) сохраняются вектором, а не «победителем»
/// (SPEC §8 «векторы классов»).
#[must_use]
pub fn scan(text: &str, schema: &Schema) -> Vec<Hit> {
    let (norm, map) = normalize::normalize(text);
    let bytes = norm.as_bytes();
    let wanted = wanted_validators(schema);
    let mut hits = Vec::new();

    for (start, end) in digit_runs(bytes) {
        let len = end - start;
        for spec in DIGIT_SPECS {
            if len < spec.min || len > spec.max {
                continue;
            }
            if !wanted.iter().any(|(v, _)| *v == spec.name) {
                continue;
            }
            if !isolated(bytes, start, end) {
                continue;
            }
            if call_validator(spec.name, &bytes[start..end]) == Some(true) {
                push_hits(&mut hits, text, &map, start..end, spec, &wanted);
            }
        }
    }

    // Окна из соседних групп цифр: форматированный номер («378-312-074 87»)
    // валидатору отдаётся склейкой, спан остаётся на оригинале.
    for run in num_runs(bytes) {
        // Окно = прогон ЦЕЛИКОМ, внутренних подокон нет. Подокно удваивало бы
        // FP-поверхность: в прогоне «1000 2000 3000 4000 5000 6000» любое
        // 16-значное склеенное окно проходит Луну с вероятностью 1/10, а
        // настоящим номерам в golden хватает целого прогона (170/170 — тест
        // `c0_covers_every_checksum_span_of_recall_split`).
        let (start, end) = (run.groups[0].start, run.groups[run.groups.len() - 1].end);
        if !isolated(bytes, start, end) {
            continue;
        }
        let canon = run.canonical(bytes, 0, run.groups.len());
        let len = canon.len();
        for spec in DIGIT_SPECS {
            if len < spec.min || len > spec.max {
                continue;
            }
            if !wanted.iter().any(|(v, _)| *v == spec.name) {
                continue;
            }
            if call_validator(spec.name, &canon) == Some(true) {
                push_hits(&mut hits, text, &map, start..end, spec, &wanted);
            }
        }
    }

    let ib = &IBAN_SPEC;
    if wanted.iter().any(|(v, _)| *v == ib.name) {
        for (start, end) in iban_tokens(bytes) {
            if !isolated(bytes, start, end) {
                continue;
            }
            // Печатная форма («RU19 0445 2522 …») длиннее канона на разделители:
            // рамку 15..=34 проверяем по канону, спан берём полный.
            let canon = strip_separators(&bytes[start..end]);
            if canon.len() < ib.min || canon.len() > ib.max {
                continue;
            }
            // mod97 считается по верхнему регистру (ISO 13616-1 §2.1); регистр
            // оригинала остаётся в координатах, а не в данных.
            let up: Vec<u8> = canon.iter().map(u8::to_ascii_uppercase).collect();
            if call_validator(ib.name, &up) == Some(true) {
                push_hits(&mut hits, text, &map, start..end, ib, &wanted);
            }
        }
    }

    hits.sort_by(|a, b| {
        (a.span.start, a.span.end, a.class.as_str()).cmp(&(
            b.span.start,
            b.span.end,
            b.class.as_str(),
        ))
    });
    hits.dedup_by(|a, b| {
        a.span.start == b.span.start
            && a.span.end == b.span.end
            && a.class == b.class
            && a.validator == b.validator
    });
    drop_contained(&mut hits);
    hits
}

/// Из вложенных спанов одного класса оставляем самый широкий.
///
/// Нужно окнам форматированных номеров: «2204-9947-4132-9761» даёт и 16-значное
/// окно (вся карта), и 12-значное (`2204-9947-4132` — тоже проходит Луну, у
/// карты диапазон 12..=19). Маскировать надо весь номер: узкое окно внутри
/// широкого того же класса — не отдельная находка, а его часть: оставить его
/// — значит сломать контракт координат (тест `c0_span_of_formatted_number_sits_on_original_text`).
///
/// Пересечение без вложения (два разных номера, частично наехавшие друг на
/// друга) правило не трогает — там обе находки настоящие.
fn drop_contained(hits: &mut Vec<Hit>) {
    let mut keep = vec![true; hits.len()];
    for i in 0..hits.len() {
        for j in 0..hits.len() {
            if i == j || !keep[i] {
                continue;
            }
            let (a, b) = (&hits[i], &hits[j]);
            let same_class = a.class == b.class;
            let inside =
                b.span.start <= a.span.start && b.span.end >= a.span.end && b.span != a.span;
            if same_class && inside {
                keep[i] = false;
            }
        }
    }
    let mut k = 0usize;
    hits.retain(|_| {
        let v = keep[k];
        k += 1;
        v
    });
}

/// Классы схемы, у которых есть валидатор: `(имя, класс)`.
///
/// Только объявленные: молча проверять «всё, что умеем» значило бы возвращать
/// классы, которые оператор выключил из схемы.
fn wanted_validators(schema: &Schema) -> Vec<(&'static str, ClassId)> {
    let mut out = Vec::new();
    let mut add = |id: &str, validators: &[String]| {
        for v in validators {
            if let Some(s) = KNOWN_VALIDATORS.iter().find(|k| *k == v) {
                out.push((*s, ClassId::new(id)));
            }
        }
    };
    for c in &schema.classes {
        add(&c.id, &c.validators);
    }
    for c in &schema.validator_only {
        add(&c.id, &c.validators);
    }
    out
}

/// Максимальные прогоны ASCII-цифр, `[start, end)` в байтах нормы.
fn digit_runs(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        out.push((start, i));
    }
    out
}

/// Разделители, которые сканер терпит **внутри** номера.
///
/// Набор — общий с валидатором ([`checksums::NUMBER_SEPARATORS`]): сканер и
/// канонизация обязаны сходиться, иначе окно строится по одному перечню, а
/// канон режется по другому.
///
/// Перечень узкий намеренно: это то, чем печатают группы номеров. Точка и косая
/// черта в наборе сознательно нет: `12.03.1990` и `19/20` — даты и дроби, а не
/// номер; в golden-наборе промер межцифровых разрывов — одиночные `' '` и `-`
/// (`guard-detectors/src/normalize.rs`, первичная проверка факта).
///
/// В нормализованном тексте все пробельные Zs (включая NBSP U+00A0 и узкий
/// U+202F) уже сведены к U+0020 нормализатором, а из дефисов доживает только
/// широкий U+FF0D — он в списке, потому что нормализатор его не трогает
/// (`normalize::rules_todo`).
/// Потолок групп в прогоне: печатные формы номеров — 4 группы (СНИЛС 3-3-3-2,
/// PAN 4-4-4-4), берём 5 с запасом на ИНН парами («24 82 01 43 38»). Прогон
/// длиннее — это перечисление чисел, а не один номер.
const MAX_WINDOW_GROUPS: usize = 5;

/// Потолок цифр в одной группе: «1000000000 2000000000» — это два числа, а не
/// 20-значный счёт; группы длиннее шести цифр окном не склеиваются.
const MAX_GROUP_DIGITS: usize = 6;

/// Канон номера: те же байты без разделителей ([`sep_len`]).
fn strip_separators(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let s = sep_len(input, i);
        if s == 0 {
            out.push(input[i]);
            i += 1;
        } else {
            i += s;
        }
    }
    out
}

/// Длина разделителя в `bytes[i..]`; 0 — здесь разделителя нет.
fn sep_len(bytes: &[u8], i: usize) -> usize {
    checksums::NUMBER_SEPARATORS
        .iter()
        .find(|s| bytes[i..].starts_with(s))
        .map_or(0, |s| s.len())
}

/// Группа цифр внутри прогона: `[start, end)` в байтах нормы.
#[derive(Debug, Clone, Copy)]
struct Group {
    start: usize,
    end: usize,
}

/// Прогон цифр: подряд идущие группы, разделённые одиночным разделителем.
#[derive(Debug)]
struct Run {
    groups: Vec<Group>,
}

impl Run {
    /// Байты канона окна `[a, b)` — группы склеены, разделители удалены.
    fn canonical(&self, bytes: &[u8], a: usize, b: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for g in &self.groups[a..b] {
            out.extend_from_slice(&bytes[g.start..g.end]);
        }
        out
    }
}

/// Все прогоны цифр с терпимостью к одиночным разделителям между группами.
///
/// Правила разбора:
/// - разделитель признаётся, только если он **между** цифрами: за ним обязана
///   идти цифра, сам он один (двойной пробел завершает прогон);
/// - группа длиннее [`MAX_GROUP_DIGITS`] не входит в прогон: прогон обрывается
///   на предыдущей группе, длинная цепочка цифр остаётся обычным прогоном
///   (её берёт `digit_runs`);
/// - прогон длиннее [`MAX_WINDOW_GROUPS`] групп обрывается: окна из соседних
///   групп всё равно перечисляет `scan`, а бесконечный хвост («2024 0115 1230
///   4567 0000 1111») нам не нужен.
fn num_runs(bytes: &[u8]) -> Vec<Run> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut groups = Vec::new();
        loop {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            groups.push(Group { start, end: i });
            if groups.len() >= MAX_WINDOW_GROUPS {
                break;
            }
            let sep = sep_len(bytes, i);
            if sep == 0 {
                break;
            }
            // Разделитель обязан принадлежать номеру: сразу за ним — цифра.
            // Это же правило отшивает сдвоенный разделитель («1234  5678»):
            // за первым separator'ом стоит второй, а не цифра.
            if i + sep >= bytes.len() || !bytes[i + sep].is_ascii_digit() {
                break;
            }
            i += sep;
        }
        // Последняя группа не обязана быть короткой: «1234567890123 4» — это
        // 13-значный ОГРН + мусор; окном станет префикс, а одиночный длинный
        // прогон как есть берёт `digit_runs`.
        let keep: Vec<Group> = groups
            .iter()
            .take_while(|g| groups.len() == 1 || g.end - g.start <= MAX_GROUP_DIGITS)
            .copied()
            .collect();
        if keep.len() > 1 {
            out.push(Run { groups: keep });
        }
    }
    out
}

/// Токены вида `RRNN…`: две латинские буквы + две цифры + альфанумерики.
fn iban_tokens(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if bytes[i].is_ascii_alphabetic()
            && bytes[i + 1].is_ascii_alphabetic()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            let start = i;
            let mut j = i + 4;
            loop {
                while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                    j += 1;
                }
                let sep = sep_len(bytes, j);
                if sep == 0 {
                    break;
                }
                // Разделитель принадлежит номеру, только если за ним — символ
                // номера: «FR28 2004 …» продолжается, «RU19 0445252254082…»
                // тоже (хвост реестровых форм идёт сплошняком), а «ES86 —
                // оплата» обрывается на дефисе.
                let k = j + sep;
                if k >= bytes.len() || !bytes[k].is_ascii_alphanumeric() {
                    break;
                }
                j = k;
            }
            out.push((start, j));
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Окно изолировано: слева и справа нет латинской буквы/цифры (см. заголовок).
fn isolated(bytes: &[u8], start: usize, end: usize) -> bool {
    let left_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
    let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
    left_ok && right_ok
}

fn push_hits(
    hits: &mut Vec<Hit>,
    text: &str,
    map: &normalize::OffsetMap,
    window: std::ops::Range<usize>,
    spec: &Spec,
    wanted: &[(&'static str, ClassId)],
) {
    let Some(span) = map.map_span_to_original(text, window) else {
        return;
    };
    for (_, class) in wanted.iter().filter(|(v, _)| *v == spec.name) {
        hits.push(Hit {
            span,
            class: class.clone(),
            validator: spec.name,
            source: spec.source,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    fn schema() -> Schema {
        Schema::embedded().expect("канон валиден")
    }

    fn classes(hits: &[Hit]) -> Vec<&str> {
        hits.iter().map(|h| h.class.as_str()).collect()
    }

    #[test]
    fn golden_values_are_found() {
        // Значения и ожидаемые классы — из data/golden/golden-v1.jsonl
        // (категория спана), а не пересчёт нашим валидатором: AGENTS §Дисциплина
        // фактов п.3.
        let cases: [(&str, &str); 6] = [
            ("ИНН 2482014338 выдан", "inn"),
            ("ИНН 825082492964 для контрагента", "inn"),
            ("СНИЛС 65707715421 в реестре", "snils"),
            ("ОГРН 7146617178591 запись", "ogrn"),
            ("ОГРНИП 313777542563312 ИП", "ogrnip"),
            ("карта 4575503590352993 на оплату", "card_pan"),
        ];
        for (text, class) in cases {
            let hits = scan(text, &schema());
            assert!(
                classes(&hits).contains(&class),
                "{text:?} дал {:?}, ждали {class}",
                classes(&hits)
            );
            for h in &hits {
                let slice = h.span.slice(text).unwrap_or_default();
                assert!(!slice.is_empty(), "пустой спан у {class} в {text:?}");
            }
        }
    }

    /// Форматированные номера (шаг 9, issue #51): значение + класс + **полный
    /// спан вместе с разделителями**. Значения взяты из golden-v1.jsonl
    /// (колонка `value_source` — канон, текст строки — форматированная форма)
    /// и из печатных форм реестра IBAN; ожидаемое не пересчитано нашим
    /// валидатором (AGENTS §Дисциплина фактов п.3).
    #[test]
    fn formatted_numbers_are_found_with_full_span() {
        let nbsp = '\u{A0}';
        let hyphen = '\u{2010}';
        let snils_nbsp = format!("СНИЛС 378{nbsp}312{nbsp}074{nbsp}87 в реестре");
        let snils_hyphen = format!("СНИЛС 378{hyphen}312{hyphen}074{hyphen}87 в реестре");
        let cases: Vec<(&str, &str)> = vec![
            ("СНИЛС 378-312-074 87 в реестре", "378-312-074 87"),
            ("СНИЛС 378 312 074 87 в реестре", "378 312 074 87"),
            (&snils_nbsp, "378\u{A0}312\u{A0}074\u{A0}87"),
            (&snils_hyphen, "378\u{2010}312\u{2010}074\u{2010}87"),
            ("карта 2204-9947-4132-9761 на оплату", "2204-9947-4132-9761"),
            ("карта 5534 4114 0127 8976 на оплату", "5534 4114 0127 8976"),
            ("ИНН 24 82 01 43 38 платёжный", "24 82 01 43 38"),
            ("ОГРН 714 66 17 178 591 запись", "714 66 17 178 591"),
            // Печатная форма реестра (колонка «IBAN print format example»,
            // FR14…): группы по 4 символа, в т.ч. буквенная «3M02».
            (
                "расчёт FR14 2004 1010 0505 0001 3M02 606 спасибо",
                "FR14 2004 1010 0505 0001 3M02 606",
            ),
            (
                "расчёт RU19 04452522540820407677025210608 спасибо",
                "RU19 04452522540820407677025210608",
            ),
            (
                "расчёт ES86 25926596771404132872 спасибо",
                "ES86 25926596771404132872",
            ),
            (
                "расчёт ES6987181615681144316009 спасибо",
                "ES6987181615681144316009",
            ),
        ];
        for (text, gold) in cases {
            let hits = scan(text, &schema());
            let found = hits
                .iter()
                .any(|h| h.span.slice(text).unwrap_or_default() == gold);
            assert!(
                found,
                "{text:?}: спан «{gold}» не найден; выпустили {:?}",
                hits.iter()
                    .map(|h| (h.class.as_str(), h.span.slice(text).unwrap_or_default()))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Координаты остаются на оригинале: нормализация свела NBSP к пробелу,
    /// а спан обязан покрывать исходные байты (широкий символ — 2 байта).
    #[test]
    fn formatted_span_maps_back_over_multibyte_separators() {
        let text = "СНИЛС 378\u{A0}312\u{A0}074\u{A0}87 в реестре";
        let hits = scan(text, &schema());
        let gold = "378\u{A0}312\u{A0}074\u{A0}87";
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "snils")
            .unwrap_or_else(|| panic!("СНИЛС с NBSP не найден: {hits:?}"));
        assert_eq!(hit.span.slice(text), Some(gold));
        assert_eq!(
            hit.span.end - hit.span.start,
            gold.len(),
            "ширина спана считается по оригиналу, не по нормализованному тексту"
        );
    }

    /// Толерантность к разделителям не имеет права ослаблять валидатор: для
    /// каждой пары «слитно / группами» вердикт обязан совпадать, а заведомо
    /// невалидный номер — не находиться ни в одной из форм. Пары подобраны по
    /// первичной формуле: для СНИЛС это ветка S >= 101 (188 % 101 = 87 —
    /// золотой вектор, 129 % 101 = 28 — а не 129 % 11 = 8, как считает
    /// популярная веб-формулировка); проверены независимой реализацией на
    /// Python до написания теста.
    #[test]
    fn separators_do_not_weaken_the_validator() {
        let schema = schema();
        let pairs = [
            ("37831207487", "378-312-074 87", "snils", true),
            ("11234567808", "112-345-678 08", "snils", false),
            ("7707083893", "77 07 08 38 93", "inn", true),
            ("7707083894", "77 07 08 38 94", "inn", false),
            ("4575503590352993", "4575 5035 9035 2993", "card_pan", true),
            ("4575503590352994", "4575 5035 9035 2994", "card_pan", false),
        ];
        for (plain, formatted, class, expect) in pairs {
            let hit = |s: &str| {
                scan(s, &schema)
                    .into_iter()
                    .any(|h| h.class.as_str() == class)
            };
            assert_eq!(
                hit(plain),
                expect,
                "слитная форма {class}: ожидалось {expect} для {plain}"
            );
            assert_eq!(
                hit(formatted),
                expect,
                "форма группами {class}: ожидалось {expect} для {formatted}"
            );
        }
    }

    /// Вложенные окна схлопываются в самое широкое: у карты диапазон
    /// 12..=19, и префикс «2204-9947-4132» проходит Луну сам по себе.
    #[test]
    fn nested_windows_collapse_to_the_widest() {
        let text = "карта 2204-9947-4132-9761 на оплату";
        let hits = scan(text, &schema());
        let cards: Vec<&Hit> = hits
            .iter()
            .filter(|h| h.class.as_str() == "card_pan")
            .collect();
        assert_eq!(
            cards.len(),
            1,
            "карта дала несколько вложенных спанов: {cards:?}"
        );
        assert_eq!(
            cards[0].span.slice(text),
            Some("2204-9947-4132-9761"),
            "осталось узкое окно"
        );
    }

    /// Рамки окна (FPS-защита правил «не более 5 групп, не более 6 цифр в
    /// группе, разделитель только между цифрами»). Ожидаемое «ничего» — это
    /// утверждение об отсутствии прохода валидатора, а не о его решении:
    /// значения подобраны так, чтобы склейка давала заведомо невалидные
    /// номера (проверяется отрицанием позитивного случая той же длины).
    #[test]
    fn window_frames_refuse_plain_number_pairs() {
        let cases = [
            // Две десятки: 10 цифр в группе — дальше рамки, склейки нет.
            (
                "платежи 1000000000 2000000000 проведены",
                &["inn", "bank_account"][..],
            ),
            // Сдвоенный разделитель — не номер.
            ("карта 4575  5035 9035 2993 на оплату", &["card_pan"][..]),
            // Разделитель в конце/начале группы — не номер.
            ("карта 4575- 503590352993 на оплату", &["card_pan"][..]),
            // Шесть групп по 4: длиннее прогона номера, это перечисление.
            (
                "артикул 1000 2000 3000 4000 5000 6000 склад",
                &["card_pan", "inn"][..],
            ),
            // Печать даты/времени группами по 4: прогон целиком = 16 цифр,
            // Луна на них не проходит (промер этого захода: 2024011512304567).
            (
                "встреча 2024 0115 1230 4567 подтверждена",
                &["card_pan"][..],
            ),
        ];
        for (text, banned) in cases {
            let hits = scan(text, &schema());
            for b in banned {
                assert!(
                    !classes(&hits).contains(b),
                    "{text:?}: не должно было быть {b}, а выпусили {:?}",
                    classes(&hits)
                );
            }
        }
    }

    #[test]
    #[allow(clippy::float_cmp)] // 1.0 здесь — константа контракта (DeterministicW), не вычисленное число
    fn iban_ru_from_golden_is_found_with_source_eu() {
        // golden-v1.jsonl: RU1904452522540820407677025210608 (iban).
        let text = "расчёт на счёт RU1904452522540820407677025210608, спасибо";
        let hits = scan(text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "iban")
            .expect("RU IBAN из датасета обязан найтись");
        assert_eq!(hit.validator, "iban");
        assert_eq!(
            hit.span.slice(text),
            Some("RU1904452522540820407677025210608")
        );
        assert_eq!(
            hit.source,
            DetectionSource::ChecksumEu,
            "IBAN = чексумма ЕС (SPEC §2)"
        );
        assert_eq!(hit.score(), 1.0, "детерминированное вето");
    }

    #[test]
    fn invalid_vectors_from_reference_table_are_not_hits() {
        // Отрицательные векторы data/golden/reference-vectors.tsv: family=inn10
        // /inn12, expected=invalid (§1, §2 первички).
        for text in [
            "номер 1110005080 в карточке",
            "номер 617547302703 в карточке",
            "номер 7743880976 в карточке",
        ] {
            let hits = scan(text, &schema());
            assert!(
                !classes(&hits).contains(&"inn"),
                "{text:?} дало {:?}, а вектор invalid",
                classes(&hits)
            );
        }
    }

    #[test]
    fn glued_digits_are_not_numbers() {
        // Хэш/артикул: цифры прижаты к латинице — окно не изолировано.
        // Число — валидный ИНН 10 из golden-v1.jsonl, иначе тест проходил бы
        // по причине «чексумма не сошлась», а не по причине склейки.
        assert_eq!(scan("sha256=2482014338abc", &schema()), [] as [Hit; 0]);
        // То же число с пробелами — находится.
        assert!(classes(&scan("sha 2482014338 ok", &schema())).contains(&"inn"));
    }

    #[test]
    fn fullwidth_digits_are_found_at_original_offsets() {
        // Нормализатор кладёт fullwidth-цифры в ASCII; карта обязана вернуть
        // координаты в оригинал (по 3 байта на цифру).
        let text = "ИНН ８２５０８２４９２９６４ уплата"; // scan-lang:allow
        let hits = scan(text, &schema());
        let h = hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .expect("найдётся");
        assert_eq!(
            h.span.slice(text),
            Some("８２５０８２４９２９６４"), // scan-lang:allow
            "спан обязан указывать на исходные широкие цифры"
        );
    }

    #[test]
    fn overlapping_classes_are_a_vector_not_a_winner() {
        // 13 цифр = ОГРН (структурное вето + mod11) и PAN по Луне одновременно:
        // SPEC §8 обещает векторы классов.
        let text = "свидетельство 7146617178591 действительно";
        let hits = scan(text, &schema());
        assert!(classes(&hits).contains(&"ogrn"), "{:?}", classes(&hits));
        assert_eq!(
            hits.iter().filter(|h| h.validator == "ogrn13").count(),
            1,
            "дубликат хита одного валидатора: {hits:?}"
        );
    }

    #[test]
    fn hits_are_sorted_by_offsets() {
        let text = "ИНН 2482014338 и ИНН 2482014338 повтор, СНИЛС 65707715421";
        let hits = scan(text, &schema());
        let mut sorted = hits.clone();
        sorted.sort_by_key(|h| (h.span.start, h.span.end));
        assert_eq!(hits, sorted, "порядок ответа = координатный");
        assert_eq!(
            hits.iter().filter(|h| h.class.as_str() == "inn").count(),
            2,
            "два разных вхождения = два хита"
        );
    }

    #[test]
    fn nothing_to_find_costs_nothing() {
        assert_eq!(scan("", &schema()), [] as [Hit; 0]);
        assert_eq!(scan("нет цифр вовсе", &schema()), [] as [Hit; 0]);
        assert_eq!(scan("---  ---", &schema()), [] as [Hit; 0]);
    }

    #[test]
    fn schema_without_a_class_disables_its_validator() {
        // Оператор вырезал iban из схемы — IBAN в ответе быть не должно, даже
        // когда чексумма проходит.
        let mut s = schema();
        s.validator_only.retain(|c| c.id != "iban");
        let hits = scan("расчёт RU1904452522540820407677025210608", &s);
        assert!(!classes(&hits).contains(&"iban"), "{hits:?}");
    }

    #[test]
    fn every_digit_spec_names_a_known_validator() {
        // Таблица длин и белый список схемы не должны разъехаться.
        for s in DIGIT_SPECS.iter().chain(std::iter::once(&IBAN_SPEC)) {
            assert!(
                KNOWN_VALIDATORS.contains(&s.name),
                "спека {} вне KNOWN_VALIDATORS",
                s.name
            );
            assert!(s.min <= s.max, "{}: перевёрнутый диапазон", s.name);
        }
        assert!(call_validator("нет-такого", b"123").is_none());
    }
}
