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
//! # Граница честности: разделители
//!
//! Сканер берёт **непрерывные** последовательности цифр. `378-312-074 87`
//! (СНИЛС с разделителями) он не находит — и не обязан: расщепление групп цифр
//! — это issue #51 («каскад-0: препроцессинг обходов»), а нормализатор каскада 0
//! разрывы между цифрами сознательно не схлопывает (`guard-detectors/src/
//! normalize.rs`, п.4 правил: «РАЗРЫВЫ МЕЖДУ ЦИФРАМИ НЕ СХЛОПЫВАЮТСЯ»). Врать
//! про recall с расщеплёнными номерами мы не будем; мерка — гейт #14 на полном
//! каскаде, его меряет родитель.
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

    let ib = &IBAN_SPEC;
    if wanted.iter().any(|(v, _)| *v == ib.name) {
        for (start, end) in iban_tokens(bytes) {
            let len = end - start;
            if len < ib.min || len > ib.max {
                continue;
            }
            if !isolated(bytes, start, end) {
                continue;
            }
            // mod97 считается по верхнему регистру (ISO 13616-1 §2.1); регистр
            // оригинала остаётся в координатах, а не в данных.
            let up: Vec<u8> = bytes[start..end]
                .iter()
                .map(u8::to_ascii_uppercase)
                .collect();
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
    hits
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
            while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                j += 1;
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
        assert!(scan("sha256=2482014338abc", &schema()).is_empty());
        // То же число с пробелами — находится.
        assert!(classes(&scan("sha 2482014338 ok", &schema())).contains(&"inn"));
    }

    #[test]
    fn fullwidth_digits_are_found_at_original_offsets() {
        // Нормализатор кладёт fullwidth-цифры в ASCII; карта обязана вернуть
        // координаты в оригинал (по 3 байта на цифру).
        let text = "ИНН ８２５０８２４９２９６４ уплата";
        let hits = scan(text, &schema());
        let h = hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .expect("найдётся");
        assert_eq!(
            h.span.slice(text),
            Some("８２５０８２４９２９６４"),
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
        assert!(scan("", &schema()).is_empty());
        assert!(scan("нет цифр вовсе", &schema()).is_empty());
        assert!(scan("---  ---", &schema()).is_empty());
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
