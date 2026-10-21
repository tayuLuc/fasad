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
//! # Разделители внутри номерка (закрыто шагом 9, PR #80)
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
//!
//! # Base64-обход (PR #94)
//!
//! Запрос может нести `ПДн` внутри base64-blob: поле интеграции приезжает как
//! `base64(ИНН)`, лог — как `base64(карты)`. Обход закрыт одним проходом
//! ([`scan_base64`]), правила такие:
//!
//! 1. **кандидат** = токен алфавита base64, ограниченный пробелом с обеих
//!    сторон (в нормализованном тексте все Zs уже сведены к U+0020), длина
//!    кратна 4, `=` только хвостом, полезная нагрузка ≥
//!    [`B64_MIN_PAYLOAD_BYTES`] байт;
//! 2. **алфавит** принимаем оба: standard (`+/`) и url-safe (`-_`). Смешанный
//!    токен (`+` рядом с `_`) кандидатом не считается: один эмитент даёт один
//!    алфавит, смесь — это текст с дефисами, а не base64 (промер на JWT:
//!    `a.b.c` распадается на сегменты, ни один не стоит на пробельной границе);
//! 3. **спан** кредитзуется на **исходный токен**: vault меняет текст по
//!    координатам оригинала, а декодированные координаты наружу не показываются
//!    (их нет в ответе вообще — SPEC §8 отдаёт только оригинальные);
//! 4. **вложенность ровно один уровень**: нагрузку мы ведём окном по байтам,
//!    но кандидатов в ней не ищем — `base64(base64(ИНН))` не раскручивается.
//!    Рекурсивный декод — это неограниченный CPU на вражеском входе и
//!    FP-поверхность на каждом уровне;
//! 5. **FP-контроль**: анти-паттерн «decode и верь» отшит тем, что спан
//!    появляется **только** если окно в нагрузке подтвердил чексумменный
//!    валидатор схемы. Случайные 16 байт, JWT-сегменты и base64 utf-8 текста
//!    без цифр спанов не дают (юниты `base64_negative_*`).
//! 6. **фильтр «в нагрузке есть цифра» стоит ПОСЛЕ нормализации**, а не на
//!    сырых байтах декода: полноширинные цифры `U+FF10…U+FF19` ASCII-цифрами в
//!    байтах не являются, и до правки ревью #94 (F-1) такой токен терялся, хотя
//!    тем же текстом находился. Пара «тот же вход текстом / тот же вход
//!    токеном» — `base64_fullwidth_digits_match_the_text_path`; цена порядка —
//!    нормализация каждого кандидата, она меряется микромерой
//!    `base64_bypass_hot_path_microbench` (цена на безцифровой заливке —
//!    промер `REVIEW94|fill_100KiB`).
//!
//! Окно в нагрузке ищет тот же слой, что и в тексте ([`validated_windows`]),
//! поэтому перемычки внутри декодированного («044 525 …») ловит тот же
//! нормализатор и те же окна групп, что и в открытом тексте.
//!
//! Поле `source` у такой находки — [`DetectionSource::Base64Decode`]
//! (JSON `base64_decode`), а не `checksum_*`: вес остаётся абсолютным вето 1.0
//! (подтверждение то же — чексумма), но происхождение спана видно и политике,
//! и человеку в `/ui`.
//!
//! # Числительные словами (атом #51 п.2)
//!
//! Диктуя номер, человек пишет число словами: «восемьсот двадцать пять
//! миллиардов …» для цифрового окна — не номер, и каскад 0 такого не видел
//! ([`crate::numwords`] собирает из слов цифры; покрытие и границы слоя — в
//! заголовке того модуля). Кредитация — ровно тот же контур, что у
//! base64-атома: [`validated_windows`] по собранным цифрам, спан — на
//! исходную фразу словами ([`push_hits`], координаты через
//! [`normalize::OffsetMap`]).
//!
//! 1. **Исходник — нормализованный текст, один уровень**: числительные внутри
//!    base64-нагрузки не ищем (паритет с `base64_nesting_is_exactly_one_level`).
//! 2. **FP-контроль общий для всех обходов**: спан появляется только если
//!    собранное число подтвердил чексумменный валидатор схемы. Слово-число само
//!    по себе спана не создаёт — «сто рублей», «пятьдесят процентов» тихие.
//! 3. **Порог длины** [`MIN_SPELLED_DIGITS`] = самая короткая сущность
//!    [`DIGIT_SPECS`] (9 цифр, `bik_format`): короткие числа в цикл валидаторов
//!    не едут вовсе. Он же — «guard года»: четыре цифры года словами
//!    («тысяча девятьсот семьдесят один» = 1971) подтвердить некому, спана нет
//!    (регрессии `year_in_words_is_not_a_hit`,
//!    `spelled_floor_is_the_shortest_digit_spec`).
//! 4. **`source` остаётся `checksum_*`** — нового варианта `DetectionSource`
//!    атом не заводит. Доказательство то же (чексумма), вес то же (вето 1.0), а
//!    происхождение спана видно по самому спану: его срез — слова, в отличие от
//!    base64, где срез токена ничего не говорит. Восьмой вариант источника =
//!    правка вектора весов SPEC §2, а это контракт
//!    `guard-types/tests/invariant_checksum_w.rs` — не уровень атома.

use base64::Engine as _;
use guard_detectors::checksums;
use guard_detectors::normalize;
use guard_types::{ByteSpan, ClassId, DetectionSource, NewtypeId};
use zeroize::Zeroizing;

use crate::numwords;
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

/// Минимальная длина числа, собранного из слов ([`crate::numwords`]).
///
/// Равна самой короткой сущности в [`DIGIT_SPECS`] (9 цифр — `bik_format`):
/// окну короче нечем подтверждаться, и в цикл валидаторов оно не едет. Это же
/// «guard года»: год словами (1971) — четыре цифры, спана не будет ни при
/// каком совпадении. Константу сверяет с таблицей тест
/// `spelled_floor_is_the_shortest_digit_spec` (живая связь: добавят валидатор
/// короче девяти цифр — тест покраснеет и напомнит про годы словами).
const MIN_SPELLED_DIGITS: usize = 9;

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
    scan_with(text, schema, true)
}

/// Ядро [`scan`]; `with_base64 = false` выключает обход (PR #94).
///
/// Параметр не публичный API, а рычаг замера: нога «до» в
/// `base64_bypass_hot_path_microbench` обязана считать ровно тот код, что был
/// на базе, в том же бинаре. Два бинаря из двух деревьев несравнимы: вклад
/// сборки в них разный, а у двух прогонов одного кода различается ровно тот
/// проход, который добавлен.
///
/// Проход числительных словами ([`scan_words`], атом #51 п.2) отдельного рычага
/// не заводит: он есть в обеих ногах base64-замера, дельта от этого не
/// меняется. Цену самого прохода меряет `words_hot_path_microbench`: корпус он
/// строит сам (как `b64_corpus` у base64), и на русской прозе без числительных
/// слой обязан стоить доли миллисекунды (префильтр кириллицы + словарь).
fn scan_with(text: &str, schema: &Schema, with_base64: bool) -> Vec<Hit> {
    let (norm, map) = normalize::normalize(text);
    let bytes = norm.as_bytes();
    let wanted = wanted_validators(schema);
    let mut hits = Vec::new();

    for w in validated_windows(bytes, &wanted) {
        push_hits(&mut hits, text, &map, w.range, w.spec, &wanted);
    }

    scan_words(text, &norm, &map, &wanted, &mut hits);

    if with_base64 {
        scan_base64(text, bytes, &map, &wanted, &mut hits);
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

/// Подтверждённое валидатором окно в координатах того буфера, по которому
/// гоняли (`range`), плюс спецификация, которая подтвердила.
struct Window {
    range: std::ops::Range<usize>,
    spec: &'static Spec,
}

/// Три прогона каскада-0 по байтам: сплошные прогоны цифр, окна групп цифр и
/// IBAN-токены — всё, что доверяется чексумме схемы, и только это.
///
/// Слой отделин от `scan` ради base64-обхода: тот же код окон обязан бегать и
/// по нормализованному тексту, и по декодированной нагрузке, а различаются
/// вызывающие только тем, **куда** кредитовать найденное окно (карта
/// координат vs спан исходного токена).
fn validated_windows(bytes: &[u8], wanted: &[(&'static str, ClassId)]) -> Vec<Window> {
    let mut out = Vec::new();

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
                out.push(Window {
                    range: start..end,
                    spec,
                });
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
        //
        // Рамка ведущей группы, рекурсивная (#138, ревью d6a34d2d): окно
        // начинается с первой группы полной ширины [`MIN_LEADING_GROUP_DIGITS`]
        // — ведущие группы-нумерация (длина 1) в окно и в канон не входят.
        // Склейка ведущей цифры с хвостом рождала **канон-суффикс**, и
        // валидатор проходил ровно его, а не форму из текста; суффикс
        // суффикса («код 1.0.0000.0000.0000» → хвост «0.0000.0000.0000» с
        // ведущим «0») режется этой же рамкой. Спан и канон считаются по
        // одному окну — спан всегда отвечает канону, которому поверил
        // валидатор (на base-прогоне без ведущих единиц [first..] = весь
        // прогон, поведение интактное). `first < groups.len()`: последняя
        // группа прогона ведущей рамке не противостоит — прогон из одной
        // группы окном не становится (`keep.len() > 1` в [`num_runs`]).
        let first = run
            .groups
            .iter()
            .position(|g| g.end - g.start >= MIN_LEADING_GROUP_DIGITS)
            .unwrap_or(0);
        let (start, end) = (run.groups[first].start, run.groups[run.groups.len() - 1].end);
        if !isolated(bytes, start, end) {
            continue;
        }
        let canon = run.canonical(bytes, first, run.groups.len());
        let len = canon.len();
        for spec in DIGIT_SPECS {
            if len < spec.min || len > spec.max {
                continue;
            }
            if !wanted.iter().any(|(v, _)| *v == spec.name) {
                continue;
            }
            if call_validator(spec.name, &canon) == Some(true) {
                out.push(Window {
                    range: start..end,
                    spec,
                });
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
                out.push(Window {
                    range: start..end,
                    spec: ib,
                });
            }
        }
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
/// Точка и косая черта (#131, word-break): печатная форма карты («4575.5035.
/// 9035.2993»), счёта и IBAN («RU03.0445.2522…», «12/345/678/901») терпят их,
/// и промер живьём на head показал FN-класс (slash/dot → none при валидном
/// целом). FP-защита — контекст: [`num_runs`] вставляет разделитель только
/// **между цифрами одного прогона** (сдвоенный, ведущий и хвостовой
/// отшиты), а точка дополнительно ограничена структурным вето
/// [`checksums::dot_glues_number`]: календарь, время, десятичная и версии
/// («12.03.1990», «12.30», «04.3», «1.2.4») точкой не склеиваются; равные
/// группы 2+2 — только календарь, попарная ИНН-форма локально от него
/// неотличима и упирается в рамку #102. Косая черта вето не нужна: «19/20»
/// — 2+2 цифры, это ниже минимального валидатора (9 цифр — самая короткая
/// сущность `DIGIT_SPECS`), склейка дроби ничем не подтверждается и спана
/// не даёт (промер «19/20» = none, живьём, на этом head).
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
///
/// Чистый перечень ([`checksums::NUMBER_SEPARATORS`]) — без контекстного
/// вето: его читают IBAN-прогон ([`iban_tokens`]) и канонизация
/// ([`strip_separators`]), где точка — печатный разделитель IBAN и вето на
/// «три цифры» было бы произволом (печатная форма IBAN — группы по 4).
/// Цифровые окна ([`num_runs`]) обязаны применять
/// [`sep_len_number`] — там точка без вето рождает FP на датах.
fn sep_len(bytes: &[u8], i: usize) -> usize {
    checksums::NUMBER_SEPARATORS
        .iter()
        .find(|s| bytes[i..].starts_with(s))
        .map_or(0, |s| s.len())
}


/// [`sep_len`] с FP-вето для цифровых окон. Две рамки, обе на склейке:
///
/// 1. **Склейка групп полной ширины** (#138, ревью d6a34d2d): разделитель
///    склеивает группы только если с обеих сторон от него стоит группа из
///    не менее чем [`MIN_LEADING_GROUP_DIGITS`] цифр. Ведущая группа из
///    одной цифры — нумерация («1.2204…», «9/2204…»), не печатная форма;
///    прогон с ней обрывается на первой склейке, хвост разбирается вторым
///    прогоном с той же проверкой — рекурсия канон-суффикса
///    («1.0.0000.0000.0000» → хвост «0.0000.0000.0000» с ведущим нулём)
///    закрывается на этом же атоме. Равные группы-по-2 у точки уже косит
///    рамка 2; для «/», «-» и пробела эта рамка — первая защита от
///    нумерации («код 1/2204/4132/9947», «пункт 1-2204-4132-9947»).
/// 2. **Точка**: склеивает группы только в печатной форме номера — см.
///    [`checksums::dot_glues_number`] (дата/десятичная/версия с равными
///    группами прогон обрывают; 4+4 = PAN склеивается).
fn sep_len_number(bytes: &[u8], i: usize) -> usize {
    let len = sep_len(bytes, i);
    if len == 0 {
        return 0;
    }
    if digit_run_len_before(bytes, i) < MIN_LEADING_GROUP_DIGITS
        || digit_run_len_after(bytes, i + len) < MIN_LEADING_GROUP_DIGITS
    {
        return 0;
    }
    if bytes[i] == b'.' && !checksums::dot_glues_number(bytes, i) {
        return 0;
    }
    len
}


/// Длина прогона ASCII-цифр, заканчивающегося строго перед `i`.
fn digit_run_len_before(bytes: &[u8], i: usize) -> usize {
    let mut n = 0usize;
    while n < i && bytes[i - 1 - n].is_ascii_digit() {
        n += 1;
    }
    n
}

/// Длина прогона ASCII-цифр, начинающегося строго после `i`.
fn digit_run_len_after(bytes: &[u8], i: usize) -> usize {
    let mut n = 0usize;
    while i + n < bytes.len() && bytes[i + n].is_ascii_digit() {
        n += 1;
    }
    n
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

/// Рамка ведущей группы цифрового окна: группа короче двух цифр номером не
/// считается (#138, ревью d6a34d2d).
///
/// Ведущая группа из одной цифры — это нумерация, а не печатная форма:
/// «1.2204.4132.9947» (пункт списка), «9.3005.0489.9258» (заголовок с
/// индексом), «0.0.0000.0000.0000» (версия). Склейка такой группы с хвостом
/// рождает **канон-суффикс**: валидатор проходит ровно тот канон, который
/// без ведущей цифры («1.0000.0000.0000.0000» → `0000000000000000`, 16 нулей
/// — сумма Луны 0), а с ведущей цифрой он за рамкой (17 цифр). Печатных
/// групп короче двух цифр не бывает: самая короткая группа реальных форм —
/// СНИЛС-контроль 2 («378-312-074 87»), её покрывает [`MAX_WINDOW_GROUPS`],
/// остальное — 3 (БИК, СНИЛС-тело), 4 (PAN, IBAN), 5–6 (счёт, ОГРН). Рамка
/// стоит на окне ([`validated_windows`]): прогон разбирается целиком, в
/// окно ведущая цифра не входит; вето на [`num_runs`] (отшив прогона)
/// бессильно — сканер пересобирает хвост отдельным прогоном с тем же
/// канон-суффиксом.
const MIN_LEADING_GROUP_DIGITS: usize = 2;

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
            let sep = sep_len_number(bytes, i);
            if sep == 0 {
                break;
            }
            // Разделитель обязан принадлежать номеру: сразу за ним — цифра.
            // Это же правило отшивает сдвоенный разделитель («1234  5678»):
            // за первым separator'ом стоит второй, а не цифра.
            if i + sep >= bytes.len() || !bytes[i + sep].is_ascii_digit() {
                break;
            }
            // Вето «точка делит номер, а не дату/десятичную» — в
            // `sep_len_number`; при склейке групп канон = конкатенация групп
            // (Run::canonical), разделители в канон не попадают, поэтому
            // «4575.5035.9035.2993» и «4575.503590352993» дают один канон.
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
        // Второй контур рамки ведущей группы (#138, ревью d6a34d2d,
        // [`MIN_LEADING_GROUP_DIGITS`]): основная рамка — на склейке
        // ([`sep_len_number`]), здесь она закрывает прогон, начатый ПЕРЕД
        // ведущей цифрой не-цифрой («x1.0000.0000.0000.0000» — ведущая
        // «1» стартует прогон, склейка за ней законна). Прогон отшивается,
        // сканер приседает на цифру за первым разделителем: хвост
        // разбирается заново, рекурсия по цепочке («1.0.0000.0000.0000» →
        // прогон «0.0000.0000.0000» → прогон «0000.0000.0000»). Склейка
        // ведущей цифры с хвостом рождала **канон-суффикс**, и валидатор
        // проходил ровно его: «1.» + четыре группы по нулю = 16 нулей
        // (сумма Луны 0 — проходит), а полный канон 17 цифр — за рамкой
        // `luhn` (промер unit-тестом
        // `leading_single_digit_group_never_becomes_a_canonical_suffix`).
        // Голый прогон из одной цифры под вето не попадает (`groups.len()
        // > 1`): он не окно (`keep.len() > 1`), а сдвиг сканера за его
        // границу съел бы хвост «12.34567890123» (СНИЛС) и голое число
        // «код 9.0000000000» (ИНН-10, base-FP #102 — этот атом не трогает).
        if groups[0].end - groups[0].start < MIN_LEADING_GROUP_DIGITS && groups.len() > 1 {
            i = groups[0].end + 1;
            continue;
        }
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
    push_span_hits(hits, span, spec, spec.source, wanted);
}

/// Тот же контракт, что [`push_hits`], но спан уже известен.
///
/// Вектор классов не дублируется: один класс схемы может быть объявлен двумя
/// валидаторами, и каждый подтверждённый даёт отдельный хит (SPEC §8 «векторы
/// классов»).
fn push_span_hits(
    hits: &mut Vec<Hit>,
    span: ByteSpan,
    spec: &Spec,
    source: DetectionSource,
    wanted: &[(&'static str, ClassId)],
) {
    for (_, class) in wanted.iter().filter(|(v, _)| *v == spec.name) {
        hits.push(Hit {
            span,
            class: class.clone(),
            validator: spec.name,
            source,
        });
    }
}

// ── Base64-обход (PR #94) ───────────────────────────────────────────────────

/// Минимальная полезная нагрузка декода, байт.
///
/// 11 — это ИНН-10 с одной перемычкой (`778524 0858`): короче нечего проверять
/// чексумме, а каждая лишняя проверка короткого канона — это FP-поверхность.
/// Побочный эффект порога известен и принят: blob, в котором ровно 10 байт
/// «2482014338» без обрамления, не проверяется (тест
/// `base64_payload_floor_is_the_documented_tradeoff`).
const B64_MIN_PAYLOAD_BYTES: usize = 11;

/// Минимальная длина кандидата, байт: 16 — ближайшее кратное 4, чей декод не
/// короче [`B64_MIN_PAYLOAD_BYTES`]. Дешёвый префильтр: отсекает кандидатов до
/// того, как мы вообще посмотрим на алфавит.
const B64_MIN_TOKEN_BYTES: usize = 16;

/// Символы обоих алфавитов base64 плюс паддинг: standard `A-Za-z0-9+/`,
/// url-safe `A-Za-z0-9-_`, `=`.
const fn is_b64_symbol(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

/// Кандидаты base64: токены алфавита, ограниченные пробелом с обеих сторон.
///
/// Граница — пробел (в нормализованном тексте все Zs уже сведены к U+0020), а
/// не «любой не-алфавитный символ». Это и есть ответ на «почему JWT не
/// декодируется»: `a.b.c` — один токеном-не-токен, точки разрывают алфавит, но
/// части не стоят на пробельной границе, а прижатая к букве base64-цепочка
/// (`sha256=…`, `data:…;base64,AAAA…`, `[[F0#base64url]]` нашего же vault) —
/// это поле формата, а не вставка пользователя. Последнее важно не только для
/// FP: разворачивать собственный маркер обратимости означало бы маскировать
/// токен, который прокси сам вставляет в тело (#60).
fn b64_tokens(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let n = bytes.len();
    let mut i = 0usize;
    while i < n {
        if !is_b64_symbol(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_b64_symbol(bytes[i]) {
            i += 1;
        }
        let end = i;
        let left_ws = start == 0 || bytes[start - 1].is_ascii_whitespace();
        let right_ws = end == n || bytes[end].is_ascii_whitespace();
        if !(left_ws && right_ws) {
            continue;
        }
        if b64_shape_ok(&bytes[start..end]) {
            out.push((start, end));
        }
    }
    out
}

/// Форма кандидата: длина кратна 4 и не короче [`B64_MIN_TOKEN_BYTES`],
/// паддинг только хвостом (≤ 2), алфавит в токене не смешан.
///
/// Каноничность паддинга и «мусор в хвосте» доверены декодеру:
/// `general_purpose::STANDARD`/`URL_SAFE` требуют каноничный паддинг
/// (`DecodePaddingMode::RequireCanonical`) и не терпят лишних битов, так что
/// здесь только то, что декодер по своим правилам не отвергает.
fn b64_shape_ok(tok: &[u8]) -> bool {
    if tok.len() < B64_MIN_TOKEN_BYTES || tok.len() % 4 != 0 {
        return false;
    }
    let mut pads = 0usize;
    let mut standard = false;
    let mut url_safe = false;
    let mut seen_pad = false;
    for &b in tok {
        match b {
            b'=' => {
                pads += 1;
                seen_pad = true;
            }
            b'+' | b'/' => {
                if seen_pad {
                    return false;
                }
                standard = true;
            }
            b'-' | b'_' => {
                if seen_pad {
                    return false;
                }
                url_safe = true;
            }
            _ => {
                if seen_pad {
                    return false;
                }
            }
        }
    }
    pads <= 2 && !(standard && url_safe)
}

/// Декод кандидата: сначала standard-алфавит, затем url-safe.
///
/// Порядок не косметика: standard — подавляющее большинство входов, и вторая
/// попытка стоит только на токенах с `-_`. Смешанный алфавит отвергают оба
/// движка (`InvalidByte`), что и есть правило «один токен — один алфавит».
///
/// Буфер обёрнут в [`Zeroizing`]: в декодированных байтах лежат оригиналы `ПДн`,
/// а AGENTS §Инженерные инварианты требует zeroize на всех таких буферах.
fn b64_decode(token: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    STANDARD
        .decode(token)
        .or_else(|_| URL_SAFE.decode(token))
        .map(Zeroizing::new)
        .ok()
}

/// Числительные словами → цифры → валидаторы схемы; спан на фразу словами.
///
/// Цифры, собранные [`numwords::spelled_numbers`], гоняются по тому же оконному
/// конвейеру, что и цифры текста ([`validated_windows`]), а координаты
/// возвращаются на исходную фразу ([`push_hits`] — тот же fail-closed на
/// не-char-границе, что у текстового и base64-путей). Числа короче
/// [`MIN_SPELLED_DIGITS`] в цикл валидаторов не едут вовсе (он же guard года).
///
/// Слой читает **нормализованный** текст и только его: числительные внутри
/// base64-нагрузки не ищем — вложенность обходов ровно один уровень, паритет с
/// `base64_nesting_is_exactly_one_level`.
fn scan_words(
    text: &str,
    norm: &str,
    map: &normalize::OffsetMap,
    wanted: &[(&'static str, ClassId)],
    hits: &mut Vec<Hit>,
) {
    if wanted.is_empty() {
        return;
    }
    for sp in numwords::spelled_numbers(norm) {
        if sp.digits.len() < MIN_SPELLED_DIGITS {
            continue;
        }
        for w in validated_windows(&sp.digits[..], wanted) {
            push_hits(hits, text, map, sp.range.clone(), w.spec, wanted);
        }
    }
}

/// Base64-обход: прогон каскада-0 по декодированной нагрузке каждого кандидата.
///
/// Координаты окон в нагрузке никуда не идут: все хиты этого токена
/// кредитуются на спан исходного токена ([`scan_base64`] заголовок модуля).
///
/// Вложенность — ровно один уровень: нагрузку ведём [`validated_windows`], но
/// [`b64_tokens`] внутри неё не зовём, поэтому `base64(base64(x))` даёт ноль
/// находок (тест `base64_nesting_is_exactly_one_level`).
fn scan_base64(
    text: &str,
    norm: &[u8],
    map: &normalize::OffsetMap,
    wanted: &[(&'static str, ClassId)],
    hits: &mut Vec<Hit>,
) {
    if wanted.is_empty() {
        return;
    }
    for (start, end) in b64_tokens(norm) {
        // Спан кредитывается на токен: если граница токена не char-граница
        // оригинала, fail-closed — находку выбрасываем, а не сдвигаем координаты
        // (маскирование не того байта дороже пропуска).
        let Some(span) = map.map_span_to_original(text, start..end) else {
            continue;
        };
        let Some(payload) = b64_decode(&norm[start..end]) else {
            continue;
        };
        if payload.len() < B64_MIN_PAYLOAD_BYTES {
            continue;
        }
        // Нагрузка — произвольные байты: читаем как UTF-8 с потерями (ASCII-
        // цифры от замены байтов не меняются, а бинарные хвосты становятся
        // U+FFFD и разрезают окна). Дальше — тот же слой, что для текста,
        // поэтому перемычки («044 525 …») внутри декодированного ловит тот же
        // нормализатор и те же окна групп.
        //
        // Честность по [`Zeroizing`]: из трёх буферов залочены два — декод
        // `payload` и его строковая копия `payload_str`. Третий, `dnorm`,
        // приходит из `normalize::normalize` как `Cow<str>`; в ветке
        // `Cow::Owned` (в нагрузке что-то заменялось) это незакрытый
        // `String`-оригинал. Тот же дефект живёт на текстовом пути: там
        // `normalize` вызывается из `scan` и обёрнут ровно так же, поэтому
        // оставляем как есть — паритет путей важнее одностороннего улучшения,
        // а чинить надо в нормализаторе одним движением для обоих (ревью #94
        // F-3, задокументировано, а не проигнорировано).
        let payload_str = Zeroizing::new(String::from_utf8_lossy(payload.as_slice()).into_owned());
        let (dnorm, _) = normalize::normalize(&payload_str);
        // Чексумме нечего проверять без цифр: все валидаторы схемы
        // (ИНН/СНИЛС/ОГРН/Луна/БИК/счёт/IBAN) требуют цифры в окне. Фильтр
        // стоит ПОСЛЕ нормализации, а не на сырых байтах: полноширинные цифры
        // `U+FF10…U+FF19` в байтах декода ASCII-цифрами не являются, а
        // нормализатор сводит их к ASCII (ревью #94 F-1; пара «тот же вход
        // текстом / тот же вход токеном» —
        // `base64_fullwidth_digits_match_the_text_path`). Цена — нормализация
        // каждого кандидата, она меряется в микромере.
        if !dnorm.as_bytes().iter().any(u8::is_ascii_digit) {
            continue;
        }
        for w in validated_windows(dnorm.as_bytes(), wanted) {
            push_span_hits(hits, span, w.spec, DetectionSource::Base64Decode, wanted);
        }
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
    fn zz_tmp_probe() {
        for t in ["код 0.2204.4132.9947","0.2204.4132.9947","карта 0.2204.4132.9947","x0.2204.4132.9947","код 0.2204-4132-9947","0.2204-4132-9947","карта 0.2204-4132-9947","x0.2204-4132-9947","код 0.2204 4132 9947","0.2204 4132 9947","карта 0.2204 4132 9947","x0.2204 4132 9947","код 0.2204/4132/9947","0.2204/4132/9947","карта 0.2204/4132/9947","x0.2204/4132/9947","код 0.0000.0000.0000","0.0000.0000.0000","карта 0.0000.0000.0000","x0.0000.0000.0000","код 0.0000-0000-0000","0.0000-0000-0000","карта 0.0000-0000-0000","x0.0000-0000-0000","код 0.0000 0000 0000","0.0000 0000 0000","карта 0.0000 0000 0000","x0.0000 0000 0000","код 0.0000/0000/0000","0.0000/0000/0000","карта 0.0000/0000/0000","x0.0000/0000/0000","код 0.0000.0000.0000.0000","0.0000.0000.0000.0000","карта 0.0000.0000.0000.0000","x0.0000.0000.0000.0000","код 0.0000-0000-0000-0000","0.0000-0000-0000-0000","карта 0.0000-0000-0000-0000","x0.0000-0000-0000-0000","код 0.0000 0000 0000 0000","0.0000 0000 0000 0000","карта 0.0000 0000 0000 0000","x0.0000 0000 0000 0000","код 0.0000/0000/0000/0000","0.0000/0000/0000/0000","карта 0.0000/0000/0000/0000","x0.0000/0000/0000/0000","код 0.3005.0489.9258","0.3005.0489.9258","карта 0.3005.0489.9258","x0.3005.0489.9258","код 0.2204.4132.9947.0000","0.2204.4132.9947.0000","карта 0.2204.4132.9947.0000","x0.2204.4132.9947.0000","код 0.2204-4132-9947-0000","0.2204-4132-9947-0000","карта 0.2204-4132-9947-0000","x0.2204-4132-9947-0000","код 0.2204/4132/9947/0000","0.2204/4132/9947/0000","карта 0.2204/4132/9947/0000","x0.2204/4132/9947/0000","код 0.2204 4132 9947 0000","0.2204 4132 9947 0000","карта 0.2204 4132 9947 0000","x0.2204 4132 9947 0000","код 0.2204.4132.9947.0018","0.2204.4132.9947.0018","карта 0.2204.4132.9947.0018","x0.2204.4132.9947.0018","код 0.2204-4132-9947-0018","0.2204-4132-9947-0018","карта 0.2204-4132-9947-0018","x0.2204-4132-9947-0018","код 0.2204/4132/9947/0018","0.2204/4132/9947/0018","карта 0.2204/4132/9947/0018","x0.2204/4132/9947/0018","код 0.0.2204.4132.9947","0.0.2204.4132.9947","карта 0.0.2204.4132.9947","x0.0.2204.4132.9947","код 0.0.0000.0000.0000","0.0.0000.0000.0000","карта 0.0.0000.0000.0000","x0.0.0000.0000.0000","код 0.2.2204.4132.9947","0.2.2204.4132.9947","карта 0.2.2204.4132.9947","x0.2.2204.4132.9947","код 0.1.2204.4132.9947","0.1.2204.4132.9947","карта 0.1.2204.4132.9947","x0.1.2204.4132.9947","код 0.2204.4132","0.2204.4132","карта 0.2204.4132","x0.2204.4132","код 0.34567890123","0.34567890123","карта 0.34567890123","x0.34567890123","код 0.044525225","0.044525225","карта 0.044525225","x0.044525225","код 0.220441329947","0.220441329947","карта 0.220441329947","x0.220441329947","код 0.300504899258","0.300504899258","карта 0.300504899258","x0.300504899258","код 0.0000000000","0.0000000000","карта 0.0000000000","x0.0000000000","код 0.000000000000","0.000000000000","карта 0.000000000000","x0.000000000000","код 0.2204.9947.4132.0000","0.2204.9947.4132.0000","карта 0.2204.9947.4132.0000","x0.2204.9947.4132.0000","код 0.2222.2222.2222.2222","0.2222.2222.2222.2222","карта 0.2222.2222.2222.2222","x0.2222.2222.2222.2222","код 0.2204.4132.9947 0000","0.2204.4132.9947 0000","карта 0.2204.4132.9947 0000","x0.2204.4132.9947 0000","код 0.2204.4132.9947 0018","0.2204.4132.9947 0018","карта 0.2204.4132.9947 0018","x0.2204.4132.9947 0018","код 0.2204-4132-9947 0000","0.2204-4132-9947 0000","карта 0.2204-4132-9947 0000","x0.2204-4132-9947 0000","код 0.2204/4132/9947 0000","0.2204/4132/9947 0000","карта 0.2204/4132/9947 0000","x0.2204/4132/9947 0000","код 0.24.82.01.43.38","0.24.82.01.43.38","карта 0.24.82.01.43.38","x0.24.82.01.43.38","код 0.378/123/456/94","0.378/123/456/94","карта 0.378/123/456/94","x0.378/123/456/94","код 0.774358.417509","0.774358.417509","карта 0.774358.417509","x0.774358.417509","код 0.0.0.0000.0000.0000","0.0.0.0000.0000.0000","карта 0.0.0.0000.0000.0000","x0.0.0.0000.0000.0000","код 0.0.2.2204.4132.9947","0.0.2.2204.4132.9947","карта 0.0.2.2204.4132.9947","x0.0.2.2204.4132.9947","код 0.2.2.2204.4132.9947","0.2.2.2204.4132.9947","карта 0.2.2.2204.4132.9947","x0.2.2.2204.4132.9947","код 0.2.0.2204.4132.9947","0.2.0.2204.4132.9947","карта 0.2.0.2204.4132.9947","x0.2.0.2204.4132.9947","код 0.1.0.0000.0000.0000","0.1.0.0000.0000.0000","карта 0.1.0.0000.0000.0000","x0.1.0.0000.0000.0000","код 0.2.0000.0000.0000","0.2.0000.0000.0000","карта 0.2.0000.0000.0000","x0.2.0000.0000.0000","код 0.0.2204.4132.9947.0018","0.0.2204.4132.9947.0018","карта 0.0.2204.4132.9947.0018","x0.0.2204.4132.9947.0018","код 0.0.2204-4132-9947-0018","0.0.2204-4132-9947-0018","карта 0.0.2204-4132-9947-0018","x0.0.2204-4132-9947-0018","код 0.2222-2222-2222-2222","0.2222-2222-2222-2222","карта 0.2222-2222-2222-2222","x0.2222-2222-2222-2222","код 0.2222 2222 2222 2222","0.2222 2222 2222 2222","карта 0.2222 2222 2222 2222","x0.2222 2222 2222 2222","код 0.2222/2222/2222/2222","0.2222/2222/2222/2222","карта 0.2222/2222/2222/2222","x0.2222/2222/2222/2222","код 0.1111.1111.1111.1111","0.1111.1111.1111.1111","карта 0.1111.1111.1111.1111","x0.1111.1111.1111.1111","код 0.2204.4132.9947.0000.0000","0.2204.4132.9947.0000.0000","карта 0.2204.4132.9947.0000.0000","x0.2204.4132.9947.0000.0000","код 0.2204.4132.9947 1.2204.4132.9947","0.2204.4132.9947 1.2204.4132.9947","карта 0.2204.4132.9947 1.2204.4132.9947","x0.2204.4132.9947 1.2204.4132.9947","код 0.2204.4132.9947 0000000000","0.2204.4132.9947 0000000000","карта 0.2204.4132.9947 0000000000","x0.2204.4132.9947 0000000000","код 0.3005-0489-9258","0.3005-0489-9258","карта 0.3005-0489-9258","x0.3005-0489-9258","код 0.3005 0489 9258","0.3005 0489 9258","карта 0.3005 0489 9258","x0.3005 0489 9258","код 0.3005/0489/9258","0.3005/0489/9258","карта 0.3005/0489/9258","x0.3005/0489/9258","код 0.1000 2000 3000 4000 5000 6000","0.1000 2000 3000 4000 5000 6000","карта 0.1000 2000 3000 4000 5000 6000","x0.1000 2000 3000 4000 5000 6000","код 0.2204.4132.9947 списка","0.2204.4132.9947 списка","карта 0.2204.4132.9947 списка","x0.2204.4132.9947 списка","код 0.2204-4132-9947 список","0.2204-4132-9947 список","карта 0.2204-4132-9947 список","x0.2204-4132-9947 список","код 0.2.0000-0000-0000","0.2.0000-0000-0000","карта 0.2.0000-0000-0000","x0.2.0000-0000-0000","код 0.2.0000 0000 0000","0.2.0000 0000 0000","карта 0.2.0000 0000 0000","x0.2.0000 0000 0000","код 0.2.0000/0000/0000","0.2.0000/0000/0000","карта 0.2.0000/0000/0000","x0.2.0000/0000/0000","код 0.2.0000.0000.0000.0000","0.2.0000.0000.0000.0000","карта 0.2.0000.0000.0000.0000","x0.2.0000.0000.0000.0000","код 0.0.0000-0000-0000","0.0.0000-0000-0000","карта 0.0.0000-0000-0000","x0.0.0000-0000-0000","код 0.0.0000 0000 0000","0.0.0000 0000 0000","карта 0.0.0000 0000 0000","x0.0.0000 0000 0000","код 0.0.0000/0000/0000","0.0.0000/0000/0000","карта 0.0.0000/0000/0000","x0.0.0000/0000/0000","код 0.0.0000.0000.0000.0000","0.0.0000.0000.0000.0000","карта 0.0.0000.0000.0000.0000","x0.0.0000.0000.0000.0000","код 0-2204.4132.9947","0-2204.4132.9947","карта 0-2204.4132.9947","x0-2204.4132.9947","код 0-2204-4132-9947","0-2204-4132-9947","карта 0-2204-4132-9947","x0-2204-4132-9947","код 0-2204 4132 9947","0-2204 4132 9947","карта 0-2204 4132 9947","x0-2204 4132 9947","код 0-2204/4132/9947","0-2204/4132/9947","карта 0-2204/4132/9947","x0-2204/4132/9947","код 0-0000.0000.0000","0-0000.0000.0000","карта 0-0000.0000.0000","x0-0000.0000.0000","код 0-0000-0000-0000","0-0000-0000-0000","карта 0-0000-0000-0000","x0-0000-0000-0000","код 0-0000 0000 0000","0-0000 0000 0000","карта 0-0000 0000 0000","x0-0000 0000 0000","код 0-0000/0000/0000","0-0000/0000/0000","карта 0-0000/0000/0000","x0-0000/0000/0000","код 0-0000.0000.0000.0000","0-0000.0000.0000.0000","карта 0-0000.0000.0000.0000","x0-0000.0000.0000.0000","код 0-0000-0000-0000-0000","0-0000-0000-0000-0000","карта 0-0000-0000-0000-0000","x0-0000-0000-0000-0000","код 0-0000 0000 0000 0000","0-0000 0000 0000 0000","карта 0-0000 0000 0000 0000","x0-0000 0000 0000 0000","код 0-0000/0000/0000/0000","0-0000/0000/0000/0000","карта 0-0000/0000/0000/0000","x0-0000/0000/0000/0000","код 0-3005.0489.9258","0-3005.0489.9258","карта 0-3005.0489.9258","x0-3005.0489.9258","код 0-2204.4132.9947.0000","0-2204.4132.9947.0000","карта 0-2204.4132.9947.0000","x0-2204.4132.9947.0000","код 0-2204-4132-9947-0000","0-2204-4132-9947-0000","карта 0-2204-4132-9947-0000","x0-2204-4132-9947-0000","код 0-2204/4132/9947/0000","0-2204/4132/9947/0000","карта 0-2204/4132/9947/0000","x0-2204/4132/9947/0000","код 0-2204 4132 9947 0000","0-2204 4132 9947 0000","карта 0-2204 4132 9947 0000","x0-2204 4132 9947 0000","код 0-2204.4132.9947.0018","0-2204.4132.9947.0018","карта 0-2204.4132.9947.0018","x0-2204.4132.9947.0018","код 0-2204-4132-9947-0018","0-2204-4132-9947-0018","карта 0-2204-4132-9947-0018","x0-2204-4132-9947-0018","код 0-2204/4132/9947/0018","0-2204/4132/9947/0018","карта 0-2204/4132/9947/0018","x0-2204/4132/9947/0018","код 0-0.2204.4132.9947","0-0.2204.4132.9947","карта 0-0.2204.4132.9947","x0-0.2204.4132.9947","код 0-0.0000.0000.0000","0-0.0000.0000.0000","карта 0-0.0000.0000.0000","x0-0.0000.0000.0000","код 0-2.2204.4132.9947","0-2.2204.4132.9947","карта 0-2.2204.4132.9947","x0-2.2204.4132.9947","код 0-1.2204.4132.9947","0-1.2204.4132.9947","карта 0-1.2204.4132.9947","x0-1.2204.4132.9947","код 0-2204.4132","0-2204.4132","карта 0-2204.4132","x0-2204.4132","код 0-34567890123","0-34567890123","карта 0-34567890123","x0-34567890123","код 0-044525225","0-044525225","карта 0-044525225","x0-044525225","код 0-220441329947","0-220441329947","карта 0-220441329947","x0-220441329947","код 0-300504899258","0-300504899258","карта 0-300504899258","x0-300504899258","код 0-0000000000","0-0000000000","карта 0-0000000000","x0-0000000000","код 0-000000000000","0-000000000000","карта 0-000000000000","x0-000000000000","код 0-2204.9947.4132.0000","0-2204.9947.4132.0000","карта 0-2204.9947.4132.0000","x0-2204.9947.4132.0000","код 0-2222.2222.2222.2222","0-2222.2222.2222.2222","карта 0-2222.2222.2222.2222","x0-2222.2222.2222.2222","код 0-2204.4132.9947 0000","0-2204.4132.9947 0000","карта 0-2204.4132.9947 0000","x0-2204.4132.9947 0000","код 0-2204.4132.9947 0018","0-2204.4132.9947 0018","карта 0-2204.4132.9947 0018","x0-2204.4132.9947 0018","код 0-2204-4132-9947 0000","0-2204-4132-9947 0000","карта 0-2204-4132-9947 0000","x0-2204-4132-9947 0000","код 0-2204/4132/9947 0000","0-2204/4132/9947 0000","карта 0-2204/4132/9947 0000","x0-2204/4132/9947 0000","код 0-24.82.01.43.38","0-24.82.01.43.38","карта 0-24.82.01.43.38","x0-24.82.01.43.38","код 0-378/123/456/94","0-378/123/456/94","карта 0-378/123/456/94","x0-378/123/456/94","код 0-774358.417509","0-774358.417509","карта 0-774358.417509","x0-774358.417509","код 0-0.0.0000.0000.0000","0-0.0.0000.0000.0000","карта 0-0.0.0000.0000.0000","x0-0.0.0000.0000.0000","код 0-0.2.2204.4132.9947","0-0.2.2204.4132.9947","карта 0-0.2.2204.4132.9947","x0-0.2.2204.4132.9947","код 0-2.2.2204.4132.9947","0-2.2.2204.4132.9947","карта 0-2.2.2204.4132.9947","x0-2.2.2204.4132.9947","код 0-2.0.2204.4132.9947","0-2.0.2204.4132.9947","карта 0-2.0.2204.4132.9947","x0-2.0.2204.4132.9947","код 0-1.0.0000.0000.0000","0-1.0.0000.0000.0000","карта 0-1.0.0000.0000.0000","x0-1.0.0000.0000.0000","код 0-2.0000.0000.0000","0-2.0000.0000.0000","карта 0-2.0000.0000.0000","x0-2.0000.0000.0000","код 0-0.2204.4132.9947.0018","0-0.2204.4132.9947.0018","карта 0-0.2204.4132.9947.0018","x0-0.2204.4132.9947.0018","код 0-0.2204-4132-9947-0018","0-0.2204-4132-9947-0018","карта 0-0.2204-4132-9947-0018","x0-0.2204-4132-9947-0018","код 0-2222-2222-2222-2222","0-2222-2222-2222-2222","карта 0-2222-2222-2222-2222","x0-2222-2222-2222-2222","код 0-2222 2222 2222 2222","0-2222 2222 2222 2222","карта 0-2222 2222 2222 2222","x0-2222 2222 2222 2222","код 0-2222/2222/2222/2222","0-2222/2222/2222/2222","карта 0-2222/2222/2222/2222","x0-2222/2222/2222/2222","код 0-1111.1111.1111.1111","0-1111.1111.1111.1111","карта 0-1111.1111.1111.1111","x0-1111.1111.1111.1111","код 0-2204.4132.9947.0000.0000","0-2204.4132.9947.0000.0000","карта 0-2204.4132.9947.0000.0000","x0-2204.4132.9947.0000.0000","код 0-2204.4132.9947 1.2204.4132.9947","0-2204.4132.9947 1.2204.4132.9947","карта 0-2204.4132.9947 1.2204.4132.9947","x0-2204.4132.9947 1.2204.4132.9947","код 0-2204.4132.9947 0000000000","0-2204.4132.9947 0000000000","карта 0-2204.4132.9947 0000000000","x0-2204.4132.9947 0000000000","код 0-3005-0489-9258","0-3005-0489-9258","карта 0-3005-0489-9258","x0-3005-0489-9258","код 0-3005 0489 9258","0-3005 0489 9258","карта 0-3005 0489 9258","x0-3005 0489 9258","код 0-3005/0489/9258","0-3005/0489/9258","карта 0-3005/0489/9258","x0-3005/0489/9258","код 0-1000 2000 3000 4000 5000 6000","0-1000 2000 3000 4000 5000 6000","карта 0-1000 2000 3000 4000 5000 6000","x0-1000 2000 3000 4000 5000 6000","код 0-2204.4132.9947 списка","0-2204.4132.9947 списка","карта 0-2204.4132.9947 списка","x0-2204.4132.9947 списка","код 0-2204-4132-9947 список","0-2204-4132-9947 список","карта 0-2204-4132-9947 список","x0-2204-4132-9947 список","код 0-2.0000-0000-0000","0-2.0000-0000-0000","карта 0-2.0000-0000-0000","x0-2.0000-0000-0000","код 0-2.0000 0000 0000","0-2.0000 0000 0000","карта 0-2.0000 0000 0000","x0-2.0000 0000 0000","код 0-2.0000/0000/0000","0-2.0000/0000/0000","карта 0-2.0000/0000/0000","x0-2.0000/0000/0000","код 0-2.0000.0000.0000.0000","0-2.0000.0000.0000.0000","карта 0-2.0000.0000.0000.0000","x0-2.0000.0000.0000.0000","код 0-0.0000-0000-0000","0-0.0000-0000-0000","карта 0-0.0000-0000-0000","x0-0.0000-0000-0000","код 0-0.0000 0000 0000","0-0.0000 0000 0000","карта 0-0.0000 0000 0000","x0-0.0000 0000 0000","код 0-0.0000/0000/0000","0-0.0000/0000/0000","карта 0-0.0000/0000/0000","x0-0.0000/0000/0000","код 0-0.0000.0000.0000.0000","0-0.0000.0000.0000.0000","карта 0-0.0000.0000.0000.0000","x0-0.0000.0000.0000.0000","код 0/2204.4132.9947","0/2204.4132.9947","карта 0/2204.4132.9947","x0/2204.4132.9947","код 0/2204-4132-9947","0/2204-4132-9947","карта 0/2204-4132-9947","x0/2204-4132-9947","код 0/2204 4132 9947","0/2204 4132 9947","карта 0/2204 4132 9947","x0/2204 4132 9947","код 0/2204/4132/9947","0/2204/4132/9947","карта 0/2204/4132/9947","x0/2204/4132/9947","код 0/0000.0000.0000","0/0000.0000.0000","карта 0/0000.0000.0000","x0/0000.0000.0000","код 0/0000-0000-0000","0/0000-0000-0000","карта 0/0000-0000-0000","x0/0000-0000-0000","код 0/0000 0000 0000","0/0000 0000 0000","карта 0/0000 0000 0000","x0/0000 0000 0000","код 0/0000/0000/0000","0/0000/0000/0000","карта 0/0000/0000/0000","x0/0000/0000/0000","код 0/0000.0000.0000.0000","0/0000.0000.0000.0000","карта 0/0000.0000.0000.0000","x0/0000.0000.0000.0000","код 0/0000-0000-0000-0000","0/0000-0000-0000-0000","карта 0/0000-0000-0000-0000","x0/0000-0000-0000-0000","код 0/0000 0000 0000 0000","0/0000 0000 0000 0000","карта 0/0000 0000 0000 0000","x0/0000 0000 0000 0000","код 0/0000/0000/0000/0000","0/0000/0000/0000/0000","карта 0/0000/0000/0000/0000","x0/0000/0000/0000/0000","код 0/3005.0489.9258","0/3005.0489.9258","карта 0/3005.0489.9258","x0/3005.0489.9258","код 0/2204.4132.9947.0000","0/2204.4132.9947.0000","карта 0/2204.4132.9947.0000","x0/2204.4132.9947.0000","код 0/2204-4132-9947-0000","0/2204-4132-9947-0000","карта 0/2204-4132-9947-0000","x0/2204-4132-9947-0000","код 0/2204/4132/9947/0000","0/2204/4132/9947/0000","карта 0/2204/4132/9947/0000","x0/2204/4132/9947/0000","код 0/2204 4132 9947 0000","0/2204 4132 9947 0000","карта 0/2204 4132 9947 0000","x0/2204 4132 9947 0000","код 0/2204.4132.9947.0018","0/2204.4132.9947.0018","карта 0/2204.4132.9947.0018","x0/2204.4132.9947.0018","код 0/2204-4132-9947-0018","0/2204-4132-9947-0018","карта 0/2204-4132-9947-0018","x0/2204-4132-9947-0018","код 0/2204/4132/9947/0018","0/2204/4132/9947/0018","карта 0/2204/4132/9947/0018","x0/2204/4132/9947/0018","код 0/0.2204.4132.9947","0/0.2204.4132.9947","карта 0/0.2204.4132.9947","x0/0.2204.4132.9947","код 0/0.0000.0000.0000","0/0.0000.0000.0000","карта 0/0.0000.0000.0000","x0/0.0000.0000.0000","код 0/2.2204.4132.9947","0/2.2204.4132.9947","карта 0/2.2204.4132.9947","x0/2.2204.4132.9947","код 0/1.2204.4132.9947","0/1.2204.4132.9947","карта 0/1.2204.4132.9947","x0/1.2204.4132.9947","код 0/2204.4132","0/2204.4132","карта 0/2204.4132","x0/2204.4132","код 0/34567890123","0/34567890123","карта 0/34567890123","x0/34567890123","код 0/044525225","0/044525225","карта 0/044525225","x0/044525225","код 0/220441329947","0/220441329947","карта 0/220441329947","x0/220441329947","код 0/300504899258","0/300504899258","карта 0/300504899258","x0/300504899258","код 0/0000000000","0/0000000000","карта 0/0000000000","x0/0000000000","код 0/000000000000","0/000000000000","карта 0/000000000000","x0/000000000000","код 0/2204.9947.4132.0000","0/2204.9947.4132.0000","карта 0/2204.9947.4132.0000","x0/2204.9947.4132.0000","код 0/2222.2222.2222.2222","0/2222.2222.2222.2222","карта 0/2222.2222.2222.2222","x0/2222.2222.2222.2222","код 0/2204.4132.9947 0000","0/2204.4132.9947 0000","карта 0/2204.4132.9947 0000","x0/2204.4132.9947 0000","код 0/2204.4132.9947 0018","0/2204.4132.9947 0018","карта 0/2204.4132.9947 0018","x0/2204.4132.9947 0018","код 0/2204-4132-9947 0000","0/2204-4132-9947 0000","карта 0/2204-4132-9947 0000","x0/2204-4132-9947 0000","код 0/2204/4132/9947 0000","0/2204/4132/9947 0000","карта 0/2204/4132/9947 0000","x0/2204/4132/9947 0000","код 0/24.82.01.43.38","0/24.82.01.43.38","карта 0/24.82.01.43.38","x0/24.82.01.43.38","код 0/378/123/456/94","0/378/123/456/94","карта 0/378/123/456/94","x0/378/123/456/94","код 0/774358.417509","0/774358.417509","карта 0/774358.417509","x0/774358.417509","код 0/0.0.0000.0000.0000","0/0.0.0000.0000.0000","карта 0/0.0.0000.0000.0000","x0/0.0.0000.0000.0000","код 0/0.2.2204.4132.9947","0/0.2.2204.4132.9947","карта 0/0.2.2204.4132.9947","x0/0.2.2204.4132.9947","код 0/2.2.2204.4132.9947","0/2.2.2204.4132.9947","карта 0/2.2.2204.4132.9947","x0/2.2.2204.4132.9947","код 0/2.0.2204.4132.9947","0/2.0.2204.4132.9947","карта 0/2.0.2204.4132.9947","x0/2.0.2204.4132.9947","код 0/1.0.0000.0000.0000","0/1.0.0000.0000.0000","карта 0/1.0.0000.0000.0000","x0/1.0.0000.0000.0000","код 0/2.0000.0000.0000","0/2.0000.0000.0000","карта 0/2.0000.0000.0000","x0/2.0000.0000.0000","код 0/0.2204.4132.9947.0018","0/0.2204.4132.9947.0018","карта 0/0.2204.4132.9947.0018","x0/0.2204.4132.9947.0018","код 0/0.2204-4132-9947-0018","0/0.2204-4132-9947-0018","карта 0/0.2204-4132-9947-0018","x0/0.2204-4132-9947-0018","код 0/2222-2222-2222-2222","0/2222-2222-2222-2222","карта 0/2222-2222-2222-2222","x0/2222-2222-2222-2222","код 0/2222 2222 2222 2222","0/2222 2222 2222 2222","карта 0/2222 2222 2222 2222","x0/2222 2222 2222 2222","код 0/2222/2222/2222/2222","0/2222/2222/2222/2222","карта 0/2222/2222/2222/2222","x0/2222/2222/2222/2222","код 0/1111.1111.1111.1111","0/1111.1111.1111.1111","карта 0/1111.1111.1111.1111","x0/1111.1111.1111.1111","код 0/2204.4132.9947.0000.0000","0/2204.4132.9947.0000.0000","карта 0/2204.4132.9947.0000.0000","x0/2204.4132.9947.0000.0000","код 0/2204.4132.9947 1.2204.4132.9947","0/2204.4132.9947 1.2204.4132.9947","карта 0/2204.4132.9947 1.2204.4132.9947","x0/2204.4132.9947 1.2204.4132.9947","код 0/2204.4132.9947 0000000000","0/2204.4132.9947 0000000000","карта 0/2204.4132.9947 0000000000","x0/2204.4132.9947 0000000000","код 0/3005-0489-9258","0/3005-0489-9258","карта 0/3005-0489-9258","x0/3005-0489-9258","код 0/3005 0489 9258","0/3005 0489 9258","карта 0/3005 0489 9258","x0/3005 0489 9258","код 0/3005/0489/9258","0/3005/0489/9258","карта 0/3005/0489/9258","x0/3005/0489/9258","код 0/1000 2000 3000 4000 5000 6000","0/1000 2000 3000 4000 5000 6000","карта 0/1000 2000 3000 4000 5000 6000","x0/1000 2000 3000 4000 5000 6000","код 0/2204.4132.9947 списка","0/2204.4132.9947 списка","карта 0/2204.4132.9947 списка","x0/2204.4132.9947 списка","код 0/2204-4132-9947 список","0/2204-4132-9947 список","карта 0/2204-4132-9947 список","x0/2204-4132-9947 список","код 0/2.0000-0000-0000","0/2.0000-0000-0000","карта 0/2.0000-0000-0000","x0/2.0000-0000-0000","код 0/2.0000 0000 0000","0/2.0000 0000 0000","карта 0/2.0000 0000 0000","x0/2.0000 0000 0000","код 0/2.0000/0000/0000","0/2.0000/0000/0000","карта 0/2.0000/0000/0000","x0/2.0000/0000/0000","код 0/2.0000.0000.0000.0000","0/2.0000.0000.0000.0000","карта 0/2.0000.0000.0000.0000","x0/2.0000.0000.0000.0000","код 0/0.0000-0000-0000","0/0.0000-0000-0000","карта 0/0.0000-0000-0000","x0/0.0000-0000-0000","код 0/0.0000 0000 0000","0/0.0000 0000 0000","карта 0/0.0000 0000 0000","x0/0.0000 0000 0000","код 0/0.0000/0000/0000","0/0.0000/0000/0000","карта 0/0.0000/0000/0000","x0/0.0000/0000/0000","код 0/0.0000.0000.0000.0000","0/0.0000.0000.0000.0000","карта 0/0.0000.0000.0000.0000","x0/0.0000.0000.0000.0000","код 0 2204.4132.9947","0 2204.4132.9947","карта 0 2204.4132.9947","x0 2204.4132.9947","код 0 2204-4132-9947","0 2204-4132-9947","карта 0 2204-4132-9947","x0 2204-4132-9947","код 0 2204 4132 9947","0 2204 4132 9947","карта 0 2204 4132 9947","x0 2204 4132 9947","код 0 2204/4132/9947","0 2204/4132/9947","карта 0 2204/4132/9947","x0 2204/4132/9947","код 0 0000.0000.0000","0 0000.0000.0000","карта 0 0000.0000.0000","x0 0000.0000.0000","код 0 0000-0000-0000","0 0000-0000-0000","карта 0 0000-0000-0000","x0 0000-0000-0000","код 0 0000 0000 0000","0 0000 0000 0000","карта 0 0000 0000 0000","x0 0000 0000 0000","код 0 0000/0000/0000","0 0000/0000/0000","карта 0 0000/0000/0000","x0 0000/0000/0000","код 0 0000.0000.0000.0000","0 0000.0000.0000.0000","карта 0 0000.0000.0000.0000","x0 0000.0000.0000.0000","код 0 0000-0000-0000-0000","0 0000-0000-0000-0000","карта 0 0000-0000-0000-0000","x0 0000-0000-0000-0000","код 0 0000 0000 0000 0000","0 0000 0000 0000 0000","карта 0 0000 0000 0000 0000","x0 0000 0000 0000 0000","код 0 0000/0000/0000/0000","0 0000/0000/0000/0000","карта 0 0000/0000/0000/0000","x0 0000/0000/0000/0000","код 0 3005.0489.9258","0 3005.0489.9258","карта 0 3005.0489.9258","x0 3005.0489.9258","код 0 2204.4132.9947.0000","0 2204.4132.9947.0000","карта 0 2204.4132.9947.0000","x0 2204.4132.9947.0000","код 0 2204-4132-9947-0000","0 2204-4132-9947-0000","карта 0 2204-4132-9947-0000","x0 2204-4132-9947-0000","код 0 2204/4132/9947/0000","0 2204/4132/9947/0000","карта 0 2204/4132/9947/0000","x0 2204/4132/9947/0000","код 0 2204 4132 9947 0000","0 2204 4132 9947 0000","карта 0 2204 4132 9947 0000","x0 2204 4132 9947 0000","код 0 2204.4132.9947.0018","0 2204.4132.9947.0018","карта 0 2204.4132.9947.0018","x0 2204.4132.9947.0018","код 0 2204-4132-9947-0018","0 2204-4132-9947-0018","карта 0 2204-4132-9947-0018","x0 2204-4132-9947-0018","код 0 2204/4132/9947/0018","0 2204/4132/9947/0018","карта 0 2204/4132/9947/0018","x0 2204/4132/9947/0018","код 0 0.2204.4132.9947","0 0.2204.4132.9947","карта 0 0.2204.4132.9947","x0 0.2204.4132.9947","код 0 0.0000.0000.0000","0 0.0000.0000.0000","карта 0 0.0000.0000.0000","x0 0.0000.0000.0000","код 0 2.2204.4132.9947","0 2.2204.4132.9947","карта 0 2.2204.4132.9947","x0 2.2204.4132.9947","код 0 1.2204.4132.9947","0 1.2204.4132.9947","карта 0 1.2204.4132.9947","x0 1.2204.4132.9947","код 0 2204.4132","0 2204.4132","карта 0 2204.4132","x0 2204.4132","код 0 34567890123","0 34567890123","карта 0 34567890123","x0 34567890123","код 0 044525225","0 044525225","карта 0 044525225","x0 044525225","код 0 220441329947","0 220441329947","карта 0 220441329947","x0 220441329947","код 0 300504899258","0 300504899258","карта 0 300504899258","x0 300504899258","код 0 0000000000","0 0000000000","карта 0 0000000000","x0 0000000000","код 0 000000000000","0 000000000000","карта 0 000000000000","x0 000000000000","код 0 2204.9947.4132.0000","0 2204.9947.4132.0000","карта 0 2204.9947.4132.0000","x0 2204.9947.4132.0000","код 0 2222.2222.2222.2222","0 2222.2222.2222.2222","карта 0 2222.2222.2222.2222","x0 2222.2222.2222.2222","код 0 2204.4132.9947 0000","0 2204.4132.9947 0000","карта 0 2204.4132.9947 0000","x0 2204.4132.9947 0000","код 0 2204.4132.9947 0018","0 2204.4132.9947 0018","карта 0 2204.4132.9947 0018","x0 2204.4132.9947 0018","код 0 2204-4132-9947 0000","0 2204-4132-9947 0000","карта 0 2204-4132-9947 0000","x0 2204-4132-9947 0000","код 0 2204/4132/9947 0000","0 2204/4132/9947 0000","карта 0 2204/4132/9947 0000","x0 2204/4132/9947 0000","код 0 24.82.01.43.38","0 24.82.01.43.38","карта 0 24.82.01.43.38","x0 24.82.01.43.38","код 0 378/123/456/94","0 378/123/456/94","карта 0 378/123/456/94","x0 378/123/456/94","код 0 774358.417509","0 774358.417509","карта 0 774358.417509","x0 774358.417509","код 0 0.0.0000.0000.0000","0 0.0.0000.0000.0000","карта 0 0.0.0000.0000.0000","x0 0.0.0000.0000.0000","код 0 0.2.2204.4132.9947","0 0.2.2204.4132.9947","карта 0 0.2.2204.4132.9947","x0 0.2.2204.4132.9947","код 0 2.2.2204.4132.9947","0 2.2.2204.4132.9947","карта 0 2.2.2204.4132.9947","x0 2.2.2204.4132.9947","код 0 2.0.2204.4132.9947","0 2.0.2204.4132.9947","карта 0 2.0.2204.4132.9947","x0 2.0.2204.4132.9947","код 0 1.0.0000.0000.0000","0 1.0.0000.0000.0000","карта 0 1.0.0000.0000.0000","x0 1.0.0000.0000.0000","код 0 2.0000.0000.0000","0 2.0000.0000.0000","карта 0 2.0000.0000.0000","x0 2.0000.0000.0000","код 0 0.2204.4132.9947.0018","0 0.2204.4132.9947.0018","карта 0 0.2204.4132.9947.0018","x0 0.2204.4132.9947.0018","код 0 0.2204-4132-9947-0018","0 0.2204-4132-9947-0018","карта 0 0.2204-4132-9947-0018","x0 0.2204-4132-9947-0018","код 0 2222-2222-2222-2222","0 2222-2222-2222-2222","карта 0 2222-2222-2222-2222","x0 2222-2222-2222-2222","код 0 2222 2222 2222 2222","0 2222 2222 2222 2222","карта 0 2222 2222 2222 2222","x0 2222 2222 2222 2222","код 0 2222/2222/2222/2222","0 2222/2222/2222/2222","карта 0 2222/2222/2222/2222","x0 2222/2222/2222/2222","код 0 1111.1111.1111.1111","0 1111.1111.1111.1111","карта 0 1111.1111.1111.1111","x0 1111.1111.1111.1111","код 0 2204.4132.9947.0000.0000","0 2204.4132.9947.0000.0000","карта 0 2204.4132.9947.0000.0000","x0 2204.4132.9947.0000.0000","код 0 2204.4132.9947 1.2204.4132.9947","0 2204.4132.9947 1.2204.4132.9947","карта 0 2204.4132.9947 1.2204.4132.9947","x0 2204.4132.9947 1.2204.4132.9947","код 0 2204.4132.9947 0000000000","0 2204.4132.9947 0000000000","карта 0 2204.4132.9947 0000000000","x0 2204.4132.9947 0000000000","код 0 3005-0489-9258","0 3005-0489-9258","карта 0 3005-0489-9258","x0 3005-0489-9258","код 0 3005 0489 9258","0 3005 0489 9258","карта 0 3005 0489 9258","x0 3005 0489 9258","код 0 3005/0489/9258","0 3005/0489/9258","карта 0 3005/0489/9258","x0 3005/0489/9258","код 0 1000 2000 3000 4000 5000 6000","0 1000 2000 3000 4000 5000 6000","карта 0 1000 2000 3000 4000 5000 6000","x0 1000 2000 3000 4000 5000 6000","код 0 2204.4132.9947 списка","0 2204.4132.9947 списка","карта 0 2204.4132.9947 списка","x0 2204.4132.9947 списка","код 0 2204-4132-9947 список","0 2204-4132-9947 список","карта 0 2204-4132-9947 список","x0 2204-4132-9947 список","код 0 2.0000-0000-0000","0 2.0000-0000-0000","карта 0 2.0000-0000-0000","x0 2.0000-0000-0000","код 0 2.0000 0000 0000","0 2.0000 0000 0000","карта 0 2.0000 0000 0000","x0 2.0000 0000 0000","код 0 2.0000/0000/0000","0 2.0000/0000/0000","карта 0 2.0000/0000/0000","x0 2.0000/0000/0000","код 0 2.0000.0000.0000.0000","0 2.0000.0000.0000.0000","карта 0 2.0000.0000.0000.0000","x0 2.0000.0000.0000.0000","код 0 0.0000-0000-0000","0 0.0000-0000-0000","карта 0 0.0000-0000-0000","x0 0.0000-0000-0000","код 0 0.0000 0000 0000","0 0.0000 0000 0000","карта 0 0.0000 0000 0000","x0 0.0000 0000 0000","код 0 0.0000/0000/0000","0 0.0000/0000/0000","карта 0 0.0000/0000/0000","x0 0.0000/0000/0000","код 0 0.0000.0000.0000.0000","0 0.0000.0000.0000.0000","карта 0 0.0000.0000.0000.0000","x0 0.0000.0000.0000.0000","код x0.2204.4132.9947","карта x0.2204.4132.9947","xx0.2204.4132.9947","код x0.2204-4132-9947","карта x0.2204-4132-9947","xx0.2204-4132-9947","код x0.2204 4132 9947","карта x0.2204 4132 9947","xx0.2204 4132 9947","код x0.2204/4132/9947","карта x0.2204/4132/9947","xx0.2204/4132/9947","код x0.0000.0000.0000","карта x0.0000.0000.0000","xx0.0000.0000.0000","код x0.0000-0000-0000","карта x0.0000-0000-0000","xx0.0000-0000-0000","код x0.0000 0000 0000","карта x0.0000 0000 0000","xx0.0000 0000 0000","код x0.0000/0000/0000","карта x0.0000/0000/0000","xx0.0000/0000/0000","код x0.0000.0000.0000.0000","карта x0.0000.0000.0000.0000","xx0.0000.0000.0000.0000","код x0.0000-0000-0000-0000","карта x0.0000-0000-0000-0000","xx0.0000-0000-0000-0000","код x0.0000 0000 0000 0000","карта x0.0000 0000 0000 0000","xx0.0000 0000 0000 0000","код x0.0000/0000/0000/0000","карта x0.0000/0000/0000/0000","xx0.0000/0000/0000/0000","код x0.3005.0489.9258","карта x0.3005.0489.9258","xx0.3005.0489.9258","код x0.2204.4132.9947.0000","карта x0.2204.4132.9947.0000","xx0.2204.4132.9947.0000","код x0.2204-4132-9947-0000","карта x0.2204-4132-9947-0000","xx0.2204-4132-9947-0000","код x0.2204/4132/9947/0000","карта x0.2204/4132/9947/0000","xx0.2204/4132/9947/0000","код x0.2204 4132 9947 0000","карта x0.2204 4132 9947 0000","xx0.2204 4132 9947 0000","код x0.2204.4132.9947.0018","карта x0.2204.4132.9947.0018","xx0.2204.4132.9947.0018","код x0.2204-4132-9947-0018","карта x0.2204-4132-9947-0018","xx0.2204-4132-9947-0018","код x0.2204/4132/9947/0018","карта x0.2204/4132/9947/0018","xx0.2204/4132/9947/0018","код x0.0.2204.4132.9947","карта x0.0.2204.4132.9947","xx0.0.2204.4132.9947","код x0.0.0000.0000.0000","карта x0.0.0000.0000.0000","xx0.0.0000.0000.0000","код x0.2.2204.4132.9947","карта x0.2.2204.4132.9947","xx0.2.2204.4132.9947","код x0.1.2204.4132.9947","карта x0.1.2204.4132.9947","xx0.1.2204.4132.9947","код x0.2204.4132","карта x0.2204.4132","xx0.2204.4132","код x0.34567890123","карта x0.34567890123","xx0.34567890123","код x0.044525225","карта x0.044525225","xx0.044525225","код x0.220441329947","карта x0.220441329947","xx0.220441329947","код x0.300504899258","карта x0.300504899258","xx0.300504899258","код x0.0000000000","карта x0.0000000000","xx0.0000000000","код x0.000000000000","карта x0.000000000000","xx0.000000000000","код x0.2204.9947.4132.0000","карта x0.2204.9947.4132.0000","xx0.2204.9947.4132.0000","код x0.2222.2222.2222.2222","карта x0.2222.2222.2222.2222","xx0.2222.2222.2222.2222","код x0.2204.4132.9947 0000","карта x0.2204.4132.9947 0000","xx0.2204.4132.9947 0000","код x0.2204.4132.9947 0018","карта x0.2204.4132.9947 0018","xx0.2204.4132.9947 0018","код x0.2204-4132-9947 0000","карта x0.2204-4132-9947 0000","xx0.2204-4132-9947 0000","код x0.2204/4132/9947 0000","карта x0.2204/4132/9947 0000","xx0.2204/4132/9947 0000","код x0.24.82.01.43.38","карта x0.24.82.01.43.38","xx0.24.82.01.43.38","код x0.378/123/456/94","карта x0.378/123/456/94","xx0.378/123/456/94","код x0.774358.417509","карта x0.774358.417509","xx0.774358.417509","код x0.0.0.0000.0000.0000","карта x0.0.0.0000.0000.0000","xx0.0.0.0000.0000.0000","код x0.0.2.2204.4132.9947","карта x0.0.2.2204.4132.9947","xx0.0.2.2204.4132.9947","код x0.2.2.2204.4132.9947","карта x0.2.2.2204.4132.9947","xx0.2.2.2204.4132.9947","код x0.2.0.2204.4132.9947","карта x0.2.0.2204.4132.9947","xx0.2.0.2204.4132.9947","код x0.1.0.0000.0000.0000","карта x0.1.0.0000.0000.0000","xx0.1.0.0000.0000.0000","код x0.2.0000.0000.0000","карта x0.2.0000.0000.0000","xx0.2.0000.0000.0000","код x0.0.2204.4132.9947.0018","карта x0.0.2204.4132.9947.0018","xx0.0.2204.4132.9947.0018","код x0.0.2204-4132-9947-0018","карта x0.0.2204-4132-9947-0018","xx0.0.2204-4132-9947-0018","код x0.2222-2222-2222-2222","карта x0.2222-2222-2222-2222","xx0.2222-2222-2222-2222","код x0.2222 2222 2222 2222","карта x0.2222 2222 2222 2222","xx0.2222 2222 2222 2222","код x0.2222/2222/2222/2222","карта x0.2222/2222/2222/2222","xx0.2222/2222/2222/2222","код x0.1111.1111.1111.1111","карта x0.1111.1111.1111.1111","xx0.1111.1111.1111.1111","код x0.2204.4132.9947.0000.0000","карта x0.2204.4132.9947.0000.0000","xx0.2204.4132.9947.0000.0000","код x0.2204.4132.9947 1.2204.4132.9947","карта x0.2204.4132.9947 1.2204.4132.9947","xx0.2204.4132.9947 1.2204.4132.9947","код x0.2204.4132.9947 0000000000","карта x0.2204.4132.9947 0000000000","xx0.2204.4132.9947 0000000000","код x0.3005-0489-9258","карта x0.3005-0489-9258","xx0.3005-0489-9258","код x0.3005 0489 9258","карта x0.3005 0489 9258","xx0.3005 0489 9258","код x0.3005/0489/9258","карта x0.3005/0489/9258","xx0.3005/0489/9258","код x0.1000 2000 3000 4000 5000 6000","карта x0.1000 2000 3000 4000 5000 6000","xx0.1000 2000 3000 4000 5000 6000","код x0.2204.4132.9947 списка","карта x0.2204.4132.9947 списка","xx0.2204.4132.9947 списка","код x0.2204-4132-9947 список","карта x0.2204-4132-9947 список","xx0.2204-4132-9947 список","код x0.2.0000-0000-0000","карта x0.2.0000-0000-0000","xx0.2.0000-0000-0000","код x0.2.0000 0000 0000","карта x0.2.0000 0000 0000","xx0.2.0000 0000 0000","код x0.2.0000/0000/0000","карта x0.2.0000/0000/0000","xx0.2.0000/0000/0000","код x0.2.0000.0000.0000.0000","карта x0.2.0000.0000.0000.0000","xx0.2.0000.0000.0000.0000","код x0.0.0000-0000-0000","карта x0.0.0000-0000-0000","xx0.0.0000-0000-0000","код x0.0.0000 0000 0000","карта x0.0.0000 0000 0000","xx0.0.0000 0000 0000","код x0.0.0000/0000/0000","карта x0.0.0000/0000/0000","xx0.0.0000/0000/0000","код x0.0.0000.0000.0000.0000","карта x0.0.0000.0000.0000.0000","xx0.0.0000.0000.0000.0000","код x0-2204.4132.9947","карта x0-2204.4132.9947","xx0-2204.4132.9947","код x0-2204-4132-9947","карта x0-2204-4132-9947","xx0-2204-4132-9947","код x0-2204 4132 9947","карта x0-2204 4132 9947","xx0-2204 4132 9947","код x0-2204/4132/9947","карта x0-2204/4132/9947","xx0-2204/4132/9947","код x0-0000.0000.0000","карта x0-0000.0000.0000","xx0-0000.0000.0000","код x0-0000-0000-0000","карта x0-0000-0000-0000","xx0-0000-0000-0000","код x0-0000 0000 0000","карта x0-0000 0000 0000","xx0-0000 0000 0000","код x0-0000/0000/0000","карта x0-0000/0000/0000","xx0-0000/0000/0000","код x0-0000.0000.0000.0000","карта x0-0000.0000.0000.0000","xx0-0000.0000.0000.0000","код x0-0000-0000-0000-0000","карта x0-0000-0000-0000-0000","xx0-0000-0000-0000-0000","код x0-0000 0000 0000 0000","карта x0-0000 0000 0000 0000","xx0-0000 0000 0000 0000","код x0-0000/0000/0000/0000","карта x0-0000/0000/0000/0000","xx0-0000/0000/0000/0000","код x0-3005.0489.9258","карта x0-3005.0489.9258","xx0-3005.0489.9258","код x0-2204.4132.9947.0000","карта x0-2204.4132.9947.0000","xx0-2204.4132.9947.0000","код x0-2204-4132-9947-0000","карта x0-2204-4132-9947-0000","xx0-2204-4132-9947-0000","код x0-2204/4132/9947/0000","карта x0-2204/4132/9947/0000","xx0-2204/4132/9947/0000","код x0-2204 4132 9947 0000","карта x0-2204 4132 9947 0000","xx0-2204 4132 9947 0000","код x0-2204.4132.9947.0018","карта x0-2204.4132.9947.0018","xx0-2204.4132.9947.0018","код x0-2204-4132-9947-0018","карта x0-2204-4132-9947-0018","xx0-2204-4132-9947-0018","код x0-2204/4132/9947/0018","карта x0-2204/4132/9947/0018","xx0-2204/4132/9947/0018","код x0-0.2204.4132.9947","карта x0-0.2204.4132.9947","xx0-0.2204.4132.9947","код x0-0.0000.0000.0000","карта x0-0.0000.0000.0000","xx0-0.0000.0000.0000","код x0-2.2204.4132.9947","карта x0-2.2204.4132.9947","xx0-2.2204.4132.9947","код x0-1.2204.4132.9947","карта x0-1.2204.4132.9947","xx0-1.2204.4132.9947","код x0-2204.4132","карта x0-2204.4132","xx0-2204.4132","код x0-34567890123","карта x0-34567890123","xx0-34567890123","код x0-044525225","карта x0-044525225","xx0-044525225","код x0-220441329947","карта x0-220441329947","xx0-220441329947","код x0-300504899258","карта x0-300504899258","xx0-300504899258","код x0-0000000000","карта x0-0000000000","xx0-0000000000","код x0-000000000000","карта x0-000000000000","xx0-000000000000","код x0-2204.9947.4132.0000","карта x0-2204.9947.4132.0000","xx0-2204.9947.4132.0000","код x0-2222.2222.2222.2222","карта x0-2222.2222.2222.2222","xx0-2222.2222.2222.2222","код x0-2204.4132.9947 0000","карта x0-2204.4132.9947 0000","xx0-2204.4132.9947 0000","код x0-2204.4132.9947 0018","карта x0-2204.4132.9947 0018","xx0-2204.4132.9947 0018","код x0-2204-4132-9947 0000","карта x0-2204-4132-9947 0000","xx0-2204-4132-9947 0000","код x0-2204/4132/9947 0000","карта x0-2204/4132/9947 0000","xx0-2204/4132/9947 0000","код x0-24.82.01.43.38","карта x0-24.82.01.43.38","xx0-24.82.01.43.38","код x0-378/123/456/94","карта x0-378/123/456/94","xx0-378/123/456/94","код x0-774358.417509","карта x0-774358.417509","xx0-774358.417509","код x0-0.0.0000.0000.0000","карта x0-0.0.0000.0000.0000","xx0-0.0.0000.0000.0000","код x0-0.2.2204.4132.9947","карта x0-0.2.2204.4132.9947","xx0-0.2.2204.4132.9947","код x0-2.2.2204.4132.9947","карта x0-2.2.2204.4132.9947","xx0-2.2.2204.4132.9947","код x0-2.0.2204.4132.9947","карта x0-2.0.2204.4132.9947","xx0-2.0.2204.4132.9947","код x0-1.0.0000.0000.0000","карта x0-1.0.0000.0000.0000","xx0-1.0.0000.0000.0000","код x0-2.0000.0000.0000","карта x0-2.0000.0000.0000","xx0-2.0000.0000.0000","код x0-0.2204.4132.9947.0018","карта x0-0.2204.4132.9947.0018","xx0-0.2204.4132.9947.0018","код x0-0.2204-4132-9947-0018","карта x0-0.2204-4132-9947-0018","xx0-0.2204-4132-9947-0018","код x0-2222-2222-2222-2222","карта x0-2222-2222-2222-2222","xx0-2222-2222-2222-2222","код x0-2222 2222 2222 2222","карта x0-2222 2222 2222 2222","xx0-2222 2222 2222 2222","код x0-2222/2222/2222/2222","карта x0-2222/2222/2222/2222","xx0-2222/2222/2222/2222","код x0-1111.1111.1111.1111","карта x0-1111.1111.1111.1111","xx0-1111.1111.1111.1111","код x0-2204.4132.9947.0000.0000","карта x0-2204.4132.9947.0000.0000","xx0-2204.4132.9947.0000.0000","код x0-2204.4132.9947 1.2204.4132.9947","карта x0-2204.4132.9947 1.2204.4132.9947","xx0-2204.4132.9947 1.2204.4132.9947","код x0-2204.4132.9947 0000000000","карта x0-2204.4132.9947 0000000000","xx0-2204.4132.9947 0000000000","код x0-3005-0489-9258","карта x0-3005-0489-9258","xx0-3005-0489-9258","код x0-3005 0489 9258","карта x0-3005 0489 9258","xx0-3005 0489 9258","код x0-3005/0489/9258","карта x0-3005/0489/9258","xx0-3005/0489/9258","код x0-1000 2000 3000 4000 5000 6000","карта x0-1000 2000 3000 4000 5000 6000","xx0-1000 2000 3000 4000 5000 6000","код x0-2204.4132.9947 списка","карта x0-2204.4132.9947 списка","xx0-2204.4132.9947 списка","код x0-2204-4132-9947 список","карта x0-2204-4132-9947 список","xx0-2204-4132-9947 список","код x0-2.0000-0000-0000","карта x0-2.0000-0000-0000","xx0-2.0000-0000-0000","код x0-2.0000 0000 0000","карта x0-2.0000 0000 0000","xx0-2.0000 0000 0000","код x0-2.0000/0000/0000","карта x0-2.0000/0000/0000","xx0-2.0000/0000/0000","код x0-2.0000.0000.0000.0000","карта x0-2.0000.0000.0000.0000","xx0-2.0000.0000.0000.0000","код x0-0.0000-0000-0000","карта x0-0.0000-0000-0000","xx0-0.0000-0000-0000","код x0-0.0000 0000 0000","карта x0-0.0000 0000 0000","xx0-0.0000 0000 0000","код x0-0.0000/0000/0000","карта x0-0.0000/0000/0000","xx0-0.0000/0000/0000","код x0-0.0000.0000.0000.0000","карта x0-0.0000.0000.0000.0000","xx0-0.0000.0000.0000.0000","код x0/2204.4132.9947","карта x0/2204.4132.9947","xx0/2204.4132.9947","код x0/2204-4132-9947","карта x0/2204-4132-9947","xx0/2204-4132-9947","код x0/2204 4132 9947","карта x0/2204 4132 9947","xx0/2204 4132 9947","код x0/2204/4132/9947","карта x0/2204/4132/9947","xx0/2204/4132/9947","код x0/0000.0000.0000","карта x0/0000.0000.0000","xx0/0000.0000.0000","код x0/0000-0000-0000","карта x0/0000-0000-0000","xx0/0000-0000-0000","код x0/0000 0000 0000","карта x0/0000 0000 0000","xx0/0000 0000 0000","код x0/0000/0000/0000","карта x0/0000/0000/0000","xx0/0000/0000/0000","код x0/0000.0000.0000.0000","карта x0/0000.0000.0000.0000","xx0/0000.0000.0000.0000","код x0/0000-0000-0000-0000","карта x0/0000-0000-0000-0000","xx0/0000-0000-0000-0000","код x0/0000 0000 0000 0000","карта x0/0000 0000 0000 0000","xx0/0000 0000 0000 0000","код x0/0000/0000/0000/0000","карта x0/0000/0000/0000/0000","xx0/0000/0000/0000/0000","код x0/3005.0489.9258","карта x0/3005.0489.9258","xx0/3005.0489.9258","код x0/2204.4132.9947.0000","карта x0/2204.4132.9947.0000","xx0/2204.4132.9947.0000","код x0/2204-4132-9947-0000","карта x0/2204-4132-9947-0000","xx0/2204-4132-9947-0000","код x0/2204/4132/9947/0000","карта x0/2204/4132/9947/0000","xx0/2204/4132/9947/0000","код x0/2204 4132 9947 0000","карта x0/2204 4132 9947 0000","xx0/2204 4132 9947 0000","код x0/2204.4132.9947.0018","карта x0/2204.4132.9947.0018","xx0/2204.4132.9947.0018","код x0/2204-4132-9947-0018","карта x0/2204-4132-9947-0018","xx0/2204-4132-9947-0018","код x0/2204/4132/9947/0018","карта x0/2204/4132/9947/0018","xx0/2204/4132/9947/0018","код x0/0.2204.4132.9947","карта x0/0.2204.4132.9947","xx0/0.2204.4132.9947","код x0/0.0000.0000.0000","карта x0/0.0000.0000.0000","xx0/0.0000.0000.0000","код x0/2.2204.4132.9947","карта x0/2.2204.4132.9947","xx0/2.2204.4132.9947","код x0/1.2204.4132.9947","карта x0/1.2204.4132.9947","xx0/1.2204.4132.9947","код x0/2204.4132","карта x0/2204.4132","xx0/2204.4132","код x0/34567890123","карта x0/34567890123","xx0/34567890123","код x0/044525225","карта x0/044525225","xx0/044525225","код x0/220441329947","карта x0/220441329947","xx0/220441329947","код x0/300504899258","карта x0/300504899258","xx0/300504899258","код x0/0000000000","карта x0/0000000000","xx0/0000000000","код x0/000000000000","карта x0/000000000000","xx0/000000000000","код x0/2204.9947.4132.0000","карта x0/2204.9947.4132.0000","xx0/2204.9947.4132.0000","код x0/2222.2222.2222.2222","карта x0/2222.2222.2222.2222","xx0/2222.2222.2222.2222","код x0/2204.4132.9947 0000","карта x0/2204.4132.9947 0000","xx0/2204.4132.9947 0000","код x0/2204.4132.9947 0018","карта x0/2204.4132.9947 0018","xx0/2204.4132.9947 0018","код x0/2204-4132-9947 0000","карта x0/2204-4132-9947 0000","xx0/2204-4132-9947 0000","код x0/2204/4132/9947 0000","карта x0/2204/4132/9947 0000","xx0/2204/4132/9947 0000","код x0/24.82.01.43.38","карта x0/24.82.01.43.38","xx0/24.82.01.43.38","код x0/378/123/456/94","карта x0/378/123/456/94","xx0/378/123/456/94","код x0/774358.417509","карта x0/774358.417509","xx0/774358.417509","код x0/0.0.0000.0000.0000","карта x0/0.0.0000.0000.0000","xx0/0.0.0000.0000.0000","код x0/0.2.2204.4132.9947","карта x0/0.2.2204.4132.9947","xx0/0.2.2204.4132.9947","код x0/2.2.2204.4132.9947","карта x0/2.2.2204.4132.9947","xx0/2.2.2204.4132.9947","код x0/2.0.2204.4132.9947","карта x0/2.0.2204.4132.9947","xx0/2.0.2204.4132.9947","код x0/1.0.0000.0000.0000","карта x0/1.0.0000.0000.0000","xx0/1.0.0000.0000.0000","код x0/2.0000.0000.0000","карта x0/2.0000.0000.0000","xx0/2.0000.0000.0000","код x0/0.2204.4132.9947.0018","карта x0/0.2204.4132.9947.0018","xx0/0.2204.4132.9947.0018","код x0/0.2204-4132-9947-0018","карта x0/0.2204-4132-9947-0018","xx0/0.2204-4132-9947-0018","код x0/2222-2222-2222-2222","карта x0/2222-2222-2222-2222","xx0/2222-2222-2222-2222","код x0/2222 2222 2222 2222","карта x0/2222 2222 2222 2222","xx0/2222 2222 2222 2222","код x0/2222/2222/2222/2222","карта x0/2222/2222/2222/2222","xx0/2222/2222/2222/2222","код x0/1111.1111.1111.1111","карта x0/1111.1111.1111.1111","xx0/1111.1111.1111.1111","код x0/2204.4132.9947.0000.0000","карта x0/2204.4132.9947.0000.0000","xx0/2204.4132.9947.0000.0000","код x0/2204.4132.9947 1.2204.4132.9947","карта x0/2204.4132.9947 1.2204.4132.9947","xx0/2204.4132.9947 1.2204.4132.9947","код x0/2204.4132.9947 0000000000","карта x0/2204.4132.9947 0000000000","xx0/2204.4132.9947 0000000000","код x0/3005-0489-9258","карта x0/3005-0489-9258","xx0/3005-0489-9258","код x0/3005 0489 9258","карта x0/3005 0489 9258","xx0/3005 0489 9258","код x0/3005/0489/9258","карта x0/3005/0489/9258","xx0/3005/0489/9258","код x0/1000 2000 3000 4000 5000 6000","карта x0/1000 2000 3000 4000 5000 6000","xx0/1000 2000 3000 4000 5000 6000","код x0/2204.4132.9947 списка","карта x0/2204.4132.9947 списка","xx0/2204.4132.9947 списка","код x0/2204-4132-9947 список","карта x0/2204-4132-9947 список","xx0/2204-4132-9947 список","код x0/2.0000-0000-0000","карта x0/2.0000-0000-0000","xx0/2.0000-0000-0000","код x0/2.0000 0000 0000","карта x0/2.0000 0000 0000","xx0/2.0000 0000 0000","код x0/2.0000/0000/0000","карта x0/2.0000/0000/0000","xx0/2.0000/0000/0000","код x0/2.0000.0000.0000.0000","карта x0/2.0000.0000.0000.0000","xx0/2.0000.0000.0000.0000","код x0/0.0000-0000-0000","карта x0/0.0000-0000-0000","xx0/0.0000-0000-0000","код x0/0.0000 0000 0000","карта x0/0.0000 0000 0000","xx0/0.0000 0000 0000","код x0/0.0000/0000/0000","карта x0/0.0000/0000/0000","xx0/0.0000/0000/0000","код x0/0.0000.0000.0000.0000","карта x0/0.0000.0000.0000.0000","xx0/0.0000.0000.0000.0000","код x0 2204.4132.9947","карта x0 2204.4132.9947","xx0 2204.4132.9947","код x0 2204-4132-9947","карта x0 2204-4132-9947","xx0 2204-4132-9947","код x0 2204 4132 9947","карта x0 2204 4132 9947","xx0 2204 4132 9947","код x0 2204/4132/9947","карта x0 2204/4132/9947","xx0 2204/4132/9947","код x0 0000.0000.0000","карта x0 0000.0000.0000","xx0 0000.0000.0000","код x0 0000-0000-0000","карта x0 0000-0000-0000","xx0 0000-0000-0000","код x0 0000 0000 0000","карта x0 0000 0000 0000","xx0 0000 0000 0000","код x0 0000/0000/0000","карта x0 0000/0000/0000","xx0 0000/0000/0000","код x0 0000.0000.0000.0000","карта x0 0000.0000.0000.0000","xx0 0000.0000.0000.0000","код x0 0000-0000-0000-0000","карта x0 0000-0000-0000-0000","xx0 0000-0000-0000-0000","код x0 0000 0000 0000 0000","карта x0 0000 0000 0000 0000","xx0 0000 0000 0000 0000","код x0 0000/0000/0000/0000","карта x0 0000/0000/0000/0000","xx0 0000/0000/0000/0000","код x0 3005.0489.9258","карта x0 3005.0489.9258","xx0 3005.0489.9258","код x0 2204.4132.9947.0000","карта x0 2204.4132.9947.0000","xx0 2204.4132.9947.0000","код x0 2204-4132-9947-0000","карта x0 2204-4132-9947-0000","xx0 2204-4132-9947-0000","код x0 2204/4132/9947/0000","карта x0 2204/4132/9947/0000","xx0 2204/4132/9947/0000","код x0 2204 4132 9947 0000","карта x0 2204 4132 9947 0000","xx0 2204 4132 9947 0000","код x0 2204.4132.9947.0018","карта x0 2204.4132.9947.0018","xx0 2204.4132.9947.0018","код x0 2204-4132-9947-0018","карта x0 2204-4132-9947-0018","xx0 2204-4132-9947-0018","код x0 2204/4132/9947/0018","карта x0 2204/4132/9947/0018","xx0 2204/4132/9947/0018","код x0 0.2204.4132.9947","карта x0 0.2204.4132.9947","xx0 0.2204.4132.9947","код x0 0.0000.0000.0000","карта x0 0.0000.0000.0000","xx0 0.0000.0000.0000","код x0 2.2204.4132.9947","карта x0 2.2204.4132.9947","xx0 2.2204.4132.9947","код x0 1.2204.4132.9947","карта x0 1.2204.4132.9947","xx0 1.2204.4132.9947","код x0 2204.4132","карта x0 2204.4132","xx0 2204.4132","код x0 34567890123","карта x0 34567890123","xx0 34567890123","код x0 044525225","карта x0 044525225","xx0 044525225","код x0 220441329947","карта x0 220441329947","xx0 220441329947","код x0 300504899258","карта x0 300504899258","xx0 300504899258","код x0 0000000000","карта x0 0000000000","xx0 0000000000","код x0 000000000000","карта x0 000000000000","xx0 000000000000","код x0 2204.9947.4132.0000","карта x0 2204.9947.4132.0000","xx0 2204.9947.4132.0000","код x0 2222.2222.2222.2222","карта x0 2222.2222.2222.2222","xx0 2222.2222.2222.2222","код x0 2204.4132.9947 0000","карта x0 2204.4132.9947 0000","xx0 2204.4132.9947 0000","код x0 2204.4132.9947 0018","карта x0 2204.4132.9947 0018","xx0 2204.4132.9947 0018","код x0 2204-4132-9947 0000","карта x0 2204-4132-9947 0000","xx0 2204-4132-9947 0000","код x0 2204/4132/9947 0000","карта x0 2204/4132/9947 0000","xx0 2204/4132/9947 0000","код x0 24.82.01.43.38","карта x0 24.82.01.43.38","xx0 24.82.01.43.38","код x0 378/123/456/94","карта x0 378/123/456/94","xx0 378/123/456/94","код x0 774358.417509","карта x0 774358.417509","xx0 774358.417509","код x0 0.0.0000.0000.0000","карта x0 0.0.0000.0000.0000","xx0 0.0.0000.0000.0000","код x0 0.2.2204.4132.9947","карта x0 0.2.2204.4132.9947","xx0 0.2.2204.4132.9947","код x0 2.2.2204.4132.9947","карта x0 2.2.2204.4132.9947","xx0 2.2.2204.4132.9947","код x0 2.0.2204.4132.9947","карта x0 2.0.2204.4132.9947","xx0 2.0.2204.4132.9947","код x0 1.0.0000.0000.0000","карта x0 1.0.0000.0000.0000","xx0 1.0.0000.0000.0000","код x0 2.0000.0000.0000","карта x0 2.0000.0000.0000","xx0 2.0000.0000.0000","код x0 0.2204.4132.9947.0018","карта x0 0.2204.4132.9947.0018","xx0 0.2204.4132.9947.0018","код x0 0.2204-4132-9947-0018","карта x0 0.2204-4132-9947-0018","xx0 0.2204-4132-9947-0018","код x0 2222-2222-2222-2222","карта x0 2222-2222-2222-2222","xx0 2222-2222-2222-2222","код x0 2222 2222 2222 2222","карта x0 2222 2222 2222 2222","xx0 2222 2222 2222 2222","код x0 2222/2222/2222/2222","карта x0 2222/2222/2222/2222","xx0 2222/2222/2222/2222","код x0 1111.1111.1111.1111","карта x0 1111.1111.1111.1111","xx0 1111.1111.1111.1111","код x0 2204.4132.9947.0000.0000","карта x0 2204.4132.9947.0000.0000","xx0 2204.4132.9947.0000.0000","код x0 2204.4132.9947 1.2204.4132.9947","карта x0 2204.4132.9947 1.2204.4132.9947","xx0 2204.4132.9947 1.2204.4132.9947","код x0 2204.4132.9947 0000000000","карта x0 2204.4132.9947 0000000000","xx0 2204.4132.9947 0000000000","код x0 3005-0489-9258","карта x0 3005-0489-9258","xx0 3005-0489-9258","код x0 3005 0489 9258","карта x0 3005 0489 9258","xx0 3005 0489 9258","код x0 3005/0489/9258","карта x0 3005/0489/9258","xx0 3005/0489/9258","код x0 1000 2000 3000 4000 5000 6000","карта x0 1000 2000 3000 4000 5000 6000","xx0 1000 2000 3000 4000 5000 6000","код x0 2204.4132.9947 списка","карта x0 2204.4132.9947 списка","xx0 2204.4132.9947 списка","код x0 2204-4132-9947 список","карта x0 2204-4132-9947 список","xx0 2204-4132-9947 список","код x0 2.0000-0000-0000","карта x0 2.0000-0000-0000","xx0 2.0000-0000-0000","код x0 2.0000 0000 0000","карта x0 2.0000 0000 0000","xx0 2.0000 0000 0000","код x0 2.0000/0000/0000","карта x0 2.0000/0000/0000","xx0 2.0000/0000/0000","код x0 2.0000.0000.0000.0000","карта x0 2.0000.0000.0000.0000","xx0 2.0000.0000.0000.0000","код x0 0.0000-0000-0000","карта x0 0.0000-0000-0000","xx0 0.0000-0000-0000","код x0 0.0000 0000 0000","карта x0 0.0000 0000 0000","xx0 0.0000 0000 0000","код x0 0.0000/0000/0000","карта x0 0.0000/0000/0000","xx0 0.0000/0000/0000","код x0 0.0000.0000.0000.0000","карта x0 0.0000.0000.0000.0000","xx0 0.0000.0000.0000.0000","код 00.2204.4132.9947","00.2204.4132.9947","карта 00.2204.4132.9947","x00.2204.4132.9947","код 00.2204-4132-9947","00.2204-4132-9947","карта 00.2204-4132-9947","x00.2204-4132-9947","код 00.2204 4132 9947","00.2204 4132 9947","карта 00.2204 4132 9947","x00.2204 4132 9947","код 00.2204/4132/9947","00.2204/4132/9947","карта 00.2204/4132/9947","x00.2204/4132/9947","код 00.0000.0000.0000","00.0000.0000.0000","карта 00.0000.0000.0000","x00.0000.0000.0000","код 00.0000-0000-0000","00.0000-0000-0000","карта 00.0000-0000-0000","x00.0000-0000-0000","код 00.0000 0000 0000","00.0000 0000 0000","карта 00.0000 0000 0000","x00.0000 0000 0000","код 00.0000/0000/0000","00.0000/0000/0000","карта 00.0000/0000/0000","x00.0000/0000/0000","код 00.0000.0000.0000.0000","00.0000.0000.0000.0000","карта 00.0000.0000.0000.0000","x00.0000.0000.0000.0000","код 00.0000-0000-0000-0000","00.0000-0000-0000-0000","карта 00.0000-0000-0000-0000","x00.0000-0000-0000-0000","код 00.0000 0000 0000 0000","00.0000 0000 0000 0000","карта 00.0000 0000 0000 0000","x00.0000 0000 0000 0000","код 00.0000/0000/0000/0000","00.0000/0000/0000/0000","карта 00.0000/0000/0000/0000","x00.0000/0000/0000/0000","код 00.3005.0489.9258","00.3005.0489.9258","карта 00.3005.0489.9258","x00.3005.0489.9258","код 00.2204.4132.9947.0000","00.2204.4132.9947.0000","карта 00.2204.4132.9947.0000","x00.2204.4132.9947.0000","код 00.2204-4132-9947-0000","00.2204-4132-9947-0000","карта 00.2204-4132-9947-0000","x00.2204-4132-9947-0000","код 00.2204/4132/9947/0000","00.2204/4132/9947/0000","карта 00.2204/4132/9947/0000","x00.2204/4132/9947/0000","код 00.2204 4132 9947 0000","00.2204 4132 9947 0000","карта 00.2204 4132 9947 0000","x00.2204 4132 9947 0000","код 00.2204.4132.9947.0018","00.2204.4132.9947.0018","карта 00.2204.4132.9947.0018","x00.2204.4132.9947.0018","код 00.2204-4132-9947-0018","00.2204-4132-9947-0018","карта 00.2204-4132-9947-0018","x00.2204-4132-9947-0018","код 00.2204/4132/9947/0018","00.2204/4132/9947/0018","карта 00.2204/4132/9947/0018","x00.2204/4132/9947/0018","код 00.0.2204.4132.9947","00.0.2204.4132.9947","карта 00.0.2204.4132.9947","x00.0.2204.4132.9947","код 00.0.0000.0000.0000","00.0.0000.0000.0000","карта 00.0.0000.0000.0000","x00.0.0000.0000.0000","код 00.2.2204.4132.9947","00.2.2204.4132.9947","карта 00.2.2204.4132.9947","x00.2.2204.4132.9947","код 00.1.2204.4132.9947","00.1.2204.4132.9947","карта 00.1.2204.4132.9947","x00.1.2204.4132.9947","код 00.2204.4132","00.2204.4132","карта 00.2204.4132","x00.2204.4132","код 00.34567890123","00.34567890123","карта 00.34567890123","x00.34567890123","код 00.044525225","00.044525225","карта 00.044525225","x00.044525225","код 00.220441329947","00.220441329947","карта 00.220441329947","x00.220441329947","код 00.300504899258","00.300504899258","карта 00.300504899258","x00.300504899258","код 00.0000000000","00.0000000000","карта 00.0000000000","x00.0000000000","код 00.000000000000","00.000000000000","карта 00.000000000000","x00.000000000000","код 00.2204.9947.4132.0000","00.2204.9947.4132.0000","карта 00.2204.9947.4132.0000","x00.2204.9947.4132.0000","код 00.2222.2222.2222.2222","00.2222.2222.2222.2222","карта 00.2222.2222.2222.2222","x00.2222.2222.2222.2222","код 00.2204.4132.9947 0000","00.2204.4132.9947 0000","карта 00.2204.4132.9947 0000","x00.2204.4132.9947 0000","код 00.2204.4132.9947 0018","00.2204.4132.9947 0018","карта 00.2204.4132.9947 0018","x00.2204.4132.9947 0018","код 00.2204-4132-9947 0000","00.2204-4132-9947 0000","карта 00.2204-4132-9947 0000","x00.2204-4132-9947 0000","код 00.2204/4132/9947 0000","00.2204/4132/9947 0000","карта 00.2204/4132/9947 0000","x00.2204/4132/9947 0000","код 00.24.82.01.43.38","00.24.82.01.43.38","карта 00.24.82.01.43.38","x00.24.82.01.43.38","код 00.378/123/456/94","00.378/123/456/94","карта 00.378/123/456/94","x00.378/123/456/94","код 00.774358.417509","00.774358.417509","карта 00.774358.417509","x00.774358.417509","код 00.0.0.0000.0000.0000","00.0.0.0000.0000.0000","карта 00.0.0.0000.0000.0000","x00.0.0.0000.0000.0000","код 00.0.2.2204.4132.9947","00.0.2.2204.4132.9947","карта 00.0.2.2204.4132.9947","x00.0.2.2204.4132.9947","код 00.2.2.2204.4132.9947","00.2.2.2204.4132.9947","карта 00.2.2.2204.4132.9947","x00.2.2.2204.4132.9947","код 00.2.0.2204.4132.9947","00.2.0.2204.4132.9947","карта 00.2.0.2204.4132.9947","x00.2.0.2204.4132.9947","код 00.1.0.0000.0000.0000","00.1.0.0000.0000.0000","карта 00.1.0.0000.0000.0000","x00.1.0.0000.0000.0000","код 00.2.0000.0000.0000","00.2.0000.0000.0000","карта 00.2.0000.0000.0000","x00.2.0000.0000.0000","код 00.0.2204.4132.9947.0018","00.0.2204.4132.9947.0018","карта 00.0.2204.4132.9947.0018","x00.0.2204.4132.9947.0018","код 00.0.2204-4132-9947-0018","00.0.2204-4132-9947-0018","карта 00.0.2204-4132-9947-0018","x00.0.2204-4132-9947-0018","код 00.2222-2222-2222-2222","00.2222-2222-2222-2222","карта 00.2222-2222-2222-2222","x00.2222-2222-2222-2222","код 00.2222 2222 2222 2222","00.2222 2222 2222 2222","карта 00.2222 2222 2222 2222","x00.2222 2222 2222 2222","код 00.2222/2222/2222/2222","00.2222/2222/2222/2222","карта 00.2222/2222/2222/2222","x00.2222/2222/2222/2222","код 00.1111.1111.1111.1111","00.1111.1111.1111.1111","карта 00.1111.1111.1111.1111","x00.1111.1111.1111.1111","код 00.2204.4132.9947.0000.0000","00.2204.4132.9947.0000.0000","карта 00.2204.4132.9947.0000.0000","x00.2204.4132.9947.0000.0000","код 00.2204.4132.9947 1.2204.4132.9947","00.2204.4132.9947 1.2204.4132.9947","карта 00.2204.4132.9947 1.2204.4132.9947","x00.2204.4132.9947 1.2204.4132.9947","код 00.2204.4132.9947 0000000000","00.2204.4132.9947 0000000000","карта 00.2204.4132.9947 0000000000","x00.2204.4132.9947 0000000000","код 00.3005-0489-9258","00.3005-0489-9258","карта 00.3005-0489-9258","x00.3005-0489-9258","код 00.3005 0489 9258","00.3005 0489 9258","карта 00.3005 0489 9258","x00.3005 0489 9258","код 00.3005/0489/9258","00.3005/0489/9258","карта 00.3005/0489/9258","x00.3005/0489/9258","код 00.1000 2000 3000 4000 5000 6000","00.1000 2000 3000 4000 5000 6000","карта 00.1000 2000 3000 4000 5000 6000","x00.1000 2000 3000 4000 5000 6000","код 00.2204.4132.9947 списка","00.2204.4132.9947 списка","карта 00.2204.4132.9947 списка","x00.2204.4132.9947 списка","код 00.2204-4132-9947 список","00.2204-4132-9947 список","карта 00.2204-4132-9947 список","x00.2204-4132-9947 список","код 00.2.0000-0000-0000","00.2.0000-0000-0000","карта 00.2.0000-0000-0000","x00.2.0000-0000-0000","код 00.2.0000 0000 0000","00.2.0000 0000 0000","карта 00.2.0000 0000 0000","x00.2.0000 0000 0000","код 00.2.0000/0000/0000","00.2.0000/0000/0000","карта 00.2.0000/0000/0000","x00.2.0000/0000/0000","код 00.2.0000.0000.0000.0000","00.2.0000.0000.0000.0000","карта 00.2.0000.0000.0000.0000","x00.2.0000.0000.0000.0000","код 00.0.0000-0000-0000","00.0.0000-0000-0000","карта 00.0.0000-0000-0000","x00.0.0000-0000-0000","код 00.0.0000 0000 0000","00.0.0000 0000 0000","карта 00.0.0000 0000 0000","x00.0.0000 0000 0000","код 00.0.0000/0000/0000","00.0.0000/0000/0000","карта 00.0.0000/0000/0000","x00.0.0000/0000/0000","код 00.0.0000.0000.0000.0000","00.0.0000.0000.0000.0000","карта 00.0.0000.0000.0000.0000","x00.0.0000.0000.0000.0000","код 00-2204.4132.9947","00-2204.4132.9947","карта 00-2204.4132.9947","x00-2204.4132.9947","код 00-2204-4132-9947","00-2204-4132-9947","карта 00-2204-4132-9947","x00-2204-4132-9947","код 00-2204 4132 9947","00-2204 4132 9947","карта 00-2204 4132 9947","x00-2204 4132 9947","код 00-2204/4132/9947","00-2204/4132/9947","карта 00-2204/4132/9947","x00-2204/4132/9947","код 00-0000.0000.0000","00-0000.0000.0000","карта 00-0000.0000.0000","x00-0000.0000.0000","код 00-0000-0000-0000","00-0000-0000-0000","карта 00-0000-0000-0000","x00-0000-0000-0000","код 00-0000 0000 0000","00-0000 0000 0000","карта 00-0000 0000 0000","x00-0000 0000 0000","код 00-0000/0000/0000","00-0000/0000/0000","карта 00-0000/0000/0000","x00-0000/0000/0000","код 00-0000.0000.0000.0000","00-0000.0000.0000.0000","карта 00-0000.0000.0000.0000","x00-0000.0000.0000.0000","код 00-0000-0000-0000-0000","00-0000-0000-0000-0000","карта 00-0000-0000-0000-0000","x00-0000-0000-0000-0000","код 00-0000 0000 0000 0000","00-0000 0000 0000 0000","карта 00-0000 0000 0000 0000","x00-0000 0000 0000 0000","код 00-0000/0000/0000/0000","00-0000/0000/0000/0000","карта 00-0000/0000/0000/0000","x00-0000/0000/0000/0000","код 00-3005.0489.9258","00-3005.0489.9258","карта 00-3005.0489.9258","x00-3005.0489.9258","код 00-2204.4132.9947.0000","00-2204.4132.9947.0000","карта 00-2204.4132.9947.0000","x00-2204.4132.9947.0000","код 00-2204-4132-9947-0000","00-2204-4132-9947-0000","карта 00-2204-4132-9947-0000","x00-2204-4132-9947-0000","код 00-2204/4132/9947/0000","00-2204/4132/9947/0000","карта 00-2204/4132/9947/0000","x00-2204/4132/9947/0000","код 00-2204 4132 9947 0000","00-2204 4132 9947 0000","карта 00-2204 4132 9947 0000","x00-2204 4132 9947 0000","код 00-2204.4132.9947.0018","00-2204.4132.9947.0018","карта 00-2204.4132.9947.0018","x00-2204.4132.9947.0018","код 00-2204-4132-9947-0018","00-2204-4132-9947-0018","карта 00-2204-4132-9947-0018","x00-2204-4132-9947-0018","код 00-2204/4132/9947/0018","00-2204/4132/9947/0018","карта 00-2204/4132/9947/0018","x00-2204/4132/9947/0018","код 00-0.2204.4132.9947","00-0.2204.4132.9947","карта 00-0.2204.4132.9947","x00-0.2204.4132.9947","код 00-0.0000.0000.0000","00-0.0000.0000.0000","карта 00-0.0000.0000.0000","x00-0.0000.0000.0000","код 00-2.2204.4132.9947","00-2.2204.4132.9947","карта 00-2.2204.4132.9947","x00-2.2204.4132.9947","код 00-1.2204.4132.9947","00-1.2204.4132.9947","карта 00-1.2204.4132.9947","x00-1.2204.4132.9947","код 00-2204.4132","00-2204.4132","карта 00-2204.4132","x00-2204.4132","код 00-34567890123","00-34567890123","карта 00-34567890123","x00-34567890123","код 00-044525225","00-044525225","карта 00-044525225","x00-044525225","код 00-220441329947","00-220441329947","карта 00-220441329947","x00-220441329947","код 00-300504899258","00-300504899258","карта 00-300504899258","x00-300504899258","код 00-0000000000","00-0000000000","карта 00-0000000000","x00-0000000000","код 00-000000000000","00-000000000000","карта 00-000000000000","x00-000000000000","код 00-2204.9947.4132.0000","00-2204.9947.4132.0000","карта 00-2204.9947.4132.0000","x00-2204.9947.4132.0000","код 00-2222.2222.2222.2222","00-2222.2222.2222.2222","карта 00-2222.2222.2222.2222","x00-2222.2222.2222.2222","код 00-2204.4132.9947 0000","00-2204.4132.9947 0000","карта 00-2204.4132.9947 0000","x00-2204.4132.9947 0000","код 00-2204.4132.9947 0018","00-2204.4132.9947 0018","карта 00-2204.4132.9947 0018","x00-2204.4132.9947 0018","код 00-2204-4132-9947 0000","00-2204-4132-9947 0000","карта 00-2204-4132-9947 0000","x00-2204-4132-9947 0000","код 00-2204/4132/9947 0000","00-2204/4132/9947 0000","карта 00-2204/4132/9947 0000","x00-2204/4132/9947 0000","код 00-24.82.01.43.38","00-24.82.01.43.38","карта 00-24.82.01.43.38","x00-24.82.01.43.38","код 00-378/123/456/94","00-378/123/456/94","карта 00-378/123/456/94","x00-378/123/456/94","код 00-774358.417509","00-774358.417509","карта 00-774358.417509","x00-774358.417509","код 00-0.0.0000.0000.0000","00-0.0.0000.0000.0000","карта 00-0.0.0000.0000.0000","x00-0.0.0000.0000.0000","код 00-0.2.2204.4132.9947","00-0.2.2204.4132.9947","карта 00-0.2.2204.4132.9947","x00-0.2.2204.4132.9947","код 00-2.2.2204.4132.9947","00-2.2.2204.4132.9947","карта 00-2.2.2204.4132.9947","x00-2.2.2204.4132.9947","код 00-2.0.2204.4132.9947","00-2.0.2204.4132.9947","карта 00-2.0.2204.4132.9947","x00-2.0.2204.4132.9947","код 00-1.0.0000.0000.0000","00-1.0.0000.0000.0000","карта 00-1.0.0000.0000.0000","x00-1.0.0000.0000.0000","код 00-2.0000.0000.0000","00-2.0000.0000.0000","карта 00-2.0000.0000.0000","x00-2.0000.0000.0000","код 00-0.2204.4132.9947.0018","00-0.2204.4132.9947.0018","карта 00-0.2204.4132.9947.0018","x00-0.2204.4132.9947.0018","код 00-0.2204-4132-9947-0018","00-0.2204-4132-9947-0018","карта 00-0.2204-4132-9947-0018","x00-0.2204-4132-9947-0018","код 00-2222-2222-2222-2222","00-2222-2222-2222-2222","карта 00-2222-2222-2222-2222","x00-2222-2222-2222-2222","код 00-2222 2222 2222 2222","00-2222 2222 2222 2222","карта 00-2222 2222 2222 2222","x00-2222 2222 2222 2222","код 00-2222/2222/2222/2222","00-2222/2222/2222/2222","карта 00-2222/2222/2222/2222","x00-2222/2222/2222/2222","код 00-1111.1111.1111.1111","00-1111.1111.1111.1111","карта 00-1111.1111.1111.1111","x00-1111.1111.1111.1111","код 00-2204.4132.9947.0000.0000","00-2204.4132.9947.0000.0000","карта 00-2204.4132.9947.0000.0000","x00-2204.4132.9947.0000.0000","код 00-2204.4132.9947 1.2204.4132.9947","00-2204.4132.9947 1.2204.4132.9947","карта 00-2204.4132.9947 1.2204.4132.9947","x00-2204.4132.9947 1.2204.4132.9947","код 00-2204.4132.9947 0000000000","00-2204.4132.9947 0000000000","карта 00-2204.4132.9947 0000000000","x00-2204.4132.9947 0000000000","код 00-3005-0489-9258","00-3005-0489-9258","карта 00-3005-0489-9258","x00-3005-0489-9258","код 00-3005 0489 9258","00-3005 0489 9258","карта 00-3005 0489 9258","x00-3005 0489 9258","код 00-3005/0489/9258","00-3005/0489/9258","карта 00-3005/0489/9258","x00-3005/0489/9258","код 00-1000 2000 3000 4000 5000 6000","00-1000 2000 3000 4000 5000 6000","карта 00-1000 2000 3000 4000 5000 6000","x00-1000 2000 3000 4000 5000 6000","код 00-2204.4132.9947 списка","00-2204.4132.9947 списка","карта 00-2204.4132.9947 списка","x00-2204.4132.9947 списка","код 00-2204-4132-9947 список","00-2204-4132-9947 список","карта 00-2204-4132-9947 список","x00-2204-4132-9947 список","код 00-2.0000-0000-0000","00-2.0000-0000-0000","карта 00-2.0000-0000-0000","x00-2.0000-0000-0000","код 00-2.0000 0000 0000","00-2.0000 0000 0000","карта 00-2.0000 0000 0000","x00-2.0000 0000 0000","код 00-2.0000/0000/0000","00-2.0000/0000/0000","карта 00-2.0000/0000/0000","x00-2.0000/0000/0000","код 00-2.0000.0000.0000.0000","00-2.0000.0000.0000.0000","карта 00-2.0000.0000.0000.0000","x00-2.0000.0000.0000.0000","код 00-0.0000-0000-0000","00-0.0000-0000-0000","карта 00-0.0000-0000-0000","x00-0.0000-0000-0000","код 00-0.0000 0000 0000","00-0.0000 0000 0000","карта 00-0.0000 0000 0000","x00-0.0000 0000 0000","код 00-0.0000/0000/0000","00-0.0000/0000/0000","карта 00-0.0000/0000/0000","x00-0.0000/0000/0000","код 00-0.0000.0000.0000.0000","00-0.0000.0000.0000.0000","карта 00-0.0000.0000.0000.0000","x00-0.0000.0000.0000.0000","код 00/2204.4132.9947","00/2204.4132.9947","карта 00/2204.4132.9947","x00/2204.4132.9947","код 00/2204-4132-9947","00/2204-4132-9947","карта 00/2204-4132-9947","x00/2204-4132-9947","код 00/2204 4132 9947","00/2204 4132 9947","карта 00/2204 4132 9947","x00/2204 4132 9947","код 00/2204/4132/9947","00/2204/4132/9947","карта 00/2204/4132/9947","x00/2204/4132/9947","код 00/0000.0000.0000","00/0000.0000.0000","карта 00/0000.0000.0000","x00/0000.0000.0000","код 00/0000-0000-0000","00/0000-0000-0000","карта 00/0000-0000-0000","x00/0000-0000-0000","код 00/0000 0000 0000","00/0000 0000 0000","карта 00/0000 0000 0000","x00/0000 0000 0000","код 00/0000/0000/0000","00/0000/0000/0000","карта 00/0000/0000/0000","x00/0000/0000/0000","код 00/0000.0000.0000.0000","00/0000.0000.0000.0000","карта 00/0000.0000.0000.0000","x00/0000.0000.0000.0000","код 00/0000-0000-0000-0000","00/0000-0000-0000-0000","карта 00/0000-0000-0000-0000","x00/0000-0000-0000-0000","код 00/0000 0000 0000 0000","00/0000 0000 0000 0000","карта 00/0000 0000 0000 0000","x00/0000 0000 0000 0000","код 00/0000/0000/0000/0000","00/0000/0000/0000/0000","карта 00/0000/0000/0000/0000","x00/0000/0000/0000/0000","код 00/3005.0489.9258","00/3005.0489.9258","карта 00/3005.0489.9258","x00/3005.0489.9258","код 00/2204.4132.9947.0000","00/2204.4132.9947.0000","карта 00/2204.4132.9947.0000","x00/2204.4132.9947.0000","код 00/2204-4132-9947-0000","00/2204-4132-9947-0000","карта 00/2204-4132-9947-0000","x00/2204-4132-9947-0000","код 00/2204/4132/9947/0000","00/2204/4132/9947/0000","карта 00/2204/4132/9947/0000","x00/2204/4132/9947/0000","код 00/2204 4132 9947 0000","00/2204 4132 9947 0000","карта 00/2204 4132 9947 0000","x00/2204 4132 9947 0000","код 00/2204.4132.9947.0018","00/2204.4132.9947.0018","карта 00/2204.4132.9947.0018","x00/2204.4132.9947.0018","код 00/2204-4132-9947-0018","00/2204-4132-9947-0018","карта 00/2204-4132-9947-0018","x00/2204-4132-9947-0018","код 00/2204/4132/9947/0018","00/2204/4132/9947/0018","карта 00/2204/4132/9947/0018","x00/2204/4132/9947/0018","код 00/0.2204.4132.9947","00/0.2204.4132.9947","карта 00/0.2204.4132.9947","x00/0.2204.4132.9947","код 00/0.0000.0000.0000","00/0.0000.0000.0000","карта 00/0.0000.0000.0000","x00/0.0000.0000.0000","код 00/2.2204.4132.9947","00/2.2204.4132.9947","карта 00/2.2204.4132.9947","x00/2.2204.4132.9947","код 00/1.2204.4132.9947","00/1.2204.4132.9947","карта 00/1.2204.4132.9947","x00/1.2204.4132.9947","код 00/2204.4132","00/2204.4132","карта 00/2204.4132","x00/2204.4132","код 00/34567890123","00/34567890123","карта 00/34567890123","x00/34567890123","код 00/044525225","00/044525225","карта 00/044525225","x00/044525225","код 00/220441329947","00/220441329947","карта 00/220441329947","x00/220441329947","код 00/300504899258","00/300504899258","карта 00/300504899258","x00/300504899258","код 00/0000000000","00/0000000000","карта 00/0000000000","x00/0000000000","код 00/000000000000","00/000000000000","карта 00/000000000000","x00/000000000000","код 00/2204.9947.4132.0000","00/2204.9947.4132.0000","карта 00/2204.9947.4132.0000","x00/2204.9947.4132.0000","код 00/2222.2222.2222.2222","00/2222.2222.2222.2222","карта 00/2222.2222.2222.2222","x00/2222.2222.2222.2222","код 00/2204.4132.9947 0000","00/2204.4132.9947 0000","карта 00/2204.4132.9947 0000","x00/2204.4132.9947 0000","код 00/2204.4132.9947 0018","00/2204.4132.9947 0018","карта 00/2204.4132.9947 0018","x00/2204.4132.9947 0018","код 00/2204-4132-9947 0000","00/2204-4132-9947 0000","карта 00/2204-4132-9947 0000","x00/2204-4132-9947 0000","код 00/2204/4132/9947 0000","00/2204/4132/9947 0000","карта 00/2204/4132/9947 0000","x00/2204/4132/9947 0000","код 00/24.82.01.43.38","00/24.82.01.43.38","карта 00/24.82.01.43.38","x00/24.82.01.43.38","код 00/378/123/456/94","00/378/123/456/94","карта 00/378/123/456/94","x00/378/123/456/94","код 00/774358.417509","00/774358.417509","карта 00/774358.417509","x00/774358.417509","код 00/0.0.0000.0000.0000","00/0.0.0000.0000.0000","карта 00/0.0.0000.0000.0000","x00/0.0.0000.0000.0000","код 00/0.2.2204.4132.9947","00/0.2.2204.4132.9947","карта 00/0.2.2204.4132.9947","x00/0.2.2204.4132.9947","код 00/2.2.2204.4132.9947","00/2.2.2204.4132.9947","карта 00/2.2.2204.4132.9947","x00/2.2.2204.4132.9947","код 00/2.0.2204.4132.9947","00/2.0.2204.4132.9947","карта 00/2.0.2204.4132.9947","x00/2.0.2204.4132.9947","код 00/1.0.0000.0000.0000","00/1.0.0000.0000.0000","карта 00/1.0.0000.0000.0000","x00/1.0.0000.0000.0000","код 00/2.0000.0000.0000","00/2.0000.0000.0000","карта 00/2.0000.0000.0000","x00/2.0000.0000.0000","код 00/0.2204.4132.9947.0018","00/0.2204.4132.9947.0018","карта 00/0.2204.4132.9947.0018","x00/0.2204.4132.9947.0018","код 00/0.2204-4132-9947-0018","00/0.2204-4132-9947-0018","карта 00/0.2204-4132-9947-0018","x00/0.2204-4132-9947-0018","код 00/2222-2222-2222-2222","00/2222-2222-2222-2222","карта 00/2222-2222-2222-2222","x00/2222-2222-2222-2222","код 00/2222 2222 2222 2222","00/2222 2222 2222 2222","карта 00/2222 2222 2222 2222","x00/2222 2222 2222 2222","код 00/2222/2222/2222/2222","00/2222/2222/2222/2222","карта 00/2222/2222/2222/2222","x00/2222/2222/2222/2222","код 00/1111.1111.1111.1111","00/1111.1111.1111.1111","карта 00/1111.1111.1111.1111","x00/1111.1111.1111.1111","код 00/2204.4132.9947.0000.0000","00/2204.4132.9947.0000.0000","карта 00/2204.4132.9947.0000.0000","x00/2204.4132.9947.0000.0000","код 00/2204.4132.9947 1.2204.4132.9947","00/2204.4132.9947 1.2204.4132.9947","карта 00/2204.4132.9947 1.2204.4132.9947","x00/2204.4132.9947 1.2204.4132.9947","код 00/2204.4132.9947 0000000000","00/2204.4132.9947 0000000000","карта 00/2204.4132.9947 0000000000","x00/2204.4132.9947 0000000000","код 00/3005-0489-9258","00/3005-0489-9258","карта 00/3005-0489-9258","x00/3005-0489-9258","код 00/3005 0489 9258","00/3005 0489 9258","карта 00/3005 0489 9258","x00/3005 0489 9258","код 00/3005/0489/9258","00/3005/0489/9258","карта 00/3005/0489/9258","x00/3005/0489/9258","код 00/1000 2000 3000 4000 5000 6000","00/1000 2000 3000 4000 5000 6000","карта 00/1000 2000 3000 4000 5000 6000","x00/1000 2000 3000 4000 5000 6000","код 00/2204.4132.9947 списка","00/2204.4132.9947 списка","карта 00/2204.4132.9947 списка","x00/2204.4132.9947 списка","код 00/2204-4132-9947 список","00/2204-4132-9947 список","карта 00/2204-4132-9947 список","x00/2204-4132-9947 список","код 00/2.0000-0000-0000","00/2.0000-0000-0000","карта 00/2.0000-0000-0000","x00/2.0000-0000-0000","код 00/2.0000 0000 0000","00/2.0000 0000 0000","карта 00/2.0000 0000 0000","x00/2.0000 0000 0000","код 00/2.0000/0000/0000","00/2.0000/0000/0000","карта 00/2.0000/0000/0000","x00/2.0000/0000/0000","код 00/2.0000.0000.0000.0000","00/2.0000.0000.0000.0000","карта 00/2.0000.0000.0000.0000","x00/2.0000.0000.0000.0000","код 00/0.0000-0000-0000","00/0.0000-0000-0000","карта 00/0.0000-0000-0000","x00/0.0000-0000-0000","код 00/0.0000 0000 0000","00/0.0000 0000 0000","карта 00/0.0000 0000 0000","x00/0.0000 0000 0000","код 00/0.0000/0000/0000","00/0.0000/0000/0000","карта 00/0.0000/0000/0000","x00/0.0000/0000/0000","код 00/0.0000.0000.0000.0000","00/0.0000.0000.0000.0000","карта 00/0.0000.0000.0000.0000","x00/0.0000.0000.0000.0000","код 00 2204.4132.9947","00 2204.4132.9947","карта 00 2204.4132.9947","x00 2204.4132.9947","код 00 2204-4132-9947","00 2204-4132-9947","карта 00 2204-4132-9947","x00 2204-4132-9947","код 00 2204 4132 9947","00 2204 4132 9947","карта 00 2204 4132 9947","x00 2204 4132 9947","код 00 2204/4132/9947","00 2204/4132/9947","карта 00 2204/4132/9947","x00 2204/4132/9947","код 00 0000.0000.0000","00 0000.0000.0000","карта 00 0000.0000.0000","x00 0000.0000.0000","код 00 0000-0000-0000","00 0000-0000-0000","карта 00 0000-0000-0000","x00 0000-0000-0000","код 00 0000 0000 0000","00 0000 0000 0000","карта 00 0000 0000 0000","x00 0000 0000 0000","код 00 0000/0000/0000","00 0000/0000/0000","карта 00 0000/0000/0000","x00 0000/0000/0000","код 00 0000.0000.0000.0000","00 0000.0000.0000.0000","карта 00 0000.0000.0000.0000","x00 0000.0000.0000.0000","код 00 0000-0000-0000-0000","00 0000-0000-0000-0000","карта 00 0000-0000-0000-0000","x00 0000-0000-0000-0000","код 00 0000 0000 0000 0000","00 0000 0000 0000 0000","карта 00 0000 0000 0000 0000","x00 0000 0000 0000 0000","код 00 0000/0000/0000/0000","00 0000/0000/0000/0000","карта 00 0000/0000/0000/0000","x00 0000/0000/0000/0000","код 00 3005.0489.9258","00 3005.0489.9258","карта 00 3005.0489.9258","x00 3005.0489.9258","код 00 2204.4132.9947.0000","00 2204.4132.9947.0000","карта 00 2204.4132.9947.0000","x00 2204.4132.9947.0000","код 00 2204-4132-9947-0000","00 2204-4132-9947-0000","карта 00 2204-4132-9947-0000","x00 2204-4132-9947-0000","код 00 2204/4132/9947/0000","00 2204/4132/9947/0000","карта 00 2204/4132/9947/0000","x00 2204/4132/9947/0000","код 00 2204 4132 9947 0000","00 2204 4132 9947 0000","карта 00 2204 4132 9947 0000","x00 2204 4132 9947 0000","код 00 2204.4132.9947.0018","00 2204.4132.9947.0018","карта 00 2204.4132.9947.0018","x00 2204.4132.9947.0018","код 00 2204-4132-9947-0018","00 2204-4132-9947-0018","карта 00 2204-4132-9947-0018","x00 2204-4132-9947-0018","код 00 2204/4132/9947/0018","00 2204/4132/9947/0018","карта 00 2204/4132/9947/0018","x00 2204/4132/9947/0018","код 00 0.2204.4132.9947","00 0.2204.4132.9947","карта 00 0.2204.4132.9947","x00 0.2204.4132.9947","код 00 0.0000.0000.0000","00 0.0000.0000.0000","карта 00 0.0000.0000.0000","x00 0.0000.0000.0000","код 00 2.2204.4132.9947","00 2.2204.4132.9947","карта 00 2.2204.4132.9947","x00 2.2204.4132.9947","код 00 1.2204.4132.9947","00 1.2204.4132.9947","карта 00 1.2204.4132.9947","x00 1.2204.4132.9947","код 00 2204.4132","00 2204.4132","карта 00 2204.4132","x00 2204.4132","код 00 34567890123","00 34567890123","карта 00 34567890123","x00 34567890123","код 00 044525225","00 044525225","карта 00 044525225","x00 044525225","код 00 220441329947","00 220441329947","карта 00 220441329947","x00 220441329947","код 00 300504899258","00 300504899258","карта 00 300504899258","x00 300504899258","код 00 0000000000","00 0000000000","карта 00 0000000000","x00 0000000000","код 00 000000000000","00 000000000000","карта 00 000000000000","x00 000000000000","код 00 2204.9947.4132.0000","00 2204.9947.4132.0000","карта 00 2204.9947.4132.0000","x00 2204.9947.4132.0000","код 00 2222.2222.2222.2222","00 2222.2222.2222.2222","карта 00 2222.2222.2222.2222","x00 2222.2222.2222.2222","код 00 2204.4132.9947 0000","00 2204.4132.9947 0000","карта 00 2204.4132.9947 0000","x00 2204.4132.9947 0000","код 00 2204.4132.9947 0018","00 2204.4132.9947 0018","карта 00 2204.4132.9947 0018","x00 2204.4132.9947 0018","код 00 2204-4132-9947 0000","00 2204-4132-9947 0000","карта 00 2204-4132-9947 0000","x00 2204-4132-9947 0000","код 00 2204/4132/9947 0000","00 2204/4132/9947 0000","карта 00 2204/4132/9947 0000","x00 2204/4132/9947 0000","код 00 24.82.01.43.38","00 24.82.01.43.38","карта 00 24.82.01.43.38","x00 24.82.01.43.38","код 00 378/123/456/94","00 378/123/456/94","карта 00 378/123/456/94","x00 378/123/456/94","код 00 774358.417509","00 774358.417509","карта 00 774358.417509","x00 774358.417509","код 00 0.0.0000.0000.0000","00 0.0.0000.0000.0000","карта 00 0.0.0000.0000.0000","x00 0.0.0000.0000.0000","код 00 0.2.2204.4132.9947","00 0.2.2204.4132.9947","карта 00 0.2.2204.4132.9947","x00 0.2.2204.4132.9947","код 00 2.2.2204.4132.9947","00 2.2.2204.4132.9947","карта 00 2.2.2204.4132.9947","x00 2.2.2204.4132.9947","код 00 2.0.2204.4132.9947","00 2.0.2204.4132.9947","карта 00 2.0.2204.4132.9947","x00 2.0.2204.4132.9947","код 00 1.0.0000.0000.0000","00 1.0.0000.0000.0000","карта 00 1.0.0000.0000.0000","x00 1.0.0000.0000.0000","код 00 2.0000.0000.0000","00 2.0000.0000.0000","карта 00 2.0000.0000.0000","x00 2.0000.0000.0000","код 00 0.2204.4132.9947.0018","00 0.2204.4132.9947.0018","карта 00 0.2204.4132.9947.0018","x00 0.2204.4132.9947.0018","код 00 0.2204-4132-9947-0018","00 0.2204-4132-9947-0018","карта 00 0.2204-4132-9947-0018","x00 0.2204-4132-9947-0018","код 00 2222-2222-2222-2222","00 2222-2222-2222-2222","карта 00 2222-2222-2222-2222","x00 2222-2222-2222-2222","код 00 2222 2222 2222 2222","00 2222 2222 2222 2222","карта 00 2222 2222 2222 2222","x00 2222 2222 2222 2222","код 00 2222/2222/2222/2222","00 2222/2222/2222/2222","карта 00 2222/2222/2222/2222","x00 2222/2222/2222/2222","код 00 1111.1111.1111.1111","00 1111.1111.1111.1111","карта 00 1111.1111.1111.1111","x00 1111.1111.1111.1111","код 00 2204.4132.9947.0000.0000","00 2204.4132.9947.0000.0000","карта 00 2204.4132.9947.0000.0000","x00 2204.4132.9947.0000.0000","код 00 2204.4132.9947 1.2204.4132.9947","00 2204.4132.9947 1.2204.4132.9947","карта 00 2204.4132.9947 1.2204.4132.9947","x00 2204.4132.9947 1.2204.4132.9947","код 00 2204.4132.9947 0000000000","00 2204.4132.9947 0000000000","карта 00 2204.4132.9947 0000000000","x00 2204.4132.9947 0000000000","код 00 3005-0489-9258","00 3005-0489-9258","карта 00 3005-0489-9258","x00 3005-0489-9258","код 00 3005 0489 9258","00 3005 0489 9258","карта 00 3005 0489 9258","x00 3005 0489 9258","код 00 3005/0489/9258","00 3005/0489/9258","карта 00 3005/0489/9258","x00 3005/0489/9258","код 00 1000 2000 3000 4000 5000 6000","00 1000 2000 3000 4000 5000 6000","карта 00 1000 2000 3000 4000 5000 6000","x00 1000 2000 3000 4000 5000 6000","код 00 2204.4132.9947 списка","00 2204.4132.9947 списка","карта 00 2204.4132.9947 списка","x00 2204.4132.9947 списка","код 00 2204-4132-9947 список","00 2204-4132-9947 список","карта 00 2204-4132-9947 список","x00 2204-4132-9947 список","код 00 2.0000-0000-0000","00 2.0000-0000-0000","карта 00 2.0000-0000-0000","x00 2.0000-0000-0000","код 00 2.0000 0000 0000","00 2.0000 0000 0000","карта 00 2.0000 0000 0000","x00 2.0000 0000 0000","код 00 2.0000/0000/0000","00 2.0000/0000/0000","карта 00 2.0000/0000/0000","x00 2.0000/0000/0000","код 00 2.0000.0000.0000.0000","00 2.0000.0000.0000.0000","карта 00 2.0000.0000.0000.0000","x00 2.0000.0000.0000.0000","код 00 0.0000-0000-0000","00 0.0000-0000-0000","карта 00 0.0000-0000-0000","x00 0.0000-0000-0000","код 00 0.0000 0000 0000","00 0.0000 0000 0000","карта 00 0.0000 0000 0000","x00 0.0000 0000 0000","код 00 0.0000/0000/0000","00 0.0000/0000/0000","карта 00 0.0000/0000/0000","x00 0.0000/0000/0000","код 00 0.0000.0000.0000.0000","00 0.0000.0000.0000.0000","карта 00 0.0000.0000.0000.0000","x00 0.0000.0000.0000.0000","код 000.2204.4132.9947","000.2204.4132.9947","карта 000.2204.4132.9947","x000.2204.4132.9947","код 000.2204-4132-9947","000.2204-4132-9947","карта 000.2204-4132-9947","x000.2204-4132-9947","код 000.2204 4132 9947","000.2204 4132 9947","карта 000.2204 4132 9947","x000.2204 4132 9947","код 000.2204/4132/9947","000.2204/4132/9947","карта 000.2204/4132/9947","x000.2204/4132/9947","код 000.0000.0000.0000","000.0000.0000.0000","карта 000.0000.0000.0000","x000.0000.0000.0000","код 000.0000-0000-0000","000.0000-0000-0000","карта 000.0000-0000-0000","x000.0000-0000-0000","код 000.0000 0000 0000","000.0000 0000 0000","карта 000.0000 0000 0000","x000.0000 0000 0000","код 000.0000/0000/0000","000.0000/0000/0000","карта 000.0000/0000/0000","x000.0000/0000/0000","код 000.0000.0000.0000.0000","000.0000.0000.0000.0000","карта 000.0000.0000.0000.0000","x000.0000.0000.0000.0000","код 000.0000-0000-0000-0000","000.0000-0000-0000-0000","карта 000.0000-0000-0000-0000","x000.0000-0000-0000-0000","код 000.0000 0000 0000 0000","000.0000 0000 0000 0000","карта 000.0000 0000 0000 0000","x000.0000 0000 0000 0000","код 000.0000/0000/0000/0000","000.0000/0000/0000/0000","карта 000.0000/0000/0000/0000","x000.0000/0000/0000/0000","код 000.3005.0489.9258","000.3005.0489.9258","карта 000.3005.0489.9258","x000.3005.0489.9258","код 000.2204.4132.9947.0000","000.2204.4132.9947.0000","карта 000.2204.4132.9947.0000","x000.2204.4132.9947.0000","код 000.2204-4132-9947-0000","000.2204-4132-9947-0000","карта 000.2204-4132-9947-0000","x000.2204-4132-9947-0000","код 000.2204/4132/9947/0000","000.2204/4132/9947/0000","карта 000.2204/4132/9947/0000","x000.2204/4132/9947/0000","код 000.2204 4132 9947 0000","000.2204 4132 9947 0000","карта 000.2204 4132 9947 0000","x000.2204 4132 9947 0000","код 000.2204.4132.9947.0018","000.2204.4132.9947.0018","карта 000.2204.4132.9947.0018","x000.2204.4132.9947.0018","код 000.2204-4132-9947-0018","000.2204-4132-9947-0018","карта 000.2204-4132-9947-0018","x000.2204-4132-9947-0018","код 000.2204/4132/9947/0018","000.2204/4132/9947/0018","карта 000.2204/4132/9947/0018","x000.2204/4132/9947/0018","код 000.0.2204.4132.9947","000.0.2204.4132.9947","карта 000.0.2204.4132.9947","x000.0.2204.4132.9947","код 000.0.0000.0000.0000","000.0.0000.0000.0000","карта 000.0.0000.0000.0000","x000.0.0000.0000.0000","код 000.2.2204.4132.9947","000.2.2204.4132.9947","карта 000.2.2204.4132.9947","x000.2.2204.4132.9947","код 000.1.2204.4132.9947","000.1.2204.4132.9947","карта 000.1.2204.4132.9947","x000.1.2204.4132.9947","код 000.2204.4132","000.2204.4132","карта 000.2204.4132","x000.2204.4132","код 000.34567890123","000.34567890123","карта 000.34567890123","x000.34567890123","код 000.044525225","000.044525225","карта 000.044525225","x000.044525225","код 000.220441329947","000.220441329947","карта 000.220441329947","x000.220441329947","код 000.300504899258","000.300504899258","карта 000.300504899258","x000.300504899258","код 000.0000000000","000.0000000000","карта 000.0000000000","x000.0000000000","код 000.000000000000","000.000000000000","карта 000.000000000000","x000.000000000000","код 000.2204.9947.4132.0000","000.2204.9947.4132.0000","карта 000.2204.9947.4132.0000","x000.2204.9947.4132.0000","код 000.2222.2222.2222.2222","000.2222.2222.2222.2222","карта 000.2222.2222.2222.2222","x000.2222.2222.2222.2222","код 000.2204.4132.9947 0000","000.2204.4132.9947 0000","карта 000.2204.4132.9947 0000","x000.2204.4132.9947 0000","код 000.2204.4132.9947 0018","000.2204.4132.9947 0018","карта 000.2204.4132.9947 0018","x000.2204.4132.9947 0018","код 000.2204-4132-9947 0000","000.2204-4132-9947 0000","карта 000.2204-4132-9947 0000","x000.2204-4132-9947 0000","код 000.2204/4132/9947 0000","000.2204/4132/9947 0000","карта 000.2204/4132/9947 0000","x000.2204/4132/9947 0000","код 000.24.82.01.43.38","000.24.82.01.43.38","карта 000.24.82.01.43.38","x000.24.82.01.43.38","код 000.378/123/456/94","000.378/123/456/94","карта 000.378/123/456/94","x000.378/123/456/94","код 000.774358.417509","000.774358.417509","карта 000.774358.417509","x000.774358.417509","код 000.0.0.0000.0000.0000","000.0.0.0000.0000.0000","карта 000.0.0.0000.0000.0000","x000.0.0.0000.0000.0000","код 000.0.2.2204.4132.9947","000.0.2.2204.4132.9947","карта 000.0.2.2204.4132.9947","x000.0.2.2204.4132.9947","код 000.2.2.2204.4132.9947","000.2.2.2204.4132.9947","карта 000.2.2.2204.4132.9947","x000.2.2.2204.4132.9947","код 000.2.0.2204.4132.9947","000.2.0.2204.4132.9947","карта 000.2.0.2204.4132.9947","x000.2.0.2204.4132.9947","код 000.1.0.0000.0000.0000","000.1.0.0000.0000.0000","карта 000.1.0.0000.0000.0000","x000.1.0.0000.0000.0000","код 000.2.0000.0000.0000","000.2.0000.0000.0000","карта 000.2.0000.0000.0000","x000.2.0000.0000.0000","код 000.0.2204.4132.9947.0018","000.0.2204.4132.9947.0018","карта 000.0.2204.4132.9947.0018","x000.0.2204.4132.9947.0018","код 000.0.2204-4132-9947-0018","000.0.2204-4132-9947-0018","карта 000.0.2204-4132-9947-0018","x000.0.2204-4132-9947-0018","код 000.2222-2222-2222-2222","000.2222-2222-2222-2222","карта 000.2222-2222-2222-2222","x000.2222-2222-2222-2222","код 000.2222 2222 2222 2222","000.2222 2222 2222 2222","карта 000.2222 2222 2222 2222","x000.2222 2222 2222 2222","код 000.2222/2222/2222/2222","000.2222/2222/2222/2222","карта 000.2222/2222/2222/2222","x000.2222/2222/2222/2222","код 000.1111.1111.1111.1111","000.1111.1111.1111.1111","карта 000.1111.1111.1111.1111","x000.1111.1111.1111.1111","код 000.2204.4132.9947.0000.0000","000.2204.4132.9947.0000.0000","карта 000.2204.4132.9947.0000.0000","x000.2204.4132.9947.0000.0000","код 000.2204.4132.9947 1.2204.4132.9947","000.2204.4132.9947 1.2204.4132.9947","карта 000.2204.4132.9947 1.2204.4132.9947","x000.2204.4132.9947 1.2204.4132.9947","код 000.2204.4132.9947 0000000000","000.2204.4132.9947 0000000000","карта 000.2204.4132.9947 0000000000","x000.2204.4132.9947 0000000000","код 000.3005-0489-9258","000.3005-0489-9258","карта 000.3005-0489-9258","x000.3005-0489-9258","код 000.3005 0489 9258","000.3005 0489 9258","карта 000.3005 0489 9258","x000.3005 0489 9258","код 000.3005/0489/9258","000.3005/0489/9258","карта 000.3005/0489/9258","x000.3005/0489/9258","код 000.1000 2000 3000 4000 5000 6000","000.1000 2000 3000 4000 5000 6000","карта 000.1000 2000 3000 4000 5000 6000","x000.1000 2000 3000 4000 5000 6000","код 000.2204.4132.9947 списка","000.2204.4132.9947 списка","карта 000.2204.4132.9947 списка","x000.2204.4132.9947 списка","код 000.2204-4132-9947 список","000.2204-4132-9947 список","карта 000.2204-4132-9947 список","x000.2204-4132-9947 список","код 000.2.0000-0000-0000","000.2.0000-0000-0000","карта 000.2.0000-0000-0000","x000.2.0000-0000-0000","код 000.2.0000 0000 0000","000.2.0000 0000 0000","карта 000.2.0000 0000 0000","x000.2.0000 0000 0000","код 000.2.0000/0000/0000","000.2.0000/0000/0000","карта 000.2.0000/0000/0000","x000.2.0000/0000/0000","код 000.2.0000.0000.0000.0000","000.2.0000.0000.0000.0000","карта 000.2.0000.0000.0000.0000","x000.2.0000.0000.0000.0000","код 000.0.0000-0000-0000","000.0.0000-0000-0000","карта 000.0.0000-0000-0000","x000.0.0000-0000-0000","код 000.0.0000 0000 0000","000.0.0000 0000 0000","карта 000.0.0000 0000 0000","x000.0.0000 0000 0000","код 000.0.0000/0000/0000","000.0.0000/0000/0000","карта 000.0.0000/0000/0000","x000.0.0000/0000/0000","код 000.0.0000.0000.0000.0000","000.0.0000.0000.0000.0000","карта 000.0.0000.0000.0000.0000","x000.0.0000.0000.0000.0000","код 000-2204.4132.9947","000-2204.4132.9947","карта 000-2204.4132.9947","x000-2204.4132.9947","код 000-2204-4132-9947","000-2204-4132-9947","карта 000-2204-4132-9947","x000-2204-4132-9947","код 000-2204 4132 9947","000-2204 4132 9947","карта 000-2204 4132 9947","x000-2204 4132 9947","код 000-2204/4132/9947","000-2204/4132/9947","карта 000-2204/4132/9947","x000-2204/4132/9947","код 000-0000.0000.0000","000-0000.0000.0000","карта 000-0000.0000.0000","x000-0000.0000.0000","код 000-0000-0000-0000","000-0000-0000-0000","карта 000-0000-0000-0000","x000-0000-0000-0000","код 000-0000 0000 0000","000-0000 0000 0000","карта 000-0000 0000 0000","x000-0000 0000 0000","код 000-0000/0000/0000","000-0000/0000/0000","карта 000-0000/0000/0000","x000-0000/0000/0000","код 000-0000.0000.0000.0000","000-0000.0000.0000.0000","карта 000-0000.0000.0000.0000","x000-0000.0000.0000.0000","код 000-0000-0000-0000-0000","000-0000-0000-0000-0000","карта 000-0000-0000-0000-0000","x000-0000-0000-0000-0000","код 000-0000 0000 0000 0000","000-0000 0000 0000 0000","карта 000-0000 0000 0000 0000","x000-0000 0000 0000 0000","код 000-0000/0000/0000/0000","000-0000/0000/0000/0000","карта 000-0000/0000/0000/0000","x000-0000/0000/0000/0000","код 000-3005.0489.9258","000-3005.0489.9258","карта 000-3005.0489.9258","x000-3005.0489.9258","код 000-2204.4132.9947.0000","000-2204.4132.9947.0000","карта 000-2204.4132.9947.0000","x000-2204.4132.9947.0000","код 000-2204-4132-9947-0000","000-2204-4132-9947-0000","карта 000-2204-4132-9947-0000","x000-2204-4132-9947-0000","код 000-2204/4132/9947/0000","000-2204/4132/9947/0000","карта 000-2204/4132/9947/0000","x000-2204/4132/9947/0000","код 000-2204 4132 9947 0000","000-2204 4132 9947 0000","карта 000-2204 4132 9947 0000","x000-2204 4132 9947 0000","код 000-2204.4132.9947.0018","000-2204.4132.9947.0018","карта 000-2204.4132.9947.0018","x000-2204.4132.9947.0018","код 000-2204-4132-9947-0018","000-2204-4132-9947-0018","карта 000-2204-4132-9947-0018","x000-2204-4132-9947-0018","код 000-2204/4132/9947/0018","000-2204/4132/9947/0018","карта 000-2204/4132/9947/0018","x000-2204/4132/9947/0018","код 000-0.2204.4132.9947","000-0.2204.4132.9947","карта 000-0.2204.4132.9947","x000-0.2204.4132.9947","код 000-0.0000.0000.0000","000-0.0000.0000.0000","карта 000-0.0000.0000.0000","x000-0.0000.0000.0000","код 000-2.2204.4132.9947","000-2.2204.4132.9947","карта 000-2.2204.4132.9947","x000-2.2204.4132.9947","код 000-1.2204.4132.9947","000-1.2204.4132.9947","карта 000-1.2204.4132.9947","x000-1.2204.4132.9947","код 000-2204.4132","000-2204.4132","карта 000-2204.4132","x000-2204.4132","код 000-34567890123","000-34567890123","карта 000-34567890123","x000-34567890123","код 000-044525225","000-044525225","карта 000-044525225","x000-044525225","код 000-220441329947","000-220441329947","карта 000-220441329947","x000-220441329947","код 000-300504899258","000-300504899258","карта 000-300504899258","x000-300504899258","код 000-0000000000","000-0000000000","карта 000-0000000000","x000-0000000000","код 000-000000000000","000-000000000000","карта 000-000000000000","x000-000000000000","код 000-2204.9947.4132.0000","000-2204.9947.4132.0000","карта 000-2204.9947.4132.0000","x000-2204.9947.4132.0000","код 000-2222.2222.2222.2222","000-2222.2222.2222.2222","карта 000-2222.2222.2222.2222","x000-2222.2222.2222.2222","код 000-2204.4132.9947 0000","000-2204.4132.9947 0000","карта 000-2204.4132.9947 0000","x000-2204.4132.9947 0000","код 000-2204.4132.9947 0018","000-2204.4132.9947 0018","карта 000-2204.4132.9947 0018","x000-2204.4132.9947 0018","код 000-2204-4132-9947 0000","000-2204-4132-9947 0000","карта 000-2204-4132-9947 0000","x000-2204-4132-9947 0000","код 000-2204/4132/9947 0000","000-2204/4132/9947 0000","карта 000-2204/4132/9947 0000","x000-2204/4132/9947 0000","код 000-24.82.01.43.38","000-24.82.01.43.38","карта 000-24.82.01.43.38","x000-24.82.01.43.38","код 000-378/123/456/94","000-378/123/456/94","карта 000-378/123/456/94","x000-378/123/456/94","код 000-774358.417509","000-774358.417509","карта 000-774358.417509","x000-774358.417509","код 000-0.0.0000.0000.0000","000-0.0.0000.0000.0000","карта 000-0.0.0000.0000.0000","x000-0.0.0000.0000.0000","код 000-0.2.2204.4132.9947","000-0.2.2204.4132.9947","карта 000-0.2.2204.4132.9947","x000-0.2.2204.4132.9947","код 000-2.2.2204.4132.9947","000-2.2.2204.4132.9947","карта 000-2.2.2204.4132.9947","x000-2.2.2204.4132.9947","код 000-2.0.2204.4132.9947","000-2.0.2204.4132.9947","карта 000-2.0.2204.4132.9947","x000-2.0.2204.4132.9947","код 000-1.0.0000.0000.0000","000-1.0.0000.0000.0000","карта 000-1.0.0000.0000.0000","x000-1.0.0000.0000.0000","код 000-2.0000.0000.0000","000-2.0000.0000.0000","карта 000-2.0000.0000.0000","x000-2.0000.0000.0000","код 000-0.2204.4132.9947.0018","000-0.2204.4132.9947.0018","карта 000-0.2204.4132.9947.0018","x000-0.2204.4132.9947.0018","код 000-0.2204-4132-9947-0018","000-0.2204-4132-9947-0018","карта 000-0.2204-4132-9947-0018","x000-0.2204-4132-9947-0018","код 000-2222-2222-2222-2222","000-2222-2222-2222-2222","карта 000-2222-2222-2222-2222","x000-2222-2222-2222-2222","код 000-2222 2222 2222 2222","000-2222 2222 2222 2222","карта 000-2222 2222 2222 2222","x000-2222 2222 2222 2222","код 000-2222/2222/2222/2222","000-2222/2222/2222/2222","карта 000-2222/2222/2222/2222","x000-2222/2222/2222/2222","код 000-1111.1111.1111.1111","000-1111.1111.1111.1111","карта 000-1111.1111.1111.1111","x000-1111.1111.1111.1111","код 000-2204.4132.9947.0000.0000","000-2204.4132.9947.0000.0000","карта 000-2204.4132.9947.0000.0000","x000-2204.4132.9947.0000.0000","код 000-2204.4132.9947 1.2204.4132.9947","000-2204.4132.9947 1.2204.4132.9947","карта 000-2204.4132.9947 1.2204.4132.9947","x000-2204.4132.9947 1.2204.4132.9947","код 000-2204.4132.9947 0000000000","000-2204.4132.9947 0000000000","карта 000-2204.4132.9947 0000000000","x000-2204.4132.9947 0000000000","код 000-3005-0489-9258","000-3005-0489-9258","карта 000-3005-0489-9258","x000-3005-0489-9258","код 000-3005 0489 9258","000-3005 0489 9258","карта 000-3005 0489 9258","x000-3005 0489 9258","код 000-3005/0489/9258","000-3005/0489/9258","карта 000-3005/0489/9258","x000-3005/0489/9258","код 000-1000 2000 3000 4000 5000 6000","000-1000 2000 3000 4000 5000 6000","карта 000-1000 2000 3000 4000 5000 6000","x000-1000 2000 3000 4000 5000 6000","код 000-2204.4132.9947 списка","000-2204.4132.9947 списка","карта 000-2204.4132.9947 списка","x000-2204.4132.9947 списка","код 000-2204-4132-9947 список","000-2204-4132-9947 список","карта 000-2204-4132-9947 список","x000-2204-4132-9947 список","код 000-2.0000-0000-0000","000-2.0000-0000-0000","карта 000-2.0000-0000-0000","x000-2.0000-0000-0000","код 000-2.0000 0000 0000","000-2.0000 0000 0000","карта 000-2.0000 0000 0000","x000-2.0000 0000 0000","код 000-2.0000/0000/0000","000-2.0000/0000/0000","карта 000-2.0000/0000/0000","x000-2.0000/0000/0000","код 000-2.0000.0000.0000.0000","000-2.0000.0000.0000.0000","карта 000-2.0000.0000.0000.0000","x000-2.0000.0000.0000.0000","код 000-0.0000-0000-0000","000-0.0000-0000-0000","карта 000-0.0000-0000-0000","x000-0.0000-0000-0000","код 000-0.0000 0000 0000","000-0.0000 0000 0000","карта 000-0.0000 0000 0000","x000-0.0000 0000 0000","код 000-0.0000/0000/0000","000-0.0000/0000/0000","карта 000-0.0000/0000/0000","x000-0.0000/0000/0000","код 000-0.0000.0000.0000.0000","000-0.0000.0000.0000.0000","карта 000-0.0000.0000.0000.0000","x000-0.0000.0000.0000.0000","код 000/2204.4132.9947","000/2204.4132.9947","карта 000/2204.4132.9947","x000/2204.4132.9947","код 000/2204-4132-9947","000/2204-4132-9947","карта 000/2204-4132-9947","x000/2204-4132-9947","код 000/2204 4132 9947","000/2204 4132 9947","карта 000/2204 4132 9947","x000/2204 4132 9947","код 000/2204/4132/9947","000/2204/4132/9947","карта 000/2204/4132/9947","x000/2204/4132/9947","код 000/0000.0000.0000","000/0000.0000.0000","карта 000/0000.0000.0000","x000/0000.0000.0000","код 000/0000-0000-0000","000/0000-0000-0000","карта 000/0000-0000-0000","x000/0000-0000-0000","код 000/0000 0000 0000","000/0000 0000 0000","карта 000/0000 0000 0000","x000/0000 0000 0000","код 000/0000/0000/0000","000/0000/0000/0000","карта 000/0000/0000/0000","x000/0000/0000/0000","код 000/0000.0000.0000.0000","000/0000.0000.0000.0000","карта 000/0000.0000.0000.0000","x000/0000.0000.0000.0000","код 000/0000-0000-0000-0000","000/0000-0000-0000-0000","карта 000/0000-0000-0000-0000","x000/0000-0000-0000-0000","код 000/0000 0000 0000 0000","000/0000 0000 0000 0000","карта 000/0000 0000 0000 0000","x000/0000 0000 0000 0000","код 000/0000/0000/0000/0000","000/0000/0000/0000/0000","карта 000/0000/0000/0000/0000","x000/0000/0000/0000/0000","код 000/3005.0489.9258","000/3005.0489.9258","карта 000/3005.0489.9258","x000/3005.0489.9258","код 000/2204.4132.9947.0000","000/2204.4132.9947.0000","карта 000/2204.4132.9947.0000","x000/2204.4132.9947.0000","код 000/2204-4132-9947-0000","000/2204-4132-9947-0000","карта 000/2204-4132-9947-0000","x000/2204-4132-9947-0000","код 000/2204/4132/9947/0000","000/2204/4132/9947/0000","карта 000/2204/4132/9947/0000","x000/2204/4132/9947/0000","код 000/2204 4132 9947 0000","000/2204 4132 9947 0000","карта 000/2204 4132 9947 0000","x000/2204 4132 9947 0000","код 000/2204.4132.9947.0018","000/2204.4132.9947.0018","карта 000/2204.4132.9947.0018","x000/2204.4132.9947.0018","код 000/2204-4132-9947-0018","000/2204-4132-9947-0018","карта 000/2204-4132-9947-0018","x000/2204-4132-9947-0018","код 000/2204/4132/9947/0018","000/2204/4132/9947/0018","карта 000/2204/4132/9947/0018","x000/2204/4132/9947/0018","код 000/0.2204.4132.9947","000/0.2204.4132.9947","карта 000/0.2204.4132.9947","x000/0.2204.4132.9947","код 000/0.0000.0000.0000","000/0.0000.0000.0000","карта 000/0.0000.0000.0000","x000/0.0000.0000.0000","код 000/2.2204.4132.9947","000/2.2204.4132.9947","карта 000/2.2204.4132.9947","x000/2.2204.4132.9947","код 000/1.2204.4132.9947","000/1.2204.4132.9947","карта 000/1.2204.4132.9947","x000/1.2204.4132.9947","код 000/2204.4132","000/2204.4132","карта 000/2204.4132","x000/2204.4132","код 000/34567890123","000/34567890123","карта 000/34567890123","x000/34567890123","код 000/044525225","000/044525225","карта 000/044525225","x000/044525225","код 000/220441329947","000/220441329947","карта 000/220441329947","x000/220441329947","код 000/300504899258","000/300504899258","карта 000/300504899258","x000/300504899258","код 000/0000000000","000/0000000000","карта 000/0000000000","x000/0000000000","код 000/000000000000","000/000000000000","карта 000/000000000000","x000/000000000000","код 000/2204.9947.4132.0000","000/2204.9947.4132.0000","карта 000/2204.9947.4132.0000","x000/2204.9947.4132.0000","код 000/2222.2222.2222.2222","000/2222.2222.2222.2222","карта 000/2222.2222.2222.2222","x000/2222.2222.2222.2222","код 000/2204.4132.9947 0000","000/2204.4132.9947 0000","карта 000/2204.4132.9947 0000","x000/2204.4132.9947 0000","код 000/2204.4132.9947 0018","000/2204.4132.9947 0018","карта 000/2204.4132.9947 0018","x000/2204.4132.9947 0018","код 000/2204-4132-9947 0000","000/2204-4132-9947 0000","карта 000/2204-4132-9947 0000","x000/2204-4132-9947 0000","код 000/2204/4132/9947 0000","000/2204/4132/9947 0000","карта 000/2204/4132/9947 0000","x000/2204/4132/9947 0000","код 000/24.82.01.43.38","000/24.82.01.43.38","карта 000/24.82.01.43.38","x000/24.82.01.43.38","код 000/378/123/456/94","000/378/123/456/94","карта 000/378/123/456/94","x000/378/123/456/94","код 000/774358.417509","000/774358.417509","карта 000/774358.417509","x000/774358.417509","код 000/0.0.0000.0000.0000","000/0.0.0000.0000.0000","карта 000/0.0.0000.0000.0000","x000/0.0.0000.0000.0000","код 000/0.2.2204.4132.9947","000/0.2.2204.4132.9947","карта 000/0.2.2204.4132.9947","x000/0.2.2204.4132.9947","код 000/2.2.2204.4132.9947","000/2.2.2204.4132.9947","карта 000/2.2.2204.4132.9947","x000/2.2.2204.4132.9947","код 000/2.0.2204.4132.9947","000/2.0.2204.4132.9947","карта 000/2.0.2204.4132.9947","x000/2.0.2204.4132.9947","код 000/1.0.0000.0000.0000","000/1.0.0000.0000.0000","карта 000/1.0.0000.0000.0000","x000/1.0.0000.0000.0000","код 000/2.0000.0000.0000","000/2.0000.0000.0000","карта 000/2.0000.0000.0000","x000/2.0000.0000.0000","код 000/0.2204.4132.9947.0018","000/0.2204.4132.9947.0018","карта 000/0.2204.4132.9947.0018","x000/0.2204.4132.9947.0018","код 000/0.2204-4132-9947-0018","000/0.2204-4132-9947-0018","карта 000/0.2204-4132-9947-0018","x000/0.2204-4132-9947-0018","код 000/2222-2222-2222-2222","000/2222-2222-2222-2222","карта 000/2222-2222-2222-2222","x000/2222-2222-2222-2222","код 000/2222 2222 2222 2222","000/2222 2222 2222 2222","карта 000/2222 2222 2222 2222","x000/2222 2222 2222 2222","код 000/2222/2222/2222/2222","000/2222/2222/2222/2222","карта 000/2222/2222/2222/2222","x000/2222/2222/2222/2222","код 000/1111.1111.1111.1111","000/1111.1111.1111.1111","карта 000/1111.1111.1111.1111","x000/1111.1111.1111.1111","код 000/2204.4132.9947.0000.0000","000/2204.4132.9947.0000.0000","карта 000/2204.4132.9947.0000.0000","x000/2204.4132.9947.0000.0000","код 000/2204.4132.9947 1.2204.4132.9947","000/2204.4132.9947 1.2204.4132.9947","карта 000/2204.4132.9947 1.2204.4132.9947","x000/2204.4132.9947 1.2204.4132.9947","код 000/2204.4132.9947 0000000000","000/2204.4132.9947 0000000000","карта 000/2204.4132.9947 0000000000","x000/2204.4132.9947 0000000000","код 000/3005-0489-9258","000/3005-0489-9258","карта 000/3005-0489-9258","x000/3005-0489-9258","код 000/3005 0489 9258","000/3005 0489 9258","карта 000/3005 0489 9258","x000/3005 0489 9258","код 000/3005/0489/9258","000/3005/0489/9258","карта 000/3005/0489/9258","x000/3005/0489/9258","код 000/1000 2000 3000 4000 5000 6000","000/1000 2000 3000 4000 5000 6000","карта 000/1000 2000 3000 4000 5000 6000","x000/1000 2000 3000 4000 5000 6000","код 000/2204.4132.9947 списка","000/2204.4132.9947 списка","карта 000/2204.4132.9947 списка","x000/2204.4132.9947 списка","код 000/2204-4132-9947 список","000/2204-4132-9947 список","карта 000/2204-4132-9947 список","x000/2204-4132-9947 список","код 000/2.0000-0000-0000","000/2.0000-0000-0000","карта 000/2.0000-0000-0000","x000/2.0000-0000-0000","код 000/2.0000 0000 0000","000/2.0000 0000 0000","карта 000/2.0000 0000 0000","x000/2.0000 0000 0000","код 000/2.0000/0000/0000","000/2.0000/0000/0000","карта 000/2.0000/0000/0000","x000/2.0000/0000/0000","код 000/2.0000.0000.0000.0000","000/2.0000.0000.0000.0000","карта 000/2.0000.0000.0000.0000","x000/2.0000.0000.0000.0000","код 000/0.0000-0000-0000","000/0.0000-0000-0000","карта 000/0.0000-0000-0000","x000/0.0000-0000-0000","код 000/0.0000 0000 0000","000/0.0000 0000 0000","карта 000/0.0000 0000 0000","x000/0.0000 0000 0000","код 000/0.0000/0000/0000","000/0.0000/0000/0000","карта 000/0.0000/0000/0000","x000/0.0000/0000/0000","код 000/0.0000.0000.0000.0000","000/0.0000.0000.0000.0000","карта 000/0.0000.0000.0000.0000","x000/0.0000.0000.0000.0000","код 000 2204.4132.9947","000 2204.4132.9947","карта 000 2204.4132.9947","x000 2204.4132.9947","код 000 2204-4132-9947","000 2204-4132-9947","карта 000 2204-4132-9947","x000 2204-4132-9947","код 000 2204 4132 9947","000 2204 4132 9947","карта 000 2204 4132 9947","x000 2204 4132 9947","код 000 2204/4132/9947","000 2204/4132/9947","карта 000 2204/4132/9947","x000 2204/4132/9947","код 000 0000.0000.0000","000 0000.0000.0000","карта 000 0000.0000.0000","x000 0000.0000.0000","код 000 0000-0000-0000","000 0000-0000-0000","карта 000 0000-0000-0000","x000 0000-0000-0000","код 000 0000 0000 0000","000 0000 0000 0000","карта 000 0000 0000 0000","x000 0000 0000 0000","код 000 0000/0000/0000","000 0000/0000/0000","карта 000 0000/0000/0000","x000 0000/0000/0000","код 000 0000.0000.0000.0000","000 0000.0000.0000.0000","карта 000 0000.0000.0000.0000","x000 0000.0000.0000.0000","код 000 0000-0000-0000-0000","000 0000-0000-0000-0000","карта 000 0000-0000-0000-0000","x000 0000-0000-0000-0000","код 000 0000 0000 0000 0000","000 0000 0000 0000 0000","карта 000 0000 0000 0000 0000","x000 0000 0000 0000 0000","код 000 0000/0000/0000/0000","000 0000/0000/0000/0000","карта 000 0000/0000/0000/0000","x000 0000/0000/0000/0000","код 000 3005.0489.9258","000 3005.0489.9258","карта 000 3005.0489.9258","x000 3005.0489.9258","код 000 2204.4132.9947.0000","000 2204.4132.9947.0000","карта 000 2204.4132.9947.0000","x000 2204.4132.9947.0000","код 000 2204-4132-9947-0000","000 2204-4132-9947-0000","карта 000 2204-4132-9947-0000","x000 2204-4132-9947-0000","код 000 2204/4132/9947/0000","000 2204/4132/9947/0000","карта 000 2204/4132/9947/0000","x000 2204/4132/9947/0000","код 000 2204 4132 9947 0000","000 2204 4132 9947 0000","карта 000 2204 4132 9947 0000","x000 2204 4132 9947 0000","код 000 2204.4132.9947.0018","000 2204.4132.9947.0018","карта 000 2204.4132.9947.0018","x000 2204.4132.9947.0018","код 000 2204-4132-9947-0018","000 2204-4132-9947-0018","карта 000 2204-4132-9947-0018","x000 2204-4132-9947-0018","код 000 2204/4132/9947/0018","000 2204/4132/9947/0018","карта 000 2204/4132/9947/0018","x000 2204/4132/9947/0018","код 000 0.2204.4132.9947","000 0.2204.4132.9947","карта 000 0.2204.4132.9947","x000 0.2204.4132.9947","код 000 0.0000.0000.0000","000 0.0000.0000.0000","карта 000 0.0000.0000.0000","x000 0.0000.0000.0000","код 000 2.2204.4132.9947","000 2.2204.4132.9947","карта 000 2.2204.4132.9947","x000 2.2204.4132.9947","код 000 1.2204.4132.9947","000 1.2204.4132.9947","карта 000 1.2204.4132.9947","x000 1.2204.4132.9947","код 000 2204.4132","000 2204.4132","карта 000 2204.4132","x000 2204.4132","код 000 34567890123","000 34567890123","карта 000 34567890123","x000 34567890123","код 000 044525225","000 044525225","карта 000 044525225","x000 044525225","код 000 220441329947","000 220441329947","карта 000 220441329947","x000 220441329947","код 000 300504899258","000 300504899258","карта 000 300504899258","x000 300504899258","код 000 0000000000","000 0000000000","карта 000 0000000000","x000 0000000000","код 000 000000000000","000 000000000000","карта 000 000000000000","x000 000000000000","код 000 2204.9947.4132.0000","000 2204.9947.4132.0000","карта 000 2204.9947.4132.0000","x000 2204.9947.4132.0000","код 000 2222.2222.2222.2222","000 2222.2222.2222.2222","карта 000 2222.2222.2222.2222","x000 2222.2222.2222.2222","код 000 2204.4132.9947 0000","000 2204.4132.9947 0000","карта 000 2204.4132.9947 0000","x000 2204.4132.9947 0000","код 000 2204.4132.9947 0018","000 2204.4132.9947 0018","карта 000 2204.4132.9947 0018","x000 2204.4132.9947 0018","код 000 2204-4132-9947 0000","000 2204-4132-9947 0000","карта 000 2204-4132-9947 0000","x000 2204-4132-9947 0000","код 000 2204/4132/9947 0000","000 2204/4132/9947 0000","карта 000 2204/4132/9947 0000","x000 2204/4132/9947 0000","код 000 24.82.01.43.38","000 24.82.01.43.38","карта 000 24.82.01.43.38","x000 24.82.01.43.38","код 000 378/123/456/94","000 378/123/456/94","карта 000 378/123/456/94","x000 378/123/456/94","код 000 774358.417509","000 774358.417509","карта 000 774358.417509","x000 774358.417509","код 000 0.0.0000.0000.0000","000 0.0.0000.0000.0000","карта 000 0.0.0000.0000.0000","x000 0.0.0000.0000.0000","код 000 0.2.2204.4132.9947","000 0.2.2204.4132.9947","карта 000 0.2.2204.4132.9947","x000 0.2.2204.4132.9947","код 000 2.2.2204.4132.9947","000 2.2.2204.4132.9947","карта 000 2.2.2204.4132.9947","x000 2.2.2204.4132.9947","код 000 2.0.2204.4132.9947","000 2.0.2204.4132.9947","карта 000 2.0.2204.4132.9947","x000 2.0.2204.4132.9947","код 000 1.0.0000.0000.0000","000 1.0.0000.0000.0000","карта 000 1.0.0000.0000.0000","x000 1.0.0000.0000.0000","код 000 2.0000.0000.0000","000 2.0000.0000.0000","карта 000 2.0000.0000.0000","x000 2.0000.0000.0000","код 000 0.2204.4132.9947.0018","000 0.2204.4132.9947.0018","карта 000 0.2204.4132.9947.0018","x000 0.2204.4132.9947.0018","код 000 0.2204-4132-9947-0018","000 0.2204-4132-9947-0018","карта 000 0.2204-4132-9947-0018","x000 0.2204-4132-9947-0018","код 000 2222-2222-2222-2222","000 2222-2222-2222-2222","карта 000 2222-2222-2222-2222","x000 2222-2222-2222-2222","код 000 2222 2222 2222 2222","000 2222 2222 2222 2222","карта 000 2222 2222 2222 2222","x000 2222 2222 2222 2222","код 000 2222/2222/2222/2222","000 2222/2222/2222/2222","карта 000 2222/2222/2222/2222","x000 2222/2222/2222/2222","код 000 1111.1111.1111.1111","000 1111.1111.1111.1111","карта 000 1111.1111.1111.1111","x000 1111.1111.1111.1111","код 000 2204.4132.9947.0000.0000","000 2204.4132.9947.0000.0000","карта 000 2204.4132.9947.0000.0000","x000 2204.4132.9947.0000.0000","код 000 2204.4132.9947 1.2204.4132.9947","000 2204.4132.9947 1.2204.4132.9947","карта 000 2204.4132.9947 1.2204.4132.9947","x000 2204.4132.9947 1.2204.4132.9947","код 000 2204.4132.9947 0000000000","000 2204.4132.9947 0000000000","карта 000 2204.4132.9947 0000000000","x000 2204.4132.9947 0000000000","код 000 3005-0489-9258","000 3005-0489-9258","карта 000 3005-0489-9258","x000 3005-0489-9258","код 000 3005 0489 9258","000 3005 0489 9258","карта 000 3005 0489 9258","x000 3005 0489 9258","код 000 3005/0489/9258","000 3005/0489/9258","карта 000 3005/0489/9258","x000 3005/0489/9258","код 000 1000 2000 3000 4000 5000 6000","000 1000 2000 3000 4000 5000 6000","карта 000 1000 2000 3000 4000 5000 6000","x000 1000 2000 3000 4000 5000 6000","код 000 2204.4132.9947 списка","000 2204.4132.9947 списка","карта 000 2204.4132.9947 списка","x000 2204.4132.9947 списка","код 000 2204-4132-9947 список","000 2204-4132-9947 список","карта 000 2204-4132-9947 список","x000 2204-4132-9947 список","код 000 2.0000-0000-0000","000 2.0000-0000-0000","карта 000 2.0000-0000-0000","x000 2.0000-0000-0000","код 000 2.0000 0000 0000","000 2.0000 0000 0000","карта 000 2.0000 0000 0000","x000 2.0000 0000 0000","код 000 2.0000/0000/0000","000 2.0000/0000/0000","карта 000 2.0000/0000/0000","x000 2.0000/0000/0000","код 000 2.0000.0000.0000.0000","000 2.0000.0000.0000.0000","карта 000 2.0000.0000.0000.0000","x000 2.0000.0000.0000.0000","код 000 0.0000-0000-0000","000 0.0000-0000-0000","карта 000 0.0000-0000-0000","x000 0.0000-0000-0000","код 000 0.0000 0000 0000","000 0.0000 0000 0000","карта 000 0.0000 0000 0000","x000 0.0000 0000 0000","код 000 0.0000/0000/0000","000 0.0000/0000/0000","карта 000 0.0000/0000/0000","x000 0.0000/0000/0000","код 000 0.0000.0000.0000.0000","000 0.0000.0000.0000.0000","карта 000 0.0000.0000.0000.0000","x000 0.0000.0000.0000.0000","код 2.2204.4132.9947","2.2204.4132.9947","карта 2.2204.4132.9947","x2.2204.4132.9947","код 2.2204-4132-9947","2.2204-4132-9947","карта 2.2204-4132-9947","x2.2204-4132-9947","код 2.2204 4132 9947","2.2204 4132 9947","карта 2.2204 4132 9947","x2.2204 4132 9947","код 2.2204/4132/9947","2.2204/4132/9947","карта 2.2204/4132/9947","x2.2204/4132/9947","код 2.0000.0000.0000","2.0000.0000.0000","карта 2.0000.0000.0000","x2.0000.0000.0000","код 2.0000-0000-0000","2.0000-0000-0000","карта 2.0000-0000-0000","x2.0000-0000-0000","код 2.0000 0000 0000","2.0000 0000 0000","карта 2.0000 0000 0000","x2.0000 0000 0000","код 2.0000/0000/0000","2.0000/0000/0000","карта 2.0000/0000/0000","x2.0000/0000/0000","код 2.0000.0000.0000.0000","2.0000.0000.0000.0000","карта 2.0000.0000.0000.0000","x2.0000.0000.0000.0000","код 2.0000-0000-0000-0000","2.0000-0000-0000-0000","карта 2.0000-0000-0000-0000","x2.0000-0000-0000-0000","код 2.0000 0000 0000 0000","2.0000 0000 0000 0000","карта 2.0000 0000 0000 0000","x2.0000 0000 0000 0000","код 2.0000/0000/0000/0000","2.0000/0000/0000/0000","карта 2.0000/0000/0000/0000","x2.0000/0000/0000/0000","код 2.3005.0489.9258","2.3005.0489.9258","карта 2.3005.0489.9258","x2.3005.0489.9258","код 2.2204.4132.9947.0000","2.2204.4132.9947.0000","карта 2.2204.4132.9947.0000","x2.2204.4132.9947.0000","код 2.2204-4132-9947-0000","2.2204-4132-9947-0000","карта 2.2204-4132-9947-0000","x2.2204-4132-9947-0000","код 2.2204/4132/9947/0000","2.2204/4132/9947/0000","карта 2.2204/4132/9947/0000","x2.2204/4132/9947/0000","код 2.2204 4132 9947 0000","2.2204 4132 9947 0000","карта 2.2204 4132 9947 0000","x2.2204 4132 9947 0000","код 2.2204.4132.9947.0018","2.2204.4132.9947.0018","карта 2.2204.4132.9947.0018","x2.2204.4132.9947.0018","код 2.2204-4132-9947-0018","2.2204-4132-9947-0018","карта 2.2204-4132-9947-0018","x2.2204-4132-9947-0018","код 2.2204/4132/9947/0018","2.2204/4132/9947/0018","карта 2.2204/4132/9947/0018","x2.2204/4132/9947/0018","код 2.0.2204.4132.9947","2.0.2204.4132.9947","карта 2.0.2204.4132.9947","x2.0.2204.4132.9947","код 2.0.0000.0000.0000","2.0.0000.0000.0000","карта 2.0.0000.0000.0000","x2.0.0000.0000.0000","код 2.2.2204.4132.9947","2.2.2204.4132.9947","карта 2.2.2204.4132.9947","x2.2.2204.4132.9947","код 2.1.2204.4132.9947","2.1.2204.4132.9947","карта 2.1.2204.4132.9947","x2.1.2204.4132.9947","код 2.2204.4132","2.2204.4132","карта 2.2204.4132","x2.2204.4132","код 2.34567890123","2.34567890123","карта 2.34567890123","x2.34567890123","код 2.044525225","2.044525225","карта 2.044525225","x2.044525225","код 2.220441329947","2.220441329947","карта 2.220441329947","x2.220441329947","код 2.300504899258","2.300504899258","карта 2.300504899258","x2.300504899258","код 2.0000000000","2.0000000000","карта 2.0000000000","x2.0000000000","код 2.000000000000","2.000000000000","карта 2.000000000000","x2.000000000000","код 2.2204.9947.4132.0000","2.2204.9947.4132.0000","карта 2.2204.9947.4132.0000","x2.2204.9947.4132.0000","код 2.2222.2222.2222.2222","2.2222.2222.2222.2222","карта 2.2222.2222.2222.2222","x2.2222.2222.2222.2222","код 2.2204.4132.9947 0000","2.2204.4132.9947 0000","карта 2.2204.4132.9947 0000","x2.2204.4132.9947 0000","код 2.2204.4132.9947 0018","2.2204.4132.9947 0018","карта 2.2204.4132.9947 0018","x2.2204.4132.9947 0018","код 2.2204-4132-9947 0000","2.2204-4132-9947 0000","карта 2.2204-4132-9947 0000","x2.2204-4132-9947 0000","код 2.2204/4132/9947 0000","2.2204/4132/9947 0000","карта 2.2204/4132/9947 0000","x2.2204/4132/9947 0000","код 2.24.82.01.43.38","2.24.82.01.43.38","карта 2.24.82.01.43.38","x2.24.82.01.43.38","код 2.378/123/456/94","2.378/123/456/94","карта 2.378/123/456/94","x2.378/123/456/94","код 2.774358.417509","2.774358.417509","карта 2.774358.417509","x2.774358.417509","код 2.0.0.0000.0000.0000","2.0.0.0000.0000.0000","карта 2.0.0.0000.0000.0000","x2.0.0.0000.0000.0000","код 2.0.2.2204.4132.9947","2.0.2.2204.4132.9947","карта 2.0.2.2204.4132.9947","x2.0.2.2204.4132.9947","код 2.2.2.2204.4132.9947","2.2.2.2204.4132.9947","карта 2.2.2.2204.4132.9947","x2.2.2.2204.4132.9947","код 2.2.0.2204.4132.9947","2.2.0.2204.4132.9947","карта 2.2.0.2204.4132.9947","x2.2.0.2204.4132.9947","код 2.1.0.0000.0000.0000","2.1.0.0000.0000.0000","карта 2.1.0.0000.0000.0000","x2.1.0.0000.0000.0000","код 2.2.0000.0000.0000","2.2.0000.0000.0000","карта 2.2.0000.0000.0000","x2.2.0000.0000.0000","код 2.0.2204.4132.9947.0018","2.0.2204.4132.9947.0018","карта 2.0.2204.4132.9947.0018","x2.0.2204.4132.9947.0018","код 2.0.2204-4132-9947-0018","2.0.2204-4132-9947-0018","карта 2.0.2204-4132-9947-0018","x2.0.2204-4132-9947-0018","код 2.2222-2222-2222-2222","2.2222-2222-2222-2222","карта 2.2222-2222-2222-2222","x2.2222-2222-2222-2222","код 2.2222 2222 2222 2222","2.2222 2222 2222 2222","карта 2.2222 2222 2222 2222","x2.2222 2222 2222 2222","код 2.2222/2222/2222/2222","2.2222/2222/2222/2222","карта 2.2222/2222/2222/2222","x2.2222/2222/2222/2222","код 2.1111.1111.1111.1111","2.1111.1111.1111.1111","карта 2.1111.1111.1111.1111","x2.1111.1111.1111.1111","код 2.2204.4132.9947.0000.0000","2.2204.4132.9947.0000.0000","карта 2.2204.4132.9947.0000.0000","x2.2204.4132.9947.0000.0000","код 2.2204.4132.9947 1.2204.4132.9947","2.2204.4132.9947 1.2204.4132.9947","карта 2.2204.4132.9947 1.2204.4132.9947","x2.2204.4132.9947 1.2204.4132.9947","код 2.2204.4132.9947 0000000000","2.2204.4132.9947 0000000000","карта 2.2204.4132.9947 0000000000","x2.2204.4132.9947 0000000000","код 2.3005-0489-9258","2.3005-0489-9258","карта 2.3005-0489-9258","x2.3005-0489-9258","код 2.3005 0489 9258","2.3005 0489 9258","карта 2.3005 0489 9258","x2.3005 0489 9258","код 2.3005/0489/9258","2.3005/0489/9258","карта 2.3005/0489/9258","x2.3005/0489/9258","код 2.1000 2000 3000 4000 5000 6000","2.1000 2000 3000 4000 5000 6000","карта 2.1000 2000 3000 4000 5000 6000","x2.1000 2000 3000 4000 5000 6000","код 2.2204.4132.9947 списка","2.2204.4132.9947 списка","карта 2.2204.4132.9947 списка","x2.2204.4132.9947 списка","код 2.2204-4132-9947 список","2.2204-4132-9947 список","карта 2.2204-4132-9947 список","x2.2204-4132-9947 список","код 2.2.0000-0000-0000","2.2.0000-0000-0000","карта 2.2.0000-0000-0000","x2.2.0000-0000-0000","код 2.2.0000 0000 0000","2.2.0000 0000 0000","карта 2.2.0000 0000 0000","x2.2.0000 0000 0000","код 2.2.0000/0000/0000","2.2.0000/0000/0000","карта 2.2.0000/0000/0000","x2.2.0000/0000/0000","код 2.2.0000.0000.0000.0000","2.2.0000.0000.0000.0000","карта 2.2.0000.0000.0000.0000","x2.2.0000.0000.0000.0000","код 2.0.0000-0000-0000","2.0.0000-0000-0000","карта 2.0.0000-0000-0000","x2.0.0000-0000-0000","код 2.0.0000 0000 0000","2.0.0000 0000 0000","карта 2.0.0000 0000 0000","x2.0.0000 0000 0000","код 2.0.0000/0000/0000","2.0.0000/0000/0000","карта 2.0.0000/0000/0000","x2.0.0000/0000/0000","код 2.0.0000.0000.0000.0000","2.0.0000.0000.0000.0000","карта 2.0.0000.0000.0000.0000","x2.0.0000.0000.0000.0000","код 2-2204.4132.9947","2-2204.4132.9947","карта 2-2204.4132.9947","x2-2204.4132.9947","код 2-2204-4132-9947","2-2204-4132-9947","карта 2-2204-4132-9947","x2-2204-4132-9947","код 2-2204 4132 9947","2-2204 4132 9947","карта 2-2204 4132 9947","x2-2204 4132 9947","код 2-2204/4132/9947","2-2204/4132/9947","карта 2-2204/4132/9947","x2-2204/4132/9947","код 2-0000.0000.0000","2-0000.0000.0000","карта 2-0000.0000.0000","x2-0000.0000.0000","код 2-0000-0000-0000","2-0000-0000-0000","карта 2-0000-0000-0000","x2-0000-0000-0000","код 2-0000 0000 0000","2-0000 0000 0000","карта 2-0000 0000 0000","x2-0000 0000 0000","код 2-0000/0000/0000","2-0000/0000/0000","карта 2-0000/0000/0000","x2-0000/0000/0000","код 2-0000.0000.0000.0000","2-0000.0000.0000.0000","карта 2-0000.0000.0000.0000","x2-0000.0000.0000.0000","код 2-0000-0000-0000-0000","2-0000-0000-0000-0000","карта 2-0000-0000-0000-0000","x2-0000-0000-0000-0000","код 2-0000 0000 0000 0000","2-0000 0000 0000 0000","карта 2-0000 0000 0000 0000","x2-0000 0000 0000 0000","код 2-0000/0000/0000/0000","2-0000/0000/0000/0000","карта 2-0000/0000/0000/0000","x2-0000/0000/0000/0000","код 2-3005.0489.9258","2-3005.0489.9258","карта 2-3005.0489.9258","x2-3005.0489.9258","код 2-2204.4132.9947.0000","2-2204.4132.9947.0000","карта 2-2204.4132.9947.0000","x2-2204.4132.9947.0000","код 2-2204-4132-9947-0000","2-2204-4132-9947-0000","карта 2-2204-4132-9947-0000","x2-2204-4132-9947-0000","код 2-2204/4132/9947/0000","2-2204/4132/9947/0000","карта 2-2204/4132/9947/0000","x2-2204/4132/9947/0000","код 2-2204 4132 9947 0000","2-2204 4132 9947 0000","карта 2-2204 4132 9947 0000","x2-2204 4132 9947 0000","код 2-2204.4132.9947.0018","2-2204.4132.9947.0018","карта 2-2204.4132.9947.0018","x2-2204.4132.9947.0018","код 2-2204-4132-9947-0018","2-2204-4132-9947-0018","карта 2-2204-4132-9947-0018","x2-2204-4132-9947-0018","код 2-2204/4132/9947/0018","2-2204/4132/9947/0018","карта 2-2204/4132/9947/0018","x2-2204/4132/9947/0018","код 2-0.2204.4132.9947","2-0.2204.4132.9947","карта 2-0.2204.4132.9947","x2-0.2204.4132.9947","код 2-0.0000.0000.0000","2-0.0000.0000.0000","карта 2-0.0000.0000.0000","x2-0.0000.0000.0000","код 2-2.2204.4132.9947","2-2.2204.4132.9947","карта 2-2.2204.4132.9947","x2-2.2204.4132.9947","код 2-1.2204.4132.9947","2-1.2204.4132.9947","карта 2-1.2204.4132.9947","x2-1.2204.4132.9947","код 2-2204.4132","2-2204.4132","карта 2-2204.4132","x2-2204.4132","код 2-34567890123","2-34567890123","карта 2-34567890123","x2-34567890123","код 2-044525225","2-044525225","карта 2-044525225","x2-044525225","код 2-220441329947","2-220441329947","карта 2-220441329947","x2-220441329947","код 2-300504899258","2-300504899258","карта 2-300504899258","x2-300504899258","код 2-0000000000","2-0000000000","карта 2-0000000000","x2-0000000000","код 2-000000000000","2-000000000000","карта 2-000000000000","x2-000000000000","код 2-2204.9947.4132.0000","2-2204.9947.4132.0000","карта 2-2204.9947.4132.0000","x2-2204.9947.4132.0000","код 2-2222.2222.2222.2222","2-2222.2222.2222.2222","карта 2-2222.2222.2222.2222","x2-2222.2222.2222.2222","код 2-2204.4132.9947 0000","2-2204.4132.9947 0000","карта 2-2204.4132.9947 0000","x2-2204.4132.9947 0000","код 2-2204.4132.9947 0018","2-2204.4132.9947 0018","карта 2-2204.4132.9947 0018","x2-2204.4132.9947 0018","код 2-2204-4132-9947 0000","2-2204-4132-9947 0000","карта 2-2204-4132-9947 0000","x2-2204-4132-9947 0000","код 2-2204/4132/9947 0000","2-2204/4132/9947 0000","карта 2-2204/4132/9947 0000","x2-2204/4132/9947 0000","код 2-24.82.01.43.38","2-24.82.01.43.38","карта 2-24.82.01.43.38","x2-24.82.01.43.38","код 2-378/123/456/94","2-378/123/456/94","карта 2-378/123/456/94","x2-378/123/456/94","код 2-774358.417509","2-774358.417509","карта 2-774358.417509","x2-774358.417509","код 2-0.0.0000.0000.0000","2-0.0.0000.0000.0000","карта 2-0.0.0000.0000.0000","x2-0.0.0000.0000.0000","код 2-0.2.2204.4132.9947","2-0.2.2204.4132.9947","карта 2-0.2.2204.4132.9947","x2-0.2.2204.4132.9947","код 2-2.2.2204.4132.9947","2-2.2.2204.4132.9947","карта 2-2.2.2204.4132.9947","x2-2.2.2204.4132.9947","код 2-2.0.2204.4132.9947","2-2.0.2204.4132.9947","карта 2-2.0.2204.4132.9947","x2-2.0.2204.4132.9947","код 2-1.0.0000.0000.0000","2-1.0.0000.0000.0000","карта 2-1.0.0000.0000.0000","x2-1.0.0000.0000.0000","код 2-2.0000.0000.0000","2-2.0000.0000.0000","карта 2-2.0000.0000.0000","x2-2.0000.0000.0000","код 2-0.2204.4132.9947.0018","2-0.2204.4132.9947.0018","карта 2-0.2204.4132.9947.0018","x2-0.2204.4132.9947.0018","код 2-0.2204-4132-9947-0018","2-0.2204-4132-9947-0018","карта 2-0.2204-4132-9947-0018","x2-0.2204-4132-9947-0018","код 2-2222-2222-2222-2222","2-2222-2222-2222-2222","карта 2-2222-2222-2222-2222","x2-2222-2222-2222-2222","код 2-2222 2222 2222 2222","2-2222 2222 2222 2222","карта 2-2222 2222 2222 2222","x2-2222 2222 2222 2222","код 2-2222/2222/2222/2222","2-2222/2222/2222/2222","карта 2-2222/2222/2222/2222","x2-2222/2222/2222/2222","код 2-1111.1111.1111.1111","2-1111.1111.1111.1111","карта 2-1111.1111.1111.1111","x2-1111.1111.1111.1111","код 2-2204.4132.9947.0000.0000","2-2204.4132.9947.0000.0000","карта 2-2204.4132.9947.0000.0000","x2-2204.4132.9947.0000.0000","код 2-2204.4132.9947 1.2204.4132.9947","2-2204.4132.9947 1.2204.4132.9947","карта 2-2204.4132.9947 1.2204.4132.9947","x2-2204.4132.9947 1.2204.4132.9947","код 2-2204.4132.9947 0000000000","2-2204.4132.9947 0000000000","карта 2-2204.4132.9947 0000000000","x2-2204.4132.9947 0000000000","код 2-3005-0489-9258","2-3005-0489-9258","карта 2-3005-0489-9258","x2-3005-0489-9258","код 2-3005 0489 9258","2-3005 0489 9258","карта 2-3005 0489 9258","x2-3005 0489 9258","код 2-3005/0489/9258","2-3005/0489/9258","карта 2-3005/0489/9258","x2-3005/0489/9258","код 2-1000 2000 3000 4000 5000 6000","2-1000 2000 3000 4000 5000 6000","карта 2-1000 2000 3000 4000 5000 6000","x2-1000 2000 3000 4000 5000 6000","код 2-2204.4132.9947 списка","2-2204.4132.9947 списка","карта 2-2204.4132.9947 списка","x2-2204.4132.9947 списка","код 2-2204-4132-9947 список","2-2204-4132-9947 список","карта 2-2204-4132-9947 список","x2-2204-4132-9947 список","код 2-2.0000-0000-0000","2-2.0000-0000-0000","карта 2-2.0000-0000-0000","x2-2.0000-0000-0000","код 2-2.0000 0000 0000","2-2.0000 0000 0000","карта 2-2.0000 0000 0000","x2-2.0000 0000 0000","код 2-2.0000/0000/0000","2-2.0000/0000/0000","карта 2-2.0000/0000/0000","x2-2.0000/0000/0000","код 2-2.0000.0000.0000.0000","2-2.0000.0000.0000.0000","карта 2-2.0000.0000.0000.0000","x2-2.0000.0000.0000.0000","код 2-0.0000-0000-0000","2-0.0000-0000-0000","карта 2-0.0000-0000-0000","x2-0.0000-0000-0000","код 2-0.0000 0000 0000","2-0.0000 0000 0000","карта 2-0.0000 0000 0000","x2-0.0000 0000 0000","код 2-0.0000/0000/0000","2-0.0000/0000/0000","карта 2-0.0000/0000/0000","x2-0.0000/0000/0000","код 2-0.0000.0000.0000.0000","2-0.0000.0000.0000.0000","карта 2-0.0000.0000.0000.0000","x2-0.0000.0000.0000.0000","код 2/2204.4132.9947","2/2204.4132.9947","карта 2/2204.4132.9947","x2/2204.4132.9947","код 2/2204-4132-9947","2/2204-4132-9947","карта 2/2204-4132-9947","x2/2204-4132-9947","код 2/2204 4132 9947","2/2204 4132 9947","карта 2/2204 4132 9947","x2/2204 4132 9947","код 2/2204/4132/9947","2/2204/4132/9947","карта 2/2204/4132/9947","x2/2204/4132/9947","код 2/0000.0000.0000","2/0000.0000.0000","карта 2/0000.0000.0000","x2/0000.0000.0000","код 2/0000-0000-0000","2/0000-0000-0000","карта 2/0000-0000-0000","x2/0000-0000-0000","код 2/0000 0000 0000","2/0000 0000 0000","карта 2/0000 0000 0000","x2/0000 0000 0000","код 2/0000/0000/0000","2/0000/0000/0000","карта 2/0000/0000/0000","x2/0000/0000/0000","код 2/0000.0000.0000.0000","2/0000.0000.0000.0000","карта 2/0000.0000.0000.0000","x2/0000.0000.0000.0000","код 2/0000-0000-0000-0000","2/0000-0000-0000-0000","карта 2/0000-0000-0000-0000","x2/0000-0000-0000-0000","код 2/0000 0000 0000 0000","2/0000 0000 0000 0000","карта 2/0000 0000 0000 0000","x2/0000 0000 0000 0000","код 2/0000/0000/0000/0000","2/0000/0000/0000/0000","карта 2/0000/0000/0000/0000","x2/0000/0000/0000/0000","код 2/3005.0489.9258","2/3005.0489.9258","карта 2/3005.0489.9258","x2/3005.0489.9258","код 2/2204.4132.9947.0000","2/2204.4132.9947.0000","карта 2/2204.4132.9947.0000","x2/2204.4132.9947.0000","код 2/2204-4132-9947-0000","2/2204-4132-9947-0000","карта 2/2204-4132-9947-0000","x2/2204-4132-9947-0000","код 2/2204/4132/9947/0000","2/2204/4132/9947/0000","карта 2/2204/4132/9947/0000","x2/2204/4132/9947/0000","код 2/2204 4132 9947 0000","2/2204 4132 9947 0000","карта 2/2204 4132 9947 0000","x2/2204 4132 9947 0000","код 2/2204.4132.9947.0018","2/2204.4132.9947.0018","карта 2/2204.4132.9947.0018","x2/2204.4132.9947.0018","код 2/2204-4132-9947-0018","2/2204-4132-9947-0018","карта 2/2204-4132-9947-0018","x2/2204-4132-9947-0018","код 2/2204/4132/9947/0018","2/2204/4132/9947/0018","карта 2/2204/4132/9947/0018","x2/2204/4132/9947/0018","код 2/0.2204.4132.9947","2/0.2204.4132.9947","карта 2/0.2204.4132.9947","x2/0.2204.4132.9947","код 2/0.0000.0000.0000","2/0.0000.0000.0000","карта 2/0.0000.0000.0000","x2/0.0000.0000.0000","код 2/2.2204.4132.9947","2/2.2204.4132.9947","карта 2/2.2204.4132.9947","x2/2.2204.4132.9947","код 2/1.2204.4132.9947","2/1.2204.4132.9947","карта 2/1.2204.4132.9947","x2/1.2204.4132.9947","код 2/2204.4132","2/2204.4132","карта 2/2204.4132","x2/2204.4132","код 2/34567890123","2/34567890123","карта 2/34567890123","x2/34567890123","код 2/044525225","2/044525225","карта 2/044525225","x2/044525225","код 2/220441329947","2/220441329947","карта 2/220441329947","x2/220441329947","код 2/300504899258","2/300504899258","карта 2/300504899258","x2/300504899258","код 2/0000000000","2/0000000000","карта 2/0000000000","x2/0000000000","код 2/000000000000","2/000000000000","карта 2/000000000000","x2/000000000000","код 2/2204.9947.4132.0000","2/2204.9947.4132.0000","карта 2/2204.9947.4132.0000","x2/2204.9947.4132.0000","код 2/2222.2222.2222.2222","2/2222.2222.2222.2222","карта 2/2222.2222.2222.2222","x2/2222.2222.2222.2222","код 2/2204.4132.9947 0000","2/2204.4132.9947 0000","карта 2/2204.4132.9947 0000","x2/2204.4132.9947 0000","код 2/2204.4132.9947 0018","2/2204.4132.9947 0018","карта 2/2204.4132.9947 0018","x2/2204.4132.9947 0018","код 2/2204-4132-9947 0000","2/2204-4132-9947 0000","карта 2/2204-4132-9947 0000","x2/2204-4132-9947 0000","код 2/2204/4132/9947 0000","2/2204/4132/9947 0000","карта 2/2204/4132/9947 0000","x2/2204/4132/9947 0000","код 2/24.82.01.43.38","2/24.82.01.43.38","карта 2/24.82.01.43.38","x2/24.82.01.43.38","код 2/378/123/456/94","2/378/123/456/94","карта 2/378/123/456/94","x2/378/123/456/94","код 2/774358.417509","2/774358.417509","карта 2/774358.417509","x2/774358.417509","код 2/0.0.0000.0000.0000","2/0.0.0000.0000.0000","карта 2/0.0.0000.0000.0000","x2/0.0.0000.0000.0000","код 2/0.2.2204.4132.9947","2/0.2.2204.4132.9947","карта 2/0.2.2204.4132.9947","x2/0.2.2204.4132.9947","код 2/2.2.2204.4132.9947","2/2.2.2204.4132.9947","карта 2/2.2.2204.4132.9947","x2/2.2.2204.4132.9947","код 2/2.0.2204.4132.9947","2/2.0.2204.4132.9947","карта 2/2.0.2204.4132.9947","x2/2.0.2204.4132.9947","код 2/1.0.0000.0000.0000","2/1.0.0000.0000.0000","карта 2/1.0.0000.0000.0000","x2/1.0.0000.0000.0000","код 2/2.0000.0000.0000","2/2.0000.0000.0000","карта 2/2.0000.0000.0000","x2/2.0000.0000.0000","код 2/0.2204.4132.9947.0018","2/0.2204.4132.9947.0018","карта 2/0.2204.4132.9947.0018","x2/0.2204.4132.9947.0018","код 2/0.2204-4132-9947-0018","2/0.2204-4132-9947-0018","карта 2/0.2204-4132-9947-0018","x2/0.2204-4132-9947-0018","код 2/2222-2222-2222-2222","2/2222-2222-2222-2222","карта 2/2222-2222-2222-2222","x2/2222-2222-2222-2222","код 2/2222 2222 2222 2222","2/2222 2222 2222 2222","карта 2/2222 2222 2222 2222","x2/2222 2222 2222 2222","код 2/2222/2222/2222/2222","2/2222/2222/2222/2222","карта 2/2222/2222/2222/2222","x2/2222/2222/2222/2222","код 2/1111.1111.1111.1111","2/1111.1111.1111.1111","карта 2/1111.1111.1111.1111","x2/1111.1111.1111.1111","код 2/2204.4132.9947.0000.0000","2/2204.4132.9947.0000.0000","карта 2/2204.4132.9947.0000.0000","x2/2204.4132.9947.0000.0000","код 2/2204.4132.9947 1.2204.4132.9947","2/2204.4132.9947 1.2204.4132.9947","карта 2/2204.4132.9947 1.2204.4132.9947","x2/2204.4132.9947 1.2204.4132.9947","код 2/2204.4132.9947 0000000000","2/2204.4132.9947 0000000000","карта 2/2204.4132.9947 0000000000","x2/2204.4132.9947 0000000000","код 2/3005-0489-9258","2/3005-0489-9258","карта 2/3005-0489-9258","x2/3005-0489-9258","код 2/3005 0489 9258","2/3005 0489 9258","карта 2/3005 0489 9258","x2/3005 0489 9258","код 2/3005/0489/9258","2/3005/0489/9258","карта 2/3005/0489/9258","x2/3005/0489/9258","код 2/1000 2000 3000 4000 5000 6000","2/1000 2000 3000 4000 5000 6000","карта 2/1000 2000 3000 4000 5000 6000","x2/1000 2000 3000 4000 5000 6000","код 2/2204.4132.9947 списка","2/2204.4132.9947 списка","карта 2/2204.4132.9947 списка","x2/2204.4132.9947 списка","код 2/2204-4132-9947 список","2/2204-4132-9947 список","карта 2/2204-4132-9947 список","x2/2204-4132-9947 список","код 2/2.0000-0000-0000","2/2.0000-0000-0000","карта 2/2.0000-0000-0000","x2/2.0000-0000-0000","код 2/2.0000 0000 0000","2/2.0000 0000 0000","карта 2/2.0000 0000 0000","x2/2.0000 0000 0000","код 2/2.0000/0000/0000","2/2.0000/0000/0000","карта 2/2.0000/0000/0000","x2/2.0000/0000/0000","код 2/2.0000.0000.0000.0000","2/2.0000.0000.0000.0000","карта 2/2.0000.0000.0000.0000","x2/2.0000.0000.0000.0000","код 2/0.0000-0000-0000","2/0.0000-0000-0000","карта 2/0.0000-0000-0000","x2/0.0000-0000-0000","код 2/0.0000 0000 0000","2/0.0000 0000 0000","карта 2/0.0000 0000 0000","x2/0.0000 0000 0000","код 2/0.0000/0000/0000","2/0.0000/0000/0000","карта 2/0.0000/0000/0000","x2/0.0000/0000/0000","код 2/0.0000.0000.0000.0000","2/0.0000.0000.0000.0000","карта 2/0.0000.0000.0000.0000","x2/0.0000.0000.0000.0000","код 2 2204.4132.9947","2 2204.4132.9947","карта 2 2204.4132.9947","x2 2204.4132.9947","код 2 2204-4132-9947","2 2204-4132-9947","карта 2 2204-4132-9947","x2 2204-4132-9947","код 2 2204 4132 9947","2 2204 4132 9947","карта 2 2204 4132 9947","x2 2204 4132 9947","код 2 2204/4132/9947","2 2204/4132/9947","карта 2 2204/4132/9947","x2 2204/4132/9947","код 2 0000.0000.0000","2 0000.0000.0000","карта 2 0000.0000.0000","x2 0000.0000.0000","код 2 0000-0000-0000","2 0000-0000-0000","карта 2 0000-0000-0000","x2 0000-0000-0000","код 2 0000 0000 0000","2 0000 0000 0000","карта 2 0000 0000 0000","x2 0000 0000 0000","код 2 0000/0000/0000","2 0000/0000/0000","карта 2 0000/0000/0000","x2 0000/0000/0000","код 2 0000.0000.0000.0000","2 0000.0000.0000.0000","карта 2 0000.0000.0000.0000","x2 0000.0000.0000.0000","код 2 0000-0000-0000-0000","2 0000-0000-0000-0000","карта 2 0000-0000-0000-0000","x2 0000-0000-0000-0000","код 2 0000 0000 0000 0000","2 0000 0000 0000 0000","карта 2 0000 0000 0000 0000","x2 0000 0000 0000 0000","код 2 0000/0000/0000/0000","2 0000/0000/0000/0000","карта 2 0000/0000/0000/0000","x2 0000/0000/0000/0000","код 2 3005.0489.9258","2 3005.0489.9258","карта 2 3005.0489.9258","x2 3005.0489.9258","код 2 2204.4132.9947.0000","2 2204.4132.9947.0000","карта 2 2204.4132.9947.0000","x2 2204.4132.9947.0000","код 2 2204-4132-9947-0000","2 2204-4132-9947-0000","карта 2 2204-4132-9947-0000","x2 2204-4132-9947-0000","код 2 2204/4132/9947/0000","2 2204/4132/9947/0000","карта 2 2204/4132/9947/0000","x2 2204/4132/9947/0000","код 2 2204 4132 9947 0000","2 2204 4132 9947 0000","карта 2 2204 4132 9947 0000","x2 2204 4132 9947 0000","код 2 2204.4132.9947.0018","2 2204.4132.9947.0018","карта 2 2204.4132.9947.0018","x2 2204.4132.9947.0018","код 2 2204-4132-9947-0018","2 2204-4132-9947-0018","карта 2 2204-4132-9947-0018","x2 2204-4132-9947-0018","код 2 2204/4132/9947/0018","2 2204/4132/9947/0018","карта 2 2204/4132/9947/0018","x2 2204/4132/9947/0018","код 2 0.2204.4132.9947","2 0.2204.4132.9947","карта 2 0.2204.4132.9947","x2 0.2204.4132.9947","код 2 0.0000.0000.0000","2 0.0000.0000.0000","карта 2 0.0000.0000.0000","x2 0.0000.0000.0000","код 2 2.2204.4132.9947","2 2.2204.4132.9947","карта 2 2.2204.4132.9947","x2 2.2204.4132.9947","код 2 1.2204.4132.9947","2 1.2204.4132.9947","карта 2 1.2204.4132.9947","x2 1.2204.4132.9947","код 2 2204.4132","2 2204.4132","карта 2 2204.4132","x2 2204.4132","код 2 34567890123","2 34567890123","карта 2 34567890123","x2 34567890123","код 2 044525225","2 044525225","карта 2 044525225","x2 044525225","код 2 220441329947","2 220441329947","карта 2 220441329947","x2 220441329947","код 2 300504899258","2 300504899258","карта 2 300504899258","x2 300504899258","код 2 0000000000","2 0000000000","карта 2 0000000000","x2 0000000000","код 2 000000000000","2 000000000000","карта 2 000000000000","x2 000000000000","код 2 2204.9947.4132.0000","2 2204.9947.4132.0000","карта 2 2204.9947.4132.0000","x2 2204.9947.4132.0000","код 2 2222.2222.2222.2222","2 2222.2222.2222.2222","карта 2 2222.2222.2222.2222","x2 2222.2222.2222.2222","код 2 2204.4132.9947 0000","2 2204.4132.9947 0000","карта 2 2204.4132.9947 0000","x2 2204.4132.9947 0000","код 2 2204.4132.9947 0018","2 2204.4132.9947 0018","карта 2 2204.4132.9947 0018","x2 2204.4132.9947 0018","код 2 2204-4132-9947 0000","2 2204-4132-9947 0000","карта 2 2204-4132-9947 0000","x2 2204-4132-9947 0000","код 2 2204/4132/9947 0000","2 2204/4132/9947 0000","карта 2 2204/4132/9947 0000","x2 2204/4132/9947 0000","код 2 24.82.01.43.38","2 24.82.01.43.38","карта 2 24.82.01.43.38","x2 24.82.01.43.38","код 2 378/123/456/94","2 378/123/456/94","карта 2 378/123/456/94","x2 378/123/456/94","код 2 774358.417509","2 774358.417509","карта 2 774358.417509","x2 774358.417509","код 2 0.0.0000.0000.0000","2 0.0.0000.0000.0000","карта 2 0.0.0000.0000.0000","x2 0.0.0000.0000.0000","код 2 0.2.2204.4132.9947","2 0.2.2204.4132.9947","карта 2 0.2.2204.4132.9947","x2 0.2.2204.4132.9947","код 2 2.2.2204.4132.9947","2 2.2.2204.4132.9947","карта 2 2.2.2204.4132.9947","x2 2.2.2204.4132.9947","код 2 2.0.2204.4132.9947","2 2.0.2204.4132.9947","карта 2 2.0.2204.4132.9947","x2 2.0.2204.4132.9947","код 2 1.0.0000.0000.0000","2 1.0.0000.0000.0000","карта 2 1.0.0000.0000.0000","x2 1.0.0000.0000.0000","код 2 2.0000.0000.0000","2 2.0000.0000.0000","карта 2 2.0000.0000.0000","x2 2.0000.0000.0000","код 2 0.2204.4132.9947.0018","2 0.2204.4132.9947.0018","карта 2 0.2204.4132.9947.0018","x2 0.2204.4132.9947.0018","код 2 0.2204-4132-9947-0018","2 0.2204-4132-9947-0018","карта 2 0.2204-4132-9947-0018","x2 0.2204-4132-9947-0018","код 2 2222-2222-2222-2222","2 2222-2222-2222-2222","карта 2 2222-2222-2222-2222","x2 2222-2222-2222-2222","код 2 2222 2222 2222 2222","2 2222 2222 2222 2222","карта 2 2222 2222 2222 2222","x2 2222 2222 2222 2222","код 2 2222/2222/2222/2222","2 2222/2222/2222/2222","карта 2 2222/2222/2222/2222","x2 2222/2222/2222/2222","код 2 1111.1111.1111.1111","2 1111.1111.1111.1111","карта 2 1111.1111.1111.1111","x2 1111.1111.1111.1111","код 2 2204.4132.9947.0000.0000","2 2204.4132.9947.0000.0000","карта 2 2204.4132.9947.0000.0000","x2 2204.4132.9947.0000.0000","код 2 2204.4132.9947 1.2204.4132.9947","2 2204.4132.9947 1.2204.4132.9947","карта 2 2204.4132.9947 1.2204.4132.9947","x2 2204.4132.9947 1.2204.4132.9947","код 2 2204.4132.9947 0000000000","2 2204.4132.9947 0000000000","карта 2 2204.4132.9947 0000000000","x2 2204.4132.9947 0000000000","код 2 3005-0489-9258","2 3005-0489-9258","карта 2 3005-0489-9258","x2 3005-0489-9258","код 2 3005 0489 9258","2 3005 0489 9258","карта 2 3005 0489 9258","x2 3005 0489 9258","код 2 3005/0489/9258","2 3005/0489/9258","карта 2 3005/0489/9258","x2 3005/0489/9258","код 2 1000 2000 3000 4000 5000 6000","2 1000 2000 3000 4000 5000 6000","карта 2 1000 2000 3000 4000 5000 6000","x2 1000 2000 3000 4000 5000 6000","код 2 2204.4132.9947 списка","2 2204.4132.9947 списка","карта 2 2204.4132.9947 списка","x2 2204.4132.9947 списка","код 2 2204-4132-9947 список","2 2204-4132-9947 список","карта 2 2204-4132-9947 список","x2 2204-4132-9947 список","код 2 2.0000-0000-0000","2 2.0000-0000-0000","карта 2 2.0000-0000-0000","x2 2.0000-0000-0000","код 2 2.0000 0000 0000","2 2.0000 0000 0000","карта 2 2.0000 0000 0000","x2 2.0000 0000 0000","код 2 2.0000/0000/0000","2 2.0000/0000/0000","карта 2 2.0000/0000/0000","x2 2.0000/0000/0000","код 2 2.0000.0000.0000.0000","2 2.0000.0000.0000.0000","карта 2 2.0000.0000.0000.0000","x2 2.0000.0000.0000.0000","код 2 0.0000-0000-0000","2 0.0000-0000-0000","карта 2 0.0000-0000-0000","x2 0.0000-0000-0000","код 2 0.0000 0000 0000","2 0.0000 0000 0000","карта 2 0.0000 0000 0000","x2 0.0000 0000 0000","код 2 0.0000/0000/0000","2 0.0000/0000/0000","карта 2 0.0000/0000/0000","x2 0.0000/0000/0000","код 2 0.0000.0000.0000.0000","2 0.0000.0000.0000.0000","карта 2 0.0000.0000.0000.0000","x2 0.0000.0000.0000.0000","код x2.2204.4132.9947","карта x2.2204.4132.9947","xx2.2204.4132.9947","код x2.2204-4132-9947","карта x2.2204-4132-9947","xx2.2204-4132-9947","код x2.2204 4132 9947","карта x2.2204 4132 9947","xx2.2204 4132 9947","код x2.2204/4132/9947","карта x2.2204/4132/9947","xx2.2204/4132/9947","код x2.0000.0000.0000","карта x2.0000.0000.0000","xx2.0000.0000.0000","код x2.0000-0000-0000","карта x2.0000-0000-0000","xx2.0000-0000-0000","код x2.0000 0000 0000","карта x2.0000 0000 0000","xx2.0000 0000 0000","код x2.0000/0000/0000","карта x2.0000/0000/0000","xx2.0000/0000/0000","код x2.0000.0000.0000.0000","карта x2.0000.0000.0000.0000","xx2.0000.0000.0000.0000","код x2.0000-0000-0000-0000","карта x2.0000-0000-0000-0000","xx2.0000-0000-0000-0000","код x2.0000 0000 0000 0000","карта x2.0000 0000 0000 0000","xx2.0000 0000 0000 0000","код x2.0000/0000/0000/0000","карта x2.0000/0000/0000/0000","xx2.0000/0000/0000/0000","код x2.3005.0489.9258","карта x2.3005.0489.9258","xx2.3005.0489.9258","код x2.2204.4132.9947.0000","карта x2.2204.4132.9947.0000","xx2.2204.4132.9947.0000","код x2.2204-4132-9947-0000","карта x2.2204-4132-9947-0000","xx2.2204-4132-9947-0000","код x2.2204/4132/9947/0000","карта x2.2204/4132/9947/0000","xx2.2204/4132/9947/0000","код x2.2204 4132 9947 0000","карта x2.2204 4132 9947 0000","xx2.2204 4132 9947 0000","код x2.2204.4132.9947.0018","карта x2.2204.4132.9947.0018","xx2.2204.4132.9947.0018","код x2.2204-4132-9947-0018","карта x2.2204-4132-9947-0018","xx2.2204-4132-9947-0018","код x2.2204/4132/9947/0018","карта x2.2204/4132/9947/0018","xx2.2204/4132/9947/0018","код x2.0.2204.4132.9947","карта x2.0.2204.4132.9947","xx2.0.2204.4132.9947","код x2.0.0000.0000.0000","карта x2.0.0000.0000.0000","xx2.0.0000.0000.0000","код x2.2.2204.4132.9947","карта x2.2.2204.4132.9947","xx2.2.2204.4132.9947","код x2.1.2204.4132.9947","карта x2.1.2204.4132.9947","xx2.1.2204.4132.9947","код x2.2204.4132","карта x2.2204.4132","xx2.2204.4132","код x2.34567890123","карта x2.34567890123","xx2.34567890123","код x2.044525225","карта x2.044525225","xx2.044525225","код x2.220441329947","карта x2.220441329947","xx2.220441329947","код x2.300504899258","карта x2.300504899258","xx2.300504899258","код x2.0000000000","карта x2.0000000000","xx2.0000000000","код x2.000000000000","карта x2.000000000000","xx2.000000000000","код x2.2204.9947.4132.0000","карта x2.2204.9947.4132.0000","xx2.2204.9947.4132.0000","код x2.2222.2222.2222.2222","карта x2.2222.2222.2222.2222","xx2.2222.2222.2222.2222","код x2.2204.4132.9947 0000","карта x2.2204.4132.9947 0000","xx2.2204.4132.9947 0000","код x2.2204.4132.9947 0018","карта x2.2204.4132.9947 0018","xx2.2204.4132.9947 0018","код x2.2204-4132-9947 0000","карта x2.2204-4132-9947 0000","xx2.2204-4132-9947 0000","код x2.2204/4132/9947 0000","карта x2.2204/4132/9947 0000","xx2.2204/4132/9947 0000","код x2.24.82.01.43.38","карта x2.24.82.01.43.38","xx2.24.82.01.43.38","код x2.378/123/456/94","карта x2.378/123/456/94","xx2.378/123/456/94","код x2.774358.417509","карта x2.774358.417509","xx2.774358.417509","код x2.0.0.0000.0000.0000","карта x2.0.0.0000.0000.0000","xx2.0.0.0000.0000.0000","код x2.0.2.2204.4132.9947","карта x2.0.2.2204.4132.9947","xx2.0.2.2204.4132.9947","код x2.2.2.2204.4132.9947","карта x2.2.2.2204.4132.9947","xx2.2.2.2204.4132.9947","код x2.2.0.2204.4132.9947","карта x2.2.0.2204.4132.9947","xx2.2.0.2204.4132.9947","код x2.1.0.0000.0000.0000","карта x2.1.0.0000.0000.0000","xx2.1.0.0000.0000.0000","код x2.2.0000.0000.0000","карта x2.2.0000.0000.0000","xx2.2.0000.0000.0000","код x2.0.2204.4132.9947.0018","карта x2.0.2204.4132.9947.0018","xx2.0.2204.4132.9947.0018","код x2.0.2204-4132-9947-0018","карта x2.0.2204-4132-9947-0018","xx2.0.2204-4132-9947-0018","код x2.2222-2222-2222-2222","карта x2.2222-2222-2222-2222","xx2.2222-2222-2222-2222","код x2.2222 2222 2222 2222","карта x2.2222 2222 2222 2222","xx2.2222 2222 2222 2222","код x2.2222/2222/2222/2222","карта x2.2222/2222/2222/2222","xx2.2222/2222/2222/2222","код x2.1111.1111.1111.1111","карта x2.1111.1111.1111.1111","xx2.1111.1111.1111.1111","код x2.2204.4132.9947.0000.0000","карта x2.2204.4132.9947.0000.0000","xx2.2204.4132.9947.0000.0000","код x2.2204.4132.9947 1.2204.4132.9947","карта x2.2204.4132.9947 1.2204.4132.9947","xx2.2204.4132.9947 1.2204.4132.9947","код x2.2204.4132.9947 0000000000","карта x2.2204.4132.9947 0000000000","xx2.2204.4132.9947 0000000000","код x2.3005-0489-9258","карта x2.3005-0489-9258","xx2.3005-0489-9258","код x2.3005 0489 9258","карта x2.3005 0489 9258","xx2.3005 0489 9258","код x2.3005/0489/9258","карта x2.3005/0489/9258","xx2.3005/0489/9258","код x2.1000 2000 3000 4000 5000 6000","карта x2.1000 2000 3000 4000 5000 6000","xx2.1000 2000 3000 4000 5000 6000","код x2.2204.4132.9947 списка","карта x2.2204.4132.9947 списка","xx2.2204.4132.9947 списка","код x2.2204-4132-9947 список","карта x2.2204-4132-9947 список","xx2.2204-4132-9947 список","код x2.2.0000-0000-0000","карта x2.2.0000-0000-0000","xx2.2.0000-0000-0000","код x2.2.0000 0000 0000","карта x2.2.0000 0000 0000","xx2.2.0000 0000 0000","код x2.2.0000/0000/0000","карта x2.2.0000/0000/0000","xx2.2.0000/0000/0000","код x2.2.0000.0000.0000.0000","карта x2.2.0000.0000.0000.0000","xx2.2.0000.0000.0000.0000","код x2.0.0000-0000-0000","карта x2.0.0000-0000-0000","xx2.0.0000-0000-0000","код x2.0.0000 0000 0000","карта x2.0.0000 0000 0000","xx2.0.0000 0000 0000","код x2.0.0000/0000/0000","карта x2.0.0000/0000/0000","xx2.0.0000/0000/0000","код x2.0.0000.0000.0000.0000","карта x2.0.0000.0000.0000.0000","xx2.0.0000.0000.0000.0000","код x2-2204.4132.9947","карта x2-2204.4132.9947","xx2-2204.4132.9947","код x2-2204-4132-9947","карта x2-2204-4132-9947","xx2-2204-4132-9947","код x2-2204 4132 9947","карта x2-2204 4132 9947","xx2-2204 4132 9947","код x2-2204/4132/9947","карта x2-2204/4132/9947","xx2-2204/4132/9947","код x2-0000.0000.0000","карта x2-0000.0000.0000","xx2-0000.0000.0000","код x2-0000-0000-0000","карта x2-0000-0000-0000","xx2-0000-0000-0000","код x2-0000 0000 0000","карта x2-0000 0000 0000","xx2-0000 0000 0000","код x2-0000/0000/0000","карта x2-0000/0000/0000","xx2-0000/0000/0000","код x2-0000.0000.0000.0000","карта x2-0000.0000.0000.0000","xx2-0000.0000.0000.0000","код x2-0000-0000-0000-0000","карта x2-0000-0000-0000-0000","xx2-0000-0000-0000-0000","код x2-0000 0000 0000 0000","карта x2-0000 0000 0000 0000","xx2-0000 0000 0000 0000","код x2-0000/0000/0000/0000","карта x2-0000/0000/0000/0000","xx2-0000/0000/0000/0000","код x2-3005.0489.9258","карта x2-3005.0489.9258","xx2-3005.0489.9258","код x2-2204.4132.9947.0000","карта x2-2204.4132.9947.0000","xx2-2204.4132.9947.0000","код x2-2204-4132-9947-0000","карта x2-2204-4132-9947-0000","xx2-2204-4132-9947-0000","код x2-2204/4132/9947/0000","карта x2-2204/4132/9947/0000","xx2-2204/4132/9947/0000","код x2-2204 4132 9947 0000","карта x2-2204 4132 9947 0000","xx2-2204 4132 9947 0000","код x2-2204.4132.9947.0018","карта x2-2204.4132.9947.0018","xx2-2204.4132.9947.0018","код x2-2204-4132-9947-0018","карта x2-2204-4132-9947-0018","xx2-2204-4132-9947-0018","код x2-2204/4132/9947/0018","карта x2-2204/4132/9947/0018","xx2-2204/4132/9947/0018","код x2-0.2204.4132.9947","карта x2-0.2204.4132.9947","xx2-0.2204.4132.9947","код x2-0.0000.0000.0000","карта x2-0.0000.0000.0000","xx2-0.0000.0000.0000","код x2-2.2204.4132.9947","карта x2-2.2204.4132.9947","xx2-2.2204.4132.9947","код x2-1.2204.4132.9947","карта x2-1.2204.4132.9947","xx2-1.2204.4132.9947","код x2-2204.4132","карта x2-2204.4132","xx2-2204.4132","код x2-34567890123","карта x2-34567890123","xx2-34567890123","код x2-044525225","карта x2-044525225","xx2-044525225","код x2-220441329947","карта x2-220441329947","xx2-220441329947","код x2-300504899258","карта x2-300504899258","xx2-300504899258","код x2-0000000000","карта x2-0000000000","xx2-0000000000","код x2-000000000000","карта x2-000000000000","xx2-000000000000","код x2-2204.9947.4132.0000","карта x2-2204.9947.4132.0000","xx2-2204.9947.4132.0000","код x2-2222.2222.2222.2222","карта x2-2222.2222.2222.2222","xx2-2222.2222.2222.2222","код x2-2204.4132.9947 0000","карта x2-2204.4132.9947 0000","xx2-2204.4132.9947 0000","код x2-2204.4132.9947 0018","карта x2-2204.4132.9947 0018","xx2-2204.4132.9947 0018","код x2-2204-4132-9947 0000","карта x2-2204-4132-9947 0000","xx2-2204-4132-9947 0000","код x2-2204/4132/9947 0000","карта x2-2204/4132/9947 0000","xx2-2204/4132/9947 0000","код x2-24.82.01.43.38","карта x2-24.82.01.43.38","xx2-24.82.01.43.38","код x2-378/123/456/94","карта x2-378/123/456/94","xx2-378/123/456/94","код x2-774358.417509","карта x2-774358.417509","xx2-774358.417509","код x2-0.0.0000.0000.0000","карта x2-0.0.0000.0000.0000","xx2-0.0.0000.0000.0000","код x2-0.2.2204.4132.9947","карта x2-0.2.2204.4132.9947","xx2-0.2.2204.4132.9947","код x2-2.2.2204.4132.9947","карта x2-2.2.2204.4132.9947","xx2-2.2.2204.4132.9947","код x2-2.0.2204.4132.9947","карта x2-2.0.2204.4132.9947","xx2-2.0.2204.4132.9947","код x2-1.0.0000.0000.0000","карта x2-1.0.0000.0000.0000","xx2-1.0.0000.0000.0000","код x2-2.0000.0000.0000","карта x2-2.0000.0000.0000","xx2-2.0000.0000.0000","код x2-0.2204.4132.9947.0018","карта x2-0.2204.4132.9947.0018","xx2-0.2204.4132.9947.0018","код x2-0.2204-4132-9947-0018","карта x2-0.2204-4132-9947-0018","xx2-0.2204-4132-9947-0018","код x2-2222-2222-2222-2222","карта x2-2222-2222-2222-2222","xx2-2222-2222-2222-2222","код x2-2222 2222 2222 2222","карта x2-2222 2222 2222 2222","xx2-2222 2222 2222 2222","код x2-2222/2222/2222/2222","карта x2-2222/2222/2222/2222","xx2-2222/2222/2222/2222","код x2-1111.1111.1111.1111","карта x2-1111.1111.1111.1111","xx2-1111.1111.1111.1111","код x2-2204.4132.9947.0000.0000","карта x2-2204.4132.9947.0000.0000","xx2-2204.4132.9947.0000.0000","код x2-2204.4132.9947 1.2204.4132.9947","карта x2-2204.4132.9947 1.2204.4132.9947","xx2-2204.4132.9947 1.2204.4132.9947","код x2-2204.4132.9947 0000000000","карта x2-2204.4132.9947 0000000000","xx2-2204.4132.9947 0000000000","код x2-3005-0489-9258","карта x2-3005-0489-9258","xx2-3005-0489-9258","код x2-3005 0489 9258","карта x2-3005 0489 9258","xx2-3005 0489 9258","код x2-3005/0489/9258","карта x2-3005/0489/9258","xx2-3005/0489/9258","код x2-1000 2000 3000 4000 5000 6000","карта x2-1000 2000 3000 4000 5000 6000","xx2-1000 2000 3000 4000 5000 6000","код x2-2204.4132.9947 списка","карта x2-2204.4132.9947 списка","xx2-2204.4132.9947 списка","код x2-2204-4132-9947 список","карта x2-2204-4132-9947 список","xx2-2204-4132-9947 список","код x2-2.0000-0000-0000","карта x2-2.0000-0000-0000","xx2-2.0000-0000-0000","код x2-2.0000 0000 0000","карта x2-2.0000 0000 0000","xx2-2.0000 0000 0000","код x2-2.0000/0000/0000","карта x2-2.0000/0000/0000","xx2-2.0000/0000/0000","код x2-2.0000.0000.0000.0000","карта x2-2.0000.0000.0000.0000","xx2-2.0000.0000.0000.0000","код x2-0.0000-0000-0000","карта x2-0.0000-0000-0000","xx2-0.0000-0000-0000","код x2-0.0000 0000 0000","карта x2-0.0000 0000 0000","xx2-0.0000 0000 0000","код x2-0.0000/0000/0000","карта x2-0.0000/0000/0000","xx2-0.0000/0000/0000","код x2-0.0000.0000.0000.0000","карта x2-0.0000.0000.0000.0000","xx2-0.0000.0000.0000.0000","код x2/2204.4132.9947","карта x2/2204.4132.9947","xx2/2204.4132.9947","код x2/2204-4132-9947","карта x2/2204-4132-9947","xx2/2204-4132-9947","код x2/2204 4132 9947","карта x2/2204 4132 9947","xx2/2204 4132 9947","код x2/2204/4132/9947","карта x2/2204/4132/9947","xx2/2204/4132/9947","код x2/0000.0000.0000","карта x2/0000.0000.0000","xx2/0000.0000.0000","код x2/0000-0000-0000","карта x2/0000-0000-0000","xx2/0000-0000-0000","код x2/0000 0000 0000","карта x2/0000 0000 0000","xx2/0000 0000 0000","код x2/0000/0000/0000","карта x2/0000/0000/0000","xx2/0000/0000/0000","код x2/0000.0000.0000.0000","карта x2/0000.0000.0000.0000","xx2/0000.0000.0000.0000","код x2/0000-0000-0000-0000","карта x2/0000-0000-0000-0000","xx2/0000-0000-0000-0000","код x2/0000 0000 0000 0000","карта x2/0000 0000 0000 0000","xx2/0000 0000 0000 0000","код x2/0000/0000/0000/0000","карта x2/0000/0000/0000/0000","xx2/0000/0000/0000/0000","код x2/3005.0489.9258","карта x2/3005.0489.9258","xx2/3005.0489.9258","код x2/2204.4132.9947.0000","карта x2/2204.4132.9947.0000","xx2/2204.4132.9947.0000","код x2/2204-4132-9947-0000","карта x2/2204-4132-9947-0000","xx2/2204-4132-9947-0000","код x2/2204/4132/9947/0000","карта x2/2204/4132/9947/0000","xx2/2204/4132/9947/0000","код x2/2204 4132 9947 0000","карта x2/2204 4132 9947 0000","xx2/2204 4132 9947 0000","код x2/2204.4132.9947.0018","карта x2/2204.4132.9947.0018","xx2/2204.4132.9947.0018","код x2/2204-4132-9947-0018","карта x2/2204-4132-9947-0018","xx2/2204-4132-9947-0018","код x2/2204/4132/9947/0018","карта x2/2204/4132/9947/0018","xx2/2204/4132/9947/0018","код x2/0.2204.4132.9947","карта x2/0.2204.4132.9947","xx2/0.2204.4132.9947","код x2/0.0000.0000.0000","карта x2/0.0000.0000.0000","xx2/0.0000.0000.0000","код x2/2.2204.4132.9947","карта x2/2.2204.4132.9947","xx2/2.2204.4132.9947","код x2/1.2204.4132.9947","карта x2/1.2204.4132.9947","xx2/1.2204.4132.9947","код x2/2204.4132","карта x2/2204.4132","xx2/2204.4132","код x2/34567890123","карта x2/34567890123","xx2/34567890123","код x2/044525225","карта x2/044525225","xx2/044525225","код x2/220441329947","карта x2/220441329947","xx2/220441329947","код x2/300504899258","карта x2/300504899258","xx2/300504899258","код x2/0000000000","карта x2/0000000000","xx2/0000000000","код x2/000000000000","карта x2/000000000000","xx2/000000000000","код x2/2204.9947.4132.0000","карта x2/2204.9947.4132.0000","xx2/2204.9947.4132.0000","код x2/2222.2222.2222.2222","карта x2/2222.2222.2222.2222","xx2/2222.2222.2222.2222","код x2/2204.4132.9947 0000","карта x2/2204.4132.9947 0000","xx2/2204.4132.9947 0000","код x2/2204.4132.9947 0018","карта x2/2204.4132.9947 0018","xx2/2204.4132.9947 0018","код x2/2204-4132-9947 0000","карта x2/2204-4132-9947 0000","xx2/2204-4132-9947 0000","код x2/2204/4132/9947 0000","карта x2/2204/4132/9947 0000","xx2/2204/4132/9947 0000","код x2/24.82.01.43.38","карта x2/24.82.01.43.38","xx2/24.82.01.43.38","код x2/378/123/456/94","карта x2/378/123/456/94","xx2/378/123/456/94","код x2/774358.417509","карта x2/774358.417509","xx2/774358.417509","код x2/0.0.0000.0000.0000","карта x2/0.0.0000.0000.0000","xx2/0.0.0000.0000.0000","код x2/0.2.2204.4132.9947","карта x2/0.2.2204.4132.9947","xx2/0.2.2204.4132.9947","код x2/2.2.2204.4132.9947","карта x2/2.2.2204.4132.9947","xx2/2.2.2204.4132.9947","код x2/2.0.2204.4132.9947","карта x2/2.0.2204.4132.9947","xx2/2.0.2204.4132.9947","код x2/1.0.0000.0000.0000","карта x2/1.0.0000.0000.0000","xx2/1.0.0000.0000.0000","код x2/2.0000.0000.0000","карта x2/2.0000.0000.0000","xx2/2.0000.0000.0000","код x2/0.2204.4132.9947.0018","карта x2/0.2204.4132.9947.0018","xx2/0.2204.4132.9947.0018","код x2/0.2204-4132-9947-0018","карта x2/0.2204-4132-9947-0018","xx2/0.2204-4132-9947-0018","код x2/2222-2222-2222-2222","карта x2/2222-2222-2222-2222","xx2/2222-2222-2222-2222","код x2/2222 2222 2222 2222","карта x2/2222 2222 2222 2222","xx2/2222 2222 2222 2222","код x2/2222/2222/2222/2222","карта x2/2222/2222/2222/2222","xx2/2222/2222/2222/2222","код x2/1111.1111.1111.1111","карта x2/1111.1111.1111.1111","xx2/1111.1111.1111.1111","код x2/2204.4132.9947.0000.0000","карта x2/2204.4132.9947.0000.0000","xx2/2204.4132.9947.0000.0000","код x2/2204.4132.9947 1.2204.4132.9947","карта x2/2204.4132.9947 1.2204.4132.9947","xx2/2204.4132.9947 1.2204.4132.9947","код x2/2204.4132.9947 0000000000","карта x2/2204.4132.9947 0000000000","xx2/2204.4132.9947 0000000000","код x2/3005-0489-9258","карта x2/3005-0489-9258","xx2/3005-0489-9258","код x2/3005 0489 9258","карта x2/3005 0489 9258","xx2/3005 0489 9258","код x2/3005/0489/9258","карта x2/3005/0489/9258","xx2/3005/0489/9258","код x2/1000 2000 3000 4000 5000 6000","карта x2/1000 2000 3000 4000 5000 6000","xx2/1000 2000 3000 4000 5000 6000","код x2/2204.4132.9947 списка","карта x2/2204.4132.9947 списка","xx2/2204.4132.9947 списка","код x2/2204-4132-9947 список","карта x2/2204-4132-9947 список","xx2/2204-4132-9947 список","код x2/2.0000-0000-0000","карта x2/2.0000-0000-0000","xx2/2.0000-0000-0000","код x2/2.0000 0000 0000","карта x2/2.0000 0000 0000","xx2/2.0000 0000 0000","код x2/2.0000/0000/0000","карта x2/2.0000/0000/0000","xx2/2.0000/0000/0000","код x2/2.0000.0000.0000.0000","карта x2/2.0000.0000.0000.0000","xx2/2.0000.0000.0000.0000","код x2/0.0000-0000-0000","карта x2/0.0000-0000-0000","xx2/0.0000-0000-0000","код x2/0.0000 0000 0000","карта x2/0.0000 0000 0000","xx2/0.0000 0000 0000","код x2/0.0000/0000/0000","карта x2/0.0000/0000/0000","xx2/0.0000/0000/0000","код x2/0.0000.0000.0000.0000","карта x2/0.0000.0000.0000.0000","xx2/0.0000.0000.0000.0000","код x2 2204.4132.9947","карта x2 2204.4132.9947","xx2 2204.4132.9947","код x2 2204-4132-9947","карта x2 2204-4132-9947","xx2 2204-4132-9947","код x2 2204 4132 9947","карта x2 2204 4132 9947","xx2 2204 4132 9947","код x2 2204/4132/9947","карта x2 2204/4132/9947","xx2 2204/4132/9947","код x2 0000.0000.0000","карта x2 0000.0000.0000","xx2 0000.0000.0000","код x2 0000-0000-0000","карта x2 0000-0000-0000","xx2 0000-0000-0000","код x2 0000 0000 0000","карта x2 0000 0000 0000","xx2 0000 0000 0000","код x2 0000/0000/0000","карта x2 0000/0000/0000","xx2 0000/0000/0000","код x2 0000.0000.0000.0000","карта x2 0000.0000.0000.0000","xx2 0000.0000.0000.0000","код x2 0000-0000-0000-0000","карта x2 0000-0000-0000-0000","xx2 0000-0000-0000-0000","код x2 0000 0000 0000 0000","карта x2 0000 0000 0000 0000","xx2 0000 0000 0000 0000","код x2 0000/0000/0000/0000","карта x2 0000/0000/0000/0000","xx2 0000/0000/0000/0000","код x2 3005.0489.9258","карта x2 3005.0489.9258","xx2 3005.0489.9258","код x2 2204.4132.9947.0000","карта x2 2204.4132.9947.0000","xx2 2204.4132.9947.0000","код x2 2204-4132-9947-0000","карта x2 2204-4132-9947-0000","xx2 2204-4132-9947-0000","код x2 2204/4132/9947/0000","карта x2 2204/4132/9947/0000","xx2 2204/4132/9947/0000","код x2 2204 4132 9947 0000","карта x2 2204 4132 9947 0000","xx2 2204 4132 9947 0000","код x2 2204.4132.9947.0018","карта x2 2204.4132.9947.0018","xx2 2204.4132.9947.0018","код x2 2204-4132-9947-0018","карта x2 2204-4132-9947-0018","xx2 2204-4132-9947-0018","код x2 2204/4132/9947/0018","карта x2 2204/4132/9947/0018","xx2 2204/4132/9947/0018","код x2 0.2204.4132.9947","карта x2 0.2204.4132.9947","xx2 0.2204.4132.9947","код x2 0.0000.0000.0000","карта x2 0.0000.0000.0000","xx2 0.0000.0000.0000","код x2 2.2204.4132.9947","карта x2 2.2204.4132.9947","xx2 2.2204.4132.9947","код x2 1.2204.4132.9947","карта x2 1.2204.4132.9947","xx2 1.2204.4132.9947","код x2 2204.4132","карта x2 2204.4132","xx2 2204.4132","код x2 34567890123","карта x2 34567890123","xx2 34567890123","код x2 044525225","карта x2 044525225","xx2 044525225","код x2 220441329947","карта x2 220441329947","xx2 220441329947","код x2 300504899258","карта x2 300504899258","xx2 300504899258","код x2 0000000000","карта x2 0000000000","xx2 0000000000","код x2 000000000000","карта x2 000000000000","xx2 000000000000","код x2 2204.9947.4132.0000","карта x2 2204.9947.4132.0000","xx2 2204.9947.4132.0000","код x2 2222.2222.2222.2222","карта x2 2222.2222.2222.2222","xx2 2222.2222.2222.2222","код x2 2204.4132.9947 0000","карта x2 2204.4132.9947 0000","xx2 2204.4132.9947 0000","код x2 2204.4132.9947 0018","карта x2 2204.4132.9947 0018","xx2 2204.4132.9947 0018","код x2 2204-4132-9947 0000","карта x2 2204-4132-9947 0000","xx2 2204-4132-9947 0000","код x2 2204/4132/9947 0000","карта x2 2204/4132/9947 0000","xx2 2204/4132/9947 0000","код x2 24.82.01.43.38","карта x2 24.82.01.43.38","xx2 24.82.01.43.38","код x2 378/123/456/94","карта x2 378/123/456/94","xx2 378/123/456/94","код x2 774358.417509","карта x2 774358.417509","xx2 774358.417509","код x2 0.0.0000.0000.0000","карта x2 0.0.0000.0000.0000","xx2 0.0.0000.0000.0000","код x2 0.2.2204.4132.9947","карта x2 0.2.2204.4132.9947","xx2 0.2.2204.4132.9947","код x2 2.2.2204.4132.9947","карта x2 2.2.2204.4132.9947","xx2 2.2.2204.4132.9947","код x2 2.0.2204.4132.9947","карта x2 2.0.2204.4132.9947","xx2 2.0.2204.4132.9947","код x2 1.0.0000.0000.0000","карта x2 1.0.0000.0000.0000","xx2 1.0.0000.0000.0000","код x2 2.0000.0000.0000","карта x2 2.0000.0000.0000","xx2 2.0000.0000.0000","код x2 0.2204.4132.9947.0018","карта x2 0.2204.4132.9947.0018","xx2 0.2204.4132.9947.0018","код x2 0.2204-4132-9947-0018","карта x2 0.2204-4132-9947-0018","xx2 0.2204-4132-9947-0018","код x2 2222-2222-2222-2222","карта x2 2222-2222-2222-2222","xx2 2222-2222-2222-2222","код x2 2222 2222 2222 2222","карта x2 2222 2222 2222 2222","xx2 2222 2222 2222 2222","код x2 2222/2222/2222/2222","карта x2 2222/2222/2222/2222","xx2 2222/2222/2222/2222","код x2 1111.1111.1111.1111","карта x2 1111.1111.1111.1111","xx2 1111.1111.1111.1111","код x2 2204.4132.9947.0000.0000","карта x2 2204.4132.9947.0000.0000","xx2 2204.4132.9947.0000.0000","код x2 2204.4132.9947 1.2204.4132.9947","карта x2 2204.4132.9947 1.2204.4132.9947","xx2 2204.4132.9947 1.2204.4132.9947","код x2 2204.4132.9947 0000000000","карта x2 2204.4132.9947 0000000000","xx2 2204.4132.9947 0000000000","код x2 3005-0489-9258","карта x2 3005-0489-9258","xx2 3005-0489-9258","код x2 3005 0489 9258","карта x2 3005 0489 9258","xx2 3005 0489 9258","код x2 3005/0489/9258","карта x2 3005/0489/9258","xx2 3005/0489/9258","код x2 1000 2000 3000 4000 5000 6000","карта x2 1000 2000 3000 4000 5000 6000","xx2 1000 2000 3000 4000 5000 6000","код x2 2204.4132.9947 списка","карта x2 2204.4132.9947 списка","xx2 2204.4132.9947 списка","код x2 2204-4132-9947 список","карта x2 2204-4132-9947 список","xx2 2204-4132-9947 список","код x2 2.0000-0000-0000","карта x2 2.0000-0000-0000","xx2 2.0000-0000-0000","код x2 2.0000 0000 0000","карта x2 2.0000 0000 0000","xx2 2.0000 0000 0000","код x2 2.0000/0000/0000","карта x2 2.0000/0000/0000","xx2 2.0000/0000/0000","код x2 2.0000.0000.0000.0000","карта x2 2.0000.0000.0000.0000","xx2 2.0000.0000.0000.0000","код x2 0.0000-0000-0000","карта x2 0.0000-0000-0000","xx2 0.0000-0000-0000","код x2 0.0000 0000 0000","карта x2 0.0000 0000 0000","xx2 0.0000 0000 0000","код x2 0.0000/0000/0000","карта x2 0.0000/0000/0000","xx2 0.0000/0000/0000","код x2 0.0000.0000.0000.0000","карта x2 0.0000.0000.0000.0000","xx2 0.0000.0000.0000.0000","код 1.2204.4132.9947","1.2204.4132.9947","карта 1.2204.4132.9947","x1.2204.4132.9947","код 1.2204-4132-9947","1.2204-4132-9947","карта 1.2204-4132-9947","x1.2204-4132-9947","код 1.2204 4132 9947","1.2204 4132 9947","карта 1.2204 4132 9947","x1.2204 4132 9947","код 1.2204/4132/9947","1.2204/4132/9947","карта 1.2204/4132/9947","x1.2204/4132/9947","код 1.0000.0000.0000","1.0000.0000.0000","карта 1.0000.0000.0000","x1.0000.0000.0000","код 1.0000-0000-0000","1.0000-0000-0000","карта 1.0000-0000-0000","x1.0000-0000-0000","код 1.0000 0000 0000","1.0000 0000 0000","карта 1.0000 0000 0000","x1.0000 0000 0000","код 1.0000/0000/0000","1.0000/0000/0000","карта 1.0000/0000/0000","x1.0000/0000/0000","код 1.0000.0000.0000.0000","1.0000.0000.0000.0000","карта 1.0000.0000.0000.0000","x1.0000.0000.0000.0000","код 1.0000-0000-0000-0000","1.0000-0000-0000-0000","карта 1.0000-0000-0000-0000","x1.0000-0000-0000-0000","код 1.0000 0000 0000 0000","1.0000 0000 0000 0000","карта 1.0000 0000 0000 0000","x1.0000 0000 0000 0000","код 1.0000/0000/0000/0000","1.0000/0000/0000/0000","карта 1.0000/0000/0000/0000","x1.0000/0000/0000/0000","код 1.3005.0489.9258","1.3005.0489.9258","карта 1.3005.0489.9258","x1.3005.0489.9258","код 1.2204.4132.9947.0000","1.2204.4132.9947.0000","карта 1.2204.4132.9947.0000","x1.2204.4132.9947.0000","код 1.2204-4132-9947-0000","1.2204-4132-9947-0000","карта 1.2204-4132-9947-0000","x1.2204-4132-9947-0000","код 1.2204/4132/9947/0000","1.2204/4132/9947/0000","карта 1.2204/4132/9947/0000","x1.2204/4132/9947/0000","код 1.2204 4132 9947 0000","1.2204 4132 9947 0000","карта 1.2204 4132 9947 0000","x1.2204 4132 9947 0000","код 1.2204.4132.9947.0018","1.2204.4132.9947.0018","карта 1.2204.4132.9947.0018","x1.2204.4132.9947.0018","код 1.2204-4132-9947-0018","1.2204-4132-9947-0018","карта 1.2204-4132-9947-0018","x1.2204-4132-9947-0018","код 1.2204/4132/9947/0018","1.2204/4132/9947/0018","карта 1.2204/4132/9947/0018","x1.2204/4132/9947/0018","код 1.0.2204.4132.9947","1.0.2204.4132.9947","карта 1.0.2204.4132.9947","x1.0.2204.4132.9947","код 1.0.0000.0000.0000","1.0.0000.0000.0000","карта 1.0.0000.0000.0000","x1.0.0000.0000.0000","код 1.2.2204.4132.9947","1.2.2204.4132.9947","карта 1.2.2204.4132.9947","x1.2.2204.4132.9947","код 1.1.2204.4132.9947","1.1.2204.4132.9947","карта 1.1.2204.4132.9947","x1.1.2204.4132.9947","код 1.2204.4132","1.2204.4132","карта 1.2204.4132","x1.2204.4132","код 1.34567890123","1.34567890123","карта 1.34567890123","x1.34567890123","код 1.044525225","1.044525225","карта 1.044525225","x1.044525225","код 1.220441329947","1.220441329947","карта 1.220441329947","x1.220441329947","код 1.300504899258","1.300504899258","карта 1.300504899258","x1.300504899258","код 1.0000000000","1.0000000000","карта 1.0000000000","x1.0000000000","код 1.000000000000","1.000000000000","карта 1.000000000000","x1.000000000000","код 1.2204.9947.4132.0000","1.2204.9947.4132.0000","карта 1.2204.9947.4132.0000","x1.2204.9947.4132.0000","код 1.2222.2222.2222.2222","1.2222.2222.2222.2222","карта 1.2222.2222.2222.2222","x1.2222.2222.2222.2222","код 1.2204.4132.9947 0000","1.2204.4132.9947 0000","карта 1.2204.4132.9947 0000","x1.2204.4132.9947 0000","код 1.2204.4132.9947 0018","1.2204.4132.9947 0018","карта 1.2204.4132.9947 0018","x1.2204.4132.9947 0018","код 1.2204-4132-9947 0000","1.2204-4132-9947 0000","карта 1.2204-4132-9947 0000","x1.2204-4132-9947 0000","код 1.2204/4132/9947 0000","1.2204/4132/9947 0000","карта 1.2204/4132/9947 0000","x1.2204/4132/9947 0000","код 1.24.82.01.43.38","1.24.82.01.43.38","карта 1.24.82.01.43.38","x1.24.82.01.43.38","код 1.378/123/456/94","1.378/123/456/94","карта 1.378/123/456/94","x1.378/123/456/94","код 1.774358.417509","1.774358.417509","карта 1.774358.417509","x1.774358.417509","код 1.0.0.0000.0000.0000","1.0.0.0000.0000.0000","карта 1.0.0.0000.0000.0000","x1.0.0.0000.0000.0000","код 1.0.2.2204.4132.9947","1.0.2.2204.4132.9947","карта 1.0.2.2204.4132.9947","x1.0.2.2204.4132.9947","код 1.2.2.2204.4132.9947","1.2.2.2204.4132.9947","карта 1.2.2.2204.4132.9947","x1.2.2.2204.4132.9947","код 1.2.0.2204.4132.9947","1.2.0.2204.4132.9947","карта 1.2.0.2204.4132.9947","x1.2.0.2204.4132.9947","код 1.1.0.0000.0000.0000","1.1.0.0000.0000.0000","карта 1.1.0.0000.0000.0000","x1.1.0.0000.0000.0000","код 1.2.0000.0000.0000","1.2.0000.0000.0000","карта 1.2.0000.0000.0000","x1.2.0000.0000.0000","код 1.0.2204.4132.9947.0018","1.0.2204.4132.9947.0018","карта 1.0.2204.4132.9947.0018","x1.0.2204.4132.9947.0018","код 1.0.2204-4132-9947-0018","1.0.2204-4132-9947-0018","карта 1.0.2204-4132-9947-0018","x1.0.2204-4132-9947-0018","код 1.2222-2222-2222-2222","1.2222-2222-2222-2222","карта 1.2222-2222-2222-2222","x1.2222-2222-2222-2222","код 1.2222 2222 2222 2222","1.2222 2222 2222 2222","карта 1.2222 2222 2222 2222","x1.2222 2222 2222 2222","код 1.2222/2222/2222/2222","1.2222/2222/2222/2222","карта 1.2222/2222/2222/2222","x1.2222/2222/2222/2222","код 1.1111.1111.1111.1111","1.1111.1111.1111.1111","карта 1.1111.1111.1111.1111","x1.1111.1111.1111.1111","код 1.2204.4132.9947.0000.0000","1.2204.4132.9947.0000.0000","карта 1.2204.4132.9947.0000.0000","x1.2204.4132.9947.0000.0000","код 1.2204.4132.9947 1.2204.4132.9947","1.2204.4132.9947 1.2204.4132.9947","карта 1.2204.4132.9947 1.2204.4132.9947","x1.2204.4132.9947 1.2204.4132.9947","код 1.2204.4132.9947 0000000000","1.2204.4132.9947 0000000000","карта 1.2204.4132.9947 0000000000","x1.2204.4132.9947 0000000000","код 1.3005-0489-9258","1.3005-0489-9258","карта 1.3005-0489-9258","x1.3005-0489-9258","код 1.3005 0489 9258","1.3005 0489 9258","карта 1.3005 0489 9258","x1.3005 0489 9258","код 1.3005/0489/9258","1.3005/0489/9258","карта 1.3005/0489/9258","x1.3005/0489/9258","код 1.1000 2000 3000 4000 5000 6000","1.1000 2000 3000 4000 5000 6000","карта 1.1000 2000 3000 4000 5000 6000","x1.1000 2000 3000 4000 5000 6000","код 1.2204.4132.9947 списка","1.2204.4132.9947 списка","карта 1.2204.4132.9947 списка","x1.2204.4132.9947 списка","код 1.2204-4132-9947 список","1.2204-4132-9947 список","карта 1.2204-4132-9947 список","x1.2204-4132-9947 список","код 1.2.0000-0000-0000","1.2.0000-0000-0000","карта 1.2.0000-0000-0000","x1.2.0000-0000-0000","код 1.2.0000 0000 0000","1.2.0000 0000 0000","карта 1.2.0000 0000 0000","x1.2.0000 0000 0000","код 1.2.0000/0000/0000","1.2.0000/0000/0000","карта 1.2.0000/0000/0000","x1.2.0000/0000/0000","код 1.2.0000.0000.0000.0000","1.2.0000.0000.0000.0000","карта 1.2.0000.0000.0000.0000","x1.2.0000.0000.0000.0000","код 1.0.0000-0000-0000","1.0.0000-0000-0000","карта 1.0.0000-0000-0000","x1.0.0000-0000-0000","код 1.0.0000 0000 0000","1.0.0000 0000 0000","карта 1.0.0000 0000 0000","x1.0.0000 0000 0000","код 1.0.0000/0000/0000","1.0.0000/0000/0000","карта 1.0.0000/0000/0000","x1.0.0000/0000/0000","код 1.0.0000.0000.0000.0000","1.0.0000.0000.0000.0000","карта 1.0.0000.0000.0000.0000","x1.0.0000.0000.0000.0000","код 1-2204.4132.9947","1-2204.4132.9947","карта 1-2204.4132.9947","x1-2204.4132.9947","код 1-2204-4132-9947","1-2204-4132-9947","карта 1-2204-4132-9947","x1-2204-4132-9947","код 1-2204 4132 9947","1-2204 4132 9947","карта 1-2204 4132 9947","x1-2204 4132 9947","код 1-2204/4132/9947","1-2204/4132/9947","карта 1-2204/4132/9947","x1-2204/4132/9947","код 1-0000.0000.0000","1-0000.0000.0000","карта 1-0000.0000.0000","x1-0000.0000.0000","код 1-0000-0000-0000","1-0000-0000-0000","карта 1-0000-0000-0000","x1-0000-0000-0000","код 1-0000 0000 0000","1-0000 0000 0000","карта 1-0000 0000 0000","x1-0000 0000 0000","код 1-0000/0000/0000","1-0000/0000/0000","карта 1-0000/0000/0000","x1-0000/0000/0000","код 1-0000.0000.0000.0000","1-0000.0000.0000.0000","карта 1-0000.0000.0000.0000","x1-0000.0000.0000.0000","код 1-0000-0000-0000-0000","1-0000-0000-0000-0000","карта 1-0000-0000-0000-0000","x1-0000-0000-0000-0000","код 1-0000 0000 0000 0000","1-0000 0000 0000 0000","карта 1-0000 0000 0000 0000","x1-0000 0000 0000 0000","код 1-0000/0000/0000/0000","1-0000/0000/0000/0000","карта 1-0000/0000/0000/0000","x1-0000/0000/0000/0000","код 1-3005.0489.9258","1-3005.0489.9258","карта 1-3005.0489.9258","x1-3005.0489.9258","код 1-2204.4132.9947.0000","1-2204.4132.9947.0000","карта 1-2204.4132.9947.0000","x1-2204.4132.9947.0000","код 1-2204-4132-9947-0000","1-2204-4132-9947-0000","карта 1-2204-4132-9947-0000","x1-2204-4132-9947-0000","код 1-2204/4132/9947/0000","1-2204/4132/9947/0000","карта 1-2204/4132/9947/0000","x1-2204/4132/9947/0000","код 1-2204 4132 9947 0000","1-2204 4132 9947 0000","карта 1-2204 4132 9947 0000","x1-2204 4132 9947 0000","код 1-2204.4132.9947.0018","1-2204.4132.9947.0018","карта 1-2204.4132.9947.0018","x1-2204.4132.9947.0018","код 1-2204-4132-9947-0018","1-2204-4132-9947-0018","карта 1-2204-4132-9947-0018","x1-2204-4132-9947-0018","код 1-2204/4132/9947/0018","1-2204/4132/9947/0018","карта 1-2204/4132/9947/0018","x1-2204/4132/9947/0018","код 1-0.2204.4132.9947","1-0.2204.4132.9947","карта 1-0.2204.4132.9947","x1-0.2204.4132.9947","код 1-0.0000.0000.0000","1-0.0000.0000.0000","карта 1-0.0000.0000.0000","x1-0.0000.0000.0000","код 1-2.2204.4132.9947","1-2.2204.4132.9947","карта 1-2.2204.4132.9947","x1-2.2204.4132.9947","код 1-1.2204.4132.9947","1-1.2204.4132.9947","карта 1-1.2204.4132.9947","x1-1.2204.4132.9947","код 1-2204.4132","1-2204.4132","карта 1-2204.4132","x1-2204.4132","код 1-34567890123","1-34567890123","карта 1-34567890123","x1-34567890123","код 1-044525225","1-044525225","карта 1-044525225","x1-044525225","код 1-220441329947","1-220441329947","карта 1-220441329947","x1-220441329947","код 1-300504899258","1-300504899258","карта 1-300504899258","x1-300504899258","код 1-0000000000","1-0000000000","карта 1-0000000000","x1-0000000000","код 1-000000000000","1-000000000000","карта 1-000000000000","x1-000000000000","код 1-2204.9947.4132.0000","1-2204.9947.4132.0000","карта 1-2204.9947.4132.0000","x1-2204.9947.4132.0000","код 1-2222.2222.2222.2222","1-2222.2222.2222.2222","карта 1-2222.2222.2222.2222","x1-2222.2222.2222.2222","код 1-2204.4132.9947 0000","1-2204.4132.9947 0000","карта 1-2204.4132.9947 0000","x1-2204.4132.9947 0000","код 1-2204.4132.9947 0018","1-2204.4132.9947 0018","карта 1-2204.4132.9947 0018","x1-2204.4132.9947 0018","код 1-2204-4132-9947 0000","1-2204-4132-9947 0000","карта 1-2204-4132-9947 0000","x1-2204-4132-9947 0000","код 1-2204/4132/9947 0000","1-2204/4132/9947 0000","карта 1-2204/4132/9947 0000","x1-2204/4132/9947 0000","код 1-24.82.01.43.38","1-24.82.01.43.38","карта 1-24.82.01.43.38","x1-24.82.01.43.38","код 1-378/123/456/94","1-378/123/456/94","карта 1-378/123/456/94","x1-378/123/456/94","код 1-774358.417509","1-774358.417509","карта 1-774358.417509","x1-774358.417509","код 1-0.0.0000.0000.0000","1-0.0.0000.0000.0000","карта 1-0.0.0000.0000.0000","x1-0.0.0000.0000.0000","код 1-0.2.2204.4132.9947","1-0.2.2204.4132.9947","карта 1-0.2.2204.4132.9947","x1-0.2.2204.4132.9947","код 1-2.2.2204.4132.9947","1-2.2.2204.4132.9947","карта 1-2.2.2204.4132.9947","x1-2.2.2204.4132.9947","код 1-2.0.2204.4132.9947","1-2.0.2204.4132.9947","карта 1-2.0.2204.4132.9947","x1-2.0.2204.4132.9947","код 1-1.0.0000.0000.0000","1-1.0.0000.0000.0000","карта 1-1.0.0000.0000.0000","x1-1.0.0000.0000.0000","код 1-2.0000.0000.0000","1-2.0000.0000.0000","карта 1-2.0000.0000.0000","x1-2.0000.0000.0000","код 1-0.2204.4132.9947.0018","1-0.2204.4132.9947.0018","карта 1-0.2204.4132.9947.0018","x1-0.2204.4132.9947.0018","код 1-0.2204-4132-9947-0018","1-0.2204-4132-9947-0018","карта 1-0.2204-4132-9947-0018","x1-0.2204-4132-9947-0018","код 1-2222-2222-2222-2222","1-2222-2222-2222-2222","карта 1-2222-2222-2222-2222","x1-2222-2222-2222-2222","код 1-2222 2222 2222 2222","1-2222 2222 2222 2222","карта 1-2222 2222 2222 2222","x1-2222 2222 2222 2222","код 1-2222/2222/2222/2222","1-2222/2222/2222/2222","карта 1-2222/2222/2222/2222","x1-2222/2222/2222/2222","код 1-1111.1111.1111.1111","1-1111.1111.1111.1111","карта 1-1111.1111.1111.1111","x1-1111.1111.1111.1111","код 1-2204.4132.9947.0000.0000","1-2204.4132.9947.0000.0000","карта 1-2204.4132.9947.0000.0000","x1-2204.4132.9947.0000.0000","код 1-2204.4132.9947 1.2204.4132.9947","1-2204.4132.9947 1.2204.4132.9947","карта 1-2204.4132.9947 1.2204.4132.9947","x1-2204.4132.9947 1.2204.4132.9947","код 1-2204.4132.9947 0000000000","1-2204.4132.9947 0000000000","карта 1-2204.4132.9947 0000000000","x1-2204.4132.9947 0000000000","код 1-3005-0489-9258","1-3005-0489-9258","карта 1-3005-0489-9258","x1-3005-0489-9258","код 1-3005 0489 9258","1-3005 0489 9258","карта 1-3005 0489 9258","x1-3005 0489 9258","код 1-3005/0489/9258","1-3005/0489/9258","карта 1-3005/0489/9258","x1-3005/0489/9258","код 1-1000 2000 3000 4000 5000 6000","1-1000 2000 3000 4000 5000 6000","карта 1-1000 2000 3000 4000 5000 6000","x1-1000 2000 3000 4000 5000 6000","код 1-2204.4132.9947 списка","1-2204.4132.9947 списка","карта 1-2204.4132.9947 списка","x1-2204.4132.9947 списка","код 1-2204-4132-9947 список","1-2204-4132-9947 список","карта 1-2204-4132-9947 список","x1-2204-4132-9947 список","код 1-2.0000-0000-0000","1-2.0000-0000-0000","карта 1-2.0000-0000-0000","x1-2.0000-0000-0000","код 1-2.0000 0000 0000","1-2.0000 0000 0000","карта 1-2.0000 0000 0000","x1-2.0000 0000 0000","код 1-2.0000/0000/0000","1-2.0000/0000/0000","карта 1-2.0000/0000/0000","x1-2.0000/0000/0000","код 1-2.0000.0000.0000.0000","1-2.0000.0000.0000.0000","карта 1-2.0000.0000.0000.0000","x1-2.0000.0000.0000.0000","код 1-0.0000-0000-0000","1-0.0000-0000-0000","карта 1-0.0000-0000-0000","x1-0.0000-0000-0000","код 1-0.0000 0000 0000","1-0.0000 0000 0000","карта 1-0.0000 0000 0000","x1-0.0000 0000 0000","код 1-0.0000/0000/0000","1-0.0000/0000/0000","карта 1-0.0000/0000/0000","x1-0.0000/0000/0000","код 1-0.0000.0000.0000.0000","1-0.0000.0000.0000.0000","карта 1-0.0000.0000.0000.0000","x1-0.0000.0000.0000.0000","код 1/2204.4132.9947","1/2204.4132.9947","карта 1/2204.4132.9947","x1/2204.4132.9947","код 1/2204-4132-9947","1/2204-4132-9947","карта 1/2204-4132-9947","x1/2204-4132-9947","код 1/2204 4132 9947","1/2204 4132 9947","карта 1/2204 4132 9947","x1/2204 4132 9947","код 1/2204/4132/9947","1/2204/4132/9947","карта 1/2204/4132/9947","x1/2204/4132/9947","код 1/0000.0000.0000","1/0000.0000.0000","карта 1/0000.0000.0000","x1/0000.0000.0000","код 1/0000-0000-0000","1/0000-0000-0000","карта 1/0000-0000-0000","x1/0000-0000-0000","код 1/0000 0000 0000","1/0000 0000 0000","карта 1/0000 0000 0000","x1/0000 0000 0000","код 1/0000/0000/0000","1/0000/0000/0000","карта 1/0000/0000/0000","x1/0000/0000/0000","код 1/0000.0000.0000.0000","1/0000.0000.0000.0000","карта 1/0000.0000.0000.0000","x1/0000.0000.0000.0000","код 1/0000-0000-0000-0000","1/0000-0000-0000-0000","карта 1/0000-0000-0000-0000","x1/0000-0000-0000-0000","код 1/0000 0000 0000 0000","1/0000 0000 0000 0000","карта 1/0000 0000 0000 0000","x1/0000 0000 0000 0000","код 1/0000/0000/0000/0000","1/0000/0000/0000/0000","карта 1/0000/0000/0000/0000","x1/0000/0000/0000/0000","код 1/3005.0489.9258","1/3005.0489.9258","карта 1/3005.0489.9258","x1/3005.0489.9258","код 1/2204.4132.9947.0000","1/2204.4132.9947.0000","карта 1/2204.4132.9947.0000","x1/2204.4132.9947.0000","код 1/2204-4132-9947-0000","1/2204-4132-9947-0000","карта 1/2204-4132-9947-0000","x1/2204-4132-9947-0000","код 1/2204/4132/9947/0000","1/2204/4132/9947/0000","карта 1/2204/4132/9947/0000","x1/2204/4132/9947/0000","код 1/2204 4132 9947 0000","1/2204 4132 9947 0000","карта 1/2204 4132 9947 0000","x1/2204 4132 9947 0000","код 1/2204.4132.9947.0018","1/2204.4132.9947.0018","карта 1/2204.4132.9947.0018","x1/2204.4132.9947.0018","код 1/2204-4132-9947-0018","1/2204-4132-9947-0018","карта 1/2204-4132-9947-0018","x1/2204-4132-9947-0018","код 1/2204/4132/9947/0018","1/2204/4132/9947/0018","карта 1/2204/4132/9947/0018","x1/2204/4132/9947/0018","код 1/0.2204.4132.9947","1/0.2204.4132.9947","карта 1/0.2204.4132.9947","x1/0.2204.4132.9947","код 1/0.0000.0000.0000","1/0.0000.0000.0000","карта 1/0.0000.0000.0000","x1/0.0000.0000.0000","код 1/2.2204.4132.9947","1/2.2204.4132.9947","карта 1/2.2204.4132.9947","x1/2.2204.4132.9947","код 1/1.2204.4132.9947","1/1.2204.4132.9947","карта 1/1.2204.4132.9947","x1/1.2204.4132.9947","код 1/2204.4132","1/2204.4132","карта 1/2204.4132","x1/2204.4132","код 1/34567890123","1/34567890123","карта 1/34567890123","x1/34567890123","код 1/044525225","1/044525225","карта 1/044525225","x1/044525225","код 1/220441329947","1/220441329947","карта 1/220441329947","x1/220441329947","код 1/300504899258","1/300504899258","карта 1/300504899258","x1/300504899258","код 1/0000000000","1/0000000000","карта 1/0000000000","x1/0000000000","код 1/000000000000","1/000000000000","карта 1/000000000000","x1/000000000000","код 1/2204.9947.4132.0000","1/2204.9947.4132.0000","карта 1/2204.9947.4132.0000","x1/2204.9947.4132.0000","код 1/2222.2222.2222.2222","1/2222.2222.2222.2222","карта 1/2222.2222.2222.2222","x1/2222.2222.2222.2222","код 1/2204.4132.9947 0000","1/2204.4132.9947 0000","карта 1/2204.4132.9947 0000","x1/2204.4132.9947 0000","код 1/2204.4132.9947 0018","1/2204.4132.9947 0018","карта 1/2204.4132.9947 0018","x1/2204.4132.9947 0018","код 1/2204-4132-9947 0000","1/2204-4132-9947 0000","карта 1/2204-4132-9947 0000","x1/2204-4132-9947 0000","код 1/2204/4132/9947 0000","1/2204/4132/9947 0000","карта 1/2204/4132/9947 0000","x1/2204/4132/9947 0000","код 1/24.82.01.43.38","1/24.82.01.43.38","карта 1/24.82.01.43.38","x1/24.82.01.43.38","код 1/378/123/456/94","1/378/123/456/94","карта 1/378/123/456/94","x1/378/123/456/94","код 1/774358.417509","1/774358.417509","карта 1/774358.417509","x1/774358.417509","код 1/0.0.0000.0000.0000","1/0.0.0000.0000.0000","карта 1/0.0.0000.0000.0000","x1/0.0.0000.0000.0000","код 1/0.2.2204.4132.9947","1/0.2.2204.4132.9947","карта 1/0.2.2204.4132.9947","x1/0.2.2204.4132.9947","код 1/2.2.2204.4132.9947","1/2.2.2204.4132.9947","карта 1/2.2.2204.4132.9947","x1/2.2.2204.4132.9947","код 1/2.0.2204.4132.9947","1/2.0.2204.4132.9947","карта 1/2.0.2204.4132.9947","x1/2.0.2204.4132.9947","код 1/1.0.0000.0000.0000","1/1.0.0000.0000.0000","карта 1/1.0.0000.0000.0000","x1/1.0.0000.0000.0000","код 1/2.0000.0000.0000","1/2.0000.0000.0000","карта 1/2.0000.0000.0000","x1/2.0000.0000.0000","код 1/0.2204.4132.9947.0018","1/0.2204.4132.9947.0018","карта 1/0.2204.4132.9947.0018","x1/0.2204.4132.9947.0018","код 1/0.2204-4132-9947-0018","1/0.2204-4132-9947-0018","карта 1/0.2204-4132-9947-0018","x1/0.2204-4132-9947-0018","код 1/2222-2222-2222-2222","1/2222-2222-2222-2222","карта 1/2222-2222-2222-2222","x1/2222-2222-2222-2222","код 1/2222 2222 2222 2222","1/2222 2222 2222 2222","карта 1/2222 2222 2222 2222","x1/2222 2222 2222 2222","код 1/2222/2222/2222/2222","1/2222/2222/2222/2222","карта 1/2222/2222/2222/2222","x1/2222/2222/2222/2222","код 1/1111.1111.1111.1111","1/1111.1111.1111.1111","карта 1/1111.1111.1111.1111","x1/1111.1111.1111.1111","код 1/2204.4132.9947.0000.0000","1/2204.4132.9947.0000.0000","карта 1/2204.4132.9947.0000.0000","x1/2204.4132.9947.0000.0000","код 1/2204.4132.9947 1.2204.4132.9947","1/2204.4132.9947 1.2204.4132.9947","карта 1/2204.4132.9947 1.2204.4132.9947","x1/2204.4132.9947 1.2204.4132.9947","код 1/2204.4132.9947 0000000000","1/2204.4132.9947 0000000000","карта 1/2204.4132.9947 0000000000","x1/2204.4132.9947 0000000000","код 1/3005-0489-9258","1/3005-0489-9258","карта 1/3005-0489-9258","x1/3005-0489-9258","код 1/3005 0489 9258","1/3005 0489 9258","карта 1/3005 0489 9258","x1/3005 0489 9258","код 1/3005/0489/9258","1/3005/0489/9258","карта 1/3005/0489/9258","x1/3005/0489/9258","код 1/1000 2000 3000 4000 5000 6000","1/1000 2000 3000 4000 5000 6000","карта 1/1000 2000 3000 4000 5000 6000","x1/1000 2000 3000 4000 5000 6000","код 1/2204.4132.9947 списка","1/2204.4132.9947 списка","карта 1/2204.4132.9947 списка","x1/2204.4132.9947 списка","код 1/2204-4132-9947 список","1/2204-4132-9947 список","карта 1/2204-4132-9947 список","x1/2204-4132-9947 список","код 1/2.0000-0000-0000","1/2.0000-0000-0000","карта 1/2.0000-0000-0000","x1/2.0000-0000-0000","код 1/2.0000 0000 0000","1/2.0000 0000 0000","карта 1/2.0000 0000 0000","x1/2.0000 0000 0000","код 1/2.0000/0000/0000","1/2.0000/0000/0000","карта 1/2.0000/0000/0000","x1/2.0000/0000/0000","код 1/2.0000.0000.0000.0000","1/2.0000.0000.0000.0000","карта 1/2.0000.0000.0000.0000","x1/2.0000.0000.0000.0000","код 1/0.0000-0000-0000","1/0.0000-0000-0000","карта 1/0.0000-0000-0000","x1/0.0000-0000-0000","код 1/0.0000 0000 0000","1/0.0000 0000 0000","карта 1/0.0000 0000 0000","x1/0.0000 0000 0000","код 1/0.0000/0000/0000","1/0.0000/0000/0000","карта 1/0.0000/0000/0000","x1/0.0000/0000/0000","код 1/0.0000.0000.0000.0000","1/0.0000.0000.0000.0000","карта 1/0.0000.0000.0000.0000","x1/0.0000.0000.0000.0000","код 1 2204.4132.9947","1 2204.4132.9947","карта 1 2204.4132.9947","x1 2204.4132.9947","код 1 2204-4132-9947","1 2204-4132-9947","карта 1 2204-4132-9947","x1 2204-4132-9947","код 1 2204 4132 9947","1 2204 4132 9947","карта 1 2204 4132 9947","x1 2204 4132 9947","код 1 2204/4132/9947","1 2204/4132/9947","карта 1 2204/4132/9947","x1 2204/4132/9947","код 1 0000.0000.0000","1 0000.0000.0000","карта 1 0000.0000.0000","x1 0000.0000.0000","код 1 0000-0000-0000","1 0000-0000-0000","карта 1 0000-0000-0000","x1 0000-0000-0000","код 1 0000 0000 0000","1 0000 0000 0000","карта 1 0000 0000 0000","x1 0000 0000 0000","код 1 0000/0000/0000","1 0000/0000/0000","карта 1 0000/0000/0000","x1 0000/0000/0000","код 1 0000.0000.0000.0000","1 0000.0000.0000.0000","карта 1 0000.0000.0000.0000","x1 0000.0000.0000.0000","код 1 0000-0000-0000-0000","1 0000-0000-0000-0000","карта 1 0000-0000-0000-0000","x1 0000-0000-0000-0000","код 1 0000 0000 0000 0000","1 0000 0000 0000 0000","карта 1 0000 0000 0000 0000","x1 0000 0000 0000 0000","код 1 0000/0000/0000/0000","1 0000/0000/0000/0000","карта 1 0000/0000/0000/0000","x1 0000/0000/0000/0000","код 1 3005.0489.9258","1 3005.0489.9258","карта 1 3005.0489.9258","x1 3005.0489.9258","код 1 2204.4132.9947.0000","1 2204.4132.9947.0000","карта 1 2204.4132.9947.0000","x1 2204.4132.9947.0000","код 1 2204-4132-9947-0000","1 2204-4132-9947-0000","карта 1 2204-4132-9947-0000","x1 2204-4132-9947-0000","код 1 2204/4132/9947/0000","1 2204/4132/9947/0000","карта 1 2204/4132/9947/0000","x1 2204/4132/9947/0000","код 1 2204 4132 9947 0000","1 2204 4132 9947 0000","карта 1 2204 4132 9947 0000","x1 2204 4132 9947 0000","код 1 2204.4132.9947.0018","1 2204.4132.9947.0018","карта 1 2204.4132.9947.0018","x1 2204.4132.9947.0018","код 1 2204-4132-9947-0018","1 2204-4132-9947-0018","карта 1 2204-4132-9947-0018","x1 2204-4132-9947-0018","код 1 2204/4132/9947/0018","1 2204/4132/9947/0018","карта 1 2204/4132/9947/0018","x1 2204/4132/9947/0018","код 1 0.2204.4132.9947","1 0.2204.4132.9947","карта 1 0.2204.4132.9947","x1 0.2204.4132.9947","код 1 0.0000.0000.0000","1 0.0000.0000.0000","карта 1 0.0000.0000.0000","x1 0.0000.0000.0000","код 1 2.2204.4132.9947","1 2.2204.4132.9947","карта 1 2.2204.4132.9947","x1 2.2204.4132.9947","код 1 1.2204.4132.9947","1 1.2204.4132.9947","карта 1 1.2204.4132.9947","x1 1.2204.4132.9947","код 1 2204.4132","1 2204.4132","карта 1 2204.4132","x1 2204.4132","код 1 34567890123","1 34567890123","карта 1 34567890123","x1 34567890123","код 1 044525225","1 044525225","карта 1 044525225","x1 044525225","код 1 220441329947","1 220441329947","карта 1 220441329947","x1 220441329947","код 1 300504899258","1 300504899258","карта 1 300504899258","x1 300504899258","код 1 0000000000","1 0000000000","карта 1 0000000000","x1 0000000000","код 1 000000000000","1 000000000000","карта 1 000000000000","x1 000000000000","код 1 2204.9947.4132.0000","1 2204.9947.4132.0000","карта 1 2204.9947.4132.0000","x1 2204.9947.4132.0000","код 1 2222.2222.2222.2222","1 2222.2222.2222.2222","карта 1 2222.2222.2222.2222","x1 2222.2222.2222.2222","код 1 2204.4132.9947 0000","1 2204.4132.9947 0000","карта 1 2204.4132.9947 0000","x1 2204.4132.9947 0000","код 1 2204.4132.9947 0018","1 2204.4132.9947 0018","карта 1 2204.4132.9947 0018","x1 2204.4132.9947 0018","код 1 2204-4132-9947 0000","1 2204-4132-9947 0000","карта 1 2204-4132-9947 0000","x1 2204-4132-9947 0000","код 1 2204/4132/9947 0000","1 2204/4132/9947 0000","карта 1 2204/4132/9947 0000","x1 2204/4132/9947 0000","код 1 24.82.01.43.38","1 24.82.01.43.38","карта 1 24.82.01.43.38","x1 24.82.01.43.38","код 1 378/123/456/94","1 378/123/456/94","карта 1 378/123/456/94","x1 378/123/456/94","код 1 774358.417509","1 774358.417509","карта 1 774358.417509","x1 774358.417509","код 1 0.0.0000.0000.0000","1 0.0.0000.0000.0000","карта 1 0.0.0000.0000.0000","x1 0.0.0000.0000.0000","код 1 0.2.2204.4132.9947","1 0.2.2204.4132.9947","карта 1 0.2.2204.4132.9947","x1 0.2.2204.4132.9947","код 1 2.2.2204.4132.9947","1 2.2.2204.4132.9947","карта 1 2.2.2204.4132.9947","x1 2.2.2204.4132.9947","код 1 2.0.2204.4132.9947","1 2.0.2204.4132.9947","карта 1 2.0.2204.4132.9947","x1 2.0.2204.4132.9947","код 1 1.0.0000.0000.0000","1 1.0.0000.0000.0000","карта 1 1.0.0000.0000.0000","x1 1.0.0000.0000.0000","код 1 2.0000.0000.0000","1 2.0000.0000.0000","карта 1 2.0000.0000.0000","x1 2.0000.0000.0000","код 1 0.2204.4132.9947.0018","1 0.2204.4132.9947.0018","карта 1 0.2204.4132.9947.0018","x1 0.2204.4132.9947.0018","код 1 0.2204-4132-9947-0018","1 0.2204-4132-9947-0018","карта 1 0.2204-4132-9947-0018","x1 0.2204-4132-9947-0018","код 1 2222-2222-2222-2222","1 2222-2222-2222-2222","карта 1 2222-2222-2222-2222","x1 2222-2222-2222-2222","код 1 2222 2222 2222 2222","1 2222 2222 2222 2222","карта 1 2222 2222 2222 2222","x1 2222 2222 2222 2222","код 1 2222/2222/2222/2222","1 2222/2222/2222/2222","карта 1 2222/2222/2222/2222","x1 2222/2222/2222/2222","код 1 1111.1111.1111.1111","1 1111.1111.1111.1111","карта 1 1111.1111.1111.1111","x1 1111.1111.1111.1111","код 1 2204.4132.9947.0000.0000","1 2204.4132.9947.0000.0000","карта 1 2204.4132.9947.0000.0000","x1 2204.4132.9947.0000.0000","код 1 2204.4132.9947 1.2204.4132.9947","1 2204.4132.9947 1.2204.4132.9947","карта 1 2204.4132.9947 1.2204.4132.9947","x1 2204.4132.9947 1.2204.4132.9947","код 1 2204.4132.9947 0000000000","1 2204.4132.9947 0000000000","карта 1 2204.4132.9947 0000000000","x1 2204.4132.9947 0000000000","код 1 3005-0489-9258","1 3005-0489-9258","карта 1 3005-0489-9258","x1 3005-0489-9258","код 1 3005 0489 9258","1 3005 0489 9258","карта 1 3005 0489 9258","x1 3005 0489 9258","код 1 3005/0489/9258","1 3005/0489/9258","карта 1 3005/0489/9258","x1 3005/0489/9258","код 1 1000 2000 3000 4000 5000 6000","1 1000 2000 3000 4000 5000 6000","карта 1 1000 2000 3000 4000 5000 6000","x1 1000 2000 3000 4000 5000 6000","код 1 2204.4132.9947 списка","1 2204.4132.9947 списка","карта 1 2204.4132.9947 списка","x1 2204.4132.9947 списка","код 1 2204-4132-9947 список","1 2204-4132-9947 список","карта 1 2204-4132-9947 список","x1 2204-4132-9947 список","код 1 2.0000-0000-0000","1 2.0000-0000-0000","карта 1 2.0000-0000-0000","x1 2.0000-0000-0000","код 1 2.0000 0000 0000","1 2.0000 0000 0000","карта 1 2.0000 0000 0000","x1 2.0000 0000 0000","код 1 2.0000/0000/0000","1 2.0000/0000/0000","карта 1 2.0000/0000/0000","x1 2.0000/0000/0000","код 1 2.0000.0000.0000.0000","1 2.0000.0000.0000.0000","карта 1 2.0000.0000.0000.0000","x1 2.0000.0000.0000.0000","код 1 0.0000-0000-0000","1 0.0000-0000-0000","карта 1 0.0000-0000-0000","x1 0.0000-0000-0000","код 1 0.0000 0000 0000","1 0.0000 0000 0000","карта 1 0.0000 0000 0000","x1 0.0000 0000 0000","код 1 0.0000/0000/0000","1 0.0000/0000/0000","карта 1 0.0000/0000/0000","x1 0.0000/0000/0000","код 1 0.0000.0000.0000.0000","1 0.0000.0000.0000.0000","карта 1 0.0000.0000.0000.0000","x1 0.0000.0000.0000.0000","код x1.2204.4132.9947","карта x1.2204.4132.9947","xx1.2204.4132.9947","код x1.2204-4132-9947","карта x1.2204-4132-9947","xx1.2204-4132-9947","код x1.2204 4132 9947","карта x1.2204 4132 9947","xx1.2204 4132 9947","код x1.2204/4132/9947","карта x1.2204/4132/9947","xx1.2204/4132/9947","код x1.0000.0000.0000","карта x1.0000.0000.0000","xx1.0000.0000.0000","код x1.0000-0000-0000","карта x1.0000-0000-0000","xx1.0000-0000-0000","код x1.0000 0000 0000","карта x1.0000 0000 0000","xx1.0000 0000 0000","код x1.0000/0000/0000","карта x1.0000/0000/0000","xx1.0000/0000/0000","код x1.0000.0000.0000.0000","карта x1.0000.0000.0000.0000","xx1.0000.0000.0000.0000","код x1.0000-0000-0000-0000","карта x1.0000-0000-0000-0000","xx1.0000-0000-0000-0000","код x1.0000 0000 0000 0000","карта x1.0000 0000 0000 0000","xx1.0000 0000 0000 0000","код x1.0000/0000/0000/0000","карта x1.0000/0000/0000/0000","xx1.0000/0000/0000/0000","код x1.3005.0489.9258","карта x1.3005.0489.9258","xx1.3005.0489.9258","код x1.2204.4132.9947.0000","карта x1.2204.4132.9947.0000","xx1.2204.4132.9947.0000","код x1.2204-4132-9947-0000","карта x1.2204-4132-9947-0000","xx1.2204-4132-9947-0000","код x1.2204/4132/9947/0000","карта x1.2204/4132/9947/0000","xx1.2204/4132/9947/0000","код x1.2204 4132 9947 0000","карта x1.2204 4132 9947 0000","xx1.2204 4132 9947 0000","код x1.2204.4132.9947.0018","карта x1.2204.4132.9947.0018","xx1.2204.4132.9947.0018","код x1.2204-4132-9947-0018","карта x1.2204-4132-9947-0018","xx1.2204-4132-9947-0018","код x1.2204/4132/9947/0018","карта x1.2204/4132/9947/0018","xx1.2204/4132/9947/0018","код x1.0.2204.4132.9947","карта x1.0.2204.4132.9947","xx1.0.2204.4132.9947","код x1.0.0000.0000.0000","карта x1.0.0000.0000.0000","xx1.0.0000.0000.0000","код x1.2.2204.4132.9947","карта x1.2.2204.4132.9947","xx1.2.2204.4132.9947","код x1.1.2204.4132.9947","карта x1.1.2204.4132.9947","xx1.1.2204.4132.9947","код x1.2204.4132","карта x1.2204.4132","xx1.2204.4132","код x1.34567890123","карта x1.34567890123","xx1.34567890123","код x1.044525225","карта x1.044525225","xx1.044525225","код x1.220441329947","карта x1.220441329947","xx1.220441329947","код x1.300504899258","карта x1.300504899258","xx1.300504899258","код x1.0000000000","карта x1.0000000000","xx1.0000000000","код x1.000000000000","карта x1.000000000000","xx1.000000000000","код x1.2204.9947.4132.0000","карта x1.2204.9947.4132.0000","xx1.2204.9947.4132.0000","код x1.2222.2222.2222.2222","карта x1.2222.2222.2222.2222","xx1.2222.2222.2222.2222","код x1.2204.4132.9947 0000","карта x1.2204.4132.9947 0000","xx1.2204.4132.9947 0000","код x1.2204.4132.9947 0018","карта x1.2204.4132.9947 0018","xx1.2204.4132.9947 0018","код x1.2204-4132-9947 0000","карта x1.2204-4132-9947 0000","xx1.2204-4132-9947 0000","код x1.2204/4132/9947 0000","карта x1.2204/4132/9947 0000","xx1.2204/4132/9947 0000","код x1.24.82.01.43.38","карта x1.24.82.01.43.38","xx1.24.82.01.43.38","код x1.378/123/456/94","карта x1.378/123/456/94","xx1.378/123/456/94","код x1.774358.417509","карта x1.774358.417509","xx1.774358.417509","код x1.0.0.0000.0000.0000","карта x1.0.0.0000.0000.0000","xx1.0.0.0000.0000.0000","код x1.0.2.2204.4132.9947","карта x1.0.2.2204.4132.9947","xx1.0.2.2204.4132.9947","код x1.2.2.2204.4132.9947","карта x1.2.2.2204.4132.9947","xx1.2.2.2204.4132.9947","код x1.2.0.2204.4132.9947","карта x1.2.0.2204.4132.9947","xx1.2.0.2204.4132.9947","код x1.1.0.0000.0000.0000","карта x1.1.0.0000.0000.0000","xx1.1.0.0000.0000.0000","код x1.2.0000.0000.0000","карта x1.2.0000.0000.0000","xx1.2.0000.0000.0000","код x1.0.2204.4132.9947.0018","карта x1.0.2204.4132.9947.0018","xx1.0.2204.4132.9947.0018","код x1.0.2204-4132-9947-0018","карта x1.0.2204-4132-9947-0018","xx1.0.2204-4132-9947-0018","код x1.2222-2222-2222-2222","карта x1.2222-2222-2222-2222","xx1.2222-2222-2222-2222","код x1.2222 2222 2222 2222","карта x1.2222 2222 2222 2222","xx1.2222 2222 2222 2222","код x1.2222/2222/2222/2222","карта x1.2222/2222/2222/2222","xx1.2222/2222/2222/2222","код x1.1111.1111.1111.1111","карта x1.1111.1111.1111.1111","xx1.1111.1111.1111.1111","код x1.2204.4132.9947.0000.0000","карта x1.2204.4132.9947.0000.0000","xx1.2204.4132.9947.0000.0000","код x1.2204.4132.9947 1.2204.4132.9947","карта x1.2204.4132.9947 1.2204.4132.9947","xx1.2204.4132.9947 1.2204.4132.9947","код x1.2204.4132.9947 0000000000","карта x1.2204.4132.9947 0000000000","xx1.2204.4132.9947 0000000000","код x1.3005-0489-9258","карта x1.3005-0489-9258","xx1.3005-0489-9258","код x1.3005 0489 9258","карта x1.3005 0489 9258","xx1.3005 0489 9258","код x1.3005/0489/9258","карта x1.3005/0489/9258","xx1.3005/0489/9258","код x1.1000 2000 3000 4000 5000 6000","карта x1.1000 2000 3000 4000 5000 6000","xx1.1000 2000 3000 4000 5000 6000","код x1.2204.4132.9947 списка","карта x1.2204.4132.9947 списка","xx1.2204.4132.9947 списка","код x1.2204-4132-9947 список","карта x1.2204-4132-9947 список","xx1.2204-4132-9947 список","код x1.2.0000-0000-0000","карта x1.2.0000-0000-0000","xx1.2.0000-0000-0000","код x1.2.0000 0000 0000","карта x1.2.0000 0000 0000","xx1.2.0000 0000 0000","код x1.2.0000/0000/0000","карта x1.2.0000/0000/0000","xx1.2.0000/0000/0000","код x1.2.0000.0000.0000.0000","карта x1.2.0000.0000.0000.0000","xx1.2.0000.0000.0000.0000","код x1.0.0000-0000-0000","карта x1.0.0000-0000-0000","xx1.0.0000-0000-0000","код x1.0.0000 0000 0000","карта x1.0.0000 0000 0000","xx1.0.0000 0000 0000","код x1.0.0000/0000/0000","карта x1.0.0000/0000/0000","xx1.0.0000/0000/0000","код x1.0.0000.0000.0000.0000","карта x1.0.0000.0000.0000.0000","xx1.0.0000.0000.0000.0000","код x1-2204.4132.9947","карта x1-2204.4132.9947","xx1-2204.4132.9947","код x1-2204-4132-9947","карта x1-2204-4132-9947","xx1-2204-4132-9947","код x1-2204 4132 9947","карта x1-2204 4132 9947","xx1-2204 4132 9947","код x1-2204/4132/9947","карта x1-2204/4132/9947","xx1-2204/4132/9947","код x1-0000.0000.0000","карта x1-0000.0000.0000","xx1-0000.0000.0000","код x1-0000-0000-0000","карта x1-0000-0000-0000","xx1-0000-0000-0000","код x1-0000 0000 0000","карта x1-0000 0000 0000","xx1-0000 0000 0000","код x1-0000/0000/0000","карта x1-0000/0000/0000","xx1-0000/0000/0000","код x1-0000.0000.0000.0000","карта x1-0000.0000.0000.0000","xx1-0000.0000.0000.0000","код x1-0000-0000-0000-0000","карта x1-0000-0000-0000-0000","xx1-0000-0000-0000-0000","код x1-0000 0000 0000 0000","карта x1-0000 0000 0000 0000","xx1-0000 0000 0000 0000","код x1-0000/0000/0000/0000","карта x1-0000/0000/0000/0000","xx1-0000/0000/0000/0000","код x1-3005.0489.9258","карта x1-3005.0489.9258","xx1-3005.0489.9258","код x1-2204.4132.9947.0000","карта x1-2204.4132.9947.0000","xx1-2204.4132.9947.0000","код x1-2204-4132-9947-0000","карта x1-2204-4132-9947-0000","xx1-2204-4132-9947-0000","код x1-2204/4132/9947/0000","карта x1-2204/4132/9947/0000","xx1-2204/4132/9947/0000","код x1-2204 4132 9947 0000","карта x1-2204 4132 9947 0000","xx1-2204 4132 9947 0000","код x1-2204.4132.9947.0018","карта x1-2204.4132.9947.0018","xx1-2204.4132.9947.0018","код x1-2204-4132-9947-0018","карта x1-2204-4132-9947-0018","xx1-2204-4132-9947-0018","код x1-2204/4132/9947/0018","карта x1-2204/4132/9947/0018","xx1-2204/4132/9947/0018","код x1-0.2204.4132.9947","карта x1-0.2204.4132.9947","xx1-0.2204.4132.9947","код x1-0.0000.0000.0000","карта x1-0.0000.0000.0000","xx1-0.0000.0000.0000","код x1-2.2204.4132.9947","карта x1-2.2204.4132.9947","xx1-2.2204.4132.9947","код x1-1.2204.4132.9947","карта x1-1.2204.4132.9947","xx1-1.2204.4132.9947","код x1-2204.4132","карта x1-2204.4132","xx1-2204.4132","код x1-34567890123","карта x1-34567890123","xx1-34567890123","код x1-044525225","карта x1-044525225","xx1-044525225","код x1-220441329947","карта x1-220441329947","xx1-220441329947","код x1-300504899258","карта x1-300504899258","xx1-300504899258","код x1-0000000000","карта x1-0000000000","xx1-0000000000","код x1-000000000000","карта x1-000000000000","xx1-000000000000","код x1-2204.9947.4132.0000","карта x1-2204.9947.4132.0000","xx1-2204.9947.4132.0000","код x1-2222.2222.2222.2222","карта x1-2222.2222.2222.2222","xx1-2222.2222.2222.2222","код x1-2204.4132.9947 0000","карта x1-2204.4132.9947 0000","xx1-2204.4132.9947 0000","код x1-2204.4132.9947 0018","карта x1-2204.4132.9947 0018","xx1-2204.4132.9947 0018","код x1-2204-4132-9947 0000","карта x1-2204-4132-9947 0000","xx1-2204-4132-9947 0000","код x1-2204/4132/9947 0000","карта x1-2204/4132/9947 0000","xx1-2204/4132/9947 0000","код x1-24.82.01.43.38","карта x1-24.82.01.43.38","xx1-24.82.01.43.38","код x1-378/123/456/94","карта x1-378/123/456/94","xx1-378/123/456/94","код x1-774358.417509","карта x1-774358.417509","xx1-774358.417509","код x1-0.0.0000.0000.0000","карта x1-0.0.0000.0000.0000","xx1-0.0.0000.0000.0000","код x1-0.2.2204.4132.9947","карта x1-0.2.2204.4132.9947","xx1-0.2.2204.4132.9947","код x1-2.2.2204.4132.9947","карта x1-2.2.2204.4132.9947","xx1-2.2.2204.4132.9947","код x1-2.0.2204.4132.9947","карта x1-2.0.2204.4132.9947","xx1-2.0.2204.4132.9947","код x1-1.0.0000.0000.0000","карта x1-1.0.0000.0000.0000","xx1-1.0.0000.0000.0000","код x1-2.0000.0000.0000","карта x1-2.0000.0000.0000","xx1-2.0000.0000.0000","код x1-0.2204.4132.9947.0018","карта x1-0.2204.4132.9947.0018","xx1-0.2204.4132.9947.0018","код x1-0.2204-4132-9947-0018","карта x1-0.2204-4132-9947-0018","xx1-0.2204-4132-9947-0018","код x1-2222-2222-2222-2222","карта x1-2222-2222-2222-2222","xx1-2222-2222-2222-2222","код x1-2222 2222 2222 2222","карта x1-2222 2222 2222 2222","xx1-2222 2222 2222 2222","код x1-2222/2222/2222/2222","карта x1-2222/2222/2222/2222","xx1-2222/2222/2222/2222","код x1-1111.1111.1111.1111","карта x1-1111.1111.1111.1111","xx1-1111.1111.1111.1111","код x1-2204.4132.9947.0000.0000","карта x1-2204.4132.9947.0000.0000","xx1-2204.4132.9947.0000.0000","код x1-2204.4132.9947 1.2204.4132.9947","карта x1-2204.4132.9947 1.2204.4132.9947","xx1-2204.4132.9947 1.2204.4132.9947","код x1-2204.4132.9947 0000000000","карта x1-2204.4132.9947 0000000000","xx1-2204.4132.9947 0000000000","код x1-3005-0489-9258","карта x1-3005-0489-9258","xx1-3005-0489-9258","код x1-3005 0489 9258","карта x1-3005 0489 9258","xx1-3005 0489 9258","код x1-3005/0489/9258","карта x1-3005/0489/9258","xx1-3005/0489/9258","код x1-1000 2000 3000 4000 5000 6000","карта x1-1000 2000 3000 4000 5000 6000","xx1-1000 2000 3000 4000 5000 6000","код x1-2204.4132.9947 списка","карта x1-2204.4132.9947 списка","xx1-2204.4132.9947 списка","код x1-2204-4132-9947 список","карта x1-2204-4132-9947 список","xx1-2204-4132-9947 список","код x1-2.0000-0000-0000","карта x1-2.0000-0000-0000","xx1-2.0000-0000-0000","код x1-2.0000 0000 0000","карта x1-2.0000 0000 0000","xx1-2.0000 0000 0000","код x1-2.0000/0000/0000","карта x1-2.0000/0000/0000","xx1-2.0000/0000/0000","код x1-2.0000.0000.0000.0000","карта x1-2.0000.0000.0000.0000","xx1-2.0000.0000.0000.0000","код x1-0.0000-0000-0000","карта x1-0.0000-0000-0000","xx1-0.0000-0000-0000","код x1-0.0000 0000 0000","карта x1-0.0000 0000 0000","xx1-0.0000 0000 0000","код x1-0.0000/0000/0000","карта x1-0.0000/0000/0000","xx1-0.0000/0000/0000","код x1-0.0000.0000.0000.0000","карта x1-0.0000.0000.0000.0000","xx1-0.0000.0000.0000.0000","код x1/2204.4132.9947","карта x1/2204.4132.9947","xx1/2204.4132.9947","код x1/2204-4132-9947","карта x1/2204-4132-9947","xx1/2204-4132-9947","код x1/2204 4132 9947","карта x1/2204 4132 9947","xx1/2204 4132 9947","код x1/2204/4132/9947","карта x1/2204/4132/9947","xx1/2204/4132/9947","код x1/0000.0000.0000","карта x1/0000.0000.0000","xx1/0000.0000.0000","код x1/0000-0000-0000","карта x1/0000-0000-0000","xx1/0000-0000-0000","код x1/0000 0000 0000","карта x1/0000 0000 0000","xx1/0000 0000 0000","код x1/0000/0000/0000","карта x1/0000/0000/0000","xx1/0000/0000/0000","код x1/0000.0000.0000.0000","карта x1/0000.0000.0000.0000","xx1/0000.0000.0000.0000","код x1/0000-0000-0000-0000","карта x1/0000-0000-0000-0000","xx1/0000-0000-0000-0000","код x1/0000 0000 0000 0000","карта x1/0000 0000 0000 0000","xx1/0000 0000 0000 0000","код x1/0000/0000/0000/0000","карта x1/0000/0000/0000/0000","xx1/0000/0000/0000/0000","код x1/3005.0489.9258","карта x1/3005.0489.9258","xx1/3005.0489.9258","код x1/2204.4132.9947.0000","карта x1/2204.4132.9947.0000","xx1/2204.4132.9947.0000","код x1/2204-4132-9947-0000","карта x1/2204-4132-9947-0000","xx1/2204-4132-9947-0000","код x1/2204/4132/9947/0000","карта x1/2204/4132/9947/0000","xx1/2204/4132/9947/0000","код x1/2204 4132 9947 0000","карта x1/2204 4132 9947 0000","xx1/2204 4132 9947 0000","код x1/2204.4132.9947.0018","карта x1/2204.4132.9947.0018","xx1/2204.4132.9947.0018","код x1/2204-4132-9947-0018","карта x1/2204-4132-9947-0018","xx1/2204-4132-9947-0018","код x1/2204/4132/9947/0018","карта x1/2204/4132/9947/0018","xx1/2204/4132/9947/0018","код x1/0.2204.4132.9947","карта x1/0.2204.4132.9947","xx1/0.2204.4132.9947","код x1/0.0000.0000.0000","карта x1/0.0000.0000.0000","xx1/0.0000.0000.0000","код x1/2.2204.4132.9947","карта x1/2.2204.4132.9947","xx1/2.2204.4132.9947","код x1/1.2204.4132.9947","карта x1/1.2204.4132.9947","xx1/1.2204.4132.9947","код x1/2204.4132","карта x1/2204.4132","xx1/2204.4132","код x1/34567890123","карта x1/34567890123","xx1/34567890123","код x1/044525225","карта x1/044525225","xx1/044525225","код x1/220441329947","карта x1/220441329947","xx1/220441329947","код x1/300504899258","карта x1/300504899258","xx1/300504899258","код x1/0000000000","карта x1/0000000000","xx1/0000000000","код x1/000000000000","карта x1/000000000000","xx1/000000000000","код x1/2204.9947.4132.0000","карта x1/2204.9947.4132.0000","xx1/2204.9947.4132.0000","код x1/2222.2222.2222.2222","карта x1/2222.2222.2222.2222","xx1/2222.2222.2222.2222","код x1/2204.4132.9947 0000","карта x1/2204.4132.9947 0000","xx1/2204.4132.9947 0000","код x1/2204.4132.9947 0018","карта x1/2204.4132.9947 0018","xx1/2204.4132.9947 0018","код x1/2204-4132-9947 0000","карта x1/2204-4132-9947 0000","xx1/2204-4132-9947 0000","код x1/2204/4132/9947 0000","карта x1/2204/4132/9947 0000","xx1/2204/4132/9947 0000","код x1/24.82.01.43.38","карта x1/24.82.01.43.38","xx1/24.82.01.43.38","код x1/378/123/456/94","карта x1/378/123/456/94","xx1/378/123/456/94","код x1/774358.417509","карта x1/774358.417509","xx1/774358.417509","код x1/0.0.0000.0000.0000","карта x1/0.0.0000.0000.0000","xx1/0.0.0000.0000.0000","код x1/0.2.2204.4132.9947","карта x1/0.2.2204.4132.9947","xx1/0.2.2204.4132.9947","код x1/2.2.2204.4132.9947","карта x1/2.2.2204.4132.9947","xx1/2.2.2204.4132.9947","код x1/2.0.2204.4132.9947","карта x1/2.0.2204.4132.9947","xx1/2.0.2204.4132.9947","код x1/1.0.0000.0000.0000","карта x1/1.0.0000.0000.0000","xx1/1.0.0000.0000.0000","код x1/2.0000.0000.0000","карта x1/2.0000.0000.0000","xx1/2.0000.0000.0000","код x1/0.2204.4132.9947.0018","карта x1/0.2204.4132.9947.0018","xx1/0.2204.4132.9947.0018","код x1/0.2204-4132-9947-0018","карта x1/0.2204-4132-9947-0018","xx1/0.2204-4132-9947-0018","код x1/2222-2222-2222-2222","карта x1/2222-2222-2222-2222","xx1/2222-2222-2222-2222","код x1/2222 2222 2222 2222","карта x1/2222 2222 2222 2222","xx1/2222 2222 2222 2222","код x1/2222/2222/2222/2222","карта x1/2222/2222/2222/2222","xx1/2222/2222/2222/2222","код x1/1111.1111.1111.1111","карта x1/1111.1111.1111.1111","xx1/1111.1111.1111.1111","код x1/2204.4132.9947.0000.0000","карта x1/2204.4132.9947.0000.0000","xx1/2204.4132.9947.0000.0000","код x1/2204.4132.9947 1.2204.4132.9947","карта x1/2204.4132.9947 1.2204.4132.9947","xx1/2204.4132.9947 1.2204.4132.9947","код x1/2204.4132.9947 0000000000","карта x1/2204.4132.9947 0000000000","xx1/2204.4132.9947 0000000000","код x1/3005-0489-9258","карта x1/3005-0489-9258","xx1/3005-0489-9258","код x1/3005 0489 9258","карта x1/3005 0489 9258","xx1/3005 0489 9258","код x1/3005/0489/9258","карта x1/3005/0489/9258","xx1/3005/0489/9258","код x1/1000 2000 3000 4000 5000 6000","карта x1/1000 2000 3000 4000 5000 6000","xx1/1000 2000 3000 4000 5000 6000","код x1/2204.4132.9947 списка","карта x1/2204.4132.9947 списка","xx1/2204.4132.9947 списка","код x1/2204-4132-9947 список","карта x1/2204-4132-9947 список","xx1/2204-4132-9947 список","код x1/2.0000-0000-0000","карта x1/2.0000-0000-0000","xx1/2.0000-0000-0000","код x1/2.0000 0000 0000","карта x1/2.0000 0000 0000","xx1/2.0000 0000 0000","код x1/2.0000/0000/0000","карта x1/2.0000/0000/0000","xx1/2.0000/0000/0000","код x1/2.0000.0000.0000.0000","карта x1/2.0000.0000.0000.0000","xx1/2.0000.0000.0000.0000","код x1/0.0000-0000-0000","карта x1/0.0000-0000-0000","xx1/0.0000-0000-0000","код x1/0.0000 0000 0000","карта x1/0.0000 0000 0000","xx1/0.0000 0000 0000","код x1/0.0000/0000/0000","карта x1/0.0000/0000/0000","xx1/0.0000/0000/0000","код x1/0.0000.0000.0000.0000","карта x1/0.0000.0000.0000.0000","xx1/0.0000.0000.0000.0000","код x1 2204.4132.9947","карта x1 2204.4132.9947","xx1 2204.4132.9947","код x1 2204-4132-9947","карта x1 2204-4132-9947","xx1 2204-4132-9947","код x1 2204 4132 9947","карта x1 2204 4132 9947","xx1 2204 4132 9947","код x1 2204/4132/9947","карта x1 2204/4132/9947","xx1 2204/4132/9947","код x1 0000.0000.0000","карта x1 0000.0000.0000","xx1 0000.0000.0000","код x1 0000-0000-0000","карта x1 0000-0000-0000","xx1 0000-0000-0000","код x1 0000 0000 0000","карта x1 0000 0000 0000","xx1 0000 0000 0000","код x1 0000/0000/0000","карта x1 0000/0000/0000","xx1 0000/0000/0000","код x1 0000.0000.0000.0000","карта x1 0000.0000.0000.0000","xx1 0000.0000.0000.0000","код x1 0000-0000-0000-0000","карта x1 0000-0000-0000-0000","xx1 0000-0000-0000-0000","код x1 0000 0000 0000 0000","карта x1 0000 0000 0000 0000","xx1 0000 0000 0000 0000","код x1 0000/0000/0000/0000","карта x1 0000/0000/0000/0000","xx1 0000/0000/0000/0000","код x1 3005.0489.9258","карта x1 3005.0489.9258","xx1 3005.0489.9258","код x1 2204.4132.9947.0000","карта x1 2204.4132.9947.0000","xx1 2204.4132.9947.0000","код x1 2204-4132-9947-0000","карта x1 2204-4132-9947-0000","xx1 2204-4132-9947-0000","код x1 2204/4132/9947/0000","карта x1 2204/4132/9947/0000","xx1 2204/4132/9947/0000","код x1 2204 4132 9947 0000","карта x1 2204 4132 9947 0000","xx1 2204 4132 9947 0000","код x1 2204.4132.9947.0018","карта x1 2204.4132.9947.0018","xx1 2204.4132.9947.0018","код x1 2204-4132-9947-0018","карта x1 2204-4132-9947-0018","xx1 2204-4132-9947-0018","код x1 2204/4132/9947/0018","карта x1 2204/4132/9947/0018","xx1 2204/4132/9947/0018","код x1 0.2204.4132.9947","карта x1 0.2204.4132.9947","xx1 0.2204.4132.9947","код x1 0.0000.0000.0000","карта x1 0.0000.0000.0000","xx1 0.0000.0000.0000","код x1 2.2204.4132.9947","карта x1 2.2204.4132.9947","xx1 2.2204.4132.9947","код x1 1.2204.4132.9947","карта x1 1.2204.4132.9947","xx1 1.2204.4132.9947","код x1 2204.4132","карта x1 2204.4132","xx1 2204.4132","код x1 34567890123","карта x1 34567890123","xx1 34567890123","код x1 044525225","карта x1 044525225","xx1 044525225","код x1 220441329947","карта x1 220441329947","xx1 220441329947","код x1 300504899258","карта x1 300504899258","xx1 300504899258","код x1 0000000000","карта x1 0000000000","xx1 0000000000","код x1 000000000000","карта x1 000000000000","xx1 000000000000","код x1 2204.9947.4132.0000","карта x1 2204.9947.4132.0000","xx1 2204.9947.4132.0000","код x1 2222.2222.2222.2222","карта x1 2222.2222.2222.2222","xx1 2222.2222.2222.2222","код x1 2204.4132.9947 0000","карта x1 2204.4132.9947 0000","xx1 2204.4132.9947 0000","код x1 2204.4132.9947 0018","карта x1 2204.4132.9947 0018","xx1 2204.4132.9947 0018","код x1 2204-4132-9947 0000","карта x1 2204-4132-9947 0000","xx1 2204-4132-9947 0000","код x1 2204/4132/9947 0000","карта x1 2204/4132/9947 0000","xx1 2204/4132/9947 0000","код x1 24.82.01.43.38","карта x1 24.82.01.43.38","xx1 24.82.01.43.38","код x1 378/123/456/94","карта x1 378/123/456/94","xx1 378/123/456/94","код x1 774358.417509","карта x1 774358.417509","xx1 774358.417509","код x1 0.0.0000.0000.0000","карта x1 0.0.0000.0000.0000","xx1 0.0.0000.0000.0000","код x1 0.2.2204.4132.9947","карта x1 0.2.2204.4132.9947","xx1 0.2.2204.4132.9947","код x1 2.2.2204.4132.9947","карта x1 2.2.2204.4132.9947","xx1 2.2.2204.4132.9947","код x1 2.0.2204.4132.9947","карта x1 2.0.2204.4132.9947","xx1 2.0.2204.4132.9947","код x1 1.0.0000.0000.0000","карта x1 1.0.0000.0000.0000","xx1 1.0.0000.0000.0000","код x1 2.0000.0000.0000","карта x1 2.0000.0000.0000","xx1 2.0000.0000.0000","код x1 0.2204.4132.9947.0018","карта x1 0.2204.4132.9947.0018","xx1 0.2204.4132.9947.0018","код x1 0.2204-4132-9947-0018","карта x1 0.2204-4132-9947-0018","xx1 0.2204-4132-9947-0018","код x1 2222-2222-2222-2222","карта x1 2222-2222-2222-2222","xx1 2222-2222-2222-2222","код x1 2222 2222 2222 2222","карта x1 2222 2222 2222 2222","xx1 2222 2222 2222 2222","код x1 2222/2222/2222/2222","карта x1 2222/2222/2222/2222","xx1 2222/2222/2222/2222","код x1 1111.1111.1111.1111","карта x1 1111.1111.1111.1111","xx1 1111.1111.1111.1111","код x1 2204.4132.9947.0000.0000","карта x1 2204.4132.9947.0000.0000","xx1 2204.4132.9947.0000.0000","код x1 2204.4132.9947 1.2204.4132.9947","карта x1 2204.4132.9947 1.2204.4132.9947","xx1 2204.4132.9947 1.2204.4132.9947","код x1 2204.4132.9947 0000000000","карта x1 2204.4132.9947 0000000000","xx1 2204.4132.9947 0000000000","код x1 3005-0489-9258","карта x1 3005-0489-9258","xx1 3005-0489-9258","код x1 3005 0489 9258","карта x1 3005 0489 9258","xx1 3005 0489 9258","код x1 3005/0489/9258","карта x1 3005/0489/9258","xx1 3005/0489/9258","код x1 1000 2000 3000 4000 5000 6000","карта x1 1000 2000 3000 4000 5000 6000","xx1 1000 2000 3000 4000 5000 6000","код x1 2204.4132.9947 списка","карта x1 2204.4132.9947 списка","xx1 2204.4132.9947 списка","код x1 2204-4132-9947 список","карта x1 2204-4132-9947 список","xx1 2204-4132-9947 список","код x1 2.0000-0000-0000","карта x1 2.0000-0000-0000","xx1 2.0000-0000-0000","код x1 2.0000 0000 0000","карта x1 2.0000 0000 0000","xx1 2.0000 0000 0000","код x1 2.0000/0000/0000","карта x1 2.0000/0000/0000","xx1 2.0000/0000/0000","код x1 2.0000.0000.0000.0000","карта x1 2.0000.0000.0000.0000","xx1 2.0000.0000.0000.0000","код x1 0.0000-0000-0000","карта x1 0.0000-0000-0000","xx1 0.0000-0000-0000","код x1 0.0000 0000 0000","карта x1 0.0000 0000 0000","xx1 0.0000 0000 0000","код x1 0.0000/0000/0000","карта x1 0.0000/0000/0000","xx1 0.0000/0000/0000","код x1 0.0000.0000.0000.0000","карта x1 0.0000.0000.0000.0000","xx1 0.0000.0000.0000.0000"] {
            let hits = scan(t, &schema());
            let v: Vec<String> = hits.iter().map(|h| format!("{}|{}", h.class.as_str(), h.span.slice(t).unwrap_or_default())).collect();
            eprintln!("RES {:?} {:?}", t, v);
        }
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

    /// Форматированные номера (шаг 9, PR #80): значение + класс + **полный
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

    /// #131 word-break: косая черта и точка склеивают группы номера; спан
    /// остаётся на оригинальных байтах (контракт `OffsetMap`: «378/123/456/94»
    /// — 14 байт, канон 11 цифр). Фикстуры чексумм проверены независимой
    /// реализацией на Python до написания теста (тот же порядок, что у
    /// `separators_do_not_weaken_the_validator`).
    #[test]
    fn slash_and_dot_separators_glue_valid_numbers() {
        let schema = schema();
        let cases = [
            ("СНИЛС 378/123/456/94", "378/123/456/94", "snils"),
            (
                "карта 2204/9947/4132/0000",
                "2204/9947/4132/0000",
                "card_pan",
            ),
            (
                "карта 2204.9947.4132.0000",
                "2204.9947.4132.0000",
                "card_pan",
            ),
            (
                "карта 4575.5035.9035.2993",
                "4575.5035.9035.2993",
                "card_pan",
            ),
        ];
        for (text, gold, class) in cases {
            let hits = scan(text, &schema);
            let hit = hits
                .iter()
                .find(|h| h.class.as_str() == class)
                .unwrap_or_else(|| panic!("{text:?} не дал {class}: {hits:?}"));
            assert_eq!(hit.span.slice(text), Some(gold), "спан {text:?}");
        }
    }

    /// #131 FP-стражи word-break: даты, время, десятичные, версии и дроби
    /// точкой/косой чертой НЕ склеиваются. «12.03.1990» — две группы 2+2
    /// (равные, не 4+4 → вето); «1.2.4»/«12.5»/«04.3» — правая группа одна
    /// цифра (вето); «19/20» — канон 4 цифры, ниже кратчайшей сущности
    /// `DIGIT_SPECS`. Ожидаемое «ничего» — утверждение об отсутствии прохода
    /// валидатора (тот же класс, что `window_frames_refuse_plain_number_pairs`).
    #[test]
    fn word_break_separators_do_not_fire_on_prose_numbers() {
        let schema = schema();
        let cases = [
            "рождение 12.03.1990 в карте",
            "созвон в 12.30 завтра",
            "версия 1.2.4 собрана",
            "цена 12.50 рубля",
            "коэффициент 04.3",
            "выполнено 19/20 процентов",
            "Релиз 0.8.20 выкатили",
            "договор 622/15 от 28.03.2024",
            "Москва – Берлин, 2 – 3 человека",
            "1 000 000 рублей",
            "телефон 12.345.678-901",
            "телефон +7 900 123-45-67",
        ];
        for text in cases {
            let hits = scan(text, &schema);
            assert!(hits.is_empty(), "{text:?} дал спаны: {hits:?}");
        }
    }

    /// Ревью #138 (findings d6a34d2d): вето `dot_glues_number` обрывает прогон
    /// на ведущей группе из одной цифры, а `keep`-фильтр `num_runs` при этом
    /// хранил длинный хвост — получался **канон-суффикс без ведущей цифры**,
    /// и проходил валидатор ровно он, а не форма из текста:
    /// «1.0000.0000.0000.0000» → канон `0000000000000000` (16 нулей) проходит
    /// Луну (сумма 0 ⇒ кратно 10), при этом весь канон прогона — 17 цифр,
    /// т.е. ведущая «1» в каноне не участвует. Тот же канон у «2.»–«9.»; у
    /// «9.3005.0489.9258» суффикс валиден как ИНН-12. Правка — рамка
    /// [`MIN_LEADING_GROUP_DIGITS`]. Фикстуры ниже — промеренные FP: до правки
    /// каждая давала спан (см. рапорт ревью-раунда), после — ни одного.
    #[test]
    fn leading_single_digit_group_never_becomes_a_canonical_suffix() {
        let schema = schema();
        // Рамка [`MIN_LEADING_GROUP_DIGITS`] (#138, ревью d6a34d2d).
        // Прогон с ведущей группой из одной цифры отшивается, сканер
        // приседает на конец хвоста: суффикс не становится окном НИКОГДА,
        // рекурсия цепочек закрыта (второй прогон начинается с ведущей
        // цифры и отшивается той же рамкой). Фикстуры — промеренные FP
        // review d6a34d2d + fuzz-регрессия LUHN-форм «1+4+4+4+4».
        let cases = [
            "1.0000.0000.0000.0000",
            "2.0000.0000.0000.0000",
            "2/0000/0000/0000/0000",
            "1/0000/0000/0000/0000",
            "3/0000/0000/0000/0000",
            "1.0000.0000.0000.0000.0000",
            "1.0000.0000.0000.0000.0018",
            "9.3005.0489.9258",
            "1.2204.4132.9947",
            "1.2204/4132/9947/0000",
            "пункт 1.2204/4132/9947/0000 списка",
            "код 1.0.0000.0000.0000",
            "код 1.0.2204.4132.9947",
            // Голый прогон из одной цифры (нумерация + число): прогон из
            // одной группы, в окно не входит, вето его не сдвигает —
            // `digit_runs` берёт число как есть (ИНН-10 base-FP #102).
            "код 9.0000000000",
            "код 1.0000000000",
            "код 9.000000000000",
        ];
        for text in cases {
            let hits = scan(text, &schema);
            assert!(
                hits.is_empty(),
                "{text:?} дал спаны: {:?}",
                hits.iter()
                    .map(|h| (h.class.as_str(), h.span.slice(text), h.validator))
                    .collect::<Vec<_>>()
            );
        }
    }

    

    /// Та же рамка, что страж выше, обязана оставаться **узкой**: номера с
    /// ведущей группой из двух цифр печатаются (ИНН парами, «044525225»),
    /// и вето на ведущую цифру не имеет права их срезать.
    #[test]
    fn two_digit_leading_group_still_glues() {
        let schema = schema();
        for (text, class) in [
            ("ИНН 24.82.01.43.38", "inn"),
            ("ИНН 24/82/01/43/38", "inn"),
            ("БИК 04.4525225", "bik"),
            ("карта 2204.9947.4132.0000", "card_pan"),
            ("карта 2204/9947/4132/0000", "card_pan"),
            ("СНИЛС 378/123/456/94", "snils"),
        ] {
            let hits = scan(text, &schema);
            assert!(
                hits.iter().any(|h| h.class.as_str() == class),
                "{text:?} не дал {class}: {hits:?}"
            );
        }
    }

    /// #131 контракт `OffsetMap` на новых разделителях: точка/слэш — ASCII,
    /// ширины не двигают, но NBSP-контекст вокруг них обязан маппиться
    /// как прежде («SPAN-ширина считается по оригиналу»).
    #[test]
    fn word_break_span_maps_back_over_multibyte_context() {
        let nbsp = '\u{A0}';
        let text = format!("СНИЛС{nbsp}378/123/456/94{nbsp}в реестре");
        let hits = scan(&text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "snils")
            .unwrap_or_else(|| panic!("СНИЛС через NBSP+слэш не найден: {hits:?}"));
        assert_eq!(hit.span.slice(&text), Some("378/123/456/94"));
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
    // ── Base64-обход (PR #94) ───────────────────────────────────────────────

    /// Кодирование тестовых входов — эталонным движком (`STANDARD`/`URL_SAFE`
    /// crate `base64`), а не нашим декодером: ожидаемое не должно зависеть от
    /// проверяемого кода (AGENTS §Дисциплина фактов п.3).
    fn b64(data: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(data)
    }

    /// То же, что [`b64`], url-safe алфавитом.
    fn b64u(data: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE;
        URL_SAFE.encode(data)
    }

    /// 3 байта `fb ff ff` — единственное место алфавита, где в standard
    /// попадают `+` и `/` (`+///…`), а в url-safe — `-` и `_` (`-___…`): на них
    /// и построена пара «оба алфавита принимаем, смешанный отвергаем».
    fn probe_bytes(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xfb, 0xff, 0xff];
        v.extend_from_slice(payload);
        v
    }

    /// Base64-обход: номер в декодированной нагрузке находится, спан сидит на
    /// исходном токене, `source` = `base64_decode`, вес = вето 1.0.
    ///
    /// Значения — те же золотые, что в `golden_values_are_found` (категории
    /// спанов из `data/golden/golden-v1.jsonl`), ожидаемое не пересчитано
    /// нашим валидатором.
    #[test]
    #[allow(clippy::float_cmp)] // 1.0 — константа контракта (DeterministicW)
    fn base64_payload_numbers_are_found_on_the_token_span() {
        let cases: [(&str, &str); 6] = [
            ("ИНН 2482014338 выдан", "inn"),
            ("ИНН 825082492964 для контрагента", "inn"),
            ("СНИЛС 65707715421 в реестре", "snils"),
            ("ОГРН 7146617178591 запись", "ogrn"),
            ("ОГРНИП 313777542563312 ИП", "ogrnip"),
            ("карта 4575503590352993 на оплату", "card_pan"),
        ];
        for (payload, class) in cases {
            let token = b64(payload.as_bytes());
            let text = format!("приложение {token} конец");
            let hits = scan(&text, &schema());
            let hit = hits
                .iter()
                .find(|h| h.class.as_str() == class)
                .unwrap_or_else(|| panic!("{payload:?} в base64 не найдено: {:?}", classes(&hits)));
            assert_eq!(
                hit.span.slice(&text),
                Some(token.as_str()),
                "спан обязан покрывать исходный токен, а не декодированные байты"
            );
            assert_eq!(
                hit.source,
                DetectionSource::Base64Decode,
                "происхождение находки — декод, а не прямое чтение текста"
            );
            assert_eq!(hit.score(), 1.0, "чексумма подтверждена — вето 1.0");
        }
    }

    /// Перемычки внутри декодированной нагрузки ловит тот же оконный слой, что
    /// и в тексте (п.8 приёмки): СНИЛС 3-3-3-2, карта 4-4-4-4, ИНН парами,
    /// IBAN groups по 4 — всё в форме, напечатанной до кодирования.
    #[test]
    fn base64_payload_separators_are_caught_by_the_window_layer() {
        let cases: [(&str, &str); 4] = [
            ("СНИЛС 378-312-074 87 в реестре", "snils"),
            ("карта 2204-9947-4132-9761 на оплату", "card_pan"),
            ("ИНН 24 82 01 43 38 платёжный", "inn"),
            ("расчёт RU19 04452522540820407677025210608 спасибо", "iban"),
        ];
        for (payload, class) in cases {
            let token = b64(payload.as_bytes());
            let text = format!("приложение {token} конец");
            let hits = scan(&text, &schema());
            assert!(
                classes(&hits).contains(&class),
                "{payload:?}: ждали {class}, выпустили {:?}",
                classes(&hits)
            );
            for h in &hits {
                assert_eq!(h.source, DetectionSource::Base64Decode, "{payload:?}");
            }
        }
    }

    /// Красный гейт F-1 (ревью #94): префильтр обязан стоять ПОСЛЕ
    /// нормализации, а не на сырых байтах декода. Пара «тот же вход текстом /
    /// тот же вход токеном» на полноширинных цифрах: нормализатор сводит
    /// `U+FF10…U+FF19` к ASCII, и оба пути обязаны найти один и тот же номер.
    /// До правки пара была асимметричной: текстом находилось, токеном — пусто.
    #[test]
    fn base64_fullwidth_digits_match_the_text_path() {
        let payload = "ИНН ２４８２０１４３３８ выдан"; // scan-lang:allow
        // Нога «текстом» — базовая линия пары: тот же вход без доставки.
        let text_hits = scan(payload, &schema());
        let text_inn = text_hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .expect("текстовый путь обязан находить полноширинные цифры");
        // Нога «токеном».
        let token = b64(payload.as_bytes());
        let text = format!("приложение {token} конец");
        let b64_hits = scan(&text, &schema());
        let b64_inn = b64_hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .expect("base64-доставка обязана найти то же, что текст (ревью #94 F-1)");
        assert_eq!(b64_inn.source, DetectionSource::Base64Decode);
        assert_eq!(
            b64_inn.span.slice(&text),
            Some(token.as_str()),
            "координаты — исходный токен в байтах оригинала, не декода"
        );
        // Паритет по валидатору и весу: тот же номер, та же чексумма.
        assert_eq!(
            b64_inn.validator, text_inn.validator,
            "валидатор разъехался"
        );
        assert_eq!(b64_inn.score(), text_inn.score(), "вес разъехался");
    }

    /// Оба алфавита принимаются: standard (`+/`) и url-safe (`-_`).
    #[test]
    fn base64_both_alphabets_are_accepted() {
        let payload = probe_bytes(b" 2482014338");
        let std = b64(&payload);
        let url = b64u(&payload);
        assert!(
            std.contains('+') && std.contains('/'),
            "вход не задевает standard-хвосты алфавита: {std}"
        );
        assert!(
            url.contains('-') && url.contains('_'),
            "вход не задевает url-safe-хвосты алфавита: {url}"
        );
        for token in [std, url] {
            let text = format!("поле {token} конец");
            let hits = scan(&text, &schema());
            let hit = hits
                .iter()
                .find(|h| h.class.as_str() == "inn" && h.validator == "inn10")
                .unwrap_or_else(|| panic!("токен {token} не разобран: {:?}", classes(&hits)));
            assert_eq!(hit.span.slice(&text), Some(token.as_str()));
            assert_eq!(hit.source, DetectionSource::Base64Decode);
        }
    }

    /// Смешанный алфавит — не кандидат: один эмитент даёт один алфавит, а
    /// смесь `+` и `_` — это текст с дефисами и плюсами, а не base64.
    #[test]
    fn base64_mixed_alphabet_token_is_rejected() {
        let payload = probe_bytes(b" 2482014338");
        let std = b64(&payload);
        let mixed = std.replacen('/', "_", 1);
        assert!(
            mixed.contains('+') && mixed.contains('_'),
            "подмена не сделала токен смешанным: {mixed}"
        );
        assert!(
            !b64_shape_ok(mixed.as_bytes()),
            "смесь обязана отшиваться формой"
        );
        let text = format!("поле {mixed} конец");
        assert_eq!(
            scan(&text, &schema()),
            [] as [Hit; 0],
            "смешанный токен {mixed} раскрутился"
        );
    }

    /// Вложенность ровно один уровень: `base64(base64(ИНН))` не раскручивается.
    #[test]
    fn base64_nesting_is_exactly_one_level() {
        let inner = b64("ИНН 2482014338 выдан".as_bytes());
        // Позитивный контроль: один уровень находится, значит пустой результат
        // ниже — следствие правила, а не сломанного декодера.
        let one = format!("поле {inner} конец");
        assert!(
            classes(&scan(&one, &schema())).contains(&"inn"),
            "первый уровень обязан находиться: {inner}"
        );
        let outer = b64(inner.as_bytes());
        let two = format!("поле {outer} конец");
        assert_eq!(
            scan(&two, &schema()),
            [] as [Hit; 0],
            "второй уровень раскручен — рекурсии быть не должно"
        );
    }

    /// Координаты — оригинальные байты текста: нормализация (NBSP вокруг
    /// токена) двигает карту, спан обязан указывать на токен в оригинале.
    #[test]
    fn base64_span_sits_on_original_bytes() {
        let token = b64("СНИЛС 65707715421 в реестре".as_bytes());
        let text = format!("СНИЛС\u{A0}{token}\u{A0}конец");
        let hits = scan(&text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "snils")
            .expect("СНИЛС в base64 находится");
        assert_eq!(hit.span.slice(&text), Some(token.as_str()));
        let at = text.find(&token).expect("токен в тексте");
        assert_eq!(hit.span.start, at, "левый край спана = левый край токена");
        assert_eq!(
            hit.span.end,
            at + token.len(),
            "правый край = правый край токена"
        );
    }

    /// Негативы (п.4 приёмки, анти-паттерн «decode и верь»). Ожидаемое «пусто»
    /// — утверждение об отсутствии подтверждения валидатором (или об отказе
    /// формы/границы), а не о том, что декод не запустился: у части входов декод
    /// проходит, и спана нет именно потому, что чексумма не сошлась.
    #[test]
    fn base64_negative_registry() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let cases: Vec<(String, &str)> = vec![
            // JWT целиком: сегменты склеены точкой, ни один не на границе.
            (jwt.to_owned(), "JWT (сегменты через точку)"),
            // Первый сегмент один на пробельной границе: декод
            // `{"alg":"HS256","typ":"JWT"}`, цифра одна — «256», 3 < minLength 9.
            (
                "шапка eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 конец".to_owned(),
                "JWT-шапка (кандидат, цифр на номер нет)",
            ),
            // Payload того же JWT с паддингом: декодируется в
            // `{"sub":"1234567890"}`, 10 цифр изолированы — ИНН 1234567890
            // невалиден (промер по §1 первички), спана нет.
            (
                "токен eyJzdWIiOiIxMjM0NTY3ODkwIn0= конец".to_owned(),
                "JWT payload: 10 цифр с невалидной чексуммой",
            ),
            // Payload без паддинга: длина 27 не кратна 4 — не кандидат.
            (
                "токен eyJzdWIiOiIxMjM0NTY3ODkwIn0 конец".to_owned(),
                "JWT payload без паддинга (длина не кратна 4)",
            ),
            // base64 utf-8 текста без цифр.
            (b64("Привет, мир! 👋🙂".as_bytes()), "utf-8 текст без цифр"),
            (b64("😀😀😀😀😀😀😀😀😀😀".as_bytes()), "эмодзи"),
            // Чистая бинарность: 16 и 18 байт, ASCII-цифр в нагрузке нет.
            (
                "blob AAAAAAAAAAAAAAAAAAAAAAAA конец".to_owned(),
                "18 байт нулей",
            ),
            ("blob //////////////////// конец".to_owned(), "15 байт 0xFF"),
            (
                "blob Rm9sbG93IG1lIG5vdyEhISEh конец".to_owned(),
                "ASCII-16 без цифр",
            ),
            (
                "blob aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ= конец".to_owned(),
                "ASCII-23 без цифр",
            ),
            // hex-дамп: алфавит base64, длина кратна 4, декод — 24 байта мусора.
            (
                "sha 0123456789abcdef0123456789abcdef конец".to_owned(),
                "hex-дамп 32 символа",
            ),
            // Чистая случайность 16 байт (фиксированный набор, не ГПСЧ: цифра
            // в отчёте обязана быть воспроизводимой).
            (
                "blob Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OQ== конец".to_owned(),
                "ASCII-22: 9 цифр, BIK-структура не проходит",
            ),
            // Нагрузка ровно 10 байт — ниже пола 11 (документированный FN).
            (b64(b"2482014338"), "ИНН без обрамления (пол 11 байт)"),
            // Отрицательные векторы reference-vectors.tsv, завёрнутые в base64.
            (
                b64("номер 1110005080 в карточке".as_bytes()),
                "invalid inn10 (§1 первички)",
            ),
            (
                b64("номер 7743880976 в карточке".as_bytes()),
                "invalid inn10 (§1 первички)",
            ),
            (
                b64("карта 4575503590352994 на оплату".as_bytes()),
                "invalid luhn (карта из golden с последней цифрой +1)",
            ),
            // Цифры прижаты к буквам внутри нагрузки: окно не изолировано
            // (то же правило, что в тексте, `glued_digits_are_not_numbers`).
            (b64(b"sha256=2482014338abc"), "склейка с хэшем"),
            // Наш собственный маркер обратимости: base64url внутри `[[F0#…]]`
            // не ограничен пробелом. Маскировать токен прокси значило бы ломать
            // deanonymize (#60).
            (
                "[[F0#Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OQ]]".to_owned(),
                "маркер vault (граница не пробельная)",
            ),
        ];
        for (text, what) in cases {
            let hits = scan(&text, &schema());
            assert!(hits.is_empty(), "{what}: {text:?} дал {hits:?}");
        }
    }

    /// Пол по нагрузке работает в обе стороны: те же 10 цифр находятся, как
    /// только появляется обрамление (нагрузка ≥ 11 байт).
    #[test]
    fn base64_payload_floor_is_the_documented_tradeoff() {
        let bare = b64(b"2482014338");
        assert_eq!(
            bare.len(),
            16,
            "промер: 10-байтная нагрузка кодируется в 16 символов"
        );
        assert_eq!(
            scan(format!("поле {bare} конец").as_str(), &schema()),
            [] as [Hit; 0],
            "нагрузка 10 байт — ниже пола 11, обход обязан промолчать"
        );
        let framed = b64("ИНН 2482014338".as_bytes());
        assert!(
            classes(&scan(format!("поле {framed} конец").as_str(), &schema())).contains(&"inn"),
            "10 цифр + обрамление = нагрузка 17 байт — находится"
        );
    }

    /// Форма кандидата: длина кратна 4 и не короче 16, `=` только хвостом
    /// (≤ 2), алфавит в токене не смешан.
    #[test]
    fn base64_candidate_shape_rules() {
        assert!(b64_shape_ok(b"MjQ4MjAxNDMzOCB2"), "16 символов канона");
        assert!(!b64_shape_ok(b"MjQ4MjAxNDMzOB2"), "15: длина не кратна 4");
        assert!(!b64_shape_ok(b"MjQ4=MjAxNDMzOB2"), " паддинг в середине");
        assert!(!b64_shape_ok(b"MjQ4MjAxNDMz+==="), "три байта паддинга");
        assert!(!b64_shape_ok(b"QUJD"), "короче порога 16");
        assert!(!b64_shape_ok(b"-///MjQ4MjAxNDMzOA=="), "смешанный алфавит");
        assert!(b64_shape_ok(b"+///MjQ4MjAxNDMzOA=="), "standard целиком");
        assert!(b64_shape_ok(b"-___IDI0ODIwMTQzMzg="), "url-safe целиком");
    }

    /// Граница кандидата обязана быть пробельной: прижатые к буквам и пунктуации
    /// base64-цепочки — это поля формата (URL, `data:`-mime, `sha256=`), а не
    /// вставка пользователя.
    #[test]
    fn base64_candidate_needs_whitespace_boundaries() {
        let token = b64("ИНН 2482014338 выдан".as_bytes());
        for (text, why) in [
            (format!("x{token} "), "прижат слева буквой"),
            (format!(" {token}y"), "прижат справа буквой"),
            (format!(" {token}, конец"), "запятая справа"),
            (format!("данные:base64,{token} "), "mime-префикс"),
        ] {
            assert!(
                b64_tokens(text.as_bytes()).is_empty(),
                "{why}: {text:?} принят кандидатом"
            );
        }
        assert_eq!(
            b64_tokens(format!(" {token} ").as_bytes()).len(),
            1,
            "пробел с двух сторон"
        );
        assert_eq!(
            b64_tokens(format!("{token}\nконец").as_bytes()).len(),
            1,
            "НФ и край текста — границы"
        );
    }

    /// Обход уважает схему: выключенный класс не приходит и из нагрузки.
    #[test]
    fn base64_respects_the_schema() {
        let token = b64("расчёт RU1904452522540820407677025210608 спасибо".as_bytes());
        let text = format!("поле {token} конец");
        let mut s = schema();
        s.validator_only.retain(|c| c.id != "iban");
        assert!(
            !classes(&scan(&text, &s)).contains(&"iban"),
            "iban выключен"
        );
        assert!(
            classes(&scan(&text, &schema())).contains(&"iban"),
            "схема с iban находит нагрузку"
        );
    }

    /// Один токен с двумя номерами даёт два хита на один спан (вектор классов,
    /// SPEC §8), а не «победителя».
    #[test]
    fn base64_one_token_two_numbers_is_a_vector() {
        let token = b64("ИНН 2482014338 и СНИЛС 65707715421".as_bytes());
        let text = format!("приложение {token} конец");
        let hits = scan(&text, &schema());
        let on_token: Vec<&Hit> = hits
            .iter()
            .filter(|h| h.span.slice(&text) == Some(token.as_str()))
            .collect();
        let cls: Vec<&str> = on_token.iter().map(|h| h.class.as_str()).collect();
        assert!(cls.contains(&"inn") && cls.contains(&"snils"), "{cls:?}");
        for h in &on_token {
            assert_eq!(h.source, DetectionSource::Base64Decode);
        }
    }

    /// Открытый текст и base64-нагрузка в одном запросе: оба источника живут,
    /// `source` различается, координаты не пересекаются.
    #[test]
    fn base64_and_plain_findings_coexist() {
        let token = b64("СНИЛС 65707715421 в реестре".as_bytes());
        let text = format!("ИНН 2482014338 и {token}");
        let hits = scan(&text, &schema());
        let inn = hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .expect("открытый ИНН");
        let snils = hits
            .iter()
            .find(|h| h.class.as_str() == "snils")
            .expect("СНИЛС в нагрузке");
        assert_eq!(inn.source, DetectionSource::ChecksumRf);
        assert_eq!(snils.source, DetectionSource::Base64Decode);
        assert_eq!(snils.span.slice(&text), Some(token.as_str()));
        assert!(
            inn.span.end <= snils.span.start,
            "спан открытого номера залез в токен: {inn:?} {snils:?}"
        );
    }

    /// Микромера горячего пути (п.7 приёмки).
    ///
    /// Метод: корпус = проза до 10 `КиБ` + 100 base64-blob по 33 байта
    /// (псевдослучайных, xorshift64 с семенем 0x5EED — корпус воспроизводим,
    /// фактическая длина печатается); 500 прогонов на ногу; считаем **минимум**
    /// и медиану (минимум — статистика микромера на шуме ноутбука); профиль
    /// `release`, `--test-threads=2`, `nice -n 10`, TMPDIR=/tmp, один прогон.
    ///
    /// Нога «до» = тот же бинарь с выключенным проходом (`scan_with(.., false)`:
    /// код трёх оконных проходов не менялся), нога «после» = `scan`.
    ///
    /// Запуск (`--lib` обязателен: без него cargo берёт integration-таргеты
    /// crate, а они на этом дереве требуют монтирования каскадов — `E0432` на
    /// `install_test_mount`, промер ревью #94 F-5; микромера про lib-код):
    /// `cargo test --release -p guard-daemon --lib base64_bypass_hot_path -- --ignored --test-threads=2 --nocapture`
    #[test]
    #[ignore = "микромера, не регресс: печать B64MICRO; требует release и щадящего режима"]
    fn base64_bypass_hot_path_microbench() {
        use std::time::Instant;

        let schema = schema();
        // Два корпуса: плотный (100 blob на 10 КиБ — худший случай, половина
        // тела кандидаты) и разреженный (2 blob — форма реального запроса).
        for blobs in [100usize, 2] {
            let (text, _) = b64_corpus(blobs);
            let tokens = b64_tokens(text.as_bytes()).len();
            println!(
                "B64MICRO|blobs|{blobs}|bytes|{}|candidates|{tokens}|iters|500",
                text.len()
            );
            let mut mins = Vec::new();
            for (label, with_base64) in [("before", false), ("after", true)] {
                let mut samples = Vec::with_capacity(500);
                let mut found = 0usize;
                for _ in 0..500 {
                    let t = Instant::now();
                    found = scan_with(&text, &schema, with_base64).len();
                    samples.push(t.elapsed().as_micros());
                }
                samples.sort_unstable();
                println!(
                    "B64MICRO|blobs|{blobs}|{label}|min_us|{}|median_us|{}|hits|{found}",
                    samples[0],
                    samples[samples.len() / 2]
                );
                mins.push(samples[0]);
                std::hint::black_box(&samples);
            }
            assert!(tokens > 0, "корпус без кандидатов — мера бессмысленна");
            assert!(
                mins[1] >= mins[0],
                "нога «после» быстрее «до»: мера недостоверна ({} < {})",
                mins[1],
                mins[0]
            );
        }
    }

    /// Корпус микромеры: `n` base64-blob'ов из псевдослучайных байт, вклеенных
    /// в русскоязычную прозу. ГПСЧ — xorshift64 с фиксированным семенем: число
    /// в отчёте обязано быть воспроизводимым, а не случайным.
    fn b64_corpus(n: usize) -> (String, usize) {
        use base64::engine::general_purpose::STANDARD;
        let prose =
            "Согласно договору поставки счёт выставлен сторонам, акт приёмки подписан директором. ";
        let mut text = String::new();
        let mut state: u64 = 0x5EED;
        for i in 0..n {
            while text.len() < (10_240 / n) * (i + 1) {
                text.push_str(prose);
            }
            let mut blob = Vec::with_capacity(33);
            for _ in 0..33 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                blob.push((state & 0xff) as u8);
            }
            text.push(' ');
            text.push_str(&STANDARD.encode(&blob));
            text.push(' ');
        }
        (text, n)
    }

    // --- Числительные словами (атом #51 п.2) --------------------------------
    //
    // Значения номеров взяты из `data/golden/golden-v1.jsonl` (колонка значения,
    // класс — из категории спана), а не пересчитаны нашим валидатором (AGENTS
    // §Дисциплина фактов п.3). Словоформа числа задана арифметикой разрядов,
    // она в комментарии к каждому case.

    /// Живая связь порога с таблицей длин: укоротят валидатор до 8 цифр —
    /// тест покраснеет и напомнит, что года словами тоже поедут валидироваться.
    #[test]
    fn spelled_floor_is_the_shortest_digit_spec() {
        let shortest = DIGIT_SPECS
            .iter()
            .map(|s| s.min)
            .min()
            .unwrap_or(usize::MAX);
        assert_eq!(
            shortest, MIN_SPELLED_DIGITS,
            "`DIGIT_SPECS` коротче ({shortest}) порога словесного слоя ({MIN_SPELLED_DIGITS}): года словами начнут кредитоваться"
        );
    }

    /// Guard года словами: четыре цифры подтвердить некому.
    #[test]
    fn year_in_words_is_not_a_hit() {
        let cases = [
            "Клиент 1971 года, тысяча девятьсот семьдесят один в анкете",
            "Год рождения: тысяча девятьсот семьдесят один",
            "призван тысяча девятьсот семьдесят первый год",
            "пятьдесят первый, тысяча девятьсот восемьдесят",
        ];
        for text in cases {
            let hits = scan(text, &schema());
            assert!(
                hits.is_empty(),
                "{text:?} дал {:?} (года словами)",
                classes(&hits)
            );
        }
    }

    /// Золотой ИНН-12 словами: класс, валидатор и **спан на всю фразу**.
    #[test]
    fn spelled_inn12_fires_with_the_phrase_as_span() {
        // 825·10⁹ + 82·10⁶ + 492·10³ + 964 = 825082492964 (golden, inn).
        let words = "восемьсот двадцать пять миллиардов восемьдесят два миллиона \
                     четыреста девяносто две тысячи девятьсот шестьдесят четыре";
        let text = format!("ИНН контрагента: {words}, просим проверить");
        let hits = scan(&text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .unwrap_or_else(|| panic!("{text:?} дал {:?}", classes(&hits)));
        assert_eq!(hit.validator, "inn12");
        assert_eq!(
            hit.source,
            DetectionSource::ChecksumRf,
            "подтверждение — чексумма, новый источник словесному слою не заведён"
        );
        assert_eq!(hit.span.slice(&text), Some(words));
    }

    /// Золотая карта словами: 16 цифр собираются вложенным масштабом
    /// («тысячи … триллионов»), Луна подтверждает.
    #[test]
    fn spelled_card_pan_passes_luhn() {
        // (4·10³ + 575)·10¹² + 503·10⁹ + 590·10⁶ + 352·10³ + 993
        // = 4575503590352993 (golden, card_pan).
        let words = "четыре тысячи пятьсот семьдесят пять триллионов пятьсот три \
                     миллиарда пятьсот девяносто миллионов триста пятьдесят две \
                     тысячи девятьсот девяносто три";
        let text = format!("карта {words} на оплату");
        let hits = scan(&text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "card_pan")
            .unwrap_or_else(|| panic!("{text:?} дал {:?}", classes(&hits)));
        assert_eq!(hit.validator, "luhn");
        assert_eq!(hit.span.slice(&text), Some(words));
    }

    /// Реестровые номера словами: СНИЛС, ИНН-10, ОГРН, ОГРНИП (значения из
    /// golden-v1.jsonl, те же, что в `golden_values_are_found`).
    #[test]
    fn spelled_registry_numbers_fire() {
        let cases: [(&str, &str, &str); 4] = [
            // 65·10⁹ + 707·10⁶ + 715·10³ + 421 = 65707715421.
            (
                "snils",
                "шестьдесят пять миллиардов семьсот семь миллионов семьсот \
                 пятнадцать тысяч четыреста двадцать один",
                "snils",
            ),
            // 2·10⁹ + 482·10⁶ + 14·10³ + 338 = 2482014338.
            (
                "inn",
                "два миллиарда четыреста восемьдесят два миллиона четырнадцать \
                 тысяч триста тридцать восемь",
                "inn",
            ),
            // 7·10¹² + 146·10⁹ + 617·10⁶ + 178·10³ + 591 = 7146617178591.
            (
                "ogrn",
                "семь триллионов сто сорок шесть миллиардов шестьсот семнадцать \
                 миллионов сто семьдесят восемь тысяч пятьсот девяносто один",
                "ogrn",
            ),
            // 313·10¹² + 777·10⁹ + 542·10⁶ + 563·10³ + 312 = 313777542563312.
            (
                "ogrnip",
                "триста тринадцать триллионов семьсот семьдесят семь миллиардов \
                 пятьсот сорок два миллиона пятьсот шестьдесят три тысячи триста \
                 двенадцать",
                "ogrnip",
            ),
        ];
        for (class, words, label) in cases {
            let text = format!("реквизиты: {words} в реестре");
            let hits = scan(&text, &schema());
            assert!(
                classes(&hits).contains(&class),
                "{label} словами дал {:?}, ждали {class}",
                classes(&hits)
            );
            let hit = hits
                .iter()
                .find(|h| h.class.as_str() == class)
                .expect("хит класса");
            assert_eq!(hit.span.slice(&text), Some(words), "спан {label}");
        }
    }

    /// Спан словесного номера возвращается на **оригинальные** байты:
    /// неразрывные пробелы внутри фразы нормализатор сводит к обычным, а
    /// координаты остаются ширины оригинала (тот же контур, что у #94).
    #[test]
    fn spelled_span_survives_normalization() {
        let nbsp = '\u{A0}';
        // 825·10⁹ + 82·10⁶ + 492·10³ + 964 = 825082492964 (golden, inn).
        let words = format!(
            "восемьсот{nbsp}двадцать{nbsp}пять{nbsp}миллиардов{nbsp}восемьдесят{nbsp}два\
             {nbsp}миллиона{nbsp}четыреста{nbsp}девяносто{nbsp}две{nbsp}тысячи{nbsp}девятьсот\
             {nbsp}шестьдесят{nbsp}четыре"
        );
        let text = format!("ИНН: {words}");
        let hits = scan(&text, &schema());
        let hit = hits
            .iter()
            .find(|h| h.class.as_str() == "inn")
            .unwrap_or_else(|| panic!("{text:?} дал {:?}", classes(&hits)));
        assert_eq!(
            hit.span.slice(&text),
            Some(words.as_str()),
            "спан словесного номера не доезжает до оригинальной ширины"
        );
    }

    /// Слова подчиняются схеме: подтверждать некому — находки нет.
    #[test]
    fn spelled_hits_respect_the_schema() {
        // 825·10⁹ + 82·10⁶ + 492·10³ + 964 = 825082492964 (golden, inn).
        let words = "восемьсот двадцать пять миллиардов восемьдесят два миллиона \
                     четыреста девяносто две тысячи девятьсот шестьдесят четыре";
        let text = format!("ИНН: {words}");
        let only_inn12 = Schema::parse(
            r#"{"version":1,"classes":[],"validator_only":[{"id":"inn","label":"ИНН","validators":["inn12"]}]}"#,
        )
        .expect("минимальная схема");
        assert_eq!(classes(&scan(&text, &only_inn12)), ["inn"]);
        let only_ogrn = Schema::parse(
            r#"{"version":1,"classes":[],"validator_only":[{"id":"ogrn","label":"ОГРН","validators":["ogrn13"]}]}"#,
        )
        .expect("минимальная схема");
        assert!(
            scan(&text, &only_ogrn).is_empty(),
            "ИНН словами утёк в схему без класса inn"
        );
    }

    /// Слова и цифры живут в одном проходе: обе находки на своих спанах.
    #[test]
    fn spelled_and_plain_numbers_coexist() {
        // 2·10⁹ + 482·10⁶ + 14·10³ + 338 = 2482014338 (golden, inn).
        let words = "восемьсот двадцать пять миллиардов восемьдесят два миллиона \
                     четыреста девяносто две тысячи девятьсот шестьдесят четыре";
        let text = format!("ИНН 2482014338 и {words}");
        let hits = scan(&text, &schema());
        let inns: Vec<&Hit> = hits.iter().filter(|h| h.class.as_str() == "inn").collect();
        assert_eq!(inns.len(), 2, "оба ИНН: {hits:?}");
        assert_eq!(inns[0].span.slice(&text), Some("2482014338"));
        assert_eq!(inns[1].span.slice(&text), Some(words));
        for h in &inns {
            assert_eq!(h.source, DetectionSource::ChecksumRf);
        }
    }

    /// Диктовка «цифра за цифрой» словами не склеивается: 1, 2, 3… — короткие
    /// числа, до валидаторов не едут (п.5 не-покрытия в `numwords`).
    #[test]
    fn digit_by_digit_dictation_is_not_a_hit() {
        let text = "продиктуйте код: один два три четыре пять шесть семь восемь \
                    девять десять одиннадцать двенадцать тринадцать четырнадцать";
        let hits = scan(text, &schema());
        assert!(
            hits.is_empty(),
            "диктовка словами склеилась: {:?}",
            classes(&hits)
        );
    }

    /// Задокументированная цена слоя (пара к
    /// `base64_payload_floor_is_the_documented_tradeoff`): круглые количества
    /// вида N·10⁹ — десятизначные числа, а mod-11 у ИНН на них часто даёт
    /// контрольную 0. «Пять миллиардов» = 5000000000: взвешенная сумма
    /// 5·2 = 10, (10 mod 11) mod 10 = 0 = последняя цифра → ИНН подтверждён.
    /// FP дёшев (обратимое маскирование, SPEC §2), FN фатален, поэтому слой
    /// круглые числа не отфильтровывает — это осознанный обмен, а не oversight.
    #[test]
    fn spelled_round_billion_is_the_documented_tradeoff() {
        let hits = scan("перевести пять миллиардов рублей", &schema());
        assert_eq!(
            classes(&hits),
            ["inn"],
            "круглое количество словами дало не то, что задокументировано"
        );
        assert_eq!(hits[0].validator, "inn10");
        // А «пять тысяч» (4 цифры) до валидаторов не доезжает: порог работает.
        let thin = scan("перевести пять тысяч рублей", &schema());
        assert_eq!(
            classes(&thin),
            Vec::<&str>::new(),
            "короткое слово-число проскочило MIN_SPELLED_DIGITS"
        );
    }

    /// Числительные внутри base64-нагрузки не ищем: вложенность обходов ровно
    /// один уровень (паритет с `base64_nesting_is_exactly_one_level`).
    #[test]
    fn words_inside_base64_are_not_scanned() {
        // 825·10⁹ + 82·10⁶ + 492·10³ + 964 = 825082492964 (golden, inn).
        let words = "восемьсот двадцать пять миллиардов восемьдесят два миллиона \
                     четыреста девяносто две тысячи девятьсот шестьдесят четыре";
        let token = b64(words.as_bytes());
        let text = format!("приложение {token}");
        let hits = scan(&text, &schema());
        assert!(
            hits.is_empty(),
            "слова в нагрузке раскрутились: {:?}",
            classes(&hits)
        );
    }

    /// Микромера слоя числительных (метод — как у
    /// `base64_bypass_hot_path_microbench`).
    ///
    /// Корпус: та же проза, что в `b64_corpus`, до 10 `КиБ`; вторая нога — тот
    /// же корпус с одним словесным номером. Меряется **сам слой**
    /// (`numwords::spelled_numbers`), а не `scan`: рычага «выключить слова» в
    /// `scan_with` нет (он в обеих ногах base64-замера, его дельта от слоя не
    /// зависит). Минимум и медиана из 500 прогонов.
    ///
    /// Утверждение — регрессия по верхней границе: слой на 10 `КиБ` обязан
    /// укладываться в 2 мс (бюджет каскада 0 — <1 мс, 10 `КиБ` — худший случай
    /// запроса; порядок, а не бенчмарк).
    ///
    /// Запуск: `cargo test --release -p guard-daemon --lib words_hot_path -- --ignored --test-threads=2 --nocapture`
    /// (под `GO`, release-прогон).
    #[test]
    #[ignore = "микромера, не регресс: печать WORDMICRO; требует release и щадящего режима"]
    fn words_hot_path_microbench() {
        use std::time::Instant;

        let prose =
            "Согласно договору поставки счёт выставлен сторонам, акт приёмки подписан директором. ";
        let number = " восемьсот двадцать пять миллиардов восемьдесят два миллиона \
                      четыреста девяносто две тысячи девятьсот шестьдесят четыре ";
        for (label, tail) in [("prose", ""), ("prose+number", number)] {
            let mut text = String::new();
            while text.len() < 10_240 {
                text.push_str(prose);
            }
            text.push_str(tail);
            let mut samples = Vec::with_capacity(500);
            let mut found = 0usize;
            for _ in 0..500 {
                let t = Instant::now();
                found = crate::numwords::spelled_numbers(&text).len();
                samples.push(t.elapsed().as_micros());
            }
            samples.sort_unstable();
            println!(
                "WORDMICRO|{label}|bytes|{}|found|{found}|iters|500|min_us|{}|median_us|{}",
                text.len(),
                samples[0],
                samples[samples.len() / 2]
            );
            assert!(
                samples[0] < 2_000,
                "слой слов на 10 КиБ стоил {} мкс — бюджет каскада 0 сломан",
                samples[0]
            );
            std::hint::black_box(&samples);
        }
    }
}
