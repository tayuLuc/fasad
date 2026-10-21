//! Гейт `restoration-integrity` (#60 п.3, монтаж — issue #134): целостность
//! разворота на уровне продукта, измеряемая **одной командой**.
//!
//! ```text
//! cargo run -p guard-daemon --example restore_probe
//! ```
//!
//! # Чем этот харнес НЕ является
//!
//! Он не повторяет `guard-vault/examples/pool_probe.rs -- integrity`. Тот промер
//! считает профиль коллизий пула суррогатов: поштучную выдачу формы токену
//! (`surrogat_for_gender`) и её индивидуальный разворот (`original_of_surrogat`),
//! в обход грамматики, реестра форм демона и суррогат-пачки. Здесь путь другой:
//! `Vault::anonymize → Vault::deanonymize` — ровно тот код, который вызывают
//! `POST /v1/anonymize` и `POST /v1/deanonymize`. Это единственный уровень, на
//! котором вообще существует то, что меряет #60 п.3: разворот **мультиымянного
//! документа** целиком, а не набор отдельных имён.
//!
//! # Почему фикстуры in-process, а не `data/golden/`
//!
//! 204 golden-текста сюда не читаются: ногу зовёт CI, а чтение датасета по
//! относительному пути краснит прогон на раннере с другим working directory и
//! молча мерит ноль там, где файл не нашёлся. Плюс побайтовая сверка датасета —
//! уже закрытый гейт (`just golden-verify`, SHA-константа B2 в
//! `tests/golden_v1.rs`): привязывать к нему второй независимый смысл значит
//! копить связь. Фикстуры живут здесь, в тексте, и покрывают **формы входа**, а
//! не объём: кириллица, base64, ФИО в падежах, числа словами, спан ровно на
//! потолке `MAX_ORIGINAL_BYTES` и за ним.
//!
//! # Контракт stdout
//!
//! ```text
//! RESTORE|verdict|ok|roundtrips|<k>|spans|<n>|skips|<s>|failures|0|modes|2|session|stateless|
//! RESTORE|mode|<mode>|roundtrips|<k>|spans|<n>|skips|<s>|surrogate_roundtrips|<s>|failures|<f>|
//! RESTORE|case|<mode>|<round>|ok|spans|<n>|surrogate|<0|1>|
//! RESTORE|counter|mismatch|<n>|fallbacks|<n>|
//! ```
//!
//! `--echo` печатает per-case строки (человеческий промер), без него — только
//! mode/counter/verdict (то, что жрёт `grep`). Строка вердикта собирается из
//! ФАКТИЧЕСКИХ счётчиков прогона, не из шаблона: литерал `verdict|ok` был бы
//! ложно-зелёным того же класса, что `thr|0.25` в `recall_golden` (ревью #60 —
//! вердикт обязан эхо-печатать фактическое).
//!
//! rc: `0` = ноль отказов и ноль расхождений; `1` = целостность нарушена;
//! `2` = харнес не смогла измерить (пустой корпус, хранилище не поднялось) —
//! «не измерено» и «измерено чисто» обязаны различаться кодом, как в `lang-scan`.
//! Тот же контракт ассертами проверяется в `cargo test` (пары
//! `crates/guard-daemon/tests/restore_integrity.rs` и `mod tests` ниже).

// Харнес-промер, не prod: паника здесь и есть отказ гейта, тот же канал, что у
// assert'ов в тестах.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "measurement-харнес (example), не prod-код: expect = отказ гейта"
)]

use guard_daemon::config::{Config, Mlock, VaultMode};
use guard_daemon::schema::Schema;
use guard_daemon::vault::{Anonymized, OP_REPLACE, SpanIn, Vault};

/// Верхняя граница оригинала спана — из продукта, не из литерала: сдвинутый
/// потолок обязан двигать фикстуры за собой, иначе нога «на границе» протухнет
/// молча.
const CAP: usize = guard_vault::token::MAX_ORIGINAL_BYTES;

/// Контрольный байт «masked-текст изуродован правкой»: в фикстурах его нет,
/// поэтому он в развёрнутом тексте всегда означает дефект.
const CUT: char = '\u{1}';

/// Один случай round-trip: текст, подстроки, обязанные быть спанами, и флаг
/// «спан за потолком» (такой маскируется отказом — см. `over_cap`).
struct CaseOwned {
    /// Идентификатор для строк `RESTORE|case|…` и для диагностических сообщений.
    id: &'static str,
    /// Текст целиком.
    text: String,
    /// Подстроки, которые обязываются быть спанами (ищутся в `text`).
    needles: Vec<String>,
    /// Спан обязан быть длиннее потолка: отказ маскирования — запланированный,
    /// он считается `skip`, а не провалом.
    over_cap: bool,
}

/// Случай, объявленный статически (текст — `&'static str`, convenience).
#[derive(Clone, Copy)]
struct Case {
    id: &'static str,
    text: &'static str,
    needles: &'static [&'static str],
    over_cap: bool,
}

impl Case {
    fn owned(self) -> CaseOwned {
        CaseOwned {
            id: self.id,
            text: self.text.to_owned(),
            needles: self.needles.iter().map(|s| (*s).to_owned()).collect(),
            over_cap: self.over_cap,
        }
    }
}

/// Фикстуры. Каждая — про ФОРМУ входа, а не про объём. Набор закрыт этим
/// списком, и он же есть покрытие гейта (реестр ложно-зелёных, «гейт,
/// скоупнутый автором»: расширять список, когда появляется новая форма).
const CASES: &[Case] = &[
    // Кириллица, ФИО в именительном: единственный класс, который в режиме 2
    // идёт суррогатом, а не меткой.
    Case {
        id: "fio-nom",
        text: "Смирнова Агафья Пименовна принята на работу.",
        needles: &["Смирнова Агафья Пименовна"],
        over_cap: false,
    },
    // Многосоставный документ: четыре ФИО в одном тексте — то, ради чего затевался
    // #60 п.3 (одиночное имя ловилось и до реверс-индекса).
    Case {
        id: "multi-name-doc",
        text: "Подписали: Тенин Аркадий Лукич, Тенина Агафья Пименовна, \
               Ушакова Кира Саввична, Гудзовский Парфен Назарович.",
        needles: &[
            "Тенин Аркадий Лукич",
            "Тенина Агафья Пименовна",
            "Ушакова Кира Саввична",
            "Гудзовский Парфен Назарович",
        ],
        over_cap: false,
    },
    // Тот же класс, что выше, но НЕ в именительном падеже: падеж меняет
    // surface-форму суррогата на выдаче, а разворот обязан вернуть исходную
    // форму слова побайтово.
    Case {
        id: "fio-cases",
        text: "Вручено: Тенину Аркадию Лукичу, Ушаковой Кире Саввичне, \
               Гудзовскому Парфену Назаровичу.",
        needles: &[
            "Тенину Аркадию Лукичу",
            "Ушаковой Кире Саввичне",
            "Гудзовскому Парфену Назаровичу",
        ],
        over_cap: false,
    },
    // Base64 в masked-тексте (PR #94): алфавит base64 пересекается с алфавитом
    // тела маркера режима 3, и разворот обязан остаться побайтовым, включая `+`,
    // `/` и паддинги `=`.
    Case {
        id: "base64-blob",
        text: "Приложение (base64): SGVsbG8g0JDQmtCQ0LDQudC5INCk0LXRgtGB0Yw= и ещё QQ==.",
        needles: &["SGVsbG8g0JDQmtCQ0LDQudC5INCk0LXRgtGB0Yw=", "QQ=="],
        over_cap: false,
    },
    // Числа словами (слой #118): фраза целиком уходит в токен. Под потолком
    // (29 Б) — маскируется, разворот побайтовый.
    Case {
        id: "spelled-under-cap",
        text: "Ожидаемая выручка: пять миллиардов рублей.",
        needles: &["пять миллиардов"],
        over_cap: false,
    },
    // Та же форма входа ЗА потолком (ИНН-12 словами, 223 Б): masking отказывает
    // по `span_too_long` (#120), и это запланированный skip, а не провал.
    Case {
        id: "spelled-over-cap",
        text: "ИНН контрагента: восемьсот двадцать пять миллиардов восемьдесят два \
               миллиона четыреста девяносто две тысячи девятьсот шестьдесят четыре, \
               просим проверить.",
        needles: &[
            "восемьсот двадцать пять миллиардов восемьдесят два миллиона четыреста \
             девяносто две тысячи девятьсот шестьдесят четыре",
        ],
        over_cap: true,
    },
    // Смешанный документ: ФИО + реквизиты + адрес в одном проходе, классы
    // разные (класс назначается по содержимому иглы, `class_for`).
    Case {
        id: "mixed-doc",
        text: "Клиент: Тенин Аркадий Лукич; ИНН 2482014338; e-mail ivan@example.ru; \
               адрес: г. Екатеринбург, улица Октябрьской Революции, дом 71.",
        needles: &[
            "Тенин Аркадий Лукич",
            "2482014338",
            "ivan@example.ru",
            "г. Екатеринбург, улица Октябрьской Революции, дом 71",
        ],
        over_cap: false,
    },
];

/// Владеющие случаи на границах потолка: длины собраны из [`CAP`], а не из
/// литерала, поэтому подъём `MAX_ORIGINAL_BYTES` двигает фикстуру за собой.
fn boundary_cases() -> Vec<CaseOwned> {
    [
        ("span-at-cap", CAP, false),
        ("span-over-cap", CAP + 1, true),
    ]
    .into_iter()
    .map(|(id, len, over_cap)| {
        let needle: String = std::iter::repeat_n('7', len).collect();
        CaseOwned {
            id,
            text: format!("Реквизит: {needle} (проверка границы)."),
            needles: vec![needle],
            over_cap,
        }
    })
    .collect()
}

/// Весь корпус: статические фикстуры + границы потолка.
fn corpus() -> Vec<CaseOwned> {
    CASES
        .iter()
        .map(|c| (*c).owned())
        .chain(boundary_cases())
        .collect()
}

/// Имя сессии на случай и раунд: сессия режима 2 обязана быть изолированной,
/// иначе коллизия слота из предыдущего случая переедет в следующий и промер
/// мерил бы накопленное состояние, а не вход.
fn session_for(mode: VaultMode, case_id: &str, round: usize) -> String {
    format!("{}-{case_id}-{round}", mode.as_str())
}

/// Класс по содержимому иглы — для смешанного документа. Класс на целостность
/// разворота не влияет (все идут одним `deanonymize`), но влияет на то, узнает
/// ли схема спан.
fn class_for(needle: &str) -> &'static str {
    if needle.contains('@') {
        "email"
    } else if needle.starts_with("г.") {
        "address"
    } else if needle.chars().all(|c| c.is_ascii_digit()) {
        "inn"
    } else {
        "person_name"
    }
}

/// Какая из ног проверки поймала отказ. Нужна для positive control'ов: «число
/// failures = 1» не различает, КТО поймал, и отказ, словленный не той ногой,
/// выглядел бы как успех контроля (реестр ложно-зелёных #18).
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct Leaves {
    /// Ноги «состояние»: опись подмен и протечка оригинала.
    state: StateLegs,
    /// Ноги «выход»: побайтовость разворота и счётчики разворота.
    output: OutputLegs,
}

/// Ноги «состояние»: что masking выдал (опись) и что осталось в masked-тексте.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct StateLegs {
    manifest: bool,
    leak: bool,
}

/// Ноги «выход»: побайтовость разворота и сходимость счётчиков разворота.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct OutputLegs {
    bytes: bool,
    counters: bool,
}

impl Leaves {
    #[cfg(test)]
    /// Поймал ли отказ указанный ассерт.
    #[must_use]
    fn is_caught(self, by: Check) -> bool {
        match by {
            Check::All | Check::Manifest => self.state.manifest,
            Check::Leak => self.state.leak,
            Check::Bytes => self.output.bytes,
            Check::Counters => self.output.counters,
        }
    }

    #[cfg(test)]
    /// Ноги, чей след в leaves непустой. Таблица ловцов пинится СПИСКОМ, а не
    /// флагом: «краснота от ноги вне названного комплекта» = таблица врёт, и
    /// это отдельная диагностика.
    #[must_use]
    fn caught(self) -> Vec<Check> {
        [Check::Manifest, Check::Leak, Check::Bytes, Check::Counters]
            .into_iter()
            .filter(|c| self.is_caught(*c))
            .collect()
    }
}

/// Счётчики одного режима.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct ModeStat {
    /// Успешных round-trip'ов (маскирование + побайтовый разворот).
    roundtrips: usize,
    /// Суммарно измеренных спанов.
    spans: usize,
    /// Запланированных пропусков (исправный отказ masking по потолку).
    skips: usize,
    /// Round-trip'ов, где хотя бы один спан ушёл суррогатом, а не маркером
    /// (`operator == "replace"`): именно на них живёт реверс-индекс целостности
    /// (#60 п.3). Ноль у этой колонки = промер разворачивал токены, а не формы,
    /// и проверял бы не то, ради чего затевался гейт.
    surrogate_roundtrips: usize,
    /// Нарушений целостности. Ноль обязателен.
    failures: usize,
    leaves: Leaves,
}

impl ModeStat {
    fn merge(&mut self, other: &Self) {
        self.roundtrips += other.roundtrips;
        self.spans += other.spans;
        self.skips += other.skips;
        self.surrogate_roundtrips += other.surrogate_roundtrips;
        self.failures += other.failures;
        // Следы ног собираются OR'ом: на уровне режима контроль «failures без
        // следа ноги» (реестр #18/#19) обязан видеть, КТО ловил отказы.
        self.leaves.state.manifest |= other.leaves.state.manifest;
        self.leaves.state.leak |= other.leaves.state.leak;
        self.leaves.output.bytes |= other.leaves.output.bytes;
        self.leaves.output.counters |= other.leaves.output.counters;
    }
}

/// Байтовые спаны по иглам — координаты считаем здесь, ровно как `/v1/analyze`
/// отдаёт их клиенту.
fn spans_for(text: &str, needles: &[String]) -> Vec<SpanIn> {
    needles
        .iter()
        .map(|needle| {
            let start = text
                .find(needle.as_str())
                .unwrap_or_else(|| panic!("фикстура: иглы нет в тексте: {needle}"));
            SpanIn {
                entity_type: class_for(needle).to_owned(),
                byte_start: start,
                byte_end: start + needle.len(),
            }
        })
        .collect()
}

/// Случаи, в которые вписываются inject-ы, работающие с суррогатной формой.
/// Прогон режима идёт ДВУМЯ раундами (чистый + после снятия записей), поэтому
/// пойманных отказов — `2 × len(списка)`.
///
/// Списки РАЗНЫЕ, и различие содержательное (промер 21.10):
///
/// * [`SUBSTITUTE_CASE_IDS`] — тихая подмена имени: нужен случай, где в тексте
///   ровно одна ФИО-подмена, иначе правка задевает чужие вхождения и контроль
///   перестаёт быть точечным;
/// * [`DIVERGENT_CASE_IDS`] — расхождение кэша: в сессии обязана быть вторая
///   суррогатная форма. При единственной форме отказ разворота оставляет в
///   тексте саму форму — она же стояла в masked-тексте, текст совпадает с
///   исходником, и побайтовая сверка молчит (промер 21.10: разворот
///   `deanonymize`-а, отвернувшего форму, даёт 199 Б против 199 Б). Ловится это
///   только тем, что в тексте есть РЯДОМ разворачивающаяся честно форма: её
///   разворот и делает строку длиннее/короче исходника.
///
/// `mixed-doc` в списках НЕТ: ФИО в смешанном документе уходит на типизированную
/// метку, а не суррогатом (`mixed_doc_fio_falls_back_to_a_label`).
/// Целевые случаи inject-а «тихая подмена имени».
const SUBSTITUTE_CASE_IDS: &[&str] = &["fio-nom"];

/// Целевые случаи inject-а «расхождение кэша» (несколько форм в сессии).
const DIVERGENT_CASE_IDS: &[&str] = &["multi-name-doc", "fio-cases"];

/// Целевые случаи inject-ов, которым нужен замазанный оригинал в описи подмен:
/// `LeakInMasked` (протечка `ПДн`) и `DropSubstitution` (подмена сорвана с выхода)
/// — обе ловятся ногой «состояние» и обязаны краснить прогон в режиме 3 тоже.
const LEAK_CASE_IDS: &[&str] = &[
    "fio-nom",
    "multi-name-doc",
    "fio-cases",
    "base64-blob",
    "spelled-under-cap",
    "mixed-doc",
];

/// Что прогон обязан увидеть в режиме 2, чтобы вердикт имел право на `ok`:
/// гладкие суррогатные подмены ФИО. Число зафиксировано пинном, а не «> 0»:
/// молча потерянный случай (фамилия перестала гнуться, пул уехал, разбор спана
/// отдаёт `NoMatch`) уронил бы покрытие до нуля, и гейт продолжал бы печатать
/// зелёное по токен-прокату (реестр ложно-зелёных, «гейт, скоупнутый автором»).
const MIN_SESSION_SURROGATE_ROUNDTRIPS: usize = 6;

/// Точка inject-а отказов для positive control'ов ассертов `run_case`.
///
/// Каждый вариант ломает ОДНУ ногу прогона так, как её ломает реальный дефект
/// #60 п.3: протёкший оригинал, partial-restore, перенятый слот. Без этой точки
/// ассерты `run_case` исполняются только на здоровом входе и остаются
/// мутационно-нечувствительными: промер «выключим ассерт → прогон всё равно
/// зелёный» показывал именно это, и это тот класс, который реестр ложно-зелёных
/// называет «print-only landing test» (член 18): зелёный под мутацией.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Без отказа — нормальный промер.
    None,
    /// Оригиналы не вычистились из masked-текста: к выходу приписан оригинал.
    /// Маркеры остаются целыми, поэтому краснеют ОБЕ ноги: и утечка в тексте
    /// (нога «состояние»), и несход побайтовости (нога «выход»).
    LeakInMasked,
    /// Подмена сорвана с выхода: опись пустая, в тексте — оригинал. Ловится
    /// ногой «состояние» (число и непустота замен).
    DropSubstitution,
    /// Одна подмена срезана с ОПИСИ, а из текста — нет: число поверхностей,
    /// которое вернул masking, расходится с числом развёрнутых подмен. Ловится
    /// ТОЛЬКО веткой счётчиков разворота (ноги «состояние» и «выход» тут слепы),
    /// и она обязана краснеть.
    ShrinkManifest,
    /// Подмену вырезали из masked-текста: разворот не находит маркер.
    DropMarker,
    /// В конец развёрнутого текста подмешан байт: разворот не побайтовый.
    TamperRestored,
    /// Кэш переписан в обход движка: форма указывает на чужой оригинал, разворот
    /// обязан ОТКАЗАТЬСЯ разворачивать её (`restore_refused > 0`), и промер
    /// обязан это увидеть. Строится прямым `store().insert` — штатным путём
    /// состояние «запись не та» недостижимо (выдача на перенятый слот отказывает,
    /// `guard-vault::slot_retaken_after_record_died_is_refused_not_swallowed`).
    /// Тот же приём, что `divergent_form_refuses_restore_and_shows_in_counter`
    /// в `src/vault.rs`.
    DivergentStore,
    /// Разворот вернул другое имя: тихая подмена, худший исход #60 п.3.
    /// Inject вписывается ровно в один ФИО-случай ([`SURROGATE_CASE_ID`]):
    /// подмена в тексте, где суррогатов нет, тривиальна и ничего не доказывает.
    SubstituteForeign,
}

/// Один случай в одном режиме: замаскировать → развернуть → сравнить побайтово.
///
/// Ассертятся ОБЕ ноги исхода (реестр ложно-зелёных, «print-only landing test»):
/// и состояние (маскирование выдало по подмене на спан, оригинала в masked-тексте
/// нет), и выход (разворот побайтово равен исходнику + счётчики разворота
/// сошлись).
#[allow(
    clippy::too_many_lines,
    reason = "линейный промер одного случая: маскирование → две ноги проверки → разворот; дробление разнесло бы пару ассертов по файлам"
)]
/// Ноги проверки внутри `run_case`. Отключаются параметром, чтобы positive
/// control «выключи ногу → прогон на её отказе зеленеет» был тестом, а не
/// правкой исходника (мутацию `if false {` тестом не зафиксировать).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    /// Все ноги (обычный промер).
    All,
    /// «Состояние»: число и непустота подмен в описи.
    Manifest,
    /// «Состояние»: протечка оригинала в masked-текст.
    Leak,
    /// «Выход»: побайтовость разворота.
    Bytes,
    /// «Выход»: счётчики разворота (`substituted`/`restore_refused`).
    Counters,
}

/// Обычный промер случая: все ноги включены.
/// Число ПОВЕРХНОСТЕЙ, которые обещает опись masking: `MaskItem` с меткой —
/// одна подмена, суррогатный спан — N слов (промер: ФИО из трёх токенов даёт
/// `substituted == 3` при одном спане). Знаменатель ноги «счётчики».
#[must_use]
fn surfaces_of(anon: &Anonymized) -> usize {
    anon.items
        .iter()
        .map(|item| {
            if item.operator == OP_REPLACE {
                item.replacement.split_whitespace().count()
            } else {
                1
            }
        })
        .sum()
}

fn run_case(
    vault: &Vault,
    schema: &Schema,
    mode: VaultMode,
    case: &CaseOwned,
    round: usize,
    echo: bool,
    fault: Fault,
) -> ModeStat {
    run_case_checked(vault, schema, mode, case, round, echo, fault, &[Check::All])
}

/// То же, с отключаемыми ногами (см. [`Check`]).
#[allow(
    clippy::too_many_lines,
    reason = "линейный промер одного случая: маскирование → ноги проверки → разворот; дробление разнесло бы пару ассертов по файлам"
)]
fn run_case_checked(
    vault: &Vault,
    schema: &Schema,
    mode: VaultMode,
    case: &CaseOwned,
    round: usize,
    echo: bool,
    fault: Fault,
    disabled: &[Check],
) -> ModeStat {
    // `Check::All` — «ничего не выключено» (обычный промер), а НЕ «все ноги
    // выключены»: `disabled` это список ОТКЛЮЧЁННЫХ ног (промер 21.10: reading
    // `All` as "all disabled" глушило все ассерты обычного прогона, и гейт
    // печатал зелёное на любом входе).
    let off = |c: Check| disabled.contains(&c);
    let mut st = ModeStat::default();
    let session = session_for(mode, case.id, round);
    let session_arg = (mode == VaultMode::Session).then_some(session.as_str());
    let spans = spans_for(&case.text, &case.needles);

    let anon = match vault.anonymize(session_arg, &case.text, &spans, schema) {
        Ok(a) => a,
        Err(e) => {
            let code = e.code();
            if case.over_cap && code == "span_too_long" {
                // Запланированный отказ: спан за потолком не маскируется
                // (fail-closed, #120). Разворачивать нечего — это skip, и он
                // назван своей причиной.
                st.skips = 1;
                if echo {
                    println!(
                        "RESTORE|case|{}|{round}|skip|reason|{code}|spans|{}|",
                        mode.as_str(),
                        spans.len()
                    );
                }
                return st;
            }
            // Причина обязана быть названа настоящей, а не «сбой харнеса»:
            // over-cap без span_too_long и любой отказ in-cap — это провал.
            eprintln!(
                "МАСКИРОВАНИЕ ОТКАЗАЛО: {} раунд {round}: код {}, причина: {e}",
                case.id, code
            );
            st.failures = 1;
            return st;
        }
    };

    // Поверхности заявлены masking ДО всякого inject-а: знаменатель ног —
    // обещание продукта клиенту, inject менять его не вправе (иначе харнес
    // сверяет разворот с самой собой).
    let surfaces = surfaces_of(&anon);

    if fault == Fault::DivergentStore && DIVERGENT_CASE_IDS.contains(&case.id) {
        // Второй токен формы начинает указывать на чужое имя: запись в кэш
        // кладётся в обход движка, как положил бы её второй писатель (ручная
        // правка, регресс, будущий второй writer). Остальные токены
        // разворачиваются честно, поэтому разворот ОТДАЁТ текст с чужим именем —
        // ровно тот исход, ради которого затевался #60 п.3. Перезапись ПЕРВОГО
        // токена отбрасывала бы весь случай на refusal, текст совпадал бы с
        // исходником, и побайтовая сверка промолчала бы (промер 21.10).
        // Под КАЖДЫЙ токен первой выданной формы кладётся чужое значение:
        // разворот этого имени отдаёт чужое имя (побайтовая нога), а расхождение
        // свидетелей оставляет след `restore_refused` (нога счётчиков).
        // Перезапись ОДНОГО токена из трёх давала текст, побайтово равный
        // исходнику, и побайтовая нога молчала (промер 21.10).
        let Some(form) = vault.session_forms(&session).first().cloned() else {
            // Случай ушёл на метку (пул не справился): суррогатной формы нет,
            // вписывать расхождение не во что — пропуск, а не паника харнеса.
            return st;
        };
        for (i, word) in form.split_whitespace().enumerate() {
            vault
                .engine()
                .store()
                .insert(
                    &guard_vault::cache::StoreKey::new(&session, &format!("SRG#{word}")),
                    guard_types::SecretString::new(format!("Ветрова{i}")),
                )
                .expect("запись вручную");
        }
    }

    let mut anon = anon;
    if fault == Fault::ShrinkManifest && LEAK_CASE_IDS.contains(&case.id) {
        // Подмена убрана ИЗ ОПИСИ и из masked-текста (маркер вырезан целиком):
        // masking обещает N−1 поверхностей, разворот разворачивает N−1, а
        // развёрнутый текст побайтово равен входу. Краснеет РОВНО одна нога —
        // счётчики; «состояние», «утечка» и «выход» тут слепы, и именно это
        // проверяет `each_leg_catches_its_own_fault_and_only_it`.
        let Some(item) = anon.items.first() else {
            return st;
        };
        let replacement = item.replacement.clone();
        anon.items.remove(0);
        anon.text = anon.text.replace(&replacement, &CUT.to_string());
    }
    if fault == Fault::DropSubstitution && LEAK_CASE_IDS.contains(&case.id) {
        // Подмена сорвана с выхода: опись пустая, в тексте — оригинал.
        for item in &mut anon.items {
            item.replacement.clear();
        }
        anon.text.clone_from(&case.text);
    }
    if fault == Fault::LeakInMasked && LEAK_CASE_IDS.contains(&case.id) {
        // ПДн протекли наружу: masked-текст сдвинут контрольным байтом, а в
        // начало вписаны оригиналы.
        //
        // Измерено 21.10: дописывание оригинала в ХВОСТ даёт failures = 0 —
        // побайтовая нога не срабатывает (разворот честно разворачивает маркеры
        // и дописывает хвост, и `masked`, куда вписана утечка, снова побайтово
        // равен фикстуре). Сдвиг нужен, чтобы inject бил РОВНО в одну ногу: на
        // смещённой границе маркеры не распознаются, разворот возвращает вход
        // дословно, побайтовая нога краснеет, и «отказ пойман» ниже читается
        // как пойманный именно ногой «утечка».
        let mut leaked = case.needles.concat();
        leaked.push(CUT);
        leaked.push_str(&anon.text);
        anon.text = leaked;
    }

    // Нога «состояние» (обе части, реестр ложно-зелёных #18): подмена на каждый
    // спан с непустым замещающим текстом, и ни одного оригинала наружу.
    if !off(Check::Manifest)
        && (anon.items.len() != spans.len() || anon.items.iter().any(|i| i.replacement.is_empty()))
    {
        eprintln!(
            "ПОДМЕН НЕ ПО ЧИСЛУ СПАНОВ / ПУСТАЯ ЗАМЕНА: {} раунд {round}: {} против {}",
            case.id,
            anon.items.len(),
            spans.len()
        );
        st.leaves.state.manifest = true;
        st.failures = 1;
        return st;
    }
    for needle in &case.needles {
        if !off(Check::Leak) && anon.text.contains(needle.as_str()) {
            eprintln!("ОРИГИНАЛ В MASKED-ТЕКСТЕ: {} раунд {round}", case.id);
            st.leaves.state.leak = true;
            st.failures = 1;
            return st;
        }
    }

    // Нога «утечка» обязана видеть ТО, что уходит наружу. Все inject-ы,
    // меняющие вышедший текст, правят буфер `masked`, и правятся ДО копирования
    // (`masked` копируется из `anon.text`): мера «протёк ли оригинал наружу»
    // = вопрос к буферу выхода, а не к внутренней копии описи.
    let mut masked = anon.text.clone();
    if fault == Fault::DropMarker {
        // Маркер/метка вырезана: разворачивать нечего, разворот обязан отказать
        // (`unresolved_token`), а не отдать текст с дырой.
        masked = String::new();
    }

    // Нога «выход»: разворот побайтово равен исходнику.
    let restored = match vault.deanonymize(session_arg, &masked) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "РАЗВОРОТ ОТКАЗАЛ: {} раунд {round}: код {}, причина: {e}",
                case.id,
                e.code()
            );
            st.failures = 1;
            return st;
        }
    };
    let mut restored = restored;
    if fault == Fault::TamperRestored {
        // Разворот побайтово не равен исходнику: заменён ПЕРВЫЙ символ.
        // Хвост трогать нельзя: `push('~')` measured failures = 0 — хвост
        // разворота режется по байтовым границам и лишним байтом от исходника не
        // отличается (промер 21.10).
        let n = restored.text.chars().next().map_or(0, char::len_utf8);
        restored.text.replace_range(0..n, "~");
    }
    if fault == Fault::SubstituteForeign && SUBSTITUTE_CASE_IDS.contains(&case.id) {
        // Худший исход #60 п.3: разворот отдаёт НЕ то имя, что подставлялось.
        // Правка точечная и своя на случай: общая replace-цепочка задевает
        // несколько токенов и даёт не «подмену», а порчу текста.
        let forged = match case.id {
            "fio-nom" => case.text.replace('а', "я"),
            other => unreachable!("inject подмены вписан только в fio-nom, а не в {other}"),
        };
        restored.text.clear();
        restored.text.push_str(&forged);
    }

    if !off(Check::Bytes) && restored.text.as_str() != case.text.as_str() {
        eprintln!(
            "РАЗВОРОТ НЕ ПОБАЙТОВЫЙ: {} раунд {round}: {} Б против {} Б",
            case.id,
            restored.text.len(),
            case.text.len()
        );
        st.leaves.output.bytes = true;
        st.failures = 1;
        return st;
    }
    // Счётчики разворота, РОВНО, а не «в коридоре». Знаменатель — поверхности,
    // заявленные masking (`surfaces_of`): `deanonymize` считает и маркеры, и
    // суррогатные СЛОВА, поэтому число спанов в знаменатель не годится.
    // Равенство, а не коридор: коридор `spans..=3·spans` mutation-промер 21.10
    // показал нечувствительным к выключенной проверке (реестр #18).
    if !off(Check::Counters) && (restored.substituted != surfaces || restored.restore_refused != 0)
    {
        eprintln!(
            "СЧЁТЧИКИ РАЗВОРОТА РАСХОДЯТСЯ: {} раунд {round}: substituted={} refused={} при {} поверхностях (спанов {})",
            case.id,
            restored.substituted,
            restored.restore_refused,
            surfaces,
            spans.len()
        );
        st.leaves.output.counters = true;
        st.failures = 1;
        return st;
    }

    st.roundtrips = 1;
    st.spans = spans.len();
    st.surrogate_roundtrips = usize::from(
        mode == VaultMode::Session && anon.items.iter().any(|item| item.operator == OP_REPLACE),
    );
    if echo {
        println!(
            "RESTORE|case|{}|{round}|ok|spans|{}|surrogate|{}|",
            mode.as_str(),
            spans.len(),
            st.surrogate_roundtrips
        );
    }
    st
}

/// Прогон режима по корпусу, дважды: чистый и после снятия записей (`invalidate`
/// сессий — то, как запись выглядит для движка после idle-лимита или evict по
/// байтовому бюджету). Счётчики деградации снимаются после чистого прогона —
/// это то, что показывает `GET /health`.
fn run_mode(
    mode: VaultMode,
    mlock: Mlock,
    cases: &[CaseOwned],
    echo: bool,
) -> (ModeStat, u64, u64) {
    run_mode_injected(mode, mlock, cases, echo, Fault::None)
}

fn run_mode_injected(
    mode: VaultMode,
    mlock: Mlock,
    cases: &[CaseOwned],
    echo: bool,
    fault: Fault,
) -> (ModeStat, u64, u64) {
    let schema = Schema::embedded().expect("канон вшит");
    let mut total = ModeStat::default();
    let mut mismatch = 0_u64;
    let mut fallbacks = 0_u64;
    for round in 0..2 {
        let vault = Vault::startup(mode, mlock)
            .unwrap_or_else(|e| panic!("хранилище {mode:?} не поднялось: {e}"));
        for case in cases {
            total.merge(&run_case(&vault, &schema, mode, case, round, echo, fault));
        }
        if round == 0 {
            mismatch = vault.unrestored_mismatch();
            fallbacks = vault.surrogate_fallbacks();
            for case in cases {
                vault.invalidate(&session_for(mode, case.id, round));
            }
        }
    }
    (total, mismatch, fallbacks)
}

/// Вердикт прогона: из счётчиков, а не из шаблона. Красным считается не только
/// провал разворота, но и прогон, не тронувший суррогаты: в режиме 2 гладкая
/// подмена ФИО — ровно та поверхность, ради которой строился реверс-индекс
/// (#60 п.3), и зелёный вердикт при нуле таких round-trip'ов был бы галочкой
/// над пустым прогоном.
#[must_use]
fn verdict_of(total: &ModeStat, mismatch: u64, session_surrogates: usize) -> &'static str {
    if total.failures != 0 || mismatch != 0 {
        "red"
    } else if session_surrogates < MIN_SESSION_SURROGATE_ROUNDTRIPS {
        "no_surrogate_coverage"
    } else {
        "ok"
    }
}

fn main() {
    // Режим и политика залочкивания берутся из конфигурации демона, а не из
    // литерала харнеса: то, что мерит гейт, должно совпадать с тем, что поднимает
    // `fasad` по default (рулинг «меряем = гоняем», #60 п.4). Env-переопределения
    // (`FASAD_VAULT_MODE`, `FASAD_MLOCK`) в харнесе не читаются — `from_lookup` с
    // пустым looked-up, иначе промер зависел бы от окружения shell'а (рецидив
    // «skip-зелёный»: env разработчика примонтировал настоящие веса в тест).
    let cfg = Config::from_lookup(|_| None).expect("дефолты конфига sane");
    let echo = std::env::args().skip(1).any(|a| a == "--echo");
    let cases = corpus();
    if cases.is_empty() {
        eprintln!(
            "RESTORE|verdict|noinput|roundtrips|0|spans|0|skips|0|failures|0|modes|2|session|stateless|"
        );
        std::process::exit(2);
    }

    let mut total = ModeStat::default();
    let mut session_surrogates = 0_usize;
    let mut mismatch = 0_u64;
    let mut fallbacks = 0_u64;
    for mode in [VaultMode::Session, VaultMode::Stateless] {
        let (st, mm, fb) = run_mode(mode, cfg.mlock, &cases, echo);
        mismatch = mismatch.max(mm);
        fallbacks = fallbacks.max(fb);
        if mode == VaultMode::Session {
            session_surrogates = st.surrogate_roundtrips;
        }
        total.merge(&st);
        println!(
            "RESTORE|mode|{}|roundtrips|{}|spans|{}|skips|{}|surrogate_roundtrips|{}|failures|{}|",
            mode.as_str(),
            st.roundtrips,
            st.spans,
            st.skips,
            st.surrogate_roundtrips,
            st.failures
        );
    }

    println!("RESTORE|counter|mismatch|{mismatch}|fallbacks|{fallbacks}|");
    // Режим по default и политика mlock — из конфигурации продукта: строка
    // говорит, чем именно промерен default (иначе «ok» не attachable к тому,
    // что реально поднимается демоном).
    println!(
        "RESTORE|config|default_mode|{}|mlock|{}|",
        cfg.vault_mode.as_str(),
        cfg.mlock.as_str()
    );
    // Вердикт — из фактических счётчиков, не из шаблона (см. [`verdict_of`]).
    let verdict = verdict_of(&total, mismatch, session_surrogates);
    println!(
        "RESTORE|verdict|{verdict}|roundtrips|{}|spans|{}|skips|{}|failures|{}|modes|2|session|stateless|",
        total.roundtrips, total.spans, total.skips, total.failures
    );
    // rc — из проверяющей команды, `just` его пробрасывает: он и краснит ногу.
    std::process::exit(match verdict {
        "ok" => 0,
        // Прогон не измерил того, что обязан измерить: это «не проверено», а не
        // «проверено и чисто» — код 2, как в `lang-scan`.
        "no_surrogate_coverage" => 2,
        _ => 1,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_daemon::vault::VaultApiError;

    /// Контракт формата строки вердикта: поле-на-поле, как `GOLDEN|verdict` в
    /// `recall_golden` (строку жрут `grep`/`awk` — порядок полей контрактен).
    #[test]
    fn verdict_line_shape_is_a_stable_contract() {
        let st = ModeStat {
            roundtrips: 16,
            spans: 41,
            skips: 2,
            surrogate_roundtrips: 6,
            failures: 0,
            leaves: Leaves::default(),
        };
        let line = format!(
            "RESTORE|verdict|{verdict}|roundtrips|{}|spans|{}|skips|{}|failures|{}|modes|2|session|stateless|",
            st.roundtrips,
            st.spans,
            st.skips,
            st.failures,
            verdict = if st.failures == 0 { "ok" } else { "red" }
        );
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(&parts[..3], ["RESTORE", "verdict", "ok"], "{parts:?}");
        // Хвост ПАРНЫЙ (ревью #134): `modes|<count>|<mode>…` — счётчик
        // режимов замкнут парой «ключ|значение», после него ровно `count`
        // значений. Непарный хвост `modes|session|stateless|` ломал парсинг
        // `chunks(2)`: «session» вставала на место значения, «stateless» — на
        // место ключа, потребители режали строку наугад.
        let pairs: Vec<(&&str, &&str)> = parts[3..parts.len() - 3]
            .chunks(2)
            .map(|c| (&c[0], &c[1]))
            .collect();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| **k).collect();
        assert_eq!(
            keys,
            vec!["roundtrips", "spans", "skips", "failures", "modes"],
            "порядок полей вердикта уехал — потребители строки сломаются"
        );
        assert_eq!(*pairs[4].1, "2", "число режимов отъехало от хвоста");
        assert_eq!(
            &parts[parts.len() - 3..],
            ["session", "stateless", ""],
            "список режимов после `modes|<count>|` — контракт"
        );
        assert!(line.ends_with('|'), "строка обязана кончаться разделителем");
        // Вердикт краснеет ровно тогда, когда есть провал: слово не литерал.
        let red = ModeStat { failures: 1, ..st };
        let line_red = format!(
            "RESTORE|verdict|{}|",
            if red.failures == 0 { "ok" } else { "red" }
        );
        assert_eq!(line_red, "RESTORE|verdict|red|");
        // Прогон, не дотянувший до пина покрытия, — не «ok»:
        // `no_surrogate_coverage` (rc 2 = «не измерено»), а не зелёный ярлык над
        // прогоном, который ничего не трогал.
        let empty = ModeStat {
            surrogate_roundtrips: 0,
            ..st
        };
        assert_eq!(
            verdict_of(&total_of(&st), 0, empty.surrogate_roundtrips),
            "no_surrogate_coverage"
        );
        assert_eq!(verdict_of(&total_of(&st), 0, st.surrogate_roundtrips), "ok");
        assert_eq!(
            verdict_of(&total_of(&red), 0, red.surrogate_roundtrips),
            "red"
        );
        assert_eq!(
            verdict_of(&total_of(&st), 1, st.surrogate_roundtrips),
            "red"
        );
        // Пин покрытия живой, а не «> 0»: на единице ниже пина вердикт обязан быть
        // красным, иначе потеря половины суррогатных случаев прошла бы зелёной.
        // Порог живой: на единицу ниже пина вердикт обязан быть «не измерено».
        // Отрицательный контроль: `MIN - 1` в usize при нулевом пине дал бы
        // огромное число и тест прошёл бы молча.
        assert!(
            MIN_SESSION_SURROGATE_ROUNDTRIPS >= 1,
            "порог покрытия обнулён: вердикт «ok» над пустым прогоном"
        );
        assert_eq!(
            verdict_of(&total_of(&st), 0, MIN_SESSION_SURROGATE_ROUNDTRIPS - 1),
            "no_surrogate_coverage",
            "порог покрытия не живой"
        );
        assert_eq!(
            verdict_of(&total_of(&st), 0, MIN_SESSION_SURROGATE_ROUNDTRIPS),
            "ok",
            "порог отсечён не на границе"
        );
    }

    /// Сумма режимов для теста вердикта (в `main` её считает `ModeStat::merge`).
    fn total_of(st: &ModeStat) -> ModeStat {
        let mut t = ModeStat::default();
        t.merge(st);
        t
    }

    /// Пин размера прогона на режим: 14 round-trip'ов (9 случаев, 2 раунда,
    /// 2 надпотолочных skip'а). Числа в control'ах inject-а от него производные;
    /// сам прогон обязан быть ровно таким, иначе «минус целевые» считает по
    /// уехавшему знаменателю.
    #[test]
    fn roundtrips_per_mode_is_pinned() {
        let cases = corpus();
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            let (st, _mm, _fb) = run_mode(mode, Mlock::Strict, &cases, false);
            assert_eq!(st.roundtrips, 14, "{mode:?}: размер прогона на режим уехал");
        }
    }

    /// Корпус обязан покрывать объявленные формы входа, а не «примерно их»:
    /// список закрыт, и каждая форма проверяется по своему признаку
    /// (set-equality против «гейта, скоупнутого автором», реестр #18).
    #[test]
    fn corpus_covers_the_declared_input_shapes() {
        let ids: Vec<&str> = CASES.iter().map(|c| c.id).collect();
        for want in [
            "fio-nom",
            "multi-name-doc",
            "fio-cases",
            "base64-blob",
            "spelled-under-cap",
            "spelled-over-cap",
            "mixed-doc",
        ] {
            assert!(
                ids.contains(&want),
                "форма {want} объявлена, случай потерян"
            );
        }
        for c in CASES {
            assert!(!c.needles.is_empty(), "{}: случай без спанов", c.id);
            for needle in c.needles {
                assert!(c.text.contains(needle), "{}: иглы нет в тексте", c.id);
            }
        }
        // Мультиымянность — суть #60 п.3: случай с ≥3 ФИО в одном тексте обязан
        // быть, иначе гейт меряет то, что мерил и шаг 7d.
        assert!(
            CASES
                .iter()
                .any(|c| c.id == "multi-name-doc" && c.needles.len() >= 3),
            "мультиымянного случая нет"
        );
    }

    /// Длина надпотолочной фикстуры — пин, а не расчёт: укоротить фразу =
    /// выключить ногу молча (тот же приём, что `assert_eq!(len, 223)` в
    /// `tests/vault_span_cap.rs`).
    #[test]
    fn over_cap_fixture_is_actually_over_the_cap() {
        let over = CASES
            .iter()
            .find(|c| c.over_cap)
            .expect("случай над потолком обязан быть");
        assert_eq!(
            over.needles[0].len(),
            223,
            "промер 21.10: фикстура 223 Б (пин против изменения фразы)"
        );
        assert!(
            over.needles[0].len() > CAP,
            "фикстура обязана быть за потолком"
        );
        let under = CASES
            .iter()
            .find(|c| c.id == "spelled-under-cap")
            .expect("случай под потолком обязан быть");
        assert_eq!(under.needles[0].len(), 29, "промер: фикстура 29 Б");
        assert!(
            under.needles[0].len() < CAP,
            "фикстура обязана быть под потолком"
        );
    }

    /// Границы потолка выводятся из константы: подъём `MAX_ORIGINAL_BYTES`
    /// обязан двигать фикстуру, иначе нога «ровно на границе» протухнет молча.
    #[test]
    fn boundary_fixtures_derive_from_the_cap_constant() {
        let b = boundary_cases();
        assert_eq!(b.len(), 2, "две границы: ровно потолок и потолок + 1");
        assert_eq!(b[0].needles[0].len(), CAP, "peg: ровно потолок");
        assert!(!b[0].over_cap, "на потолке masking обязан проходить");
        assert_eq!(b[1].needles[0].len(), CAP + 1, "peg: потолок + 1");
        assert!(b[1].over_cap, "за потолком masking обязан отказывать");
    }

    /// Пин против «зелёного прогона ноль чего»: корпус измерим и ненулевой.
    #[test]
    fn corpus_measures_more_than_nothing() {
        let cases = corpus();
        let spans: usize = cases.iter().map(|c| c.needles.len()).sum();
        assert!(
            spans >= 16,
            "корпус из {spans} спанов не покрывает заявленное"
        );
        assert_eq!(cases.len(), 9, "7 статических случаев + 2 границы потолка");
    }

    /// Живость гейта: прогон на настоящем хранилище зелёный и с ненулевыми
    /// счётчиками в ОБОИХ режимах. Без этой пары `ok` в строке вердикта —
    /// литерал, а red-сигнал — ненаблюдаемое обещание.
    #[test]
    fn live_run_is_ok_and_counters_are_nonzero_in_both_modes() {
        let cases = corpus();
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            let (st, mismatch, fb) = run_mode(mode, Mlock::Strict, &cases, false);
            assert_eq!(st.failures, 0, "{mode:?}: целостность разворота нарушена");
            assert!(
                st.roundtrips > 0,
                "{mode:?}: ни одного round-trip — прогон пустой"
            );
            assert!(st.spans > 0, "{mode:?}: ноль измеренных спанов");
            assert!(st.skips > 0, "{mode:?}: надпотолочная нога не сработала");
            assert_eq!(
                mismatch, 0,
                "{mode:?}: счётчик расхождений индекса ненулевой"
            );
            // Откатов суррогатного слота на метку в корпусе быть не должно: они
            // переводят ФИО на маркер, и промер перестает мерить формы.
            assert_eq!(fb, 0, "{mode:?}: пул суррогатов не справился с корпусом");
            if mode == VaultMode::Session {
                assert_eq!(
                    st.surrogate_roundtrips, MIN_SESSION_SURROGATE_ROUNDTRIPS,
                    "промер режима 2 тронул суррогатов не то число, что запинено"
                );
            } else {
                assert_eq!(
                    st.surrogate_roundtrips, 0,
                    "в режиме 3 суррогатов нет by design"
                );
            }
        }
    }

    /// Конечная строка stdout-контракта собирается на РЕАЛЬНЫХ счётчиках
    /// реального прогона и обязана называть `ok`: пин формата против рассинхрона
    /// `println!` в `main` и теста формата (реестр ложно-зелёных, член 15: слово
    /// вердикта отделено от числа).
    #[test]
    fn real_counters_render_the_declared_verdict_line() {
        let cases = corpus();
        let mut total = ModeStat::default();
        let mut session_surrogates = 0_usize;
        let mut mismatch = 0_u64;
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            let (st, mm, _fb) = run_mode(mode, Mlock::Strict, &cases, false);
            if mode == VaultMode::Session {
                session_surrogates = st.surrogate_roundtrips;
            }
            mismatch = mismatch.max(mm);
            total.merge(&st);
        }
        let verdict = verdict_of(&total, mismatch, session_surrogates);
        let line = format!(
            "RESTORE|verdict|{verdict}|roundtrips|{}|spans|{}|skips|{}|failures|{}|modes|2|session|stateless|",
            total.roundtrips, total.spans, total.skips, total.failures
        );
        assert_eq!(verdict, "ok", "прогон корпуса краснен: {line}");
        assert!(line.starts_with("RESTORE|verdict|ok|"), "{line}");
        assert!(
            line.ends_with("modes|2|session|stateless|"),
            "{line}: парный хвост уехал"
        );
        // Числа строки = счётчикам прогона, а не шаблону.
        // Пары «ключ|значение» после вердикта: поле 2/3 = `verdict|<слово>`,
        // дальше идут `roundtrips|<n>|spans|<n>|skips|<n>|failures|<n>|modes|…`.
        let fields: Vec<(String, String)> = line
            .split('|')
            .skip(3)
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| (c[0].to_owned(), c[1].to_owned()))
            .filter(|(k, _)| !k.is_empty())
            .take_while(|(k, _)| k != "modes")
            .collect();
        let get = |want: &str| -> usize {
            fields
                .iter()
                .find(|(k, _)| k == want)
                .unwrap_or_else(|| panic!("поля {want} в строке нет: {line}"))
                .1
                .parse()
                .unwrap_or_else(|_| panic!("поле {want} не числом: {line}"))
        };
        assert_eq!(
            get("roundtrips"),
            total.roundtrips,
            "строка печатает не те round-trip'ы, что насчитал прогон"
        );
        assert_eq!(get("spans"), total.spans, "строка печатает не те спаны");
        assert_eq!(get("skips"), total.skips, "строка печатает не те skips");
        assert_eq!(get("failures"), 0, "вердикт ok при ненулевых failures");
    }

    /// Positive control ассертов `run_case`: каждый inject-нутый отказ обязан
    /// давать `failures = 1` в ОБОИХ режимах. Это доказательство живости ноги, а
    /// не её описание: без него зелёный прогон ничего не утверждает (реестр
    /// ложно-зелёных, член 18 «print-only landing test»: печать ногой не
    /// считается, ассерт обязан краснеть на мутации).
    #[test]
    fn every_injected_fault_is_caught_in_both_modes() {
        let cases = corpus();
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            for fault in [
                Fault::LeakInMasked,
                Fault::DropSubstitution,
                Fault::ShrinkManifest,
                Fault::DropMarker,
                Fault::TamperRestored,
                Fault::SubstituteForeign,
                Fault::DivergentStore,
            ] {
                // Два отказа живут только в режиме 2: суррогатной формы в
                // режиме 3 нет по конструкции (оригинал зашифрован внутри
                // маркера, «перенять» нечего — `Vault::unrestored_mismatch`).
                // Требовать от них красноты в режиме 3 значило бы проверять
                // ветку, которой там не существует.
                if mode == VaultMode::Stateless
                    && matches!(fault, Fault::SubstituteForeign | Fault::DivergentStore)
                {
                    continue;
                }
                let (st, _mm, _fb) = run_mode_injected(mode, Mlock::Strict, &cases, false, fault);
                let targets = match fault {
                    Fault::SubstituteForeign => SUBSTITUTE_CASE_IDS.len(),
                    Fault::DivergentStore => DIVERGENT_CASE_IDS.len(),
                    Fault::LeakInMasked | Fault::DropSubstitution | Fault::ShrinkManifest => {
                        LEAK_CASE_IDS.len()
                    }
                    _ => 0,
                };
                assert!(
                    st.failures > 0,
                    "{mode:?}: inject {fault:?} не пойман (failures = {}) — ассерт мёртв",
                    st.failures
                );
                // Число красноты обязан сопровождать СЛЕД ноги: «failures += 1»
                // без leaves-флага = «кто поймал — неизвестно» (реестр #18),
                // поэтому порог — непустой список словивших ног, а не только
                // счётчик (реестр #19: ассерт обязан краснеть на выключенной
                // ноге, а не на её числе).
                assert!(
                    [Check::Manifest, Check::Leak, Check::Bytes, Check::Counters]
                        .iter()
                        .any(|c| st.leaves.is_caught(*c)),
                    "{mode:?}: inject {fault:?}: failures={failures} без следа ноги",
                    failures = st.failures
                );
                if targets != 0 {
                    assert_eq!(
                        st.failures,
                        2 * targets,
                        "{mode:?}: inject {fault:?}: поймано не то число случаев"
                    );
                }
                let expected = if targets == 0 { 0 } else { 14 - 2 * targets };
                assert_eq!(
                    st.roundtrips, expected,
                    "{mode:?}: inject {fault:?}: засчитано {} round-trip'ов, ожидалось {expected}",
                    st.roundtrips
                );
            }
            // Контроль над контролем: тот же прогон без inject-а зелёный.
            let (clean, _mm, _fb) = run_mode(mode, Mlock::Strict, &cases, false);
            assert_eq!(clean.failures, 0, "{mode:?}: чистый прогон краснен");
            assert!(clean.roundtrips > 0, "{mode:?}: чистый прогон пуст");
        }
    }

    /// Контроль отказа разворота: состояние «форма указывает на чужой оригинал»
    /// строится прямой записью в кэш, и гейт обязан увидеть `restore_refused`
    /// ЧИСЛОМ (R7 ревью #70: у события обязан быть след в самом запросе). В
    /// режиме 3 такой пары нет по конструкции — оригинал внутри маркера.
    #[test]
    fn divergent_form_yields_a_nonzero_refusal_count() {
        let cases = corpus();
        let (st, _mm, _fb) = run_mode_injected(
            VaultMode::Session,
            Mlock::Strict,
            &cases,
            false,
            Fault::DivergentStore,
        );
        assert_eq!(st.failures > 0, true, "расхождение кэша не поймано");
        // В режиме 3 inject нечего вписывать: прогон обязан остаться зелёным,
        // и это же отличает настоящую ветку от декоративной.
        let (clean, _mm2, _fb2) = run_mode_injected(
            VaultMode::Stateless,
            Mlock::Strict,
            &cases,
            false,
            Fault::DivergentStore,
        );
        assert_eq!(clean.failures, 0, "в режиме 3 суррогатного расхождения нет");
    }

    /// Подмена имени вписывается ровно в тот случай, где подмена есть: пин
    /// против situation, когда контроль `SubstituteForeign` деградирует до
    /// тривиальной правки байта в токен-прокате.
    #[test]
    fn surrogate_fault_targets_the_surrogate_case() {
        let cases = corpus();
        let schema = Schema::embedded().expect("канон вшит");
        // Свежее хранилище на случай: в общем реестре форм следующий случай
        // стартовал бы с занятыми слотами, и часть ФИО ушла бы на метки —
        // покрытие мерится по одному входу, а не по накопленному состоянию.
        for case in &cases {
            let fresh = Vault::startup(VaultMode::Session, Mlock::Strict).expect("хранилище");
            let st = run_case(
                &fresh,
                &schema,
                VaultMode::Session,
                case,
                0,
                false,
                Fault::None,
            );
            if SUBSTITUTE_CASE_IDS.contains(&case.id) || DIVERGENT_CASE_IDS.contains(&case.id) {
                assert_eq!(
                    st.surrogate_roundtrips, 1,
                    "целевой случай без суррогата: {}",
                    case.id
                );
            } else {
                assert_eq!(
                    st.surrogate_roundtrips, 0,
                    "не целевой случай дал суррогат: {}",
                    case.id
                );
            }
        }
        let (st, _mm, _fb) = run_mode_injected(
            VaultMode::Session,
            Mlock::Strict,
            &cases,
            false,
            Fault::SubstituteForeign,
        );
        assert_eq!(
            st.failures,
            2 * SUBSTITUTE_CASE_IDS.len(),
            "подмена поймана не ровно целевыми случаями: {st:?}"
        );
        assert_eq!(
            st.roundtrips,
            14 - 2 * SUBSTITUTE_CASE_IDS.len(),
            "остальные случаи обязаны остаться зелёными: {st:?}"
        );
        // Прогон режима идёт двумя раундами (чистый + после invalidate), отказ
        // приземляется в каждый: 2 × 3 целевых случая.
        assert_eq!(
            st.failures,
            2 * SUBSTITUTE_CASE_IDS.len(),
            "подмена поймана не ровно ФИО-случаями (2 раунда × 3 случая): {st:?}"
        );
        assert_eq!(
            st.roundtrips,
            14 - 2 * SUBSTITUTE_CASE_IDS.len(),
            "остальные случаи обязаны остаться зелёными: {st:?}"
        );
    }

    /// Inject-нутый отказ обязан краснить и вердикт: слово `red` выводится из
    /// счётчиков, а счётчики — из пойманных отказов (пара «число → слово»).
    #[test]
    fn injected_fault_flips_the_verdict_word() {
        let cases = corpus();
        let (st, mismatch, _fb) = run_mode_injected(
            VaultMode::Session,
            Mlock::Strict,
            &cases,
            false,
            Fault::TamperRestored,
        );
        assert!(st.failures > 0, "inject не пойман");
        assert_eq!(
            verdict_of(&st, mismatch, MIN_SESSION_SURROGATE_ROUNDTRIPS),
            "red",
            "слово вердикта отделилось от числа отказов"
        );
    }

    /// Первичка 21.10: в смешанном документе (ФИО + ИНН + e-mail + адрес) ФИО
    /// уходит на ТИПИРОВАННУЮ МЕТКУ, а не суррогатом: `operator == "mask"`,
    /// суррогатных round-trip'ов ноль. Причина — в `surrogate_forms`: разбор
    /// спана «Тенин Аркадий Лукич» в присутствии соседних сущностей даёт не
    /// `Unique`, и гладкой подмены нет. Значит `mixed-doc` не может быть
    /// контролем подмены имени, и ни в одном списке inject-ов его нет намеренно.
    /// Тест пинит это наблюдение: если разбор поправят и ФИО пойдёт суррогатом,
    /// тест краснеет и список целей пересматривается осознанно.
    #[test]
    fn mixed_doc_fio_falls_back_to_a_label() {
        let schema = Schema::embedded().expect("канон вшит");
        let vault = Vault::startup(VaultMode::Session, Mlock::Strict).expect("хранилище");
        let case = corpus()
            .into_iter()
            .find(|c| c.id == "mixed-doc")
            .expect("смешанный случай обязан быть");
        let st = run_case(
            &vault,
            &schema,
            VaultMode::Session,
            &case,
            0,
            false,
            Fault::None,
        );
        assert_eq!(st.failures, 0, "смешанный round-trip обязан проходить");
        assert_eq!(
            st.surrogate_roundtrips, 0,
            "ФИО в смешанном документе пошло суррогатом: цель inject-а пересматривается"
        );
    }

    /// Харнес мерит дефолт продукта: `Config::from_lookup(|_| None)` — это то,
    /// что поднимает `fasad` без env, и он обязан быть в списке промеряемых
    /// режимов. Иначе гейт мерит режим, которого демон не использует (класс
    /// «function covered != called on the request path»).
    #[test]
    fn measured_modes_include_the_product_default() {
        let cfg = Config::from_lookup(|_| None).expect("дефолты конфига sane");
        assert!(
            [VaultMode::Session, VaultMode::Stateless].contains(&cfg.vault_mode),
            "дефолтный режим {mode:?} вне промера",
            mode = cfg.vault_mode.as_str()
        );
        assert_eq!(cfg.mlock, Mlock::Strict, "дефолт mlock — strict (AGENTS)");
    }

    /// Пин знаменателя: число развёрнутых подмен продуктового пути обязаны
    /// равняться числу поверхностей, возвращённых masking, побайтово на каждом
    /// случае и в каждом режиме. Без этой пары «РОВНО» в `run_case` было бы
    /// согласием харнес самой с собой.
    #[test]
    fn restore_counter_equals_surfaces_exactly() {
        let schema = Schema::embedded().expect("канон вшит");
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            let vault = Vault::startup(mode, Mlock::Strict).expect("хранилище поднимается");
            let mut checked = 0_usize;
            for case in corpus() {
                let session = session_for(mode, case.id, 99);
                let session_arg = (mode == VaultMode::Session).then_some(session.as_str());
                let spans = spans_for(&case.text, &case.needles);
                let Ok(anon) = vault.anonymize(session_arg, &case.text, &spans, &schema) else {
                    continue;
                };
                let surfaces: usize = anon
                    .items
                    .iter()
                    .map(|i| {
                        if i.operator == OP_REPLACE {
                            i.replacement.split_whitespace().count()
                        } else {
                            1
                        }
                    })
                    .sum();
                let restored = vault
                    .deanonymize(session_arg, &anon.text)
                    .expect("разворот");
                assert_eq!(
                    restored.substituted, surfaces,
                    "{mode:?}/{}: surfaces != substituted",
                    case.id
                );
                assert_eq!(
                    restored.restore_refused, 0,
                    "{mode:?}/{}: отказ разворота",
                    case.id
                );
                checked += 1;
            }
            assert!(checked >= 7, "{mode:?}: проверено {checked} случаев — мало");
        }
    }

    /// Точное значение счётчика в режиме 3: маркер = спан, поэтому `substituted`
    /// обязан быть РАВЕН числу спанов. Без этой пары нижняя граница в
    /// `run_case` была бы согласием харнес самой с собой.
    #[test]
    fn stateless_substituted_is_exactly_the_span_count() {
        let schema = Schema::embedded().expect("канон вшит");
        let vault =
            Vault::startup(VaultMode::Stateless, Mlock::Strict).expect("хранилище поднимается");
        let text = "Клиент: 2482014338; e-mail ivan@example.ru.".to_owned();
        let needles = vec!["2482014338".to_owned(), "ivan@example.ru".to_owned()];
        let spans = spans_for(&text, &needles);
        let anon = vault
            .anonymize(None, &text, &spans, &schema)
            .expect("мазание проходит");
        let restored = vault
            .deanonymize(None, &anon.text)
            .expect("разворот проходит");
        assert_eq!(restored.substituted, spans.len(), "режим 3: маркер = спан");
        assert_eq!(restored.restore_refused, 0, "режим 3: суррогатов нет");
        assert_eq!(restored.text.as_str(), text.as_str(), "побайтово");
    }

    /// Positive control'ы НОГ по измерениям 21.10 (матрица «отказ × нога» —
    /// полная таблица в теле PR #134): каждая нога обязана ловить свой отказ, и
    /// отказ обязан быть таким, чтобы нога была ЕДИНСТВЕННОЙ, кто его ловит.
    /// «Выключил ногу — прогон всё равно краснеет» = контроль декоративный
    /// (реестр ложно-зелёных #18: ассерт, исполняемый только на здоровом входе,
    /// зелёный при мутации). Мутацию исходника тестом не зафиксировать, поэтому
    /// ноги отключаются параметром [`Check`].
    ///
    /// Измеренная матрица (режим 2; `all` = все ноги включены; `L/M/B/C` = нога
    /// ОТКЛЮЧЕНА; 1 = прогон краснеет):
    ///
    /// * `LeakInMasked` → L=0, M/B/C=1: ловит только «утечка»;
    /// * `DropSubstitution` → M=0, L/B/C=1: ловит только «опись»;
    /// * `TamperRestored` → B=0, L/M/C=1: ловит только «побайтовость»;
    /// * `SubstituteForeign` → B=0: тихая подмена — тоже «побайтовость»;
    /// * `DivergentStore` (мультиымянный случай) → B=0 и C=0: ловят ДВЕ ноги, и
    ///   это единственный отказ с двумя ногами (он же оставляет
    ///   `restore_refused`);
    /// * `ShrinkManifest` → краснеют ВСЕ ноги: он правит и опись, и текст,
    ///   поэтому не является контролем какой-либо одной ноги (см. его ветку).
    #[test]
    fn each_leg_catches_its_own_fault_and_only_it() {
        let schema = Schema::embedded().expect("канон вшит");
        let mode = VaultMode::Session;
        let runs = |fault: Fault, cid: &str, disabled: &[Check]| {
            let vault = Vault::startup(mode, Mlock::Strict).expect("хранилище поднимается");
            let case = corpus()
                .into_iter()
                .find(|c| c.id == cid)
                .expect("случай корпуса");
            run_case_checked(&vault, &schema, mode, &case, 0, false, fault, disabled)
        };
        // Измеренная матрица 21.10 (режим 2; случай `fio-nom`, мультиымянный —
        // для `DivergentStore`): ОТКАЗ → комплект ног, которые его ловят.
        // Матрица снята прогоном с print-only зондом и перенесена дословно.
        //
        // Комплект пинится СПИСКОМ ног, и контроль требует трёх свойств:
        //
        // * полный прогон краснеет РОВНО ногами комплекта (след ноги «вне
        //   таблицы» = таблица врёт о полноте, и позитивный контроль ниже
        //   ничего не утверждает);
        // * каждая названная нога ЖИВАЯ: выключить её, остальные ноги оставить
        //   работающими — отказ обязан остаться красным (контроль не держится
        //   на одном ассерте);
        // * выключить ВЕСЬ комплект — прогон зеленеет: ловцов ровно столько,
        //   сколько названо (реестр ложно-зелёных #18: «гейт, скоупнутый
        //   автором»).
        //
        // Порядок ног в харнесе sequential (первая словившая останавливает
        // прогон: round-trip'ы считаются по успеху), поэтому в полном прогоне
        // видна ПЕРВАЯ нога комплекта, а живость остальных проверяется
        // выключением: таблица начинается с той ноги, что краснеет первой,
        // и каждый следующий элемент — это «кто ловит, когда предыдущий
        // выключен».
        let rows = [
            (
                Fault::LeakInMasked,
                "fio-nom",
                vec![Check::Leak, Check::Bytes],
            ),
            (
                Fault::DropSubstitution,
                "fio-nom",
                vec![Check::Manifest, Check::Leak, Check::Counters],
            ),
            (
                Fault::ShrinkManifest,
                "fio-nom",
                vec![Check::Manifest, Check::Bytes, Check::Counters],
            ),
            (
                Fault::TamperRestored,
                "fio-nom",
                vec![Check::Bytes, Check::Bytes],
            ),
            (
                Fault::SubstituteForeign,
                "fio-nom",
                vec![Check::Bytes, Check::Bytes],
            ),
            (
                Fault::DivergentStore,
                "multi-name-doc",
                vec![Check::Bytes, Check::Counters],
            ),
        ];
        for (fault, cid, legs) in rows {
            let all = runs(fault, cid, &[]);
            assert_eq!(
                all.failures, 1,
                "{fault:?}/{cid}: отказ не пойман ни одной ногой — ассерт мёртв"
            );
            assert_eq!(
                all.leaves.caught(),
                vec![legs[0]],
                "{fault:?}/{cid}: в полном прогоне краснеет не первая нога комплекта {legs:?}"
            );
            for (i, &leg) in legs.iter().enumerate() {
                if i == 0 {
                    // Первая нога комплекта — ловец в полном прогоне (уже
                    // проверено выше); её живость = «без неё краснеет сосед».
                }
                let mut off = vec![Check::Manifest, Check::Leak, Check::Bytes, Check::Counters];
                off.retain(|c| *c != leg);
                let st = runs(fault, cid, &off);
                assert_eq!(
                    st.failures, 1,
                    "{fault:?}/{cid}: без {leg:?} отказ не пойван — {leg:?} не живой контроль: {st:?}"
                );
                let extra: Vec<Check> = st
                    .leaves
                    .caught()
                    .into_iter()
                    .filter(|c| !legs.contains(c))
                    .collect();
                assert!(
                    extra.is_empty(),
                    "{fault:?}/{cid}: без {leg:?} краснота от ноги вне комплекта {extra:?}: {st:?}"
                );
            }
            let bare = runs(fault, cid, &legs);
            assert_eq!(
                bare.failures, 0,
                "{fault:?}/{cid}: с выключенным комплектом {legs:?} красен — ловцов больше: {bare:?}"
            );
            assert!(
                bare.leaves.caught().is_empty(),
                "{fault:?}/{cid}: с выключенным комплектом {legs:?} следы остались: {bare:?}"
            );
        }
        // Зелёный прогон обязан оставаться зелёным при всех ногах (и чистыйЗелёный прогон обязан оставаться зелёным при всех ногах (и чистый
        // round-trip, и надпотолочный skip).
        assert_eq!(
            runs(Fault::None, "fio-nom", &[]).failures,
            0,
            "чистый краснен"
        );
        assert_eq!(
            runs(Fault::None, "spelled-over-cap", &[]).failures,
            0,
            "skip краснен"
        );
    }

    /// Positive control побайтовости: сверка обязана краснеть на порче, а не
    /// только печатать «ok». Порча — разворот изменённого masked-текста.
    #[test]
    fn byte_check_fails_on_a_tampered_restore() {
        let mode = VaultMode::Session;
        let schema = Schema::embedded().expect("канон вшит");
        let vault = Vault::startup(mode, Mlock::Strict).expect("хранилище поднимается");
        let text = "Тенин Аркадий Лукич подписал акт.".to_owned();
        let needles = vec!["Тенин Аркадий Лукич".to_owned()];
        let spans = spans_for(&text, &needles);
        let anon = vault
            .anonymize(Some("positive-control"), &text, &spans, &schema)
            .expect("мазание проходит");
        let mut tampered = anon.text.clone();
        tampered.push('X');
        let restored = vault
            .deanonymize(Some("positive-control"), &tampered)
            .expect("разворот проходит");
        assert_ne!(
            restored.text.as_str(),
            text.as_str(),
            "побайтовая сверка декоративна: порча входа не поймана"
        );
    }

    /// Positive control отказной ноги: надпотолочный случай обязан.skip'иться
    /// по НАСТОЯЩЕЙ причине. Любой другой код — это failures, а не skips
    /// (ложь о причине отказа = fail-open в диагностике).
    #[test]
    fn over_cap_refusal_skips_only_for_its_real_reason() {
        for mode in [VaultMode::Session, VaultMode::Stateless] {
            let schema = Schema::embedded().expect("канон вшит");
            let vault = Vault::startup(mode, Mlock::Strict).expect("хранилище поднимается");
            let over = boundary_cases().pop().expect("случай потолок + 1");
            let st = run_case(&vault, &schema, mode, &over, 0, false, Fault::None);
            assert_eq!(
                st.skips, 1,
                "{mode:?}: надпотолочный случай обязан skip'нуться"
            );
            assert_eq!(st.failures, 0, "{mode:?}: skip не считается провалом");
            assert_eq!(st.roundtrips, 0, "{mode:?}: за потолком разворота нет");

            // Дискриминатор ветки: случай помечен over_cap, а спан у него ПОД
            // потолком — masking проходит, и харнес обязана записать это как
            // измеренный round-trip, а не как skip. Ветка «skip» живёт ровно на
            // настоящем отказе по потолку.
            let lying = CaseOwned {
                id: "under-cap-flagged-over",
                text: "Реквизит: 777 (проверка границы).".to_owned(),
                needles: vec!["777".to_owned()],
                over_cap: true,
            };
            let st_ok = run_case(&vault, &schema, mode, &lying, 0, false, Fault::None);
            assert_eq!(
                st_ok.skips, 0,
                "{mode:?}: masking прошёл — skip'а быть не может"
            );
            assert_eq!(st_ok.failures, 0, "{mode:?}: успешный round-trip не провал");
            assert_eq!(st_ok.roundtrips, 1, "{mode:?}: round-trip не засчитан");

            // Дискриминатор НАСТОЯЩЕГО bad_span (ревью #134): спан `start > end`
            // (первичка crates/guard-daemon/src/vault.rs:543-550) — masking отказывает по `bad_span`, и
            // харнес обязана записать ЭТО как failure, а не как skip: ветка
            // skip живёт ровно на коде `span_too_long`, подставная причина
            // («отказ есть, назовём его потолком») здесь красная.
            let bad = CaseOwned {
                id: "inverted-span",
                text: "Реквизит: 777 (проверка границы).".to_owned(),
                needles: vec!["7".to_owned()],
                over_cap: true,
            };
            let mut spans = spans_for(&bad.text, &bad.needles);
            for sp in &mut spans {
                std::mem::swap(&mut sp.byte_start, &mut sp.byte_end);
            }
            let err = vault
                .anonymize(
                    (mode == VaultMode::Session).then_some("probe-inverted"),
                    &bad.text,
                    &spans,
                    &schema,
                )
                .expect_err("спан start > end не принимается");
            assert_eq!(err.code(), "bad_span", "код перевёрнутого спана закреплён");
            let st_bad = run_case(&vault, &schema, mode, &bad, 1, false, Fault::None);
            assert_eq!(
                st_bad.failures, 1,
                "{mode:?}: bad_span записан не как провал (skips={}, roundtrips={})",
                st_bad.skips, st_bad.roundtrips
            );
            assert_eq!(st_bad.skips, 0, "{mode:?}: bad_span не обязан быть skip'ом");
        }
    }

    /// Классы игл назначены по содержимому, и все они знает схема: опечатка в
    /// id класса дала бы отказ маскирования, который харнес записала бы как
    /// провал целостности — то есть ложный red.
    #[test]
    fn needle_classes_are_known_to_the_schema() {
        let schema = Schema::embedded().expect("канон вшит");
        for case in corpus() {
            for needle in &case.needles {
                let class = class_for(needle);
                assert!(
                    schema.knows(class),
                    "{}: класс {class} не знает схема",
                    case.id
                );
            }
        }
    }

    /// Тип-пин: `VaultApiError::code` для надпотолочного спана — `span_too_long`
    /// (стабилизирует ветку skip; тест `vault_span_cap.rs` пинит то же на HTTP).
    #[test]
    fn over_cap_error_code_is_the_pinned_one() {
        let schema = Schema::embedded().expect("канон вшит");
        let vault =
            Vault::startup(VaultMode::Stateless, Mlock::Strict).expect("хранилище поднимается");
        let needle: String = std::iter::repeat_n('7', CAP + 1).collect();
        let text = format!("Реквизит: {needle}.");
        let spans = spans_for(&text, &[needle]);
        let err: VaultApiError = vault
            .anonymize(None, &text, &spans, &schema)
            .expect_err("спан за потолком не маскируется");
        assert_eq!(err.code(), "span_too_long", "код причины закреплён");
        assert!(
            !err.message().contains("хранилище токенов отказало"),
            "подставная причина недопустима: {}",
            err.message()
        );
    }
}
