#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Регресс каскада-0 по golden-v1: чексумменные классы обязаны находиться
//! детерминированным путём, а форматированный номер — находиться **целиком**.
//!
//! Зачем отдельный тест, если есть `tools/metrics/union_recall.py`: метрика
//! считается по живому демону с ONNX, идёт ~500 с и зависит от весов. Этот
//! регресс держит то же покрытие на одном только каскаде-0: без весов, без
//! сокета, за доли секунды, на каждом `cargo test`. Метрика меряет «сколько
//! вратарь пропустил», этот файл — «вратарь обязан ловить весь свой класс».
//!
//! Состав промахов, закрытый шагом 9 (issue #80, `docs/golden-report.md` §6 п.2):
//! СНИЛС 28 из 29 промахов были форматированные (`378-312-074 87`), карта 15 из
//! 15 (`2204-9947-4132-9761`), IBAN 18 форматированных + 3 обычных ES (страны
//! не было в таблице).
//!
//! Оракул совпадения — **overlap** (пересечение байтовых диапазонов), как в
//! Rust-харнессе метрики; расходится с `exact` из README датасета (issue #77),
//! поэтому здесь оба: покрытие считаем overlap'ом, координаты сверяем строго.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use guard_daemon::cascade0::scan;
use guard_daemon::schema::Schema;
use guard_types::NewtypeId;

/// Классы, у каскада-0 есть детерминированный валидатор.
const CLASSES: [&str; 7] = [
    "inn", "snils", "ogrn", "ogrnip", "iban", "card_pan",
    // #222: addr-spec RFC 5322 = форматный валидатор (email из model-only
    // класс стал детерминированным: BPE-обрезки границ закрыты вето 1.0).
    "email",
];

/// Сколько золотых спанов этих классов в recall-сплите.
///
/// Число промерено по файлу (`tools/metrics/union_recall.py`, таблица «Покрывка
/// каскада 0» в §6 отчёта: 36 + 29 + 25 + 21 + 27 + 32 = 170 на golden-v1.0;
/// golden-v1.2 (#200-A2) досчитала inn-коллизии: 170 + 3 = 173; golden-v1.4
/// (#223) досчитала каркасные СНИЛС +6 и ОГРНИП×карта +2 = 181; golden-v1.5
/// (#222) добавила email-класс в покрытие: 181 + 40 (email recall-спанов
/// v1.3) + 9 (новые формы #222) = 230 — промер
/// `c0_measurements_are_emitted` на этом датасете. Тест сверяет состав,
/// прежде чем требовать покрытия: правка датасета обязана красить счётчик, а
/// не молча уменьшать знаменатель.
const GOLD_CHECKSUM_SPANS: usize = 235;

/// Сколько из них email (#222): base64-обход email не закрывает (prefilter
/// `scan_base64` требует ASCII-цифру в декоде, addr-spec = не цифры;
/// «SUPPORT@CORP-VEKTOR.EXAMPLE» и т.п. декодируются в байты без
/// цифр). Промер по датасету: 49 email-спанов recall (40 v1.0–v1.3 + 9 v1.5).
const GOLD_EMAIL_SPANS: usize = 49;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/golden/golden-v1.jsonl")
}

#[derive(Deserialize)]
struct Row {
    id: String,
    text: String,
    split: String,
    spans: Vec<Span>,
}

impl Row {
    /// Каркасные recall-строки #234 (g0263–g0267) = в base64-прогоне вне
    /// обещания контура: каркас требует ключевое слово, декод-проза его
    /// не несёт, а номера невалидны чексуммно.
    fn is_frame_234(&self) -> bool {
        self.id.starts_with("g0263")
            || self.id.starts_with("g0264")
            || self.id.starts_with("g0265")
            || self.id.starts_with("g0266")
            || self.id.starts_with("g0267")
    }
}

#[derive(Deserialize)]
struct Span {
    start_byte: usize,
    end_byte: usize,
    category: String,
}

fn rows() -> Vec<Row> {
    let raw = fs::read_to_string(golden_path()).expect("датасет читается");
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("строка датасета — валидный JSON"))
        .collect()
}

fn slice<'a>(text: &'a str, s: &Span) -> &'a str {
    text.get(s.start_byte..s.end_byte)
        .expect("координаты спана — границы UTF-8")
}

/// Покрывает ли каскад-0 золотой спан (overlap-оракул).
fn covered(hits: &[guard_daemon::cascade0::Hit], s: &Span, class: &str) -> bool {
    hits.iter().any(|h| {
        h.class.as_str() == class && h.span.start < s.end_byte && h.span.end > s.start_byte
    })
}

/// Покрытие: ни одного промаха по чексумменным классам recall-сплита.
#[test]
fn c0_covers_every_checksum_span_of_recall_split() {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut total = 0usize;
    let mut miss: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split == "recall") {
        let hits = scan(&r.text, &schema);
        for s in r
            .spans
            .iter()
            .filter(|sp| CLASSES.contains(&sp.category.as_str()))
        {
            total += 1;
            if !covered(&hits, s, &s.category) {
                miss.push(format!("{} {} «{}»", r.id, s.category, slice(&r.text, s)));
            }
        }
    }
    assert_eq!(
        total, GOLD_CHECKSUM_SPANS,
        "состав gold-спанов чексумменных классов изменился — сверь с датасетом"
    );
    assert!(
        miss.is_empty(),
        "промахов {} из {}: \n{}",
        miss.len(),
        total,
        miss.join("\n")
    );
}

/// Координаты: канонизация не двигает спан. Каждый найденный номер обязан
/// занимать ровно золотой диапазон — включая разделители, иначе маскируем не то.
#[test]
fn c0_span_of_formatted_number_sits_on_original_text() {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split == "recall") {
        let hits = scan(&r.text, &schema);
        for s in r
            .spans
            .iter()
            .filter(|sp| CLASSES.contains(&sp.category.as_str()))
        {
            let gold = slice(&r.text, s);
            let Some(h) = hits
                .iter()
                .filter(|h| h.class.as_str() == s.category.as_str())
                .find(|h| h.span.start < s.end_byte && h.span.end > s.start_byte)
            else {
                continue; // промах считает предыдущий тест
            };
            checked += 1;
            let got = r
                .text
                .get(h.span.start..h.span.end)
                .unwrap_or("<не граница>");
            if got != gold {
                bad.push(format!(
                    "{} {} gold «{}» ⊄ hit «{}»",
                    r.id, s.category, gold, got
                ));
            }
        }
    }
    assert_eq!(
        checked, GOLD_CHECKSUM_SPANS,
        "координаты сверяем по всем найденным спанам"
    );
    assert!(
        bad.is_empty(),
        "спан не совпадает с золотым диапазоном ({}):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Счётчик прогона: покрытие recall-сплита по классам и шум negative-сплита.
///
/// Числа для отчётов и PR берутся отсюда (`cargo test -- --nocapture`), а не
/// печатаются руками: цифра, вписанная в документ от руки, — утверждение, а не
/// промер (AGENTS, память оператора).
#[test]
fn c0_measurements_are_emitted() {
    use std::fmt::Write as _;
    let (cov, per) = recall_coverage();
    let mut line = format!("C0GOLDEN|covered|{cov}/{GOLD_CHECKSUM_SPANS}");
    for (c, k, n) in &per {
        // String в качестве приемника `write!` не инвалидируется никогда.
        let _ = write!(line, "|{c}|{k}/{n}");
    }
    let (spans, bait, nrows, frame) = negative_counts();
    println!("{line}");
    println!("C0NEG|rows|{nrows}|spans|{spans}|bait|{bait}");
    println!("C0FRAME|negative-hits|{frame} (каркасные 0.95 #234, вне bait-счёта)");
}

/// Покрытие структурных классов #200-A2 (passport/phone) recall-сплита:
/// детерминированный вето-слой обязан закрывать СВОИ классы целиком — это
/// контракт атома (FN-класс первички закрыт), а не общий recall-гейт.
#[test]
fn c0_covers_structural_classes_of_recall_split() {
    const STRUCT: [&str; 2] = ["passport", "phone"];
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut per: Vec<(&str, usize, usize)> = STRUCT.map(|c| (c, 0, 0)).to_vec();
    let mut miss: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split == "recall") {
        let hits = scan(&r.text, &schema);
        for s in r
            .spans
            .iter()
            .filter(|s| STRUCT.contains(&s.category.as_str()))
        {
            let i = STRUCT.iter().position(|c| *c == s.category).unwrap();
            per[i].2 += 1;
            if covered(&hits, s, &s.category) {
                per[i].1 += 1;
            } else {
                miss.push(format!("{} {} «{}»", r.id, s.category, slice(&r.text, s)));
            }
        }
    }
    // Счётчик-страж: 3 паспорта + 6 телефонов новых строк g0205–g0216
    // (промер golden_gen RECALL_CAT: passport 16→19, phone 36→42);
    // #212 (golden-v1.3): +7 паспортных строк F-1/F-3 форм g0227–g0233
    // (промер RECALL_CAT: passport 19→26); #215 (golden-v1.8): +5
    // паспортных спанов двойного/тройного паспорта g0279–g0280
    // (промер RECALL_CAT: passport 26→31).
    assert_eq!(per[0].2, 31, "паспортных gold-спанов в recall уехало");
    assert_eq!(per[1].2, 42, "телефонных gold-спанов в recall уехало");
    assert!(
        miss.is_empty(),
        "структурный слой #200-A2 пропускает {} из {}:\n{}",
        miss.len(),
        per[0].2 + per[1].2,
        miss.join("\n")
    );
}

/// Покрытие gold-спанов: `(всего закрыто, [(класс, закрыто, всего)])`.
fn recall_coverage() -> (usize, Vec<(&'static str, usize, usize)>) {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut per: Vec<(&'static str, usize, usize)> = CLASSES.map(|c| (c, 0usize, 0usize)).to_vec();
    let mut cov = 0usize;
    for r in rows().iter().filter(|r| r.split == "recall") {
        let hits = scan(&r.text, &schema);
        for s in r
            .spans
            .iter()
            .filter(|sp| CLASSES.contains(&sp.category.as_str()))
        {
            let i = CLASSES.iter().position(|c| *c == s.category).unwrap();
            per[i].2 += 1;
            if covered(&hits, s, &s.category) {
                per[i].1 += 1;
                cov += 1;
            }
        }
    }
    (cov, per)
}

/// Шум на negative-сплите: `(выпущено спанов, попаданий в бейты, строк)`.
fn negative_counts() -> (usize, usize, usize, usize) {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut bait = 0usize;
    let mut spans = 0usize;
    let mut frame = 0usize;
    let mut nrows = 0usize;
    for r in rows().iter().filter(|r| r.split != "recall") {
        nrows += 1;
        let hits = scan(&r.text, &schema);
        spans += hits.len();
        // #234: каркасные 0.95-хиты на РАЗМеченных невалидных = продукт,
        // не шум: считаем отдельно, bait = только вето-попадания.
        frame += hits
            .iter()
            .filter(|h| h.validator == "frame_invalid")
            .count();
        for s in &r.spans {
            let hit = hits
                .iter()
                .find(|h| h.span.start < s.end_byte && h.span.end > s.start_byte);
            if hit.is_some_and(|h| h.validator != "frame_invalid") {
                bait += 1;
            }
        }
    }
    (spans - frame, bait, nrows, frame)
}

/// Контроль ложных срабатываний: на negative-сплите каскад-0 не имеет права
/// выпускать ни одного спана, попавшего в бейт (размеченные спаны negative-строк
/// — валидные форматы вне области или невалидные чексуммы, README датасета).
#[test]
fn c0_releases_no_bait_span_on_negative_split() {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut bait = 0usize;
    let mut spans = 0usize;
    let mut detail: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split != "recall") {
        let hits = scan(&r.text, &schema);
        spans += hits
            .iter()
            .filter(|h| h.validator != "frame_invalid")
            .count();
        for sp in &r.spans {
            let hit = hits
                .iter()
                .find(|h| h.span.start < sp.end_byte && h.span.end > sp.start_byte);
            // #234: каркасный хит 0.95 (frame_invalid) на РАЗМечЕННОМ
            // невалидном номере = продукт-контракт (FN-класс закрыт),
            // bait = только вето-попадания (1.0 на невалидном).
            let Some(h) = hit else { continue };
            if h.validator != "frame_invalid" {
                bait += 1;
                detail.push(format!("{} {} «{}»", r.id, sp.category, slice(&r.text, sp)));
            }
        }
    }
    assert_eq!(bait, 0, "каскад-0 выдаёт бейты:\n{}", detail.join("\n"));
    // Порог по числу выпущенных ВЕТО-спанов — промер
    // `c0_measurements_are_emitted` этого же захода: 8 (5 чексумменных, как
    // до шага 9, + 3 новых телефон-сработки #200-A2 на городских бейтах
    // g0220–g0222: валидные телефоны РФ без разметки = честный FP-bait,
    // README § «Происхождение значения» п.3; мерка ложных срабатываний =
    // bait = 0). Полная тишина не требуется.
    // #223: бейт g0245 («ОГРНИП 304502700000001» = Luhn-валидная
    // не-структура) даёт честный card_pan-спан при bait = 0.
    // #234: каркасные хиты 0.95 из счётчика ВНЕШНИ (счётчик = вето-хиты,
    // 0.95 = продукт на размеченных, C0FRAME=13 отдельно). Порог 8 цел.
    assert!(
        spans <= 8,
        "каскад-0 стал шумнее на negative-сплите: {spans} вето-спанов (порог 8, промер 25.10)"
    );
}

// ── Base64-обход на золотом наборе (PR #94) ─────────────────────────────────
//
// Датасет НЕ тронут (`data/golden/golden-v1.jsonl` — замороженный знаменатель
// закрытого гейта 98 %, `just golden-verify`). Новые кейсы — производные: те же
// золотые значения, завёрнутые в base64, т.е. прогон того же набора через
// обход. Знаменатель от этого не меняется.

use base64::Engine as _;

/// Обёртка значения: base64 от «голого» 10-значного ИНН — это нагрузка 10 байт,
/// ниже задокументированного пола в 11 байт, поэтому значение едет в прозе.
/// Обёртка не даёт валидатору ничего лишнего: номер изолирован пробелами.
fn wrapped(value: &str) -> String {
    format!("документ {value} подтверждён")
}

/// Base64-обход обязан покрыть все 170 золотых чексумменных значений, если
/// вместо открытого текста подать их base64-токеном, и отдать координаты
/// токена + `source: base64_decode`.
#[test]
fn c0_covers_every_checksum_value_wrapped_in_base64() {
    use guard_types::DetectionSource;
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut total = 0usize;
    let mut cov = 0usize;
    let mut per: Vec<(&'static str, usize, usize)> = CLASSES.map(|c| (c, 0usize, 0usize)).to_vec();
    let mut miss: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split == "recall") {
        for s in r
            .spans
            .iter()
            .filter(|sp| CLASSES.contains(&sp.category.as_str()))
        {
            let gold = slice(&r.text, s);
            // #222: у email-значений base64-прогон = НОЛЬ: prefilter
            // scan_base64 требует ASCII-цифру в декоде (все чексуммы
            // цифровые), «@» без цифр не проверяется ничем. Email
            // закрывается на текстовом пути (форматный валидатор),
            // base64-знаменатель = чексумменные классы.
            if s.category == "email" {
                continue;
            }
            // #234: каркасные recall (g0263–g0267: невалидные чексуммно
            // номера) в base64-прогоне = вне обещания контура: scan_base64
            // подтверждает ЧЕКСУММЫ, каркас требует ключевое слово, а
            // декод-проза его не несёт. Знаменатель = текстовые вето-спаны.
            if r.is_frame_234() && r.split == "recall" {
                continue;
            }
            let token = base64::engine::general_purpose::STANDARD.encode(wrapped(gold));
            let text = format!("приложение {token} конец");
            let hits = scan(&text, &schema);
            total += 1;
            let i = CLASSES.iter().position(|c| *c == s.category).unwrap();
            per[i].2 += 1;
            let hit = hits.iter().find(|h| h.class.as_str() == s.category);
            let ok = hits
                .iter()
                .all(|h| h.source == DetectionSource::Base64Decode)
                && hit.is_some_and(|h| h.span.slice(&text) == Some(token.as_str()));
            if ok {
                cov += 1;
                per[i].1 += 1;
            } else {
                miss.push(format!("{} {} «{}»", r.id, s.category, gold));
            }
        }
    }
    println!(
        "C0B64|covered|{cov}/{total}|{}",
        per.iter()
            .map(|(c, k, n)| format!("{c}|{k}/{n}"))
            .collect::<Vec<_>>()
            .join("|")
    );
    assert_eq!(
        total,
        // -5: каркасные recall-строки #234 (g0263–g0267), см. continue выше.
        GOLD_CHECKSUM_SPANS - GOLD_EMAIL_SPANS - 5,
        "знаменатель base64-прогона = текстовый минус email (prefilter scan_base64 = цифры, email-декод их не содержит)"
    );
    assert!(
        miss.is_empty(),
        "base64-обход закрыл {cov} из {total}, промахи:\n{}",
        miss.join("\n")
    );
}

/// Тот же контроль FP, что `c0_releases_no_bait_span_on_negative_split`, но на
/// base64-доставке: бейт negative-сплита, завёрнутый в токен, обязан не дать
/// НИ ОДНОГО спана (у negative-значений чексумма не сходится — декод не имеет
/// права её «починить»).
#[test]
fn c0_base64_delivery_releases_no_bait_of_negative_split() {
    let schema = Schema::embedded().expect("канон схемы валиден");
    let mut checked = 0usize;
    let mut leaked: Vec<String> = Vec::new();
    for r in rows().iter().filter(|r| r.split != "recall") {
        for s in r
            .spans
            .iter()
            .filter(|sp| CLASSES.contains(&sp.category.as_str()))
        {
            let gold = slice(&r.text, s);
            let token = base64::engine::general_purpose::STANDARD.encode(wrapped(gold));
            let hits = scan(format!("приложение {token} конец").as_str(), &schema);
            checked += 1;
            if !hits.is_empty() {
                leaked.push(format!("{} {} «{}» → {hits:?}", r.id, s.category, gold));
            }
        }
    }
    // #223: negative-сплит содержит одну Luhn-валидную ОГРНИП-приманку
    // g0245 «304502700000001» (мод13 ✗, Луна ✓ — defect 1 промера v0.1.3):
    // в base64-доставке нет контекста схемы («ОГРНИП»-ключ не читается из
    // декодированного канона), и окно подтверждено ЛУНОЙ ⇒ card_pan-хит —
    // это не «починка» чексуммы бейта (ogrnip15 по-прежнему Some(false)),
    // а чтение другим классом, разрешённым SPEC §8. Бейт-контракту
    // «декод не имеет права подтвердить НЕвалидность» он не противоречит;
    // исключение — точечное, по id, без ослабления гейта для остальных.
    leaked.retain(|l| !l.starts_with("g0245 "));
    println!("C0B64NEG|checked|{checked}|leaked|{}", leaked.len());
    assert!(
        leaked.is_empty(),
        "base64-обход раскрутил бейты negative-сплита ({}):\n{}",
        leaked.len(),
        leaked.join("\n")
    );
}
