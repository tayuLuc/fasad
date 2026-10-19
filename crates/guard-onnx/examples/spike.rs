//! SPIKE(step2) — SPEC §10 шаг 2 / issue #6: RSS и латентность ORT на реальных весах.
//!
//! Это НЕ рантайм-код — промер до написания `guard-onnx` (шаг 4). Вывод
//! machine-readable: строки `METRIC|<ключ>|<число MiB|мс>` и `IO|…` (контракт
//! графа), из них собирается `docs/model-audit.md`.
//!
//! Запуск (после `scripts/fetch-models.sh`, веса в ~/.cache/fasad-models):
//! ```text
//! cargo run --release --features ort-inference --example spike -- --arb --lockr
//! ```
//! Контракт dylib (нить N6, ревью #32): build И run — ОДНИМИ env
//! (`ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=…`, цель `just spike-dylib`).
//! Plain-запуск бинаря после build БЕЗ env = SIGSEGV: ort-sys идёт путём
//! download-binaries (статика pyke 1.23) и `copy-dylibs` выкладывает шейды
//! `target/release/examples/libonnxruntime*.dylib` (1.23), которые затирают
//! dylib 1.31 рядом с бинарём (промер ревью #32: краш кадром в 0x0; лечится
//! `rm target/release/examples/libonnxruntime*.dylib` или rebuild с env).
//! CI НЕ требует весов и НЕ требует орта: без фичи `ort-inference` example —
//! no-op; тест-прокси сборки помечен `#[ignore]` (`cargo test` его считает,
//! не запускает). Прогон — только рукаместо (наша машина, macOS/Linux).
//!
//! Контракт unsafe (итог ревью #9): workspace `unsafe_code = deny` + `#![forbid(unsafe_code)]`
//! во всех src-крейтах; spike — example, точечный `#[allow]` на `mod ffi` (промер:
//! работает без всяких RUSTFLAGS). Рантайм-код (шаг 4) unsafe не содержит.

#![allow(
    missing_docs,
    dead_code, // spike без фичи ort-inference: main no-op, скелет мёртв by design
    clippy::allow_attributes_without_reason,
    reason = "SPIKE(step2): бинарь-промер issue #6; бинарь без фичи нет — см. cfg"
)]

use std::path::PathBuf;
use std::time::Instant;

/// SPIKE(step2): единственная FFI-граница в репозитории.
///
/// Rationale (issue #6, ревью #9): workspace-lint `deny` перебивается точечным
/// `allow` на этом mod (промерен вариант `-F`: inner-allow не работает — E0453,
/// поэтому в workspace стоит deny, а src-крейты держат forbid изнутри).
/// Небезопасная граница замкнута в C (`rss_mach.c`, layout-ассерты); Rust-мост
/// — dlopen/dlsym по dylib (см. build.rs), единственный unsafe-остров spike.
#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "FFI-остров example: граница небезопасности замкнута в C (rss_mach.c, _Static_assert layout); контракт forbid — для src-крейтов (#![forbid] в lib.rs), spike не prod-путь"
)]
#[cfg(feature = "ort-inference")]
mod ffi {
    // Safe-FFI: `double f(void)` без variadic/поинтеров — extern-объявление
    // разрешено без `unsafe extern` в Rust 2024; unsafe остаётся целиком в C
    // (task_info + layout _Static_assert). Контракт workspace forbid(unsafe_code)
    // для src-крейтов не затронут: это example.
    const RTLD_LAZY: i32 = 0x1;
    unsafe extern "C" {
        fn dlopen(filename: *const i8, flag: i32) -> *mut std::ffi::c_void;
        fn dlsym(handle: *mut std::ffi::c_void, symbol: *const i8) -> *mut std::ffi::c_void;
        fn dlclose(handle: *mut std::ffi::c_void) -> i32;
    }

    /// Мост к C-острову (issue #6): прямой extern не долетает до release-линковки
    /// (`docs/model-audit.md` §5); dylib грузится dlopen по полному пути из
    /// `SPIKE_DYLIB`, фанк-пойтер кэшируется `OnceLock` (nit #18 ревью #9).
    fn rss_fn() -> Option<extern "C" fn() -> f64> {
        static CACHE: std::sync::OnceLock<Option<extern "C" fn() -> f64>> =
            std::sync::OnceLock::new();
        *CACHE.get_or_init(|| {
            // dylib собирается build.rs, путь приходит env-переменной компиляции.
            // dlopen(полный путь) — deterministic (промер 19.10: статический путь
            // линкуется только в dev). Хэндл НЕ закрываем (nit #18 ревью #9):
            // spike — одноразовый процесс, dylib живёт до выхода.
            unsafe {
                let h = dlopen(
                    concat!(env!("SPIKE_DYLIB"), "\0").as_ptr().cast(),
                    RTLD_LAZY,
                );
                if h.is_null() {
                    return None;
                }
                let sym = dlsym(h, c"fasad_spike_rss".as_ptr().cast());
                if sym.is_null() {
                    dlclose(h);
                    return None;
                }
                // SAFETY: сигнатура `double (void)` зафиксирована rss_mach.c.
                Some(std::mem::transmute::<
                    *mut std::ffi::c_void,
                    extern "C" fn() -> f64,
                >(sym))
            }
        })
    }

    pub fn rss_mib() -> Option<f64> {
        let f = rss_fn()?;
        let v = f();
        if v >= 0.0 { Some(v) } else { None }
    }
}

/// RSS процесса в MiB:
/// macOS — `task_info(TASK_VM_INFO).internal` (private+resident, «Память» из
/// монитора активности, FFI через C-остров — см. `mod ffi`); Linux — `VmRSS` из
/// /proc/self/status; Windows/прочее — None (CI spike не прогоняет).
#[cfg(all(target_os = "macos", feature = "ort-inference"))]
fn rss_mib() -> Option<f64> {
    ffi::rss_mib()
}

#[cfg(all(target_os = "macos", not(feature = "ort-inference")))]
fn rss_mib() -> Option<f64> {
    None // spike без орта = no-op main, RSS не меряется
}

#[cfg(target_os = "linux")]
fn rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: f64 = line
        .trim_start_matches("VmRSS:")
        .trim_end_matches(" kB")
        .trim()
        .parse()
        .ok()?;
    #[allow(clippy::cast_possible_truncation, reason = "MiB из KiB, spike-промер")]
    Some(kib / 1024.0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rss_mib() -> Option<f64> {
    None
}

/// Кеш весов = контракт `scripts/fetch-models.sh` (`FASAD_MODEL_CACHE` или `~/.cache`).
fn cache_dir() -> PathBuf {
    std::env::var("FASAD_MODEL_CACHE").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".cache").join("fasad-models")
        },
        PathBuf::from,
    )
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--check") {
        println!("SPIKE(step2): --check — бинарь собран, веса не трогались");
        return;
    }
    let threads = arg_usize(&argv, "--threads").unwrap_or(4);

    #[cfg(feature = "ort-inference")]
    if let Err(e) = run_spike(&cache_dir(), &argv, threads) {
        eprintln!("SPIKE(step2): промер не завершился: {e}");
        std::process::exit(1);
    }
    #[cfg(not(feature = "ort-inference"))]
    {
        let _ = (&argv, threads);
        println!(
            "SPIKE(step2): собран без фичи ort-inference — no-op (так его держит CI; \
             промер гоняется --features ort-inference)"
        );
    }
}

fn arg_usize(argv: &[String], flag: &str) -> Option<usize> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .and_then(|v| v.parse().ok())
}

fn rss(label: &str) -> f64 {
    if let Some(mib) = rss_mib() {
        println!("METRIC|rss_mib_{label}|{mib:.1}");
        mib
    } else {
        println!("METRIC|rss_mib_{label}|na");
        0.0
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn p50(mut v: Vec<f64>) -> f64 {
    // nit #17 ревью #9: пустой прогон = 0.0 («na»), а не panic — потеря одной
    // метрики не должна валить весь промер (ср. rss()/na-ветку).
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn join_ms(v: &[f64]) -> String {
    v.iter()
        .map(|x| format!("{x:.0}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// SPIKE(step2): фиктивные RU-тексты для prefill, ~200 токенов по требованию
/// (у tokenizer-а `rubert` даёт 250–310 на абзац — близко к окну). Данные синтетические.
fn spike_texts() -> [&'static str; 3] {
    [
        "Здравствуйте! Меня зовут Анна Сергеевна Ковалёва, паспорт 45 07 серия 123456, \
         выдан ОУФМС по городу Москве 15.04.2007. Прописана в городе Казань, улица \
         Баумана, дом 44, квартира 12. Мой ИНН 7743013533, СНИЛС 112-233-445 95. \
         Телефон для связи: +7 916 123-45-67, электронная почта a.kovaleva@example.ru. \
         Банк: карта 2202 2011 3333 4444, срок действия 08/28. Я работаю в ООО Ромашка \
         с 2019 года, должность — ведущий юрист. Водительское удостоверение 77 AA \
         123456 категории B. Полис ОМС 1234-5678-9012-3456, военный билет RU-123456. \
         Пожалуйста, обработайте заявление и пришлите ответ по адресу 101000, Москва, \
         Старокиевский переулок 12 строение 1. Дополнительно сообщаю IP-адрес рабочего \
         станка 192.168.101.77 и URL корпоративного портала https://intranet.romashka.local \
         для сверки статуса заявки номер 4471-Б от одиннадцатого октября две тысячи \
         двадцать шестого года.",
        "Уважаемая служба поддержки! Сообщаю данные для восстановления доступа: ФИО \
         Дмитрий Олегович Соколов, дата рождения 03.09.1991, место рождения — город \
         Самара. Номер страхового свидетельства государственного пенсионного страхования \
         083-412-903 31, идентификационный номер налогоплательщика 631234567890. \
         Контактный мобильный номер телефона 8 (927) 222-11-33, резервный адрес \
         электропочты d.sokolov@mailbox.test. Паспорт гражданина РФ: серия 36 15, \
         номер 654321, код подразделения 631-042, выдан УВДМ Октябрьского района \
         города Самары 22.07.2015. Адрес регистрации: 443010, Самара, Ленинградская \
         улица, дом 28, офис 501. Адрес фактического проживания совпадает. Банковская \
         карта Мир 2202 2055 6666 7777, привязана к расчётному счёту для зачисления \
         заработной платы в ПАО Совкомбанк. Прошу подтвердить личность по двум \
         документам и восстановить доступ к личному кабинету в срок до пяти рабочих дней.",
        "Служебная записка: сотруднику отдела закупок Ивану Петровичу Громову оформить \
         командировку. Реквизиты: паспорт 45 14 номер 789456, выдан ОУФМС России по \
         Москве 30.11.2014, адрес проживания 125167, Москва, Ленинградский проспект, \
         дом 62, квартира 147. Телефон рабочего мобильного +7 (495) 987-65-43, \
         служебная электронная почта i.gromov@corp.example.org. ИНН работника \
         771423456789, СНИЛС 143-256-789 01. Полис обязательного медицинского \
         страхования 8888-7777-6666-5555. Маршрут: Москва — Нижний Новгород — Казань, \
         даты 12.11.2026 по 18.11.2026, гостиница Октябрьская, бронь номера 814. \
         Оплата картой Visa 4276 1234 5678 9012 через корпоративный счёт в АО ТБанк. \
         По прибытии предоставить отчёт и чеки; контактное лицо принимающей стороны — \
         Светлана Юрьевна Лебедева, +7 831 222-33-44, портал согласования \
         https://bpm.corp.example.org, IP ноутбука в домене 10.20.30.40.",
    ]
}

/// Маркерные special-токены Decide-разметки (id промерены из `tokenizer.json`
/// рев. `18271032`, манифест `models/manifest.md`; карточка @18271032 §Graph).
#[cfg(feature = "ort-inference")]
mod decide_marker {
    /// Структурные спец-токены Decide-разметки: имя + id (промерены из
    /// `tokenizer.json` рев. `18271032`, манифест `models/manifest.md`).
    /// Маркер `marker_positions` — индекс токена `[L]` (первичка: `config.json`
    /// глоссарий «index of each `[L]` token» + карточка @18271032 §Graph;
    /// референс `fastino-ai/GLiNER2` `gliner2/classification/scoring.py` греет
    /// эмбеддинг СРАЗУ ПОСЛЕ `[L]` — для Decide-графа, собирающего hidden на
    /// `[L]`-позициях, не конфликтует; промер 4b-2a + ревью #32 N1).
    pub const SPECIALS: [(&str, u32); 10] = [
        ("[SEP_STRUCT]", 128_001),
        ("[SEP_TEXT]", 128_002),
        ("[P]", 128_003),
        ("[C]", 128_004),
        ("[E]", 128_005),
        ("[R]", 128_006),
        ("[L]", 128_007),
        ("[EXAMPLE]", 128_008),
        ("[OUTPUT]", 128_009),
        ("[DESCRIPTION]", 128_010),
    ];
    // Нить N3 (ревью #32): `groups()` режет группы по именованным константам
    // из той же таблицы, без магических литералов.
    pub const SEP_STRUCT_ID: u32 = special_id("[SEP_STRUCT]");
    pub const SEP_TEXT_ID: u32 = special_id("[SEP_TEXT]");

    const fn special_id(name: &str) -> u32 {
        let mut i = 0;
        let mut found = 0u32;
        while i < SPECIALS.len() {
            if bytes_eq(SPECIALS[i].0.as_bytes(), name.as_bytes()) {
                found = SPECIALS[i].1;
            }
            i += 1;
        }
        // 0 в vocab Decide — [PAD]; имя заведомо из таблицы (вызовы констант
        // выше), хвост детерминированно недостижим. Panic с форматной строкой
        // в const-fn запрещён (E0015, промер гейта 20.10).
        found
    }

    const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    pub fn id_of(vocab: &std::collections::HashMap<String, u32>, name: &str) -> Option<u32> {
        let manifest = SPECIALS.iter().find(|(n, _)| *n == name)?.1;
        let live = vocab.get(name).copied()?;
        if manifest == live { Some(live) } else { None }
    }

    /// Контракт-проба 4b-2a (issue #23): живые `marker_positions` по реальной
    /// токенизации Decide-layout'а.
    ///
    /// Возвращает ГРУППИРОВАННЫЕ позиции маркеров (offset группы → позиции
    /// `[L]`-маркеров внутри неё), группы режутся по `SEP_STRUCT_ID` /
    /// `SEP_TEXT_ID` (константы из `SPECIALS`) — границам схем и схемы↔текст из
    /// `_transform_schema`/`_format_input_with_mapping` (первичка референса
    /// `fastino-ai/GLiNER2@main`: `processor.py::cls_marker_indices` =
    /// позиции routing-маркеров на схему, `classification/scoring.py` =
    /// `embs[1:]` — `[P]`-строка отдельная, `[L]`-маркер = эмбеддинг МЕТКИ;
    /// `export_onnx.py`: один `GatherElements` на позицию).
    ///
    /// Форма `(usize, Vec<usize>)` — «минимальный честный контракт» вопросно-
    /// условной разметки из ТЗ: одна группа = один вопрос, softmax внутри
    /// группы (карточка @18271032 §Graph: «softmax within each question's
    /// markers»). При `marker_ids=[L],[L]` группы = `[L]`-маркеры схем; для
    /// извлечения (`[E]`/`[R]`) — те же группы с другим id.
    ///
    /// Пустые группы не выдаются (ленивое выполнение `GatherElements` не роняет
    /// сессию на пустых маркерах — промер 4b-0, audit §5 п.3).
    pub fn groups(ids: &[u32], marker_ids: [u32; 2]) -> Vec<(usize, Vec<usize>)> {
        let mut out: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut cur: Vec<usize> = Vec::new();
        for (pos, &id) in ids.iter().enumerate() {
            if id == marker_ids[0] || id == marker_ids[1] {
                cur.push(pos);
            } else if (id == SEP_STRUCT_ID || id == SEP_TEXT_ID) && !cur.is_empty() {
                let first = cur[0];
                out.push((first, std::mem::take(&mut cur)));
            }
        }
        if !cur.is_empty() {
            let first = cur[0];
            out.push((first, cur));
        }
        out
    }
}

/// Реальный вход Decide: ОДИН `encode(join, false)` по конкатенации сегментов
/// (разделители — обычные пробелы) — HF/python-эквивалент
/// `tokenizer(text, add_special_tokens=False)`: HF-прогон step-2 строил вход
/// именно цельным `encode` (промер 4b-2a: побайтный сплайс отдельных `encode`
/// ≠ конкатенация на стыке `.` + `[SEP_TEXT]` — Metaspace склеивает ведущий
/// `▁` с точкой предыдущего сегмента). Post-процессор [CLS]/[SEP] снят
/// (`with_post_processor(None)`), сама разметка Decide спецы не содержит
/// (карточка @18271032 §Graph: «No `[CLS]`/`[SEP]`»).
///
/// Спец-маркеры (`single_word=false`, `normalized=false`) модуль
/// `AddedVocabulary::extract_and_normalize` вырезает до нормализации; ложных
/// склеек нет: фрагменты `[`/`]` в vocab есть (промер), строк `p]`, `l]`,
/// `[p` — нет.
#[cfg(feature = "ort-inference")]
fn encode_text_segments(
    tok: &tokenizers::Tokenizer,
    segments: &[&str],
) -> Result<Vec<u32>, String> {
    let mut whole = String::new();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            whole.push(' ');
        }
        whole.push_str(seg);
    }
    let enc = tok
        .encode(whole.as_str(), false)
        .map_err(|e| format!("encode(whole): {e}"))?;
    Ok(enc.get_ids().to_vec())
}

/// Живая сверка входа (гейт «промер, не вера») — НЕ наивный decode строки:
/// Metaspace-декодер склеивает `▁(` с соседями (живой промер 4b-2a:
/// `decode → "([p]"`), потому сравнение идёт по словам/маркерам:
///     1) каждое слово конкатенации обязано остаться в decode (упорядоченный
///        подпоследовательностный скан — потеря слова = провал контракта);
///     2) все спец-токены конкатенации присутствуют в `ids` своими id (промер
///        `AddedVocabulary::extract_and_normalize`: special+normalized=false
///        вырезаются до нормализации и не разбиваются).
/// Возвращает число спец-токенов в `ids`; [UNK] = ошибка контракта.
#[cfg(feature = "ort-inference")]
fn check_splice(
    tok: &tokenizers::Tokenizer,
    ids: &[u32],
    segments: &[&str],
) -> Result<usize, String> {
    let unk = ids.iter().filter(|&&id| id == 3).count();
    if unk > 0 {
        return Err(format!(
            "{unk} токенов [UNK] в живом входе — контракт токенизации сломан"
        ));
    }
    let mut whole = String::new();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            whole.push(' ');
        }
        whole.push_str(seg);
    }
    let back = tok
        .decode(ids, false)
        .map_err(|e| format!("decode(live): {e}"))?;
    let norm = |s: &str| -> String {
        s.to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let nb = norm(&back);
    let nw = norm(&whole);
    // (2) спец-токены конкатенации обязаны быть в ids своими id.
    let mut pos_scan = 0usize;
    let mut widx = 0usize;
    let wtoks: Vec<&str> = nw.split(' ').collect();
    while widx < wtoks.len() {
        let w = wtoks[widx];
        let mid = decide_marker::SPECIALS
            .iter()
            .find(|(n, _)| *n == w)
            .map(|(_, id)| *id);
        if let Some(mid) = mid {
            if !ids[pos_scan..].contains(&mid) {
                return Err(format!(
                    "спец-токен {w} потерян в id-последовательности (скан с {pos_scan})"
                ));
            }
            while ids[pos_scan] != mid {
                pos_scan += 1;
            }
            pos_scan += 1;
        } else {
            break;
        }
        widx += 1;
    }
    // (1) скан слов: каждое некопец-слово конкатенации встречается в decode
    // после предыдущего (упорядоченно, непересекающимися вхождениями).
    let mut cursor = 0usize;
    for w in &wtoks[widx..] {
        if w.is_empty() {
            continue;
        }
        match nb[cursor..].find(w) {
            Some(rel) => cursor += rel + w.len(),
            None => {
                return Err(format!(
                    "decode живого входа потерял слово {w:?} после смещения {cursor}"
                ));
            }
        }
    }
    Ok(ids
        .iter()
        .filter(|&&id| decide_marker::SPECIALS.iter().any(|(_, mid)| id == *mid))
        .count())
}

#[cfg(feature = "ort-inference")]
fn run_spike(
    cache: &std::path::Path,
    argv: &[String],
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    rss("baseline");
    let t0 = Instant::now();
    // ORT-окружение: телеметрия OFF (AGENTS: никакой телеметрии).
    let env = ort::init().with_telemetry(false).build()?;
    println!("METRIC|env_init_ms|{:.1}", ms(t0));
    rss("after_env");

    // Что мерим: только явно запрошенное флагами (issue: основной кандидат —
    // arbiter q4f16; lockR — второй график; backup'и по итогам вердикта).
    if argv.iter().any(|a| a == "--arb") {
        measure_arbiter(cache, &env, threads)?;
    }
    if argv.iter().any(|a| a == "--arb-probe") {
        arbiter_probe(cache, &env, threads)?;
    }
    if argv.iter().any(|a| a == "--lockr") {
        measure_lockr(cache, &env, threads)?;
    }
    Ok(())
}

/// Контракт-проба 4b-0 (issue #23): НЕ качество инференса — контракт Decide-графа
/// до декодера 4b-2. Промерено живьём 19.10 (/tmp/probe4b0.out, dylib 1.31):
/// входы графа = `input_ids`/`attention_mask`/`marker_positions` INT64
/// (batch,L)/(batch,M),
/// выход = `logits` f32 (batch,M) — гипотеза двухвходовости ОПРОВЕРГНА
/// реальным графом (issue #23 комментарий). Прогон с нулевым `marker_positions`
/// НЕ роняет `GatherElements`: §5.3-падение step-2 требовало НЕПУСТЫХ маркеров
/// без семантики — контракт дефекта воспроизводится только с живыми парами
/// (4b-2). `load_ms`/`delta_rss` сняты для audit (q4f16 + `external_data` 523 МБ).
#[cfg(feature = "ort-inference")]
fn arbiter_probe(
    cache: &std::path::Path,
    env: &ort::environment::Environment,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use ort::value::Tensor;

    let path = cache
        .join("onnx-community/GLiNER2.5-Decide-ONNX")
        .join("onnx/model_q4f16.onnx");
    let tok_path = cache
        .join("onnx-community/GLiNER2.5-Decide-ONNX")
        .join("tokenizer.json");
    require_weight(&path)?;
    require_weight(&tok_path)?;

    // (1) Токенизатор Decide: Unigram + added_tokens (промер tokenizer.json:
    // [PAD]0 [CLS]1 [SEP]2 [UNK]3 [MASK]128000 [SEP_STRUCT] [SEP_TEXT] [P] [C]
    // [E] [R] [L] [EXAMPLE] [OUTPUT] [DESCRIPTION]). SPAN-разметку строит
    // pre-tokenizer-конфиг — декодер обязан читать его, не угадывать.
    let tok = tokenizers::Tokenizer::from_file(&tok_path)
        .map_err(|e| format!("токенизатор Decide ({}): {e}", tok_path.display()))?;
    let vocab = tok.get_vocab(true);
    let mut n_added = 0usize;
    for marker in [
        "[CLS]",
        "[SEP]",
        "[UNK]",
        "[MASK]",
        "[SEP_STRUCT]",
        "[SEP_TEXT]",
        "[P]",
        "[C]",
        "[E]",
        "[R]",
        "[L]",
        "[EXAMPLE]",
        "[OUTPUT]",
        "[DESCRIPTION]",
    ] {
        let have = vocab.contains_key(marker);
        n_added += usize::from(have);
        println!("PROBE|vocab_marker|{marker}|{have}");
    }

    // (2) IO-контракт: open_session = external data + Disable-оптимизации
    // (контракт audit §5.1); load-метрики для бюджета q4f16.
    let base = rss("before_load_probe");
    let t = Instant::now();
    let mut session = open_session(env, &path, threads)?;
    println!("METRIC|load_ms_probe|{:.1}", ms(t));
    println!(
        "METRIC|delta_load_mib_probe|{:.1}",
        rss("after_load_probe") - base
    );
    print_io(&session, "probe");

    // (3) Живая токенизация RU-фразы, входы по фактическим именам; маркерная
    // ветка при нулевых парах не исполняется (см. док) — ок/ошибка ORT.
    let enc = tok
        .encode("Мой ИНН 7743013533, СНИЛС 112-233-445 95.", true)
        .map_err(|e| format!("encode: {e}"))?;
    let ids: Vec<i64> = enc.get_ids().iter().map(|&u| i64::from(u)).collect();
    let l = ids.len();
    println!("PROBE|tokens|{l}|added_in_vocab|{n_added}");
    let mask: Vec<i64> = vec![1i64; l];
    let mut inputs: Vec<(String, ort::value::DynTensor)> = Vec::new();
    for inp in session.inputs() {
        let name = inp.name().to_string();
        let v = match name.as_str() {
            "input_ids" => Tensor::from_array(([1usize, l], ids.clone().into_boxed_slice()))?,
            "marker_positions" => {
                Tensor::from_array(([1usize, 2], vec![0i64, 0].into_boxed_slice()))?
            }
            _ => Tensor::from_array(([1usize, l], mask.clone().into_boxed_slice()))?,
        };
        inputs.push((name, v.upcast()));
    }
    match session.run(inputs) {
        Ok(outputs) => {
            println!("PROBE|run|ok|outputs={}", outputs.values().count());
            Ok(())
        }
        Err(e) => {
            let es = e.to_string().replace('\n', " ");
            let gather_oor = es.contains("Out of range value in index tensor");
            println!("PROBE|run|ort_error|gather_oor={gather_oor}|{es}");
            Err(format!("probe-прогон: {es}").into())
        }
    }
}

/// Каркас промера: load → RSS-дельта → прогоны → p50.
#[cfg(feature = "ort-inference")]
struct Probe {
    role: &'static str,
    load_ms: f64,
    delta_load_mib: f64,
    runs_ms: Vec<f64>,
    rss_after_runs: f64,
}

#[cfg(feature = "ort-inference")]
fn emit(p: &Probe) {
    println!("METRIC|load_ms_{}|{:.1}", p.role, p.load_ms);
    println!("METRIC|delta_load_mib_{}|{:.1}", p.role, p.delta_load_mib);
    println!("METRIC|run_p50_ms_{}|{:.1}", p.role, p50(p.runs_ms.clone()));
    println!("METRIC|run_all_ms_{}|{}", p.role, join_ms(&p.runs_ms));
    println!(
        "METRIC|rss_mib_after_runs_{}|{:.1}",
        p.role, p.rss_after_runs
    );
}

/// `lockR/rubert-base-pii-ner-onnx` fp16: `BertForTokenClassification`, int64 IO,
/// единый файл без external data (контроль паттерна памяти). Токенизация —
/// `tokenizer.json` из кеша (`WordPiece`), окно pad 256 (SPEC §5.3).
#[cfg(feature = "ort-inference")]
fn measure_lockr(
    cache: &std::path::Path,
    env: &ort::environment::Environment,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use ort::value::Tensor;

    let path = cache
        .join("lockR/rubert-base-pii-ner-onnx")
        .join("model.optimized.fp16.onnx");
    let tok_path = cache
        .join("lockR/rubert-base-pii-ner-onnx")
        .join("tokenizer.json");
    require_weight(&path)?;
    require_weight(&tok_path)?;

    // Входы готовим ДО замера load: токенизатор и тензоры не входят в дельту RSS.
    let mut inputs_by_text: Vec<Vec<(String, ort::value::DynTensor)>> = Vec::new();
    let tok = tokenizers::Tokenizer::from_file(&tok_path)
        .map_err(|e| format!("токенизатор lockR ({}): {e}", tok_path.display()))?;
    let pad_id = tok.get_vocab(true).get("[PAD]").copied().unwrap_or(0);
    let target = 256usize;
    for text in spike_texts() {
        let mut enc = tok.encode(text, true).map_err(|e| format!("encode: {e}"))?;
        println!("IO|tokens|lockr|{}", enc.len());
        enc.pad(
            target,
            pad_id,
            0,
            "[PAD]",
            tokenizers::utils::padding::PaddingDirection::Right,
        );
        let ids: Vec<i64> = enc.get_ids().iter().map(|&v| i64::from(v)).collect();
        let mask: Vec<i64> = enc
            .get_attention_mask()
            .iter()
            .map(|&v| i64::from(v))
            .collect();
        let types = vec![0i64; target];
        inputs_by_text.push(vec![
            (
                "input_ids".to_string(),
                Tensor::from_array(([1usize, target], ids.into_boxed_slice()))?.upcast(),
            ),
            (
                "attention_mask".to_string(),
                Tensor::from_array(([1usize, target], mask.into_boxed_slice()))?.upcast(),
            ),
            (
                "token_type_ids".to_string(),
                Tensor::from_array(([1usize, target], types.into_boxed_slice()))?.upcast(),
            ),
        ]);
    }

    let base = rss("before_load_extractor1b");
    let t = Instant::now();
    let mut session = open_session(env, &path, threads)?;
    let load_ms = ms(t);
    let after = rss("after_load_extractor1b");
    print_io(&session, "extractor1b");

    // Порядок входов = порядок session.inputs(); сортируем по объявленным именам.
    let order: Vec<String> = session
        .inputs()
        .iter()
        .map(|i| i.name().to_string())
        .collect();
    let mut runs = Vec::new();
    for inputs in &inputs_by_text {
        let ordered: Vec<(String, ort::value::DynTensor)> = order
            .iter()
            .filter_map(|name| {
                inputs
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| (name.clone(), v.clone()))
            })
            .collect();
        let tr = Instant::now();
        let outputs = session.run(ordered)?;
        // Черновой разбор выхода: форма/число элементов (содержательный
        // инференс/декод — шаг 4).
        let elems: usize = outputs
            .iter()
            .map(|(_, v)| match v.try_extract_tensor::<f32>() {
                Ok((s, d)) => {
                    println!("IO|out_shape|lockr|{:?}|{}", s, d.len());
                    d.len()
                }
                Err(_) => 0,
            })
            .sum();
        runs.push(ms(tr));
        std::hint::black_box(elems);
    }
    let rss_after = rss("after_runs_extractor1b");
    emit(&Probe {
        role: "extractor1b",
        load_ms,
        delta_load_mib: after - base,
        runs_ms: runs,
        rss_after_runs: rss_after,
    });
    Ok(())
}

/// onnx-community/GLiNER2.5-Decide-ONNX q4f16 + external data: load (главный
/// вопрос промера: дельта RSS vs размер `.onnx_data` — гипотеза ревьюера «ORT
/// мапит external data целиком») + IO-контракт + прогоны. 4b-2a (issue #23):
/// входы — ЖИВАЯ токенизация `spike_texts()` + живые маркеры Decide вместо
/// step-2 заглушки `3 + idx%512`, из-за которой §5.3 падал
/// `GatherElements: Out of range value in index tensor`.
///
/// Контракт маркеров (первичка этого прогона): карточка
/// `onnx-community/GLiNER2.5-Decide-ONNX@18271032` §Graph — layout
/// `( [P] prompt ( [L] label_1 [L] label_2 … ) ) [SEP_STRUCT] ( [P] … )
/// [SEP_TEXT] word word … .`, `marker_positions` = «index of every `[L]`
/// token», logits = по логиту на маркер; экспорт `conversion/export_onnx.py`
/// (там же) = `GatherElements(hidden, marker_positions)` — маркерная ветка
/// исполняется при ЛЮБЫХ int64-позициях, OOB-индекс (> L) роняет именно её
/// (это и есть §5.3); падение step-2 = OOB, а не «пустые маркеры» (правка
/// рулинга 4b-0 ниже в audit addendum).
/// Констрэкт реальной Decide-разметки (стадия 1 `measure_arbiter`): EN-подсхема
/// вопросов+меток (модель обучена на английском, карточка §Limits) поверх
/// RU-state из `spike_texts()`. `decide_marker::groups(ids, [L],[L])` даёт по
/// группе на классификационную схему; `first=(первый [L] группы)` — именно
/// индекс `[L]`, контракт `marker_positions` (карточка @18271032). Нить N1
/// (ревью #32): маркер = позиция `[L]`; референс-классификатор `GLiNER2` греет
/// эмбеддинг ПОСЛЕ `[L]` (`scoring.py` `embs[1:]`) — не конфликтует: Decide-граф
/// собирает hidden на `[L]`-позициях (первички: карточка §Graph,
/// `conversion/export_onnx.py`, `conversion/verify_parity.py` L34-37).
/// Возвращает id-последовательность и группы.
/// Живой констрэкт: id-последовательность + сгруппированные маркерные позиции.
#[cfg(feature = "ort-inference")]
type ArbLayout = (Vec<u32>, Vec<(usize, Vec<usize>)>);

#[cfg(feature = "ort-inference")]
fn arb_live_layout(
    tok: &tokenizers::Tokenizer,
    vocab: &std::collections::HashMap<String, u32>,
) -> Result<ArbLayout, Box<dyn std::error::Error>> {
    let l_id = decide_marker::id_of(vocab, "[L]")
        .ok_or("маркер [L] не в vocab Decide (сверка с манифестом не прошла)")?;
    let p_id = decide_marker::id_of(vocab, "[P]")
        .ok_or("маркер [P] не в vocab Decide (сверка с манифестом не прошла)")?;
    let [t0, t1, t2] = spike_texts();
    let schema = "( [P] Is there a full name of a person ? ( [L] person [L] no ) \
                   [SEP_STRUCT] ( [P] Is there a tax identification number ? \
                   ( [L] tin [L] no ) [SEP_STRUCT] ( [P] Is there a bank card number ? \
                   ( [L] card [L] no ) ) ) [SEP_TEXT]";
    let state = format!("{t0} {t1} {t2}");
    let segments: Vec<&str> = vec![schema, state.as_str()];
    let ids_u32 = encode_text_segments(tok, &segments)?;
    let groups = decide_marker::groups(&ids_u32, [l_id, l_id]);
    if groups.is_empty() {
        return Err("decide_marker::groups вернул пусто на живом входе — контракт сломан".into());
    }
    let n_special = check_splice(tok, &ids_u32, &segments)?;
    if n_special == 0 {
        return Err("ни одного спец-токена в живом входе — констрэкт не токенизируется".into());
    }
    println!(
        "MARKER|arb|pairs={}|first=({},{})|l_tokens={}|p_tokens={}|tokens={}",
        groups.len(),
        groups[0].1[0],
        *groups[0].1.last().unwrap_or(&groups[0].1[0]),
        ids_u32.iter().filter(|&&id| id == l_id).count(),
        ids_u32.iter().filter(|&&id| id == p_id).count(),
        ids_u32.len()
    );
    Ok((ids_u32, groups))
}

/// ФАЗА A (4b-2a): воспроизведение §5.3 — та же живая токенизация, маркерный
/// вход = step-2 заглушка `3 + i%512` (256 значений). Промер: с L=1235 заглушка
/// целиком легальна и НЕ падает (ленивый `GatherElements` индексы < L в bounds);
/// точный §5.3 = индекс ≥ L, поэтому добавлен заглавный OOB-индекс L+4096 —
/// ошибка ORT печатается дословно, обхода нет (п.3 ТЗ).
#[cfg(feature = "ort-inference")]
fn arb_trap(
    session: &mut ort::session::Session,
    ids: &[i64],
    mask: &[i64],
    l: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fake: Vec<i64> = (0..256i64).map(|i| 3 + (i % 512)).collect();
    fake.push(i64::try_from(l + 4096).unwrap_or(i64::MAX));
    let trap = session
        .run(tensors_for(session, ids, mask, &fake)?)
        .map(|_| ())
        .map_err(|e| e.to_string().replace('\n', " "));
    match &trap {
        Ok(()) => println!("MARKER|arb|trap=unexpected_ok"),
        Err(e) => println!("MARKER|arb|trap=ort_error|msg={e}"),
    }
    Ok(())
}

#[cfg(feature = "ort-inference")]
fn measure_arbiter(
    cache: &std::path::Path,
    env: &ort::environment::Environment,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = cache
        .join("onnx-community/GLiNER2.5-Decide-ONNX")
        .join("onnx/model_q4f16.onnx");
    let data = {
        let mut p = path.clone().into_os_string();
        p.push("_data");
        PathBuf::from(p)
    };
    let tok_path = cache
        .join("onnx-community/GLiNER2.5-Decide-ONNX")
        .join("tokenizer.json");
    require_weight(&path)?;
    require_weight(&data)?;
    require_weight(&tok_path)?;
    println!("IO|external_data_bytes|{}", std::fs::metadata(&data)?.len());

    // Токенизатор + живые входы готовим ДО замера load: дельта RSS = сессия.
    // Post-процессор [CLS]/[SEP] снимаем — контракт Decide §Graph: «No
    // `[CLS]`/`[SEP]`» (промер tokenizers 0.23.2 `tokenizer/mod.rs`: спецтокены
    // добавляет только post_process).
    let mut tok = tokenizers::Tokenizer::from_file(&tok_path)
        .map_err(|e| format!("токенизатор Decide ({}): {e}", tok_path.display()))?;
    tok.with_post_processor(Option::<tokenizers::processors::template::TemplateProcessing>::None);
    // NB: `get_vocab(true)` ниже намеренно включает added tokens — id маркеров
    // сверяются с манифестом по реальному vocab.
    let vocab = tok.get_vocab(true);
    for (name, _) in decide_marker::SPECIALS {
        let ok = decide_marker::id_of(&vocab, name).is_some();
        println!("MARKER|vocab|{name}|{ok}");
        if !ok {
            return Err(format!("спец-токен {name} не в vocab/не сверен с манифестом").into());
        }
    }
    // id [L]/[P] сверяются и используются в arb_live_layout.

    let (ids_u32, groups) = arb_live_layout(&tok, &vocab)?;
    let l = ids_u32.len();
    let ids: Vec<i64> = ids_u32.iter().map(|&u| i64::from(u)).collect();
    let mask: Vec<i64> = vec![1i64; l];

    // Сессию поднимаем ПОСЛЕ подготовки живых входов: дельта RSS = сессия,
    // токен-работа в дельту не входит (контракт промера §3 audit).
    let base = rss("before_load_arbiter");
    let t = Instant::now();
    let mut session = open_session(env, &path, threads)?;
    let load_ms = ms(t);
    let after = rss("after_load_arbiter");
    print_io(&session, "arbiter");

    // (2) ФАЗА A — воспроизведение §5.3 (контракт-провал фиксируется, не обходится).
    arb_trap(&mut session, &ids, &mask, l)?;

    // (3) ФАЗА B — живые маркеры: marker_positions = ВСЕ позиции [L] (констрэкт
    //     даёт по одному [L] на метку; контракт графа = «index of every [L]
    //     token», (1,M) INT64), M живое. Прогон обязан дать exit 0.
    let live: Vec<i64> = groups
        .iter()
        .flat_map(|(_, ps)| ps.iter().copied())
        .map(|p| i64::try_from(p).unwrap_or(i64::MAX))
        .collect();
    let m = live.len();
    let inputs = tensors_for(&session, &ids, &mask, &live)?;
    println!("MARKER|arb|input_shapes|l={l}|m={m}");

    let mut runs = Vec::new();
    for _ in 0..3 {
        let tr = Instant::now();
        let outputs = session.run(inputs.clone())?;
        let n = outputs.values().count();
        runs.push(ms(tr));
        std::hint::black_box(n);
    }
    println!("MARKER|arb|run=ok|markers={m}");
    // (4) Выход: форма (1,M) = по логиту на маркер + softmax по меткам каждой
    //     группы — первый шаг содержательной сверки контракта logits↔маркеры.
    if let Ok(outputs) = session.run(inputs.clone()) {
        if let Some((_, v)) = outputs.iter().next() {
            if let Ok((shape, data)) = v.try_extract_tensor::<f32>() {
                let m = i64::try_from(m).unwrap_or(-1);
                println!(
                    "MARKER|arb|logits|shape={:?}|ok={}",
                    shape,
                    **shape == [1, m] && data.len() == usize::try_from(m).unwrap_or(0)
                );
                if **shape == [1, m] {
                    // marker_positions = concat(групп), логит-слайс группы gi =
                    // [off, off+n), n = число маркеров группы; softmax внутри —
                    // контракт «softmax within each question's markers».
                    let mut off = 0usize;
                    for (gi, (first, ps)) in groups.iter().enumerate() {
                        let hi = (off + ps.len()).min(data.len());
                        let probs = softmax(&data[off..hi]);
                        off = hi;
                        let joined = probs
                            .iter()
                            .map(|x| format!("{x:.4}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        println!(
                            "MARKER|arb|softmax|group={gi}|first={first}|n={}|probs={joined}",
                            ps.len()
                        );
                    }
                }
            }
        }
    }
    let rss_after = rss("after_runs_arbiter");
    emit(&Probe {
        role: "arbiter",
        load_ms,
        delta_load_mib: after - base,
        runs_ms: runs,
        rss_after_runs: rss_after,
    });
    Ok(())
}

/// Собирает входы сессии арбитра по фактическим именам IO: `input_ids`/
/// `attention_mask` формы (1,L), `marker_positions` (1,M) — M из длины `markers`.
/// Порядок = порядок `session.inputs()` (контракт run-вызова).
#[cfg(feature = "ort-inference")]
fn tensors_for(
    session: &ort::session::Session,
    ids: &[i64],
    mask: &[i64],
    markers: &[i64],
) -> Result<Vec<(String, ort::value::DynTensor)>, Box<dyn std::error::Error>> {
    use ort::value::Tensor;
    let names: Vec<String> = session
        .inputs()
        .iter()
        .map(|i| i.name().to_string())
        .collect();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let v: ort::value::DynTensor = match name.as_str() {
            "input_ids" => {
                Tensor::from_array(([1usize, ids.len()], ids.to_vec().into_boxed_slice()))?.upcast()
            }
            "marker_positions" => {
                Tensor::from_array(([1usize, markers.len()], markers.to_vec().into_boxed_slice()))?
                    .upcast()
            }
            _ => Tensor::from_array(([1usize, mask.len()], mask.to_vec().into_boxed_slice()))?
                .upcast(),
        };
        out.push((name, v));
    }
    Ok(out)
}

/// Софтмакс по slices logits одной классификационной схемы (контракт карточки:
/// «softmax within each question's markers»).
#[cfg(feature = "ort-inference")]
fn softmax(xs: &[f32]) -> Vec<f64> {
    let max = xs.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f64> = xs.iter().map(|&x| f64::from(x - max).exp()).collect();
    let sum: f64 = exps.iter().sum();
    if sum == 0.0 || !sum.is_finite() {
        return exps;
    }
    exps.iter().map(|e| e / sum).collect()
}

#[cfg(feature = "ort-inference")]
fn require_weight(p: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if p.exists() {
        Ok(())
    } else {
        Err(format!(
            "вес не найден: {} — сначала scripts/fetch-models.sh (промер без весов \
             невозможен, fail-closed; в CI example не гоняется)",
            p.display()
        )
        .into())
    }
}

#[cfg(feature = "ort-inference")]
fn print_io(session: &ort::session::Session, role: &str) {
    for inp in session.inputs() {
        println!("IO|in|{role}|{}|{}", inp.name(), inp.dtype());
    }
    for out in session.outputs() {
        println!("IO|out|{role}|{}|{}", out.name(), out.dtype());
    }
}

#[cfg(feature = "ort-inference")]
fn open_session(
    env: &ort::environment::Environment,
    path: &std::path::Path,
    threads: usize,
) -> Result<ort::session::Session, Box<dyn std::error::Error>> {
    Ok(ort::session::Session::builder(env)?
        .with_intra_threads(threads)?
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::All)?
        .commit_from_file(path)?)
}

// SPIKE(step2): компилируемость example без весов/без фичи проверяется `just lint`
// (--all-targets); этот прокси-тест #[ignore] — в CI орт не линкуется (фича off),
// веса не качаются (HF в CI запрещён), поэтому тест не запускается CI.
#[cfg(test)]
mod spike_tests {
    #[test]
    #[ignore = "SPIKE(step2): ручной промер; требует весов (--features ort-inference)"]
    fn spike_manual() {
        let _ = super::spike_texts();
    }
}
