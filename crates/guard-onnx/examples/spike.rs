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
//! CI НЕ требует весов и НЕ требует орта: без фичи `ort-inference` example —
//! no-op; тест-прокси сборки помечен `#[ignore]` (`cargo test` его считает,
//! не запускает). Прогон — только рукаместо (наша машина, macOS/Linux).
//!
//! Контракт workspace `unsafe_code = forbid` (Cargo.toml [workspace.lints.rust])
//! НЕ понижается: spike на macOS читает RSS через C-остров `spike/rss_mach.c`
//! (build.rs линкует его только в example; `_Static_assert` держат layout
//! `task_vm_info`). Единственный unsafe в Rust-части — extern-вызов, обёрнут в
//! `mod ffi` с точечным `#[allow]` (см. ниже rationale) — spike is the only
//! consumer, рантайм-код (шаг 4) unsafe не содержит.

#![allow(
    missing_docs,
    dead_code, // spike без фичи ort-inference: main no-op, скелет мёртв by design
    clippy::allow_attributes_without_reason,
    reason = "SPIKE(step2): бинарь-промер issue #6; mаина без фичи нет — см. cfg"
)]

use std::path::PathBuf;
use std::time::Instant;

/// SPIKE(step2): единственная FFI-граница в репозитории.
///
/// Rationale (issue #6, решение ревьюера 19.10): `forbid(unsafe_code)` из
/// workspace-lints приходит на rustc как `-F unsafe-code`; точечные `allow` по
/// docs rustc его не перебивают (forbid > command-line > inner-attribute).
/// Rust-обёртка task_info требует unsafe-блока, C-обёртка (rss_mach.c) — нет:
/// unsafe остаётся за пределами crate (в C, с layout-ассертами), а Rust-часть
/// видна как safe extern-вызов.
#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "FFI-остров example: граница небезопасности замкнута в C (rss_mach.c, _Static_assert layout); контракт forbid(unsafe_code) — для src-крейтов (#inner forbid в lib.rs), spike не prod-путь"
)]
#[cfg(feature = "ort-inference")]
mod ffi {
    // Safe-FFI: `double f(void)` без variadic/поинтеров — extern-объявление
    // разрешено без `unsafe extern` в Rust 2024; unsafe остаётся целиком в C
    // (task_info + layout _Static_assert). Контракт workspace forbid(unsafe_code)
    // для src-крейтов не затронут: это example.
    unsafe extern "C" {
        fn fasad_spike_rss() -> f64;
    }

    pub fn rss_mib() -> Option<f64> {
        let v = unsafe { fasad_spike_rss() };
        if v >= 0.0 { Some(v) } else { None }
    }
}

/// RSS процесса в MiB:
/// macOS — `task_info(TASK_VM_INFO).internal` (private+resident, «Память» из
/// монитора активности, FFI через C-остров — см. `mod ffi`); Linux — VmRSS из
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

#[cfg(feature = "ort-inference")]
fn run_spike(
    cache: &std::path::Path,
    argv: &[String],
    threads: usize,
) -> Result<(), Box<dyn Error>> {
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
    if argv.iter().any(|a| a == "--lockr") {
        measure_lockr(cache, &env, threads)?;
    }
    Ok(())
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

/// lockR/rubert-base-pii-ner-onnx fp16: BertForTokenClassification, int64 IO,
/// единый файл без external data (контроль паттерна памяти). Токенизация —
/// tokenizer.json из кеша (WordPiece), окно pad 256 (SPEC §5.3).
#[cfg(feature = "ort-inference")]
fn measure_lockr(
    cache: &std::path::Path,
    env: &ort::environment::Environment,
    threads: usize,
) -> Result<(), Box<dyn Error>> {
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
/// вопрос промера: дельта RSS vs размер .onnx_data — гипотеза ревьюера «ORT
/// мапит external data целиком») + IO-контракт + прогоны на synthetic-входах
/// (полноценный entity-препроцесс GLiNER2.5 — шаг 4).
#[cfg(feature = "ort-inference")]
fn measure_arbiter(
    cache: &std::path::Path,
    env: &ort::environment::Environment,
    threads: usize,
) -> Result<(), Box<dyn Error>> {
    use ort::value::Tensor;

    let path = cache
        .join("onnx-community/GLiNER2.5-Decide-ONNX")
        .join("onnx/model_q4f16.onnx");
    let data = {
        let mut p = path.clone().into_os_string();
        p.push("_data");
        PathBuf::from(p)
    };
    require_weight(&path)?;
    require_weight(&data)?;
    println!("IO|external_data_bytes|{}", std::fs::metadata(&data)?.len());

    let base = rss("before_load_arbiter");
    let t = Instant::now();
    let mut session = open_session(env, &path, threads)?;
    let load_ms = ms(t);
    let after = rss("after_load_arbiter");
    print_io(&session, "arbiter");

    // Синтетические входы строго по IO-контракту сессии: int64 [1;L] (id-входы —
    // фиктивный vocab-диапазон, mask — единицы). Смысловой инференс здесь не цель.
    let l = 256usize;
    let ids: Vec<i64> = (0..l as i64).map(|i| 3 + (i % 512)).collect();
    let mask: Vec<i64> = vec![1i64; l];
    let mut inputs: Vec<(String, ort::value::DynTensor)> = Vec::new();
    for inp in session.inputs() {
        let name = inp.name().to_string();
        let v = match name.as_str() {
            "attention_mask" | "input_mask" | "entity_mask" => mask.clone(),
            _ => ids.clone(),
        };
        inputs.push((
            name,
            Tensor::from_array(([1usize, v.len()], v.into_boxed_slice()))?.upcast(),
        ));
    }

    let mut runs = Vec::new();
    for _ in 0..3 {
        let tr = Instant::now();
        let outputs = session.run(inputs.clone())?;
        let n = outputs.values().count();
        runs.push(ms(tr));
        std::hint::black_box(n);
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

#[cfg(feature = "ort-inference")]
fn require_weight(p: &std::path::Path) -> Result<(), Box<dyn Error>> {
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
) -> Result<ort::session::Session, Box<dyn Error>> {
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
