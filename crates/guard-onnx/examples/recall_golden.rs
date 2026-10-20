//! RECALL (атом 4b-3C, issue #20/#14): span-level recall каскада-2 поверх
//! golden-v1.1 `split=recall` (N=150 — B1-пол, `golden_v1.rs`) на RUNTIME-моделях
//! (lockR fp16 + Decide q4f16 — тот квант, что живёт в демоне; fp32-первичка
//! померена separately в parity-harness, tools/verify). Один прогон-скрипт =
//! эта единица (ТЗ 4b-3C): метрики печатает, ничего не решает.
//!
//! Метрика: span-level per class (тот же оракул, что B-парити (§5.7 audit)): gold-спан
//! засчитан, если модельный спан того же golden-класса пересекает байтовый
//! диапазон при conf ≥ порога. Классы = 8 heads-покрываемых (iban/ogrn/ogrnip
//! вне модели — не в знаменателе, см. golden-инвентарь §5.7 audit).
//! Wilson lower 95% — формула dep-verify-algorithms §8 (z = 1.959963984540054),
//! НЕ вторая (тот же контракт, что гейт #14 в `golden_v1.rs`).
//!
//! Запуск (веса по манифесту, dylib 1.31 по §8 audit):
//!   `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=$HOME/onnxruntime-dylib/\`
//!     onnxruntime-osx-arm64-1.31.0/lib \
//!   `cargo run --release --features ort-inference --example recall_golden`
//! Опции: `--limit N` (первые N recall-строк), `--threads T`, `--thr F`.
//!
//! 7b (#60): пороговые гейты выполняются библиотечным кодом
//! `guard_onnx::routing` (`RoutingCfg::single`), а не локальным сравнением:
//! демоны шагов 7c/8 идут через тот же код, который мерит этот харнес
//! (инвариант «меряем = гоняем»; #60 п.4: Δ-parity до/после выноса = 0.00).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::default_trait_access,
    clippy::manual_contains,
    clippy::iter_cloned_collect,
    clippy::doc_markdown,
    reason = "measurement-харнес: счётчики ≤ 2^53 (n=285), один прогонный main; список = ровно сработавшие классы clippy 1.99 (ревью PR#49 нит №5 — мёртвые позиции срезаны); prod-кодом не является (example)"
)]

#[cfg(feature = "ort-inference")]
use std::path::{Path, PathBuf};
#[cfg(feature = "ort-inference")]
use std::time::Instant;

#[cfg(feature = "ort-inference")]
const RECALL_CATEGORIES: [&str; 11] = [
    "person_name",
    "inn",
    "snils",
    "ogrn",
    "ogrnip",
    "iban",
    "address",
    "card_pan",
    "phone",
    "email",
    "passport",
];
/// Классы, покрытые головами моделей (8 из 11 — iban/ogrn/ogrnip чексуммятся
/// каскадом-0, детекторами; для N модели = знаменатель только покрытых).
#[cfg(feature = "ort-inference")]
const CLASSES: [&str; 8] = [
    "person_name",
    "inn",
    "snils",
    "card_pan",
    "phone",
    "email",
    "address",
    "passport",
];
#[cfg(feature = "ort-inference")]
const Z95: f64 = 1.959_963_984_540_054;
#[cfg(feature = "ort-inference")]
const PAD: usize = 256;
#[cfg(feature = "ort-inference")]
const N_TAGS: usize = 43;
/// decode-контракт харнеса (parity_golden.py `LOCKR_SPECIALS`, L197): строки
/// имён; python decode([CLS]) = '' ⇒ фильтр ЛОЖЕН на спецах (O красит argmax
/// модели), PS-токен = '##вич' (промер 4b-3C) ⇒ НЕ O.
#[cfg(feature = "ort-inference")]
const LOCKR_SPECIALS: [&str; 5] = ["[CLS]", "[SEP]", "[PAD]", "[MASK]", "[UNK]"];

#[cfg(feature = "ort-inference")]
#[derive(Debug)]
struct Row {
    id: String,
    text: String,
    /// (`category`, `start_byte`, `end_byte`) только покрытые классы.
    spans: Vec<(&'static str, usize, usize)>,
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let limit = arg(&argv, "--limit").and_then(|v| v.parse::<usize>().ok());
    let threads = arg(&argv, "--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4);
    // Порог валидируется, а не подменяется дефолтом: `--thr 0,25` (запятая) или
    // `--thr 3` раньше молча считались 0.25/3.0, и отчёт рисовал порог, который
    // никто не просил. Отказ с объяснением — единственная честная реакция на
    // мусор в параметре прогона.
    let thr = match arg(&argv, "--thr") {
        None => 0.25,
        Some(raw) => match raw.parse::<f64>() {
            Ok(v) if v.is_finite() && (0.0..=1.0).contains(&v) => v,
            Ok(v) => {
                eprintln!("--thr {raw}: вне [0, 1] ({v}), порог скора обязан быть вероятностью");
                std::process::exit(2);
            }
            Err(err) => {
                eprintln!("--thr {raw}: не число ({err})");
                std::process::exit(2);
            }
        },
    };
    if run(limit, threads, thr).is_err() {
        std::process::exit(1);
    }
}

/// Строка вердикта гейта #14.
///
/// Вынесена из `run` и намеренно НЕ зависит от фичи `ort-inference`: формат
/// строки — носитель контракта «порог в строке = порог прогона». До этого правки
/// поле `thr|0.25` было литералом: прогон с `--thr 0.20` печатал 0.25, т.е.
/// ложно-зелёный класс по нашей же доктрине (число в отчёте должно браться из
/// замера, а не из шаблона).
#[cfg_attr(
    not(feature = "ort-inference"),
    expect(
        dead_code,
        reason = "звонит только ort-ветка run(); тесты формата живут под cfg(test)"
    )
)]
#[must_use]
fn verdict_line(
    thr: f64,
    verdict: &str,
    decide_hits: u64,
    lockr_hits: u64,
    den: u64,
    decide_wl: f64,
    lockr_wl: f64,
) -> String {
    let d = den.max(1) as f64;
    format!(
        "GOLDEN|verdict|{verdict}|thr|{thr}|decide_point|{:.2}|decide_wilson_lower|{:.2}|lockr_point|{:.2}|lockr_wilson_lower|{:.2}|den|{den}",
        100.0 * decide_hits as f64 / d,
        100.0 * decide_wl,
        100.0 * lockr_hits as f64 / d,
        100.0 * lockr_wl,
    )
}

/// Пары «ключ|значение» после `GOLDEN|verdict|<вердикт>` — для тестов формата.
#[cfg(test)]
fn verdict_fields(line: &str) -> Vec<(String, String)> {
    line.split('|')
        .skip(3)
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| (c[0].to_owned(), c[1].to_owned()))
        .collect()
}

fn arg<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .map(String::as_str)
}

#[cfg(feature = "ort-inference")]
fn cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("FASAD_MODELS_DIR") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    Path::new(&home).join(".cache/fasad-models")
}

/// Lower-bound Wilson 95% (dep-verify-algorithms §8 — формула гейта #14, дословно).
#[cfg(feature = "ort-inference")]
#[must_use]
fn wilson_lower(k: usize, n: usize) -> f64 {
    let p = k as f64 / n as f64;
    let z2 = Z95 * Z95;
    let denom = 1.0 + z2 / n as f64;
    let centre = (p + z2 / (2 * n) as f64) / denom;
    let half = Z95 / denom * ((p * (1.0 - p) / n as f64) + z2 / (4.0 * (n * n) as f64)).sqrt();
    centre - half
}

#[cfg(feature = "ort-inference")]
fn run(limit: Option<usize>, threads: usize, thr: f64) -> Result<(), Box<dyn std::error::Error>> {
    use guard_onnx::arbitrate::{DecideArbiter, QuestionSchema};
    use guard_onnx::decide::{ID2LABEL, lockr_bio_group};
    use guard_onnx::routing::RoutingCfg;
    use ort::value::Tensor;

    // 7b (#60): гейты прогона через lib-маршрутизатор. `single(thr)` —
    // вырожденная пара τ_low=τ_high=thr: полоса Mask пуста,
    // `route(s).extracted()` == старый гейт `s >= thr` (включительно).
    // lockR-скор — f64 (softmax над f32-логитами), порог тот же f64.
    let lockr_cfg = RoutingCfg::single(thr);
    // Decide-скор — f32, старый гейт сравнивал в f32 (`decs[ci] >= thr as
    // f32`), поэтому τ берётся точным f32-образом порога: f32→f64 порядок
    // хранит, сравнение 1-в-1 (иначе граничная точка 0.2f32 =
    // 0.19999999552… уехала бы через 0.2f64 — тест
    // `decide_gate_fidelity_uses_f32_image_of_threshold`).
    let decide_cfg = RoutingCfg::single(f64::from(thr as f32));

    // 1) Датасет — из дерева (git = источник истины, не кэш).
    let ds = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/golden/golden-v1.jsonl"
    );
    let raw = std::fs::read_to_string(ds)?;
    let mut rows: Vec<Row> = Vec::new();
    for line in raw.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        if v["split"].as_str() != Some("recall") {
            continue;
        }
        let mut spans: Vec<(&'static str, usize, usize)> = Vec::new();
        for sp in v["spans"].as_array().into_iter().flatten() {
            let cat = sp["category"].as_str().unwrap_or_default();
            let (Some(sb), Some(eb)) = (sp["start_byte"].as_u64(), sp["end_byte"].as_u64()) else {
                continue;
            };
            if RECALL_CATEGORIES.contains(&cat) {
                let stat: &'static str = Box::leak(cat.to_string().into_boxed_str());
                spans.push((stat, sb as usize, eb as usize));
            }
        }
        rows.push(Row {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            text: v["text"].as_str().unwrap_or_default().to_string(),
            spans,
        });
        if limit.is_some_and(|l| rows.len() >= l) {
            break;
        }
    }
    let n = rows.len();
    println!("RECALL|dataset|golden-v1.1|rows|{n}|thr|{thr}");

    let env = ort::init().with_telemetry(false).build()?;
    let cache = cache_dir();

    // 2) lockR fp16 (runtime extractor1b, манифест @ea7610b2).
    let ldir = cache.join("lockR/rubert-base-pii-ner-onnx");
    let lmodel = ldir.join("model.optimized.fp16.onnx");
    let ltok_path = ldir.join("tokenizer.json");
    require(&lmodel)?;
    require(&ltok_path)?;
    let mut ltok = tokenizers::Tokenizer::from_file(&ltok_path)
        .map_err(|e| format!("токенизатор lockR: {e}"))?;
    ltok.with_post_processor(Option::<tokenizers::processors::template::TemplateProcessing>::None);
    // Rust-`tokenizers` encode(true) НЕ применяет TemplateProcessing и
    // WordPiece-декодер переписывает offsets на байтовую шкалу (промер 4b-3C)
    // ⇒ снимаем пост-процессор ЯВНО; base = encode(false) даёт ЧАРЗ-оффсеты
    // слов, python-форму (75/75/75, om=(0,0)+слова+(0,0)) собирает encode_plus.
    // Контракт харнеса python `encode(add_special_tokens=True)`: ids/offsets/
    // attention 1-в-1, om = (0,0)+слова+(0,0), ЧАРЗ-шкала (промер 4b-3C g0001:
    // 75/75/75, om[17]=(56,63)='Ушакова'). Rust-`tokenizers` encode(true)
    // пост-процессор НЕ применяет и WordPiece переписывает offsets на БАЙТЫ
    // (промер: 73/73, om[17]=(87,101)) ⇒ снимаем пост-процессор ЯВНО и
    // собираем python-форму вручную (`encode_plus`): [CLS]+слова(charz)+[SEP],
    // спец-слоты (0,0). Индексы харнеса (i0=t0−1, om[i0][0]) дословны.
    let cl_id = ltok
        .get_vocab(true)
        .get("[CLS]")
        .copied()
        .ok_or("vocab lockR: нет [CLS]")?;
    let sep_id = ltok
        .get_vocab(true)
        .get("[SEP]")
        .copied()
        .ok_or("vocab lockR: нет [SEP]")?;
    // Спец-позиции: decode-фильтр харнеса (`tok.decode([id]) in
    // LOCKR_SPECIALS`) ЛОЖЕН на спецах — python decode ОДИНОЧНОГО спец-id =
    // '' (WordPiece склеивает пустые; промер 4b-3C), O там красит argmax
    // модели (O@1.0). Id-множество = эквивалент того же контракта (PS-иды
    // decode='##вич' ∉ сете — фильтр их не трогает).
    let lockr_special: Vec<u32> = LOCKR_SPECIALS
        .iter()
        .filter_map(|t| ltok.get_vocab(true).get(*t).copied())
        .collect();
    let pad_id = ltok.get_vocab(true).get("[PAD]").copied().unwrap_or(0);
    let mut lsess = ort::session::Session::builder(&env)?
        .with_intra_threads(threads)?
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::All)?
        .commit_from_file(&lmodel)?;

    // Счётчики span-level: total[class] по gold; hits по моделям.
    let mut total = [0u64; 8];
    let mut lockr_hits = [0u64; 8];
    let mut decide_hits = [0u64; 8];
    // gold-множество строк (row-level знаменатель Decide = union классов).
    for r in &rows {
        for (cat, _, _) in &r.spans {
            if let Some(ci) = CLASSES.iter().position(|c| c == cat) {
                total[ci] += 1;
            }
        }
    }

    // 3) lockR: батч-1 — decode-контракт харнеса (parity_golden.run_lockr):
    // argmax+softmax, special-фильтр (decode ∈ LOCKR_SPECIALS), B/i-скобка,
    // PS-хвосты не расширяют спан, om[i0] (python-форма, спец-плейсхолдеры).
    let t0 = Instant::now();
    for r in &rows {
        let mut hitmask = 0u64;

        // Контракт харнеса python `encode(add_special_tokens=True)` =
        // [CLS]+слова+[SEP]; ids/offsets/attention 1-в-1, om = (0,0)+слова+
        // (0,0) (промер 4b-3C g0001: 75/75/75, om[17]=(56,63)='Ушакова').
        // Rust-`tokenizers` encode(true) пост-процессор НЕ применяет и
        // WordPiece переписывает offsets в байты (промер 73/73, om[17]=
        // (87,101)) ⇒ пост-процессор снят ЯВНО, python-форму поля собирает
        // `encode_plus` (char-оффсеты encode(false), спец-слоты (0,0)).
        let base = ltok
            .encode(r.text.as_str(), false)
            .map_err(|e| format!("encode g{}: {e}", r.id))?;
        let mut enc = encode_plus(&base, cl_id, sep_id, "[CLS]", "[SEP]");
        debug_assert_eq!(enc.get_ids().len(), enc.get_offsets().len());
        let real = enc.len().min(PAD);
        let ids_u: Vec<u32> = enc.get_ids().iter().copied().collect();
        let offs = enc.get_offsets().to_vec();
        let attn: Vec<i64> = enc
            .get_attention_mask()
            .iter()
            .map(|&x| i64::from(x))
            .collect();
        // Харнес L252–257: пад-заполнение ВРУЧНУЮ (numpy zeros + срез [:ln]).
        // `enc.pad(PAD,...)` трогает ВСЕ поля, включая offsets (+2 на [PAD]
        // хвост, grow_offsets=false только для спец-слотов — промер 4b-3C),
        // поэтому снимки ids_u/offs/attn берутся ДО падения.
        enc.pad(
            PAD,
            pad_id,
            0,
            "[PAD]",
            tokenizers::utils::padding::PaddingDirection::Right,
        );
        // ИНПУТ = препад-версия харнесса: ids до PAD из real-среза (срез по
        // min(len, PAD)), пад-заполнение id PAD — L252–257 parity_golden.py
        // (пост-пад `enc.pad` питает и `token_type_ids` нулями, и ids пад-id —
        // харнес делает то же, типos все 0); порядок слов в реальном входе НЕ
        // меняется, но `real` = харнесное `ln`.
        // ИНПУТ = харнес L252–257: numpy zeros(256) + срез [:ln] ⇒ пад-id=0.
        let mut idsv: Vec<i64> = vec![0i64; PAD];
        for (dst, src) in idsv.iter_mut().zip(enc.get_ids().iter().take(real)) {
            *dst = i64::from(*src);
        }
        let ids = idsv;
        let mut attn = attn;
        attn.resize(PAD, 0);
        debug_assert_eq!(ids.len(), PAD);
        let types = vec![0i64; PAD];
        let out = lsess.run(vec![
            (
                "input_ids".to_string(),
                Tensor::from_array(([1usize, PAD], ids.into_boxed_slice()))?.upcast(),
            ),
            (
                "attention_mask".to_string(),
                Tensor::from_array(([1usize, PAD], attn.into_boxed_slice()))?.upcast(),
            ),
            (
                "token_type_ids".to_string(),
                Tensor::from_array(([1usize, PAD], types.into_boxed_slice()))?.upcast(),
            ),
        ])?;
        let (_, lg) = out["logits"].try_extract_tensor::<f32>()?;
        // tags
        let mut tagv: Vec<&str> = Vec::with_capacity(real);
        let mut probv: Vec<f64> = Vec::with_capacity(real);
        for t in 0..real {
            let row = &lg[t * N_TAGS..(t + 1) * N_TAGS];
            let mx = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let sum: f64 = row.iter().map(|&x| ((x - mx) as f64).exp()).sum();
            let mut best = 0usize;
            let mut bv = f32::NEG_INFINITY;
            for (i, &x) in row.iter().enumerate() {
                if x > bv {
                    bv = x;
                    best = i;
                }
            }
            let p = if sum > 0.0 && sum.is_finite() {
                ((bv - mx) as f64).exp() / sum
            } else {
                0.0
            };
            // Харнес-фильтр `tok.decode([id]) in LOCKR_SPECIALS` (L210):
            // LIVE-промер 4b-3C (uvx): decode ОДИНОЧНОГО спец-id = '' (WordPiece
            // склеивает пустые) ⇒ фильтр ЛОЖЕН на спецах — O там красит argmax
            // модели (O@1.0, промер логитов); decode([PS]) = '##вич' ∉ сете ⇒ PS
            // продлевают entity (SNILS 45..52 живут). Тот же контракт = id-множество
            // спец-id (красит только спеца, argmax и так O@1.0; PS не трогает).
            let special = t < ids_u.len() && lockr_special.contains(&ids_u[t]);
            // ПОРОГА В ТЕГАХ НЕТ (spans_bio_tags): thr — к conf спана после
            // скобки (lockr_counts L410); пре-гейт рвёт I-скобки (промер).
            tagv.push(if special { "O" } else { ID2LABEL[best] });
            probv.push(p);
        }
        // Прогон по ВСЕМ B/I-группам (класс-фильтр GOLDEN_TO_BIO — в счёте
        // хита, lockr_counts L410–412: address-спан ловится CITY/STREET/HOUSE).
        for (cls_tok, ts, te) in lockr_bio_group(&tagv) {
            // Оракул харнеса run_lockr (после фикса блокера №1 ревью PR#49):
            //   i1 = min(t1, len(ids_e)) − 1
            //   while i1 >= t0 and decode(ids[i1]).startswith('##'): i1 −= 1
            //   i0 = t0; if i1 < i0: skip
            //   c0 = om[i0][0]; c1 = om[min(i1, len(om) − 1)][1]
            //   b0 = len(text[:c0].encode()); b1 = len(text[:c1].encode())
            // om = encode_plus (python-форма 1-в-1 с ids, спец = (0,0)):
            // промер 20.10 g0001: len(ids)=len(offs)=75, om[17]=(56,63)='Ушакова'
            // → байт 87 = gold start_byte (двойной промер python/rust, ревьюер
            // PR#49 + родитель). РЕЦИДИВ −1, исправлен в обоих харнесах: om[t0−1]
            // = ':' → b0=85 — сдвиг влево, пересечение только ДОБАВЛЯЛО хиты.
            // PS-трим харнеса `tok.decode([id]).startswith('##')`:
            // python decode([PS]) = '##вич' ⇒ трим живой (промер 4b-3C). Rust
            // decode ОДИНОЧНОГО PS-id ЧИСТИТ маркер ('вич') — на decode
            // условие молча ложно, окна PS-склеек завышаются (первая 0.00).
            // Эквивалент python-декода = vocab `id_to_token` ('##вич').
            let mut i1 = (te - 1).min(ids_u.len() - 1);
            while i1 >= ts
                && ltok
                    .id_to_token(ids_u[i1])
                    .is_some_and(|tk| tk.starts_with("##"))
            {
                i1 -= 1;
            }
            // i0 = t0: индекс полного списка = индекс om без сдвига (см. выше).
            let i0 = ts;
            if i1 < i0 {
                continue;
            }
            let (o0, o1) = (offs.get(i0).copied(), offs.get(i1).copied());
            let (Some((c0, _)), Some((_, c1))) = (o0, o1) else {
                continue;
            };
            // Python `len(text[:c].encode('utf-8'))` (char→byte). Поле om =
            // encode_plus из encode(false): промер 4b-3C показал байтовую
            // шкалу Rust-оффсетов (b16=(87,101)) при python-char (56,63)→87 —
            // конверсия char→byte на них = ВТОРАЯ конверсия (+53.. на
            // кириллице, нулевой recall) ⇒ харнесная формула на Rust-поле:
            // b = om напрямую (шкалы совпали: харнес-байт == rust-байт).
            // ПРОМЕР 4b-3C: Rust `tokenizers` отдаёт offsets УЖЕ в байтах
            // (encode(false) g0001: om[16]=(87,101) 'Ушакова' против python
            // char (56,63); харнес `len(text[:56].encode())` = 87 — та же
            // шкала). encode_plus переносит word-оффсеты 1-в-1 ⇒ харнесные
            // b0/b1 = om напрямую; char2byte поверх = ВТОРАЯ конверсия
            // (+53.. на кириллице, 0-hit все спаны — вторая корневая
            // причина 4b-3C).
            let b0 = c0;
            let b1 = c1;
            if b1 <= b0 {
                continue;
            }
            // conf = min probs ВСЕЙ B/I-скобки (spans_grouped cur[3]); thr —
            // при счёте хита (lockr_counts L410), НЕ в тегах (пре-гейт рвёт
            // I-скобки SNILS/CITY — промер 4b-3C).
            let conf = probv[ts..te].iter().copied().fold(f64::INFINITY, f64::min);
            // 7b: гейт = lib (см. `lockr_cfg` выше); эквивалент старого
            // `if conf < thr { continue; }` включая NaN-случай (старый
            // оставлял спан, fail-closed Block тоже «extracted»).
            if !lockr_cfg.route(conf).extracted() {
                continue;
            }
            let Some(mapped) = bio_to_class(&cls_tok) else {
                continue;
            };
            for (si, (cat, gs, ge)) in r.spans.iter().enumerate() {
                if *cat == mapped && b0 < *ge && b1 > *gs {
                    hitmask |= 1u64 << si;
                }
            }
        }
        for (si, (cat, _, _)) in r.spans.iter().enumerate() {
            if hitmask & (1u64 << si) != 0
                && let Some(ci) = CLASSES.iter().position(|c| *c == *cat)
            {
                lockr_hits[ci] += 1;
            }
        }
    }
    println!("RECALL|lockr_ms|{:.0}", t0.elapsed().as_secs_f64() * 1000.0);

    // 4) Decide q4f16 (runtime арбитр, row-level per gold class): контракт B
    // (парити-харнес tools/verify/parity_golden.py): блок схем + ОДИН
    // encode(concat, false), [L],[L]-скан `decide::groups` (парный вызов
    // живого арбитра), гейт sizes=[2×8], yes = P[0] softmax-группы.
    // `check_splice`-вето живого пути (данные вне доверия) здесь осознанно
    // не дублируется — это ОФЛАЙН-измерение качества; вместо него счётчик
    // `unk_rows`. Инвентарь UNK-литер recall-строк golden = ровно `№`
    // (промер 4b-3C: Spiber `'№'` → [507, UNK]); перед прогоном `№` -> пробел
    // (промер: после замены 0 UNK-строк; row-level метрике байтовые координаты
    // не нужны, присутствие литеры в «да»-вероятности не содержательно).
    let adir = cache.join("onnx-community/GLiNER2.5-Decide-ONNX");
    let amodel = adir.join("onnx/model_q4f16.onnx");
    require(&amodel)?;
    require(&adir.join("onnx/model_q4f16.onnx_data"))?;
    let atok = adir.join("tokenizer.json");
    require(&atok)?;
    let mut arb = DecideArbiter::load(&env, &amodel, &atok, threads)
        .map_err(|e| format!("DecideArbiter::load: {e}"))?;
    let atok =
        tokenizers::Tokenizer::from_file(&atok).map_err(|e| format!("токенизатор Decide: {e}"))?;
    let schema: Vec<QuestionSchema<'static>> = CLASSES
        .iter()
        .map(|c| (question_of(c), ["yes", "no"][..].into()))
        .collect();
    let block = DecideArbiter::schema_block(&schema)?;
    let t1 = Instant::now();
    // Метод = контракт B (парити-харнес run_decide): блок + state, ОДИН
    // encode(concat, false), [L],[L]-скан границами, гейт sizes=[2×8],
    // yes=P[0], порог включительно. `check_splice`-вето живого пути здесь
    // осознанно не дублируется (офлайн-измерение качества, не контрактный
    // гейт; инвентарь UNK-литер recall-строк = ровно '№', промер 4b-3C —
    // в B-замере харнес шёл по сырому тексту, повторяем).
    let mut unk_rows = 0u32;
    for r in &rows {
        let state = DecideArbiter::sanitize_state(&r.text.replace('№', " "));
        let whole = format!("{block} {state}");
        let ids: Vec<u32> = atok
            .encode(whole.as_str(), false)
            .map_err(|e| format!("encode d g{}: {e}", r.id))?
            .get_ids()
            .to_vec();
        unk_rows += u32::from(ids.iter().any(|&x| x == 3)); // должен быть 0
        // Скан парой [P],[L] (не [L],[L], как харнес B): [L],[L]+фантомный
        // [L] в хвосте блока склеивает группу (инвариант decide::groups) —
        // layout краснеет. [P],[L] = контракт живого арбитра (SPECIALS-пара,
        // drop_first → [L]-онли маркеры = verify_parity L34–37).
        let gl = guard_onnx::decide::groups(&ids, [128_003, 128_007]);
        let gl: Vec<(usize, Vec<usize>)> = guard_onnx::arbitrate::drop_first(&gl)
            .into_iter()
            .map(|(f, ls)| (f - 1, ls))
            .collect();
        let sizes: Vec<usize> = gl.iter().map(|(_, g)| g.len()).collect();
        // Фантом-гейт (4b-3B) НЕ реализован в этом харнесе: детект фантома
        // требует позиции первой границы `[SEP_*]`, которой у groups() нет.
        // layout_miss ниже ловит и фантом, и любой иной разрыв layout —
        // diagnostic-строка честно не различает (ревью PR#49 нит №8).
        if gl.len() != schema.len() || !sizes.iter().all(|&n| n == 2) {
            // Разрыв layout = дефект ДАННЫХ (фантом в хвосте блока), не
            // прогона: считаем такие строки как miss по всем классам
            // (UNK-вето живого пути = та же судьба: None → no-hit).
            eprintln!(
                "RECALL|layout_miss|g{}|{} групп sizes {sizes:?}",
                r.id,
                gl.len()
            );
            continue;
        }
        let (flat, sz) = guard_onnx::arbitrate::marker_positions(&gl);
        let plan = guard_onnx::arbitrate::SchemaPlan {
            ids,
            groups: gl,
            markers: flat,
            group_sizes: sz,
            questions: schema.iter().map(|(q, _)| (*q).to_string()).collect(),
            labels: schema.iter().map(|(_, ls)| ls[0].to_string()).collect(),
        };
        let logits = arb.run_logits(&plan)?;
        let probs = guard_onnx::arbitrate::decide_probs(&logits, &plan.group_sizes);
        let decs: Vec<f32> = probs.iter().map(|&p| p as f32).collect();
        let mut gold: Vec<usize> = r
            .spans
            .iter()
            .filter_map(|(cat, _, _)| CLASSES.iter().position(|c| c == cat))
            .collect();
        gold.sort_unstable();
        gold.dedup();
        for ci in gold {
            // 7b: гейт = lib (`decide_cfg` — f32-образ порога, см. выше);
            // эквивалент старого `decs[ci] >= thr as f32`.
            if decide_cfg.route(f64::from(decs[ci])).extracted() {
                decide_hits[ci] += 1;
            }
        }
    }
    println!(
        "RECALL|decide_ms|{:.0}|unk_rows|{unk_rows}",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // 5) Метрики.
    for (ci, c) in CLASSES.iter().enumerate() {
        let tot = total[ci];
        if tot == 0 {
            println!("RECALL|per_class|{c}|n|0|lockr|na|decide|na");
            continue;
        }
        println!(
            "RECALL|per_class|{c}|n|{tot}|lockr|{:.2}|decide|{:.2}",
            100.0 * lockr_hits[ci] as f64 / tot as f64,
            100.0 * decide_hits[ci] as f64 / tot as f64
        );
    }
    let den: u64 = total.iter().sum();
    let nl: u64 = lockr_hits.iter().sum();
    let nd: u64 = decide_hits.iter().sum();
    println!(
        "RECALL|overall|lockr_fp16|{:.2}|wilson95_lower|{:.2}|k|{nl}|n|{den}",
        100.0 * nl as f64 / den as f64,
        100.0 * wilson_lower(nl as usize, den as usize)
    );
    println!(
        "RECALL|overall|decide_q4f16|{:.2}|wilson95_lower|{:.2}|k|{nd}|n|{den}",
        100.0 * nd as f64 / den as f64,
        100.0 * wilson_lower(nd as usize, den as usize)
    );
    // Вердикт гейта #14: каскад-2 (lockR ∧ Decide row-level OR) на golden-v1.1
    // при фактическом пороге прогона (он же в строке): overall Decide ≥ 98 % ПО
    // Wilson-lower — нет; по точке — нет. Формулировка Known (не pass/fail по
    // ≥0.98): гейт SPEC §5.7 для каскада в целом (lockR ∨ чексуммы каскада-1,
    // issue #26 хвост) — см. §5.7.
    let wl = wilson_lower(nd as usize, den as usize);
    let verdict = if wl >= 0.98 {
        "pass"
    } else {
        "known-below-98-wilson;gate=#14-deferred-to-cascade-union"
    };
    println!(
        "{}",
        verdict_line(
            thr,
            verdict,
            nd,
            nl,
            den,
            wl,
            wilson_lower(nl as usize, den as usize)
        )
    );
    Ok(())
}

#[cfg(feature = "ort-inference")]
#[must_use]
fn question_of(c: &'static str) -> &'static str {
    match c {
        "person_name" => "Is there a full name of a person ?",
        "inn" => "Is there a tax identification number ?",
        "snils" => "Is there a pension insurance number ?",
        "card_pan" => "Is there a bank card number ?",
        "phone" => "Is there a phone number ?",
        "email" => "Is there an e-mail address ?",
        "address" => "Is there a postal address ?",
        _ => "Is there a passport series and number ?",
    }
}

#[cfg(feature = "ort-inference")]
#[must_use]
fn bio_to_class(tag: &str) -> Option<&'static str> {
    // `lockr_bio_group` возвращает класс БЕЗ B-/I-префикса (decide.rs L78:
    // `tag.strip_prefix("B-")` уже внутри скобки) — префикс дропать НЕ надо.
    let t = tag;
    match t {
        "FIRST_NAME" | "LAST_NAME" | "MIDDLE_NAME" => Some("person_name"),
        "INN" => Some("inn"),
        "SNILS" => Some("snils"),
        "CREDIT_CARD" => Some("card_pan"),
        "PHONE" => Some("phone"),
        "EMAIL" => Some("email"),
        "CITY" | "STREET" | "HOUSE" | "REGION" | "COUNTRY" => Some("address"),
        "PASSPORT" => Some("passport"),
        _ => None,
    }
}

/// python-эталон `encode(text, add_special_tokens=True)` поверх Rust-`tokenizers`
/// со снятым пост-процессором: [CLS]+слова+[SEP], offsets (0,0) на спецах,
/// attention=1 — все поля 1-в-1 по длине (промер 4b-3C: python N+2/N+2/N+2).
#[cfg(feature = "ort-inference")]
#[must_use]
fn encode_plus(
    base: &tokenizers::Encoding,
    cl_id: u32,
    sep_id: u32,
    cl_tok: &str,
    sep_tok: &str,
) -> tokenizers::Encoding {
    // `Encoding::from_tokens` + `merge_with(growing_offsets=false)`: спец-слоты
    // (0,0)/special_mask=1/attention=1 — ровно `TemplateProcessing::apply_template`
    // (промер исходников tokenizers 0.23: там те же repeat_n(0,0)/1/1).
    let spm1 = |id: u32, v: &str| {
        tokenizers::Encoding::new(
            vec![id],
            vec![0],
            vec![v.to_string()],
            vec![None],
            vec![(0, 0)],
            vec![1],
            vec![1],
            vec![],
            Default::default(),
        )
    };
    let mut e = spm1(cl_id, cl_tok);
    e.merge_with(base.clone(), false);
    e.merge_with(spm1(sep_id, sep_tok), false);
    e
}

#[cfg(feature = "ort-inference")]
fn require(p: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if p.exists() {
        Ok(())
    } else {
        Err(format!("вес не найден: {} — scripts/fetch-models.sh", p.display()).into())
    }
}

#[cfg(not(feature = "ort-inference"))]
#[allow(clippy::unnecessary_wraps)] // сигнатура зеркальна ort-ветке — общий main
fn run(
    _limit: Option<usize>,
    _threads: usize,
    _thr: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("RECALL|skipped|no-ort-inference|промер гоняется --features ort-inference");
    Ok(())
}

#[cfg(test)]
mod verdict_format_tests {
    use super::*;

    #[test]
    fn threshold_field_is_the_measured_one() {
        // Тот самый регресс: прогон при 0.20 обязан сообщить 0.2, а не литерал.
        let at_20 = verdict_line(
            0.20,
            "known-below-98-wilson;gate=#14-deferred-to-cascade-union",
            270,
            247,
            285,
            0.915,
            0.8223,
        );
        assert!(at_20.contains("|thr|0.2|"), "{at_20}");
        assert!(
            !at_20.contains("thr|0.25"),
            "старый литерал вернулся: {at_20}"
        );
        let at_25 = verdict_line(0.25, "pass", 280, 250, 285, 0.99, 0.9);
        assert!(at_25.contains("|thr|0.25|"), "{at_25}");
    }

    #[test]
    fn field_order_and_head_are_stable_for_grep_consumers() {
        // Строку жрут `grep`/`awk` в отчётах: порядок полей — контракт.
        let line = verdict_line(0.20, "pass", 270, 247, 285, 0.915, 0.8223);
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(
            &parts[..4],
            ["GOLDEN", "verdict", "pass", "thr"],
            "{parts:?}"
        );
        let fields = verdict_fields(&line);
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "thr",
                "decide_point",
                "decide_wilson_lower",
                "lockr_point",
                "lockr_wilson_lower",
                "den"
            ]
        );
        let get = |want: &str| {
            fields
                .iter()
                .find(|(k, _)| k == want)
                .expect("поле есть")
                .1
                .clone()
        };
        assert_eq!(get("thr"), "0.2");
        assert_eq!(get("decide_point"), "94.74");
        assert_eq!(get("lockr_point"), "86.67");
        assert_eq!(get("den"), "285");
    }

    #[test]
    fn zero_denominator_does_not_produce_nan() {
        // Пустой прогон (den=0) обязан остаться машиночитаемым: NaN в поле
        // вердикта читается как «метрика есть, значение странное».
        let line = verdict_line(
            0.25,
            "known-below-98-wilson;gate=#14-deferred-to-cascade-union",
            0,
            0,
            0,
            0.0,
            0.0,
        );
        assert!(!line.contains("NaN"), "{line}");
        assert!(line.contains("|den|0"), "{line}");
    }
}

#[cfg(test)]
mod lockr_routing_invariance_tests {
    // 7b (#60): example и lib обязаны давать идентичный вердикт на фиксированном
    // синтетическом входе — без модели, без ORT, значит тест живёт вне фичи
    // `ort-inference` и исполняется гейтом `cargo test -p guard-onnx --examples`
    // (`just test`) на обеих ОС без dylib.

    use guard_onnx::routing::{Route, RoutingCfg};

    /// Фиксированный f64-вектор lockR-скоров: границы включательного гейта,
    /// соседние точки, ноль и единица.
    const SCORES_F64: [f64; 10] = [
        0.0,
        1e-9,
        0.199_999_999,
        0.2,
        0.200_000_001,
        0.249_999_999,
        0.25,
        0.250_000_001,
        0.9,
        1.0,
    ];

    /// Фиксированный f32-вектор Decide-вероятностей: `0.2f32` — discriminating
    /// точка: f32(0.2) = 0.19999999552… < f64(0.2), старый f32-гейт её
    /// пропускал, «наивный» f64-порт порол бы хит на ней.
    const PROBS_F32: [f32; 8] = [
        0.0,
        0.19_999_999,
        0.2,
        0.20_000_002,
        0.24_999_997,
        0.25,
        0.5,
        1.0,
    ];

    #[test]
    fn lib_router_reproduces_harness_gate_exactly() {
        // Старый гейт харнеса (до 7b): `if conf < thr { continue; }`,
        // т.е. спан остаётся при `!(conf < thr)`.
        for &thr in &[0.20_f64, 0.25] {
            let cfg = RoutingCfg::single(thr);
            for &s in &SCORES_F64 {
                let old = !(s < thr);
                assert_eq!(cfg.route(s).extracted(), old, "lockr s={s} thr={thr}");
            }
        }
    }

    #[test]
    fn decide_gate_fidelity_uses_f32_image_of_threshold() {
        // Старый гейт: `decs[ci] >= thr as f32` в f32. Порт обязан сохранять
        // f32-точность: τ = f64::from(thr as f32), скор = f64::from(p).
        for &thr in &[0.20_f64, 0.25] {
            let cfg = RoutingCfg::single(f64::from(thr as f32));
            for &p in &PROBS_F32 {
                let old = p >= (thr as f32);
                assert_eq!(
                    cfg.route(f64::from(p)).extracted(),
                    old,
                    "decide p={p} thr={thr}"
                );
            }
        }
    }

    #[test]
    fn single_pair_never_masks_nan_blocks_like_old_gate() {
        // Вырожденная пара: Mask невозможен на конечных скорах…
        let cfg = RoutingCfg::single(0.25);
        for &s in &SCORES_F64 {
            assert_ne!(cfg.route(s), Route::Mask, "single({s}) дал Mask");
        }
        // …а NaN — старое поведение харнеса («conf < thr» ложно ⇒ спан
        // оставался в подсчёте) совпадает с fail-closed Block (extracted).
        // Сравнение с NaN намеренное: проверяем, что старое поведение харнеса
        // («conf < thr» ложно) совпадает с новым fail-closed.
        #[expect(
            invalid_nan_comparisons,
            reason = "фальшивость сравнения — предмет теста"
        )]
        let old_kept = !(f64::NAN < 0.25);
        assert!(old_kept && cfg.route(f64::NAN).extracted());
        assert_eq!(cfg.route(f64::NAN), Route::Block);
    }
}

#[cfg(all(test, feature = "ort-inference"))]
mod recall_tests {
    use super::*;

    #[test]
    fn wilson_matches_dep_verify_anchor_48_50() {
        // dep-verify-algorithms §8: 48/50 → [86.540, 98.896]; нижняя = гейт #14.
        let lo = wilson_lower(48, 50);
        assert!((lo * 100.0 - 86.540).abs() < 0.01, "lo={lo}");
        assert!((wilson_lower(49, 50) * 100.0 - 89.505).abs() < 0.01);
        assert!((wilson_lower(50, 50) * 100.0 - 92.865).abs() < 0.01);
    }

    #[test]
    fn classes_cover_recall_categories() {
        assert_eq!(RECALL_CATEGORIES.len(), 11);
        assert_eq!(CLASSES.len(), 8);
        for c in CLASSES {
            assert!(RECALL_CATEGORIES.contains(&c), "{c} вне recall-инвентаря");
        }
    }

    #[test]
    fn lockr_specials_is_decode_contract_mirror() {
        // Зеркало `LOCKR_SPECIALS` харнеса (parity_golden.py L197): строки, а
        // НЕ id — python decode([CLS]) = '' (промер 4b-3C) ⇒ фильтр на спецах
        // ложь, O там красит argmax модели.
        assert_eq!(LOCKR_SPECIALS.len(), 5);
        assert!(LOCKR_SPECIALS.contains(&"[UNK]"));
    }

    #[test]
    fn question_map_is_injective() {
        let qs: Vec<&str> = CLASSES.iter().map(|c| question_of(c)).collect();
        let mut sorted = qs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(qs.len(), sorted.len(), "вопросы уникальны по классам");
    }
}
