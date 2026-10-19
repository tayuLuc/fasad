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
    let thr = arg(&argv, "--thr")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.25);
    if run(limit, threads, thr).is_err() {
        std::process::exit(1);
    }
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
    use guard_onnx::chunker::{ChunkCfg, WindowTokens};
    use guard_onnx::decide::{ID2LABEL, lockr_bio_group};
    use ort::value::Tensor;

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
    let ltok = tokenizers::Tokenizer::from_file(&ltok_path)
        .map_err(|e| format!("токенизатор lockR: {e}"))?;
    let pad_id = ltok.get_vocab(true).get("[PAD]").copied().unwrap_or(0);
    let mut lsess = ort::session::Session::builder(&env)?
        .with_intra_threads(threads)?
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::All)?
        .commit_from_file(&lmodel)?;
    let lockr_special: Vec<u32> = ["[CLS]", "[SEP]", "[PAD]", "[MASK]", "[UNK]"]
        .iter()
        .filter_map(|t| ltok.get_vocab(true).get(*t).copied())
        .collect();

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

    // 3) lockR: батч-1 (тот же decode, что parity-harness: argmax+softmax,
    // special→O, B/i-скобка, PS-хвосты не расширяют спан, offsets p-1).
    let t0 = Instant::now();
    for (j, r) in rows.iter().enumerate() {
        let mut hitmask = 0u64;
        let mut enc = ltok
            .encode(r.text.as_str(), true)
            .map_err(|e| format!("encode g{}: {e}", r.id))?;
        let real = enc.len().min(PAD);
        let ids_u: Vec<u32> = enc.get_ids().iter().copied().collect();
        let offs = enc.get_offsets().to_vec();
        let attn: Vec<i64> = enc
            .get_attention_mask()
            .iter()
            .map(|&x| i64::from(x))
            .collect();
        enc.pad(
            PAD,
            pad_id,
            0,
            "[PAD]",
            tokenizers::utils::padding::PaddingDirection::Right,
        );
        let ids: Vec<i64> = enc.get_ids().iter().map(|&x| i64::from(x)).collect();
        let mut attn = attn;
        attn.resize(PAD, 0);
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
            let special = t < ids_u.len() && lockr_special.contains(&ids_u[t]);
            tagv.push(if special || p < thr {
                "O"
            } else {
                ID2LABEL[best]
            });
            probv.push(p);
        }
        for (cls_tok, ts, te) in lockr_bio_group(&tagv) {
            let Some(cls) = bio_to_class(&cls_tok) else {
                continue;
            };
            // PS-хвосты не расширяют спан (WordPiece '##' — offsets урезаны).
            let mut te2 = te;
            while te2 - 1 > ts
                && te2 - 1 < ids_u.len()
                && ltok
                    .decode(&ids_u[te2 - 1..te2], false)
                    .is_ok_and(|d| d.starts_with("##"))
            {
                te2 -= 1;
            }
            // индексы оффсетов = токен p → offsets[p-1] ([CLS] без оффсета).
            let oi0 = ts.saturating_sub(1);
            let oi1 = (te2 - 1).saturating_sub(1);
            let (Some(&(c0, _)), Some(&(_, c1))) = (offs.get(oi0), offs.get(oi1)) else {
                continue;
            };
            if c1 <= c0 {
                continue;
            }
            let b0 = r.text[..c0].len();
            let b1 = r.text[..c1].len();
            let conf = probv[ts..te2].iter().copied().fold(f64::INFINITY, f64::min);
            if conf < thr {
                continue;
            }
            for (si, (cat, gs, ge)) in r.spans.iter().enumerate() {
                if *cat != cls {
                    continue;
                }
                if b0 < *ge && b1 > *gs {
                    hitmask |= 1u64 << si;
                }
            }
        }
        for (si, (cat, _, _)) in r.spans.iter().enumerate() {
            if hitmask & (1u64 << si) == 1
                && let Some(ci) = CLASSES.iter().position(|c| *c == *cat)
            {
                lockr_hits[ci] += 1;
            }
        }
        let _ = j;
    }
    println!("RECALL|lockr_ms|{:.0}", t0.elapsed().as_secs_f64() * 1000.0);

    // 4) Decide q4f16 (runtime арбитр, row-level per gold class): тот же путь,
    // что `arb_mod_run` (модульный DecideArbiter, sanitize_state на границе).
    let adir = cache.join("onnx-community/GLiNER2.5-Decide-ONNX");
    let amodel = adir.join("onnx/model_q4f16.onnx");
    require(&amodel)?;
    require(&adir.join("onnx/model_q4f16.onnx_data"))?;
    let atok = adir.join("tokenizer.json");
    require(&atok)?;
    let mut arb = DecideArbiter::load(&env, &amodel, &atok, threads)
        .map_err(|e| format!("DecideArbiter::load: {e}"))?;
    let schema: Vec<QuestionSchema<'static>> = CLASSES
        .iter()
        .map(|c| (question_of(c), ["yes", "no"][..].into()))
        .collect();
    let t1 = Instant::now();
    // Чанковка обязательна: метки `[yes]/[no]` — не базовые токены Spiber-vocab
    // (промер: UNK-вето `check_splice` краснеет на длинных строках, чей хвост
    // смещает окно相对 позиции меток в блоке схем). Окно/оверлей = конфиг
    // `--arb-chunked` spike: 384 токенов, overlap = минимум.
    let cfg = ChunkCfg {
        window_tokens: WindowTokens(384),
        ..ChunkCfg::default()
    };
    for r in &rows {
        let state = DecideArbiter::sanitize_state(&r.text);
        let cd = arb
            .arbitrate_chunked(&state, &schema, cfg, thr as f32)
            .map_err(|e| format!("arbitrate_chunked g{}: {e}", r.id))?;
        // union-хит по классу = max prob вопроса среди чанков (merged_hits
        // гранулярности container, #41; здесь — пер-класс union по решениям).
        let decs: Vec<f32> = (0..CLASSES.len())
            .map(|qi| {
                cd.per_chunk
                    .iter()
                    .filter_map(|c| c.decisions.get(qi))
                    .map(|d| d.prob)
                    .fold(0.0f32, f32::max)
            })
            .collect();
        let mut gold: Vec<usize> = r
            .spans
            .iter()
            .filter_map(|(cat, _, _)| CLASSES.iter().position(|c| c == cat))
            .collect();
        gold.sort_unstable();
        gold.dedup();
        for ci in gold {
            if decs[ci] >= thr as f32 {
                decide_hits[ci] += 1;
            }
        }
    }
    println!(
        "RECALL|decide_ms|{:.0}",
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
    let t = tag.strip_prefix("B-").or_else(|| tag.strip_prefix("I-"))?;
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

#[cfg(feature = "ort-inference")]
fn require(p: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if p.exists() {
        Ok(())
    } else {
        Err(format!("вес не найден: {} — scripts/fetch-models.sh", p.display()).into())
    }
}

#[cfg(not(feature = "ort-inference"))]
fn run(
    _limit: Option<usize>,
    _threads: usize,
    _thr: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("RECALL|skipped|no-ort-inference|промер гоняется --features ort-inference");
    Ok(())
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
    fn question_map_is_injective() {
        let qs: Vec<&str> = CLASSES.iter().map(|c| question_of(c)).collect();
        let mut sorted = qs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(qs.len(), sorted.len(), "вопросы уникальны по классам");
    }
}
