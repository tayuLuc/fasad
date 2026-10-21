//! Property-тесты чанкера, bucketing'а и merger'а (атом step4b-1, SPEC §10 п.4).
//!
//! `proptest` в `[workspace.dependencies]` закомментирован (пин-лист: не
//! добавлять), генерация своя — детерминированный xorshift64\* (Perkins 2015,
//! public domain) с фиксированным seed, образец
//! `crates/guard-detectors/src/normalize/proptests.rs`. Каждый инвариант прогоняет
//! `CASES = 10_000` кейсов; при падении тест печатает индекс кейса — вход
//! воспроизводится перепрогоном того же теста (один ключ = один поток).
//!
//! Инварианты:
//!
//! 1. чанкер — покрытие всего текста, СТРОГАЯ монотонность `start`, перекрытие
//!    соседей ≥ `cfg.overlap_floor(prev_span)` (edge-якорная геометрия: полная
//!    грань `(overlap−1)·BYTES_PER_TOKEN` минус уезжка реза из окна — см. док
//!    метода), окно не превышено, число чанков ≤ stride-bound (атом
//!    step10-chunkerfix), детерминированность;
//! 2. merger — попарная непересекаённость выхода, идемпотентность, независимость
//!    от порядка входа, вето чексуммы (приоритет 1.0 не понижается);
//! 3. bucketing — `bucket_len` монотонен и тотален, `plan_batches` — разбиение
//!    индексов с `B ≤ b_max`.

use super::chunker::{
    BYTES_PER_TOKEN_U, Batch, ChunkCfg, WindowTokens, approx_tokens, bucket_len, chunk,
    plan_batches,
};
use super::merger::{Category, SpanHit, merge};
use guard_types::ByteSpan;

/// Число кейсов на инвариант (ТЗ: ~10k).
const CASES: usize = 10_000;

/// xorshift64\* — детерминированный PRNG (Sebastian Perkins, 2015, public domain;
/// реализация своя, зависимостей нет; копия идиомы из `normalize/proptests.rs` —
/// общий тестовый крейт ради двух модулей не заводим).
#[derive(Debug, Clone)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Равномерно из `[0, bound)` (метод Lemire, без modulo bias).
    fn below(&mut self, bound: usize) -> usize {
        let r = self.next_u64();
        ((bound as u64).wrapping_mul(r >> 32) >> 32) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }
}

/// Алфавит: кириллица (2 байта), латиница, цифры, пробелы, знаки конца
/// предложения, переводы строк, эмодзи (4 байта). Ровно то, на чём чанкер обязан
/// держать UTF-8-границы и резы по предложениям.
const CHARS: &[char] = &[
    'Ж', 'ё', 'и', 'Щ', 'э', 'a', 'Z', '7', '0', ' ', ',', '.', '!', '?', ':', ';', '\n', '–', '«',
    '»', '_', '-', '😀', '🧨',
];

/// Случайный текст ~`max_len` символов из [`CHARS`], каждые ~40 символов —
/// знаменательная граница (иначе генератор не производит предложений).
fn rand_text(rng: &mut XorShift64, max_len: usize) -> String {
    let n = rng.below(max_len + 1);
    let mut s = String::with_capacity(n * 2);
    for i in 0..n {
        if i > 0 && i % 40 == 0 && rng.chance(70) {
            s.push(['.', '!', '?', '\n'][rng.below(4)]);
            if rng.chance(50) {
                s.push('\n');
            }
        }
        s.push(CHARS[rng.below(CHARS.len())]);
    }
    s
}

/// Случайная легальная конфигурация: окно 256..=384, overlap 1..window.
fn rand_cfg(rng: &mut XorShift64) -> ChunkCfg {
    let window = u32::try_from(256 + rng.below(129)).unwrap_or(256);
    let overlap =
        u32::try_from(1 + rng.below(usize::try_from(window - 1).unwrap_or(1))).unwrap_or(1);
    ChunkCfg {
        window_tokens: WindowTokens(window),
        overlap_tokens: overlap,
        sentence_boundaries: rng.chance(80),
    }
}

#[test]
fn prop_chunker_covers_text_monotonically() {
    let mut rng = XorShift64::new(0x000F_45A1);
    for case in 0..CASES {
        let text = rand_text(&mut rng, 2000);
        let cfg = rand_cfg(&mut rng);
        let chunks = chunk(&text, cfg);
        if text.is_empty() {
            assert!(chunks.is_empty(), "case {case}: пустой текст дал чанки");
            continue;
        }
        assert!(!chunks.is_empty(), "case {case}: непустой текст без чанков");
        assert_eq!(chunks[0].span.start, 0, "case {case}: не с нуля");
        assert_eq!(
            chunks.last().unwrap_or(&chunks[0]).span.end,
            text.len(),
            "case {case}: последнее окно не до конца"
        );
        for w in chunks.windows(2) {
            assert!(
                w[1].span.start > w[0].span.start,
                "case {case}: start не вырос: {:?} → {:?}",
                w[0].span,
                w[1].span
            );
            assert!(
                w[1].span.start <= w[0].span.end,
                "case {case}: дыра {}..{}",
                w[0].span.end,
                w[1].span.start
            );
            assert!(
                text.is_char_boundary(w[1].span.start) && text.is_char_boundary(w[1].span.end),
                "case {case}: рез внутри кода"
            );
        }
    }
}

/// Оценка числа границ предложений сверху: каждая `.!?` даёт ≤ одной границы,
/// каждый прогон `\n`/`\r` длиной ≥ 2 — ≤ одной. Пересчёт — запас, не дыра.
fn sentence_boundaries_upper_bound(text: &str) -> usize {
    let b = text.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'.' | b'!' | b'?' => n += 1,
            b'\n' | b'\r' => {
                let j = i;
                while i < b.len() && (b[i] == b'\n' || b[i] == b'\r') {
                    i += 1;
                }
                if i - j >= 2 {
                    n += 1;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    n
}

#[test]
fn prop_chunker_count_bounded_by_stride() {
    // Инвариант 3 (атом step10-chunkerfix, property-форма): шаг адванса либо
    // полный stride−3 (флор к UTF-8-границе съедает ≤ 3 байта), либо «кап»
    // по покрытию — приземление на границу предложения. Капов ≤ числа границ
    // (каждое приземление — новый старт, старты строго растут), полных шагов
    // ≤ ceil(len/(stride−3)). Старая end-якорная геометрия на «прилипшем»
    // конце ходила шагами 1–2 байта при B=3 и len=44 — bound 6 против 23.
    let mut rng = XorShift64::new(0x7A11_51DE);
    for case in 0..CASES {
        let text = rand_text(&mut rng, 3000);
        let cfg = rand_cfg(&mut rng);
        let chunks = chunk(&text, cfg);
        if text.is_empty() {
            assert!(chunks.is_empty(), "case {case}: пустой вход");
            continue;
        }
        let stride = (usize::try_from(
            cfg.window_tokens
                .0
                .saturating_sub(cfg.overlap_tokens)
                .max(1),
        )
        .unwrap_or(usize::MAX))
            * BYTES_PER_TOKEN_U;
        let bound = text
            .len()
            .div_ceil(stride.saturating_sub(3).max(1))
            + sentence_boundaries_upper_bound(&text)
            + 2;
        assert!(
            chunks.len() <= bound,
            "case {case}: {} чанков > bound {bound} (len {}, cfg {cfg:?})",
            chunks.len(),
            text.len()
        );
    }
}

#[test]
fn prop_chunker_keeps_overlap_floor_and_window_ceiling() {
    let mut rng = XorShift64::new(0x0C0F_FEE7);
    for case in 0..CASES {
        let text = rand_text(&mut rng, 3000);
        let cfg = rand_cfg(&mut rng);
        let chunks = chunk(&text, cfg);
        let win_bytes =
            usize::try_from(cfg.window_tokens.0).unwrap_or(usize::MAX) * BYTES_PER_TOKEN_U;
        for c in &chunks {
            assert!(
                c.span.byte_len() <= win_bytes,
                "case {case}: чанк {} Б > окна {win_bytes} Б",
                c.span.byte_len()
            );
        }
        // Пол перекрытия: `cfg.overlap_floor(prev_span)` — см. док метода:
        // округление к UTF-8-границе и окно, обрезанное по границе предложения.
        for w in chunks.windows(2) {
            let prev_span = w[0].span.byte_len();
            let ov =
                i64::try_from(w[0].span.end.saturating_sub(w[1].span.start)).unwrap_or(i64::MAX);
            let floor = i64::try_from(cfg.overlap_floor(prev_span)).unwrap_or(i64::MAX);
            assert!(
                ov >= floor,
                "case {case}: перекрытие {ov} Б < {floor} Б (overlap {}), cfg {cfg:?}",
                cfg.overlap_tokens
            );
        }
    }
}

#[test]
fn prop_chunker_is_deterministic() {
    let mut rng = XorShift64::new(0xDEAD_BEEF);
    for case in 0..CASES {
        let text = rand_text(&mut rng, 1500);
        let cfg = rand_cfg(&mut rng);
        assert_eq!(
            chunk(&text, cfg),
            chunk(&text, cfg),
            "case {case}: чанкер недетерминирован"
        );
    }
}

#[test]
fn prop_bucket_len_monotonic_and_total() {
    let buckets = [128u32, 256, 384];
    let mut rng = XorShift64::new(0x1234_5678);
    let (mut prev_len, mut prev_idx) = (0u32, 0usize);
    for case in 0..CASES {
        let len = u32::try_from(rng.below(100_000)).unwrap_or(u32::MAX);
        let idx = bucket_len(&buckets, len);
        assert!(idx < buckets.len(), "case {case}: индекс вне списка");
        assert!(
            buckets[idx] >= len || idx == buckets.len() - 1,
            "case {case}: бакет {len} → {} без clamp",
            buckets[idx]
        );
        if len >= prev_len {
            assert!(
                idx >= prev_idx,
                "case {case}: bucket_len не монотонен {prev_len}→{len}"
            );
        }
        (prev_len, prev_idx) = (len, idx);
    }
}

/// Случайный спан-хит над ASCII-текстом длины `text_len` (ASCII — чтобы любые
/// байтовые границы были законны: `ByteSpan::new` иначе отбраковал бы спан).
fn rand_hit(rng: &mut XorShift64, text_len: usize) -> SpanHit {
    let mut a = rng.below(text_len + 1);
    let mut b = rng.below(text_len + 1);
    if b < a {
        std::mem::swap(&mut a, &mut b);
    }
    let cat = match rng.below(4) {
        0 => Category::Checksum,
        1 => Category::Entity,
        2 => Category::Secret,
        _ => Category::Other,
    };
    // Приоритет: чексумма — ровно 1.0 (вето), остальное — из (0, 0.999].
    let priority = if cat == Category::Checksum {
        1.0
    } else {
        f32::from(u16::try_from(rng.below(999) + 1).unwrap_or(1)) / 1000.0
    };
    SpanHit {
        span: ByteSpan {
            start: a,
            end: b,
            char_start: a,
            char_end: b,
        },
        category: cat,
        priority,
    }
}

#[test]
fn prop_merge_output_is_disjoint_sorted_and_idempotent() {
    let mut rng = XorShift64::new(0xB16B_00B5);
    for case in 0..CASES {
        let n = 1 + rng.below(24);
        let text_len = 1 + rng.below(400);
        let hits: Vec<SpanHit> = (0..n).map(|_| rand_hit(&mut rng, text_len)).collect();
        let out = merge(&hits);
        for w in out.windows(2) {
            assert!(
                w[0].span.end <= w[1].span.start,
                "case {case}: пересечение {:?} {:?}",
                w[0].span,
                w[1].span
            );
        }
        assert_eq!(merge(&out), out, "case {case}: merge не идемпотентен");
        let mut sorted_hits = hits.clone();
        sorted_hits.sort_by_key(|x| (x.span.start, x.span.end));
        let out_sorted = merge(&sorted_hits);
        assert_eq!(
            out, out_sorted,
            "case {case}: merge зависит от порядка входа"
        );
    }
}

#[test]
fn prop_merge_never_lowers_checksum_veto() {
    // Вето (AGENTS): выходной спан, накрывающий входной чексумменный, обязан
    // нести приоритет 1.0 — сеть его не понижает.
    let mut rng = XorShift64::new(0x5EED_C0DE);
    for case in 0..CASES {
        let text_len = 1 + rng.below(300);
        let hits: Vec<SpanHit> = (0..10).map(|_| rand_hit(&mut rng, text_len)).collect();
        let out = merge(&hits);
        for h in hits.iter().filter(|h| h.priority.total_cmp(&1.0).is_eq()) {
            let covering = out.iter().find(|o| {
                o.span.start <= h.span.start && h.span.end <= o.span.end && !h.span.is_empty()
            });
            if let Some(o) = covering {
                assert!(
                    o.priority.total_cmp(&1.0).is_eq(),
                    "case {case}: вето {h:?} понижено до {o:?}"
                );
            }
        }
    }
}

#[test]
fn prop_plan_batches_partitions_and_respects_bmax() {
    let buckets = [128u32, 256, 384];
    let mut rng = XorShift64::new(0xCAFE_F00D);
    for case in 0..CASES {
        let n = rng.below(40);
        let chunks: Vec<super::chunker::Chunk> = (0..n)
            .map(|_| {
                let toks = u32::try_from(rng.below(600)).unwrap_or(u32::MAX);
                super::chunker::Chunk {
                    span: ByteSpan {
                        start: 0,
                        end: 4,
                        char_start: 0,
                        char_end: 4,
                    },
                    token_lo: 0,
                    token_hi: toks,
                }
            })
            .collect();
        let b_max = 1 + rng.below(8);
        let batches: Vec<Batch> = plan_batches(&chunks, b_max, &buckets);
        let total: usize = batches.iter().map(|b| b.indices.len()).sum();
        assert_eq!(total, n, "case {case}: батчи потеряли чанки");
        assert!(
            batches.iter().all(|b| b.len() <= b_max),
            "case {case}: B > b_max {b_max}"
        );
        let mut seen = vec![false; n];
        for b in &batches {
            for &i in &b.indices {
                assert!(!seen[i], "case {case}: индекс {i} в двух батчах");
                seen[i] = true;
                assert!(
                    b.bucket_tokens >= chunks[i].token_hi - chunks[i].token_lo
                        || b.bucket == buckets.len() - 1,
                    "case {case}: чанк {} в бакете {}",
                    chunks[i].token_hi,
                    b.bucket_tokens
                );
            }
        }
        assert!(seen.iter().all(|&s| s), "case {case}: индекс потерян");
        assert!(approx_tokens("abcd") <= 4);
    }
}

#[test]
fn prop_merger_incremental_equals_slice_api() {
    let mut rng = XorShift64::new(0x0000_1CE9);
    for case in 0..CASES {
        let n = 1 + rng.below(16);
        let text_len = 1 + rng.below(200);
        let hits: Vec<SpanHit> = (0..n).map(|_| rand_hit(&mut rng, text_len)).collect();
        let mut m = super::merger::Merger::new();
        for &h in &hits {
            let _ = m.push(h);
        }
        assert_eq!(
            m.finish(),
            merge(&hits),
            "case {case}: инкрементальный merger расходится"
        );
    }
}
