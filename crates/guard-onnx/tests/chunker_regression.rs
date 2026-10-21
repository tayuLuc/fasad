//! Регресс атома «чанкер: хвостовой слайдинг» (step10-chunkerfix).
//!
//! Диагноз: адванс, заякоренный на фактический `end`, при «прилипшем» конце
//! (последняя граница предложения у старта окна, хвост без `.!?`) давал форс-шаг
//! 1–2 байта и O(len) чанков. Отсюда две красные ветки этого файла:
//! `email44_regression_single_chunk` (44 Б → 23 чанка на старой геометрии) и
//! `golden_rows_single_chunk_identity` (golden-строка 358 Б → 89 чанков).
//! Фикстуры — форма ревьюера (email44 / gray283 / tail2133) плюс весь golden
//! (N=204, AGENTS §4). Интеграционный срез: только pub-API крейта
//! ([`chunk`], [`ChunkCfg`]), как его видит `guard-daemon`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::err_expect)] // в тестах паника = канал ответа

use guard_onnx::chunker::{BYTES_PER_TOKEN_U, ChunkCfg, chunk};

/// Все конфигурации промера: обе из диагноза ревьюера + конфигурация B (SPEC §5.7).
fn probe_cfgs() -> Vec<(&'static str, ChunkCfg)> {
    vec![
        ("256/32", ChunkCfg::new(256, 32).unwrap()),
        ("384/32", ChunkCfg::new(384, 32).unwrap()),
        ("rubert-448/128", ChunkCfg::rubert()),
    ]
}

/// Байтовый эквивалент окна: знаменатель `BYTES_PER_TOKEN_U` — pub-спутник
/// константы (тот же целочисленный путь, что внутренний `window_bytes`).
fn win_bytes(cfg: ChunkCfg) -> usize {
    usize::try_from(cfg.window_tokens.0).unwrap() * BYTES_PER_TOKEN_U
}

/// Stride адванса: `window_bytes − overlap_bytes` (инвариант 3 дока `chunk`).
fn stride_bytes(cfg: ChunkCfg) -> usize {
    win_bytes(cfg) - cfg.overlap_bytes()
}

/// Голова фикстуры: `base` + пробелы + точка, ровно `head_len` байт; граница
/// предложения стоит на байте `head_len` («прилипший» конец diagnosis'а).
fn head_fill(base: &str, head_len: usize) -> String {
    assert!(
        !base.bytes().any(|b| b == b'.' || b == b'!' || b == b'?' || b == b'\n'),
        "голова не должна содержать границ до финальной точки"
    );
    format!("{}{}.", base, " ".repeat(head_len - base.len() - 1))
}

/// Хвост фикстуры: `s` без `.!?` и переводов строк, добит пробелами до `n`.
fn tail_fill(s: &str, n: usize) -> String {
    assert!(
        !s.bytes().any(|b| b == b'.' || b == b'!' || b == b'?' || b == b'\n'),
        "хвост не должен содержать границ"
    );
    s.to_owned() + &" ".repeat(n - s.len())
}

/// 44-байтовый email: точка в домене `.ru` — граница посреди строки, хвост без точек.
fn fixture_email44() -> String {
    let t = String::from("a.petrov@mail.regions.ru, тел 89001234567");
    assert_eq!(t.len(), 44, "форма ревьюера: 44 B");
    t
}

/// «Серый» документ 283 B: заголовок с точкой на 88-м байте, реквизиты без terminator'ов.
fn fixture_gray283() -> String {
    let t = head_fill("Служебный документ отдела логистики «Вектор»", 88)
        + &tail_fill(
            ", ИНН 7701234567, СНИЛС 112-233-455 99, ОГРН 1027700132195, Москва, Каширское шоссе 21к4, комната 118, 89161234567",
            195,
        );
    assert_eq!(t.len(), 283);
    t
}

/// Выгрузка 2133 B: шапка с точкой на 128-м, далее ~2 KB полей без `.!?`.
fn fixture_tail2133() -> String {
    let fields: Vec<String> = (1..12)
        .map(|i| {
            format!(
                "запись {i:04} ФИО год рождения паспорт 4507 {i:06} выдан 120000 СНИЛС 100-000-000 {:02} ИНН 7700{i:08} телефон 8900000{i:04}",
                i % 100
            )
        })
        .collect();
    let t = head_fill("Уведомление о передаче данных в систему оператора", 128)
        + &tail_fill(&fields.join(", "), 2133 - 128);
    assert_eq!(t.len(), 2133);
    t
}

/// Поле `text` всех строк golden-v1.jsonl (N=204, AGENTS §4) через serde_json.
fn golden_rows() -> Vec<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/golden/golden-v1.jsonl"
    );
    let raw = std::fs::read_to_string(path)
        .expect("data/golden/golden-v1.jsonl обязана быть в дереве (гейт golden-verify)");
    let rows: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("строка golden — валидный JSON");
            v.get("text")
                .and_then(|t| t.as_str())
                .expect("в golden-строке есть поле text:string")
                .to_owned()
        })
        .collect();
    assert_eq!(rows.len(), 204, "golden-v1 — 204 строки (N≥150, AGENTS §4)");
    assert!(rows.iter().all(|r| !r.is_empty()));
    rows
}

/// 1. Регресс diagnosis'а: 44-байтовый email — хвост накрывается одним окном,
/// форс-шагового слайдинга нет. На старой end-якорной геометрии — 23 чанка.
#[test]
fn email44_regression_single_chunk() {
    let t = fixture_email44();
    for (cn, cfg) in probe_cfgs() {
        let cs = chunk(&t, cfg);
        assert!(
            cs.len() <= 2,
            "{cn}: email44 дал {} чанков (регресс хвостового слайдинга)",
            cs.len()
        );
        assert_eq!(cs.len(), 1, "{cn}: 44 Б < окна — ровно один чанк");
        assert_eq!((cs[0].span.start, cs[0].span.end), (0, 44));
    }
}

/// 2. gray283: та же форма (граница у 88-го байта, хвост 195 Б без границ) —
/// документ накрывается окном целиком, один чанк [0, 283).
#[test]
fn gray283_no_tail_sliding() {
    let t = fixture_gray283();
    for (cn, cfg) in probe_cfgs() {
        let cs = chunk(&t, cfg);
        assert_eq!(cs.len(), 1, "{cn}: gray283 дал {} чанков, ждали 1", cs.len());
        assert_eq!((cs[0].span.start, cs[0].span.end), (0, 283));
        assert_eq!(cs[0].span.slice(&t), Some(&t[..]));
    }
}

/// 3. tail2133 (первое окно не накрывает текст): число чанков ограничено
/// `ceil(len / window_bytes) + 1` — инвариант 3 дока `chunk` для форм, где
/// резы попадают на край окна. На старой геометрии — 87–88 чанков.
#[test]
fn tail2133_count_bounded_by_window_plus_one() {
    let t = fixture_tail2133();
    for (cn, cfg) in probe_cfgs() {
        let cs = chunk(&t, cfg);
        let bound = t.len().div_ceil(win_bytes(cfg)) + 1;
        assert!(
            cs.len() <= bound,
            "{cn}: tail2133 дал {} чанков > bound {bound} (len {}, win {})",
            cs.len(),
            t.len(),
            win_bytes(cfg)
        );
        assert_eq!(cs[0].span.start, 0);
        assert_eq!(cs.last().unwrap().span.end, 2133, "хвост не покрыт");
    }
}

/// 4. Проперти golden: каждая из 204 строк короче min-окна (промер: max 392 Б),
/// значит каждая — РОВНО один чанк [0, len), тождественный тексту. На старой
/// геометрии фикстура g0001 (358 Б) давала 89 чанков.
#[test]
fn golden_rows_single_chunk_identity() {
    let rows = golden_rows();
    let win_min = usize::try_from(guard_onnx::chunker::WINDOW_TOKENS_MIN).unwrap() * BYTES_PER_TOKEN_U;
    assert!(
        rows.iter().all(|r| r.len() <= win_min),
        "все golden-строки ≤ min-окна {win_min} Б: showcase-форма не поедет"
    );
    for (cn, cfg) in probe_cfgs() {
        for (i, t) in rows.iter().enumerate() {
            let cs = chunk(t, cfg);
            assert_eq!(cs.len(), 1, "{cn}: golden_row_{i:03} (len {}) дал {} чанков", t.len(), cs.len());
            assert_eq!(cs[0].span.start, 0, "golden_row_{i:03}/{cn}");
            assert_eq!(cs[0].span.end, t.len(), "golden_row_{i:03}/{cn}");
            assert_eq!(cs[0].span.slice(t), Some(&t[..]), "golden_row_{i:03}/{cn}");
        }
    }
}

/// 5. Проперти golden-потока (204 строки через \n, ~37 KB — текст длиннее окна):
/// побайтовое покрытие без дыр, строгая монотонность стартов, шаг ≥ stride,
/// чанк ≤ окна, хвост до конца, n ≤ ceil(len/stride)+1 (инвариант 3 дока).
#[test]
fn golden_stream_invariants() {
    let t = golden_rows().join("\n");
    for (cn, cfg) in probe_cfgs() {
        let cs = chunk(&t, cfg);
        assert!(!cs.is_empty(), "{cn}: пустой список на непустом входе");
        assert_eq!(cs[0].span.start, 0, "{cn}: не с нуля");
        assert_eq!(cs.last().unwrap().span.end, t.len(), "{cn}: хвост не покрыт");
        let bound = t.len().div_ceil(stride_bytes(cfg)) + 1;
        assert!(
            cs.len() <= bound,
            "{cn}: golden-поток дал {} чанков > bound {bound} (len {}, stride {})",
            cs.len(),
            t.len(),
            stride_bytes(cfg)
        );
        for c in &cs {
            assert!(
                c.span.byte_len() <= win_bytes(cfg),
                "{cn}: чанк {} Б > окна {} Б",
                c.span.byte_len(),
                win_bytes(cfg)
            );
            assert!(
                t.is_char_boundary(c.span.start) && t.is_char_boundary(c.span.end),
                "{cn}: рез внутри UTF-8-кода: {:?}",
                c.span
            );
        }
        for w in cs.windows(2) {
            assert!(
                w[1].span.start > w[0].span.start,
                "{cn}: start не вырос: {:?} → {:?}",
                w[0].span,
                w[1].span
            );
            assert!(
                w[1].span.start <= w[0].span.end,
                "{cn}: дыра {}..{}",
                w[0].span.end,
                w[1].span.start
            );
        }
        let mut covered = vec![false; t.len()];
        for c in &cs {
            for b in &mut covered[c.span.start..c.span.end] {
                *b = true;
            }
        }
        let holes: Vec<usize> = covered
            .iter()
            .enumerate()
            .filter(|(_, v)| !**v)
            .map(|(i, _)| i)
            .take(8)
            .collect();
        assert!(holes.is_empty(), "{cn}: дыры покрытия на байтах {holes:?}");
    }
}

/// 6. Координатная точность на фикстурах: спан побайтово равен срезу оригинала,
/// token_lo/hi = ceil(start/4)/ceil(end/4); в tail2133 старт соседа примотан к
/// потолку-покрытию (128), а первый ИНН (байт 248) накрыт целиком одним чанком.
#[test]
fn reviewer_forms_spans_are_exact() {
    for t in [fixture_email44(), fixture_gray283(), fixture_tail2133()] {
        for (cn, cfg) in probe_cfgs() {
            for c in chunk(&t, cfg) {
                assert_eq!(
                    c.span.slice(&t),
                    Some(&t[c.span.start..c.span.end]),
                    "{cn}: span {:?} побайтово != срез оригинала",
                    c.span
                );
                assert_eq!(
                    usize::try_from(c.token_lo).unwrap(),
                    c.span.start.div_ceil(BYTES_PER_TOKEN_U),
                    "{cn}: token_lo != ceil(start/4)"
                );
                assert_eq!(
                    usize::try_from(c.token_hi).unwrap(),
                    c.span.end.div_ceil(BYTES_PER_TOKEN_U),
                    "{cn}: token_hi != ceil(end/4)"
                );
            }
        }
    }
    let t = fixture_tail2133();
    let cfg = ChunkCfg::new(256, 32).unwrap();
    let cs = chunk(&t, cfg);
    assert_eq!(cs[0].span.end, 128, "рез по границе шапки (прилипший хвост)");
    assert_eq!(cs[1].span.start, 128, "потолок-покрытие: сосед с 128");
    let off = t.find("ИНН 770000000001").expect("первый ИНН в фикстуре");
    assert_eq!(off, 248, "офсет зафиксирован формой фикстуры");
    let covering = cs
        .iter()
        .filter(|c| c.span.start <= off && off + 19 <= c.span.end)
        .count();
    assert!(
        covering >= 1,
        "ИНН на {off} не накрыт целиком ни одним чанком (merger склеит полуса)"
    );
}
