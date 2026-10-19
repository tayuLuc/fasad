//! `decide` — контракт SPAN-разметки GLiNER2.5-Decide (шаг 4b-2b, issue #23).
//!
//! Чистые (без ort) данные и функции: таблица спец-токенов, группировка
//! маркеров `[L]` по схемам, layout-констрэкт входа. Единственный источник
//! истины по формату: карточка HF `onnx-community/GLiNER2.5-Decide-ONNX`
//! @18271032 §Graph + `conversion/export_onnx.py` (`torch.gather` по
//! позициям `[L]`) + `conversion/verify_parity.py` L34–37 (флэт всех `[L]`,
//! `[P]` дропается) + `fastino-ai/GLiNER2` `gliner2/processor.py`
//! (`_transform_schema`). spike `--arb` (4b-2a) ходит через этот модуль —
//! двойной правды нет (consumer-first рефактор в этом же PR).

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
/// Граница схем внутри schema-блока (константа из таблицы SPECIALS, без
/// магических литералов — нить N3 ревью #32).
pub const SEP_STRUCT_ID: u32 = special_id("[SEP_STRUCT]");
/// Граница schema-блока → текста (конец маркерной зоны).
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

/// Id токена по имени из vocab-карты (self-check против загруженного
/// `tokenizer.json`: контракт — каждый id из [`SPECIALS`] обязан совпасть).
#[must_use]
pub fn id_of<S: std::hash::BuildHasher>(
    vocab: &std::collections::HashMap<String, u32, S>,
    name: &str,
) -> Option<u32> {
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
#[must_use]
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::err_expect)] // тест: паника = канал ответа
mod tests {
    use super::*;

    #[test]
    fn specials_match_measured_manifest() {
        // Id промерены из tokenizer.json рев. 18271032 (манифест); случайная
        // правка таблицы = красс-контракт — сторожим побитово.
        // Полное сравнение десятки (нит N2 ревью #33): одна правка id = красный.
        assert_eq!(
            SPECIALS,
            [
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
            ]
        );
        assert_eq!(SEP_STRUCT_ID, 128_001);
        assert_eq!(SEP_TEXT_ID, 128_002);
        assert_eq!(
            id_of(
                &std::collections::HashMap::from([("[L]".to_string(), 128_007u32)]),
                "[L]"
            ),
            Some(128_007)
        );
        assert_eq!(id_of(&std::collections::HashMap::new(), "[L]"), None);
    }

    #[test]
    fn groups_partition_on_sep_struct() {
        // Синтетика контрактной формы: [P]-маркер тоже входит в группу
        // (промер 4b-2a: pairs=3 по 2 = [P],[L]; verify_parity дропает первый
        // группы при подаче — это ответственность вызывающего flat-списка).
        // `( [P] [L] ) ) [SEP_STRUCT] ( [P] [L] [L] ) )` → 1+2 маркера.
        let ids = [
            128_003u32, 128_007, 2, 2, 128_001, 128_003, 128_007, 128_007, 2, 2,
        ];
        let g = groups(&ids, [128_003, 128_007]);
        assert_eq!(g.len(), 2, "две схемы");
        assert_eq!(g[0].1.len(), 2, "первая: [P],[L]");
        assert_eq!(g[1].1.len(), 3, "вторая: [P],[L],[L]");
        assert_eq!(g[0].0, g[0].1[0], "ключ = первая позиция группы");
        assert!(g[0].1[1] < g[1].1[0], "монотонность групп");
        assert!(groups(&[], [128_003, 128_007]).is_empty(), "пустой вход");
    }
}
