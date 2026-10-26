//! `decide` — контракт SPAN-разметки GLiNER2.5-Decide (шаг 4b-2b, issue #23).
//!
//! Чистые (без ort) данные и функции: таблица спец-токенов, группировка
//! маркеров `[L]` по схемам, layout-констрэкт входа. Единственный источник
//! истины по формату: карточка HF `onnx-community/GLiNER2.5-Decide-ONNX`
//! @18271032 §Graph + `conversion/export_onnx.py` (`torch.gather` по
//! позициям `[L]`) + `conversion/verify_parity.py` L34–37 HF-репо `onnx-community/GLiNER2.5-Decide-ONNX@18271032` (в `fastino-ai/GLiNER2` — 404) — флэт всех `[L]`,
//! `[P]` дропается) + `fastino-ai/GLiNER2` `gliner2/processor.py`
//! (`_transform_schema`). spike `--arb` (4b-2a) ходит через этот модуль —
//! двойной правды нет (consumer-first рефактор в этом же PR).

/// Структурные спец-токены Decide-разметки: имя + id (промерены из
/// `tokenizer.json` рев. `18271032`, манифест `models/manifest.md`).
/// id2label 0..42 token-classification head lockR — первичка `config.json`
/// репо `lockR/rubert-base-pii-ner-onnx@ea7610b22…` (`hf_hub_download` 20.10).
/// Зеркало `ID2LABEL` в `tools/verify/parity_golden.py` (одна константа на
/// два места; тест `lockr_id2label_matches_verify_mirror` читает скрипт).
pub const ID2LABEL: [&str; 43] = [
    "O",
    "B-PASSPORT",
    "I-PASSPORT",
    "B-CREDIT_CARD",
    "I-CREDIT_CARD",
    "B-DRIVER_LICENSE",
    "I-DRIVER_LICENSE",
    "B-INN",
    "I-INN",
    "B-SNILS",
    "I-SNILS",
    "B-MILITARY_ID",
    "I-MILITARY_ID",
    "B-BIRTH_CERTIFICATE",
    "I-BIRTH_CERTIFICATE",
    "B-OMS",
    "I-OMS",
    "B-CITY",
    "B-COUNTRY",
    "B-DISTRICT",
    "B-EMAIL",
    "B-FIRST_NAME",
    "B-HOUSE",
    "B-IP_ADDRESS",
    "B-LAST_NAME",
    "B-MIDDLE_NAME",
    "B-PHONE",
    "B-REGION",
    "B-STREET",
    "B-URL",
    "I-CITY",
    "I-COUNTRY",
    "I-DISTRICT",
    "I-EMAIL",
    "I-FIRST_NAME",
    "I-HOUSE",
    "I-IP_ADDRESS",
    "I-LAST_NAME",
    "I-MIDDLE_NAME",
    "I-PHONE",
    "I-REGION",
    "I-STREET",
    "I-URL",
];

/// BIO-скобка lockR (Begin/Inside ОДНОЙ головы): цепочка `B-класс` +
/// непрерывные `I-` того же класса; `O`/чужой `I` обрывают. Возвращает
/// (`класс`, `tok_start`, `tok_end_excl`) — индексы ТОКЕНОВ; конверсию в байты
/// делает потребитель (offsets токенизатора в парити/рантайме). Чистая функция
/// (без фичи ort) — тестируется на голых тегах.
#[must_use]
pub fn lockr_bio_group(tags: &[&str]) -> Vec<(String, usize, usize)> {
    let mut out: Vec<(String, usize, usize)> = Vec::new();
    let mut cur: Option<(String, usize, usize)> = None;
    for (t, &tag) in tags.iter().enumerate() {
        if let Some(b) = tag.strip_prefix("B-") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            cur = Some((b.to_string(), t, t + 1));
        } else if let Some(i) = tag.strip_prefix("I-") {
            if cur.as_ref().is_some_and(|(c, _, _)| c == i) {
                if let Some(c) = cur.as_mut() {
                    c.2 = t + 1;
                }
            } else if let Some(c) = cur.take() {
                out.push(c);
            }
        } else if let Some(c) = cur.take() {
            out.push(c);
        }
    }
    if let Some(c) = cur {
        out.push(c);
    }
    out
}

/// Теги позиции с порогом: ниже `threshold` — `O` (prob считается softmax-ом
/// строки логитов вызывающим кодом; здесь — чистый фильтр argmax-индексов).
#[must_use]
pub fn lockr_tags(argmax: &[usize], probs: &[f64], threshold: f64) -> Vec<&'static str> {
    argmax
        .iter()
        .zip(probs)
        .map(|(&i, &p)| {
            if p >= threshold {
                ID2LABEL.get(i).copied().unwrap_or("O")
            } else {
                "O"
            }
        })
        .collect()
}

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
/// сессию на пустых маркерах — промер 4b-0, audit §W2 п.3).
///
/// 4b-3B (промер парити-рана + spike --arb-mod, тест
/// `groups_ignore_stray_markers_in_state`): граница `[SEP_*]` закрывает
/// НЕПУСТОЙ накопитель — одинокий `[L]` ДО границы становится группой из 1
/// (sizes-гейт вызывающего красен, это СИГНАЛ, не тихий сдвиг); пустой
/// накопитель на границе группу НЕ создаёт; одинокий `[L]` ПОСЛЕ последней
/// границы флешится хвостовой группой (len≠schema → тот же красный гейт).
/// Склейка с живой группой (`sizes=[3]≠[2]`) происходит только если маркер
///-мусор стоит МЕЖДУ маркерами группы БЕЗ границы — за это же держится
/// `GatherElements: Out of range value in index tensor` (промер spike:
/// обратная семантика «закрывать и пустой накопитель» давала тихий OOB-краш,
/// текущая семантика — красный гейт). Мусорные литералы режутся ДО сканера на
/// границе данных ([`DecideArbiter::sanitize_state`] / `clean_state`); в
/// `plan_of_block` клининг не вживляется: `check_splice` сверяет слова.
/// Литера, убивающая вход Decide (#88): U+2116 № NUMBER SIGN.
/// Инвентарь промера (golden v1.10, N=287; первичка `tokenizer.json` Decide
/// rev 18271032, Unigram 128000, `byte_fallback=false`): единственный символ
/// золотого датасета, дающий `[UNK]` (id 3) на Decide-токенизаторе:
/// `№` → `▁`(507) + `[UNK]`(3); в словаре нет ни одного токена, содержащего
/// `№`. Каскад 1 (`rubert` `WordPiece` 120138) имеет его в словаре (id 248) и не
/// ломается (промер PR #87, audit §10.9).
pub const UNK_LITERA: char = '\u{2116}';

/// Байт-сохраняющая замена для [`UNK_LITERA`]: ровно 3 Б = `N` (ASCII U+004E)
/// + `о` (кириллическая U+043E) — побайтово 1+2 = 3 Б = длине `№`; в Decide
///   это `▁N` + `о` (оба словарных, промер rev 18271032), 0 UNK, decode
///   сохраняет соседние слова (check_splice-стиль промера на g0133).
///   Отклонены промером: `NN` (2 Б — длина ЕХАЕТ, а канонизатор живёт ДО
///   чанковки, где `Chunk::span` = байты) и канонический NFKC `No` (2 Б +
///   normalizer токенизатора = Sequence[Replace→NFC→Strip] на нём = identity;
///   NFKC не применяется: `NFKC(NFKC('№'))='No'≠'№'` = неидемпотентен, канон
///   = замена, а не нормализация).
pub const UNK_REPLACEMENT: &str = "N\u{43e}";

/// Санитизация входа Decide (#88): `№` → [`UNK_REPLACEMENT`] — канонический
/// промпт-маппинг, НЕ правка данных. Чистая функция (feature-off модуль,
/// `just test` без ort), живой вызов — `arbitrate::arbitrate_chunked`
/// (ре-экспорт оттуда же).
///
/// Держится на входе Decide (арбитраж серой зоны), куда приходит сырой текст
/// запроса: `check_splice` (4b-2a, «промер, не вера») ветоит любой `[UNK]` в
/// живом входе, а `№` даёт ровно один — весь вход с номерной литерой терял
/// вердикты каскада 2 (деградация `Cascade2::Skipped`, #87). Харнес делал то
/// же ad-hoc (`recall_golden.rs`: `№`→пробел, row-level мере координаты не
/// нужны); продукт чинится тем же классом маппинга, и парность
/// харнес↔продукт (#87) перестаёт расходиться на этом входе.
///
/// Координатная безопасность = свойство замены, а не потребителя:
/// - байт-длина инвариантна (3 Б → 3 Б), поэтому байтовые спаны оригинала
///   (каскад 1, мерж, маскирование) не сдвигаются НИКОГДА — даже если
///   канонизированный текст куда-то утечёт, `start`/`end` оригинала
///   остаются валидными;
/// - Decide координат не производит (#41: вердикты row-level), сплайс-контур
///   (`check_splice`) сверяет слова канонизированного входа с его же decode —
///   замена внутри одного входа невидима вето;
/// - `mask`/vault не видят канонизированный текст: он живёт строго внутри
///   пути арбитра, оригинал запроса не мутируется.
///
/// Идемпотентность: `Nо` не содержит `№` ⇒ `f(f(x)) = f(x)`. // scan-lang:allow
///
/// Ограничение (задокументировано: README §5 п.4, audit §10.9–§10.10): токен
/// «Nо» не тождественен «№» модели — на строках, где серая зона решается // scan-lang:allow
/// ТОЛЬКО литерой `№` (номер договора), p2 получает канонизированный вход.
/// Цена промерена (audit §10.10): реальный пропуск за полный golden-прогон
/// был ровно 1 строка (`g0133`); метрика union/exact харнеса канонизатором
/// не двигается (харнес нёс свою замену, теперь зовёт общий канон).
#[must_use]
pub fn canonicalize_decide_input(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains(UNK_LITERA) {
        std::borrow::Cow::Owned(text.replace(UNK_LITERA, UNK_REPLACEMENT))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

/// Группировка маркеров: граница `[SEP_*]` закрывает накопитель (док выше
/// блока #88: контракта `groups` не касается).
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
    fn groups_ignore_stray_markers_in_state() {
        // 4b-3B OOB-страж: [SEP_*] НЕ сбрасывает пустой накопитель; одинокий
        // [L] ДО границы с НЕПУСТЫМ накопителем закрывается границей как
        // отдельная группа sizes=[1] (красный layout-гейт вызывающего), а
        // НЕ склеивается со следующей; склейка [0,1,2] — только если
        // мусорный маркер стоит МЕЖДУ живыми маркерами БЕЗ границы:
        let ids = vec![128_007u32, 128_002, 128_007, 128_007];
        let g = groups(&ids, [128_007, 128_007]);
        assert_eq!(g.len(), 2, "фантом ДО границы закрыт ей же + живая группа");
        assert_eq!(
            g[0].1,
            vec![0],
            "одиночка = группа из 1 (sizes-гейт красен)"
        );
        assert_eq!(g[1].1, vec![2, 3], "живая группа корректна");
        // непустая граница ЗАКРЫВАЕТ группу; одиночка ПОСЛЕ последней границы
        // НЕ глотается — флешится хвостовой группой (len≠schema → гейт красен):
        let ids2 = vec![128_007u32, 128_007, 128_002, 128_007];
        let g2 = groups(&ids2, [128_007, 128_007]);
        assert_eq!(g2.len(), 2, "живая [0,1] + хвост-одиночка [3]");
        assert_eq!(g2[0].1, vec![0, 1]);
        assert_eq!(g2[1].1, vec![3]);
    }

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
    fn lockr_bio_group_brackets_and_breaks() {
        // B-PHONE I-PHONE B-EMAIL O B-PHONE → 3 спана, последний 1 токен;
        // чужой I (I-INN после B-PHONE) обрывает и НЕ открывает (B- нет).
        let tags = [
            "O", "B-PHONE", "I-PHONE", "B-EMAIL", "I-INN", "O", "B-PHONE",
        ];
        let sp = lockr_bio_group(&tags);
        assert_eq!(sp.len(), 3, "телефон(1-3) + почта + телефон(6)");
        assert_eq!(&sp[0], &("PHONE".to_string(), 1, 3));
        assert_eq!(&sp[1].0, "EMAIL", "I-INN не продлил EMAIL и не стал спаном");
        assert_eq!(&sp[1], &("EMAIL".to_string(), 3, 4));
        assert_eq!(&sp[2], &("PHONE".to_string(), 6, 7));
    }

    #[test]
    fn lockr_tags_threshold_gates_to_o() {
        let argmax = [26usize, 27, 26]; // B-PHONE, I-PHONE, B-PHONE
        let probs = [0.9, 0.4, 0.5];
        let t = lockr_tags(&argmax, &probs, 0.5);
        assert_eq!(t, vec!["B-PHONE", "O", "B-PHONE"], "порог включительно");
        assert!(lockr_tags(&[999], &[1.0], 0.5) == vec!["O"], "вне 43 — O");
    }

    #[test]
    fn lockr_id2label_matches_verify_mirror() {
        // Один источник истины на два места (паттерн DECIDE_* констант):
        // скрипт-парити несёт ТЕ ЖЕ 43 тега.
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/verify/parity_golden.py"
        ))
        .expect("скрипт парити рядом с деревом сборки");
        let start = src
            .find("ID2LABEL = [")
            .expect("ID2LABEL в parity_golden.py");
        // зеркало читаем ВСЕМ оставшимся файлом: `]` вложен (списки-в-строках),
        // границы искать нечем — проверка «каждый тег упомянут» монолитна.
        let body = &src[start..];
        for tag in ID2LABEL {
            assert!(body.contains(&format!("\"{tag}\"")), "тег {tag} потерян");
        }
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

    /// Решётка канонизатора #88 (первичка промера — док `canonicalize_decide_input`).
    #[test]
    fn canonicalize_number_sign_is_byte_preserving_and_idempotent() {
        // Вектор из golden g0133 (первый промер, PR #87): «№» в заголовке.
        let raw = "Договор оказания услуг \u{2116} 782/24";
        let canon = canonicalize_decide_input(raw);
        // 1) байтовая длина инвариантна — спаны оригинала не сдвигаются;
        assert_eq!(canon.len(), raw.len(), "байтовая длина поехала");
        // 2) литера убита: канон не содержит U+2116;
        assert!(!canon.contains(UNK_LITERA), "№ выжил в каноне: {canon:?}");
        // 3) замена = словарный ASCII-двухбуквенник, слова-соседи целы;
        assert!(
            canon.contains("N\u{43e} 782/24"),
            "замена не на месте: {canon:?}"
        );
        assert!(canon.starts_with("Договор оказания услуг"));
        // 4) идемпотентность;
        let twice = canonicalize_decide_input(&canon);
        assert_eq!(twice.as_ref(), canon.as_ref(), "f(f(x)) != f(x)");
        // 5) чистый вход = заимствованный (нулевое выделение на горячем пути);
        assert!(matches!(
            canonicalize_decide_input("Ушакова Кира Саввична"),
            std::borrow::Cow::Borrowed(_)
        ));
        // 6) UTF-8-безопасность: replacement-boundary (№ в плотной окружении,
        //    границы = char-границы по построению replace).
        let dense = "\u{2116}\u{2116}\u{2116}";
        let c = canonicalize_decide_input(dense);
        assert_eq!(c.len(), dense.len());
        assert!(c.is_char_boundary(c.len()));
    }

    /// Канонизированный вход живёт строго в пути арбитра: `sanitize_state`
    /// (контур спец-токенов, `arbitrate`) не затрагивает `№` и остаётся
    /// ортогональным канону #88 — замена не притворяется спец-токеном и не
    /// вырезается (санитайзеры двух контуров не каннибализируют друг друга).
    #[test]
    fn canonicalize_orthogonal_to_specials_clinining() {
        // `[E]`/`[R]` = литералы SPECIALS (контур sanitize_state): канон их не
        // трогает; `№` = литера канона: sanitize_state её не трогает (зона
        // canonicalize_decide_input).
        let dirty = "\u{2116} 782 [E] 24";
        let canon = canonicalize_decide_input(dirty);
        assert!(!canon.contains('\u{2116}') && canon.contains("N\u{43e}"));
        assert!(
            canon.contains("[E]"),
            "канон не чистит спец-токены (зона sanitize_state)"
        );
    }
}
