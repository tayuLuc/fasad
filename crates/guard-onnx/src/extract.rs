//! `extract` — живой каскад 1 (lockR-экстрактор) как библиотечный API (#14A).
//!
//! До шага 9 этот декодер жил только в харнесе `examples/recall_golden.rs`, и
//! продуктовый путь `/v1/analyze` не мог его вызвать: «функция покрыта» ≠
//! «вызвана на пути запроса». Вынос сделан по инварианту 7b «меряем = гоняем» —
//! харнес после выноса зовёт ЭТУ же кодобазу, поэтому расхождение «метрика
//! харнеса vs продукт» структурно невозможно, а Δ-parity промера = 0.00
//! (проверка: `examples/recall_golden.rs` вызовами [`LockrExtractor`]).
//!
//! Контракт декода — дословный харнес `tools/verify/parity_golden.py::run_lockr`
//! (промер 4b-3C, ревью PR#49 блокеры №1/№2), а не «общее место» HF:
//!
//! 1. пост-процессор снят ЯВНО: Rust-`encode(true)` не применяет
//!    `TemplateProcessing`, а WordPiece переписывает offsets в байты;
//!    python-форму `[CLS]+слова+[SEP]` со спец-слотами `(0,0)` собирает
//!    [`encode_plus`];
//! 2. пад-заполнение вручную до [`PAD`] (256), инпут = препад-срез `real`;
//! 3. argmax+softmax по 43 головам на позицию, спец-позиции принудительно `O`
//!    (id-множество [`LOCKR_SPECIALS`] = эквивалент харнесного
//!    `decode([id]) in LOCKR_SPECIALS`, которое на одиночном спец-id ложно);
//! 4. B/I-скобка [`crate::decide::lockr_bio_group`], PS-трим хвоста по
//!    `id_to_token(..).starts_with("##")`, conf = **min** probs всей скобки;
//! 5. гейт порога — НЕ здесь: спаны отдаются с `score`, решает вызывающий через
//!    `RoutingCfg` (пре-гейт в тегах рвёт I-скобки SNILS/CITY — промер 4b-3C).
//!
//! # Что здесь fail-closed
//!
//! [`LockrExtractor::extract`] помечает срез: текст длиннее окна ([`PAD`]
//! токенов) модели НЕ покрывается, молча выбросить хвост = потерять ПДн в нём
//! (FN фатален, AGENTS §Инварианты), поэтому факт среза возвращается флагом
//! [`Extract::truncated`], и потребитель (демон) обязан отказать запросу.
//! Харнес флаг игнорирует осознанно: его знаменатель — строки golden, в окно
//! влезающие (промер: max по recall-сплиту < PAD).

use std::path::Path;

use ort::environment::Environment;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Tensor;
use tokenizers::Tokenizer;
use tokenizers::processors::template::TemplateProcessing;

use crate::decide::ID2LABEL;

/// Ширина окна lockR-графа в токенах (входной тензор `(1, PAD)`; харнес
/// `parity_golden.py` L252–257: `numpy.zeros(256)` + срез `[:ln]`).
pub const PAD: usize = 256;

/// Число голов token-classification (первичка `config.json`
/// `lockR/rubert-base-pii-ner-onnx@ea7610b2`, зеркало [`ID2LABEL`]).
pub const N_TAGS: usize = 43;

/// decode-контракт харнеса (`parity_golden.py` `LOCKR_SPECIALS`, L197): строки
/// имён; python `decode([CLS]) = ''` ⇒ фильтр ЛОЖЕН на спецах (O там красит
/// argmax модели), PS-токен `##вич` ∉ сете ⇒ PS спан не обрывают.
pub const LOCKR_SPECIALS: [&str; 5] = ["[CLS]", "[SEP]", "[PAD]", "[MASK]", "[UNK]"];

/// Ошибка экстрактора. Все ветки — «спанов нет и сделать вид, что всё чисто,
/// нельзя»; как именно отказывать, решает вызывающий (демон: 502).
#[derive(Debug)]
pub enum ExtractError {
    /// Файл модели/токенизатора отсутствует или нечитаем.
    Io(std::io::Error),
    /// ORT-ошибка (инициализация сессии, ран). rc.14 параметризует ошибку
    /// стадией, поэтому — стёртая строка (тот же трейд, что `ArbError::Ort`).
    Ort(String),
    /// Токенизатор не читает файл / не кодирует вход / в vocab нет спец-токена.
    Tokenizer(String),
    /// Выход графа не f32 `(1, PAD, N_TAGS)` — контракт IO головы.
    Shape(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "файл модели/токенизатора: {e}"),
            Self::Ort(s) => write!(f, "ort: {}", s.replace('\n', " ")),
            Self::Tokenizer(s) => write!(f, "токенизатор: {s}"),
            Self::Shape(s) => write!(f, "форма выхода: {s}"),
        }
    }
}

impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// ort rc.14 параметризует ошибку стадией (`Error<SessionBuilder>` ≠
/// `Error<()>`) и держит `NonNull`-указатели в `recover` — стираем в строку
/// ОДИН раз (тот же трейд, что `ArbError::Ort`): `Display` полный, `source()`
/// теряется осознанно.
impl From<ort::Error> for ExtractError {
    fn from(e: ort::Error) -> Self {
        Self::Ort(e.to_string())
    }
}

/// Спан каскада 1: байтовый интервал + голова модели + золотой класс + conf.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractSpan {
    /// Байт начала (включительно).
    pub byte_start: usize,
    /// Байт конца (исключительно).
    pub byte_end: usize,
    /// Голова модели без B-/I-префикса (`LAST_NAME`, `CITY`, …) — из
    /// [`ID2LABEL`], поле для логов/схемной сверки.
    pub tag: String,
    /// Golden-класс по [`tag_to_class`]; `None` — голова вне нашей онтологии
    /// (`URL`, `IP_ADDRESS`, `MILITARY_ID`, …): спан отдаётся, класс не
    /// назначен, решение (дроп/класс из схемы) за вызывающим.
    pub class: Option<&'static str>,
    /// Confidence = **min** softmax по всей B/I-скобке (контракт харнеса).
    pub score: f64,
}

/// Ответ [`LockrExtractor::extract`]: спаны + честный флаг среза окна.
#[derive(Debug, Clone, PartialEq)]
pub struct Extract {
    /// Спаны в порядке B/I-скобок (позиционный порядок токенов).
    pub spans: Vec<ExtractSpan>,
    /// Текст не влез в окно [`PAD`] — то, что за окном, НЕ посмотрено.
    /// Харнес флаг не читает (его строки в окне), демон обязан отказать.
    pub truncated: bool,
}

/// Голова → golden-класс. Зеркало харнесного `bio_to_class` (8 покрытых
/// классов; iban/ogrn/ogrnip — каскад 0, heads-покрытия нет).
#[must_use]
pub fn tag_to_class(tag: &str) -> Option<&'static str> {
    match tag {
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
/// со снятым пост-процессором: `[CLS]`+слова+`[SEP]`, offsets `(0,0)` на
/// спецах, attention = 1 — все поля 1-в-1 по длине (промер 4b-3C: 75/75/75).
///
/// `Encoding::from_tokens` + `merge_with(growing_offsets = false)`: спец-слоты
/// `(0,0)`/`special_mask = 1`/`attention = 1` — ровно `TemplateProcessing::
/// apply_template` (промер исходников tokenizers 0.23).
#[must_use]
pub fn encode_plus(
    base: &tokenizers::Encoding,
    cl_id: u32,
    sep_id: u32,
    cl_tok: &str,
    sep_tok: &str,
) -> tokenizers::Encoding {
    let spm1 = |id: u32, v: &str| {
        #[allow(
            clippy::default_trait_access,
            reason = "тип последнего поля Encoding — AHashMap из tokenizers, в явных                       зависимостях его нет"
        )]
        let e = tokenizers::Encoding::new(
            vec![id],
            vec![0],
            vec![v.to_string()],
            vec![None],
            vec![(0, 0)],
            vec![1],
            vec![1],
            vec![],
            Default::default(),
        );
        e
    };
    let mut e = spm1(cl_id, cl_tok);
    e.merge_with(base.clone(), false);
    e.merge_with(spm1(sep_id, sep_tok), false);
    e
}

/// argmax + softmax по 43 головам на позицию + спец-фильтр (пункты 3 дока
/// модуля). Чистая функция: тест гоняет её на синтетических логитах, без
/// модели и без ORT (гейт `cargo test -p guard-onnx` на обеих ОС).
///
/// Спец-позиции принудительно `O` (id-множество [`LOCKR_SPECIALS`] = эквивалент
/// харнесного decode-фильтра); ПОРОГА ЗДЕСЬ НЕТ — conf уезжает на позицию,
/// гейт по min-скобке делает вызывающий.
fn tags_and_probs(
    lg: &[f32],
    real: usize,
    ids_u: &[u32],
    special: &[u32],
) -> (Vec<&'static str>, Vec<f64>) {
    let mut tagv: Vec<&'static str> = Vec::with_capacity(real);
    let mut probv: Vec<f64> = Vec::with_capacity(real);
    for t in 0..real {
        let row = &lg[t * N_TAGS..(t + 1) * N_TAGS];
        let mx = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let sum: f64 = row.iter().map(|&x| f64::from(x - mx).exp()).sum();
        let mut best = 0usize;
        let mut bv = f32::NEG_INFINITY;
        for (i, &x) in row.iter().enumerate() {
            if x > bv {
                bv = x;
                best = i;
            }
        }
        let p = if sum > 0.0 && sum.is_finite() {
            f64::from(bv - mx).exp() / sum
        } else {
            0.0
        };
        let is_special = t < ids_u.len() && special.contains(&ids_u[t]);
        tagv.push(if is_special { "O" } else { ID2LABEL[best] });
        probv.push(p);
    }
    (tagv, probv)
}

/// Живой каскад 1: сессия lockR fp16 + токенизатор rubert.
///
/// Сессия `!Sync` (ран требует `&mut`), поэтому в демоне тип держится за
/// `Mutex` и обслуживается одним инференсным воркером (RSS-бюджет §10 п.9
/// и так не даёт крутить два параллельных прогона).
pub struct LockrExtractor {
    session: Session,
    tokenizer: Tokenizer,
    cl_id: u32,
    sep_id: u32,
    special: Vec<u32>,
}

impl LockrExtractor {
    /// Поднимает сессию и токенизатор. Путь fail-closed: отсутствие файла,
    /// кривой vocab (`[CLS]`/`[SEP]` нет) и падение `commit_from_file` —
    /// [`ExtractError`], а не «демон без каскада 1».
    ///
    /// # Errors
    ///
    /// [`ExtractError::Io`] (файл), [`ExtractError::Tokenizer`] (файл/vocab),
    /// [`ExtractError::Ort`] (сборка/коммит сессии).
    pub fn load(
        env: &Environment,
        model: &Path,
        tokenizer: &Path,
        threads: usize,
    ) -> Result<Self, ExtractError> {
        let mut tokenizer =
            Tokenizer::from_file(tokenizer).map_err(|e| ExtractError::Tokenizer(e.to_string()))?;
        // Пост-процессор снимаем ЯВНО (см. док модуля, пункт 1).
        tokenizer.with_post_processor(Option::<TemplateProcessing>::None);
        let vocab = tokenizer.get_vocab(true);
        let pick = |name: &str| -> Result<u32, ExtractError> {
            vocab
                .get(name)
                .copied()
                .ok_or_else(|| ExtractError::Tokenizer(format!("vocab lockR: нет {name}")))
        };
        let cl_id = pick("[CLS]")?;
        let sep_id = pick("[SEP]")?;
        // `[PAD]` в харнесе = `unwrap_or(0)`: пад-id вне vocab допустим
        // (вход падится нулями, attention_mask = 0 их и выключает).
        let _pad_id = vocab.get("[PAD]").copied().unwrap_or(0);
        let special: Vec<u32> = LOCKR_SPECIALS
            .iter()
            .filter_map(|t| vocab.get(*t).copied())
            .collect();
        let session = Session::builder(env)?
            .with_intra_threads(threads)
            .map_err(|e| ExtractError::Ort(format!("intra_threads({threads}): {e}")))?
            .with_optimization_level(GraphOptimizationLevel::All)
            .map_err(|e| ExtractError::Ort(e.to_string()))?
            .commit_from_file(model)?;
        Ok(Self {
            session,
            tokenizer,
            cl_id,
            sep_id,
            special,
        })
    }

    /// Прогон каскада 1 по одному тексту. Декод — контракт харнеса (док модуля),
    /// порог НЕ применяется: вызывающий гейтит [`ExtractSpan::score`] своим
    /// `RoutingCfg` (тот же код, что в харнесе 7b).
    ///
    /// # Errors
    ///
    /// [`ExtractError::Tokenizer`] (encode), [`ExtractError::Ort`] (ран),
    /// [`ExtractError::Shape`] (выход не `(1, PAD, N_TAGS)` f32).
    pub fn extract(&mut self, text: &str) -> Result<Extract, ExtractError> {
        let base = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| ExtractError::Tokenizer(e.to_string()))?;
        let enc = encode_plus(&base, self.cl_id, self.sep_id, "[CLS]", "[SEP]");
        let ids_u: Vec<u32> = enc.get_ids().to_vec();
        let offs = enc.get_offsets().to_vec();
        let real = enc.len().min(PAD);
        let truncated = enc.len() > PAD;
        // ИНПУТ = харнес L252–257: `numpy.zeros(256)` + срез `[:ln]` ⇒ пад-id
        // в тензоре 0, attention = 0 на хвосте; снимки ids/offs взяты ДО
        // паддинга (`enc.pad` трогает offsets).
        let mut ids: Vec<i64> = vec![0i64; PAD];
        for (dst, src) in ids.iter_mut().zip(ids_u.iter().take(real)) {
            *dst = i64::from(*src);
        }
        let mut attn: Vec<i64> = enc
            .get_attention_mask()
            .iter()
            .map(|&x| i64::from(x))
            .collect();
        attn.resize(PAD, 0);
        attn.truncate(PAD);
        let types = vec![0i64; PAD];
        let out = self.session.run(vec![
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
        let (_, lg) = out["logits"]
            .try_extract_tensor::<f32>()
            .map_err(|e| ExtractError::Shape(format!("logits: {e}")))?;
        if lg.len() != PAD * N_TAGS {
            return Err(ExtractError::Shape(format!(
                "logits: {} floats, ожидалось {}",
                lg.len(),
                PAD * N_TAGS
            )));
        }

        let (tagv, probv) = tags_and_probs(lg, real, &ids_u, &self.special);

        let mut spans = Vec::new();
        for (cls_tok, ts, te) in crate::decide::lockr_bio_group(&tagv) {
            // PS-трим хвоста (harネス `decode([id]).startswith('##')`), i0 = ts.
            let mut i1 = (te - 1).min(ids_u.len() - 1);
            while i1 >= ts
                && self
                    .tokenizer
                    .id_to_token(ids_u[i1])
                    .is_some_and(|tk| tk.starts_with("##"))
            {
                i1 -= 1;
            }
            let i0 = ts;
            if i1 < i0 {
                continue;
            }
            let (Some((c0, _)), Some((_, c1))) = (offs.get(i0).copied(), offs.get(i1).copied())
            else {
                continue;
            };
            // Offsets Rust-`tokenizers` уже байтовые (промер 4b-3C), char→byte
            // конверсия поверх = вторая конверсия (нулевой recall).
            let (b0, b1) = (c0, c1);
            if b1 <= b0 {
                continue;
            }
            let conf = probv[ts..te].iter().copied().fold(f64::INFINITY, f64::min);
            spans.push(ExtractSpan {
                byte_start: b0,
                byte_end: b1,
                tag: cls_tok.clone(),
                class: tag_to_class(&cls_tok),
                score: conf,
            });
        }
        Ok(Extract { spans, truncated })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_to_class_covers_eight_schema_classes() {
        // 8 покрытых heads-классов = CLASSES харнеса; вето: ни одна голова
        // схемы не должна остаться без класса.
        let heads = [
            "FIRST_NAME",
            "LAST_NAME",
            "MIDDLE_NAME",
            "INN",
            "SNILS",
            "CREDIT_CARD",
            "PHONE",
            "EMAIL",
            "CITY",
            "STREET",
            "HOUSE",
            "REGION",
            "COUNTRY",
            "PASSPORT",
        ];
        let mut classes: Vec<&str> = heads.iter().filter_map(|h| tag_to_class(h)).collect();
        classes.sort_unstable();
        classes.dedup();
        assert_eq!(
            classes,
            vec![
                "address",
                "card_pan",
                "email",
                "inn",
                "passport",
                "person_name",
                "phone",
                "snils"
            ]
        );
        // Вне онтологии: URL/IP_ADDRESS/MILITARY_ID.
        assert_eq!(tag_to_class("URL"), None);
        assert_eq!(tag_to_class("IP_ADDRESS"), None);
    }

    #[test]
    fn id2label_head_count_matches_pad_contract() {
        assert_eq!(ID2LABEL.len(), N_TAGS);
        assert_eq!(PAD, 256);
        assert_eq!(LOCKR_SPECIALS.len(), 5);
    }
}
