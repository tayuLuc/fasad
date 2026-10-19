//! `arbitrate` — живой Decide-арбитр (шаг 4b-2c, issue #20).
//!
//! Констрэкт SPAN-разметки + инференция + softmax-по-группам в одном типе:
//! [`DecideArbiter::load`] поднимает сессию `model_q4f16.onnx` (external data
//! лежит рядом — `model_q4f16.onnx_data`, контракт audit §5.1) и
//! `tokenizer.json` из кэша `scripts/fetch-models.sh`; [`DecideArbiter::prompts`]
//! строит план разметки; [`DecideArbiter::arbitrate_text`] гоняет ОДИН прогон на
//! весь текст и отдаёт вердикты по вопросам.
//!
//! Формат разметки здесь НЕ дублируется: таблица спец-токенов, их id и
//! группировка маркеров берутся из [`crate::decide`] (контракт 4b-2b) — двойной
//! правды нет. Эталон формы — живой констрэкт spike `arb_live_layout` (4b-2a),
//! который с этого шага собирается через [`DecideArbiter::schema_block`].
//!
//! Чанкование НЕ здесь: весь текст идёт одним прогоном (как spike `--arb`),
//! разбивка по окну — отдельный фоллов.
//!
//! Fail-Closed (AGENTS §Инварианты): расхождение живого vocab с
//! [`crate::decide::SPECIALS`], пустая схема и маркерный индекс вне
//! последовательности — это [`ArbError`], не паника и не деград-ответ (§5.3:
//! `GatherElements` рвёт сессию на индексе ≥ L, поэтому вето объявлено ДО `run`).
//!
//! [`softmax`], [`decide_probs`] и [`marker_positions`] — чистые функции (без
//! вызовов орта); тесты гоняют их на синтетических логитах.

use std::path::Path;

use ort::environment::Environment;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Tensor;
use tokenizers::Tokenizer;

use crate::decide::{self, SPECIALS};

/// Индекс `[SEP_STRUCT]` в таблице [`SPECIALS`] (разделитель схем).
const SEP_STRUCT: usize = 0;
/// Индекс `[SEP_TEXT]` в таблице [`SPECIALS`] (конец блока схем).
const SEP_TEXT: usize = 1;
/// Индекс `[L]` в таблице [`SPECIALS`] (маркер метки = позиция `marker_positions`).
const L: usize = 6;
/// Id неизвестного токена vocab Decide (промер `tokenizer.json` рев. 18271032).
const UNK_ID: u32 = 3;

/// Ошибка арбитра — все ветки fail-closed (ни одна не «пропустить наружу»).
#[derive(Debug)]
pub enum ArbError {
    /// Файл модели/токенизатора отсутствует или нечитаем.
    Io(std::io::Error),
    /// ORT-ошибка (инициализация, load, ран). ort rc.14 параметризует ошибку
    /// стадией (`Error<SessionBuilder>` ≠ `Error<()>`) и держит в `recover`
    /// `NonNull`-указатели, поэтому — стёртый бокс ОДИН раз в конце ошибки
    /// (Message-текст), а не `Box<dyn Error>`: трейд-офс — `source()` теряется,
    /// `Display` остаётся полным.
    Ort(String),
    /// Токенизатор не читает `tokenizer.json` / не кодирует вход.
    Tokenizer(String),
    /// Id спец-токена из [`SPECIALS`] не совпал с живым vocab ([`decide::id_of`]
    /// вернул `None`) — красс-контракт разметки; сессию не поднимаем (проверено
    /// ДО load: 523 МБ весов грузить бессмысленно).
    VocabMismatch(String),
    /// Схема вопроса пуста (ноль меток): контракт `marker_positions` требует ≥1
    /// маркера на группу (промер 4b-0: ленивый `GatherElements` на пустых не
    /// падает, но [`decide::groups`] пустые группы не выдаёт).
    EmptySchema(String),
    /// План без маркерных групп: на выход графа не на что смотреть.
    NoMarkers,
    /// Маркерный индекс вне `[0, L)` (§5.3). Вето ДО `run`, чтобы дефект был
    /// нашей ошибкой, а не порванной ORT-сессией.
    MarkerOutOfRange {
        /// Спорный индекс маркера.
        pos: usize,
        /// Длина токенизированной последовательности.
        len: usize,
    },
    /// Выход графа не f32 `(1,M)` — контракт IO (§Graph карточки @18271032).
    OutputShape(String),
    /// Констрэкт не прошёл живую сверку (`[UNK]` ≠ 0, потеря слова, группы ≠ схемы).
    Layout(String),
}

impl std::fmt::Display for ArbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "файл модели/токенизатора: {e}"),
            Self::Ort(s) => write!(f, "ort: {}", s.replace('\n', " ")),
            Self::Tokenizer(s) => write!(f, "токенизатор: {s}"),
            Self::VocabMismatch(s) => write!(f, "расхождение vocab↔SPECIALS: {s}"),
            Self::EmptySchema(q) => write!(f, "пустая схема вопроса {q:?}"),
            Self::NoMarkers => write!(f, "план без маркерных групп"),
            Self::MarkerOutOfRange { pos, len } => {
                write!(f, "маркер {pos} вне последовательности длины {len} (§5.3)")
            }
            Self::OutputShape(s) => write!(f, "контракт выхода нарушен: {s}"),
            Self::Layout(s) => write!(f, "констрэкт разметки: {s}"),
        }
    }
}

impl std::error::Error for ArbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            // Ort и текстовые ветки: источник уже внутри сообщения.
            _ => None,
        }
    }
}

impl From<std::io::Error> for ArbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ort::Error> for ArbError {
    fn from(e: ort::Error) -> Self {
        Self::Ort(e.to_string())
    }
}

impl ArbError {
    /// Стирание ort-ошибки ЛЮБОЙ стадии build-цепочки в текст:
    /// `Error<SessionBuilder>` не конвертируется в `Error<()>` через `?`, а
    /// `SessionBuilder` не `Sync` (NB: это НЕ потеря — трейд зафиксирован в
    /// доке варианта [`ArbError::Ort`]).
    fn ort<E: std::fmt::Debug + std::fmt::Display>(e: E) -> Self {
        Self::Ort(e.to_string())
    }
}

/// Схема вопроса: текст + метки (ПЕРВАЯ метка — «да», контракт Decide).
pub type QuestionSchema<'a> = (&'a str, &'a [&'a str]);

/// План инференции: id-последовательность (блок схем + текст), группы маркеров
/// в порядке вопросов и `marker_positions` для графа.
#[derive(Debug, Clone)]
pub struct SchemaPlan {
    /// Токенизированные id всего входа (одним `encode`).
    pub ids: Vec<u32>,
    /// Группы маркеров по схемам, порядок = порядок вопросов
    /// ([`decide::groups`]; `group.1[0]` — `[P]`, дальше `[L]` по метке).
    pub groups: Vec<(usize, Vec<usize>)>,
    /// Флэт `[L]`-позиций по группам, БЕЗ `[P]` первого в группе (контракт
    /// `conversion/verify_parity.py` L34–37), подаётся тензором INT64 (1,M).
    pub markers: Vec<i64>,
    /// Число `[L]`-маркеров в группе (в порядке `groups`) — offset-карта
    /// логит-слайсов: слайс группы `i` = `[sum(sizes[..i]), +sizes[i])`.
    pub group_sizes: Vec<usize>,
    /// Тексты вопросов (в порядке `groups`).
    pub questions: Vec<String>,
    /// Первая метка группы = «да» (в порядке `groups`).
    pub labels: Vec<String>,
}

impl SchemaPlan {
    /// OOB-вето (§5.3) + контракт «≥1 маркера на группу»: пустых групп не
    /// бывает, индекс вне `[0, L)` = [`ArbError::MarkerOutOfRange`] (не паника).
    ///
    /// # Errors
    ///
    /// [`ArbError::NoMarkers`] при пустом плане, [`ArbError::MarkerOutOfRange`]
    /// при маркере вне `[0, L)`.
    pub fn check_markers(&self) -> Result<(), ArbError> {
        if self.markers.is_empty() || self.group_sizes.contains(&0) {
            return Err(ArbError::NoMarkers);
        }
        let len = self.ids.len();
        let lim = i64::try_from(len).unwrap_or(i64::MAX);
        if let Some(&bad) = self.markers.iter().find(|&&m| m < 0 || m >= lim) {
            return Err(ArbError::MarkerOutOfRange {
                pos: usize::try_from(bad).unwrap_or(usize::MAX),
                len,
            });
        }
        Ok(())
    }
}

/// Вердикт по одному вопросу схемы.
#[derive(Debug, Clone)]
pub struct QuestionDecision {
    /// Текст вопроса.
    pub question: String,
    /// Метка-победитель = ПЕРВАЯ метка группы («да» по контракту Decide).
    pub label: String,
    /// Вероятность победителя (softmax внутри группы маркеров).
    pub prob: f32,
    /// `prob >= threshold` (порог сверху — AGENTS: FN фатален, FP дёшев).
    pub hit: bool,
}

/// Живой Decide-арбитр: сессия + токенизатор + сверенные id спец-токенов.
pub struct DecideArbiter {
    session: Session,
    tokenizer: Tokenizer,
    /// Id по таблице [`SPECIALS`] (индекс = позиция в ней), сверенные с живым
    /// vocab через [`decide::id_of`] в [`DecideArbiter::load`] — расхождение там
    /// же превращается в [`ArbError::VocabMismatch`], поэтому значения верны.
    ids: [u32; SPECIALS.len()],
}

impl DecideArbiter {
    /// Загрузка. Сессия — паттерн `open_session` из spike (промер 19.10):
    /// `with_intra_threads` + `GraphOptimizationLevel::All` +
    /// `commit_from_file` (external data подхватывается по соседнему
    /// `<model>.onnx_data`). Токенизатор — `Tokenizer::from_file` со снятым
    /// post-процессором (§Graph: «No `[CLS]`/`[SEP]`»). Self-check vocab против
    /// манифеста [`SPECIALS`] идёт ДО поднятия сессии (fail-closed дешевле
    /// 523 МБ load).
    ///
    /// # Errors
    ///
    /// [`ArbError::Tokenizer`] / [`ArbError::VocabMismatch`] / [`ArbError::Io`] /
    /// [`ArbError::Ort`] на соответствующих отказах загрузки.
    pub fn load(
        env: &Environment,
        model_path: &Path,
        tokenizer_path: &Path,
        intra_threads: usize,
    ) -> Result<Self, ArbError> {
        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| ArbError::Tokenizer(format!("{}: {e}", tokenizer_path.display())))?;
        tokenizer.with_post_processor(
            Option::<tokenizers::processors::template::TemplateProcessing>::None,
        );
        let vocab = tokenizer.get_vocab(true);
        let mut ids = [0u32; SPECIALS.len()];
        for (i, (name, _)) in SPECIALS.iter().enumerate() {
            ids[i] = decide::id_of(&vocab, name)
                .ok_or_else(|| ArbError::VocabMismatch(name.to_string()))?;
        }
        let session = Session::builder(env)
            .map_err(ArbError::ort)?
            .with_intra_threads(intra_threads)
            .map_err(ArbError::ort)?
            .with_optimization_level(GraphOptimizationLevel::All)
            .map_err(ArbError::ort)?
            .commit_from_file(model_path)
            .map_err(ArbError::ort)?;
        Ok(Self {
            session,
            tokenizer,
            ids,
        })
    }

    /// Id спец-токена из сверенной таблицы (`None` для имени вне [`SPECIALS`]).
    #[must_use]
    pub fn id_of(&self, name: &str) -> Option<u32> {
        SPECIALS
            .iter()
            .position(|(n, _)| *n == name)
            .map(|i| self.ids[i])
    }

    /// Строки разметки РОВНО по контракту [`crate::decide`]: схема —
    /// `( [P] {вопрос} ( [L] {метка} [L] {метка} … ) )`, схемы разделены
    /// ` [SEP_STRUCT] ` в ОДНОЙ строке, terminator — ` [SEP_TEXT] ` (живой
    /// эталон формы — spike `arb_live_layout`, 4b-2a).
    ///
    /// Пустая схема (ноль меток) = [`ArbError::EmptySchema`].
    ///
    /// # Errors
    ///
    /// [`ArbError::EmptySchema`] если у какого-то вопроса ноль меток.
    pub fn schema_block(schema: &[QuestionSchema<'_>]) -> Result<String, ArbError> {
        // Имена в SPECIALS УЖЕ с квадратными скобками («[SEP_STRUCT]») —
        // оборачивать повторно нельзя (двойные скобки ломают и строку, и
        // live-check спец-токенов; промер 4b-2c).
        let sep = format!(" {} ", SPECIALS[SEP_STRUCT].0);
        let tail = format!(" {}", SPECIALS[SEP_TEXT].0);
        let mut out = String::new();
        for (i, (question, labels)) in schema.iter().enumerate() {
            if labels.is_empty() {
                return Err(ArbError::EmptySchema((*question).to_string()));
            }
            if i > 0 {
                out.push_str(&sep);
            }
            out.push_str("( [P] ");
            out.push_str(question);
            out.push_str(" (");
            for label in *labels {
                out.push_str(" [L] ");
                out.push_str(label);
            }
            out.push_str(" ) )");
        }
        out.push_str(&tail);
        Ok(out)
    }

    /// План по схеме + тексту состояния: блок схем ([`Self::schema_block`]) и
    /// текст — два сегмента, ОДИН `encode(concat, false)` (Metaspace-склейка;
    /// сплайс отдельных `encode` запрещён промером 4b-2a), затем живая сверка
    /// [`Self::check_splice`] (`[UNK]` = 0, спец-токены и слова сохранены) и
    /// группировка маркеров [`decide::groups`] → [`schema_plan`].
    ///
    /// # Errors
    ///
    /// [`ArbError::EmptySchema`] / [`ArbError::Tokenizer`] / [`ArbError::Layout`]
    /// / [`ArbError::NoMarkers`] / [`ArbError::MarkerOutOfRange`].
    pub fn prompts(
        &self,
        text: &str,
        schema: &[QuestionSchema<'_>],
    ) -> Result<SchemaPlan, ArbError> {
        let block = Self::schema_block(schema)?;
        let segments = [block.as_str(), text];
        let whole = join_segments(&segments);
        let ids = self
            .tokenizer
            .encode(whole.as_str(), false)
            .map_err(|e| ArbError::Tokenizer(format!("encode(whole): {e}")))?
            .get_ids()
            .to_vec();
        self.check_splice(&ids, &segments)?;
        let groups = decide::groups(&ids, [self.ids[L], self.ids[L]]);
        schema_plan(&ids, &groups, schema)
    }

    /// Полный путь: план → ОДИН прогон → вердикты по порогу.
    ///
    /// # Errors
    ///
    /// Любая ветка [`Self::prompts`] плюс [`ArbError::Ort`] / [`ArbError::OutputShape`].
    pub fn arbitrate_text(
        &mut self,
        text: &str,
        schema: &[QuestionSchema<'_>],
        threshold: f32,
    ) -> Result<Vec<QuestionDecision>, ArbError> {
        let plan = self.prompts(text, schema)?;
        let logits = self.run_logits(&plan)?;
        Ok(decisions(&plan, &logits, threshold))
    }

    /// Инференция готового плана: плоские `logits` в порядке `plan.markers`.
    /// OOB-вето ([`ArbError::MarkerOutOfRange`]) повторено здесь — план мог быть
    /// построен вне (спайк-эталон `--arb`), а рвать сессию §5.3 нельзя.
    ///
    /// # Errors
    ///
    /// [`ArbError::MarkerOutOfRange`] / [`ArbError::NoMarkers`] (вето),
    /// [`ArbError::Ort`] / [`ArbError::OutputShape`] на прогоне.
    pub fn run_logits(&mut self, plan: &SchemaPlan) -> Result<Vec<f32>, ArbError> {
        plan.check_markers()?;
        let ids: Vec<i64> = plan.ids.iter().map(|&u| i64::from(u)).collect();
        let mask = vec![1i64; ids.len()];
        let inputs = self.inputs(&ids, &mask, &plan.markers)?;
        let outs = self.session.run(inputs).map_err(ArbError::ort)?;
        let (_, v) = outs
            .iter()
            .next()
            .ok_or_else(|| ArbError::OutputShape("граф вернул ноль выходов".to_string()))?;
        let (shape, data) = v
            .try_extract_tensor::<f32>()
            .map_err(|e| ArbError::OutputShape(format!("выход не f32: {e}")))?;
        let m = plan.markers.len();
        let want = [1i64, i64::try_from(m).unwrap_or(-1)];
        if **shape != want || data.len() != m {
            return Err(ArbError::OutputShape(format!(
                "ожидались logits (1,{m}), получено {:?} из {} эл.",
                shape.to_vec(),
                data.len()
            )));
        }
        Ok(data.to_vec())
    }

    /// Входы сессии по фактическим именам IO (порядок = `session.inputs()`):
    /// `input_ids`/`attention_mask` — INT64 (1,L), `marker_positions` — INT64 (1,M).
    fn inputs(
        &self,
        ids: &[i64],
        mask: &[i64],
        markers: &[i64],
    ) -> Result<Vec<(String, ort::value::DynTensor)>, ArbError> {
        let names: Vec<String> = self
            .session
            .inputs()
            .iter()
            .map(|i| i.name().to_string())
            .collect();
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let v: Tensor<i64> = match name.as_str() {
                "input_ids" => {
                    Tensor::from_array(([1usize, ids.len()], ids.to_vec().into_boxed_slice()))?
                }
                "marker_positions" => Tensor::from_array((
                    [1usize, markers.len()],
                    markers.to_vec().into_boxed_slice(),
                ))?,
                _ => Tensor::from_array(([1usize, mask.len()], mask.to_vec().into_boxed_slice()))?,
            };
            out.push((name, v.upcast()));
        }
        Ok(out)
    }

    /// Живая сверка входа (гейт «промер, не вера»; паттерн spike `check_splice`,
    /// 4b-2a): 1) `[UNK]` = 0; 2) спец-токены конкатенации присутствуют в `ids`
    /// своими id; 3) decode сохраняет некопец-слова конкатенации (упорядоченно,
    /// непересекающимися вхождениями). Metaspace-декодер склеивает `▁(` с
    /// соседями, поэтому сравнение по словам/маркерам, а не наивный decode
    /// строки (промер 4b-2a: `decode → "([p]"`).
    fn check_splice(&self, ids: &[u32], segments: &[&str]) -> Result<(), ArbError> {
        let unk = ids.iter().filter(|&&id| id == UNK_ID).count();
        if unk > 0 {
            return Err(ArbError::Layout(format!(
                "{unk} токенов [UNK] в живом входе — контракт токенизации сломан"
            )));
        }
        let whole = join_segments(segments);
        let back = self
            .tokenizer
            .decode(ids, false)
            .map_err(|e| ArbError::Layout(format!("decode(live): {e}")))?;
        let norm = |s: &str| -> String {
            s.to_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let nb = norm(&back);
        let nw = norm(&whole);
        let wtoks: Vec<&str> = nw.split(' ').collect();
        let mut pos_scan = 0usize;
        let mut widx = 0usize;
        while widx < wtoks.len() {
            let w = wtoks[widx];
            let mid = SPECIALS.iter().find(|(n, _)| *n == w).map(|(_, id)| *id);
            let Some(mid) = mid else { break };
            let Some(rel) = ids[pos_scan..].iter().position(|&x| x == mid) else {
                return Err(ArbError::Layout(format!(
                    "спец-токен {w} потерян в id-последовательности (скан с {pos_scan})"
                )));
            };
            pos_scan += rel + 1;
            widx += 1;
        }
        let mut cursor = 0usize;
        for w in &wtoks[widx..] {
            if w.is_empty() {
                continue;
            }
            let Some(rel) = nb[cursor..].find(w) else {
                return Err(ArbError::Layout(format!(
                    "decode живого входа потерял слово {w:?} после смещения {cursor}"
                )));
            };
            cursor += rel + w.len();
        }
        Ok(())
    }
}

/// Склейка сегментов одним пробелом (контракт конкатенации spike 4b-2a).
#[must_use]
pub fn join_segments(segments: &[&str]) -> String {
    segments.join(" ")
}

/// `marker_positions` из групп — флэт ВСЕХ маркеров каждой группы + числа
/// маркеров в группе (offset-карта логит-слайсов).
///
/// Смысл аргумента решает, что попадает во флэт: арбитра зовёт
/// [`decide::groups`] с маркерной парой `[L],[L]`, поэтому группа = позиции
/// `[L]` меток, `[P]` в неё не входит, и флэт = ровно контракт
/// `conversion/verify_parity.py` L34–37 («флэт всех `[L]`, `[P]` дропается») —
/// тот же список, что подаёт spike `--arb` (4b-2a: `pairs=6` при трёх схемах
/// по две метки). Если группы построены с парой `[P],[L]` (первый элемент =
/// `[P]`, как в тесте `decide.rs`), дроп делает [`drop_first`] — ответственность
/// вызывающего, двойной правды нет.
#[must_use]
pub fn marker_positions(groups: &[(usize, Vec<usize>)]) -> (Vec<i64>, Vec<usize>) {
    let mut flat = Vec::new();
    let mut sizes = Vec::with_capacity(groups.len());
    for (_, ps) in groups {
        sizes.push(ps.len());
        flat.extend(
            ps.iter()
                .copied()
                .map(|p| i64::try_from(p).unwrap_or(i64::MAX)),
        );
    }
    (flat, sizes)
}

/// Дроп первого маркера каждой группы (`[P]` при маркерной паре `[P],[L]`):
/// логита у него нет — `verify_parity` L34–37 подаёт только `[L]`. Пустые
/// группы отбрасываются (контракт `decide::groups` 4b-0: пустых не бывает).
#[must_use]
pub fn drop_first(groups: &[(usize, Vec<usize>)]) -> Vec<(usize, Vec<usize>)> {
    groups
        .iter()
        .map(|(k, ps)| (*k, ps.iter().copied().skip(1).collect::<Vec<_>>()))
        .filter(|(_, ps)| !ps.is_empty())
        .collect()
}

/// План из живых id + групп + схемы: `marker_positions` (`[L]`-only),
/// `group_sizes`, вопросы/метки по порядку групп, плюс OOB-вето §5.3 и
/// сверка «число групп = число схем».
///
/// # Errors
///
/// [`ArbError::NoMarkers`] / [`ArbError::Layout`] / [`ArbError::MarkerOutOfRange`].
pub fn schema_plan(
    ids: &[u32],
    groups: &[(usize, Vec<usize>)],
    schema: &[QuestionSchema<'_>],
) -> Result<SchemaPlan, ArbError> {
    if groups.is_empty() {
        return Err(ArbError::NoMarkers);
    }
    if groups.len() != schema.len() {
        return Err(ArbError::Layout(format!(
            "групп {} ≠ схем {} — разметка слилась",
            groups.len(),
            schema.len()
        )));
    }
    let (markers, group_sizes) = marker_positions(groups);
    let plan = SchemaPlan {
        ids: ids.to_vec(),
        groups: groups.to_vec(),
        markers,
        group_sizes,
        questions: schema.iter().map(|(q, _)| (*q).to_string()).collect(),
        labels: schema
            .iter()
            .map(|(_, ls)| (*ls.first().unwrap_or(&"")).to_string())
            .collect(),
    };
    plan.check_markers()?;
    Ok(plan)
}

/// Вероятность первой метки («да») каждой схемы по логитам графа — ЧИСТАЯ часть
/// (тестируется на синтетике, живым прогоном сверяется spike-гейтом
/// `DUAL|maxdiff`).
///
/// `logits` — флэт выхода `(1,M)` в порядке `marker_positions` (`[L]`-позиции,
/// `[P]` в них не входит); слайс группы `i` = `[sum(sizes[..i]), +sizes[i])`.
#[must_use]
pub fn decide_probs(logits: &[f32], group_sizes: &[usize]) -> Vec<f64> {
    let mut out = Vec::with_capacity(group_sizes.len());
    let mut off = 0usize;
    for &n in group_sizes {
        if n == 0 {
            out.push(0.0);
            continue;
        }
        let hi = (off + n).min(logits.len());
        let probs = softmax(&logits[off..hi]);
        off = hi;
        out.push(probs.first().copied().unwrap_or(0.0));
    }
    out
}

/// Вердикты плана по логитам: [`decide_probs`] + первая метка + порог.
#[must_use]
pub fn decisions(plan: &SchemaPlan, logits: &[f32], threshold: f32) -> Vec<QuestionDecision> {
    let probs = decide_probs(logits, &plan.group_sizes);
    plan.questions
        .iter()
        .zip(&plan.labels)
        .zip(&probs)
        .map(|((q, l), &p)| {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "вероятность ∈ [0,1] — f32 точен"
            )]
            let prob = p as f32;
            QuestionDecision {
                question: q.clone(),
                label: l.clone(),
                prob,
                hit: prob >= threshold,
            }
        })
        .collect()
}

/// Softmax по логитам ОДНОЙ схемы (контракт «softmax within each question's
/// markers»). Аккумулятор f64 — побитово та же арифметика, что инлайн-контур
/// spike `--arb`, иначе `DUAL|maxdiff` мерил разницу арифметик, а не контракта.
#[must_use]
pub fn softmax(xs: &[f32]) -> Vec<f64> {
    let max = xs.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f64> = xs.iter().map(|&x| f64::from(x - max).exp()).collect();
    let sum: f64 = exps.iter().sum();
    if sum == 0.0 || !sum.is_finite() {
        return exps;
    }
    exps.iter().map(|e| e / sum).collect()
}

// Тесты ЧИСТОЙ логики (softmax / партиция групп / порог): живого графа не
// требуют — ort-вызовов в этих функциях нет, модуль за фичей лишь потому, что
// тип-владелец держит сессию. `#[ignore]` нет: гоняются `just test` при
// включённой фиче (`cargo test -p guard-onnx --features ort-inference`).
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "тест: паника = канал ответа"
)]
mod tests {
    use super::*;

    /// Синтетика живой формы C (промер токенизатором 4b-2c):
    /// `( [P] q ( [L] a [L] b ) ) [SEP_STRUCT] ( [P] q2 ( [L] c ) ) [SEP_TEXT] x`
    /// — 10 id, `[L]` на 1, 3 и 6. Маркерная пара `[L],[L]` (= как зовёт арбитра)
    /// даёт группы = позиции `[L]`: `[1,3]` и `[6]`, `[P]` в группу не входит.
    fn fake_groups() -> Vec<(usize, Vec<usize>)> {
        let ids = [
            128_003u32, 128_007, 2, 128_007, 5, 128_001, 128_007, 8, 128_002, 42,
        ];
        decide::groups(&ids, [128_007, 128_007])
    }

    /// План двух групп (2 метки + 1 метка) на синтетике [`fake_groups`] — чистые
    /// тесты `decisions`/порога/вырождений без графа.
    fn two_group_plan() -> SchemaPlan {
        let schema: [QuestionSchema<'_>; 2] = [("q1?", &["yes", "no"][..]), ("q2?", &["yes"][..])];
        schema_plan(&[7u32; 10], &fake_groups(), &schema).unwrap()
    }

    #[test]
    fn marker_positions_flat_matches_live_contract() {
        let g = fake_groups();
        assert_eq!(g.len(), 2, "две схемы");
        assert_eq!(g[0].1, vec![1, 3], "группа 1 = позиции [L]");
        let (flat, sizes) = marker_positions(&g);
        assert_eq!(sizes, vec![2, 1], "по одному маркеру на метку");
        assert_eq!(
            flat,
            vec![1, 3, 6],
            "флэт = все [L] по порядку = контракт verify_parity и spike --arb (pairs=6)"
        );
    }

    #[test]
    fn drop_first_drops_p_and_keeps_group_order() {
        // Маркерная пара [P],[L] (как в `decide.rs::tests`): тогда [P] первым в
        // группе, и его обязан дропать вызывающий — для этого [`drop_first`].
        let with_p = vec![(0usize, vec![0usize, 2, 5]), (6usize, vec![6usize, 9])];
        let d = drop_first(&with_p);
        assert_eq!(d, vec![(0usize, vec![2usize, 5]), (6usize, vec![9])]);
        let (flat, sizes) = marker_positions(&d);
        assert_eq!(flat, vec![2, 5, 9], "[L]-флэт без [P]");
        assert_eq!(sizes, vec![2, 1]);
        assert!(
            drop_first(&[(0, vec![0])]).is_empty(),
            "группа из одного [P] пуста после дропа"
        );
    }

    #[test]
    fn decide_probs_partition_by_group_sizes() {
        // Логиты двух групп: [3.0, 0.0] и [-1.0, 1.0]. Слайс группы i =
        // [sum(sizes[..i]), +sizes[i]) — группа 2 НЕ видит логитов группы 1.
        let logits = [3.0f32, 0.0, -1.0, 1.0];
        let sizes = [2usize, 2];
        debug_assert_eq!(sizes.iter().sum::<usize>(), logits.len());
        let p = decide_probs(&logits, &sizes);
        assert_eq!(p.len(), 2);
        let expect_g0 = softmax(&logits[0..2])[0];
        let expect_g1 = softmax(&logits[2..4])[0];
        assert!((p[0] - expect_g0).abs() < 1e-12, "слайс 0");
        assert!((p[1] - expect_g1).abs() < 1e-12, "слайс 1");
        assert!(
            p[0] > 0.9 && p[1] < 0.2,
            "монотонность: больший логит → больший P"
        );
    }

    #[test]
    fn softmax_monotonic_and_shift_invariant() {
        let a = softmax(&[0.0f32, 1.0]);
        let b = softmax(&[10.0f32, 11.0]);
        assert!(a[1] > a[0] && b[1] > b[0], "монотонность по логиту");
        for (x, y) in a.iter().zip(&b) {
            assert!((x - y).abs() < 1e-12, "сдвиг не меняет softmax: {x} vs {y}");
        }
        let s: f64 = a.iter().sum();
        assert!((s - 1.0).abs() < 1e-12, "сумма = 1");
    }

    #[test]
    fn softmax_deterministic_bitwise() {
        let xs = [1.5f32, -2.25, 0.125, 7.0, -0.5];
        let a = softmax(&xs);
        let b = softmax(&xs);
        assert_eq!(a, b, "побитовый детерминизм (q4f16-гейт ревью #32)");
    }

    #[test]
    fn softmax_degenerate_matches_spike_bitwise() {
        // Все -inf: `x - max` = NEG_INFINITY - NEG_INFINITY = NaN (промер),
        // exps = [NaN, NaN]. Возвращаем их КАК ЕСТЬ — побитово то же, что
        // инлайн-контур spike `--arb` (DUAL-гейт меряет эквивалентность
        // контракта, а не нашу догладку; «починить» NaN = разойтись со spike).
        // Вырождение недостижимо на живых q4f16-логитах (промер: конечно).
        let v = softmax(&[f32::NEG_INFINITY, f32::NEG_INFINITY]);
        assert_eq!(v.len(), 2);
        // Все NaN (spike-эквивалентно), значит ни одна метка не «победила»
        // (вырождение ≠ вердикт); `is_nan` вместо `!= 1.0` — NaN не равен
        // ничему, clippy::float_cmp.
        assert!(
            v.iter().all(|x| x.is_nan()),
            "spike-эквивалентный NaN: {v:?}"
        );
        // Экстремальные, но КОНЕЧНЫЕ логиты — путь живой модели: сдвиг на
        // `max` даёт exp(0)=1 для равных логитов ⇒ P = 1/n (не 0), без NaN.
        let w = softmax(&[-1e30, -1e30]);
        assert!(
            w.iter().all(|x| x.is_finite()),
            "конечный вход → конечный вывод"
        );
        assert_eq!(w, vec![0.5, 0.5], "равные логиты = равные вероятности");
        // Вырождение (все логиты равны) НЕ даёт ложного «да»: P = 1/n, при
        // пороге выше 1/n hit = false = fail-closed.
        assert!(!decisions(&two_group_plan(), &[7.0; 3], 0.5001)[0].hit);
    }

    #[test]
    fn empty_group_never_becomes_prob_one() {
        // n = 0 (группа без [L]) → вероятность 0.0, НЕ 1.0: пустые группы не
        // выдаются, но защита обязана быть (контракт 4b-0).
        let p = decide_probs(&[9.0], &[0]);
        assert_eq!(p, vec![0.0]);
    }

    #[test]
    fn threshold_is_inclusive_on_boundary() {
        // Ровно на границе hit=true (строго `>=`), ниже — false.
        let groups = drop_first(&[(0usize, vec![0usize, 2, 5])]);
        let (markers, sizes) = marker_positions(&groups);
        assert_eq!(sizes, vec![2], "группа из двух [L] после дропа [P]");
        let plan = SchemaPlan {
            ids: vec![128_003, 128_007, 2, 128_007, 5, 128_007],
            groups,
            markers,
            group_sizes: sizes,
            questions: vec!["q?".to_string()],
            labels: vec!["yes".to_string()],
        };
        let logits = [0.0f32, 0.0]; // softmax = 0.5/0.5
        let p = decide_probs(&logits, &plan.group_sizes)[0];
        #[allow(
            clippy::cast_possible_truncation,
            reason = "тест порога: вероятность ∈ [0,1], f32-truncation не меняет сравнение"
        )]
        let pf = p as f32;
        let on = decisions(&plan, &logits, pf);
        assert!(on[0].hit, "порог включительно: {p}");
        let off = decisions(&plan, &logits, pf + 0.001);
        assert!(!off[0].hit, "чуть выше порога — мимо");
        assert_eq!(off[0].label, "yes", "метка = первая в группе");
    }

    #[test]
    fn schema_block_matches_spike_reference_shape() {
        // Эталон формы = spike arb_live_layout (4b-2a): пробелы, скобки и
        // разделители побайтно. Три схемы person/tin/card по 2 метки.
        let schema: [QuestionSchema<'_>; 3] = [
            ("Is there a full name of a person ?", &["person", "no"][..]),
            ("Is there a tax identification number ?", &["tin", "no"][..]),
            ("Is there a bank card number ?", &["card", "no"][..]),
        ];
        let got = DecideArbiter::schema_block(&schema).unwrap();
        let want = "( [P] Is there a full name of a person ? ( [L] person [L] no ) ) \
                    [SEP_STRUCT] ( [P] Is there a tax identification number ? \
                    ( [L] tin [L] no ) ) [SEP_STRUCT] ( [P] Is there a bank card number ? \
                    ( [L] card [L] no ) ) [SEP_TEXT]";
        assert_eq!(got, want, "констрэкт обязан совпасть с эталоном spike");
        // NB: spike-литерал 4b-2a (`arb_live_layout`) держит ОДНУ лишнюю
        // закрывающую скобку перед [SEP_TEXT] — промер живым токенизатором
        // без RU-контекста, 3 схемы: 55 токенов против 56 у строгого баланса, при
        // ОДИНАКОВЫХ группах sizes=[2,2,2]. Скобка не контрактна: `decide::groups`
        // режет группу по [SEP_STRUCT]/[SEP_TEXT], а не по скобкам, поэтому
        // `marker_positions` и логит-слайсы от неё не зависят. Здесь — строгий
        // баланс по формулировке ТЗ `( [P] {вопрос} ( [L] {метка} … ) )`.
    }

    #[test]
    fn empty_label_list_is_rejected() {
        let empty: [&str; 0] = [];
        let r = DecideArbiter::schema_block(&[("q?", &empty[..])]);
        assert!(
            matches!(r, Err(ArbError::EmptySchema(_))),
            "нет меток = нет маркеров: {r:?}"
        );
    }

    #[test]
    fn oob_marker_is_error_not_panic() {
        // §5.3: индекс ≥ L ⇒ ArbError::MarkerOutOfRange (не паника, не прогон).
        // Группа = одна [L]-позиция 4 при L = 4 (валидные индексы 0..4).
        let groups = vec![(4usize, vec![4usize])];
        let (markers, sizes) = marker_positions(&groups);
        let plan = SchemaPlan {
            ids: vec![1u32; 4],
            groups,
            markers,
            group_sizes: sizes,
            questions: vec!["q".to_string()],
            labels: vec!["yes".to_string()],
        };
        let e = plan.check_markers().unwrap_err();
        assert!(
            matches!(e, ArbError::MarkerOutOfRange { pos: 4, len: 4 }),
            "{e:?}"
        );
    }

    #[test]
    fn schema_plan_requires_group_per_schema() {
        let groups = fake_groups();
        let one: [QuestionSchema<'_>; 1] = [("q?", &["a"][..])];
        let r = schema_plan(&[1u32; 8], &groups, &one);
        assert!(
            matches!(r, Err(ArbError::Layout(_))),
            "2 группы ≠ 1 схема: {r:?}"
        );
        let r0 = schema_plan(&[1u32; 8], &[], &one);
        assert!(matches!(r0, Err(ArbError::NoMarkers)), "пусто = {r0:?}");
    }

    #[test]
    fn join_segments_is_single_space_concat() {
        assert_eq!(join_segments(&["a", "b", "c"]), "a b c");
        assert_eq!(join_segments(&["only"]), "only");
    }
}
