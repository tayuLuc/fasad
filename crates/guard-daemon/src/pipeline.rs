//! Конвейер `/v1/analyze`: политика → каскад 0 → аннотированные спаны.
//!
//! Отвязка от HTTP сознательная: здесь нет ни `axum`, ни заголовков, поэтому
//! логика вердиктов тестируется без сокета, а атом D (middleware) переиспользует
//! [`Policy::parse`] и [`analyze`], не переписывая их.
//!
//! # Каскады в трубе (шаг 9A, issue #14A)
//!
//! На шаге 6 здесь работал только каскад 0, и это была правда: у `guard-onnx`
//! не было библиотечного интерфейса к lockR, и `X-Guard-Stage` честно говорил
//! `cascade-0-only`. С шага 9A при заданном `FASAD_MODEL_DIR` конвейер зовёт
//! каскад 1 (`guard_onnx::extract::LockrExtractor`) и — только для серой зоны
//! контекстно-зависимых классов — каскад 2 (`DecideArbiter`), см.
//! [`crate::cascades`].
//!
//! Три инварианта, которые держит этот файл:
//!
//! 1. **Fail-closed.** Сбой модельного пути = `AnalyzeError::Cascade` = 502,
//!    запрос наружу не уходит. Молчаливого «ну ладно, посчитаем каскадом 0»
//!    при примонтированных весах не существует.
//! 2. **Вето чексуммы.** Скор детерминированного валидатора = 1.0, и модель
//!    не понижает его и не перескоривает арбитражем (SPEC §2, AGENTS);
//!    пересечения модельных и детерминированных спанов снимает
//!    [`crate::cascades::merge_disjoint`] (SPEC §2 каскад 3).
//! 3. **Один код с харнесом.** Порог — `RoutingCfg` из `guard-onnx`, декод —
//!    `LockrExtractor` из `guard-onnx`: то, чем меряют recall, и то, что
//!    обслуживает запрос, — одна функция (инвариант 7b «меряем = гоняем»).
//!
//! Гейт #14 (recall ≥ 98 % по нижнему Wilson) по-прежнему мерится харнесом на
//! golden-наборе; продукт обязан совпасть с ним по составу каскадов — за это
//! отвечает тест парности `tests/cascade_parity.rs`.

use std::time::Instant;

use guard_onnx::routing::{Route, RoutingCfg, ScoredSpan, route_spans};
use guard_types::{
    AnnotatedSpan, ByteSpan, ClassId, DetectionSource, EntityRole, NewtypeId, ScoreError, Verdict,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cascade0;
use crate::cascades::{self, Cascade12, CascadeFailure, Plan};
use crate::config::Config;
use crate::schema::Schema;
use guard_detectors::checksums;

/// Политика ответа на найденное (SPEC §8, заголовок `X-Guard-Policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Маскировать (`MaskSurrogate` по умолчанию для чексумм).
    Mask,
    /// Не выпускать запрос целиком (`BlockRequest`).
    Block,
    /// Только считать и показать: спаны помечаются `KeepPublic`.
    AuditOnly,
}

impl Policy {
    /// Разбор заголовка. Неизвестное значение — ошибка, а не «замолчим в mask»:
    /// оператор, написавший `blockl`, рассчитывал на блокировку.
    ///
    /// # Errors
    ///
    /// [`AnalyzeError::UnknownPolicy`] на любом значении вне `mask|block|audit_only`.
    pub fn parse(raw: &str) -> Result<Self, AnalyzeError> {
        match raw.trim() {
            "mask" => Ok(Self::Mask),
            "block" => Ok(Self::Block),
            "audit_only" => Ok(Self::AuditOnly),
            other => Err(AnalyzeError::UnknownPolicy(other.to_owned())),
        }
    }

    /// Вердикат, который политика выдаёт на подтверждённом спане.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match self {
            Self::Mask => Verdict::MaskSurrogate,
            Self::Block => Verdict::BlockRequest,
            Self::AuditOnly => Verdict::KeepPublic,
        }
    }

    /// Имя для заголовков/JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::Block => "block",
            Self::AuditOnly => "audit_only",
        }
    }
}

/// Причина отвергнуть запрос на разборе.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalyzeError {
    /// Значение `X-Guard-Policy` вне алфавита.
    UnknownPolicy(String),
    /// Фильтр `entities` назвал класс, которого нет в схеме.
    UnknownEntity(String),
    /// Порог не конечен или вне `[0, 1]`.
    BadThreshold(f64),
    /// Скор не прошёл контракт `AnnotatedSpan::new` (AGENTS: вето = ровно 1.0).
    Score(ScoreError),
    /// Сбой модельного каскада (1–2) при примонтированных весах: запрос наружу
    /// не выпускается. Единственный вариант перечисления, который становится
    /// **5xx**: это не отвергнутый запрос клиента, а отказ конвейера
    /// (AGENTS, Fail-Closed), и код для него — 502 `cascade_unavailable`
    /// (`http::ApiError::from_analysis`).
    Cascade(CascadeFailure),
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPolicy(p) => {
                write!(
                    f,
                    "X-Guard-Policy: неизвестное значение {p:?} (mask|block|audit_only)"
                )
            }
            Self::UnknownEntity(e) => write!(f, "entities: класса {e:?} в схеме нет"),
            Self::BadThreshold(t) => write!(f, "score_threshold {t} вне [0, 1]"),
            Self::Score(e) => write!(f, "скор не прошёл контракт спана: {e:?}"),
            Self::Cascade(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

/// Сбой модельного каскада — отказ конвейера, а не отвергнутый запрос
/// клиента, поэтому у него свой вариант, а не «подмешаем в `Score`».
impl From<CascadeFailure> for AnalyzeError {
    fn from(e: CascadeFailure) -> Self {
        Self::Cascade(e)
    }
}

/// Тело запроса `/v1/analyze` (Президио-совместимое подмножество).
#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzeRequest {
    /// Текст для анализа. `Zeroizing`: вход запроса — это потенциальные `ПДн`,
    /// и обнулять при освобождении он обязан так же, как буферы в хранилище
    /// (AGENTS «все буферы с оригиналами `ПДн`»); заодно `Debug` печатает
    /// `[REDACTED]`, поэтому текст не утекает в лог через отладочную печать.
    pub text: Zeroizing<String>,
    /// Фильтр классов (Presidio `entities`); `None` = все классы схемы.
    #[serde(default)]
    pub entities: Option<Vec<String>>,
    /// Преселективный порог: может только **поднять** планку ниже config-`τ_low`
    /// не опустится (клиент не вправе ослаблять политику сервера).
    #[serde(default)]
    pub score_threshold: Option<f64>,
}

/// Один спан в ответе `/v1/analyze`.
///
/// Поля `entity_type`/`start`/`end`/`score` — имена и семантика Presidio
/// Analyzer (`RecognizerResult`); `start`/`end` в **символах**, как в первичке
/// (`docs/dep-verify-repos.md` п.1–2 п.4: «offsets символьные»). Байтовые
/// координаты — наши поля `byte_start`/`byte_end`: они однозначны и при
/// суррогатных парах, и после нормализации, поэтому внутренний контракт
/// живёт в байтах (`guard-types::span`, SPEC §8).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AnalyzedSpan {
    /// Presidio-имя класса (= `class`, дублируется осознанно: клиенты читают
    /// `entity_type`, наши потребители — `class`).
    pub entity_type: String,
    /// Символьный offset начала.
    pub start: usize,
    /// Символьный offset конца (исключительно).
    pub end: usize,
    /// Итоговый скор `S` (SPEC §2 каскад 2).
    pub score: f64,
    /// Класс схемы.
    pub class: String,
    /// Байтовый offset начала.
    pub byte_start: usize,
    /// Байтовый offset конца.
    pub byte_end: usize,
    /// Роль сущности; на шаге 6 всегда `null` (SPEC §14 — шаг 8).
    pub role: Option<EntityRole>,
    /// Кто нашёл.
    pub source: DetectionSource,
    /// Вердикт политики.
    pub verdict: Verdict,
    /// Имя подтвердившего валидатора (`null` у немодельных источников позже).
    pub validator: Option<&'static str>,
}

impl AnalyzedSpan {
    /// Из контрактованного [`AnnotatedSpan`] + имени валидатора.
    fn from_annotated(a: &AnnotatedSpan, validator: Option<&'static str>) -> Self {
        Self {
            entity_type: a.class.as_str().to_owned(),
            start: a.span.char_start,
            end: a.span.char_end,
            score: a.score,
            class: a.class.as_str().to_owned(),
            byte_start: a.span.start,
            byte_end: a.span.end,
            role: a.role.clone(),
            source: a.source,
            verdict: a.verdict,
            validator,
        }
    }
}

/// Результат анализа с метаданными для заголовков `X-Guard-*`.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// Спаны.
    pub spans: Vec<AnalyzedSpan>,
    /// Максимальный риск по спанам = максимум скора (0, если спанов нет).
    pub max_risk: f64,
    /// Полим секунд на разбор.
    pub latency_ms: u128,
    /// Какой каскад реально работал.
    pub stage: &'static str,
    /// Что сделал каскад 2 на ЭТОМ запросе (`X-Guard-Cascade2`): `absent` без
    /// весов, `ok` штатно, `skipped` — лег был нужен и пропущен
    /// (`cascades::decide_degrades`). Stage про монтаж, этот сигнал про вердикты.
    pub cascade2: &'static str,
    /// Эффективный порог, с которым считали (эхо в заголовке — чтобы клиент не
    /// гадал, что он сам попросил).
    pub threshold: f64,
    /// Политика запроса.
    pub policy: Policy,
}

/// Интервал склейки модельных обрывков, байт (#200-A1).
///
/// Первичка соседства: `GLiNER` режет номера НА ТОКЕНАХ (issue #200:
/// «4508 455561» = «450»+«455», «+79161234567» = «79»), разрыв между
/// обрывками = разделитель(и) печатной формы. 8 байт = форма «4508  455561»
/// с запасом; больший интервал = два разных числа (клей широкого окна =
/// авто-слияние произвольных соседних `ПДн`, SPEC §2 это запрещает).
pub const GLUE_MAX_GAP: usize = 8;

/// Классы-кандидаты склейки: только числовые формы, чьё структурное вето
/// есть у каскада-0. `person_name`/`address` склеивать нельзя: вето на них нет,
/// а клей без вето = авто-слияние (issue #209 п.A(a) — «решение за
/// валидатором», валидатора нет = решения нет).
const GLUE_CLASSES: [&str; 2] = ["passport", "phone"];

/// Байты, которыми допустимо разрывать склеиваемый номер: разделители
/// печатной формы + каркас телефона (скобки, плюс).
fn glue_gap_ok(gap: &[u8]) -> bool {
    !gap.is_empty()
        && gap.iter().all(|&x| {
            matches!(x, b' ' | b'-' | b'(' | b')' | b'+' | b'.')
                || checksums::NUMBER_SEPARATORS
                    .iter()
                    .any(|sp| gap.len() >= sp.len() && x == sp[0])
        })
}

/// Кандидат-клей соседних одноимённых модельных спанов (#200-A1).
///
/// Слой стоит ДО [`cascades::merge_disjoint`] и инварианты SPEC §2 каскада 3
/// не трогает: merger видит победителя вето (veto=true, 1.0) и обычных
/// модельных; «1.0 не понижается» для склейки = закон для вето, склейка его
/// подтвердила — вето-контуром каскада-0 ([`crate::cascade0::structured_confirms`]),
/// тем же, что светит детерминированные хиты.
///
/// Алгоритм (детерминированный, один проход по парам отсортированных спанов):
///
/// 1. спаны класса из [`GLUE_CLASSES`] сортируются по `(start, end)`;
/// 2. соседние пара/цепочка с разрывом `(0, GLUE_MAX_GAP]` из допустимых
///    байт ([`glue_gap_ok`]) образуют кандидата `start..end`;
/// 3. вето подтверждает — в выход идёт ОДИН `ModelSpan` с координатами
///    склейки, `score = 1.0`, `source = ChecksumRf` (вето: в общий список
///    он попадёт как детерминированный, `merge_disjoint` не понижает);
///    не подтверждает — обрывки живут как жили, скоры модели сохранены.
fn glue_model_spans(
    text: &str,
    spans: Vec<cascades::ModelSpan>,
    schema: &Schema,
) -> Vec<cascades::ModelSpan> {
    let bytes = text.as_bytes();
    let declared = |cls: &str| !schema.validators_for(cls).is_empty();
    let mut out: Vec<cascades::ModelSpan> = Vec::with_capacity(spans.len());
    // Сортировка по началу: склейка = склейка соседних; порядок выхода —
    // порядок начала (merger входной порядок не читает, детерминизм).
    let mut sorted = spans;
    sorted.sort_by_key(|s| (s.byte_start, s.byte_end));
    let mut i = 0usize;
    while i < sorted.len() {
        let s = sorted[i].clone();
        if !GLUE_CLASSES.contains(&s.class.as_str()) || !declared(&s.class) {
            out.push(s);
            i += 1;
            continue;
        }
        // Цепочка обрывков одного класса: j = конец цепочки.
        let mut j = i;
        let mut last_end = s.byte_end;
        while j + 1 < sorted.len()
            && sorted[j + 1].class == s.class
            && sorted[j + 1].byte_start > last_end
            && sorted[j + 1].byte_start - last_end <= GLUE_MAX_GAP
            && glue_gap_ok(
                bytes
                    .get(last_end..sorted[j + 1].byte_start)
                    .unwrap_or(b"\x00"),
            )
        {
            last_end = sorted[j + 1].byte_end;
            j += 1;
        }
        if j == i {
            out.push(s);
            i += 1;
            continue;
        }
        let Some(slice) = text.get(s.byte_start..last_end) else {
            out.extend(sorted[i..=j].iter().cloned());
            i = j + 1;
            continue;
        };
        if crate::cascade0::structured_confirms(slice, &s.class) {
            // Победа вето: спан 1.0 с целыми границами (ветка детерминированного
            // источника в `Cand::veto`/`merge_disjoint` уже есть — скор = вес).
            let best = sorted[i..=j]
                .iter()
                .map(|x| x.score)
                .fold(0.0_f64, f64::max);
            out.push(cascades::ModelSpan {
                byte_start: s.byte_start,
                byte_end: last_end,
                class: s.class.clone(),
                score: DetectionSource::ChecksumRf
                    .deterministic_weight()
                    .unwrap_or(1.0),
                p1: best,
                source: DetectionSource::ChecksumRf,
            });
        } else {
            out.extend(sorted[i..=j].iter().cloned());
        }
        i = j + 1;
    }
    out
}

/// Каскады 1–2 внутри конвейера: запрос в модельный путь, спаны — в общий
/// список кандидатов, пересечения с каскадом 0 сняты (SPEC §2 каскад 3).
///
/// Отказ модельного пути возвращается ошибкой, а НЕ пустым списком: пустой
/// ответ при примонтированных весах означает «`ПДн` не нашли» — это fail-open.
fn model_mount(
    req: &AnalyzeRequest,
    schema: &Schema,
    cfg: &Config,
    threshold: f64,
    mount: &dyn Cascade12,
    cands: &mut Vec<Cand>,
) -> Result<cascades::Cascade2, AnalyzeError> {
    let plan = Plan::from_config(cfg, threshold);
    let out = mount.model_spans(&req.text, schema, &plan)?;
    // Кандидат-клей #200-A1: соседние одноимённые числовые обрывки модели
    // склеиваются в КАНДИДАТА, который уходит в вето-контур каскада-0;
    // победивший валидатор = спан 1.0 с целыми границами, проигравший =
    // исходные модельные спаны живут как жили (авто-слияния нет).
    let model = glue_model_spans(&req.text, out.spans, schema);
    for m in model {
        // Координата вне границы символа = сломанный декод модели: сдвигать её
        // «на глаз» нельзя (маскирование встанет не на то место), значит это
        // отказ конвейера, а не отфильтрованный кандидат.
        let span = ByteSpan::new(&req.text, m.byte_start, m.byte_end).map_err(|e| {
            AnalyzeError::Cascade(CascadeFailure::Inference(format!(
                "каскад 1 вернул координату {}..{} вне границы символа: {e:?}",
                m.byte_start, m.byte_end
            )))
        })?;
        cands.push(Cand {
            span,
            class: ClassId::from_id(m.class),
            score: m.score,
            source: m.source,
            // У модельного спана нет детерминированного валидатора:
            // `validator: null` в ответе клиента честно читается как
            // «гипотеза модели, чексуммой не подтверждена».
            validator: None,
            veto: m.source.deterministic_weight().is_some(),
        });
    }
    // Слияние каскада 0 с модельным выходом: вето чексуммы не понижается и не
    // дублируется, модельные пересечения снимаются leftmost-longest.
    let tuples: Vec<(usize, usize, f64, bool)> = cands
        .iter()
        .map(|c| (c.span.start, c.span.end, c.score, c.veto))
        .collect();
    let mut kept = vec![false; cands.len()];
    for i in cascades::merge_disjoint(&tuples) {
        kept[i] = true;
    }
    *cands = std::mem::take(cands)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| kept[*i])
        .map(|(_, c)| c)
        .collect();
    Ok(out.cascade2)
}

/// Кандидат на выход конвейера: один спан с классом, скором и авторством.
///
/// Живёт внутри [`analyze_with`]: нужен слой между «детектор сказал» и
/// «контрактный [`AnnotatedSpan`]», потому что между ними стоят слияние
/// пересечений (SPEC §2 каскад 3) и пороговый гейт, и оба смотрят на весь
/// набор сразу, а не на спан по одному.
#[derive(Debug)]
struct Cand {
    span: ByteSpan,
    class: ClassId,
    score: f64,
    source: DetectionSource,
    validator: Option<&'static str>,
    /// Детерминированное вето (чексумма): скор = 1.0, модель его не понижает.
    veto: bool,
}

/// Разобрать текст конвейером: каскад 0 + примонтированные каскады 1–2.
///
/// # Errors
///
/// [`AnalyzeError::UnknownPolicy`], [`AnalyzeError::UnknownEntity`],
/// [`AnalyzeError::BadThreshold`] и [`AnalyzeError::Score`] — это отвергнутый
/// запрос/внутренний контракт (4xx/500); [`AnalyzeError::Cascade`] — отказ
/// модельного пути, и он answering 502: запрос наружу не уходит (fail-closed).
pub fn analyze(
    req: &AnalyzeRequest,
    schema: &Schema,
    cfg: &Config,
    policy: Policy,
) -> Result<Analysis, AnalyzeError> {
    analyze_with(req, schema, cfg, policy, cascades::engine().as_deref())
}

/// [`analyze`] с внедрённым модельным путём.
///
/// Отдельная сигнатура — не «для красоты», а чтобы стад-машина конвейера
/// тестировалась без весов: `mount: Some(&фейк)` прогоняет ветки «каскад 1
/// дал спаны», «каскад 2 перескорил», «каскад упал → 502» в CI обеих ОС, где
/// весов нет и не будет. Прод-путь приходит через [`analyze`] и читает
/// глобальный mount, поднятый на старте ([`crate::cascades::startup`]).
///
/// # Errors
///
/// См. [`analyze`].
pub fn analyze_with(
    req: &AnalyzeRequest,
    schema: &Schema,
    cfg: &Config,
    policy: Policy,
    mount: Option<&dyn Cascade12>,
) -> Result<Analysis, AnalyzeError> {
    let started = Instant::now();
    let threshold = effective_threshold(req.score_threshold, cfg)?;
    let filter = req
        .entities
        .as_deref()
        .map(|want| check_entities(want, schema))
        .transpose()?;

    let hits = cascade0::scan(&req.text, schema);
    let mut cands: Vec<Cand> = hits
        .into_iter()
        .map(|h| {
            // Поля читаем до переезда `class`: `ClassId` — `String`, частичный
            // move ломает последующие заимствования хита.
            let (span, source, validator) = (h.span, h.source, h.validator);
            // #234: «каркас + форма без чексуммы» = 0.95 (константа контракта),
            // остальные детерминированные = вето 1.0 (h.score()).
            let score = if source == guard_types::DetectionSource::FrameInvalidChecksum {
                guard_types::DetectionSource::FRAME_INVALID_W
            } else {
                h.score()
            };
            Cand {
                span,
                class: h.class,
                score,
                source,
                validator: Some(validator),
                veto: source.deterministic_weight().is_some(),
            }
        })
        .collect();

    // ── каскады 1–2 (issue #14A) ────────────────────────────────────────────
    let mut stage = cfg.stage();
    let mut cascade2 = cascades::Cascade2::Absent;
    if let Some(mount) = mount {
        stage = cascades::STAGE_MOUNTED;
        cascade2 = model_mount(req, schema, cfg, threshold, mount, &mut cands)?;
    }
    // Пороговый гейт — общая функция харнеса, демона и прокси (мандат 7c,
    // law #53): локальная `passes` была промеренной копией вырожденной пары
    // `RoutingCfg::single` («score ≥ τ || вето» = `route(score).extracted()`),
    // и две реализации одного порога расходятся при первой же правке.
    let routing = RoutingCfg::single(threshold);
    // `C = &ClassId`: `ClassId` — newtype над `String`, не `Copy`, а
    // `route_spans` требует `Copy`; заимствование копируется и ничего не стоит.
    let scored: Vec<ScoredSpan<&ClassId>> = cands
        .iter()
        .map(|c| ScoredSpan {
            class: &c.class,
            score: c.score,
            validator: c.veto,
        })
        .collect();
    let routed_pairs = route_spans(&routing, &scored);
    // Порядок выхода = порядок входа, поэтому маршруты зиппятся с кандидатами
    // позиционно. Утверждение не вербальное: его проверяет
    // `routing::tests::route_spans_pairs_routes_with_input_order` в guard-onnx
    // (плюс позиционная проверка классов в `route_spans_vector_table`).
    let routes: Vec<Route> = routed_pairs.into_iter().map(|r| r.route).collect();
    drop(scored);
    let mut spans = Vec::with_capacity(cands.len());
    for (c, route) in cands.into_iter().zip(routes) {
        if !route.extracted() {
            continue;
        }
        if let Some(want) = filter.as_deref()
            && !want.iter().any(|w| *w == c.class.as_str())
        {
            continue;
        }
        // Поля читаем до конструктора: `class` — `String`, частичный переезд
        // ломает последующие заимствования кандидата.
        let score = c.score;
        let validator = c.validator;
        let span = AnnotatedSpan::new(
            c.span,
            c.class,
            // Ролей нет: SPEC §14 (CLIENT/VENDOR) — шаг 8, а выдумывать их из
            // соседних слов значит генерировать факты.
            None,
            c.source,
            score,
            policy.verdict(),
        )
        .map_err(AnalyzeError::Score)?;
        spans.push(AnalyzedSpan::from_annotated(&span, validator));
    }

    let max_risk = spans.iter().fold(0.0_f64, |m, s| m.max(s.score));
    Ok(Analysis {
        spans,
        max_risk,
        latency_ms: started.elapsed().as_millis(),
        stage,
        cascade2: cascade2.as_header(),
        threshold,
        policy,
    })
}

/// Порог с учётом того, что клиент вправе только поднять планку.
fn effective_threshold(client: Option<f64>, cfg: &Config) -> Result<f64, AnalyzeError> {
    let floor = cfg.thresholds.tau_low;
    match client {
        None => Ok(floor),
        Some(t) if !t.is_finite() || !(0.0..=1.0).contains(&t) => {
            Err(AnalyzeError::BadThreshold(t))
        }
        Some(t) => Ok(t.max(floor)),
    }
}

fn check_entities(want: &[String], schema: &Schema) -> Result<Vec<String>, AnalyzeError> {
    for w in want {
        if !schema.knows(w) {
            return Err(AnalyzeError::UnknownEntity(w.clone()));
        }
    }
    Ok(want.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
#[allow(clippy::float_cmp)] // скора в этих тестах — константы контракта (1.0/0.0/τ), не результат вычислений
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::from_lookup(|_| None).expect("дефолты sane")
    }

    fn schema() -> Schema {
        Schema::embedded().expect("канон валиден")
    }

    fn req(text: &str) -> AnalyzeRequest {
        AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: None,
            score_threshold: None,
        }
    }

    #[test]
    fn policy_alphabet_and_verdicts() {
        for (raw, p, v) in [
            ("mask", Policy::Mask, Verdict::MaskSurrogate),
            ("block", Policy::Block, Verdict::BlockRequest),
            ("audit_only", Policy::AuditOnly, Verdict::KeepPublic),
            ("  mask  ", Policy::Mask, Verdict::MaskSurrogate),
        ] {
            let parsed = Policy::parse(raw).expect("алфавит принят");
            assert_eq!(parsed, p, "{raw}");
            assert_eq!(parsed.verdict(), v, "{raw}");
            assert_eq!(parsed.as_str(), raw.trim());
        }
        // Опечатка в политике ≠ «заглушим в mask».
        assert_eq!(
            Policy::parse("blockl").unwrap_err(),
            AnalyzeError::UnknownPolicy("blockl".to_owned())
        );
        assert_eq!(
            Policy::parse("").unwrap_err(),
            AnalyzeError::UnknownPolicy(String::new())
        );
    }

    #[test]
    fn analyze_reports_inn_with_presidio_and_byte_fields() {
        // ИНН 10 из golden-v1.jsonl; «Иван» до числа — 2 символа, сам ИНН с
        // символа 14 (после «Иван » и «ИНН »).
        let text = "Иван ИНН 2482014338 оплатил";
        let a = analyze(&req(text), &schema(), &cfg(), Policy::Mask).expect("анализ проходит");
        assert_eq!(a.spans.len(), 1, "{:?}", a.spans);
        let s = &a.spans[0];
        assert_eq!(s.class, "inn");
        assert_eq!(s.entity_type, "inn");
        // Координаты сверяем вырезкой, а не по арифметике: байты кириллицы
        // по 2, и ручная арифметика в тесте — тот же класс ошибки, что и в проде.
        assert_eq!(
            text.get(s.byte_start..s.byte_end),
            Some("2482014338"),
            "байтовый спан обязан вырезаться ровно в номер"
        );
        assert_eq!(s.score, 1.0, "детерминированное вето (AGENTS)");
        assert_eq!(s.verdict, Verdict::MaskSurrogate);
        assert_eq!(s.validator, Some("inn10"));
        assert!(s.role.is_none(), "роли — шаг 8");
        assert_eq!(s.source, DetectionSource::ChecksumRf);
        // Символьные координаты отличаются от байтовых ровно там, где кириллица.
        assert_eq!(
            s.start,
            text[..s.byte_start].chars().count(),
            "start = символы, не байты"
        );
        assert_eq!(s.end - s.start, 10, "ИНН = 10 символов");
        assert_eq!(a.stage, "cascade-0-only");
        assert!(a.latency_ms < 1000, "казуистика: {a:?}");
    }

    #[test]
    fn client_cannot_lower_the_server_floor() {
        let cfg = cfg();
        let floor = cfg.thresholds.tau_low;
        let a = analyze(&req("ИНН 2482014338"), &schema(), &cfg, Policy::Mask).expect("ок");
        assert_eq!(a.threshold, floor, "без запроса = config τ_low");
        let low = AnalyzeRequest {
            text: Zeroizing::new("ИНН 2482014338".to_owned()),
            entities: None,
            score_threshold: Some(0.0),
        };
        let a = analyze(&low, &schema(), &cfg, Policy::Mask).expect("ок");
        assert_eq!(a.threshold, floor, "клиент не спустил порог");
        assert_eq!(a.spans.len(), 1, "вето порогом не снимается");
        let high = AnalyzeRequest {
            text: Zeroizing::new("ИНН 2482014338".to_owned()),
            entities: None,
            score_threshold: Some(1.0),
        };
        let a = analyze(&high, &schema(), &cfg, Policy::Mask).expect("ок");
        assert_eq!(a.threshold, 1.0, "поднять клиент может");
        assert_eq!(
            a.spans.len(),
            1,
            "но deterministic 1.0 проходит и этот порог"
        );
    }

    #[test]
    fn threshold_out_of_range_is_an_error_not_a_clamp() {
        let bad = AnalyzeRequest {
            text: Zeroizing::new("x".to_owned()),
            entities: None,
            score_threshold: Some(1.5),
        };
        assert_eq!(
            analyze(&bad, &schema(), &cfg(), Policy::Mask).unwrap_err(),
            AnalyzeError::BadThreshold(1.5)
        );
    }

    #[test]
    fn entity_filter_keeps_only_asked_classes_and_rejects_typos() {
        let text = "ИНН 2482014338, СНИЛС 65707715421";
        let only = AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: Some(vec!["snils".to_owned()]),
            score_threshold: None,
        };
        let a = analyze(&only, &schema(), &cfg(), Policy::Mask).expect("ок");
        let cl: Vec<&str> = a.spans.iter().map(|s| s.class.as_str()).collect();
        assert_eq!(cl, vec!["snils"], "фильтр не протёк");
        let typo = AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: Some(vec!["snisl".to_owned()]),
            score_threshold: None,
        };
        assert_eq!(
            analyze(&typo, &schema(), &cfg(), Policy::Mask).unwrap_err(),
            AnalyzeError::UnknownEntity("snisl".to_owned()),
            "опечатка в фильтре обязана быть слышна, а не «вернуть всё»"
        );
    }

    #[test]
    fn audit_only_reports_without_masking_verdict() {
        let a = analyze(&req("ИНН 2482014338"), &schema(), &cfg(), Policy::AuditOnly).expect("ок");
        assert_eq!(a.spans[0].verdict, Verdict::KeepPublic);
        assert_eq!(a.max_risk, 1.0, "audit_only не обнуляет риск");
    }

    #[test]
    fn block_policy_marks_every_span_and_max_risk_stays() {
        let a = analyze(
            &req("ИНН 2482014338, IBAN RU1904452522540820407677025210608"),
            &schema(),
            &cfg(),
            Policy::Block,
        )
        .expect("ок");
        assert!(a.spans.len() >= 2);
        assert!(a.spans.iter().all(|s| s.verdict == Verdict::BlockRequest));
        assert_eq!(a.max_risk, 1.0);
    }

    #[test]
    fn debug_of_request_does_not_print_the_text() {
        // AGENTS: `Debug`-вывод только `[REDACTED]`. Отладочная печать запроса —
        // самый вероятный путь, по которому `ПДн` утекают в лог, поэтому
        // проверяем именно строку `Debug`, а не тип поля.
        let r = req("ИНН 2482014338 СНИЛС 65707715421");
        let line = format!("{r:?}");
        assert!(!line.contains("2482014338"), "Debug печати текст: {line}");
        assert!(!line.contains("65707715421"), "Debug печати текст: {line}");
        assert!(
            line.contains("REDACTED") || line.contains("Zeroizing"),
            "Debug должен явно пометить скрытое: {line}"
        );
    }

    #[test]
    fn empty_text_is_a_valid_empty_analysis() {
        let a = analyze(&req(""), &schema(), &cfg(), Policy::Mask).expect("пустой текст не ошибка");
        assert_eq!(a.spans, [] as [AnalyzedSpan; 0]);
        assert_eq!(a.max_risk, 0.0);
        assert_eq!(a.stage, "cascade-0-only");
    }

    #[test]
    fn response_json_has_the_promise_fields() {
        // Контракт тела проверяем побайтово на наборе ключей: Presidio-клиенты
        // читают entity_type/start/end/score, наши — byte_*/class/verdict.
        let a = analyze(&req("ИНН 2482014338"), &schema(), &cfg(), Policy::Mask).expect("ок");
        let body = serde_json::to_value(&a.spans).expect("сериализуется");
        let obj = body
            .as_array()
            .expect("массив спанов")
            .first()
            .expect("один спан")
            .clone();
        let keys: Vec<&str> = obj
            .as_object()
            .expect("объект")
            .keys()
            .map(String::as_str)
            .collect();
        for k in [
            "entity_type",
            "start",
            "end",
            "score",
            "byte_start",
            "byte_end",
            "class",
            "source",
            "verdict",
            "role",
            "validator",
        ] {
            assert!(keys.contains(&k), "нет поля {k}: {keys:?}");
        }
        assert_eq!(obj["source"], "checksum_rf");
        assert_eq!(obj["verdict"], "mask_surrogate");
        assert_eq!(obj["role"], serde_json::Value::Null);
    }

    /// Base64-обход на проводе (PR #94, требование п.3 приёмки): поле
    /// `source` = `base64_decode`, координаты — исходный токен, вес — вето 1.0
    /// (тот же `DeterministicW`, что у чексумм: подтвердил окно валидатор).
    #[test]
    #[allow(clippy::float_cmp)] // 1.0 — константа контракта
    fn response_json_marks_base64_decoded_spans() {
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("СНИЛС 65707715421 в реестре");
        let text = format!("приложение {token} конец");
        let a = analyze(&req(&text), &schema(), &cfg(), Policy::Mask).expect("ок");
        let body = serde_json::to_value(&a.spans).expect("сериализуется");
        let obj = body
            .as_array()
            .expect("массив спанов")
            .first()
            .expect("спан есть")
            .clone();
        assert_eq!(obj["source"], "base64_decode", "{obj}");
        assert_eq!(obj["class"], "snils");
        assert_eq!(obj["validator"], "snils");
        assert_eq!(obj["score"], 1.0);
        assert_eq!(obj["verdict"], "mask_surrogate");
        // Координаты — байты токена в оригинале: декодированные наружу не
        // показываются вообще.
        let at = text.find(&token).expect("токен в тексте");
        assert_eq!(obj["byte_start"], at);
        assert_eq!(obj["byte_end"], at + token.len());
        assert_eq!(
            obj["entity_type"], "snils",
            "entity_type = класс находки (Presidio-совместимое поле)"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = канал ответа
#[allow(clippy::float_cmp)] // скора в этих тестах — константы контракта
/// Стад-машина каскадов 1–2 без весов.
///
/// Тесты гоняют `analyze_with` на фейковом [`Cascade12`]: в CI весов нет ни на
/// одной ОС, а тест, который требует весов, — это не тест, а надежда. Фейк
/// даёт ровно ту границу, которую должен проверять конвейер: «модель сказала»,
/// «модель упала», «модель сказала чушь».
mod mount_tests {
    use super::*;
    use crate::cascades::{Cascade12, CascadeFailure, ModelSpan, Plan};
    use guard_types::ByteSpan;

    /// Фейк модельного пути: отдаёт заготовленные спаны либо заготовленный
    /// отказ. `calls` — счётчик вызовов (проверяет, что без mount мы в модель
    /// не ходим и что обращение было ровно один раз на запрос).
    struct FakeMount {
        spans: Vec<ModelSpan>,
        cascade2: cascades::Cascade2,
        fail: Option<CascadeFailure>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeMount {
        fn ok(spans: Vec<ModelSpan>) -> Self {
            Self {
                spans,
                fail: None,
                cascade2: cascades::Cascade2::Ok,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        /// Тот же фейк, но лег каскада 2 объявлен пропущенным — на нём
        /// проверяется, что сигнал доезжает до `Analysis`, а не теряется.
        fn skipped(spans: Vec<ModelSpan>) -> Self {
            Self {
                spans,
                fail: None,
                cascade2: cascades::Cascade2::Skipped,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn fail(f: CascadeFailure) -> Self {
            Self {
                spans: Vec::new(),
                fail: Some(f),
                cascade2: cascades::Cascade2::Ok,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl Cascade12 for FakeMount {
        fn model_spans(
            &self,
            _text: &str,
            _schema: &Schema,
            _plan: &Plan,
        ) -> Result<cascades::Outcome, CascadeFailure> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match &self.fail {
                Some(f) => Err(f.clone()),
                None => Ok(cascades::Outcome {
                    spans: self.spans.clone(),
                    cascade2: self.cascade2,
                }),
            }
        }
    }

    fn cfg() -> Config {
        Config::from_lookup(|_| None).expect("дефолты sane")
    }

    fn schema() -> Schema {
        Schema::embedded().expect("канон валиден")
    }

    fn req(text: &str) -> AnalyzeRequest {
        AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: None,
            score_threshold: None,
        }
    }

    /// Спан каскада 1, вписанный в текст по байтовым координатам подстроки.
    fn span_of(text: &str, needle: &str, class: &str, p: f64) -> ModelSpan {
        let start = text.find(needle).expect("подстрока в тестовом тексте есть");
        ModelSpan {
            byte_start: start,
            byte_end: start + needle.len(),
            class: class.to_owned(),
            score: p,
            p1: p,
            source: DetectionSource::GlinerExtractor,
        }
    }

    const NAME_TEXT: &str = "Иванов Пётр Сергеевич звонил";

    /// Значение `stage` сверяется строкой, а не фактом «что-то поменялось»:
    /// тест-пара имён слеп к тому, что реально читает оператор в заголовке,
    /// поэтому здесь — точное значение гейт-строки (#87 review).
    #[test]
    fn skipped_cascade2_leg_is_visible_on_the_analysis() {
        let mount = FakeMount::skipped(vec![span_of(NAME_TEXT, "Иванов", "person_name", 0.55)]);
        let a = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        )
        .expect("ок");
        assert_eq!(a.stage, "cascade-0+models");
        assert_eq!(
            a.cascade2, "skipped",
            "деградация легов обязана быть видна per-request"
        );
        assert_eq!(a.spans.len(), 1, "спан при деградации не теряется");
    }

    /// Без весов сигнал = `absent`: пустая строка читалась бы как «не
    /// поддерживается», а не как «каскада 2 в процессе нет».
    #[test]
    fn unmounted_cascade2_signal_is_absent() {
        let a = analyze_with(&req(NAME_TEXT), &schema(), &cfg(), Policy::Mask, None).expect("ок");
        assert_eq!(a.cascade2, "absent");
    }

    #[test]
    fn mounted_cascade_adds_model_spans_and_relabels_stage() {
        let mount = FakeMount::ok(vec![span_of(NAME_TEXT, "Иванов", "person_name", 0.91)]);
        let a = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        )
        .expect("ок");
        assert_eq!(
            a.stage, "cascade-0+models",
            "примонтированный путь обязан называться своим именем"
        );
        assert_eq!(
            a.spans.len(),
            1,
            "только модельный спан: чексумм в тексте нет"
        );
        let s = &a.spans[0];
        assert_eq!(s.class, "person_name");
        assert_eq!(s.source, DetectionSource::GlinerExtractor);
        assert!(
            (s.score - 0.91).abs() < 1e-12,
            "скор модели не меняется конвейером"
        );
        assert!(
            s.validator.is_none(),
            "у модели нет детерминированного валидатора"
        );
        assert_eq!(
            mount.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "один запрос = один вызов модели"
        );
    }

    #[test]
    fn no_mount_means_cascade0_only_and_zero_model_calls() {
        let a = analyze(&req(NAME_TEXT), &schema(), &cfg(), Policy::Mask).expect("ок");
        assert_eq!(a.stage, "cascade-0-only");
        assert!(
            a.spans.is_empty(),
            "без каскада 1 ФИО не находится — это и есть дыра, которую закрывает #14A"
        );
    }

    #[test]
    fn cascade_failure_is_fail_closed_not_empty_answer() {
        for f in [
            CascadeFailure::Inference("орт сказал нет".to_owned()),
            CascadeFailure::Timeout {
                budget_ms: 3000,
                stage: "inference",
            },
            CascadeFailure::Truncated { window: 256 },
            CascadeFailure::Overloaded { depth: 8 },
            CascadeFailure::Dead,
        ] {
            let mount = FakeMount::fail(f.clone());
            let r = analyze_with(
                &req(NAME_TEXT),
                &schema(),
                &cfg(),
                Policy::Mask,
                Some(&mount),
            );
            assert!(
                matches!(r, Err(AnalyzeError::Cascade(_))),
                "отказ каскада {f:?} обязан быть ошибкой конвейера, получено {r:?}"
            );
        }
    }

    #[test]
    fn checksum_veto_is_not_lowered_by_model() {
        // Текст с валидным ИНН: каскад 0 даёт вето 1.0, модель пытается
        // претендовать на те же байты как на «адрес» с меньшим скором.
        let text = "ИНН 2482014338 оплата";
        let mount = FakeMount::ok(vec![span_of(text, "2482014338", "address", 0.66)]);
        let a =
            analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount)).expect("ок");
        assert_eq!(
            a.spans.len(),
            1,
            "пересечение снято слиянием, не дубликатом"
        );
        assert_eq!(a.spans[0].class, "inn", "вето чексуммы не понижается");
        assert!(
            (a.spans[0].score - 1.0).abs() < f64::EPSILON,
            "скор чексуммы = ровно 1.0, AGENTS-инвариант"
        );
        assert_eq!(a.spans[0].validator, Some("inn10"));
    }

    #[test]
    fn model_span_below_effective_threshold_is_dropped() {
        // Пороговый гейт конвейера applies к модели так же, как к харнесу:
        // фейк, нарушивший обещание `plan.tau`, не должен протащить спан.
        let mount = FakeMount::ok(vec![span_of(NAME_TEXT, "Иванов", "person_name", 0.05)]);
        let a = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        )
        .expect("ок");
        assert!(a.spans.is_empty(), "p1 < τ не выходит наружу");
    }

    #[test]
    fn client_threshold_raises_model_gate_too() {
        let mount = FakeMount::ok(vec![span_of(NAME_TEXT, "Иванов", "person_name", 0.5)]);
        let mut r = req(NAME_TEXT);
        r.score_threshold = Some(0.7);
        let a = analyze_with(&r, &schema(), &cfg(), Policy::Mask, Some(&mount)).expect("ок");
        assert!(
            a.spans.is_empty(),
            "клиент поднял планку до 0.7 — модельный спан 0.5 отброшен"
        );
        assert!((a.threshold - 0.7).abs() < 1e-12);
    }

    #[test]
    fn entities_filter_applies_to_model_spans() {
        let mount = FakeMount::ok(vec![
            span_of(NAME_TEXT, "Иванов", "person_name", 0.9),
            span_of(NAME_TEXT, "Пётр", "person_name", 0.9),
        ]);
        let mut r = req(NAME_TEXT);
        r.entities = Some(vec!["phone".to_owned()]);
        let a = analyze_with(&r, &schema(), &cfg(), Policy::AuditOnly, Some(&mount)).expect("ок");
        assert!(a.spans.is_empty(), "фильтр классов работает и по модели");
    }

    #[test]
    fn model_span_outside_char_boundary_is_refused_not_fixed() {
        // Байт внутри кириллического символа: «починить» координату нельзя,
        // маскирование встанет не на то место. Отказ конвейера = 502.
        let text = "Иванов звонил";
        let mount = FakeMount::ok(vec![ModelSpan {
            byte_start: 1,
            byte_end: 4,
            class: "person_name".to_owned(),
            score: 0.9,
            p1: 0.9,
            source: DetectionSource::GlinerExtractor,
        }]);
        let r = analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount));
        assert!(
            matches!(r, Err(AnalyzeError::Cascade(CascadeFailure::Inference(_)))),
            "битая координата модели = отказ, не тихая подрезка: {r:?}"
        );
    }

    #[test]
    fn model_score_out_of_contract_is_refused() {
        let mount = FakeMount::ok(vec![span_of(NAME_TEXT, "Иванов", "person_name", 1.7)]);
        let r = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        );
        assert!(
            matches!(r, Err(AnalyzeError::Score(_))),
            "контракт скора един для всех источников: {r:?}"
        );
    }

    #[test]
    fn arbitrated_span_is_attributed_to_cascade2() {
        let mut sp = span_of(NAME_TEXT, "Иванов", "person_name", 0.55);
        sp.score = 0.78;
        sp.source = DetectionSource::GlinerDecideArbitrator;
        let mount = FakeMount::ok(vec![sp]);
        let a = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        )
        .expect("ок");
        assert_eq!(a.spans[0].source, DetectionSource::GlinerDecideArbitrator);
        assert_eq!(a.spans[0].entity_type, "person_name");
    }

    #[test]
    fn merged_output_has_no_overlapping_spans() {
        // Инвариант «разбиение», нужный маскированию: два модельных перекрывающихся
        // спана (ФИО + фамилия) не выходят наружу пересечёнными.
        let text = "Иванов Пётр Сергеевич звонил";
        let mount = FakeMount::ok(vec![
            span_of(text, "Иванов Пётр Сергеевич", "person_name", 0.9),
            span_of(text, "Сергеевич звонил", "person_name", 0.6),
        ]);
        let a =
            analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount)).expect("ок");
        assert_eq!(a.spans.len(), 1, "leftmost-longest снимает пересечение");
        assert_eq!(a.spans[0].score, 0.9, "живёт более уверенный левый");
    }

    #[test]
    fn byte_span_of_model_span_is_consistent() {
        let text = "Иванов звонил";
        let mount = FakeMount::ok(vec![span_of(text, "Иванов", "person_name", 0.9)]);
        let a =
            analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount)).expect("ок");
        let s = &a.spans[0];
        assert_eq!(&text[s.byte_start..s.byte_end], "Иванов");
        assert_eq!(s.start, 0, "символьные координаты считает ByteSpan");
        assert_eq!(s.end, 6);
        let _ = ByteSpan::new(text, s.byte_start, s.byte_end).expect("границы валидны");
    }

    // ── #200-A1: кандидат-клей модельных обрывков ──────────────────────────

    const PP_TEXT: &str = "Паспорт 4508 455561 выдан 15.04.2015";

    /// Модель дала обрывки паспорта (первичка #200, промер v0.1.1:
    /// «Паспорт 4508 455561» = обрывки «4508»+«455561», «45 08 455561» =
    /// «45 08»+«455» — у токенизатора граница токена посередине группы, клей
    /// склеивает ОКНА, целочисленность границ не зависит от реза): клей
    /// строит кандидата, вето подтверждает → ОДИН спан 1.0 целыми границами.
    #[test]
    fn glue_pair_becomes_full_veto_span() {
        let a = span_of(PP_TEXT, "4508", "passport", 0.82);
        let b = span_of(PP_TEXT, "455561", "passport", 0.93);
        let mount = FakeMount::ok(vec![a, b]);
        let an = analyze_with(&req(PP_TEXT), &schema(), &cfg(), Policy::Mask, Some(&mount))
            .expect("анализ");
        let p: Vec<&AnalyzedSpan> = an
            .spans
            .iter()
            .filter(|s| s.entity_type == "passport")
            .collect();
        assert_eq!(p.len(), 1, "склеенный паспорт не один");
        let sp = &an.spans[0];
        assert_eq!(&PP_TEXT[sp.byte_start..sp.byte_end], "4508 455561");
        assert_eq!(p[0].score, 1.0, "победа вето = вес 1.0");
    }

    /// Клей без вето не авто-сливает: «4508.2015» (дата-бэйт) = формат
    /// паспорта не подтверждён → обрывки живут как жили.
    #[test]
    fn glue_without_veto_keeps_pieces() {
        let text = "Паспорт 4508.2015 выдан";
        let a = span_of(text, "4508", "passport", 0.7);
        let b = span_of(text, "2015", "passport", 0.6);
        let mount = FakeMount::ok(vec![a, b]);
        let an = analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount))
            .expect("анализ");
        let p: Vec<&AnalyzedSpan> = an
            .spans
            .iter()
            .filter(|s| s.entity_type == "passport")
            .collect();
        assert_eq!(p.len(), 2, "несклеенный бэйт обязан остаться двумя спанами");
        assert!(p.iter().all(|s| s.score < 1.0), "вето без подтверждения");
    }

    /// Телефон: два phone-обрывка «79»+«161234567» с каркасом +7 = склейка
    /// в целый спан 1.0 (первичка #200: обрывок «79» на +79161234567).
    #[test]
    fn glue_phone_frames_full_span() {
        let text = "звоните +79161234567 срочно";
        let a = span_of(text, "79", "phone", 0.99);
        let b = span_of(text, "161234567", "phone", 0.8);
        let mount = FakeMount::ok(vec![a, b]);
        let an = analyze_with(&req(text), &schema(), &cfg(), Policy::Mask, Some(&mount))
            .expect("анализ");
        let p: Vec<&AnalyzedSpan> = an
            .spans
            .iter()
            .filter(|s| s.entity_type == "phone")
            .collect();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].score, 1.0);
    }

    /// Чужие классы склейка не трогает: person_name-обрывки не сливаются
    /// ([`GLUE_CLASSES`] закрыт, вето на имя нет).
    #[test]
    fn glue_leaves_other_classes() {
        let a = span_of(NAME_TEXT, "Иванов", "person_name", 0.55);
        let b = span_of(NAME_TEXT, "Пётр", "person_name", 0.51);
        let mount = FakeMount::ok(vec![a, b]);
        let an = analyze_with(
            &req(NAME_TEXT),
            &schema(),
            &cfg(),
            Policy::Mask,
            Some(&mount),
        )
        .expect("анализ");
        let p: Vec<&AnalyzedSpan> = an
            .spans
            .iter()
            .filter(|s| s.entity_type == "person_name")
            .collect();
        assert_eq!(p.len(), 2, "имена не склеиваются");
    }

    /// Разрыв больше бюджета ([`GLUE_MAX_GAP`]) не склеивается, даже с вето-формой:
    /// «4508 …… 455561» через длинный текст = два разных числа.
    #[test]
    fn glue_gap_budget() {
        let text = format!("паспорт 4508 {} 455561", "x".repeat(20));
        let a = span_of(text.as_str(), "4508", "passport", 0.7);
        let b = span_of(text.as_str(), "455561", "passport", 0.7);
        let mount = FakeMount::ok(vec![a, b]);
        let an = analyze_with(&req(&text), &schema(), &cfg(), Policy::Mask, Some(&mount))
            .expect("анализ");
        let p: Vec<&AnalyzedSpan> = an
            .spans
            .iter()
            .filter(|s| s.entity_type == "passport")
            .collect();
        assert_eq!(p.len(), 2, "разрыв за бюджетом склеился");
    }
}
