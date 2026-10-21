//! Монтаж каскадов 1–2 в продуктовый конвейер (issue #14A, SPEC §2).
//!
//! До шага 9A демон поднимал **только каскад 0**: `model_dir` был полем
//! конфигурации, которое ни на что не влияло, а метка `cascade-0+models` —
//! обещанием, которое конвейер не выполнял. Здесь обещание становится кодом:
//! при заданном `FASAD_MODEL_DIR` конвейер вызывает каскад 1
//! ([`guard_onnx::extract::LockrExtractor`]) и — только для серой зоны —
//! каскад 2 ([`guard_onnx::arbitrate::DecideArbiter`]).
//!
//! # Почему либа, а не харнес
//!
//! Тот же `LockrExtractor`, что вызывает демон, вызывает
//! `crates/guard-onnx/examples/recall_golden.rs`. Инвариант 7b «меряем =
//! гоняем»: продукт и метрика recall читают один decode-контракт, расхождение
//! «92 % по харнесу против продукта» по каскаду 1 стало структурно невозможным.
//!
//! # Fail-closed (AGENTS: «ошибка детектора = запрос наружу не уходит»)
//!
//! Любой сбой модельного пути — незагруженная модель, ошибка инференса,
//! превышение бюджета, обрезка текста окном 256 токенов, заполненная очередь —
//! это [`CascadeFailure`], которая поднимается из
//! [`analyze`](crate::pipeline::analyze) и становясь `502 cascade_unavailable`
//! ([`crate::http`]). Молчаливая деградация к каскаду 0 при выставленном
//! `model_dir` = fail-open на recall, и она не становится допустимой от того,
//! что «модель просто не успела».
//!
//! Стартовый отказ — тот же инвариант, только виден сразу:
//!
//! 1. бинарь собран без фичи `ort-inference`, а `FASAD_MODEL_DIR` задан →
//!    [`startup`] отказывает ([`CascadeFailure::BuiltWithoutInference`]);
//! 2. веса не загрузились → отказ старта с причиной в stderr.
//!
//! Именно поэтому [`Config::stage`](crate::config::Config::stage) больше не
//! врёт: метка описает собранный и поднятый контур, а не намерение оператора.
//!
//! # Чанкинг пути запроса (issue #84)
//!
//! Текст длиннее окна lockR ([`guard_onnx::extract::PAD`] = 256 токенов) больше
//! не 502: он режется [`guard_onnx::chunker::chunk`] и экстрактор гоняется по
//! чанкам **последовательно** (тот же RSS-инвариант, что у воркера: пик —
//! один прогон, не `N`). Решения, каждое — контракт, а не имплементационная
//! деталь:
//!
//! 1. **Границы.** Приоритет реза: абзац (`\n\n`) → предложение (`.!?`) →
//!    край окна; резы всегда на UTF-8-границе ([`extract_chunked`], слой
//!    `chunker`). Окно lockR-конфига = `PAD` (256 токенов = 1024 байта
//!    байтовой оценки), НЕ 384: граф.pad-256 жёсткий, 384-окно SPEC §2 —
//!    потолок конфигурации A, а lockR живёт на нижней границе своего
//!    фиксированного окна (`docs/model-audit.md` §5: «чанкер 4b-1 сокращает
//!    только арбитра, lockR окно 256 фиксировано»).
//! 2. **Overlap = 32 токена** (SPEC §2, [`guard_onnx::chunker::OVERLAP_TOKENS`],
//!    128 байта оценки). Мера — байтовая оценка `bytes/4` (промер первички в
//!    доке `chunker`: XLM-R 4.64 Б/токен, GPT-2 3.35 Б/токен): для ruBERT-ядра
//!    оценка консервативна (чанк режется раньше реального окна), для Decide —
//!    `arb_chunk_cfg` укладывает окно+overhead в 512. Сущность короче
//!    124 байт (31 токен + запас 4 Б на флор UTF-8-границы и guard прогресса),
//!    разрезанной границей окна не бывает: она целиком попадает в перекрытие
//!    и соседний чанк видит её целиком (тест `fio_split_across_boundary_survives`).
//! 3. **Координаты.** Спан чанка переносится в оригинал сложением
//!    `chunk.span.start` (чанкер возвращает спаны оригинала, конверсии нет —
//!    тот же инвариант, что у `arbitrate_chunked` и у оконного слоя каскада 0
//!    с его `normalize::OffsetMap`).
//! 4. **Дедуп.** One span — once: [`merge_disjoint`] по всем модельным спанам
//!    (все `deterministic = false`), приоритет leftmost-longest, при равенстве
//!    координат — больший `p1`, при равенстве — порядок входа = порядок чанков
//!    (более ранний чанк). Фрагмент сущности, отсечённый краем чанка, проигрывает
//!    целому (тот же `start` при большем `end`). Чексуммные спаны каскада 0
//!    этот дедуп не видит: он живёт до слияния с каскадом 0, а там действует
//!    прежнее правило вето (`merge_disjoint` п.2).
//! 5. **Край `Truncated` остаётся.** Если ФАКТИЧЕСКИЙ токен-счёт чанка
//!    переполняет окно (оценка байтами недооценила: сплошные цифры, XLM-R
//!    режет их посимвольно), чанк даёт `Extract::truncated` → 502
//!    [`CascadeFailure::Truncated`]. Это край, а не норма (issue #84 п.4):
//!    молча выбросить хвост = fail-open, инвариант AGENTS не тронут.
//! 6. **Бюджет.** Каждый чанк стоит один полный прогон окна
//!    (`run_p50_ms_extractor1b` = 271.8 мс при threads=4, `docs/model-audit.md`
//!    §5; при `FASAD_THREADS=2` — выше), Decide-чанк ≈ 1.0–1.5 с
//!    (§5.6 п.6, фикс-оверхед прогона доминирует). Бюджет запроса
//!    `FASAD_TIMEOUT_MS` проверяется на КАЖДОМ чанке lockR
//!    ([`extract_chunked`]'й `over_budget`), вне бюджета — `Timeout`, не
//!    бесконечный прогон: «чанкам нужен свой бюджет, иначе таймаут становится
//!    единственным исходом» (issue #84 п.2) закрыт формулой
//!    `budget ≳ N_lockR × 0.3 с + N_decide × 8 с` при threads=2 — промер
//!    docs/model-audit.md §11: Decide-чанк дороже предсказания в 4 раза
//!    (README демона).
//! 7. **Decide чанкуется** ([`guard_onnx::arbitrate::DecideArbiter::arbitrate_chunked`]
//!    с `arb_chunk_cfg(384 + 56 ≤ 512)`), вердикт класса = **max** вероятности
//!    по чанкам (FN фатален, тот же закон, что у `merge_arb_hits`: union, ниже
//!    не берём). Текст короче окна = один чанк = прежнее
//!    `arbitrate_text`-выражение 1-в-1 (тот же `plan_of_block`, те же
//!    `decisions`), витринный текст §2 от чанкинга не изменился НИ НА БАЙТ.
//!
//! # Что сознательно НЕ закрыто этим атомом
//!
//! 1. **Каскад 2 не даёт координат.** Decide отвечает «есть ли класс в тексте»
//!    (row-level, issue #41), спанов у него нет, поэтому в продукте он может
//!    только **перескорить** спан каскада 1, но не добавить новый. Набор
//!    спанов продукта = каскад 0 ∪ каскад 1, и парность мерится против
//!    «строгой» меры харнеса (без row-level кредита Decide).
//! 2. **`α` не калибрована.** SPEC §2 даёт формулу `S = α·p1 + (1−α)·p2` без
//!    числа; дефолт [`crate::config::DEFAULT_ALPHA`] = 0.5 и ручка
//!    `FASAD_ARBITER_ALPHA`, калибровка — issue #14B.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use guard_types::DetectionSource;

use crate::config::Config;
use crate::schema::Schema;

/// Глубина очереди на поток инференса. Больше — не «больше пропускная
/// способность», а больше очередей, в которых держатся тексты `ПДн`: каждая
/// запись — `Zeroizing<String>` объёмом до `FASAD_MAX_BODY_BYTES` (1 MiB).
pub const QUEUE_DEPTH: usize = 8;

/// Метка конвейера, когда каскады 1–2 примонтированы (значение
/// [`Config::stage`](crate::config::Config::stage) при заданном `model_dir`).
pub const STAGE_MOUNTED: &str = "cascade-0+models";

/// Спан, пришедший из модельного каскада (координаты — байты, как у каскада 0).
#[derive(Debug, Clone, PartialEq)]
pub struct ModelSpan {
    /// Байт начала.
    pub byte_start: usize,
    /// Байт конца (исключительно).
    pub byte_end: usize,
    /// Класс схемы: маппинг `lockr_tags` → id схемы делает схема, а не код.
    pub class: String,
    /// Итоговый скор `S` (SPEC §2): `p1`, либо смесь `α·p1 + (1−α)·p2`.
    pub score: f64,
    /// Скор каскада 1 до арбитража — для отладки и для промера `α`.
    pub p1: f64,
    /// Кто нашёл: каскад 1, либо каскад 2 (перескоренный арбитражем спан).
    pub source: DetectionSource,
}

/// Причина, по которой модельный путь не дал ответа. Каждый вариант = 502.
#[derive(Debug, Clone, PartialEq)]
pub enum CascadeFailure {
    /// Веса/токенизатор не загрузились, каталог неполон (отказ на старте).
    Load(String),
    /// Сбой инференса (`ort`-ран, битый граф, непредвиденный выход).
    Inference(String),
    /// Инференс не уложился в `FASAD_TIMEOUT_MS`. Бюджет проверяется по
    /// границам стадий: у `ort` rc.14 нет cancel-флажка, способного прервать
    /// `run` (промер `session/run_options.rs`), поэтому «убить ран» честнее
    /// назвать «не дождаться и не выпустить запрос».
    Timeout {
        /// Бюджет, мс.
        budget_ms: u64,
        /// Стадия, на которой истёк бюджет.
        stage: &'static str,
    },
    /// Очередь инференса заполнена: ждать в очереди дольше бюджета — значит
    /// держать соединение и чужие тексты `ПДн` в буферах.
    Overloaded {
        /// Глубина очереди, [`QUEUE_DEPTH`].
        depth: usize,
    },
    /// Текст не влез в окно экстрактора: часть текста не просмотрена, а значит
    /// часть `ПДн` может уйти наружу.
    Truncated {
        /// Окно lockR в токенах.
        window: usize,
    },
    /// Поток инференса умер (паника внутри `ort`). Состояние сессии
    /// неизвестно → отказываем запрос, а не отвечаем пусто.
    Dead,
    /// `model_dir` задан, а бинарь собран без фичи `ort-inference`: каскады
    /// физически нечем гонять, и молча объявлять `cascade-0+models` нельзя.
    BuiltWithoutInference,
}

impl std::fmt::Display for CascadeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Текст запроса в причину не попадает: имена файлов и классы — да,
            // содержимое — нет (AGENTS: оригиналы `ПДн` не светятся в логах).
            Self::Load(m) => write!(f, "модельный каскад не загружен: {m}"),
            Self::Inference(m) => write!(f, "сбой инференса: {m}"),
            Self::Timeout { budget_ms, stage } => {
                write!(f, "инференс ({stage}) не уложился в {budget_ms} мс")
            }
            Self::Overloaded { depth } => {
                write!(f, "очередь инференса заполнена ({depth} задач)")
            }
            Self::Truncated { window } => write!(
                f,
                "чанк текста не влез в окно экстрактора ({window} токенов) даже после \
                 чанкинга (#84): каскад 1 видел не весь текст"
            ),
            Self::Dead => write!(f, "поток инференса завершён — состояние неизвестно"),
            Self::BuiltWithoutInference => write!(
                f,
                "FASAD_MODEL_DIR задан, а бинарь собран без фичи `ort-inference` \
                 (нужно `--features guard-daemon/ort-inference`)"
            ),
        }
    }
}

impl std::error::Error for CascadeFailure {}

/// Лег каскада 2 (Decide) на этом запросе: оператор обязан видеть деградацию
/// per-request, а не только то, что модели примонтированы (`X-Guard-Stage`
/// говорит про монтаж, а не про вердикты). Значение печатается в
/// `X-Guard-Cascade2` (сетка SPEC §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cascade2 {
    /// Каскада 2 в процессе нет: конвейер собран без весов.
    Absent,
    /// Лег отработал штатно. Short-circuit (серой зоны не было, Decide не
    /// звался) — тоже `Ok`: это штатная ветка SPEC §2, а не отказ.
    Ok,
    /// Лег был нужен и пропущен: контракт склейки нарушен на входе
    /// ([`decide_degrades`]), вердиктов нет, серые спаны остались на `p1`.
    Skipped,
}

impl Cascade2 {
    /// Значение заголовка `X-Guard-Cascade2`.
    #[must_use]
    pub const fn as_header(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Ok => "ok",
            Self::Skipped => "skipped",
        }
    }
}

/// Выход модельного пути: спаны каскада 1 (после перескора) + сигнал легов.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Спаны каскада 1, перескоренные каскадом 2 в серой зоне.
    pub spans: Vec<ModelSpan>,
    /// Что сделал каскад 2 на этом запросе.
    pub cascade2: Cascade2,
}

/// Контракт модельного пути. Отделён от `ort`, чтобы стад-машину конвейера
/// можно было тестировать без весов: юнит-тесты `pipeline` гоняют её на фейке
/// в CI обеих ОС, где весов нет и быть не может.
pub trait Cascade12: Send + Sync {
    /// Спановый выход каскада 1 + перескор серой зоны каскадом 2.
    ///
    /// Реализация обязана: (1) применить порог `plan.tau` к `p1`; (2) звать
    /// каскад 2 **только** когда в тексте есть спан серой зоны
    /// контекстно-зависимого класса (SPEC §2, short-circuit); (3) вернуть
    /// ошибку на любом сбое, а не пустой список.
    ///
    /// # Errors
    ///
    /// [`CascadeFailure`] — см. варианты.
    fn model_spans(
        &self,
        text: &str,
        schema: &Schema,
        plan: &Plan,
    ) -> Result<Outcome, CascadeFailure>;
}

/// Что считать модельному пути: порог, границы серой зоны, вес `α`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Plan {
    /// Порог извлечения `τ_low` (эффективный, с учётом права клиента поднять).
    pub tau: f64,
    /// Низ серой зоны.
    pub gray_lo: f64,
    /// Верх серой зоны (исключительно).
    pub gray_hi: f64,
    /// Вес `α` формулы SPEC §2.
    pub alpha: f64,
}

impl Plan {
    /// План из конфигурации и эффективного порога запроса.
    #[must_use]
    pub const fn from_config(cfg: &Config, tau: f64) -> Self {
        Self {
            tau,
            gray_lo: cfg.thresholds.gray_lo,
            gray_hi: cfg.thresholds.gray_hi,
            alpha: cfg.thresholds.alpha,
        }
    }
}

/// Спан серой зоны? Границы SPEC §2: `gray_lo ≤ p1 < gray_hi`.
///
/// `NaN` сравнениями ниже в серую зону не попадает — осознанно: безумному
/// скору не положено второе мнение арбитра, он отсекается порогом на выходе
/// (`route(NaN) = Block`, см. `guard_onnx::routing`).
#[must_use]
pub fn in_grey_zone(p1: f64, plan: &Plan) -> bool {
    p1 >= plan.gray_lo && p1 < plan.gray_hi
}

/// Смешанный скор серой зоны: `S = α·p1 + (1−α)·p2` (SPEC §2).
#[must_use]
pub fn blend(p1: f64, p2: f64, alpha: f64) -> f64 {
    alpha.mul_add(p1, (1.0 - alpha) * p2)
}

/// Классы, по которым арбитр имеет право голоса (SPEC §2 «контекстно-зависимые»:
/// `PERSON/ORG/КОММЕРЧЕСКАЯ_ТАЙНА`).
///
/// Критерий — схема, а не список в коде: **модельный класс без детерминированного
/// валидатора**. В каноне это `person_name`, `address`, `passport`, `phone`,
/// `email`. У `inn`/`snils`/`card_pan` решение принимает чексумма (каскад 0,
/// вето 1.0), и арбитр там может только добавить ложных отрицаний. Свой
/// словарь классов (свой `validators`) получает и свой состав арбитража —
/// без правки кода.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CascadeCtx {
    /// Id контекстно-зависимых классов, в порядке схемы.
    pub context_classes: Vec<String>,
}

impl CascadeCtx {
    /// Свертка схемы: что является контекстно-зависимым классом.
    #[must_use]
    pub fn of(schema: &Schema) -> Self {
        Self {
            context_classes: schema
                .classes
                .iter()
                .filter(|c| c.model && c.validators.is_empty())
                .map(|c| c.id.clone())
                .collect(),
        }
    }

    /// Контекстно-зависимый класс = арбитр его касается.
    #[must_use]
    pub fn is_context_dependent(&self, class_id: &str) -> bool {
        self.context_classes.iter().any(|c| c == class_id)
    }
}

/// Уникальные классы спанов, по которым стоит спрашивать Decide (порядок —
/// порядок спанов, детерминированно).
#[must_use]
pub fn grey_classes(spans: &[ModelSpan], ctx: &CascadeCtx, plan: &Plan) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in spans {
        if !in_grey_zone(s.p1, plan) || !ctx.is_context_dependent(&s.class) {
            continue;
        }
        if !out.iter().any(|c| c == &s.class) {
            out.push(s.class.clone());
        }
    }
    out
}

/// Перескор серой зоны вердиктами арбитра (SPEC §2, формула `S`).
///
/// `p2` — вероятность «да» по классу (row-level); классов в `p2` может быть
/// меньше, чем спанов: спрашивали только то, что попало в серую зону.
/// Спан, не попавший в серую зону, НЕ трогается: `p1 ≥ gray_hi` = «высокая
/// уверенность», арифметика арбитра его не понижает (иначе каскад 2 правил бы
/// каскадом 1 за пределами своей зоны).
pub fn apply_arbiter(spans: &mut [ModelSpan], p2: &[(String, f64)], ctx: &CascadeCtx, plan: &Plan) {
    for s in spans {
        if !in_grey_zone(s.p1, plan) || !ctx.is_context_dependent(&s.class) {
            continue;
        }
        let Some((_, prob)) = p2.iter().find(|(c, _)| c == &s.class) else {
            continue;
        };
        s.score = blend(s.p1, *prob, plan.alpha);
        s.source = DetectionSource::GlinerDecideArbitrator;
    }
}
/// Что делает отказ арбитра деградацией (вердиктов нет), а не боем запроса.
///
/// Единственная деградирующая ветка — [`ArbError::Layout`]: она проверяет
/// живой вход (нулевой [UNK], сохранность слов склейки) и потому зависит от
/// символов текста, а не от состояния сессии. Всё остальное — сломанная
/// инициализация, словарь, ORT: на них молчать нельзя, запрос обязан уйти в
/// 502 (`CascadeFailure::Inference`).
#[cfg(feature = "ort-inference")]
pub(super) fn decide_degrades(err: &guard_onnx::arbitrate::ArbError) -> bool {
    matches!(err, guard_onnx::arbitrate::ArbError::Layout(_))
}

/// Индексы спанов, переживших слияние каскада 0 с модельным выходом
/// (SPEC §2 каскад 3: `interval tree`, greedy leftmost-longest).
///
/// Вход — `(start, end, score, deterministic)` в любом порядке, выход —
/// индексы входа в непересекающемся покрытии **модельной части**, в порядке
/// входа.
///
/// Три правила, первое из них — промеренное, а не теоретическое:
///
/// 1. Детерминированные спаны (каскад 0, вето 1.0) живут **все**, ни один не
///    отбрасывается. Два валидатора на одних байтах — это два законных класса
///    одного числа (промер golden `g0004`: `22xxxx…` проходит и как PAN «Мир»,
///    и как ОГРНИП по mod-13), и выбирать между ними «по длине» — значит
///    терять класс, который каскад 0 нашёл всегда. Первая версия этого
///    слияния проецировала непересечение на весь список и роняла `ogrnip`
///    рядом с `card_pan` — тест парности поймал это как `lost=[("ogrnip",…)]`.
/// 2. Модельный спан, пересекающийся с любым детерминированным, отбрасывается:
///    вето чексуммы не понижается и не дублируется гипотезой модели.
/// 3. Среди модельных остаётся самый левый и длинный (`start ↑`, `end ↓`,
///    при равенстве — больший скор, при равенстве — порядок входа). Победитель
///    не «поглощает» проигравшего, расширяя координаты: координаты модели —
///    то, что модель увидела; придумывать ей хвост мы не вправе.
///
/// Касание (`start == конец предыдущего`) конфликтом не считается.
///
/// Сложность `O(n²)` на числе спанов одного запроса: `n` здесь — модельные
/// спаны окна в 256 токенов (единицы–десятки), и windowed-`interval tree`
/// SPEC §2 на таком `n` добавит только кода. С чанкингом пути запроса (#84)
/// сверху `n` держит длина документа: 2000 слов ≈ 13 чанков ≈ десятки
/// спанов, квадрат на этом масштабе — единицы микросекунд; дерево
/// понадобится, когда документация перестанет быть десятками тысяч байт
/// (issue #41/дальше), не раньше.
#[must_use]
pub fn merge_disjoint(spans: &[(usize, usize, f64, bool)]) -> Vec<usize> {
    let mut keep: Vec<usize> = Vec::with_capacity(spans.len());
    let mut det: Vec<(usize, usize)> = Vec::new();
    for (i, (start, end, _, d)) in spans.iter().enumerate() {
        if *d {
            det.push((*start, *end));
            keep.push(i);
        }
    }
    let mut model: Vec<usize> = (0..spans.len()).filter(|i| !spans[*i].3).collect();
    model.sort_by(|&a, &b| {
        let (sa, ea, pa, _) = spans[a];
        let (sb, eb, pb, _) = spans[b];
        sa.cmp(&sb)
            .then(eb.cmp(&ea))
            .then(
                pb.partial_cmp(&pa)
                    // NaN не имеет права выигрывать сравнение скоров; при
                    // несоразмерных скорах решает порядок входа.
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.cmp(&b))
    });
    let mut accepted: Vec<(usize, usize)> = Vec::with_capacity(model.len());
    for i in model {
        let (start, end, _, _) = spans[i];
        let clash_det = det.iter().any(|(ds, de)| start < *de && end > *ds);
        let clash_model = accepted.iter().any(|(ms, me)| start < *me && end > *ms);
        if clash_det || clash_model {
            continue;
        }
        accepted.push((start, end));
        keep.push(i);
    }
    keep.sort_unstable();
    keep
}

/// Спан чанкового прогона экстрактора в КООРДИНАТАХ ОРИГИНАЛА
/// ([`extract_chunked`] переносит их сложением `chunk.span.start`).
///
/// Зеркало [`guard_onnx::extract::ExtractSpan`] без `class`: класс спана
/// назначает схема (`job.tags`), а не либа, — золотой класс `ExtractSpan::class`
/// на продуктовом пути не используется (промер: `run` читает только
/// `tag`/`score`).
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkedSpan {
    /// Байт начала в оригинале.
    pub byte_start: usize,
    /// Байт конца (исключительно) в оригинале.
    pub byte_end: usize,
    /// Голова модели без B-/I-префикса.
    pub tag: String,
    /// Confidence = min softmax по скобке (контракт харнеса).
    pub score: f64,
}

/// Выход одного чанкового прогона: `(спановые гипотезы в ОТНОСИТЕЛЬНЫХ
/// координатах куска, факт среза окна моделью)`.
pub type ChunkProbeOut = (Vec<ChunkedSpan>, bool);

/// Отказ чанкового прогона ([`extract_chunked`]).
#[derive(Debug, Clone, PartialEq)]
pub enum ChunkFailure<E> {
    /// Ошибка одного чанка: fail-closed, «остальные чанки досчитали» не бывает
    /// — часть текста без вердикта = часть `ПДн` под угрозой (AGENTS).
    Extract(E),
    /// Чанк не влез в окно ФАКТИЧЕСКИ (оценка байтов/4 недооценила: цифры,
    /// сплошной ASCII): край, а не норма — см. док модуля, п.5.
    Truncated {
        /// Окно экстрактора в токенах.
        window: usize,
    },
    /// Граница чанка вне UTF-8: инвариант чанкера сломан (кода такого быть не
    /// должно, а ложная причина отказа отправила бы чинить не то).
    BadBoundary,
    /// Бюджет запроса исчерпан ДО старта следующего чанка: прогон наружу не
    /// выпускаем, `Timeout` — он же деградация каскада (502), не fail-open.
    OverBudget {
        /// Бюджет, мс (называет вызывающий: замыкает его `Instant`).
        budget_ms: u64,
    },
}

/// Последовательный прогон экстрактора по чанкам с переносом координат и дедупом.
///
/// Семантика (док модуля «Чанкинг пути запроса», пункты 1–5):
///
/// * чанки — [`guard_onnx::chunker::chunk`] (абзац → предложение → край окна,
///   overlap, UTF-8-границы);
/// * порядок прогонов = порядок чанков (последовательно, RSS одного прогона);
/// * координаты — оригинал: `chunk.span.start + span.byte_start`;
/// * дедуп — [`merge_disjoint`] по модельным спанам (leftmost-longest, затем
///   больший `p1`, затем порядок входа = более ранний чанк): один спан отдаётся
///   один раз;
/// * `truncated` ЛЮБОГО чанка — отказ целиком (край «чанк не влез» остаётся);
/// * `over_budget()` перед КАЖДЫМ чанком — бюджет чанков (issue #84 п.2),
///   вызывающий считает из него `Timeout`.
///
/// * пустой текст → пустой список (чанков нет, экстрактор не зовётся); текст
///   короче окна → ровно ОДИН вызов `extract` на весь текст, координаты и
///   содержимое спанов — бит-в-бит как без чанкинга (витрина §2 регрессионно
///   закрыта тестом `short_text_calls_extract_once_bit_identical`);
/// * выходной порядок — порядок входа (чанки идут по тексту, внутри чанка —
///   порядок B/I-скобок).
///
/// Функция отделена от `ort` (замыкает [`guard_onnx::extract::LockrExtractor`]
/// вызывающий), чтобы гейты чанкинга гонялись в CI обеих ОС без весов.
///
/// # Errors
///
/// [`ChunkFailure::Extract`] — сбой одного чанка (fail-closed: остаток текста
/// без вердикта не досчитывается); [`ChunkFailure::Truncated`] — чанк не влез
/// в окно (край #84 п.4); [`ChunkFailure::BadBoundary`] — сломан инвариант
/// чанкера; [`ChunkFailure::OverBudget`] — бюджет исчерпан до старта чанка.
pub fn extract_chunked<E>(
    text: &str,
    cfg: guard_onnx::chunker::ChunkCfg,
    extract: &mut dyn FnMut(&str) -> Result<ChunkProbeOut, E>,
    over_budget: &mut dyn FnMut() -> Option<u64>,
) -> Result<Vec<ChunkedSpan>, ChunkFailure<E>> {
    let window = usize::try_from(cfg.window_tokens.0).unwrap_or(usize::MAX);
    let mut all: Vec<ChunkedSpan> = Vec::new();
    for ch in guard_onnx::chunker::chunk(text, cfg) {
        if let Some(budget_ms) = over_budget() {
            return Err(ChunkFailure::OverBudget { budget_ms });
        }
        // `slice` обязана быть Some: границы чанков подняты самим чанкером по
        // UTF-8-границам (инвариант 3 модуля `chunker`). None = сломанный
        // инвариант, не «данные такие»: отказ с ИСТИННОЙ причиной, а не
        // ложный Truncated (чинить тогда надо не бюджет и не окно).
        let Some(piece) = ch.span.slice(text) else {
            return Err(ChunkFailure::BadBoundary);
        };
        let (mut spans, truncated) = extract(piece).map_err(ChunkFailure::Extract)?;
        if truncated {
            return Err(ChunkFailure::Truncated { window });
        }
        for s in &mut spans {
            s.byte_start += ch.span.start;
            s.byte_end += ch.span.start;
        }
        all.extend(spans);
    }
    // Дедуп пересечений overlap-зоны (док модуля, п.4). Все спаны — модельные
    // (deterministic = false): чексуммный каскад-0 сюда не заходит и вето не
    // трогает. merge_disjoint возвращает индексы входа в порядке входа.
    let tuples: Vec<(usize, usize, f64, bool)> = all
        .iter()
        .map(|s| (s.byte_start, s.byte_end, s.score, false))
        .collect();
    let keep: Vec<bool> = {
        let mut k = vec![false; all.len()];
        for i in merge_disjoint(&tuples) {
            k[i] = true;
        }
        k
    };
    let mut out = Vec::with_capacity(all.len());
    for (i, s) in all.into_iter().enumerate() {
        if keep[i] {
            out.push(s);
        }
    }
    Ok(out)
}

/// Установка модельного пути: движок, который читает конвейер.
///
/// Глобальность вынужденная, не удобная: `pipeline::analyze` вызывается из
/// `http.rs` и `proxy.rs` одной сигнатурой, а менять её ради одного
/// дополнительного аргумента означало бы трогать роутер (занято атомом #75).
/// Пишется ОДИН раз на старте ([`startup`]); тесты подменяют его
/// [`install_test_mount`].
static MOUNT: Mutex<Option<Arc<dyn Cascade12>>> = Mutex::new(None);

fn mount_slot() -> MutexGuard<'static, Option<Arc<dyn Cascade12>>> {
    // Отравка мьютекса возможна только паникой под захватом, а пишем мы в слот
    // ровно один раз на старте; содержимое (`Option<Arc>`) чужой паникой не
    // портится, поэтому берём его через `into_inner`, а не рвём старт.
    MOUNT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Примонтированный движок (`None` = конвейер работает каскадом 0).
#[must_use]
pub fn engine() -> Option<Arc<dyn Cascade12>> {
    mount_slot().clone()
}

/// Подмена движка тестовым фейком (юнит-тесты стад-машины без весов).
///
/// В релизе (prod-бинарь) функции нет: `debug_assertions` там выключены, и
/// подменить движок работающему демону становится нельзя ни из какого кода.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn install_test_mount(mount: Option<Arc<dyn Cascade12>>) {
    *mount_slot() = mount;
}

/// Поднять модельный путь по конфигурации. Вызывается ОДИН раз из `main` до
/// подъёма сокета; `Err` = старт невозможен (fail-closed, см. `main.rs`).
///
/// Смысл функции в том, чего она НЕ делает: не поднимает каскады «на сколько
/// хватит весов» и не молчит, когда каталог назван, а открыть его нечем.
///
/// # Errors
///
/// [`CascadeFailure::BuiltWithoutInference`] (нет фичи при заданном
/// `model_dir`), [`CascadeFailure::Load`] (веса битые/отсутствуют),
/// [`CascadeFailure::Timeout`] (вес не поднялся в бюджет старта).
pub fn startup(cfg: &Config) -> Result<(), CascadeFailure> {
    match cfg.model_dir.as_ref() {
        // Весов нет — каскад 0. Это не деградация, а заявленный контур:
        // `Config::stage()` скажет «cascade-0-only», и `/health` покажет то же.
        None => Ok(()),
        #[cfg(feature = "ort-inference")]
        Some(dir) => {
            let mount = onnx::OnnxMount::load(cfg, dir)?;
            *mount_slot() = Some(Arc::new(mount));
            Ok(())
        }
        #[cfg(not(feature = "ort-inference"))]
        Some(_dir) => Err(CascadeFailure::BuiltWithoutInference),
    }
}

/// Бюджет загрузки весов при старте, мс (публичный геттер: константа живёт в
/// приватном модуле `onnx`, а тесту она нужна как проверяемое число).
#[cfg(feature = "ort-inference")]
#[must_use]
pub const fn startup_load_budget_ms() -> u64 {
    onnx::STARTUP_LOAD_BUDGET_MS
}

/// Живой модельный путь: отдельный поток инференса + канал задач с бюджетом.
///
/// `ort`-сессии не `Sync` (и не обязаны им быть), поэтому они не «в `Arc` под
/// мьютексом в tokio-воркере», а в выделенном потоке: запрос ставит задачу и
/// ждёт ответа с дедлайном. Это даёт три вещи разом:
///
/// 1. бюджет `FASAD_TIMEOUT_MS` реализуем без cancel-флажка, которого у
///    rc.14 нет;
/// 2. паника внутри `ort` (`catch_unwind`) убивает ЗАПРОС (502), а не демон
///    (`panic = "unwind"`, AGENTS);
/// 3. последовательный прогон = пиковый RSS одного запроса, а не `N`
///    одновременных (SPEC §10 п.9, бюджет <2 GiB).
#[cfg(feature = "ort-inference")]
mod onnx {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
    use std::thread;
    use std::time::{Duration, Instant};

    use guard_onnx::arbitrate::{
        ChunkDecision, DecideArbiter, QuestionSchema, SCHEMA_OVERHEAD_TOKENS, arb_chunk_cfg,
    };
    use guard_onnx::chunker::{ChunkCfg, OVERLAP_TOKENS};
    use guard_onnx::extract::{ExtractError, LockrExtractor, PAD};
    use guard_onnx::routing::RoutingCfg;
    use guard_types::DetectionSource;
    use zeroize::Zeroizing;

    use super::{
        Cascade2, Cascade12, CascadeCtx, CascadeFailure, ChunkFailure, ChunkedSpan, ModelSpan,
        Outcome, Plan, QUEUE_DEPTH, apply_arbiter, extract_chunked, grey_classes,
    };
    use crate::config::Config;
    use crate::schema::Schema;

    /// Бюджет на загрузку весов при старте, мс. Отдельный от
    /// `FASAD_TIMEOUT_MS`: тот — бюджет ОДНОГО запроса, этот — «сколько раз
    /// при старте мы готовы ждать готовность модели» (один).
    pub const STARTUP_LOAD_BUDGET_MS: u64 = 120_000;

    /// Задача потоку инференса.
    struct Job {
        text: Zeroizing<String>,
        plan: Plan,
        budget_ms: u64,
        /// Свертка схемы для арбитража (контекстно-зависимые классы).
        ctx: CascadeCtx,
        /// `tag → class id` по схеме (`ClassDef::lockr_tags`): продукт слушает
        /// схему, а не жёсткий маппинг либы, — свой словарь тегов = свой состав
        /// классов без правки кода.
        tags: Vec<(String, String)>,
        /// Модельные классы схемы: `(id, вопрос Decide, ответы)`.
        questions: Vec<(String, String, Vec<String>)>,
        reply: SyncSender<Result<Outcome, CascadeFailure>>,
    }

    /// То, что переезжает в поток инференса (пути весов + потоки `ort`).
    struct Spec {
        lockr_model: PathBuf,
        lockr_tok: PathBuf,
        arb_model: PathBuf,
        arb_tok: PathBuf,
        threads: usize,
    }

    /// Модельный путь поверх `ort`: lockR (каскад 1) + Decide (каскад 2).
    pub struct OnnxMount {
        tx: SyncSender<Job>,
        budget_ms: u64,
    }

    impl OnnxMount {
        /// Загрузить модели и поднять поток инференса.
        ///
        /// Раскладка каталога = раскладка `scripts/fetch-models.sh` (кэш
        /// весов, манифест `models/manifest.md`):
        ///
        /// * `lockR/rubert-base-pii-ner-onnx/{model.optimized.fp16.onnx,tokenizer.json}`
        /// * `onnx-community/GLiNER2.5-Decide-ONNX/{onnx/model_q4f16.onnx,tokenizer.json}`
        pub fn load(cfg: &Config, model_dir: &Path) -> Result<Self, CascadeFailure> {
            let spec = Spec {
                lockr_model: model_dir
                    .join("lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx"),
                lockr_tok: model_dir.join("lockR/rubert-base-pii-ner-onnx/tokenizer.json"),
                arb_model: model_dir
                    .join("onnx-community/GLiNER2.5-Decide-ONNX/onnx/model_q4f16.onnx"),
                arb_tok: model_dir.join("onnx-community/GLiNER2.5-Decide-ONNX/tokenizer.json"),
                threads: cfg.threads,
            };
            for p in [
                &spec.lockr_model,
                &spec.lockr_tok,
                &spec.arb_model,
                &spec.arb_tok,
            ] {
                if !p.is_file() {
                    return Err(CascadeFailure::Load(format!(
                        "нет файла {} (каталог весов {}, раскладка — scripts/fetch-models.sh)",
                        p.display(),
                        model_dir.display()
                    )));
                }
            }
            let (job_tx, job_rx) = sync_channel::<Job>(QUEUE_DEPTH);
            let (ready_tx, ready_rx) = sync_channel::<Result<(), String>>(0);
            thread::Builder::new()
                .name("fasad-inference".to_owned())
                .spawn(move || worker(&job_rx, &ready_tx, &spec))
                .map_err(|e| CascadeFailure::Load(format!("поток инференса не поднят: {e}")))?;
            // Отдельное `let`: внешний `?` — про канал (таймаут/смерть воркера),
            // внутренний `Result` — про причину, которую воркер сам сообщил.
            let ready = ready_rx
                .recv_timeout(Duration::from_millis(STARTUP_LOAD_BUDGET_MS))
                .map_err(|e| match e {
                    RecvTimeoutError::Timeout => CascadeFailure::Timeout {
                        budget_ms: STARTUP_LOAD_BUDGET_MS,
                        stage: "startup",
                    },
                    RecvTimeoutError::Disconnected => {
                        CascadeFailure::Load("поток инференса умер при загрузке весов".to_owned())
                    }
                })?;
            // Сообщение воркера о причине отказа загрузки — текст с путями
            // весов и версией `ort`, он идёт в stderr при отказе старта.
            ready.map_err(CascadeFailure::Load)?;
            Ok(Self {
                tx: job_tx,
                budget_ms: cfg.timeout_ms,
            })
        }
    }

    impl Cascade12 for OnnxMount {
        fn model_spans(
            &self,
            text: &str,
            schema: &Schema,
            plan: &Plan,
        ) -> Result<Outcome, CascadeFailure> {
            let (reply_tx, reply_rx) = sync_channel(1);
            let job = Job {
                text: Zeroizing::new(text.to_owned()),
                plan: *plan,
                budget_ms: self.budget_ms,
                ctx: CascadeCtx::of(schema),
                tags: schema
                    .classes
                    .iter()
                    .flat_map(|c| c.lockr_tags.iter().map(move |t| (t.clone(), c.id.clone())))
                    .collect(),
                questions: schema
                    .model_classes()
                    .iter()
                    .map(|c| (c.id.clone(), c.question.clone(), c.answers.clone()))
                    .collect(),
                reply: reply_tx,
            };
            // Очередь глубины `QUEUE_DEPTH` заполнена — не ждём: ждать дольше
            // бюджета значит держать соединение и чужой текст `ПДн` в буфере.
            self.tx.try_send(job).map_err(|e| match e {
                TrySendError::Full(_) => CascadeFailure::Overloaded { depth: QUEUE_DEPTH },
                TrySendError::Disconnected(_) => CascadeFailure::Dead,
            })?;
            reply_rx
                .recv_timeout(Duration::from_millis(self.budget_ms))
                .map_err(|_| CascadeFailure::Timeout {
                    budget_ms: self.budget_ms,
                    stage: "inference",
                })?
        }
    }

    /// Тело потока инференса: загрузка (с ответом в `ready_tx`) и цикл задач.
    fn worker(rx: &Receiver<Job>, ready_tx: &SyncSender<Result<(), String>>, spec: &Spec) {
        let started = start(spec);
        let (mut lockr, mut arb) = match started {
            Ok(pair) => pair,
            Err(msg) => {
                let _ = ready_tx.send(Err(msg));
                return;
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return;
        }
        while let Ok(job) = rx.recv() {
            // Панику внутри `ort` переживаем как отказ ЗАПРОСА (502), демон
            // жив; состояние сессии после паники неизвестно, поэтому поток
            // новых задач уже не берёт — остальные получают `Dead` (fail-closed).
            let res = catch_unwind(AssertUnwindSafe(|| run(&mut lockr, &mut arb, &job)));
            let fatal = res.is_err();
            let payload = match res {
                Ok(res) => res,
                Err(_) => Err(CascadeFailure::Dead),
            };
            let _ = job.reply.send(payload);
            if fatal {
                return;
            }
        }
    }

    fn start(spec: &Spec) -> Result<(LockrExtractor, DecideArbiter), String> {
        let env = guard_onnx::extract::environment().map_err(|e| format!("{e}"))?;
        let lockr = LockrExtractor::load(&env, &spec.lockr_model, &spec.lockr_tok, spec.threads)
            .map_err(|e| format!("lockR {}: {e}", spec.lockr_model.display()))?;
        let arb = DecideArbiter::load(&env, &spec.arb_model, &spec.arb_tok, spec.threads)
            .map_err(|e| format!("decide {}: {e}", spec.arb_model.display()))?;
        Ok((lockr, arb))
    }

    /// Одна задача: чанковый каскад 1 → (только при серой зоне) чанковый
    /// каскад 2 (док модуля «Чанкинг пути запроса», issue #84).
    fn run(
        lockr: &mut LockrExtractor,
        arb: &mut DecideArbiter,
        job: &Job,
    ) -> Result<Outcome, CascadeFailure> {
        let started = Instant::now();
        let raw = lockr_raw(lockr, job, started)?;
        let mut spans = gate_spans(&raw, job);
        // Каскад 2, short-circuit (SPEC §2): ни одного спана серой зоны —
        // Decide не зовём вообще. Его латентность на прогон ≈1.0–1.5 с
        // фикс-оверхеда (docs/model-audit.md §5.6 п.6), и гонять её на каждом
        // запросе = гарантированно вылетать из FASAD_TIMEOUT_MS на ровном месте.
        let grey = grey_classes(&spans, &job.ctx, &job.plan);
        if grey.is_empty() {
            // Short-circuit SPEC §2: Decide не звался, и это штатная ветка, а не
            // деградация — сигнал `Ok`, иначе оператор читал бы «skipped» там,
            // где каскад 2 не нужен по построению.
            return Ok(Outcome {
                spans,
                cascade2: Cascade2::Ok,
            });
        }
        // u64::MAX при невозможном переполнении (584 млн лет аптайма) =
        // «бюджет исчерпан», т.е. отказ, а не продолжение: направление ошибки
        // совпадает с направлением инварианта.
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if elapsed_ms > job.budget_ms {
            return Err(CascadeFailure::Timeout {
                budget_ms: job.budget_ms,
                stage: "lockR",
            });
        }
        let asked: Vec<&(String, String, Vec<String>)> = job
            .questions
            .iter()
            .filter(|(id, _, _)| grey.iter().any(|g| g == id))
            .collect();
        let (p2, cascade2) = decide_p2(arb, job, &asked)?;
        apply_arbiter(&mut spans, &p2, &job.ctx, &job.plan);
        Ok(Outcome { spans, cascade2 })
    }

    /// Каскад 1 чанками: окно = `PAD`, порядок последовательный, координаты —
    /// оригинал, дедуп пересечений overlap-зоны (док модуля, п.1–5).
    fn lockr_raw(
        lockr: &mut LockrExtractor,
        job: &Job,
        started: Instant,
    ) -> Result<Vec<ChunkedSpan>, CascadeFailure> {
        // Окно lockR = PAD (256 токенов): граф паддит вход жёстко до 256,
        // 384-потолок SPEC §2 для него недостижим (model-audit §5: «lockR окно
        // 256 фиксировано»). 256 — нижняя граница легального множества
        // `ChunkCfg::new`, отказ здесь = рассинхронизация констант, не данные.
        let lockr_window = u32::try_from(PAD).unwrap_or(u32::MAX);
        let cfg = ChunkCfg::new(lockr_window, OVERLAP_TOKENS)
            .map_err(|e| CascadeFailure::Inference(format!("lockR: конфигурация чанкера: {e}")))?;
        extract_chunked(
            &job.text,
            cfg,
            &mut |piece| {
                let ex = lockr.extract(piece)?;
                Ok((
                    ex.spans
                        .into_iter()
                        .map(|s| ChunkedSpan {
                            byte_start: s.byte_start,
                            byte_end: s.byte_end,
                            tag: s.tag,
                            score: s.score,
                        })
                        .collect(),
                    ex.truncated,
                ))
            },
            &mut || {
                // Бюджет проверяется ПЕРЕД каждым чанком (issue #84 п.2):
                // N чанков — это N полных прогонов окна, и «досчитать до конца
                // любой ценой» означало бы держать соединение и чужие `ПДн`
                // в буферах неограниченно.
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                (ms > job.budget_ms).then_some(job.budget_ms)
            },
        )
        .map_err(|c: ChunkFailure<ExtractError>| match c {
            ChunkFailure::Extract(e) => CascadeFailure::Inference(format!("lockR: {e}")),
            ChunkFailure::Truncated { window } => CascadeFailure::Truncated { window },
            ChunkFailure::BadBoundary => {
                CascadeFailure::Inference("lockR: граница чанка вне UTF-8".to_owned())
            }
            ChunkFailure::OverBudget { budget_ms } => CascadeFailure::Timeout {
                budget_ms,
                stage: "lockR",
            },
        })
    }

    /// Гейт τ + гейт онтологии схемы для спанов чанкового прогона.
    fn gate_spans(raw: &[ChunkedSpan], job: &Job) -> Vec<ModelSpan> {
        // Порог каскада 1 — тем же lib-гейтом, что у харнеса (7b), а не
        // локальным сравнением: два сравнения с τ расходятся при первой правке.
        let routing = RoutingCfg::single(job.plan.tau);
        let mut spans: Vec<ModelSpan> = Vec::new();
        for s in raw {
            if !routing.route(s.score).extracted() {
                continue;
            }
            // Класс спана берётся из СХЕМЫ (её `lockr_tags`); тег, которого в
            // схеме нет, в продукт не выходит — у нас нет права изобретать
            // классы вне онтологии (`check_entities` тот же закон).
            let Some(class) = job
                .tags
                .iter()
                .find(|(t, _)| *t == s.tag)
                .map(|(_, c)| c.clone())
            else {
                continue;
            };
            spans.push(ModelSpan {
                byte_start: s.byte_start,
                byte_end: s.byte_end,
                class,
                score: s.score,
                p1: s.score,
                source: DetectionSource::GlinerExtractor,
            });
        }
        spans
    }

    /// Лег каскада 2 чанками: вердикт класса = max вероятности по чанкам
    /// (док модуля, п.7). Возвращает `p2` (пустой = вердиктов нет, спаны
    /// остаются на p1) и сигнал лега для `X-Guard-Cascade2`.
    fn decide_p2(
        arb: &mut DecideArbiter,
        job: &Job,
        asked: &[&(String, String, Vec<String>)],
    ) -> Result<(Vec<(String, f64)>, Cascade2), CascadeFailure> {
        let answers: Vec<Vec<&str>> = asked
            .iter()
            .map(|(_, _, a)| a.iter().map(String::as_str).collect())
            .collect();
        let qs: Vec<QuestionSchema<'_>> = asked
            .iter()
            .zip(&answers)
            .map(|((_, q, _), a)| (q.as_str(), a.as_slice()))
            .collect();
        // τ в `arbitrate_chunked` — f32 (сигнатура либы): шаг f32 ≈ 6e-8 на
        // порядок меньше шага сетки порогов (0.05), а τ приходит из конфига,
        // где он провалидирован в [0, 1].
        #[allow(
            clippy::cast_possible_truncation,
            reason = "τ ∈ [0,1], шаг f32 незаметен на сетке 0.05"
        )]
        let tau = job.plan.tau as f32;
        // Decide чанкуется (issue #84 п.2, config A): весь документ арбитром не
        // гоняется — O(L²) (5963 мс при L=1235, docs/model-audit.md §5), на
        // document-входе таймаут стал бы единственным исходом.
        // `arb_chunk_cfg(384, 56)` укладывает окно+overhead в 512 (промер
        // 4b-2d); `None` на этих константах невозможен (тесты `arb_chunk_cfg`
        // в либе), отказ — fail-closed на рассинхронизации констант.
        let arb_cfg =
            arb_chunk_cfg(ChunkCfg::default(), SCHEMA_OVERHEAD_TOKENS).ok_or_else(|| {
                CascadeFailure::Inference(
                    "decide: конфигурация чанковки вне легального множества \
                     (константы окна/overhead рассинхронизированы)"
                        .to_owned(),
                )
            })?;
        let mut cascade2 = Cascade2::Ok;
        let per_chunk: Vec<ChunkDecision> =
            match arb.arbitrate_chunked(&job.text, &qs, arb_cfg, tau) {
                Ok(cd) => cd.per_chunk,
                // Отказ на КОНКРЕТНОМ входе (контракт склейки): в словаре Spiber
                // `№` → [507, UNK] (инвентарь 4b-3C в `recall_golden.rs`), а
                // `check_splice` требует нуля [UNK] в живом входе. Харнес на это
                // заменяет `№` на пробел перед прогоном Decide (row-level мере
                // координаты не нужны); продукт заменить текст не может —
                // координаты спанов это байты оригинала. Значит вердиктов каскада 2
                // по этому входу нет, и направление деградации безопасно: серый
                // спан остаётся на p1, а p1 ≥ gray_lo = 0.22 > τ = 0.20, то есть
                // спан не теряется — пропадает только способность арбитра двигать
                // оценку. Отказывать здесь 502 = не обслуживать весь класс
                // документов с «№» (16 из 185 строк golden ≤200 символов), а это не
                // fail-closed, а отказ от работы. Остальные ветки (`Io`, `Ort`,
                // `VocabMismatch`, `Tokenizer`, `ChunkTooLong`, …) — настоящий
                // сбой: 502.
                Err(e) if super::decide_degrades(&e) => {
                    // В лог — только причина арбитра, без текста запроса (AGENTS).
                    eprintln!("fasad: каскад 2 пропущен для этого входа: {e}");
                    cascade2 = Cascade2::Skipped;
                    Vec::new()
                }
                Err(e) => return Err(CascadeFailure::Inference(format!("decide: {e}"))),
            };
        // p2 класса = МАКС вероятности по чанкам: row-level вопрос «есть ли
        // класс в тексте» на чанковом входе живёт ответом «есть в любом чанке»,
        // а вероятность — лучшим свидетельством (FN фатален: min/последний
        // брали бы худшее; тот же закон, что у max в `merge_arb_hits`).
        // Индексное соответствие «вопрос → ответ» проверяется на КАЖДОМ чанке —
        // единственный способ не перепутать классы (совпадение по тексту
        // вопроса молча сливает дубликаты). Текст короче окна = один чанк =
        // дословно прежнее `arbitrate_text`-число (тот же план, те же
        // `decisions`), витрина §2 бит-в-бит закрыта здесь и тестом
        // `decide_p2_is_max_over_chunks_single_chunk_is_identity`.
        let mut p2: Vec<(String, f64)> = Vec::new();
        if !per_chunk.is_empty() {
            for c in &per_chunk {
                if c.decisions.len() != asked.len() {
                    return Err(CascadeFailure::Inference(format!(
                        "decide вернул {} ответов на {} вопросов",
                        c.decisions.len(),
                        asked.len()
                    )));
                }
            }
            for (i, (id, _, _)) in asked.iter().enumerate() {
                let mut prob = 0.0f32;
                for c in &per_chunk {
                    prob = prob.max(c.decisions[i].prob);
                }
                p2.push((id.clone(), f64::from(prob)));
            }
        }
        Ok((p2, cascade2))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = канал ответа
#[allow(clippy::float_cmp)] // сравниваем константы контракта (0.0/1.0/τ/α)
mod tests {
    use super::*;
    use crate::schema::Schema;

    fn schema() -> Schema {
        Schema::embedded().expect("канон валиден")
    }

    /// Деградация Decide на входе с «№» (контракт склейки) не является боем
    /// запроса, а все остальные ветки `ArbError` остаются 502.
    #[cfg(feature = "ort-inference")]
    #[test]
    fn only_layout_degrades_the_arbiter() {
        assert!(decide_degrades(&guard_onnx::arbitrate::ArbError::Layout(
            "1 токенов [UNK] в живом входе".into()
        )));
        assert!(!decide_degrades(
            &guard_onnx::arbitrate::ArbError::NoMarkers
        ));
        assert!(!decide_degrades(
            &guard_onnx::arbitrate::ArbError::Tokenizer("tokenizer.json".into())
        ));
    }

    fn plan() -> Plan {
        Plan {
            tau: 0.20,
            gray_lo: 0.22,
            gray_hi: 0.80,
            alpha: 0.5,
        }
    }

    fn span(class: &str, p1: f64) -> ModelSpan {
        ModelSpan {
            byte_start: 0,
            byte_end: 5,
            class: class.to_owned(),
            score: p1,
            p1,
            source: DetectionSource::GlinerExtractor,
        }
    }

    #[test]
    fn grey_zone_bounds_are_lo_inclusive_hi_exclusive() {
        let p = plan();
        assert!(in_grey_zone(0.22, &p), "низ включается (SPEC §2 `≤`)");
        assert!(in_grey_zone(0.79, &p));
        assert!(!in_grey_zone(0.2199, &p), "ниже низа — не серая зона");
        assert!(!in_grey_zone(0.80, &p), "верх исключается (`<`)");
        assert!(
            !in_grey_zone(f64::NAN, &p),
            "NaN не получает второго мнения"
        );
    }

    #[test]
    fn blend_matches_spec_formula() {
        // S = α·p1 + (1−α)·p2.
        assert!((blend(0.3, 0.9, 0.5) - 0.6).abs() < 1e-12);
        assert!(
            (blend(0.3, 0.9, 1.0) - 0.3).abs() < 1e-12,
            "α=1 → чистый p1"
        );
        assert!(
            (blend(0.3, 0.9, 0.0) - 0.9).abs() < 1e-12,
            "α=0 → чистый p2"
        );
    }

    #[test]
    fn grey_classes_skips_checksum_classes() {
        let s = schema();
        let spans = [span("inn", 0.5), span("person_name", 0.5)];
        assert_eq!(
            grey_classes(&spans, &CascadeCtx::of(&s), &plan()),
            vec!["person_name".to_owned()],
            "у inn решение принимает чексумма: арбитр его не касается"
        );
    }

    #[test]
    fn grey_classes_skips_confident_and_weak() {
        let s = schema();
        let spans = [span("person_name", 0.9), span("person_name", 0.1)];
        assert!(
            grey_classes(&spans, &CascadeCtx::of(&s), &plan()).is_empty(),
            "p1 ≥ 0.80 не перескоривается, p1 < τ не дошёл до арбитра"
        );
    }

    #[test]
    fn arbiter_raises_grey_span_and_relabels_source() {
        let s = schema();
        let mut spans = vec![span("person_name", 0.3)];
        apply_arbiter(
            &mut spans,
            &[("person_name".to_owned(), 1.0)],
            &CascadeCtx::of(&s),
            &plan(),
        );
        assert!((spans[0].score - 0.65).abs() < 1e-12, "0.5·0.3+0.5·1.0");
        assert_eq!(
            spans[0].source,
            DetectionSource::GlinerDecideArbitrator,
            "перескоренный спан обязан быть приписан каскаду 2"
        );
        assert!((spans[0].p1 - 0.3).abs() < 1e-12, "p1 сохраняется");
    }

    #[test]
    fn arbiter_does_not_touch_confident_span() {
        let s = schema();
        let mut spans = vec![span("person_name", 0.9)];
        apply_arbiter(
            &mut spans,
            &[("person_name".to_owned(), 0.0)],
            &CascadeCtx::of(&s),
            &plan(),
        );
        assert!(
            (spans[0].score - 0.9).abs() < 1e-12,
            "выше серой зоны арбитр не понижает: каскад 2 не правила каскадом 1"
        );
        assert_eq!(spans[0].source, DetectionSource::GlinerExtractor);
    }

    #[test]
    fn arbiter_lowers_grey_span_when_decide_denies() {
        let s = schema();
        let mut spans = vec![span("address", 0.3)];
        apply_arbiter(
            &mut spans,
            &[("address".to_owned(), 0.0)],
            &CascadeCtx::of(&s),
            &plan(),
        );
        assert!((spans[0].score - 0.15).abs() < 1e-12);
        assert!(
            spans[0].score < 0.20,
            "после отказа арбитра спан уходит ниже τ — это и есть FP-подавление"
        );
    }

    #[test]
    fn missing_p2_leaves_span_at_p1() {
        let s = schema();
        let mut spans = vec![span("passport", 0.4)];
        apply_arbiter(&mut spans, &[], &CascadeCtx::of(&s), &plan());
        assert!(
            (spans[0].score - 0.4).abs() < 1e-12,
            "нет вердикта — не выдумываем"
        );
    }

    #[test]
    fn merge_keeps_checksum_and_drops_overlapping_model_span() {
        // (start, end, score, deterministic). Модель лезет в ИНН — чексумма
        // не понижается и не дублируется.
        let keep = merge_disjoint(&[(0, 12, 1.0, true), (2, 9, 0.7, false)]);
        assert_eq!(keep, vec![0]);
    }

    #[test]
    fn merge_keeps_disjoint_and_touching_spans() {
        let keep = merge_disjoint(&[(0, 5, 0.6, false), (5, 9, 0.7, false), (20, 30, 0.9, false)]);
        assert_eq!(
            keep,
            vec![0, 1, 2],
            "касание start == конец предыдущего — не конфликт"
        );
    }

    #[test]
    fn merge_prefers_leftmost_longest_among_model_spans() {
        let keep = merge_disjoint(&[(0, 4, 0.9, false), (0, 12, 0.5, false)]);
        assert_eq!(keep, vec![1], "при равном левом крае живёт более длинный");
    }

    #[test]
    fn merge_keeps_two_checksum_classes_on_the_same_bytes() {
        // Промёренный регресс (golden g0004, тест парности): `22xxxx…` — и PAN
        // «Мир», и ОГРНИП. Обе чексуммы законны на одних байтах, и слияние
        // каскадов не имеет права выбрать «одну».
        let keep = merge_disjoint(&[(95, 110, 1.0, true), (95, 110, 1.0, true)]);
        assert_eq!(keep, vec![0, 1], "вето не участвует в снятии пересечений");
    }

    #[test]
    fn merge_is_order_independent() {
        let a = merge_disjoint(&[(0, 12, 1.0, true), (2, 9, 0.7, false), (40, 44, 0.8, false)]);
        let b = merge_disjoint(&[(40, 44, 0.8, false), (2, 9, 0.7, false), (0, 12, 1.0, true)]);
        assert_eq!(
            a, b,
            "результат не зависит от порядка входа (тот же закон, что у Merger)"
        );
    }

    // ── Чанкинг пути запроса (issue #84): гейты на фейковом экстракторе ────
    //
    // Нейросети в юнитах CI нет (весов нет и быть не может), поэтому
    // дискриминаторы чанкинга гоняются на замыкаемой функции: фейк находит
    // иглы в куске и отдаёт их ОТНОСИТЕЛЬНЫМИ координатами — ровно как
    // `LockrExtractor::extract` для своего куска. Перенос координат, дедуп,
    // край `Truncated` и бюджет — вся логика `extract_chunked`, тот же код,
    // что вызывает демон (`run`).

    use super::{ChunkFailure, ChunkedSpan, extract_chunked};
    use guard_onnx::chunker::ChunkCfg;

    /// Окно lockR-конфига из продовой сборки: 256 токенов = 1024 байта оценки.
    fn chunk_cfg() -> ChunkCfg {
        ChunkCfg::new(256, 32).expect("256/32 легальны (SPEC §2)")
    }

    /// Фейк `LockrExtractor`: отдаёт иглы относительными спанами; `truncated_at`
    /// — номер куска, на котором фейк объявляет срез окна (край «чанк не влез»).
    struct FakeExtract {
        needles: Vec<(&'static str, f64)>,
        calls: Vec<String>,
        truncated_at: Option<usize>,
        error_at: Option<usize>,
    }

    impl FakeExtract {
        fn new(needles: Vec<(&'static str, f64)>) -> Self {
            Self {
                needles,
                calls: Vec::new(),
                truncated_at: None,
                error_at: None,
            }
        }

        fn call(&mut self) -> impl FnMut(&str) -> Result<(Vec<ChunkedSpan>, bool), String> + '_ {
            move |piece: &str| {
                let idx = self.calls.len();
                self.calls.push(piece.to_owned());
                if self.error_at == Some(idx) {
                    return Err(format!("фейк-орт сказал нет на чанке {idx}"));
                }
                let truncated = self.truncated_at == Some(idx);
                let mut spans = Vec::new();
                for (needle, score) in &self.needles {
                    if let Some(rel) = piece.find(needle) {
                        spans.push(ChunkedSpan {
                            byte_start: rel,
                            byte_end: rel + needle.len(),
                            tag: "INN".to_owned(),
                            score: *score,
                        });
                    }
                }
                Ok((spans, truncated))
            }
        }
    }

    fn no_budget() -> impl FnMut() -> Option<u64> {
        || None
    }

    /// Текст из предложений по 12 байт («Текст. »): граница первого окна
    /// (1024 Б) падает на 1020 — последнюю границу предложения внутри окна.
    fn sentences(k: usize) -> String {
        "Текст. ".repeat(k)
    }

    #[test]
    fn span_beyond_five_windows_lands_at_original_bytes() {
        // Гейт «ИНН за 5×окна»: игла на байте 5124 (> 5·1024), чанков ≥ 6.
        let needle = "7714563544";
        let prefix = sentences(427); // 427·12 = 5124 байта ровно
        assert_eq!(
            prefix.len(),
            5124,
            "фикстура: байтовая арифметика промерена"
        );
        let text = format!("{prefix}{needle} хвост.");
        let mut fake = FakeExtract::new(vec![(needle, 0.9)]);
        let out = extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget())
            .expect("чанки влезают");
        assert!(
            fake.calls.len() >= 6,
            "текст за 5 окнами обязан дать ≥6 чанков"
        );
        let abs = text.find(needle).expect("игла в тексте");
        assert_eq!(
            out.iter()
                .map(|s| (s.byte_start, s.byte_end))
                .collect::<Vec<_>>(),
            vec![(abs, abs + needle.len())],
            "спан в середине длинного текста возвращается в байтах ОРИГИНАЛА"
        );
    }

    #[test]
    fn fio_split_across_boundary_survives_via_overlap() {
        // ФИО пересекает конец первого окна (cut = 1020, игла 1008..1048):
        // чанк 0 [0,1020) её НЕ видит целиком, чанк 1 начинается ≤ 1020−128+4
        // = 896 ⇒ видит. Без overlap целой иглы в тексте чанков нет вовсе.
        let needle = "Ушакова Кира Саввична";
        let prefix = sentences(84); // 1008 байт
        assert_eq!(prefix.len(), 1008, "фикстура");
        let text = format!("{prefix}{needle} конец.");
        let abs = text.find(needle).expect("игла");
        assert!(
            abs < 1020 && abs + needle.len() > 1020,
            "фикстура режет иглу"
        );
        let mut fake = FakeExtract::new(vec![(needle, 0.95)]);
        let out =
            extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget()).expect("окно");
        assert_eq!(
            out.iter()
                .map(|s| (s.byte_start, s.byte_end))
                .collect::<Vec<_>>(),
            vec![(abs, abs + needle.len())],
            "overlap обязан дать чанк, где ФИО целиком, ровно один раз"
        );
    }

    #[test]
    fn dedup_same_span_from_overlapping_chunks_once() {
        // Игла целиком внутри overlap-зоны (префикс 900 Б, игла 900..914;
        // чанк 0 = [0,1017), чанк 1 = [888,…), хвост длиннее окна, чтобы
        // второй чанк существовал): её находят ДВАЖДЫ, отдавать обязаны один.
        let needle = "Ушакова";
        let text = format!("{}{needle} {}{}", sentences(75), "хвост.", sentences(50));
        let mut fake = FakeExtract::new(vec![(needle, 0.9)]);
        let out =
            extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget()).expect("окно");
        let found = fake.calls.iter().filter(|p| p.contains(needle)).count();
        assert!(found >= 2, "фикстура: игла должна найтись ≥2 раз (overlap)");
        assert_eq!(out.len(), 1, "дедуп: {found} нахождений → 1 спан");
    }

    #[test]
    fn dedup_prefers_whole_over_truncated_fragment() {
        // Фрагмент с тем же левым краем (игла отсечена краем чанка) проигрывает
        // целому: leftmost-longest (тот же закон, что у Merger/`merge_disjoint`).
        let needle = "Ушакова Кира Саввична";
        let prefix = sentences(84);
        let text = format!("{prefix}{needle} конец.");
        let abs = text.find(needle).unwrap();
        let mut fake = FakeExtract::new(vec![
            (needle, 0.9),
            ("Ушакова", 0.8), // фрагмент: тот же старт, короче
        ]);
        let out =
            extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget()).expect("окно");
        let whole: Vec<_> = out
            .iter()
            .filter(|s| s.byte_start == abs && s.byte_end == abs + needle.len())
            .collect();
        assert_eq!(whole.len(), 1, "целый спан живёт");
        assert!(
            out.iter()
                .all(|s| s.byte_end - s.byte_start == needle.len()),
            "фрагмент (те же байты начала, короче) снят дедупом: {out:?}"
        );
    }

    #[test]
    fn truncated_chunk_still_refuses_the_request() {
        // Край issue #84 п.4: «чанк не влез» остаётся 502-отказом, а не
        // «досчитали остальные чанки».
        let text = format!("{}хвост.", sentences(300));
        let mut fake = FakeExtract::new(vec![]);
        fake.truncated_at = Some(2);
        let r = extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget());
        assert_eq!(r, Err(ChunkFailure::Truncated { window: 256 }));
    }

    #[test]
    fn chunk_extract_error_fails_closed() {
        // Ошибка одного чанка = отказ запроса (AGENTS Fail-Closed), не пропуск.
        let text = format!("{}хвост.", sentences(300));
        let mut fake = FakeExtract::new(vec![]);
        fake.error_at = Some(1);
        let r: Result<Vec<ChunkedSpan>, ChunkFailure<String>> =
            extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget());
        assert!(matches!(r, Err(ChunkFailure::Extract(m)) if m.contains("чанке 1")));
    }

    #[test]
    fn budget_check_runs_before_every_chunk() {
        // Issue #84 п.2: бюджет проверяется на каждом чанке; здесь — кончается
        // на третьем. Отказ = OverBudget с НАЗВАННЫМ бюджетом (истинная
        // причина, вызывающий из неё делает Timeout).
        let text = format!("{}хвост.", sentences(500));
        let mut fake = FakeExtract::new(vec![]);
        let mut ticks = 0usize;
        let r = extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut || {
            ticks += 1;
            (ticks > 2).then_some(3000)
        });
        assert_eq!(r, Err(ChunkFailure::OverBudget { budget_ms: 3000 }));
        assert_eq!(fake.calls.len(), 2, "третий чанк не запускался");
    }

    #[test]
    fn short_text_calls_extract_once_bit_identical() {
        // Витрина §2 (регресс cmp-гейта): текст короче окна = ОДИН вызов на
        // ВЕСЬ текст (тот же вход экстрактору, что до чанкинга) и спаны
        // без сдвига координат.
        let text = "Ушакова Кира Саввична, ИНН 2482014338, СНИЛС 65707715421";
        let needle = "2482014338";
        let mut fake = FakeExtract::new(vec![(needle, 0.99)]);
        let out =
            extract_chunked(text, chunk_cfg(), &mut fake.call(), &mut no_budget()).expect("окно");
        assert_eq!(fake.calls.len(), 1, "короткий текст — один прогон");
        assert_eq!(fake.calls[0], text, "прогон обязан быть на ВЕСЬ текст");
        let abs = text.find(needle).unwrap();
        assert_eq!(
            out.iter()
                .map(|s| (s.byte_start, s.byte_end))
                .collect::<Vec<_>>(),
            vec![(abs, abs + needle.len())]
        );
        assert_eq!(out[0].score, 0.99, "скор не тронут");
    }

    #[test]
    fn chunks_sequential_cover_monotonic_with_overlap() {
        // Порядок прогонов = порядок чанков; покрытие без дыр; соседи
        // перекрываются не ниже грани чанкера.
        let text = sentences(400);
        let mut starts: Vec<usize> = Vec::new();
        let mut lens: Vec<usize> = Vec::new();
        let base = text.as_ptr() as usize;
        let r: Result<Vec<ChunkedSpan>, ChunkFailure<String>> = extract_chunked(
            &text,
            chunk_cfg(),
            &mut |piece: &str| {
                starts.push(piece.as_ptr() as usize - base);
                lens.push(piece.len());
                Ok((Vec::new(), false))
            },
            &mut no_budget(),
        );
        r.expect("окно");
        assert!(starts.len() > 4);
        assert_eq!(starts[0], 0, "первый чанк с нуля");
        assert_eq!(
            *starts.last().unwrap() + *lens.last().unwrap(),
            text.len(),
            "покрытие до конца"
        );
        for w in starts.windows(2) {
            assert!(w[1] > w[0], "старты строго растут (последовательность)");
        }
        for k in 1..starts.len() {
            let prev_end = starts[k - 1] + lens[k - 1];
            assert!(starts[k] <= prev_end, "дыра перед чанком {k}");
            let ov = prev_end - starts[k];
            let floor = chunk_cfg().overlap_floor(lens[k - 1]);
            assert!(ov >= floor, "перекрытие {ov} < грани {floor} на чанке {k}");
        }
    }

    #[test]
    fn checksum_spans_are_not_touched_by_chunk_dedup() {
        // Дедуп чанков живёт ДО слияния с каскадом 0 и чексумм не видит; на
        // слиянии (merge_disjoint конвейера) модельные близнецы из overlap-зоны
        // схлопнуты, вето живёт один раз и модель в его байты не лезет.
        let text = format!("{}2482014338 хвост.", sentences(200));
        let mut fake = FakeExtract::new(vec![("2482014338", 0.9)]);
        let model =
            extract_chunked(&text, chunk_cfg(), &mut fake.call(), &mut no_budget()).expect("окно");
        let abs = text.find("2482014338").unwrap();
        assert_eq!(model.len(), 1, "модельный близнец схлопнут");
        // Конвейер: детерминированный ИНН (вето 1.0) + дедупленний модельный.
        let tuples: Vec<(usize, usize, f64, bool)> = vec![
            (abs, abs + 10, 1.0, true),
            (
                model[0].byte_start,
                model[0].byte_end,
                model[0].score,
                false,
            ),
        ];
        let keep = merge_disjoint(&tuples);
        assert_eq!(keep, vec![0], "вето одно, модельный дубль байт вето снят");
    }

    #[test]
    fn decide_p2_is_max_over_chunks_single_chunk_is_identity() {
        // Агрегация p2 (max по чанкам) на одном чанке = дословно прежнее
        // число `arbitrate_text` (витрина §2 бит-в-бит на леге Decide):
        // max(0, p) = p для p ∈ [0,1], индексное соответствие — 1:1.
        for p in [0.31f32, 0.77] {
            let mut acc = 0.0f32;
            acc = acc.max(p);
            assert_eq!(acc, p, "идентичность на единственном чанке");
        }
        let mut acc = 0.0f32;
        for p in [0.31f32, 0.77, 0.44] {
            acc = acc.max(p);
        }
        assert_eq!(acc, 0.77, "FN фатален: лучшее свидетельство, не последнее");
    }

    #[test]
    fn startup_without_inference_is_refused_when_models_are_configured() {
        // Красный дискриминатор fail-open: `model_dir` есть, касать нечем.
        // Тест идёт в CI БЕЗ фичи (`just test`), и это ровно тот случай,
        // который раньше выглядел как «cascade-0+models» в /health.
        let cfg = Config::from_lookup(|k| (k == "FASAD_MODEL_DIR").then(|| "/tmp/w".to_owned()))
            .expect("конфиг читается");
        let r = startup(&cfg);
        #[cfg(feature = "ort-inference")]
        {
            // С фичей отказ обязан быть про сами веса (их в /tmp/w нет),
            // а не про сборку.
            assert!(
                matches!(r, Err(CascadeFailure::Load(_))),
                "ожидан Load с причиной, получено {r:?}"
            );
        }
        #[cfg(not(feature = "ort-inference"))]
        assert_eq!(
            r,
            Err(CascadeFailure::BuiltWithoutInference),
            "бинарь без ort не имеет права объявять cascade-0+models"
        );
    }

    #[test]
    fn startup_without_model_dir_is_cascade0() {
        let cfg = Config::from_lookup(&|_: &str| None).expect("дефолты sane");
        assert_eq!(startup(&cfg), Ok(()));
        assert_eq!(cfg.stage(), "cascade-0-only");
    }
}
