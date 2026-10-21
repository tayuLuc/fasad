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
//! # Что сознательно НЕ закрыто этим атомом
//!
//! 1. **Окно lockR = 256 токенов.** Харнес его игнорирует (golden-строки
//!    короче), продукт обязан отказывать: текст, не влезший в окно, — это
//!    «часть текста не просмотрена», а значит «часть `ПДн` может уйти
//!    наружу» → [`CascadeFailure::Truncated`] → 502. Чанкирование lockR
//!    (SPEC §2: чанки 256–384 с перекрытием 32) — отдельный атом, issue #14B.
//! 2. **Каскад 2 не даёт координат.** Decide отвечает «есть ли класс в тексте»
//!    (row-level, issue #41), спанов у него нет, поэтому в продукте он может
//!    только **перескорить** спан каскада 1, но не добавить новый. Набор
//!    спанов продукта = каскад 0 ∪ каскад 1, и парность мерится против
//!    «строгой» меры харнеса (без row-level кредита Decide).
//! 3. **`α` не калибрована.** SPEC §2 даёт формулу `S = α·p1 + (1−α)·p2` без
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
                "текст длиннее окна экстрактора ({window} токенов): каскад 1 видел не весь текст"
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
/// SPEC §2 на таком `n` добавит только кода. Сверху `n` держит то же окно;
/// дерево понадобится вместе с чанками (issue #14B).
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

    use guard_onnx::arbitrate::{DecideArbiter, QuestionSchema};
    use guard_onnx::extract::{LockrExtractor, PAD};
    use guard_onnx::routing::RoutingCfg;
    use guard_types::DetectionSource;
    use zeroize::Zeroizing;

    use super::{
        Cascade2, Cascade12, CascadeCtx, CascadeFailure, ModelSpan, Outcome, Plan, QUEUE_DEPTH,
        apply_arbiter, grey_classes,
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

    /// Одна задача: каскад 1 → (только при серой зоне) каскад 2.
    fn run(
        lockr: &mut LockrExtractor,
        arb: &mut DecideArbiter,
        job: &Job,
    ) -> Result<Outcome, CascadeFailure> {
        let started = Instant::now();
        let ex = lockr
            .extract(&job.text)
            .map_err(|e| CascadeFailure::Inference(format!("lockR: {e}")))?;
        if ex.truncated {
            return Err(CascadeFailure::Truncated { window: PAD });
        }
        // Порог каскада 1 — тем же lib-гейтом, что у харнеса (7b), а не
        // локальным сравнением: два сравнения с τ расходятся при первой правке.
        let routing = RoutingCfg::single(job.plan.tau);
        let mut spans: Vec<ModelSpan> = Vec::new();
        for s in &ex.spans {
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
        // Каскад 2, short-circuit (SPEC §2): ни одного спана серой зоны —
        // Decide не зовём вообще. Его латентность O(L²) (промер 5963 мс при
        // L=1235, docs/model-audit.md), и гонять её на каждом запросе =
        // гарантированно вылетать из FASAD_TIMEOUT_MS на ровном месте.
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
        let answers: Vec<Vec<&str>> = asked
            .iter()
            .map(|(_, _, a)| a.iter().map(String::as_str).collect())
            .collect();
        let qs: Vec<QuestionSchema<'_>> = asked
            .iter()
            .zip(&answers)
            .map(|((_, q, _), a)| (q.as_str(), a.as_slice()))
            .collect();
        // τ в `arbitrate_text` — f32 (сигнатура либы): шаг f32 ≈ 6e-8 на
        // порядок меньше шага сетки порогов (0.05), а τ приходит из конфига,
        // где он провалидирован в [0, 1].
        #[allow(
            clippy::cast_possible_truncation,
            reason = "τ ∈ [0,1], шаг f32 незаметен на сетке 0.05"
        )]
        let tau = job.plan.tau as f32;
        let mut cascade2 = Cascade2::Ok;
        let ds = match arb.arbitrate_text(&job.text, &qs, tau) {
            Ok(ds) => ds,
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
            // `VocabMismatch`, `Tokenizer`, …) — настоящий сбой: 502.
            Err(e) if super::decide_degrades(&e) => {
                // В лог — только причина арбитра, без текста запроса (AGENTS).
                eprintln!("fasad: каскад 2 пропущен для этого входа: {e}");
                cascade2 = Cascade2::Skipped;
                Vec::new()
            }
            Err(e) => return Err(CascadeFailure::Inference(format!("decide: {e}"))),
        };
        if !ds.is_empty() && ds.len() != asked.len() {
            // Индексное соответствие «вопрос → ответ» — единственный способ
            // не перепутать классы: совпадение по тексту вопроса молча сливает
            // дубликаты. Расхождение длин = контракт сломан, не угадываем.
            return Err(CascadeFailure::Inference(format!(
                "decide вернул {} ответов на {} вопросов",
                ds.len(),
                asked.len()
            )));
        }
        let p2: Vec<(String, f64)> = asked
            .iter()
            .zip(&ds)
            .map(|((id, _, _), d)| (id.clone(), f64::from(d.prob)))
            .collect();
        apply_arbiter(&mut spans, &p2, &job.ctx, &job.plan);
        Ok(Outcome { spans, cascade2 })
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
