//! Чанкинг: окно 256–384 токена, overlap 32, length bucketing, B=1..4 на CPU.
//!
//! Контракт — SPEC §2 «Каскад 1» (чанкинг) и §10 п.4 (шаг 4); вторая конфигурация
//! окна для 512-моделей — SPEC §5.7 п.4 (448 токенов, stride 128).
//!
//! ```text
//! батчить 4096 токенов одним куском нельзя (O(L²) + padding waste)  [SPEC §2]
//! ```
//!
//! Отсюда два инвариантных требования к этому модулю: окно ограничено сверху
//! ([`WindowTokens::MIN`]..=[`WindowTokens::MAX`]), а хвосты разной длины собираются
//! в бакеты ([`bucket_len`], [`plan_batches`]) — attention платит квадратом за самое
//! длинное окно в батче, поэтому батчится одинаковое, а не всё подряд.
//!
//! ## Почему оценка токенов байтами, а не настоящим токенизатором
//!
//! Чанкер обязан уметь разбить текст ДО того, как в руки попал tokenizer-файл
//! модели: окно — свойство конфигурации, а не графа, и planning батчей происходит
//! на CPU-потоке демона. Настоящий tokenizer (`tokenizers` за фичей
//! `ort-inference`) дал бы точный счёт, но потянул бы загрузку 3.7 MiB / 8.3 MiB
//! vocabulary на каждый вызов. Поэтому длина измеряется [`approx_tokens`] —
//! консервативной оценкой, а точное число токенов считается позже, на этапе
//! инференса, где tokenizer уже в кэше.

use guard_types::ByteSpan;

/// Байт на токен — знаменатель оценки [`approx_tokens`].
///
/// `[claim-промер вне дерева]` (19.10): одноразовый расчёт вне дерева
/// (`uv run --no-project --with tokenizers`), вход — 200 текстов
/// `data/golden/golden-v1.jsonl`, 37 787 байт; tokenizer-файлы — две модели из
/// `models/manifest.md` (sha256 сверены там же, репозиторий `models/` в git).
///
/// | измерение | токенов | байт/токен |
/// |---|---|---|
/// | `lockR/rubert-base-pii-ner-onnx` (XLM-R), без спецтокенов | 7 740 | 4.88 |
/// | тот же, `add_special_tokens=True` (реальный вход модели) | 8 140 | 4.64 |
/// | `onnx-community/GLiNER2.5-Decide-ONNX` (GPT-2 BPE), без спецтокенов | 11 285 | 3.35 |
/// | тот же, со спецтокенами | 11 685 | 3.23 |
///
/// Взято **4.0** — середина между двумя живыми моделями каскада. Ошибка в обе
/// стороны симметрична и мала (−14 % на ruBERT, +19 % на `GLiNER`), а направление
/// каждой безопасно: оценка длины чанка в токенах `len/4.0` на ruBERT-ядре даёт
/// больше токенов, чем есть (окно режется раньше), на `GLiNER` — меньше (окно
/// режется позже); в обоих случаях окно остаётся внутри модельных 512, потому что
/// `ChunkCfg::new` не выпускает окно за `256..=384` байт-эквивалент.
///
/// Форма промера из ТЗ (`байты / (whitespace-словa × 1.3)`) на этом корпусе даёт
/// **9.09** — в 2.3 раза больше реальной BPE-длины: 1.3 subword'а на слово не
/// учитывает, что PII-числа (ИНН/СНИЛС/пан) режутся посимвольно, а кириллица в
/// XLM-R стоит 2–3 токена на слово. Формула записана как промер-артефакт и как
/// знаменатель НЕ используется; константа держится промером первички (AGENTS
/// §Дисциплина фактов п.1), а не транскриптом.
pub const BYTES_PER_TOKEN: f64 = 4.0;

/// Целочисленный спутник [`BYTES_PER_TOKEN`]: ровно 4, пока constant = 4.0.
///
/// Все байтовые вычисления (`window_bytes`, `overlap_floor_bytes`, деление в
/// [`approx_tokens`]) идут по нему, чтобы не ловить pedantic-линты приведения
/// f64↔usize. Инвариант `BYTES_PER_TOKEN_U == BYTES_PER_TOKEN as usize` держится
/// тестом `bytes_per_token_int_mirror`; смена константы на нецелую обязана
/// перепisać эти места на f64-путь (и обновить промер-док).
pub const BYTES_PER_TOKEN_U: usize = 4;

/// Перекрытие соседних окон в токенах (SPEC §2 «overlap 32»).
pub const OVERLAP_TOKENS: u32 = 32;

/// Нижняя граница окна (SPEC §2 «256–384 токена»).
pub const WINDOW_TOKENS_MIN: u32 = 256;

/// Верхняя граница окна (SPEC §2 «256–384 токена»).
pub const WINDOW_TOKENS_MAX: u32 = 384;

/// Окно конфигурации A: 384 токена (GLiNER-ветка SPEC §2).
pub const DEFAULT_WINDOW_TOKENS: u32 = WINDOW_TOKENS_MAX;

/// Окно конфигурации B: 448 токенов при модельном окне 512, stride 128
/// (SPEC §5.7 п.4, ruBERT-ветка).
pub const RUBERT_WINDOW_TOKENS: u32 = 448;

/// Stride конфигурации B (SPEC §5.7 п.4).
pub const RUBERT_STRIDE_TOKENS: u32 = 128;

/// Оценочное число токенов в строке: байты / [`BYTES_PER_TOKEN`], округление вверх.
///
/// Округление вверх — сознательное: недооценить длину значит попытаться запихнуть
/// в окно больше, чем он может вместить.
#[must_use]
pub fn approx_tokens(s: &str) -> u32 {
    // Деление целиком в целых: `len.div_ceil(BYTES_PER_TOKEN_U)`, без f64 и без
    // потери разряда. Равенство `BYTES_PER_TOKEN_U == BYTES_PER_TOKEN as usize`
    // держится тестом `bytes_per_token_int_mirror`; перепромер в нецелую константу
    // обязан перепisać этот путь на f64-ветку.
    let tokens = s.len().div_ceil(BYTES_PER_TOKEN_U);
    u32::try_from(tokens).unwrap_or(u32::MAX)
}

/// Конец предложения: ASCII `.`, `!`, `?` и пустая строка (`\n\n`).
/// `…` (U+2026) разделителем НЕ является — незавершённость, не конец (N7
/// ревью PR#21: док приведён к коду; тест `ellipsis_is_not_a_boundary`).
///
/// Возвращает байтовую позицию СРАЗУ после разделителя — туда и ставится рез,
/// чтобы точка осталась в левом окне (иначе её потеряет и то, и другое окно).
fn sentence_end_at(text: &str, i: usize) -> Option<usize> {
    match text.as_bytes()[i] {
        b'.' | b'!' | b'?' => Some(i + 1),
        _ => None,
    }
}

/// Позиции границ предложений в `text`: байты сразу после `.!?` и после `\n\n`.
fn sentence_boundaries(text: &str) -> Vec<usize> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if let Some(end) = sentence_end_at(text, i) {
            out.push(end.min(text.len()));
            i += 1;
            continue;
        }
        // Многоточие и перевод строки пакетом: режем после последовательности.
        if b[i] == b'\n' {
            let mut j = i;
            while j < b.len() && (b[j] == b'\n' || b[j] == b'\r') {
                j += 1;
            }
            if j - i >= 2 {
                out.push(j);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Ближайшая к `target` граница символа, не превосходящая `target`.
fn floor_char_boundary(text: &str, target: usize) -> usize {
    if target >= text.len() {
        return text.len();
    }
    let mut i = target;
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Ближайшая к `from` граница символа СТРОГО после `from` (гарантия прогресса).
fn next_char_boundary(text: &str, from: usize) -> usize {
    let mut i = from + 1;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i.min(text.len())
}

/// Байтовая цель, с которой начинается overlap-хвост предыдущего окна.
///
/// Инвариант SPEC: перекрытие меряется в токенах, а чанки живут в байтах, поэтому
/// `overlap_bytes` отнимается от края окна `start + window_bytes` (не от фактического
/// `end` — см. комментарий в [`chunk`]); конкретная точка старта опускается до
/// UTF-8-границы вызывающим ([`floor_char_boundary`]).
fn overlap_target(window_end: usize, overlap_bytes: usize) -> usize {
    window_end.saturating_sub(overlap_bytes)
}

/// Кусок текста, уходящий в каскад-1: спан в оригинале + оценочные токены.
///
/// `span` — в координатах исходного текста (не вырезки!): merger и vault работают
/// с оригиналом, смещение чанка теряется на первом же слиянии спанов (SPEC §2
/// каскад 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// Байтовый интервал в исходном тексте.
    pub span: ByteSpan,
    /// Оценка числа токенов до начала окна (для отчётов/трассировки).
    pub token_lo: u32,
    /// Оценка числа токенов в конце окна; `token_hi - token_lo` ≈ [`Chunk::n_tokens`].
    pub token_hi: u32,
}

impl Chunk {
    /// Оценка длины чанка в токенах ([`approx_tokens`] от его текста).
    #[must_use]
    pub fn n_tokens(&self, text: &str) -> u32 {
        approx_tokens(self.span.slice(text).unwrap_or(""))
    }
}

/// Окно чанкера в токенах — новыйtype с инвариантом `256..=384`.
///
/// Тип, а не голое `u32`, потому что контракт SPEC §2 запрещает окно вне
/// диапазона: `WindowTokens(4096)` компилировался бы и молча убивал бы память
/// демона квадратом attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowTokens(pub u32);

/// Причина, по которой конфигурация окна нелегальна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkCfgError {
    /// Окно вне `256..=384` (SPEC §2) — конфигурация B (448) собирается отдельно,
    /// [`ChunkCfg::rubert`].
    WindowOutOfRange {
        /// Переданное окно.
        got: u32,
        /// Разрешённый минимум.
        min: u32,
        /// Разрешённый максимум.
        max: u32,
    },
    /// `overlap == 0` или `overlap >= window` — окно не продвигалось бы вперёд.
    BadOverlap {
        /// Переданный overlap.
        overlap: u32,
        /// Переданное окно.
        window: u32,
    },
}

impl core::fmt::Display for ChunkCfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WindowOutOfRange { got, min, max } => {
                write!(f, "window {got} tokens outside {min}..={max}")
            }
            Self::BadOverlap { overlap, window } => {
                write!(f, "overlap {overlap} invalid for window {window}")
            }
        }
    }
}

impl std::error::Error for ChunkCfgError {}

/// Конфигурация чанкера.
///
/// [`Default`] — контракт SPEC §2 (окно 384, overlap 32, резы по предложениям);
/// [`ChunkCfg::rubert`] — контракт SPEC §5.7 п.4 (448/128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkCfg {
    /// Максимум токенов в окно, инвариант `256..=384`.
    pub window_tokens: WindowTokens,
    /// Перекрытие соседних окон в токенах (SPEC §2: 32).
    pub overlap_tokens: u32,
    /// Резать по границам предложений (`.!?`, `\n\n`). `false` — чистое окно со
    /// stride, для текстов без пунктуации (OCR-куски, логи).
    pub sentence_boundaries: bool,
}

/// Нижняя грань байтового перекрытия соседей для `overlap_tokens`.
///
/// Инвариант SPEC держится в **токенах**, а старт чанка — байт на UTF-8-границе:
/// [`floor_char_boundary`] опускает старт максимум на 3 байта (самый длинный код
/// минус 1), а guard строгого прогресса может отодвинуть его назад ещё на один
/// код — итого фактическое перекрытие ≥ `overlap·BYTES_PER_TOKEN − 4`.
/// Проверяется property-тестом на текстах с 4-байтовыми эмодзи.
#[must_use]
pub fn overlap_floor_bytes(overlap_tokens: u32) -> usize {
    let bytes = usize::try_from(overlap_tokens)
        .unwrap_or(usize::MAX)
        .saturating_mul(BYTES_PER_TOKEN_U);
    bytes.saturating_sub(BYTES_PER_TOKEN_U)
}

impl Default for ChunkCfg {
    fn default() -> Self {
        Self {
            window_tokens: WindowTokens(DEFAULT_WINDOW_TOKENS),
            overlap_tokens: OVERLAP_TOKENS,
            sentence_boundaries: true,
        }
    }
}

impl ChunkCfg {
    /// Собирает конфигурацию, проверяя инварианты окна SPEC §2.
    ///
    /// # Errors
    ///
    /// [`ChunkCfgError::WindowOutOfRange`] при окне вне `256..=384`,
    /// [`ChunkCfgError::BadOverlap`] при `overlap == 0` или `overlap >= window`.
    pub fn new(window_tokens: u32, overlap_tokens: u32) -> Result<Self, ChunkCfgError> {
        if !(WINDOW_TOKENS_MIN..=WINDOW_TOKENS_MAX).contains(&window_tokens) {
            return Err(ChunkCfgError::WindowOutOfRange {
                got: window_tokens,
                min: WINDOW_TOKENS_MIN,
                max: WINDOW_TOKENS_MAX,
            });
        }
        if overlap_tokens == 0 || overlap_tokens >= window_tokens {
            return Err(ChunkCfgError::BadOverlap {
                overlap: overlap_tokens,
                window: window_tokens,
            });
        }
        Ok(Self {
            window_tokens: WindowTokens(window_tokens),
            overlap_tokens,
            sentence_boundaries: true,
        })
    }

    /// Конфигурация B: окно 448 при модели 512, stride 128 (SPEC §5.7 п.4).
    ///
    /// Вне `256..=384` осознанно — §5.7 п.4 перерисовывает §2 для ruBERT-ветки;
    /// overlap здесь = stride = 128, что и даёт перекрытие 128 токенов.
    #[must_use]
    pub fn rubert() -> Self {
        Self {
            window_tokens: WindowTokens(RUBERT_WINDOW_TOKENS),
            overlap_tokens: RUBERT_STRIDE_TOKENS,
            sentence_boundaries: true,
        }
    }

    /// Байтовый эквивалент overlap'а этой конфигурации.
    #[must_use]
    pub fn overlap_bytes(&self) -> usize {
        window_bytes(self.overlap_tokens)
    }

    /// Гарантированная нижняя грань перекрытия соседей при длине предыдущего
    /// чанка `prev_span` байт.
    ///
    /// Инвариант SPEC («overlap 32») живёт в токенах и в **полном** окне; здесь
    /// два законных источника урезки, оба учтены:
    ///
    /// 1. старт следующего окна опускается до UTF-8-границы
    ///    ([`floor_char_boundary`]) — минус ≤ 3 байта, поэтому полная грань
    ///    `(overlap − 1) · BYTES_PER_TOKEN` (запас ровно в один токен);
    /// 2. предыдущее окно, обрезанное по границе предложения короче шага
    ///    overlap, не может отдать перекрытие больше собственного размера —
    ///    тогда грань `prev_span − 4` (guard строгого прогресса сдвигает старт
    ///    вперёд максимум на один UTF-8-код).
    #[must_use]
    pub fn overlap_floor(&self, prev_span: usize) -> usize {
        let full = overlap_floor_bytes(self.overlap_tokens);
        if prev_span >= self.overlap_bytes() {
            full
        } else {
            prev_span.saturating_sub(4).min(full)
        }
    }
}

/// Разбивает `text` на чанки по конфигурации `cfg`.
///
/// Алгоритм: жадный проход по окну; если [`ChunkCfg::sentence_boundaries`] и в
/// окне есть граница предложения, режем по последней такой границе (окно при этом
/// **не расширяется** за `window_tokens` — контракт SPEC, проверено тестом), иначе
/// режем по краю окна. Следующее окно начинается на `overlap_tokens` раньше конца
/// предыдущего.
///
/// Инварианты (каждый — отдельный тест):
///
/// 1. Покрытие: каждый байт `text` лежит хотя бы в одном чанке; пустой текст → пустой список.
/// 2. Монотонность: `span.start` неубывает.
/// 3. Перекрытие соседей ≥ `min(span_предыдущего, overlap_floor_bytes(cfg))` байт
///    (чанк, обрезанный по границе предложения короче окна, полного перекрытия
///    дать не может; грань helper'а учитывает округление к UTF-8-границе).
/// 4. Ни один чанк не длиннее окна + одного предложения-хвоста? — нет: длина
///    чанка ограничена сверху `window_tokens` по оценке (окно не расширяется).
///
/// Возвращает пустой вектор на пустом входе; текст короче окна — один чанк.
#[must_use]
pub fn chunk(text: &str, cfg: ChunkCfg) -> Vec<Chunk> {
    if text.is_empty() {
        return Vec::new();
    }
    let win_bytes = window_bytes(cfg.window_tokens.0);
    let ov_bytes = window_bytes(cfg.overlap_tokens);
    let bounds: Vec<usize> = if cfg.sentence_boundaries {
        sentence_boundaries(text)
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < text.len() {
        let hard_end = start.saturating_add(win_bytes).min(text.len());
        // Кандидат реза: граница предложения или край окна; обе ветки cut_at
        // возвращают законную UTF-8-границу, но `max(start + 1)` мог бы её
        // сдвинуть внутрь символа — поэтому минимальный прогресс clamp'им по
        // границе символа отдельно.
        let cand = cut_at(text, hard_end, start, &bounds);
        let end = if cand > start {
            cand
        } else {
            // Окно меньше одного символа: продвигаемся к следующей границе.
            next_char_boundary(text, start).min(text.len())
        };
        debug_assert!(
            text.is_char_boundary(start) && text.is_char_boundary(end),
            "chunker: start={start} end={end} hard={hard_end}"
        );
        let token_hi = approx_tokens(&text[..end]);
        let token_lo = approx_tokens(&text[..start]);
        if let Ok(span) = ByteSpan::new(text, start, end) {
            out.push(Chunk {
                span,
                token_lo,
                token_hi,
            });
        } else {
            // Граница не UTF-8 — откатываемся к силовой границе символа.
            let safe = floor_char_boundary(text, end).max(start + 1);
            if safe > start {
                let token_hi = approx_tokens(&text[..safe]);
                if let Ok(span) = ByteSpan::new(text, start, safe) {
                    out.push(Chunk {
                        span,
                        token_lo,
                        token_hi,
                    });
                }
            }
        }
        if end >= text.len() {
            break;
        }
        // Продвижение. Якорь — фактический `end` окна: перекрытие соседей меряется
        // от него (`prev_end − next_start`), поэтому `target = end − ov_bytes` и
        // старт опушен до UTF-8-границы: floor отодвигает старт НАЗАД (≤ 3 байта),
        // то есть перекрытие только РАСТЁТ относительно точного `ov_bytes`; грань
        // инварианта `(overlap − 1)·BYTES_PER_TOKEN` держится с запасом.
        let target = overlap_target(end, ov_bytes);
        let mut next = floor_char_boundary(text, target);
        if next <= start {
            // Окно короче overlap либо весь остаток — один символ: форсируем
            // прогресс по следующей границе символа, иначе цикл не завершится.
            next = next_char_boundary(text, start);
        }
        debug_assert!(text.is_char_boundary(next));
        start = next;
    }
    out
}

/// Байтовый эквивалент окна в `tokens` токенов (точное: знаменатель целой 4).
fn window_bytes(tokens: u32) -> usize {
    usize::try_from(tokens)
        .unwrap_or(usize::MAX)
        .saturating_mul(BYTES_PER_TOKEN_U)
}

/// Где резать: последняя граница предложения в `(start, hard_end]` или `hard_end`.
fn cut_at(text: &str, hard_end: usize, start: usize, bounds: &[usize]) -> usize {
    if bounds.is_empty() {
        return floor_char_boundary(text, hard_end);
    }
    // бинарный поиск: последняя граница предложения ≤ hard_end
    let hi = bounds.partition_point(|&p| p <= hard_end);
    if hi == 0 {
        return floor_char_boundary(text, hard_end);
    }
    // Границы `bounds` подняты по UTF-8-безопасным позициям (`.!?`+1, `\n`-прогон),
    // но hard_end-фолбэк обязан быть зафлорен — режем ровно по найденной границе.
    bounds[..hi]
        .iter()
        .rev()
        .copied()
        .find(|&p| p > start)
        .unwrap_or_else(|| floor_char_boundary(text, hard_end))
}

/// Бакет по длине: сортированный вверх список границ.
///
/// Дефолт `[128, 256, 384]` — спеку SPEC §2 «length bucketing»: бакет 128 ловит
/// короткие реплики чата (их большинство), 256 — середину, 384 — потолок окна A.
/// Бакет ≠ окно: чанк в 300 токенов попадает в бакет 384 и паддчится до 384, а не
/// до 300, зато весь батч платит за одно и то же.
pub const DEFAULT_BUCKETS: [u32; 3] = [128, 256, 384];

/// Номер бакета для длины `tokens`: первый бакет ≥ `tokens`, иначе — последний.
///
/// Возвращает индекс в слайсе `buckets` (вызывающий знает его содержимое), а не
/// саму границу: caller'у нужен и индекс, и значение.
#[must_use]
pub fn bucket_len(buckets: &[u32], tokens: u32) -> usize {
    buckets
        .partition_point(|&b| b < tokens)
        .min(buckets.len() - 1)
}

/// Длина паддинга батча: граница бакета, в который попал самый длинный чанк.
#[must_use]
pub fn pad_len(buckets: &[u32], longest_tokens: u32) -> u32 {
    buckets[bucket_len(buckets, longest_tokens)]
}

/// Батч: индекс бакета + индексы чанков (в `&[Chunk]`), не более `b_max`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// Индекс бакета в списке границ.
    pub bucket: usize,
    /// Граница бакета в токенах (для паддинга).
    pub bucket_tokens: u32,
    /// Индексы чанков в исходном слайсе, в порядке входа.
    pub indices: Vec<usize>,
}

impl Batch {
    /// Число последовательностей в батче (`B`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Пустой ли батч (бывает после фильтрации, в `plan_batches` — нет).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
}

/// Грейдировая разбивка чанков на батчи: по бакетам, `B ≤ b_max`, стабильно.
///
/// «Стабильно»: порядок чанков внутри бакета = порядок входа (никакой сортировки —
/// иначе батч-план зависит от адреса памяти и разрушает детерминизм golden-прогона).
/// Бакеты обходятся по возрастанию, внутри бакета батчи режутся по `b_max` слева
/// направо.
#[must_use]
pub fn plan_batches(chunks: &[Chunk], b_max: usize, buckets: &[u32]) -> Vec<Batch> {
    plan_batches_with(chunks, b_max, buckets, |c| {
        c.token_hi.saturating_sub(c.token_lo)
    })
}

/// То же, но с измерителем длины (для чанков, у кого длина известна иначе, чем из
/// `token_hi - token_lo`).
#[must_use]
pub fn plan_batches_with(
    chunks: &[Chunk],
    b_max: usize,
    buckets: &[u32],
    mut len_of: impl FnMut(&Chunk) -> u32,
) -> Vec<Batch> {
    if b_max == 0 || buckets.is_empty() {
        return Vec::new();
    }
    let nb = buckets.len();
    let mut groups: Vec<Vec<usize>> = vec![Vec::new(); nb];
    for (i, c) in chunks.iter().enumerate() {
        groups[bucket_len(buckets, len_of(c))].push(i);
    }
    let mut out = Vec::new();
    for (b, idxs) in groups.into_iter().enumerate() {
        for part in idxs.chunks(b_max) {
            out.push(Batch {
                bucket: b,
                bucket_tokens: buckets[b],
                indices: part.to_vec(),
            });
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::err_expect)] // в тестах паника = канал ответа
mod tests {
    use super::*;

    /// Помощник: собирает текст из `n` предложений вида «Предложение номер K.»
    fn sentences(n: usize) -> String {
        let mut s = String::new();
        for i in 1..=n {
            use std::fmt::Write as _;
            let _ = writeln!(s, "Предложение номер {i} содержит ровно семь слов тут.");
        }
        s
    }

    #[test]
    fn bytes_per_token_int_mirror() {
        // Целочисленный путь (`approx_tokens`, `window_bytes`) законен, пока
        // f64-константа промера ровно целая и равна спутнику. Смена промера на
        // нецелое значение роняет этот тест — сигнал перепisać ветку на f64.
        assert!(
            (BYTES_PER_TOKEN - f64::from(u32::try_from(BYTES_PER_TOKEN_U).unwrap_or(u32::MAX)))
                .abs()
                < f64::EPSILON,
            "BYTES_PER_TOKEN_U рассинхронизирован с промером"
        );
        assert_eq!(BYTES_PER_TOKEN.total_cmp(&4.0), core::cmp::Ordering::Equal);
    }

    #[test]
    fn approx_tokens_rounds_up_and_zero_is_zero() {
        assert_eq!(approx_tokens(""), 0);
        // 4 байта = ровно 1 токен; 5 байт = ceil(1.25) = 2
        assert_eq!(approx_tokens("abcd"), 1);
        assert_eq!(approx_tokens("abcde"), 2);
        // кириллица: 2 байта/символ → «восемь симв» = 10 симв + пробел = 21 байт = 6 токенов
        assert_eq!(approx_tokens("восемь симв"), 6);
    }

    #[test]
    fn cfg_default_matches_spec_and_validates_range() {
        let d = ChunkCfg::default();
        assert_eq!(d.window_tokens, WindowTokens(384));
        assert_eq!(d.overlap_tokens, OVERLAP_TOKENS);
        assert!(d.sentence_boundaries);
        assert!(ChunkCfg::new(256, 32).is_ok());
        assert!(ChunkCfg::new(384, 32).is_ok());
        assert_eq!(
            ChunkCfg::new(385, 32),
            Err(ChunkCfgError::WindowOutOfRange {
                got: 385,
                min: 256,
                max: 384
            })
        );
        assert_eq!(
            ChunkCfg::new(255, 32),
            Err(ChunkCfgError::WindowOutOfRange {
                got: 255,
                min: 256,
                max: 384
            })
        );
        assert!(matches!(
            ChunkCfg::new(384, 0),
            Err(ChunkCfgError::BadOverlap { .. })
        ));
    }

    #[test]
    fn window_tokens_rejects_out_of_range() {
        // N5 (ревью PR#21): конструктор кричит на выход за SPEC §2; поле pub
        // — осознанный escape-hatch для property-генератора (док WindowTokens).
        assert!(ChunkCfg::new(9999, 32).is_err(), "9999 вне 256..=384");
        assert!(ChunkCfg::new(255, 32).is_err(), "255 вне диапазона");
        assert!(ChunkCfg::new(256, 32).is_ok());
        assert!(ChunkCfg::new(384, 32).is_ok());
        assert_eq!(ChunkCfg::rubert().window_tokens.0, 448);
    }

    #[test]
    fn ellipsis_is_not_a_boundary() {
        // N7 (ревью PR#21): `…` НЕ разделитель предложений. Коварный кейс
        // был в первой редакции теста: «a…»×400, hard_end=1536 припадает
        // РОВНО на конец U+2026 (1536 % 4 == 0) — фолбэк по краю окна
        // совпадает с концом многоточия (совпадение по модулю, не «рез по …»).
        // Фикстура ниже различает: юнит 7 байт «a…b. », 1536 % 7 = 6 ⇒ край
        // окна никогда не кратен юниту, рез идёт по ASCII-точке; ни один
        // внутренний край спана не стоит на хвосте «…».
        let unit = "a…b. ";
        debug_assert_eq!(unit.len(), 7, "промер фикстуры");
        let t = unit.repeat(300); // 2100 байт > окна 1536
        let cs = chunk(&t, ChunkCfg::default());
        assert!(cs.len() >= 2, "текст длиннее окна обязан резаться");
        for c in &cs {
            let e = c.span.end;
            assert!(t.is_char_boundary(e), "рез {e} внутрь символа");
            if e >= t.len() || e < 3 {
                continue;
            }
            assert!(
                &t.as_bytes()[e - 3..e] != [0xE2, 0x80, 0xA6].as_slice(),
                "рез на байте {e} = конец «…» — многоточие не граница"
            );
        }
    }

    #[test]
    fn empty_text_yields_no_chunks() {
        let chunks = chunk("", ChunkCfg::default());
        assert!(chunks.is_empty(), "пустой вход дал чанки: {chunks:?}");
    }

    #[test]
    fn short_text_is_single_chunk_and_covers_everything() {
        let t = "Привет, мир.";
        let cs = chunk(t, ChunkCfg::default());
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].span.start, 0);
        assert_eq!(cs[0].span.end, t.len());
    }

    #[test]
    fn coverage_and_monotonic_start_on_long_ru_text() {
        let t = sentences(120);
        let cs = chunk(&t, ChunkCfg::default());
        assert!(cs.len() > 3, "окно 384 должно резать длинный текст");
        // покрытие: union == [0, len)
        assert_eq!(cs[0].span.start, 0);
        assert_eq!(cs.last().unwrap().span.end, t.len());
        for w in cs.windows(2) {
            assert!(w[1].span.start >= w[0].span.start, "start не убывает");
            assert!(
                w[1].span.start <= w[0].span.end,
                "дыра между чанками {}..{}",
                w[0].span.end,
                w[1].span.start
            );
        }
    }

    #[test]
    fn overlap_at_least_overlap_minus_one_bytes() {
        let t = sentences(200);
        let cfg = ChunkCfg::new(256, 32).unwrap();
        for w in chunk(&t, cfg).windows(2) {
            let prev_span = w[0].span.byte_len();
            let ov = w[0].span.end.saturating_sub(w[1].span.start);
            let floor = cfg.overlap_floor(prev_span);
            assert!(
                ov >= floor,
                "перекрытие {ov} Б < {floor} Б (span {prev_span}): {:?} {:?}",
                w[0].span,
                w[1].span
            );
        }
    }

    #[test]
    fn tail_500_chars_bounded_chunks() {
        // Ревью PR#21 N1 — ЗАМЕР поведения (редизайн хвостов = issue #3).
        // Фикстура-дегенерат: 1159 точек + перевод строки + хвост ≤1000.
        // Жадный leftmost-cut режет по ПЕРВОЙ точке ⇒ шаг 1 байт, ~1160
        // чанков = ОДИН чанк на байт: линейно по in_len (adversarial
        // 256→1024 ревьюера = 132→136 — квадратичного blow-up нет).
        // Сторожим: линейность (≤ len), целое покрытие, монотонность
        // стартов; всплеск сверх len = регрессия.
        let base = ".".repeat(1159);
        for tail in [1usize, 100, 499, 500, 501, 1000] {
            let t = format!("{base}\n{}", "x".repeat(tail));
            let cs = chunk(&t, ChunkCfg::default());
            assert!(
                cs.len() <= t.len(),
                "tail={tail}: сверхлинейный всплеск {} чанков на {} Б",
                cs.len(),
                t.len()
            );
            assert_eq!(
                cs.last().unwrap().span.end,
                t.len(),
                "tail={tail}: покрытие"
            );
            for w in cs.windows(2) {
                assert!(w[0].span.start < w[1].span.start, "tail={tail}: старты");
            }
        }
    }

    #[test]
    fn window_never_expands_beyond_cfg() {
        let t = sentences(300);
        let cfg = ChunkCfg::new(256, 32).unwrap();
        let win_bytes = 256 * 4;
        for c in &chunk(&t, cfg) {
            // Длина чанка в байтах ≤ окно (окно не расширяется): реальный контракт,
            // `token_hi − token_lo` не используем — ceil байтов/4 не аддитивен на
            // префиксах, и это завысило бы «длину» на 1 токен (промерено).
            assert!(
                c.span.byte_len() <= win_bytes,
                "чанк {} Б > окна {win_bytes} Б",
                c.span.byte_len()
            );
            assert!(
                c.n_tokens(&t) <= 256,
                "чанк {} токенов > окна",
                c.n_tokens(&t)
            );
        }
    }

    #[test]
    fn ru_sentence_boundaries_are_cut_on() {
        // «…конечные! Следующее?» — рез обязан попасть сразу после «!»/«?».
        let t = "Первое предложение тут. Второе кончается! Третье заканчивается? И четвёртое.";
        let cfg = ChunkCfg {
            window_tokens: WindowTokens(256),
            overlap_tokens: 32,
            sentence_boundaries: true,
        };
        // Принудительно маленькое «окно» невозможно по типу, поэтому режем длинный
        // текст из одинаковых предложений и проверяем, что конец чанка — после `.!?`.
        let long = "Абзац один. Абзац два! Абзац три? Абзац четыре.\n\n".repeat(200);
        let cs = chunk(&long, cfg);
        assert!(cs.len() > 2);
        for c in &cs[..cs.len() - 1] {
            let end = c.span.end;
            let prev = long.as_bytes().get(end.saturating_sub(1)).copied();
            let is_sent_end = matches!(prev, Some(b'.' | b'!' | b'?'));
            let is_par_end = long[..end].ends_with("\n\n");
            assert!(
                is_sent_end || is_par_end,
                "рез внутри предложения, байт перед концом: {prev:?}"
            );
        }
        // короткий текст одним куском — границы не важны
        assert_eq!(chunk(t, cfg).len(), 1);
    }

    #[test]
    fn no_sentence_boundaries_mode_cuts_on_window() {
        let long = "слов ";
        let t = long.repeat(500); // 2500 байт ≈ 625 токенов > 384
        let cfg = ChunkCfg {
            sentence_boundaries: false,
            ..ChunkCfg::default()
        };
        let cs = chunk(&t, cfg);
        assert!(cs.len() >= 3);
        // резы строго на границе бакета байт (без привязки к пробелу)
        assert_eq!(cs[0].span.end, window_bytes(384));
    }

    #[test]
    fn chunks_are_char_boundary_safe_on_emoji() {
        let t = format!("{}😀{}🧨", "д".repeat(1000), "и".repeat(1000));
        let cs = chunk(&t, ChunkCfg::default());
        for c in &cs {
            assert!(t.is_char_boundary(c.span.start) && t.is_char_boundary(c.span.end));
            assert!(c.span.slice(&t).is_some());
        }
    }

    #[test]
    fn rubert_cfg_448_128_produces_overlap() {
        let t = sentences(400);
        let cfg = ChunkCfg::rubert();
        assert_eq!(cfg.window_tokens.0, 448);
        assert_eq!(cfg.overlap_tokens, 128);
        let cs = chunk(&t, cfg);
        for w in cs.windows(2) {
            let ov = w[0].span.end - w[1].span.start;
            let floor = cfg.overlap_floor(w[0].span.byte_len());
            assert!(ov >= floor, "ruBERT overlap {ov} мал (floor {floor})");
        }
        for c in &cs {
            assert!(c.n_tokens(&t) <= 448);
        }
    }

    #[test]
    fn bucket_boundaries_127_128_129_255_256_384_385() {
        let b = DEFAULT_BUCKETS;
        assert_eq!(bucket_len(&b, 0), 0);
        assert_eq!(bucket_len(&b, 1), 0);
        assert_eq!(bucket_len(&b, 127), 0);
        assert_eq!(bucket_len(&b, 128), 0); // первый ≥ t
        assert_eq!(bucket_len(&b, 129), 1);
        assert_eq!(bucket_len(&b, 255), 1);
        assert_eq!(bucket_len(&b, 256), 1);
        assert_eq!(bucket_len(&b, 257), 2);
        assert_eq!(bucket_len(&b, 384), 2);
        assert_eq!(bucket_len(&b, 385), 2); // > max → clamp в последний
        assert_eq!(bucket_len(&b, u32::MAX), 2);
        assert_eq!(pad_len(&b, 129), 256);
        assert_eq!(pad_len(&b, 9999), 384);
    }

    #[test]
    fn plan_batches_respects_bmax_and_is_stable() {
        // 9 чанков: 3 коротких (бакет 128), 3 средних (256), 3 длинных (384)
        let mk = |n: u32| Chunk {
            span: ByteSpan::new("abcd", 0, 4).unwrap(),
            token_lo: 0,
            token_hi: n,
        };
        let cs = vec![
            mk(100),
            mk(120),
            mk(50),
            mk(200),
            mk(256),
            mk(130),
            mk(300),
            mk(384),
            mk(400), // > 384 → последний бакет
        ];
        let bs = plan_batches(&cs, 4, &DEFAULT_BUCKETS);
        assert!(!bs.iter().any(|b| b.len() > 4));
        // бакеты по возрастанию
        assert!(bs.windows(2).all(|w| w[0].bucket <= w[1].bucket));
        // стабильность: внутри бакета индексы растут (порядок входа)
        for b in &bs {
            assert!(b.indices.windows(2).all(|w| w[0] < w[1]));
        }
        let all: Vec<usize> = bs.iter().flat_map(|b| b.indices.clone()).collect();
        assert_eq!(all.len(), cs.len());
        let mut sorted = all.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..cs.len()).collect::<Vec<_>>());
        // 100,120,50 → бакет 0 (3 шт, один батч); 200,256,130 → бакет 1; 300,384,400 → бакет 2
        assert_eq!(bs.len(), 3);
        assert_eq!(bs[0].indices, vec![0, 1, 2]);
        assert_eq!(bs[0].bucket_tokens, 128);
        assert_eq!(bs[2].bucket_tokens, 384);
    }

    #[test]
    fn plan_batches_bmax_1_splits_everything() {
        let mk = |n: u32| Chunk {
            span: ByteSpan::new("abcd", 0, 4).unwrap(),
            token_lo: 0,
            token_hi: n,
        };
        let cs: Vec<Chunk> = (0..6).map(|i| mk(i * 60)).collect();
        let bs = plan_batches(&cs, 1, &DEFAULT_BUCKETS);
        assert_eq!(bs.len(), 6);
        assert!(bs.iter().all(|b| b.len() == 1));
    }

    #[test]
    fn plan_batches_degenerate_bmax_and_empty_chunks() {
        let plan = plan_batches(&[], 4, &DEFAULT_BUCKETS);
        assert!(plan.is_empty(), "пустой вход дал батчи: {plan:?}");
        let c = Chunk {
            span: ByteSpan::new("ab", 0, 2).unwrap(),
            token_lo: 0,
            token_hi: 1,
        };
        let plan = plan_batches(&[c], 0, &DEFAULT_BUCKETS);
        assert!(plan.is_empty(), "b_max=0 дал батчи: {plan:?}");
    }
}
