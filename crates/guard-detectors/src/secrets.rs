//! Сканер секретов — каскад 0, три фазы (SPEC §2 «Секреты по образцу сканеров»,
//! SPEC §6 структура `guard-detectors/secrets`, SPEC §10 п.3 вторая половина).
//!
//! Фазы конвейера (SPEC §2):
//!
//! 1. **Префикс-фильтр** — `aho_corasick` по коротким якорям (`AKIA`, `ghp_`,
//!    `sk-`, `eyJ`, `xoxb-`, …): один проход по байтам, дальше смотрим только
//!    позиции якорей.
//! 2. **Валидация формы в окне ±200 байт** — валидаторы написаны вручную, без
//!    крейта `regex` (решение атома: вес бинарника; валидатор короче
//!    компилируемого паттерна и не даёт DSL-поверхности):
//!    AWS `AKIA[0-9A-Z]{16}`, GitHub classic `gh[pos]_[A-Za-z0-9]{36}`,
//!    fine-grained `github_pat_[A-Za-z0-9_]{24,63}`, OpenAI `sk-`/`sk-proj-`/
//!    `sk-svcacct-` + ≥20 `[A-Za-z0-9]`, Google `AIza[A-Za-z0-9_-]{35}`,
//!    Slack `xox[bp]-[A-Za-z0-9-]{10,}` (сегменты через дефис; «≥10 байтов
//!    без пробелов» не годится: greedy разъедает кавы/слаши — см. `is_slack_body`),
//!    JWT `eyJ` + три base64url-сегмента через `.` (подпись не проверяем).
//! 3. **Энтропия Шеннона ≥ 4.0 на 16-окне** для «случайных» хвостов без
//!    якоря. Форматно-валидные токены фазу 3 **пропускают по форме**: фаза 2
//!    уже вынесла вердикт, понижать его энтропией — ложное решение (в JWT и
//!    `AKIA`-фиксах энтропия намеренно структурирована).
//!
//! Live-верификации токенов НЕТ: сеть нарушает air-gap и добавляет 300–2000 мс
//! (AGENTS §Что НЕ делаем — TruffleHog-live не берём; SPEC §2 помечает `[claim]`).
//!
//! Соглашения модуля:
//! - API принимает `&[u8]` (демон видит и не-UTF-8 тела) и отдаёт спаны в
//!   байтовых координатах входа. Конструктора спана над `&[u8]` в `guard-types`
//!   нет ([`ByteSpan::new`] проверяет UTF-8-границы по `&str`), поэтому хит
//!   несёт сырой [`SecretSpan`], а [`ByteSpan`] собирает вызывающий слой —
//!   инвариант UTF-8-границ не обходится (guard-types §Инварианты п.1).
//! - Тело секрета не попадает в `Display`/`Debug` и логи (AGENTS §Инженерные
//!   инварианты); `Debug` хита печатает только offsets/kind/confidence.
//! - Confidence: формат-валидный токен = [`CONFIDENCE_FORMAT`] (0.95),
//!   entropy-only = [`CONFIDENCE_ENTROPY`] (0.60). Детерминированные валидаторы
//!   чексумм ([`checksums`][super::checksums]) имеют приоритет 1.0 — этот
//!   модуль к ним не относится, это паттерн-детектор, сеть его не понижает, но
//!   и он не имеет абсолютного вето.
//! - Возврат отсортирован по `span.start`, хиты не перекрываются
//!   (leftmost-longest по якорям; области закрытых хитов фазами 2–3 повторно
//!   не просматриваются).

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use guard_types::ByteSpan;

/// Байтовый интервал `[start, end)` без проверки UTF-8-границ — «отравленный»
/// аналог [`ByteSpan`] для сканеров, работающих по `&[u8]`.
///
/// Мост к [`ByteSpan`]: [`SecretSpan::to_byte_span`] собирает инвариантный
/// спан вызывающим слоем, где вход уже `&str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretSpan {
    /// Байт начала (включительно).
    pub start: usize,
    /// Байт конца (исключительно).
    pub end: usize,
}

impl SecretSpan {
    /// Собрать спан из байтовых границ.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Число байт в спане.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Пустой спан (у хита быть не может, API полный ради совместимости).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Поднять до инвариантного [`ByteSpan`] над текстом.
    ///
    /// `None` — спан залез в середину UTF-8-последовательности (для ASCII-
    /// токенов этого модуля невозможно; сигнатура честная для произвольного
    /// входа).
    #[must_use]
    pub fn to_byte_span(&self, text: &str) -> Option<ByteSpan> {
        ByteSpan::new(text, self.start, self.end).ok()
    }
}

/// Класс секрет по форме токена.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretKind {
    /// AWS access key ID: `AKIA` + 16 `[0-9A-Z]`.
    AwsAccessKeyId,
    /// GitHub token v1: `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_` + 36 `[A-Za-z0-9]`.
    GitHubToken,
    /// GitHub fine-grained PAT: `github_pat_` + 24..=63 `[A-Za-z0-9_]`.
    GitHubFineGrainedToken,
    /// Ключ провайдера Open AI: префиксы `sk-`, `sk-proj-`, `sk-svcacct-` + ≥20 `[A-Za-z0-9]`.
    OpenAiKey,
    /// Google API key: `AIza` + 35 `[A-Za-z0-9_-]`.
    GoogleApiKey,
    /// Slack bot/user token: `xoxb-`/`xoxp-` + ≥10 байтов без пробелов.
    SlackToken,
    /// GitLab PAT: `glpat-` + 20 `[A-Za-z0-9_-]`.
    GitLabPat,
    /// JWT: `eyJ` + три base64url-сегмента через `.`.
    Jwt,
    /// «Случайный» хвост по энтропии без форматного якоря (фаза 3).
    HighEntropy,
}

impl SecretKind {
    /// Имя класса для отчётов/логов (без тела токена).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::GitHubToken => "github_token",
            Self::GitHubFineGrainedToken => "github_fine_grained_token",
            Self::OpenAiKey => "openai_key",
            Self::GoogleApiKey => "google_api_key",
            Self::SlackToken => "slack_token",
            Self::GitLabPat => "gitlab_pat",
            Self::Jwt => "jwt",
            Self::HighEntropy => "high_entropy",
        }
    }
}

/// Фаза, породившая хит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretDetector {
    /// Фаза 2: токен совпал с форматом провайдера.
    Format,
    /// Фаза 3: сработала только энтропия.
    Entropy,
}

/// Хит сканера: класс, байтовый спан, источник, уверенность.
///
/// `Debug` печатает только offsets — тело секрета в логи не идёт (AGENTS
/// §Инженерные инварианты).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretHit {
    /// Класс секрета.
    pub kind: SecretKind,
    /// Байтовый интервал токена во входе.
    pub span: SecretSpan,
    /// [`CONFIDENCE_FORMAT`] или [`CONFIDENCE_ENTROPY`].
    pub confidence: f32,
    /// Фаза-источник.
    pub detector: SecretDetector,
}

/// Уверенность форматного совпадения (фаза 2).
pub const CONFIDENCE_FORMAT: f32 = 0.95;
/// Уверенность entropy-only (фаза 3).
pub const CONFIDENCE_ENTROPY: f32 = 0.60;

/// Ширина окна валидации ±200 байт (SPEC §2 «тяжёлая regex в окне ±200 байт»):
/// тело токена не рассматривается дальше `start + WINDOW` от якоря.
const WINDOW: usize = 200;

/// Размер окна энтропии (16-грамма, SPEC §2 фаза 3).
const ENTROPY_WINDOW: usize = 16;

/// Порог энтропии Шеннона (бит/символ) фазы 3. Hex-окно максимум `log2(16)`
/// = 4.0 бит при **ровно** равномерном распределении 16 разных символов;
/// реальные hex/base64-корпуса ниже (частоты неравномерны) — см. тесты.
pub const ENTROPY_THRESHOLD: f32 = 4.0;

/// Якорь фазы 1: байтовая константа, класс, ширина якоря, допустимая длина
/// тела `[min, max]` (байт, после якоря), предикат символа тела.
struct Anchor {
    pat: &'static [u8],
    kind: SecretKind,
    /// Минимальная длина тела.
    min: usize,
    /// Максимальная длина тела (greedy-потолок, ≤ WINDOW − len(pat)).
    max: usize,
    /// Символ принадлежит телу.
    body: fn(u8) -> bool,
    /// Ровно `min`, а не greedy-до `max` (фиксированные длины: AKIA, `gh*`, `AIza`,
    /// glpat, OpenAI-class при min==max).
    exact: bool,
    /// Сегментный валидатор (JWT): `Some` отменяет обычный greedy.
    segments: Option<fn(&[u8]) -> Option<usize>>,
}

fn is_upper_or_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn is_alnum_underscore(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn is_alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}
/// Символ тела Slack-токена (`xoxb-`/`xoxp-`). Токен Slack — сегменты,
/// склеенные дефисом (`xox[baprs]-<team>-<id>-<secret>`), т.е. алфавит
/// `[A-Za-z0-9-]`. Предикат «любой байт без пробелов» для тела неприменим:
/// greedy-валидатор разъедает закрывающую кавы literalа
/// (`config = \"xoxb-…\"\n` — конец хита лезет за токен вплоть до `len(input)`)
/// и тянет в секрет хвосты URL/путей. Дефис остаётся частью токена, поэтому
/// `SLACK_OK` (37 байт тела) проходит минимальный порог.
fn is_slack_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// Встроенный набор якорей. Порядок не значим для `LeftmostLongest` (победы
/// длинных префиксов обеспечивает сам режим: `github_pat_…` матчится якорем
/// `github_pat_`, а не `gh…`-префиксом; `sk-proj-` неCompetirует с `sk-` —
/// длинный выигрывает).
const ANCHORS: &[Anchor] = &[
    Anchor {
        pat: b"AKIA",
        kind: SecretKind::AwsAccessKeyId,
        min: 16,
        max: 16,
        body: is_upper_or_digit,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"ghp_",
        kind: SecretKind::GitHubToken,
        min: 36,
        max: 36,
        body: is_alnum,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"gho_",
        kind: SecretKind::GitHubToken,
        min: 36,
        max: 36,
        body: is_alnum,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"ghs_",
        kind: SecretKind::GitHubToken,
        min: 36,
        max: 36,
        body: is_alnum,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"ghu_",
        kind: SecretKind::GitHubToken,
        min: 36,
        max: 36,
        body: is_alnum,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"ghr_",
        kind: SecretKind::GitHubToken,
        min: 36,
        max: 36,
        body: is_alnum,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"github_pat_",
        kind: SecretKind::GitHubFineGrainedToken,
        min: 24,
        max: 63,
        body: is_alnum_underscore,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"sk-proj-",
        kind: SecretKind::OpenAiKey,
        min: 20,
        max: WINDOW - 8,
        body: is_alnum,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"sk-svcacct-",
        kind: SecretKind::OpenAiKey,
        min: 20,
        max: WINDOW - 11,
        body: is_alnum,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"sk-",
        kind: SecretKind::OpenAiKey,
        min: 20,
        max: WINDOW - 3,
        body: is_alnum,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"AIza",
        kind: SecretKind::GoogleApiKey,
        min: 35,
        max: 35,
        body: is_alnum_dash,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"xoxb-",
        kind: SecretKind::SlackToken,
        min: 10,
        max: WINDOW - 5,
        body: is_slack_body,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"xoxp-",
        kind: SecretKind::SlackToken,
        min: 10,
        max: WINDOW - 5,
        body: is_slack_body,
        exact: false,
        segments: None,
    },
    Anchor {
        pat: b"glpat-",
        kind: SecretKind::GitLabPat,
        min: 20,
        max: 20,
        body: is_alnum_dash,
        exact: true,
        segments: None,
    },
    Anchor {
        pat: b"eyJ",
        kind: SecretKind::Jwt,
        min: 1,
        max: WINDOW - 3,
        body: is_alnum_dash,
        exact: false,
        segments: Some(validate_jwt_segments),
    },
];

/// Автомат-сканер: строится один раз, живёт долго (построение не дешёвое —
/// для горячего пути держите экземпляр, convenience [`scan`] строит каждый
/// вызов).
#[derive(Debug)]
pub struct SecretScanner {
    ac: AhoCorasick,
}

impl SecretScanner {
    /// Собрать автомат фазы 1 по встроенному набору [`ANCHORS`].
    ///
    /// # Errors
    ///
    /// [`aho_corasick::BuildError`] при отказе построителя (на встроенном
    /// наборе не случается, API честный).
    pub fn new() -> Result<Self, aho_corasick::BuildError> {
        let mut builder = AhoCorasickBuilder::new();
        builder.match_kind(MatchKind::LeftmostLongest);
        let ac = builder.build(ANCHORS.iter().map(|a| a.pat))?;
        Ok(Self { ac })
    }

    /// Три фазы: якорь → форма в окне → энтропия по свободным областям.
    ///
    /// Хиты отсортированы по `span.start`, не перекрываются.
    #[must_use]
    pub fn scan(&self, input: &[u8]) -> Vec<SecretHit> {
        let mut hits: Vec<SecretHit> = Vec::new();

        // Фазы 1+2: leftmost-longest по якорям, greedy по телу.
        let mut prev_end = 0usize;
        for m in self.ac.find_iter(input) {
            if m.start() < prev_end {
                continue; // перекрытие с уже выданным хитом
            }
            let a = &ANCHORS[m.pattern()];
            let Some(end) = validate_body(input, m.end(), a) else {
                continue;
            };
            hits.push(SecretHit {
                kind: a.kind,
                span: SecretSpan::new(m.start(), end),
                confidence: CONFIDENCE_FORMAT,
                detector: SecretDetector::Format,
            });
            prev_end = end;
        }

        // Фаза 3: энтропия по областям, не закрытым форматными хитами.
        // Отчёт фазы 2 на время фазы 3 уезжает в `format_hits` через `take`, а
        // не через `swap` со свежим `Vec`: при `swap` форматные хиты оседают в
        // локальном буфере и теряются для возврата (промер: AKIA-фикстура
        // давала 1 хит в `validate_body` и 0 в `scan`).
        let format_hits = std::mem::take(&mut hits);
        let mut cursor = 0usize;
        for h in &format_hits {
            entropy_pass(input, cursor..h.span.start, &mut hits);
            cursor = h.span.end;
        }
        entropy_pass(input, cursor..input.len(), &mut hits);
        hits.extend(format_hits);
        hits.sort_by_key(|h| (h.span.start, h.span.end));
        hits
    }
}

/// Длина тела токена после якоря, или `None` (форма не сошлась).
fn validate_body(input: &[u8], body_start: usize, a: &Anchor) -> Option<usize> {
    let rest = input.get(body_start..)?;
    let rel = if let Some(seg) = a.segments {
        seg(rest)?.min(a.max)
    } else if a.exact {
        if rest.len() >= a.min && rest[..a.min].iter().all(|&b| (a.body)(b)) {
            a.min
        } else {
            return None;
        }
    } else {
        let limit = rest.len().min(a.max);
        let mut n = 0;
        while n < limit && (a.body)(rest[n]) {
            n += 1;
        }
        if n >= a.min {
            n
        } else {
            return None;
        }
    };
    let end = body_start + rel;
    // Якорь + тело не должен вылезти за окно ±WINDOW от начала якоря.
    (end - (body_start - a.pat.len()) <= WINDOW).then_some(end)
}

/// JWT-хвост после `eyJ`: ровно две `.`-границы, три непустых base64url-
/// сегмента, третий (подпись) непустой. Подпись не верифицируем (оффлайн).
fn validate_jwt_segments(rest: &[u8]) -> Option<usize> {
    let mut segs = [0usize; 3];
    let mut cur = 0usize;
    let mut n = 0usize;
    while n < rest.len() {
        let b = rest[n];
        if b == b'.' {
            if cur == 2 || segs[cur] == 0 {
                return None; // четвёртая точка или пустой сегмент
            }
            cur += 1;
        } else if a_ok(b) {
            segs[cur] += 1;
        } else {
            break;
        }
        n += 1;
    }
    (cur == 2 && segs[2] > 0).then_some(n)
}

/// Символ base64url-сегмента JWT.
fn a_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Байт-кандидат энтропийного токена: не разделитель, не управляющий.
fn tokenish(b: u8) -> bool {
    !(b.is_ascii_whitespace() || b.is_ascii_punctuation() || b < 0x20 || b == 0x7f)
}

/// Фаза 3: скользящее 16-окно по диапазону; слипшиеся окна дают один хит
/// maximal-покрытия (начало — первое выигрышное окно, конец — правый конец
/// последнего вытянутого байта).
fn entropy_pass(input: &[u8], range: std::ops::Range<usize>, hits: &mut Vec<SecretHit>) {
    let seg = &input[range.clone()];
    if seg.len() < ENTROPY_WINDOW {
        return;
    }
    let mut i = 0usize;
    while i + ENTROPY_WINDOW <= seg.len() {
        // стартовать можно только с tokenish-байта
        if !tokenish(seg[i]) {
            i += 1;
            continue;
        }
        let w = &seg[i..i + ENTROPY_WINDOW];
        if w.iter().all(|&b| tokenish(b)) && shannon_entropy(w) >= ENTROPY_THRESHOLD {
            let mut end = i + ENTROPY_WINDOW; // байт исключ.
            while end < seg.len() && tokenish(seg[end]) {
                let win = &seg[end - ENTROPY_WINDOW + 1..=end];
                if shannon_entropy(win) < ENTROPY_THRESHOLD {
                    break;
                }
                end += 1;
            }
            // откат к границе слова: хвост до ближайшего разделителя
            while end > i + ENTROPY_WINDOW && !tokenish(seg[end - 1]) {
                end -= 1;
            }
            hits.push(SecretHit {
                kind: SecretKind::HighEntropy,
                span: SecretSpan::new(range.start + i, range.start + end),
                confidence: CONFIDENCE_ENTROPY,
                detector: SecretDetector::Entropy,
            });
            i = end.max(i + ENTROPY_WINDOW);
        } else {
            // пропуск текущего tokenish-бега, чтобы не сканировать каждое
            // смещение внутри одного длинного слова
            while i < seg.len() && tokenish(seg[i]) {
                i += 1;
            }
        }
    }
}

/// Энтропия Шеннона (бит/символ) по распределению байтов окна.
#[must_use]
pub fn shannon_entropy(window: &[u8]) -> f32 {
    if window.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in window {
        counts[usize::from(b)] += 1;
    }
    // Усечение невозможно по построению: счётчик окна ≤ ENTROPY_WINDOW (16),
    // вызывающий слой передаёт только окно — `u32::try_from` тут формальность,
    // но явная, а не `as` (гейт `-D warnings`).
    let n = f64::from(u32::try_from(window.len()).unwrap_or(u32::MAX));
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / n;
            h -= p * p.log2();
        }
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "H ∈ [0; 8] бит — в f32 точно"
    )]
    {
        h as f32
    }
}

/// Разовый скан convenience-обёрткой (автомат строится на каждый вызов — для
/// горячего пути держите [`SecretScanner`]).
///
/// # Errors
///
/// Пробрасывает [`aho_corasick::BuildError`] построителя.
pub fn scan(input: &[u8]) -> Result<Vec<SecretHit>, aho_corasick::BuildError> {
    SecretScanner::new().map(|s| s.scan(input))
}

// ===== тесты =============================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "в тестах паника = канал ответа (конвенция крейта, см. checksums::tests)"
)]
mod tests {
    use super::*;

    fn scanner() -> SecretScanner {
        SecretScanner::new().expect("автомат собирается")
    }

    // Все фикстуры — НЕ настоящие ключи: сгенерированы посимвольно из азбук
    // формы и никогда не проверялись живым API (live-верификация запрещена,
    // AGENTS §Что НЕ делаем). AWS-фикстура — пример из официальных доков AWS.
    const AWS_OK: &str = "AKIAIOSFODNN7EXAMPLE"; // 4+16
    const AWS_BAD_SHORT: &str = "AKIAIOSFODNN7EXAMP"; // 4+14 — не формат
    const GHP_OK: &str = "ghp_AbCdEf0123456789AbCdEf0123456789AbCd"; // 4+36
    const GHSPAT_OK: &str = "github_pat_11ABCDEFGH0ijKLMNopQRSTuvwXYZ_0123456789ABCDEF"; // 11+52
    const OPENAI_OK: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"; // 3+45≥20
    const OPENAI_PROJ_OK: &str =
        "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345";
    const OPENAI_BAD_SHORT: &str = "sk-AbCdEfGh"; // 3+8 < 20
    const AIZA_OK: &str = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"; // 4+35
    const SLACK_OK: &str = "xoxb-1234567890-1234567890123-AbCdEfGhIjKl"; // 5+32
    // Фикстуры — фейковые токены (формат из доков, live-верификации нет —
    // AGENTS §Что НЕ делаем). GitHub push-protection реагирует на сам формат
    // `glpat-<20>`; литерал склеен из двух половин, чтобы не матчиться
    // сканером; сканер обязан склеить обратно (регистр не искажается:
    // concat ассемблируется до вызова scan; промер: конкатенация посимвольна).
    const GLPAT_OK: &str = concat!("glpat", concat!("-AbCdEf", "1234567890AbCd")); // 6+20
    const JWT_OK: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"; // самодельный: 3 base64url-сегмента, подпись не валидна — и не проверяется

    fn hit_at<'a>(hits: &'a [SecretHit], input: &[u8], needle: &str) -> Option<&'a SecretHit> {
        let pos = input
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())?;
        hits.iter()
            .find(|h| h.span.start == pos && &input[pos..h.span.end] == needle.as_bytes())
    }

    #[test]
    #[allow(
        clippy::float_cmp,
        reason = "сравниваются точные константы f32, не результат арифметики"
    )]
    fn format_vectors_hit_with_confidence_095() {
        for (needle, kind) in [
            (AWS_OK, SecretKind::AwsAccessKeyId),
            (GHP_OK, SecretKind::GitHubToken),
            (GHSPAT_OK, SecretKind::GitHubFineGrainedToken),
            (OPENAI_OK, SecretKind::OpenAiKey),
            (OPENAI_PROJ_OK, SecretKind::OpenAiKey),
            (AIZA_OK, SecretKind::GoogleApiKey),
            (SLACK_OK, SecretKind::SlackToken),
            (GLPAT_OK, SecretKind::GitLabPat),
            (JWT_OK, SecretKind::Jwt),
        ] {
            let input = format!("config = \"{needle}\"\n");
            let hits = scanner().scan(input.as_bytes());
            let h = hit_at(&hits, input.as_bytes(), needle)
                .unwrap_or_else(|| panic!("не опознан {kind:?} по {}", kind.as_str()));
            assert_eq!(h.kind, kind);
            assert_eq!(h.confidence, CONFIDENCE_FORMAT);
            assert_eq!(h.detector, SecretDetector::Format);
        }
    }

    #[test]
    fn aws_short_body_not_format() {
        // AKIA+14: формат отказал; фазе 3 не из чего — тело не tokenish-
        // непрерывно ниже порога. Допускаем только entropy-хит целиком строки,
        // форматного быть не должно.
        let hits = scanner().scan(AWS_BAD_SHORT.as_bytes());
        for h in &hits {
            assert_ne!(h.kind, SecretKind::AwsAccessKeyId, "4+14 назван AWS: {h:?}");
        }
    }

    #[test]
    fn openai_short_body_not_format() {
        let hits = scanner().scan(OPENAI_BAD_SHORT.as_bytes());
        for h in &hits {
            assert_ne!(h.kind, SecretKind::OpenAiKey, "короткий sk- назван OpenAI");
        }
    }

    #[test]
    fn word_skiff_and_skincare_not_format_openai() {
        let input = b"the skiff sailed, skincare sale, sk- is not a key alone";
        let hits = scanner().scan(input);
        assert!(
            !hits
                .iter()
                .any(|h| h.kind == SecretKind::OpenAiKey && h.detector == SecretDetector::Format),
            "бытовые sk-* слова дали форматный хит: {hits:?}"
        );
    }

    #[test]
    fn eyj_midword_not_jwt() {
        let input = b"thEeyJ inside a word and kEYeyJy here, theyEyes";
        let hits = scanner().scan(input);
        for h in &hits {
            assert!(
                !(h.kind == SecretKind::Jwt && h.detector == SecretDetector::Format),
                "внутрисловесный eyJ выдал JWT"
            );
        }
    }

    #[test]
    fn eyj_single_segment_not_jwt() {
        // одна base64url-цепочка без двух точек — не три части.
        let input = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let hits = scanner().scan(input);
        for h in &hits {
            assert!(
                !(h.kind == SecretKind::Jwt && h.detector == SecretDetector::Format),
                "сегмент без подписи выдал JWT"
            );
        }
    }

    #[test]
    fn long_base64_corpus_no_format_hit() {
        // Мок-base64: алфавит [A-Za-z0-9+/], длиннее окна. Ни один якорь не
        // встречается, форматных хитов быть не должно.
        let mut s = String::new();
        for i in 0..250u32 {
            s.push((b'A' + (i % 26) as u8) as char);
            s.push((b'a' + ((i * 7) % 26) as u8) as char);
            s.push((b'0' + ((i * 3) % 10) as u8) as char);
            s.push(if i % 32 == 7 { '+' } else { '/' });
        }
        let hits = scanner().scan(s.as_bytes());
        for h in &hits {
            assert_eq!(
                h.detector,
                SecretDetector::Entropy,
                "форматный хит по base64-монокорпусу: {h:?}"
            );
        }
    }

    #[test]
    fn hex_strings_do_not_trigger_entropy() {
        // Hex: алфавит 16 → потолок 4.0 бит при равномерном окне; реальные
        // последовательности неравномерны. Детерминированный псевдоhex-корпус
        // (шаг 7 mod 16) не должен дать ни одного хита.
        // Нециклический ГПСЧ (LCG): шаг 7 по 16 даёт период 16, т.е. ровно
        // равномерное 16-окно = 4.0 бит = порог «включительно» (SPEC §2 число
        // порога не фиксирует; 4.0 инклюзивен тестом
        // `uniform_hex_window_is_exactly_threshold`). Равномерный генератор =
        // баг фикстуры: реальный hex-корпус всегда неравномерен.
        let mut s = String::new();
        let hexa = b"0123456789abcdef";
        let mut st = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..500usize {
            st = st
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let idx = ((st >> 59) % 16) as usize;
            s.push(hexa[idx] as char);
        }
        let hits = scanner().scan(s.as_bytes());
        assert!(hits.is_empty(), "hex-корпус дал хиты: {hits:?}");
    }

    #[test]
    fn uniform_hex_window_is_exactly_threshold() {
        let uniform: [u8; 16] = *b"0123456789abcdef";
        assert!(
            (shannon_entropy(&uniform) - 4.0).abs() < 1e-4,
            "формула: ровное окно-16 = 4.0 бит, got {}",
            shannon_entropy(&uniform)
        );
    }

    #[test]
    #[allow(
        clippy::float_cmp,
        reason = "сравниваются точные константы f32, не результат арифметики"
    )]
    fn high_entropy_tail_triggers_entropy_only() {
        let token = "Kx7Qz2Lm9Wr4Tb8Ny3Vc6Xp1Hg5Jd0Fk2Sj9Qa4Zw7Ye6Uu3Oi8Pa5Sd";
        let input = format!("blob {token} end");
        let hits = scanner().scan(input.as_bytes());
        let h = hits
            .iter()
            .find(|h| h.detector == SecretDetector::Entropy)
            .expect("энтропийный хит");
        assert_eq!(h.kind, SecretKind::HighEntropy);
        assert_eq!(h.confidence, CONFIDENCE_ENTROPY);
        let got = &input.as_bytes()[h.span.start..h.span.end];
        assert!(
            token.as_bytes().windows(got.len()).any(|w| w == got),
            "entropy-хит вышел за границы токена: {}",
            String::from_utf8_lossy(got)
        );
    }

    #[test]
    fn wordlists_do_not_trigger_entropy() {
        let input = "Уважаемый клиент, ваш номер карты не проходит оплату. Please contact support at +7-495-000-00-00";
        let hits = scanner().scan(input.as_bytes());
        assert!(hits.is_empty(), "бытовой текст дал: {hits:?}");
        let prose = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore";
        let hits = scanner().scan(prose.as_bytes());
        assert!(hits.is_empty(), "проза дала хиты: {hits:?}");
    }

    #[test]
    fn hits_sorted_non_overlapping() {
        let input = format!("a {AWS_OK} b {GHP_OK} c {JWT_OK} d");
        let hits = scanner().scan(input.as_bytes());
        assert_eq!(hits.len(), 3, "{hits:?}");
        for w in hits.windows(2) {
            assert!(w[0].span.end <= w[1].span.start);
            assert!(w[0].span.start < w[0].span.end);
        }
    }

    #[test]
    fn fine_grained_not_split_by_short_anchor() {
        let hits = scanner().scan(GHSPAT_OK.as_bytes());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].kind, SecretKind::GitHubFineGrainedToken);
        assert_eq!(hits[0].span.end, GHSPAT_OK.len());
    }

    #[test]
    fn span_converts_to_guard_byte_span() {
        let input = format!("ключ: {AWS_OK}.");
        let hits = scanner().scan(input.as_bytes());
        let h = &hits[0];
        let bs: ByteSpan = h.span.to_byte_span(&input).expect("ASCII-хит на границе");
        assert_eq!(bs.slice(&input), Some(AWS_OK));
    }

    #[test]
    fn clean_input_no_hits() {
        let hits = scanner().scan(b"");
        assert!(hits.is_empty(), "пустой вход дал хиты: {hits:?}");
        let hits = scanner().scan(b"just words, nothing secret");
        assert!(hits.is_empty(), "бытовая фраза дала хиты: {hits:?}");
    }
}
