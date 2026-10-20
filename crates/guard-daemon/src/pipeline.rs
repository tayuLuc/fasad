//! Конвейер `/v1/analyze`: политика → каскад 0 → аннотированные спаны.
//!
//! Отвязка от HTTP сознательная: здесь нет ни `axum`, ни заголовков, поэтому
//! логика вердиктов тестируется без сокета, а атом D (middleware) переиспользует
//! [`Policy::parse`] и [`analyze`], не переписывая их.
//!
//! # Промеренная граница этого шага
//!
//! На шаге 6 демон поднимает **только каскад 0**. Причина не в лени, а в API:
//! `guard-onnx` под фичей `ort-inference` даёт сессию арбитра Decide
//! (`arbitrate::DecideArbiter`), а сессию извлечения lockR — нет
//! (она живёт в `crates/guard-onnx/examples/recall_golden.rs`, библиотечного
//! интерфейса у неё нет). Decide без спанов спрашивать не о чем: он отвечает на
//! вопрос «есть ли класс в тексте», координат не даёт. Значит модельный путь
//! спанов в демоне физически отсутствует, и мы это честно пишем в
//! `X-Guard-Stage: cascade-0-only` и в `/health`, а не делаем вид, что recall
//! полный. Гейт #14 (recall ≥ 98 % по нижнему Wilson) родитель меряет харнесом
//! на полном каскаде 0/1/2, не демоном.

use std::time::Instant;

use guard_types::{AnnotatedSpan, DetectionSource, EntityRole, NewtypeId, ScoreError, Verdict};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cascade0::{self, Hit};
use crate::config::Config;
use crate::schema::Schema;

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
        }
    }
}

impl std::error::Error for AnalyzeError {}

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
    /// Эффективный порог, с которым считали (эхо в заголовке — чтобы клиент не
    /// гадал, что он сам попросил).
    pub threshold: f64,
    /// Политика запроса.
    pub policy: Policy,
}

/// Разобрать текст конвейером шага 6.
///
/// # Errors
///
/// [`AnalyzeError`] — см. варианты; всё перечисленное ответом 4xx, а не 5xx:
/// это отвергнутый запрос, а не сбой конвейера.
pub fn analyze(
    req: &AnalyzeRequest,
    schema: &Schema,
    cfg: &Config,
    policy: Policy,
) -> Result<Analysis, AnalyzeError> {
    let started = Instant::now();
    let threshold = effective_threshold(req.score_threshold, cfg)?;
    let filter = req
        .entities
        .as_deref()
        .map(|want| check_entities(want, schema))
        .transpose()?;

    let hits = cascade0::scan(&req.text, schema);
    let mut spans = Vec::with_capacity(hits.len());
    for h in hits {
        if !passes(&h, threshold, filter.as_deref()) {
            continue;
        }
        let span = AnnotatedSpan::new(
            h.span,
            h.class.clone(),
            // Ролей на шаге 6 нет: SPEC §14 (CLIENT/VENDOR) — шаг 8, а
            // выдумывать их из соседних слов значит генерировать факты.
            None,
            h.source,
            h.score(),
            policy.verdict(),
        )
        .map_err(AnalyzeError::Score)?;
        spans.push(AnalyzedSpan::from_annotated(&span, Some(h.validator)));
    }

    let max_risk = spans.iter().fold(0.0_f64, |m, s| m.max(s.score));
    Ok(Analysis {
        spans,
        max_risk,
        latency_ms: started.elapsed().as_millis(),
        stage: cfg.stage(),
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

fn passes(hit: &Hit, threshold: f64, filter: Option<&[String]>) -> bool {
    if let Some(want) = filter {
        if !want.iter().any(|w| *w == hit.class.as_str()) {
            return false;
        }
    }
    // Детерминированное вето весит 1.0 и порогами не понижается (AGENTS);
    // сравнение оставлено на будущее модельных источников с весом < 1.
    hit.score() >= threshold || hit.source.deterministic_weight().is_some()
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
}
