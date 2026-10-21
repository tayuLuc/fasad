//! Вердикты, источники детекции и аннотированный спан — язык обмена каскадов.

use serde::{Deserialize, Serialize};

use crate::span::ByteSpan;

/// Общий шаблон newtype-идентификатора: строка только в одном месте, `Debug`
/// не печатает содержимое (наследование конвенции [`crate::SecretString`]).
pub trait NewtypeId: Sized {
    /// Внутреннее значение.
    fn as_str(&self) -> &str;

    /// Сборка из любого строкового representation.
    fn from_id<S: AsRef<str>>(s: S) -> Self;
}

macro_rules! newtype_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Box<str>);

        impl NewtypeId for $name {
            fn as_str(&self) -> &str {
                &self.0
            }

            fn from_id<S: AsRef<str>>(s: S) -> Self {
                Self(s.as_ref().into())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Значение id может совпадать с оригиналом ПДн (например имя сущности
                // в роли) — светим только длину, как SecretString.
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("<{} chars>", self.0.chars().count()))
                    .finish()
            }
        }

        impl $name {
            /// Конструктор из строки.
            pub fn new<S: AsRef<str>>(s: S) -> Self {
                <Self as NewtypeId>::from_id(s)
            }
        }
    };
}

newtype_id! {
    /// Идентификатор класса конфиденциальности (`PERSON`, `INN`, `КОММЕРЧЕСКАЯ_ТАЙНА`).
    ///
    /// Строка, а не `enum`: схема категорий правится на ходу через `PUT /v1/schema`
    /// (SPEC §8) и включает кириллические классы §14; варианты enum стали бы
    /// контрактом компиляции для пользовательской схемы.
    ClassId
}

newtype_id! {
    /// Роль сущности в диалоге — префикс типизированного токена
    /// `[CLIENT_PERSON_1]` / `[VENDOR_ORG_2]` (SPEC §2 каскад 3, §14 п.2).
    EntityRole
}

/// Что нашло спан.
///
/// Вес детекции несёт сам источник: [`DetectionSource::DeterministicW`] = 1.0
/// ровно у чексумм — абсолютное вето детерминированного валидатора не должно
/// зависеть от вызывающего кода (SPEC §2 каскад 0, AGENTS §Инженерные инварианты).
///
/// Порядок вариантов = приоритет каскада; он же держит контракт JSON-имён
/// `/v1/analyze`, поэтому сверяется тестом `tests/invariant_checksum_w.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// Чексумма российского документа (ИНН/СНИЛС/ОГРН/БИК/карты) — SPEC §2 каскад 0.
    ChecksumRf,
    /// Чексумма иностранного документа (IBAN и т.п.) — SPEC §2 каскад 0.
    #[serde(rename = "checksum_eu")]
    ChecksumEu,
    /// Та же чексумма, что подтверждена ВНУТРИ декодированной base64-нагрузки
    /// токена (PR #94, каскад 0). Имя отдельное, а не `checksum_*`:
    /// происхождение спана нужно политике и отладке (номер найден не в тексте,
    /// а в бинаре — это надо уметь видеть в ответе), а вес общий с чексуммами:
    /// подтверждает окно валидатор, значит вето абсолютное (SPEC §2).
    #[serde(rename = "base64_decode")]
    Base64Decode,
    /// Энтропия Шеннона + Probability-of-Randomness в окне секрет-префикса.
    SecretEntropy,
    /// Детерминированный автомат (Ахо–Корасик): ОПФ, адресные/паспортные маркеры.
    AhoCorasickRule,
    /// Экстрактор каскада 1 (ONNX, span-free boundary).
    GlinerExtractor,
    /// Арбитр каскада 2 (`GLiNER` Decide) — решение по серой зоне.
    GlinerDecideArbitrator,
}

impl DetectionSource {
    /// Ровный вес детерминированного вето: чексумму не понижает ни один
    /// нейросетевой скоринг (SPEC §2 каскад 0). Имя задано контрактом задачи
    /// (`DeterministicW = 1.0`), верхний регистр clippy-конвенции тут осознанно
    /// нарушен — сверка имени в `tests/invariant_checksum_w.rs`.
    #[allow(non_upper_case_globals)]
    pub const DeterministicW: f64 = 1.0;

    /// Вес детекции: `Some(1.0)` ровно у чексумм (абсолютное вето, SPEC §2 каскад 0:
    /// «приоритет чексуммы = 1.0, нейросети его не пересматривают»), `None` — у
    /// вероятностных источников; их скор приходит в [`AnnotatedSpan::score`].
    ///
    /// [`Self::Base64Decode`] стоит в весовой ручке наравне с чексуммами: то, что
    /// окно нашли после декода, меняет способ доставки, а не доказательство —
    /// подтвердил его тот же валидатор (PR #94; вектор весов сверяет
    /// `tests/invariant_checksum_w.rs`, правка вектора = правка SPEC §2).
    #[must_use]
    pub const fn deterministic_weight(self) -> Option<f64> {
        match self {
            Self::ChecksumRf | Self::ChecksumEu | Self::Base64Decode => Some(Self::DeterministicW),
            Self::SecretEntropy
            | Self::AhoCorasickRule
            | Self::GlinerExtractor
            | Self::GlinerDecideArbitrator => None,
        }
    }

    /// Источник из детерминированного каскада 0.
    #[must_use]
    pub fn is_deterministic(self) -> bool {
        self.deterministic_weight().is_some() || matches!(self, Self::AhoCorasickRule)
    }
}

/// Вердикт пайплайна по спану/запросу (SPEC §0, §8 заголовок `X-Guard-Policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Оставить как есть: спан не секрет / арбитр решил `PUBLIC_KEEP` (SPEC §14 п.3, режим арбитра).
    KeepPublic,
    /// Заменить гладким синтетическим суррогатом той же морфологии (SPEC §4).
    MaskSurrogate,
    /// Заменить суффиксной капсулой `Основа_1-ем` для кастомных терминов (SPEC §4).
    MaskCapsule,
    /// Запрос наружу не уходит вовсе — fail-closed (SPEC §1 п.5).
    BlockRequest,
}

impl Verdict {
    /// Требует ли вердикт записи оригинала в vault (обратимость нужна только при
    /// маскировании).
    #[must_use]
    pub const fn needs_vault(self) -> bool {
        matches!(self, Self::MaskSurrogate | Self::MaskCapsule)
    }
}

/// Спан + его разметка: то, что отдаёт `/v1/analyze` (SPEC §8) и что потребляют
/// каскады 2–3 и vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotatedSpan {
    /// Байтовый интервал в исходном тексте.
    pub span: ByteSpan,
    /// Класс конфиденциальности.
    pub class: ClassId,
    /// Роль сущности (`CLIENT`/`VENDOR`/…); `None` — роль не выведена.
    pub role: Option<EntityRole>,
    /// Кто нашёл.
    pub source: DetectionSource,
    /// Итоговый скор `S` (SPEC §2 каскад 2): 1.0 у чексумм, иначе p1 или
    /// `α·p1+(1−α)·p2`.
    pub score: f64,
    /// Вердикт.
    pub verdict: Verdict,
}

impl AnnotatedSpan {
    /// Конструктор с проверкой скорингового контракта.
    ///
    /// Скор вне `[0.0, 1.0]` или `NaN` — ошибка конфиг/декода модели, а не данные:
    /// оставляем её на вызывающем, сами молча не климпим (fail-closed, AGENTS).
    ///
    /// # Errors
    ///
    /// [`ScoreError::NotFinite`] / [`ScoreError::OutOfRange`] /
    /// [`ScoreError::DeterministicMustWeighOne`] — см. варианты enum.
    pub fn new(
        span: ByteSpan,
        class: ClassId,
        role: Option<EntityRole>,
        source: DetectionSource,
        score: f64,
        verdict: Verdict,
    ) -> Result<Self, ScoreError> {
        if !score.is_finite() {
            return Err(ScoreError::NotFinite(score));
        }
        if !(0.0..=1.0).contains(&score) {
            return Err(ScoreError::OutOfRange(score));
        }
        if source.deterministic_weight() == Some(DetectionSource::DeterministicW)
            && score != DetectionSource::DeterministicW
        {
            return Err(ScoreError::DeterministicMustWeighOne { source, score });
        }
        Ok(Self {
            span,
            class,
            role,
            source,
            score,
            verdict,
        })
    }

    /// Эффективный вес: для детерминированных источников — 1.0 независимо от
    /// занесённого скора (вето не пересматривается), иначе сам скор.
    #[must_use]
    pub fn effective_weight(&self) -> f64 {
        self.source.deterministic_weight().unwrap_or(self.score)
    }
}

/// Нарушение контракта скора при сборке [`AnnotatedSpan`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreError {
    /// Скор не в `[0, 1]`.
    OutOfRange(f64),
    /// Скор `NaN`/`inf`.
    NotFinite(f64),
    /// Чексумма-детекция с весом ≠ 1.0 (AGENTS: абсолютное вето).
    DeterministicMustWeighOne {
        /// Источник детекции.
        source: DetectionSource,
        /// Переданный скор.
        score: f64,
    },
}

impl core::fmt::Display for ScoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange(s) => write!(f, "score {s} outside [0, 1]"),
            Self::NotFinite(s) => write!(f, "score {s} is not finite"),
            Self::DeterministicMustWeighOne { source, score } => {
                write!(
                    f,
                    "{source:?} is a checksum detector: score must be 1.0, got {score}"
                )
            }
        }
    }
}

impl std::error::Error for ScoreError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    fn span(text: &str) -> ByteSpan {
        ByteSpan::new(text, 0, text.len()).expect("весь текст — законный спан")
    }

    #[test]
    fn checksum_source_weighs_exactly_one() {
        assert_eq!(
            DetectionSource::ChecksumRf.deterministic_weight(),
            Some(1.0)
        );
        assert_eq!(
            DetectionSource::ChecksumEu.deterministic_weight(),
            Some(1.0)
        );
        assert_eq!(
            DetectionSource::GlinerExtractor.deterministic_weight(),
            None
        );
        assert!(
            DetectionSource::SecretEntropy
                .deterministic_weight()
                .is_none()
        );
    }

    #[test]
    // Ровность 1.0 здесь — часть контракта (точное значение, не измерение);
    // float_cmp — про допуск, тут допуска нет намеренно.
    #[allow(clippy::float_cmp)]
    fn neural_source_cannot_downgrade_checksum() {
        let text = "7707083898";
        let s = span(text);
        // Арбитр пытается понизить чексумму до 0.4 — конструктор обязан отвергнуть.
        let err = AnnotatedSpan::new(
            s,
            ClassId::new("INN"),
            None,
            DetectionSource::ChecksumRf,
            0.4,
            Verdict::MaskSurrogate,
        )
        .expect_err("детерминированное вето");
        assert!(matches!(
            err,
            ScoreError::DeterministicMustWeighOne { score: 0.4, .. }
        ));
        // Тот же спан с честным весом 1.0 проходит.
        let ok = AnnotatedSpan::new(
            s,
            ClassId::new("INN"),
            None,
            DetectionSource::ChecksumRf,
            DetectionSource::DeterministicW,
            Verdict::MaskSurrogate,
        )
        .expect("валидный спан");
        let w = ok.effective_weight();
        assert_eq!(w, 1.0, "вес детерминированного вето обязан быть ровно 1.0");
    }

    #[test]
    fn rejects_nonfinite_and_out_of_range_scores() {
        let text = "abc";
        let s = span(text);
        let mk = |score: f64| {
            AnnotatedSpan::new(
                s,
                ClassId::new("PERSON"),
                None,
                DetectionSource::GlinerExtractor,
                score,
                Verdict::KeepPublic,
            )
        };
        assert_eq!(mk(1.4).err(), Some(ScoreError::OutOfRange(1.4)));
        assert!(matches!(mk(f64::NAN), Err(ScoreError::NotFinite(_))));
        assert!(matches!(mk(f64::INFINITY), Err(ScoreError::NotFinite(_))));
        assert!(mk(0.25).is_ok());
    }

    #[test]
    fn verdict_vault_needs() {
        assert!(Verdict::MaskSurrogate.needs_vault());
        assert!(Verdict::MaskCapsule.needs_vault());
        assert!(!Verdict::KeepPublic.needs_vault());
        assert!(!Verdict::BlockRequest.needs_vault());
    }

    #[test]
    fn cyrillic_class_id_round_trips_as_string() {
        let c = ClassId::new("КОММЕРЧЕСКАЯ_ТАЙНА");
        let j = serde_json::to_string(&c).expect("сериализуется");
        assert_eq!(j, "\"КОММЕРЧЕСКАЯ_ТАЙНА\"");
        let back: ClassId = serde_json::from_str(&j).expect("десериализуется");
        assert_eq!(back, c);
    }

    #[test]
    fn detection_source_serde_names_are_stable() {
        // Контракт /v1/analyze: JSON-имена источников не должны поменяться молча.
        for (src, name) in [
            (DetectionSource::ChecksumRf, "checksum_rf"),
            (DetectionSource::ChecksumEu, "checksum_eu"),
            (DetectionSource::Base64Decode, "base64_decode"),
            (DetectionSource::SecretEntropy, "secret_entropy"),
            (DetectionSource::AhoCorasickRule, "aho_corasick_rule"),
            (DetectionSource::GlinerExtractor, "gliner_extractor"),
            (
                DetectionSource::GlinerDecideArbitrator,
                "gliner_decide_arbitrator",
            ),
        ] {
            let j = serde_json::to_string(&src).expect("сериализуется");
            assert_eq!(j, format!("\"{name}\""));
            let back: DetectionSource = serde_json::from_str(&j).expect("десериализуется");
            assert_eq!(back, src);
        }
    }

    #[test]
    fn verdict_serde_names_are_stable() {
        for (v, name) in [
            (Verdict::KeepPublic, "keep_public"),
            (Verdict::MaskSurrogate, "mask_surrogate"),
            (Verdict::MaskCapsule, "mask_capsule"),
            (Verdict::BlockRequest, "block_request"),
        ] {
            let j = serde_json::to_string(&v).expect("сериализуется");
            assert_eq!(j, format!("\"{name}\""));
            let back: Verdict = serde_json::from_str(&j).expect("десериализуется");
            assert_eq!(back, v);
        }
    }

    #[test]
    fn newtype_debug_hides_value() {
        let c = ClassId::new("Алексей Смирнов");
        let d = format!("{c:?}");
        assert!(
            !d.contains("Алексей"),
            "Debug newtype обязан прятать значение: {d}"
        );
        assert!(d.contains("15 chars"));
    }
}
