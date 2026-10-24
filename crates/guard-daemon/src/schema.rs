//! Схема классов PII: канон 8 + раздел ответственности с валидаторами.
//!
//! Носитель контракта — `config/schema.default.json` (SPEC §6 «категории +
//! описания label», #56 п.1). Файл внешним путём не подменяется молча:
//! встроенная копия = `include_str!`, override только через `FASAD_SCHEMA`,
//! и любой вариант проходит [`Schema::parse`] с валидацией.
//!
//! # Почему порядок — контракт, а не косметика
//!
//! u-вероятность Decide порядко-зависима: перестановка блока схем двигала
//! recall класса `snils` на −24 п.п. при τ=0.25 (issue #53, зафиксировано в
//! `docs/quant-policy.md` §3 п.2b как контракт замера). Значит массив `classes`
//! — часть измеренного артефакта, и [`Schema::parse`] сознательно НЕ сортирует
//! и не нормализует порядок: переставил = перезамерил. Тест
//! [`tests::canonical_order_is_frozen`] держит эталонный порядок, а
//! [`tests::questions_are_verbatim_from_the_measured_harness`] — что тексты
//! вопросов совпадают с харнесом, на котором порядок измеряли.

use std::path::Path;

use serde::Deserialize;

/// Встроенный канон — байты `config/schema.default.json` на момент сборки.
pub const DEFAULT_SCHEMA_JSON: &str = include_str!("../../../config/schema.default.json");

/// Потолок размера файла схемы: схема — конфигурация на десятки строк, а не
/// пользовательский документ; мегабайтный JSON на старте = отказ, а не OOM-потенциал.
pub const MAX_SCHEMA_BYTES: usize = 65_536;

/// Валидаторы каскада 0, которые схема имеет право назвать.
///
/// Список закрытый и сверен с `crates/guard-detectors/src/checksums.rs`
/// (`pub fn` того же имени): опечатка в имени валидатора означала бы «класс
/// объявлен, а проверять его нечем» — то есть тихий fail-open в детерминированном
/// каскаде, поэтому имя вне списка = [`SchemaError::UnknownValidator`].
pub const KNOWN_VALIDATORS: [&str; 12] = [
    "inn10",
    "inn12",
    "snils",
    "ogrn13",
    "ogrnip15",
    "luhn",
    "iban",
    "bik_format",
    "bank_account_format",
    "bik_account_cross",
    "passport_format",
    "phone_rf",
];

/// Один класс схемы.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClassDef {
    /// Идентификатор класса (`person_name`) — он же ключ токена vault и поле JSON.
    pub id: String,
    /// Человекочитаемое имя для UI (SPEC §6).
    pub label: String,
    /// Вопрос Decide (первая метка ответа = «да», контракт `arbitrate.rs`).
    #[serde(default)]
    pub question: String,
    /// Метки ответа, первая = «да».
    #[serde(default)]
    pub answers: Vec<String>,
    /// Покрыт ли класс головой модели (`false` = только валидаторы).
    #[serde(default)]
    pub model: bool,
    /// Теги BIO каскада 1, свёрнутые в этот класс.
    #[serde(default)]
    pub lockr_tags: Vec<String>,
    /// Имена валидаторов каскада 0 для этого класса.
    #[serde(default)]
    pub validators: Vec<String>,
    /// Класс вне ведения модели (ogrn/ogrnip/iban, #56 п.1).
    #[serde(default)]
    pub validator_only: bool,
}

/// Класс, который схеме известен, но модели не задаётся.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ValidatorOnlyClass {
    /// Идентификатор класса.
    pub id: String,
    /// Человекочитаемое имя.
    pub label: String,
    /// Валидаторы, закрывающие класс.
    #[serde(default)]
    pub validators: Vec<String>,
}

/// Схема целиком, как её понимает демон.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Schema {
    /// Версия формата файла.
    pub version: u32,
    /// Пояснения файла (JSON не умеет комментариев — держим массивом строк).
    #[serde(default)]
    pub note: Vec<String>,
    /// Классы модели — порядок значим (см. заголовок модуля).
    pub classes: Vec<ClassDef>,
    /// Классы только с валидаторами.
    #[serde(default)]
    pub validator_only: Vec<ValidatorOnlyClass>,
}

/// Причина, по которой схема отвергнута.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// Файл больше [`MAX_SCHEMA_BYTES`].
    TooLarge {
        /// Размер в байтах.
        bytes: usize,
    },
    /// JSON не парсится.
    BadJson(String),
    /// Файл не читается (для `FASAD_SCHEMA` это отказ стартовать, не «возьмём дефолт»:
    /// оператор явно попросил эту схему).
    Io(String),
    /// Классов нет вовсе — каскаду нечего возвращать.
    Empty,
    /// Один id встречается дважды (в т.ч. между `classes` и `validator_only`).
    DuplicateId(String),
    /// Класс помечен моделью, но вопроса нет — модель его никогда не назовёт.
    MissingQuestion(String),
    /// Меток ответа меньше двух или первая не «да» (контракт Decide, `arbitrate.rs`:
    /// «ПЕРВАЯ метка — да»).
    BadAnswers(String),
    /// Валидатор вне [`KNOWN_VALIDATORS`] — опечатка, которая выключила бы проверку.
    UnknownValidator {
        /// Класс.
        class: String,
        /// Что написали.
        name: String,
    },
    /// `validator_only: true` вместе с `model: true` — два ответа на один вопрос.
    Contradiction(String),
    /// Неизвестная версия формата.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes } => {
                write!(f, "схема {bytes} байт > лимита {MAX_SCHEMA_BYTES}")
            }
            Self::BadJson(e) => write!(f, "схема не является валидным JSON: {e}"),
            Self::Io(e) => write!(f, "схема не читается: {e}"),
            Self::Empty => f.write_str("схема без классов"),
            Self::DuplicateId(id) => write!(f, "дубликат id класса: {id}"),
            Self::MissingQuestion(id) => {
                write!(f, "класс {id} помечен model:true, но question пуст")
            }
            Self::BadAnswers(id) => {
                write!(
                    f,
                    "класс {id}: нужны ≥2 метки и первая = \"yes\" (контракт Decide)"
                )
            }
            Self::UnknownValidator { class, name } => {
                write!(
                    f,
                    "класс {class}: валидатор {name:?} не из KNOWN_VALIDATORS"
                )
            }
            Self::Contradiction(id) => {
                write!(
                    f,
                    "класс {id}: model:true и validator_only:true одновременно"
                )
            }
            Self::UnsupportedVersion(v) => write!(f, "версия схемы {v} не поддерживается"),
        }
    }
}

impl std::error::Error for SchemaError {}

impl Schema {
    /// Разобрать и проверить байты схемы.
    ///
    /// # Errors
    ///
    /// Любой [`SchemaError`] — все они означают «демон не стартует», потому что
    /// частично применимая схема хуже отсутствующей (fail-closed, AGENTS).
    pub fn parse(raw: &str) -> Result<Self, SchemaError> {
        if raw.len() > MAX_SCHEMA_BYTES {
            return Err(SchemaError::TooLarge { bytes: raw.len() });
        }
        let schema: Self =
            serde_json::from_str(raw).map_err(|e| SchemaError::BadJson(e.to_string()))?;
        schema.check()?;
        Ok(schema)
    }

    /// Встроенный канон (байты сборки демона).
    ///
    /// # Errors
    ///
    /// [`SchemaError`] — теоретически: собственный файл проходил валидацию на
    /// каждом коммите, но `FASAD_SCHEMA` указывает не сюда, а сломанный
    /// `include_str!`-файл значит испорченную сборку.
    pub fn embedded() -> Result<Self, SchemaError> {
        Self::parse(DEFAULT_SCHEMA_JSON)
    }

    /// Схема с диска (override из `FASAD_SCHEMA`).
    ///
    /// # Errors
    ///
    /// [`SchemaError::Io`] на нечитаемом пути, далее — то же, что [`Self::parse`].
    pub fn load(path: &Path) -> Result<Self, SchemaError> {
        let raw = std::fs::read_to_string(path).map_err(|e| SchemaError::Io(e.to_string()))?;
        Self::parse(&raw)
    }

    /// Канон по умолчанию, если путь не задан; ошибка — если задан и плох.
    ///
    /// # Errors
    ///
    /// См. [`Self::load`] / [`Self::embedded`].
    pub fn from_config(path: Option<&Path>) -> Result<Self, SchemaError> {
        match path {
            None => Self::embedded(),
            Some(p) => Self::load(p),
        }
    }

    /// Только классы модели, в порядке файла (для блока схем Decide).
    #[must_use]
    pub fn model_classes(&self) -> Vec<&ClassDef> {
        self.classes.iter().filter(|c| c.model).collect()
    }

    /// Пары «вопрос → метки» в порядке схемы: готовый вход блока схем
    /// (`guard_onnx::arbitrate::DecideArbiter::schema_block` принимает их же).
    #[must_use]
    pub fn questions(&self) -> Vec<(&str, Vec<&str>)> {
        self.model_classes()
            .into_iter()
            .map(|c| {
                (
                    c.question.as_str(),
                    c.answers.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }

    /// Знает ли схема такой класс (по всем объявлениям, включая validator-only).
    #[must_use]
    pub fn knows(&self, id: &str) -> bool {
        self.classes.iter().any(|c| c.id == id) || self.validator_only.iter().any(|c| c.id == id)
    }

    /// Класс каскада 1 по BIO-тегу.
    #[must_use]
    pub fn lockr_class(&self, tag: &str) -> Option<&str> {
        self.classes
            .iter()
            .find(|c| c.lockr_tags.iter().any(|t| t == tag))
            .map(|c| c.id.as_str())
    }

    /// Валидаторы класса (пустой срез, если класса нет или у него нет чексумм).
    ///
    /// Одалживается у схемы: срез живёт столько же, сколько `Schema`, и читается
    /// на каждом спане — аллоцировать/утекать здесь значит платить за чтение.
    #[must_use]
    pub fn validators_for(&self, id: &str) -> &[String] {
        const NONE: &[String] = &[];
        if let Some(c) = self.classes.iter().find(|c| c.id == id) {
            return &c.validators;
        }
        self.validator_only
            .iter()
            .find(|c| c.id == id)
            .map_or(NONE, |c| &c.validators)
    }

    /// Проверки целостности (см. [`SchemaError`]).
    fn check(&self) -> Result<(), SchemaError> {
        if self.version != 1 {
            return Err(SchemaError::UnsupportedVersion(self.version));
        }
        if self.classes.is_empty() && self.validator_only.is_empty() {
            return Err(SchemaError::Empty);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.classes.len());
        for c in &self.classes {
            if seen.contains(&c.id.as_str()) || self.validator_only.iter().any(|v| v.id == c.id) {
                return Err(SchemaError::DuplicateId(c.id.clone()));
            }
            seen.push(&c.id);
            if c.model && c.validator_only {
                return Err(SchemaError::Contradiction(c.id.clone()));
            }
            if c.model {
                if c.question.trim().is_empty() {
                    return Err(SchemaError::MissingQuestion(c.id.clone()));
                }
                if c.answers.len() < 2 || c.answers[0] != "yes" {
                    return Err(SchemaError::BadAnswers(c.id.clone()));
                }
            }
            check_validators(&c.id, &c.validators)?;
        }
        for v in &self.validator_only {
            if v.validators.is_empty() {
                return Err(SchemaError::UnknownValidator {
                    class: v.id.clone(),
                    name: "(пусто)".to_owned(),
                });
            }
            check_validators(&v.id, &v.validators)?;
        }
        Ok(())
    }
}

fn check_validators(class: &str, names: &[String]) -> Result<(), SchemaError> {
    for n in names {
        if !KNOWN_VALIDATORS.contains(&n.as_str()) {
            return Err(SchemaError::UnknownValidator {
                class: class.to_owned(),
                name: n.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    /// Исходник измерительного харнеса — тоже данные этого теста: он держит
    /// равенство схемы тому, на чём измеряли порядок и recall.
    const HARNESS: &str = include_str!("../../guard-onnx/examples/recall_golden.rs");

    /// Владелица BIO-маппинга с шага 9A (issue #14A) — либа, а не харнес:
    /// `tag_to_class` в `guard-onnx::extract` зовут и харнес, и демон, поэтому
    /// якорь «тег не выдуман схемой, он из измеренного декода» переехал вместе
    /// с владельцем маппинга. Харнес больше не держит список тегов — он их
    /// получает из либы; якорь на источник вопросов (`HARNESS`) остаётся.
    const EXTRACT: &str = include_str!("../../guard-onnx/src/extract.rs");

    fn names(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    fn canon() -> Schema {
        Schema::embedded().expect("встроенная схема валидна")
    }

    #[test]
    fn canonical_order_is_frozen() {
        let s = canon();
        let ids: Vec<&str> = s.classes.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "person_name",
                "inn",
                "snils",
                "card_pan",
                "phone",
                "email",
                "address",
                "passport"
            ],
            "порядок блоков схемы = измеренный контракт (#53, quant-policy §3 п.2b)"
        );
        let vo: Vec<&str> = s.validator_only.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            vo,
            vec!["ogrn", "ogrnip", "iban"],
            "#56 п.1: ровно это трио"
        );
    }

    #[test]
    fn questions_are_verbatim_from_the_measured_harness() {
        for c in canon().model_classes() {
            let quoted = format!("\"{}\"", c.question);
            assert!(
                HARNESS.contains(&quoted),
                "вопрос {:?} не найден в харнесах — схема разошлась с измерением",
                c.question
            );
            assert!(
                HARNESS.contains(&format!("\"{}\"", c.id)),
                "класс {} не упоминается в харнесе",
                c.id
            );
        }
        // Метки ответа — те же, что `.map(|c| (question_of(c), ["yes","no"]]))`.
        assert!(HARNESS.contains("[\"yes\", \"no\"]") || HARNESS.contains("[\"yes\",\"no\"]"));
        for c in canon().model_classes() {
            assert_eq!(
                c.answers,
                vec!["yes", "no"],
                "контракт Decide: первая метка = да"
            );
        }
    }

    #[test]
    fn lockr_tags_are_the_harness_bio_mapping() {
        // tag_to_class() либы (общий для харнеса и демона) сворачивает те же
        // теги в те же классы, что приписывает им схема.
        let s = canon();
        assert_eq!(s.lockr_class("MIDDLE_NAME"), Some("person_name"));
        assert_eq!(s.lockr_class("CREDIT_CARD"), Some("card_pan"));
        assert_eq!(s.lockr_class("HOUSE"), Some("address"));
        assert_eq!(s.lockr_class("PASSPORT"), Some("passport"));
        assert_eq!(
            s.lockr_class("ORGANIZATION"),
            None,
            "непокрытый тег = None, не паника"
        );
        for c in s.model_classes() {
            assert!(
                !c.lockr_tags.is_empty(),
                "класс {} без BIO-тегов мёртв",
                c.id
            );
            for t in &c.lockr_tags {
                assert!(
                    EXTRACT.contains(&format!("\"{t}\"")),
                    "тег {t} не из измеренного BIO-маппинга"
                );
            }
        }
    }

    #[test]
    fn embedded_matches_the_file_on_disk() {
        // Артефакт SPEC §9 («архив = бинарь + dylib + schema.default.json») обязан
        // совпадать с тем, что вкомпилировано: правка файла без пересборки = разнобой.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/schema.default.json");
        let disk = Schema::load(&path).expect("файл на диске валиден");
        assert_eq!(disk, canon());
        assert_eq!(
            std::fs::read_to_string(&path).expect("читается").as_bytes(),
            DEFAULT_SCHEMA_JSON.as_bytes()
        );
    }

    #[test]
    fn bogus_validator_is_refused_not_ignored() {
        // Опечатка в имени валидатора выключила бы детерминированную проверку —
        // это fail-open, значит ответ «нет», а не «примем и пометим».
        let broken = DEFAULT_SCHEMA_JSON.replace("\"inn10\", \"inn12\"", "\"inn10\", \"inn24\"");
        let err = Schema::parse(&broken).unwrap_err();
        assert_eq!(
            err,
            SchemaError::UnknownValidator {
                class: "inn".to_owned(),
                name: "inn24".to_owned()
            }
        );
    }

    #[test]
    fn duplicate_and_empty_and_contradiction_are_refused() {
        let dup = DEFAULT_SCHEMA_JSON.replace("\"id\": \"passport\"", "\"id\": \"inn\"");
        assert!(matches!(
            Schema::parse(&dup).unwrap_err(),
            SchemaError::DuplicateId(_)
        ));
        let empty = r#"{"version":1,"classes":[],"validator_only":[]}"#.to_owned();
        assert_eq!(Schema::parse(&empty).unwrap_err(), SchemaError::Empty);
        let contradicted = serde_json::json!({
            "version": 1,
            "classes": [{"id":"inn","label":"x","question":"q ?","answers":["yes","no"],
                         "model":true,"validator_only":true,"validators":["inn10"]}],
            "validator_only": []
        })
        .to_string();
        assert!(matches!(
            Schema::parse(&contradicted).unwrap_err(),
            SchemaError::Contradiction(_)
        ));
    }

    #[test]
    fn missing_question_and_bad_answers_are_refused() {
        let no_q = serde_json::json!({
            "version":1,
            "classes":[{"id":"person_name","label":"x","question":"","answers":["yes","no"],"model":true}],
            "validator_only":[]
        })
        .to_string();
        assert!(matches!(
            Schema::parse(&no_q).unwrap_err(),
            SchemaError::MissingQuestion(_)
        ));
        // «no» первой = инвертированный контракт Decide: арбитр молча врывает
        // обратный смысл каждому ответу.
        let inv = serde_json::json!({
            "version":1,
            "classes":[{"id":"person_name","label":"x","question":"q ?","answers":["no","yes"],"model":true}],
            "validator_only":[]
        })
        .to_string();
        assert!(matches!(
            Schema::parse(&inv).unwrap_err(),
            SchemaError::BadAnswers(_)
        ));
    }

    #[test]
    fn oversized_and_bad_version_are_refused() {
        let big = format!(
            "{{\"version\":1,\"note\":[\"{}\"]}}",
            "а".repeat(MAX_SCHEMA_BYTES)
        );
        assert!(matches!(
            Schema::parse(&big).unwrap_err(),
            SchemaError::TooLarge { .. }
        ));
        let badv = DEFAULT_SCHEMA_JSON.replace("\"version\": 1", "\"version\": 7");
        assert!(matches!(
            Schema::parse(&badv).unwrap_err(),
            SchemaError::UnsupportedVersion(7)
        ));
    }

    #[test]
    fn model_classes_are_the_eight_and_validator_only_have_no_question() {
        let s = canon();
        assert_eq!(s.model_classes().len(), 8);
        assert_eq!(
            s.questions().len(),
            8,
            "блок схем Decide = ровно 8 вопросов"
        );
        for v in &s.validator_only {
            assert!(s.knows(&v.id));
            assert_ne!(v.validators, [] as [String; 0]);
        }
        // Валидаторы объявлены там, где чексумма реально есть.
        assert_eq!(names(s.validators_for("inn")), vec!["inn10", "inn12"]);
        assert_eq!(names(s.validators_for("card_pan")), vec!["luhn"]);
        assert_eq!(s.validators_for("person_name"), [] as [String; 0]);
        assert_eq!(s.validators_for("нет-такого"), [] as [String; 0]);
        assert!(!s.knows("нет-такого"));
    }
}
