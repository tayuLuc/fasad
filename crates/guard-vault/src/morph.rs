//! Морфология ФИО: суффиксальная таблица как данные (SPEC §4, §10 шаг 5 атом D).
//!
//! Решение #46 закрыто веткой (а): таблица + `petrovich` как decliner-резерв за
//! фичей `decliner`. `rsmorphy` из скелета вычеркнут — крейт мёртв (промер
//! `docs/dep-verify-crates.md` §12), никаких TODO по нему держать нельзя.
//!
//! ## Откуда данные
//!
//! Таблица и исключения — артефакты промера шага 4b3 (`proto2.py`, конфиг
//! `tail3+gstrict`), обучены **только** из golden-таблиц форка
//! `rodem/petrovich-rs@019e06d` (`tests/data/{surnames,firstnames,midnames}.tsv`,
//! 270 072 строки), методом lcp-выравнивания лемма↔форма. Проверить первичку
//! локально: `docs/dep-verify-crates.md` §12. Хэши файлов в репозитории —
//! `data/morph/README.md`.
//!
//! ## Формат таблицы (первичка: `proto2.py:293`, серийный формат писателя)
//!
//! ```text
//! type \t case \t wr \t lr \t genders \t tails
//! ```
//!
//! 1. `type` — `surname` | `firstname` | `midname`.
//! 2. `case` — `nom` `gen` `dat` `acc` `ins` `pre` (латиницей, НЕ русскими
//!    граммемами: русские написания `им рд дт вн тв пр` живут в первичных
//!    golden-таблицах и в [`Case::from_russian`], а в наш TSV они уже
//!    транслитерированы `CASE_MAP` прототипа).
//! 3. `wr` — окончание **формы** (что дописать к основе).
//! 4. `lr` — окончание **леммы** (что отнять у леммы).
//! 5. `genders` — наблюдавшиеся роды правила: `f`, `m` или `f,m`.
//!    Среднего рода в ФИО-таблице нет ни в одной строке (промер колонки: 19 `f`
//!    + 58 `m` + 42 `f,m`), поэтому [`Gender`] двухзначный.
//! 6. `tails` — через запятую хвосты длины 3 от **лемм**, на которых правило
//!    наблюдено; нужны как guard, когда `lr` короче 3 символов.
//!
//! Разбор и поиск — буквальный порт `_table_cands`/`classify` прототипа
//! (`proto2.py:92-127`) на `&'static str`-срезах `include_str!`: ноль
//! аллокаций на разборе строк таблицы, владение — только собранные кандидаты.
//!
//! ## Чего здесь НЕТ по сравнению с прототипом
//!
//! Прототип в конфиге `genderstrict` фильтровал кандидатов по полу, выведенному
//! из *пулов* (`pools` — лемма→род из golden) и статистики `sg` (хвост-3→род,
//! порог 0.9 и ≥5 наблюдений). Оба сигнала в артефакт не сериализованы
//! (`results-summary.md` строка 8: артефакты = `proto2.py` + таблица), так что
//! род берётся из колонки `genders` самого правила. Следствие — собственные
//! промеры этого порта (тест `coverage_on_golden_person_names`, 20.10):
//!
//! 1. покрытие 56 реальных ФИО из `data/golden/golden-v1.jsonl` = **56/56**
//!    (неверных разборов 0) — выше, чем 98.2 % у прототипа с пулами, и равно
//!    его же строке `tail3` без genderstrict;
//! 2. `strict`-уникальность (леммы+падеж+род одним значением) = **0/56**: в
//!    именной форме правило даёт `genders = f,m`, так что род по таблице не
//!    выводится вообще;
//! 3. паритет синтетического склонения с golden = **233/240 = 97.1 %**
//!    (тест `fixture_matches_golden_forms`).
//!
//! Пункт 2 — не дефект разбора, а свойство данных: род для суррогата обязан
//! брать из метки детектора либо из отдельного пола-пула (в таблицу не вошёл),
//! шаг 6 на `SpanParse::LemmaUnique` проверять род по маске.
//!
//! ## Нормализация
//!
//! Всё сравнение идёт по `norm(s) = s.to_uppercase()` с `Ё → Е` (строго как в
//! прототипе, `proto2.py:19`) — регистр и `Ё` входного слова теряются для
//! сопоставления, но [`MorphTable::inflect`] возвращает форму в маске регистра
//! исходной леммы. `Ё` внутри формы не восстанавливается: таблица обучена на
//! `Ё`→`Е`, это ограничение данных, а не реализации.

#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use std::sync::OnceLock;

/// Таблица правил (119 строк, 131 270 Б).
pub const TABLE_TSV: &str = include_str!("../../../data/morph/table_tail3_genderstrict.tsv");
/// Список исключений (80 строк, 5 298 Б).
pub const EXCEPTIONS_TSV: &str = include_str!("../../../data/morph/exceptions.tsv");

/// Длина хвоста-контекста, при которой правило доверяет себе без `tails`-guard.
const TAILN: usize = 3;

/// Падеж. Производные названия — латиницей, как в колонке `case` таблицы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Case {
    /// Именительный (`им`, `nom`) — сама лемма.
    Nom,
    /// Родительный (`рд`, `gen`).
    Gen,
    /// Дательный (`дт`, `dat`).
    Dat,
    /// Винительный (`вн`, `acc`).
    Acc,
    /// Творительный (`тв`, `ins`).
    Ins,
    /// Предложный (`пр`, `pre`).
    Pre,
}

impl Case {
    /// Все падежи в порядке таблицы.
    pub const ALL: [Case; 6] = [
        Case::Nom,
        Case::Gen,
        Case::Dat,
        Case::Acc,
        Case::Ins,
        Case::Pre,
    ];

    /// Разбор по латинской аббревиатуре из колонки `case`.
    #[must_use]
    pub fn from_abbrev(s: &str) -> Option<Self> {
        Some(match s {
            "nom" => Self::Nom,
            "gen" => Self::Gen,
            "dat" => Self::Dat,
            "acc" => Self::Acc,
            "ins" => Self::Ins,
            "pre" => Self::Pre,
            _ => return None,
        })
    }

    /// Разбор по русскому граммеме golden-таблиц (`им`/`рд`/`дт`/`вн`/`тв`/`пр`).
    #[must_use]
    pub fn from_russian(s: &str) -> Option<Self> {
        Some(match s {
            "им" => Self::Nom,
            "рд" => Self::Gen,
            "дт" => Self::Dat,
            "вн" => Self::Acc,
            "тв" => Self::Ins,
            "пр" => Self::Pre,
            _ => return None,
        })
    }

    /// Латинская аббревиатура — тот же алфавит, что в колонке `case`.
    #[must_use]
    pub fn abbrev(self) -> &'static str {
        match self {
            Self::Nom => "nom",
            Self::Gen => "gen",
            Self::Dat => "dat",
            Self::Acc => "acc",
            Self::Ins => "ins",
            Self::Pre => "pre",
        }
    }

    /// Русская граммема (для логов и сверки с golden).
    #[must_use]
    pub fn russian(self) -> &'static str {
        match self {
            Self::Nom => "им",
            Self::Gen => "рд",
            Self::Dat => "дт",
            Self::Acc => "вн",
            Self::Ins => "тв",
            Self::Pre => "пр",
        }
    }
}

/// Род. Двухзначный: среднего рода в таблице нет ни одной строки (промер
/// колонки `genders`: 19 `f`, 58 `m`, 42 `f,m`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Gender {
    /// Мужской (`m`, граммема `мр`).
    Masc,
    /// Женский (`f`, граммема `жр`).
    Fem,
}

/// Битовая маска родов — носитель колонки `genders` (`f,m` = оба).
type GenderMask = u8;
const M: GenderMask = 1;
const F: GenderMask = 2;

impl Gender {
    /// Бит маски.
    #[must_use]
    pub const fn bit(self) -> GenderMask {
        match self {
            Self::Masc => M,
            Self::Fem => F,
        }
    }

    /// Разбор токена колонки `genders`.
    fn from_token(s: &str) -> Option<GenderMask> {
        Some(match s {
            "m" => M,
            "f" => F,
            "m,f" | "f,m" => M | F,
            _ => return None,
        })
    }

    /// Разбор русской грамемы golden-таблицы; `ср` (средний род) сознательно
    /// не мапится — в ФИО-корпусе его нет (см. док [`Gender`]).
    #[must_use]
    pub fn from_russian(s: &str) -> Option<Self> {
        match s {
            "мр" => Some(Self::Masc),
            "жр" => Some(Self::Fem),
            _ => None,
        }
    }

    /// Токен колонки `genders`.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Masc => "m",
            Self::Fem => "f",
        }
    }
}

/// Тип токена ФИО. Порядок вариантов = `ORDER` прототипа (фамилия, имя,
/// отчество) — в нём же разбирается многословный спан.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameType {
    /// Фамилия.
    Surname,
    /// Имя.
    Firstname,
    /// Отчество.
    Midname,
}

impl NameType {
    /// Порядок токенов ФИО-спанного значения в датасете.
    pub const ORDER: [Self; 3] = [Self::Surname, Self::Firstname, Self::Midname];

    /// Токен колонки `type`.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Surname => "surname",
            Self::Firstname => "firstname",
            Self::Midname => "midname",
        }
    }

    /// Разбор колонки `type`.
    fn from_token(s: &str) -> Option<Self> {
        Some(match s {
            "surname" => Self::Surname,
            "firstname" => Self::Firstname,
            "midname" => Self::Midname,
            _ => return None,
        })
    }
}

/// Ошибка разбора таблицы. Данные компилируются в бинарь, так что сломанный
/// файл = сломанная сборка данных, а не рантайм; наружу это отдаётся как
/// `Err`, а не паника (в prod `panic` запрещён).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MorphError {
    /// Строка N таблицы разобранась не в 6 (или 5) полей.
    #[error("строка {line}: ожидалось {want} поля, найдено {got}")]
    WrongFieldCount {
        /// Номер строки в файле.
        line: usize,
        /// Сколько полей ждали.
        want: usize,
        /// Сколько нашли.
        got: usize,
    },
    /// Неизвестный токен `type`/`case`/`genders`.
    #[error("строка {line}: неизвестный токен {got:?} в поле {field}")]
    UnknownToken {
        /// Номер строки.
        line: usize,
        /// Имя поля.
        field: &'static str,
        /// Значение.
        got: String,
    },
    /// Файл не содержит ни одного правила.
    #[error("таблица пуста")]
    Empty,
}

/// Кандидат анализа: что слово могло бы быть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate<'a> {
    /// Восстановленная лемма (в норме `norm`: верхний регистр, `Ё`→`Е`).
    pub lemma: String,
    /// Тип токена.
    pub ty: NameType,
    /// Падеж формы.
    pub case: Case,
    /// Наблюдавшиеся роды правила.
    pub genders: GenderMask,
    /// Исключение ли это (`true`) или правило суффиксов (`false`).
    pub exact: bool,
    /// `wr`/`lr` правила — для отладки; у исключения — форма.
    pub rule: &'a str,
}

/// Разобранное правило.
struct Rule<'a> {
    ty: NameType,
    case: Case,
    gender: GenderMask,
    wr: &'a str,
    wr_chars: usize,
    lr: &'a str,
    lr_chars: usize,
    tails: Vec<&'a str>,
}

/// Разобранное исключение.
struct Exc<'a> {
    form: &'a str,
    ty: NameType,
    case: Case,
    lemma: &'a str,
    gender: GenderMask,
}

/// Итог разбора многословного спана.
///
/// Градация повторяет метрики прототипа: `D strict-uniq` = [`SpanParse::Unique`],
/// `D lemma-uniq` = [`SpanParse::Unique`] + [`SpanParse::LemmaUnique`]
/// (`results-summary.md`, матрица). Для суррогата нужна лемма, поэтому
/// `LemmaUnique` — рабочий исход, род отдаётся списком кандидатов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanParse {
    /// Единственная тройка (леммы, падеж, род).
    Unique {
        /// Леммы токенов в порядке [`NameType::ORDER`].
        lemmas: Vec<String>,
        /// Общий падеж.
        case: Case,
        /// Общий род.
        gender: Gender,
    },
    /// Леммы и падеж единственны, род не сошёлся: без пулов рода (см. док
    /// модуля) правило `nom` с `genders = f,m` не различает мужчин и женщин.
    LemmaUnique {
        /// Леммы токенов в порядке [`NameType::ORDER`].
        lemmas: Vec<String>,
        /// Общий падеж.
        case: Case,
        /// Роды-кандидаты (не пустой).
        genders: Vec<Gender>,
    },
    /// Разбор не единственный — вызывающий обязан откатиться к маскировке
    /// без восстановления (fail-closed).
    Ambiguous(Vec<Vec<String>>),
    /// Падеж/род противоречивы либо токен не разобран.
    NoMatch(String),
}

/// Суффиксальная таблица + исключения.
pub struct MorphTable<'a> {
    rules: Vec<Rule<'a>>,
    exc: Vec<Exc<'a>>,
}

/// Норма двух строк для сравнения (порядок аргументов не важен).
#[cfg(feature = "decliner")] // единственный потребитель — модуль decliner
pub(crate) fn same_norm(a: &str, b: &str) -> bool {
    norm(a) == norm(b)
}

/// Нормализация сравнения: верхний регистр и `Ё → Е` (как `proto2.py:19`).
#[must_use]
pub fn norm(s: &str) -> String {
    s.to_uppercase().replace('Ё', "Е")
}

/// Хвост из `n` символов (весь строка, если она короче).
fn tail_chars(s: &str, n: usize) -> &str {
    let mut it = s.char_indices().rev();
    let mut cut = s.len();
    for _ in 0..n {
        match it.next() {
            Some((i, _)) => cut = i,
            None => break,
        }
    }
    &s[cut..]
}

/// Приводит форму к маске регистра леммы: ВВВ→ВВВ, Стр→Стр, стр→стр.
///
/// Распознаются три маски (иерархия сверху вниз): ВВВ — все буквы заглавные;
/// Стр — первая заглавная, остальные строчные; стр — всё строчное. Смешанное
/// написание (`ПОЛОВЦОВА А.С.`) попадает в маску ВВВ: важнее заглавность всех
/// букв, чем позиция. `Ё` при этом не возвращается — см. ограничение нормы в
/// доке модуля.
fn apply_case(src: &str, form: &str) -> String {
    let letters: Vec<char> = src.chars().filter(|c| c.is_alphabetic()).collect();
    let all_upper = !letters.is_empty() && letters.iter().all(|c| c.is_uppercase());
    let cap = !letters.is_empty()
        && letters[0].is_uppercase()
        && letters[1..].iter().all(|c| c.is_lowercase());
    let mut out = String::with_capacity(form.len());
    for (i, ch) in form.chars().enumerate() {
        out.push(match (all_upper, cap, i == 0) {
            (true, _, _) | (false, true, true) => ch.to_uppercase().next().unwrap_or(ch),
            _ => ch.to_lowercase().next().unwrap_or(ch),
        });
    }
    out
}

impl<'a> MorphTable<'a> {
    /// Разбирает TSV таблицы и TSV исключений.
    ///
    /// Пустые строки и строки с `#` в начале пропускаются (в fixture-файлах
    /// их нет, в репозиторных — комментарий-шапка допустима).
    pub fn parse(table: &'a str, exceptions: &'a str) -> Result<MorphTable<'a>, MorphError> {
        let mut rules = Vec::new();
        for (i, line) in table.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&'a str> = line.split('\t').collect();
            if f.len() != 6 {
                return Err(MorphError::WrongFieldCount {
                    line: i + 1,
                    want: 6,
                    got: f.len(),
                });
            }
            let Some(ty) = NameType::from_token(f[0]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "type",
                    got: f[0].to_owned(),
                });
            };
            let Some(case) = Case::from_abbrev(f[1]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "case",
                    got: f[1].to_owned(),
                });
            };
            let Some(gender) = parse_gender_column(f[4]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "genders",
                    got: f[4].to_owned(),
                });
            };
            let mut tails: Vec<&'a str> = f[5].split(',').filter(|t| !t.is_empty()).collect();
            tails.sort_unstable();
            tails.dedup();
            rules.push(Rule {
                ty,
                case,
                gender,
                wr: f[2],
                wr_chars: f[2].chars().count(),
                lr: f[3],
                lr_chars: f[3].chars().count(),
                tails,
            });
        }
        if rules.is_empty() {
            return Err(MorphError::Empty);
        }

        let mut exc = Vec::new();
        for (i, line) in exceptions.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&'a str> = line.split('\t').collect();
            if f.len() != 5 {
                return Err(MorphError::WrongFieldCount {
                    line: i + 1,
                    want: 5,
                    got: f.len(),
                });
            }
            let Some(ty) = NameType::from_token(f[1]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "type",
                    got: f[1].to_owned(),
                });
            };
            let Some(case) = Case::from_abbrev(f[2]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "case",
                    got: f[2].to_owned(),
                });
            };
            let Some(gender) = parse_gender_column(f[4]) else {
                return Err(MorphError::UnknownToken {
                    line: i + 1,
                    field: "gender",
                    got: f[4].to_owned(),
                });
            };
            exc.push(Exc {
                form: f[0],
                ty,
                case,
                lemma: f[3],
                gender,
            });
        }
        Ok(Self { rules, exc })
    }

    /// Таблица, вкомпилированная в бинарь (`OnceLock`, разбор один раз).
    ///
    /// `None` означает, что данные в репозитории битые — тест
    /// `shipped_tables_parse_clean` это запрещает, а рантайм обязан откатиться к
    /// маскировке без восстановления, а не запаниковать.
    pub fn shipped() -> Option<&'static MorphTable<'static>> {
        static CACHE: OnceLock<Result<MorphTable<'static>, MorphError>> = OnceLock::new();
        CACHE
            .get_or_init(|| MorphTable::parse(TABLE_TSV, EXCEPTIONS_TSV))
            .as_ref()
            .ok()
    }

    /// Число правил и исключений — метрика для `/v1/metrics` и тестов.
    #[must_use]
    pub fn stats(&self) -> (usize, usize) {
        (self.rules.len(), self.exc.len())
    }

    /// Кандидаты по одному токену заданного типа: порт `_table_cands`
    /// (`proto2.py:92-106`) плюс исключения (`proto2.py:121-126`).
    pub fn cands(&self, word: &str, ty: NameType) -> Vec<Candidate<'a>> {
        let w = norm(word);
        let mut out = Vec::new();
        for r in &self.rules {
            if r.ty != ty || r.wr_chars > w.chars().count() || !w.ends_with(r.wr) {
                continue;
            }
            let Some(stem) = w.strip_suffix(r.wr) else {
                continue;
            };
            // `wr` ≠ "" и пустая основа = «слово совпало с одним окончанием»:
            // прототип такие отбрасывает (`if wr and not stem: continue`).
            if !r.wr.is_empty() && stem.is_empty() {
                continue;
            }
            let lemma = format!("{stem}{}", r.lr);
            if r.lr_chars < TAILN {
                let need = tail_chars(&lemma, TAILN);
                if r.tails.binary_search(&need).is_err() {
                    continue;
                }
            }
            out.push(Candidate {
                lemma,
                ty,
                case: r.case,
                genders: r.gender,
                exact: false,
                rule: r.wr,
            });
        }
        for e in &self.exc {
            if e.ty == ty && e.form == w {
                out.push(Candidate {
                    lemma: e.lemma.to_owned(),
                    ty,
                    case: e.case,
                    genders: e.gender,
                    exact: true,
                    rule: e.form,
                });
            }
        }
        out
    }

    /// Кандидаты по токену без привязки к типу (ФИО не подписано типом токена).
    pub fn cands_any(&self, word: &str) -> Vec<Candidate<'a>> {
        NameType::ORDER
            .iter()
            .flat_map(|t| self.cands(word, *t))
            .collect()
    }

    /// Какие падежи и роды возможны для слова.
    ///
    /// Возврат отсортирован и дедуплицирован; пустой список = слово не ФИО по
    /// таблице (для гарда это сигнал «маскировать как есть»).
    pub fn case_of(&self, word: &str) -> Vec<(Case, Gender)> {
        let mut out: Vec<(Case, Gender)> = self
            .cands_any(word)
            .iter()
            .flat_map(|c| {
                [Gender::Masc, Gender::Fem]
                    .into_iter()
                    .filter(|g| c.genders & g.bit() != 0)
                    .map(|g| (c.case, g))
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Склоняет лемму в падеж, подбирая тип сам (порядок [`NameType::ORDER`]).
    ///
    /// `None` — форма не выведена. Вызывающий обязан откатиться к маскировке
    /// исходного написания, а не выдумывать форму.
    pub fn inflect(&self, lemma: &str, want: Case, gender: Gender) -> Option<String> {
        NameType::ORDER
            .iter()
            .find_map(|t| self.inflect_typed(lemma, want, gender, *t))
    }

    /// Склоняет лемму известного типа.
    ///
    /// Приоритет — исключение (точная строка golden), затем первое подходящее
    /// правило в порядке файла: он детерминирован (писатель прототипа обходит
    /// `dict` в порядке вставки), так что форма воспроизводима.
    pub fn inflect_typed(
        &self,
        lemma: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
    ) -> Option<String> {
        let l = norm(lemma);
        for e in &self.exc {
            if e.ty == ty && e.case == want && e.lemma == l && e.gender & gender.bit() != 0 {
                return Some(apply_case(lemma, e.form));
            }
        }
        if want == Case::Nom {
            // Именительный = лемма; правил `nom` с непустым `wr` в таблице нет
            // (3 строки `nom` имеют пустые `wr`/`lr`) — возвращаем как есть.
            return Some(lemma.to_owned());
        }
        for r in &self.rules {
            if r.ty != ty || r.case != want || r.gender & gender.bit() == 0 {
                continue;
            }
            let Some(stem) = l.strip_suffix(r.lr) else {
                continue;
            };
            if !r.lr.is_empty() && stem.is_empty() {
                continue;
            }
            if r.lr_chars < TAILN && r.tails.binary_search(&tail_chars(&l, TAILN)).is_err() {
                continue;
            }
            return Some(apply_case(lemma, &format!("{stem}{}", r.wr)));
        }
        None
    }

    /// Все формы леммы во всех падежах (для предподсчёта суррогатов шагом 6).
    pub fn paradigm(&self, lemma: &str, gender: Gender) -> Vec<(Case, Option<String>)> {
        Case::ALL
            .iter()
            .map(|c| (*c, self.inflect(lemma, *c, gender)))
            .collect()
    }

    /// Разбор многословного ФИО-спана: порт `classify_span` (`proto2.py:127-143`).
    ///
    /// Токены трактуются по позициям [`NameType::ORDER`] — ровно как в
    /// `value_source` golden-датасета (фамилия имя отчество).
    pub fn parse_span(&self, value: &str) -> SpanParse {
        let toks: Vec<&str> = value.split_whitespace().collect();
        if toks.len() != NameType::ORDER.len() {
            return SpanParse::NoMatch(format!(
                "ожидалось {} токенов, найдено {}",
                NameType::ORDER.len(),
                toks.len()
            ));
        }
        let per: Vec<Vec<Candidate<'a>>> = toks
            .iter()
            .zip(NameType::ORDER)
            .map(|(t, ty)| self.cands(t, ty))
            .collect();
        for (i, cs) in per.iter().enumerate() {
            if cs.is_empty() {
                return SpanParse::NoMatch(format!("токен «{}» не разобран", toks[i]));
            }
        }
        // Пересечение множеств падежей по токенам — как `set.intersection` в
        // прототипе (proto2.py:136).
        let mut cases: Vec<Case> = Case::ALL
            .iter()
            .filter(|c| {
                per.iter()
                    .all(|cs| cs.iter().any(|x| x.case == **c && x.genders != 0))
            })
            .copied()
            .collect();
        cases.dedup();
        let mut sols: Vec<(Vec<String>, Case, GenderMask)> = Vec::new();
        for c in &cases {
            let lists: Vec<Vec<&Candidate<'a>>> = per
                .iter()
                .map(|cs| cs.iter().filter(|x| &x.case == c).collect())
                .collect();
            for combo in product(&lists) {
                let mut mask: GenderMask = M | F;
                for x in &combo {
                    mask &= x.genders;
                }
                if mask == 0 {
                    continue;
                }
                let lemmas: Vec<String> = combo.iter().map(|x| x.lemma.clone()).collect();
                // Одни и те же леммы+падеж из разных правил — одно решение с
                // объединённой маской родов (прототип считает их разными, отсюда
                // его `strict-uniq` ниже, чем `lemma-uniq`).
                if let Some(e) = sols.iter_mut().find(|(l, cc, _)| *l == lemmas && *cc == *c) {
                    e.2 |= mask;
                } else {
                    sols.push((lemmas, *c, mask));
                }
            }
        }
        match sols.len() {
            0 => SpanParse::NoMatch("падеж/род противоречивы".to_owned()),
            1 => {
                let (lemmas, case, mask) = sols.remove(0);
                match sole_gender(mask) {
                    Some(g) => SpanParse::Unique {
                        lemmas,
                        case,
                        gender: g,
                    },
                    None => SpanParse::LemmaUnique {
                        lemmas,
                        case,
                        genders: vec![Gender::Masc, Gender::Fem],
                    },
                }
            }
            _ => {
                // Только леммы: при неоднозначности решение «маскировать как
                // есть», детали на поведение вызывающего не влияют.
                SpanParse::Ambiguous(sols.into_iter().map(|(l, _, _)| l).collect())
            }
        }
    }
}

/// Разбор колонки родов: `f` | `m` | `f,m` | `m,f`.
fn parse_gender_column(s: &str) -> Option<GenderMask> {
    Gender::from_token(s)
}

/// Декартово произведение списков ссылок — минимальный аналог
/// `itertools::product` из прототипа (комбинаторика 3×≤4 кандидатов).
fn product<'a>(lists: &[Vec<&'a Candidate<'a>>]) -> Vec<Vec<&'a Candidate<'a>>> {
    let mut out: Vec<Vec<&'a Candidate<'a>>> = vec![Vec::new()];
    for list in lists {
        let mut next = Vec::with_capacity(out.len() * list.len().max(1));
        for acc in &out {
            for x in list {
                let mut v = acc.clone();
                v.push(*x);
                next.push(v);
            }
        }
        out = next;
    }
    out
}

/// Склонатор-резерв: `petrovich-core` за фичей `decliner` (SPEC §4, решение #46
/// ветка (а): таблица — основной путь, petrovich — второй источник формы).
///
/// Включается `cargo build -p guard-vault --features decliner`. Пин — git-rev
/// (`Cargo.toml` [dependencies.petrovich-core]), промер первички —
/// `docs/dep-verify-crates.md` §12: runtime-зависимостей 0, build-deps yaml.
///
/// Два отличия от таблицы, оба важны для вызывающего:
///
/// 1. падежей **пять**, не шесть: `petrovich::Case` не содержит именительного
///    (он = лемма), поэтому [`decline`] на [`Case::Nom`] возвращает саму лемму;
///    формулировку SPEC §4 «все 6 падежей» читать так (записано в §12);
/// 2. на нераспознанном имени petrovich возвращает вход без изменений
///    (`lib.rs:177` `unwrap_or(name_part.to_owned())`), а это неотличимо от
///    «форма совпадает с леммой». Значит `None` здесь = «движок не дал формы»,
///    и вызывающий обязан взять форму из таблицы, а не выдумывать её.
#[cfg(feature = "decliner")]
pub mod decliner {
    use super::{Case, Gender, MorphTable, NameType};

    /// Падеж → `petrovich::Case` (`None` для именительного — его нет в крейте).
    fn pcase(want: Case) -> Option<petrovich::Case> {
        Some(match want {
            Case::Gen => petrovich::Case::Genitive,
            Case::Dat => petrovich::Case::Dative,
            Case::Acc => petrovich::Case::Accusative,
            Case::Ins => petrovich::Case::Instrumental,
            Case::Pre => petrovich::Case::Prepositional,
            Case::Nom => return None,
        })
    }

    const fn pgender(gender: Gender) -> petrovich::Gender {
        match gender {
            Gender::Masc => petrovich::Gender::Male,
            Gender::Fem => petrovich::Gender::Female,
        }
    }

    /// Форма по petrovich; `None` — движок не распознал имя (см. док модуля).
    #[must_use]
    pub fn decline(lemma: &str, want: Case, gender: Gender, ty: NameType) -> Option<String> {
        if want == Case::Nom {
            return Some(lemma.to_owned());
        }
        let pc = pcase(want)?;
        let g = pgender(gender);
        let raw = match ty {
            NameType::Surname => petrovich::lastname(g, lemma, pc),
            NameType::Firstname => petrovich::firstname(g, lemma, pc),
            NameType::Midname => petrovich::middlename(g, lemma, pc),
        };
        if super::same_norm(&raw, lemma) {
            None
        } else {
            Some(raw)
        }
    }

    /// Таблица против petrovich: форма из таблицы выигрывает, petrovich добирает
    /// то, чего таблица не дала (шаг 6 строит суррогат через это).
    #[must_use]
    pub fn form_with_fallback(
        table: &MorphTable<'_>,
        lemma: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
    ) -> Option<String> {
        table
            .inflect_typed(lemma, want, gender, ty)
            .or_else(|| decline(lemma, want, gender, ty))
    }
}

/// Какого рода множество из маски (для логов: `Some` только если род один).
#[must_use]
pub fn sole_gender(mask: GenderMask) -> Option<Gender> {
    match mask {
        M => Some(Gender::Masc),
        F => Some(Gender::Fem),
        _ => None,
    }
}

/// Какие падежи и роды возможны для слова (удобная обёртка над
/// [`MorphTable::case_of`]; пустой список = не ФИО).
#[must_use]
pub fn case_of(word: &str) -> Vec<(Case, Gender)> {
    MorphTable::shipped().map_or_else(Vec::new, |t| t.case_of(word))
}

/// Склоняет лемму (обёртка над [`MorphTable::inflect`]).
#[must_use]
pub fn inflect(lemma: &str, want: Case, gender: Gender) -> Option<String> {
    MorphTable::shipped().and_then(|t| t.inflect(lemma, want, gender))
}

/// Разбирает ФИО-спан целиком (обёртка над [`MorphTable::parse_span`]).
#[must_use]
pub fn parse_span(value: &str) -> SpanParse {
    MorphTable::shipped().map_or_else(
        || SpanParse::NoMatch("таблица не разобрана".to_owned()),
        |t| t.parse_span(value),
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)] // паника в тесте = красный CI, это канал ответа
mod tests {
    use super::*;

    /// сверка формы с golden через ту же норму, что и сопоставление.
    fn same_form(a: &str, b: &str) -> bool {
        norm(a) == norm(b)
    }

    fn table() -> &'static MorphTable<'static> {
        MorphTable::shipped().expect("таблица в репозитории обязана разбираться")
    }

    /// Данные в репозитории — часть контракта: битый TSV = битый билд.
    #[test]
    fn shipped_tables_parse_clean() {
        let (rules, exc) = table().stats();
        // Числа промерены `wc -l`/`cut|uniq -c` по файлам в репозитории.
        assert_eq!(rules, 119, "правила: промер по таблице — 119 строк");
        assert_eq!(exc, 80, "исключения: промер по файлу — 80 строк");
        assert_eq!(TABLE_TSV.len(), 131_270, "размер таблицы уехал");
        assert_eq!(EXCEPTIONS_TSV.len(), 5298, "размер исключений уехал");
    }

    #[test]
    fn column_alphabets_are_the_documented_ones() {
        // Док модуля обещает конкретные написания граммем — проверим по данным.
        let mut cases = std::collections::BTreeSet::new();
        let mut types = std::collections::BTreeSet::new();
        let mut genders = std::collections::BTreeSet::new();
        for line in TABLE_TSV.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 6 {
                continue;
            }
            types.insert(f[0].to_owned());
            cases.insert(f[1].to_owned());
            genders.insert(f[4].to_owned());
        }
        assert_eq!(
            types,
            ["firstname", "midname", "surname"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert_eq!(
            cases,
            ["acc", "dat", "gen", "ins", "nom", "pre"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert_eq!(
            genders,
            ["f", "f,m", "m"].into_iter().map(str::to_owned).collect(),
            "среднего рода в таблице быть не должно"
        );
    }

    #[test]
    fn malformed_line_is_error_not_panic() {
        let bad = "surname\tnom\t\tf\n"; // 4 поля вместо 6
        assert!(matches!(
            MorphTable::parse(bad, ""),
            Err(MorphError::WrongFieldCount {
                want: 6,
                got: 4,
                ..
            })
        ));
        let bad_case = "surname\tтвор\t\tx\tf\tААА\n";
        assert!(matches!(
            MorphTable::parse(bad_case, ""),
            Err(MorphError::UnknownToken { field: "case", .. })
        ));
        let bad_exc = "БАБАЙЦА\tsurname\tacc\tБАБАЕЦ\tсредний\n";
        assert!(matches!(
            MorphTable::parse(TABLE_TSV, bad_exc),
            Err(MorphError::UnknownToken {
                field: "gender",
                ..
            })
        ));
        assert!(matches!(
            MorphTable::parse("# только комментарий\n", ""),
            Err(MorphError::Empty)
        ));
    }

    /// Прямой порт `_table_cands`: reconstruct леммы из формы.
    #[test]
    fn cands_recover_lemma_from_form() {
        let t = table();
        let c = t.cands("Ушакова", NameType::Surname);
        assert!(!c.is_empty(), "фамилия не разобралась");
        assert!(
            c.iter().any(|x| x.lemma == "УШАКОВ" && x.case == Case::Gen),
            "нет разбора «Ушакова» → УШАКОВ/родительный: {c:?}"
        );
        // Именительный = та же лемма.
        assert!(
            t.cands("Ушаков", NameType::Surname)
                .iter()
                .any(|x| x.lemma == "УШАКОВ" && x.case == Case::Nom),
            "именительный не нашёлся"
        );
    }

    #[test]
    fn case_of_returns_sorted_deduped_pairs() {
        let t = table();
        let pairs = t.case_of("Ушакова");
        assert!(pairs.contains(&(Case::Gen, Gender::Fem)));
        assert!(pairs.windows(2).all(|w| w[0] <= w[1]), "не отсортировано");
        let mut d = pairs.clone();
        d.dedup();
        assert_eq!(d.len(), pairs.len(), "дубликаты");
        // Несклоняемое мусорное слово не даёт вариантов вообще.
        assert_eq!(t.case_of("квант-кодировщик-7").len(), 0);
    }

    #[test]
    fn registry_of_common_forms() {
        let t = table();
        // Словарные проверки по одной форме на каждый падеж — сверено с
        // golden-таблицей первички (тест `fixture_matches_golden_forms`).
        assert_eq!(
            t.inflect("Ушакова", Case::Dat, Gender::Fem).as_deref(),
            Some("Ушаковой")
        );
        assert_eq!(
            t.inflect("Ушакова", Case::Ins, Gender::Fem).as_deref(),
            Some("Ушаковой")
        );
        assert_eq!(
            t.inflect("Ушаков", Case::Gen, Gender::Masc).as_deref(),
            Some("Ушакова")
        );
        assert_eq!(
            t.inflect("Ушаков", Case::Nom, Gender::Masc).as_deref(),
            Some("Ушаков")
        );
    }

    #[test]
    fn nominative_is_the_lemma_itself() {
        let t = table();
        for w in ["Смирнова", "Иванова", "Фёдоров", "Шмидт", "Алябьева"]
        {
            assert_eq!(
                t.inflect(w, Case::Nom, Gender::Fem).as_deref(),
                Some(w),
                "именительный обязан совпадать с леммой: {w}"
            );
        }
    }

    /// Ё→Е: форма по «Федоров» не должна терять регистровую маску, а вход с
    /// `Ё` обязан находиться по нормальной форме.
    #[test]
    fn yo_is_normalized_and_case_mask_is_preserved() {
        let t = table();
        assert!(
            !t.cands("Фёдорова", NameType::Surname).is_empty(),
            "вход с Ё не нашёлся"
        );
        let f = t.inflect("федоров", Case::Gen, Gender::Masc);
        assert_eq!(f.as_deref(), Some("федорова"), "маска регистра съехала");
        let up = t.inflect("ФЕДОРОВ", Case::Gen, Gender::Masc);
        assert_eq!(up.as_deref(), Some("ФЕДОРОВА"));
    }

    /// Метрика C — покрытие реальных ФИО из нашего golden-датасета.
    /// Считается заново здесь, а не копируется из `results-summary.md`.
    #[test]
    fn coverage_on_golden_person_names() {
        let path = format!(
            "{}/../../data/golden/golden-v1.jsonl",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).expect("golden-датасет обязан быть на месте");
        let mut total = 0_usize;
        let mut correct = 0_usize;
        let mut strict = 0_usize;
        let mut lemma_unique = 0_usize;
        let mut wrong = 0_usize;
        let mut uncovered = 0_usize;
        let mut fail: Vec<String> = Vec::new();
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).expect("golden — валидный JSON");
            let empty = Vec::new();
            let spans = v["spans"].as_array().unwrap_or(&empty);
            for s in spans {
                if s["category"].as_str() != Some("person_name") {
                    continue;
                }
                let Some(val) = s["value_source"].as_str() else {
                    continue;
                };
                total += 1;
                let lemmas = match table().parse_span(val) {
                    SpanParse::Unique { lemmas, .. } => {
                        strict += 1;
                        lemmas
                    }
                    SpanParse::LemmaUnique { lemmas, .. } => {
                        lemma_unique += 1;
                        lemmas
                    }
                    SpanParse::Ambiguous(_) => {
                        uncovered += 1;
                        fail.push(format!("{val} → ambiguous"));
                        continue;
                    }
                    SpanParse::NoMatch(r) => {
                        uncovered += 1;
                        fail.push(format!("{val} → no-match {r}"));
                        continue;
                    }
                };
                // Все 56 спанов датасета стоят в именительном падеже, поэтому
                // правильный разбор = леммы побуквенно совпали с токенами.
                let toks: Vec<&str> = val.split_whitespace().collect();
                if lemmas
                    .iter()
                    .map(|l| norm(l))
                    .eq(toks.iter().map(|t| norm(t)))
                {
                    correct += 1;
                } else {
                    wrong += 1;
                    fail.push(format!("{val} → {lemmas:?}"));
                }
            }
        }
        eprintln!(
            "метрика C: покрыто {correct}/{total}, strict {strict}, lemma-unique {lemma_unique}, неверных {wrong}, не покрыто {uncovered}"
        );
        assert_eq!(total, 56, "person_name-спанов в датасете должно быть 56");
        assert_eq!(
            correct + wrong + uncovered,
            total,
            "учтены не все спаны: {correct}+{wrong}+{uncovered} != {total}"
        );
        assert_eq!(
            wrong, 0,
            "единственный разбор противоречит оригиналу: {fail:?}"
        );
        // Пороги = собственное измерение этого порта (без пулов рода): см.
        // вывод теста. Округление вниз до 5 %-шага — чтобы тест не протух от
        // одной правки таблицы; перечитать при изменении таблицы.
        let cov = correct * 100 / total;
        assert!(
            cov >= 95,
            "покрытие C = {correct}/{total} = {cov} % ниже порога 95 %: {fail:?}"
        );
    }

    /// Fixture из первички: 240 реальных пар (лемма, форма, падеж, род).
    #[test]
    fn fixture_matches_golden_forms() {
        let raw = include_str!("../../../data/morph/fixture_golden_pairs.tsv");
        let tbl = table();
        let mut ok = 0_usize;
        let mut bad: Vec<String> = Vec::new();
        let mut total = 0_usize;
        for line in raw
            .lines()
            .filter(|ln| !ln.starts_with('#') && !ln.is_empty())
        {
            let cols: Vec<&str> = line.split('\t').collect();
            let [ty, lemma, form, case, gender] = cols.as_slice() else {
                panic!("fixture битый: {line}");
            };
            total += 1;
            let ty = NameType::from_token(ty).expect("тип fixture");
            let c = Case::from_abbrev(case).expect("падеж fixture");
            let g = match *gender {
                "m" => Gender::Masc,
                "f" => Gender::Fem,
                _ => panic!("род fixture: {gender}"),
            };
            match tbl.inflect_typed(lemma, c, g, ty) {
                Some(got) if same_form(&got, form) => ok += 1,
                Some(got) => bad.push(format!("{ty:?} {lemma} {c:?} → {got} ≠ {form}")),
                None => bad.push(format!("{ty:?} {lemma} {c:?} → нет формы")),
            }
        }
        assert_eq!(total, 240, "размер fixture уехал");
        let rate = f64::from(u32::try_from(ok).expect("fixture по размеру")) * 100.0
            / f64::from(u32::try_from(total).expect("fixture по размеру"));
        // Измерено этим портом: 233/240 = 97.1 %. Порог = измеренное минус
        // один промах (7 ошибок из 240 — это строки таблицы, где правило даёт
        // форму на -ова/-ева для мужской леммы; см. bad).
        assert!(
            rate >= 96.0,
            "правильных форм {ok}/{total} ({rate:.1} %) ниже измеренных 97.1 % — порт деградирует: {bad:?}"
        );
        eprintln!("fixture parity: {ok}/{total} = {rate:.1} %");
    }

    /// Паритет таблица ↔ petrovich на том же fixture. Чистая сверка двух
    /// источников формы; пороги — собственное измерение (см. eprintln).
    #[cfg(feature = "decliner")]
    #[test]
    fn parity_table_vs_petrovich() {
        use crate::morph::decliner;
        let raw = include_str!("../../../data/morph/fixture_golden_pairs.tsv");
        let tbl = table();
        let (mut agree, mut table_only, mut petrovich_only, mut both_no, mut differ) =
            (0_usize, 0_usize, 0_usize, 0_usize, 0_usize);
        let mut diff: Vec<String> = Vec::new();
        for line in raw
            .lines()
            .filter(|ln| !ln.starts_with('#') && !ln.is_empty())
        {
            let cols: Vec<&str> = line.split('\t').collect();
            let [ty, lemma, form, case, gender] = cols.as_slice() else {
                panic!("fixture битый: {line}");
            };
            let Some(want) = Case::from_abbrev(case) else {
                panic!("падеж fixture: {case}");
            };
            if want == Case::Nom {
                // Именительного в petrovich нет — сравнивать нечего.
                continue;
            }
            let ttype = NameType::from_token(ty).expect("тип fixture");
            let gd = match *gender {
                "m" => Gender::Masc,
                "f" => Gender::Fem,
                _ => panic!("род fixture: {gender}"),
            };
            let golden = {
                let mut chars = form.chars().collect::<String>();
                chars.make_ascii_uppercase();
                chars.replace('Ё', "Е")
            };
            let from_table = tbl.inflect_typed(lemma, want, gd, ttype);
            let from_pet = decliner::decline(lemma, want, gd, ttype);
            match (&from_table, &from_pet) {
                (None, None) => both_no += 1,
                (Some(x), Some(y)) if norm(x) == norm(y) => {
                    if norm(x) == golden {
                        agree += 1;
                    } else {
                        differ += 1;
                        diff.push(format!("{lemma} {case} → оба дали {x}, golden {golden}"));
                    }
                }
                (Some(x), None) => {
                    table_only += 1;
                    if norm(x) != golden {
                        diff.push(format!("{lemma} {case} → таблица {x} ≠ golden {golden}"));
                    }
                }
                (None, Some(y)) => {
                    petrovich_only += 1;
                    if norm(y) != golden {
                        diff.push(format!("{lemma} {case} → petrovich {y} ≠ golden {golden}"));
                    }
                }
                (Some(x), Some(y)) => {
                    differ += 1;
                    diff.push(format!("{lemma} {case} → таблица {x} vs petrovich {y}"));
                }
            }
        }
        let union = agree + table_only + petrovich_only;
        eprintln!(
            "паритет petrovich: совпало {agree}, только таблица {table_only}, только petrovich {petrovich_only}, оба молчат {both_no}, расходятся {differ}; объединение покрывает {union}/200"
        );
        assert_eq!(
            agree + table_only + petrovich_only + both_no + differ,
            200,
            "учтены не все строки fixture (200 некосвенных)"
        );
        // Пороги = измеренное ниже на один случай; перечитать при смене пина.
        assert!(
            agree >= 150,
            "petrovich разошёлся с таблицей сильнее меры: {diff:?}"
        );
        assert!(
            union >= 180,
            "объединение двух источников covers {union}/200"
        );
    }

    #[test]
    fn exceptions_win_over_rules() {
        let t = table();
        // Исключение из таблицы: БАБАЙЦА (родительный/винительный) → БАБАЕЦ.
        assert_eq!(
            t.inflect("БАБАЕЦ", Case::Gen, Gender::Masc).as_deref(),
            Some("БАБАЙЦА"),
            "исключение не применено"
        );
        assert!(
            t.cands("БАБАЙЦА", NameType::Surname)
                .iter()
                .any(|c| c.exact && c.lemma == "БАБАЕЦ"),
            "исключение не участвует в анализе формы"
        );
    }

    #[test]
    fn span_parse_handles_full_names_and_rejects_garbage() {
        let t = table();
        assert!(matches!(
            t.parse_span("Ушакова Кира Саввична"),
            SpanParse::Unique { .. } | SpanParse::LemmaUnique { .. } | SpanParse::Ambiguous(_)
        ));
        assert!(matches!(t.parse_span("два слова"), SpanParse::NoMatch(_)));
        assert!(matches!(
            t.parse_span("ксерограф дубликат копир"),
            SpanParse::NoMatch(_)
        ));
    }

    #[test]
    fn norm_matches_the_prototype() {
        assert_eq!(norm("фёдоров"), "ФЕДОРОВ");
        assert_eq!(norm("Ёлка"), "ЕЛКА");
        assert_eq!(
            norm("Алябьева"),
            "АЛЯБЬЕВА",
            "ё в середине не должна исчезать из norm"
        );
        assert_eq!(tail_chars("АЛЯБЬЕВА", 3), "ЕВА");
        assert_eq!(tail_chars("ОВ", 3), "ОВ");
    }

    #[test]
    fn case_and_gender_spellings_roundtrip() {
        for c in Case::ALL {
            assert_eq!(Case::from_abbrev(c.abbrev()), Some(c));
            assert_eq!(Case::from_russian(c.russian()), Some(c));
        }
        assert_eq!(Case::from_abbrev("твор"), None);
        assert_eq!(Case::from_russian("зв"), None);
        assert_eq!(Gender::from_russian("ср"), None, "среднего рода нет");
        assert_eq!(Gender::from_token("f,m"), Some(M | F));
        assert_eq!(sole_gender(M | F), None);
        assert_eq!(sole_gender(F), Some(Gender::Fem));
    }
}
