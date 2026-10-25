//! Пул суррогатов — библиотека лемм, из которых [`VaultEngine`] берёт подмену.
//!
//! [`VaultEngine`]: crate::VaultEngine
//!
//! # Почему файл, а не константа в коде
//!
//! До шага 7а пул был списком из 24 имён (`const SURROGATES`), по 4 леммы на
//! корзину `(тип, род)`. Четыре слота на позицию — это «дири-голо на 5-м имени»:
//! промер `examples/pool_probe.rs` на `golden-v1` (метрика — **отказы**: пары
//! разных оригиналов в одном слоте) даёт 218 пар из 351, то есть 62.1 %: второй
//! оригинал в сессии упирался в занятый слот чаще, чем нет. Те же данные в
//! других единицах — 347 совпадений имён по позициям в 351 паре и 248 пар с
//! общим слотом; разница между 347 и 218 есть пары с общим токеном, где владеет
//! один и тот же оригинал и first-writer-wins идемпотентен, — отказа там нет, и
//! в документации отказной метрикой считается 218. Пул вынесен в
//! `data/morph/surrogates.tsv` и генерируется
//! `scripts/surrogen.py` из той же первички, что и морф-таблица (petrovich-rs
//! `019e06d`, MIT, §2 `THIRD-PARTY-NOTICES.md`), по шести фильтрам — см. шапку
//! генератора.
//!
//! # Чем защищён артефакт
//!
//! Молчаливую правку файла ловят тесты: [`SURROGATES_TSV`] закреплён длиной и
//! числом строк, каждая лемма обязана сгибаться нашей таблицей во всех шести
//! падежах, корзина — держать не меньше [`MIN_PER_BUCKET`], а пул — не
//! пересекаться с токенами `person_name` из `data/golden/golden-v1.jsonl`.
//! Совпадение с реальным именем в том же документе сломало бы гейт P6
//! `crate::VaultEngine::is_current_surrogate`: легитимный запрос был бы отвергнут
//! как «повторная анонимизация». Там же, кстати, причина фильтра `DROP`: из
//! старой константы не сгибались нашей таблицей на косвенных падежах Пимен,
//! Назар, Захар, Куприян и Селиван — в пул попадает только то, что покрыто
//! таблицей полностью, а не «имена, которые кажутся правдоподобными».
//!
//! # Разбор — тотальный
//!
//! Строка, не похожая на `тип ⇥ род ⇥ лемма`, не уронит демон: она пропускается,
//! а пропуск виден по [`stats`] и по тестам. Корзина меньше [`MIN_PER_BUCKET`]
//! — это уже не расширение пула, и выборка деградирует не к ложной подмене, а к
//! отказу выдать суррогат (откат на метку, см. `guard-daemon`).

use crate::morph::{Gender, NameType};
use std::sync::OnceLock;

/// Сырой артефакт пула, вкомпилирован (см. § «Чем защищён артефакт»).
pub const SURROGATES_TSV: &str = include_str!("../../../data/morph/surrogates.tsv");

/// Минимум лемм в корзине: вдвое ниже сегодняшнего (128), но вшестеро выше
/// дна, с которого начали (#60: 4 на корзину).
pub const MIN_PER_BUCKET: usize = 64;

/// Счётчики разбора артефакта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Строк-кандидатов (без комментариев и пустых).
    pub lines: usize,
    /// Строк разобрано и положено в корзину.
    pub accepted: usize,
    /// Строк отвергнуто: битый формат, неизвестный тип или род.
    pub rejected: usize,
    /// Наполненных корзин (`[тип][род]`), ожидаемо `N_BUCKETS`.
    pub buckets_filled: usize,
    /// Размер наименьшей корзины: по нему судят о деградации пула.
    pub min_bucket: usize,
}

/// Леммы, разложенные по корзинам `[тип][род]`.
struct Buckets {
    slots: [[Vec<&'static str>; 2]; 3],
    lines: usize,
    accepted: usize,
    rejected: usize,
}

fn ty_slot(ty: NameType) -> usize {
    match ty {
        NameType::Surname => 0,
        NameType::Firstname => 1,
        NameType::Midname => 2,
    }
}

fn gender_slot(g: Gender) -> usize {
    match g {
        Gender::Masc => 0,
        Gender::Fem => 1,
    }
}

/// Разбор TSV. Тотальный: битая строка попадает в `rejected`, а не в панику.
fn parse(t: &'static str) -> Buckets {
    let mut slots = [
        [Vec::new(), Vec::new()],
        [Vec::new(), Vec::new()],
        [Vec::new(), Vec::new()],
    ];
    let (mut lines, mut accepted, mut rejected) = (0usize, 0usize, 0usize);
    for line in t.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines += 1;
        let mut cols = line.split('\t');
        let (ty, gender, lemma) = (cols.next(), cols.next(), cols.next());
        let ty = match ty {
            Some("surname") => NameType::Surname,
            Some("firstname") => NameType::Firstname,
            Some("midname") => NameType::Midname,
            _ => {
                rejected += 1;
                continue;
            }
        };
        let gender = match gender {
            Some("m") => Gender::Masc,
            Some("f") => Gender::Fem,
            _ => {
                rejected += 1;
                continue;
            }
        };
        let extra = cols.next();
        let Some(lemma) = lemma.filter(|l| !l.is_empty() && !l.contains(' ')) else {
            rejected += 1;
            continue;
        };
        if extra.is_some() {
            rejected += 1;
            continue;
        }
        slots[ty_slot(ty)][gender_slot(gender)].push(lemma);
        accepted += 1;
    }
    Buckets {
        slots,
        lines,
        accepted,
        rejected,
    }
}

fn buckets() -> &'static Buckets {
    static B: OnceLock<Buckets> = OnceLock::new();
    B.get_or_init(|| parse(SURROGATES_TSV))
}

/// Леммы пула для пары `(тип, род)`, в порядке файла. Файл отсортирован, а
/// выборка из него детерминирована хэшем леммы — значит одно и то же имя даёт
/// одну и ту же форму между перезапусками.
#[must_use]
pub fn lemmas(ty: NameType, gender: Gender) -> &'static [&'static str] {
    &buckets().slots[ty_slot(ty)][gender_slot(gender)]
}

/// Счётчики разбора артефакта.
#[must_use]
pub fn stats() -> PoolStats {
    let b = buckets();
    let mut min = usize::MAX;
    let mut filled = 0usize;
    for bucket in &b.slots {
        for list in bucket {
            if !list.is_empty() {
                filled += 1;
            }
            min = min.min(list.len());
        }
    }
    PoolStats {
        lines: b.lines,
        accepted: b.accepted,
        rejected: b.rejected,
        buckets_filled: filled,
        min_bucket: if min == usize::MAX { 0 } else { min },
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_test_module
)] // паника в тесте = красный CI, это канал ответа
mod tests {
    use super::*;
    use crate::morph::{Case, MorphTable};
    use std::collections::BTreeSet;

    /// Токены `person_name` из golden-набора, верхним регистром без `Ё`.
    fn golden_tokens() -> BTreeSet<String> {
        let raw = std::fs::read_to_string(format!(
            "{}/../../data/golden/golden-v1.jsonl",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("golden-набор обязан читаться в тесте");
        let mut out = BTreeSet::new();
        for line in raw.lines() {
            let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(spans) = rec.get("spans").and_then(|s| s.as_array()) else {
                continue;
            };
            for sp in spans {
                if sp.get("category").and_then(serde_json::Value::as_str) != Some("person_name") {
                    continue;
                }
                // #238: фильтр по ТОКЕНУ, не строке: транслит-пары несут
                // кириллицу в тексте, а P6-проверка («суррогат не должен
                // жить в golden») смотрит кириллический пул — латинские
                // токены («Ushakov», «Petr») вне алфавита пула.
                let is_cyrillic_token = |w: &str| w.chars().any(|c| ('Ѐ'..='ӿ').contains(&c));
                let value = sp
                    .get("value_source")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        let text = rec.get("text")?.as_str()?;
                        let start = usize::try_from(sp.get("start_byte")?.as_u64()?).ok()?;
                        let end = usize::try_from(sp.get("end_byte")?.as_u64()?).ok()?;
                        Some(text.get(start..end)?.to_owned())
                    });
                if let Some(v) = value {
                    for w in v.split_whitespace() {
                        if !is_cyrillic_token(w) {
                            continue;
                        }
                        out.insert(w.to_uppercase().replace('Ё', "Е"));
                    }
                }
            }
        }
        out
    }

    /// Разбор артефакта: пины длины и числа строк + расхождение счётчиков.
    ///
    /// Числа закреплены, потому что молчаливая правка `data/morph/surrogates.tsv`
    /// (регенерация другой версией скрипта, ручная «мелкая» правка) — тот же
    /// класс дефекта, что и прошлый пул из 24 имён: пул тихо сжимается, и
    /// коллизии возвращаются.
    #[test]
    fn pool_artifact_is_pinned() {
        assert_eq!(SURROGATES_TSV.len(), 22_208, "размер пула уехал");
        assert_eq!(SURROGATES_TSV.lines().count(), 772, "число строк уехало");
        let s = stats();
        assert_eq!(s.lines, 768, "строк-кандидатов");
        assert_eq!(s.accepted, 768, "разобрано");
        assert_eq!(s.rejected, 0, "битых строк быть не должно");
        assert!(
            s.min_bucket >= MIN_PER_BUCKET,
            "корзина сдохла до {MIN_PER_BUCKET}: пул перестаёт быть расширением (#60)"
        );
        assert_eq!(
            s.buckets_filled,
            NameType::ORDER.len() * 2,
            "пул обязан держать все корзины: 3 типа × 2 рода"
        );
        for ty in NameType::ORDER {
            for gender in [Gender::Masc, Gender::Fem] {
                assert_eq!(lemmas(ty, gender).len(), 128, "{ty:?}/{gender:?}");
            }
        }
    }

    /// Битая строка не роняет разбор и не попадает в корзину: счётчик ловит её,
    /// а `lemmas()` остаётся в своих границах.
    #[test]
    fn pool_parse_is_total_not_panicking() {
        let broken = concat!(
            "# коммент\n",
            "\n",
            "surname\tm\tВетров\n",
            "surname\tм\tЛожныйРодКириллицей\n",
            "unknown\tm\tХлеб\n",
            "surname\tf\tДюжина\tлишняя\tколонка\n",
            "surname\tm\t \n",
        );
        let b = parse(broken);
        assert_eq!(
            (b.lines, b.accepted, b.rejected),
            (5, 1, 4),
            "счётчики разбора"
        );
        assert_eq!(b.slots[0][0], vec!["Ветров"], "в корзину только валидное");
    }

    /// Каждый пул — это обещание «такая форма существует». Лемма, которую наша
    /// таблица не гнёт, дала бы `None` на выдаче, и имя ушло бы на метку:
    /// не дефект безопасности, но тихая деградация, за которую отвечает файл.
    /// Плюс непересечение с golden: суррогат, совпавший с реальным именем из
    /// корпуса, ломает гейт P6 в тот момент, когда он нужнее всего.
    #[test]
    fn surrogate_pool_is_clean_and_declinable() {
        let t = MorphTable::shipped().expect("таблица");
        let golden = golden_tokens();
        let mut bad: Vec<String> = Vec::new();
        for line in SURROGATES_TSV.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut cols = line.split('\t');
            let (ty_s, g_s, lemma) = (
                cols.next().unwrap_or_default(),
                cols.next().unwrap_or_default(),
                cols.next().unwrap_or_default(),
            );
            let ty = match ty_s {
                "surname" => NameType::Surname,
                "firstname" => NameType::Firstname,
                _ => NameType::Midname,
            };
            let gender = if g_s == "f" {
                Gender::Fem
            } else {
                Gender::Masc
            };
            assert!(
                !golden.contains(&lemma.to_uppercase().replace('Ё', "Е")),
                "суррогат {lemma} есть в golden-v1 — P6 отверг бы легитимный запрос"
            );
            for case in Case::ALL {
                match t.inflect_typed(lemma, case, gender, ty) {
                    None => bad.push(format!("{lemma} {case:?}: таблица не дала формы")),
                    Some(f) if f.is_empty() => bad.push(format!("{lemma} {case:?}: пусто")),
                    Some(f) if case != Case::Nom && f == lemma => {
                        bad.push(format!("{lemma} {case:?}: вернула лемму ({f})"));
                    }
                    Some(_) => {}
                }
            }
        }
        assert!(
            bad.is_empty(),
            "пул суррогатов нечист ({} позиц\n{}\n— менять только вместе с проверкой, \
             отвергнутые леммы вычеркиваются фильтром DROP в scripts/surrogen.py)",
            bad.len(),
            bad.join("\n")
        );
    }
}
