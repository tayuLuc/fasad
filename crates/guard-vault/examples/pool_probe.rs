//! Промер пула суррогатов (#60, шаг 7а) — три режима.
//!
//! `check` — печатает леммы `data/morph/surrogates.tsv`, которые наша морф-таблица
//! не гнёт (не даёт формы или возвращает лемму в косвенном падеже). Вывод
//! скармливается фильтру `DROP` в `scripts/surrogen.py`: артефакт обязан быть
//! чистым до теста, а не «почти чистым, тест красным».
//!
//! `probe` — профиль коллизий на реальных ФИО из `data/golden/golden-v1.jsonl`
//! для корзин разного размера: исторические 4 леммы на корзину (список до #60,
//! чтобы цифру «до» не выдумывать) и срезы текущего артефакта 16/32/64/128.
//! Метрика — доля пар ФИО, которые **упёрлись бы в отказ**: хотя бы в одной
//! позиции у них разные леммы-ключи, но одна и та же лемма пула. Просто совпадение
//! слота не считается: два «Ивановича» — один владелец слота, и движок на них не
//! отказывает. Именно такая пара на шаге 6 упиралась в `Collision` в движке и в
//! `422` в демоне. Считается вызовом `VaultEngine::pick_surrogat_from`, т.е. тем
//! же кодом, что выбирает форму на запросе, а не моделью «посчитаем хэши».
//!
//! Отбор имён: те, что демон вообще пустит на суррогатный путь, — разбор
//! `Unique`/`LemmaUnique` с родом по окончанию первого токена и 2..=3 токена.
//! Остальные на суррогатный путь не попадают в принципе (`NoMatch`/`Ambiguous`
//! = маска меткой), и считать коллизии по ним значило бы
//! приписывать пулу чужие отказа. Отсев печатается отдельным числом.
//!
//! Срез корзины размера `n` берётся равным шагом по отсортированному списку, а не
//! первыми `n` строками: префикс был бы сплошь из «А…», и профиль получился бы
//! невыдуманным, но нерепрезентативным.
//!
//! Третий режим, `forms <ФИО>…`, печатает выбранные формы по тем же правилам
//! разбора: из него берутся литералы для тестов и README, а не на слух.
//!
//! Запуск: `cargo run -p guard-vault --example pool_probe -- probe`.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "промерный харнес, не prod: счётчики пар ≤ 2^53 (351 шт.), байтовые оффсеты из собственного golden-файла; список = ровно сработавшие классы clippy 1.97 и 1.99"
)]

use guard_vault::VaultEngine;
use guard_vault::morph::{Case, Gender, MorphTable, NameType, SpanParse, suffix_gender};
use guard_vault::pool::{self, SURROGATES_TSV};
use std::collections::BTreeSet;

/// Исторический пул до #60: `const SURROGATES` из `lib.rs` на коммите `832d7b4`.
const HISTORICAL: [(&str, Gender, NameType); 24] = [
    ("Ветров", Gender::Masc, NameType::Surname),
    ("Седов", Gender::Masc, NameType::Surname),
    ("Тенин", Gender::Masc, NameType::Surname),
    ("Леснов", Gender::Masc, NameType::Surname),
    ("Ветрова", Gender::Fem, NameType::Surname),
    ("Седова", Gender::Fem, NameType::Surname),
    ("Тенина", Gender::Fem, NameType::Surname),
    ("Леснова", Gender::Fem, NameType::Surname),
    ("Афанасий", Gender::Masc, NameType::Firstname),
    ("Спиридон", Gender::Masc, NameType::Firstname),
    ("Всеслав", Gender::Masc, NameType::Firstname),
    ("Парфен", Gender::Masc, NameType::Firstname),
    ("Варвара", Gender::Fem, NameType::Firstname),
    ("Прасковья", Gender::Fem, NameType::Firstname),
    ("Матрона", Gender::Fem, NameType::Firstname),
    ("Агафья", Gender::Fem, NameType::Firstname),
    ("Афанасьевич", Gender::Masc, NameType::Midname),
    ("Пименович", Gender::Masc, NameType::Midname),
    ("Назарович", Gender::Masc, NameType::Midname),
    ("Парфенович", Gender::Masc, NameType::Midname),
    ("Афанасьевна", Gender::Fem, NameType::Midname),
    ("Пименовна", Gender::Fem, NameType::Midname),
    ("Назаровна", Gender::Fem, NameType::Midname),
    ("Парфеновна", Gender::Fem, NameType::Midname),
];

/// Размеры корзины, для которых считается профиль.
const SIZES: [usize; 5] = [4, 16, 32, 64, 128];

/// Имя, годное для суррогатного пути: surface-токены в порядке `NameType::ORDER`
/// и лемма-ключ каждого токена (то, по чему `pick_surrogat` считает слот).
struct Name {
    value: String,
    tokens: Vec<(String, NameType, Gender, Case, String)>,
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(rel)
        .or_else(|_| {
            std::fs::read_to_string(format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), rel))
        })
        .unwrap_or_else(|e| panic!("нет {rel}: {e}"))
}

/// Строки артефакта: `(тип, род, лемма)`.
fn rows() -> Vec<(NameType, Gender, &'static str)> {
    let mut out = Vec::new();
    for line in SURROGATES_TSV.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut c = line.split('\t');
        let (Some(t), Some(g), Some(l)) = (c.next(), c.next(), c.next()) else {
            continue;
        };
        let ty = match t {
            "surname" => NameType::Surname,
            "firstname" => NameType::Firstname,
            _ => NameType::Midname,
        };
        let gender = if g == "f" { Gender::Fem } else { Gender::Masc };
        out.push((ty, gender, l));
    }
    out
}

fn slot(ty: NameType, gender: Gender) -> usize {
    let t = match ty {
        NameType::Surname => 0,
        NameType::Firstname => 1,
        NameType::Midname => 2,
    };
    t * 2 + usize::from(gender == Gender::Fem)
}

/// Корзина размера `n`: исторический список или равным шагом по артефакту.
fn bucket(n: usize, full: &[Vec<&'static str>], s: usize) -> Vec<&'static str> {
    if n == 4 {
        return HISTORICAL
            .iter()
            .filter(|(_, g, t)| slot(*t, *g) == s)
            .map(|(l, _, _)| *l)
            .collect();
    }
    let src = &full[s];
    let step = (src.len() / n).max(1);
    (0..n).map(|i| src[(i * step).min(src.len() - 1)]).collect()
}

fn check() -> i32 {
    let Some(table) = MorphTable::shipped() else {
        eprintln!("морф-таблица не разбрана");
        return 1;
    };
    let r = rows();
    let mut bad = BTreeSet::new();
    for (ty, gender, lemma) in &r {
        for case in Case::ALL {
            let declined = match table.inflect_typed(lemma, case, *gender, *ty) {
                None => false,
                Some(f) => !f.is_empty() && (case == Case::Nom || f != *lemma),
            };
            if !declined {
                bad.insert(*lemma);
                break;
            }
        }
    }
    for l in &bad {
        println!("{l}");
    }
    eprintln!("проверено {}, отвергнуто таблицей {}", r.len(), bad.len());
    0
}

fn names(table: &MorphTable<'_>) -> (Vec<Name>, usize, usize, usize) {
    let raw = repo_file("data/golden/golden-v1.jsonl");
    let mut seen = BTreeSet::new();
    let mut out: Vec<Name> = Vec::new();
    let (mut unparsed, mut not_three, mut unresolved) = (0usize, 0usize, 0usize);
    for line in raw.lines() {
        let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let text = rec
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let Some(spans) = rec.get("spans").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for sp in spans {
            if sp.get("category").and_then(serde_json::Value::as_str) != Some("person_name") {
                continue;
            }
            let value = sp
                .get("value_source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    let a = sp.get("start_byte")?.as_u64()? as usize;
                    let b = sp.get("end_byte")?.as_u64()? as usize;
                    text.get(a..b).map(str::to_owned)
                })
                .unwrap_or_default();
            let toks: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
            // Ровно то же условие, что в демоне: токенов 2..=3 и столько же лемм.
            if !(2..=NameType::ORDER.len()).contains(&toks.len()) {
                not_three += 1;
                continue;
            }
            if !seen.insert(value.clone()) {
                continue;
            }
            // Ровно как демон: `Unique` даёт род сам, `LemmaUnique` — только
            // кандидатов, и род добирается окончанием первого токена (`f`, `m`
            // в именных правилах не различаются). Тот же `suffix_gender`, что
            // на запросе, — иначе промер мерил бы не то поведение.
            let (lemmas, case, gender) = match table.parse_span(&value) {
                SpanParse::Unique {
                    lemmas,
                    case,
                    gender,
                } => (lemmas, case, Some(gender)),
                SpanParse::LemmaUnique {
                    lemmas,
                    case,
                    genders,
                } => (
                    lemmas,
                    case,
                    // Род — только по окончанию первого токена, как в демоне:
                    // угаданный род дал бы промер не того поведения.
                    toks.first()
                        .and_then(|w| suffix_gender(w))
                        .filter(|g| genders.contains(g)),
                ),
                _ => {
                    unparsed += 1;
                    continue;
                }
            };
            let Some(gender) = gender else {
                unresolved += 1;
                continue;
            };
            if lemmas.len() != toks.len() {
                not_three += 1;
                continue;
            }
            out.push(Name {
                value,
                tokens: toks
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        (
                            w.clone(),
                            NameType::ORDER[i],
                            gender,
                            case,
                            lemmas[i].clone(),
                        )
                    })
                    .collect(),
            });
        }
    }
    (out, unparsed, not_three, unresolved)
}

fn probe() -> i32 {
    let Some(table) = MorphTable::shipped() else {
        eprintln!("морф-таблица не разбрана");
        return 1;
    };
    let full = rows()
        .into_iter()
        .fold(vec![Vec::new(); 6], |mut acc, (ty, g, l)| {
            acc[slot(ty, g)].push(l);
            acc
        });
    let (names, unparsed, not_three, unresolved) = names(table);
    println!(
        "golden-v1: имён годно {}, не разбирается {unparsed}, не три токена {not_three}, род не решён {unresolved}",
        names.len()
    );
    let pairs = names.len() * (names.len() - 1) / 2;
    for n in SIZES {
        // Отказ движка наступает не на «совпал слот», а на «совпал слот при
        // разных ключах»: два «Ивановых» с общей фамилой — один владелец слота,
        // и движок на них не отказывает (идемпотентность по пересечению
        // множеств лемм в `surrogat_for_gender`). Метрика считает отказные пары.
        let picks: Vec<Vec<(&str, &str)>> = names
            .iter()
            .map(|nm| {
                nm.tokens
                    .iter()
                    .map(|(w, ty, g, case, key)| {
                        let b = bucket(n, &full, slot(*ty, *g));
                        (
                            VaultEngine::pick_surrogat_from(w, *case, *g, *ty, &b)
                                .map_or("<нет формы>", |s| s.lemma),
                            key.as_str(),
                        )
                    })
                    .collect()
            })
            .collect();
        let mut shared = 0usize;
        let mut examples: Vec<String> = Vec::new();
        for i in 0..names.len() {
            for j in i + 1..names.len() {
                if picks[i]
                    .iter()
                    .zip(&picks[j])
                    .any(|(x, y)| x.0 == y.0 && x.0 != "<нет формы>" && x.1 != y.1)
                {
                    shared += 1;
                    if n == 128 && examples.len() < 4 {
                        examples.push(format!("{} ↔ {}", names[i].value, names[j].value));
                    }
                }
            }
        }
        for x in &examples {
            println!("  отказная пара: {x}");
        }
        let lens: Vec<usize> = (0..6).map(|s| bucket(n, &full, s).len()).collect();
        let pct = 100.0 * shared as f64 / pairs.max(1) as f64;
        println!(
            "корзина {n:>3} (фактически {lens:?}): пар, упёршихся в отказ: {shared}/{pairs} = {pct:.1} %"
        );
    }
    0
}

/// Формы суррогатов для переданных ФИО — генератор тестовых литералов.
fn forms(args: &[String]) -> i32 {
    let Some(table) = MorphTable::shipped() else {
        eprintln!("морф-таблица не разбрана");
        return 1;
    };
    for value in args {
        let toks: Vec<&str> = value.split_whitespace().collect();
        let (case, gender) = match table.parse_span(value) {
            SpanParse::Unique { case, gender, .. } => (case, Some(gender)),
            SpanParse::LemmaUnique { case, genders, .. } => {
                (case, suffix_gender(toks[0]).filter(|g| genders.contains(g)))
            }
            _ => {
                println!("{value}: не разбирается");
                continue;
            }
        };
        let Some(gender) = gender else {
            println!("{value}: род не решён окончанием");
            continue;
        };
        let mut out = Vec::new();
        for (i, w) in toks.iter().enumerate() {
            let ty = NameType::ORDER[i];
            let s = VaultEngine::pick_surrogat_from(w, case, gender, ty, pool::lemmas(ty, gender));
            out.push(s.map_or("—".to_owned(), |s| format!("{} ({})", s.form, s.lemma)));
        }
        println!("{value} => {} [{case:?}]", out.join(" | "));
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().cloned().unwrap_or_else(|| "probe".to_owned());
    let rc = match mode.as_str() {
        "check" => check(),
        "probe" => probe(),
        "forms" => forms(&args[1..]),
        other => {
            eprintln!("неизвестный режим {other} (check|probe|forms)");
            2
        }
    };
    std::process::exit(rc);
}
