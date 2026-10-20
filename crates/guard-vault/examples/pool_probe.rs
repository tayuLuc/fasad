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
//! `integrity` — метрика `restoration-integrity` (#60 п.3): доля byte-exact
//! разворотов на мультиымянном документе, рядом с recall (#14), который её не
//! ловит вовсе. Два прогона (чистый и со снятием записей из кэша), главное в
//! выводе — ноль в колонке «подменено».
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

use guard_vault::cache::{Limits, StoreKey};
use guard_vault::morph::{Case, Gender, MorphTable, NameType, SpanParse, suffix_gender};
use guard_vault::pool::{self, SURROGATES_TSV};
use guard_vault::{SRG_PREFIX, SessionKey, SurrogatError, VaultEngine};
use std::collections::{BTreeMap, BTreeSet};

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

/// Метрика `restoration-integrity` (#60 п.3): доля byte-exact разворотов на
/// мультиымянном документе — то, чего recall (#14) не ловит вовсе.
///
/// Два прогона на одном и том же корпусе (все годные ФИО golden-v1 в одной
/// сессии, пул — shipped-артефакт). Чистый: выдали — развернули, записи живы.
/// Со снятием: после каждого имени его строки удаляются из кэша `invalidate`-ом,
/// ровно так, как их снял бы `idle`-лимит 15 мин или evict по байтовому бюджету.
/// Второй прогон — и есть сцена тихой подмены до шага 7d: свободный слот
/// доставался следующему имени, а разворот отдавал не то, что подставлялось.
///
/// Главное в выводе — не доля, а ноль: `подменено` обязано быть нулевым в обоих
/// прогонов. Доля в чистом прогоне 100 % по конструкции (отказ вместо подмены),
/// а в прогоне со снятием смотрят, сколько имён заплатило отказом за этот ноль.
fn integrity() -> i32 {
    let Some(table) = MorphTable::shipped() else {
        eprintln!("морф-таблица не разбрана");
        return 1;
    };
    let (names, unparsed, not_three, unresolved) = names(table);
    println!(
        "golden-v1: имён годно {}, не разбирается {unparsed}, не три токена {not_three}, род не решён {unresolved}",
        names.len()
    );
    for (evict, label) in [(false, "чистый"), (true, "со снятием записей")] {
        let e = VaultEngine::new(
            SessionKey::new([9_u8; 32]),
            Limits::for_test(
                std::time::Duration::from_secs(3600),
                std::time::Duration::from_secs(7200),
            ),
        );
        // «без свидетельства» — отказ на уже пустом слоте: до шага 7d это была
        // не отказная пара, а тихая подмена.
        let (mut issued, mut exact, mut refused, mut blind) = (0_usize, 0_usize, 0_usize, 0_usize);
        let (mut noform, mut wrong) = (0_usize, 0_usize);
        for nm in &names {
            let mut mine: Vec<(String, String)> = Vec::new();
            for (w, ty, g, case, _) in &nm.tokens {
                match e.surrogat_for_gender("probe", w, *case, *g, *ty) {
                    Ok(Some(s)) => {
                        issued += 1;
                        mine.push((s.form.clone(), w.clone()));
                    }
                    Ok(None) => noform += 1,
                    Err(SurrogatError::Collision { form }) => {
                        refused += 1;
                        // Отказ на ПОЛОКЕ, где кэш ничего не помнит, — это и есть
                        // довоенная тихая подмена: без индекса слот считался
                        // свободным, и форма уезжала второму владельцу.
                        if !e
                            .store()
                            .contains(&StoreKey::new("probe", &format!("{SRG_PREFIX}{form}")))
                        {
                            blind += 1;
                        }
                    }
                    Err(SurrogatError::Store(_)) => refused += 1,
                }
            }
            for (form, word) in &mine {
                match e.original_of_surrogat("probe", form) {
                    Some(v) if v.as_str() == word => exact += 1,
                    Some(v) => {
                        wrong += 1;
                        println!(
                            "ПОДМЕНА: форма {form} развёрнута в «{got}», подставлялось «{word}»",
                            got = v.as_str()
                        );
                    }
                    None => println!("ПОТЕРЯ: форма {form} не развернулась вообще"),
                }
            }
            if evict {
                for (form, _) in &mine {
                    e.store()
                        .invalidate(&StoreKey::new("probe", &format!("{SRG_PREFIX}{form}")));
                }
            }
        }
        let pct = exact
            .checked_mul(100)
            .and_then(|v| v.checked_div(issued))
            .unwrap_or(0);
        println!(
            "{label}: выдано форм {issued}, byte-exact развёрнуто {exact} ({pct} %), отказов на выдаче {refused} (из них на пустом слоте — тихих подмен до шага 7d — {blind}), форм без решения {noform}, подменено {wrong}, расхождений индекса {}",
            e.restoration_mismatches()
        );
    }
    0
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
        // Разбивка отказов по позициям triple'а: она же отвечает на вопрос,
        // «куда» падает коллизия, и из неё берётся пара для теста атомарности
        // пачки (нужна коллизия НЕ на первом токене).
        let mut by_pos = vec![0usize; NameType::ORDER.len()];
        for i in 0..names.len() {
            for j in i + 1..names.len() {
                let hit: Vec<usize> = picks[i]
                    .iter()
                    .zip(&picks[j])
                    .enumerate()
                    .filter(|(_, (x, y))| x.0 == y.0 && x.0 != "<нет формы>" && x.1 != y.1)
                    .map(|(k, _)| k)
                    .collect();
                if hit.is_empty() {
                    continue;
                }
                shared += 1;
                for k in &hit {
                    by_pos[*k] += 1;
                }
                if n == 128 && examples.len() < 6 {
                    let where_ = hit
                        .iter()
                        .map(|k| format!("{:?}", NameType::ORDER[*k]))
                        .collect::<Vec<_>>()
                        .join("+");
                    examples.push(format!(
                        "{} ↔ [{}] на {}",
                        names[i].value, names[j].value, where_
                    ));
                }
            }
        }
        for x in &examples {
            println!("  отказная пара: {x}");
        }
        let where_ = NameType::ORDER
            .iter()
            .zip(&by_pos)
            .map(|(ty, c)| format!("{ty:?}={c}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  отказы по позициям: {where_}");
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

/// Пары лемм одной корзины, попадающие в один слот.
///
/// Нужны затем, что золотой корпус на пуле 128 не даёт ни одной коллизии НЕ на
/// первом токене (промер `probe`: Surname=6, Firstname=0, Midname=0), а тест
/// атомарности пачки форм требует коллизию на втором токене: только там
/// предшествующие формы уже лежат в `PendingForms`, и только там их откат
/// (`truncate`) что-то значит. Леммы пула годятся в поверхности: они по
/// построению гнутся нашей таблицей во всех шести падежах (`check`-режим).
fn collide(args: &[String]) -> i32 {
    let [ty_s, g_s] = args else {
        eprintln!("использование: collide <surname|firstname|midname> <f|m>");
        return 2;
    };
    let Some(ty) = [
        (NameType::Surname, "surname"),
        (NameType::Firstname, "firstname"),
        (NameType::Midname, "midname"),
    ]
    .iter()
    .find(|(_, n)| *n == ty_s)
    .map(|(t, _)| *t) else {
        eprintln!("неизвестный тип {ty_s}");
        return 2;
    };
    let Some(gender) = (match g_s.as_str() {
        "f" | "fem" => Some(Gender::Fem),
        "m" | "masc" => Some(Gender::Masc),
        _ => None,
    }) else {
        eprintln!("неизвестный род {g_s}");
        return 2;
    };
    let bucket = pool::lemmas(ty, gender);
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for w in bucket {
        if let Some(s) = VaultEngine::pick_surrogat_from(w, Case::Nom, gender, ty, bucket) {
            groups
                .entry(s.lemma.to_string())
                .or_default()
                .push((*w).to_owned());
        }
    }
    let mut pairs = 0usize;
    for (slot, keys) in groups.iter().filter(|(_, k)| k.len() > 1) {
        pairs += keys.len() * keys.len().saturating_sub(1) / 2;
        println!("слот {slot}: {}", keys.join(" + "));
    }
    println!(
        "{ty:?}/{gender:?}: лемм {}/{}, слотов с >1 ключом {}, пар {}",
        groups.values().map(Vec::len).sum::<usize>(),
        bucket.len(),
        groups.values().filter(|k| k.len() > 1).count(),
        pairs
    );
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().cloned().unwrap_or_else(|| "probe".to_owned());
    let rc = match mode.as_str() {
        "check" => check(),
        "probe" => probe(),
        "forms" => forms(&args[1..]),
        "collide" => collide(&args[1..]),
        "integrity" => integrity(),
        other => {
            eprintln!("неизвестный режим {other} (check|probe|forms|collide|integrity)");
            2
        }
    };
    std::process::exit(rc);
}
