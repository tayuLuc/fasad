//! Механическая проверка инварианта «детерминированное вето» (AGENTS §Инженерные
//! инварианты, SPEC §2 каскад 0).
//!
//! `DetectionSource::DeterministicW` — контракт, который нельзя выразить типом:
//! const живёт в impl-блоке отдельно от enum, и рефакторинг может рассинхронизировать
//! вес с источниками, которым он выдаётся. Тест сверяет имя и значение константы с
//! текстом `src/verdict.rs`; разбор намеренно простой и работает только с формой,
//! которую мы сами пишем (сломанная форма = красная проверка, а не ложно-зелёная).

// Файл целиком — тестовый: паника = канал ответа (красный CI), expect здесь узаконен.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::OnceLock;

/// Ошибки сверки.
#[derive(Debug, PartialEq, Eq)]
enum Drift {
    /// `pub const Deterministic…` не найден — форма константы поменялась.
    MissingConst,
    /// `Some(...)` в `deterministic_weight` ссылается не на имя константы.
    NameMismatch {
        /// Имя в `Some(Self::<NAME>)` внутри match-ручки.
        in_match: String,
        /// Имя `pub const <NAME>`.
        in_const: String,
    },
}

/// Полностью сплющенный verdict.rs (переводы строк и пробельные run'ы → один
/// пробел): match-ручки в rustfmt-форме переносятся через строку, поэтому
/// разбор построчно ловит не всё.
fn flat_src() -> &'static str {
    static FLAT: OnceLock<String> = OnceLock::new();
    FLAT.get_or_init(|| {
        let src = include_str!("../src/verdict.rs");
        let mut out = String::with_capacity(src.len());
        for token in src.split_whitespace() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(token);
        }
        out
    })
}

/// Имена всех вариантов `pub enum DetectionSource` (строка вида `Ident,`).
fn parse_enum_variants(src: &str) -> Vec<String> {
    let marker = "pub enum DetectionSource {";
    let start = src
        .find(marker)
        .unwrap_or_else(|| panic!("в src/verdict.rs нет enum DetectionSource"));
    let rest = &src[start + marker.len()..];
    let body = rest.split_once("\n}").map_or(rest, |(b, _)| b);
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            // Вариант = одинокий идентификатор с запятой: без пробелов, атрибутов, `::`.
            if line.ends_with(',') && !line.contains(' ') && !line.contains("::") {
                let ident = line[..line.len() - 1].trim();
                if ident.starts_with(char::is_uppercase)
                    && ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Some(ident.to_owned());
                }
            }
            None
        })
        .collect()
}

/// Собирает `(имя_константы, текст_значения, [взвешенные_варианты])` из сплющенного
/// verdict.rs. Границы паттерна ручки ищем бегом назад по цепочке `Self::A | Self::B`.
fn parse_weight_fact(flat: &str) -> Result<(String, String, Vec<String>), Drift> {
    let mut name = String::new();
    let mut weight = String::new();
    for chunk in flat.split("pub const ") {
        if let Some(rest) = chunk.strip_prefix("Deterministic") {
            let ident_end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            name = format!("Deterministic{}", &rest[..ident_end]);
            let after_ident = &rest[ident_end..];
            let ty_end = after_ident.find('=').ok_or(Drift::MissingConst)?;
            weight = after_ident[ty_end + 1..]
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            break;
        }
    }
    if name.is_empty() || weight.is_empty() {
        return Err(Drift::MissingConst);
    }

    let mut weighed = Vec::new();
    let mut referenced = String::new();
    // Все ручки match'а вида `… => Some(Self::<NAME>)` — первая же не-весовая
    // ссылка = NameMismatch, первая весовая задаёт pattern-разбор.
    for (idx, _) in flat.match_indices("=> Some(Self::") {
        let inner = flat[idx..]
            .split_once("Some(")
            .and_then(|(_, r)| r.split(')').next())
            .unwrap_or("")
            .trim_start_matches("Self::")
            .to_owned();
        if !inner.starts_with("Deterministic") {
            return Err(Drift::NameMismatch {
                in_match: inner,
                in_const: name.clone(),
            });
        }
        referenced = inner;
        // Паттерн ручки: идём назад от стрелки по цепочке `| Self::X`.
        let before = flat[..idx].trim_end();
        let Some(mut pattern_start) = before.rfind("Self::") else {
            continue;
        };
        loop {
            let head = before[..pattern_start].trim_end();
            if !head.ends_with('|') {
                break;
            }
            match head[..head.len() - 1].rfind("Self::") {
                Some(prev) => pattern_start = prev,
                None => break,
            }
        }
        for part in before[pattern_start..].split('|') {
            if let Some(v) = part.trim().strip_prefix("Self::") {
                weighed.push(v.trim().to_owned());
            }
        }
    }
    if !referenced.is_empty() && referenced != name {
        return Err(Drift::NameMismatch {
            in_match: referenced,
            in_const: name,
        });
    }
    Ok((name, weight, weighed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_and_variants_are_in_sync() {
        let (name, weight, weighed) = parse_weight_fact(flat_src()).expect("контракт разбирается");
        assert_eq!(name, "DeterministicW");
        assert!(
            weight == "1.0" || weight == "1.0_f64",
            "вес детерминированного вето обязан быть ровно 1.0, а не {weight}"
        );
        // Список детерминированных источников зафиксирован здесь, а не выводится из
        // того же кода: правка вектора весов = правка SPEC §2, не рефакторинг.
        assert_eq!(
            weighed,
            vec!["ChecksumRf".to_owned(), "ChecksumEu".to_owned()],
            "список источников с абсолютным вето изменился"
        );
    }

    #[test]
    fn parser_sees_every_variant() {
        // Анти-galo: разбор обязан видеть все 6 вариантов enum, иначе «все учтены»
        // становится ложно-зелёным.
        let variants = parse_enum_variants(include_str!("../src/verdict.rs"));
        assert_eq!(
            variants,
            vec![
                "ChecksumRf",
                "ChecksumEu",
                "SecretEntropy",
                "AhoCorasickRule",
                "GlinerExtractor",
                "GlinerDecideArbitrator",
            ]
        );
        // Ни один вариант не потерялся между «взвешен» и «вероятностен»:
        let (_, _, weighed) = parse_weight_fact(flat_src()).expect("контракт разбирается");
        let probabilistic: Vec<&String> =
            variants.iter().filter(|v| !weighed.contains(v)).collect();
        assert_eq!(
            probabilistic.len(),
            4,
            "вероятностных источников должно быть 4"
        );
    }

    #[test]
    fn drift_is_detected_by_the_parser_itself() {
        // Мутируем копию сплющенного текста и убеждаемся, что сверка краснеет, а не
        // «зеленеет на ничего».
        let flat = flat_src();

        let mutated = flat.replace("DeterministicW: f64 = 1.0;", "DeterministicW: f64 = 0.9 ;");
        let (_, weight, _) = parse_weight_fact(&mutated).expect("разбирается");
        assert_eq!(weight, "0.9");

        let dropped = flat.replace(
            "Self::ChecksumRf | Self::ChecksumEu => Some(Self::DeterministicW)",
            "Self::ChecksumEu => Some(Self::DeterministicW)",
        );
        let (_, _, weighed) = parse_weight_fact(&dropped).expect("разбирается");
        assert_eq!(weighed, vec!["ChecksumEu".to_owned()]);

        // Константа переименована/удалена → MissingConst: парсер ищет `pub const
        // Deterministic…`, после переименования контракта разбор честно падает.
        let renamed = flat.replace("pub const DeterministicW", "pub const VetoWeight");
        assert_eq!(parse_weight_fact(&renamed), Err(Drift::MissingConst));

        let gone = flat.replace("pub const DeterministicW: f64 = 1.0;", "");
        assert_eq!(parse_weight_fact(&gone), Err(Drift::MissingConst));

        // Рассинхрон имени: константа осталась, а ручки ссылаются на другую.
        // Собираем форму на лету, чтобы тест не зависел от spacing'а rustfmt.
        let desync_anchor = "pub const DeterministicW: f64 = 1.0;";
        assert!(flat.contains(desync_anchor), "константа уехала из вида");
        let desync = flat.replace(
            "=> Some(Self::DeterministicW),",
            "=> Some(Self::VetoWeight),",
        );
        assert_eq!(
            parse_weight_fact(&desync),
            Err(Drift::NameMismatch {
                in_match: "VetoWeight".to_owned(),
                in_const: "DeterministicW".to_owned()
            })
        );

        let desync = flat.replace(
            "=> Some(Self::DeterministicW),",
            "=> Some(Self::VetoWeight),",
        );
        assert_eq!(
            parse_weight_fact(&desync),
            Err(Drift::NameMismatch {
                in_match: "VetoWeight".to_owned(),
                in_const: "DeterministicW".to_owned()
            })
        );
    }
}
