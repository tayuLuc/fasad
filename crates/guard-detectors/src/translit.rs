//! Транслит-ФИО эвристика (#51/#238, контур A′): окна заглавных слов латиницы.
//!
//! ЧИСТАЯ функция (zero-deps, как `checksums`): находит ОКНА-кандидаты,
//! решение о маскировании принимает НЕ она. Модель rubert-base-pii-ner
//! обучена на кириллических ФИО и латиницу-транслит не видит (первичка
//! issue #238: «Ushakov Petr Sergeevich» = 5 WordPiece-фрагментов);
//! эвристика подаёт кандидата в СЕРУЮ ЗОНУ модельного пути, а вердикт
//! выносит арбитр каскада 2 (GLiNER Decide). На стадии `cascade-0-only`
//! контур не живёт физически (серой зоны без арбитра нет) — это витрина
//! FN, задокументирована в README §Известные ограничения п.3.
//!
//! Форма окна (решётка юнитов = контракт):
//!
//! - 2–4 ТОЛЬКО соседних слова (ровно один пробел между), каждое:
//!   заглавная латинская + `[A-Za-z-]` (длина 2..30), ЛИБО инициал
//!   `[A-Z].` (одна заглавная + точка, `Sokolov D. A.` = реестровая
//!   форма; `Sokolov D A` без точек = НЕ форма: одиночная заглавная
//!   без точки — это аббревиатура/код, не инициал);
//! - в окне ≥2 полных слов ИЛИ ≥1 полного + окно кончается инициалом
//!   (`Ushakov P.` = фамилия+инициал, форма писем; `Ushakov P S` = нет);
//! - стоп-слова рвут окно (закрытый список: титулы, ОПФ/юр. суффиксы,
//!   гео-топуонимы и слова-кальку `Region/City/Federation`, месяцы,
//!   квартальные метки): `Comcast Corporation`, `New York City`,
//!   `Moscow Region`, `The Beatles` = НЕ кандидаты; бренды без стоп-
//!   слова (`Gazprom Neft`) = кандидат, и это контракт серой зоны:
//!   их отсекает арбитр (row-level «Is there a person?»), не список;
//! - границы = не-буква латиницы (`Ushakov Petr Sergeevich12` = окно
//!   без хвоста цифр; `mailto:Ushakov P` = run из 1 слова = нет);
//! - порядок слов не предполагается (Фамилия Имя Отчество = порядок
//!   реестров, Имя Отчество Фамилия = порядок писем — обе формы).
//!
//! Окна возвращаются в байтовых координатах ВХОДНОГО текста, не
//! пересекаясь (первое по началу выигрывает: окно maximal = 4 слова,
//! дальше окно начинается за его краем).

/// Стоп-слова, рвущие окно (закрытый список; регистр точный, как у
/// токена: строчные слова токеном не считаются). Классы: титулы,
/// ОПФ/корпоративные суффиксы, топонимы и кальки гео-слов, месяцы,
/// квартальные метки, маркеры стран.
const STOPWORDS: &[&str] = &[
    // титулы
    "Mr",
    "Mrs",
    "Ms",
    "Mme",
    "Dr",
    "Prof",
    // ОПФ/корпоративные
    "Corp",
    "Corporation",
    "LLC",
    "OOO",
    "OAO",
    "ZAO",
    "PAO",
    "OJSC",
    "GUP",
    "MChS",
    "Inc",
    "Ltd",
    "Group",
    "Company",
    "Bank",
    "The",
    // гео/кальки
    "Region",
    "City",
    "Street",
    "Ulitsa",
    "Prospekt",
    "Moscow",
    "Moskva",
    "Russia",
    "Russian",
    "Federation",
    "Sankt",
    "Peterburg",
    "Saint",
    "York",
    "Boston",
    "Seattle",
    "London",
    "Berlin",
    "Paris",
    // месяцы
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
    // квартальные метки отчётов
    "Q1",
    "Q2",
    "Q3",
    "Q4",
];

/// Максимум слов в окне (4 = Фамилия Имя Отчество + хвост-инициал).
const MAX_WORDS: usize = 4;

/// Минимум полных (не-инициальных) слов: 2, либо 1, если окно кончается
/// инициалом (`Ushakov P.`).
fn enough_name(seg: &[(usize, usize, &str)]) -> bool {
    let full = seg.iter().filter(|(_, _, w)| !w.ends_with('.')).count();
    match full {
        n if n >= 2 => true,
        1 => seg.last().is_some_and(|(_, _, w)| w.ends_with('.')),
        _ => false,
    }
}

fn is_stop(word: &str) -> bool {
    STOPWORDS.contains(&word)
}

/// Токен на позиции `i`: заглавная + `[a-z-]`-хвост (1..29) или
/// `[A-Z].` (инициал); границы = не-`[A-Za-z]`. Возвращает (start, end).
fn token_at(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = bytes[i];
    if !first.is_ascii_uppercase() {
        return None;
    }
    if i > 0 && bytes[i - 1].is_ascii_alphabetic() {
        return None;
    }
    // инициал: заглавная + точка
    if bytes.get(i + 1) == Some(&b'.') && !bytes.get(i + 2).is_some_and(u8::is_ascii_alphabetic) {
        return Some((i, i + 2));
    }
    // полное слово: заглавная + минимум одна строчная/дефис, длина ≤ 30
    let mut j = i + 1;
    while j < bytes.len() && (bytes[j].is_ascii_lowercase() || bytes[j] == b'-') && j - i < 30 {
        j += 1;
    }
    if j == i + 1 {
        // заглавная без строчного хвоста = одиночная буква без точки
        return None;
    }
    // правая граница: за словом не буква
    if bytes.get(j).is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    Some((i, j))
}

/// Окна-кандидаты транслит-ФИО: `(start_byte, end_byte)` входного текста.
#[must_use]
pub fn name_runs(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out: Vec<(usize, usize)> = Vec::new();
    // Токены подряд: сегмент = соседние токены через ровно один пробел.
    let mut i = 0usize;
    let mut seg: Vec<(usize, usize, &str)> = Vec::new();
    let mut prev_end: Option<usize> = None;
    while i < bytes.len() {
        match token_at(bytes, i) {
            Some((s, e)) => {
                // соседство = ровно один пробел между окном слова
                let adj = s > 0 && prev_end == Some(s - 1) && bytes[s - 1] == b' ';
                if !adj {
                    flush_seg(&mut seg, &mut out);
                }
                prev_end = Some(e);
                let w = &text[s..e];
                if is_stop(w) {
                    flush_seg(&mut seg, &mut out);
                } else {
                    seg.push((s, e, w));
                    if seg.len() == MAX_WORDS {
                        flush_seg(&mut seg, &mut out);
                    }
                }
                i = e;
            }
            None => i += 1,
        }
    }
    flush_seg(&mut seg, &mut out);
    out
}

/// Сегмент соседних токенов -> окно (если форма) + сброс сегмента.
fn flush_seg(seg: &mut Vec<(usize, usize, &str)>, out: &mut Vec<(usize, usize)>) {
    if !seg.is_empty() && seg.len() <= MAX_WORDS && enough_name(seg) {
        out.push((seg[0].0, seg[seg.len() - 1].1));
    }
    seg.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slices(text: &str) -> Vec<&str> {
        name_runs(text)
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect()
    }

    /// Решётка контракта (таблица прототипа 26.10, issue #238): ФИО-формы
    /// = окно, гео/компани/даты = тишина, смешанные = узкий спан.
    #[test]
    fn translit_name_runs_table() {
        // ФИО-формы (recall-контур)
        assert_eq!(
            slices("Ushakov Petr Sergeevich"),
            ["Ushakov Petr Sergeevich"]
        );
        assert_eq!(
            slices("Petr Sergeevich Ushakov"),
            ["Petr Sergeevich Ushakov"]
        );
        assert_eq!(slices("Sokolov Denis"), ["Sokolov Denis"]);
        assert_eq!(
            slices("Ushakova Kira Savvichna"),
            ["Ushakova Kira Savvichna"]
        );
        assert_eq!(slices("Sokolov Denis A."), ["Sokolov Denis A."]);
        assert_eq!(slices("Sokolov D. A."), ["Sokolov D. A."]);
        assert_eq!(slices("Ushakov P."), ["Ushakov P."]);
        // порядок в тексте: кириллица не мешает, гео-стоп рвёт окно
        assert_eq!(
            slices("Contract with Ushakov Petr Sergeevich, Moscow Region"),
            ["Ushakov Petr Sergeevich"]
        );
        assert_eq!(
            slices("Иванов И.И. и Ushakov Petr Sergeevich"),
            ["Ushakov Petr Sergeevich"]
        );
        // бейты: стоп-слова/формы = тишина
        assert_eq!(slices("Comcast Corporation"), [] as [&str; 0]);
        assert_eq!(slices("Comcast Corporation Q2 report"), [] as [&str; 0]);
        assert_eq!(
            slices("Meeting in New York City, January 15"),
            [] as [&str; 0]
        );
        assert_eq!(slices("Boston Consulting Group"), [] as [&str; 0]);
        assert_eq!(slices("Moscow Region"), [] as [&str; 0]);
        assert_eq!(slices("The Beatles"), [] as [&str; 0]);
        assert_eq!(slices("Russian Federation"), [] as [&str; 0]);
        // «Microsoft Windows Update» = кандидат ПО ФОРМЕ (два полных слова,
        // стоп-слов нет; бренды вне закрытого списка = контракт A′: их
        // отсекает арбитр row-level вопросом, не список). Список-гейт
        // растить = путь стоп-слов на 10^5 брендов, первичка #238.
        assert_eq!(
            slices("Microsoft Windows Update"),
            ["Microsoft Windows Update"]
        );
        // не-формы: одиночные буквы без точек, один токен, склейка с цифрой
        assert_eq!(
            slices("Ushakov P S"),
            [] as [&str; 0],
            "инициал без точки = не форма"
        );
        assert_eq!(
            slices("Ivanov I I"),
            [] as [&str; 0],
            "две буквы без точек = не форма"
        );
        assert_eq!(slices("mailto:Ushakov P"), [] as [&str; 0], "один токен");
        assert_eq!(
            slices("Ushakov P.Sergeevich"),
            [] as [&str; 0],
            "склейка без пробела"
        );
        // граница = не-буква: цифры не входят в окно
        assert_eq!(
            slices("Ushakov Petr Sergeevich12"),
            ["Ushakov Petr Sergeevich"]
        );
        // бренд без стоп-слова = кандидат (решает арбитр, не список)
        assert_eq!(slices("Gazprom Neft"), ["Gazprom Neft"]);
    }

    /// Координаты окон = байты входа, окна не пересекаются.
    #[test]
    fn runs_are_disjoint_byte_coordinates() {
        let text = "Ushakov Petr Sergeevich, Sokolov Denis Andreevich — оба";
        let runs = name_runs(text);
        assert_eq!(runs.len(), 2, "{runs:?}");
        for (_s, e) in &runs {
            assert!(text.is_char_boundary(*e), "граница символа");
        }
        assert!(runs[0].1 <= runs[1].0, "пересечение: {runs:?}");
        assert_eq!(&text[runs[0].0..runs[0].1], "Ushakov Petr Sergeevich");
        assert_eq!(&text[runs[1].0..runs[1].1], "Sokolov Denis Andreevich");
    }
}
