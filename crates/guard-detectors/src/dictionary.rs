//! Словарный матчер — каскад 0 (SPEC §2 «Автомат Ахо–Корасик», SPEC §6 структура
//! `guard-detectors/dictionary`, SPEC §10 п.3 вторая половина).
//!
//! Один `aho_corasick::AhoCorasick` на весь список маркеров (ОПФ, адресные и
//! паспортные маркеры, суффиксы отчеств — SPEC §2); конкретные списки слов —
//! **не хардкод этого модуля**: категории и описания живут в конфигурации
//! (`config/schema.default.json`, SPEC §6, §8 `PUT /v1/schema`), сюда приходят
//! как `patterns: &[&str]`.
//!
//! Регистронезависимость: `aho-corasick` с features `std, perf-literal`
//! (пин workspace) понимает только **ASCII**-case-insensitive
//! (`ascii_case_insensitive`); unicode-регистр требует feature `unicode-case`
//! + `unicode` — тяжёлую ветку таблиц, в бинарь оффлайн-демона (<2 ГБ, SPEC §1)
//! не берём. Следствие: для RU-кириллицы `case_insensitive = true` даёт
//! **нечувствительность только к ASCII-регистрам**, кириллические слова
//! матчатся регистр-сохраняющим матчем (совпадение «Ромашка»≠«ромашка» —
//! словарь обязан содержать нужную форму; морфология падежей/регистров —
//! шаг 5, SPEC §10 п.5, `guard-vault/morphology`).
//!
//! Word-boundary фильтр — опция [`WordBoundary::Ascii`]: граница слова по
//! **символу-соседу** с обеих сторон совпадения, чтобы `ООО` внутри `ОООО` и
//! «ip» внутри `lipsum` не матчилось. Класс слова — юникодный
//! (`char::is_alphanumeric() || '_'`), поэтому **не-ASCII буква (кириллица)
//! слово продолжает и границу НЕ даёт**: `введитеООО` — слитное слово, а
//! «.ООО» — совпадение. Полная формулировка и причина символьного (а не
//! байтового) правила — в доке [`ascii_word_bound`].
//!
//! Live-политики нет: модуль возвращает спаны, решение о классе/редакте —
//! каскад выше.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use guard_types::ByteSpan;

/// Стратегия фильтрации совпадений по границам слова.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordBoundary {
    /// Без фильтра: совпадение матчится в любом контексте.
    None,
    /// Граница слова по символу-соседу с обеих сторон (см. [`ascii_word_bound`]).
    Ascii,
}

/// Автомат по списку словарных паттернов.
///
/// Строится один раз на список (построение O(суммарная длина паттернов));
/// для меняющегося словаря пересобирайте или держите кэш по хэшу списка.
#[derive(Debug)]
pub struct DictionaryMatcher {
    ac: AhoCorasick,
}

impl DictionaryMatcher {
    /// Собрать автомат.
    ///
    /// Пустые паттерны игнорируются (ахо-автомат пустых слов не матчит, но и
    /// строить из них нечего); дубликаты допустимы — в выводе отдаётся одно
    /// левейшее-длиннейшее совпадение на позицию.
    ///
    /// # Errors
    ///
    /// [`aho_corasick::BuildError`] при отказе построителя.
    pub fn new(
        patterns: &[&str],
        case_insensitive: bool,
    ) -> Result<Self, aho_corasick::BuildError> {
        let mut builder = AhoCorasickBuilder::new();
        builder
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(case_insensitive);
        let ac = builder.build(patterns.iter().filter(|p| !p.is_empty()))?;
        Ok(Self { ac })
    }

    /// Все совпадения, отсортированные по началу, без перекрытий
    /// (`LeftmostLongest`). Пересекающиеся паттерны (`a`, `b`, `ab`) разреша-
    /// ются в пользу более длинного на общей левой границе.
    #[must_use]
    pub fn match_spans(&self, haystack: &[u8], boundary: WordBoundary) -> Vec<ByteSpan> {
        match boundary {
            WordBoundary::None => self
                .ac
                .find_iter(haystack)
                .filter_map(|m| {
                    ByteSpan::new(&String::from_utf8_lossy(haystack), m.start(), m.end()).ok()
                })
                .collect(),
            WordBoundary::Ascii => self
                .ac
                .find_iter(haystack)
                .filter(|m| ascii_word_bound(haystack, m.start(), m.end()))
                .filter_map(|m| {
                    ByteSpan::new(&String::from_utf8_lossy(haystack), m.start(), m.end()).ok()
                })
                .collect(),
        }
    }

    /// То же, что [`match_spans`](Self::match_spans), но над `&str`: спаны
    /// собираются конструктором напрямую, без round-trip через `lossy`.
    #[must_use]
    pub fn match_spans_str(&self, haystack: &str, boundary: WordBoundary) -> Vec<ByteSpan> {
        let f = |m: aho_corasick::Match| {
            boundary != WordBoundary::Ascii
                || ascii_word_bound(haystack.as_bytes(), m.start(), m.end())
        };
        self.ac
            .find_iter(haystack)
            .filter(|m| f(*m))
            .filter_map(|m| ByteSpan::new(haystack, m.start(), m.end()).ok())
            .collect()
    }
}

/// Граница слова для [`WordBoundary::Ascii`] — по **символу-соседу**, а не по
/// байтовому классу.
///
/// Политика (принята на шаге 3c — фиксация поведения, не реализации): край
/// совпадения является границей слова только тогда, когда соседний символ не
/// буква, не цифра и не `_`. Класс слова — [`is_word_char`], юникодный:
///
/// - ASCII-сосед `[A-Za-z0-9_]` → не граница (`ip` внутри `lipsum`, `_ip_`);
/// - **не-ASCII буква (кириллица, акцент) → тоже не граница**: это буква
///   слова, а не разделитель, `введитеООО` — одно слитное слово;
/// - любой прочий символ (пробел, `.,;:()"`, `/`, `-`, эмодзи) и край входа →
///   граница.
///
/// Почему нельзя мерить границу одним байтом: RU-буква занимает в UTF-8 2
/// байта, поэтому соседний с ASCII-шаблоном байт оказывается lead-байтом
/// кириллицы (`0xD0`) либо continuation-байтом (`0x9E`) — по байтовому
/// признаку «не буква», хотя по смыслу это продолжение слова. Прежняя байтовая
/// версия на этом путалась: continuation-байт глушил границу там, где её нет,
/// а не-ASCII буква считалась границей вопреки слитному слову. Отсюда
/// символьное правило; соседний символ декодируется явно
/// ([`left_neighbor`], [`right_neighbor`]).
fn ascii_word_bound(hay: &[u8], start: usize, end: usize) -> bool {
    edge_is_boundary(left_neighbor(hay, start)) && edge_is_boundary(right_neighbor(hay, end))
}

/// Граница слова по соседу: соседа нет (край входа) либо он не принадлежит
/// классу слова.
fn edge_is_boundary(neighbor: Option<char>) -> bool {
    neighbor.is_none_or(|c| !is_word_char(c))
}

/// Класс «буква/цифра/подчёркивание» в юникодном смысле (включает кириллицу).
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Символ непосредственно слева от `start`; `None` — край входа.
fn left_neighbor(hay: &[u8], start: usize) -> Option<char> {
    let left = hay.get(..start)?;
    if left.is_empty() {
        return None;
    }
    std::str::from_utf8(left).ok()?.chars().last()
}

/// Символ непосредственно справа от `end`; `None` — край входа.
fn right_neighbor(hay: &[u8], end: usize) -> Option<char> {
    let right = hay.get(end..)?;
    if right.is_empty() {
        return None;
    }
    std::str::from_utf8(right).ok()?.chars().next()
}

/// Convenience-обёртка API атома: `match_spans(haystack, patterns, case_
/// insensitive)` — автомат строится на вызов (для горячего пути держите
/// [`DictionaryMatcher`]).
///
/// Пустые паттерны пропускаются; пустой список даёт пустой результат.
///
/// # Errors
///
/// [`aho_corasick::BuildError`] при отказе построителя.
pub fn match_spans(
    haystack: &[u8],
    patterns: &[&str],
    case_insensitive: bool,
) -> Result<Vec<ByteSpan>, aho_corasick::BuildError> {
    DictionaryMatcher::new(patterns, case_insensitive).map(|m| {
        m.ac.find_iter(haystack)
            .filter_map(|mt| {
                ByteSpan::new(&String::from_utf8_lossy(haystack), mt.start(), mt.end()).ok()
            })
            .collect()
    })
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

    fn spans(hay: &str, pats: &[&str], ci: bool, wb: WordBoundary) -> Vec<(usize, usize)> {
        let m = DictionaryMatcher::new(pats, ci).expect("автомат собирается");
        m.match_spans_str(hay, wb)
            .into_iter()
            .map(|s| (s.start, s.end))
            .collect()
    }

    #[test]
    fn ru_case_sensitive_matches() {
        // «Ромашка» с заглавной — паттерн с заглавной, CI off.
        let hay = "общество Ромашка и РОМАШКА не одно и то же при ci=off";
        assert_eq!(
            spans(hay, &["Ромашка"], false, WordBoundary::None),
            vec![(17, 31)]
        );
    }

    #[test]
    fn ru_ci_does_not_fold_cyrillic_documented() {
        // Документированное ограничение ASCII-CI: кириллица регистр НЕ сворачивает.
        let hay = "ромашка РОМАШКА";
        assert_eq!(
            spans(hay, &["ромашка"], true, WordBoundary::None),
            vec![(0, 14)]
        );
    }

    #[test]
    fn ascii_ci_folds_case() {
        let hay = "Ooo Holdings oOO firm";
        let got = spans(hay, &["ooo"], true, WordBoundary::None);
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn overlapping_patterns_leftmost_longest() {
        // a / b / ab: на «ab» побеждает ab; на «a b» — два отдельных.
        assert_eq!(
            spans("ab", &["a", "b", "ab"], false, WordBoundary::None),
            vec![(0, 2)]
        );
        assert_eq!(
            spans("a b", &["a", "b"], false, WordBoundary::None),
            vec![(0, 1), (2, 3)]
        );
        assert_eq!(
            spans("aab", &["a", "b", "aa"], false, WordBoundary::None),
            vec![(0, 2), (2, 3)]
        );
    }

    #[test]
    fn word_boundary_ascii_filters_intraword() {
        // «ООО» не матчится внутри «ОООО»; «ип» внутри «lipsum» — нет.
        assert_eq!(
            spans("ООООО", &["ООО"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("OOOO", &["OOO"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("lipsum", &["ip"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("ООО Ромашка", &["ООО"], false, WordBoundary::Ascii),
            vec![(0, 6)]
        );
        assert_eq!(
            spans("_ip_", &["ip"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
    }

    #[test]
    fn word_boundary_non_ascii_letter_is_not_boundary() {
        // Принятая политика шага 3c: не-ASCII **буква** рядом с шаблоном —
        // продолжение слова, совпадения с `WordBoundary::Ascii` нет.
        assert_eq!(
            spans("введитеООО", &["ООО"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("ОООРомашка", &["ООО"], false, WordBoundary::Ascii),
            Vec::<(usize, usize)>::new()
        );
        // Край входа и не-буквенный сосед — граница: тот же шаблон матчится.
        assert_eq!(
            spans("ООО.", &["ООО"], false, WordBoundary::Ascii),
            vec![(0, 6)]
        );
        assert_eq!(
            spans("«ООО»", &["ООО"], false, WordBoundary::Ascii),
            vec![(2, 8)]
        );
    }

    #[test]
    fn spans_are_byte_offsets_with_multibyte_context() {
        // Офсеты — байтовые, не символьные. Ожидаемое промерено вне дерева
        // (`s.encode().index(...)`) и зафиксировано таблицей, а не пересчитано
        // той же функцией, что проверяется (AGENTS §Дисциплина фактов п.3).
        let hay = "общество ООО, партнёр ПАО";
        let got = spans(hay, &["ООО", "ПАО"], false, WordBoundary::None);
        assert_eq!(got, vec![(17, 23), (40, 46)]);
        // Срез по спану возвращает именно шаблон, а не сдвиг на байт.
        let b = hay.as_bytes();
        assert_eq!(&b[got[0].0..got[0].1], "ООО".as_bytes());
        assert_eq!(&b[got[1].0..got[1].1], "ПАО".as_bytes());
        // Байтовый спан НЕ равен символьному: перед «ООО» 9 символов, но 17
        // байт — именно это расхождение и есть предмет теста.
        let sp = DictionaryMatcher::new(&["ООО", "ПАО"], false)
            .expect("автомат")
            .match_spans_str(hay, WordBoundary::None)
            .remove(0);
        assert_eq!((sp.start, sp.end), (17, 23), "байтовый спан уехал");
        assert_eq!(
            (sp.char_start, sp.char_end),
            (9, 12),
            "символьный спан уехал"
        );
    }

    #[test]
    fn empty_patterns_and_empty_hay() {
        assert_eq!(
            spans("abc", &[], false, WordBoundary::None),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("abc", &[""], false, WordBoundary::None),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            spans("", &["a"], false, WordBoundary::None),
            Vec::<(usize, usize)>::new()
        );
    }

    #[test]
    fn convenience_api_matches_matcher() {
        let hay = "ООО Ромашка";
        let direct = match_spans(hay.as_bytes(), &["Ромашка"], false).expect("строится");
        assert_eq!(direct.len(), 1);
        assert_eq!(
            &hay.as_bytes()[direct[0].start..direct[0].end],
            "Ромашка".as_bytes()
        );
    }
}
