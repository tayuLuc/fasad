//! Слияние пересекающихся спанов: interval tree, greedy leftmost-longest.
//!
//! Контракт — SPEC §2 «Каскад 3» (строка 85): «Слияние пересекающихся спанов:
//! interval tree, greedy leftmost-longest, `min(start)..max(end)`, приоритет
//! чексуммы не понижается», плюс §10 п.4 (шаг 4).
//!
//! ## Почему leftmost-longest и почему жадно
//!
//! Набор спанов из каскада-1 — это перекрывающиеся гипотезы: `ИНН 7707083898`
//! может быть помечен и как `INN` (чексумма сошлась), и как `CARD` (10 цифр подряд),
//! и как часть `ADDRESS` более длинным спаном. Тривиальное «взяли все» даёт
//! пересечения, а каскад-3 обязан выдать разбиение текста: типизированные токены
//! вставляются позиционно, и два токена на одном байте разрушают обратимость.
//! Жадный leftmost-longest детерминирован (никакого выбора «что взять первым» —
//! порядок задают `(start, −end, приоритет)`), и именно он максимизирует покрытие
//! слева направо, что и нужно для маскирования.
//!
//! ## Приоритет
//!
//! [`SpanHit::priority`] — f32-вес источника; 1.0 = детерминированный валидатор
//! ([`guard_types::DetectionSource::DeterministicW`]). По AGENTS
//! §Инженерные инварианты нейросеть **не понижает** чексумму, поэтому при
//! конфликте классов побеждает больший приоритет, а `1.0` недостижим для сети
//! (`p1 ≤ 1.0`, арбитраж даёт `α·p1+(1−α)·p2 < 1.0`). Разрешение конфликта —
//! см. [`Merger::push`].
//!
//! ## Структура
//!
//! «Interval tree» здесь — отсортированный `Vec` + бинарный поиск по префиксному
//! максимуму конца (`max_end`), без внешних крейтов. Для одноразового слияния
//! набора спанов одного запроса (десятки–сотни штук) это быстрее сбалансированного
//! дерева: нет аллокаций узлов, один проход, cache-local. Дерево в смысле API —
//! [`Merger`]: инкрементальный `push` + запрос «пересекается ли новый спан с
//! absorbed».

use guard_types::{ByteSpan, DetectionSource};

/// Класс спана-кандидата.
///
/// В `guard-types` класса как enum **нет** и не будет: онтология живёт строкой
/// [`guard_types::ClassId`] и правится на ходу через `PUT /v1/schema` (SPEC §8,
/// §14 — кириллические классы). Поэтому merger оперирует приоритетом (f32), а не
/// рангом класса: ранг — свойство схемы, а не слияния. Локальный enum ниже —
/// только для типов, которые merger различает сам (вето чексуммы), `#[non_exhaustive]`
/// — чтобы вызывающий не матчил его как закрытый.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    /// Детерминированный валидатор (чексумма): ИНН, СНИЛС, ОГРН, IBAN, карта.
    /// Приоритет фиксирован [`guard_types::DetectionSource::DeterministicW`].
    Checksum,
    /// Секрет/токент (regex+энтропия каскада-0).
    Secret,
    /// Нейросетевая сущность (`PERSON`, `ORG`, адрес, …) — приоритет из модели.
    Entity,
    /// Класс вне известных merger'у: приоритет решает, семантику не интерпретируем.
    Other,
}

impl Category {
    /// Приоритет по умолчанию для источника детекции.
    ///
    /// Чексумма → ровно [`DetectionSource::DeterministicW`] (1.0): вето
    /// детерминированного валидатора не понижается ни при каких обстоятельствах
    /// (AGENTS §Инженерные инварианты).
    #[must_use]
    pub fn default_priority(source: DetectionSource) -> f32 {
        // DeterministicW == 1.0 ровно (verdict.rs), f64→f32 для него точен;
        // сверяем по константе, а не кастом, чтобы не множить cast-lint.
        if source.deterministic_weight() == Some(DetectionSource::DeterministicW) {
            1.0
        } else {
            0.0
        }
    }
}

/// Кандидат на слияние: спан + класс + приоритет.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpanHit {
    /// Интервал в байтах исходного текста.
    pub span: ByteSpan,
    /// Класс (для отчёта и для вето чексуммы).
    pub category: Category,
    /// Приоритет: 1.0 = детерминированный валидатор, ниже — модель/эвристика.
    pub priority: f32,
}

impl SpanHit {
    /// Собирает хит из спана, класса и приоритета.
    #[must_use]
    pub fn new(span: ByteSpan, category: Category, priority: f32) -> Self {
        Self {
            span,
            category,
            priority,
        }
    }

    /// Хит из результата каскада-0: приоритет берётся из источника
    /// ([`Category::default_priority`]), класс — из строкового id (см. [`Category::of`]).
    #[must_use]
    pub fn from_detection(span: ByteSpan, category: Category, source: DetectionSource) -> Self {
        Self::new(span, category, Category::default_priority(source))
    }
}

/// Ключ сортировки greedy leftmost-longest: `start` ↑, `end` ↓, приоритет ↓.
///
/// Третичный ключ (приоритет) нужен для детерминизма: два хита с одинаковым
/// интервалом обязаны выдавать один результат независимо от порядка входа —
/// иначе golden-прогон невоспроизводим. Приоритет в ключе развёрнут (`b` vs `a`),
/// потому что f32 не `Ord`: сравнение вручную через `total_cmp` (NaN-в-сравнении
/// не допускаем — приоритет приходит из score'а модели, 0.0..=1.0).
fn sort_cmp(a: &SpanHit, b: &SpanHit) -> core::cmp::Ordering {
    a.span
        .start
        .cmp(&b.span.start)
        .then(b.span.end.cmp(&a.span.end))
        .then(b.priority.total_cmp(&a.priority))
}

/// Отсортированный по leftmost-longest набор спанов с префиксным `max_end`.
///
/// Инкрементальный контейнер: [`Merger::push`] отдаёт, поглощён ли новый хит,
/// [`Merger::finish`] выдаёт непересекающееся покрытие. Порядок `push` не важен
/// (внутри сортировка), повтор `push` одного хита — идемпотенен.
#[derive(Debug, Default, Clone)]
pub struct Merger {
    hits: Vec<SpanHit>,
    /// `max_end[i]` = max `span.end` над `hits[..=i]` — префиксный максимум,
    /// по нему бинарный поиск «есть ли пересечение с префиксом».
    max_end: Vec<usize>,
}

impl Merger {
    /// Пустой merger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Число принятых хитов (включая поглощённые).
    #[must_use]
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    /// Ни одного хита.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    /// Добавляет хит, пересчитывая префиксный `max_end`.
    ///
    /// Возвращает `true`, если хит intersects с уже принятым (`end == start`
    /// пересечением **не** считается — смежные спаны законны).
    #[must_use]
    pub fn push(&mut self, h: SpanHit) -> bool {
        let i = self.hits.partition_point(|x| sort_cmp(x, &h).is_le());
        let prev_max = i.checked_sub(1).map_or(0, |j| self.max_end[j]);
        let new_max = prev_max.max(h.span.end);
        self.hits.insert(i, h);
        self.max_end.insert(i, new_max);
        for m in &mut self.max_end[i + 1..] {
            if *m >= new_max {
                break;
            }
            *m = new_max;
        }
        prev_max > h.span.start
    }

    /// Прогоняет greedy leftmost-longest и отдаёт непересекающийся результат.
    ///
    /// Пустой merger → пустой результат (не паника).
    #[must_use]
    pub fn finish(self) -> Vec<SpanHit> {
        merge_sorted(self.hits)
    }
}

/// Н2 (ревью PR#21): нулевой спан (`start == end`) приоритетом НЕ управляется —
/// выродыш не является хитом детектора; если он всё же попал во вход, халл
/// вправе перенять его приоритет — осознанно. Ненулевым спанам правило
/// «1.0 не понижается» сохраняется полностью, и результат не зависит от
/// порядка входа (детермин-тест `nested_veto_deterministic_order_independent`).
#[must_use]
pub fn merge(hits: &[SpanHit]) -> Vec<SpanHit> {
    let mut m = Merger::new();
    for &h in hits {
        // Возврат `push` (пересекается ли) здесь не нужен: `finish` пересобирает
        // покрытие по отсортированным хитам независимо от порядка вставки.
        let _ = m.push(h);
    }
    m.finish()
}

/// Ядро слияния: жадный проход по отсортированным хитам.
///
/// Правила (SPEC §2 каскад 3):
///
/// 1. Берём хиты в порядке `(start ↑, end ↓, priority ↓)`.
/// 2. Текущий «чемпион» живёт, пока новый хит начинается **строго раньше** его
///    конца (`start < end` — касание `start == end` не конфликт).
/// 3. Конфликт: чемпион поглощает нового (обёртка `min(start)..max(end)`), но
///    **класс и приоритет остаются у чемпиона** — победитель определён сортировкой.
///    Если новый хит имеет приоритет 1.0 (вето чексуммы), а чемпион — ниже,
///    чемпион **заменяется** на новый: вето не понижается (AGENTS).
/// 4. Не-пересекающийся хит закрывает чемпиона и становится новым.
fn merge_sorted(mut hits: Vec<SpanHit>) -> Vec<SpanHit> {
    hits.sort_by(sort_cmp);
    let mut out: Vec<SpanHit> = Vec::with_capacity(hits.len());
    for h in hits {
        match out.last_mut() {
            None => out.push(h),
            Some(cur) if h.span.start >= cur.span.end => out.push(h),
            // Касание не пересечение — обработано выше веткой `>=`.
            Some(cur) => {
                // Вето детерминированного валидатора не понижается: хит с
                // приоритетом 1.0 поверх более слабого становится чемпионом.
                if h.priority > cur.priority {
                    cur.category = h.category;
                    cur.priority = h.priority;
                }
                // min(start)..max(end): левый край уже у чемпиона (сортировка),
                // правый растёт.
                if h.span.end > cur.span.end {
                    cur.span.end = h.span.end;
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::err_expect)] // в тестах паника = канал ответа
mod tests {
    use super::*;

    fn hit(s: usize, e: usize, p: f32) -> SpanHit {
        SpanHit::new(
            ByteSpan {
                start: s,
                end: e,
                char_start: s,
                char_end: e,
            },
            Category::Entity,
            p,
        )
    }

    fn checksum(s: usize, e: usize) -> SpanHit {
        SpanHit::new(
            ByteSpan {
                start: s,
                end: e,
                char_start: s,
                char_end: e,
            },
            Category::Checksum,
            1.0,
        )
    }

    #[test]
    fn nested_veto_deterministic_order_independent() {
        // Н3 (ревью PR#21): вложенное вето НЕ зависит от порядка входа.
        // Широкая Entity 0.557 (1..99) + вето 1.0 (57..98): в любом порядке
        // халл остаётся широким, приоритет перехватывает вето.
        let wide = hit(1, 99, 0.557);
        let veto = hit(57, 98, 1.0);
        for order in [[wide, veto], [veto, wide]] {
            let m = merge(&order);
            assert_eq!(m.len(), 1, "халл один при любом порядке");
            assert_eq!((m[0].span.start, m[0].span.end), (1, 99), "халл широкий");
            assert!((m[0].priority - 1.0).abs() < f32::EPSILON, "вето-приоритет");
        }
    }

    #[test]
    fn nested_checksum_veto_deterministic() {
        // N3 (ревью PR#21): детерминированный конфликт — вложенный Checksum 1.0
        // внутри широкого Entity 0.557 (класс кейса мутации «убрать вето»);
        // hull широкого, класс/приоритет — вето; оба порядка входа.
        let text = "0123456789".repeat(10); // 100 байт
        let wide = SpanHit::new(
            ByteSpan::new(&text, 1, 99).unwrap(),
            Category::Entity,
            0.557,
        );
        let inner = SpanHit::new(
            ByteSpan::new(&text, 57, 98).unwrap(),
            Category::Checksum,
            1.0,
        );
        for order in [[wide, inner], [inner, wide]] {
            let out = merge(&order);
            assert_eq!(out.len(), 1, "сливаются в hull (1,99)");
            assert_eq!((out[0].span.start, out[0].span.end), (1, 99));
            assert_eq!(
                out[0].category,
                Category::Checksum,
                "вето 1.0 перехватывает класс"
            );
            assert!(out[0].priority.total_cmp(&1.0f32).is_eq());
        }
    }

    #[test]
    fn empty_input_gives_empty_output() {
        let m = merge(&[]);
        assert!(m.is_empty(), "пустой вход дал спаны: {m:?}");
        let m = Merger::new().finish();
        assert!(m.is_empty(), "пустой Merger дал спаны: {m:?}");
    }

    #[test]
    fn disjoint_hits_pass_through_in_order() {
        let hs = [hit(0, 4, 0.5), hit(10, 14, 0.6), hit(20, 24, 0.4)];
        let out = merge(&hs);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].span.start, 0);
        assert_eq!(out[2].span.end, 24);
    }

    #[test]
    fn touching_spans_do_not_merge() {
        // end == start — НЕ пересечение (контракт ТЗ).
        let hs = [hit(0, 8, 0.5), hit(8, 16, 0.5)];
        assert_eq!(merge(&hs).len(), 2);
    }

    #[test]
    fn nested_is_absorbed_and_hull_taken() {
        // вложенный [2,4] внутри [0,10]: остаётся один спан 0..10
        let hs = [hit(0, 10, 0.5), hit(2, 4, 0.9)];
        let out = merge(&hs);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].span.start, out[0].span.end), (0, 10));
    }

    #[test]
    fn leftmost_wins_span_bounds() {
        // перекрывающиеся: [0,6] и [4,12] → обёртка 0..12
        let hs = [hit(0, 6, 0.5), hit(4, 12, 0.5)];
        let out = merge(&hs);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].span.start, out[0].span.end), (0, 12));
    }

    #[test]
    fn leftmost_longest_prefers_longest_at_same_start() {
        // два с одним start: берётся более длинный (end desc)
        let hs = [hit(0, 5, 0.9), hit(0, 20, 0.4)];
        let out = merge(&hs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].span.end, 20);
    }

    #[test]
    fn checksum_priority_1_0_never_lowered_both_input_orders() {
        // 0.9-vs-1.0 конфликт в обоих порядках входа: итог — приоритет 1.0.
        let cs = checksum(10, 20);
        let net = hit(12, 16, 0.9);
        for hs in [&[cs, net][..], &[net, cs][..]] {
            let out = merge(hs);
            assert_eq!(out.len(), 1, "порядок {hs:?}");
            assert!(out[0].priority.total_cmp(&1.0).is_eq());
            assert_eq!(out[0].category, Category::Checksum);
            assert_eq!((out[0].span.start, out[0].span.end), (10, 20));
        }
    }

    #[test]
    fn network_hit_cannot_extend_checksum_span_class() {
        // чексумма внутри большого сетевого спана: класс остаётся Checksum
        let cs = checksum(12, 16);
        let net = hit(10, 20, 0.7);
        let out = merge(&[net, cs]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, Category::Checksum);
        // hull: min(start)..max(end) = 10..20
        assert_eq!((out[0].span.start, out[0].span.end), (10, 20));
    }

    #[test]
    fn higher_priority_absorbs_lower_regardless_of_length() {
        let lo = hit(0, 100, 0.3);
        let hi = hit(20, 30, 0.95);
        let out = merge(&[lo, hi]);
        assert_eq!(out.len(), 1);
        assert!(out[0].priority.total_cmp(&0.95).is_eq());
    }

    #[test]
    fn output_is_disjoint_and_sorted() {
        let hs = [
            hit(0, 10, 0.5),
            hit(5, 15, 0.6),
            hit(14, 16, 0.2),
            hit(30, 40, 0.8),
            hit(39, 41, 0.8),
        ];
        let out = merge(&hs);
        for w in out.windows(2) {
            assert!(w[0].span.end <= w[1].span.start);
        }
    }

    #[test]
    fn merge_is_idempotent() {
        let hs = [
            hit(0, 10, 0.5),
            hit(5, 15, 0.6),
            hit(20, 25, 0.4),
            checksum(22, 24),
        ];
        let once = merge(&hs);
        let twice = merge(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn order_of_input_does_not_matter() {
        let a = [hit(0, 10, 0.5), hit(5, 15, 0.6), hit(30, 40, 0.8)];
        let mut b = a;
        b.reverse();
        assert_eq!(merge(&a), merge(&b));
    }

    #[test]
    fn merger_incremental_matches_slice_api() {
        let hs = [hit(0, 10, 0.5), hit(5, 15, 0.6), hit(8, 9, 0.7)];
        let mut m = Merger::new();
        for &h in &hs {
            let _ = m.push(h);
        }
        assert_eq!(m.finish(), merge(&hs));
    }

    #[test]
    fn push_reports_intersection_not_touching() {
        let mut m = Merger::new();
        assert!(!m.push(hit(0, 10, 0.5)));
        assert!(m.push(hit(9, 20, 0.5))); // пересечение
        let mut m2 = Merger::new();
        assert!(!m2.push(hit(0, 10, 0.5)));
        assert!(!m2.push(hit(10, 20, 0.5))); // касание
    }

    #[test]
    fn chain_absorption_merges_transitively() {
        // [0,5][4,9][8,13][12,20] → один спан 0..20
        let hs = [
            hit(0, 5, 0.5),
            hit(4, 9, 0.5),
            hit(8, 13, 0.5),
            hit(12, 20, 0.5),
        ];
        let out = merge(&hs);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].span.start, out[0].span.end), (0, 20));
    }
}
