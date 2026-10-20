//! [`ByteSpan`] — байтовый интервал в тексте с инвариантом UTF-8-границы.
//!
//! Байты, а не символы, потому что байтовая координата однозначна и при
//! суррогатных парах, и после нормализации текста; SPEC §8 требует offsets в
//! байтах. Про Presidio важно не пересказывать: его `/v1/analyze` отдаёт
//! `start`/`end` в **символах** (первичка — `docs/dep-verify-repos.md` п.1–2
//! п.4, «offsets символьные»), поэтому наш ответ держит оба поля и не выдаёт
//! символьные за байтовые. Символьные нужны UI (раскраска по символам),
//! байтовые — обратимости в vault.

use serde::{Deserialize, Serialize};

/// Причина, по которой интервал нельзя назвать спаном над данным текстом.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanError {
    /// `start > end` — пустой или перевёрнутый интервал.
    Inverted {
        /// Переданный `start`.
        start: usize,
        /// Переданный `end`.
        end: usize,
    },
    /// `end` за пределами текста.
    OutOfBounds {
        /// Переданный `end`.
        end: usize,
        /// Длина текста в байтах.
        text_len: usize,
    },
    /// Граница попала внутрь многобайтового кода.
    NotCharBoundary {
        /// Спорная граница (байт).
        offset: usize,
        /// Роль границы в спане.
        edge: SpanEdge,
    },
}

/// Какая граница оказалась внутри символа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanEdge {
    /// Левая граница (`start`).
    Start,
    /// Правая граница (`end`).
    End,
}

impl core::fmt::Display for SpanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inverted { start, end } => {
                write!(f, "span start {start} is greater than end {end}")
            }
            Self::OutOfBounds { end, text_len } => {
                write!(f, "span end {end} exceeds text length {text_len}")
            }
            Self::NotCharBoundary { offset, edge } => write!(
                f,
                "span {edge:?} boundary {offset} falls inside a UTF-8 code point"
            ),
        }
    }
}

impl std::error::Error for SpanError {}

/// Интервал `[start, end)` в байтах, гарантированно на границах символов.
///
/// Единственный способ собрать спан над текстом —
/// [`ByteSpan::new`], который инвариант проверяет.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteSpan {
    /// Байт начала (включительно).
    pub start: usize,
    /// Байт конца (исключительно).
    pub end: usize,
    /// Индекс символа начала.
    pub char_start: usize,
    /// Индекс символа конца.
    pub char_end: usize,
}

impl core::fmt::Debug for ByteSpan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Только offsets: содержимое спана — потенциальные ПДн, его тут быть не должно.
        f.debug_struct("ByteSpan")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("char_start", &self.char_start)
            .field("char_end", &self.char_end)
            .finish()
    }
}

impl ByteSpan {
    /// Собирает спан и проверяет инвариант UTF-8-границы над `text`.
    ///
    /// Ошибки отдаются по возрастанию серьёзности: сначала структура интервала,
    /// потом границы — чтобы вызывающий не чинил `char_start` у заведомо
    /// перевёрнутого спана.
    ///
    /// # Errors
    ///
    /// [`SpanError::Inverted`], [`SpanError::OutOfBounds`] или
    /// [`SpanError::NotCharBoundary`] — см. варианты enum.
    pub fn new(text: &str, start: usize, end: usize) -> Result<Self, SpanError> {
        if start > end {
            return Err(SpanError::Inverted { start, end });
        }
        if end > text.len() {
            return Err(SpanError::OutOfBounds {
                end,
                text_len: text.len(),
            });
        }
        for (offset, edge) in [(start, SpanEdge::Start), (end, SpanEdge::End)] {
            if !text.is_char_boundary(offset) {
                return Err(SpanError::NotCharBoundary { offset, edge });
            }
        }
        // count_chars здесь O(n) сознательно: шаг 1 не даёт латентных обещаний на
        // этом пути, а карта offset→char — собственность нормализатора (OffsetMap,
        // SPEC §6 guard-detectors, шаг 3).
        let char_start = text[..start].chars().count();
        let char_end = char_start + text[start..end].chars().count();
        Ok(Self {
            start,
            end,
            char_start,
            char_end,
        })
    }

    /// Вырезка из `text`, если спан ему принадлежит.
    #[must_use]
    pub fn slice<'t>(&self, text: &'t str) -> Option<&'t str> {
        text.get(self.start..self.end)
    }

    /// Число байт в спане.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.end - self.start
    }

    /// Число символов в спане.
    #[must_use]
    pub fn char_len(&self) -> usize {
        self.char_end - self.char_start
    }

    /// Пустой спан (нулевая длина) — законный результат границы/вставки.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Пересечение двух спанов, если оно непустое. Нужно слиянию спанов
    /// (SPEC §2 каскад 3: interval tree, greedy leftmost-longest).
    ///
    /// Границы пересчитываются конструктором, поэтому результат снова
    /// удовлетворяет инварианту UTF-8, даже если входные спаны были подняты из JSON.
    #[must_use]
    pub fn intersection(&self, other: &Self, text: &str) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start >= end {
            return None;
        }
        Self::new(text, start, end).ok()
    }

    /// Обёртка `min(start)..max(end)` — объединяющий интервал двух спанов
    /// (SPEC §2 каскад 3: слияние пересекающихся спанов, min(start)..max(end)).
    #[must_use]
    pub fn merge_hull(text: &str, a: &Self, b: &Self) -> Option<Self> {
        let start = a.start.min(b.start);
        let end = a.end.max(b.end);
        Self::new(text, start, end).ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::err_expect)] // в тестах паника = канал ответа
mod tests {
    use super::*;

    #[test]
    fn accepts_ascii_and_multibyte_bounds() {
        let text = "ИНН 7707083898";
        // «ИНН» = 3 символа по 2 байта = 6; пробел байт 6; номер начинается с байта 7.
        let cyr = ByteSpan::new(text, 0, 7).expect("русское слово + пробел");
        assert_eq!(cyr.slice(text), Some("ИНН "));
        assert_eq!(cyr.byte_len(), 7);
        assert_eq!(cyr.char_len(), 4);
        assert_eq!(cyr.char_start, 0);
        assert_eq!(cyr.char_end, 4);

        let latin = ByteSpan::new(text, 7, 17).expect("ASCII-границы");
        assert_eq!(latin.slice(text), Some("7707083898"));
        assert_eq!(latin.char_start, 4);
        assert_eq!(latin.char_end, 14);

        let empty = ByteSpan::new(text, 7, 7).expect("пустой спан законен");
        assert!(empty.is_empty());
        assert_eq!(empty.slice(text), Some(""));
    }

    #[test]
    fn rejects_boundary_inside_cyrillic_sequence() {
        // «И» = [0,2), «Н» = [2,4): байт 1 лежит внутри «И».
        let text = "ИНН";
        let err = ByteSpan::new(text, 1, 3).err().expect("должно отвергнуть");
        assert_eq!(
            err,
            SpanError::NotCharBoundary {
                offset: 1,
                edge: SpanEdge::Start
            }
        );
        // Правая граница внутри «Н» = [2,4): байт 3.
        let err = ByteSpan::new(text, 0, 3).err().expect("должно отвергнуть");
        assert_eq!(
            err,
            SpanError::NotCharBoundary {
                offset: 3,
                edge: SpanEdge::End
            }
        );
    }

    #[test]
    fn rejects_four_byte_interiors() {
        let text = "🚩s";
        // «🚩» занимает [0,4): середины 1,2,3 запрещены.
        for mid in 1..4 {
            let err = ByteSpan::new(text, mid, 5)
                .err()
                .expect("должно отвергнуть");
            assert_eq!(
                err,
                SpanError::NotCharBoundary {
                    offset: mid,
                    edge: SpanEdge::Start
                }
            );
        }
    }

    #[test]
    fn rejects_inverted_and_out_of_bounds() {
        let text = "abc";
        assert_eq!(
            ByteSpan::new(text, 2, 1).err(),
            Some(SpanError::Inverted { start: 2, end: 1 })
        );
        assert_eq!(
            ByteSpan::new(text, 0, 4).err(),
            Some(SpanError::OutOfBounds {
                end: 4,
                text_len: 3
            })
        );
        // Граница ровно на конце текста законна.
        assert!(ByteSpan::new(text, 0, 3).is_ok());
    }

    #[test]
    fn intersection_and_hull() {
        let text = "ООО Ромашка ИНН";
        // Границы символов: «ООО » = [0, 7), «Ромашка» = [7, 21), « » = [21, 22),
        // «ИНН» = [22, 28).
        let a = ByteSpan::new(text, 0, 21).expect("«ООО Ромашка»");
        let b = ByteSpan::new(text, 13, 22).expect("«ашка »");
        let c = a.intersection(&b, text).expect("пересекаются");
        assert_eq!((c.start, c.end), (13, 21));
        assert_eq!((c.char_start, c.char_end), (7, 11));
        assert_eq!(c.slice(text), Some("ашка"));
        let hull = ByteSpan::merge_hull(text, &a, &b).expect("объединяющий интервал");
        assert_eq!((hull.start, hull.end), (0, 22));
        // Непересекающиеся спаны дают None, а не пустой интервал.
        let far = ByteSpan::new(text, 22, 28).expect("«ИНН»");
        assert!(a.intersection(&far, text).is_none());
    }

    #[test]
    fn debug_never_prints_the_original_text() {
        let text = "паспорт 45 07 123456";
        let s = ByteSpan::new(text, 8, 19).expect("серия+номер");
        let d = format!("{s:?}");
        assert!(
            !d.contains("123456") && !d.contains("паспорт"),
            "Debug спана обязан нести только offsets, а не текст: {d}"
        );
        assert!(d.contains("start: 8") && d.contains("end: 19"));
    }

    #[test]
    fn rejects_spans_cutting_through_a_bom() {
        // BOM = EF BB BF: байты 1 и 2 — внутренние.
        let text = "\u{feff}ИНН";
        assert!(ByteSpan::new(text, 0, 3).is_ok());
        assert!(ByteSpan::new(text, 1, 3).is_err());
        assert!(ByteSpan::new(text, 0, 1).is_err());
    }

    #[test]
    fn slice_on_foreign_text_is_none_not_panic() {
        // Спан поднялся из JSON и применён к другому тексту: ни паники, ни unwrap.
        let span: ByteSpan =
            serde_json::from_str(r#"{"start":50,"end":60,"char_start":50,"char_end":60}"#)
                .expect("десериализуется");
        assert_eq!(span.slice("короткий"), None);
    }
}
