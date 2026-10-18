//! Онтология типов fasad (SPEC §6).
//!
//! Всё, что здесь живёт, — язык обмена между каскадами: детекторы (§2 каскад 0),
//! экстрактор/арбитр (каскады 1–2), vault (§3) и HTTP-слой демона (§8).
//!
//! Инварианты, которые несёт этот крейт:
//!
//! 1. [`ByteSpan`] не может существовать в разрезах UTF-8 — конструктор возвращает
//!    [`SpanError`], «отравленного» объекта нет (SPEC §2 каскад 1: выход — спаны
//!    `[byte_start, byte_end]`).
//! 2. [`DetectionSource::DeterministicW`] = 1.0 и не понижается сетью:
//!    детерминированный валидатор имеет абсолютное вето (AGENTS §Инженерные
//!    инварианты, SPEC §2 каскад 0).
//! 3. [`SecretString`] не светит содержимое ни в `Debug`, ни в `Display`, и
//!    затирается при drop (SPEC §3: «обычный `drop` НЕ стирает байты»).
//! 4. Спан не знает про класс — класс это [`ClassId`], а не вариант enum: схема
//!    категорий меняется на ходу через `PUT /v1/schema` (SPEC §8).

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations, clippy::unwrap_used)]

mod secret;
mod span;
mod verdict;

pub use secret::SecretString;
pub use span::{ByteSpan, SpanError};
pub use verdict::{AnnotatedSpan, ClassId, DetectionSource, EntityRole, NewtypeId, Verdict};
