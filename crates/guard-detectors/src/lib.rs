#![forbid(unsafe_code)]
//! Каскад 0 — детерминированный (<1 мс по SPEC §2).
//!
//! Скелет шага 1 (SPEC §10 п.1); модули по SPEC §6, реализация — шаг 3.
//!
//! Порядок модулей важен: нормализатор считает [`OffsetMap`], все последующие
//! детекторы отдают спаны уже в координатах исходного текста.

/// Карта «offset нормализованного текста → offset исходного» + нормализатор
/// каскада 0 (SPEC §6, §10 п.3; реализация и property-тесты — `normalize.rs`).
pub mod normalize;

/// Чексуммы документов РФ и ЕС (SPEC §2 Каскад 0; формулы и эталонные векторы —
/// `docs/dep-verify-algorithms.md`, перенос таблиц без пересчёта ожидаемого
/// проверяемой функцией — AGENTS §Дисциплина фактов п.3).
///
/// Реализовано: ИНН-10/12 (§1–2), СНИЛС mod101 (§3), ОГРН-13/ОГРНИП-15 (§4),
/// Луна 7812-1:2017 + BIN «Мир» (§5), IBAN mod97 с RU (§6), формат БИК и счёта
/// (§7). Хвосты (первичка не закрыта): номер акта ОГРН (`egrul-refseq`
/// недоступен), таблица 579-П — TODO в `checksums::tests` под `#[ignore]`.
// `must_use_candidate` (pedantic): публичные валидаторы модуля — предикаты
// `Option<bool>`; вызывающий слой каскада-0 обязан их проверять, сигнатура уже
// не даёт «случайно проигнорировать», а `-D warnings` в CI (just lint) делает
// каждый `#[must_use]`-атрибут шумом без выигрыша. Остальные allow — по месту
// в `checksums.rs`.
#[allow(clippy::must_use_candidate)]
pub mod checksums;

/// Сканер секретов: префикс-фильтр → regex в окне → энтропия.
///
/// TODO(шаг 3): двухфазный фильтр через `aho_corasick` (префиксы `AKIA`, `ghp_`,
/// `sk-`, `eyJ`, `xoxb-`), тяжёлая regex в окне ±200 байт, энтропия Шеннона +
/// Probability-of-Randomness. Референсы архитектур (не зависимости):
/// `mongodb/kingfisher`, `praetorian-inc/noseyparker`, `sirwart/ripsecrets`.
/// Live-верификацию токенов не делаем (air-gap, AGENTS §Что НЕ делаем).
pub mod secrets {
    /// Заглушка модуля.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Placeholder;
}

/// Автомат Ахо–Корасика: ОПФ, адресные/паспортные маркеры, суффиксы отчеств.
///
/// TODO(шаг 3): один `AhoCorasick` на все маркеры + обратный автомат для форм
/// суррогатов из vault (SPEC §4: «все формы регистрируются в обратном
/// `aho-corasick` с привязкой (`EntityId`, `Case`)»).
pub mod dictionary {
    /// Заглушка модуля.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Placeholder;
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_types_are_constructible() {
        // Гарантиша каркаса: крейт компилируется и типы живые.
        // `OffsetMap` проверяется конструктором `default()` — тип из файла
        // `normalize.rs` (шаг 3a), заглушка-единица шага 1 удалена.
        let _ = <super::normalize::OffsetMap as Default>::default();
        let _ = super::secrets::Placeholder;
        let _ = super::dictionary::Placeholder;
    }
}
