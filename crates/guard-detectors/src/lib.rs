//! Каскад 0 — детерминированный (<1 мс по SPEC §2).
//!
//! Скелет шага 1 (SPEC §10 п.1); модули по SPEC §6, реализация — шаг 3.
//!
//! Порядок модулей важен: нормализатор считает [`OffsetMap`], все последующие
//! детекторы отдают спаны уже в координатах исходного текста.

/// Карта «offset нормализованного текста → offset исходного».
///
/// TODO(шаг 3): нормализация (NFKC-подобная, склейка разорванных номерков) с
/// property-тестами на рваной кириллице (SPEC §9: «property-тесты `OffsetMap`»).
pub mod normalize {
    /// Заглушка типа: шаг 3 заменит содержательной реализацией.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OffsetMap;
}

/// Чексуммы документов РФ и ЕС.
///
/// TODO(шаг 3): переносить эталонные векторы таблицами из
/// `docs/dep-verify-algorithms.md`; запрещено вычислять ожидаемое той же
/// функцией, что проверяется (AGENTS §Дисциплина фактов п.3).
/// Закрытые формулы: ИНН mod11, СНИЛС mod101, ОГРНИП mod13, LUHN по 7812-1:2017,
/// БИК без чексуммы, RU IBAN mod97. Хвосты: формула ОГРН, таблица 579-П (§11 п.6).
pub mod checksums {
    /// Заглушка модуля.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Placeholder;
}

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
        let _ = super::normalize::OffsetMap;
        let _ = super::checksums::Placeholder;
        let _ = super::secrets::Placeholder;
        let _ = super::dictionary::Placeholder;
    }
}
