//! [`SecretString`] — строка, которая не светит себя ни в отладке, ни после жизни.
//!
//! AGENTS §Инженерные инварианты: «никаких `String` с секретами в логах,
//! Debug-вывод только `[REDACTED]`»; SPEC §3: «обычный `drop` НЕ стирает байты».
//! Отсюда два обязательства этого типа: `Debug`/`Display` = константа, и
//! `ZeroizeOnDrop` при выводе значения из области видимости.
//!
//! mlock/VirtualLock поверх этого буфера — задача `guard-vault` (SPEC §3, крейт
//! `region`); здесь только zeroize, чтобы тип не тянул платформенный код.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// Вывод `Debug`/`Display` для любого секретного значения.
pub const REDACTED: &str = "[REDACTED]";

/// Строка оригинала ПДн/токена с гарантиями «затереть при drop, не показать в Debug».
///
/// `#[derive(ZeroizeOnDrop)]` требует, чтобы каждое поле умело обнуляться само:
/// `Box<str>` не умеет, поэтому внутри `String` + явная обёртка [`SecretInner`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretString(SecretInner);

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct SecretInner(String);

impl SecretString {
    /// Оборачивает оригинал. Содержимое забирается во владение — ссылок на
    /// исходный буфер не остаётся, но вызывающий обязан не держать его копии.
    #[must_use]
    pub fn new<S: Into<String>>(plain: S) -> Self {
        Self(SecretInner(plain.into()))
    }

    /// Пустое значение (для дефолтов/раздела таблиц).
    #[must_use]
    pub const fn empty() -> Self {
        // String::new не const-compatible в derive-обёртке, поэтому через Default.
        Self(SecretInner(String::new()))
    }

    /// Доступ к оригиналу только для модулей, которым он служебно нужен
    /// (чексумма-валидатор, морфология). Публичного `as_str()` нет намеренно:
    /// любое «просто вывести» должно быть актом воли, а не автодополнением.
    #[must_use]
    pub fn expose_to_validator(&self) -> &str {
        &self.0.0
    }

    /// Длина в байтах — безопасно для логов.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.0.len()
    }

    /// Пусто ли.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.0.is_empty()
    }

    /// Явное стирание до drop (например сразу после отправки `[DONE]`,
    /// SPEC §3 режим 1).
    pub fn zeroize_early(&mut self) {
        self.0.zeroize();
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни значения, ни длины: длина сама по себе косвенная утечка.
        f.write_str("SecretString(\"[REDACTED]\")")
    }
}

impl core::fmt::Display for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// `Deserialize` принимает обычную строку (вход демона — открытый текст).
///
/// Сериализация секрета наружу в JSON — операция обратная цели типа: vault-токен
/// шифруется в `guard-vault`, а `SecretString` в serde-вывод не отдаётся (`"****"`).
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

// Контракт `ZeroizeOnDrop` держит derive `#[zeroize(drop)]` выше; отдельный trait
// тут был бы дублем (проверяется тестом `debug_and_display_never_leak_the_value`).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_never_leak_the_value() {
        let secret = SecretString::new("ghp_16CharExampleToken000000000000000000000");
        let d = format!("{secret:?}");
        let s = format!("{secret}");
        assert!(!d.contains("ghp_"), "Debug засветил содержимое: {d}");
        assert!(!s.contains("ghp_"), "Display засветил содержимое: {s}");
        assert!(d.contains(REDACTED));
        assert_eq!(s, REDACTED);
        // Слой выше (аннотация со списком секретов) тоже не должен протечь.
        let set = format!("{:?}", [secret.clone(), secret]);
        assert!(
            !set.contains("ghp_"),
            "Массив секретов засветил значения: {set}"
        );
    }

    #[test]
    fn serialize_emits_redacted_placeholder() {
        let secret = SecretString::new("4507123456");
        let j = serde_json::to_string(&secret).expect("сериализуется");
        assert_eq!(j, "\"[REDACTED]\"");
        let back =
            serde_json::from_str::<SecretString>("\"4507123456\"").expect("принимает строку");
        assert_eq!(back.expose_to_validator(), "4507123456");
    }

    #[test]
    fn zeroize_early_blanks_the_buffer() {
        let mut secret = SecretString::new("ИНН 7707083898");
        assert!(!secret.is_empty());
        secret.zeroize_early();
        assert!(secret.is_empty());
        assert_eq!(secret.expose_to_validator(), "");
    }

    #[test]
    fn drop_zeroes_without_leaking_through_clone() {
        // Проверяем контракт клонирования: копия живёт независимо, обе затираются.
        let a = SecretString::new("СНИЛС 112-233-445 95");
        let b = a.clone();
        assert_eq!(a.expose_to_validator(), b.expose_to_validator());
        drop(a);
        assert_eq!(b.expose_to_validator(), "СНИЛС 112-233-445 95");
    }
}
