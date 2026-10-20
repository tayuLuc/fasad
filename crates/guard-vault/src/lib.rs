#![forbid(unsafe_code)]
//! Vault — обратимость маскирования (SPEC §3–§4).
//!
//! Скелет шага 1 (SPEC §10 п.1); реализация — шаг 5.
//!
//! Три режима жизни данных (§3): request-scoped ephemeral, session cache (moka,
//! sliding TTL 15 мин / hard TTL 2 ч), stateless `vault_token` (LZ4 →
//! ChaCha20-Poly1305, мастер-ключ 32 байта в mlock). Оригиналы в RAM лежат
//! открыто — защита это `ZeroizeOnDrop` + mlock/VirtualLock, а не шифрование.

/// Морфология RU: лемматизация + синтетические суррогаты во всех падежах.
///
/// TODO(шаг 5): спан → лемма (`rsmorphy`) → дедуп падежных форм → пул имени того
/// же рода → склонение (`petrovich`) в 6 падежей → регистрация форм в обратном
/// aho-corasick с привязкой `(EntityId, Case)`. Оба крейтов мертвы (2018/2020,
/// `docs/dep-verify-crates.md`) — лицензия/MSRV/замена решаются на шаге 5.
pub mod morphology {
    /// Заглушка падежа (6 падежей RU + краткая форма).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GrammaticalCase {
        /// Именительный.
        Nominative,
        /// Родительный.
        Genitive,
        /// Дательный.
        Dative,
        /// Винительный.
        Accusative,
        /// Творительный.
        Instrumental,
        /// Предложный.
        Prepositional,
    }
}

/// Сессионный кэш оригиналов (`moka`, eviction listener → `.zeroize()`).
///
/// TODO(шаг 5): `time_to_idle` 15 мин, `time_to_live` 2 ч; нужен для многоходовых
/// чатов («Алексей Смирнов» в 1-м и «Алексею» в 5-м = один `EntityId`).
pub mod session_store {
    /// Заглушка конфигурации TTL (SPEC §3 режим 2).
    #[derive(Debug, Clone, Copy)]
    pub struct TtlConfig {
        /// Простой, за который запись выбрасывается (секунды).
        pub idle_secs: u64,
        /// Жёсткий потолок жизни записи (секунды).
        pub live_secs: u64,
    }
}

pub mod cache;
pub mod morph;
pub mod rewriter;

/// Stateless-токен для `/v1/anonymize`: оригинал → LZ4 → XChaCha20-Poly1305.
///
/// Реализация шага 5 (атом A): SPEC §3 режим 3 — сервер в покое хранит 0 байт
/// пользовательских данных, расшифровка идёт в mlock+zeroize-буфер.
pub mod token;

/// SSE look-ahead FSM: обратная подмена на потоке ответа.
///
/// TODO(шаг 5): буфер look-ahead до 32 байт — токен `[PERSON_1]` может прилететь
/// нарезанным на 3 пакета; наивный replace по чанку ломает обратимость (§8).
/// Стресс-тест с нарезкой по 1–2 байта — SPEC §9.
pub mod stream_rewriter {
    /// Заглушка размера окна look-ahead (§8: до 32 байт).
    #[derive(Debug, Clone, Copy)]
    pub struct LookAhead {
        /// Максимум буферизуемых байт до выдачи.
        pub max_bytes: usize,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_types_are_constructible() {
        use super::morphology::GrammaticalCase;
        assert_ne!(GrammaticalCase::Nominative, GrammaticalCase::Genitive);
        let _ = super::session_store::TtlConfig {
            idle_secs: 900,
            live_secs: 7200,
        };
        let _ = super::stream_rewriter::LookAhead { max_bytes: 32 };
    }
}
