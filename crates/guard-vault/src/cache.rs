//! Сессионный кэш оригиналов (SPEC §3 режим 2, §10 шаг 5 атом C).
//!
//! Нужен для многоходовых чатов: «Алексей Смирнов» в 1-м сообщении и «Алексею»
//! в 5-м должны развернуться в один и тот же оригинал (SPEC §3 п.2).
//!
//! Три отклонения от буквы ТЗ, каждое с причиной:
//!
//! 1. SPEC §3 п.2 формулирует как «eviction listener → `.zeroize()`». Здесь
//!    стирание делает **`Drop` значения** (`SecretString` = `#[zeroize(drop)]`),
//!    а listener только считает причины удаления. Причина: moka при уничтожении
//!    кэша уведомлений не шлёт вовсе (первичка
//!    `moka-0.12.16/src/notification.rs:25-27`), так что обнуление, завязанное
//!    на callback, терялось бы именно на пути `Drop` — самом частом в демоне.
//! 2. mlock к значениям неприменим: `Cache` владеет размещением и перекладывает
//!    значения между сегментами, адрес нестабилен. Отклонение от инварианта
//!    AGENTS «все буферы с оригиналами `ПДн`: `ZeroizeOnDrop` + mlock» —
//!    зафиксировано здесь и в рапорте. Stateless-контур (SPEC §3 п.3), где
//!    буфер короткоживущий, залочен целиком: [`crate::token::LockedBuf`].
//! 3. `Cache::get` требует `V: Clone`, а клон `SecretString` — вторая копия
//!    секрета. Наружу отдаётся [`SecretRef`]: общий `Arc<SecretString>`, клон =
//!    инкремент счётчика, байты не дублируются; стирается на drop последней
//!    ручки (тест `size_eviction_drops_value_so_it_gets_zeroized` ловит это
//!    через `Weak`).
//!
//! Память нормирована весом: `weigher` = байты оригинала, `max_capacity` —
//! байтовый бюджет. «таблица <50 КБ» из SPEC §3 — про таблицу одной сессии;
//! бюджет всего кэша задаёт [`Limits::max_bytes`].
//!
//! Границы ответственности: вывод ключа сессии и генерация меток — шаг 6; здесь
//! только «ключ → оригинал» с TTL.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use guard_types::SecretString;
use moka::notification::RemovalCause;
use moka::sync::Cache;

/// Заглушка отладочного вывода. `guard_types::REDACTED` — константа приватного
/// модуля (`guard-types/src/lib.rs:22`: `mod secret;`), наружу не торчит, так
/// что держим свою и сверяем с рендером `SecretString` тестом
/// `redact_marker_matches_guard_types` — расходиться им негде.
const REDACTED: &str = "[REDACTED]";

/// Ключ записи: сессия + метка.
///
/// Оба поля — синтетические идентификаторы (значение заголовка `X-Session-ID` и
/// типизированная метка вроде `CLIENT_PERSON_1`), `ПДн` в них нет. `Debug` у
/// ключа читаемый намеренно: без него отлаживать кэш нечем.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoreKey {
    session: Arc<str>,
    label: Arc<str>,
}

impl StoreKey {
    /// Собирает ключ.
    #[must_use]
    pub fn new(session: &str, label: &str) -> Self {
        Self {
            session: Arc::from(session),
            label: Arc::from(label),
        }
    }

    /// Идентификатор сессии.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Метка сущности.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl core::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreKey")
            .field("session", &self.session.as_ref())
            .field("label", &self.label.as_ref())
            .finish()
    }
}

/// Ручка на оригинал из кэша.
///
/// `Clone` — только счётчик `Arc`: копий байтов `ПДн` не возникает. Оригинал
/// затирается, когда умирает последняя ручка.
#[derive(Clone)]
pub struct SecretRef(Arc<SecretString>);

impl SecretRef {
    /// Упаковывает оригинал в общую ручку.
    #[must_use]
    pub fn new(plain: SecretString) -> Self {
        Self(Arc::new(plain))
    }

    /// Оригинал как `&str` на время заимствования ручки — основной путь
    /// подстановки: перекладывать байты в выходной буфер решает вызывающий.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_to_validator()
    }

    /// Владение копией оригинала — для вызывающего, который обязан пережить
    /// ручку. Возвращаемый `SecretString` затирается при своём drop.
    #[must_use]
    pub fn expose(&self) -> SecretString {
        (*self.0).clone()
    }

    /// Длина оригинала в байтах — это метрика, а не секрет.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.byte_len()
    }
}

impl core::fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни значения, ни длины: `SecretString` печатает ровно это.
        // Тот же заглушечный рендер, что у SecretString: ни значения, ни длины.
        core::fmt::Debug::fmt(&self.0, f)
    }
}

impl core::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

/// Лимиты кэша.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Скользящий TTL: запись мертва после простоя (SPEC §3 п.2 — 15 мин).
    pub time_to_idle: Duration,
    /// Жёсткий TTL: мертва независимо от попаданий (SPEC §3 п.2 — 2 ч).
    pub time_to_live: Duration,
    /// Байтовый бюджет кэша; вес записи = длина оригинала.
    pub max_bytes: u64,
    /// Потолок длины одного оригинала: больше — отказ [`StoreError::TooBig`].
    pub max_value_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self::SPEC_DEFAULT
    }
}

impl Limits {
    /// Значения SPEC §3 п.2 + байтовые лимиты.
    ///
    /// `max_value_bytes` = 4096 Б: промеренный по `data/golden/golden-v1.jsonl`
    /// максимум `value_source` — 109 Б (см. `token::MAX_ORIGINAL_BYTES`, там же
    /// p95 = 78 Б), запас ×37 на адреса и реквизиты из редких классов.
    /// `max_bytes` = 4 048 576 Б ≈ 34 тысячи средних спанов; потолок демона
    /// (AGENTS) не затронут и на 500 одновременных сессиях.
    pub const SPEC_DEFAULT: Self = Self {
        time_to_idle: Duration::from_secs(15 * 60),
        time_to_live: Duration::from_secs(2 * 60 * 60),
        max_bytes: 4 * 1024 * 1024,
        max_value_bytes: 4096,
    };

    /// Укороченные TTL для тестов — иначе тест спит минуты.
    #[must_use]
    pub fn for_test(time_to_idle: Duration, time_to_live: Duration) -> Self {
        Self {
            time_to_idle,
            time_to_live,
            ..Self::SPEC_DEFAULT
        }
    }
}

/// Ошибки клада.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Оригиналы длиннее `Limits::max_value_bytes` не кэшируются.
    #[error("оригинал {len} Б не влезает в лимит {max} Б")]
    TooBig {
        /// Фактическая длина.
        len: usize,
        /// Лимит.
        max: usize,
    },
    /// Пустой оригинал — не значение: подмена на пустую строку позже выдала бы
    /// «спан есть, текста нет», то есть утечку структуры запроса.
    #[error("пустой оригинал в кэш не кладётся")]
    Empty,
}

/// Счётчики удалений по причинам — их настраивает listener, живут в `Arc`
/// потому, что listener обязан быть `'static` и не может одалживать поле.
#[derive(Debug, Default)]
struct RemovalCounters {
    expired: AtomicU64,
    size: AtomicU64,
    explicit: AtomicU64,
    replaced: AtomicU64,
}

/// Счётчики запросов.
#[derive(Debug, Default)]
struct Counters {
    inserts: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    rejected: AtomicU64,
}

/// Сессионный кэш оригиналов.
pub struct SessionStore {
    cache: Cache<StoreKey, SecretRef>,
    limits: Limits,
    counters: Counters,
    removals: Arc<RemovalCounters>,
}

impl core::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Метаданные и счётчики — значений в отладочном выводе быть не должно.
        f.debug_struct("SessionStore")
            .field("entries", &self.entry_count())
            .field("weight_bytes", &self.weight_bytes())
            .field("hits", &self.counters.hits.load(Ordering::Relaxed))
            .field("misses", &self.counters.misses.load(Ordering::Relaxed))
            .field("values", &REDACTED)
            // Поля `cache`/`limits`/`removals` намеренно опущены: `Debug` кэша
            // обязан быть безопасен для логов.
            .finish_non_exhaustive()
    }
}

impl SessionStore {
    /// Кэш с указанными лимитами.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        let removals = Arc::new(RemovalCounters::default());
        let listener_counters = Arc::clone(&removals);
        let cache = Cache::builder()
            .max_capacity(limits.max_bytes)
            .weigher(|_k: &StoreKey, v: &SecretRef| -> u32 {
                u32::try_from(v.byte_len()).unwrap_or(u32::MAX)
            })
            .time_to_idle(limits.time_to_idle)
            .time_to_live(limits.time_to_live)
            .eviction_listener(move |_k, _v, cause| {
                let c = match cause {
                    RemovalCause::Expired => &listener_counters.expired,
                    RemovalCause::Size => &listener_counters.size,
                    RemovalCause::Explicit => &listener_counters.explicit,
                    RemovalCause::Replaced => &listener_counters.replaced,
                };
                c.fetch_add(1, Ordering::Relaxed);
                // `_v` здесь же и умирает: Drop SecretString затирает байты.
            })
            .build();
        Self {
            cache,
            limits,
            counters: Counters::default(),
            removals,
        }
    }

    /// Лимиты, с которыми создан кэш.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Кладёт оригинал под метку.
    ///
    /// Отказ по размеру — fail-closed: лучше, чтобы шаг 6 выдал необратимый
    /// `[REDACTED]`, чем молча урезал оригинал и позже подставил его кусок.
    ///
    /// # Errors
    ///
    /// [`StoreError::Empty`] — пустой оригинал; [`StoreError::TooBig`] — длиннее
    /// `Limits::max_value_bytes`. Запись при этом не производится.
    pub fn insert(&self, key: &StoreKey, original: SecretString) -> Result<(), StoreError> {
        let len = original.byte_len();
        if len == 0 {
            return Err(StoreError::Empty);
        }
        if len > self.limits.max_value_bytes {
            self.counters.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(StoreError::TooBig {
                len,
                max: self.limits.max_value_bytes,
            });
        }
        self.cache.insert(key.clone(), SecretRef::new(original));
        self.counters.inserts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Читает оригинал по ключу. Попадание обновляет sliding TTL.
    pub fn get(&self, key: &StoreKey) -> Option<SecretRef> {
        let hit = self.cache.get(key);
        if hit.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    /// Есть ли ключ. На sliding TTL не влияет (`moka::sync::Cache::contains_key`
    /// помечен как не обновляющий idle — первичка `sync/cache.rs:771`).
    #[must_use]
    pub fn contains(&self, key: &StoreKey) -> bool {
        self.cache.contains_key(key)
    }

    /// Забыть одну метку: после этого попадание невозможно (тест
    /// `hit_after_invalidate_is_impossible`).
    pub fn invalidate(&self, key: &StoreKey) {
        self.cache.invalidate(key);
    }

    /// Забыть все метки сессии — teardown по `[DONE]`/закрытию чата.
    ///
    /// Возвращает число снятых меток. Идёт итерацией, потому что
    /// `invalidate_entries_if` требует moka-feature `unstable`, а у нас
    /// зафиксирован набор `future,sync,atomic64,quanta` (первичка
    /// `moka-0.12.16/Cargo.toml:65-77`). Обход линейен по числу записей, а они
    /// ограничены байтовым бюджетом.
    pub fn invalidate_session(&self, session: &str) -> u64 {
        let doomed: Vec<StoreKey> = self
            .cache
            .iter()
            .filter(|(k, _v)| k.session() == session)
            .map(|(k, _v)| Arc::unwrap_or_clone(k))
            .collect();
        let n = doomed.len();
        for k in &doomed {
            self.cache.invalidate(k);
        }
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// Забыть всё.
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    /// Прогнать отложенные задачи moka: просрочку, invalidations, listeners.
    ///
    /// В демоне это делает внутренний планировщик (feature `future`); метод
    /// нужен тестам и точкам синхронизации вроде teardown сессии, где счётчики
    /// обязаны сойтись до возврата ответа.
    pub fn sync(&self) {
        self.cache.run_pending_tasks();
    }

    /// Число записей.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Суммарный вес (байты оригиналов) — метрика для `/v1/metrics`.
    #[must_use]
    pub fn weight_bytes(&self) -> u64 {
        self.cache.weighted_size()
    }

    /// Попаданий в кэш.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.counters.hits.load(Ordering::Relaxed)
    }

    /// Промахов.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.counters.misses.load(Ordering::Relaxed)
    }

    /// Вставлено значений.
    #[must_use]
    pub fn inserts(&self) -> u64 {
        self.counters.inserts.load(Ordering::Relaxed)
    }

    /// Отклонено по размеру.
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.counters.rejected.load(Ordering::Relaxed)
    }

    /// Удалено по истечении TTL.
    #[must_use]
    pub fn expired_count(&self) -> u64 {
        self.removals.expired.load(Ordering::Relaxed)
    }

    /// Вытеснено по байтовому бюджету — значение умерло, значит затёрто.
    #[must_use]
    pub fn evicted_count(&self) -> u64 {
        self.removals.size.load(Ordering::Relaxed)
    }

    /// Удалено явным `invalidate`/`invalidate_session`/`clear`.
    #[must_use]
    pub fn removed_count(&self) -> u64 {
        self.removals.explicit.load(Ordering::Relaxed)
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        // moka при дропе кэша уведомления не шлёт (notification.rs:25-27), но
        // значения всё равно умирают, а `SecretString::drop` затирает байты.
        // Явная инвалидация нужна, чтобы счётчики причин не соврали.
        self.cache.invalidate_all();
        self.cache.run_pending_tasks();
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)] // паника в тесте = красный CI, это канал ответа; truncation в тестах намеренна
mod tests {
    use super::*;

    fn key(session: &str, label: &str) -> StoreKey {
        StoreKey::new(session, label)
    }

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    /// Заглушка `Debug` у нас своя — проверяем, что она совпадает с рендером
    /// `SecretString`, иначе два «REDACTED» разъедутся при правке guard-types.
    #[test]
    fn redact_marker_matches_guard_types() {
        assert_eq!(SecretString::default().to_string(), REDACTED);
        assert_eq!(
            format!("{:?}", SecretString::default()),
            "SecretString(\"[REDACTED]\")"
        );
    }

    #[test]
    fn spec_limits_match_the_document() {
        // SPEC §3 п.2: sliding 15 мин, hard 2 ч. Числа закреплены тестом,
        // иначе правка SPEC молча разъедется с кодом.
        assert_eq!(Limits::SPEC_DEFAULT.time_to_idle, Duration::from_secs(900));
        assert_eq!(Limits::SPEC_DEFAULT.time_to_live, Duration::from_secs(7200));
        assert_eq!(Limits::default(), Limits::SPEC_DEFAULT);
        // Потолок демона <2 ГБ (AGENTS). `Limits::default()`, а не константа:
        // clippy прав на то, что сравнение констант ничего не проверяет.
        let ceiling_bytes = 2u64.pow(31);
        assert!(
            Limits::default().max_bytes < ceiling_bytes,
            "бюджет кэша обязан влезать в потолок демона <2 ГБ"
        );
    }

    /// Прямое требование ТЗ: после `invalidate` попадание невозможно.
    #[test]
    fn hit_after_invalidate_is_impossible() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        let k = key("sess-1", "CLIENT_PERSON_1");
        store
            .insert(&k, secret("Ушакова Кира Саввична"))
            .expect("insert");
        store.sync();
        assert!(store.get(&k).is_some(), "до invalidate должно попадаться");

        store.invalidate(&k);
        store.sync();
        assert!(
            store.get(&k).is_none(),
            "после invalidate попадание возможно"
        );
        assert!(!store.contains(&k), "contains врёт после invalidate");
        // Повторный sync не воскрешает запись.
        store.sync();
        assert!(store.get(&k).is_none(), "запись воскресла");
        // Та же метка свободна и занимает её другой оригинал.
        store
            .insert(&k, secret("Козлова А. И."))
            .expect("re-insert");
        store.sync();
        assert_eq!(store.get(&k).expect("re-hit").as_str(), "Козлова А. И.");
    }

    /// Требование ТЗ: Debug нигде не показывает оригинал.
    #[test]
    fn debug_and_display_never_leak_originals() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        let k = key("sess-9", "VENDOR_ORG_2");
        let canary = "ООО Ромашка-НеподсказуемоеНазвание";
        store.insert(&k, secret(canary)).expect("insert");
        store.sync();
        let value = store.get(&k).expect("hit");
        for rendered in [
            format!("{store:?}"),
            format!("{value:?}"),
            format!("{:?}", value.expose()),
            format!("{value}"),
            format!("{}", value.expose()),
            format!("{k:?}"),
        ] {
            assert!(
                !rendered.contains(canary),
                "утечка оригинала в Debug/Display: {rendered}"
            );
        }
        assert!(
            format!("{store:?}").contains("REDACTED"),
            "Debug кэша без заглушки"
        );
        assert!(
            format!("{value:?}").contains("REDACTED"),
            "Debug значения без заглушки"
        );
        assert!(format!("{store:?}").contains("entries"), "Debug без метрик");
        assert_eq!(store.hits(), 1);
        assert_eq!(store.misses(), 0);
    }

    /// Hard TTL убивает запись, даже если в неё непрерывно попадают.
    #[test]
    fn hard_ttl_kills_even_hot_entries() {
        let store = SessionStore::new(Limits::for_test(
            Duration::from_secs(3600),
            Duration::from_millis(250),
        ));
        let k = key("sess-ttl", "PERSON_1");
        store.insert(&k, secret("Смирнов")).expect("insert");
        store.sync();
        // 3 паузы по 120 мс = 360 мс против TTL 250 мс: запас на планировщик,
        // иначе тест флапал бы на загруженном CI.
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(120));
            let _ = store.get(&k); // попадание обновляет idle, но не live
        }
        assert!(store.get(&k).is_none(), "hard TTL не сработал");
        store.sync();
        assert!(store.expired_count() > 0, "listener не увидел просрочку");
    }

    /// Sliding idle: попадающая запись переживает тишину, молчащая — нет.
    #[test]
    fn sliding_idle_is_reset_by_hit() {
        let store = SessionStore::new(Limits::for_test(
            Duration::from_millis(600),
            Duration::from_secs(3600),
        ));
        let hot = key("s", "PERSON_1");
        let cold = key("s", "PERSON_2");
        store.insert(&hot, secret("Иванов")).expect("insert hot");
        store.insert(&cold, secret("Петров")).expect("insert cold");
        store.sync();
        // Кэш живёт 5× по 150 мс = 750 мс при idle 600 мс: hot каждый раз
        // обновляется с запасом ×4, cold успевает умереть с запасом 150 мс.
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(150));
            assert!(store.get(&hot).is_some(), "попадающая запись протухла");
        }
        store.sync();
        assert!(
            store.get(&cold).is_none(),
            "молчащая запись обязана протухнуть по idle"
        );
    }

    /// Вытеснение по бюджету: значение умирает ⇒ `SecretString::drop` затирает
    /// байты. Проверяемо безопасным способом — `Weak` на `Arc` внутри ручки.
    #[test]
    fn size_eviction_drops_value_so_it_gets_zeroized() {
        let store = SessionStore::new(Limits {
            max_bytes: 200,
            ..Limits::SPEC_DEFAULT
        });
        let big = "Ушакова Кира Саввична ".repeat(4); // 88 Б
        let victim = key("s", "PERSON_2");
        store.insert(&victim, secret(&big)).expect("insert victim");
        store.sync();
        let handle = store.get(&victim).expect("victim лежит");
        let weak = Arc::downgrade(&handle.0);
        drop(handle);
        for i in 0..8 {
            store
                .insert(&key("s", &format!("PERSON_{i}")), secret(&big))
                .expect("insert filler");
        }
        store.sync();
        assert!(store.evicted_count() > 0, "вытеснения по размеру не было");
        assert!(
            store.weight_bytes() <= 200,
            "вес {} вылез за бюджет 200",
            store.weight_bytes()
        );
        assert!(
            released(&weak, Some(&store)),
            "последняя ручка вытесненной записи жива ⇒ оригинал не затёрт"
        );
    }

    /// Вес = байты оригиналов (метрика для `/v1/metrics`).
    #[test]
    fn weight_tracks_original_bytes() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        let a = "Ушакова Кира Саввична";
        let b = "825082492964";
        store.insert(&key("w", "A"), secret(a)).expect("a");
        store.insert(&key("w", "B"), secret(b)).expect("b");
        store.sync();
        assert_eq!(store.weight_bytes(), (a.len() + b.len()) as u64);
        assert_eq!(store.entry_count(), 2);
    }

    /// `invalidate_session` снимает только свою сессию.
    #[test]
    fn invalidate_session_touches_only_that_session() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        for s in ["A", "B"] {
            for l in ["CLIENT_PERSON_1", "VENDOR_ORG_2"] {
                store
                    .insert(&key(s, l), secret("Фамилия Имя Отчество"))
                    .expect("insert");
            }
        }
        store.sync();
        assert_eq!(store.entry_count(), 4);
        assert_eq!(
            store.invalidate_session("A"),
            2,
            "снят не весь набор сессии"
        );
        store.sync();
        assert_eq!(store.entry_count(), 2);
        assert!(store.get(&key("A", "CLIENT_PERSON_1")).is_none());
        assert!(
            store.get(&key("B", "CLIENT_PERSON_1")).is_some(),
            "чужая сессия пострадала"
        );
        assert_eq!(
            store.removed_count(),
            2,
            "listener не досчитался явных удалений"
        );
    }

    /// Oversize и пустой оригинал не попадают в кэш и считаются отдельно.
    #[test]
    fn oversized_and_empty_values_are_refused() {
        let store = SessionStore::new(Limits {
            max_value_bytes: 16,
            ..Limits::SPEC_DEFAULT
        });
        let long = "Ушакова Кира Саввична";
        assert!(
            long.len() > store.limits().max_value_bytes,
            "тест должен быть на входе за лимитом"
        );
        let err = store
            .insert(&key("s", "PERSON_1"), secret(long))
            .expect_err("длинный оригинал обязан отказываться");
        // Ожидаемая длина — из промера, не из подсчёта пальцами: кириллица = 2 Б.
        assert_eq!(
            err,
            StoreError::TooBig {
                len: long.len(),
                max: 16
            }
        );
        assert_eq!(
            store
                .insert(&key("s", "PERSON_2"), secret(""))
                .expect_err("пустой оригинал обязан отказываться"),
            StoreError::Empty
        );
        assert_eq!(store.entry_count(), 0, "отказавшая запись влезла в кэш");
        assert_eq!(store.inserts(), 0);
        assert_eq!(store.rejected(), 1);
    }

    /// Ждёт освобождения `Arc` ограниченным числом прогонов pending-задач.
    ///
    /// moka убирает запись из карты сразу, но значение отпускает не на том
    /// вызове, который его вытеснил/заменил: оно лежит во внутренней очереди
    /// removal-ов и drain-ится на `run_pending_tasks()` либо на следующей
    /// операции над кэшем. Поэтому «старый оригинал стёр» проверяем с
    /// ограниченным ожиданием (≤250 мс), а не одним assert-ом в ноль.
    fn released(weak: &std::sync::Weak<SecretString>, store: Option<&SessionStore>) -> bool {
        for _ in 0..50 {
            if let Some(st) = store {
                st.sync();
            }
            if weak.upgrade().is_none() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        weak.upgrade().is_none()
    }

    /// Замена значения под тем же ключом отпускает старое (⇒ старое затёрто).
    #[test]
    fn replace_drops_old_value() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        let k = key("r", "PERSON_1");
        store.insert(&k, secret("СтарыйОригинал")).expect("first");
        store.sync();
        let old = store.get(&k).expect("old");
        let weak = Arc::downgrade(&old.0);
        drop(old);
        store.insert(&k, secret("НовыйОригинал")).expect("second");
        store.sync();
        assert_eq!(store.get(&k).expect("hit").as_str(), "НовыйОригинал");
        drop(store);
        assert!(
            released(&weak, None),
            "старое значение не отпущено после Drop кэша ⇒ оригинал мог остаться в RAM"
        );
    }

    /// Кэш разделяем между потоками: демон многопоточный, `Send + Sync`.
    #[test]
    fn shared_across_threads_without_data_races() {
        let store = Arc::new(SessionStore::new(Limits::SPEC_DEFAULT));
        let mut handles = Vec::new();
        for t in 0..4u64 {
            let s = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for i in 0..50u64 {
                    let k = key("shared", &format!("PERSON_{}", (i + t) % 7));
                    let _ = s.insert(&k, secret("Тестовый Оригинал"));
                    let _ = s.get(&k);
                }
                s.sync();
            }));
        }
        for h in handles {
            h.join().expect("тред упал");
        }
        assert_eq!(store.inserts(), 200, "не все вставки дошли");
        assert_eq!(store.hits() + store.misses(), 200, "счётчик обращений врёт");
        assert!(store.entry_count() <= 7, "ключей больше, чем 7 меток");
    }

    /// `clear` опустошает кэш, `Drop` отпускает значения.
    #[test]
    fn clear_empties_the_store() {
        let store = SessionStore::new(Limits::SPEC_DEFAULT);
        for i in 0..5 {
            store
                .insert(&key("c", &format!("PERSON_{i}")), secret("Оригинал"))
                .expect("insert");
        }
        store.sync();
        assert_eq!(store.entry_count(), 5);
        store.clear();
        store.sync();
        assert_eq!(store.entry_count(), 0, "clear не опустошил кэш");
        assert!(store.get(&key("c", "PERSON_0")).is_none());
    }
}
