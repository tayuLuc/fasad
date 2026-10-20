//! Stateless-токен обратимой маскировки (SPEC §3 режим 3, §10 шаг 5 атом A).
//!
//! Контейнер: `nonce(24) ‖ ciphertext ‖ tag(16)` поверх **LZ4-block** оригинала,
//! упакованный в base64url без паддинга. AEAD — `XChaCha20Poly1305` в детачном
//! режиме (`AeadInOut::encrypt_inout_detached`): тег живёт отдельным полем
//! контейнера, как требует форма упаковки.
//!
//! Границы ответственности:
//! * Ключ входит **уже выведенным** 32-байтовым [`SessionKey`]. HKDF/пер-сессинная
//!   деривация — шаг 6 (SPEC §10 п.6), здесь её нет намеренно.
//! * Нонса — только системный CSPRNG через `Generate::try_generate`: отказ
//!   энтропии даёт `Err`, а не тихую детерминированную нонсу (fail-closed).
//! * `AAD` привязан константой к формату `F0` — доменное разделение: токен
//!   другого формата этот декодер не примет даже случайно.
//! * Заголовок LZ4 читается и сверяется с лимитом **до** аллокации
//!   (`VaultError::Bomb`).
//! * Все буферы, содержащие оригинал (LZ4-блок до шифрования, plaintext после
//!   расшифровки), проходят через [`LockedBuf`] = mlock + zeroize (инвариант
//!   AGENTS «Все буферы с оригиналами `ПДн`: `ZeroizeOnDrop` + mlock/VirtualLock»,
//!   SPEC §3 «расшифровка идёт в mlock+zeroize-буфер»). `region::lock` — safe
//!   функция, поэтому крейт по-прежнему живёт под `#![forbid(unsafe_code)]`.

#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, Generate, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Длина выведенного сессионного ключа (`XChaCha20Poly1305` — 256 бит).
pub const KEY_LEN: usize = 32;
/// Длина нонсы `XChaCha20Poly1305`.
pub const NONCE_LEN: usize = 24;
/// Длина Poly1305-тега (детачно).
pub const TAG_LEN: usize = 16;

/// Верхняя граница длины оригинала в байтах, которую токен готов понести.
///
/// Числа в ТЗ на этот атом не было, и в SPEC его нет: §4 maxLength не задаёт, а
/// §8 («look-ahead буфер до 32 байт») описывает человекочитаемый лейбл
/// `[PERSON_1]`, не крипто-токен. Значение выведено из промера датасета:
/// `data/golden/golden-v1.jsonl`, 378 спанов, поле `value_source`: max = 109 Б
/// («г. Екатеринбург, Октябрьской Революции улица, дом 71 к. 1 стр. 4»),
/// p95 = 78 Б. Взято 128 Б — ближайшее круглое выше промеренного максимума,
/// то есть покрыты все спаны золотого набора.
pub const MAX_ORIGINAL_BYTES: usize = 128;

/// Без префикса: ровно `lz4_flex::block::get_maximum_output_size`.
const fn lz4_worst_no_prefix(n: usize) -> usize {
    16 + 4 + n * 110 / 100
}

/// Худшая длина LZ4-block с префиксом размера для `n` байт входа.
///
/// `4` — u32 LE объявленный размер (формат `compress_prepend_size`), плюс
/// граница `get_maximum_output_size` (промер
/// `lz4_flex-0.14.0/src/block/compress.rs:605`). На коротких строках `ПДн` LZ4 не
/// сжимает, поэтому граница берётся по худшему случаю.
const fn lz4_worst(n: usize) -> usize {
    4 + lz4_worst_no_prefix(n)
}

/// Худшая длина LZ4-block при лимите оригинала (= `lz4_worst(128)` = 164).
pub const MAX_LZ4_BYTES: usize = lz4_worst(MAX_ORIGINAL_BYTES);

/// Худшая длина бинарного контейнера `nonce ‖ ct ‖ tag`.
pub const MAX_WIRE_BYTES: usize = NONCE_LEN + MAX_LZ4_BYTES + TAG_LEN;

/// Длина base64url без паддинга для `n` байт.
const fn b64url_len(n: usize) -> usize {
    n / 3 * 4
        + match n % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

/// Худшая длина токена в символах base64url при [`MAX_ORIGINAL_BYTES`].
///
/// Это настоящий `maxLength` inline-токена, и он не равен 124 из ТЗ. Пересчёт
/// (тест `budget_arithmetic_is_self_consistent`): 124 символа = 93 байта
/// контейнера = 53 байта LZ4-блока = оригинал не длиннее **27 байт** — не
/// влезает даже ФИО из золотого набора (42 Б).
pub const MAX_TOKEN_B64_LEN: usize = b64url_len(MAX_WIRE_BYTES);

/// Префикс inline-маркера формата F0. Версия формата живёт в префиксе, а не
/// внутри шифртекста: контейнер по ТЗ = `nonce ‖ ct ‖ tag` без заголовка.
pub const MARKER_PREFIX: &str = "[[F0#";
/// Суффикс inline-маркера формата F0.
pub const MARKER_SUFFIX: &str = "]]";
/// Худшая длина маркера целиком — бюджет look-ahead для `rewriter` (атом B).
pub const MAX_MARKER_BYTES: usize = MARKER_PREFIX.len() + MAX_TOKEN_B64_LEN + MARKER_SUFFIX.len();

/// Additional authenticated data — доменное разделение формата F0.
const AAD: &[u8] = b"fasad-vault-F0";

/// Политика mlock для буферов с оригиналами.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MlockPolicy {
    /// Требовать VirtualLock/mlock: не удалось — ошибка, запрос не обслуживается
    /// (fail-closed, дефолт по AGENTS).
    #[default]
    Strict,
    /// Разрешить незащищённую от свопинга аллокацию (но всё равно обнуляемую).
    /// Только для окружений, где оператор явно принял риск: `RLIMIT_MEMLOCK`
    /// на CI, Windows без `SeLockMemoryPrivilege`.
    BestEffort,
}

/// Ошибки контейнера. Все fail-closed: ни одна не отдаёт partial-plaintext.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// Пустой оригинал: маскировать нечего, а токен нулевого блока — подарок
    /// для padding-oracle.
    #[error("пустой оригинал не токенизируется")]
    Empty,
    /// Оригинал длиннее [`MAX_ORIGINAL_BYTES`] либо LZ4-блок упёрся в
    /// [`MAX_LZ4_BYTES`] — урезать нельзя, значит не выпускаем.
    #[error("длина {len} Б не влезает в лимит {max} Б")]
    TooLong {
        /// Фактическая длина.
        len: usize,
        /// Лимит.
        max: usize,
    },
    /// LZ4-заголовок объявляет размер больше лимита — отклонено до аллокации.
    #[error("LZ4-заголовок объявляет {declared} Б при лимите {max} Б")]
    Bomb {
        /// Что объявил заголовок.
        declared: usize,
        /// Лимит.
        max: usize,
    },
    /// Base64url распался, но не канонично (паддинг, лишние биты остатка).
    #[error("неканоничный base64url")]
    NonCanonical,
    /// Вход вообще не base64url.
    #[error("декодирование base64url не удалось")]
    Encoding,
    /// Контейнер короче минимума `nonce ‖ tag` или длиннее бюджета.
    #[error("контейнер вне допустимой длины")]
    Truncated,
    /// Длина ключа не [`KEY_LEN`].
    #[error("длина ключа {0} != {KEY_LEN}")]
    KeyLen(usize),
    /// Тег не сошёлся: подделка, чужой ключ, битый транспорт.
    #[error("токен не аутентичен")]
    Auth,
    /// LZ4-сжатие не удалось (выход больше худшей границы).
    #[error("LZ4-сжатие не удалось")]
    Compress,
    /// LZ4-декомпрессия не удалась после успешной аутентификации.
    #[error("LZ4-блок битый")]
    Corrupt,
    /// Расшифрованное — не валидный UTF-8.
    #[error("оригинал не UTF-8")]
    NotUtf8,
    /// Системный CSPRNG отказал.
    #[error("системный CSPRNG отказал")]
    Entropy,
    /// mlock не удался при [`MlockPolicy::Strict`] — оригинал в свопе недопустим.
    #[error("mlock/VirtualLock не удался (RLIMIT_MEMLOCK?)")]
    Mlock,
}

/// Буфер под `ПДн`: выделен, залочен в RAM, стирается при drop.
///
/// `guard` объявлен ПОСЛЕ `data`: ручной `Drop` сначала обнуляет байты, потом
/// снимает блокировку, а не наоборот (munlock по обнулённой памяти).
pub struct LockedBuf {
    data: Zeroizing<Vec<u8>>,
    guard: Option<region::LockGuard>,
}

impl LockedBuf {
    /// Аллоцирует `len` байт и пытается их залочить.
    ///
    /// `MlockPolicy::Strict` ⇒ отказ блокировки есть ошибка. `BestEffort` ⇒
    /// возвращается незащищённый от свопинга (но всё равно обнуляемый) буфер.
    pub fn allocate(len: usize, policy: MlockPolicy) -> Result<Self, VaultError> {
        let data = Zeroizing::new(vec![0_u8; len]);
        let guard = lock_data(&data, policy)?;
        Ok(Self { data, guard })
    }

    /// Содержимое для записи.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Содержимое для чтения.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Длина буфера.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Буфер нулевой длины.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Перекладывает первые `new_len` байт в новый залоченный буфер; старый
    /// стирается и разблокируется при drop.
    ///
    /// Нужно потому, что точный размер LZ4-блока известен только после сжатия,
    /// а лочим мы ровно тот диапазон, который отдаём наружу.
    fn resized(self, new_len: usize, policy: MlockPolicy) -> Result<Self, VaultError> {
        let keep = new_len.min(self.len());
        let mut next = Self::allocate(new_len, policy)?;
        next.as_mut_slice()[..keep].copy_from_slice(&self.as_slice()[..keep]);
        Ok(next)
    }
}

impl ZeroizeOnDrop for LockedBuf {}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.data.zeroize();
        // Снимаем блокировку ПОСЛЕ обнуления.
        self.guard = None;
    }
}

/// mlock диапазону данных `data`.
fn lock_data(data: &[u8], policy: MlockPolicy) -> Result<Option<region::LockGuard>, VaultError> {
    if data.is_empty() {
        // region::lock требует ненулевого размера; пустой буфер запирать нечего.
        return Ok(None);
    }
    match region::lock(data.as_ptr(), data.len()) {
        Ok(guard) => Ok(Some(guard)),
        Err(_) if policy == MlockPolicy::BestEffort => Ok(None),
        Err(_) => Err(VaultError::Mlock),
    }
}

/// Выведенный сессионный ключ: `ZeroizeOnDrop`, `Debug = [REDACTED]`.
///
/// AGENTS §Инженерные инварианты требует стирания буферов с `ПДн`; ключ — самый
/// чувствительный из них. `Zeroizing` даёт стирание на drop, явная маркировка —
/// маркерный трейт (derive на обёртке его не генерирует; разбор в
/// `guard-types/src/secret.rs`).
pub struct SessionKey(Zeroizing<[u8; KEY_LEN]>);

impl SessionKey {
    /// Оборачивает уже выведенный ключ.
    #[must_use]
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Из среза: длина обязана быть ровно [`KEY_LEN`], без тихой обрезки.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != KEY_LEN {
            return Err(VaultError::KeyLen(bytes.len()));
        }
        let mut buf = [0_u8; KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self(Zeroizing::new(buf)))
    }

    /// Шифр, подготовленный из этого ключа.
    ///
    /// `KeyInit::new` принимает `&Key` фиксированной длины, а длину гарантирует
    /// конструктор, поэтому здесь нет ветки ошибки. Сам `XChaCha20Poly1305`
    /// стирает ключ на drop (feature `zeroize`).
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.0))
    }
}

impl TryFrom<&[u8]> for SessionKey {
    type Error = VaultError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(bytes)
    }
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни значения, ни длины.
        f.write_str("SessionKey(\"[REDACTED]\")")
    }
}

impl ZeroizeOnDrop for SessionKey {}

/// Stateless-токен: `nonce ‖ ct ‖ tag` до упаковки в base64url.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultToken {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_LEN],
}

impl ZeroizeOnDrop for VaultToken {}

impl core::fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Шифртекст не светим, и длину оригинала тоже — она сама по себе
        // косвенная утечка (сколько ПДн было в запросе).
        f.debug_struct("VaultToken")
            .field("wire_len", &self.wire_len())
            .finish_non_exhaustive()
    }
}

impl VaultToken {
    /// Минимальная длина контейнера: нонса + тег + хотя бы байт блока.
    const MIN_WIRE: usize = NONCE_LEN + TAG_LEN + 1;

    /// Упаковывает оригинал с дефолтной (Strict) политикой блокировки памяти.
    pub fn seal(key: &SessionKey, original: &[u8]) -> Result<Self, VaultError> {
        Self::seal_with(key, original, MlockPolicy::Strict)
    }

    /// Упаковывает оригинал: LZ4-block → `XChaCha20Poly1305` (детачно) →
    /// `nonce ‖ ct ‖ tag`. Нонса — системный CSPRNG.
    pub fn seal_with(
        key: &SessionKey,
        original: &[u8],
        policy: MlockPolicy,
    ) -> Result<Self, VaultError> {
        if original.is_empty() {
            return Err(VaultError::Empty);
        }
        if original.len() > MAX_ORIGINAL_BYTES {
            return Err(VaultError::TooLong {
                len: original.len(),
                max: MAX_ORIGINAL_BYTES,
            });
        }
        let nonce = XNonce::try_generate().map_err(|_| VaultError::Entropy)?;
        // Буфер под LZ4-блок: до шифрования он содержит ПДн, поэтому mlock+zeroize.
        // Размер — худшая граница формата, точный узнаём после сжатия.
        let mut buf = LockedBuf::allocate(lz4_worst(original.len()), policy)?;
        // Объявленный размер в префиксе — u32 LE (формат lz4_flex). Лимит выше
        // гарантирует влезание, но приведение делаем проверяемым, не `as`.
        let declared = u32::try_from(original.len()).map_err(|_| VaultError::TooLong {
            len: original.len(),
            max: MAX_ORIGINAL_BYTES,
        })?;
        buf.as_mut_slice()[..4].copy_from_slice(&declared.to_le_bytes());
        let written = lz4_flex::block::compress_into(original, &mut buf.as_mut_slice()[4..])
            .map_err(|_| VaultError::Compress)?;
        let block_len = 4usize.checked_add(written).ok_or(VaultError::Compress)?;
        if block_len > MAX_LZ4_BYTES {
            return Err(VaultError::TooLong {
                len: block_len,
                max: MAX_LZ4_BYTES,
            });
        }
        let mut buf = buf.resized(block_len, policy)?;
        let tag: Tag = key
            .cipher()
            .encrypt_inout_detached(&nonce, AAD, InOutBuf::from(buf.as_mut_slice()))
            .map_err(|_| VaultError::Auth)?;
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce[..]);
        let mut tag_bytes = [0_u8; TAG_LEN];
        tag_bytes.copy_from_slice(&tag[..]);
        // Наружу уходит копия уже шифртекста; сам буфер стирается на drop.
        Ok(Self {
            nonce: nonce_bytes,
            ciphertext: buf.as_slice().to_vec(),
            tag: tag_bytes,
        })
    }

    /// Разбор бинарного контейнера.
    pub fn from_wire(wire: &[u8]) -> Result<Self, VaultError> {
        if wire.len() < Self::MIN_WIRE || wire.len() > MAX_WIRE_BYTES {
            return Err(VaultError::Truncated);
        }
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&wire[..NONCE_LEN]);
        let mut tag = [0_u8; TAG_LEN];
        tag.copy_from_slice(&wire[wire.len() - TAG_LEN..]);
        Ok(Self {
            nonce,
            ciphertext: wire[NONCE_LEN..wire.len() - TAG_LEN].to_vec(),
            tag,
        })
    }

    /// Собирает `nonce ‖ ct ‖ tag`.
    #[must_use]
    pub fn as_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Длина контейнера в байтах.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        NONCE_LEN + self.ciphertext.len() + TAG_LEN
    }

    /// Токен строкой base64url без паддинга — то, что едет в тексте/JSON.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.as_wire())
    }

    /// Разбор строки base64url со строгой каноничностью: перекодировка
    /// расширенного обязана совпасть с входом символ в символ.
    pub fn from_base64url(s: &str) -> Result<Self, VaultError> {
        use base64::Engine as _;
        let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| VaultError::Encoding)?;
        if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire) != s {
            return Err(VaultError::NonCanonical);
        }
        Self::from_wire(&wire)
    }

    /// Маркер для подстановки в текст: `[[F0#<base64url>]]`.
    #[must_use]
    pub fn to_marker(&self) -> String {
        format!("{MARKER_PREFIX}{}{MARKER_SUFFIX}", self.to_base64url())
    }

    /// Обратная операция с дефолтной (Strict) политикой блокировки.
    pub fn open(&self, key: &SessionKey) -> Result<Zeroizing<String>, VaultError> {
        self.open_with(key, MlockPolicy::Strict)
    }

    /// Обратная операция: аутентификация → LZ4 → оригинал.
    ///
    /// Расшифровка идёт в [`LockedBuf`] (mlock + zeroize), выход —
    /// `Zeroizing<String>`: байты оригинала не переживают значение.
    pub fn open_with(
        &self,
        key: &SessionKey,
        policy: MlockPolicy,
    ) -> Result<Zeroizing<String>, VaultError> {
        let nonce = XNonce::try_from(&self.nonce[..]).map_err(|_| VaultError::Truncated)?;
        let tag = Tag::try_from(&self.tag[..]).map_err(|_| VaultError::Truncated)?;
        let mut buf = LockedBuf::allocate(self.ciphertext.len(), policy)?;
        buf.as_mut_slice().copy_from_slice(&self.ciphertext);
        key.cipher()
            .decrypt_inout_detached(&nonce, AAD, InOutBuf::from(buf.as_mut_slice()), &tag)
            .map_err(|_| VaultError::Auth)?;
        let plain = lz4_decompress(buf.as_slice(), policy)?;
        // Копия уходит вызывающему в Zeroizing<String> и сотрётся на его drop;
        // залоченный источник сотрётся здесь.
        match String::from_utf8(plain) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                Err(VaultError::NotUtf8)
            }
        }
    }
}

/// LZ4-распаковка формата `compress_prepend_size` с проверкой объявления до
/// аллокации.
fn lz4_decompress(block: &[u8], policy: MlockPolicy) -> Result<Vec<u8>, VaultError> {
    let (declared, rest) =
        lz4_flex::block::uncompressed_size(block).map_err(|_| VaultError::Corrupt)?;
    if declared > MAX_ORIGINAL_BYTES {
        return Err(VaultError::Bomb {
            declared,
            max: MAX_ORIGINAL_BYTES,
        });
    }
    let mut buf = LockedBuf::allocate(declared, policy)?;
    if let Ok(written) = lz4_flex::block::decompress_into(rest, buf.as_mut_slice()) {
        Ok(buf.as_slice()[..written].to_vec())
    } else {
        buf.as_mut_slice().zeroize();
        Err(VaultError::Corrupt)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // паника в тесте = красный CI, это канал ответа
mod tests {
    use super::*;

    /// Ключ KAT-вектора.
    fn kat_key() -> SessionKey {
        SessionKey::new([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ])
    }

    fn key() -> SessionKey {
        SessionKey::new([0x2a; KEY_LEN])
    }

    /// Детерминированный LCG — псевдослучайные байты для проверки границы LZ4
    /// без зависимости от RNG в тесте (только для сверки размеров).
    fn incompressible(n: usize) -> Vec<u8> {
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s.to_le_bytes()[0]
            })
            .collect()
    }

    /// Псевдослучайный валидный UTF-8 ровно `bytes` байт: контракт контейнера —
    /// текст спана `ПДн`, поэтому худший случай считаем на кириллице (2 байта на
    /// знак из 32-символьного алфавита, минимальная избыточность).
    fn incompressible_utf8(bytes: usize) -> String {
        assert_eq!(bytes % 2, 0, "граница строится на 2-байтовых знаках");
        let alphabet: Vec<char> = ('а'..='я').collect();
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = String::with_capacity(bytes);
        for _ in 0..bytes / 2 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            out.push(alphabet[(s % 32) as usize]);
        }
        assert_eq!(out.len(), bytes);
        out
    }

    /// KAT-первичка — IETF `draft-irtf-cfrg-xchacha-03`, Appendix A.1 «Example
    /// and Test Vector for `AEAD_XCHACHA20_POLY1305»`
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt>
    /// (скачан 20.10, 36 930 Б ASCII, sha256
    /// `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd`,
    /// блок — строки 487–546: KEY `80..9f`, IV `40..57`, AAD
    /// `50 51 52 53 c0..c7`, CT `bd 6d 17 9d … b5 2e`, Tag
    /// `c0:87:59:24:c1:c7:98:79:47:de:af:d8:78:0a:cf:49`).
    ///
    /// Вторичное подтверждение — что именно эта реализация вектор воспроизводит:
    /// `chacha20poly1305-0.11.0/tests/lib.rs`, `mod xchacha20` (строки 151–190,
    /// `.crate` sha256 `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789
    /// bac751cb`, файла sha256 `02b398b55dd393d896e2f111f202e86c72779036527a2afb
    /// c662bd41e1a29006`). Числа там записаны байтовыми литералами, а не
    /// сплошной hex-строкой — отсюда ложное «векторов нет» при grep по
    /// `bd6d179d`.
    ///
    /// RFC 8439 §2.4.2 для нашего пути неприменим: тот вектор —
    /// `ChaCha20Poly1305` с 12-байтовой нонсой, а контейнер идёт на `XChaCha` с
    /// 24-байтовой (SPEC §3 режим 3). KEY/PLAINTEXT в обоих наборах общие,
    /// отличаются NONCE/AAD/CT/TAG — взяты официальные векторы `XChaCha`.
    const KAT_NONCE: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    /// AAD самого вектора — НЕ производственный [`AAD`]: формат F0 привязывает
    /// свой доменный разделитель, здесь проверяется совместимость с чужим
    /// вектором. Разница видна тестом ниже: с нашим AAD тег не совпадёт.
    const KAT_AAD: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const KAT_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";
    const KAT_CT: &[u8] = &[
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
    ];
    const KAT_TAG: [u8; 16] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf,
        0x49,
    ];

    /// Вектор шифруется НАПРЯМУЮ, в обход LZ4, тем же detached-вызовом, которым
    /// пользуется `seal`: так KAT проверяет обвязку AEAD (detached + расстановка
    /// полей + чувствительность тега к AAD), а не LZ4.
    #[test]
    fn kat_xchacha20poly1305_detached_with_aad() {
        let mut buf = Zeroizing::new(KAT_PT.to_vec());
        let nonce = XNonce::try_from(&KAT_NONCE[..]).expect("24 байта");
        let tag: Tag = kat_key()
            .cipher()
            .encrypt_inout_detached(&nonce, KAT_AAD, InOutBuf::from(&mut buf[..]))
            .expect("шифрование вектора");
        assert_eq!(&buf[..], KAT_CT, "KAT: ciphertext разошёлся");
        assert_eq!(&tag[..], &KAT_TAG[..], "KAT: tag разошёлся");
        // Тот же вход с нашим доменным AAD ⇒ другой тег (тот же шифртекст):
        // AAD действительно участвует в аутентификации формата F0.
        let mut cross = Zeroizing::new(KAT_PT.to_vec());
        let foreign_tag: Tag = kat_key()
            .cipher()
            .encrypt_inout_detached(&nonce, AAD, InOutBuf::from(&mut cross[..]))
            .expect("шифрование с производственным AAD");
        assert_eq!(&cross[..], KAT_CT, "AAD не должен менять шифртекст");
        assert_ne!(&foreign_tag[..], &KAT_TAG[..], "AAD не повлиял на тег");
    }

    /// Тот же векторный plaintext — уже через публичный контейнер (LZ4+AEAD).
    /// 114 байт, в лимит 128 влезает, так что round-trip обязан сойтись.
    #[test]
    fn kat_plaintext_roundtrips_through_container() {
        assert!(KAT_PT.len() <= MAX_ORIGINAL_BYTES);
        let tok = VaultToken::seal(&kat_key(), KAT_PT).expect("seal вектора");
        let back = tok.open(&kat_key()).expect("open вектора");
        assert_eq!(back.as_bytes(), KAT_PT);
    }

    #[test]
    fn roundtrip_restores_original_utf8() {
        for original in [
            "Ушакова Кира Саввична",
            "825082492964",
            "СНИЛС 378-312-074 87",
            "Ё",
            "Ж",
            "г. Ростов-на-Дону, Октябрьской Революции улица, дом 48",
        ] {
            let tok = VaultToken::seal(&key(), original.as_bytes()).expect("seal");
            let back = tok.open(&key()).expect("open");
            assert_eq!(
                back.as_str(),
                original,
                "round-trip сломался на {original:?}"
            );
        }
    }

    /// Нонса случайна ⇒ два токена одного оригинала различаются, но оба
    /// расшифровываются.
    #[test]
    fn nonce_is_random_so_tokens_differ() {
        let o = "Козлова А. И.".as_bytes();
        let a = VaultToken::seal(&key(), o).expect("seal a");
        let b = VaultToken::seal(&key(), o).expect("seal b");
        assert_ne!(a.to_base64url(), b.to_base64url(), "нонса повторилась");
        let ta = a.open(&key()).expect("open a");
        let tb = b.open(&key()).expect("open b");
        assert_eq!(ta.as_str(), tb.as_str());
    }

    #[test]
    fn marker_and_base64_roundtrip_is_byte_exact() {
        let tok = VaultToken::seal(&key(), "Ушакова Кира Саввична".as_bytes()).expect("seal");
        let b64 = tok.to_base64url();
        assert!(
            b64.len() <= MAX_TOKEN_B64_LEN,
            "токен {} символов превысил бюджет {MAX_TOKEN_B64_LEN}",
            b64.len()
        );
        assert!(
            !b64.contains(['+', '/', '=']),
            "base64url без padding: {b64}"
        );
        let parsed = VaultToken::from_base64url(&b64).expect("разбор");
        assert_eq!(parsed.as_wire(), tok.as_wire());
        let marker = tok.to_marker();
        assert!(marker.starts_with(MARKER_PREFIX));
        assert!(marker.ends_with(MARKER_SUFFIX));
        assert!(marker.len() <= MAX_MARKER_BYTES);
    }

    /// Подмена любого бита в любом поле → `Err`, никогда panic, никогда
    /// partial-plaintext. Проход по ВСЕМ позициям: «один битый байт» не
    /// доказывает, что байт в другом месте не пройдёт.
    #[test]
    fn fail_closed_on_every_single_bit_flip() {
        let tok = VaultToken::seal(&key(), "Смирнова".as_bytes()).expect("seal");
        let wire = tok.as_wire();
        let mut checked = 0_usize;
        for idx in 0..wire.len() {
            for bit in 0..8 {
                let mut bad = wire.clone();
                bad[idx] ^= 1 << bit;
                let parsed = VaultToken::from_wire(&bad).expect("контейнер разбирается");
                checked += 1;
                if let Ok(text) = parsed.open(&key()) {
                    // Ни символов оригинала в сообщении паники: только длина.
                    panic!(
                        "подмена байта {idx} бита {bit} вернула текст длиной {} Б",
                        text.len()
                    );
                }
            }
        }
        assert_eq!(checked, wire.len() * 8, "пройден не весь контейнер");
        assert!(
            wire.len() > NONCE_LEN + TAG_LEN,
            "в контейнере есть LZ4-блок"
        );
    }

    #[test]
    fn wrong_key_never_yields_plaintext() {
        let tok = VaultToken::seal(&key(), "ИНН 7701234567".as_bytes()).expect("seal");
        let other = SessionKey::new([0x11; KEY_LEN]);
        assert_eq!(tok.open(&other).err(), Some(VaultError::Auth));
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert_eq!(VaultToken::seal(&key(), b"").err(), Some(VaultError::Empty));
        let big = vec![b'q'; MAX_ORIGINAL_BYTES + 1];
        assert!(matches!(
            VaultToken::seal(&key(), &big).err(),
            Some(VaultError::TooLong { .. })
        ));
        // Граница лимита пролазит (несжимаемый текст — худший случай).
        let edge = incompressible_utf8(MAX_ORIGINAL_BYTES);
        let tok = VaultToken::seal(&key(), edge.as_bytes()).expect("граница лимита");
        assert_eq!(tok.open(&key()).expect("open").as_str(), edge);
        assert!(tok.to_base64url().len() <= MAX_TOKEN_B64_LEN);
    }

    /// Контракт: контейнер несёт ТЕКСТ. Байты, которые не являются UTF-8,
    /// проходят шифрование (мы не проверяем вход на входе), но на `open` дают
    /// `NotUtf8` — fail-closed, без частичного plaintext.
    #[test]
    fn non_utf8_payload_fails_closed_on_open() {
        let bytes = vec![0xFF, 0xFE, 0x00, 0x41];
        let tok = VaultToken::seal(&key(), &bytes).expect("seal сырых байтов");
        assert_eq!(tok.open(&key()).err(), Some(VaultError::NotUtf8));
    }

    #[test]
    fn rejects_noncanonical_and_truncated_strings() {
        assert!(matches!(
            VaultToken::from_base64url("!!!").err(),
            Some(VaultError::Encoding)
        ));
        assert!(VaultToken::from_base64url("").is_err());
        assert!(VaultToken::from_wire(&[0_u8; 40]).is_err());
        // 4 символа = 3 байта контейнера — заведомо короче MIN_WIRE.
        assert!(matches!(
            VaultToken::from_base64url("AAAA").err(),
            Some(VaultError::Truncated)
        ));
        // Паддинг в base64url-no-pad не каноничен.
        let tok = VaultToken::seal(&key(), "Бик".as_bytes()).expect("seal");
        let padded = format!("{}=", tok.to_base64url());
        assert!(matches!(
            VaultToken::from_base64url(&padded).err(),
            Some(VaultError::Encoding | VaultError::NonCanonical)
        ));
    }

    #[test]
    fn debug_never_leaks_key_or_plaintext() {
        let k = SessionKey::new([0x42; KEY_LEN]);
        let d = format!("{k:?}");
        assert!(!d.contains("42"), "ключ засветился в Debug: {d}");
        let tok = VaultToken::seal(&k, "СекретнаяФирма".as_bytes()).expect("seal");
        let td = format!("{tok:?}");
        assert!(!td.contains("Секретная"), "токен засветил оригинал: {td}");
        // Zeroizing-обёртка ключа тоже не печатает содержимое.
        assert!(!format!("{:?}", k.0).contains("42"));
    }

    /// Раздутый LZ4-заголовок отклоняется ДО аллокации.
    #[test]
    fn decompression_bomb_is_rejected_before_alloc() {
        let huge = vec![b'x'; MAX_ORIGINAL_BYTES * 4];
        let block = lz4_flex::block::compress_prepend_size(&huge);
        let (declared, _) = lz4_flex::block::uncompressed_size(&block).expect("заголовок");
        assert!(declared > MAX_ORIGINAL_BYTES);
        assert_eq!(
            lz4_decompress(&block, MlockPolicy::Strict).err(),
            Some(VaultError::Bomb {
                declared,
                max: MAX_ORIGINAL_BYTES
            })
        );
        // Тот же блок — внутри честного контейнера: open обязан отказать.
        let tok = VaultToken::seal(&key(), "Фамилия".as_bytes()).expect("seal");
        let mut buf = Zeroizing::new(block);
        let nonce = XNonce::try_from(&tok.nonce[..]).expect("нонса");
        let tag = key()
            .cipher()
            .encrypt_inout_detached(&nonce, AAD, InOutBuf::from(&mut buf[..]))
            .expect("шифрование большого блока");
        let mut wire = tok.nonce.to_vec();
        wire.extend_from_slice(&buf[..]);
        wire.extend_from_slice(&tag[..]);
        let forged = VaultToken::from_wire(&wire).expect("разбор");
        assert!(matches!(
            forged.open(&key()).err(),
            Some(VaultError::Bomb { .. })
        ));
    }

    /// mlock — инвариант AGENTS, а не украшение: проверяем, что Strict-путь на
    /// этом хосте действительно проходит (`region::lock` не вернул ошибку) и что
    /// залоченный диапазон остаётся запрашиваемым.
    #[test]
    fn locked_buffer_is_actually_locked() {
        let mut buf = LockedBuf::allocate(4096, MlockPolicy::Strict).expect("mlock на dev-хосте");
        buf.as_mut_slice()[..8].copy_from_slice(b"12345678");
        let query = region::query(buf.as_slice().as_ptr());
        assert!(query.is_ok(), "диапазон буфера не виден region::query");
        assert_eq!(buf.len(), 4096);
        assert!(!buf.is_empty());
        // BestEffort обязан отдать буфер даже там, где Strict мог бы отказать;
        // на этом хосте он тоже залочен, и это допустимо.
        let soft = LockedBuf::allocate(64, MlockPolicy::BestEffort).expect("best effort");
        assert_eq!(soft.len(), 64);
    }

    /// Пересчёт бюджета из ТЗ: 124 символа base64url покрывают только
    /// 27-байтовый оригинал, поэтому взят расчётный `MAX_TOKEN_B64_LEN`.
    #[test]
    fn budget_arithmetic_is_self_consistent() {
        assert_eq!(b64url_len(93), 124, "арифметика base64url из ТЗ");
        // 124 символа = 93 Б контейнера = 53 Б LZ4-блока.
        assert_eq!(124 / 4 * 3, 93);
        assert_eq!(93 - NONCE_LEN - TAG_LEN, 53);
        assert!(lz4_worst(27) <= 53, "27 Б входа в 124 символа влезает");
        assert!(lz4_worst(28) > 53, "28 Б входа в 124 символа не влезает");
        // Наш бюджет.
        assert_eq!(MAX_LZ4_BYTES, 164);
        assert_eq!(MAX_WIRE_BYTES, NONCE_LEN + MAX_LZ4_BYTES + TAG_LEN);
        assert_eq!(MAX_TOKEN_B64_LEN, 272);
        assert_eq!(
            MAX_MARKER_BYTES,
            MARKER_PREFIX.len() + MAX_TOKEN_B64_LEN + MARKER_SUFFIX.len()
        );
        // Граница LZ4 не занижена даже на худшем входе.
        let worst = lz4_flex::block::compress_prepend_size(&incompressible(MAX_ORIGINAL_BYTES));
        assert!(worst.len() <= MAX_LZ4_BYTES, "граница LZ4 занижена");
    }
}
