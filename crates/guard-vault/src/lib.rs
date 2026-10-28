#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations, clippy::unwrap_used)]
//! Vault — обратимость маскирования (SPEC §3–§4); шаг 5 реализован.
//!
//! Три режима жизни данных (§3), все в этом крейте:
//!
//! 1. **request-scoped ephemeral** — оригинал живёт только время запроса;
//!    [`token`]: печатная форма → LZ4 → XChaCha20-Poly1305 (detached) в
//!    mlock+zeroize-буфере, наружу — маркер `[[F0#base64url]]`;
//! 2. **session cache** — [`cache`]: кэш оригиналов по `(session, label)`,
//!    sliding idle 15 мин / hard TTL 2 ч, стирание на `Drop` значения;
//! 3. **stateless `vault_token`** — сервер в покое хранит 0 байт пользовательских
//!    данных, всё содержимое зашифровано внутри токена.
//!
//! Обратно в текст оригинал возвращает [`rewriter`]: потоковый побайтовый FSM,
//! который не режет UTF-8 и переживает нарезку маркера по чанкам (SPEC §8;
//! стресс-тест с нарезкой по 1–2 байта — в атоме B).
//!
//! Морфология ФИО — [`morph`]: суффиксальная таблица как данные, 119 правил и 80
//! исключений через `include_str!`. Решение #46 закрыто веткой (а): своя таблица,
//! а `petrovich-core` — decliner за фичей `decliner`. TODO про `rsmorphy` из
//! скелета удалён: крейт мёртв (2018), первичка промерена, замена выбрана
//! (`docs/dep-verify-crates.md` §12).
//!
//! # Чем этот файл является
//!
//! Тонкой прокладкой между четырьмя модулями — [`VaultEngine`]. HTTP, мандатов
//! вызывающего и обратного aho-corasick здесь нет: это шаг 6 (`guard-daemon`).
//! Политик удержания — кэш, и только он держит оригиналы. Сверх кэша живёт
//! реверс-индекс целостности разворота: в нём ключёвые отпечатки форм, а не
//! `ПДн` (см. [`VaultEngine::restoration_mismatches`]).

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use guard_types::SecretString;
use sha2::{Digest as _, Sha256};

pub mod cache;
pub mod morph;
pub mod pool;
pub mod rewriter;
pub mod token;

pub use cache::{Limits, SecretRef, SessionStore, StoreError, StoreKey};
pub use morph::{Case, Gender, MorphTable, NameType, SpanParse};
pub use rewriter::{BodyKind, DynStreamRewriter, FnResolver, Grammar, Resolution, StreamRewriter};
pub use token::{MlockPolicy, SessionKey, VaultError, VaultToken};

/// Ошибка выдачи токена: одна из двух причин, обе отказные.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// Токен не seal-нулся: длина оригинала, отказ генератора энтропии или `mlock`
    /// при [`MlockPolicy::Strict`].
    #[error(transparent)]
    Token(#[from] VaultError),
    /// Оригинал не попал в кэш: пустой или больше `Limits::max_value_bytes`.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Результат прогона байтов через переписыватель ([`VaultEngine::rewrite_stream`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOutcome {
    /// Байты выдачи (оригиналы уже подменены).
    pub bytes: Vec<u8>,
    /// Сколько маркеров подменено.
    pub substituted: usize,
    /// Сколько маркеров не удалось разрешить — они прошли в выдачу **дословно**.
    /// Нерезолвнутый `[[F0#…]]` = чужой или повреждённый токен: мы не выдумываем
    /// содержимое и не теряем текст; решение «валить ли ответ» принимает шаг 6.
    pub unresolved: usize,
    /// На хвосте остался незакрытый маркер — поток надо продолжать.
    pub incomplete: bool,
}

/// Инкрементальный разворот маркеров, см. [`VaultEngine::stream`].
///
/// Обёртка над `StreamRewriter` с вытертым типом резолвера: вызывающему шага 7c
/// (SSE-релай в `guard-daemon`) нужно держать машину в собственном поле, а имя
/// типа замыкания, замкнутого на движок, извне не выразить. Состояние — ровно
/// одно окно look-ahead и счётчик; второго кэша оригиналов здесь нет.
pub struct VaultStream<'a> {
    rw: rewriter::DynStreamRewriter<'a>,
    unresolved: std::rc::Rc<Cell<usize>>,
}

impl core::fmt::Debug for VaultStream<'_> {
    /// Проксировать метаданные автомата; резолвер с оригиналами не печатается
    /// (`Debug` `StreamRewriter` это уже гарантирует).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultStream")
            .field("rewriter", &self.rw)
            .field("unresolved", &self.unresolved.get())
            .finish()
    }
}

impl VaultStream<'_> {
    /// Скормить кусок ответа; всё распознанное и дословное пишется в `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> rewriter::Push {
        self.rw.push(chunk, out)
    }

    /// Конец потока: несъевшийся остаток отдаётся дословно.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> rewriter::Finish {
        self.rw.finish(out)
    }

    /// Весь вход за один вызов — путь без стрима (тот же автомат, что у
    /// [`VaultEngine::rewrite_stream`]).
    pub fn run_to_end(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        self.rw.run_to_end(input)
    }

    /// Сколько маркеров подменено суммарно.
    #[must_use]
    pub fn substituted(&self) -> usize {
        self.rw.substituted()
    }

    /// Сколько маркеров прошло дословно как нерезолвленные.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.unresolved.get()
    }

    /// Есть ли на хвосте незакрытый маркер.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        self.rw.is_incomplete()
    }
}

/// Стирание типа резолвера: поле [`VaultStream`] хочет `DynStreamRewriter`,
/// а имени типа замыкания, замкнутого на `&self`, снаружи не выразить.
fn boxed<'a>(f: impl FnMut(&[u8]) -> Resolution + 'a) -> Box<dyn FnMut(&[u8]) -> Resolution + 'a> {
    Box::new(f)
}

/// Синтетический суррогат вместо `[PERSON_n]` (SPEC §4, обратимая подмена).
///
/// В отладочный вывод попадает только выдуманное имя: леммы оригинала здесь нет
/// намеренно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surrogat {
    /// Форма суррогата в том же падеже, что и исходное слово.
    pub form: String,
    /// Лемма суррогата — для регистрации обратного соответствия шагом 6.
    pub lemma: &'static str,
    /// Тип токена, подобранный под исходное слово.
    pub ty: NameType,
    /// Падеж исходного слова.
    pub case: Case,
    /// Род исходного слова.
    pub gender: Gender,
}

// Пул лемм-суррогатов — внешний артефакт `data/morph/surrogates.tsv`, модуль
// [`pool`]: там же промер коллизий до/после (#60), чем защищён файл и почему
// старые «Пимен/Назар/Захар/Куприян/Селиван» из константы не годились в пул.
// Здесь остаются только правила выбора слота.

/// Префикс метки, под которой движок кэширует обратное соответствие суррогата.
///
/// Публично: форма ключа — часть контракта хранилища (её печатает README
/// §«Хранилище» и ею же говорит промер `pool_probe -- integrity`, которому нужно
/// снять запись так, как её снимет `idle`-лимит).
pub const SRG_PREFIX: &str = "SRG#";

/// Отказ выдачи суррогатной формы.
///
/// Отдельно от [`VaultError`]: тот описывает криптографию токена, а здесь —
/// политика слота в кэше сессии.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SurrogatError {
    /// Форма уже выдана ДРУГОМУ оригиналу этой сессии. First-writer-wins:
    /// владеющий слотом не смещается, второй просит — отказ (B2/P8).
    #[error("суррогат «{form}» в этой сессии уже выдан другому оригиналу")]
    Collision {
        /// Занятая форма. Это выдуманное имя, не `ПДн`, — его можно в сообщение.
        form: String,
    },
    /// Хранилище отказало по своей причине (`TooBig` / `Empty`).
    #[error("хранилище сессий отказало: {0}")]
    Store(#[from] StoreError),
}

/// Исход разворота одной суррогатной формы ([`VaultEngine::try_restore`]).
///
/// `PartialEq` не выводится: `SecretRef` намеренно не сравнивается (секреты не
/// сверяют знаком равенства), а сравнивать исходы «по содержимому» негде.
#[derive(Debug, Clone)]
pub enum Restore {
    /// Оригинал найден, его отпечаток совпал со свидетельством выдачи.
    Found(SecretRef),
    /// Записи нет: форма этой сессии не выдавалась, или её снял TTL / teardown.
    Absent,
    /// Запись есть, но её отпечаток не совпал со свидетельством выдачи.
    /// Разворот запрещён: отдать чужое имя дороже, чем оставить форму в тексте.
    Diverged,
}

/// Длина отпечатка в реверс-индексе целостности: усечённый ключёвый хэш.
const ISSUE_TAG_LEN: usize = 8;

/// Отпечаток оригинала, подставленного в форму.
type IssueTag = [u8; ISSUE_TAG_LEN];

/// Остаточный риск — коллизия самого отпечатка: 8 байт, то есть вероятность
/// молчаливой подмены на одно событие перенятого слота ≈ 2⁻⁶⁴. Полный хэш в
/// индексе стоил бы вдвое больше памяти и ничего не добавил бы против перебора
/// ключа сессии, который и так нужен, чтобы форму вообще подобрать.
///
/// Реверс-индекс целостности разворота: `(сессия, форма)` → отпечаток того
/// оригинала, который МЫ в эту форму подставили.
///
/// Нужен потому, что владение слотом в [`SessionStore`] живёт ровно столько,
/// сколько запись: скользящий `idle` 15 мин (SPEC §3 п.2) и evict по байтовому
/// бюджету снимают её, а у клиента остаётся текст с формой в руках. Проверка
/// «слота нет» на голом кэше означает «слот свободен», тогда как это «свидетельство
/// потеряно»: следующая фамилия, упавшая в ту же корзину пула, получает чужую
/// форму, а разворот молча отдаёт не то, что подставлялось. Индекс переживает
/// снятие записи, потому что держит не `ПДн`, а 8-байтный отпечаток под ключом
/// сессии: прямого обращения нет, словарную проверку «было ли в этой сессии
/// имя X» делает только тот, у кого уже есть ключ сессии.
#[derive(Default)]
struct Integrity {
    /// Что мы подставляли: `(сессия, форма)` → отпечаток оригинала.
    issued: HashMap<(String, String), IssueTag>,
    /// Расхождения на развороте по живым сессиям.
    mismatches: HashMap<String, u64>,
    /// Сумма расхождений уже снятых сессий: метрика обязана пережить teardown,
    /// иначе счётчик исчезает вместе с проблемой.
    retired: u64,
}

impl std::fmt::Debug for Integrity {
    /// Отпечатки в `Debug` не печатаются: сами по себе они не `ПДн`, но это
    /// ключёвый MAC, а `Debug` имеет привычку уезжать в логи.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Integrity")
            .field("issued", &self.issued.len())
            .field("mismatched_sessions", &self.mismatches.len())
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

/// Прокладка «токен + кэш + переписыватель + морфология».
///
/// `Debug` безопасен: [`SessionKey`] печатается как `SessionKey("[REDACTED]")`,
/// [`SessionStore`] печатает значения как `[REDACTED]` (атом C).
#[derive(Debug)]
pub struct VaultEngine {
    store: SessionStore,
    key: SessionKey,
    /// Реверс-индекс «форма → что в неё подставили» (см. [`Integrity`]).
    integrity: Mutex<Integrity>,
}

impl VaultEngine {
    /// Собирает движок из ключа сессии и лимитов кэша.
    #[must_use]
    pub fn new(key: SessionKey, limits: Limits) -> Self {
        Self {
            store: SessionStore::new(limits),
            key,
            integrity: Mutex::new(Integrity::default()),
        }
    }

    /// Кэш оригиналов: метрики, инвалидация по закрытии сессии.
    #[must_use]
    pub fn store(&self) -> &SessionStore {
        &self.store
    }

    /// Ключ сессии — чтобы вызывающий мог seal'ить и вне движка.
    #[must_use]
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Шифрует оригинал и возвращает готовый маркер `[[F0#…]]`.
    ///
    /// Одновременно кладёт оригинал в кэш под `(session, label)` — второй путь
    /// восстановления, не требующий токена ([`Grammar::LABEL`]). Порядок
    /// намеренный: сначала seal, потом кэш, чтобы при отказе шифрования в кэше
    /// ничего не осело.
    ///
    /// # Errors
    ///
    /// [`IssueError::Token`] — оригинал длиннее `MAX_ORIGINAL_BYTES`, пуст, либо
    /// отказал генератор энтропии / `mlock` при [`MlockPolicy::Strict`];
    /// [`IssueError::Store`] — оригинал больше `Limits::max_value_bytes`
    /// (пустой отбивает ещё и более ранний слой токена).
    pub fn issue_token(
        &self,
        session: &str,
        label: &str,
        original: &str,
    ) -> Result<String, IssueError> {
        let sealed = VaultToken::seal(&self.key, original.as_bytes())?;
        self.store
            .insert(&StoreKey::new(session, label), SecretString::new(original))?;
        Ok(sealed.to_marker())
    }

    /// Прогоняет байты ответа через [`StreamRewriter`], подменяя маркеры.
    ///
    /// Для [`BodyKind::Base64Url`] тело декшифруется ключом движка, для
    /// [`BodyKind::Label`] оригинал берётся из кэша по `(session, label)`.
    /// Нерезолвнутый маркер проходит дословно и учтён в
    /// [`StreamOutcome::unresolved`].
    ///
    /// Не-потоковый случай: весь вход сразу. Для стрима (SSE-прокси, шаг 7c)
    /// тот же резолвер и тот же счётчик даёт [`Self::stream`]; двух мест, где
    /// по-своему объясняется «что такое нерезолвленный маркер», быть не может,
    /// поэтому этот метод собран из того же резолвера.
    #[must_use]
    pub fn rewrite_stream(&self, session: &str, grammar: Grammar, input: &[u8]) -> StreamOutcome {
        let mut s = self.stream(session.to_owned(), grammar);
        let (bytes, incomplete) = s.run_to_end(input);
        StreamOutcome {
            bytes,
            substituted: s.substituted(),
            unresolved: s.unresolved(),
            incomplete,
        }
    }

    /// Инкрементальный разворот маркеров: машина состояния плюс счётчик отказов.
    ///
    /// Отличие от [`Self::rewrite_stream`] только в форме вызова — байты
    /// подкладываются кусками произвольной нарезки, а машина сама держит
    /// look-ahead ([`Grammar::window`]) и оборванную UTF-8-последовательность на
    /// границе куска. Это то, что нужно SSE-релая: метку может принести нарезанную
    /// на два `data:`-события, и наивная подмена по чанку её либо пропустит, либо
    /// съест (SPEC §8, промер шага 7c — тесты `sse::tests` в `guard-daemon`).
    /// `session` — владелец строки: машина живёт дольше вызова, поэтому слот
    /// ей передаётся в собственность, а не взят на заём.
    ///
    /// Счётчик [`VaultStream::unresolved`] общий для всех вызовов одной машины:
    /// нерезолвленный маркер — не ошибка машины, но скрыть его нельзя
    /// (AGENTS: подмена причины отказа = fail-open в диагностике).
    #[must_use]
    pub fn stream(&self, session: String, grammar: Grammar) -> VaultStream<'_> {
        let unresolved = std::rc::Rc::new(Cell::new(0_usize));
        let counter = std::rc::Rc::clone(&unresolved);
        // Боксование явное: имя типа замыкания, замкнутого на движок, извне не
        // выразить, а поле `VaultStream` хочет `DynStreamRewriter`.
        let rw = StreamRewriter::new(
            grammar,
            FnResolver(boxed(move |body: &[u8]| -> Resolution {
                let Ok(text) = std::str::from_utf8(body) else {
                    counter.set(counter.get() + 1);
                    return Resolution::Unknown;
                };
                let found = match grammar.body {
                    BodyKind::Base64Url => VaultToken::from_base64url(text)
                        .and_then(|t| t.open(&self.key))
                        .map(|plain| plain.as_bytes().to_vec())
                        .ok(),
                    BodyKind::Label => self
                        .store
                        .get(&StoreKey::new(&session, text))
                        .map(|r| r.as_str().as_bytes().to_vec()),
                };
                if let Some(bytes) = found {
                    Resolution::Substitute(bytes)
                } else {
                    counter.set(counter.get() + 1);
                    Resolution::Unknown
                }
            })),
        );
        VaultStream { rw, unresolved }
    }

    /// Подбирает синтетическое имя того же рода, падежа и типа ФИО-токена.
    ///
    /// `Ok(None)` — слово не разбирается таблицу с **одним** родом: этот порт
    /// берёт род из колонки `genders` правила, а она для именных форм `f,m`
    /// (промер 0/56 в доке [`morph`]), так что род обязан прийти извне —
    /// [`Self::surrogat_for_gender`] принимает его явно.
    ///
    /// `Err(`[`SurrogatError::Collision`]`)` — выбранная форма уже принадлежит
    /// другому оригиналу этой же сессии (B2/P8), см. [`Self::pick_surrogat`].
    ///
    /// # Errors
    ///
    /// [`SurrogatError::Collision`] — слот занят другим оригиналом;
    /// [`SurrogatError::Store`] — отказ хранилища сессий.
    pub fn surrogat_for(
        &self,
        session: &str,
        word: &str,
    ) -> Result<Option<Surrogat>, SurrogatError> {
        let Some(table) = MorphTable::shipped() else {
            return Ok(None);
        };
        let cands = table.cands_any(word);
        let mut cases: Vec<Case> = cands.iter().map(|c| c.case).collect();
        cases.sort_unstable();
        cases.dedup();
        if cases.len() != 1 {
            return Ok(None);
        }
        let case = cases[0];
        let mask = cands
            .iter()
            .filter(|c| c.case == case)
            .fold(0_u8, |acc, c| acc | c.genders);
        let Some(gender) = morph::sole_gender(mask) else {
            return Ok(None);
        };
        let Some(ty) = NameType::ORDER
            .iter()
            .find(|t| cands.iter().any(|c| &c.ty == *t && c.case == case))
            .copied()
        else {
            return Ok(None);
        };
        self.surrogat_for_gender(session, word, case, gender, ty)
    }

    /// Чистый выбор суррогата: пул и морфология, хранилище не тронуто.
    ///
    /// Нужен вызывающему, чтобы проверить слот **до первой подмены**:
    /// [`Self::surrogat_for_gender`] пишет сразу, и без чистого пика коллизия
    /// всплывала бы уже после уничтожения прежней связи.
    #[must_use]
    pub fn pick_surrogat(word: &str, want: Case, gender: Gender, ty: NameType) -> Option<Surrogat> {
        Self::pick_surrogat_from(word, want, gender, ty, pool::lemmas(ty, gender))
    }

    /// То же, что [`Self::pick_surrogat`], но из заданной корзины лемм.
    ///
    /// Нужны двум вещам: промеру `examples/pool_probe.rs` (считать профиль
    /// коллизий на пуле произвольного размера — в том числе на историческом
    /// «4 на корзину», чтобы цифру «до» не выдумывать) и тесту дири-голо,
    /// который не должен зависеть от текущего размера артефакта.
    #[must_use]
    pub fn pick_surrogat_from(
        word: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
        pool: &[&'static str],
    ) -> Option<Surrogat> {
        let table = MorphTable::shipped()?;
        if pool.is_empty() {
            return None;
        }
        // Ключ выбора — лемма, а не форма: «Ушакова» и «ушаковой» обязаны дать
        // одного и того же суррогата (иначе обратимость рвётся по падежам).
        let pick_key = Self::pick_lemma(&table.cands_any(word), word, want, gender, ty);
        let lemma = pool[pick_index(&pick_key, pool.len())];
        let form = table.inflect_typed(lemma, want, gender, ty)?;
        Some(Surrogat {
            form,
            lemma,
            ty,
            case: want,
            gender,
        })
    }

    /// Лемма-ключ суррогата: `(rod, padezh, tip)` с приоритетом точного рода.
    ///
    /// Кандидат для ключа ищется по всем трём осям, а не по двум. На омонимах
    /// родительного (`«Ушакова»` = и женский `Nom`, и мужской `Gen`; первичка
    /// `cands` 28.10, `ty=Surname`: `Nom g=f,m lemma=УШАКОВА`,
    /// `Gen g=m lemma=УШАКОВ`, `Acc g=m lemma=УШАКОВ`) выбор по `(case, ty)`
    /// брал первого: запрос `Gen`+`Fem` («нет кого? Ушакова») получал мужскую
    /// лемму `УШАКОВ`, а `Nom`+`Fem` того же человека — `УШАКОВА`. Одна женщина
    /// разъезжалась на два слота (#63).
    ///
    /// Род — ПЕРВАЯ ось, падеж — вторая (формулировка issue: «ключ = (rod,
    /// padezh, tip) с приоритетом точного рода»). Три прослойки, все Necessary
    /// (промер мут-матрицей, PR #63):
    ///
    /// 1. точный род + нужный падеж;
    /// 2. точный род, любой падеж (в том же типе токена) — суть чина: у
    ///    омонима «Ушакова» женского кандидата с `case=Gen` в таблице НЕТ
    ///    (`Gen` несёт только маску `m`), без этой прослойки Fem+Gen падает
    ///    на мужскую `УШАКОВ` = дефект #63. Муты: «прослойка 2 вырезана» =
    ///    красные оба зуба; «прослойки 1 и 2 переставлены» = красные оба
    ///    зуба И соседний `surrogate_is_deterministic_and_varies_by_word`
    ///    (мужской Gen уезжает на Nom-омоним, промер 28.10);
    /// 3. нужный падеж без сверки рода = прежнее поведение, держит выдачу на
    ///    словах, где запрошенного рода в кандидатах нет вовсе (эквивалентный
    ///    мут «прослойка 3 вырезана» = зелёный на ФИО-поверхностях: род есть
    ///    у каждого кандидата нашего пула; прослойка оставлена как явный
    ///    шаг, и это задокументировано, а не промолчано).
    ///
    /// Прослойка «омоним с маской `f,m`» (оба рода, отдельным приоритетом) НЕ
    /// введена, и это промер, а не экономия: на всех поверхностях
    /// `surrogates.tsv` (× 6 падежей × 2 рода × 3 типа) она недостижима —
    /// `f,m` в таблице живёт только на `Nom`, а прослойка 1 берёт `Nom f,m`
    /// по роду из маски раньше. Род из маски `f,m` при этом работает:
    /// `genders & bit != 0` истинен и для `f,m`, поэтому `Nom`+`Fem` на
    /// «Ушакова» решается прослойкой 1 (клетка `key("Ушакова", Nom, Fem)`).
    ///
    /// Фоллбэк без кандидата — нормализация слова; она сохранена дословно
    /// (мут «фоллбэк вырезан» = красные зубы `pick_lemma_…` и `b2_…`:
    /// незнакомое слово с ключом `""` ломало бы выдачу).
    fn pick_lemma(
        cands: &[morph::Candidate<'_>],
        word: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
    ) -> String {
        let bit = gender.bit();
        let same_ty = |c: &morph::Candidate<'_>| c.ty == ty;
        let keyed = |c: &morph::Candidate<'_>| same_ty(c) && c.case == want;
        cands
            .iter()
            .find(|c| keyed(c) && c.genders & bit != 0)
            .or_else(|| cands.iter().find(|c| same_ty(c) && c.genders & bit != 0))
            .or_else(|| cands.iter().find(|c| keyed(c)))
            .map_or_else(|| morph::norm(word), |c| c.lemma.clone())
    }

    /// Один ли это человек в двух написаниях: сечение множеств лемм непустое.
    ///
    /// Вынесено из ветки отказа, потому что сравнение нужно и там, где индекс уже
    /// подтвердил владение слотом. Без таблицы морфологии отличить одного от двоих
    /// нельзя, и решаем в пользу отказа: угадать владельца — тихая подмена.
    fn is_same_owner_word(prev: &str, word: &str) -> bool {
        MorphTable::shipped()
            .is_some_and(|tb| !Self::lemma_set(tb, prev).is_disjoint(&Self::lemma_set(tb, word)))
    }

    /// Множество лемм, формой которых слово может быть. Пустое — не разобралось,
    /// тогда подставляем нормализацию, чтобы сравнение осталось честным.
    ///
    /// Именно множество, а не «первая лемма»: таблица для «Ушакова» даёт первым
    /// кандидатом `УШАКОВА`, а для «ушаковой» — `УШАКОВОЙ`, и сравнение по
    /// первому кандидату развело бы одного человека на двоих (промер 20.10:
    /// `Collision` на повторе того же слова в другом падеже).
    fn lemma_set(table: &MorphTable, word: &str) -> std::collections::BTreeSet<String> {
        let mut set: std::collections::BTreeSet<String> =
            table.cands_any(word).into_iter().map(|c| c.lemma).collect();
        if set.is_empty() {
            set = table
                .cands_any(&Self::upper_first(word))
                .into_iter()
                .map(|c| c.lemma)
                .collect();
        }
        if set.is_empty() {
            set.insert(morph::norm(word));
        }
        set
    }

    /// Первая буква заглавная — только для добора по индексу таблицы.
    fn upper_first(word: &str) -> String {
        let mut out = word.to_owned();
        if let Some(first) = word.chars().next() {
            out.replace_range(..first.len_utf8(), &first.to_uppercase().to_string());
        }
        out
    }

    /// То же, что [`Self::surrogat_for`], но род, падеж и тип заданы явно.
    ///
    /// First-writer-wins (B2/P8): слот принадлежит первому оригиналу до конца
    /// сессии. Тот же оригинал повторно — идемпотентно та же форма; ДРУГОЙ
    /// оригинал на занятый слот — [`SurrogatError::Collision`]. Прежняя
    /// реализация писала `let _ = store.insert(…)`: результат вставки
    /// отбрасывался, слот доставался последнему писателю, и `deanonymize`
    /// возвращал чужое имя как настоящие `ПДн` (промер: 248 пар из 351 в
    /// golden-v1 делят хотя бы один слот; 347 — совпадений по позициям).
    /// # Errors
    ///
    /// [`SurrogatError::Collision`] — слот формы занят ДРУГИМ оригиналом этой
    /// сессии; [`SurrogatError::Store`] — отказ хранилища. При отказе ничего не
    /// перезаписывается: первый владелец остаётся владельцем.
    pub fn surrogat_for_gender(
        &self,
        session: &str,
        word: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
    ) -> Result<Option<Surrogat>, SurrogatError> {
        self.surrogat_for_gender_in(session, word, want, gender, ty, pool::lemmas(ty, gender))
    }

    /// Ключёвый отпечаток оригинала для данной `(сессия, форма)`.
    ///
    /// Отпечаток берётся от [`Self::owner_key`] (нормализованной поверхности), а
    /// не от сырой: два регистра одного человека — один свидетель, иначе тег
    /// читает разницу регистра как смену владельца и ложно отказывает (#65/#72;
    /// до промера первички это считали багом `lemma_set`).
    ///
    /// Конвертный SHA-256 (ключ в начале И в конце), усечённый до 8 байт. Не
    /// HMAC: узла `hmac` в дереве нет, а требование здесь одно — невозможность
    /// обратного обращения и словарной проверки без ключа сессии; length-extension
    /// SHA-256 закрыт хвостовым ключом. Отпечаток — не `ПДн`: по нему имя не
    /// восстановить, а длина оригинала из него не читается.
    fn issue_tag(&self, session: &str, form: &str, original: &str) -> IssueTag {
        let key = self.key.key_bytes();
        let mut h = Sha256::new();
        h.update(key);
        h.update(session.as_bytes());
        h.update(form.as_bytes());
        h.update(Self::owner_key(original).as_bytes());
        h.update(key);
        let digest = h.finalize();
        let mut tag = [0_u8; ISSUE_TAG_LEN];
        tag.copy_from_slice(&digest[..ISSUE_TAG_LEN]);
        tag
    }

    /// Ключ опознавания владельца: поверхность токена, приведённая к
    /// эквивалентности `morph::norm` (верхний регистр и `Ё → Е`).
    ///
    /// Единая функция для двух мест, которые раньше решали «это тот же
    /// человек?» разными ключами и расходились ровно на регистре (#65/#72):
    /// движок ([`Self::surrogat_for_gender_in`]) сравнивает леммы таблицы, а
    /// леммы `MorphTable::cands` строятся из `norm(word)` — то есть движок по
    /// построению нейтрален к регистру уже сейчас (промер: `is_same_owner_word
    /// ("Ушакова", "ушакова") = true`); а тег реверс-индекса и пред-проверка
    /// батча (`PendingForms::push` в демоне) ключевали сырой поверхностью, и
    /// «Кира»/«кира» читались как два человека.
    ///
    /// Нормализация **не склеивает разных людей**: она приводит регистр, а лемма
    /// «Ушакова» ≠ лемма «Жукова» и после приведения — истинная коллизия
    /// остаётся отказом (регресс `true_collision_survives_owner_key_normalization`).
    ///
    /// Приведение **поверхностное, не деструктивное**: `to_uppercase` + `Ё→Е`
    /// (то же отношение эквивалентности, что `morph::norm`), а не сам `norm` —
    /// деструктивная норма осела бы в witness-теге, и разворот вернул бы
    /// заглавный «УШАКОВА» вместо написание, которое демон подставлял в текст.
    /// Тег обязан быть свёркой по поверхности, сохраняющей написание.
    #[must_use]
    pub fn owner_key(word: &str) -> String {
        word.chars()
            .flat_map(char::to_uppercase)
            .map(|c| if c == 'Ё' { 'Е' } else { c })
            .collect()
    }

    /// Ключом реверс-индекса — `(сессия, форма)`.
    fn form_key(session: &str, form: &str) -> (String, String) {
        (session.to_owned(), form.to_owned())
    }

    /// То же, но с подставной корзиной лемм — нужно тесту дири-голо, чтобы не
    /// зависеть от размера артефакта (иначе расширение пула превратило бы тест
    /// в гонку за длиной списка).
    pub(crate) fn surrogat_for_gender_in(
        &self,
        session: &str,
        word: &str,
        want: Case,
        gender: Gender,
        ty: NameType,
        bucket: &[&'static str],
    ) -> Result<Option<Surrogat>, SurrogatError> {
        let Some(srg) = Self::pick_surrogat_from(word, want, gender, ty, bucket) else {
            return Ok(None);
        };
        let key = StoreKey::new(session, &format!("{SRG_PREFIX}{}", srg.form));
        let form_key = Self::form_key(session, &srg.form);
        let tag = self.issue_tag(session, &srg.form, word);
        // Вся цепочка «индекс → кэш → запись в кэш → запись в индекс» под одним
        // замком. Короткая критическая секция здесь была бы дырой, а не
        // добродетелью: два параллельных запроса в одной сессии на коллизирующей
        // паре успевали пройти проверку до записи соперника, форма выдавалась
        // дважды, индекс молча перезаписывался вторым владельцем, а
        // `restoration_mismatches` показывал ноль (промер ревьюера #70: 26 двойных
        // выдач из 300 раундов, в развороте чужое имя у обоих). Цена — серийная
        // выдача на процесс; для loopback-демона с операцией в микросекунды это ноль.
        let mut gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(seen) = gi.issued.get(&form_key).copied() {
            if seen != tag {
                // Форма уже светилась с ДРУГИМ оригиналом. Молча занять её —
                // значит выдать клиенту разворот не тем именем, что подставлялось;
                // отказ тут дешевле, чем там, где его не поймут (B2/P8).
                //
                // Тег свёрнут по [`Self::owner_key`], поэтому «Ушакова» и
                // «ушакова» сюда не попадают: один владелец — один свидетель,
                // ложного отказа на регистре больше нет (#65/#72; до промера
                // первички это называли регистрозависимостью `lemma_set`, а
                // отказ рождался именно здесь).
                return Err(SurrogatError::Collision { form: srg.form });
            }
            // Тот же оригинал (с точностью до регистра) в той же форме: слот
            // обязан жить, иначе разворот прежнего текста даст пустоту. Запись НЕ
            // перезаписываем поверхностью запроса: один слот — одна запись, и
            // она принадлежит первому написанию (first-writer-wins, B2/P8).
            // Свидетель остаётся тегом владельца; `norm`-тег от обеих
            // поверхностей одинаков, поэтому разворот жив, а `deanonymize`
            // разворачивает ВСЕ вхождения формы в написание владельца (#65/#72).
            if self.store.get(&key).is_none() {
                self.store
                    .insert(&key, SecretString::new(word.to_owned()))?;
            }
            return Ok(Some(srg));
        }
        if let Some(prev) = self.store.get(&key) {
            // Замок держится с начала функции: проверка индекса, чтение стора
            // и запись — одна атомарная цепочка, между её шагами никто не успевает
            // пересоздать слот.
            // Записи в индексе нет, а слот занят: запись сюда попала до индекса
            // (перезапуск демона) или из `store()` напрямую. Владелец опознаётся
            // по ПЕРЕСЕЧЕНИЮ МНОЖЕСТВ ЛЕММ, а не по поверхности и не по лемме
            // пула: «Ушакова» и «ушаковой» — один человек в двух падежах, обязан
            // получить ту же форму (иначе обратимость рвётся по падежам);
            // «Ушакова» и «Жукова» — два человека в одном слоте, и это отказ.
            // Лемму берём по любому кандидату (не по запрошенному падежу): у
            // слова в творительном падеже кандидат с `case=Gen` не находится, и
            // сравнение разбилось бы на регистре, а не на человеке. Пул-лемму
            // сравнивать нельзя: у коллизии она у обоих одна и та же.
            if !Self::is_same_owner_word(prev.as_str(), word)
                && Self::owner_key(prev.as_str()) != Self::owner_key(word)
            {
                return Err(SurrogatError::Collision { form: srg.form });
            }
            // Тег берётся от ВЛАДЕЛЬЦА записи, а не от текущего запроса: «Ушакова»
            // и «ушаковой» — один человек, а в кэше лежит surface прошлой выдачи.
            // Записать тег запроса значило бы на развороте посчитать ложное
            // расхождение там, где всё честно (R5 ревью #70).
            gi.issued
                .insert(form_key, self.issue_tag(session, &srg.form, prev.as_str()));
            return Ok(Some(srg));
        }
        self.store
            .insert(&key, SecretString::new(word.to_owned()))?;
        gi.issued.insert(form_key, tag);
        Ok(Some(srg))
    }

    /// Оригинальное слово по суррогатной форме (обратный ход подмены).
    ///
    /// Разворот обязан вернуть ровно то, что было подставлено. Если индекс
    /// помнит в этой форме другое имя, запись в кэше сменила владельца (slot
    /// retake после evict — см. [`Integrity`]), и молча отдавать её нельзя:
    /// клиент получил бы чужие `ПДн` на месте своих. Такой разворот считается
    /// расхождением целостности ([`VaultEngine::restoration_mismatches`]) и
    /// отдаётся как `None` — то есть как неразвёрнутый маркер, а не как чужое имя.
    #[must_use]
    pub fn original_of_surrogat(&self, session: &str, form: &str) -> Option<SecretRef> {
        match self.try_restore(session, form) {
            Restore::Found(v) => Some(v),
            Restore::Absent | Restore::Diverged => None,
        }
    }

    /// То же, что [`Self::original_of_surrogat`], но исход различим: «записи нет»
    /// и «запись расходится со свидетельством» — для клиента разные события.
    ///
    /// Первое — косметика истёкшей или снятой сессии: форма остаётся в тексте, и
    /// это не `ПДн`. Второе — событие целостности: прокси обязано показать его
    /// числом (#60 п.3, R7 ревью #70), иначе молчание выдаёт отказ разворота за
    /// успешный разворот.
    #[must_use]
    pub fn try_restore(&self, session: &str, form: &str) -> Restore {
        let form_key = Self::form_key(session, form);
        let mut gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Кэш читается под тем же замком, что и индекс: иначе параллельная выдача
        // влезает между двумя чтениями, и пара «значение / тег» приходит из двух
        // разных миров — ложное расхождение на ровном месте.
        let Some(found) = self
            .store
            .get(&StoreKey::new(session, &format!("{SRG_PREFIX}{form}")))
        else {
            return Restore::Absent;
        };
        // Свидетель обязателен: разворачиваем только то, за что ручаемся. Запись
        // без строки индекса — это либо состояние гонки teardown и выдачи (её
        // закрывает порядок захвата замка выше), либо писатель в обход движка; в
        // обоих случаях мы не знаем, тот ли это оригинал, что был выдан, и
        // выдавать его наружу нельзя. Отказ здесь — не событие целостности (нет
        // с чем сравнить), поэтому `Absent`, а не `Diverged`: счётчик `unrestored
        // _mismatch` остаётся метрикой именно расхождений.
        let Some(seen) = gi.issued.get(&form_key).copied() else {
            return Restore::Absent;
        };
        if seen != self.issue_tag(session, form, found.as_str()) {
            *gi.mismatches.entry(session.to_owned()).or_insert(0) += 1;
            return Restore::Diverged;
        }
        Restore::Found(found)
    }

    /// Сколько разворотов отказало из-за расхождения с реверс-индексом.
    ///
    /// Процессный счётчик, переживает teardown сессий. Вне отладочного режима
    /// виден в `GET /health` объектом `vault` (поля `unrestored_mismatch`).
    #[must_use]
    pub fn restoration_mismatches(&self) -> u64 {
        let gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gi.retired + gi.mismatches.values().sum::<u64>()
    }

    /// То же, но по одной сессии: чтобы отказ разворота был атрибутируем, а не
    /// «где-то в процессе».
    #[must_use]
    pub fn restoration_mismatches_for(&self, session: &str) -> u64 {
        self.integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mismatches
            .get(session)
            .copied()
            .unwrap_or(0)
    }

    /// Сбрасывает всё, что накоплено сессией (конец диалога, выход из запроса).
    pub fn invalidate_session(&self, session: &str) -> u64 {
        // Замок берётся ДО снятия записей стора, а не после. Иначе выдача,
        // вклинившаяся между `store.invalidate_session` и чисткой индекса,
        // застаёт строку индекса живой, записи мёртвой — и возвращает в стор
        // оригинал для сессии, индекс которой уже вычищен: оригинал переживает
        // удаление сессии без свидетеля, а разворот потом молча его находит
        // (промер барьерного теста: 1 нарушение инварианта из 2000 раундов).
        // Цена — teardown сериализован с выдачей; для стора в десятки записей
        // это микросекунды.
        let mut gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let removed = self.store.invalidate_session(session);
        gi.issued.retain(|(s, _), _| s != session);
        if let Some(n) = gi.mismatches.remove(session) {
            gi.retired += n;
        }
        removed
    }

    /// Тестовый наблюдатель: есть ли у формы строка в индексе целостности.
    ///
    /// `#[cfg(test)]`: индекс — внутреннее состояние, продуктовый код не имеет
    /// права на него опираться, а тесту нужно отличать «записи нет» от «запись
    /// есть, а свидетеля уже сняли».
    #[cfg(test)]
    #[must_use]
    pub fn issued_witness(&self, session: &str, form: &str) -> bool {
        self.integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .issued
            .contains_key(&(session.to_owned(), form.to_owned()))
    }
}

/// Детерминированный выбор из пула: FNV-1a по нормализованному слову.
///
/// `DefaultHasher` из `std` не гарантирует стабильность между релизами
/// компилятора, а суррогат обязан быть одним и тем же для одного и того же
/// оригинала в пределах бинаря — отсюда свой хэш без зависимостей.
fn pick_index(normalized: &str, len: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in normalized.as_bytes() {
        h ^= u64::from(b.to_ascii_lowercase());
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    usize::try_from(h % u64::try_from(len).unwrap_or(1)).unwrap_or(0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_test_module
)] // паника в тесте = красный CI, это канал ответа
mod tests {
    use super::*;
    use token::KEY_LEN;

    fn engine() -> VaultEngine {
        VaultEngine::new(
            SessionKey::new([7_u8; KEY_LEN]),
            Limits::for_test(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(600),
            ),
        )
    }

    #[test]
    fn issue_then_rewrite_roundtrips_the_original() {
        let e = engine();
        let original = "Ушакова Кира Саввична";
        let marker = e
            .issue_token("s1", "PERSON_1", original)
            .expect("выдача токена");
        assert!(marker.starts_with("[[F0#") && marker.ends_with("]]"));
        let input = format!("Контрагент: {marker}, ИНН 825082492964");
        let out = e.rewrite_stream("s1", Grammar::F0_INLINE, input.as_bytes());
        assert_eq!(out.substituted, 1, "подмена не случилась");
        assert_eq!(out.unresolved, 0);
        assert!(!out.incomplete);
        assert_eq!(
            String::from_utf8(out.bytes).expect("выдача обязана быть UTF-8"),
            "Контрагент: Ушакова Кира Саввична, ИНН 825082492964"
        );
    }

    #[test]
    fn label_grammar_resolves_from_session_cache() {
        let e = engine();
        e.issue_token("s2", "CLIENT_PERSON_9", "Гущин Лукьян Фокич")
            .expect("выдача");
        let out = e.rewrite_stream(
            "s2",
            Grammar::LABEL,
            "поклажедателю [CLIENT_PERSON_9] надлежит".as_bytes(),
        );
        assert_eq!(out.substituted, 1);
        assert_eq!(
            String::from_utf8(out.bytes).expect("UTF-8"),
            "поклажедателю Гущин Лукьян Фокич надлежит"
        );
        // Чужая сессия тот же лейбл не видит.
        let other = e.rewrite_stream("s3", Grammar::LABEL, b"[CLIENT_PERSON_9]");
        assert_eq!(other.substituted, 0);
        assert_eq!(other.unresolved, 1);
        assert_eq!(other.bytes, b"[CLIENT_PERSON_9]".as_slice());
    }

    #[test]
    fn foreign_key_marker_passes_through_and_is_counted() {
        let e = engine();
        let alien =
            VaultToken::seal(&SessionKey::new([9_u8; KEY_LEN]), "секрет".as_bytes()).expect("seal");
        let text = format!("перед {} после", alien.to_marker());
        let out = e.rewrite_stream("s4", Grammar::F0_INLINE, text.as_bytes());
        assert_eq!(out.substituted, 0);
        assert_eq!(out.unresolved, 1, "чужой токен обязан быть учтён");
        assert_eq!(out.bytes, text.as_bytes(), "текст не должен портиться");
    }

    #[test]
    fn issue_token_fails_closed_on_both_layers() {
        let e = engine();
        // Пусто и длинна отбивает слой токена (он дешевле — до кэша).
        let empty = e
            .issue_token("s5", "L2", "")
            .expect_err("пустой оригинал не нужен ни в токене, ни в кэше");
        assert!(
            matches!(empty, IssueError::Token(VaultError::Empty)),
            "{empty:?}"
        );
        let long = "а".repeat(token::MAX_ORIGINAL_BYTES + 1);
        let err = e
            .issue_token("s5", "L", &long)
            .expect_err("длину надо отклонить");
        assert!(matches!(err, IssueError::Token(_)), "{err:?}");
        assert_eq!(
            e.store().inserts(),
            0,
            "отказ не должен ничего законсервить"
        );
        // Узкий max_value_bytes — единственный достижимый путь в Store-руку:
        // обычный спан (ФИО, 21 Б) в 16 байт не влезает, кэш обязан сказать
        // «нет». Число 16 не связано с потолком токена (#120 поднял его со 128
        // до 1024 Б), поэтому сюда не переезжает: фикстура проверяет отказ
        // кэша, а не отказ контейнера.
        let tight = VaultEngine::new(
            SessionKey::new([7_u8; KEY_LEN]),
            Limits {
                max_value_bytes: 16,
                ..Limits::for_test(
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(600),
                )
            },
        );
        let big = "Ушакова Кира Саввична";
        let err = tight
            .issue_token("s5", "L3", big)
            .expect_err("кэш обязан отказать по размеру");
        assert!(
            matches!(err, IssueError::Store(StoreError::TooBig { .. })),
            "{err:?}"
        );
        assert_eq!(tight.store().inserts(), 0);
    }

    #[test]
    fn debug_never_leaks_key_or_original() {
        let e = engine();
        e.issue_token("s6", "PERSON_1", "Соколов Демид Устинович")
            .expect("выдача");
        let d = format!("{e:?}");
        assert!(!d.contains("Соколов"), "оригинал засветился в Debug: {d}");
        assert_eq!(
            d.matches("[REDACTED]").count(),
            2,
            "обе redaction-метки обязаны быть видны: {d}"
        );
        assert!(!d.contains("7, 7, 7"), "ключ засветился: {d}");
    }

    #[test]
    fn surrogate_keeps_case_gender_and_is_not_the_original() {
        let e = engine();
        let srg = e
            .surrogat_for_gender("s7", "Ушакова", Case::Nom, Gender::Fem, NameType::Surname)
            .expect("отказа быть не может: сессия свежая")
            .expect("суррогат для женской фамилии");
        assert_ne!(srg.form, "Ушакова");
        assert_eq!(srg.gender, Gender::Fem);
        assert_eq!(srg.ty, NameType::Surname);
        // Падеж сохранён: суррогат стоит в той же форме, что и оригинал.
        let forms = morph::case_of(&srg.form);
        assert!(
            forms.contains(&(Case::Nom, Gender::Fem)),
            "суррогат {} разобран как {forms:?}",
            srg.form
        );
        // Обратное соответствие найдено, и оно — про оригинал.
        let back = e
            .original_of_surrogat("s7", &srg.form)
            .expect("обратная метка");
        assert_eq!(back.as_str(), "Ушакова");
    }

    /// Один и тот же владелец обязан получать одну форму во всех падежах, в
    /// которых его может увидеть демон. Пары Surface↔падеж взяты достижимыми:
    /// запрос `Gen` для поверхности «Ушакова» — это мужской родительный
    /// (`нет Ушакова`), а женская фамилия в Gen пишется «ушаковой», и такой
    /// спан («Ушакова Киры Саввичны») разбор `parse_span` не разрешает вовсе, и
    /// демон отдаёт его меткой, на суррогат он не приходит.
    #[test]
    fn surrogate_is_deterministic_and_varies_by_word() {
        let e = engine();
        let a = e
            .surrogat_for_gender("s8", "Ушакова", Case::Nom, Gender::Fem, NameType::Surname)
            .expect("первый")
            .expect("форма");
        let b = e
            .surrogat_for_gender("s8", "ушаковой", Case::Gen, Gender::Fem, NameType::Surname)
            .expect("второй")
            .expect("форма");
        // Слот (лемма) обязан быть один: форма различается по падежу, и это
        // правильно — «Гудзовская» и «Гудзовской» один человек.
        assert_eq!(
            a.lemma, b.lemma,
            "одна и та же фамилия обязана давать один суррогат"
        );
        // Третья фамилия обязана дать ЛИБО другой слот, ЛИБО отказ. Тихо
        // сместить первого писателя — нельзя ни при каком пуле (B2/P8), и
        // ровно это раньше и происходило: `let _ = store.insert(…)`.
        match e.surrogat_for_gender("s8", "Жукова", Case::Gen, Gender::Fem, NameType::Surname)
        {
            Ok(Some(c)) => assert_ne!(a.lemma, c.lemma, "разные слоты — ок"),
            Ok(None) => panic!("Жукова обязана разбираться в женскую фамилию"),
            Err(SurrogatError::Collision { form }) => {
                assert_eq!(form, a.form, "отказ обязан называть занятую форму");
                assert_eq!(
                    e.original_of_surrogat("s8", &a.form)
                        .expect("первый жив")
                        .as_str(),
                    "Ушакова",
                    "отказ не имел права сместить владельца слота"
                );
            }
            Err(other) => panic!("неожиданный отказ: {other:?}"),
        }
    }

    /// Та же фамилия в другом регистре — тот же владелец, и слот обязан остаться
    /// его: суррогат стабильно один, отказа нет, документ не деградировал.
    ///
    /// Первичка (промер `zz`-зондом на `5c8db56`, таблицы `data/morph/*.tsv`):
    /// `MorphTable::cands` строит лемму из `norm(word)` (`morph.rs:373` —
    /// `to_uppercase` + `Ё→Е`), поэтому леммы таблицы **верхнего регистра у
    /// построения**, и `lemma_set`/`is_same_owner_word` сравнивают регистр уже
    /// сейчас нейтрально: `is_same_owner_word("Ушакова", "ушакова") = true`
    /// (промер). Утверждение #72 «`lemma_set` сравнивает леммы регистрозависимо»
    /// первичке противоречит. Отказ рождается на ветке реверс-индекса
    /// (`:586`): `gi.issued` помнит `issue_tag(… , word)` от **поверхности**
    /// запроса, тег строчной формы не совпадает с тегом прописной, и сравнение
    /// `seen != tag` читает разницу регистра как смену владельца.
    ///
    /// Канон поведения после #65/#72: владелец опознаётся по лемме (как в
    /// движке), отпечаток — по **нормализованной** поверхности; оба регистра
    /// дают одну форму, разворот возвращаетsurface выдачи, счётчик расхождений
    /// молчит. Регресс держим на обоих регистрах в обе стороны.
    #[test]
    fn case_variant_of_issued_word_keeps_the_same_surrogat() {
        let e = engine();
        let sess = "s24";
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in(sess, word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова")
            .expect("прописная выдаётся")
            .expect("форма слота");
        let second = ask("ушакова");
        let second = match second {
            Ok(Some(second)) => second,
            Ok(None) => panic!("строчная форма обязана разбираться в фамилию"),
            Err(SurrogatError::Collision { form }) => {
                panic!("ложная коллизия на регистре: форма {form} занята тем же человеком")
            }
            Err(other) => panic!("неожиданный отказ: {other:?}"),
        };
        assert_eq!(
            first.form, second.form,
            "оба регистра одного владельца обязаны давать одну форму"
        );
        assert!(
            matches!(e.try_restore(sess, &first.form), Restore::Found(_)),
            "разворот обязан остаться живым после второй выдачи"
        );
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "вторая выдача того же человека не событие целостности"
        );
        // Регресс в обе стороны: прописная после строчной — тот же слот.
        let sess2 = "s24b";
        let ask2 = |word: &str| {
            e.surrogat_for_gender_in(sess2, word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let lower = ask2("ушакова").expect("строчная выдаётся").expect("форма");
        let upper = ask2("Ушакова");
        match upper {
            Ok(Some(u)) => assert_eq!(u.form, lower.form, "обратный порядок регистров"),
            Ok(None) => panic!("прописная обязана разбираться"),
            Err(other) => panic!("обратный порядок регистров отказал: {other:?}"),
        }
        assert_eq!(e.restoration_mismatches(), 0, "ни одного расхождения");
    }

    /// Исторический снимок #72 (до фикса): второй регистр отказывал, не смещая
    /// первого владельца. Безопасность границы — утечки нет — была зафиксирована
    /// именно здесь; после #65/#72 отказ на регистре стал ложным, и канон
    /// переехал в `case_variant_of_issued_word_keeps_the_same_surrogat`.
    ///
    /// Тест держит то, что от отказа неотъемлемо: он называет занятую форму, не
    /// трогает разворот первой выдачи и не двигает счётчик целостности. Вход —
    /// `УШАКОВА` (все буквы заглавные, OCR-выравнивание): леммы `cands`
    /// верхнего регистра, владелец опознаётся, и до фикса отказывал именно
    /// тег-путь реверс-индекса.
    #[test]
    fn all_caps_owner_refusal_keeps_first_owner_intact() {
        let e = engine();
        let sess = "s24c";
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in(sess, word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова").expect("первый").expect("форма");
        match ask("УШАКОВА") {
            Ok(Some(second)) => {
                assert_eq!(first.form, second.form, "тот же владелец — та же форма");
            }
            Ok(None) => panic!("`УШАКОВА` обязана разбираться в фамилию"),
            Err(SurrogatError::Collision { form }) => {
                assert_eq!(form, first.form, "отказ обязан назвать занятую форму");
            }
            Err(other) => panic!("неожиданный отказ: {other:?}"),
        }
        assert!(
            matches!(e.try_restore(sess, &first.form), Restore::Found(_)),
            "отказ второй выдачи не имел права тронуть первую"
        );
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "здесь не о чем расходиться: отказ не пишет свидетель"
        );
    }

    /// Истинная коллизия обязана пережить нормализацию ключа владельца (#65
    /// «Осторожно»: ослаблять B2/P8 нельзя без регресса на настоящих двух
    /// людях): «Ушакова» и «Жукова» в одном слоте — отказ, первый владелец
    /// цел, счётчик молчит. Тот же отказ на **нормализованной** поверхности
    /// (`жукова`): приведение регистра не имеет права склеить разных людей.
    #[test]
    fn true_collision_survives_owner_key_normalization() {
        let e = engine();
        let sess = "s24d";
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in(sess, word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова").expect("первый").expect("форма");
        let err = ask("Жукова").expect_err("второй владелец не смещает первого");
        assert_eq!(
            err,
            SurrogatError::Collision {
                form: first.form.clone()
            },
            "отказ обязан назвать занятую форму"
        );
        assert_eq!(
            ask("жукова").expect_err("нормализация регистра не склеивает разных людей"),
            SurrogatError::Collision { form: first.form },
            "отказ по нормализованной поверхности того же второго человека"
        );
        assert_eq!(
            e.original_of_surrogat(
                sess,
                &e.surrogat_for_gender_in(
                    sess,
                    "Ушакова",
                    Case::Nom,
                    Gender::Fem,
                    NameType::Surname,
                    &one
                )
                .unwrap()
                .unwrap()
                .form
            )
            .expect("первый жив")
            .as_str(),
            "Ушакова",
            "отказ не имел права сместить владельца слота"
        );
        assert_eq!(e.restoration_mismatches(), 0, "отказ не пишет свидетель");
    }

    /// R5 (#70): тег-свидетель пишется от владельца, а не от поверхности
    /// запроса; на достижимых из движка входах эти поверхности для одного слота
    /// совпадают, и мутация `issue_tag(…, word)` остаётся **эквивалентным
    /// мутантом** — это промерено, а не принято на веру.
    ///
    /// Промер на HEAD этого PR: `issue_tag(session, form, prev.as_str())` →
    /// `issue_tag(session, form, word)` в ветке `store.get` — 96/96 зелёные.
    /// Ветка `store.get` — писатель в обход движка (запись есть, свидетельства
    /// в индексе нет); ни один тест её не достигает, и на достижимых входах там
    /// `prev == word`: ровно то, о чём писал `case_variant_…` до #65/#72.
    ///
    /// Что тест держит по-настоящему — **живую** ветку индекса: второй регистр
    /// того же человека обязан (а) не отказывать (нормализация тега, #65/#72) и
    /// (б) оставить разворот целым: `deanonymize` обязан достать оригинал, а не
    /// посчитать ложное расхождение. Краснеет на мутации корневой причины —
    /// `issue_tag` без `owner_key` (промер PR: 2 red, см. тело PR).
    #[test]
    fn owner_tag_survives_the_other_case_written_by_the_engine() {
        let e = engine();
        let sess = "s24r5";
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in(sess, word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова").expect("первый").expect("форма");
        ask("ушакова").expect("второй регистр того же человека не отказывает");
        // В кэше после второй выдачи лежит surface `ушакова` (или `Ушакова` —
        // решает ветка, см. фикс), а свидетель обязан остаться тегом владельца.
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "вторая выдача того же человека не событие целостности"
        );
        let back = e.try_restore(sess, &first.form);
        assert!(
            matches!(back, Restore::Found(_)),
            "разворот не имеет права считаться расхождением: {back:?}"
        );
    }

    /// Базлайн, зафиксированный промером до правки: слот, опустевший по TTL или
    /// evict по байтовому бюджету, выглядит для голой проверки кэша
    /// свободным, и
    /// следующая фамилия получала чужую форму молча.
    ///
    /// Мутация (проверена снятием индекса): без реверс-индекса третий вызов
    /// отдаёт ту же форму, а `original_of_surrogat` возвращает «Родионова» там,
    /// где в текст клиента было подставлено «Ушакова» — тихая подмена `ПДн`.
    /// С индексом отказ происходит на выдаче (`Collision`), разворот прежнего маркера
    /// остаётся пустым, и счётчик целости молчит: нечего считать.
    #[test]
    fn slot_retaken_after_record_died_is_refused_not_swallowed() {
        let e = engine();
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in("s17", word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова").expect("первый").expect("форма");
        // Снятие записи — тем же примитивом, которым её снимает `idle`-лимит или
        // evict по байтовому бюджету: для теста важно состояние «строки кэша нет,
        // а индекс помнит», а не то, какой именно таймер его породил. Таймеры в
        // тесте = плавающий CI (промер wire-сюиты #66: 23/23 только на свежем
        // процессе, любое sleep-племя нервничает под нагрузкой раннера).
        e.store().invalidate(&StoreKey::new(
            "s17",
            &format!("{SRG_PREFIX}{}", first.form),
        ));
        assert!(
            e.original_of_surrogat("s17", &first.form).is_none(),
            "промер: запись снята — свидетель потерялся, а индекс остался"
        );
        let err = ask("Родионова").expect_err("вернуть форму второму владельцу нельзя");
        assert_eq!(
            err,
            SurrogatError::Collision {
                form: first.form.clone()
            }
        );
        assert!(
            e.original_of_surrogat("s17", &first.form).is_none(),
            "отказ не имел права ни занять слот, ни развернуть его в чужое имя"
        );
        assert_eq!(
            ask("Ушакова")
                .expect("владелец индекса")
                .expect("форма")
                .form,
            first.form,
            "тот же оригинал обязан получить свою форму обратно, а не новую"
        );
        assert_eq!(
            e.original_of_surrogat("s17", &first.form)
                .expect("разворот после оживления")
                .as_str(),
            "Ушакова",
            "разворот обязан вернуть то, что подставлялось"
        );
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "ложного расхождения быть не должно"
        );
    }

    /// Расхождение, которого штатный путь не создаёт: кэш говорит одно, индекс —
    /// другое. Так выглядит перезаписанная извне запись (старый бинарь, откат,
    /// прямой `store()`), и разворота чужим именем здесь быть не должно.
    #[test]
    fn divergent_store_entry_refuses_restore_and_is_counted() {
        let e = engine();
        let one = ["Тенина"];
        let a = e
            .surrogat_for_gender_in(
                "s18",
                "Ушакова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect("выдача")
            .expect("форма");
        e.store()
            .insert(
                &StoreKey::new("s18", &format!("{SRG_PREFIX}{}", a.form)),
                SecretString::new("Родионова".to_owned()),
            )
            .expect("запись вручную");
        assert!(
            e.original_of_surrogat("s18", &a.form).is_none(),
            "форма, под которую подложено другое имя, разворачиваться не обязана"
        );
        assert_eq!(
            e.restoration_mismatches(),
            1,
            "расхождение обязано быть посчитано"
        );
        assert_eq!(
            e.restoration_mismatches_for("s18"),
            1,
            "и быть атрибутируемо сессии"
        );
        assert_eq!(
            e.restoration_mismatches_for("s19"),
            0,
            "чужая сессия не при чём"
        );
    }

    /// Запись в сторе без строки в индексе не разворачивается.
    ///
    /// Так выглядит и состояние гонки teardown с выдачей (её закрывает порядок
    /// захвата замка), и запись, положенная в обход движка. Держим отдельным
    /// тестом, потому что это граница утечки: форма пула известна всем (пул в
    /// репозитории), и разворот записи без свидетеля в переиспользованном id
    /// сессии выдал бы новому клиенту оригинал из чужой, уже удалённой сессии.
    #[test]
    fn record_without_witness_is_not_restored() {
        let e = engine();
        let sess = "s21";
        e.store()
            .insert(
                &StoreKey::new(sess, &format!("{SRG_PREFIX}Тенина")),
                SecretString::new("Ушакова Кира Саввична".to_owned()),
            )
            .expect("запись в обход движка");
        assert!(
            !e.issued_witness(sess, "Тенина"),
            "свидетеля в индексе действительно нет"
        );
        assert!(
            matches!(e.try_restore(sess, "Тенина"), Restore::Absent),
            "нет свидетеля — нет разворота: молчаливый возврат чужого оригинала              и есть та утечка, ради которой этот индекс заводится",
        );
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "разворот без свидетеля — отсутствие доказательства, а не расхождение"
        );
    }

    /// Самопроверка R1: teardown обязан быть сериализован с выдачей.
    ///
    /// `invalidate_session` снимал записи стора ДО того, как брал замок индекса.
    /// Выдача, вклинившаяся в это окно, видела строку индекса (её ещё не сняли),
    /// не видела записи стора (их уже сняли) и возвращала запись в стор — итог:
    /// оригинал сессии пережил её удаление, а свидетеля у него нет. Инвариант,
    /// который это ловит: запись в сторе и строка в индексе живут ровно вместе.
    ///
    /// Мощность промера измерена на предке 79d5687 в изолированном target-каталоге
    /// (общий target давал аномалии списков тестов, для базлайнов не годится): из
    /// четырёх прогонов красятся два — 13 и 1 нарушение из 2000 раундов. Зелёный
    /// прогон — сетка, а не доказательство: окно в десятки инструкций
    /// детерминировать без тестовой щели в продуктовом коде нельзя, гарантия —
    /// порядок захвата замка. Детерминированный напарник этого теста —
    /// `record_without_witness_is_not_restored`, он на предке краснеет всегда.
    #[test]
    fn teardown_and_issue_never_leave_record_without_witness() {
        const ROUNDS: usize = 2_000;
        let e = VaultEngine::new(
            SessionKey::new([7_u8; KEY_LEN]),
            Limits::for_test(
                std::time::Duration::from_secs(600),
                std::time::Duration::from_secs(600),
            ),
        );
        // Четыре выдавщика на один teardown: окно между снятием стора и чисткой
        // индекса узкое, одним выдавщиком ловилось 1 нарушение из 2000 раундов и
        // промахивалось в трёх прогонах подряд.
        let issuers = 4_usize;
        let word = "Ушакова";
        let one = ["Тенина"];
        let mut bad = 0_usize;
        let mut first_bad = String::new();
        for r in 0..ROUNDS {
            let sess = format!("td{r}");
            let form = e
                .surrogat_for_gender_in(
                    &sess,
                    word,
                    Case::Nom,
                    Gender::Fem,
                    NameType::Surname,
                    &one,
                )
                .expect("первая выдача не валится")
                .expect("первая выдача даёт форму")
                .form;
            let bar = std::sync::Barrier::new(1 + issuers);
            std::thread::scope(|s| {
                let t1 = s.spawn(|| {
                    bar.wait();
                    e.invalidate_session(&sess);
                });
                let issuers: Vec<_> = (0..issuers)
                    .map(|_| {
                        s.spawn(|| {
                            bar.wait();
                            e.surrogat_for_gender_in(
                                &sess,
                                word,
                                Case::Nom,
                                Gender::Fem,
                                NameType::Surname,
                                &one,
                            )
                        })
                    })
                    .collect();
                t1.join().expect("teardown не паникует");
                for h in issuers {
                    let _second = h.join().expect("выдача не паникует");
                }
            });
            let store_has = e
                .store()
                .get(&StoreKey::new(&sess, &format!("{SRG_PREFIX}{form}")))
                .is_some();
            let index_has = e.issued_witness(&sess, &form);
            if store_has != index_has {
                bad += 1;
                if first_bad.is_empty() {
                    first_bad = format!(
                        "раунд {r}: форма {form}: запись в сторе = {store_has},                          свидетель в индексе = {index_has}"
                    );
                }
            }
        }
        assert_eq!(
            bad, 0,
            "запись без свидетеля переживает teardown {bad} раз(а) из {ROUNDS}; {first_bad}"
        );
    }

    /// Гонка на коллизирующей паре в ОДНОЙ сессии (R1 ревью #70) — постоянная
    /// версия промера ревьюера: живым демоном такое воспроизведение не повторяемо.
    ///
    /// Два потока, свежая сессия на раунд, одна корзина пула (обе фамилии дают
    /// лемму «Тенина», то есть обязаны сойтись на одной форме). Пока цепочка
    /// «проверка индекса → запись в кэш → запись в индекс» не под одним замком,
    /// оба потока видят пустой индекс, форма уходит двоим, индекс молча
    /// перезаписывается вторым владельцем, а `restoration_mismatches` остаётся
    /// нулевым — метрика лжёт ровно там, где обязана кричать.
    #[test]
    fn concurrent_issue_never_hands_one_form_to_two_owners() {
        use std::sync::{Arc, Barrier};
        const ROUNDS: usize = 2_000;
        let e = Arc::new(VaultEngine::new(
            SessionKey::new([7_u8; KEY_LEN]),
            Limits::for_test(
                std::time::Duration::from_secs(600),
                std::time::Duration::from_secs(600),
            ),
        ));
        let one = ["Тенина"];
        let bar = Arc::new(Barrier::new(2));
        // Оба потока запускаются до первого join: барьер на двух участников,
        // а join по очереди означал бы, что первый ждёт второго вечно.
        let mut handles = Vec::new();
        for word in ["Ушакова", "Родионова"] {
            let (eng, gate) = (Arc::clone(&e), Arc::clone(&bar));
            handles.push(std::thread::spawn(move || {
                let mut got = Vec::with_capacity(ROUNDS);
                for r in 0..ROUNDS {
                    gate.wait();
                    let sess = format!("race{r}");
                    // Отказ (`Collision`) и промах морфологии сводятся к None:
                    // нас интересует только случай «оба ушли с формой».
                    let form = match eng.surrogat_for_gender_in(
                        &sess,
                        word,
                        Case::Nom,
                        Gender::Fem,
                        NameType::Surname,
                        &one,
                    ) {
                        Ok(Some(s)) => Some(s.form),
                        _ => None,
                    };
                    got.push(form);
                }
                got
            }));
        }
        let runs: Vec<Vec<Option<String>>> = handles
            .into_iter()
            .map(|h| h.join().expect("поток выдачи не паникует"))
            .collect();
        let mut double = 0_usize;
        let mut first_bad = String::new();
        for (r, (fa, fb)) in runs[0].iter().zip(&runs[1]).enumerate() {
            let (Some(fa), Some(fb)) = (fa.clone(), fb.clone()) else {
                continue;
            };
            assert_eq!(
                fa, fb,
                "корзина из одной леммы не может выдать двум потокам разные формы"
            );
            double += 1;
            if first_bad.is_empty() {
                let back = e
                    .original_of_surrogat(&format!("race{r}"), &fa)
                    .map_or_else(
                        || "<разворота нет>".to_owned(),
                        |v| v.expose().expose_to_validator().to_owned(),
                    );
                first_bad = format!("раунд {r}: форма {fa} выдана обоим, разворот = {back}");
            }
        }
        assert_eq!(
            double, 0,
            "двойных выдач {double} из {ROUNDS} раундов; {first_bad}"
        );
        assert_eq!(
            e.restoration_mismatches(),
            0,
            "атомарная выдача не имеет права порождать расхождений"
        );
    }

    /// Счётчик обязан пережить `invalidate_session`: иначе метрика исчезает
    /// вместе с сессией, то есть ровно тогда, когда её хотят посмотреть.
    #[test]
    fn mismatch_counter_survives_session_teardown() {
        let e = engine();
        let one = ["Тенина"];
        let a = e
            .surrogat_for_gender_in(
                "s19",
                "Ушакова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect("выдача")
            .expect("форма");
        e.store()
            .insert(
                &StoreKey::new("s19", &format!("{SRG_PREFIX}{}", a.form)),
                SecretString::new("Родионова".to_owned()),
            )
            .expect("запись вручную");
        assert!(e.original_of_surrogat("s19", &a.form).is_none());
        e.invalidate_session("s19");
        assert_eq!(
            e.restoration_mismatches_for("s19"),
            0,
            "живой сессии больше нет"
        );
        assert_eq!(
            e.restoration_mismatches(),
            1,
            "сумма процесса обязана остаться"
        );
    }

    /// B2/P8: слот занят другим оригиналом — отказ, первый владелец остаётся.
    ///
    /// Корзина подставляется синтетическая, из одной леммы: на реальном пуле в
    /// 128 имён пара «Ушакова»/«Родионова» в одну корзину больше не попадает
    /// (это и есть результат #60), а ветка «слот занят» обязана работать при
    /// любом пуле — иначе тест проверял бы содержимое артефакта, а не механизм.
    #[test]
    fn surrogate_slot_refuses_second_original_and_keeps_the_first() {
        let e = engine();
        let one = ["Тенина"];
        let a = e
            .surrogat_for_gender_in(
                "s10",
                "Ушакова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect("первый")
            .expect("форма");
        let again = e
            .surrogat_for_gender_in(
                "s10",
                "Ушакова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect("идемпотентность")
            .expect("форма");
        assert_eq!(a.form, again.form, "тот же оригинал — та же форма");
        let err = e
            .surrogat_for_gender_in(
                "s10",
                "Родионова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect_err("занятый слот не перезаписывается");
        assert_eq!(
            err,
            SurrogatError::Collision {
                form: a.form.clone()
            }
        );
        assert_eq!(
            e.original_of_surrogat("s10", &a.form)
                .expect("владелец на месте")
                .as_str(),
            "Ушакова",
            "разворота чужим именем быть не могло"
        );
        // Другая сессия тем же слотом владеет отдельно.
        let other = e
            .surrogat_for_gender_in(
                "s11",
                "Родионова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
                &one,
            )
            .expect("своя сессия")
            .expect("форма");
        assert_eq!(other.form, a.form, "пул общий, владение — посессионное");
    }

    /// Дири-голо: `N + 1` разных фамилий при корзине из `N` лемм обязаны дать
    /// хотя бы один отказ. Корзина подставляется синтетическая, поэтому тест
    /// не зависит от размера артефакта и переживёт любое его изменение.
    #[test]
    fn surrogate_pigeonhole_refuses_within_pool_plus_one() {
        const SLOTS: usize = 3;
        let e = engine();
        let bucket: &[&'static str] = &["Ветрова", "Седова", "Тенина"];
        let words = [
            "Блякова",
            "Вжикова",
            "Глюкова",
            "Джельменова",
            "Ёлочкина",
            "Жмыхова",
            "Кляйменова",
        ];
        assert!(words.len() > SLOTS, "выборки мало для дири-голо");
        let slots = SLOTS;
        let refusals = words
            .iter()
            .filter(|w| {
                matches!(
                    e.surrogat_for_gender_in(
                        "s12",
                        w,
                        Case::Nom,
                        Gender::Fem,
                        NameType::Surname,
                        bucket
                    ),
                    Err(SurrogatError::Collision { .. })
                )
            })
            .count();
        assert!(
            refusals >= words.len() - slots,
            "при {slots} слотах и {} именах отказов должно быть не меньше {}: {refusals}",
            words.len(),
            words.len() - slots
        );
    }

    /// B2 закрыто на шаге 7а (#60): 25 разных фамилий в одной сессии.
    ///
    /// Держится инвариант, ради которого тест и писался — **тихая подмена
    /// невозможна**: каждая выданная форма разворачивается ровно в своего
    /// владельца, а отказ возможен только `Collision` (никакого `200 OK` с
    /// чужим именем). «Отказов вообще нет» утверждением не стало осознанно: при
    /// 4 слотах отказ был бы неизбежен, а на 128 эти 25 фамилий легли на разные
    /// формы (промер этим тестом: 25 выдано, 0 коллизий) — но гарантия не на
    /// том держится, что хэш не столкновётся, а на том, что столкновение
    /// слышно. Ниже — порог 20, а не 25: он ловит деградацию пула, не требуя
    /// от FNV идеального распределения.
    #[test]
    fn b2_multi_name_document_roundtrips_without_silent_swap() {
        let e = engine();
        let words: Vec<String> = (0..25).map(|i| format!("Тестова{i:02}")).collect();
        let mut forms = Vec::new();
        let mut collisions = 0usize;
        for w in &words {
            match e.surrogat_for_gender("b2", w, Case::Nom, Gender::Fem, NameType::Surname) {
                Ok(Some(s)) => forms.push((w.clone(), s.form)),
                Ok(None) => panic!("пустой пул: {w}"),
                Err(SurrogatError::Collision { .. }) => collisions += 1,
                Err(other) => panic!("отказ не по коллизии: {other:?}"),
            }
        }
        assert_eq!(forms.len() + collisions, words.len());
        assert!(
            forms.len() >= 20,
            "пул на 128 лемм должен пропускать не меньше 20 имён из 25, вышло {}",
            forms.len()
        );
        for (w, f) in &forms {
            assert_eq!(
                e.original_of_surrogat("b2", f)
                    .expect("обратная связь")
                    .as_str(),
                w.as_str(),
                "форма {f} разворачивается не того владельца"
            );
        }
    }

    /// #63: ключевые клетки пикера — точечно, по прослойкам.
    ///
    /// Движковый зуб (`homonym_surrogat_key_follows_gender…`) меряет конец
    /// (один слот на пуле); этот зуб меряет сам ключ, чтобы мута прослойки
    /// краснела на той оси, которую она ломает, а не на косвенном следствии.
    #[test]
    fn pick_lemma_prefers_exact_gender_then_homonym_mask() {
        let table = MorphTable::shipped().expect("таблица");
        let key = |word: &str, case: Case, gender: Gender| {
            VaultEngine::pick_lemma(
                &table.cands_any(word),
                word,
                case,
                gender,
                NameType::Surname,
            )
        };
        // Прослойка 1 (род+падеж) + род из маски `f,m`: Nom омонима.
        assert_eq!(
            key("Ушакова", Case::Nom, Gender::Fem),
            "УШАКОВА",
            "Nom+Fem обязан дать женскую лемму (кандидат Nom несёт маску `f,m`)"
        );
        // Прослойка 1 на точном роде: мужской Gen омонима остаётся мужским.
        assert_eq!(
            key("Ушакова", Case::Gen, Gender::Masc),
            "УШАКОВ",
            "Gen+Masc обязан остаться мужской леммой (омоним не перетягивает)"
        );
        // Прослойка 2 (род, любой падеж) = суть чина: у «Ушакова» женского
        // кандидата с `case=Gen` в таблице нет (первичка: `Gen g=m`), и без
        // прослойки 2 Fem+Gen падает в прослойку 3 = мужскую `УШАКОВ` =
        // дефект #63. Мута «прослойки 2–3 вырезаны» краснит эту клетку.
        assert_eq!(
            key("Ушакова", Case::Gen, Gender::Fem),
            "УШАКОВА",
            "род решает раньше падежа: Fem+Gen обязан дать женскую лемму"
        );
        // Контра порядка 1→2: если «род, любой падеж» поставить ПЕРЕД
        // «род+падеж», мужской Gen на «Ушакова» возьмёт Nom-кандидата
        // (маска `f,m` проходит тест `& bit` для Masc) = УШАКОВА, мужчина
        // уезжает на женский слот — зеркальный #63. Промер муты: клетка
        // красная (промер 28.10, left=УШАКОВА).
        assert_eq!(
            key("Ушакова", Case::Gen, Gender::Masc),
            "УШАКОВ",
            "падеж обязан уточнять род: мужской Gen не уезжает на Nom-омоним"
        );
        // Прослойка 3 (падеж без рода) = прежнее поведение на словах без
        // запрошенного рода: у «азина» в `Gen` только `g=m lemma=АЗИН`,
        // женского кандидата нет вовсе; прослойка 2 по роду берёт Nom
        // `АЗИНА` — и обязана взять: ключ Fem-запроса остаётся женским.
        assert_eq!(
            key("азина", Case::Gen, Gender::Fem),
            "АЗИНА",
            "род раньше падежа: Fem-ключ обязан остаться на женской лемме"
        );
        assert_eq!(
            key("азина", Case::Gen, Gender::Masc),
            "АЗИН",
            "мужской ключ того же слова = падежно-точная мужская лемма"
        );
        // Фоллбэк без кандидата — нормализация, дословно как была (мут
        // «`map_or_else` → `unwrap_or_default`» краснит эту клетку и b2-зуб).
        assert_eq!(
            key("Фывджща", Case::Gen, Gender::Fem),
            morph::norm("Фывджща"),
            "фоллбэк без кандидата трогать нельзя"
        );
    }

    /// #63: одна женщина — один слот. Ключ суррогата обязан сверять род.
    ///
    /// Первичка таблицы (`cands("Ушакова", Surname)`, промер 28.10):
    /// `Nom g=f,m lemma=УШАКОВА`, `Gen g=m lemma=УШАКОВ`, `Acc g=m lemma=УШАКОВ`.
    /// Прежний `pick_surrogat_from` искал кандидата по `(case, ty)` и брал
    /// первого: запрос `Gen`+`Fem` («нет кого? Ушакова») получал ключ `УШАКОВ`
    /// — лемму мужчины, а запрос `Nom`+`Fem` того же человека — `УШАКОВА`.
    /// Одна женщина в одном документе разъезжалась на два суррогатных слота:
    /// разворот оставался byte-exact (метка владеет оригиналом), но визуальная
    /// консистентность маски была нарушена — «Гудзовская … Евстрахиной».
    ///
    /// Дискриминатор = полный пул (128 лемм на корзину, артефакт #60): на нём
    /// два падежа одного и того же surface-слова дают РАЗНЫЕ леммы пула —
    /// ровно то, что запрещает инвариант. Дири-голо корзина из одной леммы тут
    /// слепа: слот на ней один по построению, и дефект ключа в выдаче не виден
    /// вовсе. Регрессию ловит движок на настоящем артефакте.
    #[test]
    fn homonym_surrogat_key_follows_gender_one_woman_one_slot() {
        // Движковый уровень на полном пуле (дири-голо слеп, см. док): Nom и Gen
        // одного и того же surface-слова одной женщины = ОДИН lemma-слот, формы — по падежам.
        let e = engine();
        let a = e
            .surrogat_for_gender("s63", "Ушакова", Case::Nom, Gender::Fem, NameType::Surname)
            .expect("выдача Nom")
            .expect("форма Nom");
        let b = e
            .surrogat_for_gender("s63", "Ушакова", Case::Gen, Gender::Fem, NameType::Surname)
            .expect("выдача Gen")
            .expect("форма Gen");
        assert_eq!(
            a.lemma, b.lemma,
            "одна женщина не имеет права разъезжаться на два слота: Nom={}/{} Gen={}/{}",
            a.form, a.lemma, b.form, b.lemma
        );
        assert_ne!(a.form, b.form, "разные падежи — разные формы, один слот");
        for (label, form) in [("Nom", &a.form), ("Gen", &b.form)] {
            assert_eq!(
                e.original_of_surrogat("s63", form)
                    .unwrap_or_else(|| panic!("обратная метка {label} потерялась"))
                    .as_str(),
                "Ушакова",
                "обе формы обязаны разворачиваться в одного человека"
            );
        }
    }

    #[test]
    fn surrogat_for_needs_unambiguous_gender() {
        let e = engine();
        // Именная форма: таблица даёт род `f,m` ⇒ без явного рода None (fail-closed).
        assert!(
            e.surrogat_for("s9", "Ушакова")
                .expect("не хранилище")
                .is_none()
        );
        // Несклоняемое — тоже None.
        assert!(
            e.surrogat_for("s9", "825082492964")
                .expect("не хранилище")
                .is_none()
        );
    }

    /// Пул-артефакт проверяется целиком в `pool::tests` (он же — владелец
    /// файла): сгибание каждой леммы, длина, непересечение с golden.
    #[test]
    fn pick_index_is_inside_pool_and_stable() {
        assert!(pick_index("УШАКОВА", 4) < 4);
        assert_eq!(pick_index("УШАКОВА", 4), pick_index("УШАКОВА", 4));
        assert_eq!(pick_index("ЛЮБОЕ", 1), 0);
    }

    #[test]
    fn invalidate_session_clears_only_that_session() {
        let e = engine();
        e.issue_token("s10", "A", "Алябьева Пелагея Ратиборовна")
            .expect("выдача A");
        e.issue_token("s10", "B", "Малышев Марк Сергеевич")
            .expect("выдача B");
        e.issue_token("s11", "A", "Хвостов Кирилл Сергеевич")
            .expect("выдача чужой сессии");
        e.store().sync();
        assert_eq!(e.store().entry_count(), 3);
        assert_eq!(e.invalidate_session("s10"), 2);
        e.store().sync();
        assert!(e.rewrite_stream("s10", Grammar::LABEL, b"[A]").unresolved > 0);
        assert_eq!(
            e.rewrite_stream("s11", Grammar::LABEL, b"[A]").substituted,
            1,
            "чужая сессия пострадать не должна"
        );
    }
}
