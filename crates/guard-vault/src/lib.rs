#![forbid(unsafe_code)]
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

/// Длина отпечатка в реверс-индексе целостности: усечённый ключёвый хэш.
const ISSUE_TAG_LEN: usize = 8;

/// Отпечаток оригинала, подставленного в форму.
type IssueTag = [u8; ISSUE_TAG_LEN];

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
        let pick_key = table
            .cands_any(word)
            .into_iter()
            .find(|c| c.case == want && c.ty == ty)
            .map_or_else(|| morph::norm(word), |c| c.lemma);
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

    /// Множество лемм, формой которых слово может быть. Пустое — не разобралось,
    /// Один ли это человек в двух написаниях: сечение множеств лемм непустое.
    ///
    /// Вынесено из ветки отказа, потому что сравнение нужно и там, где индекс уже
    /// подтвердил владение слотом. Без таблицы морфологии отличить одного от двоих
    /// нельзя, и решаем в пользу отказа: угадать владельца — тихая подмена.
    fn is_same_owner_word(prev: &str, word: &str) -> bool {
        MorphTable::shipped()
            .is_some_and(|tb| !Self::lemma_set(tb, prev).is_disjoint(&Self::lemma_set(tb, word)))
    }

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
        h.update(original.as_bytes());
        h.update(key);
        let digest = h.finalize();
        let mut tag = [0_u8; ISSUE_TAG_LEN];
        tag.copy_from_slice(&digest[..ISSUE_TAG_LEN]);
        tag
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
        // Критическая секция короткая: только чтение индекса, без обращения к
        // кэшу под замком.
        let seen = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .issued
            .get(&form_key)
            .copied();
        if let Some(seen) = seen {
            if seen != tag {
                // Форма уже светилась с ДРУГИМ оригиналом. Молча занять её —
                // значит выдать клиенту разворот не тем именем, что подставлялось;
                // отказ тут дешевле, чем там, где его не поймут (B2/P8).
                return Err(SurrogatError::Collision { form: srg.form });
            }
            // Тот же оригинал в той же форме: слот обязан жить, иначе разворот
            // прежнего текста даст пустоту.
            if self.store.get(&key).is_none() {
                self.store
                    .insert(&key, SecretString::new(word.to_owned()))?;
            }
            return Ok(Some(srg));
        }
        if let Some(prev) = self.store.get(&key) {
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
            if !Self::is_same_owner_word(prev.as_str(), word) {
                return Err(SurrogatError::Collision { form: srg.form });
            }
        } else {
            self.store
                .insert(&key, SecretString::new(word.to_owned()))?;
        }
        self.integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .issued
            .insert(form_key, tag);
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
        let found = self
            .store
            .get(&StoreKey::new(session, &format!("{SRG_PREFIX}{form}")))?;
        let form_key = Self::form_key(session, form);
        let mut gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(seen) = gi.issued.get(&form_key).copied() {
            if seen != self.issue_tag(session, form, found.as_str()) {
                *gi.mismatches.entry(session.to_owned()).or_insert(0) += 1;
                return None;
            }
        }
        Some(found)
    }

    /// Сколько разворотов отказало из-за расхождения с реверс-индексом.
    ///
    /// Процессный счётчик, переживает teardown сессий. Вне отладочного режима
    /// виден в `GET /v1/status` полем `unrestored_mismatch`.
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
        let removed = self.store.invalidate_session(session);
        let mut gi = self
            .integrity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gi.issued.retain(|(s, _), _| s != session);
        if let Some(n) = gi.mismatches.remove(session) {
            gi.retired += n;
        }
        removed
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
        // токен в 128 байт в него не влезает, кэш обязан сказать «нет».
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

    /// Базлайн, зафиксированный промером до правки: слот, опустевший по `idle`,
    /// выглядит для голой проверки кэша свободным, и следующая фамилия получала
    /// чужую форму молча.
    ///
    /// Мутация (проверена снятием индекса): без реверс-индекса третий вызов
    /// отдаёт ту же форму, а `original_of_surrogat` возвращает «Родионова» там,
    /// где в текст клиента было подставлено «Ушакова» — тихая подмена `ПДн`.
    /// С индексом отказ происходит на выдаче (`Collision`), разворот прежнего маркера
    /// остаётся пустым, и счётчик целости молчит: нечего считать.
    #[test]
    fn slot_retaken_after_ttl_is_refused_not_swallowed() {
        let e = VaultEngine::new(
            SessionKey::new([7_u8; KEY_LEN]),
            Limits::for_test(
                std::time::Duration::from_millis(20),
                std::time::Duration::from_secs(600),
            ),
        );
        let one = ["Тенина"];
        let ask = |word: &str| {
            e.surrogat_for_gender_in("s17", word, Case::Nom, Gender::Fem, NameType::Surname, &one)
        };
        let first = ask("Ушакова").expect("первый").expect("форма");
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(
            e.original_of_surrogat("s17", &first.form).is_none(),
            "промер: запись умерла по `idle` — свидетель потерялся, а индекс остался"
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
