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
//! Политик удержания, кроме кэша, тут тоже нет.

use std::cell::Cell;

use guard_types::SecretString;

pub mod cache;
pub mod morph;
pub mod rewriter;
pub mod token;

pub use cache::{Limits, SecretRef, SessionStore, StoreError, StoreKey};
pub use morph::{Case, Gender, MorphTable, NameType, SpanParse};
pub use rewriter::{BodyKind, Grammar, Resolution, StreamRewriter};
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

/// Пул суррогатов: по четыре имени на пару (тип, род).
///
/// 4 слота на позицию = дири-голо на 5-м имени: в `golden-v1` 27 суррогатных
/// ФИО делят хотя бы один слот в 347 парах из 351 (промер 20.10), поэтому
/// выдача формы сделана first-writer-wins с отказом ([`SurrogatError::Collision`])
/// — иначе второй оригинал молча смещал бы первого, и разворот возвращал чужое
/// имя. Расширение пула — шаг 7 (KNOWN-RED-тест `known_red_b2_…` держит условие).
///
/// Имена подобраны так, чтобы ни одного не было в `data/golden/golden-v1.jsonl`
/// (тест `surrogate_pool_is_clean_and_declinable`); суррогат, совпадающий с
/// реальной фамилией из другого документа, сломал бы обратимость подмены.
/// Склоняемость каждой леммы во всех шести падежах проверяется тем же тестом,
/// поэтому пул нельзя «просто пополнить» — только вместе с проверкой. Отбраковано
/// промером (правила типа `firstname` их не покрывают): Пимен, Назар, Захар,
/// Куприян, Селиван — таблица на косвенных падежах возвращает им лемму.
const SURROGATES: &[(&str, Gender, NameType)] = &[
    ("Ветров", Gender::Masc, NameType::Surname),
    ("Седов", Gender::Masc, NameType::Surname),
    ("Тенин", Gender::Masc, NameType::Surname),
    ("Леснов", Gender::Masc, NameType::Surname),
    ("Ветрова", Gender::Fem, NameType::Surname),
    ("Седова", Gender::Fem, NameType::Surname),
    ("Тенина", Gender::Fem, NameType::Surname),
    ("Леснова", Gender::Fem, NameType::Surname),
    ("Афанасий", Gender::Masc, NameType::Firstname),
    ("Спиридон", Gender::Masc, NameType::Firstname),
    ("Всеслав", Gender::Masc, NameType::Firstname),
    ("Парфен", Gender::Masc, NameType::Firstname),
    ("Варвара", Gender::Fem, NameType::Firstname),
    ("Прасковья", Gender::Fem, NameType::Firstname),
    ("Матрона", Gender::Fem, NameType::Firstname),
    ("Агафья", Gender::Fem, NameType::Firstname),
    ("Афанасьевич", Gender::Masc, NameType::Midname),
    ("Пименович", Gender::Masc, NameType::Midname),
    ("Назарович", Gender::Masc, NameType::Midname),
    ("Парфенович", Gender::Masc, NameType::Midname),
    ("Афанасьевна", Gender::Fem, NameType::Midname),
    ("Пименовна", Gender::Fem, NameType::Midname),
    ("Назаровна", Gender::Fem, NameType::Midname),
    ("Парфеновна", Gender::Fem, NameType::Midname),
];

/// Префикс метки, под которой движок кэширует обратное соответствие суррогата.
const SRG_PREFIX: &str = "SRG#";

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

/// Прокладка «токен + кэш + переписыватель + морфология».
///
/// `Debug` безопасен: [`SessionKey`] печатается как `SessionKey("[REDACTED]")`,
/// [`SessionStore`] печатает значения как `[REDACTED]` (атом C).
#[derive(Debug)]
pub struct VaultEngine {
    store: SessionStore,
    key: SessionKey,
}

impl VaultEngine {
    /// Собирает движок из ключа сессии и лимитов кэша.
    #[must_use]
    pub fn new(key: SessionKey, limits: Limits) -> Self {
        Self {
            store: SessionStore::new(limits),
            key,
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
    #[must_use]
    pub fn rewrite_stream(&self, session: &str, grammar: Grammar, input: &[u8]) -> StreamOutcome {
        let unresolved = Cell::new(0_usize);
        let mut rw = StreamRewriter::new(grammar, |body: &[u8]| -> Resolution {
            let Ok(text) = std::str::from_utf8(body) else {
                unresolved.set(unresolved.get() + 1);
                return Resolution::Unknown;
            };
            let found = match grammar.body {
                BodyKind::Base64Url => VaultToken::from_base64url(text)
                    .and_then(|t| t.open(&self.key))
                    .map(|plain| plain.as_bytes().to_vec())
                    .ok(),
                BodyKind::Label => self
                    .store
                    .get(&StoreKey::new(session, text))
                    .map(|r| r.as_str().as_bytes().to_vec()),
            };
            if let Some(bytes) = found {
                Resolution::Substitute(bytes)
            } else {
                unresolved.set(unresolved.get() + 1);
                Resolution::Unknown
            }
        });
        let (bytes, incomplete) = rw.run_to_end(input);
        StreamOutcome {
            bytes,
            substituted: rw.substituted(),
            unresolved: unresolved.get(),
            incomplete,
        }
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
        let table = MorphTable::shipped()?;
        let pool: Vec<&'static str> = SURROGATES
            .iter()
            .filter(|(_, g, t)| *g == gender && *t == ty)
            .map(|(l, _, _)| *l)
            .collect();
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
    /// возвращал чужое имя как настоящие `ПДн` (промер: 347 пар из 351 в
    /// golden-v1 делят хотя бы один слот).
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
        let Some(srg) = Self::pick_surrogat(word, want, gender, ty) else {
            return Ok(None);
        };
        let key = StoreKey::new(session, &format!("{SRG_PREFIX}{}", srg.form));
        if let Some(prev) = self.store.get(&key) {
            // Владелец опознаётся по ПЕРЕСЕЧЕНИЮ МНОЖЕСТВ ЛЕММ, а не по поверхности и не
            // по лемме пула: «Ушакова» и «ушаковой» — один человек в двух
            // падежах, обязан получить ту же форму (иначе обратимость рвётся по
            // падежам); «Ушакова» и «Жукова» — два человека в одном слоте, и
            // это отказ. Лемму берём по любому кандидату (не по запрошенному
            // падежу): у слова в творительном падеже кандидат с `case=Gen` не
            // находится, и сравнение разбилось бы на регистре, а не на человеке.
            // Пул-лемма сравнивать нельзя: у коллизии она у обоих одна и та же
            // по построению.
            let same_owner = MorphTable::shipped().is_some_and(|tb| {
                !Self::lemma_set(tb, prev.as_str()).is_disjoint(&Self::lemma_set(tb, word))
            });
            if !same_owner {
                return Err(SurrogatError::Collision { form: srg.form });
            }
            return Ok(Some(srg));
        }
        self.store
            .insert(&key, SecretString::new(word.to_owned()))?;
        Ok(Some(srg))
    }

    /// Оригинальное слово по суррогатной форме (обратный ход подмены).
    #[must_use]
    pub fn original_of_surrogat(&self, session: &str, form: &str) -> Option<SecretRef> {
        self.store
            .get(&StoreKey::new(session, &format!("{SRG_PREFIX}{form}")))
    }

    /// Сбрасывает всё, что накоплено сессией (конец диалога, выход из запроса).
    pub fn invalidate_session(&self, session: &str) -> u64 {
        self.store.invalidate_session(session)
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

    #[test]
    fn surrogate_is_deterministic_and_varies_by_word() {
        let e = engine();
        let a = e
            .surrogat_for_gender("s8", "Ушакова", Case::Gen, Gender::Fem, NameType::Surname)
            .expect("первый")
            .expect("форма");
        let b = e
            .surrogat_for_gender("s8", "ушаковой", Case::Gen, Gender::Fem, NameType::Surname)
            .expect("второй")
            .expect("форма");
        assert_eq!(
            a.form, b.form,
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

    /// B2/P8: слот занят другим оригиналом — отказ, первый владелец остаётся.
    ///
    /// Пара промерена на текущем пуле: обе фамилии дают «Тенина».
    #[test]
    fn surrogate_slot_refuses_second_original_and_keeps_the_first() {
        let e = engine();
        let a = e
            .surrogat_for_gender("s10", "Ушакова", Case::Nom, Gender::Fem, NameType::Surname)
            .expect("первый")
            .expect("форма");
        let again = e
            .surrogat_for_gender("s10", "Ушакова", Case::Nom, Gender::Fem, NameType::Surname)
            .expect("идемпотентность")
            .expect("форма");
        assert_eq!(a.form, again.form, "тот же оригинал — та же форма");
        let err = e
            .surrogat_for_gender(
                "s10",
                "Родионова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
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
            .surrogat_for_gender(
                "s11",
                "Родионова",
                Case::Nom,
                Gender::Fem,
                NameType::Surname,
            )
            .expect("своя сессия")
            .expect("форма");
        assert_eq!(other.form, a.form, "пул общий, владение — посессионное");
    }

    /// Дири-голо: `N + 1` разных фамилий при пуле из `N` обязаны дать хотя бы
    /// один отказ. Тест не зависит от размера пула и переживёт его расширение.
    #[test]
    fn surrogate_pigeonhole_refuses_within_pool_plus_one() {
        let e = engine();
        let slots = SURROGATES
            .iter()
            .filter(|(_, g, t)| *g == Gender::Fem && *t == NameType::Surname)
            .count();
        let words = [
            "Блякова",
            "Вжикова",
            "Глюкова",
            "Джельменова",
            "Ёлочкина",
            "Жмыхова",
            "Кляйменова",
        ];
        assert!(words.len() > slots, "выборки мало для дири-голо");
        let refusals = words
            .iter()
            .filter(|w| {
                matches!(
                    e.surrogat_for_gender("s12", w, Case::Nom, Gender::Fem, NameType::Surname),
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

    /// KNOWN-RED B2 (review #58): документ с несколькими разными ФИО обязан
    /// разворачиваться целиком и байт-в-байт. Краснеет сегодня на дири-голо:
    /// 25 имён в 4 слота — это отказ, а не маскирование. Зеленым станет после
    /// расширения пула (issue шага 7), здесь держим как измерение границы.
    #[test]
    #[ignore = "KNOWN-RED B2: пул 4 имени на (род, тип); ждёт расширения на шаге 7"]
    fn known_red_b2_multi_name_document_roundtrips_byte_exact() {
        let e = engine();
        let words: Vec<String> = (0..25).map(|i| format!("Тестова{i:02}")).collect();
        let mut forms = Vec::new();
        for w in &words {
            let s = e
                .surrogat_for_gender("b2", w, Case::Nom, Gender::Fem, NameType::Surname)
                .expect("расширенный пул не должен отказывать")
                .expect("форма");
            forms.push((w.clone(), s.form));
        }
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

    #[test]
    fn surrogate_pool_is_clean_and_declinable() {
        let t = MorphTable::shipped().expect("таблица");
        let golden = std::fs::read_to_string(format!(
            "{}/../../data/golden/golden-v1.jsonl",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("golden");
        let mut bad: Vec<String> = Vec::new();
        for (lemma, gender, ty) in SURROGATES {
            if golden.contains(lemma) {
                bad.push(format!("{lemma}: есть в golden-датасете"));
                continue;
            }
            for case in Case::ALL {
                match t.inflect_typed(lemma, case, *gender, *ty) {
                    None => bad.push(format!("{lemma} {case:?}: таблица не дала формы")),
                    Some(f) if f.is_empty() => bad.push(format!("{lemma} {case:?}: пусто")),
                    Some(f) if case != Case::Nom && f == *lemma => {
                        bad.push(format!("{lemma} {case:?}: вернула лемму ({f})"));
                    }
                    Some(_) => {}
                }
            }
        }
        assert!(
            bad.is_empty(),
            "пул суррогатов нечист ({} позиц\n{}\n — менять только вместе с проверкой)",
            bad.len(),
            bad.join("\n")
        );
    }

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
