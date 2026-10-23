//! Контракт весового бандла: раскладка каталога, манифест, статус, загрузка (#192).
//!
//! Три стены этого модуля:
//!
//! 1. **Раскладка одна.** Пять файлов каскадов 1–2 заданы здесь и нигде
//!    больше; [`crate::cascades::startup`] сверяет с ней путь монтирования
//!    (юнит `layout_matches_the_fetch_cache_contract`), а кнопка «Скачать
//!    веса» пишет ровно в неё. Расхождение «UI показывает ✓, а демон говорит
//!    „нет файла“» — это две раскладки в двух файлах; теперь раскладка одна.
//! 2. **Манифест вшит в бинарь** (`include_str!`, прецедент
//!    [`crate::schema::DEFAULT_SCHEMA_JSON`]): релизный бандл несёт тот же
//!    `models/manifest.tsv`, что репозиторий (зуб
//!    `manifest_shipped_in_bundle` в `scripts/make-bundle.sh`), поэтому UI
//!    видит revision/размеры оффлайн.
//! 3. **Сеть — только по клику и только на HF-хост из манифеста/env.** Это
//!    осознанное разрешение оператора (issue #192, 22.10): air-gap-инвариант
//!    AGENTS («никаких сетевых вызовов кроме явного `X-Upstream-URL`»)
//!    дополняется вторым, точечным исходящим путём — загрузкой весов.
//!    Trigger только UI-клик (`POST /v1/models/fetch`), адрес строится ИЗ
//!    ВШИТОГО манифеста, схема https, redirect не сопровождается,
//!    sha256+размер fail-closed. Модуль — второй санкционированный сетевой
//!    файл демона (первый — `proxy.rs`); гейт `tests/net_audit.rs` фиксирует
//!    это именованным контрактом, а не молчаливым ослаблением.
//!
//! Скачанные байты = веса (не `ПДн`), прогресс живёт в памяти процесса, на
//! диск пишется только файл модели через `.part`-файл + атомарный rename (паритет
//! `scripts/fetch-models.sh:89-117`).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// Дефолтный HF-хост загрузки (значение `FASAD_HF_HOST` в
/// `scripts/fetch-models.sh:25`). Переопределяется ТОЛЬКО env при старте —
/// запрос-параметра хоста нет: URL строится из манифеста, и «инъекции»
/// адреса в endpoint не из чего.
pub const DEFAULT_HF_HOST: &str = "https://huggingface.co";

/// Машиночитаемый манифест весов, вшитый в бинарь. Тот же файл, что несёт
/// бандл и что читает `scripts/fetch-models.sh`.
pub const MANIFEST_TSV: &str = include_str!("../../../models/manifest.tsv");

/// Одна строка манифеста (поля 1–6 формата 8 полей, см. заголовок файла).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Роль (`extractor1b` / `arbiter` / …) — только для диагностики.
    pub role: String,
    /// Репозиторий HF (`owner/name`).
    pub repo: String,
    /// Commit-шейа, по которому качаем (детерминизм: не ветка).
    pub revision: String,
    /// Относительный путь файла в репозитории.
    pub file: String,
    /// Подтверждённый sha256 (64 hex). `TBD` = первого подтверждения нет:
    /// в рантайме это fail-closed отказ (демон не переписывает манифест, в
    /// отличие от скрипта первого подтверждения).
    pub sha256: String,
    /// Промеренный размер, байт; 0 = сверка по размеру выключена (контракт sh).
    pub size_bytes: u64,
}

impl ManifestEntry {
    /// Записи `@auto`-revision в рантайме не обслуживаются: скрипт
    /// (`resolve_revision`) резолвит их через HF API и переписывает манифест,
    /// демон угадыванием revision не занимается.
    #[must_use]
    pub fn auto_revision(&self) -> bool {
        self.revision == "@auto"
    }
}

/// Разбор манифеста: строки `#` и пустые пропускаются; табуляция, минимум 6
/// полей; мусорная строка = `None` (вызывающий обязан отказать, а не качать
/// «что поняли»).
#[must_use]
pub fn parse_manifest(text: &str) -> Option<Vec<ManifestEntry>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split('\t');
        let (Some(role), Some(repo), Some(revision), Some(file), Some(sha256), Some(size)) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            return None;
        };
        let Ok(size_bytes) = size.trim().parse::<u64>() else {
            return None;
        };
        out.push(ManifestEntry {
            role: role.to_owned(),
            repo: repo.to_owned(),
            revision: revision.to_owned(),
            file: file.to_owned(),
            sha256: sha256.to_owned(),
            size_bytes,
        });
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Записи манифеста для рантайма. Пусто/битый = пустой список: тогда загрузка
/// отказывает (`manifest_unparsable`), а статус рисует «рекордов нет».
///
/// Источник = вшитый `MANIFEST_TSV` (prod), либо мок-файл
/// `FASAD_MANIFEST=<путь>` (интеграционные e2e mock-HF: sha256-гейт
/// меряется НАСТОЯЩИМ кодом на фикстуре; env выставляют только тесты —
/// тот же класс аффорданса, что `FASAD_PROXY_LOOPBACK_HTTP`).
#[must_use]
pub fn embedded_entries() -> Vec<ManifestEntry> {
    parse_manifest(runtime_manifest_text()).unwrap_or_default()
}

/// Текст манифеста для рантайма (prod = вшитый; см. [`embedded_entries`]).
#[must_use]
pub fn runtime_manifest_text() -> &'static str {
    static MOCK: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    MOCK.get_or_init(|| {
        std::env::var("FASAD_MANIFEST")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
    })
    .as_deref()
    .unwrap_or(MANIFEST_TSV)
}

// ── Раскладка каталога (контракт fetch-кешей + каскадов) ────────────────────

/// Роль lockR-экстрактора в манифесте (граф, без external data).
pub const ROLE_LOCKR_MODEL: &str = "extractor1b";
/// Роль веса арбитра (external data Decide).
pub const ROLE_ARB_WEIGHTS: &str = "arbiter-weights";

/// Модель lockR в раскладке (первичка `cascades.rs`: путь монтирования).
pub const LOCKR_MODEL_FILE: &str = "lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx";
/// Токенизатор lockR.
pub const LOCKR_TOK_FILE: &str = "lockR/rubert-base-pii-ner-onnx/tokenizer.json";
/// Граф арбитра Decide.
pub const ARB_MODEL_FILE: &str = "onnx-community/GLiNER2.5-Decide-ONNX/onnx/model_q4f16.onnx";
/// Токенизатор арбитра.
pub const ARB_TOK_FILE: &str = "onnx-community/GLiNER2.5-Decide-ONNX/tokenizer.json";
/// Внешние веса арбитра (523 МБ; без них граф = ошибка загрузки, см. заголовок
/// манифеста «имена …_data обязательны парами»).
pub const ARB_DATA_FILE: &str = "onnx-community/GLiNER2.5-Decide-ONNX/onnx/model_q4f16.onnx_data";

/// Полный layout каталога весов: 5 файлов (4 из ТЗ #192 + external data
/// арбитра — монтажу каскадов он обязателен, «4 файла ✓» без него было бы ✓
/// над несмонтируемым бандлом). Порядок = порядок скачивания (мелкие первыми:
/// быстрый первый ✓ в UI).
#[must_use]
pub const fn layout() -> &'static [&'static str] {
    &[
        LOCKR_MODEL_FILE,
        LOCKR_TOK_FILE,
        ARB_MODEL_FILE,
        ARB_TOK_FILE,
        ARB_DATA_FILE,
    ]
}

/// Путь файла layout в каталоге весов.
#[must_use]
pub fn layout_path(dir: &Path, rel: &str) -> PathBuf {
    dir.join(rel)
}

/// Роль манифеста, чей файл лежит по этому пути layout (сверка repo/file).
#[must_use]
pub fn role_for(rel: &str) -> Option<&'static str> {
    match rel {
        LOCKR_MODEL_FILE => Some(ROLE_LOCKR_MODEL),
        ARB_DATA_FILE => Some(ROLE_ARB_WEIGHTS),
        LOCKR_TOK_FILE => Some("tok-extractor1b"),
        ARB_MODEL_FILE => Some("arbiter"),
        ARB_TOK_FILE => Some("tok-arbiter"),
        _ => None,
    }
}

/// Запись манифеста по роли (`None` = записи нет — статус обязан сказать
/// «рекордов нет», а не нарисовать прочерк).
#[must_use]
pub fn entry_by_role<'a>(entries: &'a [ManifestEntry], role: &str) -> Option<&'a ManifestEntry> {
    entries.iter().find(|e| e.role == role)
}

// ── Присутствие файлов (читается при каждом GET /v1/status — дешёвый stat) ──

/// Один файл layout в статусе. sha256 здесь не считается: 879 МБ пересчёта на
/// каждый GET = отказ по времени; размер + manifest-revision = ответ на
/// «файл на месте и тот ли он» (решение ТЗ #192: проверка чексуммы = по
/// кнопке загрузки, не по просмотру).
#[derive(Debug, serde::Serialize)]
pub struct WeightFile {
    /// Относительный путь (layout-контракт, не абсолют: домашний путь наружу
    /// не светим — `/health` без аутентификации).
    pub path: &'static str,
    /// Роль из манифеста (подпись в UI).
    pub role: &'static str,
    /// Файл существует.
    pub present: bool,
    /// Фактический размер (отсутствует = файла нет).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Размер из манифеста: UI рисует «не тот размер» красным (обрывок без
    /// `.part`-имени, порча).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_bytes: Option<u64>,
    /// Присутствует И размер совпадает с манифестом.
    pub ok: bool,
}

/// Все пять файлов раскладки смонтированы (присутствуют и размеры совпали
/// с манифестом). #198: env-граница `Config::from_env` чинит ожидающий старт
/// на «веса уже скачаны, перезапусти» — трей без env обязан ПОДНЯТЬСЯ и
/// показать карточку с ✓ (кнопка не нужна), а не окном отказа. Пустой
/// каталог/несовпадение = false (окно/ожидающий UI = честная причина).
#[must_use]
pub fn layout_complete(dir: &Path) -> bool {
    let entries = embedded_entries();
    if entries.is_empty() {
        // Манифест вшитый испорчен: смонтировать нечего, «готов» = ложь.
        return false;
    }
    scan(dir, &entries).iter().all(|f| f.ok)
}

/// Присутствие 5 файлов layout в каталоге (по фактическому `dir`).
#[must_use]
pub fn scan(dir: &Path, entries: &[ManifestEntry]) -> Vec<WeightFile> {
    layout()
        .iter()
        .map(|rel| {
            let role = role_for(rel).unwrap_or("?");
            let expected = entry_by_role(entries, role).map(|e| e.size_bytes);
            let bytes = std::fs::metadata(layout_path(dir, rel))
                .ok()
                .map(|m| m.len());
            WeightFile {
                path: rel,
                role,
                present: bytes.is_some(),
                bytes,
                expected_bytes: expected,
                ok: bytes.is_some_and(|b| expected.is_none_or(|e| e == 0 || e == b)),
            }
        })
        .collect()
}

// ── Состояние фоновой загрузки (память процесса, ПДн тут нет) ───────────────

/// Фаза текущего файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Скачивание в `.part`.
    Download,
    /// Пересчёт sha256 + сверка (после скачивания, до rename).
    Verify,
    /// Файл уже в кеше и прошёл сверку — сеть не тронута.
    CacheHit,
}

/// Прогресс текущего файла.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Progress {
    /// Layout-путь файла.
    pub file: &'static str,
    /// Байт принято (для verify/cache-hit = 0/полный).
    pub bytes_done: u64,
    /// Размер из манифеста (0 = неизвестен).
    pub bytes_total: u64,
    /// Фаза.
    pub phase: Phase,
}

/// Состояние загрузки: `idle` до первого клика, затем один из четырёх.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum FetchState {
    /// Загрузка не запускалась (свежий демон).
    Idle,
    /// Идёт файл `index` из `total` с текущим прогрессом.
    Running {
        /// Номер текущего файла (1-базный, как в UI).
        index: usize,
        /// Всего файлов в layout.
        total: usize,
        /// Прогресс текущего файла.
        progress: Progress,
    },
    /// Все файлы на месте и сверены.
    Done {
        /// Число файлов layout.
        files: usize,
    },
    /// Отказ: файл + класс (токенов/`ПДн` нет по построению: `error` =
    /// конечный набор классов, `file` = относительный layout-путь).
    Failed {
        /// Layout-путь файла, на котором споткнулись.
        file: String,
        /// Класс + деталь (`code: detail`, sanitize #192).
        error: String,
    },
}

/// Общий слот статуса: пишет рабочий поток `spawn_blocking`, читает
/// `GET /v1/status`. `Mutex` (не атомик): меняется вся структура разом.
pub type FetchStatus = Mutex<FetchState>;

/// Слот живёт в `OnceLock` процесса: `AppState::new` (тесты роутера, демоны в
/// одном процессе) получают ОДИН слот на процесс — ровно как `MOUNT`
/// каскадов: загрузка в продукте одна, и второй `AppState` обязан видеть её
/// же, а не параллельную историю.
static FETCH: OnceLock<FetchStatus> = OnceLock::new();

/// Слот состояния загрузки (единственный на процесс).
#[must_use]
pub fn fetch_slot() -> &'static FetchStatus {
    FETCH.get_or_init(|| Mutex::new(FetchState::Idle))
}

fn slot_state() -> FetchState {
    fetch_slot()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Запрос на загрузку занят (один job на процесс, повтор = 409).
#[must_use]
pub fn fetch_busy() -> bool {
    matches!(slot_state(), FetchState::Running { .. })
}

/// Выставить состояние (пишет рабочий поток, читает статус).
pub fn set_fetch_state(state: FetchState) {
    *fetch_slot().lock().unwrap_or_else(PoisonError::into_inner) = state;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    /// #198: полный контур «5/5 И размеры совпали» (тот же код, что читает
    /// env-граница #192/#198 через `layout_complete`). Мок-манифест через
    /// env-мок манифеста НЕ ставится: `runtime_manifest_text` кэширует
    /// `OnceLock` на процесс, а юниты параллельны — мок отравил бы соседям «вшитый» манифест
    /// (класс ложно-зелёной проверки: `manifest_parses_all_five_rows…` читал
    /// бы фикстуру, думая, что читает `include_str!`). Поэтому фикстура
    /// передаётся ПРЯМЫМ списком entries (тот же контракт `scan`/`WeightFile`,
    /// из которого собран `layout_complete`), а живой `layout_complete` на
    /// вшитом манифесте промеряется ниже на пустом каталоге (false гарантирован
    /// без мока: ни одна машина CI не имеет 879 МБ в tmp).
    #[test]
    fn layout_complete_counts_five_of_five_only() {
        // Мок-записи = layout-пути, размеры 1 Б (tmp-файлики по байту).
        let mk = |size: u64| -> Vec<ManifestEntry> {
            layout()
                .iter()
                .map(|rel| ManifestEntry {
                    role: role_for(rel).expect("роль есть").to_owned(),
                    repo: rel.split('/').next().expect("repo есть").to_owned(),
                    revision: "rev1".to_owned(),
                    file: rel.split_once('/').expect("repo/file").1.to_owned(),
                    sha256: "0".repeat(64),
                    size_bytes: size,
                })
                .collect()
        };
        let root = std::env::temp_dir().join(format!("fasad-wc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let full = root.join("full");
        std::fs::create_dir_all(&full).expect("tmp создаётся");
        for rel in layout() {
            let path = layout_path(&full, rel);
            std::fs::create_dir_all(path.parent().expect("родитель есть")).expect("дерево");
            std::fs::write(&path, b"x").expect("байт пишется");
        }
        // Полный контур: scan + all(ok) = contract `layout_complete`.
        let complete = |dir: &std::path::Path, size: u64| scan(dir, &mk(size)).iter().all(|f| f.ok);
        assert!(complete(&full, 1), "5/5 по байту = смонтировано");
        assert!(
            !complete(&full, 2),
            "размер не из манифеста = не смонтировано"
        );
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).expect("tmp создаётся");
        assert!(!complete(&empty, 1), "пустой каталог ≠ смонтировано");
        // Живой `layout_complete` на вшитом манифесте: пустой tmp = false
        // (без 879 МБ смонтированным не бывает).
        assert!(
            !layout_complete(&empty),
            "вшитый манифест на пустом = false"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_parses_all_five_rows_with_hex_sha() {
        let es = embedded_entries();
        assert_eq!(es.len(), 5, "манифест вшит полностью: {es:?}");
        for e in &es {
            assert_eq!(e.sha256.len(), 64, "{}: sha не 64-hex", e.role);
            assert!(
                e.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{}: sha не hex",
                e.role
            );
            assert!(
                !e.auto_revision(),
                "{}: @auto в рантайме не обслуживаем",
                e.role
            );
            assert!(e.size_bytes > 0, "{}: размер 0", e.role);
        }
    }

    #[test]
    fn layout_paths_resolve_through_manifest_rows() {
        // Паритет layout↔манифест: каждый путь layout = `repo/file` строки
        // манифеста (иначе кнопка качает не то, что монтирует демон).
        let es = embedded_entries();
        for rel in layout() {
            let role = role_for(rel).expect("роль известна");
            let e = entry_by_role(&es, role).unwrap_or_else(|| panic!("запись {role} в манифесте"));
            let want = format!("{}/{}", e.repo, e.file);
            assert_eq!(
                *rel,
                want.as_str(),
                "layout рассинхронизирован с манифестом"
            );
        }
    }

    #[test]
    fn arbiter_external_data_named_by_the_graph_it_belongs_to() {
        // Контракт манифеста «…_data обязательны парами»: имя веса = имя
        // графа + `_data` (рассинхрон = ort не найдёт веса при монтаже).
        assert_eq!(ARB_DATA_FILE, format!("{ARB_MODEL_FILE}_data"));
    }

    #[test]
    fn scan_reports_missing_in_empty_dir() {
        let dir = std::env::temp_dir().join(format!("fasad-w-scan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp каталог");
        let es = embedded_entries();
        let files = scan(&dir, &es);
        assert_eq!(files.len(), 5);
        assert!(files.iter().all(|f| !f.present && !f.ok));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_flags_wrong_size_as_not_ok() {
        let dir = std::env::temp_dir().join(format!("fasad-w-size-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lockR/rubert-base-pii-ner-onnx")).expect("tmp");
        let p = layout_path(&dir, LOCKR_MODEL_FILE);
        std::fs::write(&p, b"not-a-model").expect("запись");
        let es = embedded_entries();
        let files = scan(&dir, &es);
        let f = files.iter().find(|f| f.path == LOCKR_MODEL_FILE).unwrap();
        assert!(f.present && !f.ok, "размер ≠ манифест = красным: {f:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifest_parser_refuses_garbage_not_parts() {
        assert!(parse_manifest("").is_none());
        assert!(parse_manifest("# только комментарии\n").is_none());
        // 5 полей = мусорная строка = None (fail-closed, не «качаем что поняли»).
        assert!(parse_manifest("a\tb\tc\td\te\n").is_none());
        let ok = "r\trepo/x\tdeadbeef\tf.onnx\t0000000000000000000000000000000000000000000000000000000000000000\t7\thf\t-\n";
        assert_eq!(parse_manifest(ok).map(|v| v.len()), Some(1));
    }
}
