//! Загрузка весов по клику UI (`POST /v1/models/fetch`, issue #192).
//!
//! # Санкционированный сетевой файл №2 (после `proxy.rs`)
//!
//! AGENTS: «никаких сетевых вызовов кроме явного `X-Upstream-URL`» — это
//! про трафик с `ПДн`. Загрузка весов — осознанное разрешение оператора
//! (issue #192, решения в теле issue, 22.10: «fetch из UI = да, сеть HF-`allowlist`, это ЯВНАЯ пользовательская загрузка, не телеметрия»), и
//! держится она четырьмя стенками:
//!
//! 1. **Trigger.** Только явный `POST /v1/models/fetch` (клик кнопки). Демон
//!    сам не качает никогда: ни на старте, ни по таймеру.
//! 2. **Куда.** URL = `FASAD_HF_HOST` (env при старте, дефолт
//!    [`weights::DEFAULT_HF_HOST`]) + `repo/file` из **вшитого** манифеста.
//!    Хост — не запрос-параметр, в JSON тела запроса нет ни одного поля,
//!    из которого можно собрать адрес (инъекции не из чего). Схема обязана
//!    быть https, порт — только 443 (исключение: `127.0.0.1`/`localhost`
//!    c `FASAD_PROXY_LOOPBACK_HTTP=1` — тот же тестовый аффорданс, что у
//!    прокси: mock-HF на петле, TLS-терминации в тесте нет).
//! 3. **Что скачиваем.** sha256 + размер из манифеста, fail-closed:
//!    несовпадение = отказ, файл в кеш под финальным именем не попадает
//!    (`.part` + атомарный rename, паритет `scripts/fetch-models.sh:89-117`).
//!    Redirect не сопровождается: `hf.co` отдаёт 302 на CDN, а слепое
//!    сопровождение 302 = обход стенки «куда». Вместо этого — ровно один
//!    повтор на Location из `Location:`, если её авторити =
//!    `cdn-lfs.hf.co` / `cdn-lfs-us-1.hf.co` (официальный CDN HF) или совпадает
//!    с авторити запроса. Токенов в запросе нет (публичные веса).
//! 4. **Сколько.** Размер ответа ограничен размером из манифеста (поток
//!    обрывается на превышении), байты идут в файл, не в RAM (пик RSS — буфер
//!    чтения, не 523 МБ).
//!
//! Прогресс — в памяти процесса ([`crate::weights::FetchState`]), наружу только
//! через `GET /v1/status` (тот же loopback-контур, что `/health`). Скачанные
//! байты = веса: `ПДн` здесь не бывают, буферы не нужны.

use std::io::Read as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::config::Config;
use crate::weights::{self, FetchState, ManifestEntry, Phase, Progress};

/// Размер куска чтения, байт (тот же порядок, что `proxy::READ_CHUNK`).
const READ_CHUNK: usize = 64 * 1024;

/// Бюджет коннекта загрузки, мс. Отдельный от `FASAD_TIMEOUT_MS`: тот —
/// бюджет ОДНОГО запроса (80–300 мс обещаны на инференс), этот — «сколько
/// ждём TCP/TLS до 523-мегабайтного файла» (one-shot операция фона).
const CONNECT_BUDGET_MS: u64 = 30_000;

/// Классы отказа загрузки. Коды наружу — короткие машинные имена; полный
/// текст transport-ошибки `ureq` в статус не попадает (в него умеют
/// прилетать фрагменты URL, а это нарушает «sanitize: без токенов/`ПДн`»)./// HTTP-статус не 2xx/3xx (назван числом в детали).
pub const E_HTTP: &str = "http_status";
/// Транспорт: connect/DNS/TLS/обрыв потока.
pub const E_TRANSPORT: &str = "transport";
/// Поток превысил размер из манифеста.
pub const E_TOO_LARGE: &str = "too_large";
/// Размер файла ≠ манифесту.
pub const E_SIZE: &str = "size_mismatch";
/// sha256 ≠ манифесту (fail-closed: файл удалён, не принят).
pub const E_SHA: &str = "sha256_mismatch";
/// Файловая система (класс kind, без пути).
pub const E_IO: &str = "io";
/// Хост/схема вне контракта (env, redirect-allowlist).
pub const E_HOST: &str = "host_denied";
/// Каталог весов недоступен (HOME unset, fs).
pub const E_NO_DIR: &str = "no_model_dir";

/// Разрешённые редирект-цели загрузки (официальные LFS-CDN Hugging Face;
/// промер: `fetch-models.sh` ходит с `-L`, то есть CDN — часть контракта HF).
const ALLOWED_REDIRECT_HOSTS: &[&str] = &["cdn-lfs.hf.co", "cdn-lfs-us-1.hf.co"];

/// Итог одной загрузки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError {
    /// Класс отказа (машинное имя, идёт в `status` поле `fetch.error`).
    code: &'static str,
    /// Стадия/файл, на котором споткнулись (человеческий текст без `ПДн`).
    detail: String,
}

impl FetchError {
    /// Конструктор (нужен валидатору витрины, #224: тот же класс отказа, что
    /// у env-контура, собирается в одном месте).
    pub(crate) fn new(code: &'static str, detail: &str) -> Self {
        Self {
            code,
            detail: detail.to_owned(),
        }
    }

    /// Машинный класс отказа (идёт в `fetch.error`).
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Человекочитаемая деталь (классы, без путей HOME: sanitize #192).
    #[must_use]
    pub fn display_safe(&self) -> String {
        self.detail.clone()
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// Конфигурация загрузки, собранная из конфигурации демона ОДИН раз при
/// старте (`AppState::new`). Хост резолвится здесь, не на запросе: env
/// «при старте», как зафиксировано в решениях #192.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Авторити HF (`host[:port]`, без схемы): из `FASAD_HF_HOST`.
    host: String,
    /// Схема: https; http — только loopback при `FASAD_PROXY_LOOPBACK_HTTP`.
    https: bool,
    /// Каталог назначения (разрешённый `model_dir`: env или дефолт #192);
    /// `None` только на машине без `HOME` — endpoint отвечает классом.
    pub dir: Option<std::path::PathBuf>,
}

impl FetchConfig {
    /// Собрать из [`Config`] (хост + схема + каталог).
    ///
    /// # Errors
    ///
    /// [`FetchError::E_HOST`] — `FASAD_HF_HOST` не разобран как
    /// `scheme://host[:port]` (отказ на старте, не на клике: молча
    /// проигнорированный мусорный env = дырка, о которой оператор не знает).
    pub fn from_config(cfg: &Config) -> Result<Self, FetchError> {
        // #224 MAJOR-2: env > файл (тот же приоритет, что у всего config-слоя).
        // До этого слой читал ТОЛЬКО env, и файловый `FASAD_HF_HOST` был
        // мёртвым ключом: GET врал source, fetch хост не видел.
        Self::from_lookup(cfg, &|k| match std::env::var(k) {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => cfg.file_value(k).map(str::to_owned),
        })
    }

    /// Валидатор значения `FASAD_HF_HOST` = ТОТ ЖЕ парсер, что у живого
    /// контура (`split_host` + `valid_authority` + https-стенка), вызванный
    /// изолированно для `POST /v1/config` (#224 MAJOR-1/2: единая точка,
    /// второй грамматики нет).
    ///
    /// Стенка http: `http://` разрешён только петлевому upstream-хосту с
    /// `FASAD_PROXY_LOOPBACK_HTTP=1` (env, #219: флаг читается на старте) —
    /// здесь проверка консервативна: http в файле отвергается, env-контур
    /// живёт как жил (он знает про включённый флаг).
    ///
    /// # Errors
    ///
    /// [`FetchError::E_HOST`] с тем же классом, что у env-контура.
    pub fn validate_host(raw: &str, proxy_loopback_http: bool) -> Result<(), FetchError> {
        let (scheme, authority) = split_host(raw)
            .ok_or_else(|| FetchError::new(E_HOST, "не формата scheme://host[:port]"))?;
        let host = authority.to_ascii_lowercase();
        if !valid_authority(&host) {
            return Err(FetchError::new(E_HOST, "авторити с запрещёнными символами"));
        }
        // Схема: https = всегда; http = петлевой тест с env-флагом (тот же
        // аффорданс, что у прокси, `FASAD_PROXY_LOOPBACK_HTTP` читается из
        // окружения процесса = «петлевой тест», env-контур живёт как жил).
        // Прочие схемы = отказ (ревью #224: `ftp://…` проходил старый
        // валидатор, `https`-стенка fetch ловила это только на загрузке).
        match scheme {
            "https" => Ok(()),
            "http" => {
                let loopback = host == "localhost"
                    || host.split(':').next().is_some_and(|h| {
                        h.parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                    });
                // Флаг = ЭФФЕКТИВНОЕ значение контура конфига (env > файл),
                // которое передаёт вызывающий: второй правды о источнике нет
                // (#224 MAJOR-2: валидатор и рантайм обязаны сходиться).
                if loopback && proxy_loopback_http {
                    Ok(())
                } else {
                    Err(FetchError::new(
                        E_HOST,
                        "http:// к HF запрещён (только https; петлевой тест = FASAD_PROXY_LOOPBACK_HTTP + loopback)",
                    ))
                }
            }
            other => Err(FetchError::new(
                E_HOST,
                &format!("схема {other:?} не поддержана (нужен https)"),
            )),
        }
    }

    /// Чистая часть (контракт `Config::from_lookup`): `FASAD_HF_HOST` из
    /// инжектируемого источника — тесты не трогают среду процесса.
    ///
    /// # Errors
    ///
    /// См. [`Self::from_config`].
    pub fn from_lookup<L>(cfg: &Config, mut lookup: L) -> Result<Self, FetchError>
    where
        L: FnMut(&'static str) -> Option<String>,
    {
        let raw = lookup("FASAD_HF_HOST").unwrap_or_else(|| weights::DEFAULT_HF_HOST.to_owned());
        let (scheme, authority) = split_host(&raw).ok_or(FetchError {
            code: E_HOST,
            detail: "FASAD_HF_HOST не формата scheme://host[:port]".to_owned(),
        })?;
        let host = authority.to_ascii_lowercase();
        if !valid_authority(&host) {
            return Err(FetchError {
                code: E_HOST,
                detail: "FASAD_HF_HOST: авторити с запрещёнными символами".to_owned(),
            });
        }
        let loopback = host == "localhost"
            || host.split(':').next().is_some_and(|h| {
                h.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
        // https = ВСЕГДА, кроме петлевого http-исключения (тот же аффорданс, что у
        // прокси): http + флаг + loopback → http; http без исключения = отказ ниже.
        let insecure_ok = cfg.proxy_loopback_http && loopback;
        if scheme == "http" && !insecure_ok {
            return Err(FetchError {
                code: E_HOST,
                detail: "http:// к HF запрещён (только https; петлевой тест = FASAD_PROXY_LOOPBACK_HTTP + loopback)".to_owned(),
            });
        }
        let https = scheme != "http";
        Ok(Self {
            host,
            https,
            // #192: dir = Some всегда, кроме HOME-unset-машины (витрина и
            // endpoint отвечают «каталог не определён» классом, не паникой).
            dir: cfg.model_dir.clone().or_else(|| {
                // #192: дефолт подставляется на env-границе `Config::from_env`;
                // харнеси `from_lookup` её минуют — каталог резолвится здесь,
                // из env, для всех источников конфига одинаково.
                std::env::var("HOME")
                    .ok()
                    .as_deref()
                    .and_then(|h| crate::config::default_model_dir_from_home(Some(h)))
            }),
        })
    }

    /// Канонический адрес для витрины (`GET /v1/config`, #220): `scheme://host`.
    #[must_use]
    pub fn host_display(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}", self.host)
    }

    /// URL файла из манифеста. Путь собирается побайтово, без «склейки
    /// пользовательских строк»: все части — из вшитого файла (см. док модуля).
    #[must_use]
    pub fn url(&self, e: &ManifestEntry) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!(
            "{scheme}://{}/{}/resolve/{}/{}",
            self.host, e.repo, e.revision, e.file
        )
    }
}

fn split_host(raw: &str) -> Option<(&str, &str)> {
    // env-значение хоста: authority БЕЗ пути (мусор = отказ на старте, не «отрежем»).
    let raw = raw.trim().trim_end_matches('/');
    let (scheme, rest) = raw.split_once("://")?;
    if rest.is_empty() || rest.contains('/') || rest.contains(char::is_whitespace) {
        return None;
    }
    Some((scheme, rest))
}

/// Стенка хоста (env `FASAD_HF_HOST`): имя авторити обязано состоять из
/// допустимых символов host/IPv6 (включая `:` порта и скобки IPv6): `@`,
/// пробел, `{}`, управляющие — отказ. Инъекция в URL-авторити отсюда не
/// проходит.
fn valid_authority(a: &str) -> bool {
    !a.is_empty()
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Разбор `scheme://authority[/path]` (свой парсер, как `proxy::Upstream`:
/// `url`-крейта в дереве нет, и заводить его ради трёх вызовов = вторая
/// поверхность доверия).
fn split_authority(raw: &str) -> Option<(&str, &str, &str)> {
    let raw = raw.trim().trim_end_matches('/');
    let (scheme, rest) = raw.split_once("://")?;
    if rest.is_empty() || rest.contains(char::is_whitespace) || rest.contains('@') {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    Some((scheme, authority, path))
}

/// Ответ со статусом (урезано до нужного: `ureq`-конкретика не уезжает выше
/// этого модуля).
type Resp = ureq::http::Response<ureq::Body>;

/// GET одной операции загрузки (публичный: интеграционный e2e mock-HF меряет
/// транспорт, не только файлы на диске).
///
/// # Errors
///
/// [`FetchError`] класса `http_status`/`transport`/`host_denied`.
pub fn get_pub(agent: &ureq::Agent, url: &str) -> Result<Resp, FetchError> {
    get_once(agent, url)
}

/// Агент с заданным host-контуром (тесты: http-loopback без env-магии).
#[must_use]
pub fn agent_for(https: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .https_only(https)
        .max_redirects(0)
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .timeout_connect(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .timeout_send_request(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .timeout_recv_response(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Один GET с ровно одним шагом редиректа по allowlist CDN.
fn get_once(agent: &ureq::Agent, url: &str) -> Result<Resp, FetchError> {
    let (_scheme, host, _) = split_authority(url).ok_or(FetchError {
        code: E_HOST,
        detail: "собран невалидный URL (внутренняя ошибка контракта)".to_owned(),
    })?;
    let resp = agent
        .get(url)
        .header(
            "user-agent",
            concat!("fasad-fetch/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|e| {
            // Класс по `ureq::Error` (transport), текст наружу — короткий:
            // Debug-формы `ureq` в статус не пишем (может нести фрагменты
            // URL; sanitize-контракт #192).
            let _ = e;
            FetchError {
                code: E_TRANSPORT,
                detail: "connect/transport (см. stderr)".to_owned(),
            }
        })?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) && !(300..400).contains(&status) {
        return Err(FetchError {
            code: E_HTTP,
            detail: format!("HTTP {status}"),
        });
    }
    if (300..400).contains(&status) {
        // Один шаг: Location обязан быть на HF-авторити запроса или CDN-allowlist.
        let loc: Option<String> = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let Some(loc) = loc else {
            return Err(FetchError {
                code: E_HTTP,
                detail: "редирект без Location".to_owned(),
            });
        };
        let (scheme, lh) = split_host(&loc).ok_or(FetchError {
            code: E_HOST,
            detail: "редирект вне scheme://host (не CDN)".to_owned(),
        })?;
        let base_host = host.to_ascii_lowercase();
        let lh = lh.to_ascii_lowercase();
        let lh_base = lh.split(':').next().unwrap_or(&lh);
        let base_name = base_host.split(':').next().unwrap_or(&base_host);
        let allowed = lh_base == base_name || ALLOWED_REDIRECT_HOSTS.contains(&lh_base);
        if !allowed {
            return Err(FetchError {
                code: E_HOST,
                detail: "редирект на не-allowlisted хост".to_owned(),
            });
        }
        if scheme != "https" && !loopback_authority(&lh) {
            return Err(FetchError {
                code: E_HOST,
                detail: "редирект на http (не loopback-тест)".to_owned(),
            });
        }
        return agent
            .get(&loc)
            .header(
                "user-agent",
                concat!("fasad-fetch/", env!("CARGO_PKG_VERSION")),
            )
            .call()
            .map_err(|_| FetchError {
                code: E_TRANSPORT,
                detail: "connect к CDN (см. stderr)".to_owned(),
            });
    }
    Ok(resp)
}

fn loopback_authority(authority: &str) -> bool {
    authority == "localhost"
        || authority.split(':').next().is_some_and(|h| {
            h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
}

/// Скачать один файл манифеста в каталог `dir` (layout-путь) с проверкой
/// размера+sha256. Синхронный: вызывается из `spawn_blocking`.
///
/// Возвращает `true`, если файл был в кеше и сверка прошла без сети
/// (фаза `cache-hit`), `false` — если скачан.
///
/// # Errors
///
/// [`FetchError`] transport/http/io/size/sha-класса (константы `E_*`).
pub fn fetch_file(
    agent: &ureq::Agent,
    fc: &FetchConfig,
    dir: &Path,
    e: &ManifestEntry,
    rel: &'static str,
    index: usize,
    total: usize,
) -> Result<bool, FetchError> {
    let dest = weights::layout_path(dir, rel);
    let tmp = dest.with_extension("part");

    let publish = |phase: Phase, done: u64, total_bytes: u64| {
        weights::set_fetch_state(FetchState::Running {
            index,
            total,
            progress: Progress {
                file: rel,
                bytes_done: done,
                bytes_total: total_bytes,
                phase,
            },
        });
    };

    if e.auto_revision() || !is_hex64(&e.sha256) {
        // Fail-closed (#192: демон не резолвит @auto и не пишет TBD-манифест).
        return Err(FetchError {
            code: E_SHA,
            detail: format!(
                "манифест: revision/sha для {} непригодны для рантайма",
                e.role
            ),
        });
    }

    publish(Phase::Verify, 0, e.size_bytes);
    if dest.is_file() && verify_file(&dest, e)? {
        return Ok(true);
    }

    let url = fc.url(e);
    let mut resp = get_once(agent, &url)?;
    let mut body = resp.body_mut().as_reader();

    // Поток → .part + sha на лету. Кап = размер из манифеста: лишний байт =
    // E_TOO_LARGE (обрезок/подмена ловятся на сверке).
    publish(Phase::Download, 0, e.size_bytes);
    let file = std::fs::File::create(&tmp).map_err(|err| FetchError {
        code: E_IO,
        detail: format!("создать .part: {}", io_class(&err)),
    })?;
    let mut sink = CountingHash::new(file, e.size_bytes);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut last_publish =
        std::time::Instant::now().checked_sub(std::time::Duration::from_secs(60));
    loop {
        match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                sink.write(&buf[..n]).map_err(|err| FetchError {
                    code: if err.code == E_TOO_LARGE {
                        E_TOO_LARGE
                    } else {
                        E_IO
                    },
                    detail: err.detail,
                })?;
                let due = last_publish
                    .is_none_or(|t| t.elapsed() >= std::time::Duration::from_millis(500));
                if due {
                    publish(Phase::Download, sink.done, e.size_bytes);
                    last_publish = Some(std::time::Instant::now());
                }
            }
            Err(err) => {
                drop(sink);
                std::fs::remove_file(&tmp).ok();
                return Err(FetchError {
                    code: E_TRANSPORT,
                    detail: format!("чтение потока: {}", io_class(&err)),
                });
            }
        }
    }
    let got_sha = sink.finish_sha();

    publish(Phase::Verify, e.size_bytes, e.size_bytes);
    let got_size = std::fs::metadata(&tmp)
        .map_err(|err| FetchError {
            code: E_IO,
            detail: io_class(&err),
        })?
        .len();
    if e.size_bytes != 0 && got_size != e.size_bytes {
        std::fs::remove_file(&tmp).ok();
        return Err(FetchError {
            code: E_SIZE,
            detail: format!("размер {got_size} ≠ манифест {}", e.size_bytes),
        });
    }
    if !eq_hex(&e.sha256, &got_sha) {
        std::fs::remove_file(&tmp).ok();
        return Err(FetchError {
            code: E_SHA,
            detail: "sha256 не совпал с манифестом (fail-closed)".to_owned(),
        });
    }
    std::fs::rename(&tmp, &dest).map_err(|err| FetchError {
        code: E_IO,
        detail: format!("rename: {}", io_class(&err)),
    })?;
    Ok(false)
}

/// Прогон загрузки всех файлов layout (вызывается из `spawn_blocking`).
/// Каждое состояние пишется в общий слот; любое `Err` = `Failed` и остановка
/// (fail-closed: половинчатый бандл не выдаётся за готовый).
pub fn run_fetch(fc: FetchConfig, entries: Vec<ManifestEntry>) {
    #![allow(clippy::needless_pass_by_value)] // во владение фона: spawn_blocking = 'static
    let Some(dir) = fc.dir.clone() else {
        weights::set_fetch_state(FetchState::Failed {
            file: String::new(),
            error: format!("{E_NO_DIR}: каталог весов не определён"),
        });
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        // Каталог (дефолт #192) создаём лениво при загрузке — на первом клике,
        // не на старте: демон без weights-knife не обязан плодить ~/.cache.
        weights::set_fetch_state(FetchState::Failed {
            file: String::new(),
            error: format!("{E_NO_DIR}: каталог не создаётся (класс)"),
        });
        return;
    }
    let agent = build_agent(&fc);
    let total = weights::layout().len();
    for (i, rel) in weights::layout().iter().enumerate() {
        let index = i + 1;
        let Some(role) = weights::role_for(rel) else {
            weights::set_fetch_state(FetchState::Failed {
                file: (*rel).to_owned(),
                error: format!("{E_NO_DIR}: роль неизвестна (битый layout)"),
            });
            return;
        };
        let Some(entry) = weights::entry_by_role(&entries, role) else {
            weights::set_fetch_state(FetchState::Failed {
                file: (*rel).to_owned(),
                error: format!("{E_NO_DIR}: записи {role} нет в манифесте"),
            });
            return;
        };
        if let Some(sub) = dest_dir(&dir, rel)
            && let Err(e) = std::fs::create_dir_all(sub)
        {
            weights::set_fetch_state(FetchState::Failed {
                file: (*rel).to_owned(),
                error: format!("{E_NO_DIR}: каталог: {}", io_class(&e)),
            });
            return;
        }
        match fetch_file(&agent, &fc, &dir, entry, rel, index, total) {
            Ok(_cache_hit) => {}
            Err(e) => {
                eprintln!("fasad: fetch {rel}: {e}");
                weights::set_fetch_state(FetchState::Failed {
                    file: (*rel).to_owned(),
                    error: e.to_string(),
                });
                return;
            }
        }
    }
    weights::set_fetch_state(FetchState::Done { files: total });
}

fn dest_dir(dir: &Path, rel: &str) -> Option<std::path::PathBuf> {
    weights::layout_path(dir, rel)
        .parent()
        .map(std::path::Path::to_path_buf)
}

fn build_agent(fc: &FetchConfig) -> ureq::Agent {
    // Конфиг отдельного агента (не пула прокси): загрузка — долгая операция
    // вне запроса, свои бюджеты; `redirects-by-policy` — политика домена
    // (см. док модуля, стенка 3), крейт-автомат не включаем.
    let config = ureq::Agent::config_builder()
        .https_only(fc.https)
        .max_redirects(0)
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .timeout_connect(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .timeout_send_request(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .timeout_recv_response(Some(std::time::Duration::from_millis(CONNECT_BUDGET_MS)))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Файл на месте: размер по манифесту + sha256 (кеш-хит валидируется
/// пересчётом, а не доверием к существованию — паритет `fetch-models.sh`).
fn verify_file(path: &Path, e: &ManifestEntry) -> Result<bool, FetchError> {
    let meta = std::fs::metadata(path).map_err(|err| FetchError {
        code: E_IO,
        detail: io_class(&err),
    })?;
    if e.size_bytes != 0 && meta.len() != e.size_bytes {
        return Ok(false);
    }
    let mut f = std::fs::File::open(path).map_err(|err| FetchError {
        code: E_IO,
        detail: io_class(&err),
    })?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|err| FetchError {
            code: E_IO,
            detail: io_class(&err),
        })?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(eq_hex(&e.sha256, &hex_lower(h.finalize().as_slice())))
}

/// Поток в файл с подсчётом sha256 и капом по размеру.
struct CountingHash {
    file: std::fs::File,
    hasher: Sha256,
    done: u64,
    cap: u64,
}

impl CountingHash {
    fn new(file: std::fs::File, cap: u64) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            done: 0,
            cap,
        }
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), FetchError> {
        use std::io::Write as _;
        self.done += bytes.len() as u64;
        if self.cap != 0 && self.done > self.cap {
            return Err(FetchError {
                code: E_TOO_LARGE,
                detail: format!("поток превысил размер манифеста ({} Б)", self.cap),
            });
        }
        self.hasher.update(bytes);
        self.file.write_all(bytes).map_err(|e| FetchError {
            code: E_IO,
            detail: io_class(&e),
        })
    }
    fn finish_sha(self) -> String {
        hex_lower(self.hasher.finalize().as_slice())
    }
}

fn io_class(err: &std::io::Error) -> String {
    // Класс, не полный Debug: путь файла лежит в строке os-ошибки и в
    // Debug-формате — в статусе путь домашний не светится (sanitize #192).
    match err.kind() {
        std::io::ErrorKind::NotFound => "not_found".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission_denied".to_owned(),
        std::io::ErrorKind::StorageFull => "storage_full".to_owned(),
        k => format!("io({k:?})"),
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn eq_hex(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

fn hex_lower(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[usize::from(b >> 4)] as char);
        s.push(D[usize::from(b & 0xf)] as char);
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    #[test]
    fn host_parsing_refuses_garbage() {
        assert!(split_host("https://huggingface.co").is_some());
        assert!(split_host("http://127.0.0.1:8099").is_some());
        assert!(split_host("huggingface.co").is_none());
        assert!(split_host("https://host/path").is_none());
        assert!(split_host("https:// host").is_none());
        assert!(split_host("https://").is_none());
        assert!(valid_authority("huggingface.co"));
        assert!(valid_authority("127.0.0.1:8099"));
        assert!(valid_authority("[::1]:8099"));
        assert!(!valid_authority("user@evil.test"));
        assert!(!valid_authority("a b"));
        assert!(!valid_authority(""));
    }

    fn make_cfg(loopback_http: bool) -> Config {
        let flag = loopback_http;
        Config::from_lookup(move |k| match k {
            "FASAD_PROXY_LOOPBACK_HTTP" if flag => Some("1".to_owned()),
            _ => None,
        })
        .expect("конфиг пробы")
    }

    #[test]
    fn hf_host_env_decides_scheme_and_loopback_exception() {
        // Дефолт: https, без env.
        let fc = FetchConfig::from_lookup(&make_cfg(false), &|_| None).expect("дефолт");
        assert!(fc.https);
        // http наружу = отказ, даже с loopback-флагом прокси (флаг про петлю).
        let e = FetchConfig::from_lookup(&make_cfg(true), &|_| Some("http://evil.test".to_owned()))
            .expect_err("http наружу запрещён");
        assert_eq!(e.code(), E_HOST);
        // http на loopback + флаг = легален (тот же аффорданс, что у прокси).
        // Проверка = публичный `url()` (контракт, а не поле): scheme-префикс
        // обязан быть http (иначе mock-HF на петле = self-TLS-тупик).
        let fc = FetchConfig::from_lookup(&make_cfg(true), &|_| {
            Some("http://127.0.0.1:8099".to_owned())
        })
        .expect("loopback-тест");
        let probe = ManifestEntry {
            role: "r".into(),
            repo: "o/n".into(),
            revision: "rev".into(),
            file: "f.onnx".into(),
            sha256: "0".repeat(64),
            size_bytes: 1,
        };
        assert!(
            fc.url(&probe).starts_with("http://127.0.0.1:8099/"),
            "петлевое исключение не применено: {}",
            fc.url(&probe)
        );
        // Мусор = отказ классом (старт жив, endpoint краснеет честно).
        let e = FetchConfig::from_lookup(&make_cfg(false), &|_| Some("мусор".to_owned()))
            .expect_err("host не разбирается");
        assert_eq!(e.code(), E_HOST);
    }

    #[test]
    fn sha_mismatch_is_classified_without_paths() {
        let e = FetchError {
            code: E_SHA,
            detail: "sha256 не совпал с манифестом (fail-closed)".to_owned(),
        };
        let shown = e.to_string();
        assert!(shown.starts_with(E_SHA), "{shown}");
        assert!(!shown.contains('/'), "путь в статусе: {shown}");
    }

    #[test]
    fn url_is_built_from_manifest_parts() {
        let fc = FetchConfig {
            host: "huggingface.co".to_owned(),
            https: true,
            dir: Some(std::path::PathBuf::from("/tmp/x")),
        };
        let e = ManifestEntry {
            role: "r".into(),
            repo: "owner/name".into(),
            revision: "cafe".into(),
            file: "onnx/model.onnx".into(),
            sha256: "0".repeat(64),
            size_bytes: 1,
        };
        assert_eq!(
            fc.url(&e),
            "https://huggingface.co/owner/name/resolve/cafe/onnx/model.onnx"
        );
    }

    #[test]
    fn hex_helpers() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(eq_hex("aB0", "Ab0"));
        assert_eq!(hex_lower(&[0x0a, 0xff]), "0aff");
    }
}
