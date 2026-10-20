//! Прокси `POST /v1/chat/completions` (SPEC §8, шаг 7c).
//!
//! # Две стенки
//!
//! Это единственное место демона, откуда уходит наружу трафик, и единственное,
//! куда чужой трафик приходит без мандата клиента. Отсюда две стенки:
//!
//! 1. **Куда.** Адрес берётся только из `X-Upstream-URL` и только если он в
//!    `FASAD_UPSTREAM_ALLOWLIST` (AGENTS: «никаких сетевых вызовов кроме явного
//!    `X-Upstream-URL`»). Пустой список = прокси выключен (`403
//!    allowlist_empty`), а не «разрешено всё»: open redirector из гарда делает
//!    второй продукт, и он опаснее первого.
//! 2. **Что.** Наружу уходит **замаскированный** запрос (тот же конвейер, что у
//!    `/v1/analyze` + `/v1/anonymize`), обратно — развёрнутый. Полей контракта
//!    `OpenAI` не добавляется и не убирается: правятся только речевые строки.
//!
//! # Порядок блоков маскирования (law #53)
//!
//! Разметка чувствительна к порядку блоков (#53: перестановка сдвигает row-recall
//! на десятки пунктов), поэтому обход заморожен и выражен одной функцией
//! [`block_index`]: `messages[]` по индексу, внутри `content[]` по индексу,
//! только текстовые части. Порядок — предмет теста
//! [`tests::blocks_are_in_document_order`], равенство разметки с `/v1/analyze` на
//! том же тексте — теста `proxy_mask_matches_the_analyze_api_span_for_span`
//! в `tests/wire_e2e.rs`.
//!
//! # Политика на этом маршруте
//!
//! `X-Guard-Policy: block` уважается (запрос не уходит), `mask` — дефолт,
//! `audit_only` **отклоняется** (`400 policy_not_applicable`): на маршруте, где
//! тело уходит третьей стороне, «только посчитать и пропустить» означает, что
//! клиентским заголовком снимается с гарда его единственная работа. Такой
//! переключатель и есть fail-open, а им снаружи не управляют.
//!
//! # Таймауты и почему их три
//!
//! * входящее тело клиента — тишина дольше `FASAD_READ_TIMEOUT_MS` между кусками
//!   = `408 read_timeout`; не 413: перелив и молчание суть разные отказы, а
//!   подмена причины отправляет чинить не то (AGENTS «ложь о причине отказа»,
//!   README §Fail-closed п.4);
//! * коннект, отправка и TTFB upstream — `FASAD_TIMEOUT_MS` = `504
//!   upstream_timeout` с названием стадии;
//! * чтение ответа — `FASAD_READ_TIMEOUT_MS`; для стрима это бюджет **всего**
//!   ответа, потому что у `ureq 3.4.2` нет таймаута на паузу между чтениями
//!   (промер `ureq-3.4.2/src/config.rs:905-932`: поля `Timeouts` — `global`,
//!   `per_call`, `resolve`, `connect`, `send_request`, `await_100`,
//!   `send_body`, `recv_response`, `recv_body`; меж-кадрового idle нет). Оговорка стоит того, чтобы быть названной: длинную
//!   генерацию нужно поднимать переменной, а не надеяться на дефолт.

use std::io::Read as _;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::http::{self, ApiError, AppState, h, insert, json_body, session_of};
use crate::pipeline::{self, AnalyzeRequest, Policy};
use crate::sse::{self, Relay, RelayError};
use crate::vault::SpanIn;

/// Заголовок, из которого прокси берёт адрес upstream (SPEC §8).
pub const HEADER_UPSTREAM: &str = "x-upstream-url";

/// Размер куска чтения upstream-тела, байт.
const READ_CHUNK: usize = 8 * 1024;

/// Ответ upstream: `http::Response` с телом-потоком `ureq`.
type UpstreamResponse = ureq::http::Response<ureq::Body>;

/// Причина отказа прокси, каждая со своим HTTP-кодом и машинным именем.
///
/// Коды не склеиваются: `502 upstream_unreachable` и `504 upstream_timeout`
/// требуют от клиента разных действий, а `403 allowlist_denied` и `403
/// allowlist_empty` — разных правок конфигурации.
#[derive(Debug)]
pub enum ProxyError {
    /// Заголовка `X-Upstream-URL` нет.
    MissingHeader,
    /// Заголовок дан дважды.
    DuplicateHeader,
    /// Список разрешённых хостов пуст — прокси выключен конфигурацией.
    AllowlistEmpty,
    /// Хост не в списке.
    Denied {
        /// Что просили (только хост: путь может быть данными).
        host: String,
    },
    /// Значение заголовка не является `scheme://host[:port]/path`.
    BadUrl,
    /// `http://` там, где конфигурация его не разрешает.
    Insecure,
    /// Запрошена политика, которую на этом маршруте применить нельзя.
    PolicyNotApplicable,
    /// `X-Guard-Policy: block`, и текст содержит `ПДн`: запрос не отправлен.
    Blocked,
    /// Соединение или резолв не удались.
    Unreachable,
    /// `TLS` не сложился (цепочка, сертификат, рукопожатие).
    Tls,
    /// Upstream ответил редиректом; сопровождать запрещено.
    Redirect,
    /// Ответ нарушает протокол.
    Protocol,
    /// Таймаут с названной стадией.
    Timeout(&'static str),
    /// Тело ответа больше `max_body_bytes`.
    TooLarge {
        /// Предел, байт.
        limit: usize,
    },
    /// Тело запроса — не `OpenAI`-контракт (`messages` нет или не массив).
    NotChatRequest,
    /// Задачу-насос убил клиент (канал закрыт).
    Aborted,
    /// Хранилище отказало на развороте ответа.
    Vault(crate::vault::VaultApiError),
}

impl ProxyError {
    /// HTTP-код отказа.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::MissingHeader
            | Self::DuplicateHeader
            | Self::BadUrl
            | Self::NotChatRequest
            | Self::PolicyNotApplicable => StatusCode::BAD_REQUEST,
            Self::AllowlistEmpty | Self::Denied { .. } | Self::Insecure | Self::Blocked => {
                StatusCode::FORBIDDEN
            }
            Self::Unreachable | Self::Tls | Self::Redirect | Self::Protocol | Self::Aborted => {
                StatusCode::BAD_GATEWAY
            }
            Self::Vault(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    /// Машинный код контракта `{"error":{"code":…}}`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_upstream",
            Self::DuplicateHeader | Self::BadUrl => "bad_upstream_url",
            Self::AllowlistEmpty => "allowlist_empty",
            Self::Denied { .. } => "allowlist_denied",
            Self::Insecure => "insecure_upstream",
            Self::PolicyNotApplicable => "policy_not_applicable",
            Self::Blocked => "blocked_by_policy",
            Self::Unreachable => "upstream_unreachable",
            Self::Tls => "upstream_tls",
            Self::Redirect => "upstream_redirect",
            Self::Protocol => "upstream_protocol",
            Self::Timeout(_) => "upstream_timeout",
            Self::TooLarge { .. } => "upstream_too_large",
            Self::NotChatRequest => "bad_json",
            Self::Aborted => "client_aborted",
            Self::Vault(_) => "vault_error",
        }
    }

    /// Разбор ошибки `ureq` в нашу: у `ureq::Error::Timeout` есть *фаза*, и мы
    /// её транслируем, а не сваливаем в безликую «upstream не ответил».
    ///
    /// `StatusCode` сюда не попадает: агент собран с
    /// `http_status_as_error(false)`, то есть `4xx`/`5xx` upstream — это ответ,
    /// а не ошибка, и мы пробрасываем его код как есть.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "стадии таймаута достаются из значения: по ссылке пришлось бы держать временный Error"
    )]
    fn from_ureq(err: ureq::Error) -> Self {
        use ureq::Error as U;
        match err {
            U::Timeout(phase) => Self::Timeout(match phase {
                ureq::Timeout::Connect => "connect",
                ureq::Timeout::Resolve => "resolve",
                ureq::Timeout::SendRequest => "send-request",
                ureq::Timeout::SendBody => "send-body",
                ureq::Timeout::RecvResponse => "recv-response",
                ureq::Timeout::RecvBody => "recv-body",
                ureq::Timeout::Global => "global",
                _ => "unknown",
            }),
            U::TooManyRedirects | U::RedirectFailed => Self::Redirect,
            U::RequireHttpsOnly(_) => Self::Insecure,
            U::ConnectionFailed | U::HostNotFound | U::Io(_) => Self::Unreachable,
            U::Tls(_) => Self::Tls,
            _ => Self::Protocol,
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader => write!(f, "нет заголовка {HEADER_UPSTREAM}"),
            Self::DuplicateHeader => write!(f, "{HEADER_UPSTREAM} дан более одного раза"),
            Self::AllowlistEmpty => write!(f, "FASAD_UPSTREAM_ALLOWLIST пуст, прокси выключен"),
            Self::Denied { host } => write!(f, "хост {host} не в FASAD_UPSTREAM_ALLOWLIST"),
            Self::BadUrl => {
                write!(
                    f,
                    "{HEADER_UPSTREAM} не разбирается как scheme://host[:port]/path"
                )
            }
            Self::Insecure => write!(
                f,
                "http:// запрещено; нужен https или FASAD_PROXY_LOOPBACK_HTTP=1 на loopback"
            ),
            Self::PolicyNotApplicable => write!(
                f,
                "X-Guard-Policy audit_only на прокси не применяется (см. доку модуля)"
            ),
            Self::Blocked => {
                write!(
                    f,
                    "X-Guard-Policy block, и текст содержит ПДн: запрос не отправлен"
                )
            }
            Self::Unreachable => write!(f, "upstream недоступен"),
            Self::Tls => write!(f, "TLS-сессия с upstream не установлена"),
            Self::Redirect => write!(f, "upstream ответил редиректом, сопровождение запрещено"),
            Self::Protocol => write!(f, "upstream нарушил протокол"),
            Self::Timeout(stage) => write!(f, "таймаут upstream на стадии {stage}"),
            Self::TooLarge { limit } => write!(f, "ответ upstream больше {limit} байт"),
            Self::NotChatRequest => write!(f, "тело запроса не содержит массива messages"),
            Self::Aborted => write!(f, "клиент отключился во время стрима"),
            Self::Vault(err) => write!(f, "хранилище: {err}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<crate::vault::VaultApiError> for ProxyError {
    fn from(err: crate::vault::VaultApiError) -> Self {
        Self::Vault(err)
    }
}

impl From<ProxyError> for ApiError {
    fn from(err: ProxyError) -> Self {
        Self::new(err.status(), err.code(), &err.to_string())
    }
}

/// Схема адреса upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `https://` — единственный разрешённый по умолчанию.
    Https,
    /// `http://` — только loopback и только с `FASAD_PROXY_LOOPBACK_HTTP=1`.
    Http,
}

/// Разобранный `X-Upstream-URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Схема.
    pub scheme: Scheme,
    /// Хост в нижнем регистре (`IPv6` — без скобок).
    pub host: String,
    /// Порт: явный или по умолчанию для схемы.
    pub port: u16,
    /// Путь с запросом, включая ведущий `/`.
    pub path: String,
}

impl Upstream {
    /// Разбор значения заголовка.
    ///
    /// Парсер свой: `_url` в `ureq` намеренно выключен
    /// (`docs/dep-verify-crates.md` §14), а тянуть отдельный крейт ради одного
    /// заголовка — значит расширять поверхность доверия ради удобства.
    ///
    /// # Errors
    ///
    /// [`ProxyError::BadUrl`] на всё, что не является абсолютным `URL` без учёных
    /// данных, пробелов и `CRLF`.
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        let raw = raw.trim();
        let (scheme, rest) = raw
            .strip_prefix("https://")
            .map(|r| (Scheme::Https, r))
            .or_else(|| raw.strip_prefix("http://").map(|r| (Scheme::Http, r)))
            .ok_or(ProxyError::BadUrl)?;
        if rest.is_empty() || rest.contains(char::is_whitespace) || rest.contains('\\') {
            return Err(ProxyError::BadUrl);
        }
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(ProxyError::BadUrl);
        }
        let (host, port) = split_authority(authority, scheme)?;
        if path.contains(['\r', '\n']) {
            // CRLF в пути = попытка дописать к запросу заголовок.
            return Err(ProxyError::BadUrl);
        }
        Ok(Self {
            scheme,
            host,
            port,
            path: path.to_owned(),
        })
    }

    /// Итоговый `URL` для клиента.
    #[must_use]
    pub fn url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{scheme}://{host}:{}{}", self.port, self.path)
    }

    /// Проверка конфигурацией: пустой список, хост, схема. Отказ называет свою
    /// причину, потому что `allowlist_empty` и `allowlist_denied` чинятся разными
    /// правками `env`.
    ///
    /// # Errors
    ///
    /// [`ProxyError::AllowlistEmpty`], [`ProxyError::Denied`],
    /// [`ProxyError::Insecure`].
    pub fn check(&self, cfg: &Config) -> Result<(), ProxyError> {
        if cfg.upstream_allowlist.is_empty() {
            return Err(ProxyError::AllowlistEmpty);
        }
        if !cfg
            .upstream_allowlist
            .iter()
            .any(|a| a.matches(&self.host, self.port))
        {
            return Err(ProxyError::Denied {
                host: self.host.clone(),
            });
        }
        if self.scheme == Scheme::Http && (!cfg.proxy_loopback_http || !is_loopback(&self.host)) {
            return Err(ProxyError::Insecure);
        }
        Ok(())
    }
}

/// Хост + порт из authority-части (IPv6 в скобках поддерживается).
fn split_authority(authority: &str, scheme: Scheme) -> Result<(String, u16), ProxyError> {
    let fallback = default_port(scheme);
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (inner, tail) = bracketed.split_once(']').ok_or(ProxyError::BadUrl)?;
        if inner.is_empty() {
            return Err(ProxyError::BadUrl);
        }
        let port = port_after_colon(tail)?.unwrap_or(fallback);
        return Ok((inner.to_ascii_lowercase(), port));
    }
    if authority.contains(']') {
        return Err(ProxyError::BadUrl);
    }
    // Порт ищем справа от последнего `:`: голый хост и IPv4 без порта попадают
    // в ветку `None`, а `:8080` — в ветку цифр.
    let (host, digits) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        Some((h, "")) => (h, None),
        Some(_) => return Err(ProxyError::BadUrl),
        None => (authority, None),
    };
    if host.is_empty() || host.contains('/') {
        return Err(ProxyError::BadUrl);
    }
    let port = digits.map(parse_digits).transpose()?.unwrap_or(fallback);
    Ok((host.to_ascii_lowercase(), port))
}

/// Порт из хвоста вида `":8080"`; пустой хвост = `None`; `8080` без двоеточия =
/// отказ (это не порт, а продолжение хоста).
fn port_after_colon(tail: &str) -> Result<Option<u16>, ProxyError> {
    if tail.is_empty() {
        return Ok(None);
    }
    let digits = tail.strip_prefix(':').ok_or(ProxyError::BadUrl)?;
    parse_digits(digits).map(Some)
}

/// Цифры порта: только десятичные, без знака, `1..=65535`.
fn parse_digits(raw: &str) -> Result<u16, ProxyError> {
    if raw.is_empty() || raw.len() > 5 || !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(ProxyError::BadUrl);
    }
    let port: u32 = raw.parse().map_err(|_| ProxyError::BadUrl)?;
    let port = u16::try_from(port).map_err(|_| ProxyError::BadUrl)?;
    if port == 0 {
        return Err(ProxyError::BadUrl);
    }
    Ok(port)
}

/// Порт по умолчанию для схемы.
const fn default_port(scheme: Scheme) -> u16 {
    match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    }
}

/// Loopback-имя или loopback-адрес (исключение `FASAD_PROXY_LOOPBACK_HTTP`).
fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Пул клиентов: два `ureq::Agent` с разными бюджетами чтения.
#[derive(Debug, Clone)]
pub struct Client {
    /// Ответ читается целиком: бюджет `FASAD_READ_TIMEOUT_MS` на тело.
    buffered: ureq::Agent,
    /// Ответ читается по кадрам: бюджет на **всю** операцию, потому что
    /// idle-таймаута на паузу между чтениями у крейта нет (доку модуля).
    streaming: ureq::Agent,
}

impl Client {
    /// Собран из конфигурации; строится один раз при старте ([`AppState::new`]).
    ///
    /// Пул держится, иначе на каждое сообщение чата — новый `TLS`-рукопожатие, а
    /// бюджет латентности у демона 80-300 мс (SPEC §1).
    ///
    /// `https_only` включён, кроме случая, когда оператор явно разрешил
    /// loopback-`http`: тогда стенку «не наружу» держит [`Upstream::check`], и
    /// держит до отправки — тест `http_needs_the_loopback_exception` это меряет.
    #[must_use]
    pub fn new(cfg: &Config) -> Self {
        let connect = Duration::from_millis(cfg.timeout_ms);
        let read = Duration::from_millis(cfg.read_timeout_ms);
        let make = |recv_body: Option<Duration>, global: Option<Duration>| {
            let config = ureq::Agent::config_builder()
                .https_only(!cfg.proxy_loopback_http)
                .max_redirects(0)
                .max_redirects_will_error(true)
                .http_status_as_error(false)
                .timeout_connect(Some(connect))
                .timeout_send_request(Some(connect))
                .timeout_send_body(Some(connect))
                .timeout_recv_response(Some(connect))
                .timeout_recv_body(recv_body)
                .timeout_global(global)
                .build();
            ureq::Agent::new_with_config(config)
        };
        Self {
            buffered: make(Some(read), None),
            streaming: make(None, Some(read)),
        }
    }

    /// `POST` с телом; заголовки — только переносимые (см. [`carry_headers`]).
    ///
    /// # Errors
    ///
    /// [`ProxyError`] transport-класса: [`ProxyError::Timeout`],
    /// [`ProxyError::Unreachable`], [`ProxyError::Tls`], [`ProxyError::Redirect`],
    /// [`ProxyError::Insecure`], [`ProxyError::Protocol`].
    pub fn post(
        &self,
        upstream: &Upstream,
        carried: &[(HeaderName, HeaderValue)],
        body: &[u8],
        stream: bool,
    ) -> Result<UpstreamResponse, ProxyError> {
        let agent = if stream {
            &self.streaming
        } else {
            &self.buffered
        };
        let mut req = agent.post(upstream.url());
        for (name, value) in carried {
            req = req.header(name.clone(), value.clone());
        }
        req = req.header("content-type", "application/json");
        if stream {
            req = req.header("accept", "text/event-stream");
        }
        req.send(body).map_err(ProxyError::from_ureq)
    }
}

/// HTTP-обработчик маршрута `POST /v1/chat/completions`.
pub async fn handle(State(st): State<AppState>, req: Request) -> Response {
    let started = Instant::now();
    let (headers, body) = match http::read_body(st.clone(), req).await {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    let upstream = match parse_upstream_header(&headers) {
        Ok(u) => u,
        Err(err) => return err.into_response(),
    };
    let policy = match http::parse_policy(&headers) {
        Ok(p) => p,
        Err(err) => return err.into_response(),
    };
    if policy == Policy::AuditOnly {
        return ApiError::from(ProxyError::PolicyNotApplicable).into_response();
    }
    // Порядок отказов: сначала то, что клиент обязан исправить в запросе
    // (заголовок, политика, сессия), потом конфигурация. Иначе `audit_only`
    // на неизвестном хосте получает «хост не в списке» — правка env не лечит
    // настоящую причину, и это тот же класс лжи о причине отказа.
    if let Err(err) = upstream.check(st.config()) {
        return ApiError::from(err).into_response();
    }
    let session = match session_of(&headers) {
        Ok(s) => s.map(str::to_owned),
        Err(err) => return err.into_response(),
    };
    let carried = carry_headers(&headers);
    let masked = match guarded_mask(&st, &body, session.as_deref(), &headers, policy) {
        Ok(m) => m,
        Err(err) => return err.into_response(),
    };
    let mut extra = HeaderMap::new();
    insert(&mut extra, h::COUNT, masked.count);
    insert(&mut extra, h::LATENCY, started.elapsed().as_millis());
    insert(&mut extra, h::STAGE, st.config().stage());
    let result = if masked.stream {
        stream_through(&st, upstream, carried, masked.body, session).await
    } else {
        buffer_through(&st, upstream, carried, masked.body, session).await
    };
    match result {
        Ok(mut resp) => {
            for (name, value) in extra {
                if let Some(name) = name {
                    resp.headers_mut().append(name, value);
                }
            }
            resp
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

/// Разбор и проверка `X-Upstream-URL`.
fn parse_upstream_header(headers: &HeaderMap) -> Result<Upstream, ApiError> {
    let mut values = headers.get_all(HEADER_UPSTREAM).iter();
    let raw = match (values.next(), values.next()) {
        (None, _) => return Err(ProxyError::MissingHeader.into()),
        (Some(_), Some(_)) => return Err(ProxyError::DuplicateHeader.into()),
        (Some(v), None) => v,
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::from(ProxyError::BadUrl))?;
    Ok(Upstream::parse(raw)?)
}

/// Заголовки, переносимые на upstream.
///
/// Ровно два кредита: без них прокси бесполезен для платных `API`, и ровно они,
/// потому что `User-Agent`/`Cookie`/`X-Request-Id` наружу — это fingerprinting-
/// канал, которого гард обеспечивать не обязан. `content-type` ставим сами.
fn carry_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    const CARRIED: [&str; 2] = ["authorization", "x-api-key"];
    CARRIED
        .iter()
        .filter_map(|name| {
            HeaderName::from_bytes(name.as_bytes())
                .ok()
                .and_then(|n| headers.get(&n).cloned().map(|v| (n, v)))
        })
        .collect()
}

/// Что дала маскировка запроса.
struct Masked {
    /// Сериализованное тело, готовое к отправке.
    body: Vec<u8>,
    /// Сколько спанов замаскировано (йдёт в `X-Guard-Redacted-Count`).
    count: usize,
    /// Флаг `stream` из тела запроса.
    stream: bool,
}

/// Маскирование в `panic`-обёртке: тот же контракт, что у [`http::guarded`].
fn guarded_mask(
    st: &AppState,
    body: &[u8],
    session: Option<&str>,
    headers: &HeaderMap,
    policy: Policy,
) -> Result<Masked, ApiError> {
    let closure = || mask_request(st, body, session, headers, policy);
    match std::panic::catch_unwind(AssertUnwindSafe(closure)) {
        Ok(Ok(masked)) => Ok(masked),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(ApiError::panic()),
    }
}

/// Маскирование тела запроса: один `analyze` + `anonymize` на текстовый блок.
///
/// Тот же конвейер и те же руки, что у `/v1/analyze` → `/v1/anonymize`, поэтому
/// спаны идентичны (см. parity-тест). Отказ конвейера = запрос наружу не уходит
/// (AGENTS, Fail-Closed): в частности поэтому `audit_only` на маршруте отклонён,
/// а не реализован как «пропустили без маскировки».
fn mask_request(
    st: &AppState,
    raw: &[u8],
    session: Option<&str>,
    headers: &HeaderMap,
    policy: Policy,
) -> Result<Masked, ApiError> {
    let mut body: serde_json::Value = json_body(raw).map_err(|_| ProxyError::NotChatRequest)?;
    if !body
        .get("messages")
        .is_some_and(serde_json::Value::is_array)
    {
        // Прокси «как есть» здесь не вариант: тогда наружу уйдёт оригинал ПДн в
        // поле, которого мы не видели, и гард перестанет быть гардом.
        return Err(ProxyError::NotChatRequest.into());
    }
    let stream = body
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let threshold = client_threshold(headers, st.config());
    let mut count = 0_usize;
    for slot in block_index(&body) {
        // Индексы отдельно от заимствования: `block_index` читает дерево,
        // переписывание — по позиции, иначе `serde_json` нас не пустит.
        let Some(text) = read_slot(&body, &slot) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        let req = AnalyzeRequest {
            text: Zeroizing::new(text.to_owned()),
            entities: None,
            score_threshold: threshold,
        };
        let analysis = pipeline::analyze(&req, st.schema(), st.config(), policy)
            .map_err(ApiError::from_analysis)?;
        if policy == Policy::Block && !analysis.spans.is_empty() {
            return Err(ProxyError::Blocked.into());
        }
        let spans: Vec<SpanIn> = analysis
            .spans
            .iter()
            .map(|s| SpanIn {
                entity_type: s.entity_type.clone(),
                byte_start: s.byte_start,
                byte_end: s.byte_end,
            })
            .collect();
        count += spans.len();
        let masked = st
            .vault()
            .anonymize(session, text, &spans, st.schema())
            .map_err(|e| ApiError::from_vault(&e))?
            .text;
        write_slot(&mut body, &slot, &masked);
    }
    let out = serde_json::to_vec(&body).map_err(|_| ProxyError::Protocol)?;
    Ok(Masked {
        body: out,
        count,
        stream,
    })
}

/// Позиция текстового блока в дереве запроса (без заимствования).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    message: usize,
    part: Option<usize>,
}

/// Замороженный порядок обхода: `messages[]`, затем `content[]`, только части с
/// текстовым полем `text`.
///
/// Изменение этого порядка = изменение разметки = правка метрик молча, поэтому
/// порядок здесь единственный, и на него есть тест.
fn block_index(body: &serde_json::Value) -> Vec<Slot> {
    let mut out = Vec::new();
    let Some(messages) = body.get("messages").and_then(serde_json::Value::as_array) else {
        return out;
    };
    for (mi, msg) in messages.iter().enumerate() {
        let Some(content) = msg.get("content") else {
            continue;
        };
        match content {
            serde_json::Value::String(_) => out.push(Slot {
                message: mi,
                part: None,
            }),
            serde_json::Value::Array(parts) => {
                for (pi, part) in parts.iter().enumerate() {
                    if part.get("text").is_some_and(serde_json::Value::is_string) {
                        out.push(Slot {
                            message: mi,
                            part: Some(pi),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Прочитать блок по позиции.
fn read_slot<'a>(body: &'a serde_json::Value, slot: &Slot) -> Option<&'a str> {
    let content = body
        .get("messages")?
        .as_array()?
        .get(slot.message)?
        .get("content")?;
    match slot.part {
        None => content.as_str(),
        Some(pi) => content.as_array()?.get(pi)?.get("text")?.as_str(),
    }
}

/// Записать блок по позиции; отсутствие пути = тихий пропуск: контракт запроса
/// правками не дополняем.
fn write_slot(body: &mut serde_json::Value, slot: &Slot, text: &str) {
    let Some(msgs) = body
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    let Some(msg) = msgs.get_mut(slot.message) else {
        return;
    };
    match slot.part {
        None => {
            if msg.get("content").is_some_and(serde_json::Value::is_string) {
                msg["content"] = serde_json::Value::String(text.to_owned());
            }
        }
        Some(pi) => {
            if let Some(serde_json::Value::Array(parts)) = msg.get_mut("content") {
                if let Some(part) = parts.get_mut(pi) {
                    if part.get("text").is_some_and(serde_json::Value::is_string) {
                        part["text"] = serde_json::Value::String(text.to_owned());
                    }
                }
            }
        }
    }
}

/// Порог из заголовка: клиент вправе только поднять планку (правило то же, что у
/// `/v1/analyze`), и ниже config-`τ_low` он не опустится.
fn client_threshold(headers: &HeaderMap, cfg: &Config) -> Option<f64> {
    headers
        .get(h::THRESHOLD)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v) && *v >= cfg.thresholds.tau_low)
}

/// Буферизованный ответ: читаем целиком, разворачиваем, отдаём целиком.
async fn buffer_through(
    st: &AppState,
    upstream: Upstream,
    carried: Vec<(HeaderName, HeaderValue)>,
    masked: Vec<u8>,
    session: Option<String>,
) -> Result<Response, ProxyError> {
    let st2 = st.clone();
    let resp =
        tokio::task::spawn_blocking(move || st2.client().post(&upstream, &carried, &masked, false))
            .await
            .map_err(|_| ProxyError::Aborted)??;
    let status = resp.status();
    let content_type = resp.headers().get("content-type").cloned();
    let body = read_capped(resp, st.config().max_body_bytes)?;
    let (bytes, restored) = deanonymize_json_body(st, session.as_deref(), &body)?;
    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    if let Some(ct) = content_type {
        out.headers_mut().insert("content-type", ct);
    }
    report_restored(out.headers_mut(), &restored);
    Ok(out)
}

/// Отчёт о развороте буферизованного ответа заголовками.
///
/// Пишем только ненулевое: `absent` лучше фиктивного нуля (та же логика, что у
/// `guard_headers`), и «мы не посмотрели» не должно читаться как «всё чисто».
fn report_restored(headers: &mut HeaderMap, restored: &Restored) {
    if restored.unresolved > 0 {
        insert(headers, h::UNRESOLVED, restored.unresolved);
    }
    if restored.malformed {
        insert(headers, h::MALFORMED, 1);
    }
}

/// Стрим: заголовок Known до тела, тело льётся из блокирующей задачи.
async fn stream_through(
    st: &AppState,
    upstream: Upstream,
    carried: Vec<(HeaderName, HeaderValue)>,
    masked: Vec<u8>,
    session: Option<String>,
) -> Result<Response, ProxyError> {
    let st2 = st.clone();
    let resp =
        tokio::task::spawn_blocking(move || st2.client().post(&upstream, &carried, &masked, true))
            .await
            .map_err(|_| ProxyError::Aborted)??;
    let status = resp.status();
    let content_type = resp.headers().get("content-type").cloned();
    let streamed = content_type
        .as_ref()
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    if !streamed {
        // `stream: true`, а пришёл обычный JSON: разворачиваем буфером и отдаём
        // как есть — не выдаём не-SSE за SSE.
        let body = read_capped(resp, st.config().max_body_bytes)?;
        let (bytes, restored) = deanonymize_json_body(st, session.as_deref(), &body)?;
        let mut out = Response::new(Body::from(bytes));
        *out.status_mut() = status;
        report_restored(out.headers_mut(), &restored);
        return Ok(out);
    }
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, (String, String)>>(64);
    let st3 = st.clone();
    tokio::task::spawn_blocking(move || {
        let pumped = std::panic::catch_unwind(AssertUnwindSafe(|| {
            pump_sse(&st3, resp, session.as_deref(), &tx);
        }));
        if pumped.is_err() {
            let _ = tx.blocking_send(Err((
                "internal_panic".to_owned(),
                ApiError::PANIC_MESSAGE.to_owned(),
            )));
        }
    });
    let mut out = Response::new(Body::from_stream(Incoming { rx, dead: false }));
    *out.status_mut() = status;
    out.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/event-stream"),
    );
    out.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-cache"));
    Ok(out)
}

/// Прочитать тело с потолком (тот же `max_body_bytes`, что у тела запроса).
fn read_capped(mut resp: UpstreamResponse, limit: usize) -> Result<Vec<u8>, ProxyError> {
    let mut reader = resp.body_mut().as_reader();
    let mut body: Vec<u8> = Vec::new();
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        // `BodyReader::read` отдаёт `io::Error`; `ureq` свои ошибки оборачивает
        // сам, а сюда io доходит уже своим ходом — заворачиваем в тот же вариант.
        let n = reader
            .read(&mut buf)
            .map_err(|e| ProxyError::from_ureq(ureq::Error::Io(e)))?;
        if n == 0 {
            return Ok(body);
        }
        if body.len() + n > limit {
            return Err(ProxyError::TooLarge { limit });
        }
        body.extend_from_slice(&buf[..n]);
    }
}

/// Насос `SSE`: кусок upstream → [`Relay`] → канал клиенту.
///
/// Ошибка посреди стрима не может изменить HTTP-код (заголовки уже ушли),
/// поэтому она приходит как `data:`-событие с причиной и `[DONE]`: молчаливый
/// `EOF` клиент прочёл бы как «модель столько сказала», а это подмена факта.
fn pump_sse(
    st: &AppState,
    mut resp: UpstreamResponse,
    session: Option<&str>,
    tx: &mpsc::Sender<Result<Vec<u8>, (String, String)>>,
) {
    let mut relay = match Relay::new(st.vault(), session, st.config()) {
        Ok(relay) => relay,
        Err(err) => {
            let _ = tx.blocking_send(Err(relay_reason(&err)));
            return;
        }
    };
    let limit = st.config().max_body_bytes;
    let mut total = 0_usize;
    let mut buf = vec![0_u8; READ_CHUNK];
    let mut out: Vec<u8> = Vec::with_capacity(4 * READ_CHUNK);
    let mut reader = resp.body_mut().as_reader();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > limit {
                    let err = ProxyError::TooLarge { limit };
                    let _ = tx.blocking_send(Err((err.code().to_owned(), err.to_string())));
                    return;
                }
                if let Err(err) = relay.push(&buf[..n], &mut out) {
                    let _ = tx.blocking_send(Err(relay_reason(&err)));
                    return;
                }
                if !out.is_empty() {
                    let chunk = std::mem::take(&mut out);
                    if tx.blocking_send(Ok(chunk)).is_err() {
                        return; // клиент ушёл: соединение с upstream закрывается
                    }
                }
            }
            Err(err) => {
                // Стадию называем прямо: это чтение тела, а не отказ коннекта,
                // и «недоступен» был бы ложью о причине (код при этом общий).
                let shown = err.to_string();
                let code = ProxyError::from_ureq(ureq::Error::Io(err)).code();
                let _ = tx.blocking_send(Err((
                    code.to_owned(),
                    format!("чтение тела upstream: {shown}"),
                )));
                return;
            }
        }
    }
    relay.finish(&mut out);
    out.extend_from_slice(&sse::trailer(relay.stats(), relay.unresolved()));
    let _ = tx.blocking_send(Ok(out));
}

/// Причина остановки релая словами клиента: `SSE` не имеет трейлеров статуса.
/// Причина обрыва потока парой `(код, сообщение)`.
///
/// Код обязателен: «поток оборвался» без причины — это та же ложь о причине
/// отказа, за которую мы отвергли 413 там, где был таймаут.
fn relay_reason(err: &RelayError) -> (String, String) {
    match err {
        RelayError::FrameTooBig { limit } => {
            let e = ProxyError::TooLarge { limit: *limit };
            (e.code().to_owned(), e.to_string())
        }
        RelayError::Vault(vault) => ("vault_error".to_owned(), vault.to_string()),
    }
}

/// Кадр `event: error` — способ сообщить причину, когда заголовок ответа уже
/// ушёл клиенту и менять код статуса поздно (SPEC §8, «начатый SSE закрывается
/// err-событием»).
fn error_event(code: &str, message: &str) -> Vec<u8> {
    let payload = serde_json::json!({ "error": { "code": code, "message": message } });
    format!("event: error\ndata: {payload}\n\n").into_bytes()
}

/// Итог разворота буферизованного ответа.
#[derive(Debug, Default)]
struct Restored {
    /// Сколько маркеров прошло дословно (чужой токен, другая сессия).
    unresolved: usize,
    /// Тело ответа не разбиралось как JSON.
    malformed: bool,
}

/// Разворот не-потокового ответа.
///
/// Правим только речевые поля `choices[].message` — тот же список, что у
/// [`sse::Relay`], и по той же причине: `tool_calls.arguments` мы не понимаем, а
/// переписывать непонятое нельзя.
///
/// Два прохода, а не один: `deanonymize_soft` одалживает текст из дерева, а
/// писать в то же дерево, пока оно одолжено, нельзя — поэтому сначала собираем
/// правки, потом применяем.
fn deanonymize_json_body(
    st: &AppState,
    session: Option<&str>,
    raw: &[u8],
) -> Result<(Vec<u8>, Restored), ProxyError> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        // Не JSON: отдаём байты как есть и помечаем `malformed`. Выдумывать
        // структуру из чужих байтов — тот же класс лжи, что и подмена причины
        // отказа.
        return Ok((
            raw.to_vec(),
            Restored {
                unresolved: 0,
                malformed: true,
            },
        ));
    };
    let mut restored = Restored::default();
    let mut edits: Vec<(usize, &'static str, String)> = Vec::new();
    if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
        for (ci, ch) in choices.iter().enumerate() {
            let Some(message) = ch.get("message").and_then(serde_json::Value::as_object) else {
                continue;
            };
            for field in sse::SPEECH_FIELDS {
                let Some(text) = message.get(field).and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let r = st.vault().deanonymize_soft(session, text)?;
                restored.unresolved += r.unresolved;
                if r.substituted + r.unresolved > 0 {
                    edits.push((ci, field, r.text.to_string()));
                }
            }
        }
    }
    if edits.is_empty() {
        // Разворачивать нечего: байты уходят как пришли. Здесь «пусто» значит
        // «маркеров не было», а не «мы не сумели».
        return Ok((raw.to_vec(), restored));
    }
    for (ci, field, text) in edits {
        let target = value
            .get_mut("choices")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|a| a.get_mut(ci))
            .and_then(|ch| ch.get_mut("message"))
            .and_then(serde_json::Value::as_object_mut);
        if let Some(message) = target {
            message.insert((*field).to_owned(), serde_json::Value::String(text));
        }
    }
    Ok((
        serde_json::to_vec(&value).map_err(|_| ProxyError::Protocol)?,
        restored,
    ))
}

/// Поток из канала блокирующей задачи в [`Body::from_stream`].
///
/// `tokio-stream` ради одного `ReceiverStream` в дерево безопасности не берётся:
/// `poll_recv` — это двадцать строк и ноль новых крейтов (он уже в дереве через
/// `axum`, так что и `lock` не двигается).
pub struct Incoming {
    /// Очередь кадров от блокирующей задачи-насоса.
    rx: mpsc::Receiver<Result<Vec<u8>, (String, String)>>,
    /// Поток помечен мёртвым: после err-кадра мы больше ничего не обещаем.
    dead: bool,
}

impl futures_core::Stream for Incoming {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.dead {
            return Poll::Ready(None);
        }
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(Some(Err((code, message)))) => {
                // Ошибка — это КАДР, а не молчаливый aboрт тела: `io::Error`
                // здесь означал бы «клиент сам виноват, не дочитал», и ни
                // один SDK не узнал бы причину. Фрейм `event: error` читается
                // клиентом как отказ с кодом.
                this.dead = true;
                Poll::Ready(Some(Ok(error_event(&code, &message))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    /// Конфиг из тестовых пар: тот же путь разбора, что у продакшна
    /// (`Config::from_lookup`), а не ручная сборка структуры.
    fn cfg(allow: &str, loopback: bool) -> Config {
        let pairs: [(std::borrow::Cow<'static, str>, String); 2] = [
            (
                std::borrow::Cow::Borrowed("FASAD_UPSTREAM_ALLOWLIST"),
                allow.to_owned(),
            ),
            (
                std::borrow::Cow::Borrowed("FASAD_PROXY_LOOPBACK_HTTP"),
                i32::from(loopback).to_string(),
            ),
        ];
        Config::from_lookup(|k| {
            pairs
                .iter()
                .find(|(n, _)| n.as_ref() == k)
                .map(|(_, v)| v.clone())
        })
        .expect("конфиг из тестовых пар")
    }

    /// Код отказа (`None` = отказа не было): сравниваем именно его, потому что
    /// `ProxyError` не `PartialEq` — внутри он держит `VaultApiError`.
    fn code(err: Option<ProxyError>) -> Option<&'static str> {
        err.map(|e| e.code())
    }

    /// Тот же код, но уже из строки отказа: `Display` начинается с кода? Нет —
    /// поэтому ищем подстроку, а не восстанавливаем код.
    fn code_str(shown: Option<&str>) -> Option<&'static str> {
        [
            ("не в FASAD_UPSTREAM_ALLOWLIST", "allowlist_denied"),
            ("FASAD_UPSTREAM_ALLOWLIST пуст", "allowlist_empty"),
            ("http:// запрещено", "insecure_upstream"),
        ]
        .iter()
        .find(|(needle, _)| shown.is_some_and(|s| s.contains(needle)))
        .map(|(_, code)| *code)
    }

    fn body(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_absolute_urls_only() {
        let u = Upstream::parse("https://api.openai.com/v1/chat/completions").unwrap();
        assert_eq!(
            (u.scheme, u.host.as_str(), u.port, u.path.as_str()),
            (Scheme::Https, "api.openai.com", 443, "/v1/chat/completions")
        );
        assert_eq!(u.url(), "https://api.openai.com:443/v1/chat/completions");
        let u = Upstream::parse("https://proxy.corp:8443").unwrap();
        assert_eq!((u.port, u.path.as_str()), (8443, "/"));
        assert_eq!(Upstream::parse("https://[::1]:9/v1").unwrap().host, "::1");
        // Отказано всему, что не абсолютный URL или тащит в себе что-то лишнее.
        for bad in [
            "/v1/chat",
            "ftp://host/x",
            "https://",
            "https://host x",
            "https://user@host/x",
            "https://host:0/x",
            "https://host:notport/x",
            "https://host/x\r\nX-Evil: 1",
            "https://host\\..",
        ] {
            assert_eq!(
                code(Upstream::parse(bad).err()),
                Some("bad_upstream_url"),
                "{bad}"
            );
        }
    }

    #[test]
    fn http_needs_the_loopback_exception() {
        let https = Upstream::parse("https://api.openai.com/v1").unwrap();
        let http_local = Upstream::parse("http://127.0.0.1:8080/v1").unwrap();
        let http_remote = Upstream::parse("http://evil.example/v1").unwrap();
        // Список, в котором нет этих хостов, отвечает сначала про список.
        let denied = https
            .check(&cfg("other.example", false))
            .err()
            .map(|e| e.to_string());
        assert_eq!(
            code_str(denied.as_deref()),
            Some("allowlist_denied"),
            "не в списке"
        );
        assert!(
            denied.is_some_and(|s| s.contains("api.openai.com")),
            "отказ не называет хост"
        );
        assert_eq!(
            code(https.check(&cfg("", false)).err()),
            Some("allowlist_empty")
        );
        assert!(https.check(&cfg("api.openai.com", false)).is_ok());
        // http на loopback живёт только с флагом, и только если хост в списке.
        assert_eq!(
            code(http_local.check(&cfg("127.0.0.1:8080", false)).err()),
            Some("insecure_upstream")
        );
        assert!(http_local.check(&cfg("127.0.0.1:8080", true)).is_ok());
        // С флагом чужой http всё равно не проходит — по списку, не по схеме.
        assert_eq!(
            code(http_remote.check(&cfg("127.0.0.1", true)).err()),
            Some("allowlist_denied"),
            "с флагом чужой http всё равно отсекается списком"
        );
    }

    #[test]
    fn blocks_are_in_document_order() {
        // Замороженный порядок: сообщения по индексу, внутри части по индексу.
        let v = body(
            r#"{"messages":[
                 {"role":"system","content":"системный промпт"},
                 {"role":"user","content":[{"type":"text","text":"второе"},
                                            {"type":"image_url","image_url":{"url":"x"}},
                                            {"type":"text","text":"третье"}]},
                 {"role":"user","content":null},
                 {"role":"user","content":"четвёртое"}
               ],"model":"m"}"#,
        );
        let slots = block_index(&v);
        assert_eq!(
            slots,
            vec![
                Slot {
                    message: 0,
                    part: None
                },
                Slot {
                    message: 1,
                    part: Some(0)
                },
                Slot {
                    message: 1,
                    part: Some(2)
                },
                Slot {
                    message: 3,
                    part: None
                },
            ]
        );
        assert_eq!(read_slot(&v, &slots[2]), Some("третье"));
        assert_eq!(read_slot(&v, &slots[1]), Some("второе"));
    }

    #[test]
    fn permutation_changes_labels_but_not_membership() {
        // law #53: перестановка блоков меняет нумерацию меток. Разметка
        // «по порядку» проверяется здесь, на маске запроса, а не только в
        // юнит-тестах хранилища.
        let a = body(r#"{"messages":[{"role":"user","content":"Иванов П. и Петров С."}]}"#);
        let slots = block_index(&a);
        assert_eq!(slots.len(), 1);
        let b = body(
            r#"{"messages":[{"role":"user","content":"Иванов П."},{"role":"user","content":"Петров С."}]}"#,
        );
        assert_eq!(
            block_index(&b),
            vec![
                Slot {
                    message: 0,
                    part: None
                },
                Slot {
                    message: 1,
                    part: None
                }
            ]
        );
    }

    #[test]
    fn write_slot_does_not_invent_fields() {
        let mut v = body(r#"{"messages":[{"role":"user","content":"x","extra":1}]}"#);
        write_slot(
            &mut v,
            &Slot {
                message: 0,
                part: None,
            },
            "y",
        );
        assert_eq!(v["messages"][0]["content"], "y");
        assert_eq!(v["messages"][0]["extra"], 1);
        // Числовой content — не текст, и мы его не переписываем.
        let mut n = body(r#"{"messages":[{"role":"user","content":5}]}"#);
        write_slot(
            &mut n,
            &Slot {
                message: 0,
                part: None,
            },
            "y",
        );
        assert_eq!(n["messages"][0]["content"], 5);
    }

    #[test]
    fn error_codes_are_distinct_per_reason() {
        // Таблично: каждая причина имеет свой код, и «пустой список» не
        // путается с «не в списке» (у оператора разные правки env).
        let cases = [
            (
                ProxyError::AllowlistEmpty,
                (StatusCode::FORBIDDEN, "allowlist_empty"),
            ),
            (
                ProxyError::Denied { host: "h".into() },
                (StatusCode::FORBIDDEN, "allowlist_denied"),
            ),
            (
                ProxyError::Insecure,
                (StatusCode::FORBIDDEN, "insecure_upstream"),
            ),
            (
                ProxyError::Timeout("connect"),
                (StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            ),
            (
                ProxyError::Unreachable,
                (StatusCode::BAD_GATEWAY, "upstream_unreachable"),
            ),
            (
                ProxyError::TooLarge { limit: 1 },
                (StatusCode::PAYLOAD_TOO_LARGE, "upstream_too_large"),
            ),
            (
                ProxyError::Blocked,
                (StatusCode::FORBIDDEN, "blocked_by_policy"),
            ),
        ];
        for (err, (status, code)) in cases {
            assert_eq!((err.status(), err.code()), (status, code), "{err}");
        }
        let mut seen = std::collections::HashSet::new();
        for err in [
            ProxyError::MissingHeader,
            ProxyError::AllowlistEmpty,
            ProxyError::Denied { host: "h".into() },
            ProxyError::Insecure,
            ProxyError::PolicyNotApplicable,
            ProxyError::Blocked,
            ProxyError::Unreachable,
            ProxyError::Tls,
            ProxyError::Redirect,
            ProxyError::Protocol,
            ProxyError::Timeout("global"),
            ProxyError::TooLarge { limit: 9 },
            ProxyError::NotChatRequest,
            ProxyError::Aborted,
        ] {
            assert!(seen.insert(err.code()), "код {} повторяется", err.code());
        }
    }

    /// Контракт «начатый SSE закрывается err-событием»: молчаливый обрыв тела
    /// клиент читает как «модель ответила пустотой», а `io::Error` в потоке axum
    /// — это и есть молчаливый обрыв.
    #[tokio::test]
    async fn broken_stream_ends_with_an_error_frame_not_silence() {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, (String, String)>>(4);
        tx.send(Ok(b"data: {ok}\n\n".to_vec()))
            .await
            .expect("канал живой");
        tx.send(Err((
            "upstream_timeout".to_owned(),
            "таймаут upstream на стадии body".to_owned(),
        )))
        .await
        .expect("канал живой");
        drop(tx);
        let body = Body::from_stream(Incoming { rx, dead: false });
        let got = axum::body::to_bytes(body, 4096)
            .await
            .expect("поток читается без io-ошибки");
        let text = String::from_utf8(got.to_vec()).expect("UTF-8");
        assert!(
            text.starts_with("data: {ok}\n\nevent: error\ndata: "),
            "порядок кадров: {text}"
        );
        assert!(
            text.contains(r#""code":"upstream_timeout""#),
            "err-кадр не называет причину: {text}"
        );
    }

    #[test]
    fn carried_headers_are_exactly_two_credentials() {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("Bearer x"));
        h.insert("cookie", HeaderValue::from_static("session=1"));
        h.insert("user-agent", HeaderValue::from_static("fasad-test"));
        h.insert("x-api-key", HeaderValue::from_static("k"));
        let carried = carry_headers(&h);
        let names: Vec<String> = carried.iter().map(|(n, _)| n.as_str().to_owned()).collect();
        assert_eq!(names, vec!["authorization", "x-api-key"]);
    }
}
