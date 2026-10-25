//! Проводные тесты песочницы (шаг 8, SPEC §10 п.8).
//!
//! Браузера в CI нет, поэтому проверяется то, что браузер видит первым: ответы
//! демона на те самые запросы, которые делает `ui/app.js`. Три группы:
//!
//! 1. статика отдаётся, с типами, с `CSP`, и только четырьмя именами;
//! 2. схема в песочницу приходит теми же байтами, что демон вшил в себя;
//! 3. клиентский маршрут «analyze -> anonymize -> deanonymize» сходится
//!    побайтово, телами запросов — ровно теми, что собирает фронт.
//!
//! Harness (`Daemon`, `call`) — вторая копия, не общая с `wire_e2e.rs`:
//! HTTP-клиент в dev-зависимостях поймал бы `net_audit`-гейт (он читает манифест
//! целиком), а выносить харнесс в `tests/common` в этом же заходе нельзя —
//! `wire_e2e.rs` прямо сейчас правится в #70, и общий файл дал бы конфликт в
//! тот момент, когда его никто не разберёт. После влития #70 харнесс стоит
//! склеить в один (задача в теле PR).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use guard_daemon::ui::CSP;

struct Daemon {
    child: Child,
    addr: String,
    /// Общий лог stderr демона (#224 R4): диагностика отказов после баннера.
    log: std::sync::Arc<std::sync::Mutex<String>>,
    /// Держим канал строк stdout: ранняя гибель `rx` (паника теста) =
    /// читатель выходит = трубка закрывается = EPIPE-паника print'а
    /// ЖИВОГО демона (#224 R4, stdio.rs:1168).
    _stdout_lines: std::sync::mpsc::Receiver<String>,
}

/// Поток-читатель stdout = пожизненный (#224 R4: раннее закрытие трубки =
/// EPIPE-паника print'а демона, stdio.rs:1168); строки = канал, байты —
/// sink процесса.
fn stdout_reader(stdout: std::process::ChildStdout) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut reader = stdout;
        let mut carry = String::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk[..n]).into_owned();
                    carry.push_str(&text);
                    while let Some(pos) = carry.find('\n') {
                        let line = carry[..=pos].to_owned();
                        carry.drain(..=pos);
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    rx
}

/// Читатель stderr демона в общий лог (#224 R4 диагностика: отказ после
/// баннера обязан называть причину, а не молчать).
fn stderr_log(child: &mut std::process::Child) -> std::sync::Arc<std::sync::Mutex<String>> {
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let log = std::sync::Arc::clone(&log);
        let mut stderr = child.stderr.take().expect("stderr перехвачен");
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut chunk = [0u8; 1024];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        log.lock()
                            .expect("лог не отравлен")
                            .push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
            }
        });
    }
    log
}

impl Daemon {
    /// Готовность = ОТВЕТИВШИЙ сокет, не баннер (#224 R4): connect-проба с
    /// ливенес-проверкой до возврата addr (мёртвый процесс = exit-код).
    fn wait_ready(
        child: &mut Child,
        addr: &str,
        seen: &str,
        log: &std::sync::Arc<std::sync::Mutex<String>>,
    ) {
        let ready = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("статус читается") {
                let buf = log.lock().expect("лог не отравлен").clone();
                panic!(
                    "демон умер в окне готовности (rc={:?}, {addr}); stdout: {seen:?} stderr: {buf:?}",
                    status.code()
                );
            }
            if TcpStream::connect(addr).is_ok() {
                return;
            }
            assert!(
                ready.elapsed() < Duration::from_secs(10),
                "порт {addr} не открылся за 10 с; stdout: {seen:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn start(env: &[(&str, &str)]) -> Self {
        // #185: full-бинарь (feature `ort-inference`) без весов не стартует —
        // live-контур файла (UI-протокол, каскад-0-ожидания, ревью #87) =
        // feature-off бинарь; на ort-контуре — явная SKIPPED-строка и rc=0
        // (молчание = ложно-зелёная проверка, тот же контракт, что wire_e2e).
        if cfg!(feature = "ort-inference") {
            eprintln!(
                "SKIP|ui_sandbox|full-бинарь (#185) без весов не стартует; live-контур \
                 файла = каскад-0-ожидания (ревью #87), ort-контур покрыт unit-тестами \
                 http.rs/cascades.rs"
            );
            std::process::exit(0);
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fasad"));
        cmd.env("FASAD_BIND", "127.0.0.1")
            .env("FASAD_PORT", "0")
            // #192: на машине оператора дефолт `FASAD_MODEL_DIR`
            // (`~/.cache/fasad-models`) резолвится из HOME — каскад-0-бинарь
            // с названным каталогом краснеет `BuiltWithoutInference`, а
            // `env_remove` уже не спасает. Флаг = «харнес cascade-0»: env-
            // граница `from_env` не подставляет дефолт (см. config.rs).
            .env("FASAD_TEST_CASCADE0", "1")
            // #203 §2.1: харнес = каскад-0-контур; env-мишень #198 из
            // оболочки не наследуется (на машине с весами она включала
            // Some(кеш) = stage cascade-0+models = харнес красный).
            .env_remove("FASAD_TEST_TRAY_CONTOUR")
            // Тестовый демон поднимается БЕЗ весов и без чужих ручек окружения.
            // Причина (ревью #87, воспроизведено на этом дереве): с
            // унаследованным `FASAD_MODEL_DIR` каждый прогон грузит веса в
            // каждый демон — файл распухает с 1.42 с до 23.90 с, и у
            // ревьюера на `ui_schema_editor_knobs_reach_the_wire` это уже
            // 8 passed / 1 failed (баннер не успевает за таймаут загрузки).
            // Тесты файла про протокол UI, не про модель: веса им не нужны.
            // «В CI же чисто» гейт не чинит: он обязан быть воспроизводимым
            // на машине с весами, поэтому remove явный, а не молчаливый
            // дефолт.
            .env_remove("FASAD_MODEL_DIR")
            .env("FASAD_TEST_CASCADE0", "1")
            // #203 §2.1: харнес = каскад-0-контур; env-мишень #198 из
            // оболочки не наследуется (на машине с весами она включала
            // Some(кеш) = stage cascade-0+models = харнес красный).
            .env_remove("FASAD_TEST_TRAY_CONTOUR")
            .env_remove("FASAD_THREADS")
            // #224 R4 (первичка CI ubuntu: витрина вернула
            // `file.path=/home/runner/.config/…` при HOME-игле = tempdir):
            // канон-резолв config-файла = `XDG_CONFIG_HOME` > HOME, и
            // XDG-переменные раннера/машины пробивают HOME-иглу (на
            // ubuntu-раннере задан XDG_DATA_HOME — наследие среды =
            // невоспроизводимый флейк). Иглы изоляции = ВСЕ канон-переменные.
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("FASAD_TIMEOUT_MS")
            // #219 (E-контур): харнес обязан быть изолирован от файла
            // конфигурации. Файл оператора (`~/.config/fasad/config`) на
            // локальной машине дал бы харнесу его значения (порт, пороги,
            // режим) — CI-раннер «чисто» не чинит этого, и тот же аргумент,
            // что у env_remove выше: воспроизводимость на машине оператора.
            // Игла = СУЩЕСТВУЮЩИЙ пустой файл в tmp (см. `fasad_empty_config`):
            // env-граница обязана получить «значений нет», а не «HOME
            // оператора»; несуществующий путь дал бы отказ старта (#185).
            .env("FASAD_CONFIG", fasad_empty_config())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("бинарь фасада запускается");
        let stdout = child.stdout.take().expect("stdout перехвачен");
        let rx = stdout_reader(stdout);
        let log = stderr_log(&mut child);
        let started = Instant::now();
        let mut seen = String::new();
        while started.elapsed() < Duration::from_secs(25) {
            let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) else {
                if child.try_wait().expect("статус читается").is_some() {
                    break;
                }
                continue;
            };
            seen.push_str(&line);
            if let Some((_, rest)) = seen.split_once("listening on http://") {
                let addr = rest
                    .split('/')
                    .next()
                    .expect("адрес заканчивается путём")
                    .to_owned();
                Self::wait_ready(&mut child, &addr, &seen, &log);
                DAEMONS.lock().expect("реестр не отравлен").push((
                    addr.clone(),
                    child.id(),
                    true,
                    std::sync::Arc::clone(&log),
                ));
                return Self {
                    child,
                    addr,
                    log,
                    _stdout_lines: rx,
                };
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "демон не напечатал баннер за {:?}; stdout: {seen:?}",
            started.elapsed()
        );
    }
}

/// Уникальный tmp-путь теста. `std::process::id()` НЕ уникален: `cargo test`
/// = ОДИН процесс, тесты живут в ПОТОКАХ — два теста с одним PID-суффиксом
/// пишут в ОДИН каталог/файл (первичка CI ubuntu job 120977735379 @b68e853:
/// `config_write…` получил ECONNREFUSED — демон стартовал на чужом
/// перезаписанном `config` и отказался (rc=2), порт не занят). Суффикс =
/// PID + атомарный счётчик + наносекунды (std-only, dev-deps не заводим).
fn unique_tmp_path(prefix: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // Уникальность = гонка-создание КАТАЛОГА (`create_dir` краснеет на
    // коллизии, EEXIST = шаг счётчика): наносекунды часов не гарантируют её
    // между потоками одного процесса — на CI два теста получили ОДИН
    // tempdir-путь (первичка #224 R4). Возврат = ПУТЬ ВНУТРИ каталога
    // (существование parent = инвариант всех потребителей; каталог =
    // то, что вызывающие удаляют `remove_dir_all`-ем в конце теста).
    let root = std::env::temp_dir();
    for _ in 0..128 {
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let dir = root.join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir.join("p"),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("unique_tmp_path({prefix}): {e}"),
        }
    }
    panic!("unique_tmp_path: 128 коллизий имени {prefix}");
}

/// Путь-игла E-контура #219: СУЩЕСТВУЮЩИЙ пустой файл конфигурации в tmp.
///
/// Пустой, а не «несуществующий»: явный `FASAD_CONFIG` в несуществующий путь =
/// отказ старта (#185-контур: опечатка в пути обязана быть названа), а харнесу
/// нужен ровно «файла нет по существу» = пустые значения. Файл создаётся на
/// вызове: CI-раннер обязан найти его, а не оператора tmp-содержимое.
/// Игла E-контура = ОДИН путь на весь тест-процесс (PID-имя): пересоздание
/// на каждый вызов роняло предыдущий демон на `MissingExplicitPath` (файл
/// исчез) = rc=2 = порт не занят = «сокет/ответ недоступны 30 с» (первичка
/// #224 R4: харнесевы ноги гоняют демонов параллельно).
static HARNESS_EMPTY_CONFIG: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

fn fasad_empty_config() -> std::path::PathBuf {
    HARNESS_EMPTY_CONFIG
        .get_or_init(|| {
            let path = unique_tmp_path("fasad-harness-empty.cfg");
            std::fs::write(&path, "# fasad harness (#219): empty = no values\n")
                .expect("игла создаётся");
            path
        })
        .clone()
}

impl Daemon {
    /// Снимок stderr демона (#224 R4): вшивается в assert-сообщения live-ног,
    /// чтобы «сокет недоступен» превращался в «демон сказал X».
    #[allow(dead_code)]
    fn log_tail(&self) -> String {
        self.log.lock().expect("лог не отравлен").clone()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // #224 R4: SIGTERM = axum graceful: ACCEPT-ЦИКЛ закрывается МГНОВЕННО,
        // «остальные запросы дозавершаются» (первичка docs/axum/src/serve.rs:
        // `Listener::poll_accept` → `loop { ... self.accepting.get() ... }`
        // stop, а graceful = только активные соединения). Сосед по тесту,
        // стартующий в окне kill→reap, ловит ECONNREFUSED 30 с = весь
        // призрак-класс. Graceful-дрейна у харнеса нет: shutdown-контур
        // демона (SIGTERM-флаг) = отдельный продукт-контур, не тестовый.
        // Харнес = SIGKILL: ядро закрывает listening-сокет сразу, освободив
        // порт для следующего демона без окна refuse.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Ok(mut reg) = DAEMONS.lock() {
            for e in reg.iter_mut() {
                if e.0 == self.addr {
                    e.2 = false;
                }
            }
        }
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("не JSON: {e}: {}", self.text()))
    }
}

/// Реестр демонов процесса (#224 R4): addr → (pid, жив, хвост stderr).
/// Первичка 30-с refused при «живом» демоне: реестр отвечает «жив ли, pid,
/// что говорил» — диагностика без гадания.
type DaemonReg = Vec<(String, u32, bool, std::sync::Arc<std::sync::Mutex<String>>)>;

static DAEMONS: std::sync::Mutex<DaemonReg> = std::sync::Mutex::new(Vec::new());

fn daemon_diag(addr: &str) -> String {
    let reg = DAEMONS.lock().expect("реестр не отравлен");
    let entry = reg.iter().find(|(a, _, _, _)| a == addr);
    match entry {
        Some((_, pid, alive, log)) => {
            let v = log.lock().expect("лог не отравлен").clone();
            let n = v.chars().count();
            let tail: String = v.chars().skip(n.saturating_sub(600)).collect();
            format!("pid={pid} жив={alive} stderr={tail:?}")
        }
        None => "в реестре (этот процесс) не значится".to_string(),
    }
}

fn call(addr: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        use std::fmt::Write as _;
        writeln!(req, "{k}: {v}").expect("в String не бывает ошибки записи");
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    // Win-контра CI #224 (первичка job-лога): `Connection: close` =
    // однократная связь; серия POST подряд (в решётке 8 ног) — следующий
    // запрос попадает в RST-окно закрытия: write_all = EPIPE/ECONNRESET
    // (unix) или ответ = RST без байт, `raw` пуст (winsock 10054; данные
    // могут лежать в буфере — read_to_end отдаёт их с ошибкой). Оборот =
    // reconnect ≤3 попытки, пауза 200 мс; после трёх пустых — panic (тест
    // обязан видеть красное, а не молча глотать). НЕ сужать решётку: 8 ног
    // = покрытие.
    // #224 R4: reconnect-оборот: CI-раннер = «backlog заполнен» → SYN режет
    // SYN/ACK → ECONNREFUSED; пустой ответ = RST-окно закрытия (win/unix).
    // Бюджет окна 30 с (live-контур; CI-шаг = step-timeout 12 мин).
    let mut raw = Vec::new();
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        raw.clear();
        if let Ok(mut sock) = TcpStream::connect(addr) {
            sock.set_read_timeout(Some(Duration::from_secs(15)))
                .expect("таймаут ставится");
            let _ = sock.write_all(&bytes).and_then(|()| sock.flush());
            // Данные могут лежать в буфере вместе с ошибкой (10054):
            // read_to_end отдаёт их, заголовок прочитан = ответ принят.
            let _ = sock.read_to_end(&mut raw);
        }
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        // Deadlines #224 R4: refused (демона нет на порту) = красное за ~2 с
        // (полный цикл решётки не вешается на мёртвый демон), живой демон в
        // RST/backlog-окне = окно 30 с.
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "сокет/ответ недоступны 30 с ({attempt} попыток): addr {addr}, байты {}. Демон: {}",
            raw.len(),
            daemon_diag(addr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("ответ с заголовками");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status_line = lines.next().expect("строка статуса есть");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("код статуса разбирается");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

/// Сессия ровно в том виде, в каком её генерирует фронт: 16 случайных байт в
/// hex (см. `newSession` в `ui/app.js`), то есть 32 символа из допустимого
/// алфавита `X-Session-ID`.
fn ui_session() -> String {
    "0123456789abcdef0123456789abcdef".to_owned()
}

const SESSION: [(&str, &str); 2] = [
    ("FASAD_VAULT_MODE", "session"),
    (
        "FASAD_VAULT_KEY",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ),
];

// --- статика -------------------------------------------------------------

#[test]
fn static_pages_are_served_with_strict_csp() {
    let d = Daemon::start(&SESSION);
    for path in ["/", "/ui"] {
        let r = call(&d.addr, "GET", path, &[], b"");
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        assert!(
            r.text().contains("fasad — песочница"),
            "{path}: отдаётся не страница песочницы"
        );
        assert!(
            r.header("content-type")
                .is_some_and(|v| v.starts_with("text/html")),
            "{path}: content-type = {:?}",
            r.header("content-type")
        );
        let csp = r
            .header("content-security-policy")
            .expect("CSP обязан быть");
        assert_eq!(csp, CSP, "CSP на ответе разошёлся с константой");
        assert!(
            csp.contains("default-src 'none'") && csp.contains("script-src 'self'"),
            "CSP распущен: {csp}"
        );
        assert!(
            !csp.contains('*') && !csp.contains("http://") && !csp.contains("https://"),
            "CSP разрешает внешний источник: {csp}"
        );
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        // Фронт без inline-скриптов и inline-стилей: политика это переживёт.
        let page = r.text();
        assert!(
            !page.contains("<script>") && !page.contains("style=\""),
            "в странице появился inline — CSP его отрезает, и песочница \
             сломается у пользователя, а не в этом тесте"
        );
    }
}

#[test]
fn assets_are_served_with_types_and_schema_is_the_shipped_file() {
    let d = Daemon::start(&SESSION);
    for (name, kind) in [("app.css", "text/css"), ("app.js", "javascript")] {
        let r = call(&d.addr, "GET", &format!("/assets/{name}"), &[], b"");
        assert_eq!(r.status, 200, "{name}: {}", r.text());
        assert!(
            r.header("content-type").is_some_and(|v| v.contains(kind)),
            "{name}: content-type = {:?}",
            r.header("content-type")
        );
        assert!(
            r.header("content-security-policy").is_some(),
            "{name}: CSP обязан быть и на ассете"
        );
        assert!(!r.body.is_empty(), "{name}: пустой файл отдали");
    }

    // Ключевой ноль расхождений: схема в песочнице = те же байты, что демон
    // вшил в себя как `DEFAULT_SCHEMA_JSON`.
    let r = call(&d.addr, "GET", "/assets/schema.json", &[], b"");
    assert_eq!(r.status, 200, "schema.json: {}", r.text());
    assert!(
        r.header("content-type").is_some_and(|v| v.contains("json")),
        "schema.json: content-type = {:?}",
        r.header("content-type")
    );
    let shipped = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/schema.default.json"
    ))
    .expect("дефолтная схема читается");
    assert_eq!(
        r.body, shipped,
        "песочница отдаёт не ту схему, что вшита в демон"
    );
    let json: serde_json::Value = serde_json::from_slice(&r.body).expect("схема — JSON");
    let classes = json["classes"]
        .as_array()
        .expect("список классов есть")
        .iter()
        .map(|c| c["id"].as_str().expect("id класса").to_owned())
        .collect::<Vec<_>>();
    assert!(
        classes.contains(&"person_name".to_owned()) && classes.contains(&"inn".to_owned()),
        "в списке классов песочницы нет базовых классов: {classes:?}"
    );
}

#[test]
fn asset_names_outside_the_allow_list_are_refused() {
    let d = Daemon::start(&SESSION);
    for path in [
        "/assets/Cargo.toml",
        "/assets/app.css%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fconfig%2fkeys",
        "/assets/",
        "/assets/index.html",
        // Канарейка: реальный файл из `config/`, который не должен попадать ни
        // в сборку, ни наружу. Схема отдаётся константой `DEFAULT_SCHEMA_JSON`,
        // папку `config/` демон не шьёт целиком.
        "/assets/embed-probe.md",
        "/assets/schema.default.json",
    ] {
        let r = call(&d.addr, "GET", path, &[], b"");
        assert_eq!(r.status, 404, "{path} отдали: {}", r.text());
        assert!(
            !r.text().contains("[dependencies") && !r.text().contains("FASAD_VAULT_KEY"),
            "{path}: в теле утекло содержимое файла"
        );
    }
    // «index.html» как ассет — тоже отказ: страница отдаётся только маршрутами
    // `/` и `/ui`, иначе у неё появляется второе имя и кэш-ключ.
    let r = call(&d.addr, "GET", "/assets/app.js", &[], b"");
    assert_eq!(r.status, 200);
}

// --- клиентский маршрут --------------------------------------------------

/// Прогон маршрута `analyze → anonymize` телами, которые собирает `ui/app.js`:
/// `analyze` — с `entities`/`score_threshold`, `anonymize` — спанами дословно из
/// ответа анализа. Возвращает маску и число спанов; общий для теста roundtrip и
/// теста сброса сессии (по одному прогону на тест, цена прогона — живой демон).
fn ui_mask(d: &Daemon, text: &str, session: &str) -> (String, usize) {
    let json = [
        ("content-type", "application/json"),
        ("x-session-id", session),
    ];
    let analyze = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &json,
        format!(r#"{{"text":"{text}"}}"#).as_bytes(),
    );
    assert_eq!(analyze.status, 200, "analyze: {}", analyze.text());
    let spans = analyze.json();
    let arr = spans.as_array().expect("голый массив спанов").clone();
    assert_eq!(
        arr.len(),
        2,
        "на эталонном входе должно быть два спана: {arr:?}"
    );
    assert_eq!(
        arr.iter()
            .map(|s| s["entity_type"].as_str().expect("класс"))
            .collect::<Vec<_>>(),
        vec!["inn", "snils"],
        "состав найденных классов разъехался с эталоном"
    );
    assert!(
        analyze.header("x-guard-stage").is_some(),
        "фронт показывает `X-Guard-Stage`, демон его не прислал"
    );
    let anon = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &json,
        format!(
            r#"{{"text":"{text}","spans":{}}}"#,
            serde_json::to_string(&arr).expect("спанов сериализуется")
        )
        .as_bytes(),
    );
    assert_eq!(anon.status, 200, "anonymize: {}", anon.text());
    let count = arr.len().to_string();
    assert_eq!(
        anon.header("x-guard-redacted-count"),
        Some(count.as_str()),
        "счётчик подмен на заголовке не равен числу спанов"
    );
    (
        anon.json()["text"]
            .as_str()
            .expect("текст маски")
            .to_owned(),
        arr.len(),
    )
}

/// Что зашито в бинарник — промер по артефакту, а не по соседнему файлу.
///
/// Тесты выше доказывают, что демон *отдаёт* index и ассеты. Они бы прошли и на
/// сборке, которая читает `ui/` с диска рядом с исходниками, а оператору нужен
/// один файл. Поэтому `debug-embed` в `Cargo.toml` включён намеренно: отладочная
/// сборка вшивает статику так же, как релизная, и этот тест измеряет байты самого
/// `fasad`. С выключенным `debug-embed` он краснеет в debug — «статика в
/// бинарнике» оказывается гейтом, а не строчкой в README.
///
/// Правка статики при этом по-прежнему пересобирает демон: `include_bytes!`
/// регистрирует файл как compile-time зависимость (проверено: `touch` файла
/// вызывал rebuild).
#[test]
fn ui_payload_is_inside_the_binary() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_fasad")).expect("бинарь читается");
    for marker in [
        "fasad — песочница".as_bytes(),
        b"mark.block",
        b"GUARD_HEADERS",
    ] {
        assert!(
            exe.windows(marker.len()).any(|w| w == marker),
            "в бинаре нет куска статики «{}»: сборка отдаёт её с диска",
            String::from_utf8_lossy(marker)
        );
    }
}

/// Зеркало `ui_payload_is_inside_the_binary`: канарейка из `config/` обязана НЕ
/// попадать в бинарь. Положительная сторона доказывает, что `rust-embed` шьёт
/// статику; эта — что фильтр `include` не снят. Снятие фильтра уезжает в
/// наружный артефакт всей папкой: локальные оверрайды, служебные дампы, чужая
/// схема. Маршрут `/assets/embed-probe.md` при этом может остаться 404 (роутер
/// белым списком закрыт), и тест на отказ маршрута ничего не увидит — поэтому
/// проверка на уровне байтов сборки, а не запроса.
#[test]
fn probe_file_stays_out_of_the_binary() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_fasad")).expect("бинарь читается");
    let body = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/embed-probe.md"
    ))
    .expect("канарейка читается");
    let head = &body[..body.len().min(64)];
    for marker in [b"embed-probe.md".as_slice(), head] {
        assert!(
            !exe.windows(marker.len()).any(|w| w == marker),
            "в бинаре найдено «{}»: фильтр `include` у rust-embed снят, папка config/ шьётся наружу",
            String::from_utf8_lossy(marker)
        );
    }
}

/// Сетка служебных заголовков, которую фронт показывает под форме, обязана
/// совпадать с сеткой SPEC §8. Тест-пара к `header_table_in_docs_matches_emitted_names`
/// из `http.rs`: тот держит равенство «эмиссия = док», этот — «док = фронт».
/// Без него переименование заголовка молча исчезает из песочницы: фронт печатает
/// только те имена, которые нашёл.
#[test]
fn ui_header_readout_matches_spec_grid() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/SPEC.md"))
        .expect("SPEC читается");
    let section = spec
        .split("\n## ")
        .find(|s| s.starts_with("8."))
        .expect("секция 8 в SPEC есть");
    let mut grid: Vec<String> = section
        .lines()
        .filter(|l| l.starts_with("- `X-"))
        .map(|l| {
            l.split('`')
                .nth(1)
                .expect("имя в бэктиках")
                .to_ascii_lowercase()
        })
        .collect();
    grid.sort();
    assert!(!grid.is_empty(), "сетка §8 пуста — тест выше не о чём");

    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("фронт читается");
    let start = js
        .find("const GUARD_HEADERS = [")
        .expect("список заголовков у фронта есть");
    let body = js[start..].split("];").next().expect("список закрыт");
    let mut shown: Vec<String> = body
        .lines()
        .filter_map(|l| l.split('"').nth(1))
        .map(str::to_ascii_lowercase)
        .collect();
    shown.sort();
    assert_eq!(
        shown, grid,
        "фронт показывает не ту сетку заголовков, что обещает §8"
    );
}

/// Клиентский маршрут фронта целиком: `analyze → anonymize → deanonymize`
/// обязан вернуться к исходнику побайтово.
#[test]
fn ui_flow_roundtrips_through_live_daemon() {
    let d = Daemon::start(&SESSION);
    // Эталонный вход каскада 0: два класса, которые детерминированные
    // валидаторы находят гарантированно. ФИО и e-mail — каскад 1+
    // (`docs/daemon-scope.md` §«Что каскад 0 находит и не находит»), на этом этапе
    // песочница их не красит, и тест этого не обещает.
    let text = "ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";
    let session = ui_session();
    let (masked, n) = ui_mask(&d, text, &session);
    assert!(
        !masked.contains("2482014338") && !masked.contains("65707715421"),
        "маска не закрыла данные: {masked}"
    );
    let json = [
        ("content-type", "application/json"),
        ("x-session-id", &session),
    ];
    let back = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &json,
        format!(
            r#"{{"text":{}}}"#,
            serde_json::to_string(&masked).expect("строка в JSON")
        )
        .as_bytes(),
    );
    assert_eq!(back.status, 200, "deanonymize: {}", back.text());
    assert_eq!(
        back.json()["text"].as_str().expect("текст"),
        text,
        "roundtrip песочницы не вернул исходник побайтово"
    );
    assert_eq!(
        back.json()["substituted"]
            .as_u64()
            .expect("счётчик разворотов"),
        u64::try_from(n).expect("влезает"),
        "развёрнуто не то число, что подменено"
    );
}

/// Тот же маршрут в режиме по умолчанию — `stateless` (`config.rs`: при
/// отсутствующем `FASAD_VAULT_MODE` он и есть). Песочница открывается именно в
/// такой демон, и roundtrip там обязан работать без всяких сессий: токен
/// самовскрывающийся, маркер вида `[[F0#…`.
#[test]
fn ui_flow_roundtrips_in_default_stateless_mode() {
    let d = Daemon::start(&[]);
    let text = "ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";
    let session = ui_session();
    let (masked, n) = ui_mask(&d, text, &session);
    assert!(
        masked.contains("[[F0#"),
        "в режиме по умолчанию маска обязана быть токеном: {masked}"
    );
    let back = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &[
            ("content-type", "application/json"),
            ("x-session-id", &session),
        ],
        format!(
            r#"{{"text":{}}}"#,
            serde_json::to_string(&masked).expect("строка в JSON")
        )
        .as_bytes(),
    );
    assert_eq!(back.status, 200, "deanonymize: {}", back.text());
    assert_eq!(
        back.json()["text"].as_str().expect("текст"),
        text,
        "roundtrip в режиме по умолчанию не вернул исходник"
    );
    assert_eq!(
        back.json()["substituted"]
            .as_u64()
            .expect("счётчик разворотов"),
        u64::try_from(n).expect("влезает")
    );
}

/// Кнопка «Сброс сессии»: после `DELETE /v1/sessions/{id}` разворот обязан
/// отказывать своим кодом, а не возвращать половину документа.
#[test]
fn ui_session_reset_closes_the_restore() {
    let d = Daemon::start(&SESSION);
    let text = "ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";
    let session = ui_session();
    let (masked, _) = ui_mask(&d, text, &session);
    let del = call(
        &d.addr,
        "DELETE",
        &format!("/v1/sessions/{session}"),
        &[("x-session-id", &session)],
        b"",
    );
    assert_eq!(del.status, 200, "teardown: {}", del.text());
    let after = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &[
            ("content-type", "application/json"),
            ("x-session-id", &session),
        ],
        format!(
            r#"{{"text":{}}}"#,
            serde_json::to_string(&masked).expect("строка в JSON")
        )
        .as_bytes(),
    );
    assert_eq!(
        after.status,
        422,
        "после сброса сессии разворот обязан отказывать, а не вернуть partial: {}",
        after.text()
    );
    assert_eq!(
        after.json()["error"]["code"]
            .as_str()
            .expect("код отказа есть"),
        "unresolved_token",
        "отказ обязан быть назван своим кодом, а не общим 5xx"
    );
}

/// Редактор схемы говорит с API двумя полями, и оба обязаны работать так, как
/// подписаны во фронте: `entities` — фильтр классов, `score_threshold` — планка,
/// которую можно только поднимать.
#[test]
fn ui_schema_editor_knobs_reach_the_wire() {
    let d = Daemon::start(&SESSION);
    let text = "ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";
    let session = ui_session();
    let json = [
        ("content-type", "application/json"),
        ("x-session-id", &session),
    ];

    let all = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &json,
        format!(r#"{{"text":"{text}"}}"#).as_bytes(),
    );
    let only_inn = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &json,
        format!(r#"{{"text":"{text}","entities":["inn"]}}"#).as_bytes(),
    );
    assert_eq!(only_inn.status, 200, "фильтр классов: {}", only_inn.text());
    let classes = |reply: &Reply| -> Vec<String> {
        reply
            .json()
            .as_array()
            .expect("массив")
            .iter()
            .map(|s| s["entity_type"].as_str().expect("класс").to_owned())
            .collect()
    };
    let base = classes(&all);
    let filtered = classes(&only_inn);
    assert!(
        base.contains(&"inn".to_owned()) && base.contains(&"snils".to_owned()),
        "базовый прогон обязан найти оба класса: {base:?}"
    );
    assert_eq!(
        filtered,
        vec!["inn".to_owned()],
        "снятая галка класса не сработала: {filtered:?}"
    );

    let high = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &json,
        format!(r#"{{"text":"{text}","score_threshold":0.99}}"#).as_bytes(),
    );
    assert_eq!(high.status, 200, "порог: {}", high.text());
    assert!(
        classes(&high).len() <= base.len(),
        "порог 0.99 не сократил выборку: {:?}",
        classes(&high)
    );
    assert_eq!(
        high.header("x-guard-score-threshold").map(str::to_owned),
        Some("0.99".to_owned()),
        "применённый порог не показан клиенту"
    );

    // Обещание фронта («порог может только поднимать планку») — проверяемая
    // часть: запрос ниже серверной планки не имеет права находить больше.
    let low = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &json,
        format!(r#"{{"text":"{text}","score_threshold":0.0}}"#).as_bytes(),
    );
    assert_eq!(low.status, 200, "низкий порог: {}", low.text());
    assert_eq!(
        classes(&low).len(),
        base.len(),
        "нулевой порог ослабил серверную планку"
    );
}

/* ── #192: карточка веса + загрузка по клику ────────────────────────────── */

/// Живой контур кнопки: mock-HF на **петле** (python http.server) — внешняя
/// сеть в CI запрещена air-gap-контуром (net-audit: исходящие = proxy +
/// fetch на HF-контракт; loopback-мок не сеть в смысле гейта, прецедент
/// `FASAD_PROXY_LOOPBACK_HTTP` 7c). Заодно это промер макета: скачанные
/// файлы лежат РОВНО в `cascades::OnnxMount::load`-раскладке.
#[test]
fn weights_card_shows_files_and_fetch_lands_the_layout() {
    if std::env::var("FASAD_MOCK_HF").is_err() {
        eprintln!(
            "SKIP|ui_sandbox|weights_fetch|нет FASAD_MOCK_HF (http://127.0.0.1:PORT \
             с mock-дерева) — промер живого контура кнопки; CI-нога без сети"
        );
        return;
    }
    let dir = unique_tmp_path("fasad-fetch");
    let _ = std::fs::remove_dir_all(&dir);
    let d = Daemon::start(&[
        ("FASAD_MODEL_DIR", dir.to_str().expect("tmp путь")),
        (
            "FASAD_HF_HOST",
            &std::env::var("FASAD_MOCK_HF").expect("проверен выше"),
        ),
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
    ]);

    // (а) GET /v1/status: schema витрины + ПДн-безопасность.
    let r = call(&d.addr, "GET", "/v1/status", &[], b"");
    assert_eq!(r.status, 200, "статус отдаётся: {}", r.text());
    let j = r.json();
    // Тестовый демон: feature-off + FASAD_MODEL_DIR назван (tmp-каталог) =>
    // stage cascade-0+models (метка «назван», не «смонтирован» — #185).
    assert!(j["stage"].is_string());
    assert!(j["version"].is_string());
    assert_eq!(j["fetch"]["state"], "idle");
    let files = j["weights"]["present"].as_array().expect("список файлов");
    assert_eq!(files.len(), 5, "layout = 5 записей: {files:?}");
    for f in files {
        assert_eq!(f["present"], false, "свежий каталог пуст: {f}");
        assert_eq!(f["ok"], false);
        assert_eq!(
            f["path"].as_str().unwrap().find(".."),
            None,
            "путь относительный"
        );
    }
    assert_eq!(j["model"]["manifest_records"], 5);
    assert!(j["model"]["lockr_revision"].is_string());
    // ПДн-безопасность: домашний путь и маркеры не светятся.
    let home = std::env::var("HOME").unwrap_or_default();
    assert!(
        !home.is_empty() && !r.text().contains(&home),
        "домашний путь в статусе"
    );
    assert!(!r.text().contains("СЕКРЕТ"));

    // (б) POST /v1/models/fetch → 202, повтор → 409.
    let r = call(&d.addr, "POST", "/v1/models/fetch", &[], b"{}");
    assert_eq!(r.status, 202, "старт принят: {}", r.text());
    let r2 = call(&d.addr, "POST", "/v1/models/fetch", &[], b"{}");
    assert!(
        r2.status == 409 || r2.status == 202,
        "занято=409, быстро=202, получено {}",
        r2.status
    );

    // (в) полл до терминального состояния (мок локальный = секунды).
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut final_state = String::new();
    while Instant::now() < deadline {
        let r = call(&d.addr, "GET", "/v1/status", &[], b"");
        let js = r.json();
        let st = js["fetch"]["state"].as_str().unwrap_or("").to_owned();
        if st == "done" || st == "failed" {
            final_state = st;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(
        final_state,
        "done",
        "загрузка не дошла: {final_state}: {:?}",
        call(&d.addr, "GET", "/v1/status", &[], b"").json()["fetch"]
    );

    // (г) ГЛАВНЫЙ ПРОМЕР: файлы на месте РОВНО в раскладке каскадов.
    for rel in guard_daemon::weights::layout() {
        let p = dir.join(rel);
        assert!(p.is_file(), "файл не на месте по макету: {p:?}");
    }
    let r = call(&d.addr, "GET", "/v1/status", &[], b"");
    let js = r.json();
    let files = js["weights"]["present"].as_array().expect("список");
    assert!(
        files.iter().all(|f| f["ok"] == true),
        "после done карточка обязана гореть зелёным: {files:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fetch_endpoint_contract_offline() {
    // Контракт endpoints без сети: 409/контент-тип/отсутствие ПДн.
    let d = Daemon::start(&[]);
    let r = call(&d.addr, "GET", "/v1/status", &[], b"");
    assert_eq!(r.header("content-type").unwrap_or(""), "application/json");
    let j = r.json();
    assert!(j["vault"].is_object(), "счётчики vault в статусе (ТЗ B)");
    // Тело запроса не читается: POST с мусор-телом проходит (инъекций из
    // тела не собирается), а отказ = 503 с классом `host_denied` (тестовый
    // демон без HOME-дефолта: каталога нет) — не 4xx-за-тело.
    let r = call(&d.addr, "POST", "/v1/models/fetch", &[], b"not json");
    assert!(
        [202, 409, 503].contains(&r.status),
        "не-JSON тело не запрещено: {}",
        r.status
    );
    let body = r.text();
    assert!(
        !body.contains("not json"),
        "тело запроса не эхо-ится: {body}"
    );
    // Очистка фона после теста (job на петле к несуществующему хосту
    // краснеет failed сам; ждём терминала, чтобы не течь в соседний тест).
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let st = call(&d.addr, "GET", "/v1/status", &[], b"").json()["fetch"]["state"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        if st == "failed" || st == "done" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// JS-зуб счётчика токенов чата (#203 §4, нить e): паттерн `chatTokens`
/// обязан считать ОБЕ формы меток vault — stateless `[[F0#…]]`
/// (`MARKER_PREFIX`, `token.rs:117`) и session `[КЛАСС_н_nonce]` с ПОДЧЕРКИВАНИЕМ
/// (первичка `vault.rs:12/31`: `[PERSON_NAME_1_9A31C2D4]`), и НЕ считать
/// формат-подстановку `[Телефон:12345678901]` (SPEC §3). Прежний шаблон с `#`
/// в session-режиме давал «токенов раскрыто: 0» при N подмен — счётчик врал
/// нулём (ревью #203 §4.4); мутация паттерна краснит этот зуб.
///
/// Движок: `node` в PATH (win/linux-раннеры CI), иначе `/usr/bin/osascript -l
/// JavaScript` (mac-раннер). Оба исполняют ОДИН скрипт-файл (расхождение
/// движков = красный, не print-only-зелёный, false-green-реестр). Нет ни
/// одного — print SKIP (файл-контракт: живой промер; молча не проходит).
#[test]
fn chat_token_counter_counts_both_forms() {
    // JS-движок-зуб #203 §4 (нить e): фикстура tests/fixtures/
    // chat_tokens_runner.js меряет `chatTokens` из ui/app.js НА ОБЕИХ формах
    // меток vault (stateless `[[F0#…]]` = token.rs:117 MARKER_PREFIX;
    // session `[КЛАСС_н_nonce]` = первичка vault.rs:12/31, ПОДЧЁРКИВАНИЕ) и
    // на формат-подстановке `[Телефон:…]` (SPEC §3), которая считаться НЕ
    // должна. Прежний паттерн с `#` в session-режиме = «токенов раскрыто: 0»
    // при N подмен (ревью #203 §4.4). Ожидаемый промер: [2,3] (2 stateless +
    // 3 session-метки ЗАГЛАВНЫМИ классами: реальная форма `Grammar::LABEL`,
    // vault.rs:240/914, алфавит A-Z0-9_; формат-подстановка не считается).
    let app = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"));
    let fixture = include_str!("fixtures/chat_tokens_runner.js");
    let out = run_js_fixture(fixture, app);
    if out.trim().is_empty() {
        eprintln!("SKIP chat_token_counter: ни node, ни osascript недоступны");
        return;
    }
    assert_eq!(out.trim(), "[2,3]", "счётчик токенов (обе формы): {out}");
}

/// JS-зуб #225: шаблон-промпта «с задачей» + `labelForms` (обе формы метки,
/// контур chatTokens #203). Фикстура `task_prompt_runner.js` режет остров
/// функций из ui/app.js и меряет: подстановка уникальных меток со счётчиком,
/// graceful пустого списка («меток не найдено»), хвост = masked-текст,
/// labelForms = 2 (stateless + session; формат-подстановка `[Телефон:…]` и
/// числа `4508 455561`/`1 224 000` = НЕ формы), длина 48-меточного
/// промпта ≤ 2000 (константа + список, личных данных в шаблоне нет) и
/// `headerAlive` (константа доехала в остров целиком). Фикстура =
/// CRLF-нормализация входа (#225 CI-провен: win git checkout = \r\n,
/// маркеры с \n-якорем красны на windows; промер на LF-копии = идентичен).
#[test]
fn task_prompt_template_islands() {
    let app = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"));
    let fixture = include_str!("fixtures/task_prompt_runner.js");
    let out = run_js_fixture(fixture, app);
    if out.trim().is_empty() {
        eprintln!("SKIP task_prompt_template: ни node, ни osascript недоступны");
        return;
    }
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("зуб печатает JSON");
    assert_eq!(
        v["labelsCounted"],
        serde_json::json!(true),
        "список меток не подставлен: {out}"
    );
    assert_eq!(
        v["deduped"],
        serde_json::json!(true),
        "дубли меток не схлопнуты: {out}"
    );
    assert_eq!(
        v["graceful"],
        serde_json::json!(true),
        "пустой список не graceful: {out}"
    );
    assert_eq!(
        v["tailIsText"],
        serde_json::json!(true),
        "masked не в хвосте: {out}"
    );
    assert_eq!(
        v["headerAlive"],
        serde_json::json!(true),
        "константа-шаблон не доехала в остров целиком: {out}"
    );
    assert_eq!(
        v["forms"],
        serde_json::json!(2),
        "labelForms обязан считать ОБЕ формы и не считать формат-подстановку/числа: {out}"
    );
    let len48 = v["len48"].as_u64().expect("длина числом");
    assert!(len48 <= 2000, "48-меточный промпт раздут: {len48}");
}

/// Запуск фикстуры-раннера (#203 §4): node (argv = [script, app]), фолбэк
/// osascript JXA (argv в `-f`-скрипт не пробрасывается — первичка JXA-провен,
/// `-f` = не флаг: man osascript; путь app = литерал `__APP_PATH__`, который
/// тест подставляет в tmp-копию скрипта). Ошибка движка = panic (не тихий
/// SKIP); отсутствие ОБОИХ = пустая строка (зуб печатает SKIP сам).
fn run_js_fixture(fixture: &str, app: &std::path::Path) -> String {
    let dir = unique_tmp_path("fasad203-ct");
    std::fs::create_dir_all(&dir).expect("tmp создаётся");
    let script = dir.join("runner.js");
    std::fs::write(
        &script,
        fixture.replace("__APP_PATH__", &app.display().to_string()),
    )
    .expect("скрипт пишется");
    match std::process::Command::new("node")
        .arg(&script)
        .arg(app)
        .output()
    {
        Ok(v) if v.status.success() => {
            std::fs::remove_dir_all(&dir).ok();
            return String::from_utf8_lossy(&v.stdout).into_owned();
        }
        Ok(v) => panic!("node: {}", String::from_utf8_lossy(&v.stderr)),
        Err(_) => {}
    }
    #[cfg(target_os = "macos")]
    {
        let v = std::process::Command::new("/usr/bin/osascript")
            .args(["-l", "JavaScript"])
            .arg(&script)
            .output()
            .expect("osascript есть на mac-раннере");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            v.status.success(),
            "JXA: {}",
            String::from_utf8_lossy(&v.stderr)
        );
        String::from_utf8_lossy(&v.stdout).into_owned()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        String::new()
    }
}

/// #225: DOM/JS-контракты шаблона-промпта (кнопка, список меток из items,
/// чек-лист раскрытия, прокси-шаблон).
#[test]
fn ui_task_template_wiring() {
    let d = Daemon::start(&[]);
    let t = call(&d.addr, "GET", "/", &[], b"").text();
    assert!(
        t.contains("btnCopyTask") && t.contains("revealChecklist"),
        "в index.html нет #225-элементов (кнопка/чек-лист)"
    );
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    assert!(
        js.contains(r#"$("btnCopyTask").addEventListener"#) && js.contains("copyMaskedTask"),
        "нет кнопки «Скопировать с задачей» (#225)"
    );
    assert!(
        js.contains("res.data.items") && js.contains("lastLabels"),
        "список меток не из items anonymize-ответа (#225)"
    );
    assert!(
        js.contains("renderRevealChecklist") && js.contains(r#"$("revealChecklist")"#),
        "нет чек-листа раскрытия N из M / остаточные метки (#225)"
    );
    assert!(
        js.contains("taskPrompt(masked, lastLabels)"),
        "прокси-запрос не несёт шаблон-задачу (#225)"
    );
}

/// #225: демо-документ += платёжная связка с проверяемым итогом (задача
/// «посчитай арифметику» даёт модели результат, который оператор глазами
/// видит вернувшимся после расшифровки).
#[test]
fn ui_demo_carries_payment_arithmetic() {
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    let start = js.find("const DEMO_TEXT = [").expect("DEMO_TEXT есть");
    let end = js[start..]
        .find("].join(")
        .map(|o| start + o)
        .expect("join есть");
    let body = &js[start..end];
    assert!(
        body.contains("1 224 000") && body.contains("367 200") && body.contains("856 800"),
        "в DEMO_TEXT пропала арифметическая связка #225 (сумма/аванс/остаток)"
    );
}

/// #222: email-форма в демо (плюс-адрес = RFC-atext `+`, витрина вето).
#[test]
fn ui_demo_carries_email_plus_form() {
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    let start = js.find("const DEMO_TEXT = [").expect("DEMO_TEXT есть");
    let end = js[start..]
        .find("].join(")
        .map(|o| start + o)
        .expect("join есть");
    let body = &js[start..end];
    assert!(
        body.contains("support+reestr@cloud.i-o.example"),
        "в DEMO_TEXT пропала email-форма #222 (плюс-адрес)"
    );
}

/// #202: демо-документ + чат-панель — DOM/JS-контракты и покрытие классов.
#[test]
fn ui_demo_document_and_chat_panel() {
    let d = Daemon::start(&[]);
    let t = call(&d.addr, "GET", "/", &[], b"").text();
    for id in [
        "btnDemo",
        "demoNoAuto",
        "btnChat",
        "btnReveal",
        // #203 §4: ручной цикл без прокси (вставка ответа своего чата).
        "btnRevealPaste",
        "chatPaste",
        "outChat",
        "outChatRevealed",
        "upstream",
        "chatModel",
        "chatStatus",
    ] {
        assert!(t.contains(id), "в index.html нет #202-элемента: {id}");
    }
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    // JS-пара: fetch-контур чата = маршруты демона (не выдуманные),
    // заголовок #68, XSS-контракт (окна чата = textContent).
    assert!(
        js.contains("/v1/chat/completions"),
        "app.js не зовёт прокси-маршрут"
    );
    assert!(
        js.contains("X-Upstream-URL"),
        "app.js не шлёт заголовок #68"
    );
    assert!(
        js.contains(r#"outChat").textContent"#),
        "окно чата не через textContent"
    );
    assert!(
        js.contains(r#"outChatRevealed").textContent"#),
        "окно раскрытия не через textContent"
    );
    assert!(
        js.contains("/v1/deanonymize"),
        "раскрытие ответа не через deanonymize"
    );
    // #203 §4: кнопка вставки = отдельный обработчик (source="paste"),
    // читает #chatPaste, а не буфер стрима.
    assert!(
        js.contains(r#"$("chatPaste").value"#) && js.contains("revealChatAnswer(\"paste\")"),
        "нет пути раскрытия вставленного текста (#203 §4)"
    );
    // #203 §4: подсказка про короткие куски (прокси) и ручной полный путь.
    assert!(
        js.contains("≤3") || t.contains("≤3"),
        "UI не называет бюджет прокси-кнопки (#84)"
    );
    assert!(
        t.contains("Скопировать обезличенный") && t.contains("Раскрыть вставленный"),
        "README-контур цикла (полный путь через вставку) пропал из UI"
    );
    assert!(
        js.contains("demoAutofillOnLoad"),
        "нет автозаполнения примера"
    );
    assert!(js.contains("localStorage"), "нет localStorage-флага #202");

    // Демо-текст: извлекаем константу app.js и меряем покрытие + размер.
    let start = js.find("const DEMO_TEXT = [").expect("DEMO_TEXT есть");
    let end = js[start..]
        .find("].join(")
        .map(|o| start + o)
        .expect("join есть");
    let body = &js[start..end];
    // Фикстура = все 8 классов схемы (первичка ids ниже).
    let schema = call(&d.addr, "GET", "/assets/schema.json", &[], b"").json();
    let ids: Vec<&str> = schema["classes"]
        .as_array()
        .expect("классы")
        .iter()
        .map(|c| c["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids.len(), 8, "схема = 8 классов, фикстура на это завязана");
    // Эталонные вхождения классов (первичка schema.default.json: person_name,
    // inn, snils, card_pan, phone, email, address, passport).
    let probes = [
        ("person_name", "Ушакову Петру Сергеевичу"),
        ("inn", "7707083893"),
        ("snils", "112-233-455 95"),
        ("card_pan", "2202 2036 5123 4567"),
        ("phone", "+7 916 240-18-77"),
        ("email", "d.sokolov@romashka.example"),
        ("address", "107031, Москва, ул. Кузнецкий Мост"),
        ("passport", "45 09 123456"),
    ];
    assert_eq!(probes.len(), ids.len(), "число проб = число классов");
    for (class, probe) in probes {
        assert!(ids.contains(&class), "класс {class} выпал из схемы");
        assert!(
            body.contains(probe),
            "в DEMO_TEXT нет вхождения {class}: {probe}"
        );
    }
    // Формы #200 = витрина границ (в тексте, не в классе).
    assert!(body.contains("4508 455561"), "форма #200 паспорта пропала");
    assert!(
        body.contains("Ushakov Petr Sergeevich"),
        "транслит-пара пропала"
    );
    // Размер ≤ MAX_BODY_BYTES (1 MiB, config.rs DEFAULT_MAX_BODY_BYTES) и
    // ≥ 1.5 КБ («большой» = контракт issue, не регресс в абзац).
    let approx = body.len();
    assert!(
        approx <= 1_048_576,
        "DEMO_TEXT больше лимита тела: {approx}"
    );
    assert!(approx >= 1500, "DEMO_TEXT ужался (<1.5 КБ): {approx}");
}

#[test]
fn ui_html_carries_the_weights_card() {
    let d = Daemon::start(&[]);
    let r = call(&d.addr, "GET", "/", &[], b"");
    let t = r.text();
    for id in [
        "weightsPaneSettings",
        "weightsFilesS",
        "btnFetchS",
        "fetchBarS",
    ] {
        assert!(t.contains(id), "в index.html нет карточки: {id}");
    }
    assert!(t.contains("Скачать веса"), "нет подписи кнопки");
}

/// #198 + #201: DOM-контракт страницы (id-сетка, подписи, disabled-очередь,
/// pending-баннер). Статика: индекс отдаётся роутером, grep-контракт =
/// тест-пара изменению разметки (класс `ui_header_readout_...`: переименование
/// id молча ломает app.js, JS-скан `js_ids_exist_in_html` ниже краснеет
/// ровно на этом).
#[test]
fn ui_html_carries_steps_windows_and_pending_pane() {
    let d = Daemon::start(&[]);
    let t = call(&d.addr, "GET", "/", &[], b"").text();
    // #201 шаги 1-2-3 + disabled-очередь с причинами (title).
    for id in [
        "steps",
        "step1",
        "step2",
        "step3",
        "btnCopy",
        "outMasked",
        "outBack",
        "roundtrip",
    ] {
        assert!(t.contains(id), "в index.html нет #201-элементов: {id}");
    }
    assert!(t.contains("Что ушло"), "нет окна обезличенного");
    assert!(t.contains("Исходник вернулся"), "нет окна roundtrip");
    assert!(
        t.contains(r#"disabled title="сначала «Разобрать»""#),
        "очередь #201 (disabled + причина) потеряна"
    );
    assert!(t.contains("Новая сессия"), "п.4: сброс переименован");
    // #198: баннер ожидающего старта (скрыт до /health stage).
    assert!(t.contains("pendingPane"), "нет pending-баннера #198");
    // #201-добавка: строка режима человекочитая + путь смены (env-контур).
    assert!(t.contains("modeHint"), "нет строки подсказки режима #201");
    let js2 = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    assert!(
        js2.contains("FASAD_VAULT_MODE=session"),
        "app.js не объясняет смену режима (env-контур #201)"
    );
    // JS-пара: все getElementById-иды живут в HTML.
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    for id in [
        "step1t",
        "step2t",
        "step3t",
        "pendingPane",
        "btnCopy",
        "outMasked",
        "outBack",
        "roundtrip",
    ] {
        // `step1..3` адресуются конкатенацией ($("step" + i)), литералов нет;
        // проверка литералами = контракт для id, которые app.js зовёт напрямую.
        assert!(
            js.contains(&format!(r#""{id}""#)),
            "app.js не знает про {id} (id-контракт разъехался)"
        );
    }
}

// --- #220/#221: табы, страница настроек, GET/POST /v1/config ----------------

/// DOM-контракт двух табов + формы настроек + #221 (порог = number).
/// id-сетка = контракт app.js (переименование молча ломает фронт: тот же
/// класс, что `ui_html_carries_steps_windows_and_pending_pane`).
#[test]
fn ui_html_carries_tabs_and_settings_form() {
    let d = Daemon::start(&[]);
    let t = call(&d.addr, "GET", "/", &[], b"").text();
    for id in [
        "tabs",
        "tabWork",
        "tabSettings",
        "tabWorkPane",
        "tabSettingsPane",
        "weightsStrap",
        "settingsPane",
        "configRows",
        "settingsFile",
        "restartBanner",
        "settingsStatus",
    ] {
        assert!(t.contains(id), "в index.html нет #220-элемента: {id}");
    }
    assert!(t.contains("Настройки"), "нет подписи таба");
    assert!(t.contains("Работа"), "нет подписи таба");
    assert!(
        t.contains("требуется перезапуск"),
        "баннер перезапуска потерян (#219: hot-reload вне контура)"
    );
    // #221: порог = type=number с диапазоном валидатора, output-дубль убран.
    assert!(
        t.contains(r#"<input id="thr" type="number" min="0" max="1" step="0.01""#),
        "порог S не стал number (#221)"
    );
    assert!(!t.contains(r#"type="range""#), "range-ползунок остался");
    assert!(
        !t.contains("thrOut"),
        "output-дублирование значения осталось"
    );
    // Секретный инвариант страницы: формулировка «только env» в разметке.
    assert!(t.contains("FASAD_VAULT_KEY"), "нет строки про ключ");
}

/// JS-пара #220: табы и форма живут в app.js (localStorage-контур, POST-контур).
#[test]
fn ui_js_carries_tab_and_config_wiring() {
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/app.js"))
        .expect("app.js читается");
    for needle in [
        "fasad.tab",
        "showTab",
        "tabSettingsPane",
        "loadSettings",
        "saveConfig",
        "CFG_NUMERIC",
    ] {
        assert!(js.contains(needle), "app.js потерял {needle}");
    }
    assert!(js.contains("/v1/config"), "app.js не зовёт /v1/config");
    assert!(
        js.contains("min: 1024, max: 65535"),
        "порт без числавого диапазона валидатора (#221)"
    );
    assert!(
        js.contains("min: 0, max: 1, step: 0.01"),
        "пороги без диапазона [0,1] (#221)"
    );
}

/// `GET /v1/config` на живом демоне: таблица ключей = белый список,
/// СЕКРЕТОВ В ОТВЕТЕ НЕТ даже при заданном `FASAD_VAULT_KEY` (#220: ключ
/// показывается фактом «задан», не байтами), bind read-only.
#[test]
fn config_endpoint_lists_keys_and_hides_the_secret() {
    let d = Daemon::start(&SESSION);
    let r = call(&d.addr, "GET", "/v1/config", &[], b"");
    assert_eq!(r.status, 200, "config = read-only витрина");
    let body = r.text();
    let j = r.json();
    assert_eq!(j["vault_key"], "задан", "ключ = факт наличия, не значение");
    assert!(
        !body.contains("00112233445566778899aabbccddeeff"),
        "значение FASAD_VAULT_KEY утекло в GET /v1/config"
    );
    assert!(
        !body.contains("FASAD_VAULT_KEY\\\":\\\"00"),
        "ключ уехал значением: {body}"
    );
    let keys: Vec<&str> = j["entries"]
        .as_array()
        .expect("entries = массив")
        .iter()
        .map(|e| e["key"].as_str().expect("ключ строкой"))
        .collect();
    assert!(keys.contains(&"FASAD_MODEL_DIR"), "{keys:?}");
    assert!(keys.contains(&"FASAD_PORT"), "{keys:?}");
    assert!(
        !keys.contains(&"FASAD_VAULT_KEY") && !keys.contains(&"FASAD_BIND"),
        "секрет/бинд в таблице = утечка (белый список config.rs нарушен): {keys:?}"
    );
    for e in j["entries"].as_array().expect("entries") {
        let src = e["source"].as_str().expect("источник");
        assert!(
            matches!(src, "env" | "file" | "default"),
            "источник вне канона: {src}"
        );
        assert_eq!(e["restart_required"], true, "все ключи = старт-время");
    }
    // Бинд = строка адреса (read-only, вне таблицы), порт = фактический.
    let bind = j["bind"].as_str().expect("bind строкой");
    assert!(bind.starts_with("127.0.0.1:"), "бинд не loopback: {bind}");
    let port = j["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["key"] == "FASAD_PORT")
        .expect("порт в таблице")["value"]
        .as_str()
        .expect("значение строкой");
    assert_eq!(
        bind.rsplit(':').next().expect("порт в bind"),
        port,
        "эффективный порт обязан совпасть с bind (витрина не врёт)"
    );
}

/// POST /v1/config: запрещённые ключи = 403 с причиной; вне белого списка =
/// 403; мусорное значение = 422 текстом валидатора (не браузером); запись
/// в `FASAD_CONFIG` (tmp-файл харнеса) = 200 + «требуется перезапуск».
#[test]
#[allow(clippy::too_many_lines)] // решётка POST-отказов = один тест-контракт (решётка ног #224)
fn config_write_endpoint_validates_and_refuses_secrets() {
    // Харнес уже указывает FASAD_CONFIG в tmp (изоляция E-контура); для
    // записи нужен сушествующий каталог — свой файл на свой порт.
    let dir = unique_tmp_path("fasad-cfg-ui");
    std::fs::create_dir_all(&dir).expect("каталог");
    let file = dir.join("config");
    // Файл с валидным FASAD_HF_HOST: он же живая нога #224 MAJOR-2 (GET
    // обязан показать файловый хост и source=file, а не «дефолт + file»),
    // и же база для всех POST-ног ниже.
    std::fs::write(
        &file,
        "# харнес #220\nFASAD_HF_HOST=https://from-file.example.test\n",
    )
    .expect("база");
    let d = Daemon::start(&[
        ("FASAD_CONFIG", file.to_str().expect("utf-8 путь")),
        ("FASAD_PORT", "0"),
    ]);
    {
        let r = call(&d.addr, "GET", "/v1/config", &[], b"");
        let j = r.json();
        let row = j["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["key"] == "FASAD_HF_HOST")
            .expect("HF_HOST в таблице");
        assert_eq!(
            row["value"], "https://from-file.example.test",
            "файловый HF_HOST обязан доходить до витрины: {j}"
        );
        assert_eq!(row["source"], "file", "источник = файл: {j}");
    }
    let post = |body: String| {
        call(
            &d.addr,
            "POST",
            "/v1/config",
            &[("content-type", "application/json")],
            body.as_bytes(),
        )
    };
    // Секрет = 403 с причиной, файл не тронут.
    let r = post(r#"{"key":"FASAD_VAULT_KEY","value":"aa"}"#.to_owned());
    assert_eq!(r.status, 403, "секрету в файл запрещено");
    assert!(r.text().contains("env"), "причина обязана назвать канал");
    // Вне белого списка = отказ.
    assert_eq!(
        post(r#"{"key":"FASAD_BUDUSCHEE","value":"1"}"#.to_owned()).status,
        403
    );
    // Бинд (инвариант loopback) = 403.
    assert_eq!(
        post(r#"{"key":"FASAD_BIND","value":"8.8.8.8"}"#.to_owned()).status,
        403
    );
    // Мусорные значения = 422 ТЕКСТОМ валидатора (#221: серверная стена, не
    // браузер; #224 MAJOR-1: тихого фолбэка `port_from_value` в контуре
    // записи нет ни на одной ноге; #224 MAJOR-2: HF_HOST бьётся парсером
    // fetch-контура).
    for (body, why) in [
        (r#"{"key":"FASAD_THREADS","value":"abc"}"#, "не число"),
        (r#"{"key":"FASAD_PORT","value":"abc"}"#, "порт не число"),
        // 0 = «случайный порт»: легален в env/файле (харнес-контракт #224),
        // вне контура записи (UI): 422 текстом границы.
        (
            r#"{"key":"FASAD_PORT","value":"0"}"#,
            "нулевой порт = харнес-контур, не UI",
        ),
        (r#"{"key":"FASAD_PORT","value":"-1"}"#, "отрицательный порт"),
        (r#"{"key":"FASAD_PORT","value":"65536"}"#, "за u16"),
        (r#"{"key":"FASAD_PORT","value":"99999"}"#, "за u16"),
        // #224 MINOR: привилегированный порт = 422 текстом диапазона, а не
        // rc=1 PermissionDenied после рестарта.
        (
            r#"{"key":"FASAD_PORT","value":"1"}"#,
            "1 < 1024 привилегированный",
        ),
        (
            r#"{"key":"FASAD_PORT","value":"1023"}"#,
            "1023 привилегированный",
        ),
        (
            r#"{"key":"FASAD_HF_HOST","value":"garbage-not-a-url"}"#,
            "не URL",
        ),
        (
            r#"{"key":"FASAD_HF_HOST","value":"ftp://files.example.test"}"#,
            "не https",
        ),
        (
            r#"{"key":"FASAD_HF_HOST","value":"https://user@evil.example"}"#,
            "учётки в авторити",
        ),
    ] {
        let r = post(body.to_owned());
        assert_eq!(r.status, 422, "{why}: ожидаем 422, ответ: {}", r.text());
    }
    assert!(
        post(r#"{"key":"FASAD_PORT","value":"1"}"#.to_owned())
            .text()
            .contains("1024..=65535"),
        "текст отказа обязан называть диапазон"
    );
    // Грань диапазона легальна (PORT=1024) — зуб не мёртвый.
    let r = post(r#"{"key":"FASAD_PORT","value":"1024"}"#.to_owned());
    assert_eq!(r.status, 200, "1024 = нижняя грань: {}", r.text());
    // Инвариант порогов = 422 текстом (gray_hi 0.9 > дефолтный tau_high 0.8).
    let r = post(r#"{"key":"FASAD_GRAY_HI","value":"0.9"}"#.to_owned());
    assert_eq!(r.status, 422, "инвариант красен: {}", r.text());
    assert!(r.text().contains("пороги"), "текст инварианта потерян");
    // Легальная запись = 200 + restart_required + файл обновлён; значение
    // пишется trimmed (#224 MINOR): « 2 » → «FASAD_THREADS=2».
    let r = post(r#"{"key":"FASAD_THREADS","value":" 2 "}"#.to_owned());
    assert_eq!(r.status, 200, "запись прошла: {}", r.text());
    assert_eq!(
        r.json()["restart_required"],
        true,
        "успех обязан требовать перезапуск"
    );
    let text = std::fs::read_to_string(&file).expect("файл");
    assert!(text.contains("FASAD_THREADS=2"), "{text}");
    assert!(!text.contains("= 2 "), "значение пишется trimmed: {text}");
    assert!(
        text.contains("FASAD_HF_HOST=https://from-file.example.test"),
        "HF_HOST обязан пережить перезапись (ключевая нога #224): {text}"
    );
    assert!(
        text.contains("# харнес"),
        "комментарий не пережил запись: {text}"
    );
    assert!(
        // Имя-первичка #224 MINOR: `.part` = file_name + ".part" = `config.part`;
        // после rename обязана исчезнуть (атомарность).
        !dir.join("config.part").exists(),
        ".part обязан исчезнуть после rename (атомарность)"
    );
    // Только-для-файла (FASAD_SCHEMA) = 403 key_read_only (ui_editable=false).
    assert_eq!(
        post(r#"{"key":"FASAD_SCHEMA","value":"/tmp/x.json"}"#.to_owned()).status,
        403
    );
    std::fs::remove_dir_all(&dir).ok();
}
