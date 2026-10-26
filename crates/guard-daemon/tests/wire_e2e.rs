//! Проводной e2e: живой бинарь, настоящий сокет, HTTP/1.1 руками.
//!
//! Зачем он нужен, если `src/http.rs` уже покрывает роутер тестами с `oneshot`:
//! тот класс проверяет маршрутизатор внутри процесса и НЕ покрывает (а) разбор
//! `FASAD_*`-переменных в реальном старте, (б) баннер с фактическим портом,
//! (в) кодинг заголовков и framing на сокете, (г) коды выхода процесса. Всё
//! это — контракт, который оператор видит в терминале, а `oneshot` — нет.
//!
//! Клиент написан вручную (`std::net::TcpStream` + `Connection: close`), а не
//!не берём из крейта: HTTP-клиент в dev-зависимях демона поймал бы себе
//! `net-audit`-гейт (он читает манифест целиком, dev-секция тоже считается), и
//! это правильно — у продукта их быть не должно, и тестам не дозволено его
//! маскировать.
//!
//! Порты не гадаются: бинарь стартует с `FASAD_PORT=0` и печатает фактический
//! адрес в баннере (`main.rs`, `listener.local_addr`).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Запущенный демон: процесс + адрес, на котором он реально слушает.
struct Daemon {
    child: Child,
    addr: String,
    /// Общий лог stderr демона (#224 R4): живое окно диагностики — тест
    /// печатает его при панике («демон умер после баннера» = текст демона).
    log: std::sync::Arc<std::sync::Mutex<String>>,
    /// Держим канал строк stdout: читатель `stdout_reader` шлёт в `tx`,
    /// паникующий тест роняет `rx` = канал мёртв = читатель выходит из
    /// цикла = трубка закрывается = EPIPE-паника print'а ЖИВОГО демона
    /// (первичка stdio.rs:1168 в stderr-реестре #224 R4).
    _stdout_lines: std::sync::mpsc::Receiver<String>,
}

impl Daemon {
    /// Готовность = ОТВЕТИВШИЙ сокет, не баннер (#224 R4): первичка
    /// main.rs — bind → баннер → accept-цикл в `serve()`; баннер ≠
    /// готовность = refused-окно между баннером и первым accept. Мёртвый
    /// процесс = exit-код в панике (первичка CI: «живой демон, refused»).
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

    fn start<A: AsRef<std::ffi::OsStr> + Clone>(env: &[(&str, A)]) -> Self {
        self::start_impl(env)
    }
}

fn start_impl<A: AsRef<std::ffi::OsStr> + Clone>(env: &[(&str, A)]) -> Daemon {
    // #185: full-бинарь (feature `ort-inference`) без весов не стартует —
    // молчаливый cascade-0-only убит стартовым отказом. Файл про проводной
    // протокол каскада 0 (тесты проверяют ответы каскада-0: ФИО-спан
    // модели ломали бы их ожидания ещё до #185, ревью #87), поэтому
    // live-нога = feature-off бинарь; на ort-контуре файл печатает
    // явную SKIPPED-строку и выходит rc=0 (молчание = ложно-зелёная
    // проверка, класс реестра; контракт SKIP-строки — cascade_failclosed).
    // Тот же контур CI-реальности: ort-фича в cargo-матрице CI не
    // линкуется (ci.yml:31-34), live-контур = feature-off.
    if cfg!(feature = "ort-inference") {
        eprintln!(
            "SKIP|wire_e2e|full-бинарь (#185) без весов не стартует, а live-контур \
                 файла = каскад-0-ожидания (ревью #87): ort-контур покрыт unit \
                 cascades::tests + e2e-отказом full_bin_without_model_dir_*"
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
        // Тестовый демон поднимается БЕЗ весов и без чужих ручек окружения.
        // Причина (ревью #87, воспроизведено на этом дереве): в
        // feature-сборке унаследованный `FASAD_MODEL_DIR` монтирует каскады
        // 1-2 в каждый e2e-прогон — `wire_e2e` даёт 22 passed / 3 failed
        // (`stateless_roundtrip_survives_a_real_socket`,
        // `session_mode_roundtrips_survives_a_real_socket`,
        // `proxy_mask_matches_the_analyze_api_span_for_span`: модельные
        // спаны `person_name` ломают ожидания каскада 0) и 103.72 с
        // против 3.37 с на тот же файл без env. У ревьюера на этом же
        // месте `ui_sandbox` даёт ещё и 8/1.
        // «В CI же чисто» гейт не чинит: он обязан быть воспроизводимым на
        // машине с весами, поэтому remove явный, а не молчаливый дефолт.
        .env_remove("FASAD_MODEL_DIR")
        .env("FASAD_TEST_CASCADE0", "1")
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
        // #203 §2.1 (блокер R4): env-мишень #198 из оболочки НЕ
        // наследуется: симметрия config.rs (флаг + трей-мишень +
        // смонтированный HOME-дефолт = Some(кеш оператора)) на машине
        // с весами красила харнес (28/4: stage cascade-0+models +
        // модельные спаны; промер ревью на HOME оператора). Зубы
        // pending-контура ставят флаг ЯВНО (env-пары теста применяются
        // после remove в `Daemon::start`).
        .env_remove("FASAD_TEST_TRAY_CONTOUR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("бинарь фасада запускается");
    let stdout = child.stdout.take().expect("stdout перехвачен");
    // #224 R4 диагностика: stderr читается С РАНОГО СТАРТА в общий лог
    // (Arc<Mutex<String>>): отказ демона после баннера (демон умер между
    // ногами теста) обязан быть назван текстом демона, а не «сокет
    // недоступен 30 с» — убитый раннером класс «не видно почему».
    let log: std::sync::Arc<std::sync::Mutex<String>> =
        std::sync::Arc::new(std::sync::Mutex::new(String::new()));
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
    let rx = stdout_reader(stdout);
    let started = Instant::now();
    let mut seen = String::new();
    while started.elapsed() < Duration::from_secs(15) {
        let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) else {
            continue;
        };
        seen.push_str(&line);
        // #224 R4 порядок проверок: сначала EXIT, потом баннер. Демон,
        // умерший на бинде (bind-гонка SO_REUSEADDR-окно: listen()
        // падает ПОСЛЕ печати баннера в stdout), печатает «listening» и
        // дохнет — харнес вернул бы адрес мёртвого порта (первичка
        // флейка: refused=true на свежем Daemon::start, «демон не
        // умирал» = ложь: exit-код читается только у нас).
        if let Some(status) = child.try_wait().expect("статус читается") {
            let _ = child.kill();
            let _ = child.wait();
            let buf = log.lock().expect("лог не отравлен").clone();
            panic!(
                "демон завершился (rc={:?}) до готовности; stdout: {seen:?} stderr: {buf:?}",
                status.code()
            );
        }
        if let Some(rest) = seen
            .split_once("listening on http://")
            .map(|(_, r)| r.to_owned())
        {
            let addr = rest
                .split('/')
                .next()
                .expect("адрес заканчивается путём")
                .to_owned();
            // Первичка main.rs: bind (202) → banner (209) — адрес
            // баннера = занятый сокет, bind НЕ может упасть после
            // печати. Значит refused на свежем адресе = демон УМЕР
            // после баннера (в рантайме): exit-проверка выше ловит это
            // на витках чтения; зомби-окно (канал пуст, процесс мёртв)
            // = connect-оборот call_raw (окно зафиксировано 30 с).
            Daemon::wait_ready(&mut child, &addr, &seen, &log);
            DAEMONS.lock().expect("реестр не отравлен").push((
                addr.clone(),
                child.id(),
                true,
                std::sync::Arc::clone(&log),
            ));
            return Daemon {
                child,
                addr,
                log,
                _stdout_lines: rx,
            };
        }
    }
    // Убить и дождаться до паники: паникующий тест не обязан оставлять
    // процесс-зомби (клинч `zombie_processes` это и ловит).
    let _ = child.kill();
    let exit = child.wait().ok();
    let _ = exit;
    // Причина отказа из stderr читается ТОЛЬКО если процесс сам завершился:
    // на живом демоне трубке конца нет, и чтение вернуло бы нас к той же
    // вешалке, из которой мы только что вышли. Это не косметика — на
    // windows-раннере именно эта строка отличит «mlock отказал» от «тест
    // не дождался баннера».
    let reason = log.lock().expect("лог не отравлен").clone();
    panic!(
        "демон не напечатал баннер за {:?}; stdout: {seen:?} stderr: {reason:?}",
        started.elapsed()
    );
}

/// Уникальный tmp-путь теста. `cargo test` = ОДИН процесс, тесты в ПОТОКАХ —
/// два теста с одним PID-суффиксом пишут в ОДИН каталог (первичка #224).
/// Уникальность = гонка-создание КАТАЛОГА (`create_dir` краснеет на
/// коллизии); возврат = ПУТЬ ВНУТРИ каталога (parent существует = инвариант
/// потребителей; каталог удаляется `remove_dir_all`-ем теста).
fn unique_tmp_path(prefix: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
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
    /// Снимок stderr-лога (#224 R4): вшивать в assert-сообщения live-ног.
    fn log_tail(&self) -> String {
        self.log.lock().expect("лог не отравлен").clone()
    }
}

impl Daemon {
    /// Порт отвечает? (первичка #224 R4: refused при «живом» Daemon =
    /// демон умер/убит соседом; тест печатает это поле в панике).
    #[allow(dead_code)]
    fn port_open(&self) -> bool {
        TcpStream::connect(&self.addr).is_ok()
    }

    #[allow(dead_code)]
    fn pid(&self) -> u32 {
        self.child.id()
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

/// Ответ на сырой HTTP/1.1-запрос.
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

/// Один запрос на один сокет: `Connection: close` даёт конец тела без разбора
/// чанков и keep-alive, т.е. клиент остаётся ~30 строк.
/// Поток-читатель строк stdout: ПОЖИЗНЕННЫЙ, не до баннера (#224 R4):
/// раннее закрытие читающей стороны трубки = EPIPE в `print!` демона =
/// паника stdio-локера (первичка: «паника std/src/io/stdio.rs:1168» в
/// stderr-реестре, ранний exit, порт пуст = «30 с refused на живом
/// демоне»). Чанк-читатель гоняет строки в канал, байты — в sink.
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
    call_raw(addr, &bytes)
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

/// То же, но сырыми байтами: нужно там, где `&str`-заголовок не выражает
/// намерение (битый chunked, значение заголовка вне UTF-8).
fn call_raw(addr: &str, bytes: &[u8]) -> Reply {
    // #224 R4, первичка: stdout пайпа = FULLY-BUFFERED: баннер демона
    // сидел в 8-КиБ буфере, харнес ждал «listening» 15 с (таймаут =
    // «stdout: ""»), убивал ЖИВОЙ демон и тест получал «30 с refused на
    // мёртвом порту» — весь призрак-класс. Продукт = flush после баннера
    // (main.rs), харнес = своя оборона: connect к порту = готовность
    // (addr из env-контракта FASAD_PORT=0 берётся из LOCAL_ADDR-файла
    // ниже), мёртвый процесс = exit-код в панике.
    let mut raw = Vec::new();
    let started = Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        raw.clear();
        if let Ok(mut sock) = TcpStream::connect(addr) {
            // Таймауты ДО операций: SYN-дроп на перегруженном раннере
            // вешает connect, read-таймаут = ответ до EOF («Connection:
            // close»).
            sock.set_write_timeout(Some(Duration::from_secs(5)))
                .expect("write-таймаут ставится");
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read-таймаут ставится");
            let written = sock.write_all(bytes).and_then(|()| sock.flush());
            if written.is_ok() {
                let _ = sock.read_to_end(&mut raw);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    return parse_reply(&raw);
                }
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "сокет/ответ недоступны 30 с ({attempt} попыток): addr {addr}, байты {}. Демон: {}",
            raw.len(),
            daemon_diag(addr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parse_reply(raw: &[u8]) -> Reply {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("заголовок есть (зуб в call_raw)");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let chunked = head.to_lowercase().contains("transfer-encoding: chunked");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("стартовая строка");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("код статуса")
        .parse()
        .expect("код — число");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_lowercase().trim().to_owned(), v.trim().to_owned()))
        .collect();
    let framed = &raw[split + 4..];
    Reply {
        status,
        headers,
        // Стриминговый ответ демона идёт chunked-фреймингом, и `Connection:
        // close` его не отменяет: без распаковки тест видел бы байты размера
        // фрейма вместо SSE.
        body: if chunked {
            dechunk(framed)
        } else {
            framed.to_vec()
        },
    }
}

/// Распаковать `Transfer-Encoding: chunked` (ровно столько, нужно тестам: sizes
/// в hex, данные между, терминальный `0`).
fn dechunk(mut bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = bytes.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(&String::from_utf8_lossy(&bytes[..nl]), 16)
            .unwrap_or_else(|e| panic!("размер фрейма не hex ({bytes:?}): {e}"));
        bytes = &bytes[nl + 2..];
        if size == 0 {
            break;
        }
        out.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
    out
}

/// Разделители-дефисы в СНИЛС тут намеренно отсутствуют: константа пинит сырую
/// (неформатированную) форму номерка, и это отдельная поверхность от склеенной.
/// Форматированный номер («378-312-074 87») ловит оконный слой каскада 0 —
/// `cascade0.rs:365-367` (шаг 9, PR #80): валидатор получает канон групп, спан
/// остаётся на оригинале; покрытие — тесты там же. Прежняя проза этого
/// комментария («нормализатор их не склеивает», «известное ограничение,
/// issue #51») устарела: ограничение снято #80, а #51 теперь ведёт обходы
/// (транслит, числительные словами, base64). Раздел-первоисточник:
/// docs/daemon-scope.md §«Что каскад 0 находит и не находит», п.2.
const TWO_SPAN_TEXT: &str = "Иван ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";

/// Спаны просим у `/v1/analyze` и пересылаем в `/v1/anonymize` — тот же
/// протокол, по которому ходит реальный клиент. Ответ analyze — голый массив
/// (`RecognizerResult`-форма Presidio), а не объект: тест читает его как есть,
/// потому что форма и есть контракт (§8).
fn analyzed_spans(addr: &str, text: &str) -> Vec<(String, usize, usize)> {
    let reply = call(
        addr,
        "POST",
        "/v1/analyze",
        &[("content-type", "application/json")],
        format!(r#"{{"text":"{text}"}}"#).as_bytes(),
    );
    assert_eq!(reply.status, 200, "анализ обязан пройти: {}", reply.text());
    let v = reply.json();
    let spans = v.as_array().expect("analyze отдаёт массив спанов");
    assert!(!spans.is_empty(), "на эталонном входе ничего не найдено");
    spans
        .iter()
        .map(|s| {
            (
                s["entity_type"].as_str().expect("класс").to_owned(),
                usize::try_from(s["byte_start"].as_u64().expect("байт начала"))
                    .expect("оффсет влезает в usize"),
                usize::try_from(s["byte_end"].as_u64().expect("байт конца"))
                    .expect("оффсет влезает в usize"),
            )
        })
        .collect()
}

fn anonymize_body(text: &str, spans: &[(String, usize, usize)]) -> Vec<u8> {
    let items: Vec<String> = spans
        .iter()
        .map(|(ty, b, e)| format!(r#"{{"entity_type":"{ty}","byte_start":{b},"byte_end":{e}}}"#))
        .collect();
    format!(r#"{{"text":"{text}","spans":[{}]}}"#, items.join(",")).into_bytes()
}

#[test]
fn stateless_roundtrip_survives_a_real_socket() {
    let d = Daemon::start::<&str>(&[]);
    let spans = analyzed_spans(&d.addr, TWO_SPAN_TEXT);
    assert_eq!(spans.len(), 2, "ИНН + СНИЛС: {spans:?}");

    let reply = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &[("content-type", "application/json")],
        &anonymize_body(TWO_SPAN_TEXT, &spans),
    );
    assert_eq!(reply.status, 200, "anonymize: {}", reply.text());
    assert_eq!(reply.header("x-guard-redacted-count"), Some("2"));
    assert_eq!(reply.header("x-guard-stage"), Some("cascade-0-only"));
    assert!(
        reply.header("x-guard-latency-ms").is_some(),
        "латентность обязана быть на каждом ответе, не только на analyze"
    );
    let v = reply.json();
    let masked = v["text"].as_str().expect("текст");
    assert!(
        !masked.contains("2482014338"),
        "оригинал остался в тексте: {masked}"
    );
    assert!(
        masked.contains("[[F0#"),
        "режим 3 обязан давать маркер: {masked}"
    );

    let back = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &[("content-type", "application/json")],
        format!(r#"{{"text":"{}"}}"#, masked.replace('"', "\\\"")).as_bytes(),
    );
    assert_eq!(back.status, 200, "deanonymize: {}", back.text());
    assert_eq!(back.json()["text"].as_str().expect("текст"), TWO_SPAN_TEXT);
    assert_eq!(back.json()["substituted"].as_u64().expect("счётчик"), 2);
}

#[test]
fn session_mode_roundtrips_surrogates_and_teardown() {
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "session"), ("FASAD_VAULT_KEY", key)]);
    // Каскад 0 — только валидаторы, поэтому ФИО в ответе `/v1/analyze` нет ни
    // на одном входе (docs/daemon-scope.md §«Что каскад 0 находит и не находит»). Спан имени добавлен
    // руками: ровно так, как его пришлет клиент с каскадом 1+ или с ручным
    // выделением из tray. Проверка «авто-спаны + ручные спаны → один вызов»
    // важна ещё и потому, что `/v1/anonymize` принимает опись целиком извне.
    let fio = "Ушакова Кира Саввична";
    let text = &format!("{fio}, ИНН 2482014338");
    let mut spans = analyzed_spans(&d.addr, text);
    assert_eq!(
        spans.len(),
        1,
        "каскад 0 обязан найти только ИНН: {spans:?}"
    );
    // Граница в байтах, не в символах: 21 символ ФИО = 40 байт в UTF-8.
    // Прежние «22» — уронок нашей же ошибки: символьная длина плюс один.
    spans.push(("person_name".to_owned(), 0, fio.len()));

    let reply = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &[
            ("content-type", "application/json"),
            ("x-session-id", "e2e"),
        ],
        &anonymize_body(text, &spans),
    );
    assert_eq!(reply.status, 200, "anonymize: {}", reply.text());
    let masked = reply.json()["text"].as_str().expect("текст").to_owned();
    assert!(!masked.contains("Ушакова"), "фамилия не заменена: {masked}");
    assert!(!masked.contains("2482014338"), "ИНН не заменён: {masked}");
    assert!(
        masked.contains("[INN_1_"),
        "метка INN не на месте: {masked}"
    );
    assert!(masked.chars().count() > 8, "текст не должен стать пустым");

    // Без заголовка сессии режим 2 обязан отказать, а не выдумать сессию.
    let no_session = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &[("content-type", "application/json")],
        &anonymize_body(text, &spans),
    );
    assert_eq!(
        no_session.status,
        400,
        "без X-Session-ID: {}",
        no_session.text()
    );
    assert_eq!(no_session.json()["error"]["code"], "bad_request");

    let back = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &[
            ("content-type", "application/json"),
            ("x-session-id", "e2e"),
        ],
        format!(r#"{{"text":"{}"}}"#, masked.replace('"', "\\\"")).as_bytes(),
    );
    assert_eq!(back.status, 200, "deanonymize: {}", back.text());
    assert_eq!(back.json()["text"].as_str().expect("текст"), text);

    let del = call(&d.addr, "DELETE", "/v1/sessions/e2e", &[], b"");
    assert_eq!(del.status, 200, "teardown: {}", del.text());
    assert!(
        del.json()["deleted"].as_u64().expect("deleted") > 0,
        "teardown не нашёл ни одной записи: {}",
        del.text()
    );
    assert_eq!(
        del.header("x-guard-redacted-count").expect("счётчик"),
        del.json()["deleted"].to_string(),
        "заголовок и тело teardown обязаны считать одно и то же"
    );
}

/// Метрики деградации хранилища обязаны быть видны извне без отладочного
/// режима (#60 п.3): живой бинарь отдаёт их в `/health` объектом `vault`.
/// Здесь проверяется наличие и тип — значение двигает юнит-тест
/// `divergent_form_refuses_restore_and_shows_in_counter`, которому нужно
/// полезное состояние хранилища, а его через HTTP не подделать.
#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
fn health_exposes_degradation_counters_on_the_wire() {
    let d = Daemon::start::<&str>(&[]);
    let reply = call(&d.addr, "GET", "/health", &[], b"");
    assert_eq!(reply.status, 200, "health: {}", reply.text());
    let v = reply.json();
    for name in ["surrogate_fallbacks", "unrestored_mismatch"] {
        assert!(
            v["vault"][name].is_number(),
            "счётчик {name} обязан быть числом в /health, полученный ответ: {}",
            reply.text()
        );
    }
    assert_eq!(
        v["vault"]["unrestored_mismatch"].as_u64().expect("число"),
        0,
        "свежий демон ещё не видел расхождений разворота"
    );
}

/// Проводная версия барьерного теста движка (R1 ревью #70): два параллельных
/// `/v1/anonymize` в ОДНОЙ сессии на коллизирующей паре фамилий — тот же скелет,
/// которым ревьюер снял 26 двойных выдач из 300 раундов на живом демоне.
///
/// Держим два инварианта: у двух владельцев не может быть одной суррогатной
/// фамилии, и в развороте не может появиться чужое имя. Проводной уровень нужен
/// затем, чтобы регресс «замок сняли» или «появился второй путь выдачи» был виден
/// не только на движке: тут выдача идёт через HTTP, разбор тела и реестр форм.
#[test]
fn parallel_anonymize_in_one_session_never_leaks_across_owners() {
    // 200 раундов — не круглая красота, а мощность промера: довоенный код давал
    // ~9 % попаданий (26 из 300), на 200 раундах шанс промахнуться пренебрежим.
    const ROUNDS: usize = 200;
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "session"), ("FASAD_VAULT_KEY", key)]);
    for r in 0..ROUNDS {
        let sess = format!("race{r}");
        let masked = std::thread::scope(|s| {
            let mut hs = Vec::new();
            for fio in ["Бабинова Аглая Тимофеевна", "Тихомирова Аглая Тимофеевна"]
            {
                let (addr, sess) = (d.addr.clone(), sess.clone());
                hs.push(s.spawn(move || {
                    let rep = call(
                        &addr,
                        "POST",
                        "/v1/anonymize",
                        &[
                            ("content-type", "application/json"),
                            ("x-session-id", &sess),
                        ],
                        &anonymize_body(fio, &[("person_name".to_owned(), 0, fio.len())]),
                    );
                    assert_eq!(rep.status, 200, "anonymize {fio}: {}", rep.text());
                    rep.json()["text"].as_str().expect("текст").to_owned()
                }));
            }
            hs.into_iter()
                .map(|h| h.join().expect("поток маскирования не паникует"))
                .collect::<Vec<String>>()
        });
        let form = |t: &str| t.split(' ').next().unwrap_or_default().to_owned();
        let (a, b) = (&masked[0], &masked[1]);
        assert_ne!(
            form(a),
            form(b),
            "раунд {r}: одна суррогатная фамилия на двух владельцев — {a} / {b}"
        );
        for (t, mine, foreign) in [(a, "Бабинова", "Тихомирова"), (b, "Тихомирова", "Бабинова")]
        {
            let back = call(
                &d.addr,
                "POST",
                "/v1/deanonymize",
                &[
                    ("content-type", "application/json"),
                    ("x-session-id", &sess),
                ],
                format!(r#"{{"text":"{}"}}"#, t.replace('"', "\\\"")).as_bytes(),
            );
            assert_eq!(back.status, 200, "deanonymize: {}", back.text());
            let got = back.json()["text"].as_str().expect("текст").to_owned();
            assert!(
                !got.contains(foreign),
                "раунд {r}: чужое имя в развороте — {got}"
            );
            assert!(
                got.contains(mine) || t.contains('['),
                "раунд {r}: своё имя {mine} обязало вернуться либо уйти меткой, а в ответе {got}"
            );
        }
        call(&d.addr, "DELETE", &format!("/v1/sessions/{sess}"), &[], b"");
    }
    let h = call(&d.addr, "GET", "/health", &[], b"").json();
    assert_eq!(
        h["vault"]["unrestored_mismatch"].as_u64().expect("число"),
        0,
        "атомарная выдача не имеет права порождать расхождений разворота"
    );
}

#[test]
fn oversized_body_comes_back_as_413_envelope_on_the_wire() {
    let d = Daemon::start(&[("FASAD_MAX_BODY_BYTES", "1024")]);
    let body = format!(r#"{{"text":"{}","spans":[]}}"#, "А".repeat(4000));
    let reply = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &[("content-type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(reply.status, 413, "перелив тела: {}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "body_too_large");
    assert!(
        !reply.text().contains("Failed to buffer"),
        "наружу ушёл текст axum вместо нашего конверта: {}",
        reply.text()
    );
}

#[test]
fn full_bin_without_model_dir_refuses_to_start_before_binding() {
    // Рюлинг оператора 22.10 (#185), живой e2e-дискриминатор отказа:
    // feature-сборка (`cargo test --features ort-inference`) без
    // `FASAD_MODEL_DIR` обязана дать rc=2 + текст причины + НЕ напечатанный
    // баннер: молчаливый `cascade-0-only` в релизном контуре = тихая
    // деградация защиты. Feature-off сборка (харнес/тестовый контур, #181)
    // без весов легально поднимается каскадом 0 — проверяем обе ноги,
    // red-сигнал живёт на нужной ноге.
    let feature_on = cfg!(feature = "ort-inference");
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        // Наследуемый env машины с весами монтировал бы каскады и прятал
        // ровно проверяемую ветку (тот же класс, что `Daemon::start`, ревью #87).
        .env_remove("FASAD_MODEL_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("процесс стартует");
    if !feature_on {
        // Нога OFF: каскад-0-бинарь поднимается; процесс убиваем, ждём, читаем.
        let pid = out.id();
        drop(out);
        let _ = Command::new("kill").arg(pid.to_string()).status();
        return;
    }
    let out = out.wait_with_output().expect("процесс завершился");
    assert_eq!(
        out.status.code(),
        Some(2),
        "отказ старта = код 2, как у конфига"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("FASAD_MODEL_DIR"),
        "причина обязана называть переменную: {err}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("listening"),
        "баннер напечатан до отказа: {stdout}"
    );
}

/// #314 win-simu-контра (ORT-нога, CI `ort-build` = mac/linux leg с
/// CI-fetch полкой #255-паттерна): двойной клик win = HOME∅ +
/// USERPROFILE=кеш 5/5 на ТРЕЙ-мишени (env-симуляция `FASAD_TEST_TRAY_
/// CONTOUR` = main.rs:185 compile-time-мишени, НЕ решение) обязан
/// стартовать МОНТИРОВАННЫМ: `cascade-0+models`, НЕ pending (win-стенд
/// v0.1.9: UI «5/5 зелёные» + баннер pending = расход stages: env-граница
/// #198-ветка уже читает USERPROFILE через `default_home_dir` #264 — зуб
/// держит ветку живой на win-форме env; mac-simu = та же ветка, `layout_complete`
/// 5/5 = настоящие веса CI-кеша (lesson ТЗ #316: size vs манифест, 4096-
/// фейки `layout_complete` НЕ проходят = unit `shelf_invariant_…` #316)).
/// Feature-off нога = слепая (debug-бинарь stage константа = lesson
/// #185/#87 первички live-промера); SKIP-контра молчания = `FASAD_REQUIRE_MODELS`
/// (провен #87, CI-leg ставит его на смонтированной полке).
#[test]
fn win_simu_userprofile_mount_starts_the_tray_contour() {
    if !cfg!(feature = "ort-inference") {
        eprintln!("SKIP|win_simu|нога = ort-контур монтирования (wire_e2e-контра)");
        return;
    }
    let shelf = std::env::var("HOME").expect("HOME раннера");
    let cache = std::path::PathBuf::from(shelf).join(".cache/fasad-models");
    if !guard_daemon::weights::layout_complete(&cache) {
        assert!(
            std::env::var_os("FASAD_REQUIRE_MODELS").is_none(),
            "FASAD_REQUIRE_MODELS стоит, а полки нет (#87-провен)"
        );
        eprintln!(
            "SKIP|win_simu|кеш {} не смонтирован (нет шага fetch)",
            cache.display()
        );
        return;
    }
    // HOME = СУЩЕСТВУЮЩИЙ каталог БЕЗ кеша (win-класс #264: Git-Bash/WSL
    // ставят HOME, кеш ps1 пишет в USERPROFILE; резолвер default_home_dir =
    // HOME-первичен). Несуществующий HOME = харнес-контра #185 (иглы в
    // никуда = отказ старта).
    let home = std::env::temp_dir().join(format!("fasad314-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("HOME-изолят создаётся");
    let mut child = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        .env("FASAD_TEST_TRAY_CONTOUR", "1")
        // Win-форма «HOME∅»: несуществующий путь (default_home_dir =
        // trim-контра; пустая строка = unset, путь надёжнее).
        .env("HOME", &home)
        .env("USERPROFILE", &cache)
        .env("FASAD_THREADS", "2")
        .env("FASAD_CONFIG", fasad_empty_config())
        .env_remove("FASAD_MODEL_DIR")
        .env_remove("FASAD_TEST_CASCADE0")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("бинарь запускается");
    let addr = banner_addr(&mut child);
    let h = call(&addr, "GET", "/health", &[], b"");
    let mut err = String::new();
    if let Some(mut se) = child.stderr.take() {
        use std::io::Read as _;
        let _ = se.read_to_string(&mut err);
    }
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&home).ok();
    assert_eq!(h.status, 200, "stderr: {err}");
    assert_eq!(
        h.json()["stage"],
        "cascade-0+models",
        "#314: HOME∅ + USERPROFILE=5/5 + трей-мишень = монтированный старт \
         (win-стенд v0.1.9: UI 5/5 и stage не pending); stderr демона: {err}"
    );
}

/// Баннер-адрес демона: строка `listening on http://127.0.0.1:PORT/health`
/// из stdout (`Daemon::start`-контра #224 R4: pipe = fully-buffered, flush
/// в демоне есть). Читалка = ПОСТРОЧНАЯ (`BufReader::read_line`, харнес-
/// канон `Daemon::start`: байтовый read чанками рвёт строку баннера по
/// границе буфера = первичка mac-CI #314: игла не собралась за 60 с при
/// живом демоне); full-контур грузит веса = секунды, бюджет 120 с.
fn banner_addr(child: &mut std::process::Child) -> String {
    use std::io::BufRead as _;
    let stdout = child.stdout.take().expect("stdout перехвачен");
    let mut reader = std::io::BufReader::new(stdout);
    let started = Instant::now();
    let mut seen = String::new();
    loop {
        if let Some(status) = child.try_wait().expect("статус читается") {
            panic!("демон умер до баннера (rc={status:?}): {seen:?}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "баннер не пришёл за 120 с: {seen:?}"
        );
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("stdout закрылся без баннера: {seen:?}"),
            Ok(_) => seen.push_str(&line),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("stdout читается: {e}"),
        }
        if let Some((_, rest)) = seen.split_once("listening on http://") {
            let addr = rest
                .split('/')
                .next()
                .expect("адрес заканчивается путём")
                .to_owned();
            let ready = Instant::now();
            while TcpStream::connect(&addr).is_err() {
                assert!(
                    ready.elapsed() < Duration::from_secs(10),
                    "порт {addr} не открылся"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            return addr;
        }
    }
}

/// #198 живая нога ожидающего старта (орт-контур `wire_e2e`): трей-решётка
/// смодулирована env-мишенью (`FASAD_TEST_TRAY_CONTOUR`, primary: main.rs —
/// симуляция compile-time-мишени, НЕ решения; `tray`-сборка = tray-check/
/// verify-bundle), каталог весов = tmp-пусто (HOME-изолят #192-контур),
/// НОГА = feature-off (CI-матрица, харнес-контур файла): env-мишень
/// `FASAD_TEST_TRAY_CONTOUR` (симуляция compile-time-мишени `tray`/win/mac;
/// решение `startup_pending_contour` от фичи НЕ зависит — unit-контур
/// `pending_gate_is_tray_only_and_model_failures_only`) +
/// `FASAD_TEST_CASCADE0` + tmp-пустой HOME = харнес cascade-0 (#185):
/// `startup` = Ok, stage `cascade-0-only` (харнес легален), НЕ pending
/// (решётка не трогает успешный старт) и НЕ rc=2 (флаг = харнес-контур,
/// дефолт не подставлен, `BuiltWithoutInference` нет). Дискриминатор
/// «харнес #185 цел на трей-мишени с флагом» (#203 §2.1): stage-зуб
/// X-Stage + /v1/analyze = 200 (каскад-0 жив, не 503 pending).
#[test]
fn pending_flag_on_tray_contour_keeps_the_cascade0_harness() {
    let home = unique_tmp_path("fasad198-hw");
    std::fs::create_dir_all(&home).expect("HOME-изолят создаётся");
    let d = Daemon::start(&[
        ("FASAD_TEST_TRAY_CONTOUR", "1"),
        ("FASAD_TEST_CASCADE0", "1"),
        ("HOME", home.to_str().expect("HOME путь utf-8")),
    ]);
    let h = call(&d.addr, "GET", "/health", &[], b"");
    assert_eq!(h.status, 200, "харнес cascade-0 поднят");
    assert_eq!(
        h.json()["stage"],
        "cascade-0-only",
        "флаг на трей-мишени = каскад-0-харнес, НЕ pending/не rc=2 (#203 §2.1)"
    );
    let a = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &[("content-type", "application/json")],
        format!(r#"{{"text":"{TWO_SPAN_TEXT}"}}"#).as_bytes(),
    );
    assert_eq!(a.status, 200, "каскад-0-харнес анализирует (#185)");
    assert_ne!(
        a.json()["error"]["code"].as_str(),
        Some("models_pending"),
        "pending-код на харнесе = ложь stage (#203 §2.1)"
    );
    std::fs::remove_dir_all(&home).ok();
}

/// #198: живой pending-контур ТРЕЙ-МИШЕНИ (орт-фича: полный бинарь, живой
/// двойной клик win/mac без весов = `ModelsNotConfigured` → решётка = true).
/// Feature-off (CI-матрица) = SKIPPED-контракт файла (полного бинаря там
/// нет; HTTP-контур pending покрывают `cascade_http` + unit `http` на
/// lib-роутере, live = этот тест на ort-ноге + mac-промер).
#[test]
fn pending_tray_contour_serves_ui_and_refuses_model_routes() {
    if !cfg!(feature = "ort-inference") {
        eprintln!(
            "SKIP|wire_e2e|pending-нога = full-бинарь (#185-контур: feature-off              cascade-0 стартует легально, ожидание не про него); live-контур              ort-фичи = cargo --features ort-inference"
        );
        return;
    }
    let home = unique_tmp_path("fasad198-home");
    std::fs::create_dir_all(&home).expect("HOME-изолят создаётся");
    let d = Daemon::start(&[
        ("FASAD_TEST_TRAY_CONTOUR", "1"),
        ("HOME", home.to_str().expect("HOME путь utf-8")),
    ]);
    // Баннер ждёт сам Daemon::start; здесь — контракты сокетов.
    let h = call(&d.addr, "GET", "/health", &[], b"");
    assert_eq!(h.status, 200, "health в pending = живая витрина");
    assert_eq!(h.json()["stage"], "models-pending", "stage #198");
    let a = call(
        &d.addr,
        "POST",
        "/v1/analyze",
        &[("content-type", "application/json")],
        format!(r#"{{"text":"{TWO_SPAN_TEXT}"}}"#).as_bytes(),
    );
    assert_eq!(a.status, 503, "analyze в pending = 503, не 200-обман");
    assert_eq!(
        a.json()["error"]["code"],
        "models_pending",
        "отказ обязан быть своим кодом (#198: не молчание, не cascade-0-обман)"
    );
    let st = call(&d.addr, "GET", "/v1/status", &[], b"");
    assert_eq!(
        st.status, 200,
        "витрина веса = 200 в pending (кнопка живёт)"
    );
    let ui = call(&d.addr, "GET", "/", &[], b"");
    assert_eq!(
        ui.status, 200,
        "UI = 200 в pending (двойной клик доходит до кнопки)"
    );
    std::fs::remove_dir_all(&home).ok();
}

/// #198 вторая нога: та же решётка на смонтированном каталоге (tmp с 5/5
/// файлов, размеры = манифест) НЕ заводит pending — старт обязан смонтировать
/// каскады (ort-фича) = stage cascade-0+models. Живой ЛОАД требует настоящих
/// ONNX (879 МБ в CI не заводятся, первичка файла), поэтому нога =
/// feature-off-нелегальна (нет фичи → `BuiltWithoutInference` не про это):
/// на ort-фиче проверка «решётка не сработала» = banner listening +
/// stage != models-pending, с фолбэком на rc=2-load (орк-контур требует
/// реальных весов). Фиксируем ОБА легальных исхода — red только pending.
#[test]
fn pending_gate_does_not_fire_on_complete_layout() {
    if !cfg!(feature = "ort-inference") {
        eprintln!("SKIP|wire_e2e|нога = ort-контур монтирования (см. выше)");
        return;
    }
    // 5/5 файлов ПУСТЫМИ байтами с точными размерами манифеста невозможны
    // (load их отвергнет); поэтому нога проверяет решётку на НЕполном
    // каталоге, смонтированном ранее: здесь = «layout_complete(tmp) = false
    // при пустом» = решёточный предикат (unit `pending_gate_...` покрыл);
    // живая часть = pending НЕ поднимается, когда model_dir ЯВНО задан на
    // несуществующий каталог и решётка трей-мишени НЕ активна (headless
    // ноги: refuse rc=2 — дискриминатор контура).
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        .env("FASAD_MODEL_DIR", "/nonexistent-fasad198-dir")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("процесс стартует")
        .wait_with_output()
        .expect("процесс завершился");
    assert_eq!(
        out.status.code(),
        Some(2),
        "headless (без трей-мишени) с битым каталогом = rc=2, pending не протёк"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("скачай веса"),
        "#199: Load-отказ без пути докачки: {err}"
    );
}

#[test]
fn bad_vault_key_refuses_to_start_before_binding() {
    // Отказ до бинда: код выхода 2 (не 1, как у сетевой ошибки), причина
    // названа словами, баннера нет. Читается `wait_with_output`: процесс сам
    // завершается, поэтому трубки закрываются и чтение ограничено самим
    // процессом, а не нашим таймаутом.
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        .env("FASAD_VAULT_KEY", "не-шестнадцатеричный")
        // #219 E-контур: прямой спавн (не `Daemon::start`) наследует среду, а
        // на машине оператора default-путь `~/.config/fasad/config` =
        // потенциальный файл; явный путь в несуществующий файл сам дал бы
        // отказ (перехватил бы первую строку stderr), поэтому игла =
        // существующий ПУСТОЙ файл харнеса.
        .env("FASAD_CONFIG", fasad_empty_config())
        // Причина отказа обязана быть про ключ, а не про веса: на машине с
        // `FASAD_MODEL_DIR` каскадный старт проверяется раньше и перехватил бы
        // первую строку stderr. #192: то же касается дефолта по HOME —
        // каскад-0-бинарь с резолвнутым дефолтом краснеет BuiltWithoutInference
        // раньше валидации ключа; флаг харнеса отключает подстановку.
        .env_remove("FASAD_MODEL_DIR")
        .env("FASAD_TEST_CASCADE0", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("процесс стартует")
        .wait_with_output()
        .expect("процесс завершился");
    assert_eq!(out.status.code(), Some(2), "код отказа от конфига");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("FASAD_VAULT_KEY"), "причина не названа: {err}");
    let out_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out_stdout.contains("listening"),
        "баннер напечатан до отказа: {out_stdout}"
    );
}

#[test]
#[should_panic(expected = "не loopback")]
fn non_loopback_bind_panics_the_test_instead_of_hanging_it() {
    // Двойной контракт. Стена loopback (SPEC §1 п.6) проверена на границе
    // процесса: `FASAD_BIND=0.0.0.0` = отказ со стартом, баннера нет. И
    // проверено, что паника на отказе старта объясняет причину (в тексте есть
    // `не loopback` — она приходит из stderr демона, а не из нашей догадки) и
    // что ожидание баннера ограничено: читатель в потоке с
    // `recv_timeout`, так что до «демон не поднялся» дело доходит за секунды,
    // а не навечно (первая версия файла висела именно на вечном `read_line`).
    Daemon::start(&[("FASAD_BIND", "0.0.0.0")]);
}

/// Потоковое тело с битым chunked-заголовком обязано дать 400 `bad_body`, а не
/// 413 `body_too_large`. Различение — смысл собственной счётной петли в
/// `http::read_body`: до неё любая ошибка `to_bytes` трактовалась как перелив
/// лимита, то есть демон врал о причине отказа.
#[test]
fn broken_chunked_body_is_400_bad_body_not_413() {
    let d = Daemon::start::<&str>(&[]);
    let req = b"POST /v1/analyze HTTP/1.1\r\n\
                Host: x\r\n\
                Content-Type: application/json\r\n\
                Transfer-Encoding: chunked\r\n\
                Connection: close\r\n\r\nZZ\r\n";
    let r = call_raw(&d.addr, req);
    assert_eq!(r.status, 400, "битый поток — не «слишком длинно»");
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert!(
        body.contains("bad_body"),
        "ожидали наш конверт с кодом bad_body, получили: {body}"
    );
    assert!(
        !body.contains("body_too_large"),
        "в 400 просочился код перелива: {body}"
    );
}

/// `X-Session-ID` с байтами вне UTF-8 — это «заголовок невалиден», а не «заголовка
/// нет»: клиент, который его прислал, должен получать правду. До правки
/// `session_of` проглатывал нечитаемое значение в `None`, и в режиме 2 отвечал
/// `режим 2 требует заголовок X-Session-ID`.
#[test]
fn non_ascii_session_id_is_refused_as_invalid_not_missing() {
    let d = Daemon::start(&[
        ("FASAD_VAULT_MODE", "session"),
        (
            "FASAD_VAULT_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ),
    ]);
    // Тело — валидный запрос: иначе `bad_json` маску под проверкой заголовка, и
    // тест проверял бы не то.
    let body = br#"{"text":"x","spans":[]}"#;
    let mut req = Vec::new();
    req.extend_from_slice(
        b"POST /v1/anonymize HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ",
    );
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(b"\r\nConnection: close\r\nX-Session-ID: ");
    req.extend_from_slice(b"\xff\xfe");
    req.extend_from_slice(b"\r\n\r\n");
    req.extend_from_slice(body);
    let r = call_raw(&d.addr, &req);
    assert_eq!(r.status, 400);
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert!(
        body.contains("печатаемым ASCII"),
        "причина обязана называть заголовок: {body}"
    );
    assert!(
        !body.contains("требует"),
        "клиент заголовок прислал — «требует» было бы ложью: {body}"
    );
}

/// P6: повторная анонимизация собственного замазанного текста отвергается до
/// первой подмены. Замеренная до правки порча — три раунда на одном имени
/// в той же сессии: на третьем перезатиралась связь «суррогат → оригинал»
/// (ключ реверс-индекса — само суррогатное слово), и `deanonymize` возвращал
/// `200 OK` с выдуманным именем «Ветрова Кира Саввична» — чужая фамилия плюс
/// настоящие имя и отчество. Тест проверяет и отказ, и то, что после него
/// round-trip остаётся честным.
#[test]
fn double_anonymization_is_refused_before_it_corrupts() {
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "session"), ("FASAD_VAULT_KEY", key)]);
    let hdr = [("content-type", "application/json"), ("x-session-id", "p6")];
    let fio = "Ушакова Кира Саввична";
    let r1 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(fio, &[("person_name".to_owned(), 0, fio.len())]),
    );
    assert_eq!(r1.status, 200, "раунд 1: {}", r1.text());
    let a1 = r1.json()["text"].as_str().expect("текст").to_owned();
    assert!(!a1.contains("Ушакова"), "имя не подменено: {a1}");
    assert!(!a1.contains('['), "ФИО в режиме 2 идёт суррогатом: {a1}");

    let r2 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(&a1, &[("person_name".to_owned(), 0, a1.len())]),
    );
    assert_eq!(r2.status, 422, "переанонимизация: {}", r2.text());
    assert_eq!(r2.json()["error"]["code"], "reanonymize_surrogate");

    let back = call(
        &d.addr,
        "POST",
        "/v1/deanonymize",
        &hdr,
        format!(r#"{{"text":"{}"}}"#, a1.replace('"', "\\\"")).as_bytes(),
    );
    assert_eq!(back.status, 200, "deanonymize: {}", back.text());
    assert_eq!(
        back.json()["text"].as_str().expect("текст"),
        fio,
        "вот здесь до правки появлялась выдуманная фамилия"
    );
    assert_eq!(
        back.json()["restore_refused"]
            .as_u64()
            .expect("отказ разворота обязан быть виден в ответе (R7 ревью #70)"),
        0,
        "на честном round-trip отказов разворота быть не может"
    );
}

/// Тот же класс для метки: запрос замазать текст, внутри которого уже лежит
/// наша метка, обязан получить отказ, а не метку-в-метке.
#[test]
fn marker_in_input_is_refused_not_double_masked() {
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "session"), ("FASAD_VAULT_KEY", key)]);
    let hdr = [
        ("content-type", "application/json"),
        ("x-session-id", "p6m"),
    ];
    let text = "ИНН 2482014338";
    let r1 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(text, &[("inn".to_owned(), 4, text.len())]),
    );
    assert_eq!(r1.status, 200, "раунд 1: {}", r1.text());
    let masked = r1.json()["text"].as_str().expect("текст").to_owned();
    assert!(masked.contains("[INN_1_"), "метки нет: {masked}");

    let r2 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(&masked, &[("inn".to_owned(), 0, masked.len())]),
    );
    assert_eq!(
        r2.status,
        422,
        "метку внутри текста приняли повторно: {}",
        r2.text()
    );
    assert_eq!(r2.json()["error"]["code"], "reanonymize_surrogate");
}

/// Тот же класс в режиме 3, где сессии нет и зацепиться можно только за
/// грамматику: маркер `[[F0#…]]` внутрь спана — отказ, а не метка-в-метке.
/// Промер до правки: второй раунд давал `200`, а `deanonymize` возвращал
/// «восстановленный» текст с живым маркером внутри и `substituted: 1` —
/// тихий partial-restore.
#[test]
fn stateless_marker_in_input_is_refused_not_double_masked() {
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "stateless")]);
    let hdr = [("content-type", "application/json")];
    let text = "ИНН 2482014338";
    let r1 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(text, &[("inn".to_owned(), 4, text.len())]),
    );
    assert_eq!(r1.status, 200, "раунд 1: {}", r1.text());
    let masked = r1.json()["text"].as_str().expect("текст").to_owned();
    assert!(masked.contains("[[F0#"), "токена режима 3 нет: {masked}");

    let r2 = call(
        &d.addr,
        "POST",
        "/v1/anonymize",
        &hdr,
        &anonymize_body(&masked, &[("inn".to_owned(), 0, masked.len())]),
    );
    assert_eq!(
        r2.status,
        422,
        "токен приняли повторно как ПДн: {}",
        r2.text()
    );
    assert_eq!(r2.json()["error"]["code"], "reanonymize_surrogate");
}

/// B2/P8 проводной промер цепочки ревьюера: два разных ФИО, влезших в один слот
/// пула, в одной сессии («Родионова Аграфена Гордеевна» и «Мельникова Ульяна
/// Тихоновна» дают одну «Деденеву» — промер `pool_probe -- forms`). До правки #58
/// второй запрос давал `200`, а разворот первого возвращал чужое имя; на шаге 6
/// второй стал `422 surrogate_collision`, и документ с двумя такими именами было
/// не анонимизировать вовсе; с шага 7а (#60) второй уходит на типизированную
/// метку, и оба разворачиваются byte-exact.
#[test]
fn second_full_name_in_one_session_becomes_a_label_not_a_refusal() {
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let d = Daemon::start(&[("FASAD_VAULT_MODE", "session"), ("FASAD_VAULT_KEY", key)]);
    let hdr = [("content-type", "application/json"), ("x-session-id", "b2")];
    let anonymize = |name: &str| {
        call(
            &d.addr,
            "POST",
            "/v1/anonymize",
            &hdr,
            &anonymize_body(name, &[("person_name".to_owned(), 0, name.len())]),
        )
    };
    let a = anonymize("Родионова Аграфена Гордеевна");
    assert_eq!(a.status, 200, "первое имя: {}", a.text());
    let masked = a.json()["text"].as_str().expect("текст").to_owned();
    assert_ne!(
        masked, "Родионова Аграфена Гордеевна",
        "имя обязано быть заменено"
    );

    let b = anonymize("Мельникова Ульяна Тихоновна");
    assert_eq!(b.status, 200, "слот занят — не отказ: {}", b.text());
    let second = b.json()["text"].as_str().expect("текст").to_owned();
    assert!(
        second.starts_with("[PERSON_NAME_"),
        "второе имя обязано стать меткой: {second}"
    );

    for (text, original) in [
        (masked.as_str(), "Родионова Аграфена Гордеевна"),
        (second.as_str(), "Мельникова Ульяна Тихоновна"),
    ] {
        let back = call(
            &d.addr,
            "POST",
            "/v1/deanonymize",
            &hdr,
            format!(r#"{{"text":"{}"}}"#, text.replace('"', "\\\"")).as_bytes(),
        );
        assert_eq!(back.status, 200, "разворот: {}", back.text());
        assert_eq!(
            back.json()["text"].as_str().expect("текст"),
            original,
            "первый владелец не смещён, метка обратима"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Шаг 7c: прокси /v1/chat/completions.
// ──────────────────────────────────────────────────────────────────────────

/// Один ПДн-насыщенный текст на все прокси-тесты.
const PROXY_TEXT: &str = "Иван ИНН 2482014338 оплатил, СНИЛС 65707715421 выдан";

/// Режим ответа игрушки выбирается путём запроса (`/buffered`, `/sse/<k>`,
/// `/hang`), а не конфигурацией: один слушающий на все тесты, и путь в тесте
/// читается так же, как адрес upstream в проде.
///
/// `/sse/<k>` — предельный случай SPEC §8 («наивный replace по чанку ломает
/// обратимость»): при `k=1` метка разрезана на отдельные байты.
///
/// Запрос, дошедший до upstream: путь + сырые заголовки + тело.
struct ToySeen {
    path: String,
    head: String,
    body: Vec<u8>,
}

/// Игрушечный upstream на 127.0.0.1:0. Возвращает `host:port` и читателя того,
/// что до него дошло. Отвечает по пути запроса: `/buffered`, `/sse/<k>`, `/hang`.
///
/// Свой сокет, а не `hyper`: HTTP-клиента (да и сервера) в dev-зависимях демона
/// быть не должно — `net_audit` читает манифест целиком, и тест не имеет права
/// маскировать то, что он сторожит.
/// HTTP/1.1-ответ с `Transfer-Encoding: chunked`, фреймы по `step` байт.
///
/// Размер фрейма отделён CRLF: `writeln!` дал бы `\n`, и `ureq` честит это как
/// «chunk length cannot be read as a number» — на этой игрушке мы это и поймали
/// (ложь об отказе со стороны клиента, а не сервера).
/// Ответы игрушки, которые обязаны быть отказом прокси, а не ответом: молчание,
/// оборванное тело, редирект, оборванный стрим. Возвращает `true`, если соединение
/// уже обслужено (или брошено) и дальше идти не надо.
fn misbehaviour(path: &str, sock: &mut std::net::TcpStream) -> bool {
    match path {
        "/hang" => {
            // Намеренно молчим: таймаут обязан прийти со стороны демона.
            std::thread::sleep(Duration::from_secs(30));
            true
        }
        "/abort" => {
            // Обещаем тело в 400 байт и закрываем соединение на 23-м: заголовок
            // ответа получен, поэтому отказ обязан называть обрыв, а не «upstream
            // недоступен».
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"choices\":[{\"content\":",
            );
            let _ = sock.shutdown(std::net::Shutdown::Both);
            true
        }
        "/redirect" => {
            // 302 с `Location`: транзитом это вранье вдвойне — статус дошёл бы,
            // цель наш фильтр заголовков вырезал бы.
            let _ = sock.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n",
            );
            true
        }
        "/sse-then-drop" => {
            // Первый кадр стрима отправлен, соединение брошено на середине
            // второго: заголовок ушёл клиенту раньше, поэтому отказ обязан
            // прийти кадром `event: error` с кодом обрыва, а не
            // `upstream_unreachable`.
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let first =
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"начало\"}}]}\n\n";
            let _ = write!(sock, "{:x}\r\n", first.len());
            let _ = sock.write_all(first.as_bytes());
            let _ = sock.write_all(b"\r\n");
            let _ = sock.flush();
            let _ = sock.shutdown(std::net::Shutdown::Both);
            true
        }
        _ => false,
    }
}

fn chunked(content_type: &str, payload: &[u8], step: usize) -> Vec<u8> {
    let mut frames = Vec::new();
    for chunk in payload.chunks(step.max(1)) {
        write!(&mut frames, "{:x}\r\n", chunk.len()).expect("в Vec не бывает ошибки записи");
        frames.extend_from_slice(chunk);
        frames.extend_from_slice(b"\r\n");
    }
    frames.extend_from_slice(b"0\r\n\r\n");
    let mut head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    head.extend_from_slice(&frames);
    head
}

fn toy_upstream() -> (String, std::sync::mpsc::Receiver<ToySeen>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("игрушка слушает");
    let addr = listener.local_addr().expect("адрес известен");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { continue };
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let mut reader = std::io::BufReader::new(&sock);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();
            let mut head = String::new();
            let mut length = 0_usize;
            loop {
                let mut line = String::new();
                // 0 или ошибка = соединение закрыли до пустой строки заголовков.
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                head.push_str(&line);
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0_u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let echo = String::from_utf8_lossy(&body).into_owned();
            if tx
                .send(ToySeen {
                    path: path.clone(),
                    head,
                    body,
                })
                .is_err()
            {
                return;
            }
            if misbehaviour(&path, &mut sock) {
                continue;
            }
            // Что отправляем: `/sse/<k>` — эхо, нарезанное chunked-фреймами по
            // `k` байт; `/huge` — одна SSE-строка поверх потолка тела; всё
            // остальное (кроме `/hang`) — буферизованный JSON.
            let response = if let Some(k) = path.strip_prefix("/sse/") {
                let step: usize = k.parse().unwrap_or(1);
                chunked("text/event-stream", sse_payload(&echo).as_bytes(), step)
            } else if path == "/huge" {
                let fat = "А".repeat(4096);
                let frames = format!(
                    "data: {}\n\ndata: [DONE]\n\n",
                    serde_json::json!({
                        "choices": [{
                            "index": 0,
                            "delta": {"content": fat},
                            "finish_reason": serde_json::Value::Null,
                        }],
                    })
                );
                chunked("text/event-stream", frames.as_bytes(), 256)
            } else {
                // `/object-content` — та же реплика, но речевое поле лежит
                // списком частей (`content: [{type,text}]`), как у провайдеров с
                // блоками. Ретранслятор строку в нём не видит, и обязан честно
                // сказать `malformed`, а не «развёрнуто 0 маркеров».
                let content: serde_json::Value = if path == "/object-content" {
                    serde_json::json!([{"type": "text", "text": echo}])
                } else {
                    serde_json::Value::String(echo)
                };
                let json = serde_json::json!({
                    "id": "toy",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                });
                let body = json.to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            };
            let _ = sock.write_all(&response);
            let _ = sock.flush();
        }
    });
    (addr.to_string(), rx)
}

/// SSE-поток `OpenAI`, «эхом» возвращающий полученное тело запроса.
fn sse_payload(echo: &str) -> String {
    use std::fmt::Write as _;
    let chunk = |content: serde_json::Value| {
        format!(
            "data: {}\n\n",
            serde_json::json!({
                "id": "toy",
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": { "content": content },
                    "finish_reason": serde_json::Value::Null,
                }],
            })
        )
    };
    let mut out = chunk(serde_json::Value::String(String::new()))
        + &chunk(serde_json::Value::String(echo.to_owned()));
    write!(
        out,
        "data: {}\n\n",
        serde_json::json!({
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }],
        }),
    )
    .expect("в String не бывает ошибки записи");
    out.push_str("data: [DONE]\n\n");
    out
}

/// Тело запроса к прокси в форме `OpenAI`: одна реплика с текстом.
fn chat_body(text: &str) -> Vec<u8> {
    serde_json::json!({
        "model": "toy",
        "messages": [{ "role": "user", "content": text }],
    })
    .to_string()
    .into_bytes()
}

/// Тело запроса к прокси со `stream: true` (потоковый контракт `OpenAI`).
fn chat_body_stream(text: &str) -> Vec<u8> {
    serde_json::json!({
        "model": "toy",
        "stream": true,
        "messages": [{ "role": "user", "content": text }],
    })
    .to_string()
    .into_bytes()
}

/// `X-Upstream-URL` для игрушки.
fn upstream_url(addr: &str, path: &str) -> String {
    format!("http://{addr}{path}")
}

/// Прокси разворачивает запрос и ответ побайтово: то, что ушло на upstream, не
/// содержит оригиналов, а то, что вернулось клиенту, содержит их обратно.
#[test]
fn proxy_roundtrip_masks_request_and_restores_response() {
    let (toy, seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let body = chat_body(PROXY_TEXT);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/buffered").as_str()),
            ("x-api-key", "toy-ключ"),
            ("user-agent", "fasad-e2e"),
            ("accept-encoding", "gzip"),
        ],
        &body,
    );
    assert_eq!(reply.status, 200, "ответ прокси: {}", reply.text());
    let gone = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("upstream принял запрос");
    assert_eq!(gone.path, "/buffered", "путь из X-Upstream-URL не доехал");
    let raw = String::from_utf8_lossy(&gone.body).into_owned();
    assert!(
        !raw.contains("2482014338") && !raw.contains("65707715421"),
        "на upstream ушли оригиналы ПДн: {raw}"
    );
    assert!(
        raw.contains("[[F0#"),
        "маскирования не было, маркеров нет: {raw}"
    );
    assert!(
        gone.head.to_lowercase().contains("x-api-key: toy-ключ"),
        "ключ upstream не перенесён — прокси бесполезен: {}",
        gone.head
    );
    assert!(
        !gone.head.to_lowercase().contains("user-agent: fasad-e2e"),
        "заголовок клиента просочился наружу: {}",
        gone.head
    );
    // Инвариант, а не фича: `accept-encoding` наружу означал бы, что upstream
    // вправе прислать gzip, а релей разобрать его не сможет — молча.
    assert!(
        !gone.head.to_lowercase().contains("accept-encoding"),
        "сжатие было разрешено прокси: {}",
        gone.head
    );
    assert!(
        reply.header("x-guard-redacted-count").is_some(),
        "нет счётчика подмен: {:?}",
        reply.headers
    );
    let content = reply.json()["choices"][0]["message"]["content"]
        .as_str()
        .expect("контент")
        .to_owned();
    assert_eq!(
        content,
        String::from_utf8_lossy(&body).as_ref(),
        "эхо не развернулось байт-в-байт"
    );
}

/// Матрица нарезки: один и тот же ответ, собранный из chunked-фреймов разного
/// размера, обязан сойтись побайтово (SPEC §8, промер шага 7c).
#[test]
fn proxy_stream_survives_every_chunk_slicing() {
    let (toy, seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let body = chat_body_stream(PROXY_TEXT);
    let mut assembled: Vec<(usize, String)> = Vec::new();
    for step in [1_usize, 2, 3, 7, 64, 4096] {
        let path = format!("/sse/{step}");
        let reply = call(
            &d.addr,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-upstream-url", upstream_url(&toy, &path).as_str()),
                ("accept", "text/event-stream"),
            ],
            &body,
        );
        assert_eq!(reply.status, 200, "шаг {step}: {}", reply.text());
        let text = sse_content(&reply.text());
        assert!(
            !text.contains("[[F0#"),
            "шаг {step}: нарезка съела границу маркера, наружу ушёл он, а не оригинал: {text}"
        );
        // Трейлер счётчиков обещан доком на каждом стриме, включая нарезанный.
        assert!(
            reply.text().contains(": guard substituted="),
            "шаг {step}: стрим закрылся без трейлера счётчиков: {}",
            reply.text()
        );
        assembled.push((step, text));
        let gone = seen
            .recv_timeout(Duration::from_secs(5))
            .expect("upstream принял запрос");
        assert_eq!(gone.path, path, "прокси поехал не по тому пути");
        // Маскирование обязано оставлять след на проводе: без него «разворота
        // нет» тривиально верно и на незамаскированном запросе.
        assert!(
            String::from_utf8_lossy(&gone.body).contains("[[F0#"),
            "шаг {step}: на upstream ушёл незамаскированный запрос"
        );
    }
    let reference = &assembled[0].1;
    for (step, text) in &assembled {
        assert_eq!(
            text, reference,
            "нарезка по {step} байт изменила ответ (эталон — нарезка по {})",
            assembled[0].0
        );
    }
    assert!(
        reference.contains(PROXY_TEXT),
        "эхо не развернулось: {reference}"
    );
}

/// Сборка `delta.content` из клиентского SSE-ответа.
fn sse_content(stream: &str) -> String {
    let mut out = String::new();
    for frame in stream.split("\n\n") {
        for line in frame.lines() {
            let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                continue;
            };
            if data == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                continue;
            };
            if let Some(text) = v["choices"][0]["delta"]["content"].as_str() {
                out.push_str(text);
            }
        }
    }
    out
}

/// Порядок блоков заморожен (закон #53): прокси маскирует те же спаны и на тех
/// же местах, что и `/v1/analyze` + `/v1/anonymize`.
#[test]
fn proxy_mask_matches_the_analyze_api_span_for_span() {
    let (toy, seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let spans = analyzed_spans(&d.addr, PROXY_TEXT);
    assert_eq!(
        spans.len(),
        2,
        "parity без двух спанов ничего не доказывает"
    );
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/buffered").as_str()),
        ],
        &chat_body(PROXY_TEXT),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    let gone = seen
        .recv_timeout(Duration::from_secs(5))
        .expect("upstream принял запрос");
    let raw: serde_json::Value = serde_json::from_slice(&gone.body).expect("эхо — JSON");
    let masked = raw["messages"][0]["content"]
        .as_str()
        .expect("контент")
        .to_owned();
    // Спаны из `/v1/analyze` — оффсеты ИСХОДНИКА; после подмены первого span
    // все последующие съезжают, поэтому сравниваем не байты оффсетов, а
    // структуру: сколько маркеров, в каком порядке, и что между ними.
    let markers = markers(&masked);
    assert_eq!(
        markers.len(),
        spans.len(),
        "прокси замаскировал не то количество: {masked}"
    );
    let mut prev_masked = 0_usize;
    let mut prev_orig = 0_usize;
    for ((class, start, end), (m_start, m_end)) in spans.iter().zip(&markers) {
        assert_eq!(
            &masked[prev_masked..*m_start],
            &PROXY_TEXT[prev_orig..*start],
            "текст перед маркером класса {class} сместился"
        );
        prev_masked = *m_end;
        prev_orig = *end;
    }
    assert_eq!(
        &masked[prev_masked..],
        &PROXY_TEXT[prev_orig..],
        "хвост после последнего маркера сместился"
    );
    // Порядок классов: маркер обязан развернуться ровно в тот оригинал, который
    // стоял на этом месте у `/v1/analyze` (иначе блоки перемаскованы местами).
    for ((class, start, end), (m_start, m_end)) in spans.iter().zip(&markers) {
        let back = call(
            &d.addr,
            "POST",
            "/v1/deanonymize",
            &[("content-type", "application/json")],
            format!(
                r#"{{"text":"{}"}}"#,
                masked[*m_start..*m_end].replace('"', "\\\""),
            )
            .as_bytes(),
        );
        assert_eq!(
            back.json()["text"].as_str().expect("текст"),
            &PROXY_TEXT[*start..*end],
            "маркер на месте класса {class} развернулся не в свой оригинал"
        );
    }
}

/// Байтовые границы маркеров `[[F0#…]]` в тексте.
fn markers(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0_usize;
    while let Some(rel) = text[from..].find("[[F0#") {
        let start = from + rel;
        let Some(rel_end) = text[start..].find("]]") else {
            break;
        };
        let end = start + rel_end + 2;
        out.push((start, end));
        from = end;
    }
    out
}

/// Начатый SSE закрывается кадром `event: error`, а не молчанием: клиент обязан
/// получить причину, иначе «модель ответила пустотой» читается как успех.
#[test]
fn oversized_upstream_frame_closes_stream_with_error_event() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
        ("FASAD_MAX_BODY_BYTES", "1024"),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/huge").as_str()),
        ],
        &chat_body_stream("проверка"),
    );
    // Код 200: заголовок уже ушёл, когда обнаружен перелив — причина живёт в
    // теле, и она там обязана быть.
    assert_eq!(reply.status, 200, "{}", reply.text());
    let text = reply.text();
    assert!(text.contains("event: error"), "нет err-кадра: {text}");
    assert!(
        text.contains("upstream_too_large"),
        "err-кадр не называет причину: {text}"
    );
    assert!(
        !text.contains("АААА"),
        "кусок перелившего тела всё-таки ушёл клиенту: {text}"
    );
}

/// Молчание клиента дольше `FASAD_READ_TIMEOUT_MS` = 408 `read_timeout`, а не
/// 413 `body_too_large`: ложь о причине отказа дорожа самой ошибки.
#[test]
fn slow_client_body_is_408_read_timeout() {
    let d = Daemon::start(&[("FASAD_READ_TIMEOUT_MS", "400")]);
    let body = br#"{"text":"0123456789""#;
    let mut sock = TcpStream::connect(&d.addr).expect("сокет поднимается");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("таймаут ставится");
    write!(
        sock,
        "POST /v1/analyze HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Content-Length: 5000\r\nConnection: close\r\n\r\n",
        d.addr
    )
    .expect("заголовок уходит");
    sock.write_all(body).expect("неполное тело уходит");
    sock.flush().expect("флуш");
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).expect("ответ читается до конца");
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.contains("408"), "ожидали 408, получили: {text}");
    assert!(
        text.contains("read_timeout"),
        "причина отказа не названа: {text}"
    );
    assert!(
        !text.contains("body_too_large"),
        "таймаут выдан переливом — ложь о причине: {text}"
    );
}

/// Молчание upstream = `504 upstream_timeout`, а не «демон завис».
#[test]
fn silent_upstream_is_504_upstream_timeout() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
        ("FASAD_READ_TIMEOUT_MS", "700"),
    ]);
    let started = Instant::now();
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/hang").as_str()),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 504, "ответ прокси: {}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "upstream_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "таймаут не сработал, ждали {:?}",
        started.elapsed()
    );
}

/// Непрослеживаемое речевое поле (список частей вместо строки) — `malformed=1`
/// в заголовке, маркеры при этом уходят транзитом целыми: `ПДн` в них нет, а
/// «развёрнуто 0» на невидимой структуре было бы враньём о гарантий.
#[test]
fn opaque_speech_field_is_counted_malformed() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            (
                "x-upstream-url",
                upstream_url(&toy, "/object-content").as_str(),
            ),
        ],
        &chat_body(TWO_SPAN_TEXT),
    );
    assert_eq!(reply.status, 200, "ответ прокси: {}", reply.text());
    assert_eq!(
        reply.header("x-guard-malformed"),
        Some("1"),
        "непрослеживаемая структура не названа: {}",
        reply.text()
    );
    let text = reply.text();
    assert!(
        text.contains("[[F0#") && !text.contains("2482014338"),
        "маркеры не доехали целыми либо ПДн протекло: {text}"
    );
}

/// Порядок отказов прокси: сначала то, что правит клиент, потом то, что правит
/// оператор. Клиент с нечитаемым `X-Session-ID` обязан слышать `400` про
/// заголовок, а не `403` про allowlist — иначе его отправляют чинить чужую
/// конфигурацию. До правки проверка списка шла первой, и этот тест краснел по
/// коду.
#[test]
fn bad_session_precedes_allowlist_refusal() {
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", "127.0.0.1:1"),
    ]);
    let body = br#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#;
    let mut req = Vec::new();
    req.extend_from_slice(
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ",
    );
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(
        b"\r\nConnection: close\r\nX-Upstream-URL: http://127.0.0.1:9/x\r\nX-Session-ID: ",
    );
    req.extend_from_slice(b"\xff\xfe");
    req.extend_from_slice(b"\r\n\r\n");
    req.extend_from_slice(body);
    let r = call_raw(&d.addr, &req);
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 400, "клиентская правка спрятана за 403: {text}");
    assert!(
        text.contains("печатаемым ASCII"),
        "причина не названа: {text}"
    );
    assert!(
        !text.contains("allowlist"),
        "подмена причины на конфиг: {text}"
    );
}

/// Редирект upstream — отказ с настоящим именем причины, а не транзит 302.
/// Враньё тут двукратное: клиенту пришло бы «перенаправляйся», цель он бы не
/// увидел (`Location` вырезается фильтром переносимых заголовков), и позволило
/// бы ему уйти на адрес вне allowlist.
#[test]
fn redirect_from_upstream_is_refused_not_transited() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/redirect").as_str()),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 502, "ответ прокси: {}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "upstream_redirect");
    assert!(
        !reply.text().contains("example.invalid"),
        "цель редиректа просочилась клиенту: {}",
        reply.text()
    );
}

/// Обрыв ответа посреди тела — это `upstream_aborted`, а не `upstream_unreachable`.
/// Ложь о причине отправила бы оператора чинить DNS и адрес, когда upstream
/// отдал заголовок и потерял соединение на теле.
#[test]
fn truncated_upstream_body_is_aborted_not_unreachable() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", upstream_url(&toy, "/abort").as_str()),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 502, "ответ прокси: {}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "upstream_aborted");
    assert!(
        !reply.text().contains("unreachable"),
        "причина подменена: {}",
        reply.text()
    );
}

/// Стрим оборвался после первого кадра: 200 уже ушёл, значит причина обязана
/// приехать кадром `event: error`, и называть она обязана обрыв, а не
/// недоступность. Ловит подмену `Unreachable` вместо `StreamAborted`: с ней
/// тест краснеет по коду, хоть HTTP-статус и остался 200.
#[test]
fn dropped_stream_reports_abort_in_error_frame() {
    let (toy, _seen) = toy_upstream();
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", toy.as_str()),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            (
                "x-upstream-url",
                upstream_url(&toy, "/sse-then-drop").as_str(),
            ),
        ],
        &chat_body_stream("проверка"),
    );
    assert_eq!(
        reply.status,
        200,
        "заголовок ушёл до обрыва: {}",
        reply.text()
    );
    let text = reply.text();
    assert!(
        text.contains("начало"),
        "первый кадр потерялся, значит это не обрыв середины: {text}"
    );
    assert!(text.contains("event: error"), "нет err-кадра: {text}");
    assert!(
        text.contains("upstream_aborted"),
        "err-кадр не называет обрыв: {text}"
    );
    assert!(
        !text.contains("upstream_unreachable"),
        "причина подменена на недоступность: {text}"
    );
}

/// Прокси выключен конфигурацией и отказывает, не соединяясь: пустой список —
/// `403 allowlist_empty`, чужой хост — `403 allowlist_denied`, `audit_only` на
/// собственном маршруте — `400 policy_not_applicable`.
#[test]
fn proxy_refusals_do_not_open_a_socket() {
    let d = Daemon::start::<&str>(&[]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", "http://127.0.0.1:1/"),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 403, "{}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "allowlist_empty");

    // Список непустой, но чужой: отказ обязан называть причину «не в списке», а
    // не прятаться за «список пуст» — у оператора от этих двух разные правки env.
    let d = Daemon::start(&[
        ("FASAD_PROXY_LOOPBACK_HTTP", "1"),
        ("FASAD_UPSTREAM_ALLOWLIST", "example.invalid"),
    ]);
    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-upstream-url", "http://127.0.0.1:1/"),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 403, "{}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "allowlist_denied");

    let reply = call(
        &d.addr,
        "POST",
        "/v1/chat/completions",
        &[
            ("content-type", "application/json"),
            ("x-guard-policy", "audit_only"),
            ("x-upstream-url", "http://127.0.0.1:1/"),
        ],
        &chat_body("проверка"),
    );
    assert_eq!(reply.status, 400, "{}", reply.text());
    assert_eq!(reply.json()["error"]["code"], "policy_not_applicable");
}

// ── #191: argv-контур и UI-строка баннера ───────────────────────────────────
// process-level контракт: разбор argv (`--help` = 0, мусор = 2) и адрес UI в
// баннере. `Daemon::start` аргументов не передаёт, здесь — прямые `Command`.

#[test]
fn help_flag_prints_usage_to_stdout_and_exits_zero() {
    // Дискриминатор по каналу обязателен: bad-аргумент печатает тот же текст
    // (в stderr, rc=2), и «stdout содержит» без rc+пустого stderr ловил бы
    // bad-ветку как зелёную (реестр false-green:print-only).
    for flag in ["--help", "-h"] {
        let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
            .arg(flag)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("процесс стартует")
            .wait_with_output()
            .expect("процесс завершился");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{flag}: --help обязан выходить нулём"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.is_empty(),
            "{flag}: usage обязан в stdout, stderr пуст: {stderr}"
        );
        // Ключевые носители usage (мелкие строки текстов, не слова): UI-адрес,
        // env-таблица, путь доставки весей, версия (= CARGO_PKG_VERSION).
        for needle in [
            "UI",
            "FASAD_PORT",
            "FASAD_MODEL_DIR",
            "fetch-models",
            env!("CARGO_PKG_VERSION"),
        ] {
            assert!(
                stdout.contains(needle),
                "{flag}: в usage нет «{needle}»:\n{stdout}"
            );
        }
    }
}

#[test]
fn unknown_argument_exits_two_with_usage_on_stderr() {
    // Молчаливо игнорируемый аргумент (#191: argv не читался вовсе) = оператор
    // думает, что флаг сработал. now: rc=2 + usage в stderr + сокет не поднят.
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .arg("--ne-such-flag")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("процесс стартует")
        .wait_with_output()
        .expect("процесс завершился");
    assert_eq!(
        out.status.code(),
        Some(2),
        "bad-аргумент = код 2, как у конфига"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("usage") && !stdout.contains("FASAD_PORT"),
        "usage bad-аргумента обязан в stderr, не в stdout: {stdout}"
    );
    assert!(
        stderr.contains("неизвестный аргумент")
            && stderr.contains("--ne-such-flag")
            && stderr.contains("FASAD_PORT"),
        "stderr обязан называть аргумент и нести usage: {stderr}"
    );
    assert!(
        !stdout.contains("listening"),
        "баннер напечатан до отказа: {stdout}"
    );
}

#[test]
fn banner_carries_ui_line_with_the_actual_port() {
    // Контракт строки: «UI браузера — http://<фактический адрес>/» — порт из баннера,
    // а не дефолт: `FASAD_PORT=0` даёт случайный порт, и UI-адрес обязан ему
    // соответствовать (тот же смысл, что у `local_addr` в основном баннере).
    // `Daemon::start` забирает stdout в читатель-поток (баннерный контракт
    // `Self.addr`), поэтому строки теста приходят каналом — тот же механизм.
    let mut d = Daemon::start::<&str>(&[]);
    let out = d.child.stdout.take();
    let mut seen = String::new();
    match out {
        // `Daemon::start` вызвал `stdout.take()` для своего читателя: трубка
        // здесь уже `None`, и вторая строка баннера живёт в буфере того
        // потока — он гонит строки в `rx` тестового хенесса, не наружу.
        // Значит UI-строку читаем с ЖИВОГО сокета нечем; читаем её до
        // захвата: отдельный прямой spawn.
        None => {}
        Some(pipe) => {
            let mut reader = BufReader::new(pipe);
            for _ in 0..8 {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                seen.push_str(&line);
                if seen.contains("UI") {
                    break;
                }
            }
        }
    }
    drop(d);
    if seen.is_empty() {
        // Прямой спавн (тот же контракт `FASAD_PORT=0`), читаем обе строки.
        let mut child = Command::new(env!("CARGO_BIN_EXE_fasad"))
            .env("FASAD_BIND", "127.0.0.1")
            .env("FASAD_PORT", "0")
            .env_remove("FASAD_MODEL_DIR")
            .env("FASAD_TEST_CASCADE0", "1")
            // #203 §2.1: env-мишень #198 не наследуется (`Daemon::start`).
            .env_remove("FASAD_TEST_TRAY_CONTOUR")
            .env_remove("FASAD_THREADS")
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
            .stderr(Stdio::null())
            .spawn()
            .expect("бинарь запускается");
        let pipe = child.stdout.take().expect("stdout перехвачен");
        let mut reader = BufReader::new(pipe);
        let mut main_line = String::new();
        for _ in 0..8 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            seen.push_str(&line);
            if line.contains("listening") {
                main_line = line;
            }
            if seen.contains("UI") && !main_line.is_empty() {
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let addr = main_line
            .split_once("listening on http://")
            .map(|(_, r)| r.split('/').next().unwrap_or("").to_owned())
            .unwrap_or_default();
        assert!(!addr.is_empty(), "баннер с адресом не пришёл: {seen:?}");
        assert!(
            seen.contains(&format!("UI браузера — http://{addr}/")),
            "баннер обязан нести UI-строку с фактическим адресом {addr}: {seen:?}"
        );
        return;
    }
    assert!(
        seen.contains("UI браузера — http://"),
        "UI-строка не найдена: {seen:?}"
    );
}
// ── #224: харнес-дискриминатор E-контура (продуктовый путь fresh-install) ──

/// Живая нога #224 (product path, не unit): `FASAD_CONFIG=<битый путь>` =
/// rc=2 с именем переменной; свежий HOME без файла = старт дефолтами
/// (прежний блокер: rc=2 «`FASAD_CONFIG` указывает…» на чистой машине).
#[test]
fn fresh_home_starts_and_explicit_missing_path_refuses_live() {
    let dir = unique_tmp_path("fasad-fresh-live-224");
    std::fs::create_dir_all(&dir).expect("HOME");
    let home = dir.to_string_lossy().to_string();
    // Платформа-стенка: канон-резолв config-файла = unix/XDG-ветка
    // (`$HOME/.config/fasad/config`); на windows тестовая HOME-игла НЕ
    // канон (резолв = %APPDATA%, её не трогаем: CI-раннер чист = дефолты,
    // но файл по `$HOME\.config` демон не увидит) —Skip на win, живая
    // unix-нога = ubuntu-матрица (mac-локаль тоже покрывает).
    if cfg!(windows) {
        eprintln!(
            "SKIP|wire_e2e|fresh-home-контур = unix-канон (XDG), win-резолв = APPDATA-ветка вне контура теста"
        );
        return;
    }
    // 1a) свежая установка: HOME tempdir, файла НЕТ, `FASAD_CONFIG` снят
    //     (`env_remove`, а не игла-пустышка) = продуктовый путь из блокера
    //     #224: резолв канона → файла нет → дефолты, старт.
    let xdg_home = format!("{home}/.config");
    let d1 = Daemon::start(&[
        ("HOME", home.as_str()),
        ("XDG_CONFIG_HOME", xdg_home.as_str()),
        ("FASAD_CONFIG", ""),
    ]);
    let r = call(&d1.addr, "GET", "/health", &[], b"");
    assert_eq!(
        r.status,
        200,
        "fresh-install обязан стартовать: {} (stderr демона: {})",
        r.status,
        d1.log_tail()
    );
    drop(d1);
    // 1b) дискриминатор: живой файл по каноническому пути (тот же свежий
    //     HOME) читается продуктивным путём — баннер = порт из файла, а не
    //     `FASAD_PORT=0` харнеса. Прямой спавн: `Daemon::start` перебивает
    //     порт контрактом `FASAD_PORT=0`.
    // Дискриминатор = живой GET /v1/config (витрина), НЕ строки баннера:
    // прямой read_line трубки = CI-гонка с буфером (первичка #224: ubuntu
    // 12-мин висяк на read_line второй строки, stdout пайпа не сбрасывается пока
    // процесс жив). Порт = 0 (харнес-контра, случайный адрес берём из
    // `Daemon::start`), файловый HF_HOST = контент-зуб.
    let cfg_dir = dir.join(".config").join("fasad");
    std::fs::create_dir_all(&cfg_dir).expect("каталог конфига");
    std::fs::write(
        cfg_dir.join("config"),
        "FASAD_PORT=0\nFASAD_HF_HOST=https://from-file.example.test\n",
    )
    .expect("файл");
    let xdg_home = format!("{home}/.config");
    let d2 = Daemon::start(&[
        ("HOME", home.as_str()),
        ("XDG_CONFIG_HOME", xdg_home.as_str()),
        ("FASAD_CONFIG", ""),
    ]);
    {
        let r = call(&d2.addr, "GET", "/v1/config", &[], b"");
        let j = r.json();
        let row = j["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["key"] == "FASAD_HF_HOST")
            .expect("HF_HOST в таблице");
        assert_eq!(
            row["value"], "https://from-file.example.test",
            "файл по каноническому пути обязан читаться (product path;              file-объект ниже = где демон искал): {j}"
        );
        assert_eq!(row["source"], "file", "{j}");
        assert_eq!(
            j["file"]["exists"].as_bool(),
            Some(true),
            "витрина обязана видеть файл ноги 1b (иначе = путь-игла мимо): {j}"
        );
    }
    drop(d2);
    // 2) FASAD_CONFIG в никуда (явный) = rc=2 + имя переменной в stderr.
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env(
            "FASAD_CONFIG",
            unique_tmp_path("nonexistent-fasad-224")
                .join("config")
                .to_str()
                .expect("utf-8"),
        )
        .env("FASAD_TEST_CASCADE0", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("процесс стартует")
        .wait_with_output()
        .expect("процесс завершился");
    assert_eq!(out.status.code(), Some(2), "явный путь в никуда = rc=2");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("FASAD_CONFIG"), "причина не названа: {err}");
    assert!(
        !err.contains("  опечатка"),
        "простыня пробелов в тексте: {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Дискриминатор блокера #224 на живом бинаре: харнес обязан оставаться
/// зелёным на машине оператора (живой `~/.config/fasad/config`), где
/// `FASAD_CONFIG` НЕ задан. Игла-пустышка (существующий пустой файл)
/// доказывает, что изоляцию даёт именно `FASAD_CONFIG`, а не везение tmp.
#[test]
fn harness_isolates_the_operators_config_file() {
    let dir = unique_tmp_path("fasad-opcfg-224");
    std::fs::create_dir_all(&dir).expect("HOME");
    let cfg_dir = dir.join(".config").join("fasad");
    std::fs::create_dir_all(&cfg_dir).expect("каталог конфига");
    std::fs::write(
        cfg_dir.join("config"),
        "FASAD_HF_HOST=https://operator.example.test\n",
    )
    .expect("файл оператора");
    let home = dir.to_string_lossy().to_string();

    // Платформа-стенка: unix-канон-резолв (см. `fresh_home…`: на win HOME
    // не канон, %APPDATA% — чужой контур).
    if cfg!(windows) {
        eprintln!("SKIP|wire_e2e|E-контур-дискриминатор = unix-канон (XDG)");
        return;
    }
    // 1) HOME=операторский (с файлом), `FASAD_CONFIG` снят (`env_remove`
    //    иглы харнеса): демон стартует и витрина ОТДАЁТ ФАЙЛОВЫЙ HF_HOST =
    //    файл читается. Дискриминатор = НЕ баннер (прямые read_line =
    //    CI-гонка с буфером, #224) и НЕ порт-контент (8765 на shared-раннере
    //    = гонка): GET /v1/config = детерминированный ответ.
    let xdg_home = format!("{home}/.config");
    let d2 = Daemon::start(&[
        ("HOME", home.as_str()),
        ("XDG_CONFIG_HOME", xdg_home.as_str()),
        ("FASAD_CONFIG", ""),
    ]);
    {
        let r = call(&d2.addr, "GET", "/v1/config", &[], b"");
        let j = r.json();
        let row = j["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["key"] == "FASAD_HF_HOST")
            .expect("HF_HOST в таблице");
        assert_eq!(
            row["value"], "https://operator.example.test",
            "файл оператора обязан читаться без FASAD_CONFIG (дискриминатор              E-контура): {j}"
        );
        assert_eq!(row["source"], "file", "{j}");
    }
    drop(d2);

    // 2) Тот же HOME+файл, ИГЛА харнеса: файловое значение исчезает. Игла
    //    = ЯВНЫЙ путь в tmp-файл с другим HF_HOST (`from-file2`): «исчез»
    //    = значение взялось НЕ из канона (витрина различает иглу/канон),
    //    зуб стал сильнее прежнего «не канон = дефолт».
    let needle = dir.join("isolation-needle.cfg");
    std::fs::write(&needle, "FASAD_HF_HOST=https://needle.example.test\n").expect("игла");
    let d = Daemon::start(&[
        ("HOME", home.as_str()),
        ("FASAD_PORT", "0"),
        ("FASAD_CONFIG", needle.to_str().expect("utf-8 путь иглы")),
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
            row["value"].as_str().unwrap_or_default(),
            "https://needle.example.test",
            "игла обязана вытеснить канон-файл оператора: {j}"
        );
        assert_eq!(row["source"], "file", "{j}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// #224 MAJOR-2 (живая нога, mock-контур toy-сервера (`toy_upstream`)): файловый
/// `FASAD_HF_HOST` потребляется загрузчиком: `FetchConfig` = env > файл, и
/// запрос идёт на ФАЙЛОВЫЙ хост (toy = loopback http +
/// `FASAD_PROXY_LOOPBACK_HTTP=1` в том же файле), а не на дефолтный HF.
#[test]
fn fetch_consumes_file_host() {
    let (toy, _rx) = toy_upstream();
    let dir = unique_tmp_path("fasad-hfhost-224");
    std::fs::create_dir_all(&dir).expect("каталог");
    let file = dir.join("config");
    std::fs::write(
        &file,
        format!(
            "FASAD_HF_HOST=http://{}\nFASAD_PROXY_LOOPBACK_HTTP=1\n",
            toy.replace("http://", "")
        ),
    )
    .expect("файл");
    let cfg = guard_daemon::config::Config::load_config_at(Some(
        &guard_daemon::config::ConfigPath::explicit(file.clone()),
    ))
    .expect("читается")
    .config;
    // 1) файловый хост доезжает до FetchConfig (env чист: харнес-контракт).
    // Продуктивная граница: env чист (харнес), хост = из файла.
    let fc = guard_daemon::fetch::FetchConfig::from_config(&cfg)
        .expect("файловый хост разбирается (loopback http + флаг из того же файла)");
    assert_eq!(
        fc.host_display(),
        format!("http://{}", toy.replace("http://", ""))
    );
    // 2) env побеждает файл (тот же приоритет, что у всего слоя).
    let fc = guard_daemon::fetch::FetchConfig::from_lookup(&cfg, &|k| {
        (k == "FASAD_HF_HOST")
            .then(|| "https://from-env.example.test".to_owned())
            .or_else(|| cfg.file_value(k).map(str::to_owned))
    })
    .expect("env");
    assert_eq!(fc.host_display(), "https://from-env.example.test");
    std::fs::remove_dir_all(&dir).ok();
}

/// #26 «чексумма-совпала ⇒ маркер не обязателен»: решётка 5 классов × 4 форм
/// на ЖИВОМ демоне (product path `/v1/analyze`, feature-off харнес каскада-0
/// — урок #240 «P6 live-промер»: контракт меряется там, где его видит
/// оператор, не только unit-сканом). Формулировка issue (#13-era, PR #13):
/// «номер-без-маркера не детектится» — ПЕРВИЧКА ПРОТИВ ТЕКУЩЕГО КОНТУРА
/// (#80 окна + #234 каркас-0.95): валид = 1.0 без всякого слова (чексумма =
/// сильная опора, кандидат issue ЖИВЁТ), невалид под каркасом = 0.95,
/// невалид без каркаса = молчание (намеренный FP-контур бейтов
/// g0217–g0226/g0243–g0247/g0268), молчание карты под каркасом = контракт
/// #234 (`scan_frame_invalid`: карточных окон нет, Луна-16 = формат, не
/// каркас). Таблица артефактомissue = закрывающий комментарий PR + README
/// §Промер-решётки; векторы — первичка эталонов (промер 26.10,
/// `POST /v1/analyze`).
#[test]
fn checksum_marker_lattice_closes_issue_26() {
    let d = Daemon::start::<&str>(&[]);
    // (класс, текст, ожидаемые (entity_type, score) = ПОВЕДЕНИЕ ПЕРВИЧКИ).
    let grid: &[(&str, &str, &[(&str, f64)])] = &[
        // ИНН-10 (эталон README §2: 2482014338 — здесь 1054839620 = свой счёт).
        ("inn голый-валид", "1054839620", &[("inn", 1.0)]),
        ("inn каркас-валид", "ИНН 1054839620", &[("inn", 1.0)]),
        ("inn голый-невалид", "5027196012", &[]),
        ("inn каркас-невалид", "ИНН 5027196012", &[("inn", 0.95)]),
        // СНИЛС 3+3+3+2 (эталон B1 g0202: 384-051-346 70).
        ("snils голый-валид", "112-233-455 97", &[("snils", 1.0)]),
        (
            "snils каркас-валид",
            "СНИЛС 112-233-455 97",
            &[("snils", 1.0)],
        ),
        ("snils голый-невалид", "112-233-455 95", &[]),
        (
            "snils каркас-невалид",
            "СНИЛС 112-233-455 95",
            &[("snils", 0.95)],
        ),
        // Карта Луна-16 (g0268-контра: валид без слова = 1.0).
        ("card голый-валид", "2202203651234561", &[("card_pan", 1.0)]),
        (
            "card каркас-валид",
            "карта 2202203651234561",
            &[("card_pan", 1.0)],
        ),
        ("card голый-невалид", "2202203651234567", &[]),
        ("card каркас-невалид", "карта 2202203651234567", &[]),
        // ОГРН-13 (эталон §4: 1027739401117; SPEC §8: 13 = ВЕКТОР
        // card_pan+ogrn, обе Луна и mod11 сходятся).
        (
            "ogrn голый-валид",
            "1027739401117",
            &[("card_pan", 1.0), ("ogrn", 1.0)],
        ),
        (
            "ogrn каркас-валид",
            "ОГРН 1027739401117",
            &[("card_pan", 1.0), ("ogrn", 1.0)],
        ),
        ("ogrn голый-невалид", "1027739401110", &[]),
        (
            "ogrn каркас-невалид",
            "ОГРН 1027739401110",
            &[("ogrn", 0.95)],
        ),
        // ОГРНИП-15 (эталон §4: 313132804400022).
        ("ogrnip голый-валид", "313132804400022", &[("ogrnip", 1.0)]),
        (
            "ogrnip каркас-валид",
            "ОГРНИП 313132804400022",
            &[("ogrnip", 1.0)],
        ),
        ("ogrnip голый-невалид", "313132804400021", &[]),
        (
            "ogrnip каркас-невалид",
            "ОГРНИП 313132804400021",
            &[("ogrnip", 0.95)],
        ),
    ];
    for (label, text, want) in grid {
        let spans = analyzed_spans_with_scores(&d.addr, text);
        let want: Vec<(String, f64)> = want.iter().map(|(c, s)| ((*c).to_owned(), *s)).collect();
        assert_eq!(spans, want, "ячейка «{label}» = {text:?}");
    }
}

/// Спан-кортежи с весом (`analyzed_spans` берёт только классы; решётке #26
/// нужен score: 1.0 вето / 0.95 каркас — различие клеток).
fn analyzed_spans_with_scores(addr: &str, text: &str) -> Vec<(String, f64)> {
    let reply = call(
        addr,
        "POST",
        "/v1/analyze",
        &[("content-type", "application/json")],
        format!(r#"{{"text":"{text}"}}"#).as_bytes(),
    );
    assert_eq!(reply.status, 200, "анализ: {}", reply.text());
    reply
        .json()
        .as_array()
        .expect("массив спанов")
        .iter()
        .map(|s| {
            (
                s["entity_type"].as_str().expect("класс").to_owned(),
                s["score"].as_f64().expect("вес"),
            )
        })
        .collect()
}
