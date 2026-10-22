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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use guard_daemon::ui::CSP;

struct Daemon {
    child: Child,
    addr: String,
}

impl Daemon {
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
            .env_remove("FASAD_THREADS")
            .env_remove("FASAD_TIMEOUT_MS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("бинарь фасада запускается");
        let stdout = child.stdout.take().expect("stdout перехвачен");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if tx.send(line.clone()).is_err() {
                    break;
                }
            }
        });
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
                return Self { child, addr };
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

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
    let mut sock = TcpStream::connect(addr).expect("сокет поднимается");
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .expect("таймаут ставится");
    sock.write_all(&bytes).expect("запрос уходит");
    sock.flush().expect("флуш");
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).expect("ответ читается до конца");
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
