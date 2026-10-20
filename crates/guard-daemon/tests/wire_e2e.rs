//! Проводной e2e: живой бинарь, настоящий сокет, HTTP/1.1 руками.
//!
//! Зачем он нужен, если `src/http.rs` уже покрывает роутер тестами с `oneshot`:
//! тот класс проверяет маршрутизатор внутри процесса и НЕ покрывает (а) разбор
//! `FASAD_*`-переменных в реальном старте, (б) баннер с фактическим портом,
//! (в) кодинг заголовков и framing на сокете, (г) коды выхода процесса. Всё
//! это — контракт, который оператор видит в терминале, а `oneshot` — нет.
//!
//! Клиент написан вручную (`std::net::TcpStream` + `Connection: close`), а не
//!taken из крейта: HTTP-клиент в dev-зависимях демона поймал бы себе
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
}

impl Daemon {
    fn start(env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fasad"));
        cmd.env("FASAD_BIND", "127.0.0.1")
            .env("FASAD_PORT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("бинарь фасадa запускается");
        let stdout = child.stdout.take().expect("stdout перехвачен");
        // Читатель в отдельном потоке и с `recv_timeout`: блокирующий `read_line`
        // на трубке CHILD'а, который умер до баннера, вешает тест на неопределённо
        // (проверено: три параллельных e2e-теста стояли 10 минут), а тайм-аут
        // обязан быть у ожидания, а не у всего теста.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let started = Instant::now();
        let mut seen = String::new();
        let mut exited = None;
        while started.elapsed() < Duration::from_secs(15) {
            let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) else {
                if let Some(status) = child.try_wait().expect("статус читается") {
                    exited = Some(status);
                    break;
                }
                continue;
            };
            seen.push_str(&line);
            if let Some(rest) = seen
                .split_once("listening on http://")
                .map(|(_, r)| r.to_owned())
            {
                let addr = rest
                    .split('/')
                    .next()
                    .expect("адрес заканчивается путём")
                    .to_owned();
                return Self { child, addr };
            }
        }
        // Убить и дождаться до паники: паникующий тест не обязан оставлять
        // процесс-зомби (клинч `zombie_processes` это и ловит).
        let _ = child.kill();
        let _ = child.wait();
        // Причина отказа из stderr читается ТОЛЬКО если процесс сам завершился:
        // на живом демоне трубке конца нет, и чтение вернуло бы нас к той же
        // вешалке, из которой мы только что вышли. Это не косметика — на
        // windows-раннере именно эта строка отличит «mlock отказал» от «тест
        // не дождался баннера».
        let reason = match exited {
            Some(_) => {
                let mut buf = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut e, &mut buf);
                }
                buf
            }
            None => String::new(),
        };
        panic!(
            "демон не напечатал баннер за {:?}; stdout: {seen:?} stderr: {reason:?}",
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

/// То же, но сырыми байтами: нужно там, где `&str`-заголовок не выражает
/// намерение (битый chunked, значение заголовка вне UTF-8).
fn call_raw(addr: &str, bytes: &[u8]) -> Reply {
    let mut sock = TcpStream::connect(addr).expect("сокет поднимается");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("таймаут ставится");
    sock.write_all(bytes).expect("запрос уходит");
    sock.flush().expect("флуш");
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).expect("ответ читается до конца");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("ответ с заголовками");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
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
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

/// Разделители-дефисы в СНИЛС тут намеренно отсутствуют: нормализатор каскада 0
/// их не склеивает (известное ограничение, docs/daemon-scope.md §«Что каскад 0 не находит»,
/// issue #51), и тест обязан отражать фактическое поведение, а не желаемое.
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
    let d = Daemon::start(&[]);
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
    // на одном входе (docs/daemon-scope.md §«Что каскад 0 не находит»). Спан имени добавлен
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
fn bad_vault_key_refuses_to_start_before_binding() {
    // Отказ до бинда: код выхода 2 (не 1, как у сетевой ошибки), причина
    // названа словами, баннера нет. Читается `wait_with_output`: процесс сам
    // завершается, поэтому трубки закрываются и чтение ограничено самим
    // процессом, а не нашим таймаутом.
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        .env("FASAD_VAULT_KEY", "не-шестнадцатеричный")
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
    let d = Daemon::start(&[]);
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
