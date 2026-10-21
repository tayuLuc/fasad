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
}

impl Daemon {
    fn start(env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fasad"));
        cmd.env("FASAD_BIND", "127.0.0.1")
            .env("FASAD_PORT", "0")
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
        .unwrap_or_else(|| {
            panic!(
                "ответ без заголовков: {} байт, начало {:?}",
                raw.len(),
                &raw[..raw.len().min(120)]
            )
        });
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
    let d = Daemon::start(&[]);
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
fn bad_vault_key_refuses_to_start_before_binding() {
    // Отказ до бинда: код выхода 2 (не 1, как у сетевой ошибки), причина
    // названа словами, баннера нет. Читается `wait_with_output`: процесс сам
    // завершается, поэтому трубки закрываются и чтение ограничено самим
    // процессом, а не нашим таймаутом.
    let out = Command::new(env!("CARGO_BIN_EXE_fasad"))
        .env("FASAD_BIND", "127.0.0.1")
        .env("FASAD_PORT", "0")
        .env("FASAD_VAULT_KEY", "не-шестнадцатеричный")
        // Причина отказа обязана быть про ключ, а не про веса: на машине с
        // `FASAD_MODEL_DIR` каскадный старт проверяется раньше и перехватил бы
        // первую строку stderr.
        .env_remove("FASAD_MODEL_DIR")
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
    let d = Daemon::start(&[]);
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
