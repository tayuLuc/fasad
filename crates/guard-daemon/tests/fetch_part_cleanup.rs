//! #199 (parent-триаж): осиротевший `.part` на раннем отказе загрузки.
//!
//! ПЕРВИЧКА дефекта — с кода (`fetch.rs::fetch_file`, промер на `1ed675f`):
//! `.part` пишется в поток по мере чтения, а `remove_file(&tmp)` стоит только
//! на трёх ветках — `Err`-чтение потока, `E_SIZE`, `E_SHA`. На `E_TOO_LARGE`
//! и на `E_IO`-записи поток обрывается РАНИШЕ этих веток (`sink.write` → `?`):
//! функция выходит по `?`, `.part` с половинным телом остаётся в каталоге
//! весов навсегда — следующий прогон пишет в тот же путь с нуля. Продуктовый
//! fs-мусор в кэше оператора.
//!
//! ПЕРВИЧКА tmp-пути с кода (`fetch.rs:442`): `dest.with_extension("part")`
//! = «onnx/model.onnx» → «onnx/model.part» (расширение ЗАМЕНЯЕТСЯ). Проверка
//! «model.onnx.part отсутствует» была бы вечно зелёной стеной — файл с таким
//! именем не создаётся никогда (промер этой сессии: зуб на ложном имени = ok
//! при живом мусоре на диске) = урок ложно-зелёной проверки.
//!
//! ДИСКРИМИНАТОР (`E_TOO_LARGE`, а не `E_SIZE`): кап срабатывает ДО финальной
//! сверки размера, т.е. ветка `E_SIZE`-уборки на этом входе не исполняется
//! вовсе. Тот же вход на `E_SIZE`-пути = зелёный и без чина = мёртвый зуб.
//!
//! КАНАЛ = живой `fetch_file` против петлевого HTTP-источника (тот же
//! аффорданс, что `FASAD_PROXY_LOOPBACK_HTTP` у fetch-контуров), фикстура =
//! байты в памяти, sha256 считается `sha2`-ом — ТЕМ ЖЕ крейтом, что продукт,
//! и ожидаемое собирается НЕ той же функцией, что проверяется (AGENTS
//! §Дисциплина фактов).
//!
//! Канон чина = die-cleanup #327: уборка tmp-носителя на ЛЮБОМ выходе
//! (Drop-guard с дизармом перед штатным rename).

#![allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = канал ответа

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;

use sha2::Digest as _;

use guard_daemon::config::Config;
use guard_daemon::fetch::{self, E_TOO_LARGE};
use guard_daemon::weights::ManifestEntry;

/// Петлевой HTTP-источник, отдающий `body` и закрывающий соединение.
/// Возвращает авторити `127.0.0.1:<порт>`.
fn loopback_source(body: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("петлевой источник слушает");
    let addr = listener.local_addr().expect("адрес источника известен");
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            let mut probe = [0_u8; 1024];
            let _ = sock.read(&mut probe);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes());
            let _ = sock.write_all(body);
            let _ = sock.flush();
        }
    });
    addr.to_string()
}

/// Каталог раскладки весов в temp; уникален на тест (tag = второй ключ).
fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fasad-part-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(dir.join("onnx")).expect("создать раскладку");
    dir
}

/// Конфиг петлевого fetch-контура (тот же аффорданс, что у fetch-тестов).
fn loopback_cfg(authority: &str) -> fetch::FetchConfig {
    let cfg = Config::from_lookup({
        let flag = true;
        move |k| match k {
            "FASAD_PROXY_LOOPBACK_HTTP" if flag => Some("1".to_owned()),
            _ => None,
        }
    })
    .expect("конфиг пробы");
    let host = format!("http://{authority}");
    fetch::FetchConfig::from_lookup(&cfg, &|k| match k {
        "FASAD_HF_HOST" => Some(host.clone()),
        _ => None,
    })
    .expect("петлевой fetch-контур легален")
}

/// Содержимое каталога `onnx/` — свидетель для отказа (не «файла нет»,
/// а «что именно осталось»: ложь о причине отказа = AGENTS).
fn listing(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir.join("onnx"))
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn too_large_refusal_leaves_no_part_file() {
    // Поток больше манифестной декларации = E_TOO_LARGE на записи в sink
    // (кап = `size_bytes` манифеста, строка 491-499 fetch.rs на промере).
    let dir = sandbox("toolarge");
    let authority = loopback_source(&[7_u8; 4096]);
    let fc = loopback_cfg(&authority);
    let entry = ManifestEntry {
        role: "extractor1b".into(),
        repo: "o/n".into(),
        revision: "rev".into(),
        file: "onnx/model.onnx".into(),
        sha256: "0".repeat(64),
        // Декларация ЗАВЕДОМО меньше тела: кап срабатывает на потоке.
        size_bytes: 1024,
    };
    let agent = fetch::agent_for(false);
    let err = fetch::fetch_file(&agent, &fc, &dir, &entry, "onnx/model.onnx", 1, 1)
        .expect_err("поток больше манифеста = отказ");
    let text = err.to_string();
    let part_left = dir.join("onnx/model.part").exists();
    let seen = listing(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        text.starts_with(E_TOO_LARGE),
        "ожидался E_TOO_LARGE: {text}"
    );
    assert!(
        !part_left,
        "{E_TOO_LARGE}: .part обязан быть убран с диска (die-cleanup #327-канон), \
         каталог onnx/: {seen:?}"
    );
}

#[test]
fn sha_mismatch_path_stays_clean() {
    // E_SHA-ветка (уборка в коде ЕСТЬ) = интактна после чина. Positive
    // control живости контура: без него «.part исчез» достигался бы и полным
    // отказом скачивать (полка #339-класс слепого пятна).
    let body: &'static [u8] = b"weight-bytes-for-the-mock";
    let dir = sandbox("shamiss");
    let authority = loopback_source(body);
    let fc = loopback_cfg(&authority);
    let entry = ManifestEntry {
        role: "extractor1b".into(),
        repo: "o/n".into(),
        revision: "rev".into(),
        file: "onnx/model.onnx".into(),
        // Верный размер, ЗАВЕДОМО битый sha = fail-closed после полного чтения.
        sha256: "f".repeat(64),
        size_bytes: body.len() as u64,
    };
    let agent = fetch::agent_for(false);
    let err = fetch::fetch_file(&agent, &fc, &dir, &entry, "onnx/model.onnx", 1, 1)
        .expect_err("битый sha = отказ");
    let seen = listing(&dir);
    let code_ok = err.to_string().starts_with(fetch::E_SHA);
    std::fs::remove_dir_all(&dir).ok();
    assert!(code_ok, "ожидался E_SHA, каталог onnx/: {seen:?}: {err}");
    assert!(
        !seen.iter().any(|n| std::path::Path::new(n)
            .extension()
            .is_some_and(|e| e == "part")),
        "E_SHA: .part обязан быть убран (существующая ветка), onnx/: {seen:?}"
    );
}

#[test]
fn success_path_publishes_file_and_no_part() {
    // Штатный исход: tmp переименован в dest; `.part` не переживает rename
    // (дизарм guard-а обязан стоять ДО rename, иначе фикс сожрёт скачанный файл).
    let body: &'static [u8] = b"weight-bytes-for-the-mock";
    let digest = sha2::Sha256::digest(body);
    let good_sha: String = digest.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let dir = sandbox("success");
    let authority = loopback_source(body);
    let fc = loopback_cfg(&authority);
    let entry = ManifestEntry {
        role: "extractor1b".into(),
        repo: "o/n".into(),
        revision: "rev".into(),
        file: "onnx/model.onnx".into(),
        sha256: good_sha,
        size_bytes: body.len() as u64,
    };
    let agent = fetch::agent_for(false);
    let downloaded =
        fetch::fetch_file(&agent, &fc, &dir, &entry, "onnx/model.onnx", 1, 1).expect("загрузка");
    let published = dir.join("onnx/model.onnx").is_file();
    let seen = listing(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!downloaded, "файла в кеше не было = скачан");
    assert!(published, "файл обязан лежать на месте, onnx/: {seen:?}");
    assert!(
        !seen.iter().any(|n| std::path::Path::new(n)
            .extension()
            .is_some_and(|e| e == "part")),
        ".part не должен переживать rename, onnx/: {seen:?}"
    );
}
