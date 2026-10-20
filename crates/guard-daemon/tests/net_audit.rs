//! Гейт «демон шага 6 не тащит сеть» (#56 п.5) в переносимой форме.
//!
//! Ранее это был `grep`-рецепт в `justfile`, и у него было два дефекта. Первый:
//! `just` на Windows гоняет рецепты без shebang через `cmd`, где `grep` не
//! обязан быть, т.е. гейт спотыкался бы об ОС, а не об факт. Второй: рецепт не
//! входил в CI-матрицу (jobs зовут `just lint`/`test`/`deny` поштучно), значит
//! на ubuntu+windows он не исполнялся вовсе — ложно-зелёная стена.
//!
//! Здесь те же три проверки, но на `std` + `cargo`, и они бегут в `cargo test
//! --workspace` на обеих ОС:
//!
//! 1. манифест crate не объявляет HTTP-клиента;
//! 2. в `src/` нет ни одного клиентского пути (`::connect(`, `TcpStream::`, …);
//!    `bind` листенера не запрещён — он принимает, а не ходит наружу;
//! 3. в дереве зависимостей `guard-daemon` нет `reqwest`/`ureq`: `cargo tree -i`
//!    на отсутствующий пакет завершается ошибкой, и мы инвертируем rc.
//!
//! Константы гейта написаны открыто: область сканирования — только `src/` и
//! `Cargo.toml`, поэтому файл гейта сам себе не матчится.

// Файл целиком — тестовый: паника `expect` здесь и есть отказ гейта (красный
// CI), т.е. тот же канал, что у assert'ов.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Что запрещено видеть в исходниках демона: пути к исходящему сокету.
///
/// Имена с `::` намеренно: проза док-комментариев упоминает крейты голыми
/// именами, а матчится только путь использования (`reqwest::…`) — иначе гейт
/// краснел бы на собственном описании, как уже случилось с grep-версией.
const FORBIDDEN_SRC: &[&str] = &[
    "::connect(",
    "TcpStream::",
    "UdpSocket::",
    "reqwest::",
    "ureq::",
    "hyper::client",
    "rustls::",
];

/// Что запрещено объявлять в манифесте (здесь `::` не нужен — зависимостей у
/// crate быть не должно ни в каком виде).
const FORBIDDEN_MANIFEST: &[&str] = &["reqwest", "ureq", "hyper", "rustls", "tonic"];

/// Клиентские крейты, чьё отсутствие в дереве проверяется через `cargo tree`.
const FORBIDDEN_TREE: &[&str] = &["reqwest", "ureq"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("каталог src существует") {
        let path = entry.expect("запись каталога читается").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn daemon_manifest_declares_no_http_client() {
    let manifest =
        fs::read_to_string(manifest_dir().join("Cargo.toml")).expect("манифест читается");
    for token in FORBIDDEN_MANIFEST.iter().copied() {
        assert!(
            !manifest.contains(token),
            "манифест guard-daemon объявляет {token}: сеть шага 6 запрещена (#56 п.5), \
             `X-Upstream-URL` — шаг 7"
        );
    }
}

#[test]
fn daemon_sources_contain_no_outbound_socket() {
    let mut files = Vec::new();
    rs_files(&manifest_dir().join("src"), &mut files);
    assert!(
        files.len() >= 5,
        "сканируем не всё: найдено {} файлов",
        files.len()
    );
    for file in &files {
        let text = fs::read_to_string(file).expect("источник читается");
        for (at, line) in text.lines().enumerate() {
            for token in FORBIDDEN_SRC.iter().copied() {
                assert!(
                    !line.contains(token),
                    "{}:{}: встречен исходящий сокет {token} — демон шага 6 не имеет \
                     права ходить наружу (#56 п.5)",
                    file.display(),
                    at + 1,
                );
            }
        }
    }
}

#[test]
fn dependency_tree_of_daemon_has_no_client_crate() {
    for token in FORBIDDEN_TREE.iter().copied() {
        let out = Command::new(env!("CARGO"))
            .args(["tree", "-p", "guard-daemon", "-i", token, "--offline"])
            .current_dir(manifest_dir())
            .output()
            .expect("cargo tree запускается");
        assert!(
            !out.status.success(),
            "`cargo tree -i {token}` нашёл пакет в дереве guard-daemon: \
             stdout {}\nСеть в демоне шага 6 запрещена (#56 п.5).",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
