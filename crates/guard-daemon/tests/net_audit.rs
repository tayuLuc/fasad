//! Гейт «у демона ровно один исходящий путь» (шаг 6: #56 п.5; шаг 7c: SPEC §10 п.7).
//!
//! Ранее это был `grep`-рецепт в `justfile`, и у него было два дефекта. Первый:
//! `just` на Windows гоняет рецепты без shebang через `cmd`, где `grep` не
//! обязан быть, т.е. гейт спотыкался бы об ОС, а не об факт. Второй: рецепт не
//! входил в CI-матрицу (jobs зовут `just lint`/`test`/`deny` поштучно), значит
//! на ubuntu+windows он не исполнялся вовсе — ложно-зелёная стена.
//!
//! С шага 7c формулировка «клиента нет» стала неверной: прокси `/v1/chat/completions`
//! обязан уметь ходить наружу. Гейт от этого не ослаб, а стал строже — три факта,
//! и все три обходятся только очевидным вандализмом:
//!
//! 1. манифест объявляет клиент ровно один: `ureq` с `default-features = false`
//!    и с фичей `rustls` — TLS-стек приходит изнутри единственного клиента;
//! 2. клиентский путь (`ureq::`) живёт ровно в одном файле — `src/proxy.rs`, —
//!    и запрет подкреплён обратным требованием: в этом файле маркер обязан
//!    встречаться, иначе «исключение» оформлено под код, которого нет;
//! 3. в дереве зависимостей `guard-daemon` есть `ureq` и нет `reqwest`.
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

/// Что запрещено видеть в исходниках демона **вне** санкционированного модуля:
/// пути к исходящему сокету и чужие транспортные крейты.
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

/// Единственный файл `src/`, которому разрешено ходить наружу.
const SANCTIONED_SRC: &str = "proxy.rs";

/// Маркер исходящего пути, обязательный внутри санкционированного файла.
const REQUIRED_IN_SANCTIONED: &str = "ureq::";

/// Что запрещено **объявлять ключом** в секции зависимостей. `ureq` в списке нет:
/// он объявлен намеренно и проверяется отдельно ([`SANCTIONED_CLIENT`]).
///
/// Сравнение по ключу, а не подстрокой: `rustls` в манифесте встречается — как
/// фича того же `ureq`, и это ровно то, что нам нужно. Подстрока краснела бы на
/// собственном разрешении (промерено на этом файле, первая версия гейта).
const FORBIDDEN_MANIFEST: &[&str] = &[
    "reqwest",
    "hyper",
    "tonic",
    "native-tls",
    "openssl",
    "rustls",
    "tokio-rustls",
];

/// Объявленный клиент: имя, по которому ищем строку объявления. Проверка его
/// атрибутов — не косметика: `default-features = false` у `ureq` означает
/// «никаких gzip, cookie и системного прокси», и включение их обратно — тихое
/// расширение поверхности.
const SANCTIONED_CLIENT: &str = "ureq";

/// Клиенты, чьё присутствие/отсутствие в дереве проверяется через `cargo tree`.
///
/// `hyper` в списке «нет» не стоит: он в дереве есть законно, как сервер `axum`.
/// То, что он не стал вторым клиентом, держат проверка манифеста (по ключу) и
/// проверка исходников (`hyper::client`).
/// Ровно один вход клиента в дерево — но меряется на **дефолтных** фичах.
/// С `--features ort-inference` у `ort` появляется собственный `ureq` (загрузка
/// моделей), и «один вход» станет двумя по законной причине: гейт проверяет
/// путь демона, а не чужие опциональные рущи.
const TREE_MUST_EXIST: &[&str] = &["ureq"];
const TREE_MUST_BE_ABSENT: &[&str] = &["reqwest"];

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

/// Объявлена ли зависимость с таким именем: ключ `name = …` или заголовок
/// подсекции `[dependencies.name]` (в т.ч. внутри target-таблиц). Значения фич
/// намеренно не смотрятся — см. doc у [`FORBIDDEN_MANIFEST`].
fn declares_dependency(manifest: &str, token: &str) -> bool {
    let heading = format!("[dependencies.{token}");
    let nested = format!(".dependencies.{token}]");
    manifest.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with(&heading)
            || line.contains(&nested)
            || line.split_once('=').is_some_and(|(k, _)| k.trim() == token)
    })
}

#[test]
fn daemon_manifest_declares_exactly_one_client_with_locked_features() {
    let manifest =
        fs::read_to_string(manifest_dir().join("Cargo.toml")).expect("манифест читается");
    for token in FORBIDDEN_MANIFEST.iter().copied() {
        assert!(
            !declares_dependency(&manifest, token),
            "манифест guard-daemon объявляет {token}: второй транспортный путь \
             запрещён (SPEC §10 п.7, AGENTS «никаких сетевых вызовов кроме X-Upstream-URL»)"
        );
    }
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(SANCTIONED_CLIENT))
        .unwrap_or_else(|| {
            panic!(
                "манифест не объявляет {SANCTIONED_CLIENT}: прокси 7c обязан ходить \
                 наружу ровно одним путём"
            )
        });
    assert!(
        line.contains("default-features = false"),
        "`{SANCTIONED_CLIENT}` объявлен с дефолтами: включаются gzip, cookies и \
         системный прокси — тихое расширение поверхности. Линия: {line}"
    );
    assert!(
        line.contains("rustls"),
        "`{SANCTIONED_CLIENT}` объявлен без `rustls`: TLS либо берётся из второго \
         места, либо включается `native-tls`. Линия: {line}"
    );
}

#[test]
fn outbound_path_lives_in_one_file_only() {
    let mut files = Vec::new();
    rs_files(&manifest_dir().join("src"), &mut files);
    assert!(
        files.len() >= 6,
        "сканируем не всё: найдено {} файлов",
        files.len()
    );
    let mut sanctioned_seen = false;
    let mut sanctioned_hits = 0_usize;
    for file in &files {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let text = fs::read_to_string(file).expect("источник читается");
        for (at, line) in text.lines().enumerate() {
            for token in FORBIDDEN_SRC.iter().copied() {
                if line.contains(token) {
                    assert_eq!(
                        name,
                        SANCTIONED_SRC,
                        "{}:{}: исходящий сокет {token} вне санкционированного модуля \
                         ({SANCTIONED_SRC}): второй путь наружу = дыра, которую не \
                         закрывает ни один allowlist",
                        file.display(),
                        at + 1,
                    );
                    sanctioned_seen = true;
                    if line.contains(REQUIRED_IN_SANCTIONED) {
                        sanctioned_hits += 1;
                    }
                }
            }
        }
    }
    // Два требования вместо одного: «файл-исключение существует» и «файл-исключение
    // работает». Без второго гейт был бы зелёным на пустом proxy.rs, а зелёный на
    // пустом файле гейт и есть ложная стена.
    assert!(
        sanctioned_seen,
        "санкционированный файл {SANCTIONED_SRC} не найден в `src/`"
    );
    assert!(
        sanctioned_hits > 0,
        "{SANCTIONED_SRC} не содержит ни одного обращения к клиенту \
         ({REQUIRED_IN_SANCTIONED}): исключение оформлено под код, которого нет"
    );
}

#[test]
fn dependency_tree_carries_the_one_client_and_no_second_one() {
    for token in TREE_MUST_EXIST.iter().copied() {
        let out = run_tree(token);
        assert!(
            out.status.success(),
            "`cargo tree -i {token}` не нашёл пакета в дереве guard-daemon: \
             stderr {}\nПрокси 7c обязан линковать ровно один клиент.",
            String::from_utf8_lossy(&out.stderr)
        );
        let tree = String::from_utf8_lossy(&out.stdout);
        let direct = tree
            .lines()
            .filter(|l| l.trim_start().starts_with(token))
            .count();
        assert_eq!(
            direct, 1,
            "{token} входит в дерево {direct} разами: у клиента должен быть ровно один вход"
        );
    }
    for token in TREE_MUST_BE_ABSENT.iter().copied() {
        let out = run_tree(token);
        assert!(
            !out.status.success(),
            "`cargo tree -i {token}` нашёл пакет в дереве guard-daemon: \
             stdout {}\nВторой транспортный путь запрещён (SPEC §10 п.7).",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// `cargo tree -p guard-daemon -i <token> --offline`.
fn run_tree(token: &str) -> std::process::Output {
    Command::new(env!("CARGO"))
        .args(["tree", "-p", "guard-daemon", "-i", token, "--offline"])
        .current_dir(manifest_dir())
        .output()
        .expect("cargo tree запускается")
}
