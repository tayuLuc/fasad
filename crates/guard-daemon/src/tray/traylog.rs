//! Лог-контур трея (#244 win → #263 platform-root): след startup/refuse/
//! warning/трей-отказ текстов в `<config-root>/fasad-tray.log`.
//!
//! Зачем: под GUI-подсистемой (#226/#228: `windows_subsystem = "windows"` для
//! `fasad-tray.exe`) stderr = NULL-поток: ВСЕ тексты (startup/refuse/warning +
//! ветвь «трей недоступен») невидимы при запуске двойным кликом. Родительский
//! диагноз #244 (коммент 6399041556, пункт (б)): GUI-контур «запустил и
//! забыл» обязан оставлять след на диске — лог-файл, путь в README бандла и
//! в окне отказа.
//!
//! #263 (первичка родителя: mac-ассет v0.1.6 = `strings bin/fasad-tray |
//! grep -c fasad-tray.log` = 0): мишень #244 «ТОЛЬКО Windows» сужала контур
//! до win-CFG-острова, тогда как механика (формат строки, ротация, append) =
//! чистый std. На mac/linux `windows_subsystem` НЕ действует (win-only
//! атрибут), но ДВОЙНОЙ КЛИК Finder'ом = запуск без терминала = stderr =
//! NULL: тихая ветка mac-полки (#238-полка, #198 «запустил и забыл»). Чин =
//! лог-контур ОС-НЕЗАВИСИМЫЙ под `all(feature = "tray")` (монтаж в `tray.rs`
//! /`main.rs`): win-формула канона интактна byte-for-byte, mac/linux = тот
//! же config-root (`config_file_path_from`: XDG/HOME), без new-крейтов.
//! Headless-бинарь (`fasad`) = НЕ затронут: консоль есть всегда (контра
//! #185/#190), NOOP-нога `win_log` main.rs интактна.
//!
//! Путь = корень конфига (win: `config_dir_from_appdata` #224; unix/mac:
//! XDG/HOME, первичка config.rs) + [`LOG_FILE_NAME`]: «куда пишет демон» и
//! «где читать» = одна формула, две истины нельзя.
//!
//! Формат строки (контракт юнита [`format_log_line`]): целые unix-секунды UTC
//! + пробел + текст + перевод строки. Без chrono: лог = диагностика, не
//! календарь; grep по времени работает и по монотонной шкале.
//!
//! Ротация = 5 МБ (ТЗ #244): переполнение = СОХРАНИТЬ ПРЕДЫДУЩИЙ СЛОЙ ОДИН
//! (`.log.1`) и обнулить живой файл: append без потолка = растущий файл на
//! вечном демоне, полное затирание = «следов нет» — тот же класс лжи нулём,
//! что молчаливый stderr.
//!
//! Ошибки записи = молчание: лог = витрина; отказ диска не имеет права валить
//! демон (тот же профиль, что `open_ui` / `open_instruction_url`).

/// Порог ротации живого лога, байты (ТЗ #244: 5 МБ).
pub const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

/// Имя файла в каталоге конфига: `%APPDATA%\fasad\fasad-tray.log` (README
/// бандла ссылается на это имя).
pub const LOG_FILE_NAME: &str = "fasad-tray.log";

/// Резолв пути лога: env `FASAD_TRAY_LOG` (явный = стенд/харнеси: CI-нога и
/// полка оператора пишут в свой файл; пустое значение = «не задан», контракт
/// #219-lookup) → канон `<config-root>/fasad-tray.log`. ЧИСТАЯ функция
/// (headless-контра #151): env-машина = аргумент, юнит меряет все ветки без
/// живой ОС.
/// Формула канона = корень конфига + [`LOG_FILE_NAME`]: путь «куда писать» в
/// README, окне и коде = одна истина. Корень = та же env-цепочка, что файл
/// конфигурации ([`crate::config::config_file_path_from`], первичка
/// config.rs): win = `%APPDATA%\fasad` (#244-канон интактен: `APPDATA` +
/// `fasad`), unix/mac = `$XDG_CONFIG_HOME/fasad`, дефолт `$HOME/.config/
/// fasad` (#263: mac/Linux-трей = тот же корень, без new-крейтов и без
/// second-truth о домашнем каталоге).
/// `None` = писать негде (env пуст/не задан = сломанный env): вызывающий
/// обязан молчать — врать о пути лога нельзя.
#[must_use]
pub fn resolve_log_path(
    mut lookup: impl FnMut(&'static str) -> Option<String>,
) -> Option<std::path::PathBuf> {
    if let Some(p) = lookup("FASAD_TRAY_LOG")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        return Some(std::path::PathBuf::from(p));
    }
    crate::config::config_file_path_from(&mut lookup)
        .map(|cp| cp.path.with_file_name(LOG_FILE_NAME))
}

/// Путь лога на живой env-машине (`std::env::var`).
#[must_use]
pub fn log_path() -> Option<std::path::PathBuf> {
    resolve_log_path(|k| std::env::var(k).ok())
}

/// Формат строки лога (контракт юнита): `"<ts> <text>\n"`, ts = целые
/// unix-секунды UTC. Формат зафиксирован: это контракт grep-читаемости,
/// а не косметика.
#[must_use]
pub fn format_log_line(ts_secs: u64, text: &str) -> String {
    format!("{ts_secs} {text}\n")
}

/// Текущая unix-дата (секунды); epoch-сбой = 0: метка времени = косметика,
/// строка обязана быть написана.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Append одной строки в лог (контур #244). Все исходы, кроме успешной
/// записи, = молчание: отсутствие диска не имеет права убить демона
/// (контракт `open_instruction_url`).
pub fn append_log(text: &str) {
    let _ = append_log_at(log_path().as_deref(), text);
}

/// Механика [`append_log`] на названном пути (pub-контра unit-зуба win-ноги
/// CI: живой файл = tempdir-уникальный путь (#224-харнес-урок), env-машина
/// тестов не гоняется — `std::env::set_var` = race-класс).
///
/// # Errors
///
/// `Err` = сбой диска: `rotate_if_needed` не тронул живой файл (metadata/
/// rename) или открыть/записать не смог. `Ok(false)` = путь не назван
/// (молчание-норма «писать негде»), `Ok(true)` = строка записана.
pub fn append_log_at(path: Option<&std::path::Path>, text: &str) -> std::io::Result<bool> {
    use std::io::Write;
    let Some(path) = path else { return Ok(false) };
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    // Каталог = канон конфига; UI-write (#219) его создаёт, но при отказе
    // конфига каталога может и не быть — создаём сами (best-effort).
    let _ = std::fs::create_dir_all(parent);
    rotate_if_needed(path)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format_log_line(now_unix_secs(), text).as_bytes())?;
    Ok(true)
}

/// Ротация по порогу: живой файл >= порога -> снести старый `.1` слой, живой
/// переезжает в `.1`, живое имя освобождается (следующий append пересоздаёт).
/// `Ok(())` = NORMAL-ветки: порог не достигнут; файла нет (`NotFound` =
/// норма CreateNew-контура, не отказ); ротация прошла.
/// `Err` = сбой диска (metadata/rename) — живой файл НЕ ТРОГАЛИ, вызывающий
/// обязан пропустить запись, а не затереть её append'ом.
fn rotate_if_needed(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::metadata(path) {
        Ok(md) if md.len() >= LOG_ROTATE_BYTES => {}
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    let _ = std::fs::remove_file(sibling(path, ".1"));
    std::fs::rename(path, sibling(path, ".1"))
}

/// Соседний путь с добавленным суффиксом (`x.log` -> `x.log.1`): std-полка
/// суффиксов не имеет (rust-lang/rust#45309, открыт).
fn sibling(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // в тестах паника = красный CI, это канал ответа
mod tests {
    use super::*;

    fn lookup(kv: &[(&'static str, &'static str)]) -> impl FnMut(&'static str) -> Option<String> {
        let kv = kv.to_vec();
        move |k| {
            kv.iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn log_path_win_appdata_formula_is_intact() {
        // #244-контра (win-ветка формулы, интактен после #263): лог = канон
        // конфига `%APPDATA%\fasad\fasad-tray.log`. Канон собирается той же
        // чистой функцией, что win-ветка `config_file_path_from`
        // (`config_dir_from_appdata`, первичка config.rs) — прямая формула
        // (проверяется на любой ОС, win-контра config.rs:2468 того же
        // профиля); unix-лег канона = `log_path_unix_root_is_config_root`
        // через общую env-цепочку `config_file_path_from`.
        let dir = crate::config::config_dir_from_appdata(Some("C:\\Users\\u\\AppData\\Roaming"))
            .expect("APPDATA даёт каталог");
        // Ожидание = Path::join-цепочка (сепаратор ОС-относителен; win-нога
        // CI мерит форму `%APPDATA%\fasad\fasad-tray.log`).
        assert_eq!(
            dir.join(LOG_FILE_NAME),
            std::path::Path::new("C:\\Users\\u\\AppData\\Roaming")
                .join("fasad")
                .join(LOG_FILE_NAME)
        );
        // Живой env win-раннера (`cfg!(windows)` в config-цепочке = промер на
        // win-ноге CI): APPDATA-корень + имя файла = канон README.
        if cfg!(windows) {
            let p = resolve_log_path(lookup(&[("APPDATA", "C:\\Users\\u\\AppData\\Roaming")]));
            assert_eq!(
                p,
                Some(
                    std::path::Path::new("C:\\Users\\u\\AppData\\Roaming")
                        .join("fasad")
                        .join(LOG_FILE_NAME)
                ),
                "win-канон = %APPDATA%\\fasad\\fasad-tray.log"
            );
        }
    }

    #[test]
    fn log_path_unix_root_is_config_root() {
        // #263 (mac/Linux-нога канона, чистая env-машина = мерится на любой
        // ОС): XDG-форма и HOME-дефолт = тот же корень, что файл конфигурации.
        let p = resolve_log_path(lookup(&[("XDG_CONFIG_HOME", "/xdg")]));
        assert_eq!(
            p,
            Some(std::path::PathBuf::from("/xdg/fasad/fasad-tray.log")),
            "XDG задан = сам XDG (без .config), контракт config.rs"
        );
        let p = resolve_log_path(lookup(&[("HOME", "/home/u")]));
        assert_eq!(
            p,
            Some(std::path::PathBuf::from(
                "/home/u/.config/fasad/fasad-tray.log"
            )),
            "HOME-дефолт = .config/fasad"
        );
    }

    #[test]
    fn log_path_explicit_env_wins() {
        // #263-контра: `FASAD_TRAY_LOG` = харнес-оверрайд выигрывает корень
        // (стенд/CI пишут в свой файл, home-каталоги чистого раннера не
        // пачкаются); пустое значение = «не задан» (#219-lookup).
        let p = resolve_log_path(lookup(&[
            ("FASAD_TRAY_LOG", "/tmp/probe/tray.log"),
            ("APPDATA", "C:\\Users\\u\\AppData\\Roaming"),
        ]));
        assert_eq!(p, Some(std::path::PathBuf::from("/tmp/probe/tray.log")));
        let p = resolve_log_path(lookup(&[("FASAD_TRAY_LOG", "   "), ("HOME", "/home/u")]));
        assert_eq!(
            p,
            Some(std::path::PathBuf::from(
                "/home/u/.config/fasad/fasad-tray.log"
            )),
            "пустой FASAD_TRAY_LOG = unset"
        );
    }

    #[test]
    fn log_path_none_without_root() {
        // Ни env-оверрая, ни корня (`APPDATA`/`XDG_CONFIG_HOME`/`HOME`
        // unset/пуст) = писать негде; вызывающий обязан молчать, а не
        // сочинять путь (полка release.md: CI-нога без пользовательского
        // сеанса = ровно эта ветка).
        assert_eq!(resolve_log_path(lookup(&[])), None);
        assert_eq!(resolve_log_path(lookup(&[("APPDATA", "   ")])), None);
        assert_eq!(resolve_log_path(lookup(&[("HOME", "")])), None);
    }

    #[test]
    fn log_line_format_is_ts_space_text_newline() {
        // Контракт формата (grep-читаемость): целые секунды, один пробел,
        // один перевод строки, текст как есть (многострочный текст =
        // многострочная запись — норма, префикс строки только у первой).
        assert_eq!(format_log_line(0, "start"), "0 start\n");
        assert_eq!(format_log_line(1_764_000_000, "x: y"), "1764000000 x: y\n");
        assert_eq!(format_log_line(7, ""), "7 \n");
    }

    /// Уникальный tempdir-каталог (harvest харнес-урока #224: наносекунды
    /// часов не гарантируют уникальность между потоками — гонка-создание
    /// каталога краснеет на коллизии).
    fn unique_log_dir(prefix: &str) -> std::path::PathBuf {
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
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("unique_log_dir({prefix}): {e}"),
            }
        }
        panic!("unique_log_dir: 128 коллизий имени {prefix}");
    }

    #[test]
    fn rotation_keeps_one_previous_layer() {
        // Механика ротации на маленьком пороге: константу 5 МБ в тесте не
        // раздуваем (писать 5 МБ на CI = гонка на диске), порог — параметр
        // `rotate_at`. Сценарий: живой файл >= порога -> переезжает в `.1`,
        // живой освобождается, следующий append = свежий файл; старый `.1`
        // при второй ротации сносится (слой ОДИН, не колонна).
        fn rotate_at(path: &std::path::Path, limit: u64) {
            let big = std::fs::metadata(path).is_ok_and(|md| md.len() >= limit);
            if big {
                let _ = std::fs::remove_file(sibling(path, ".1"));
                std::fs::rename(path, sibling(path, ".1")).unwrap();
            }
        }
        let dir = unique_log_dir("fasad-rot");
        let path = dir.join(LOG_FILE_NAME);
        std::fs::write(&path, b"line-A").unwrap();
        // Порог 4 байта, файл 6 = ротация.
        rotate_at(&path, 4);
        assert!(!path.exists(), "живой файл освобождён");
        assert_eq!(std::fs::read(sibling(&path, ".1")).unwrap(), b"line-A");
        std::fs::write(&path, b"line-B").unwrap();
        rotate_at(&path, 4);
        assert_eq!(
            std::fs::read(sibling(&path, ".1")).unwrap(),
            b"line-B",
            "слой .1 = последний ротированный, НЕ колонна"
        );
        // Мета-контра: порог — живой файл, файл < порога не ротируется.
        rotate_at(&path, 4); // path сейчас не существует = NotFound-норма
        std::fs::write(&path, b"ab").unwrap();
        rotate_at(&path, 100);
        assert!(path.exists(), "файл меньше порога остаётся живым");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_if_needed_reports_disk_errors() {
        // `rotate_if_needed` живого файла с путём-в-никуда = Err (вызывающий
        // обязан пропустить запись, а не затереть append'ом) и NotFound =
        // Ok (CreateNew-норма).
        let missing = std::path::Path::new("C:\\__fasad_none__\\fasad-tray.log");
        assert!(
            rotate_if_needed(missing).is_ok(),
            "нет файла = Ok(нет ротации)"
        );
        let dir = unique_log_dir("fasad-rot-err");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").unwrap();
        // 1 байт << порог 5 МБ = Ok БЕЗ ротации: живой файл цел, `.1` нет
        // (metadata-ветка). Негативных исходов (rename-Err) на tempdir-дереве
        // не вымучиваем (права на CI неизвестны), контракт Err = «диск
        // сломан» = вызывающий (append_log_at `?`) пропускает запись, не
        // затирая живой файл append'ом.
        assert!(rotate_if_needed(&file).is_ok());
        assert!(file.exists(), "файл меньше порога не ротируется");
        assert!(!sibling(&file, ".1").exists(), "слой .1 не создан");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_constants_are_the_readme_contract() {
        // README бандла (#244) дословно называет путь и имя — константы =
        // источник правды; зуб держит их от дрейфа относительно текста.
        assert_eq!(LOG_FILE_NAME, "fasad-tray.log");
        assert_eq!(LOG_ROTATE_BYTES, 5 * 1024 * 1024);
    }

    #[test]
    fn append_log_at_writes_and_rotates_live_file() {
        // Живая нога контура (win-нога CI; tempdir unique = #224-харнес-урок,
        // env-машина не гоняется): append = файл создан + строка; второй
        // append = ДОПИСОК (append-контра, не затирание); путь None =
        // Ok(false) без паники (молчание-норма «писать негде»).
        let dir = unique_log_dir("fasad-append");
        let path = dir.join(LOG_FILE_NAME);
        assert!(append_log_at(Some(&path), "первая").unwrap());
        assert!(append_log_at(Some(&path), "вторая").unwrap());
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "append, не затирание: {body}");
        assert!(lines[0].ends_with(" первая") && lines[1].ends_with(" вторая"));
        assert!(
            !append_log_at(None, "нет пути").unwrap(),
            "None-путь = Ok(false)"
        );
        // Файл меньше порога НЕ ротируется (полоса зубa ротации выше):
        assert!(!sibling(&path, ".1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
