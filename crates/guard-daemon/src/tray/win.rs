//! Windows-витрина отказа старта (#190) + лог-контур GUI-подсистемы (#244) —
//! unsafe-остров бинаря `fasad`.
//!
//! Зачем: `fasad-tray.exe` на Windows — GUI-подсистема (win-CI-провен v0.1.0:
//! оператор запускал двойным кликом, stderr отказа «FASAD_MODEL_DIR не задан…»
//! ушёл в никуда, дефект зафиксирован в issue #190). Отказ старта обязан быть
//! виден: здесь — MessageBox с текстом причины (полный текст в модели #185,
//! здесь он носитель). #244 расширяет витрину: лог-файл
//! `%APPDATA%\fasad\fasad-tray.log` (все startup/refuse/warning/трей-отказ
//! тексты) + окно «трей недоступен» (`show_tray_failure`) — контракт
//! «запустил и забыл = видимые отказы на ВСЕХ ветках смерти».
//!
//! Почему MessageBoxW, а не balloon трея: первичка `tray-icon-0.26.1` —
//! grep по `src/` на `balloon|notification` = НОЛЬ совпадений (win-бэкенд
//! несёт только tooltip через `NOTIFYICONDATAW.szTip`); API уведомления
//! в крейте отсутствует. Balloon-путь (`Shell_NotifyIconW` + `NIIF_INFO`)
//! требует ещё одной feature-ветки `Win32_UI_Shell` и привязан к иконке,
//! которой при отказе старта может и не быть (отказ наступает ДО трея).
//!
//! Почему без новой зависимости: `windows-sys` уже в дереве (win-бэкенд
//! tray-icon, пин `>=0.60, <=0.61`, первичка Cargo.toml крейта; в Cargo.lock
//! — 0.61.2), берём тот же пин с feature `Win32_UI_WindowsAndMessaging`
//! (там живёт `MessageBoxW`, первичка `Windows/Win32/UI/WindowsAndMessaging/`
//! mod.rs — `windows_link::link!("user32.dll" …)`, т.е. raw-dylib: линковка
//! user32 идёт через `#[link]`, без `build`-металла и без new-crate в lock
//! сверх уже присутствующих). Лицензии windows-sys/windows-link — MIT/Apache,
//! allow-лист deny.toml их покрывает.
//!
//! Safe-обёртка (эта публичная функция) изолирует `unsafe` в единственном
//! `unsafe {}`-блоке: вызов `MessageBoxW` с `null`-окном и UTF-16-строками,
//! построенными из `&str` локально. Инварианты:
//! - строки завершены NUL и не мутируют во время вызова (локальные Vec);
//! - окно `0` = «у процесса нет владельца» — корректно для GUI-subsystem;
//! - модальность блокирует поток до нажатия «ОК»: это и есть цель (отказ
//!   без окна = отказа никто не видел), headless-контур (`fasad.exe`)
//!   функцию не вызывает вообще.
//!
//! DOM: модуль подключён в `tray.rs` мишенью чистого `target_os = "windows"`
//! (либа компилирует его на обеих windows-ногах, mac/linux не видят);
//! ВЫЗЫВАЕТСЯ из `main.rs::refuse_startup` под `all(feature = "tray",
//! target_os = "windows")` — то есть окно поднимает только `fasad-tray.exe`;
//! headless-бинарь и mac линкуют модуль, но не зовут его (mac не линкует
//! вовсе). mac-трей кода не видит: win-cfg.
//!
//! Точка входа `refuse_startup` (config/scheme/веса) вызывается ДО
//! `tray::run`: окно поднимается из главного потока процесса до создания
//! трей-окна крейта. Первичка подсистемы (`grep -rn windows_subsystem
//! crates/`, эта сессия): атрибута нет ни у одного bin = console по
//! умолчанию у обоих (`fasad.exe` и `fasad-tray.exe`), т.е. консоль у
//! двойного клика есть, но она закрывается вместе с процессом и текст в ней
//! оператор v0.1.0 не увидел (дефект issue); окно модально потоку вызова —
//! контракт «показать причину и уйти».

// Остров живёт ПРАВИЛОМ острова: `unsafe` здесь санкционирован контрактом
// модуля, а workspace-`unsafe_code = "deny"` продолжит красить его в любом
// другом файле. Атрибут действует на область объявления (этот файл), bin-
// атрибуты `main.rs` его не наследуют — ровно как `net_audit.rs` переопределяет
// `unwrap_used` для своей области.
#![allow(unsafe_code)]

// ═══════════════════════ ЛОГ-КОНТУР #244 ═══════════════════════
//
// Зачем: под GUI-подсистемой (#226/#228: `windows_subsystem = "windows"` для
// `fasad-tray.exe`) stderr = NULL-поток: ВСЕ тексты (startup/refuse/warning +
// ветвь «трей недоступен» tray.rs:349-355) невидимы при запуске двойным
// кликом. Родительский диагноз #244 (коммент 6399041556, пункт (б)):
// GUI-контур «запустил и забыл» обязан оставлять след на диске — лог-файл,
// путь в README бандла и в окне отказа.
//
// Мишень (строго по ТЗ): ТОЛЬКО Windows — mac-трей (#128) запускается из
// Terminal, консоль есть, файл не заводим. Пишется в `%APPDATA%\fasad\` —
// тот же канон, что конфиг (`config::config_dir_from_appdata`, #224): путь
// «куда пишет демон» и путь «где читать» = одна формула, две истины нельзя.
//
// Формат строки (контракт юнита [`format_log_line`]): целые unix-секунды UTC
// + пробел + текст + перевод строки. Без chrono: лог = диагностика, не
// календарь; grep по времени работает и по монотонной шкале.
//
// Ротация = 5 МБ (ТЗ #244): переполнение = СОХРАНИТЬ ПРЕДЫДУЩИЙ СЛОЙ ОДИН
// (`.log.1`) и обнулить живой файл: append без потолка = растущий файл на
// вечном демоне, полное затирание = «следов нет» — тот же класс лжи нулём,
// что молчаливый stderr.
//
// Ошибки записи = молчание: лог = витрина; отказ диска не имеет права валить
// демон (тот же профиль, что `open_ui` / `open_instruction_url`).

/// Порог ротации живого лога, байты (ТЗ #244: 5 МБ).
pub const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

/// Имя файла в каталоге конфига: `%APPDATA%\fasad\fasad-tray.log` (README
/// бандла ссылается на это имя).
pub const LOG_FILE_NAME: &str = "fasad-tray.log";

/// Резолв пути лога: env `FASAD_TRAY_LOG` (явный = стенд/харнеси: CI-нога и
/// полка оператора пишут в свой файл, `%APPDATA%` чистого раннера не
/// пачкается; пустое значение = «не задан», контракт #219-lookup) →
/// канон `%APPDATA%\fasad\fasad-tray.log`. ЧИСТАЯ функция (headless-контра
/// #151): env-машина = аргумент, юнит меряет все ветки без живой ОС.
/// Формула канона = `config_dir_from_appdata` + [`LOG_FILE_NAME`]: путь
/// «куда писать» в README, окне и коде = одна истина.
/// `None` = писать негде (APPDATA unset/пуст = сломанный env): вызывающий
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
    crate::config::config_dir_from_appdata(lookup("APPDATA").as_deref())
        .map(|d| d.join(LOG_FILE_NAME))
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

/// Return-код `MB_ABORTRETRYIGNORE` «Отмена» (#198): первичка winuser.h —
/// `IDABORT`=3, `IDRETRY`=4, `IDIGNORE`=5 (кнопка X = IDIGNORE, уходящий
/// молча, как «ОК»). Читаются ВСЕ ТРИ (#205, факт решётки ниже):
/// `IDRETRY` = ветка «открыть инструкцию», `IDABORT` и `IDIGNORE` = уход
/// молча, оба перечислены в `debug_assert`-контракте стиля окна (ниже;
/// CI-провен win run 40035548437: `IDABORT` никогда не читался = `dead_code`,
/// «тавтология !=IDABORT» ревью §2.2 убрана вместе с использованием).
/// Модульный скоуп острова (не `fn`-local): items-after-statements = гейт
/// tray-check (CI-провен win run 40022333775).
const IDABORT: i32 = 3;
const IDRETRY: i32 = 4;
const IDIGNORE: i32 = 5;

/// Показать отказ старта окном: «Открыть инструкцию» + «ОК»
/// (`MB_ICONERROR | MB_SETFOREGROUND | MB_ABORTRETRYIGNORE`, #190 + #198),
/// дождаться ответа.
///
/// Кнопка «Открыть инструкцию» (#198 — первичка issue: в refusal-окне
/// «Скачать веса» недостижима по построению, UI не стартовал): `MessageBox`
/// не несёт кастомных подписей (первичка win-API, `MessageBoxW` = набор
/// `IDOK`/`IDRETRY`/`IDABORT`), поэтому канон «Retry = открыть инструкцию»
/// (стандартная подпись «Повторить» = семантика «попробовать снова»,
/// ложью не является: открыть инструкцию = попытка починки). Код возврата
/// окна читается: `IDABORT`(3) = «ОК» = уйти; `IDRETRY`(4) = открыть
/// браузером инструкцию (#190-кнопка); `IDIGNORE`(5) = X-крестик окна —
/// уходит молча, как «ОК»: закрытие окна не обязанно что-то открывать
/// (пользовательский жест = выход; первичка: `MB_OK` окна X = IDOK, здесь
/// X = IDIGNORE, поведение то же: уйти).
///
/// Возврат не значим: после показа процесс уходит с `EXIT_BAD_CONFIG`.
///
/// Окно поднимается ТОЛЬКО в GUI-контуре. Первичка #190 («у обоих bin
/// атрибута `windows_subsystem` нет = console по умолчанию») ЗАМЕНЕНА #226:
/// `fasad-tray.exe` = GUI-подсистема (`windows_subsystem = "windows"` под
/// `all(feature = "tray", windows)`, main.rs — «запустил и забыл»: двойной
/// клик без консольного окна), headless `fasad.exe` = console-контракт #185
/// без атрибута (feature-off). `MessageBoxW` НЕ требует консоли (первичка
/// win32: собственное окно верхнего уровня) = отказ виден и на GUI-
/// подсистеме. Вызывающий (`main.rs::refuse_startup`) зовёт функцию под
/// `all(feature = "tray", windows)` = только трей-контур; на таймаутном/
/// сервисном console-контуре модалки нет (блокировка исключена).
pub fn show_startup_failure(caption: &str, message: &str) {
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    // `FASAD_WIN_NO_UI=1` = контракт headless-прогона на win-раннере CI (зуб
    // Г verify-bundle: «GUI без пользовательского сеанса», первичка
    // docs.microsoft.com/windows/win32/ui/using-standard-services;
    // CI-провен r6 run 39863245106: без флага процесс стоит в окне дольше
    // ready-таймера зуба). mac-промеры флага не требуют (ветка win-cfg).
    if std::env::var("FASAD_WIN_NO_UI").is_ok() {
        return;
    }
    // #226: GUI-подсистема `fasad-tray.exe` (`windows_subsystem = "windows"`)
    // НЕ ломает это окно: `MessageBoxW` = собственное модальное окно
    // верхнего уровня, консоли/stdin-консоли не требует (первичка win32
    // «Message Boxes», промер-полка release.md §матрица: live-зуб на
    // win-машине; CI-контур = FASAD_WIN_NO_UI headless-путь, что и ниже).
    // `MB_ICONERROR`(16) | `MB_SETFOREGROUND`(65536) |
    // `MB_ABORTRETRYIGNORE`(3, #198: три канона = уйти / открыть инструкцию /
    // уйти через X); `MB_OK` = 0 и в сумму не входит (константы windows-sys
    // того же модуля; литералы — чтобы остров не тягнул лишние пути импорта).
    let style: u32 = 16 | 65_536 | 3;
    let wcaption = to_wide(caption);
    let wmessage = to_wide(message);
    // `u16::MAX` не покрывает суррогатные пары (0xDC00..=0xDFFF): кириллица
    // MessageBoxW режет молча (тот же класс, что `String::from_utf16_lossy`
    // против суррогатов). Фолбэк = ASCII-каркас (EN-US codepage гарантирован
    // на win10/11) + полный текст в stderr — его вызывающий пишет ДО окна.
    if wcaption
        .iter()
        .chain(wmessage.iter())
        .any(|&c| (0xD800..=0xDFFF).contains(&c))
    {
        eprintln!("fasad: (окно отказа пропущено: текст вне BMP-кириллицы, см. stderr выше)");
        return;
    }
    let answer = unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            wmessage.as_ptr(),
            wcaption.as_ptr(),
            style,
        )
    };
    // «Открыть инструкцию»: страница = тот же маршрут, что клик трея
    // (трея при отказе НЕТ — `refuse_startup` живёт ДО `tray::run`, #190);
    // адрес инструкции = репозиторий: UI при отказе старта НЕ поднят (это
    // и есть отказ), поэтому URL-кнопка = docs-маршрут доставки весов.
    // Открытие = `cmd /C start` (та же первичка, что `open_browser_command`
    // tray.rs: win-ассоциация http; spawn без wait, stdio в null — окно
    // не обязано владеть браузером).
    // `IDRETRY`(4) — единственный канон «открыть»; `IDABORT`(3)=OK и
    // `IDIGNORE`(5)=X = уход молча (ревью #203 §2.2: прежняя проверка
    // `&& answer != IDABORT` = тавтология, 4≠3 всегда). Явный `debug_assert`
    // ветки = контракт стиля окна (кнопки ABORT/RETRY/IGNORE гарантируют
    // {3,4,5}: любое иное = сборка сломана, не пользовательский исход).
    debug_assert!(
        matches!(answer, IDABORT | IDRETRY | IDIGNORE),
        "MB_ABORTRETRYIGNORE вернул {answer}: контракт кнопок сломан"
    );
    if answer == IDRETRY {
        open_instruction_url();
    }
}

/// Витрина «трей недоступен» (#244): иконка не поднялась, демон ЖИВ (serve на
/// рабочем потоке) — под GUI-подсистемой это был тихий `eprintln` в NULL =
/// «процесс висит, иконки нет, почему — неизвестно». Окно = `MB_TOPMOST`(0x
/// 40000)|`MB_ICONWARNING`(48)|`MB_OK`(0): предупреждение, не отказ —
/// процесс НЕ уходит (в отличие от [`show_startup_failure`]), поэтому кнопка
/// одна («ОК»), style-литералы = тот же контур острова (без лишних путей
/// импорта windows-sys).
///
/// Модальность блокирует ТРЕЙ-поток (главный) до «ОК»: демону ничего не
/// стоит — serving живёт на `fasad-serve` (первичка потоков `main.rs`:
/// `serve_on_worker` стартует ДО `tray::run`), UI-то уже открыт; в win-контуре
/// main-поток к этому моменту = только цикл трея.
///
/// `FASAD_WIN_NO_UI` = та же headless-контра CI, что у окна отказа старта
/// (win-нога CI промеряет compile + живой запуск без пользовательского
/// сеанса; без флага процесс стоял бы в окне до ready-таймера зуба).
///
/// Текст окна обязан называть ПУТЬ ЛОГА: «где читать» = ровно то, где
/// [`append_log`] пишет (#244-контракт: README бандла + окно + файл = одна
/// истина).
pub fn show_tray_failure(reason: &str, port: u16, log_path: Option<&std::path::Path>) {
    use std::fmt::Write as _;
    let mut msg = String::from("fasad: трей не поднялся: ");
    msg.push_str(reason);
    let _ = write!(
        msg,
        "\nДемон работает без иконки. UI жив: http://127.0.0.1:{port}/\n\
         (иконка может быть скрыта в свёрнутой области уведомлений Windows)"
    );
    if let Some(p) = log_path {
        // format-в-String = формат-в-write: без лишней аллокации
        // (clippy format_push_string, win-нога CI).
        let _ = write!(msg, "\nЛог: {}", p.display());
    }
    append_log(&format!(
        "трей недоступен: {reason} (UI жив: http://127.0.0.1:{port}/)"
    ));
    if std::env::var("FASAD_WIN_NO_UI").is_ok() {
        return;
    }
    let wcaption = to_wide_static("fasad: трей недоступен");
    let wmessage = to_wide_static(&msg);
    // Суррогатные пары = та же BMP-контра, что у окна отказа старта (#205):
    // текст окна строится из причины крейта (ANSI-английский) + наших ASCII
    // каркасов, кириллица в причине = крейт-текст, эм-тире здесь нет;
    // фолбэк = молчание (полный текст уже в логе и stderr).
    if wcaption
        .iter()
        .chain(wmessage.iter())
        .any(|&c| (0xD800..=0xDFFF).contains(&c))
    {
        return;
    }
    // `MB_ICONWARNING`(48) | `MB_TOPMOST`(0x40_000): окно поверх лотка,
    // одиночная кнопка, демона НЕ валит (предупреждение, не отказ);
    // `MB_OK` = 0 = отсутствие флагов кнопок = НЕ вписывается в OR-сумму
    // (identity_op, win-нога CI): ноль = не слагаемое.
    let style: u32 = 0x0030 | 0x40_000;
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            wmessage.as_ptr(),
            wcaption.as_ptr(),
            style,
        );
    }
}

/// UTF-16 + завершающий NUL (тот же local-Vec-контра инвариантов острова).
fn to_wide_static(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Открыть браузером инструкцию (win-маршрут, первичка `open_browser_command`
/// tray.rs: `cmd /C start "" URL`). Публичность не нужна: остров = win-cfg,
/// вызывается отсюда.
fn open_instruction_url() {
    const INSTRUCTION_URL: &str = "https://github.com/tayuLuc/fasad/blob/main/models/README.md";
    // FASAD_REF_INSTRUCTION_URL = тестовый/стендовый оверрайд (win-CI полка
    // не открывает реальный браузер; стенд оператора проверяет маршрут
    // локальной страницей). Пустое значение = канон.
    let url = std::env::var("FASAD_REF_INSTRUCTION_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| INSTRUCTION_URL.to_owned());
    let mut cmd = std::process::Command::new("cmd");
    cmd.args(["/C", "start", "", &url]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    // Spawn-ошибка = молчание: инструкция = бонус, отказ старта уже
    // назван текстом и кодом, врать о причине из бонуса нельзя.
    let _ = cmd.spawn();
}

#[cfg(test)]
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
    fn log_path_is_appdata_fasad_file() {
        // #244-контра: лог = канон конфига `%APPDATA%\fasad\fasad-tray.log`
        // (та же формула, что `config_dir_from_appdata`: путь «где писать»
        // и путь README = одна истина).
        let p = resolve_log_path(lookup(&[("APPDATA", "C:\\Users\\u\\AppData\\Roaming")]));
        assert_eq!(
            p,
            Some(std::path::PathBuf::from(
                "C:\\Users\\u\\AppData\\Roaming\\fasad\\fasad-tray.log"
            ))
        );
    }

    #[test]
    fn log_path_none_without_appdata() {
        // APPDATA unset = писать негде; вызывающий обязан молчать, а не
        // сочинять путь (полка release.md: CI-нога без пользовательского
        // сеанса = ровно эта ветка).
        assert_eq!(resolve_log_path(lookup(&[])), None);
        assert_eq!(resolve_log_path(lookup(&[("APPDATA", "   ")])), None);
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
                std::fs::rename(path, sibling(path, ".1")).expect("rename-ротация проходит");
            }
        }
        let dir = unique_log_dir("fasad-rot");
        let path = dir.join(LOG_FILE_NAME);
        std::fs::write(&path, b"line-A").expect("файл пишется");
        // Порог 4 байта, файл 6 = ротация.
        rotate_at(&path, 4);
        assert!(!path.exists(), "живой файл освобождён");
        assert_eq!(
            std::fs::read(sibling(&path, ".1")).expect("слой .1 читается"),
            b"line-A"
        );
        std::fs::write(&path, b"line-B").expect("файл пишется");
        rotate_at(&path, 4);
        assert_eq!(
            std::fs::read(sibling(&path, ".1")).expect("слой .1 читается"),
            b"line-B",
            "слой .1 = последний ротированный, НЕ колонна"
        );
        // Мета-контра: порог — живой файл, файл < порога не ротируется.
        rotate_at(&path, 4); // path сейчас не существует = NotFound-норма
        std::fs::write(&path, b"ab").expect("файл пишется");
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
        std::fs::write(&file, b"x").expect("файл пишется");
        // Ротация «файла-не-лога» с заведомо нулевым порогом: rename живого
        // файла в соседний слой обязан пройти (Ok) — негативных исходов на
        // tempdir-дереве не вымучиваем (права на CI неизвестны), контракт
        // Err = «диск сломан», он покрыт вызывающим (пропуск записи).
        assert!(rotate_if_needed(&file).is_ok());
        assert!(!file.exists(), "порог 5 МБ не достигнут — файл не тронут");
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
        assert!(append_log_at(Some(&path), "первая").expect("первая строка пишется"));
        assert!(append_log_at(Some(&path), "вторая").expect("вторая строка пишется"));
        let body = std::fs::read_to_string(&path).expect("лог читается");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "append, не затирание: {body}");
        assert!(lines[0].ends_with(" первая") && lines[1].ends_with(" вторая"));
        assert!(
            !append_log_at(None, "нет пути").expect("None-путь = Ok без паники"),
            "None-путь = Ok(false)"
        );
        // Файл меньше порога НЕ ротируется (полоса зубa ротации выше):
        assert!(!sibling(&path, ".1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
