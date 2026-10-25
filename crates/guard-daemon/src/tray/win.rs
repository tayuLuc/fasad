//! Windows-витрина отказа старта (#190, MessageBox-окна) — unsafe-остров
//! бинаря `fasad`. Лог-контур #244 (файл следа) с #263 живёт ОС-НЕЗАВИСИМО в
//! [`super::traylog`] (механика = чистый std, win-cfg-остров его не требовал;
//! win-формула канона `%APPDATA%\fasad\fasad-tray.log` интактна через общий
//! config-root).
//!
//! Зачем: `fasad-tray.exe` на Windows — GUI-подсистема (win-CI-провен v0.1.0:
//! оператор запускал двойным кликом, stderr отказа «FASAD_MODEL_DIR не задан…»
//! ушёл в никуда, дефект зафиксирован в issue #190). Отказ старта обязан быть
//! виден: здесь — MessageBox с текстом причины (полный текст в модели #185,
//! здесь он носитель). #244 расширил витрину: лог-файл следа (все
//! startup/refuse/warning/трей-отказ тексты, путь = config-root) + окно
//! «трей недоступен» (`show_tray_failure`) — контракт «запустил и забыл =
//! видимые отказы на ВСЕХ ветках смерти».
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
/// [`traylog::append_log`](super::traylog::append_log) пишет (#244-контракт:
/// README бандла + окно + файл = одна истина).
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
    crate::tray::traylog::append_log(&format!(
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
