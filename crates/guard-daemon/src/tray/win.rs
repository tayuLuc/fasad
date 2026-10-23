//! Windows-витрина отказа старта (#190) — unsafe-остров бинаря `fasad`.
//!
//! Зачем: `fasad-tray.exe` на Windows — GUI-подсистема (win-CI-провен v0.1.0:
//! оператор запускал двойным кликом, stderr отказа «FASAD_MODEL_DIR не задан…»
//! ушёл в никуда, дефект зафиксирован в issue #190). Отказ старта обязан быть
//! виден: здесь — MessageBox с текстом причины (полный текст в модели #185,
//! здесь он носитель).
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
/// молча, как «ОК»). Используется ОБА: `IDRETRY` = ветка «открыть
/// инструкцию», `IDABORT` = явная проверка «ухода по кнопке ОК» (ниже,
/// `debug_assert` ветки = контракт против смены стиля окна; CI-провен win run
/// 40035548437: `IDABORT` никогда не читался = `dead_code`, «тавтология
/// !=IDABORT» ревью §2.2 убрана вместе с использованием).
/// Модульный скоуп острова (не `fn`-local): items-after-statements = гейт
/// tray-check (CI-провен win run 40022333775).
const IDABORT: i32 = 3;
const IDRETRY: i32 = 4;

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
/// Окно поднимается ТОЛЬКО в GUI-контуре (решение #190 по первичке
/// подсистемы): у обоих bin атрибута `windows_subsystem` нет = console по
/// умолчанию (grep `crates/` = 0, промер этой сессии), т.е. у любого bin,
/// запущенного из cmd/PowerShell,stderr виден оператору, а модалка на
/// таймаутном/сервисном контуре = блокировка. Консоль закрывается вместе с
/// процессом двойного клика — это ровно тот случай, для которого окно:
/// вызывающий (`main.rs::refuse_startup`) зовёт функцию под
/// `all(feature = "tray", windows)` = только `fasad-tray.exe`.
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
        matches!(answer, IDABORT | IDRETRY | 5),
        "MB_ABORTRETRYIGNORE вернул {answer}: контракт кнопок сломан"
    );
    if answer == IDRETRY {
        open_instruction_url();
    }
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
