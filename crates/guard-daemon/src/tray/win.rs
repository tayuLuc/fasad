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

/// Показать отказ старта окном (`MB_ICONERROR | MB_SETFOREGROUND`), дождаться «ОК».
///
/// Возврат не значим: после показа процесс уходит с `EXIT_BAD_CONFIG`.
pub fn show_startup_failure(caption: &str, message: &str) {
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
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
    // `MB_ICONERROR`(16) | `MB_SETFOREGROUND`(65536); `MB_OK` = 0 и в сумму
    // не входит (константы windows-sys того же модуля; литералы — чтобы
    // остров не тягнул лишние пути импорта).
    let style: u32 = 16 | 65_536;
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            wmessage.as_ptr(),
            wcaption.as_ptr(),
            style,
        );
    }
}
