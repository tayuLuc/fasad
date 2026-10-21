//! Иконка трея для Windows и macOS (#128 фаза 2, решение оператора в комментарии
//! к issue: «Linux-сервер = systemd-юнит (консольный демон, без трея), Windows и
//! macOS = трей (иконка статуса)»).
//!
//! # Границы модуля
//!
//! - **Только под фичей `tray` и только под win/mac** (cfg здесь же). На linux
//!   фича физически недоступна: `tray-icon` с `default-features = false` красит
//!   `compile_error` под linux-таргетом (`tray-icon-0.26.1/src/lib.rs:128-138`,
//!   первичка docs/dep-verify-crates.md §16, промер этой сессии на
//!   `--target x86_64-unknown-linux-gnu`) — легальной headless-сборки трея на
//!   linux нет ни одной фичей, поэтому здесь нет и linux-ветки.
//! - **Никакой сети.** Клик открывает песочницу `/ui` средствами ОС
//!   (`/usr/bin/open` на macOS, `cmd /C start` на Windows —
//!   [`std::process::Command`], без крейта-обёртки: `open`-крейт не промерен
//!   (§16 объём), per-OS вызов = три строки). Демон ни к кому не соединяется;
//!   единственный исходящий путь остаётся `proxy.rs` — гейт `net_audit`
//!   сканирует `src/` целиком и держит эту стену.
//! - **Никаких `ПДн` в подписях.** Подсказка (`tooltip`) и заголовок несут только метрики
//!   (тот же профиль, что `/health`: стадия, порт, счётчики деградации).
//!
//! # Нити (первичка docs крейта)
//!
//! `tray-icon` (lib.rs, «Platform-specific notes»): «On macOS, an event loop
//! must be running on the main thread so you also need to create the tray icon
//! on the main thread»; `muda` (lib.rs): «On macOS, menus can only be used from
//! the main thread, and most functionality will panic if you try to use it from
//! any other thread». Поэтому [`run`] вызывается **из главного потока**
//! процесса, а tokio-serving уезжает на рабочий поток (`main.rs`, ветка фичи).
//! Цикл событий ([`poll_once`]) будится каналами крейта
//! (`TrayIconEvent::receiver`, `MenuEvent::receiver`) и таймером — поллинга
//! CPU нет.
//!
//! # Выход
//!
//! Канала «сигнал → демон» headless-контур не имел (первичка main.rs: serving
//! = бесконечный `axum::serve`), поэтому трей вводит [`Shutdown`] — общий флаг
//! атомик: Quit из меню ставит его, цикл главного потока на нём выходит,
//! serve-контур на нём завершается (`with_graceful_shutdown`). Сигналы ОС
//! трогать нечем: на win/mac-сценарии systemd нет, headless-ветка не тронута.

#![cfg(all(feature = "tray", any(target_os = "windows", target_os = "macos")))]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::http::Inner;

/// Период цикла трея, сек: с таким шагом просыпается обновление tooltip, и с
/// таким же таймаутом читаются каналы (событие будит раньше шага).
const TICK_SECS: u64 = 2;

/// GUID иконки в реестре Windows (win-ветка крейта регистрирует иконку по
/// GUID'у, `NIF_GUID`; смена ключа = осиротевшая иконка в лотке после
/// апгрейда). Число случайное, зафиксировано навечно.
pub const TRAY_GUID: u128 = 0x0f5a_d17e_5f72_4b1f_9a44_c3d2_8e01_7002;

/// Меню-пункт «Открыть fasad UI»: id, по которому цикл различает пункты.
pub const MENU_ID_OPEN: &str = "open-ui";

/// Иконка «всё чисто»: отказов хранилища нет.
pub const ICON_STATE_OK: u8 = 0;

/// Иконка «есть отказы»: хоть один счётчик деградации nonzero.
pub const ICON_STATE_ALARM: u8 = 1;

/// Контур клика: адрес песочницы — только loopback, только собственный порт.
///
/// Строка отделена от запуска, чтобы тестируемой была инвариантная часть
/// (§1 п.6: бинд loopback — то и открывается).
#[must_use]
pub fn ui_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/ui")
}

/// Команда «открыть URL в браузере по умолчанию» для текущей ОС.
///
/// Строит [`std::process::Command`], но НЕ запускает: построение — тестируемый
/// факт (юнит сверяет программу и аргументы), spawn живого браузера —
/// `#[ignore]`-интеграл (требует GUI-сессии).
///
/// Выбор бинаря — первичка платформы, не конвенция:
///
/// 1. macOS: `/usr/bin/open` (абсолютный путь: PATH процесса не наследует
///    shell-окружение оператора).
/// 2. Windows: `cmd /C start "" <url>` — пустой аргумент обязателен: `start`
///    без заголовка принимает следующий аргумент как заголовок окна, и адрес
///    уезжает в заголовок вместо браузера.
/// 3. Прочее: `xdg-open` — linux-сборка под этим cfg в дереве не бывает
///    (`compile_error` крейта, док модуля); ветка — для полноты функции и
///    тестов на хостах вне win/mac.
#[must_use]
pub fn open_browser_command(url: &str) -> std::process::Command {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut cmd = std::process::Command::new("/usr/bin/open");
        cmd.arg(url);
        cmd
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "start", "", url]);
        cmd
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut cmd = std::process::Command::new("xdg-open");
        cmd.arg(url);
        cmd
    };
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd
}

/// Логика «какой клик открывает UI», вынесенная из обработчика событий.
///
/// Левый клик (кнопка **отпущена** = завершённый клик) открывает песочницу;
/// правый открывает контекстное меню средствами ОС (`.with_menu`), нажатие без
/// отпускания — не клик.
#[must_use]
pub fn click_opens_ui(button: tray_icon::MouseButton, state: tray_icon::MouseButtonState) -> bool {
    button == tray_icon::MouseButton::Left && state == tray_icon::MouseButtonState::Up
}

/// Процедурная иконка 32×32 (32bpp RGBA — формат `Icon::from_rgba`, первичка
/// `tray-icon-0.26.1/src/icon.rs`).
///
/// PNG-ассет не тащим: `from_rgba` закрывает задачу без новой поверхности
/// путей в бандле. Форма — квадрат со скруглением и «гард-точкой» в центре;
/// палитра семантическая: [`ICON_STATE_OK`] — зелёный (отказов нет),
/// [`ICON_STATE_ALARM`] — янтарный (fail-closed видно цветом, не только
/// tooltip'ом).
#[must_use]
pub fn status_rgba(state: u8) -> Vec<u8> {
    const S: usize = 32;
    let (r, g, b) = if state == ICON_STATE_ALARM {
        (196, 128, 0)
    } else {
        (38, 139, 58)
    };
    let mut rgba = vec![0u8; S * S * 4];
    // Геометрия — целочисленная (удвоенные координаты: полу-пиксельный центр
    // 31 = 2·15.5, радиусы ×2): f32-каст из usize = cast_precision_loss, а
    // пиксельной сетке 32×32 точность целых чисел с запасом.
    for y in 0..S {
        for x in 0..S {
            // `i32::try_from` — не косметика: счётчик `0..S` это `usize`, а
            // арифметика центра (`−31`) обязана быть знаковой; на 32-битных
            // мишенях `usize`-вычитание = переполнение (debug — паника,
            // release — обёртка). i32 покрывает удвоенную сетку 32×32 с запасом.
            let cx = i32::try_from(2 * x + 1).unwrap_or(i32::MAX) - 31;
            let cy = i32::try_from(2 * y + 1).unwrap_or(i32::MAX) - 31;
            // Квадрат со скруглением 7 px (SDF: удвоенная сетка, край = 30,
            // corner-круг 14 ⇒ 30−14 = 16; `.max(0)` = «внутри полосы — 0»).
            let dx = (cx.abs() - 16).max(0);
            let dy = (cy.abs() - 16).max(0);
            let in_body = dx * dx + dy * dy <= 196; // (2·7)²
            let d2 = cx * cx + cy * cy;
            let px = if !in_body {
                [0, 0, 0, 0] // угол за скруглением: прозрачно (нет чёрной рамки)
            } else if d2 <= 900 {
                [r, g, b, 255] // тело статуса: радиус 15 px ⇒ (2d)² ≤ 30²
            } else {
                [0, 0, 0, 0] // между телом и краем: прозрачно
            };
            let at = (y * S + x) * 4;
            rgba[at..at + 4].copy_from_slice(&px);
        }
    }
    // Ядро-«гард»: белый диск поверх тела (после тела, порядок важен):
    // радиус 5.5 px ⇒ (2d)² ≤ 11².
    for y in 0..S {
        for x in 0..S {
            let cx = i32::try_from(2 * x + 1).unwrap_or(i32::MAX) - 31;
            let cy = i32::try_from(2 * y + 1).unwrap_or(i32::MAX) - 31;
            if cx * cx + cy * cy <= 121 {
                let at = (y * S + x) * 4;
                rgba[at..at + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
    }
    rgba
}

/// Состояние, которое трей показывает наружу: числа, не тексты запросов.
///
/// Те же метрики, что отдаёт `/health` (`http::HealthReply`): стадия, порт,
/// счётчики деградации хранилища. Ни имени, ни строки запроса, ни маркера `ПДн`
/// здесь быть не может по типу поля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInfo {
    /// Собранный контур (`"cascade-0-only"` / `"cascade-0+models"`).
    pub stage: &'static str,
    /// Порт, на котором демон реально слушает loopback.
    pub port: u16,
    /// Отказы `mlock`/`VirtualLock` (fail-closed: 503 на входе).
    pub lock_failures: u64,
    /// Отказы по исчерпанию залоченного пула.
    pub busy_rejects: u64,
    /// Суррогатные подмены (ФИО → метка при занятом слоте).
    pub surrogate_fallbacks: u64,
    /// Отказы разворота по расхождению с реверс-индексом.
    pub unrestored_mismatch: u64,
}

impl StatusInfo {
    /// Снимок с живых счётчиков: vault-метрики — у хранилища и у пула
    /// залоченной памяти, остальное — статика старта.
    #[must_use]
    pub fn snapshot(vault: &Arc<Inner>, stage: &'static str, port: u16) -> Self {
        let pool = guard_vault::token::pool_state();
        Self {
            stage,
            port,
            lock_failures: pool.lock_failures,
            busy_rejects: pool.busy_rejects,
            surrogate_fallbacks: vault.vault().surrogate_fallbacks(),
            unrestored_mismatch: vault.vault().unrestored_mismatch(),
        }
    }

    /// Копка отказов = сумма четырёх счётчиков (saturating: переполнение
    /// счётчика не имеет права обнулить сигнал).
    #[must_use]
    pub fn failures(&self) -> u64 {
        self.lock_failures
            .saturating_add(self.busy_rejects)
            .saturating_add(self.surrogate_fallbacks)
            .saturating_add(self.unrestored_mismatch)
    }

    /// Строка tooltip: `fasad: <счётчик отказов> / <stage>` — контракт
    /// оператора (комментарий к #128). Формат зафиксирован юнитом: это
    /// контракт видимости деградации, а не косметика.
    #[must_use]
    pub fn tooltip(&self) -> String {
        format!("fasad: {} / {}", self.failures(), self.stage)
    }

    /// Заголовок иконки: только порт (`:8765`). В win-трее заголовок печатается
    /// у иконки; на macOS пустой заголовок экономит место меню-бара — поэтому
    /// короткая строка, а не слово.
    #[must_use]
    pub fn title(&self) -> String {
        format!(":{}", self.port)
    }

    /// Вердикт для цвета иконки.
    #[must_use]
    pub fn icon_state(&self) -> u8 {
        if self.failures() == 0 {
            ICON_STATE_OK
        } else {
            ICON_STATE_ALARM
        }
    }
}

/// Запрос graceful shutdown от трея (Quit из меню).
///
/// Headless-контур канала выхода не имел; трей вводит флаг атомик как
/// единственный общий сигнал: цикл главного потока на нём выходит, serve-контур
/// на нём завершается (graceful — активные соединения дозаписывают ответ,
/// `axum::serve::with_graceful_shutdown`). Сигналы ОС контур не трогает: на
/// win/mac-сценарии трея systemd нет, linux живёт под systemd (`kill` — процессу
/// целиком, #140).
#[derive(Debug, Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    /// Новый сигнал: флаг опущен = «живём».
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Поднять флаг (quit). Идемпотентно.
    pub fn trigger(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Поднят ли флаг.
    #[must_use]
    pub fn triggered(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Клон флага — для цикла, которому нужен `Send`-доступ.
    #[must_use]
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }
}

/// Копка открытий UI по клику — метрика диагностики (в tooltip её нет: там
/// счётчики отказов).
pub static OPEN_CLICKS: AtomicU64 = AtomicU64::new(0);

/// Запуск трея из **главного потока** (требование крейта — док модуля).
///
/// Цикл не возвращает управление, пока демон жив; Quit ставит `shutdown` и
/// цикл выходит (иконка снимается `Drop`'ом: macOS `removeStatusItem`, Windows
/// `NIM_DELETE` — первичка `platform_impl`).
///
/// Отказ поднять иконку НЕ валит демон: трей = витрина, HTTP-контур = продукт
/// (fail-closed относится к запросам). Причина — в stderr (текст ошибки
/// крейта; `ПДн` в нём быть не может); serve на рабочем потоке жив, процесс ждёт
/// сигнала выхода, как ждал бы цикла.
pub fn run(vault: &Arc<Inner>, stage: &'static str, port: u16, shutdown: &Shutdown) {
    let icon = match build_tray(vault, stage, port) {
        Ok(icon) => icon,
        Err(e) => {
            eprintln!("fasad: трей недоступен: {e} (демон работает без иконки)");
            park_forever(&shutdown.flag());
            return;
        }
    };
    let mut last_tick = Instant::now();
    loop {
        if !poll_once(vault, stage, port, shutdown, &icon, &mut last_tick) {
            break;
        }
        if shutdown.triggered() {
            break;
        }
    }
    drop(icon);
}

/// Один шаг цикла событий: прочитать каналы с таймаутом [`TICK_SECS`] и
/// обновить подпись по шагу. Возвращает `false`, если канал событий закрыт
/// (процесс уходит, цикл не нужен) — вызывающий завершает [`run`].
pub fn poll_once(
    vault: &Arc<Inner>,
    stage: &'static str,
    port: u16,
    shutdown: &Shutdown,
    icon: &TrayIcon,
    last_tick: &mut Instant,
) -> bool {
    match TrayIconEvent::receiver().recv_timeout(Duration::from_secs(TICK_SECS)) {
        Ok(TrayIconEvent::Click {
            button,
            button_state,
            ..
        }) => {
            if click_opens_ui(button, button_state) {
                open_ui(port);
            }
        }
        // Двойной клик = тот же смысл, что одинарный (win; на mac id общий).
        Ok(TrayIconEvent::DoubleClick { .. }) => open_ui(port),
        // Enter/Move/Leave — не пользовательские намерения.
        Ok(_) => {}
        // Таймаут = «тик прошёл, событий не было» — норма. Закрытый канал =
        // процесс уходит: цикл сворачивается, а не паникует.
        Err(err) => {
            if err.is_disconnected() {
                return false;
            }
        }
    }
    while let Ok(ev) = MenuEvent::receiver().try_recv() {
        if ev.id.as_ref() == MENU_ID_OPEN {
            open_ui(port);
        } else {
            // Единственный иной активный пункт — Quit.
            shutdown.trigger();
        }
    }
    if last_tick.elapsed() >= Duration::from_secs(TICK_SECS) {
        *last_tick = Instant::now();
        refresh_icon(vault, stage, port, icon);
    }
    true
}

/// Поднять иконку, контекстное меню и подписать tooltip/заголовок.
fn build_tray(
    vault: &Arc<Inner>,
    stage: &'static str,
    port: u16,
) -> Result<TrayIcon, Box<dyn std::error::Error + Send + Sync>> {
    let status = StatusInfo::snapshot(vault, stage, port);
    let icon = Icon::from_rgba(status_rgba(status.icon_state()), 32, 32)?;
    let menu = Menu::new();
    menu.append_items(&[
        &MenuItem::with_id(MENU_ID_OPEN, "Открыть fasad UI", true, None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::quit(Some("Выход (graceful)")),
    ])?;
    let tray = TrayIconBuilder::new()
        .with_id(tray_icon::TrayIconId::new("fasad"))
        .with_guid(TRAY_GUID)
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_tooltip(status.tooltip())
        .with_title(status.title())
        .build()?;
    Ok(tray)
}

/// Переснять метрики и обновить иконку/tooltip/заголовок.
///
/// Ошибки крейта (ОС отозвала слот) игнорируются намеренно: cosmetic-канал,
/// продукт на него не завязан; события продолжают приходить.
fn refresh_icon(vault: &Arc<Inner>, stage: &'static str, port: u16, icon: &TrayIcon) {
    let status = StatusInfo::snapshot(vault, stage, port);
    let _ = icon.set_tooltip(Some(status.tooltip()));
    icon.set_title(Some(status.title()));
    if let Ok(rgba) = Icon::from_rgba(status_rgba(status.icon_state()), 32, 32) {
        let _ = icon.set_icon(Some(rgba));
    }
}

/// Открыть песочницу в браузере по умолчанию.
fn open_ui(port: u16) {
    let url = ui_url(port);
    OPEN_CLICKS.fetch_add(1, Ordering::Relaxed);
    let mut cmd = open_browser_command(&url);
    // Браузер не поднялся (headless-сессия) — причина в stderr, трей жив:
    // витрина не имеет права валить продукт.
    if let Err(e) = cmd.spawn() {
        eprintln!("fasad: не удалось открыть {url}: {e}");
    }
}

/// Ждать флаг выхода в главном потоке (путь «иконка не поднялась»).
fn park_forever(flag: &Arc<AtomicBool>) {
    while !flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(failures: u64) -> StatusInfo {
        StatusInfo {
            stage: "cascade-0-only",
            port: 8765,
            lock_failures: failures,
            busy_rejects: 0,
            surrogate_fallbacks: 0,
            unrestored_mismatch: 0,
        }
    }

    #[test]
    fn tooltip_is_failures_slash_stage() {
        assert_eq!(status(0).tooltip(), "fasad: 0 / cascade-0-only");
        assert_eq!(status(7).tooltip(), "fasad: 7 / cascade-0-only");
    }

    #[test]
    fn tooltip_sums_all_four_counters() {
        let st = StatusInfo {
            lock_failures: 1,
            busy_rejects: 2,
            surrogate_fallbacks: 3,
            unrestored_mismatch: 4,
            ..status(0)
        };
        assert_eq!(st.tooltip(), "fasad: 10 / cascade-0-only");
    }

    #[test]
    fn tooltip_carries_no_pii_and_exactly_one_slash() {
        // Контракт оператора «без ПДн» (комментарий к #128): формат строки
        // допускает только префикс, число, слэш, стадию. Проверка — по
        // конструкции: слэш ровно один, в хвосте (стадия) нет ни `@`, ни
        // адреса, ни пути.
        let t = status(3).tooltip();
        assert!(t.starts_with("fasad: ") && t.contains(" / "));
        assert_eq!(t.matches('/').count(), 1, "ровно один слэш: {t}");
        let tail = t.rsplit(" / ").next().unwrap_or_default();
        for banned in ["@", "http", "\\", ":", " ", "."] {
            assert!(!tail.contains(banned), "стадия содержит {banned:?}: {tail}");
        }
    }

    #[test]
    fn failures_saturate_and_never_wrap_to_zero() {
        let st = StatusInfo {
            lock_failures: u64::MAX,
            busy_rejects: u64::MAX,
            surrogate_fallbacks: u64::MAX,
            unrestored_mismatch: u64::MAX,
            ..status(0)
        };
        assert_eq!(st.failures(), u64::MAX);
        assert_eq!(st.icon_state(), ICON_STATE_ALARM);
    }

    #[test]
    fn icon_state_switches_on_any_failure() {
        assert_eq!(status(0).icon_state(), ICON_STATE_OK);
        let alarm = StatusInfo {
            surrogate_fallbacks: 1,
            ..status(0)
        };
        assert_eq!(alarm.icon_state(), ICON_STATE_ALARM);
    }

    #[test]
    fn title_carries_port_only() {
        assert_eq!(status(0).title(), ":8765");
    }

    #[test]
    fn rgba_is_32x32_with_transparent_corners_and_opaque_core() {
        let rgba = status_rgba(ICON_STATE_OK);
        assert_eq!(rgba.len(), 32 * 32 * 4, "32bpp RGBA для Icon::from_rgba");
        let px = |x: usize, y: usize| &rgba[(y * 32 + x) * 4..(y * 32 + x) * 4 + 4];
        assert_eq!(px(0, 0)[3], 0, "угол за скруглением прозрачен");
        assert_eq!(px(16, 16)[3], 255, "центр непрозрачен");
        assert_eq!(px(16, 16)[0], 255, "ядро белое");
        assert_eq!(px(16, 16)[1], 255);
        assert_eq!(px(16, 16)[2], 255);
        // Тело (не центр, не угол): непрозрачно и не белое — это цвет статуса.
        assert_eq!(px(28, 16)[3], 255);
        assert_ne!(px(28, 16)[0], 255, "окружение ядра = цвет статуса");
    }

    #[test]
    fn icon_state_changes_the_body_color() {
        let calm = status_rgba(ICON_STATE_OK);
        let alarm = status_rgba(ICON_STATE_ALARM);
        assert_ne!(
            &calm[(16 * 32 + 28) * 4..(16 * 32 + 28) * 4 + 3],
            &alarm[(16 * 32 + 28) * 4..(16 * 32 + 28) * 4 + 3],
            "зелёный и янтарный различимы"
        );
    }

    #[test]
    fn ui_url_is_loopback_with_own_port() {
        assert_eq!(ui_url(8765), "http://127.0.0.1:8765/ui");
        assert_eq!(ui_url(9001), "http://127.0.0.1:9001/ui");
    }

    #[test]
    fn open_command_is_per_os_and_carries_the_loopback_url() {
        let cmd = open_browser_command("http://127.0.0.1:8765/ui");
        let prog = cmd.get_program().to_string_lossy().into_owned();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        #[cfg(target_os = "macos")]
        {
            assert_eq!(prog, "/usr/bin/open");
            assert_eq!(args, ["http://127.0.0.1:8765/ui"]);
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(prog, "cmd");
            assert_eq!(args[0], "/C");
            assert_eq!(args[1], "start");
            assert_eq!(
                args[2], "",
                "пустой заголовок обязателен: start съедает следующий аргумент как заголовок"
            );
            assert_eq!(args[3], "http://127.0.0.1:8765/ui");
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            assert_eq!(prog, "xdg-open");
            assert_eq!(args, ["http://127.0.0.1:8765/ui"]);
        }
    }

    #[test]
    fn click_semantics_only_left_release_opens() {
        assert!(click_opens_ui(
            tray_icon::MouseButton::Left,
            tray_icon::MouseButtonState::Up
        ));
        assert!(!click_opens_ui(
            tray_icon::MouseButton::Left,
            tray_icon::MouseButtonState::Down
        ));
        assert!(!click_opens_ui(
            tray_icon::MouseButton::Right,
            tray_icon::MouseButtonState::Up
        ));
        assert!(!click_opens_ui(
            tray_icon::MouseButton::Middle,
            tray_icon::MouseButtonState::Up
        ));
    }

    #[test]
    fn shutdown_flag_crosses_threads() {
        let sd = Shutdown::new();
        assert!(!sd.triggered());
        let flag = sd.flag();
        let joined = std::thread::spawn(move || flag.store(true, Ordering::SeqCst)).join();
        assert!(joined.is_ok(), "поток quit не упал: {joined:?}");
        assert!(sd.triggered());
        // Идемпотентность: повторный quit не роняет и не «отпускает».
        sd.trigger();
        assert!(sd.triggered());
    }

    #[test]
    fn guid_is_a_fixed_const() {
        assert_eq!(TRAY_GUID, 0x0f5a_d17e_5f72_4b1f_9a44_c3d2_8e01_7002);
    }
}
