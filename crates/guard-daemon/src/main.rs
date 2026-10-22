//! Точка входа демона `fasad`.
//!
//! Шаг 6: слушает 127.0.0.1 (SPEC §1 п.6: никаких сетевых вызовов, кроме явного
//! `X-Upstream-URL`, и старт только на loopback), поднимает `/health`,
//! `/v1/analyze`, `/v1/anonymize`, `/v1/deanonymize`, `/v1/sessions/{id}`;
//! конфиг из `FASAD_*`-переменных, схема из встроенного канона (или
//! `FASAD_SCHEMA`). Tray и UI — шаги 8+.
//!
//! Хук паники ставится до первого сокета: дефолтный хук печатает сообщение
//! паники, а сообщение сторонней библиотеки могут собирать из аргументов, т.е.
//! из текста запроса (`ПДн`). Печатается только место в коде.

#![forbid(unsafe_code)]
// #190: bin НЕ наследует остров либы — вызов `guard_daemon::tray::win`
// идёт через публичный safe-API либы (`forbid` bin-крифта цел: промер
// сессии — island под bin-forbid красен E0453, под lib-deny зелёный).
#![warn(clippy::unwrap_used)]

use guard_daemon::Health;
use guard_daemon::config::Config;
use guard_daemon::schema::Schema;
use guard_daemon::vault::Vault;

/// Хук паники: место в коде без сообщения.
///
/// Обработчики завёрнуты в `http::guarded` и превращают панику в 503, но сообщение в stderr пишет хук, а не обёртка —
/// поэтому хук ставится здесь, до бинда.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "неизвестно".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        eprintln!("fasad: паника в {loc} (сообщение скрыто: в нём может быть вход запроса)");
    }));
}

/// Код выхода при отклонённой конфигурации: отдельный от сетевых ошибок, чтобы
/// systemd/докер видели «неверный конфиг» как неверный конфиг, а не как порт
/// занят (перезапуск с backoff тут бессмыслен и маскирует опечатку).
const EXIT_BAD_CONFIG: i32 = 2;

/// usage-текст `--help` (#191): сжатая таблица env + UI-адрес + версия.
const USAGE_HELP: &str = concat!(
    "fasad ",
    env!("CARGO_PKG_VERSION"),
    " — локальный AI-гард (оффлайн, loopback-only).\n",
    "\n",
    "запуск: fasad (слушает http://127.0.0.1:<порт>/health; UI браузера — http://127.0.0.1:<порт>/)\n",
    "переменные (полная таблица — README.md §Переменные / docs/release.md §Запуск):\n",
    "  FASAD_PORT=8765          порт; 0 = случайный (адрес в баннере)\n",
    "  FASAD_BIND=127.0.0.1     только loopback\n",
    "  FASAD_MODEL_DIR=…        каталог весов каскадов 1–2 (full-бинарь без него не стартует, #185)\n",
    "  FASAD_VAULT_MODE=stateless|session   режим обратимого маскирования\n",
    "  FASAD_VAULT_KEY=<64 hex> ключ, переживающий перезапуск (session)\n",
    "  FASAD_THREADS=8          потоки инференса\n",
    "  FASAD_TIMEOUT_MS=3000    бюджет конвейера (на монтаже держите ≥ 5000)\n",
    "  FASAD_SCHEMA=…           своя схема классов (канон встроен)\n",
    "  FASAD_UPSTREAM_ALLOWLIST=…  адреса прокси /v1/chat/completions (пусто = выключен)\n",
    "веса: scripts/fetch-models.sh (win: .\\scripts\\fetch-models.ps1), sha256-гейт\n",
    "исходники: https://github.com/tayuLuc/fasad\n"
);

/// Разбор argv (#191): процесс вчерашнего дня игнорировал аргументы молча
/// (первичка `main.rs:41` — только env). Контракт:
/// - `--help` / `-h` = usage на stdout, код 0;
/// - любой иной аргумент = usage на stderr, код 2 (`EXIT_BAD_CONFIG`):
///   молчаливо игнорируемый аргумент = оператор думает, что он что-то сделал.
///
/// Разбор — `std::env::args`, без clap: трёх исходов зависимость не стоит.
fn parse_args() {
    let mut args = std::env::args().skip(1);
    match args.next() {
        None => {}
        Some(a) if a == "--help" || a == "-h" => {
            println!("{USAGE_HELP}");
            std::process::exit(0);
        }
        Some(a) => {
            eprintln!("fasad: неизвестный аргумент: {a}\n");
            eprint!("{USAGE_HELP}");
            std::process::exit(EXIT_BAD_CONFIG);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    parse_args();
    install_panic_hook();
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => refuse_startup(&e),
    };

    // Схема проверяется до подъёма сокета: частично применимая схема хуже
    // отсутствующей, а `/health` с 200 на испорченном каноне ввёл бы оператора
    // в заблуждение (fail-closed, AGENTS §Инженерные инварианты).
    let schema = match Schema::from_config(cfg.schema_path.as_deref()) {
        Ok(schema) => schema,
        Err(e) => refuse_startup(&e),
    };

    // Монтаж каскадов 1–2 (#14A) — ДО подъёма сокета. Две причины не откладывать:
    // 1. веса грузятся секунды, и оператор обязан увидеть причину отказа в
    //    stderr при старте, а не получать 502 на первом запросе;
    // 2. `/health` обязан родиться с честным `stage`: `model_dir` назван, а
    //    каскады не поднялись — это отказ старта, а не «cascade-0+models» на
    //    пустых весах (fail-closed, AGENTS).
    // 3. рюлинг #185: full-бинарь (фича `ort-inference`) без `FASAD_MODEL_DIR`
    //    отказывает здесь же (`ModelsNotConfigured`) — молчаливого
    //    `cascade-0-only` в релизном контуре нет; stage каскад-0-only легален
    //    только харнесам/тестам (бинарь без фичи).
    if let Err(e) = guard_daemon::cascades::startup(&cfg) {
        refuse_startup(&e);
    }

    // Loopback обязателен и проверен на разборе: гард не сетевой сервис
    // (SPEC §1 п.6), и `0.0.0.0` сюда протаскивается только через эту стену.
    let tray_stage = cfg.stage();
    let health = Health {
        version: env!("CARGO_PKG_VERSION"),
        stage: tray_stage,
        mode: cfg.vault_mode.as_str(),
    };
    // Хранилище поднимается до сокета по той же причине, что и схема: режим 2/3
    // без ключа и без залочкированной памяти обслуживать нельзя, а отказ после
    // bind выглядит как «демон живой, но ничего не работает».
    let vault = match Vault::startup(cfg.vault_mode, cfg.mlock) {
        Ok(vault) => vault,
        Err(e) => refuse_startup(&e),
    };
    let vault_key_source = vault.key_source().as_str();
    let classes = schema.classes.len();
    // Состояние — общим `Arc`ом (`inner_arc`): на него смотрит роутер, и на
    // том же объекте трей читает счётчики деградации (метрика tooltip'а обязана
    // сходиться с `/health`, две копии сошлись бы враньём — #128).
    let state = guard_daemon::http::AppState::new(cfg.clone(), schema, health, vault);
    let app = guard_daemon::http::router(state.clone());

    let listener = tokio::net::TcpListener::bind(cfg.addr).await?;
    // Порт в баннере — фактически занятый, а не запрошенный: `FASAD_PORT=0`
    // означает «дай свободный», и без `local_addr` оператор (и e2e-тест
    // `tests/wire_e2e.rs`, который поднимает этот бинарь) увидел бы в баннере
    // ноль и не узнал, куда стучаться.
    let addr = listener.local_addr()?;
    println!(
        "fasad {} {}, listening on http://{}/health (классов схемы: {}, vault: {}/{}, ключ: {})",
        env!("CARGO_PKG_VERSION"),
        cfg.stage(),
        addr,
        classes,
        cfg.vault_mode.as_str(),
        cfg.mlock.as_str(),
        vault_key_source,
    );
    // UI-строка баннера (#191): адрес песочницы — отдельной строкой, первым
    // глазом (оператор win/mac запускает бинарь из cmd/Terminal и ищет
    // «куда тыкнуть»; трей-контур делает то же двойным кликом по иконке).
    // Канон адреса = корень: песочница отдаётся на `/` И на `/ui` (промер
    // живым демоном: GET / = 200, GET /ui = 200; `ui::router`), короткий
    // адрес — для человека. Парсер баннера `wire_e2e`
    // (`split_once("listening on http://")`) строку не видит — контракт
    // порта не тронут.
    println!("fasad: UI браузера — http://{addr}/");

    // Трей (#128 фаза 2, win/mac). Первичка docs крейта: на macOS иконка и меню
    // живут только на главном потоке с крутящимся event loop'ом
    // (`tray-icon/src/lib.rs`, «Platform-specific notes»; `muda/src/lib.rs`:
    // «most functionality will panic if you try to use it from any other
    // thread») — значит главный поток отдаётся циклу трея, а serving переезжает
    // на рабочий поток с собственным рантаймом ([`serve_on_worker`]). Без фичи
    // — ровно прежний `axum::serve` в этом потоке: feature-off = headless-
    // бинарь бандла, ноль новых строк в рантайме и ноль новых нитей.
    #[cfg(all(feature = "tray", any(target_os = "windows", target_os = "macos")))]
    {
        let port = addr.port();
        let shutdown = guard_daemon::tray::Shutdown::new();
        // Serving стартует первым: к моменту первого клика по иконке порт уже
        // слушает (иначе «Открыть UI» открывал бы страницу отказа).
        serve_on_worker(listener, app, shutdown.clone());
        guard_daemon::tray::run(&state.inner_arc(), tray_stage, port, &shutdown);
        // Выход из цикла трея = Quit из меню: serve-контур уже сворачивается по
        // флагу (`with_graceful_shutdown`), остаётся завершить процесс.
        Ok(())
    }
    #[cfg(not(all(feature = "tray", any(target_os = "windows", target_os = "macos"))))]
    {
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Serving на выделенном потоке с собственным tokio-рантаймом (только ветка
/// фичи `tray`, см. комментарий в [`main`]).
///
/// Завершение graceful: `with_graceful_shutdown` по флагу
/// `tray::Shutdown` — Quit из меню = SIGTERM-эквивалент для трей-сценария
/// (linux-контур живёт под systemd, #140; там фичи нет и этот путь не
/// компилируется).
#[cfg(all(feature = "tray", any(target_os = "windows", target_os = "macos")))]
fn serve_on_worker(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: guard_daemon::tray::Shutdown,
) {
    let worker = std::thread::Builder::new().name("fasad-serve".to_owned());
    let spawned = worker.spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                // Serving не поднялся = продукта нет: это не cosmetic-сбой, а
                // отказ (причина в stderr, ненулевой код — systemd/супервизор
                // видят смерть, молчаливой витрины без HTTP нет).
                eprintln!("fasad: рантайм serving не поднят: {e}");
                std::process::exit(3);
            }
        };
        rt.block_on(async move {
            let flag = shutdown.flag();
            let watch = async move {
                while !flag.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            };
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(watch)
                .await
            {
                eprintln!("fasad: serving завершился с ошибкой: {e}");
            }
        });
    });
    if let Err(e) = spawned {
        eprintln!("fasad: поток serving не поднят: {e}");
        std::process::exit(3);
    }
}

/// Отказ на старте (конфиг, схема, веса): причина в stderr, сокет не поднимается.
///
/// Вынесено в `-> !`, чтобы поток управления был явен для компилятора, а не
/// через `unwrap_or_else(|e| todo!())`.
///
/// Win-трей (#190): у `fasad-tray.exe` stderr при запуске двойным кликом
/// уходит в никуда (промер оператора v0.1.0: отказ `FASAD_MODEL_DIR не
/// задан…` оператор не увидел) — к stderr добавляется модальное `MessageBox`
/// с тем же текстом (контур острова — `tray::win`; mac-трей и headless
/// ничего не получают: у mac запуск из Terminal/Terminal видит stderr,
/// у `fasad.exe` консоль есть всегда).
fn refuse_startup(err: &dyn std::fmt::Display) -> ! {
    let msg = format!("fasad: старт невозможен: {err}");
    eprintln!("{msg}");
    #[cfg(all(feature = "tray", target_os = "windows"))]
    guard_daemon::tray::win::show_startup_failure("fasad — запуск не удался", &msg);
    std::process::exit(EXIT_BAD_CONFIG);
}
