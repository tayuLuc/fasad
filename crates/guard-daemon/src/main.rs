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
// #226: GUI-подсистема для `fasad-tray` (issue: оператор 24.10 «запуск на
// винде даёт уродское терминальное окно; трей = запустил и забыл»). Атрибут
// привязан к КОНТУРУ «трей на win» (`all(feature = "tray", windows)`),
// НЕ к имени bin: bin-цели = два компайла ОДНОГО main.rs (Cargo.toml
// [[bin]] ×2, `fasad-tray` = `required-features = ["tray"]`), аттрибут на
// golem-уровне попал бы и в `fasad`. Релизный контур (just
// release-build-tray = `cargo build --features tray --bin fasad-tray`;
// релизный console-`fasad` = feature-off, промер рецепта 22.10) даёт
// точное разделение: `fasad-tray.exe` = GUI (ни консоли при двойном
// клике — первичка win.rs:85-92 «у обоих bin атрибута нет» обновлена
// #226), `fasad.exe`/`fasad` = console-контракт #185 «текст отказа в
// stderr» НЕ тронут. Побочный эффект контура (принят осознанно):
// `cargo build --features tray` без `--bin` = и `fasad.exe` GUI (тот же
// код+фича; CLI-контур #185 в релизе feature-off, не трей-сборка).
// `windows_subsystem = "windows"` = PE
// подсистема GUI: ни консоли при двойном клике, ни stdio-окна; refuse-
// контур = MessageBoxW (не требует консоли, первичка win.rs island
// #190); stdout-контра (баннер #224) на GUI-подсистеме деградирована в
// null-поток = безвредна (flush-ошибки игнорируются, R4-контра).
#![cfg_attr(
    all(feature = "tray", target_os = "windows"),
    windows_subsystem = "windows"
)]

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
    "  FASAD_CONFIG=…             файл конфигурации (env > файл > дефолт; README §Файл конфигурации)\n",
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
    // #219 atom-1: env > файл > дефолт. Предупреждения файла (неизвестные
    // ключи) печатаются СЮДА, а не из lib: юнит меряет вектор
    // (`LoadedConfig::warnings`), а eprintln из библиотеки тесту невидим —
    // warning, который никто не печатает, = та же ложь нулём, что молча
    // проигнорированная строка.
    let loaded = match Config::load_config() {
        Ok(loaded) => loaded,
        Err(e) => refuse_startup(&e),
    };
    for warning in &loaded.warnings {
        eprintln!("fasad: {warning}");
        // #244: под GUI-подсистемой (#226/#228) stderr = NULL: warning,
        // который никто не печатает, = та же ложь нулём, что молча
        // проигнорированная строка (док-контра этого места, #219).
        win_log(warning);
    }
    let loaded_file_used = loaded.file_used;
    let cfg = loaded.config;
    // Путь файла в баннере (#219): оператор, записавший настройку через UI,
    // обязан видеть, какой файл демон прочитал, иначе «сохранил и не
    // применилось» неразличимо с «сохранил не туда».
    // Путь = всегда, когда резолвился (пишем в тот же файл, где читали);
    // `file_used` гейтит только строку баннера (печатать «конфиг: путь» на
    // пустом файле = ложь о том, что файл на что-то повлиял).
    let config_path = loaded.path;
    // Записанное значение #219 atom-2 = файл, а файл применяется на старте:
    // UI обязан уметь сказать «куда писать» без второй правды о пути.
    guard_daemon::http::set_config_path(config_path.clone());

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
    // 4. #198 (win-UX первого запуска): ТРЕЙ-бинарь desktop-доставки при
    //    отказе МОДЕЛЬНОЙ ДОСТАВКИ (Load/ModelsNotConfigured) НЕ выходит
    //    rc=2 — стартует «ожидающим UI-режимом»: HTTP жив (UI + `/v1/status`
    //    + кнопка «Скачать веса»), stage = `models-pending` (отдельная
    //    строка: `cascade-0-only` на релизном бинаре = ложь stage-зуба
    //    #185), модельные маршруты = 503 `models_pending` (не молчание, не
    //    каскад-0-обман). Headless (`fasad` без фичи, systemd/докер) =
    //    прежнее rc=2: prod fail-closed цел, решётка `startup_pending`
    //    (cascades.rs) unit-контуром закрыта с обеих сторон. Прочие отказы
    //    (схема/vault/конфиг/BuiltWithoutInference/Timeout) = refuse и в
    //    трее: pending-режим чинит доставку весов, а не сломанный бинарь.
    // Feature-мишень по канону крейта (`ui::router` #171): константа на
    // feature-off мишени = false, без ветвей `#[cfg(not)]` и заглушек.
    // Тестовый контур wire_e2e (живой бинарь, не lib-роутер): env-флаг
    // симулирует трей-мишень на headless-двойнике `fasad` (орт-контур
    // wire_e2e под `ort-inference` без `tray`-фичи: 879 МБ весов в live-тесты
    // не заводятся, первичка файла; `tray`-сборка = `just tray-check`,
    // live-нога = `verify-bundle`). Флаг не меняет РЕШИМКУ (`startup_pending
    // / _contour` = contract unit), только compile-time-мишень — ровно так
    // же, как `FASAD_TEST_CASCADE0` отключает подстановку дефолта (#192).
    let tray_contour = cfg!(all(
        feature = "tray",
        any(target_os = "windows", target_os = "macos")
    )) || std::env::var("FASAD_TEST_TRAY_CONTOUR").is_ok();
    let pending = match guard_daemon::cascades::startup(&cfg) {
        Ok(()) => false,
        Err(e) => {
            if guard_daemon::cascades::startup_pending_contour(tray_contour, &e) {
                eprintln!(
                    "fasad: весов нет ({e}) — ожидающий режим #198: UI поднят, \
                     кнопка «Скачать веса» в песочнице; после скачка перезапусти"
                );
                true
            } else {
                refuse_startup(&e);
            }
        }
    };

    // Loopback обязателен и проверен на разборе: гард не сетевой сервис
    // (SPEC §1 п.6), и `0.0.0.0` сюда протаскивается только через эту стену.
    let tray_stage = if pending {
        guard_daemon::cascades::STAGE_PENDING
    } else {
        cfg.stage()
    };
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
    let state =
        guard_daemon::http::AppState::with_pending(cfg.clone(), schema, health, vault, pending);
    let app = guard_daemon::http::router(state.clone());

    // Bind-отказ (#244): порт занят/нельзя биндиться = НЕ config-ветка, и
    // прежний `?` = тихая смерть под GUI-подсистемой (stderr = NULL,
    // MessageBox только на refuse_startup = диагноз #244, полка оператора
    // v0.1.5). Bind-ошибка = отказ старта = refusal-контур: окно + лог +
    // rc=2 (тот же канал, что конфиг/схема/веса: контракт «видим при ВСЕХ
    // startup-отказах», родительский коммент 6399041556).
    let listener = match tokio::net::TcpListener::bind(cfg.addr).await {
        Ok(listener) => listener,
        Err(e) => refuse_startup(&std::io::Error::new(
            e.kind(),
            format!("порт {} занят или недоступен: {e}", cfg.addr),
        )),
    };
    // Порт в баннере — фактически занятый, а не запрошенный: `FASAD_PORT=0`
    // означает «дай свободный», и без `local_addr` оператор (и e2e-тест
    // `tests/wire_e2e.rs`, который поднимает этот бинарь) увидел бы в баннере
    // ноль и не узнал, куда стучаться.
    let addr = listener.local_addr()?;
    println!(
        "fasad {} {}, listening on http://{}/health (классов схемы: {}, vault: {}/{}, ключ: {})",
        env!("CARGO_PKG_VERSION"),
        tray_stage,
        addr,
        classes,
        cfg.vault_mode.as_str(),
        cfg.mlock.as_str(),
        vault_key_source,
    );
    // #224 R4: stdout = pipe харнеса (не TTY) = FULLY-BUFFERED: строка
    // баннера сидит в 8-КиБ буфере, пока процесс жив; харнес ждёт её
    // `read_line` и таймаутится при ЖИВОМ бинде. Явный flush = контракт
    // «строка в трубке сразу»; в терминале (line-buffered) безразлично.
    // ОШИБКА ФЛУША = ТРУБКА ЗАКРЫТА (харнес дочитал баннер и умер по
    // таймауту 15 с, CI-раннер убивает дерево): panic в stdio-локере =
    // гибель ДЕМАНА на раннем баннере = весь призрак-класс 30-с refused
    // (первичка stderr-реестра харнеса: «паника std/src/io/stdio.rs:1168»).
    // Косметика stdout демон валить не обязан (#185: отказ = rc=2 по делу).
    let _ = std::io::Write::flush(&mut std::io::stdout());
    // UI-строка баннера (#191): адрес песочницы — отдельной строкой, первым
    // глазом (оператор win/mac запускает бинарь из cmd/Terminal и ищет
    // «куда тыкнуть»; трей-контур делает то же двойным кликом по иконке).
    // Канон адреса = корень: песочница отдаётся на `/` И на `/ui` (промер
    // живым демоном: GET / = 200, GET /ui = 200; `ui::router`), короткий
    // адрес — для человека. Парсер баннера `wire_e2e`
    // (`split_once("listening on http://")`) строку не видит — контракт
    // порта не тронут.
    println!("fasad: UI браузера — http://{addr}/");
    // Строка файла конфигурации (#219): только когда файл реально дал значения.
    // Молчание «файла нет» = правда; печатать несуществующий путь = ложь,
    // по которой оператор пойдёт править несуществующий файл.
    if let Some(path) = config_path.as_deref().filter(|_| loaded_file_used) {
        // Формат строки = контракт баннера (зубы wire_e2e #224): путь +
        // список КЛЮЧЕЙ, приехавших из файла (без значений: секреты в
        // файле запрещены, а ключи — диагностика «почему демон не такой»).
        let keys = cfg
            .file_keys
            .as_ref()
            .map_or_else(String::new, |ks| ks.join(","));
        println!(
            "fasad: конфиг-файл {} (значения из файла): FASAD_CONFIG={}",
            path.display(),
            keys
        );
        // #224 R4: вторая строка = в ту же трубку; flush-контракт строки 1
        // покрывает её на NEXT-баннере, здесь явный — харнес-ноги #224
        // (wire_e2e баннер-дискриминатор) читают обе.
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

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
        // #318: stage = ЖИВОЕ замыкание (тот же атом, что /health):
        // hot-mount #316 = трей-строка flip-ается на тике, статика старта в вине не живёт.
        guard_daemon::tray::run(&state.inner_arc(), state.stage_reader(), port, &shutdown);
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
                // видят смерть, молчаливой витрины без HTTP нет). #244: под
                // GUI-подсистемой stderr = NULL, а `process::exit` убивает и
                // поток трея — окно обязано показать причину ДО выхода
                // (модалка блокирует ЭТОТ поток; трей-поток с ним не связан,
                // primary потоков: serve = рабочий, трей = main).
                eprintln!("fasad: рантайм serving не поднят: {e}");
                win_fatal("рантайм serving не поднят", &e.to_string());
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
        win_fatal("поток serving не поднят", &e.to_string());
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
/// Подсказка пути докачки в тексте отказа (#199). Строковая константа, не
/// калькулятор: `refuse_startup` вызывается и на отказе конфига (HOME
/// может быть тем самым сломанным env), а UI-контур #198 при живом HTTP
/// показывает конкретный путь витриной `/v1/status` (tilde-форма) — stderr
/// называет форму по умолчанию, не пересобирая резолв config.
const WEIGHTS_HINT: &str = "веса: скачай через UI (http://127.0.0.1:<порт>/ → \
«Скачать веса») или scripts/fetch-models.sh (win: scripts\\fetch-models.ps1); \
каталог по умолчанию: $HOME/.cache/fasad-models (win: %USERPROFILE%\\.cache\\fasad-models), \
свой — FASAD_MODEL_DIR";

/// Дубль текста в трей-лог-файл (#244 → #263, `tray::traylog::append_log`):
/// GUI-подсистема (`fasad-tray.exe`) не имеет видимого stderr при запуске
/// двойным кликом; mac/linux-трей (#263, первичка mac-ассета v0.1.6) = та же
/// тихая ветка при запуске без терминала (Finder-двойной-клик/launcher,
/// `windows_subsystem` = win-only атрибут, stderr NULL). Startup-тексты
/// обязаны оставлять след на диске на ВСЕХ трей-ногах: путь = config-root.
/// Headless (`fasad`, фича выкл.) = NOOP: консоль есть всегда (#185/#190).
/// Заголовок строки = момент жизни демона (startup/serve), текст =
/// исходная строка stderr: две истины не плодим, каналы параллельны.
#[cfg(feature = "tray")]
fn win_log(text: &str) {
    guard_daemon::tray::traylog::append_log(text);
}

#[cfg(not(feature = "tray"))]
fn win_log(_text: &str) {}

/// Фатальный отказ ВНЕ refusal-контура (#244): serve-контур мёртв, процесс
/// уходит с rc=3. Под GUI-подсистемой `eprintln` = NULL = тихая смерть
/// (диагноз #244: видимы обязаны быть ВСЕ startup-отказы, не только
/// config-ветки): лог + окно с причиной. #263: лог = все трей-ноги
/// (mac-двойной-клик = тихая ветка); окно = win-мишень (mac/linux консоль
/// есть, окно не заводим — философия #190). headless = NOOP (консоль).
#[cfg(all(feature = "tray", target_os = "windows"))]
fn win_fatal(what: &str, reason: &str) {
    let msg = format!("fasad: {what}: {reason}");
    guard_daemon::tray::traylog::append_log(&msg);
    guard_daemon::tray::win::show_startup_failure("fasad — запуск не удался", &msg);
}

#[cfg(not(all(feature = "tray", target_os = "windows")))]
fn win_fatal(_what: &str, _reason: &str) {
    // mac/linux-трей: лог = NOOP здесь (serve-контур mac = консольный
    // запуск, текст уже в stderr; тихий mac-запуск = полка #238, log-контур
    // на refuse/warning-ногах живёт через `win_log`), окно = win-мишень;
    // NOOP-контур = вызывающие компилируются на всех ногах.
    // Единственный продуктовый вызов = serve-контур: на mac-трей-ноге он
    // ЗОВЁТСЯ (serve_on_worker компилируется под mac тоже), на headless-
    // бинаре = нет — `allow` (не `expect`: expectation = «нигде не зовётся»,
    // что ложь на mac-трей-ноге = unfulfilled-красное, промер этой сессии).
    #![allow(dead_code, reason = "NOOP-контра: продуктовый вызов = win-трей")]
}

fn refuse_startup(err: &dyn std::fmt::Display) -> ! {
    // #199: текст отказа обязан называть ПУТЬ ДОКАЧКИ, а не только причину:
    // оператор win-двойного-клика читает окно/консоль, а не docs. Канала два
    // (UI-кнопка для ожидающего контура #198 и скрипт для headless), каталог
    // = тот, что подставляет config (#192).
    let msg = format!("fasad: старт невозможен: {err}");
    eprintln!("{msg}");
    eprintln!("fasad: {WEIGHTS_HINT}");
    // #244: stderr под GUI-подсистемой = NULL — отказ обязан оставлять след на
    // диске (путь в README бандла и в окне), обе строки = один лог-контур.
    win_log(&msg);
    win_log(&format!("fasad: {WEIGHTS_HINT}"));
    #[cfg(all(feature = "tray", target_os = "windows"))]
    {
        // Окно #244 += путь лога: «где читать» = ровно то, где пишет
        // `append_log` (контра README бандла + окно + файл = одна истина).
        let win_msg = match guard_daemon::tray::traylog::log_path() {
            Some(p) => format!("{msg}\nfasad: {WEIGHTS_HINT}\n\nЛог: {}", p.display()),
            None => format!("{msg}\nfasad: {WEIGHTS_HINT}"),
        };
        guard_daemon::tray::win::show_startup_failure("fasad — запуск не удался", &win_msg);
    }
    std::process::exit(EXIT_BAD_CONFIG);
}
