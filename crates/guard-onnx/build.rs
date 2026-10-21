//! SPIKE(step2, issue #6): линкует C-остров `spike/rss_mach.c` (`task_info` →
//! private-RSS на macOS) в rlib крейта. `unsafe_code = forbid` в workspace-линтах
//! нельзя инвертировать точечным allow (rustc E0453), поэтому FFI изолирован в C
//! и вызывается из example через extern-декларацию.
//!
//! Example `spike` компилируется всегда (фича `ort-inference` off-by-default —
//! no-op main); C-кусок линкуется только на macOS. CI-матрица (ubuntu/windows)
//! C не видит.

fn main() {
    println!("cargo:rerun-if-env-changed=ORT_PREFER_DYNAMIC_LINK");
    println!("cargo:rerun-if-env-changed=ORT_LIB_PATH");
    // Релизный путь ORT — официальный dylib (issue #11). ort-sys rc.14 сам
    // читает ORT_PREFER_DYNAMIC_LINK / ORT_LIB_PATH (build/vars.rs), но rpath
    // в бинарь не прописывает — локатор ищет по DYLD_LIBRARY_PATH/LD_LIBRARY_PATH
    // (`/opt/homebrew/.../registry/.../ort-sys-2.0.0-rc.14/build/dynamic_link.rs`
    // : строка rpath отсутствует в src grep'ом), чего для релизного демона мало.
    // Прописываем rpath здесь. Unix-линкер: `-Wl,-rpath,<dir>`; MSVC-линкер
    // (-C linker=lld-link) понимает `/LIBPATH:<dir>` для поиска .lib, но RUNPATH
    // в PE не кладёт: Windows-доставка = copy-dylibs (ort `copy-dylibs` фича,
    // promer: build/dynamic_link.rs Windows-ветка копирует onnxruntime.dll в
    // target-каталог) + WindowsLoader-поиск рядом с exe.
    // `if … && let` (let-chains, стабилизированы в Rust 1.88) — MSRV-канон 1.90
    // (#128: tray-icon/muda 1.90) их разрешает; до бампа clippy 1.99 просил
    // `collapsible_if`, а сворачивания на уровне синтаксиса для пары
    // `if + if let` не существовало (let-chains были nightly).
    // Функция идентична: порядок и короткое замыкание те же.
    if std::env::var("ORT_PREFER_DYNAMIC_LINK").is_ok()
        && let Ok(dir) =
            std::env::var("ORT_LIB_PATH").or_else(|_| std::env::var("ORT_LIB_LOCATION"))
    {
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        // unix (macOS/linux): -Wl,-rpath; windows: RUNPATH в PE нет,
        // поиск .lib через /LIBPATH делает ort-sys по ORT_LIB_PATH, а
        // onnxruntime.dll в каталог бинаря кладёт фича `copy-dylibs`.
        if matches!(os.as_str(), "macos" | "linux") {
            println!("cargo:rustc-link-arg-examples=-Wl,-rpath,{dir}");
        }
    }
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR")
        .map_err(|e| format!("OUT_DIR: {e}"))
        .unwrap_or_else(|_| {
            // SAFETY(build-script): без OUT_DIR компиляция C всё равно невозможна —
            // build-скрипт падает детерминированно, это не runtime-путь.
            panic!("SPIKE(step2): OUT_DIR не задан");
        });
    let obj = std::path::PathBuf::from(&out_dir).join("rss_mach.o");
    if target == "macos" {
        println!("cargo:rerun-if-changed=spike/rss_mach.c");

        println!("cargo:rerun-if-env-changed=CC");
        // cc-аргументы минимальны: системный SDK, без внешних зависимостей.
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into()); // build-script: дефолт cc легален (не prod-путь)
        let ok = std::process::Command::new(&cc)
            .arg("-std=c11")
            .arg("-O0")
            .arg("-Wall")
            .arg("-Werror")
            // Символ доступен из example; статический линк не нужен.
            .arg("-fPIC")
            .arg("-c")
            .arg("spike/rss_mach.c")
            .arg("-o")
            .arg(obj.as_path())
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "SPIKE(step2): компиляция rss_mach.c не удалась");
        // Только example линкует C-объект (lib-цель его не объявляет).
        // Промер cargo 1.97.1: `cargo::rustc-link-arg-example-<name>` НЕ принимается
        // (Unknown key), рабочая форма — `cargo:rustc-link-arg-examples=` (все examples).
        //
        // Промер этого захода (issue #6, «конструктив» по директиве родителя):
        //   - link-arg-examples=<.o>: долетает до линкера в dev, в release НЕ долетает;
        //   - rustc-link-lib=static (аргумент `-l`): долетает в обоих профилях, но ld
        //     НЕ вытаскивает объект из архива — единственному .o нет undefined-референса
        //     (Rust-объявление safe-extern ссылку не эмитит, оно ищется через dlsym) →
        //     символ не попадает в образ, dlsym(RTLD_DEFAULT)=NULL (промер nm dev: rc=1);
        //   - рабочий путь: архив как ЯВНЫЙ вход линкера — символ в образе всегда,
        //     dlsym находит его в dev и release (runtime-мост в spike.rs ffi::rss_mib).
        // Промеры 19.10 (issue #6, серия): статический путь НЕЛИНКВАБЕЛен в
        // release — `rustc-link-arg-examples` кладёт аргументы ДО rlib (ld ещё
        // не знает undefined'ов, dead-strip выбрасывает объект), force_load в
        // ранней позиции слепнет, `-l static` без undefined-референсов (dlsym
        // ссылку не эмитит) не вытаскивает член архива. Рабочая конструкция:
        // собираем DYLIB и грузим его рантаймом через dlopen (полный путь
        // прописывается во время build — второй dlsym-прогон уже не нужен).
        let dylib = std::path::PathBuf::from(&out_dir).join("libfasad_spike_dylib.dylib");
        let ok = std::process::Command::new(&cc)
            .arg("-dynamiclib")
            .arg(obj.as_path())
            .arg("-o")
            .arg(dylib.as_path())
            .status()
            .is_ok_and(|st| st.success());
        assert!(ok, "SPIKE(step2): сборка dylib не удалась");

        println!("cargo:rustc-env=SPIKE_DYLIB={}", dylib.display());
        if target == "macos" {
            // GNU-ld не знает dynamic_lookup; Linux-веть spike (/proc VmRSS)
            // в нём не нуждается (nit #6 ревью #9).
            println!("cargo:rustc-link-arg-examples=-Wl,-undefined,dynamic_lookup");
        }
        println!("cargo:rustc-link-arg-examples={}", obj.display());
        // Промеры 19.10 (серия): статический путь (link-arg-examples=.o) не
        // долетает до release-линкера; force_load не спасает (порядок);
        // `-undefined dynamic_lookup` (ld classic) переводит ВСЕ unresolved
        // (включая ___isPlatformVersionAtLeast из орт-статика) в рантайм-лок
        // up; helper резолвится из dylib'а, который dlopen'ится первым шагом
        // main() (см. spike.rs: dylib грузится до Environment::builder()).
        // dylib грузится рантаймом (env SPIKE_DYLIB), в линковку не нужен;
        // ld при -dead_strip не знает про dlopen-зависимости, а undefined из
        // орт-статика резолвится объектом внутри dylib (ссылка host_utils.mm
        // остаётся неудовлетворённой в главном образе без dylib в cmdline) →
        // линкуем dylib явно: rpath не нужен, dlopen идёт по абсолютному пути.
        // dylib НЕ линкуем (ссылка ld на него не нужна — грузим по пути из
        // SPIKE_DYLIB); undefined-хелпер орт-статика резолвится СТАБОМ ВНУТРИ
        // самого TU rss_mach.c (сильное определение, промер 54888b8) — отдельная
        // platform_stub.c не линкуется никуда (nit #7 ревью #9: мёртвая компиляция
        // с assert на каждом macOS-билде удалена).
    }
}
