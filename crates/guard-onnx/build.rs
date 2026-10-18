//! SPIKE(step2, issue #6): линкует C-остров `spike/rss_mach.c` (`task_info` →
//! private-RSS на macOS) в rlib крейта. `unsafe_code = forbid` в workspace-линтах
//! нельзя инвертировать точечным allow (rustc E0453), поэтому FFI изолирован в C
//! и вызывается из example через extern-декларацию.
//!
//! Example `spike` компилируется всегда (фича `ort-inference` off-by-default —
//! no-op main); C-кусок линкуется только на macOS. CI-матрица (ubuntu/windows)
//! C не видит.

fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR")
        .map_err(|e| format!("OUT_DIR: {e}"))
        .unwrap_or_else(|_| {
            // SAFETY(build-script): без OUT_DIR компиляция C всё равно невозможна —
            // build-скрипт падает детерминированно, это не runtime-путь.
            panic!("SPIKE(step2): OUT_DIR не задан");
        });
    let obj = std::path::Path::new(&out_dir).join("rss_mach.o");
    if target == "macos" {
        println!("cargo:rerun-if-changed=spike/rss_mach.c");
        println!("cargo:rerun-if-env-changed=CC");
        // cc-аргументы минимальны: системный SDK, без внешних зависимостей.
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        let ok = std::process::Command::new(&cc)
            .arg("-std=c11")
            .arg("-O0")
            .arg("-Wall")
            .arg("-Werror")
            .arg("-c")
            .arg("spike/rss_mach.c")
            .arg("-o")
            .arg(obj.as_path())
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "SPIKE(step2): компиляция rss_mach.c не удалась");
        // Только example линкует C-объект (lib-цель его не объявляет).
        println!("cargo:rustc-link-arg-examples={}", obj.display());
    }
}
