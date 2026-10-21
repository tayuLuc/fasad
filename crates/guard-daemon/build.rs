//! Релизный `rpath` для бинаря демона (шаг 9A #14A; путь ORT — issue #11, §8).
//!
//! Зачем он нужен именно демону. Продактив-конфигурация каскадов — dynamic-link
//! с официальным dylib (`ORT_PREFER_DYNAMIC_LINK=1` + `ORT_LIB_PATH`, §8 модели
//! `model-audit.md`). В этом режиме `ort-sys` оставляет в бинаре
//! `LC_LOAD_DYLIB @rpath/libonnxruntime.1.dylib`, а `LC_RPATH` не прописывает
//! (grep по `ort-sys-2.0.0-rc.14`: строки `rpath` в build-скрипте нет). Промёрзший
//! симптом: `target/release/fasad` без этого файла умирает ещё до `main` —
//! `Abort trap: 6 / Library not loaded: @rpath/libonnxruntime.1.dylib …
//! Reason: no LC_RPATH's found`, то есть демон с примонтированными каскадами
//! не стартует вообще.
//!
//! Почему не чинится в `guard-onnx`: у того крейта есть своя rpath-ветка
//! ([`../guard-onnx/build.rs`]), но `cargo:rustc-link-arg-*` распространяются
//! только на цели **своего** пакета — до бинаря `fasad` они не доезжают. Этим
//! же объясняется, почему dev-тесты падали в другой яме: там `ort` собирается с
//! `load-dynamic` (feature-unification по dev-таргетам) и грузит dylib через
//! `dlopen`, который `DYLD_LIBRARY_PATH` видит, — а release-бинарь продукта
//! линкуется статически по install-name и к окружению не обязан.
//!
//! Windows: `RUNPATH` в PE не кладётся, доставка — `copy-dylibs` (#76), поэтому
//! для windows здесь намеренно ничего не делается.

fn main() {
    println!("cargo:rerun-if-env-changed=ORT_PREFER_DYNAMIC_LINK");
    println!("cargo:rerun-if-env-changed=ORT_LIB_PATH");
    println!("cargo:rerun-if-env-changed=ORT_LIB_LOCATION");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("ORT_PREFER_DYNAMIC_LINK").is_err() {
        return;
    }
    let Ok(dir) = std::env::var("ORT_LIB_PATH").or_else(|_| std::env::var("ORT_LIB_LOCATION"))
    else {
        return;
    };
    // rpath лишним не бывает и при выключенной фиче `ort-inference` (динамически
    // ничего не грузится), так что условие по фиче тут только запутало бы сборку.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if matches!(os.as_str(), "macos" | "linux") {
        println!("cargo:rustc-link-arg-bins=-Wl,-rpath,{dir}");
    }
}
