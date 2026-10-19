# justfile — контракт сборки fasad (паттерн copyosity `make fix/check`, SPEC §5.5.5).
#
# CI (`.github/workflows/ci.yml`) зовёт `just lint` — локально тот же набор, что
# краснит PR. `just check` — полный гейт перед push. Установка just: brew install
# just (или cargo install just).

_default:
    @just --list

# Прогнать всё, что блокирует merge: линты + тесты + аудит зависимостей.
check: lint test deny

# Авточинит всё, что чинится автоматически (fmt + clippy --fix).
fix:
    cargo fmt --all -- --fix
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Только линтеры (fmt-проверка + clippy с deny-флагами CI).
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used

# Тесты всего workspace.
test:
    cargo test --workspace

# Аудит дерева зависимостей (bans/advisories/licenses) — deny.toml.
deny:
    cargo deny check

# Релизный путь ORT (issue #11): официальный dylib вместо статики pyke.
# Каталог lib: MAC — onnxruntime-osx-arm64-1.31.0/lib release-архива
# (docs/model-audit.md §8), Linux — onnxruntime-linux-x64-1.31.0/lib.
# ORT_DIR переопределяется окружением.

ort-dylib *ARGS:
    # Собирает/гоняет с динамическим ORT: rpath прописывает build.rs (guard-onnx),
    # окружение — два обязательных env. Пример: just ort-dylib -- --arb --lockr
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" {{ARGS}}

# Полный spike-прогон релиза на dylib (issue #11 гейт): сборка release + --arb --lockr.
# Контракт (нить N6, ревью #32): build и run — ОДНИМИ env ниже. Build без
# ORT_PREFER_DYNAMIC_LINK → путь download-binaries (pyke-статика 1.23) +
# copy-dylibs кладёт шейды libonnxruntime*.dylib рядом с бинарём → plain-run
# бинаря, линкованного на 1.31 = SIGSEGV (промер ревью #32; снятие:
# rm target/release/examples/libonnxruntime*.dylib или rebuild с env).
spike-dylib:
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" cargo build --release --features ort-inference --example spike
    ORT_PREFER_DYNAMIC_LINK=1 target/release/examples/spike --arb --lockr
