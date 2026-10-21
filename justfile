# justfile — контракт сборки fasad (паттерн copyosity `make fix/check`, SPEC §5.5.5).
#
# CI (`.github/workflows/ci.yml`) зовёт `just lint` — локально тот же набор, что
# краснит PR. `just check` — полный гейт перед push. Установка just: brew install
# just (или cargo install just).

_default:
    @just --list

# Рычаги щадящего режима (рулинг оператора 21.10, AGENTS §3 п.3): один источник
# для всех локальных прогонов. `CARGO_BUILD_JOBS` режет параллельную сборку,
# `RUST_TEST_THREADS` — параллель тестов (то же, что `-- --test-threads=2`, но
# применимо к рецепту целиком), `nice` отдаёт ядра интерактивным процессам.
# В CI не используется: там свои ядра и свои лимиты раннера.
CPU_CALM := "CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10"

# Прогнать всё, что блокирует merge: линты + тесты + аудит зависимостей + python.
check: lint python-lint golden-verify test net-audit deny

# Гейт «демон не тащит сеть» (#56 п.5). Исполняется как обычный интеграционный
# тест `crates/guard-daemon/tests/net_audit.rs`, а не grep-рецептом: `just` на
# Windows гоняет рецепты без shebang через `cmd`, где `grep` не обязан быть, и
# grep-версия к тому же не попадала в CI-матрицу (джобы зовут lint/test/deny
# поштучно) — т.е. стена была ложно-зелёной на обеих ОС. Три проверки (манифест,
# исходники, `cargo tree -i`) живут в тесте и бегут в `cargo test --workspace`.
net-audit:
    cargo test -p guard-daemon --test net_audit
    @echo "net-audit ok: манифест, исходники и дерево зависимостей демона чисты от сети"

# Авточинит всё, что чинится автоматически (fmt + clippy --fix).
fix:
    cargo fmt --all -- --fix
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Только линтеры (fmt-проверка + clippy с deny-флагами CI).
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    # Опциональные фичи в `--workspace --all-targets` НЕ попадают (не включены по
    # default) ⇒ их пути не компилируются ни на одной ОС, и гейт ложно-зелёный
    # (ревью #54 Н3). Каждая фича — отдельной строкой здесь и в lint-ci.
    cargo clippy -p guard-vault --all-targets --features decliner -- -D warnings -D clippy::unwrap_used

# Линтер CI-тулчейном (issue #25: CI стабильно свежее локального stable —
# assert_is_empty-класс drift'а ловится ТОЛЬКО прогоном версии CI).
# Версию обновлять синхронно с rustc на раннере (промер: gh run view --log).
lint-ci:
    rustup run 1.99.1 cargo fmt --all -- --check
    rustup run 1.99.1 cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    rustup run 1.99.1 cargo clippy -p guard-onnx --all-targets --features ort-inference -- -D warnings -D clippy::unwrap_used
    rustup run 1.99.1 cargo clippy -p guard-vault --all-targets --features decliner -- -D warnings -D clippy::unwrap_used

# Тесты всего workspace + пути опциональных фич (та же причина, что в `lint`:
# `--workspace` их не включает, а матрица ci.yml обязана гонять их на Linux и
# Windows, иначе гейт #50 не живой).
test:
    cargo test --workspace
    cargo test -p guard-vault --features decliner
    # Тесты примеров БЕЗ ort-inference: формат строки вердикта харнеса гейта #14
    # (`recall_golden`) — носитель контракта, а под фичей эти тесты не линкуются
    # на раннерах (нет dylib), поэтому проверяем только то, что от ORT не зависит.
    cargo test -p guard-onnx --examples

# То же, что `test`, но в щадящем режиме CPU (рулинг 21.10): поверхность
# применения правила, чтобы рычаги не перепечатывались в каждой сессии.
# Набор команд идентичен `test` (весь workspace, decliner guard-vault, тесты
# примеров guard-onnx) — отличается только окружением запуска.
local-test:
    {{CPU_CALM}} cargo test --workspace
    {{CPU_CALM}} cargo test -p guard-vault --features decliner
    {{CPU_CALM}} cargo test -p guard-onnx --examples

# Аудит дерева зависимостей (bans/advisories/licenses) — deny.toml.
deny:
    @command -v cargo-deny >/dev/null 2>&1 || { echo "cargo-deny не установлен (cargo install cargo-deny) — гейт НЕИСПОЛНЕН, не провален"; exit 2; }
    cargo deny check

# ── Python-тулинг (gutter, рулинг 19.10: AGENTS п.6) ────────────────────────
# Обвязка под uv: pyproject.toml + uv.lock + .python-version (один источник
# пинов). `uv run` сам синхронизирует .venv по lockfile. Требуется uv:
# brew install uv (mac) или taiki-e/install-action в CI.

# Линт Python-скриптов проекта (генератор датасета + verify/metrics-харнесы).
python-lint:
    uv run --locked ruff check data/golden scripts tools/verify tools/metrics

# Побайтовая воспроизводимость golden-датасета: реген + сверка с B2-константой
# (тот же инвариант, что tests/golden_v1.rs::golden_file_sha256_matches_embedded_const).
golden-verify:
    uv run --locked python scripts/golden_regen_verify.py

# Гейт #14-B: union-recall ПОЛНОГО каскада (0∨1∨2) на golden-наборе, SPEC §5 п.6
# (в AGENTS.md и README golden тот же пункт именуется «§5 п.7»).
# Каскад 0 меряется продуктовым бинарём (POST /v1/analyze), каскады 1/2 —
# runtime-квантами (lockR fp16 + Decide q4f16); декодер импортируется из
# tools/verify/parity_golden.py, поэтому второй реализации оракула нет (рецидив
# «три места = молча разные метрики»).
# Щадящий режим (рюлинг оператора 21.10, AGENTS §3 п.3): nice -n 10, 2 треда
# (intra/inter_op; OMP_NUM_THREADS на вендорном osx-arm64 инертен), один прогон
# за раз, сетка τ последовательная. Число потоков — часть воспроизводимости.
# Веса: scripts/fetch-models.sh; в CI не запускается (модели 879 МБ вне git),
# промер живёт в docs/golden-report.md с sha входов.
union-recall *ARGS:
    cargo build --bin fasad
    nice -n 10 env OMP_NUM_THREADS=2 uv run --isolated --python ~/.local/bin/python3.13 \
        --with numpy --with onnxruntime --with tokenizers \
        python tools/metrics/union_recall.py --threads 2 {{ARGS}}

# docs/golden-report.md из сырого артефакта прогона: числа в документацию попадают
# генерацией, а не переписыванием руками (правило факта «отформатированное число —
# не факт»). Прогон меняешь — документ перегенерируется целиком. PROBE — артефакт
# `tools/metrics/probe_coords.py` (COORD-строки, §6.4/§8.1): без него раздел о
# направлении смещения печатает «?» и остаётся прозой без первички.
union-report RAW OUT PROBE="":
    uv run --locked python tools/metrics/render_report.py {{RAW}} {{OUT}} {{PROBE}}

# Positive control генератора отчёта: подсаженные утечки (имя поля вместо значения,
# плейсхолдер "? %", значение = имя поля, вердикт о планке вразрез с числом)
# обязаны ловиться. Мёртвый контроль = rc=2, тот же контракт, что у lang-scan:
# зелёная проверка без живого контроля = ничто.
report-selftest:
    uv run --locked python tools/metrics/render_report.py --self-test

# Язык-гейт текста: CJK-утечки и склейка кириллицы с латиницей. Positive control
# (--self-test) обязателен: зелёный сканер без контроля = ложно-зелёная проверка
# (первый же контроль поймал мёртвый CJK-класс из начал диапазонов). BSD grep для
# этого неприменим: классы трактует не по кодовым точкам (промер 20.10).
# Дефолт `--all` = весь текстовый tree (инвентарь репозитория; пустой вход = rc 2,
# не «чисто»). На диффе PR — `just lang-scan-files <файлы>`.
lang-scan:
    uv run --locked python scripts/scan_lang.py --self-test --all

# Тот же гейт по списку файлов (на диффе PR: красный = только что добавленное).
lang-scan-files *FILES:
    uv run --locked python scripts/scan_lang.py --self-test --files {{FILES}}

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
