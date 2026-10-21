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

# Единый источник списка шелл-скриптов для локального shellcheck-гейта (находка
# #137): глоб, а не ручной список — новый скрипт в scripts/ или tools/verify/
# попадает в гейт в момент появления в дереве; ручные списки дрейфуют, и CI
# краснеет при зелёном `just lint` (класс рецидива). Фиксация расхождения:
# MegaLinter-список статичен (lint.yml:38 ENABLE_LINTERS, файл не трогаем),
# локальный список = glob.
# Промер 24.10 (just 1.58): backtick-`ls …` раскрывается при определении
# переменной и в recipe прилетает МНОГОСТРОЧНЫМ блоком — под bash-массив
# уходит первая строка, остальные ломают синтаксис (промер: 1 файл из 7 /
# syntax error — ложно-зелёная слепая зона). Форма `!ls …` (bang-prefix,
# рабочая): значение = одна строка, в bash-массиве раскрывается полным
# списком слов (промер: 7 аргументов из 7, «!ls» префиксом в ls — glob живой,
# ls бегает рантаймом shell при каждом вызове).
SHELL_SOURCES := "!ls scripts/*.sh tools/verify/*.sh"

# Расхождение списков (промер ls vs lint.yml): в дереве 7 скриптов —
# scripts/fetch-models.sh, make-bundle.sh, measure-daemon-rss.sh, measure-rss.sh,
# snapshot-competitors.sh, verify-bundle.sh, tools/verify/fetch_manifest_weights.sh.
# Ручного списка файлов в lint.yml нет (первичка файла 24.10): MegaLinter берёт
# дерево своим глоболом (VALIDATE_ALL_CODEBASE: "true", lint.yml:36).

# Прогнать всё, что блокирует merge: линты + тесты + аудит зависимостей + python.
#
# `lang-scan` — Python-нога (язык-гейт текста, #103/#105), в recipe её добавило
# ревью #116 F1: раньше её там не было, а тело PR #116 продавало red-сигнал
# «через just check» — ложь, пойманная промером. Дешёвое (Python) идёт до
# cargo-тяжестей, чтобы язык-гейт краснел за секунды, а не после минуты сборки.
#
# Монтирование (промер #116): CI зовёт рецепты поштучно — `just lint`, `just test`,
# `just deny` (ci.yml:47,51,52) и `just python-lint`, `just golden-verify`
# (ci.yml:79,80, джоба `python-golden`); `just check` целиком в CI не вызывается
# (grep `.github/` «just check» — ноль совпадений), ссылок на lang-scan/scan_lang
# в `.github/` тоже ноль, а джоба `Lint` (lint.yml:21) = MegaLinter по Actions YAML
# и shell, где Python-гейты не бегут. Итог: `just check` — ЛОКАЛЬНЫЙ полный гейт
# перед push (плюс ручной `just lang-scan`), в CI язык-гейт НЕ смонтирован.

# Прогнать всё, что блокирует merge: линты (Rust + Python) + язык-гейт + тесты + аудит.
# `restore-integrity` (#60 п.3) — локальная нога по образцу union-recall: поднимает
# живой демон на recall-сплите, в CI не монтируется (там модели 879 МБ вне git и
# union-recall не смонтирован — grep `.github/` union-recall, ноль).
check: lint shellcheck python-lint lang-scan golden-verify test net-audit deny restore-integrity

# Гейт «демон не тащит сеть» (#56 п.5). Исполняется как обычный интеграционный
# тест `crates/guard-daemon/tests/net_audit.rs`, а не grep-рецептом: `just` на
# Windows гоняет рецепты без shebang через `cmd`, где `grep` не обязан быть, и
# grep-версия к тому же не попадала в CI-матрицу (джобы зовут lint/test/deny
# поштучно) — т.е. стена была ложно-зелёной на обеих ОС. Три проверки (манифест,
# исходники, `cargo tree -i`) живут в тесте и бегут в `cargo test --workspace`.

# Гейт «демон не тащит сеть»: интеграционный тест net_audit.
net-audit:
    cargo test -p guard-daemon --test net_audit
    @echo "net-audit ok: манифест, исходники и дерево зависимостей демона чисты от сети"

# Авточинит всё, что чинится автоматически (fmt + clippy --fix).
fix:
    cargo fmt --all -- --fix
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Только линтеры (fmt-проверка + clippy с deny-флагами CI).
# Шелл-нога — ОТДЕЛЬНЫЙ рецепт `shellcheck` (находка #137), в `lint` НЕ
# монтируется: recipe обязана владеть shebang-блоком целиком (промер 24.10:
# строки ДО `#!/usr/bin/env bash` sh парсит своим доменом, после — тело
# скрипта), а раннеры build-test (macos/windows) бинаря shellcheck не имеют —
# fail-closed recipe валила ci.yml rc=2 (промер runs 39625561652/39628047538),
# ci.yml трогать нельзя (контракт микро-атома). Вешать бинарь на 3 раннера =
# правка ci.yml = отдельный атом. check (локальный полный гейт) монтирует её
# сам; на CI шелл-контур = MegaLinter в lint.yml.
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    # Опциональные фичи в `--workspace --all-targets` НЕ попадают (не включены по
    # default) ⇒ их пути не компилируются ни на одной ОС, и гейт ложно-зелёный
    # (ревью #54 Н3). Каждая фича — отдельной строкой здесь и в lint-ci.
    cargo clippy -p guard-vault --all-targets --features decliner -- -D warnings -D clippy::unwrap_used
    # Шаг 9A (#14A): смонтированный путь демона (каскады 1–2) живёт под фичей
    # `ort-inference` и по той же причине (#54 Н3) обязан быть отдельной строкой.
    # Промёрзший пример класса: коммит 1fc5127 поймал E0252 в guard-onnx ровно на
    # этой конфигурации, и ниже стоящая строка guard-onnx его поймала, а `just
    # lint` — нет, потому что путей демона с фичей в ней не было.
    cargo clippy -p guard-daemon --all-targets --features ort-inference -- -D warnings -D clippy::unwrap_used

# Шелл-гейт дерева (находка #137): джоба Lint = MegaLinter BASH_SHELLCHECK по
# дереву (lint.yml:38), в локальном гейте shellcheck не было ни строки —
# мёртвая переменная в новом скрипте краснила CI при зелёном `just lint`.
# Формула `!ls` (bang-prefix, см. SHELL_SOURCES): bash раскрывает её в массиве
# списком слов, артефакт «!ls» режет слайс [1:] — shellcheck получает ровно
# 7 файлов.
# Граница = warning (явно, не дефолтом): descriptor BASH_SHELLCHECK severity
# не передаёт (промер megalinter v9.6.0 bash.megalinter-descriptor.yml,
# cli_lint_extra_args = --color=auto --external-sources), у бинаря дефолт
# warning. Версия CI-контейнера локальной не равна (класс issue #25): в логе
# run 39625561652 SC2015-info печатались при пине v0.11.0, а podman-промер
# koalaman/shellcheck:v0.10.0 на merge-дереве даёт РОВНО эти 5 info, v0.11.0 —
# ноль: контейнер CI на прогоне печатал ниже warning. warning-срез идентичен
# на обеих версиях (промер обеих на merge-дереве) — явный флаг делает skew
# безвредным, дефолт 0.10-контейнера красил бы CI зелёным-локальным-красным.
# fail-closed по образцу `deny`: бинарь вне PATH = rc 2 с сообщением
# (brew install shellcheck / apt-get install shellcheck / choco install
# shellcheck — по ОС раннера).
# Промёр: green rc=0; dead var → SC2034 (warning) rc=1; shellcheck вне PATH
# → rc=2.
shellcheck:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck не установлен — гейт НЕИСПОЛНЕН, не провален (brew install shellcheck / apt-get install shellcheck / choco install shellcheck)"; exit 2; }
    files=( {{SHELL_SOURCES}} )
    files=( "${files[@]:1}" )
    shellcheck --severity=warning -x "${files[@]}"

# Трей (#128 фаза 2): feature-on линт — ОТДЕЛЬНЫЙ рецепт, не строка в `lint`.
# Причина ровно зеркальная #54 H3: под `--workspace` фича не включается (дефолт
# OFF), а смонтировать её в `lint` нельзя — линт бегает и на ubuntu-ноге CI, где
# `--features tray` физически несобираем (`compile_error` tray-icon,
# docs/dep-verify-crates.md §16): linux-нога краснела бы всегда. CI зовёт этот
# рецепт условно (ci.yml: `if: matrix.os != 'ubuntu-24.04'`), локально он же —
# гейт mac/windows-машины оператора.
tray-check:
    cargo clippy -p guard-daemon --all-targets --features tray -- -D warnings -D clippy::unwrap_used
    cargo check -p guard-daemon --features tray
    # Юниты модуля под фичей; живые GUI-тесты — `#[ignore]` (headless-раннер
    # без окна краснеет на тесте, не на продукте) и промеряются руками:
    # cargo test -p guard-daemon --features tray --test tray_live -- --ignored
    cargo test -p guard-daemon --features tray --lib

# Линтер CI-тулчейном (issue #25: CI стабильно свежее локального stable —
# assert_is_empty-класс drift'а ловится ТОЛЬКО прогоном версии CI).
# Версию обновлять синхронно с rustc на раннере (промер: gh run view --log).

# Линтер CI-тулчейном 1.99.1 (ловит drift локального stable).
lint-ci:
    rustup run 1.99.1 cargo fmt --all -- --check
    rustup run 1.99.1 cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    rustup run 1.99.1 cargo clippy -p guard-onnx --all-targets --features ort-inference -- -D warnings -D clippy::unwrap_used
    rustup run 1.99.1 cargo clippy -p guard-vault --all-targets --features decliner -- -D warnings -D clippy::unwrap_used
    rustup run 1.99.1 cargo clippy -p guard-daemon --all-targets --features ort-inference -- -D warnings -D clippy::unwrap_used
    # Трей под CI-тулчейном — та же ОС-обязанность, что в `tray-check`: на
    # linux фича несобираема (§16), вызов только вне linux.
    if [ "$(uname -s)" != "Linux" ]; then rustup run 1.99.1 cargo clippy -p guard-daemon --all-targets --features tray -- -D warnings -D clippy::unwrap_used; fi

# Тесты всего workspace + пути опциональных фич (та же причина, что в `lint`:
# `--workspace` их не включает, а матрица ci.yml обязана гонять их на Linux и
# Windows, иначе гейт #50 не живой).

# Тесты workspace + опциональные фичи отдельными прогонами.
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

# Тесты workspace + опциональные фичи в щадящем режиме CPU (рычаги 21.10).
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

# Побайтовая воспроизводимость golden-датасета (реген + сверка с B2).
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

# Union-recall полного каскада (0∨1∨2) на golden-наборе — гейт #14-B.
union-recall *ARGS:
    cargo build --bin fasad
    nice -n 10 env OMP_NUM_THREADS=2 uv run --isolated --python ~/.local/bin/python3.13 \
        --with numpy --with onnxruntime --with tokenizers \
        python tools/metrics/union_recall.py --threads 2 {{ ARGS }}

# Гейт #60 п.3: restoration-integrity — доля побайтовых возвратов исходнику на
# ПОЛНОГО контура демона (analyze → anonymize → deanonymize, режим хранилища 2)
# на текстах golden-v1. Рядом с recall (#14): recall мерит детект, эта метрика
# мерит обратный ход (реверс-индекс + разворот, шаг 7d #70); `pool_probe
# -- integrity` мерит движок guard-vault на 27 ФИО, эта нога — продуктовый HTTP
# на recall-сплите. Positive control (clean/sabotage) обязан быть живым:
# мёртвый контроль = rc=2, метрика не засчитывается (доктрина ложно-зелёного).
# Щадящий режим (рюлинг 21.10): nice -n 10, демон на 2 треда (FASAD_THREADS),
# один прогон за раз. Датасет только читается; B2-хэш проверяется на входе
# харнеса, гейт правок остаётся `just golden-verify`.
# В CI не монтируется по образцу union-recall (тяжёлый контур с живым демоном;
# grep .github union-recall — ноль): локальная нога, в `just check`.

# Restoration-integrity полного контура демона (vault=session) — гейт #60 п.3.
restore-integrity *ARGS:
    cargo build --bin fasad
    nice -n 10 env FASAD_THREADS=2 python3 tools/metrics/restore_integrity.py {{ ARGS }}

# Та же метрика на смонтированном весе (каскады 1–2 маскируют детектом):
# сборка демона под ort-inference на официальном dylib (контраонта
# crates/guard-daemon/README.md §«Как включить монтаж»; macOS: без env-префикса
# линковка краснеет, docs/model-audit §5 п.2), веса FASAD_MODEL_DIR, бюджет
# запроса 10 с (дефолт 3000 мс на смонтированном пути не вмещает Decide-чанк —
# README §env, промер ревью #97). Стадия проверяется харнесом по /health.
# Ключ `--features` в профиль target/ — общий с каскад-0 сборкой: полный прогон
# ПЕРЕТИРАЛ бы target/debug/fasad орт-смонтированным бинарём (ревью #139:
# `just restore-integrity` ниже поднял бы смонтированный демон, и stage в
# RESTORE|daemon|stage уехал бы молча). Отдельный --target-dir изолирует
# артефакт, --daemon указывает на него.
restore-integrity-full *ARGS:
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" \
        CARGO_BUILD_JOBS=2 nice -n 10 cargo build --target-dir target-ort --features guard-daemon/ort-inference --bin fasad
    nice -n 10 env FASAD_THREADS=2 FASAD_MODEL_DIR="${HOME}/.cache/fasad-models" \
        FASAD_TIMEOUT_MS=10000 \
        python3 tools/metrics/restore_integrity.py --daemon target-ort/debug/fasad {{ ARGS }}

# docs/golden-report.md из сырого артефакта прогона: числа в документацию попадают
# генерацией, а не переписыванием руками (правило факта «отформатированное число —
# не факт»). Прогон меняешь — документ перегенерируется целиком. PROBE — артефакт
# `tools/metrics/probe_coords.py` (COORD-строки, §6.4/§8.1): без него раздел о
# направлении смещения печатает «?» и остаётся прозой без первички.

# docs/golden-report.md, сгенерированный из сырого артефакта прогона.
union-report RAW OUT PROBE="":
    uv run --locked python tools/metrics/render_report.py {{ RAW }} {{ OUT }} {{ PROBE }}

# Positive control генератора отчёта: подсаженные утечки (имя поля вместо значения,
# плейсхолдер "? %", значение = имя поля, вердикт о планке вразрез с числом)
# обязаны ловиться. Мёртвый контроль = rc=2, тот же контракт, что у lang-scan:
# зелёная проверка без живого контроля = ничто.

# Positive control генератора отчёта: подсаженные утечки обязаны ловиться.
report-selftest:
    uv run --locked python tools/metrics/render_report.py --self-test

# Язык-гейт текста: CJK-утечки и склейка кириллицы с латиницей. Positive control
# (--self-test) обязателен: зелёный сканер без контроля = ложно-зелёная проверка
# (первый же контроль поймал мёртвый CJK-класс из начал диапазонов). BSD grep для
# этого неприменим: классы трактует не по кодовым точкам (промер 20.10).
# rc-контракт (#105 + #116 F5, он же печатается в `--help`): 0 = чисто; 1 = найдены
# хиты; 2 = проверка НЕ выполнена — мёртвый positive control, пустой обход `--all`
# (дерево без текстовых файлов = сломанный glob), ни один входной файл не прочитан
# (`--files` по несуществующим путям), либо git-инвентарь недоступен: `--all` в
# дереве без `.git` (распакованный тарбол, копия дерева). До #116 F5 этот случай
# был traceback `CalledProcessError` → rc 1, т.е. «найдены хиты» — ложь о причине
# отказа; теперь `LANG|git|no-inventory|…` + NOINPUT reason|no-git, rc 2.
# Двойка краснит рецепт СВОИМ кодом: just пробрасывает rc команды (промер 1.58.0),
# так что «пустой прогон» красный.
# Дефолт `--all` = весь текстовый tree (инвентарь репозитория). В обходе теперь и
# файлы без расширения (#103: justfile, LICENSE, Makefile, NOTICE, dotfiles) —
# раньше они выпадали из инвентаря молча, и утечка в комментарии рецепта была
# невидима для гейта. Покрытие меряют ДВЕ ноги: `CONTROL|inventory` по предикату и
# `CONTROL|traversal` по строке фильтра внутри `git_text_files` (#116 F2: первая
# мерит предикат и мутацию call-site не видит — посаженный в justfile CJK оставался
# невидим при `live` + `clean`, files 141 → 134). На диффе PR —
# `just lang-scan-files <файлы>`.
# Легальный CJK (тесты полноширинных цифр, цитаты иероглифов) исключается
# директивой `scan-lang:` + `allow` (в коде — слитно) ровно в той же строке, где
# стоит литерал: области
# действия у неё нет за пределами строки, файловых исключений нет, а «мёртвая»
# директива (строка без хита) краснит прогон — мёртвое исключение равно
# мёртвому контролю. Разрешённые печатаются в отчёте (`LANG|allow|…`).

# Язык-гейт всего текстового дерева: CJK-утечки и склейка кириллицы с латиницей.
lang-scan:
    uv run --locked python scripts/scan_lang.py --self-test --all

# Тот же гейт по списку файлов (на диффе PR: красный = только что добавленное).
lang-scan-files *FILES:
    uv run --locked python scripts/scan_lang.py --self-test --files {{ FILES }}

# Релизный путь ORT (issue #11): официальный dylib вместо статики pyke.
# Каталог lib: MAC — onnxruntime-osx-arm64-1.31.0/lib release-архива
# (docs/model-audit.md §8), Linux — onnxruntime-linux-x64-1.31.0/lib.
# ORT_DIR переопределяется окружением. Две строки этого блока раньше были
# ТЕЛОМ рецепта (Just их пропускает, но читать recipe body ради прозы нечего).
#
# Формат док-комментария в этом файле: смежной с рецептом обязана быть КОРОТКАЯ
# сводка, длинная проза отделяется пустой строкой — `just --list` показывает
# последнюю строку блока комментариев (промер до правки: хвосты предложений у 10
# рецептов из 17, ревью #76 F6).

# Сборка/прогон с динамическим ORT (rpath прописывает build.rs).
ort-dylib *ARGS:
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" {{ ARGS }}

# Полный spike-прогон релиза на dylib (issue #11 гейт): сборка release + --arb --lockr.
# Контракт (нить N6, ревью #32): build и run — ОДНИМИ env ниже. Build без
# ORT_PREFER_DYNAMIC_LINK → путь download-binaries (pyke-статика 1.23) +
# copy-dylibs кладёт шейды libonnxruntime*.dylib рядом с бинарём → plain-run
# бинаря, линкованного на 1.31 = SIGSEGV (промер ревью #32; снятие:
# rm target/release/examples/libonnxruntime*.dylib или rebuild с env).

# Полный spike-прогон релиза на dylib (issue #11 гейт).
spike-dylib:
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" cargo build --release --features ort-inference --example spike
    ORT_PREFER_DYNAMIC_LINK=1 target/release/examples/spike --arb --lockr

# ── Релиз (SPEC §10 п.9, шаг 9) ──────────────────────────────────────────────
# Контракт тот же, что по всему файлу (§5.5.5): CI зовёт ТЕ ЖЕ цели, что
# оператор локально. Тела рецептов — shebang-bash: на windows-2022 `just` без
# shebang идёт через `cmd`, где нет ни `set -euo`, ни пайплайнов, ни tar (тот же
# класс дефекта, из-за которого net-audit переехал из grep-рецепта в тест).
# Логика упаковки — в scripts/make-bundle.sh: heredoc на колонке 0 ломает
# парсер just (промер 21.10: `unknown start of token 'Л'`), а скрипт при этом
# линтуется shellcheck'ом в job `lint-actions`.

# Версия workspace: единый источник — `[workspace.package] version` в Cargo.toml
# (RELEASES.md п.1). Python в build-контур не пускаем (AGENTS п.6).

# Версия workspace из `[workspace.package] version` в Cargo.toml (sed, без Python).
_version:
    @sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -1

# Host-тройка (имя артефакта = fasad-<version>-<triple>).
_triple:
    @rustc -vV | sed -n 's/^host: //p'

# Релизный бинарь. Контур = каскад-0: у guard-daemon НЕТ фичей
# (crates/guard-daemon/Cargo.toml), `ort-inference` живёт в guard-onnx и в демоне
# не включается — модельного пути спанов в демоне физически нет
# (crates/guard-daemon/src/pipeline.rs, заголовок модуля). Артефакт метится
# честно, см. docs/release.md §«Что в бандле».

# Релизный бинарь guard-daemon (контур = каскад-0).
release-build:
    cargo build --release -p guard-daemon

# Трей-бинарь win/mac (#128 фаза 2): ДРУГОЙ bin-путь → `fasad-tray` (cargo
# пишет бинарь по [[bin]].path, отдельного флага имени нет; `[[bin]]` ниже в
# crates/guard-daemon/Cargo.toml). Линкуется на целевой ОС билда: linux-хост
# эту фичу не соберёт (compile_error, §16) — рецепт для win/mac-ноги и
# локальной машины оператора.
release-build-tray:
    cargo build --release -p guard-daemon --features tray

# Сборка харнеса полного каскада (spike) релизным профилем на официальном dylib
# ORT: контракт docs/model-audit.md §5 п.1 + §8 (статика pyke на macOS release =
# SIGSEGV; dylib 1.31.0 = живой прогон). Нужна для `just measure-rss --full`.

# Харнес полного каскада (spike) релизным профилем на dylib ORT.
build-ort:
    #!/usr/bin/env bash
    set -euo pipefail
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}" \
        cargo build --release --features ort-inference --example spike

# THIRD-PARTY-LICENSES.txt по about.toml + about.hbs (синтаксис шаблона — первичка
# cargo-about 0.9.2 docs/src/cli/generate/output.md, промер 21.10: контекст
# `overview`/`licenses`, поля `crate.name`/`crate.version`; двойные скобки
# HTML-экранируют, в текстовом бандле нужны тройные).
# `--offline`: список собирается без сети (air-gap-контур продукта + оффлайн-
# сборка релиза); `--fail`: нераспознанная лицензия = красный гейт, а не дырка в
# бандле (первичка generate/README.md: «Exits with a non-zero exit code if any
# crate's license cannot be reasonably determined»).

# THIRD-PARTY-LICENSES.txt по about.toml + about.hbs.
deps-licenses:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v cargo-about >/dev/null 2>&1 || { echo "cargo-about не установлен (cargo install --locked --features cli cargo-about) — гейт НЕИСПОЛНЕН, не провален"; exit 2; }
    mkdir -p dist
    cargo about generate -c about.toml --workspace --offline --fail about.hbs -o dist/THIRD-PARTY-LICENSES.txt
    echo "deps-licenses ok: $(wc -l < dist/THIRD-PARTY-LICENSES.txt | tr -d ' ') строк, $(grep -c '^  - ' dist/THIRD-PARTY-LICENSES.txt | tr -d ' ') записей пакет→версия→лицензия"

# Упаковка бандла (бинарь + LICENSE + README-ссылка + схема + лицензии +
# SHA256SUMS) в архив. Формат выбирает ОС ХОСТА СБОРКИ, не параметр: unix →
# tar.gz, Windows (MINGW/MSYS/CYGWIN) → zip через `powershell Compress-Archive`
# (Git-for-Windows `tar` zip не умеет) — scripts/make-bundle.sh:86-89,163-164.
# На macOS локальный прогон даёт ОДИН tar.gz: обещать рядом zip в этой строке
# было бы врать про ячейку, на которой ты стоишь.
# Девелер: dist/ в .gitignore (строка `dist/`).

# Упаковка бандла (бинарь, лицензии, схема, SHA256SUMS): tar.gz на unix, zip на Windows-хосте.
# Трей-бинарь (#128): на win/mac хостах передаём `--tray-binary` (second bin
# `fasad-tray`); linux-ветка скрипта сама кладёт systemd-юнит (#140).
dist: release-build release-build-tray deps-licenses
    #!/usr/bin/env bash
    set -euo pipefail
    ext=""
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) ext=".exe" ;;
    esac
    if [ "$(uname -s)" = "Darwin" ] || [ -n "$ext" ]; then
        bash scripts/make-bundle.sh --tray-binary "target/release/fasad-tray${ext}"
    else
        bash scripts/make-bundle.sh
    fi

# Полный релизный прогон на хосте = одна ячейка матрицы CI локально.
release: dist
    @echo "release ok: версия $(just _version), тройка $(just _triple), артефакты в dist/"

# RAM-гейт SPEC §10 п.9 (цель ≤1.8 ГБ): контур каскада-0 (релизный бинарь,
# footprint/ps с методом в выводе) + опция --full (харнес spike, орт-сессии
# lockR+Decide). Числа идут в docs/model-audit.md §9 «Release RSS».
# Примеры: just measure-rss ; just measure-rss --full ; just measure-rss --full --skip-build

# RAM-гейт SPEC §10 п.9: каскад-0, опция --full — харнес.
measure-rss *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    bash scripts/measure-rss.sh {{ ARGS }}
