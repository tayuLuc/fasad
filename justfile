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
SHELL_SOURCES := "!ls scripts/*.sh tools/verify/*.sh .githooks/commit-msg .githooks/tests/*.sh"

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
#
# Канон гейта #60 п.3 — python-метрика `just restore-integrity` (HTTP-контур,
# golden-датасет N=150, Wilson; PR #139), её монтаж в `check` — в том PR.
# `restore_probe` (#141) — DEV-слой: modes session/stateless, которых
# python-нога не покрывает; он живёт тестами (`cargo test -p guard-daemon
# --examples` в `local-test`) и ЛОКАЛЬНЫМ recipe `restore-integrity-probe`
# ниже — в `check` НЕ смонтирован, чтобы не плодить две canonical-ноги.

# Прогнать всё, что блокирует merge: линты (Rust + Python) + язык-гейт + тесты + аудит.
# `restore-integrity` (#60 п.3) — локальная нога по образцу union-recall: поднимает
# живой демон на recall-сплите, в CI не монтируется (там модели 879 МБ вне git и
# union-recall не смонтирован — grep `.github/` union-recall, ноль).
check: lint shellcheck python-lint lang-scan golden-verify test net-audit deny restore-integrity hooks-test

# #180: локальная установка хуков авторства (git config core.hooksPath =
# ЛОКАЛЬНАЯ настройка репо, НЕ глобальная; идемпотентна; fresh-клон/worktree
# = первый шаг после clone). Enforcement = hooks-test (решётка на реальном
# git-контейнере; хуки CI-чекаутом НЕ исполняются = test-контра).
hooks-install:
    git config core.hooksPath .githooks
    @echo "hooks-install ok: core.hooksPath=.githooks (локально, этот репозиторий)"

# #180: решёточный тест .githooks/commit-msg (8 кейсов: чистый/человек-
# трейлер (github noreply) = rc 0; anthropic/пустой угол/`@local`/пустой
# email автора/CRLF = rc 1; `--no-verify` = git-обход, контракт-граница).
# Mounted-носитель в CI = шаг build-test-матрицы (ревью #276: «just check»
# в CI не исполняется; live-git тест = переносим).
hooks-test:
    TMPDIR=${TMPDIR:-/tmp} bash .githooks/tests/commit-msg.t.sh

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
    files=( {{ SHELL_SOURCES }} )
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
    # #224 CI-завись-контра: прогресс-строки между ногами = висяк виден по
    # ПОСЛЕДНЕЙ напечатанной ноге (шаг `just test` в ci.yml = step-timeout
    # 12 мин; без строк log-хвост молчит и не называет висящий прогон).
    echo "just test: cargo test --workspace"
    cargo test --workspace
    echo "just test: guard-vault decliner"
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
    {{ CPU_CALM }} cargo test --workspace
    {{ CPU_CALM }} cargo test -p guard-vault --features decliner
    {{ CPU_CALM }} cargo test -p guard-onnx --examples
    # Тесты харнеса гейта #60 п.3 (#134): контракт формата `RESTORE|verdict` и
    # positive control'ы живости ног. Тот же носитель контракта, что у строки
    # `guard-onnx --examples` выше: тестов примеров не видно ни в
    # `cargo test --workspace`, ни в CI, если их не звать явно.
    {{ CPU_CALM }} cargo test -p guard-daemon --examples

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
    # #100: маржа гейта (#14B) = selftest'ы чистых функций (stdlib-путь, без
    # ort-весов: рюлинг #81) смонтированы в CI = пороговая клетка bar±ε живая.
    uv run --locked python tools/metrics/union_recall.py --selftest-bar
    # #104: хардкод-страж render_report — аналитические числа (медианы смещения
    # координат, фикстуры-номера, bait-доли) обязаны приходить из артефакта
    # прогона (`COORD|`/`UNION|`) или из data/golden (выборка), а не из
    # строкового литерала генератора; без источника — только с датой промера.
    uv run --locked python tools/metrics/render_report.py --selftest-hardcode
    # #104: фикстуры §6 п.9 = выборка из data/golden, а не список номеров в
    # прозе: окно промерено, воспроизводима, контроль жив (пустое окно = пусто).
    uv run --locked python tools/metrics/render_report.py --selftest-fixtures
    # #351: живой контроль контра #351 (selfcheck+идемпотентность shipped-документа):
    # 3 порчи (словарь-утечка / ручная правка числа / файл без §8) обязаны давать
    # rc 1/1/2; мёртвый контроль = rc=2. ПРОВОЕН контроль (не проверка shipped-файла:
    # она красна на HEAD из-за эпох-вставок #77, монтаж красной ноги = отдельное
    # решение оператора) — зелёная нога, монтируется в CI python-golden сейчас.
    uv run --locked python tools/metrics/report_selfcheck.py --self-test
    # #81: python-окружение промера union-recall запинено: recipe = --locked
    # --group metrics; pyproject ∩ uv.lock ∩ .python-version; wheel-контра
    # трёх ОС CI-матрицы. Дрифт onnxruntime = другой инференс = другие
    # recall-числа, sha-префлайт харнеса библиотеку не меряет ⇒ зуб обязателен.
    uv run --locked python scripts/metrics_env_check.py

# Побайтовая воспроизводимость golden-датасета: реген + сверка с B2-константой
# (тот же инвариант, что tests/golden_v1.rs::golden_file_sha256_matches_embedded_const).

# Побайтовая воспроизводимость golden-датасета (реген + сверка с B2) +
# «якорь»-контра (#85-реестр #313): README-числа/секции и тест-пины N =
# артефакт golden-v1.jsonl (scripts/golden_anchor_check.py, stdlib-only).
golden-verify:
    uv run --locked python scripts/golden_regen_verify.py
    uv run --locked python scripts/golden_anchor_check.py

# Dev-нога #134 (НЕ канон гейта — канон python-метрика #139 в `check`):
# целостность разворота продуктового пути in-process, оба режима хранилища.
#
# Харнес `crates/guard-daemon/examples/restore_probe.rs` гоняет
# `Vault::anonymize → deanonymize` — ровно тот код, что вызывают
# `POST /v1/anonymize` / `POST /v1/deanonymize`, — на фикстурах ФОРМ входа
# (кириллица, ФИО в падежах, мультиымянный документ, base64, числа словами, спан
# ровно на потолке `MAX_ORIGINAL_BYTES` и за ним), в обоих режимах хранилища и в
# двух раундах (чистый + после снятия записей `invalidate`, то есть так, как
# запись выглядит для движка после idle-лимита).
# `guard-vault/examples/pool_probe -- integrity` остаётся промером ПУЛА
# суррогатов (выдача формы токену и её индивидуальный разворот); этот харнес —
# целостность round-trip'а документа целиком.
#
# Контракт stdout — строки `RESTORE|…` парами «ключ|значение», как
# `GOLDEN|verdict` в `recall_golden`: per-mode, per-case (с `--echo`), счётчики
# деградации и
#   RESTORE|verdict|ok|roundtrips|<k>|spans|<n>|skips|<s>|failures|0|modes|session|stateless|
# Строка печатается ФАКТИЧЕСКИМИ числами прогона; вердикт краснеет и при нулевом
# покрытии суррогатов (`no_surrogate_coverage`): «не измерено» и «измерено чисто»
# различаются кодом выхода — 0 ok, 1 целостность нарушена, 2 не измерено (тот же
# rc-контракт, что у `lang-scan`).
#
# rc берётся ОТ ПРОВЕРЯЮЩЕЙ КОМАНДЫ (`just` его пробрасывает, промер 1.58.0), а
# не из `grep`-хвоста: конвейер `… | grep RESTORE` заглушил бы rc и дал
# ложно-зелёный прогон (реестр ложно-зелёных: exit code с конвейера).
#
# Щадящий режим (рюлинг 21.10): те же рычаги, что у `local-test` (в тексте
# рецептов `{{…}}` раскрывается, в комментариях — нет, поэтому сюда он не
# подставлялся). Промер 21.10: инкрементальный прогон 2.3 с, сборка с нуля
# ~1 м 40 с (числа — в теле PR).
restore-integrity-probe:
    {{ CPU_CALM }} cargo run -p guard-daemon --example restore_probe

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
# Окружение промера = [dependency-groups] metrics (uv.lock, единственный источник
# пинов; #81): `--locked` краснит расхождение pyproject↔uv.lock; интерпретатор —
# из .python-version (uv сам его ставит в CI). Зуб python-lint
# (scripts/metrics_env_check.py) не даёт recipe вернуться к --isolated/--with.
union-recall *ARGS:
    cargo build --bin fasad
    nice -n 10 env OMP_NUM_THREADS=2 uv run --locked --group metrics \
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

# Selfcheck + контра идемпотентности SHIPPED-документа (#351). `report-selftest`
# мерил генератор на СИНТЕТИКЕ (--self-test), а shipped docs/golden-report.md в CI
# не перегенерировывался НИ РАЗУ — первичка #349: файл на HEAD до #349 не проходил
# selfcheck() собственного генератора (2 leak). Класс: документ = артефакт прогона,
# уезжает от генератора руками. Шаг перегоняет документ из вложенного §8-артефакта
# (extract_report_artifact.py, stdlib) и требует doc == f(артефакт) + selfcheck чист.
#
# ЧЕСТНЫЙ СТАТУС НА HEAD (#77 «строки эпохи v1.x»): на shipped-документе шаг КРАСЕН
# rc=1 — 69 строк дрифта: 61 ручная вставка эпох #200/#289/#217, которых генератор
# не эмитирует ни в одной версии (промер `git log -S` на a464cf4 = самый старый
# автор документа); 8 строк генератора сверх (из них 1 реальный #81-дрейф: §4-команда
# --isolated→--locked --group metrics заведён #350 ПОСЛЕ снимка документа). Сужение
# области до разделов мертво: вставки живут ВНУТРИ §2/§5/§6 (### 5.3b/5.3c), section-
# scope = 8/8 разделов = тот же полный diff ⇒ ложная зелёность. Молча подгонять
# генератор = перенести в него спорную прозу (#77 вне объёма). Поэтому CI-монтаж
# (красный на HEAD) ОТЛОЖЕН за #77-конвертом: смонтировать одной строкой в
# python-golden, когда #77 вольёт doc := f(artifact). Positive control --self-test
# (3 порчи → rc 1/1/2) смонтирован ниже в python-lint (живой контроль, GREEN rc 0).
# rc: 0 = doc==f(artifact)+selfcheck; 1 = дрифт/утечки (RED); 2 = не выполнено.
golden-report-selfcheck:
    uv run --locked python tools/metrics/report_selfcheck.py docs/golden-report.md

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

# Релизный контур = ТОЛЬКО full (рюлинг оператора 22.10, issue #181: «Нужно
# только фулл»; cascade-0-бандл в релизе не продаём). Монтаж каскадов 1–2 в
# HTTP-рантайме есть с #14A (`crates/guard-daemon/src/cascades.rs`):
# `FASAD_MODEL_DIR` → LockrExtractor+DecideArbiter, бинарь без фичи при
# названных весах краснеет (`CascadeFailure::BuiltWithoutInference`), поэтому
# релизный бинарь собирается С фичей `ort-inference`, а метка бандла = `full`.
# Без весов полный бинарь работает каскадом 0 — это легальный режим, а не
# деградация (cascades.rs:639-641: `model_dir` нет → Ok, `stage()` =
# `cascade-0-only`).
# mac-нога: env-префикс dylib-контракта (голый release-линк с фичей краснеет
# на `___isPlatformVersionAtLeast`, docs/model-audit-weights.md §W2 п.2, промер
# ревью #97 + пересъёмка 22.10 в docs/release.md §ORT п.2). Дефолт `ORT_DIR`
# совпадает с `just build-ort`/`just spike-dylib` (тот же путь локальной
# машины); если каталога нет (win/linux-раннер), префикс не ставится: win идёт
# download-binaries+copy-dylibs (`onnxruntime.dll` рядом с exe), linux на
# релизной матрице линкуется по тому же правилу, что `ort-dylib` job —
# живой промер win/linux = первая релизная матрица, риск записан в #181.

# Релизный бинарь guard-daemon (контур = full: ort-inference).
#
# `--bin fasad` обязателен (промер 22.10): без фильтра bin-целей cargo собирает
# ОБА бинаря крейта (`fasad` + `fasad-tray`), и на win/mac-хостах это падение
# линка трей-цели (её rpath-контракт собирается рецептом release-build-tray).
# На linux `--bin fasad` = no-op: фича tray там compile_error (§16), второй
# bin-цели в сборке нет.
release-build:
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_FEATURE_ORT_INFERENCE=1
    export ORT_DIR="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0}"
    if [ -d "$ORT_DIR/lib" ]; then
        export ORT_PREFER_DYNAMIC_LINK=1
        export ORT_LIB_PATH="$ORT_DIR/lib"
        echo "release-build: mac-контур dylib ($ORT_DIR/lib)"
    fi
    cargo build --release -p guard-daemon --features ort-inference --bin fasad

# Трей-бинарь win/mac (#128 фаза 2): ДРУГОЙ bin-путь → `fasad-tray` (cargo
# пишет бинарь по [[bin]].path, отдельного флага имени нет; `[[bin]]` ниже в
# crates/guard-daemon/Cargo.toml). Линкуется на целевой ОС билда: linux-хост
# эту фичу не соберёт (compile_error, §16) — рецепт для win/mac-ноги и
# локальной машины оператора.
# Контур #181: трей = ТОТ ЖЕ main.rs + фича `tray` (crates/guard-daemon/
# Cargo.toml `[[bin]] name="fasad-tray"` = тот же src/main.rs), то есть трей
# вызывает `cascades::startup` и обслуживает `/v1/analyze` тем же конвейером:
# без `ort-inference` трей-бинарь при `FASAD_MODEL_DIR` краснеет
# BuiltWithoutInference, и full-контур релиза требовал фичи и здесь — иначе
# бандл нес бы два контура в одном архиве (headless=full, трей=cascade-0).
# Фичи складываются (`--features tray,ort-inference`), env-префикс mac-контура
# — тот же, что у release-build.
#
# `--bin fasad-tray` (не `--bins`): cargo перелинковывает БИНАРЬ, а не rlib,
# когда меняются только env-аргументы линковки (фича-отпечаток орт-sys
# `rerun-if-env-changed` в registry/.../ort-sys-2.0.0-rc.14/build/vars.rs:19
# пересобирает КРЕЙТ, bin-цель не трогает). `--bins` пересобрал бы и
# `target/release/fasad` тем же профилем, а `just dist` вызывает recipes
# ПОСЛЕДОВАТЕЛЬНО (release-build → release-build-tray), и последний bin-build
# перезаписал бы артефакт, упакованный первым. Отдельный `--bin` на рецепт =
# два независимых артефакта, каждый линкуется своей командой (промер 22.10:
# фасад = LC_LOAD_DYLIB @rpath/libonnxruntime.1.dylib, трей = тот же граф,
# сборка трей-цели = `cargo build --features tray,ort-inference --bin
# fasad-tray`, rc 0).
release-build-tray:
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_FEATURE_ORT_INFERENCE=1
    export ORT_DIR="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0}"
    if [ -d "$ORT_DIR/lib" ]; then
        export ORT_PREFER_DYNAMIC_LINK=1
        export ORT_LIB_PATH="$ORT_DIR/lib"
        echo "release-build-tray: mac-контур dylib ($ORT_DIR/lib)"
    fi
    cargo build --release -p guard-daemon --features tray,ort-inference --bin fasad-tray

# Сборка харнеса полного каскада (spike) релизным профилем на официальном dylib
# ORT: контракт docs/model-audit-weights.md §W2 п.1 + docs/model-audit.md §8 (статика pyke на macOS release =
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
    # Контур флага (#188, провен релиз-репетиции run 39798415641, все три
    # dist-ноги): `--offline` красит CI-контур — `cargo metadata` требует
    # скачивания crate, отсутствующего в warm-кэше матрицы (провен «failed to
    # download bumpalo v3.20.3» ubuntu/win/mac; bumpalo = транзитив wasm-цепи,
    # в target-сборку матрицы не попадает, в lock — есть). Air-gap-контракт
    # AGENTS — про продукт (рантайм), а лицензионный гейт в CI сеть имеет
    # (curl-шаги скачивают). Рычаг DEPS_OFFLINE=1 = offline-форма для
    # оффлайн-машины оператора (локальный репертуар скачан); дефолт = online.
    offline_flag=""
    if [ "${DEPS_OFFLINE:-0}" = "1" ]; then offline_flag="--offline"; fi
    # Флаг = shell-переменная рецепта (just-шаблон с двойными фигурными
    # скобками здесь не используется намеренно).
    # shellcheck disable=SC2086
    cargo about generate -c about.toml --workspace $offline_flag --fail about.hbs -o dist/THIRD-PARTY-LICENSES.txt
    echo "deps-licenses ok: $(wc -l < dist/THIRD-PARTY-LICENSES.txt | tr -d ' ') строк, $(grep -c '^  - ' dist/THIRD-PARTY-LICENSES.txt | tr -d ' ') записей пакет→версия→лицензия"

# Упаковка бандла (бинарь + LICENSE + README-ссылка + схема + лицензии +
# SHA256SUMS) в архив. Формат выбирает ОС ХОСТА СБОРКИ, не параметр: unix →
# tar.gz, Windows (MINGW/MSYS/CYGWIN) → zip через `powershell Compress-Archive`
# (Git-for-Windows `tar` zip не умеет) — scripts/make-bundle.sh:86-89,163-164.
# На macOS локальный прогон даёт ОДИН tar.gz: обещать рядом zip в этой строке
# было бы врать про ячейку, на которой ты стоишь.
# Девелер: dist/ в .gitignore (строка `dist/`).

# Каскад-0-бинарь (без `ort-inference`) — НЕ релизный артефакт (#181: релизный
# контур = только full), а ДИСКРИМИНАТОР: `verify-bundle.sh` ЗУБ В проверяет им
# отказ старта при `FASAD_MODEL_DIR` (CascadeFailure::BuiltWithoutInference,
# cascades.rs:649-650) — живой промер того, что full-метка бандла не может
# достаться бинарю без орт-контура. Голая команда (без env-префикса): линкуется
# статикой pyke на linux/win, на mac НЕ линкуется (release.md §ORT п.2 —
# промеренное падение `___isPlatformVersionAtLeast`), поэтому linux-контур
# промера. Релизный `just dist` его НЕ собирает.
release-build-cascade0:
    cargo build --release -p guard-daemon

# Упаковка бандла (бинарь, лицензии, схема, SHA256SUMS): tar.gz на unix, zip на Windows-хосте.
# Трей-бинарь (#128): на win/mac хостах передаём `--tray-binary` (second bin
# `fasad-tray`); linux-ветка скрипта сама кладёт systemd-юнит (#140).
# Контур #181: метка `full` (дефолт скрипта); mac несёт dylib из $ORT_DIR
# (дефолт = $HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0, тот же
# каталог, что у build-ort/spike-dylib); win несёт onnxruntime.dll из $ORT_DLL
# (win-ячейка CI: путь к runtimes/win-x64/native из pyke-кэша ort-sys,
# delivery-контракт ort-доки «рядом с exe»).
# linux-ветка (#188): трей-зависимость из dep-списка СНЯТА — фича `tray` на
# linux физически несобираема (compile_error в tray-icon, §16), а CI зовёт
# `just dist` на всех трёх ОС: провен релиз-репетиции run 39791625858 —
# dist ubuntu-24.04 упал на release-build-tray (tray-icon compile_error) ДО
# упаковки. mac/win-контур сохранён пословно: трей собирается в uname-ветке
# ниже (та же последовательность release-build → release-build-tray →
# make-bundle; комментарий release-build-tray про порядок bin-целей).
dist: release-build deps-licenses
    #!/usr/bin/env bash
    set -euo pipefail
    ext=""
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) ext=".exe" ;;
    esac
    ort_dir_args=()
    if [ "$(uname -s)" = "Darwin" ]; then
        ort_dir_args=(--ort-dir "${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0}")
    fi
    dll_args=()
    if [ -n "$ext" ] && [ -n "${ORT_DLL:-}" ]; then
        dll_args=(--ort-dll "$ORT_DLL")
    fi
    if [ "$(uname -s)" = "Darwin" ] || [ -n "$ext" ]; then
        just release-build-tray
        bash scripts/make-bundle.sh --tray-binary "target/release/fasad-tray${ext}" ${ort_dir_args[@]+"${ort_dir_args[@]}"} ${dll_args[@]+"${dll_args[@]}"}
    else
        bash scripts/make-bundle.sh ${dll_args[@]+"${dll_args[@]}"}
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
