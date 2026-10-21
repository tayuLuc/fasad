# Релиз fasad (SPEC §10 п.9, шаг 9)

Владелец процедур сборки/упаковки/публикации. Числа RAM — в
[docs/model-audit.md](model-audit.md) §9 «Release RSS» (первичка промеров).
Политика версий — [RELEASES.md](../RELEASES.md).

## Что в бандле

Бандл = **каскад-0**. Это не маркетинговая метка, а свойство бинаря:

1. `guard-daemon` не объявляет ни одной feature-флага
   (`crates/guard-daemon/Cargo.toml`), а `ort-inference` существует только у
   `guard-onnx` и по умолчанию выключена.
2. Модельного пути спанов в демоне физически нет: `crates/guard-daemon/src/pipeline.rs`
   (заголовок модуля) — каскады 1–2 живут в харнесе `spike` (`guard-onnx`), не
   в HTTP-рантайме.
3. `FASAD_MODEL_DIR` (`crates/guard-daemon/src/config.rs:404`) меняет только
   метку стадии в `/health` (`"stage":"cascade-0+models"`), детекторов из
   моделей не добавляя.
4. Проверка контура вшита в гейт: `scripts/verify-bundle.sh` требует из
   распакованного бандла `{"stage":"cascade-0-only",…}` и совпадения версии
   архива с версией демона.

Следствие для релиза: артефакты именуются `fasad-<version>-<triple>-cascade-0.*`,
и «полный гард с моделями» из этого архива не собирается. Когда модели заедут
в демон (шаг 8/9, issue #70-#71 контур), метка меняется на `full` — менять её
надо в одном месте: `scripts/make-bundle.sh` (`--label`).

Состав архива (`scripts/make-bundle.sh`):

1. `bin/fasad` (`.exe` на Windows) — `cargo build --release -p guard-daemon`.
2. `README.md` — сгенерированная ориентировка пользователя + ссылка на репозиторий.
3. `LICENSE` — Apache-2.0 (текст лицензии продукта).
4. `THIRD-PARTY-LICENSES.txt` — `just deps-licenses` (cargo-about, см. ниже).
5. `schema.default.json` — канон схемы классов (`config/schema.default.json`,
   `FASAD_SCHEMA`).
6. `SHA256SUMS.txt` — sha256 всех файлов бандла; рядом с архивом лежит
   `fasad-…-cascade-0.<ext>.sha256` (хэш самого архива).

## Матрица сборки

`.github/workflows/release.yml`, job `dist` (матрица `include`, `fail-fast: false`):

| runner | triple | архив |
| --- | --- | --- |
| ubuntu-24.04 | x86_64-unknown-linux-gnu | tar.gz |
| windows-2022 | x86_64-pc-windows-msvc | zip |
| macos-14 | aarch64-apple-darwin | tar.gz |

Отличие от SPEC §9 (ubuntu-22.04, две ОС): раннер Linux поднят до 24.04 по
постановке задачи шага 9, macOS-14 добавлен как третья платформа (issue #31).
glibc-пол: SPEC §9 требовал сборки на 22.04 (glibc 2.35) ради переносимости;
на 24.04 (glibc 2.39) бинарь не поедет в 22.04-окружение. Это осознанный размен
постановки: кто нужен в 22.04 — менять `matrix.os` на `ubuntu-22.04` (одна
строка), артефакт от этого не меняет имени.

Тройка берётся с хоста (`rustc -vV | host`), не из матрицы: имя архива =
факт о сборке. Целевые triple в матрицы не передаются (`--target` не used) —
иначе `just dist` упаковал бы `target/release/fasad`, а не кросс-артефакт.

## Запуск (что читает пользователь бандла)

1. `bin/fasad` слушает `http://127.0.0.1:8765/health`; бинд строго loopback
   (`DEFAULT_BIND = 127.0.0.1`, `crates/guard-daemon/src/config.rs:28`),
   непроксируемый адрес наружу = отказ старта с именованием переменной
   (промер тестом `config.rs:728`: `FASAD_BIND=8.8.8.8` → диагностика «loopback»).
2. `FASAD_PORT=0` = «дай свободный порт», баннер печатает фактический адрес
   (`main.rs`, `local_addr`) — на этом трюке ездят `scripts/verify-bundle.sh` и
   `scripts/measure-rss.sh`.
3. Мусор в числовой переменной оставляет дефолт (`config.rs:15`), а откровенно
   битое значение (`FASAD_THREADS=0`, `-1`, `abc`) — отказ старта с именем
   переменной в тексте ошибки (`config.rs:692-727`).
4. Переменные (первичка — `crates/guard-daemon/src/config.rs`, строки рядом):

| Переменная | Дефолт | Первичка |
| --- | --- | --- |
| `FASAD_PORT` | 8765 | config.rs:24 |
| `FASAD_BIND` | 127.0.0.1 (только loopback) | config.rs:28 |
| `FASAD_MAX_BODY_BYTES` | 1048576 | config.rs:33 |
| `FASAD_THREADS` | 8 | config.rs:67 |
| `FASAD_TIMEOUT_MS` (исходящие) | 3000 | config.rs:72 |
| `FASAD_READ_TIMEOUT_MS` (входящее тело) | 30000 | config.rs:84 |
| `FASAD_GRAY_LO` / `FASAD_GRAY_HI` | 0.22 / 0.80 | config.rs:59, :62 |
| `FASAD_TAU_LOW` / `FASAD_TAU_HIGH` | 0.20 / 0.80 | guard-onnx/src/routing.rs:70, :74 |
| `FASAD_VAULT_MODE` | stateless-контур; значения `2\|3\|session\|stateless` | config.rs:326 |
| `FASAD_MLOCK` | `strict` (`strict\|best_effort`) | config.rs:119-133 |
| `FASAD_SCHEMA` | встроенный канон (`schema.default.json` в бандле) | config.rs:244, :405 |
| `FASAD_MODEL_DIR` | нет = стадия `cascade-0-only` | config.rs:404 |
| `FASAD_UPSTREAM_ALLOWLIST` | пусто = наружу ходить некуда | config.rs:252, :411 |
| `FASAD_PROXY_LOOPBACK_HTTP` | false | config.rs:258, :412 |

5. Ответы: `/health` (версия, стадия контура, режим залочкивания),
   `/v1/analyze` (массив спанов, поле `entity_type` — промер живого ответа
   21.10), `/v1/anonymize` (`{text, spans}`, спаны берутся из `/v1/analyze`;
   голый `{"text":…}` = 400, `vault.rs::AnonymizeRequest`).
6. Никакой телеметрии: сетевой вызов наружу только по явному
   `FASAD_UPSTREAM_ALLOWLIST` (AGENTS, инварианты).

### Совместимость с main (промер 21.10, PR #76)

Скрипты RAM-гейта и гейта бандла парсят вывод демона, а в main за это время
уехал шаг 7d (#70: метрика целостности разворота в `/health`). Проверено по
исходникам main (`git show origin/main:<файл>`), а не «на глаз по merger'у»:

1. Баннер: `main.rs:82` на main и на базе ветки — одна и та же строка
   «fasad {} {}, listening on http://{}/health (классов схемы: …)», значит
   регэксп порта в `scripts/measure-rss.sh` и `scripts/verify-bundle.sh`
   работает и после слияния.
2. `/health`: на main остаются `version`, `stage` (тест http.rs:710 ждёт
   `cascade-0-only`) и `mode`; наши проверки — подстроковые, новые поля
   (метрикa #70) их не ломают.
3. Контракт прогрева `/v1/anonymize` = `{text, spans}` (main:
   `vault.rs:141-148`, `spans: Vec<SpanIn>`) — тот же, на нём построен прогрев
   measure-rss.
4. Таблица `FASAD_*` в §Запуск актуальна и после слияния: множество переменных
   в `config.rs` на main и на базе совпадает (`diff` отсортированных списков
   пуст, 16 имён).

## Как выпустить

1. Поднять версию в `[workspace.package] version` (единый источник,
   `Cargo.toml`) + прогнать `cargo update -w`? — нет: `Cargo.lock` регенерится
   обычным `cargo check`/`just check`, отдельного шага нет.
2. `just release` локально (пик на своей ОС: сборка → лицензии → бандл).
3. `just check` зелёный (гейты: lint, python-lint, golden-verify, test,
   net-audit, deny).
4. `git tag -s v<version> && git push origin v<version>` → workflow `release`
   (триггер `push: tags: v*`) собирает матрицу, прогоняет гейты и публикует
   GitHub Release шагом `gh release create` в job `release` (единственной с
   `contents: write`). Экшен `softprops/action-gh-release` на это место **не**
   взят: zizmor даёт на него `superfluous-actions` (confidence High — «функциональность
   уже есть в раннере»), а MegaLinter краснит гейт находкой любой severity (промер
   CI 21.10: run 39514678570, «11 findings (10 suppressed): 1 informational»,
   zizmor rc=11). Плюс из workflow с правами на запись уходит сторонний экшен —
   меньше поверхность supply-chain.
5. Логи RAM-гейта остаются в job-логах (`RSS|…`, `BUDGET|…`). Числа в
   docs/model-audit.md §9 не перепечатываются: `just measure-rss --cascade0
   --doc-rows` печатает готовый markdown-блок и `BUDGET`-строку из артефакта
   прогона (флаг добавлен по рюлингу kernel 21.10 «цифры документа генерируются
   из артефакта»); в CI гейт идёт без флага, вывод тот же по формату.
6. Повторный прогон job `release` по тому же тегу = красный с HTTP 422
   («Release already exists»): `gh release create` не идемпотентен (первичка —
   `gh release create --help`, gh 2.102.0: «By default, the release is created
   even if there are no new commits… duplicate release»). Перевыложить ассеты =
   `gh release delete <tag> --yes` и заново запустить workflow по тегу;
   update-in-place не реализован (п.7 списка «Что не сделано»).

Гейт `workflow_dispatch` есть (ручной прогон матрицы без публикации): job
`release` защищена `if: startsWith(github.ref, 'refs/tags/v')`, поэтому ручной
прогон артефакты собирает, а релиз не трогает.

Прогнать матрицу до слияния нельзя: `gh workflow run release.yml --ref <ветка>`
отвечает HTTP 404 «workflow release.yml not found on the default branch»
(промер 21.10 на PR #76) — GitHub ищет воркфлоу в дефолтной ветке. Значит
`windows-2022` (zip через `powershell Compress-Archive`), linux-бандл и job
`ort-dylib` получают первый живой промер сразу после слияния (первый тег либо
`workflow_dispatch`). До слияния локально промерен только macOS-путь: бандл
`fasad-0.1.0-aarch64-apple-darwin-cascade-0.tar.gz`; идентификатор прогона —
строка `SHA256SUMS.txt`:
`854844605ad858c64e7fc1be33e4bf651192a4d0e3948eaddeb250dcde316ce9  fasad-0.1.0-aarch64-apple-darwin-cascade-0.tar.gz`.
Размер архива фактом не подаётся (ревью #76, F6): он не воспроизводится
байт-в-байт, gzip пишет mtime входящих файлов, и четыре сборки одного дерева
21.10 дали четыре разных числа: 1 728 002 Б (прежняя запись в этом абзаце),
1 728 016 Б, 1 727 997 Б и 1 728 001 Б (прогон `just release` на head `43158f7`).
`shasum -a 256 -c SHA256SUMS.txt` = OK; `scripts/verify-bundle.sh` = rc 0 (прогон
21.10: `ANALYZE|spans=1`, `ANALYZE|inn10=ok`); позитивные контроли: подменённый
байт в `bin/fasad` = rc 1, ИНН с битой чексуммой в проверочном запросе = rc 1.

## Лицензии (THIRD-PARTY)

1. Генератор — `cargo-about` 0.9.x: `cargo install --locked --features cli cargo-about`
   (в CI ставится `taiki-e/install-action` со `tool: cargo-about` — список
   инструментов первичен: `TOOLS.md` pinned-коммита install-action, строка
   `cargo-about`).
2. Профиль — `about.toml`: `accepted` зеркалит `deny.toml [licenses] allow`
   (расхождение = бандл показывал бы лицензии, которые собственный гейт
   считает запрещёнными), `targets` = три triple матрицы,
   `workarounds = ["ring", "rustls"]`, `ignore-dev-dependencies = true`.
3. Шаблон — `about.hbs`: имя пакета, версия, идентификатор и полный текст
   лицензии (минимум задачи: name/version/license; текст добавлен, потому что
   Apache-2.0/MIT требуют донесения текста до получателя).
4. Контекст шаблона — первичка cargo-about 0.9.2
   (`docs/src/cli/generate/output.md`): переменные `overview` (`count`, `name`,
   `id`) и `licenses` (`name`, `id`, `text`, `used_by`), у `used_by` —
   `crate.name`/`crate.version`.
5. Скобки в шаблоне тройные: двойные `{{x}}` HTML-экранируют (живой прогон дал
   `BSD 3-Clause &quot;New&quot;` в текстовом файле).
6. Флаг `--fail`: нераспознанная лицензия = красный гейт, а не дырка в бандле.
7. Прогон 21.10 (macOS, `--workspace --offline --fail`): 6043 строки, 197
   записей «пакет → версия», 7 лицензионных наборов (Apache-2.0 124, MIT 38,
   ISC 18, BSD-3-Clause 6, Zlib 2, CDLA-Permissive-2.0 1, Unicode-3.0 1).

## RAM

1. Замеры сделаны при `FASAD_THREADS=2`, `CARGO_BUILD_JOBS=2` (рюлинг
   оператора 21.10). Рычаг потоков демона — `FASAD_THREADS`
   (`crates/guard-daemon/src/config.rs:67`, дефолт 8); харнеса — `--threads`
   (`spike.rs:158`, дефолт 4). `OMP_NUM_THREADS` не рычаг: вендорный
   `libonnxruntime` osx-arm64 без OpenMP, переменную не читает (первичка
   правки к рюлингу — `otool`/`strings`, ревью #73).
2. Каскад-0 (публикуемый бинарь): пик 3.4 MiB (`ps -o rss`) / 1.6 MiB
   (`footprint phys_footprint`) после прогрева. Число потоков контур демона не
   затрагивает: три прогона при `FASAD_THREADS=8` дают 3.3/3.3/3.4 MiB, прогон
   при `=2` — 3.4 MiB (N=4, 21.10; прежде здесь стояло одиночное
   неавторитетное 2.8 — снято по ревью #76, F4). Бюджет SPEC §1 (1843.2 MiB) не
   задействован и на 1 %.
3. Полный каскад 1–2 (харнес `spike`, релизный профиль, официальный dylib ORT
   1.31.0): пик двух моделей в одном процессе 976.3 MiB (`--threads 4`,
   53 % бюджета) и 889.1 MiB (`--threads 2`, 48 %); для бюджета держим max.
   Промеры 21.10, метод и сырые строки — docs/model-audit.md §9.
4. Профиль: бюджет-гейт раньше был закрыт dev-числом 1434.6 MiB (§5.6 п.5),
   релизный профиль даёт 976.3 — оговорка профиля по этой точке снята.
5. Windows: **не промерено**. `scripts/measure-rss.sh` на `MINGW*`/`MSYS*`
   падает exit 2 с явной причиной (реализованы Darwin/Linux); PowerShell-метод
   (`Get-Process` `WorkingSet64`/`PrivateMemorySize64`) не реализован, шаг
   RAM-гейта в `dist` на windows-2022 выключен условием. Числа для Windows
   появятся вместе с реализацией метода — не раньше.
6. Метод замера печатается в каждой строке вывода — `RSS|<контур>|<точка>|<MiB>|<метод>`,
   вердикт `BUDGET|<контур>|ok|peak_mib=…|budget_mib=1843.2|tool=…`.

## ORT-контур на macOS (промер, issue #31)

1. Статика pyke (`download-binaries`, default) в **release**-профиле на macOS
   SIGSEGV'ит (docs/model-audit.md §5 п.1, промер ×5, обе конфигурации) —
   релизный путь = официальный dylib (ort-дока
   https://ort.pyke.io/setup/linking: compile-time dynamic = `ORT_LIB_PATH` +
   `ORT_PREFER_DYNAMIC_LINK=1`; рантайм-поиск на macOS — rpath `@loader_path`
   либо каталог рядом с бинарём).
2. Фактическая сборка промерена 21.10 на macOS arm64 (rustc 1.99.1):
   `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib cargo build --release --features ort-inference --example spike`
   = exit 0 за 4m05s, линкуется на `libonnxruntime.1.31.0.dylib`, полный
   прогон `--arb-budget --arb --lockr` = exit 0 (числа RAM — §9).
3. В CI это закрыто job `ort-dylib` (macos-14 + ubuntu-24.04): скачивание
   официального архива v1.31.0, сверка sha256 (первичка §8 п.3), `just build-ort`,
   проверка `otool -L`/`ldd` на наличие dylib в load commands.
4. Windows-ячейка матрицы ort-проверки **не** содержит: в ort-доке доставка
   dll на Windows = «в PATH или рядом с exe» (там же), а промера Windows-пути
   в этой сессии не было. Компильная проверка ort-фичи на Windows есть в
   `ci.yml` (`cargo clippy -p guard-onnx --all-targets --features ort-inference`
   в матрице обеих ОС).
5. В бандл `-cascade-0` dylib **не** кладётся: бинарь его не грузит (п.1–3
   раздела «Что в бандле»). Пункт SPEC §9 про `libonnxruntime.so`/`onnxruntime.dll`
   внутри архива становится живым вместе с модельным путём в демоне.

## Пины action'ов (промер 21.10, `gh api repos/<owner>/<repo>/releases/latest`)

| action | пин в release.yml | живой latest на момент промера |
| --- | --- | --- |
| actions/checkout | `3d3c42e5…` # v7.0.1 | v7.0.1 |
| actions/upload-artifact | `cf430e03…` # v7.0.2 | v7.0.2 |
| actions/download-artifact | `9000827c…` # v8.0.2 | v8.0.2 |
| Swatinem/rust-cache | `d1527c8f…` # v2.9.3 | v2.9.3 |
| taiki-e/install-action | `8cca0918…` # v2.87.29 | v2.87.29 (совпадает с ci.yml) |
| dtolnay/rust-toolchain | `b725eda5…` («toolchain: stable», 2026-10-16) | v1 |

Пин dtolnay/rust-toolchain сделан коммитом осознанно: moving-тег `v1` существует
(`releases/latest` = v1, `git/ref/tags/v1` → commit `683b588c487a`, промер 21.10),
но он и есть движущаяся цель — `v1` едет вместе со `stable`, а релизному контуру
нужна воспроизводимость по sha. Прежняя скобка «мажорных тегов нет» (найдена
ревью #76, F3) утверждала обратное и удалена; первоисточник формулировки —
docs/dep-verify-repos.md:45 (файл вне этого PR), правка там за его владельцем.

Публикация релиза — `gh release create` (CLI раннера), пинить нечего: сторонний
экшен снят по zizmor `superfluous-actions`, см. §«Как выпустить», п.4. Промер
`gh api` живой мажор v3.0.3 остаётся в docs/dep-verify-repos.md:45 как факт про
репозиторий экшена.

Аннотированные теги (`v3.0.3`, `v2.9.3`) дереференцены в commit
(`gh api repos/<r>/git/ref/tags/<t>` → `git/tags/<sha>` → commit): пинить
sha tag-объекта нельзя, он не resolvable в `uses:`.

`ci.yml` остаётся на своих пинах (`actions/checkout` v4, `upload-artifact` v4,
`rust-cache` v2.8.7): снятие просроченных мажоров в `ci.yml` — отдельная
работа (docs/dep-verify-repos.md §1 `[PARTIAL]`), в этот PR не входит.

## Что не сделано в этом шаге

1. union-recall N≥150 (гейт §5 п.7) — не трогался.
2. README продукта (витрина, §10 п.9 часть B) — не в объёме задачи.
3. Финальный чек-лист SPEC §11 — за родителем.
4. Модельный путь в демоне (issue #70/#71 контур) — вне объёма; до него
   бандл остаётся `-cascade-0`.
5. Windows-метод RAM-гейта — не реализован (см. §RAM п.3).
6. Подпись артефактов (cosign/sigstore, attestation) — не делалась.
7. Идемпотентность публикации: повторный прогон по существующему релизу
   краснеет (HTTP 422) вместо обновления ассетов — см. §«Как выпустить», п.6.
