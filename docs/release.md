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
3. `FASAD_MODEL_DIR` (`crates/guard-daemon/src/config.rs:424`) меняет только
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
7. Платформенный контур запуска (решение оператора 21.10, issue #128):
   **linux-бандл = headless-демон под systemd** (консольный запуск, юнит
   `contrib/systemd/fasad.service` в бандле — #140, бинд loopback по дефолту —
   `config.rs`), трей в linux-артефакт не входит; **win/mac-бандлы несут
   tray-бинарь** `bin/fasad-tray` (feature `tray` ON, иконка статуса — #128
   фаза 2, PR-контур `crates/guard-daemon/src/tray.rs`: клик = открыть UI
   браузером ОС, меню = «Выход (graceful)» = shutdown-канал демона, tooltip =
   `fasad: <счётчик отказов> / <stage>` без ПДн). На стороне зависимостей это
   зафиксировано в [dep-verify-crates.md](dep-verify-crates.md) §16: `tray-icon`
   берётся с `default-features = false` (linux-дефолт `libappindicator` =
   GTK3-вес, а linux-сборка трея без него физически невозможна — `compile_error`
   в `tray-icon-0.26.1/src/lib.rs:128-138`), linux-джобы CI собирают
   feature-off, win/mac-ноги проверяют feature-on (`just tray-check`).
   Проверка контура — `scripts/verify-bundle.sh` п.5: linux-бандл обязан нести
   юнит и НЕ нести трей-бинарь; win/mac-бандл обязан нести исполняемый
   `bin/fasad-tray`, поднимающийся на `/health` с тем же `stage`.

## Linux: установка systemd-юнита (#140)

Юнит едет в linux-бандле (`contrib/systemd/fasad.service`), статический
(без авто-`enable`). Установка из распакованного бандла (права root, путь
`/usr/local` — не пакетный менеджер, бандл и есть менеджер):

    useradd -r -s /usr/sbin/nologin -d /var/lib/fasad -m fasad
    install -Dm755 bin/fasad /usr/local/bin/fasad
    install -Dm644 contrib/systemd/fasad.service /etc/systemd/system/fasad.service
    systemctl start fasad.service && systemctl status fasad.service

Первичка полей юнита (не конвенция): `MemoryMax=1843M` = SPEC §1 п.3 «≤1.8 ГБ»
(1843.2 MiB в замере `scripts/measure-rss.sh`, округление вниз);
`LimitMEMLOCK=64K` = типичный `RLIMIT_MEMLOCK` дефолтного раннера, vault-пул
34 KiB (`POOL_SLOTS·POOL_SLOT_BYTES` = 16·2176 Б,
`crates/guard-vault/src/token.rs`, const-assert «пул влезает в 64 KiB» держит
связку на компиляции); `Restart=on-failure` + `User=fasad` +
`NoNewPrivileges` — по брифу #140. Конфиг = `EnvironmentFile=-/etc/default/fasad`
(`FASAD_*`, первичка `crates/guard-daemon/src/config.rs`).

## Матрица сборки

`.github/workflows/release.yml`, job `dist` (матрица `include`, `fail-fast: false`):

| runner | triple | архив | контур |
| --- | --- | --- | --- |
| ubuntu-24.04 | x86_64-unknown-linux-gnu | tar.gz | headless + systemd-юнит (#140) |
| windows-2022 | x86_64-pc-windows-msvc | zip | + `bin/fasad-tray.exe` (#128) |
| macos-14 | aarch64-apple-darwin | tar.gz | + `bin/fasad-tray` (#128) |

win/mac-ячейки собирают второй бинарь шагом `just release-build-tray`
(фича `tray`); linux-ячейка его не собирает физически (§16) и несёт
`contrib/systemd/fasad.service`; зуб «бандл несёт контур своей ОС» —
`scripts/verify-bundle.sh` п.5.

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
   (промер тестом `config.rs:756`: `FASAD_BIND=8.8.8.8` → диагностика «loopback»).
2. `FASAD_PORT=0` = «дай свободный порт», баннер печатает фактический адрес
   (`main.rs`, `local_addr`) — на этом трюке ездят `scripts/verify-bundle.sh` и
   `scripts/measure-rss.sh`.
3. Мусор в числовой переменной оставляет дефолт (`config.rs:15`), а откровенно
   битое значение — отказ старта с именем переменной в тексте ошибки
   (первичка `config.rs:718-758`): `FASAD_THREADS=abc` (`:723`),
   `FASAD_TIMEOUT_MS=-1` (`:724`), `FASAD_MAX_BODY_BYTES=0` (`:722`),
   `FASAD_THREADS=0` (`:754`).
4. Переменные (первичка — `crates/guard-daemon/src/config.rs`, строки рядом):

| Переменная | Дефолт | Первичка |
| --- | --- | --- |
| `FASAD_PORT` | 8765 | config.rs:24 |
| `FASAD_BIND` | 127.0.0.1 (только loopback) | config.rs:28 |
| `FASAD_MAX_BODY_BYTES` | 1048576 | config.rs:33 |
| `FASAD_THREADS` | 8 | config.rs:76 |
| `FASAD_TIMEOUT_MS` (исходящие) | 3000 | config.rs:81 |
| `FASAD_READ_TIMEOUT_MS` (входящее тело) | 30000 | config.rs:93 |
| `FASAD_GRAY_LO` / `FASAD_GRAY_HI` | 0.22 / 0.80 | config.rs:59, :62 |
| `FASAD_TAU_LOW` / `FASAD_TAU_HIGH` | 0.20 / 0.80 | guard-onnx/src/routing.rs:70, :74 |
| `FASAD_VAULT_MODE` | stateless-контур; значения `2\|3\|session\|stateless` | config.rs:345 |
| `FASAD_MLOCK` | `strict` (`strict\|best_effort`) | config.rs:128-142 |
| `FASAD_SCHEMA` | встроенный канон (`schema.default.json` в бандле) | config.rs:263, :425 |
| `FASAD_MODEL_DIR` | нет = стадия `cascade-0-only` | config.rs:424 |
| `FASAD_UPSTREAM_ALLOWLIST` | пусто = наружу ходить некуда | config.rs:271, :431 |
| `FASAD_PROXY_LOOPBACK_HTTP` | false | config.rs:277, :432 |

5. Ответы: `/health` (версия, стадия контура, режим залочкивания),
   `/v1/analyze` (массив спанов, поле `entity_type` — промер живого ответа
   21.10), `/v1/anonymize` (`{text, spans}`, спаны берутся из `/v1/analyze`;
   голый `{"text":…}` = 400, `vault.rs::AnonymizeRequest`).
6. Никакой телеметрии: сетевой вызов наружу только по явному
   `FASAD_UPSTREAM_ALLOWLIST` (AGENTS, инварианты).

### Совместимость с main (промер 21.10, PR #76)

Скрипты RAM-гейта и гейта бандла парсят вывод демона, а в main за это время
уехал шаг 7d (#70: метрика целостности разворота в `/health`). Проверено по
исходникам main (`git show origin/main:<файл>`), а не «на глаз по merger'у».
Сравнение «main против базы ветки» — исторический промер #76; номера строк ниже
пересняты grep'ом на текущем дереве (класс #93: влитые PR сдвинули строки):

1. Баннер: `main.rs:92` на main и на базе ветки — одна и та же строка
   «fasad {} {}, listening on http://{}/health (классов схемы: …)», значит
   регэксп порта в `scripts/measure-rss.sh` и `scripts/verify-bundle.sh`
   работает и после слияния.
2. `/health`: на main остаются `version`, `stage` (тест http.rs:764 ждёт
   `cascade-0-only`) и `mode`; наши проверки — подстроковые, новые поля
   (метрика #70) их не ломают.
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

   4a. Тег сверяется с версией (зуб добавлен 21.10, промер посадки ниже по
       тексту). Job `dist` передаёт в `scripts/verify-bundle.sh`
       `FASAD_EXPECT_VERSION=github.ref_name` (только на тег-триггере; на
       `workflow_dispatch` env пуст), и тег `v9.9.9` над
       `[workspace.package] version = 0.1.0` красит контур ДО публикации.
       Строка `VERSION|ok` — это ДВЕ строки, проверка двух независимых
       первичек: `VERSION|ok|ref=…|workspace.package=…` (тег против
       `[workspace.package] version`, `scripts/verify-bundle.sh:99` — метаданные
       до распаковки) и `VERSION|ok|ref=…|daemon=…` (тег против версии,
       вкомпилированной в бинарь бандла, `scripts/verify-bundle.sh:263` —
       «Cargo.toml подняли после сборки» даёт красный именно здесь). Видеть
       одну из двух = не видеть проверки. `VERSION|SKIPPED` = проверка не
       запрошена (локальный прогон без `--expect-version`) — печатается, а не
       молчится. До правки контур пропускал такой тег зелёным: `gh release
       create --verify-tag` сверяет тег с коммитом, версию тега не смотрел никто.
       Пре-релизные теги (`v0.1.0-rc1`) краснеют НАМЕРЕННО: SemVer п.9 их
       допускает, а наш контур сверяет тег со строкой `X.Y.Z` побайтово
       (промер 21.10: `FASAD_EXPECT_VERSION=v0.1.0-rc1` против `0.1.0` = rc=1)
       — релизный контур = чистый `X.Y.Z`, политика RELEASES.md §Политика
       версий п.4.
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
байт в `bin/fasad` = rc 1, ИНН с битой чексуммой в проверочном запросе = rc 1. Посадка зуба
«тег == версия» (п.4a, промер 21.10 на этом дереве): `FASAD_EXPECT_VERSION=v9.9.9`
против `Cargo.toml = 0.1.0` = rc 1 с двумя строками причины; тот же прогон с
`v0.1.0` = rc 0 и ДВУМЯ строками `VERSION|ok` (`…|workspace.package=0.1.0` +
`…|daemon=0.1.0`, п.4a); без аргумента = rc 0 и строка
`VERSION|SKIPPED` (проверка не запрошена — печатается, не молчится). Отрицательный
контроль пре-релизного тега (п.4a): `FASAD_EXPECT_VERSION=v0.1.0-rc1` против
`0.1.0` = rc 1 — красным намеренно, релизный контур принимает чистый `X.Y.Z`.

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
   (`crates/guard-daemon/src/config.rs:76`, дефолт 8); харнеса — `--threads`
   (`spike.rs:158`, дефолт 4). У рычага демона есть граница монтажа (контракт
   AGENTS §3 п.3): на стадии `cascade-0-only` он инертен — разбор `config.rs:423`
   кладёт значение в `cfg.threads`, а единственным потребителем поля в демоне
   оставался тест `config.rs:638`; с монтажом каскадов 1–2 (#87) рычаг жив —
   `cascades.rs:750` берёт `cfg.threads` в `Spec`, и он уходит в
   `LockrExtractor::load(…, threads)` и `DecideArbiter::load(…, threads)`
   (`cascades.rs:867,869`). Номера пересняты grep'ом на этом дереве (класс #93:
   влитые PR сдвинули строки первички #76). `OMP_NUM_THREADS` не рычаг: вендорный
   `libonnxruntime` osx-arm64 без OpenMP, переменную не читает (первичка
   правки к рюлингу — `otool`/`strings`, ревью #73).
2. Каскад-0 (публикуемый бинарь): пик 3.4 MiB (`ps -o rss`) / 1.6 MiB
   (`footprint phys_footprint`) после прогрева. Число потоков этому контуру не
   фактор — по причине п.1 (стадия `cascade-0-only`, рычаг инертен): три прогона
   при `FASAD_THREADS=8` дают 3.3/3.3/3.4 MiB, прогон при `=2` — 3.4 MiB (N=4,
   21.10; прежде здесь стояло одиночное неавторитетное 2.8 — снято по ревью #76,
   F4). На смонтированном пути (#87) это уже не так: там сравнение потоков —
   отдельный промер, docs/model-audit.md §10 п.8. Бюджет SPEC §1 (1843.2 MiB) не
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
   появятся вместе с реализацией метода — не раньше. Само обещание `exit 2`
   промерено 21.10 шимом `uname` (`uname() { echo FreeBSD; }` в начале PATH):
   rc=2 + строка причины в stderr; до правки ревью #98 (R1) та же ветка давала
   rc=1 (`die` = `exit 1`), т.е. `exit 2` тут, в шапке скрипта и в
   `.github/workflows/release.yml:111` был ложью — детали в п.10 а.
6. Метод замера печатается в каждой строке вывода — `RSS|<контур>|<точка>|<MiB>|<метод>`,
   вердикт `BUDGET|<контур>|ok|peak_mib=…|budget_mib=1843.2|tool=…`.
7. Вердикт — не только строка, у него есть код возврата (зуб добавлен 21.10):
   `OVER` любого прогнанного контура = `rc=1` всего `scripts/measure-rss.sh`
   (причина в stderr словом `OVER` + числа пика и бюджета), `ok` = `rc=0`.
   До правки `OVER` печатался, а скрипт выходил нулём, и шаг «RAM-гейт» в
   `.github/workflows/release.yml` зеленел при превышении бюджета (класс
   false-green «print-only landing test», реестр 15/18). Бюджет вынесен в env
   `BUDGET_MIB` (по умолчанию 1843.2 = контракт SPEC §1, CI его не трогает) —
   рычаг нужен, чтобы посадка гейта промерялась живым прогоном без правки кода:
   `BUDGET_MIB=0.001 just measure-rss --skip-build` = rc=1. Тот же зуб
   поставлен `scripts/measure-daemon-rss.sh` (вердикт `over` = rc=1, бюджет
   тем же env); он вне CI-контура и вызывается только как метод промера —
   упоминается в трёх docs (crates/guard-daemon/README.md — раздел про монтаж
   каскадов 1–2, docs/model-audit.md §10 — метод, и этот раздел ниже), но у двух скриптов с одним вердиктом
   обязан быть один код возврата. Числа этого раздела промеров НЕ пересняты:
   правка меняет код возврата, а не методику замера. Валидация `BUDGET_MIB` —
   п.10 б (рычаг без неё был fail-open).
8. Провал не обрезает вывод (ревью #98): хвост печатается на обеих ветках и
   печатается ДО `exit 1` — `OK|measure-rss завершён|gate=ok|…` при проходе,
   `FAIL|measure-rss завершён|gate=OVER|…` при провале. Stdout проваленного
   прогона совпадает со stdout успешного с точностью до вердикт-строк
   (`BUDGET|…` + сам хвост): `rc=1` «вместо хвоста» был бы нечем разбирать.
   Токен хвоста несёт вердикт — напечатать `OK` при rc=1 означало бы завести
   новую ложно-зелёную поверхность (grep `^OK` по stdout даёт OK при провале).
9. rc не зависит от пути вызова: `just measure-rss` (рецепт зовёт скрипт под
   `set -euo pipefail`) и прямой `bash scripts/measure-rss.sh` дают один и тот
   же rc (промер 21.10: обе ветки rc=1 при `BUDGET_MIB=0.001`). Флаг `GATE_FAIL`
   доходит до конца скрипта, потому что контуры вызываются напрямую, а не из
   командной подстановки; на случай refactor-в-подстановку вердикт перечитывается
   из файл-артефакта прогона (бэкстоп; мутационный промер: та же подстановка с
   выключенным бэкстопом даёт `OVER` в stdout при rc=0, с бэкстопом — rc=1).
   Код возврата мерить от самой проверяющей команды (`cmd; echo $?`), а не от
   хвоста пайпа: `cmd | tail -1`/`| tee` отдаёт rc последнего звена = 0 при
   rc=1 скрипта (промер 21.10: этим способом живой гейт выглядит мёртвым).
10. Коды возврата совпадают с обещаниями (ревью #98, R1 + R2, промер 21.10):
    a) `2` = «метод замера не реализован на этой ОС». Раньше ветка
       «неизвестная ОС» звала `die`, а `die` = `exit 1`: двойки в скрипте не
       было ни на каком пути, хотя `exit 2` обещали три места — шапка скрипта,
       комментарий шага RAM-гейта в `.github/workflows/release.yml:111` и п.5
       этого раздела. Ветка печатает причину в stderr и выходит `2` напрямую,
       минуя `die`. Контроль — шим `uname` (`uname() { echo FreeBSD; }`): до
       правки rc=1, после — rc=2 с внятной строкой; пути Darwin/Linux rc не
       меняют (0/1 как были).
    b) env `BUDGET_MIB` валидируется в ОБОИХ скриптах (`measure-rss.sh`,
       `measure-daemon-rss.sh`) по `^[0-9]+([.][0-9]+)?$`; мусор = `rc=1` с
       именем переменной и значением. До валидации рычаг бюджета был
       FAIL-OPEN: вердикт считает `awk` (`p <= b`), а не-числовой `b` делает
       сравнение лексикографическим (не strnum → строковое): «3.4» <= «abc»
       истинно ('3' < 'a'), отсюда `BUDGET_MIB=abc` →
       `BUDGET|cascade0|ok|budget_mib=abc` при rc=0 (в `measure-daemon-rss.sh`
       — `METRIC|budget|abc|verdict|ok`, rc=0; промер awk: `p=3.4 b=abc` →
       `ok`; `b=-1` — strnum → числовое сравнение → `OVER`; `b=1,843.2` —
       строка, «3.4» > «1,843.2» → `OVER`).
       Опечатка в env релизного контура (`1,843.2`) зелёнила гейт при любом
       пике. Политика проекта: мусор в числовом env = отказ, а не молчаливый
       ноль — тот же смысл, что у запуска демона (§«Запуск» п.3:
       `FASAD_THREADS` = `abc`/`0`, `FASAD_TIMEOUT_MS` = `-1` — отказ старта
       с именем переменной, первичка `config.rs:718-758`). Отрицательное, `1.`, `.5`, `1.2.3`, `1e3` — отказ;
       пустое значение = default 1843.2 (`${BUDGET_MIB:-1843.2}`), т.е. отказ
       наказывает только мусор, а не «не задал».

## ORT-контур на macOS (промер, issue #31)

1. Статика pyke (`download-binaries`, default) в **release**-профиле на macOS
   SIGSEGV'ит (docs/model-audit.md §5 п.1, промер ×5, обе конфигурации) —
   релизный путь = официальный dylib (ort-дока
   https://ort.pyke.io/setup/linking: compile-time dynamic = `ORT_LIB_PATH` +
   `ORT_PREFER_DYNAMIC_LINK=1`; рантайм-поиск на macOS — rpath `@loader_path`
   либо каталог рядом с бинарём).
   Голое `cargo build --release --features ort-inference` (без env-префикса) на
   чистой macOS не линкуется: `___isPlatformVersionAtLeast` undefined, CoreML-
   хелпер из pyke-статики (docs/model-audit.md §5 п.2; промер ревью #97, 2-й
   раунд). Команды сборки в этой ветке пишутся с префиксом — рецепт
   §«Как включить монтаж каскадов 1–2» п.1 в `crates/guard-daemon/README.md`.
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
docs/dep-verify-repos.md: строка таблицы `dtolnay/rust-toolchain` (:47) и проза
п.3 «тегов по мажорам нет (только служебный `v1`)» (:197); :45 — строка
`softprops/action-gh-release`, к dtolnay отношения не имеет (ревью #76, D2).
Файл вне этого PR, правка там за его владельцем; та же формулировка в
docs/SPEC.md:331 снята здесь (SPEC вторичен, но ложь в нём — тоже ложь).

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
