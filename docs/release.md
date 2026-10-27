# Релиз fasad (SPEC §10 п.9, шаг 9)

Владелец процедур сборки/упаковки/публикации. Числа RAM — в
[docs/model-audit.md](model-audit.md) §9 «Release RSS» (первичка промеров).
Политика версий — [RELEASES.md](../RELEASES.md).

## Что в бандле

Бандл = **full** (рюлинг оператора 22.10, issue #181: «Нужно только фулл»;
каскад-0-бандл в релизе не продаётся). Каскады 1–2 смонтированы в демон
(#14A, `crates/guard-daemon/src/cascades.rs`), и это свойство бинаря:

1. Релизный бинарь собирается с `ort-inference` (`just release-build`;
   mac-контур — env-префикс dylib, §«ORT-контур на macOS»). При заданном
   `FASAD_MODEL_DIR` (`crates/guard-daemon/src/config.rs:424`) конвейер
   вызывает каскад 1 (`LockrExtractor`) и каскад 2 (`DecideArbiter`);
   смонтировалось — `/health` → `"stage":"cascade-0+models"`
   (`config.rs:457-462`, `cascades.rs:125`).
2. Полный контур = бинарь + веса + `FASAD_MODEL_DIR`. Веса (~879 МБ,
   манифест `models/manifest.tsv`) в архив не входят: бандл несёт
   `scripts/fetch-models.sh` + манифест + `models/README.md` (скачивание по
   commit-шейа со сверкой sha256, fail-closed). Full-бинарь **требует**
   `FASAD_MODEL_DIR`: без весов HEADLESS-бинарь отказывает (`ModelsNotConfigured`,
   код 2, причина + путь докачки в stderr — #185/#199, рюлинг оператора 22.10),
   молчаливой деградации до `cascade-0-only` нет; stage каскад-0-only = харнес/тесты
   (каскад-0-бинарь без фичи), не продакшн-режим. ТРЕЙ-бинарь (win/mac,
   `fasad-tray`) без весов = ОЖИДАЮЩИЙ СТАРТ (#198, замена утверждения #185
   для desktop-контура): UI + `/v1/status` + кнопка «Скачать веса» живы,
   `stage=models-pending`, модельные маршруты = 503 `models_pending` (не
   каскад-0-обман); двойной клик по иконке доходит до кнопки доставки.
   `MessageBox` отказа win-трея (#190) остаётся на НЕмодельных отказах
   (схема/vault/конфиг) и += кнопка «Открыть инструкцию» (#198).
   Полка win-трея (#226, «запустил и забыл»): `fasad-tray.exe` =
   GUI-подсистема (`windows_subsystem` под `all(tray, windows)`: двойной
   клик НЕ открывает консольное окно; console-контракт #185 = headless
   `fasad.exe`, feature-off) · меню = «UI: 127.0.0.1:<порт>» (disabled,
   адрес глазами = фактический привязанный сокет; `FASAD_PORT=0` =
   случайный порт виден там же, где в баннере) + «Открыть fasad UI в
   браузере» + «Выход (graceful)» (graceful-дозапись vault = без изменений)
   ; tooltip = адрес + метрики (`UI 127.0.0.1:<порт> — fasad: …`,
   эм-тире вместо `·` — нит-хвост #228). Live-полка = win-машина: MessageBox на GUI-
   подсистеме (не требует консоли, первичка win.rs #190), отсутствие
   консоли при двойном клике, кликабельность меню; CI-гейт win =
   build-test + tray-check (юниты сборки меню = `tray::tests`).
   Форма «переменная не задана» = та же для unset HOME/USERPROFILE:
   desktop-контур (#192 резолвит каталог по HOME, win — по USERPROFILE)
   при unset = НЕ rc=2, а ожидающий старт трея (решётка `startup_pending*`
   берёт отказ доставки; промер ревью #203 §2.3: `env -i` без HOME на
   трей-бинаре = pending UI). Headless-бинарь при unset HOME = rc=2,
   строка #192 в таблице выше про него и остаётся.
   `FASAD_TEST_CASCADE0=1` (харнес-флаг #185) на feature-off-мишени =
   каскад-0-семантика (харнес легален, дефолт не подставлен). На
   ТРЕЙ-мишени с флагом раньше всходил ALIVE `models-pending` (stage
   харнесу врёт, #203 §2.1); теперь трей+флаг = Some(каталог) при
   СМОНТИРОВАННОМ HOME-дефолте = живой mounted-контур (не pending, не
   каскад-0: трей с весами монтируется, feature-off + трей env-мишень +
   смонтированный кеш = ALIVE `cascade-0+models`), при пустом = каскад-0
   (зуб `pending_flag_on_tray_contour_keeps_the_cascade0_harness` +
   `weights::tests::layout_complete_counts_five_of_five_only` +
   `cascades::tests::pending_gate_is_tray_only_and_model_failures_only`).
   Харнес тестов (`Daemon::start` wire/ui_sandbox) снимает
   `FASAD_TEST_TRAY_CONTOUR` из унаследованной среды (#203 §2.1-блокер:
   прогон на машине с весами = 32/0, не 28/4).
3. Назвал `FASAD_MODEL_DIR`, а смонтировать нечем (бинарь без орт-контура
   или веса битые/отсутствуют) — демон **не стартует**
   (`CascadeFailure::BuiltWithoutInference` / `Load`, `cascades.rs:635-650`);
   молчаливой деградации при обещанных весах нет — fail-open на recall.
4. Проверка контура вшита в гейт (`scripts/verify-bundle.sh`, #181):
   1. ЗУБ А — бинарь бандла содержит орт-контур (mac: `libonnxruntime`
      в динамическом графе — dylib-контракт сборки; linux: маркер орт-статики
      в теле — download-контур ort-sys линкует СТАТИКОЙ, `main.rs:177-183`,
      CI-провен `readelf -d` run 39786761298 = NEEDED без onnxruntime (#188);
      win: маркер EP-либ win-контура (`DirectML`, pyke
      `static_link_prerequisites`, ort-sys `static_link/mod.rs:50-54`) —
      заголовочных путей C++ в PE нет (#188, провен r6/r7 релиз-репетиции);
      PE-доставка =
      `bin/onnxruntime.dll` рядом с exe); mac-бандл несёт dylib 1.31.0 в
      `lib/`, бинари — rpath `@loader_path/../lib`.
   2. ЗУБ Б — live-промер смонтированного контура при доступном кеше весов:
      `stage=cascade-0+models` + `person_name`-спан на ФИО-фикстуре.
      mac-ячейка CI скачивает веса шагом `fetch-models.sh`; win/linux —
      строка `MOUNTED|SKIPPED` с причиной (доставка весов в их CI-контуре не
      смонтирована, #181), доказательства смонтированного контракта там —
      unit-тесты `cascades.rs`.
   3. ЗУБ В — дискриминатор: каскад-0-бинарь при `FASAD_MODEL_DIR` обязан
      отказать стартом (`BuiltWithoutInference`) — против каскад-0-артефакта
      под full-меткой.
   4. ЗУБ Г (#185) — full-бинарь бандла (headless и трей) БЕЗ
      `FASAD_MODEL_DIR` обязан отказать стартом (`ModelsNotConfigured`,
      rc=2, причина в stderr, баннера нет) — против молчаливой деградации
      релиза; строка гейта `REFUSAL|ok`.
   5. Плюс прежние: хэши `SHA256SUMS.txt`, версия архива = версия демона
      (читается из `/health` mounted-ноги — живого каскад-0-сокета в релизе
      нет, #185), тег = версия.
5. Гард метки: `make-bundle.sh` краснеет на `--label cascade-0` — откат
   релизного контура возможен только через смену рюлинга (issue #181), не
   через флаг упаковки.

Следствие для релиза: артефакты именуются `fasad-<version>-<triple>-full.*`.
Метка — дефолт `--label` в `scripts/make-bundle.sh`.

Состав архива (`scripts/make-bundle.sh`):

1. `bin/fasad` (`.exe` на Windows) — `just release-build`
   (`cargo build --release -p guard-daemon --features ort-inference`).
2. `README.md` — сгенерированная ориентировка пользователя + ссылка на репозиторий.
3. `LICENSE` — Apache-2.0 (текст лицензии продукта).
4. `THIRD-PARTY-LICENSES.txt` — `just deps-licenses` (cargo-about, см. ниже).
5. `schema.default.json` — канон схемы классов (`config/schema.default.json`,
   `FASAD_SCHEMA`).
6. `SHA256SUMS.txt` — sha256 всех файлов бандла; рядом с архивом лежит
   `fasad-…-full.<ext>.sha256` (хэш самого архива).
7. `scripts/fetch-models.sh` + `scripts/fetch-models.ps1` (#190: нативная
   win-доставка, паритет `.sh`; во всех бандлах) + `models/manifest.tsv` +
   `models/README.md` — скачивание весов каскадов 1–2 по sha256-манифесту
   (#181; веса в архив не входят, см. п.2 выше). win-README несёт
   PowerShell-первенство (`bin\fasad-tray.exe`, `$env:FASAD_MODEL_DIR`,
   Git-Bash = альтернатива, #190).
8. mac: `lib/libonnxruntime.1.dylib` — официальный dylib 1.31.0 (тот же
   архив и sha256, что проверяет job `ort-dylib`), доставка рантайма внутри
   бандла (`--ort-dir`, rpath-чин install_name_tool); win:
   `bin/onnxruntime.dll` (`--ort-dll`, из pyke-кэша build-контура, доставка
   «рядом с exe»).
9. Платформенный контур запуска (решение оператора 21.10, issue #128):
   **linux-бандл = headless-демон под systemd** (консольный запуск, юнит
   `contrib/systemd/fasad.service` в бандле — #140, бинд loopback по дефолту —
   `config.rs`), трей в linux-артефакт не входит; **win/mac-бандлы несут
   tray-бинарь** `bin/fasad-tray` (features `tray,ort-inference` — #181:
   трей = тот же `main.rs` с монтажом #14A, в full-бандле оба бинаря одного
   контура; иконка статуса — #128 фаза 2, PR-контур
   `crates/guard-daemon/src/tray.rs`: клик = открыть UI браузером ОС, меню =
   «Выход (graceful)» = shutdown-канал демона, tooltip =
   `UI 127.0.0.1:<порт> — fasad: <счётчик отказов> / <stage>` без ПДн
   — #128-контракт видимости, формат зафиксирован юнитом). На стороне зависимостей это
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
| ubuntu-24.04 | x86_64-unknown-linux-gnu | tar.gz | full headless + systemd-юнит (#140) |
| windows-2022 | x86_64-pc-windows-msvc | zip | full + `bin/fasad-tray.exe` + `bin/onnxruntime.dll` (#128/#181); README = win-форма доставки (`scripts\fetch-models.ps1`, #190) |
| macos-14 | aarch64-apple-darwin | tar.gz | full + `bin/fasad-tray` + `lib/libonnxruntime.1.dylib` (#128/#181) |

win/mac-ячейки собирают второй бинарь шагом `just release-build-tray`
(features `tray,ort-inference`); linux-ячейка его не собирает физически (§16)
и несёт `contrib/systemd/fasad.service`; зуб «бандл несёт контур своей ОС» —
`scripts/verify-bundle.sh` п.5, зуб «бинарь = орт-контур» — ЗУБ А того же
скрипта (#181). mac-ячейка дополнительно ставит dylib 1.31.0 (шаг с sha256,
первичка §8 п.3 [model-audit.md](model-audit.md)) и скачивает веса
(`scripts/fetch-models.sh`) для live-промера ЗУБа Б; win/linux-live-промер
смонтрованного контура в CI не смонтирован (доставка весов = +879 МБ на
прогон), риск win/linux-сборок full-контура записан в issue #181: первый
живой промер = ci.yml job `ort-build` (#184/#187, PR-контур; #188 перенёс
первый промер с «тега» на PR — win линкуется, linux = download-статика,
провен run 39786761298).

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
2a. Адрес и порт в UI (#227, LAN-режим = НЕТ по решению оператора): порт =
   поле `FASAD_PORT` вкладки «Настройки» (#224), адрес = read-only строка
   «адрес интерфейса» = `window.location.origin` (эффективный url браузера,
   не догадка про бинд), `FASAD_BIND` = только env: гард без TLS и без
   аутентификации, в LAN его читает кто угодно.
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
| `FASAD_MOUNT_POLL_MS` (интервал hot-mount, #316; 0 = выключен) | 4000 | config.rs `DEFAULT_MOUNT_POLL_MS`, cascades.rs `spawn_mount_poll` |
| `FASAD_GRAY_LO` / `FASAD_GRAY_HI` | 0.22 / 0.80 | config.rs:59, :62 |
| `FASAD_TAU_LOW` / `FASAD_TAU_HIGH` | 0.20 / 0.80 | guard-onnx/src/routing.rs:70, :74 |
| `FASAD_VAULT_MODE` | stateless-контур; значения `2\|3\|session\|stateless` | config.rs:345 |
| `FASAD_MLOCK` | `strict` (`strict\|best_effort`) | config.rs:128-142 |
| `FASAD_SCHEMA` | встроенный канон (`schema.default.json` в бандле) | config.rs:263, :425 |
| `FASAD_MODEL_DIR` | full-бинарь (headless) без него **не стартует** (#185, `ModelsNotConfigured`, текст += путь докачки #199); трей-бинарь (win/mac) = ожидающий UI `models-pending` с кнопкой «Скачать веса» (#198); задан = `cascade-0+models` (отказ старта, если смонтировать нечем) | config.rs, cascades.rs `startup`/`startup_pending*` |
| `FASAD_UPSTREAM_ALLOWLIST` | пусто = наружу ходить некуда | config.rs:271, :431 |
| `FASAD_PROXY_LOOPBACK_HTTP` | false | config.rs:277, :432 |
| `FASAD_FRAME_MIN` | 0.95 (вес каркасного хита #234, рычаг #246, диапазон (0.5, 1]) | config.rs `Config::frame_min`, `DEFAULT_FRAME_MIN` |
| `FASAD_TRANSLIT` | true (1/0; кандидаты серой зоны #238, живут при `α·gray_lo < τ_low`) | config.rs `Config::translit`, pipeline `TranslitCtx` |
| `FASAD_CONFIG` | нет (`%APPDATA%\fasad\config` win / `$XDG_CONFIG_HOME`|`$HOME/.config`/fasad/config unix, mac) | config.rs `config_file_path` (#219) |

4a. Файл конфигурации (#219, #220): приоритет **env > файл > дефолт**; формат
KV `KEY=значение` (собственный парсер, зависимостей ноль — промер
docs/dep-verify-crates.md §17); значения проходят те же валидаторы, что env
(`config::validate_value` = единая точка). Разрешённые ключи = реестр
`config::FILE_ALLOWED_KEYS` (таблица в README §Файл конфигурации); секрет
`FASAD_VAULT_KEY`, бинд, mlock и харнес-флаги в файле = отказ старта. Харнесы
wire_e2e/ui_sandbox изолированы иглой `FASAD_CONFIG=<пустой файл в tmp>`
(E-контур #219: файл оператора не должен протекать в тесты).

5. Модели каскадов 1–2 (контур full, #181): скачивание из каталога бандла —
   `./scripts/fetch-models.sh` (sha256-гейт по `models/manifest.tsv`,
   commit-шейа revision, кеш `~/.cache/fasad-models`, зеркало
   `FASAD_HF_HOST`), затем `export FASAD_MODEL_DIR="$HOME/.cache/fasad-models"`.
   Windows (#190): `\.\scripts\fetch-models.ps1` (кеш
   `$env:USERPROFILE\.cache\fasad-models` = ps1:127); **env с #264 НЕ нужен**:
   кеш-дефолт резолвится по `USERPROFILE` при HOME-unset (двойной клик),
   кнопка «Скачать веса» в UI качает в тот же кеш, перезапуск = смонтирован.
   Явный `$env:FASAD_MODEL_DIR` = override (свой путь), не ритуал (заменяющее
   #182; Git-Bash — альтернатива, кеш тот же). Баннер демона несёт
   строку `UI браузера — http://<порт>/`, `--help` = usage (#191).
   Детали и раскладка — `models/README.md` бандла и §«Как включить монтаж
   каскадов 1–2» в `crates/guard-daemon/README.md` (владелец деталей).
   `FASAD_TIMEOUT_MS=3000` (дефолт) на смонтированном контуре вмещает не
   каждый запрос Decide-серой зоны — на полном тексте держите ≥ 5 000
   (промер ревью #97, `crates/guard-daemon/README.md` §env).
6. Ответы: `/health` (версия, стадия контура, режим залочкивания),
   `/v1/analyze` (массив спанов, поле `entity_type` — промер живого ответа
   21.10), `/v1/anonymize` (`{text, spans}`, спаны берутся из `/v1/analyze`;
   голый `{"text":…}` = 400, `vault.rs::AnonymizeRequest`).
7. Никакой телеметрии: сетевой вызов наружу только по явному
   `FASAD_UPSTREAM_ALLOWLIST` (AGENTS, инварианты). Скачивание весов —
   явное действие пользователя скриптом `fetch-models.sh`, не рантайм.

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
2. `/health`: на main остаются `version`, `stage` (тест http.rs ждёт
   `cascade-0-only` — unit-контур конфига без весов, легальный для feature-off;
   full-бинарь без весов не стартует с #185, живого `cascade-0-only` в релизе
   нет) и `mode`; наши проверки — подстроковые, новые поля
   (метрика #70) их не ломают.
3. Контракт прогрева `/v1/anonymize` = `{text, spans}` (main:
   `vault.rs:141-148`, `spans: Vec<SpanIn>`) — тот же, на нём построен прогрев
   measure-rss.
4. Таблица `FASAD_*` в §Запуск актуальна и после слияния: множество переменных
   в `config.rs` на main и на базе совпадает (`diff` отсортированных списков
   пуст, 16 имён).

## Как выпустить

Порядок публикаций (#181, решение оператора): тег `v0.1.0` ставится ПОСЛЕ
мерджа full-контура, его ревью и проде-тестов релизного контура — артефакты
`-full` светятся только на теге (`release.yml` триггер `push: tags: v*`).

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
прогон артефакты собирает, а релиз не трогает. На dispatch (`ref_name` = имя
ветки) зуб тега↔версии = `VERSION|SKIPPED` (env `FASAD_EXPECT_VERSION` пуст,
release.yml:428); имя артефакта dispatch-прогона несёт версию
`[workspace.package]` (`fasad-0.1.1-<triple>-full.*`), не имя ветки
(make-bundle.sh:126-130). Репетиция v0.1.1 (PR #197, dispatch на ветку v11):
зелёный контур = run 39865012131 (5/5 job, ассеты mac/win/linux, mac-leg
манифест-зуба А + linux/win leg B через `FASAD_CASCADE0_BIN`); красные
предшествующие прогоны 39854576251/39856985952/39858973730/39860315995/
39861721435/39863245106 — латенты #192-контура (HOME-дефолт веса́й в зубах
`env -u FASAD_MODEL_DIR` = `FASAD_TEST_CASCADE0=1`-контур config.rs:419-421;
strings-форма манифест-зуба = живой /v1/status-промер; win-отказ трея =
модальный MessageBoxW #190 = `FASAD_WIN_NO_UI=1` (флаг читается в
`tray/win.rs` с #198; до этого в Rust его НЕ БЫЛО — контракт живал только
в комментарии verify-bundle: латент win-ячейки, закрыт этим PR), каждая строка — в
CHANGELOG v0.1.1.

Прогнать матрицу до слияния нельзя было: `gh workflow run release.yml --ref
<ветка>` отвечал HTTP 404 «workflow release.yml not found on the default
branch» (промер 21.10 на PR #76) — GitHub ищет воркфлоу в дефолтной ветке.
С #188 (воркфлоу живёт в main) репетиция промерена: dispatch run 39791625858
на head PR #189 — `windows-2022`/mac-ячейки dist и `ort-dylib` получают
первый живой промер именно так (публикация на dispatch не срабатывает: job
`release` гейтится тегом). Первый пуш воркфлоу в main = промер 25.10. До
репетиции локально был промерен только macOS-путь: бандл
`fasad-0.1.0-aarch64-apple-darwin-cascade-0.tar.gz`; идентификатор прогона —
строка `SHA256SUMS.txt`:
`854844605ad858c64e7fc1be33e4bf651192a4d0e3948eaddeb250dcde316ce9  fasad-0.1.0-aarch64-apple-darwin-cascade-0.tar.gz`.
Размер архива фактом не подаётся (ревью #76, F6): он не воспроизводится
байт-в-байт, gzip пишет mtime входящих файлов, и четыре сборки одного дерева
21.10 дали четыре разных числа: 1 728 002 Б (прежняя запись в этом абзаце),
1 728 016 Б, 1 727 997 Б и 1 728 001 Б (прогон `just release` на head `43158f7`).
Пересъёмка 22.10 на head `237bd1c` (`just release-build` + `just
release-build-tray` + `make-bundle --tray-binary`, mac-контур #128: бандл
несёт `bin/fasad` + `bin/fasad-tray`, потому в размере он не сравним с
прежней полосой ~1.7 МБ): три упаковки одного дерева дали 3 873 029 /
3 873 030 / 3 873 031 Б — разброс ±1 Б = gzip-mtime, закон абзаца
подтверждён; идентификатор прогона — `SHA256SUMS.txt` архива
`d8c83510d1f34f74e207a52a97616600afbdad5b2545eaf443e5accf1c6c6c1b`.
`shasum -a 256 -c SHA256SUMS.txt` = OK (6/6 файлов); `scripts/verify-bundle.sh` = rc 0 (пересъёмка
22.10: `ANALYZE|spans=1`, `ANALYZE|inn10=ok`, `HEALTH|…stage":"cascade-0-only"…`,
`TRAY|ok|port=60864` — промер ДО #185; после #185 тот же прогон даёт
`REFUSAL|ok|rc=2` + mounted-ногу `HEALTH|mounted|…cascade-0+models…` +
`TRAY|ok|…stage=cascade-0+models`). Позитивные контроли: подменённый
байт в `bin/fasad` = rc 1, ИНН с битой чексуммой в проверочном запросе = rc 1. Посадка зуба
«тег == версия» (п.4a, промер 21.10 на этом дереве; контроль 22.10 на `237bd1c`
повторил все ветки: v9.9.9 = rc 1 с двумя строками причины, пре-релиз
v0.1.0-rc1 = rc 1, `v0.1.0` = rc 0 и ДВУМЯ строками `VERSION|ok`
(`…|workspace.package=0.1.0` + `…|daemon=0.1.0`), без аргумента = rc 0 +
`VERSION|SKIPPED`):
`FASAD_EXPECT_VERSION=v9.9.9`
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
7. Прогон 22.10 на head `237bd1c` (macOS arm64, cargo-about 0.9.2, `just
   deps-licenses` = `cargo about generate -c about.toml --workspace --offline
   --fail about.hbs`, rc=0; артефакт `dist/THIRD-PARTY-LICENSES.txt` sha256
   `9dabadec8c48cc0ac25e175050ca1267cbbc9f0f0309b866114bff5f2ee42c21`, два
   повтора генерации побайтово совпали): 5187 строк (`wc -l`), 174 записи
   «пакет → версия» (формула первички — `grep -c '^  - '`, она же печатается
   в хвосте `just deps-licenses`), 6 лицензионных наборов (Apache-2.0 111,
   MIT 35, ISC 18, BSD-3-Clause 2, CDLA-Permissive-2.0 1, Unicode-3.0 1 —
   блок «Краткий обзор» артефакта; по блокам «Используют:» 168 `used_by`-
   записей, 148 уникальных пар «имя+версия» — счётчики `overview` идут по
   лицензионным множествам, 20 пакетов несут по две лицензии).
   Прежняя запись «прогон 21.10: 6043 строки, 197 записей, 7 наборов (…
   Zlib 2 …)» снята пересъёмкой #106: дерево уехало (с #146 на win/mac
   едет `tray-icon`+`muda`-дерево), Zlib-набора в текущем бандле нет
   (первичка: `grep -ci zlib` по артефакту = 0), наборов 6. Число лицензий
   на Linux-ячейке матрицы (x-cache) не переснималось — промер локальный,
   macOS.

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
2. Каскад-0-контур замера (`just measure-rss` в job dist: каскад-0-артефакт
   (`cargo build --release -p guard-daemon --target-dir target-c0`, фича
   выключена, `FASAD_RSS_TARGET` указывает скрипту на target-c0/release; #185:
   full-бинарь без `FASAD_MODEL_DIR` не стартует — прежняя форма «full-бинарь
   без весов даёт ту же стадию», #181, убита правкой старта):
   пик 3.5 MiB (`ps -o rss`) / 1.7 MiB
   (`footprint phys_footprint`) после прогрева — пересъёмка 22.10 на head
   `237bd1c`, четыре прогона `just measure-rss --cascade0 --skip-build`
   (основной + три повтора), все `peak_mib=3.5`, idle 2.6–2.7/1.4; первичка
   чисел — `--doc-rows`-блок прогона, docs/model-audit.md §9 п.1.
   Число потоков этому контуру не
   фактор — по причине п.1 (стадия `cascade-0-only`, рычаг инертен): три прогона
   при `FASAD_THREADS=8` дают 3.3/3.3/3.4 MiB, прогон при `=2` — 3.4 MiB (N=4,
   21.10, прежняя база, снята пересъёмкой 22.10; прежде здесь стояло
   одиночное неавторитетное 2.8 — снято по ревью #76,
   F4). На смонтированном пути (#87) это уже не так: там сравнение потоков —
   отдельный промер, docs/model-audit.md §10 п.8. Бюджет SPEC §1 (1843.2 MiB) не
   задействован и на 1 %.
3. Полный каскад 1–2 (харнес `spike`, релизный профиль, официальный dylib ORT
   1.31.0): ЧИСЛА ЭТОГО ПУНКТА = МЕДИАНА + ПОЛОСА повторов N=3, а не одиночный
   срез (методика с #170: `just measure-rss --full --skip-build` гонит N=3
   прогона `--threads 2` и печатает `RSS|full|peak_median|…` плюс
   `RSS|full|peak_max|…`; в ГЕЙТ идёт max — семантика консервативной свёртки
   не менялась, в ДОКУМЕНТ идёт медиана).
   Почему так (первичка #168, бисек `f4945c93`, 15 прогонов по t2-CI-методике):
   полоса ОДИНОЧНЫХ срезов 870.3…1816.1 MiB; на ОДНОМ sha разброс до 550 MiB
   (`e02c203` = 870.3 / 1420.9); термик и фон (load1 2.27→4.23) двигают пик
   примерно на +370 MiB. Одиночное число посреди такой полосы = lucky slice и
   в документ не пишется (kernel-закон: «число, вписанное в документ от руки, —
   claim; цифры документа генерируются из артефакта прогона»).
   Данные #168, свёртка по новой методике (медиана из трёх, max — гейт):
   a) `e02c203` — пара 870.3 / 1420.9 (разброс 550.6 = 38.8 % от 1420.9 — худшая
      полоса выборки; N=2, медианы нет);
   b) `HEAD-3` — 1400.6 / 1503.6 / 1775.4 → медиана 1503.6, max 1775.4
      (разброс 374.8 = 25 % от медианы);
   c) контроль-пара `0a1c100` = 1023.8 / 1083.5 / 1425.5 (медиана 1083.5, max
      1425.5) против `e02c203` = 1420.9: ДРЕЙФА КОДА 21.10→22.10 НЕТ,
      culprit-PR не существует — полоса есть шум прогона, а не регресс.
      Прежнее 889.1 (промер 21.10) на этом дереве не воспроизводится НИГДЕ
      (минимум всей выборки 1023.8) — снято как lucky slice.
   ЧИСЛО БЮДЖЕТА v0.1.0 (решение оператора #168) = консервативный max по
   промерам #168 = **1816.1 MiB = 98.5 % бюджета 1843.2 MiB**. Первичка числа:
   худший срез всей выборки #168, `77107c6` (пул 1024, #137) = 1789.6 / 1816.1;
   свёртка N=3 по нему невозможна (N=2), поэтому число перенесено как верх
   полосы. Деление машинное: 1816.1 / 1843.2 = 0.98529 (не «на глаз»).
   Резерв гейта на полный каскад = 27.1 MiB = 1.5 % бюджета: на худшем срезе
   полосы spec-бюджет НЕ превышается, но и запаса нет — число этого контура
   выше 1816.1 ломает план бюджета, и это сигнал на работу над RAM, а не на
   raise бюджета.
   ПОЛОСА: ±250 MiB на одиночный срез (формулировка оператора #168: «методику
   t2-CI как точечное число не использовать»). Число ДИСКЛЕЙМЕРНОЕ и
   округлено В БОЛЬШУЮ сторону от типичного разброса (b) = 374.8 ≈ ±187;
   хвост полосы #168 шире: 550.6 на паре `e02c203`, терминый сдвиг ≈ +370,
   т.е. ±250 описывает типичный разброс повторного прогона, а не его хвост.
   Цитировать число этого пункта без полосы = врать о точности: срез 1816.1 и
   срез 870.3 — один и тот же код.
   Промеры #170 на этом же дереве (head `86f5b58`, `--threads 2`, N=3,
   артефакты прогонов `--doc-rows`, телеметрия машины ~35 % WindowServer —
   термик-фактор п.2 первички #168 жив и здесь):
   a) 1419.6 / 1789.7 / 1790.5 → медиана 1789.7, max 1790.5 (разброс 370.9);
   b) 1402.7 / 1763.1 / 1788.3 → медиана 1763.1, max 1788.3 (разброс 385.6);
   c) 1499.5 / 1549.3 / 1789.9 → медиана 1549.3, max 1789.9 (разброс 290.4).
   Все шесть срезов и все шесть свёрток — в бюджете 1843.2 (верх выборки
   1790.5 = 97.1 % бюджета, резерв 52.7 MiB). Разброс внутри каждой тройки
   (290.4…385.6) и разброс медиан между тройками (1549.3…1789.7 = 240.4) —
   прямое подтверждение правила пункта: медиана ТРЁХ прогонов тоже скачет на
   полосу, поэтому медиана печатается ВСЕГДА вместе с N и с полосой срезов
   (`INFO|full|repeats=…|slices=…`), а гейт считает по max.
   Медиана c) 1549.3 против медианы b) первички 1503.6 (тот же sha HEAD) —
   расхождение 45.7 = 3 % при одном и том же коде: по одному срезу (и даже по
   одной медиане) рост не диагностируется и не опровергается.
   Прежние числа этого пункта (1527.7 / 1524.5, пересъёмка 22.10 на head
   `237bd1c`, и 976.3 / 889.1 промеров 21.10) были ОДИНОЧНЫМИ срезами и сняты
   как lucky slice; разбор сырых строк — docs/model-audit.md §9.
   Метод и сырые строки — docs/model-audit.md §9.
4. Профиль: бюджет-гейт раньше был закрыт dev-числом 1434.6 MiB (docs/model-audit-weights.md §W2.6 п.5);
   релизный профиль 21.10 давал 976.3 («dev = верх» было подтверждено).
   Пересъёмка 22.10 подтверждение ОТЗЫВАЕТ: полный релизный прогон на head
   `540a2ca` (методика #170, N=3, `--threads 2`) — медианы троек
   1504.9…1788.9, max-ы 1786.6/1787.6/1815.3, верх 1815.3 ВЫШЕ dev-числа на
   380.7 MiB (27 %) — оговорка профиля по этой точке не подтверждена, бюджет
   планируем по max релизных прогонов (формулировка синхронна
   docs/model-audit.md §9 п.3; прежнее «1330.6–1527.7» было арифметикой над
   одиночными срезами пересъёмки на `237bd1c` — снята методикой #170).
   П.3 и первичка #168 этот вывод усиливают: верх полосы поднимался до 1816.1
   на том же коде, что давал 870.3, — план бюджета = консервативный max
   повторов (#170), а не «самый красивый срез».
5. Windows: **не промерено**. `scripts/measure-rss.sh` на `MINGW*`/`MSYS*`
   падает exit 2 с явной причиной (реализованы Darwin/Linux); PowerShell-метод
   (`Get-Process` `WorkingSet64`/`PrivateMemorySize64`) не реализован, шаг
   RAM-гейта в `dist` на windows-2022 выключен условием. Числа для Windows
   появятся вместе с реализацией метода — не раньше. Само обещание `exit 2`
   промерено 21.10 шимом `uname` (`uname() { echo FreeBSD; }` в начале PATH):
   rc=2 + строка причины в stderr; до правки ревью #98 (R1) та же ветка давала
   rc=1 (`die` = `exit 1`), т.е. `exit 2` тут, в шапке скрипта и в
   `.github/workflows/release.yml:111` был ложью — детали в п.11 а.
6. Метод замера печатается в каждой строке вывода — `RSS|<контур>|<точка>|<MiB>|<метод>`,
   вердикт `BUDGET|<контур>|ok|peak_mib=…|budget_mib=1843.2|tool=…`.
   Контур `full` с #170 печатает ДВЕ свёртки повторов — `RSS|full|peak_median|…`
   (N = `FASAD_RSS_REPEATS`, default 3) и `RSS|full|peak_max|…`, а его вердикт
   несёт гейт-число в поле `peak_max_mib=` плюс `peak_median_mib=` и `repeats=`:
   `BUDGET|full|ok|peak_max_mib=…|peak_median_mib=…|repeats=3|budget_mib=…|tool=…`.
   Поле `peak_mib=` остаётся у каскада-0 (там повторов нет). Прежнее имя точки
   `peak_both_models` под медиану НЕ переиспользовано: у него задокументированная
   семантика «пик ОДНОГО прогона», подмена смысла под прежним именем = ложно
   зелёное чтение старых строк из новых. Каждая из N сырых точек печатается
   отдельной `RSS|full|peak_both_models|…`-строкой, поэтому арифметика свёрток
   проверяема по артефакту прогона, а `--doc-rows` дописывает полосу срезов
   целиком.
7. Контур `full` с #170 имеет preflight-зуб на dylib-контракт §W2 п.1 ДО
   прогонов: бинарь харнеса спрашивается напрямую (`otool -L` на macOS,
   `readelf -d`/`ldd` на Linux) плюс grep-маркер pyke-статики
   `onnxruntime/core/session` по самому бинарю. Комбинация «статика pyke ЕСТЬ,
   динамического dylib НЕТ» = `rc=2` и строка «spike собран голым контуром
   (pyke-статика, §W2 п.1) — just build-ort»; бинарь, в котором орта нет НИ В
   КАКОЙ форме (релизный каскад-0, `just release-build`, фича `ort-inference`
   выключена) зуб НЕ краснит — одноногая версия «нет dylib = красный» давала
   rc=2 релизному CI-контуру (промер правки; release.yml:135
   `just measure-rss --skip-build`), т.е. чинила один ложно-красный класс
   заводом второго. Тот же зуб стоит в `scripts/measure-daemon-rss.sh`
   (`rc=2` = «артефакт непригоден», рядом с «нет бинаря»; рычаг
   `FASAD_RSS_ORT_PREFLIGHT=0` — промер самого зуба). Первичка зуба —
   #168-бисек signal B и #167 п.4; артефакты red/green-промеров — в теле PR.

8. Вердикт — не только строка, у него есть код возврата (зуб добавлен 21.10):
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
   п.11 б (рычаг без неё был fail-open).
9. Провал не обрезает вывод (ревью #98): хвост печатается на обеих ветках и
   печатается ДО `exit 1` — `OK|measure-rss завершён|gate=ok|…` при проходе,
   `FAIL|measure-rss завершён|gate=OVER|…` при провале. Stdout проваленного
   прогона совпадает со stdout успешного с точностью до вердикт-строк
   (`BUDGET|…` + сам хвост): `rc=1` «вместо хвоста» был бы нечем разбирать.
   Токен хвоста несёт вердикт — напечатать `OK` при rc=1 означало бы завести
   новую ложно-зелёную поверхность (grep `^OK` по stdout даёт OK при провале).
10. rc не зависит от пути вызова: `just measure-rss` (рецепт зовёт скрипт под
   `set -euo pipefail`) и прямой `bash scripts/measure-rss.sh` дают один и тот
   же rc (промер 21.10: обе ветки rc=1 при `BUDGET_MIB=0.001`). Флаг `GATE_FAIL`
   доходит до конца скрипта, потому что контуры вызываются напрямую, а не из
   командной подстановки; на случай refactor-в-подстановку вердикт перечитывается
   из файл-артефакта прогона (бэкстоп; мутационный промер: та же подстановка с
   выключенным бэкстопом даёт `OVER` в stdout при rc=0, с бэкстопом — rc=1).
   Код возврата мерить от самой проверяющей команды (`cmd; echo $?`), а не от
   хвоста пайпа: `cmd | tail -1`/`| tee` отдаёт rc последнего звена = 0 при
   rc=1 скрипта (промер 21.10: этим способом живой гейт выглядит мёртвым).
11. Коды возврата совпадают с обещаниями (ревью #98, R1 + R2, промер 21.10):
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
    в) **Политика rc env-ошибки гейта (решение #178, с 22.10):** битый env
       measure-гейта = «артефакт непригоден» (`rc=2`, класс п.11 а), а НЕ
       превышение бюджета (`rc=1`, п.8). Прежняя легализация «rc=1» (п.11 б
       выше) была последовательна с `die`, но подменяла смысл: `rc=1` у этого
       скрипта несёт слово OVER = «промерен и превысил», и «не промерено»
       становилось неотличимо от «не прошло» ровно там, где опаснее всего —
       релизный контур, идущий дальше по несуществующему промеру (review-
       профиль rc-классификации шире: `uname`-шим п.11 а и preflight-зуб п.7
       за тот же «прогон не начинался» получают двойку). Формулировка:
       env-ошибка гейта = **«не промерено»**, не «не прошло».
       Применение (промер 22.10, все промеры дешёвые — валидация идёт ДО
       прогонов): `BUDGET_MIB=abc` → `rc=2` + stderr «артефакт непригоден:
       BUDGET_MIB=…» (во всех трёх measure-скриптах: `measure-rss.sh` через
       `die_env`, `measure-daemon-rss.sh`, `measure-vault-cap-rss.sh` — тот же
       класс, rc-контракт шапки объявлен общим); `FASAD_RSS_REPEATS=0` /
       `=abc` → `rc=2` + «артефакт непригоден: FASAD_RSS_REPEATS=…»
       (`measure-rss.sh`); `SESSIONS`/`REQS`/`THREADS` не-числа в
       `measure-vault-cap-rss.sh` — туда же. Зубы прежних классов НЕ съехали:
       шим `uname`=FreeBSD → `rc=2` (п.11 а), `BUDGET_MIB=0.001` при живом
       бинаре → OVER `rc=1` (п.8, промер 22.10), пустое `BUDGET_MIB` →
       default 1843.2 → `rc=0` (промер 22.10: 0.45 c против 0.01 c у
       env-отказа, т.е. валидация действительно первая).
       Через `die` это выходить не могло: `die` = `exit 1` — ровно та причина,
       по которой ОС-ветка (#98 R1) выходит двойкой напрямую. Синхронизированы
       шапки всех трёх скриптов (rc-контракты в комментариях — носители
       обещания, как шапка `measure-rss.sh` из п.11 а).

## ORT-контур на macOS (промер, issue #31)

1. Статика pyke (`download-binaries`, default) в **release**-профиле на macOS
   SIGSEGV'ит (docs/model-audit-weights.md §W2 п.1, промер ×5, обе конфигурации) —
   релизный путь = официальный dylib (ort-дока
   https://ort.pyke.io/setup/linking: compile-time dynamic = `ORT_LIB_PATH` +
   `ORT_PREFER_DYNAMIC_LINK=1`; рантайм-поиск на macOS — rpath `@loader_path`
   либо каталог рядом с бинарём).
   Голое `cargo build --release --features ort-inference` (без env-префикса) на
   чистой macOS не линкуется: `___isPlatformVersionAtLeast` undefined, CoreML-
   хелпер из pyke-статики (docs/model-audit-weights.md §W2 п.2; промер ревью #97, 2-й
   раунд). Команды сборки в этой ветке пишутся с префиксом — рецепт
   §«Как включить монтаж каскадов 1–2» п.1 в `crates/guard-daemon/README.md`.
2. Фактическая сборка промерена 21.10 на macOS arm64 (rustc 1.99.1):
   `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib cargo build --release --features ort-inference --example spike`
   = exit 0 за 4m05s, линкуется на `libonnxruntime.1.31.0.dylib`, полный
   прогон `--arb-budget --arb --lockr` = exit 0 (числа RAM — §9).
   Контроль 22.10 на head `237bd1c`: та же команда = rc 0; `otool -L`
   target/release/examples/spike → `@rpath/libonnxruntime.1.dylib (current
   version 1.31.0)`; полный харнес-прогон = rc 0 (числа — §9 пересъёмки).
   Пара контроля (п.1 этого же раздела, два binary-пути, 22.10): голый
   `cargo build --release -p guard-daemon --features ort-inference` (без
   env-префикса) падает в линке ровно на обещанном символе — `ld: Undefined
   symbols: ___isPlatformVersionAtLeast ... host_utils.mm.o` (pyke-статика,
   §W2 п.2); тот же голый путь для example-цели
   `cargo build --release --features ort-inference --example spike` линкуется
   (rc 0): build.rs крейта даёт example-цели
   `-Wl,-undefined,dynamic_lookup` (`crates/guard-onnx/build.rs:102`), и
   хелпер резолвится в рантайме из dlopen'нутого орт-контура; у bin-цели
   этого link-arg нет — отсюда падение. Голый example-путь остаётся
   pyke-статическим (release-SIGSEGV-контракт п.1, §W2 п.1), в релизную
   методику не входит: `just build-ort`/`measure-rss --full` собирают и
   гоняют example с префиксом.
3. В CI это закрыто job `ort-dylib` (macos-14 + ubuntu-24.04): скачивание
   официального архива v1.31.0, сверка sha256 (первичка §8 п.3; mac-форма =
   hex-сверка `shasum -a 256`, linux-нога сверки = GNU `sha256sum -c`),
   `just build-ort`, проверка `otool -L`/`ldd` на наличие dylib в load
   commands. Латент #188 (найдён релиз-репетицией, провен run 39791625858
   обе ноги): шаг давал `ORT_DIR=<корень архива>` против контракта рецепта
   `ORT_LIB_PATH="${ORT_DIR}/lib"` (justfile:487) → линкер искал библиотеку не
   в том каталоге; форма починена, job на обеих ногах = живой промер
   динамик-линка spike. linux-РЕЛИЗ при этом = download-статика dist-матрицы
   (не dylib, main.rs:177-183; ram-мера харнеса меряется на mac, §9;
   динамик-контур linux = отдельное решение оператора).
4. Windows-ячейка матрицы ort-проверки **не** содержит: в ort-доке доставка
   dll на Windows = «в PATH или рядом с exe» (там же), а промера Windows-пути
   в этой сессии не было. Компильная проверка ort-фичи на Windows есть в
   `ci.yml` (`cargo clippy -p guard-onnx --all-targets --features ort-inference`
   в матрице обеих ОС).
5. Релизный бандл `full` несёт библиотеку рантайма: mac —
   `lib/libonnxruntime.1.dylib` (официальный архив 1.31.0, sha256 §8 п.3; CI
   скачивает шаг-в-шаг с job `ort-dylib`, `make-bundle.sh --ort-dir`;
   бинари получают rpath `@loader_path/../lib` — `install_name_tool
   -add_rpath`, промер `otool -L` в make-bundle/verify-bundle ЗУБ А), win —
   `bin/onnxruntime.dll` рядом с exe (PE-локатор, доставка pyke-кэша
   build-контура `copy-dylibs`, `--ort-dll`; путь dll = КОРЕНЬ `target/` —
   `vars::target_dir()`, первичка ort-sys `build/vars.rs:32-42` +
   `build/dynamic_link.rs:14-20`, CI-провен win-нога run 39786761298: dll НЕ в
   `target/release/`; релизный win-шаг берёт из корня, #188). SPEC §9
   (`libonnxruntime.so`/`onnxruntime.dll` рядом) жив: модельный путь в демоне
   смонтирован (#14A), бандл full (#181). linux: СТАТИКА — download-контур
   ort-sys линкует орт статическим архивом (первичка ort-sys
   `build/main.rs:177-183`: `static_link_prerequisites` +
   `rustc-link-lib=static=onnxruntime`), в ELF-графе onnxruntime НЕТ —
   CI-провен `readelf -d`/`ldd` run 39786761298 (ort-build linux, NEEDED =
   libstdc++/libgcc_s/libm/libc/ld-linux, .so нет); прежняя формулировка
   «динамическая зависимость» (readelf-нога ЗУБа А) была ЛОЖНОЙ для этого
   контура и краснила гейт ложно (#188: linux-нога ЗУБа А = маркер-форма
   win-ноги, `LC_ALL=C grep -a 'onnxruntime/core/session'`). Доставка
   `libonnxruntime.so` в архив не смонтирована и не нужна статике;
   динамик-контур linux = отдельное решение оператора, не #188. Первый живой
   linux-промер full-контура = ci.yml `ort-build` (#184/#187, PR-контур).

## Пины action'ов (промер 21.10, `gh api repos/<owner>/<repo>/releases/latest`; пересъёмка 22.10 на head `237bd1c`)

| action | пин в release.yml | живой latest на момент промера |
| --- | --- | --- |
| actions/checkout | `3d3c42e5…` # v7.0.1 | v7.0.1 |
| actions/upload-artifact | `cf430e03…` # v7.0.2 | v7.0.2 |
| actions/download-artifact | `9000827c…` # v8.0.2 | v8.0.2 |
| Swatinem/rust-cache | `d1527c8f…` # v2.9.3 | v2.9.3 |
| taiki-e/install-action | `8cca0918…` # v2.87.29 | **v2.87.30** (пересъёмка 22.10: latest уехал на патч; пин `8cca0918…` = v2.87.29 валиден, апгрейд пина — не этот PR) |
| dtolnay/rust-toolchain | `b725eda5…` («toolchain: stable», 2026-10-16) | v1 |

Пин dtolnay/rust-toolchain сделан коммитом осознанно: moving-тег `v1` существует
(`releases/latest` = v1, `git/ref/tags/v1` → commit `683b588c487a`, промер 21.10; пересъёмка 22.10: `releases/latest` = v1, тот же sha `683b588c487a`),
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
4. Модельный путь в демоне — смонтирован (#14A), релизный контур = full
   (#181): бандл несёт орт-бинари + доставку рантайма + инструкцию весов.
   Не смонтировано: доставка весов в win/linux-ячейки CI (879 МБ на прогон;
   mac-ячейка промеряет смонтированный контур живьём, verify ЗУБ Б).
5. Windows-метод RAM-гейта — не реализован (см. §RAM п.5).
6. Подпись артефактов (cosign/sigstore, attestation) — не делалась.
7. Идемпотентность публикации: повторный прогон по существующему релизу
   краснеет (HTTP 422) вместо обновления ассетов — см. §«Как выпустить», п.6.

## Полка каскад-0-промера релизного бандла (25.10, v0.1.5)

Релизный бандл (`-full`) = bin-цель с `ort-inference` (release-build-tray,
#181/#128): полный контур. На нём харнес-флаг `FASAD_TEST_CASCADE0` НЕ делает
каскад-0-сервер: env-граница config.rs:1051-1073 отключает только подстановку
дефолта `FASAD_MODEL_DIR` (ветки 1073/1128), а монтаж каскадов на full-бинаре
требует реальные веса — `cascades.rs:707` (`is_ok() → Ok(())`) живёт в ветке
`BuiltWithoutInference` = контур feature-off бинаря, на full-артефакте он не
срабатывает. Попытка «release binary + FASAD_TEST_CASCADE0 + пустой/без
model_dir» = честные отказы rc=2 («FASAD_MODEL_DIR не задан» / Load) и 503
models_pending (трей) = ЗУБ Г, не дефект.
Каскад-0-семантику релизного артефакта мёрят: (1) CI verify-bundle ЗУБ Б
(mac, смонтированный контур, `/v1/analyze` mounted-нога), (2) локально на
машине с весовым кешем `~/.cache/fasad-models` (879 МБ, fetch-models) без
харнес-флагов, (3) debug-бинарь feature-off = харнес-контур (wire_e2e).

## Полка win-трея #244 (25.10, v0.1.5-b): тихая смерть иконки при живом процессе

Первичка диагноза (issue #244, коммент родителя 6399041556):

1. КОРЕНЬ-кандидат (подтверждён первичкой крейта, не live-промером):
   tray-icon-0.26.1 README:12 / lib.rs «Platform-specific notes»:17 — «On
   Windows … an event loop must be running on the thread» (win-бэкенд не
   самодостаточен; KSNI-исключение = только Linux). Контур `poll_once` =
   `recv_timeout` на crossbeam-канале, НЕ разбор win-очереди: без pump'а
   сообщения скрытого окна крейта не обрабатываются = иконка не заводится /
   не живёт, процесс «висит» с мёртвой витриной. mac-полка #128 работала:
   cocoa-контур доставляет в канал сам. v0.1.3-полка оператора («иконка
   была») = live-провен той же ветки без pump: live-причина регресса
   решёткой не покрыта (полка v0.1.5), pump = требование первички.
2. Ветка «трей недоступен: {e}» (tray.rs:349-355) = тихая: под
   GUI-подсистемой (#226/#228) stderr = NULL — процесс жив, иконки нет,
   причина невидима. Чин: лог-файл + MessageBox (`win::show_tray_failure`).
3. Bind-отказ (порт занят) = `?` в main = exit без окна (не config-ветка) =
   тихая смерть под GUI: переведён в refusal-контур (окно + лог + rc=2).
4. GUID/второй экземпляр (кандидат ТЗ): ПЕРВИЧКА tray-icon-0.26.1
   platform_impl/windows/mod.rs:164 — `NIM_ADD` при FALSE = НЕ отказ
   (окно живёт, ждёт TaskbarCreated); отказ `build()` = `CreateWindowExW`
   = null (per-process, GUID-коллизией не вызывается); `TrayIconId::new
   ("fasad")` = логический id (tray_icon_id.rs), win-регистрация = GUID
   (`NIF_GUID`). Второй процесс тихо не падает: bind-отказ = пункт 3.
   Single-instance mutex = на полку (контра «второй запуск = окно «fasad
   уже запущен»» не блокирует #244-чин).
5. Payload-иконка (#229-подозрение): 32×32 RGBA, `CreateIcon`-контра
   (windows/icon.rs:31-53) — легальна, вины не найдено.

Чин: (1) win-контур трея = `TrayIconEvent::set_event_handler` (штатный
встроенный контур крейта, lib.rs:885-898; первичка: обработчик вызывается
НАПРЯМУЮ из wndproc'а = поток создателя окна = наш поток; канал обходится) +
`pump_win`-цикл (MenuEvent-чтение + tooltip-тик + shutdown-флаг); mac-контур
`poll_once` НЕ тронут. (2) log-файл `<config-root>/fasad-tray.log`
(win = `%APPDATA%\fasad\...`, mac/linux = `$XDG_CONFIG_HOME/fasad`/
`$HOME/.config/fasad` — #263: контур ОС-независим под `tray`-фичей, первичка
mac-ассета v0.1.6 = 0 следов; append, ротация 5 МБ + слой `.1`, env
`FASAD_TRAY_LOG` = харнес-оверрайд): startup/warning/refuse/serve-fatal/
трей-отказ — все тексты GUI-контура.
(3) `show_tray_failure` = `MB_ICONWARNING|MB_TOPMOST|MB_OK` с причиной,
адресом UI и путём лога; блокирует только поток трея (serve = рабочий поток,
первичка main.rs). (4) bind/serve-смерть = окно. Зубы: unit-контра log-
пути/формата/ротации (`tray::traylog`, cfg-нейтрально с #263 — меряется на
любой ноге; win-канон = прямая формула + `cfg!(windows)`-лег), строка-зуб
`grep -ac fasad-tray.log` в бинаре трея (release.yml, win/mac — дискриминатор
#263: на базе mac = 0, win = 1; `strings`-форма убита #265b: binutils-strings
win-раннера + MSVC strip = 0 на живом бинаре = ложно-красный), FASAD_WIN_NO_UI-контра
headless-ноги, compile-гейт win = CI build-test/tray-check (ring/cc локально
недостижим — урок #228). Полка v0.1.5-b: живая win-нога — иконка, лог,
окно при отказе; второй экземпляр = bind-окно rc=2.


## Полка win-иконки #336 (28.10, v0.1.10): «иконка была с окном терминала» = console-бинарь

1. Операторская первичка: иконка «была, когда запускал из консоли» = запускался
   `fasad.exe` (console-бинарь: окно = stderr-тексты, #185), а иконку ставит
   `tray::run` только в `fasad-tray.exe` (GUI-подсистема, консоли нет = #226
   7e9cd9f). Иконки в консольном запуске НЕ БЫЛО никогда = ∅-дефект продукта,
   дефект README-диагноза.
2. Чин = заменяющая строка в README бандла (§Запуск win + §Запуск mac +
   desktop-полка + README.md §win/mac-трей): «иконка в трее =
   `bin\fasad-tray.exe`; `bin\fasad.exe` = консольный сервер (тексты в
   консоль, иконки нет = не дефект)». Зуб = `ui_sandbox::shelf_tray_icon_diagnosis`
   (grep-контра heredoc-источника make-bundle.sh, ветки is_win/Darwin; linux =
   headless systemd #140 = полка не печатается; мута-контра: удалить строку =
   зуб краснеет). Ветвь «запускал именно fasad-tray.exe» = диагностический
   зуб #244 (`%APPDATA%\fasad\fasad-tray.log`).

## Полка win-иконки #313 (26.10, v0.1.8): повтор «иконки нет» = RGBA-первичка

Повторный live-report оператора (bin\fasad-tray.exe из бандла v0.1.8,
«иконки так и нет»). Ветви ТЗ разделены промером:

1. **Payload-контур (status_rgba) = ЗДОРОВ, промер пикселей.** Генератор
   `tray.rs::status_rgba` (unit, headless): инвентарь альфы 32×32 = 709
   пикселей alpha=255 (тело-диск радиуса 15 + белое ядро 5.5) и 315 alpha=0
   (углы скругления + кольцевой зазор), значений вне {0, 255} = 0; средняя
   строка = непрерывная полоса x∈1..=29 (диаметр 30 px). Зуб
   `rgba_alpha_inventory_is_binary_with_opaque_core_and_ring` (полный
   инвентарь, не углы-выборка) — обе палитры (OK/ALARM).
2. **Первичка крейта (tray-icon 0.26.1, `platform_impl/windows/icon.rs:28-53`):**
   `into_windows_icon` = and_mask = `a.wrapping_sub(255)` (инверсия альфы) +
   BGRA-swap + `CreateIcon(…, 1, 32bpp, and_mask, rgba)`. 32bpp-путь CreateIcon
   (alpha в маске, `hBits` из RGBA): пиксели alpha=0 невидимы, alpha=255 =
   цвет. 709/1024 (69 %) непрозрачных = иконка обязана рисоваться;
   «полностью прозрачная иконка» (0 opaque) = класс, который ЗУБ закрывает
   (assert непрозрачных ≥ половины + центр/край диска = 255). Вина payload
   промёржена = НЕТ (п.1) — lesson #229 («легальна, вины не найдено»)
   подтверждён на v0.1.8-дере.
3. **Win11-класс (свёрнутая область) = README-контра, не чин.** Строка
   бандл-README «иконка не появилась, процесс жив → скрыта в свёрнутой
   области (стрелка ▲; Параметры → Уведомления → выборочные значки)» влита
   #309/#311 (make-bundle.sh:575-579).
4. **Live-приёмник = оператор:** скрин трей-области (▲ раскрыт), задачи
   (`fasad-tray.exe` в Process list), `type %APPDATA%\fasad\fasad-tray.log`
   (строки startup/трей-отказ = #244-контур: «трей недоступен: {e}» +
   MessageBox при крейте). ПЕРВИЧКА оператора 26.10 = http://192.168.1.119:8917.
   Локальных win-сборок у нас нет (ring/cc = CI, урок #228) — win-live =
   только приёмник.
5. **Кандидат-чин «alpha 255 везде» НЕ взят:** промер п.1 = alpha-контра
   легальна для CreateIcon (69 % непрозрачных = видимая иконка), сплошной
   квадрат = откат контракта «скругление без чёрной рамки» (unit-зуб углов)
   без первички-причины. Если операторский скрин покажет иконку В ТРЕЕ при
   alpha-контрактной форме (т.е. форма «слишком тонкая» = 315 прозрачных
   пикселей на 16-px рендере) — следующий атом = залить фон скругления
   (сплошной диск 31 px), зуб-инвентарь это переживёт (assert >= половины).

Ref #313 (#251 #244 #309 #311 #229).
