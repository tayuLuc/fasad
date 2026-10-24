# Changelog

Факты. Одна строка = одно изменение. Источник записей = влитые PR (#номер).
Формат: Added / Changed / Fixed / Removed (Keep a Changelog, секции = версии).
Правила: заменяющие утверждения (ruling #182); даты = дата влития; числа = артефакт прогона.

## v0.1.2 (2026-10-24)

### Added
- Ожидающий старт трей-контура (#198): `fasad-tray` (win/mac) без весов НЕ отказывает rc=2 — поднимает UI (`stage=models-pending`, `/v1/status`+кнопка «Скачать веса» живы), модельные маршруты (`/v1/analyze`, `/v1/anonymize`, `/v1/deanonymize`, прокси) = 503 `models_pending` (не молчание, не каскад-0-обман #185); headless `fasad` = прежний rc=2 (prod fail-closed цел, решётка `cascades::startup_pending*` unit-контуром); `MessageBox` отказа (win, #190) += кнопка «Открыть инструкцию» (`MB_ABORTRETRYIGNORE`, canvas-кнопка недосягаема в `MessageBoxW` — Retry-канал, первичка win-API); UI-баннер ожидающего режима + шаги «(нужны веса)».
- UI-песочница #202: демо-документ «Пример» (2.5 КБ деловое письмо, все 8 классов схемы + формы #200/транслит-пара = витрина границ детектора, автозаполнение при первом открытии с localStorage-флагом) + панель «В свой AI-чат»: поле upstream (X-Upstream-URL allowlist #68, localStorage) + «В чат через прокси» (SSE-поток #68 по мере генерации) + «Раскрыть ответ» (деанон ответа ИИ, строка «токенов раскрыто: N») = ручная проверка оператора «смысл цел, ПДн нет» за 60 секунд (README §1); прокси-контур не дублирован — UI = клиент существующего маршрута.
- UI-песочница #201: нумерованные шаги 1-2-3 над кнопками (очередь читается, неактивные = disabled + title-причина), ДВА окна результата («Что ушло (обезличено)» + «Исходник вернулся», roundtrip не затирает; строка «побайтово совпал: ДА/НЕТ»), «Скопировать обезличенный» (clipboard API + textarea-fallback, CSP-clean), «Сброс сессии» → «Новая сессия», status-полоса крупнее; строка режима vault человекочитая + подсказка (`FASAD_VAULT_MODE=session` = путь смены, режим = env-конфиг не запрос — UI не переключает молча).
- Текст отказа старта (#199) называет ПУТЬ докачки: «скачай веса: UI (→ «Скачать веса») или scripts/fetch-models.sh / .ps1» — в `CascadeFailure::{Load, ModelsNotConfigured}` (unit-зуб), в stderr `refuse_startup` и в `MessageBox`.

### Fixed
- win.rs (#205, хвост ревью #203 §2.3): `IDIGNORE` объявлен константой (`const IDIGNORE: i32 = 5;`), `debug_assert`-решётка читает `IDABORT | IDRETRY | IDIGNORE` вместо литерала `5` (литерал мёртв для имени), doc-текст «Используется ОБА» приведён к факту решётки (читаются все три: IDRETRY = инструкция, IDABORT = debug_assert-контракт, IDIGNORE = X = уход молча). Прежняя строка CHANGELOG (#203) обещала эту правку, файла в диффе не было (класс «diff-unproven claim», кандидат 33).
- `CascadeFailure::ModelsNotConfigured` Display (#206, хвост #199): unit-зубы содержания вне `ort-inference`-гейта — текст отказа называет ОБА канала докачки весов (UI `http://127.0.0.1:<порт>/` → «Скачать веса» + `scripts/fetch-models.sh`, win: `scripts\fetch-models.ps1`); Load-контур-зуб #203 не тронут.
- Харнес-контур #203 §2.1 (блокер R4): харнесы wire_e2e/ui_sandbox снимают `FASAD_TEST_TRAY_CONTOUR` из унаследованной среды (`Daemon::start` + прямой спавн): на машине с смонтированным HOME-кешем унаследованный флаг + симметрия config.rs = Some(кеш) = харнес 28/4 красным (дискриминатор промерен: отравленный env = 32/0 после фикса); release.md-формулировка «на ЛЮБОЙ мишени» приведена к факту решётки (трей+флаг+смонт.кеш = ALIVE mounted). Ссылки config.rs на несуществующий `test_cascade0_flag_disables_every_default` → реальные зубы (рецидив §2.4).
- UI-чат #202 (ревью #203 §4): «Раскрыть вставленный» = ручной цикл полного документа (поле вставки ответа из своего чата; прокси-кнопка = короткие куски, бюджет = подмены в окне экстрактора #84: промер ≲3 stateless / ≲12 session), подсказка в панели + README §1 оба пути. Счётчик «токенов» чата теперь считает ОБЕ формы меток (паттерн с `#` не видел `[КЛАСС_н_nonce]` = «токенов раскрыто: 0» при N подмен в session-режиме, первичка vault.rs:12); JS-зуб `chat_token_counter_counts_both_forms` (node/JXA fixture-раннер); форма session-метки = ЗАГЛАВНЫЙ класс (`Grammar::LABEL` алфавит A-Z0-9_, vault.rs:240/914; живой промер: `[PERSON_NAME_1_SOHIKRAL]` ×48, паттерн по строчным schema-id = 0 = та же ложь нулём; regex `(?i)`).
- `FASAD_TEST_CASCADE0=1` на трей-мишени = ALIVE `models-pending` (stage харнесу врал, ревью #203 §2.1) — флаг симметричен: каскад-0-семантика на любой мишени, Some(каталог) = смонтированный HOME-дефолт (зуб `layout_complete_counts_five_of_five_only`).
- win.rs: дубль комментария style + тавтология `answer == IDRETRY && answer != IDABORT` (4≠3 всегда, §2.2). release.md: «HOME unset» = факт решётки (трей = pending, headless = rc=2, §2.3); config.rs-ссылка на несуществующий тест → реальные имена (§2.4).
- Транзитив `ctutils` 0.4.2 → 0.4.5 (`cargo update ctutils`): RUSTSEC-2026-0385 (non-constant-time mask, crypto-failure, первичка advisory-db: patched >=0.4.4) — красный `just deny` CI-провен run 40020710741; `ignore`-список deny.toml остался пустым (контур «дыра краснит, не заминается»).
- ЗУБ Г (трей) verify-bundle: win-контур отказа = ожидающий UI (#198), unix/mac-нога = живой промер pending (stage/503/витрина); SKIPPED-контур win = стенд #197.
- Баннер ожидающего старта печатает честный stage (`models-pending`), а не `cfg.stage()` (промер mac: `cascade-0+models` на несмонтированном = ложь витрины, поймано живым прогоном этой сессии).

## v0.1.1 (2026-10-22)

### Added
- UX первого запуска (#192): карточка «Веса моделей» в UI (`GET /v1/status`: путь default/факт, наличие 5 файлов layout + размер против манифеста, revision lockR/Decide из **вшитого** `models/manifest.tsv`, stage/mode/vault) + кнопка «Скачать веса» (`POST /v1/models/fetch`: один job, повтор 409, прогресс-байты поллом, `.part`+rename, sha256+размер fail-closed — второй санкционированный сетевой модуль `src/fetch.rs`, URL только из манифеста + env `FASAD_HF_HOST`, redirect = один шаг на HF-CDN); дефолт `FASAD_MODEL_DIR` = `$HOME/.cache/fasad-models` при unset (win: `%USERPROFILE%` через Git-Bash/ps1-контракт; HOME unset = `None` = прежний отказ старта текстом #185).
- win-доставка веса́й: `scripts/fetch-models.ps1` (PowerShell 5.1+, паритет `.sh`: манифест / `Get-FileHash` sha256-гейт fail-closed / rev-URL / кеш-раскладка идентична / `-List` без сети; `TBD`-контур и resume — только в `.sh`, названо в шапке), win-секции README бандла (PowerShell-первенство, `bin\fasad-tray.exe`, Git-Bash = альтернатива) — #190; CI win-ячейка ort-build: `-List` + mock-промер (малый файл HF, sha256-ok, повтор без сети через hosts-глушилку) + red-контроль «битый sha = rc1».
- win-трей: отказ старта показан `MessageBox` (текст причины #185; остров `src/tray/win.rs`, `windows-sys` target-gated = пакет уже в дереве tray-icon, `net_audit` fact-5 += «windows» в linux-дереве фичи = ноль) — #190 (v0.1.0: промер оператора — stderr двойного клика уходит в никуда).
- UX первого запуска (#191): `--help`/`-h` = usage (env-таблица + UI-адрес), НЕ-флаг аргумент = exit 2 + usage в stderr (argv читается впервые; первичка: молчаливое игнорирование); строка `UI — http://<порт>/` в стартовом баннере (парсер `wire_e2e` не тронут); клик по трею = браузер с UI (win/mac) — был и в v0.1.0 (`tray.rs::open_browser_command`: win `cmd /C start`, mac `/usr/bin/open`), закрыт промером тестов/доков, кода не потребовало.

### Fixed
- Релизный контур v0.1.1-репетиции (dispatch run 39854576251, латент #192): `env -u FASAD_MODEL_DIR` в зубе #185 (`release.yml`) и зубе Г (`verify-bundle.sh`) на машине с `HOME` перестал быть отказом — дефолт `~/.cache/fasad-models` (config.rs:422-426) вставал на снятую переменную (mac-нога поднималась `stage=cascade-0+models` на кеше шага fetch-models, win/linux падали с текстом HOME-пути вместо `FASAD_MODEL_DIR`); зубы переведены на тестовый контракт env-границы `FASAD_TEST_CASCADE0=1` (config.rs:419-421) — контракт #185 «переменная не названа» без HOME-подстановки.
- Релизный контур до первого тега (#188, латенты из эскалаций #184/#187): mac-шаги `release.yml` — `sha256sum: command not found` rc=127 на macos-14 (провен run 39784396502) → hex-сверка `shasum -a 256` (форма ort-build, прообраз зелёный); win-шаг `onnxruntime.dll` — ложно-красный путь `target/release/` → корень `target/` (`vars::target_dir`, первичка ort-sys `vars.rs:32` + CI-провен run 39786761298); linux-контур — «динамическая зависимость» было ЛОЖНЫМ (download-контур = СТАТИКА, ort-sys `main.rs:177-183`, CI-провен readelf run 39786761298) → linux = статика, ЗУБ А verify-bundle = маркер-форма win-ноги, readelf-шаг матрицы = запись ELF-графа (INFO), docs/§Матрица синхронны.
- Найденные релиз-репетицией (#188, dispatch run 39791625858 — workflow `release` исполнен впервые): `just dist` на linux падал на трей-зависимости (tray-icon compile_error, §16) — трей-сборка перенесена в mac/win uname-ветку рецепта; spike-нога `ort-dylib` (linux) линковала `-lonnxruntime` против корня архива (so лежит в `<архив>/lib`) при mac-only обвязке dynamic_lookup (build.rs:99) — linux-нога харнеса снята как не-контракт (ram-контур = mac, §9), mac-нога = dylib-dlopen-контракт.
- ЗУБ Г (трей) verify-bundle на win-CI: отказ старта трея = модальное `MessageBoxW` (#190, `main.rs::refuse_startup` cfg(tray,windows)) — процесс живёт в окне дольше любой ready-таймер-окна (провены r5/r6 runs 39861721435/39863245106); зуб = `FASAD_WIN_NO_UI=1` (контракт windows-rust), win-CI без флага = `REFUSAL|SKIPPED|tray` с причиной, headless ЗУБ Г на win зелёный = тот же #185-контур.
- Язык-гейт `just check` красен на main (4 хита `lang-scan`): склейка кириллицы с латиницей в комментариях `ci.yml:134/149`, `crates/guard-daemon/Cargo.toml:122`, `scripts/make-bundle.sh:155` (влиты #188/#189/#193) → написание исправлено на кириллицу, текст комментариев по смыслу не менялся.

## v0.1.0 (2026-10-22)

Релиз опубликован: ассеты win/mac/linux (full-контур), теги v0.1.0 (annotated), репетиция run 39814275536.

### Added
- Полный контур в релизе: бандл `-full` = демон с онн-каскадами (ФИО/адрес/паспорт из gliner-экстрактора, серая зона через Decide-арбитр) + dylib в бандле (mac) + инструкция весов `models/` (веса 879 МБ скачиваются по sha256-манифесту, `scripts/fetch-models.sh`) — #181/#183.
- `FASAD_MODEL_DIR` без онн-фичи в бинаре = отказ старта с текстом причины (#14A/#183).
- Релиз-зубы: метка каскад-0 в dist запрещена (rc=1); каскад-0-бинарь под full-меткой rc=1; mac-бандл без dylib rc=1 (#183).
- Трей win/mac: иконка статуса, клик = UI браузером, graceful выход, tooltip без ПДн (#128/#146, #151/#153).
- Linux-бандл: systemd-юнит `contrib/systemd/fasad.service` (#140).
- `FASAD_READ_TIMEOUT_MS`: перерыв тела = честный 408 `read_timeout`, не 413 (#68).
- SSE-прокси `/v1/chat/completions` с маскированием и parity-тестом (#68, SPEC §10 п.7).
- Тесты-стражи с счётчиками фикстур `assert_eq!(len, N)` (#178/#179, реестр «страж с cases=[]»).
- `commit-msg` hook: запрет внешних co-author-трейлеров и пустого user.email (#180/#182, инцидент authorship-trailers).
- measure-rss: N=3 повтора, медиана + max-гейт, preflight-зуб dylib-контракта, rc=2 env-ошибок гейта (#170/#172/#178).

### Changed
- Word-break точка/слэш/дефис внутри цифровых токенов (#131/#138): канон через разделители; leading-рамка (группа ≥2 цифр, `MIN_LEADING_GROUP_DIGITS`); zero-canon veto — канон из одной цифры не валидируется (#158).
- Пул токенов CAP=1024 (лимит токена; #137/#150), бандл 3.87 МБ full (mac, промер 22.10).
- RAM-гейт: бюджет 1843.2 МиБ, max-свёртка; методика N=3, полоса 870–1816 MiB t2-полного контура задокументирована (#168/#170).
- Витрина README = живой промер (порядок=контракт ответа, «вична» скелетон, stateless-токены диапазон длин) (#152/#154/#156).

### Fixed
- Трей: graceful shutdown через shutdown-канал демона (#151), features пер-крейт (#153).
- restore-integrity: python-канон в `just check` (#139), CAP-фикстуры probe (#150), positive control'ы ног (#157).
- Бандл: бандлы win/mac не несли трей (#146), linux нёс GTK-трей (#146/#153).
- `just dist` красен на mac/win (пустой массив под `set -u`, bash 3.2/4.4) (#183 ревью).
- `actionlint`: `runner.home` не существует в workflow-выражениях (#183).
- CI: rust-cache пин v2.8.7 = verified sha (#142).
- Full-бинарь (фича `ort-inference`) без `FASAD_MODEL_DIR` отказывается стартовать (`ModelsNotConfigured`, rc=2, текст причины): молчаливой деградации до каскад-0-only нет — каскад-0 = харнес/тесты, не продакшн (рюлинг оператора 22.10; unit + e2e + зуб Г verify-bundle + шаг-зуб release.yml; RAM-гейт CI меряется каскад-0-артефактом в target-c0) — #185.

### Removed
- (пусто)
