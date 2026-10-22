# Changelog

Факты. Одна строка = одно изменение. Источник записей = влитые PR (#номер).
Формат: Added / Changed / Fixed / Removed (Keep a Changelog, секции = версии).
Правила: заменяющие утверждения (ruling #182); даты = дата влития; числа = артефакт прогона.

## Unreleased

### Added
- win-доставка веса́й: `scripts/fetch-models.ps1` (PowerShell 5.1+, паритет `.sh`: манифест / `Get-FileHash` sha256-гейт fail-closed / rev-URL / кеш-раскладка идентична / `-List` без сети; `TBD`-контур и resume — только в `.sh`, названо в шапке), win-секции README бандла (PowerShell-первенство, `bin\fasad-tray.exe`, Git-Bash = альтернатива) — #190; CI win-ячейка ort-build: `-List` + mock-промер (малый файл HF, sha256-ok, повтор без сети через hosts-глушилку) + red-контроль «битый sha = rc1».
- win-трей: отказ старта показан `MessageBox` (текст причины #185; остров `src/tray/win.rs`, `windows-sys` target-gated = пакет уже в дереве tray-icon, `net_audit` fact-5 += «windows» в linux-дереве фичи = ноль) — #190 (v0.1.0: промер оператора — stderr двойного клика уходит в никуда).
- UX первого запуска (#191): `--help`/`-h` = usage (env-таблица + UI-адрес), НЕ-флаг аргумент = exit 2 + usage в stderr (argv читается впервые; первичка: молчаливое игнорирование); строка `UI — http://<порт>/` в стартовом баннере (парсер `wire_e2e` не тронут); клик по трею = браузер с UI (win/mac) — был и в v0.1.0 (`tray.rs::open_browser_command`: win `cmd /C start`, mac `/usr/bin/open`), закрыт промером тестов/доков, кода не потребовало.

### Fixed
- Релизный контур до первого тега (#188, латенты из эскалаций #184/#187): mac-шаги `release.yml` — `sha256sum: command not found` rc=127 на macos-14 (провен run 39784396502) → hex-сверка `shasum -a 256` (форма ort-build, прообраз зелёный); win-шаг `onnxruntime.dll` — ложно-красный путь `target/release/` → корень `target/` (`vars::target_dir`, первичка ort-sys `vars.rs:32` + CI-провен run 39786761298); linux-контур — «динамическая зависимость» было ЛОЖНЫМ (download-контур = СТАТИКА, ort-sys `main.rs:177-183`, CI-провен readelf run 39786761298) → linux = статика, ЗУБ А verify-bundle = маркер-форма win-ноги, readelf-шаг матрицы = запись ELF-графа (INFO), docs/§Матрица синхронны.
- Найденные релиз-репетицией (#188, dispatch run 39791625858 — workflow `release` исполнен впервые): `just dist` на linux падал на трей-зависимости (tray-icon compile_error, §16) — трей-сборка перенесена в mac/win uname-ветку рецепта; spike-нога `ort-dylib` (linux) линковала `-lonnxruntime` против корня архива (so лежит в `<архив>/lib`) при mac-only обвязке dynamic_lookup (build.rs:99) — linux-нога харнеса снята как не-контракт (ram-контур = mac, §9), mac-нога = dylib-dlopen-контракт.

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
