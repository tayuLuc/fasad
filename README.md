# fasad

Локальный AI-гард: один стендэлон-демон на Rust, оффлайн. Размечает текст по
классам ПДн, маскирует обратимо и проксирует OpenAI-совместимые запросы так,
что наружу уходит замазанное, а обратно возвращается развёрнутое. Весь разбор
завершается на 127.0.0.1 до первой сокет-операции (SPEC §1 п.6); телеметрии
нет, сетевой вызов ровно один — явно названный клиентом `X-Upstream-URL`.

Все примеры ниже прогнаны живьём 21.10 на релизном бинаре
`cargo build --release -p guard-daemon` (macOS arm64, rustc 1.99.1,
`FASAD_THREADS=2`); ответы приведены дословно, без правок.

## 1. Быстрый старт

Нужен Rust 1.99.1 (пин `rust-toolchain.toml`, rustup поднимет сам) и
[just](https://github.com/casey/just) для контракта команд.

```sh
cargo build --release -p guard-daemon
./target/release/fasad
```

Баннер прогона (запуск без единой переменной окружения, порт по умолчанию 8765;
промер 21.10):

```
fasad 0.1.0 cascade-0-only, listening on http://127.0.0.1:8765/health (классов схемы: 8, vault: stateless/strict, ключ: ephemeral)
```

```sh
curl -s localhost:8765/health
```

```json
{"version":"0.1.0","stage":"cascade-0-only","mode":"stateless","vault":{"surrogate_fallbacks":0,"unrestored_mismatch":0}}
```

Переменные окружения (значения — из `crates/guard-daemon/src/config.rs`, номер
строки первички указан для дефолтов):

| Переменная | Дефолт | Что делает |
| --- | --- | --- |
| `FASAD_PORT` | 8765 (config.rs:24) | порт; `0` = случайный порт, он печатается в баннере |
| `FASAD_BIND` | 127.0.0.1 (config.rs:28) | только loopback: на внешний адрес демон стартовать отказывается |
| `FASAD_VAULT_MODE` | `stateless` | `stateless`/`3` = SPEC §3.3, `session`/`2` = SPEC §3.2 (таблица §3 ниже) |
| `FASAD_VAULT_KEY` | нет (ключ эфемерный) | 64 hex-символа (32 байта); с ним обратимость переживает перезапуск (vault.rs:377) |
| `FASAD_THREADS` | 8 (config.rs:67) | потоки инференса; на стадии `cascade-0-only` рычаг инертен: значение разбирается (config.rs:403), а единственным потребителем поля в демоне остаётся тест config.rs:610 — до сессий ORT оно не доходит (промер grep по `crates/` на `bfb0014`; живым станет с монтажом каскадов #87). Харнесы каскадов — рычагом `--threads 2` (рюлинг CPU, AGENTS §3) |
| `FASAD_MLOCK` | `strict` (config.rs:391) | `strict`/`best_effort` — политика залочки буферов ПДн; деградация видна в баннере (`main.rs:82-89`), в `/health` её поля нет — там `version`/`stage`/`mode` и счётчики vault (`http.rs:153-165`) |
| `FASAD_GRAY_LO`, `FASAD_GRAY_HI` | 0.22 / 0.80 (config.rs:59,62) | полоса неуверенности |
| `FASAD_TAU_LOW`, `FASAD_TAU_HIGH` | 0.20 / 0.80 (guard-onnx/src/routing.rs:70,74) | пороги; инвариант `low ≤ gray_lo < gray_hi ≤ high`, рассогласование = отказ старта |
| `FASAD_MAX_BODY_BYTES` | 1048576 (config.rs:33) | лимит тела запроса |
| `FASAD_TIMEOUT_MS`, `FASAD_READ_TIMEOUT_MS` | 3000 / 30000 (config.rs:72,84) | таймаут upstream и тишины клиента (504 и 408 — разные отказы) |
| `FASAD_UPSTREAM_ALLOWLIST` | пусто = прокси выключен | список `host[:port]`, куда пускать `X-Upstream-URL` |
| `FASAD_PROXY_LOOPBACK_HTTP` | выключен | разрешить `http://` только на loopback (для локального стенда) |
| `FASAD_SCHEMA` | нет (схема встроена) | путь к своей схеме классов; канон встроенной — `config/schema.default.json` (config.rs:248) |
| `FASAD_MODEL_DIR` | нет | каталог весов каскадов 1–2; демоном на стадии `cascade-0-only` не читается (config.rs:404) |

## 2. Три запроса, ради которых продукт ставят

### analyze

```sh
curl -s -X POST localhost:8765/v1/analyze \
  -H 'content-type: application/json' \
  -d '{"text":"Ушакова Кира Саввична, ИНН 2482014338, СНИЛС 65707715421"}'
```

Ответ — голый массив спанов (контракт Presidio `AnalyzerResult`; `start`/`end`
в символах, `byte_start`/`byte_end` в байтах):

```json
[{"entity_type":"inn","start":27,"end":37,"score":1.0,"class":"inn","byte_start":49,"byte_end":59,"role":null,"source":"checksum_rf","verdict":"mask_surrogate","validator":"inn10"},{"entity_type":"snils","start":45,"end":56,"score":1.0,"class":"snils","byte_start":72,"byte_end":83,"role":null,"source":"checksum_rf","verdict":"mask_surrogate","validator":"snils"}]
```

Заголовки этого же ответа: `x-guard-redacted-count: 2`, `x-guard-max-risk: 1`,
`x-guard-latency-ms: 0`, `x-guard-stage: cascade-0-only`,
`x-guard-policy-applied: mask`, `x-guard-score-threshold: 0.2`.
Имени человека в ответе нет намеренно — см. §4 п.2.

### anonymize и deanonymize

Спан для маскирования передаётся байтовыми координатами из `analyze`
(`entity_type` + `byte_start` + `byte_end`; символьные в запросе не принимаются,
vault.rs:126-137):

```sh
curl -s -X POST localhost:8765/v1/anonymize \
  -H 'content-type: application/json' \
  -d '{"text":"Ушакова Кира Саввична, ИНН 2482014338, СНИЛС 65707715421",
       "spans":[{"entity_type":"inn","byte_start":49,"byte_end":59},
                {"entity_type":"snils","byte_start":72,"byte_end":83}]}'
```

Ответ (режим `stateless`, маркер = AES-256-GCM, на покое ноль байт):

```json
{"text":"Ушакова Кира Саввична, ИНН [[F0#HqAw2LFptJ2LOBJpuX9KZKaZinWe3IW3pJ5kCyrTwySNzBaYUXwLIaPcRAw6KHtnbijtvPNQPg]], СНИЛС [[F0#9lSANes6Q7Jd-iIJmgqqdoaPQ0cSSHtn1BZlRPKsqaKE3NL72UTPjY8kU7PTaLriOyhVMAgVyYg]]","items":[{"entity_type":"inn","start":27,"end":37,"byte_start":49,"byte_end":59,"replacement":"[[F0#HqAw2LFptJ2LOBJpuX9KZKaZinWe3IW3pJ5kCyrTwySNzBaYUXwLIaPcRAw6KHtnbijtvPNQPg]]","operator":"mask"},{"entity_type":"snils","start":45,"end":56,"byte_start":72,"byte_end":83,"replacement":"[[F0#9lSANes6Q7Jd-iIJmgqqdoaPQ0cSSHtn1BZlRPKsqaKE3NL72UTPjY8kU7PTaLriOyhVMAgVyYg]]","operator":"mask"}]}
```

Обратный ход тем же запросом к `/v1/deanonymize` (`{"text": "<замазанное>"}`):

```json
{"text":"Ушакова Кира Саввична, ИНН 2482014338, СНИЛС 65707715421","substituted":2,"restore_refused":0}
```

### proxy

Прокси — единственная дверь наружу, и она открывается только по явному адресу
клиента (proxy.rs, §«Две стенки»). Наружу уходит замазанный запрос, обратно —
развёрнутый ответ; из клиентских заголовков переносятся только `authorization`
и `x-api-key` (proxy.rs:602), ключ демона не хранит. Значение заголовка в примере
— плейсхолдер `sk-REPLACE-ME`, подставьте свой: угловые скобки в значении
заголовка недопустимы, с ними маршрут отвечает `502 upstream_protocol` (промер
21.10 на значении `<ваш ключ…>`).

```sh
FASAD_UPSTREAM_ALLOWLIST='api.openai.com' ./target/release/fasad
```

```sh
curl -s -X POST localhost:8765/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer sk-REPLACE-ME' \
  -H 'X-Upstream-URL: https://api.openai.com/v1/chat/completions' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ИНН 2482014338 — позвони Ушаковой Кире Саввичне"}]}'
```

Полный цикл проверен живьём на loopback-upstream (эхо-сервер на
`127.0.0.1:8199`, запуск с `FASAD_PROXY_LOOPBACK_HTTP=1` и
`FASAD_UPSTREAM_ALLOWLIST='127.0.0.1:8199'`): в тексте запроса ИНН ушёл наружу
замаркированным (`x-guard-redacted-count: 1`), в ответе разворачивается обратно,
`finish_reason: stop`. Промер 21.10 тем же curl'ом, что выше, но с
`X-Upstream-URL: http://127.0.0.1:8199/v1/chat/completions` — на адрес вне
allowlist (`https://api.openai.com/…`) этот rig отвечает `403`
`allowlist_denied`, а `FASAD_PROXY_LOOPBACK_HTTP=1` ничего не переадресует: он
разрешает http только на loopback (proxy.rs:373) и снимает `https_only` с
агента (proxy.rs:473). На loopback-URL: тело, ушедшее upstream, содержит
маркер `[[F0#…]]` и не содержит ИНН; ответ разворачивается в
исходный текст байт-в-байт (`cmp` rc=0); заголовок `authorization` долетел
дословно. Без allowlist маршрут отдаёт `403` (промер):

```json
{"error":{"code":"allowlist_empty","message":"FASAD_UPSTREAM_ALLOWLIST пуст, прокси выключен"}}
```

`X-Guard-Policy: block` на этом маршруте уважается (запрос не уходит),
`audit_only` отвергается с `400 policy_not_applicable`: клиентским заголовком
нельзя снять с гарда его единственную работу.

## 3. Режимы хранилища

`FASAD_VAULT_MODE` принимает четыре значения (config.rs: «допустимо
2|3|session|stateless»), семантик у них две (SPEC §3.2 и §3.3):

| Значение env | Режим | Маркер | `X-Session-ID` | Обратимость |
| --- | --- | --- | --- | --- |
| `stateless` (дефолт) | SPEC §3.3 | `[[F0#base64url]]`, AES-256-GCM, AAD = id сессии | не нужен | тем же процессом |
| `3` | он же, числом | он же | не нужен | тем же процессом |
| `session` | SPEC §3.2 | метка `[КЛАСС_seq_nonce]` + суррогат ФИО, оригиналы в кэше (idle 15 мин, live 2 ч) | обязателен | тем же процессом; с `FASAD_VAULT_KEY` — переживает перезапуск |
| `2` | он же, числом | он же | обязателен | она же |

Промеры живым запросом (режим 2, тот же текст):

1. Без заголовка: `400 {"error":{"code":"bad_request","message":"режим 2 требует заголовок X-Session-ID"}}`.
2. С `X-Session-ID: demo`: `ИНН [INN_1_MTMWENLT], СНИЛС [SNILS_2_MTMWENLT]`.
3. `/v1/deanonymize` в сессии `demo` возвращает оригиналы (`substituted: 2`).
4. `/v1/deanonymize` с чужим `X-Session-ID`: `422 {"error":{"code":"unresolved_token","message":"не развернулось маркеров: 2 — отдаём отказ, а не partial-restore"}}`.
5. Баннер печатает `ключ: env` или `ключ: ephemeral` — во втором случае
   обратимость умирает вместе с процессом.

## 4. Что умеет сегодня, честно

1. Каскад 0 = детерминированные валидаторы по восьми классам схемы
   (`config/schema.default.json`): `person_name`, `inn`, `snils`, `card_pan`,
   `phone`, `email`, `address`, `passport`. Приоритет чексуммы = 1.0, нейросеть
   его не понижает (AGENTS); в примере выше источник спана — `checksum_rf`,
   валидатор `inn10`.
2. `person_name` каскадом 0 **не находится никогда**: его ищет
   токеноклассификатор каскада 1+. В промере §2 из «Ушакова Кира Саввична,
   ИНН …» найдены ИНН и СНИЛС, имени нет. При этом `/v1/anonymize` имя замажет,
   если спан прислан клиентом (выделение в интерфейсе, каскад 1+ из другой
   сборки).
3. Нормализатор каскада 0 склеивает разделители внутри номера: `65707715421`,
   `657-077-154 21`, `657 077 154 21` и `657-077-154-21` дают один и тот же
   `snils`-спан с `score: 1.0` (перемычки входят в границы: `start: 6, end: 20`),
   `ИНН 248-2014-338` находится как `inn10` (`start: 4, end: 16`), а карта —
   промер `оплата картой 2204 9947 4132 9761` даёт `card_pan` (luhn,
   `start: 14, end: 33`),
   раздельные IBAN `RU19 04452522540820407677025210608` и
   `ES69 8718 1615 6811 4431 6009` (g0006, g0015 из golden-набора) находятся с
   `class: iban`, `source: checksum_eu`: полная таблица влита с #86. Класс
   `iban` не входит в восемь классов схемы (он в `validator_only`, баннер
   печатает «классов схемы: 8»), спан при этом отдаётся. Отказ по чексумме
   жив: `RU02044525225807173881231016909` (длина 31, mod97 = 25, номер
   выдуман) → пустой массив. Разделители закрыты #86 (`bfb0014`); транслит,
   числительные словами и base64 остаются открыты в #51 (issue OPEN).
   Прежняя формулировка этого пункта («`657-077-154 21` — нет») была верна
   состоянию до #86 и снята; промер 21.10 демоном без env на бинаре из этого
   дерева (база `a9b21b9`).
4. Каскады 1–2 (ONNX-токеноклассификатор + LoRA-арбитр) живут в харнесе
   `crates/guard-onnx/examples/` и в CI-контуре на официальном dylib ORT 1.31.0,
   в демона не смонтированы — отсюда честная стадия `cascade-0-only` в баннере,
   в `/health` и в заголовке `X-Guard-Stage`
   ([docs/daemon-scope.md](docs/daemon-scope.md), §«Деградация каскада»). Монтаж
   каскадов в рантайм — отдельная задача, в main её нет.
5. UI-песочница (`/ui`: раскраска по confidence, редактор схемы) пришла в main с
   PR #75 (влит `bf95412`): фронт вшит в бинарь (`rust-embed`, ui.rs:25-27),
   маршрут `GET /ui` — ui.rs:47. Промер 21.10 демоном без env: `GET /ui` = 200,
   3313 байт HTML.
6. Релизный контур пришёл в main с PR #76 (squash `94fecdb`, 21.10):
   `release.yml` с матрицей трёх ОС (ubuntu-24.04, windows-2022, macos-14),
   RSS-гейтом, проверкой бандлов и лицензионным инвентарём. Самих релизов на
   GitHub ещё нет (`gh api releases` = 0, промер 21.10): контур стартует
   пуллом тега, маршрут описан в `docs/release.md`.
7. Трек union-recall #80 влит в main (`b5b0fe3`), терпимость к разделителям и
   полная таблица IBAN дошли с #86 (`bfb0014`). Планка ≥98 % (рюлинг #77: нижняя
   граница Вилсона, span-уровень, byte-exact) ЗАКРЫТА: union 99.72 % при
   k = 357 из 358 (допуск ровно один промах), нижняя граница Вилсона 98.43 %
   против планки 98.0 %; статус гейта #14B — закрыт
   (`docs/golden-report.md:260-262` и `:266`, §5.5). Прежняя формулировка пункта
   («не закрыта: 91.34 %, граница 87.97 %», первичка `golden-report.md` на blob
   `b5b0fe3`, строки 271-273 — в новом файле эти номера ушли, поэтому ссылка
   привязана к blob) была верна состоянию до #86 и снята: цитата протухает
   вместе с первичкой.

## 5. Границы

1. Один пользователь, одна машина: bind вне loopback запрещён самим демоном.
2. Остаточный риск реверс-индекса назван в
   [docs/daemon-scope.md](docs/daemon-scope.md) (строка 33) — вероятность на одно
   событие перенятого слота; формулу сюда не переносим: цитата её и есть
   перепечатывание.
3. Лимиты реестра: 256 сессий (FIFO, `MAX_SESSIONS`, vault.rs:114) и 1024 ФОРМ
   СУРРОГАТОВ на сессию (`MAX_FORMS_PER_SESSION`, config.rs:46). Считаются формы
   подмен, а не метки: одна ФИО-подмена даёт до 4 форм, то есть 1024 — это ~256
   ФИО (config.rs:35-45). Переполнение — `422 too_many_forms` до первой подмены, а
   не тихая потеря формы (потерянная форма дала бы partial-restore, то есть
   fail-open на данных); закреплено тестом
   `forms_cap_refuses_request_before_first_substitution` (`vault.rs:1530`). С этой
   страницы (стадия `cascade-0-only`) порога не достичь: форму плодит подмена ФИО,
   а её детектор — каскад 1, `/v1/analyze` на каскаде 0 форм не создаёт.
4. Отсутствие `X-Guard-Redacted-Count` на 2xx-ответе маршрутов разбора и прокси
   (`/v1/analyze`, `/v1/anonymize`, `/v1/deanonymize`, `/v1/sessions/{id}`,
   `/v1/chat/completions` — http.rs:214-220, proxy.rs:561) клиент обязан считать
   ошибкой: демон никогда не подменяет счётчик нулём, если не знает значения. У
   `/health`, `/ui` и `/assets/*` этого заголовка нет по устройству — 200 без них
   является нормой.
5. `panic = "unwind"`: паника одного запроса не валит демон, но и не обещает
   «неубиваемости» — это контур изоляции отказа, а не отказоустойчивость.
6. Скриншотов нет: витрина — команды и живые ответы этой страницы.

## 6. Где метрики (и почему их тут нет)

Числа в этот README не заносятся: метрики живут в артефактах прогонов, и
перепечатанное число превращается в неподтверждённое утверждение.

1. Датасет и гейт-права recall: `data/golden/README.md`; воспроизводимость
   проверяется `just golden-verify`, генерируемая строка промера:
   `OK: golden-v1.jsonl воспроизводится байт-в-байт (N=204 строк)`.
2. Метрики прогона каскадов (RSS, латентность, dev-профиль, threads=4):
   [docs/model-audit.md](docs/model-audit.md) §2 — сырые `METRIC`-строки.
3. RAM релизного контура: docs/model-audit.md §9 «Release RSS» (секция пришла с
   PR #76, squash `94fecdb`; цифры там генерируются `just measure-rss --doc-rows`,
   не с клавиатуры).
4. Латентность отдельного запроса — в заголовке `X-Guard-Latency-Ms` каждого
   ответа (в промерах §2 каскад 0 на loopback укладывается в 0 мс).

## 7. Команды разработки

| Задача | Команда |
| --- | --- |
| Полный гейт перед push | `just check` (lint, python-lint, golden-verify, test, net-audit, deny) |
| Линты Rust | `just lint` (fmt --check + clippy `-D warnings -D clippy::unwrap_used`) |
| Тесты | `just test` |
| Датасет | `just golden-verify` (uv, побайтовая сверка `golden-v1.jsonl`) |
| Аудит сети | `just net-audit` (манифест, исходники и дерево зависимостей демона чисты от сети) |
| Зависимости | `just deny` (cargo-deny: advisories/bans/licenses/sources) |
| Харнес каскадов | `just spike-dylib` (нужен dylib ORT 1.31.0, пути — docs/model-audit.md §8) |
| Тесты щадяще CPU | `just local-test` (тот же набор, что `just test`, под рычагами) |
| Язык текста | `just lang-scan` (self-test + весь текстовый tree), на диффе PR — `just lang-scan-files <файлы>` |

Тяжёлые локальные прогоны — в щадящем режиме CPU (AGENTS §3, рюлинг оператора
21.10): `CARGO_BUILD_JOBS=2`, `cargo test -- --test-threads=2`, у харнесов
инференса потоки рычагом `--threads 2`, `nice -n 10`, один прогон за раз;
готовая обёртка того же набора — `just local-test`. `OMP_NUM_THREADS` на нашей
сборке инертен (вендорный `libonnxruntime` osx-arm64 собран без OpenMP), а
`FASAD_THREADS` инертен на стадии `cascade-0-only` по причине из таблицы §1.

## Ссылки

1. [docs/SPEC.md](docs/SPEC.md) — спецификация (вторичный источник:
   LLM-транскрипт, числа из него проверяются по `docs/dep-verify-*.md`).
2. [AGENTS.md](AGENTS.md) — правила workspace и дисциплина фактов.
3. [crates/guard-daemon/README.md](crates/guard-daemon/README.md) — контракт
   эндпоинтов, коды ошибок, режимы хранилища.
4. [docs/daemon-scope.md](docs/daemon-scope.md) — сетка заголовков `X-Guard-*`,
   границы объёма, остаточные риски.
5. [docs/source-note.md](docs/source-note.md) — откуда фактура и где расхождения.
6. Лицензия Apache-2.0 ([LICENSE](LICENSE)); перечень третьих сторон —
   [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
