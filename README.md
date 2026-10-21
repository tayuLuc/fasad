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

Баннер прогона (запуск с `FASAD_PORT=0`, то есть порт случайный и напечатан в
самом баннере; ниже примеры на дефолтном 8765):

```
fasad 0.1.0 cascade-0-only, listening on http://127.0.0.1:50646/health (классов схемы: 8, vault: stateless/strict, ключ: ephemeral)
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
| `FASAD_THREADS` | 8 (config.rs:67) | потоки инференса; локальные прогоны — `2` (рюлинг CPU, AGENTS §3) |
| `FASAD_MLOCK` | `strict` (config.rs:390) | `strict`/`best_effort` — политика залочки буферов ПДн; деградация видна в баннере и в `/health` |
| `FASAD_GRAY_LO`, `FASAD_GRAY_HI` | 0.22 / 0.80 (config.rs:59,62) | полоса неуверенности |
| `FASAD_TAU_LOW`, `FASAD_TAU_HIGH` | 0.20 / 0.80 (guard-onnx/src/routing.rs:70,74) | пороги; инвариант `low ≤ gray_lo < gray_hi ≤ high`, рассогласование = отказ старта |
| `FASAD_MAX_BODY_BYTES` | 1048576 (config.rs:33) | лимит тела запроса |
| `FASAD_TIMEOUT_MS`, `FASAD_READ_TIMEOUT_MS` | 3000 / 30000 (config.rs:72,84) | таймаут upstream и тишины клиента (504 и 408 — разные отказы) |
| `FASAD_UPSTREAM_ALLOWLIST` | пусто = прокси выключен | список `host[:port]`, куда пускать `X-Upstream-URL` |
| `FASAD_PROXY_LOOPBACK_HTTP` | выключен | разрешить `http://` только на loopback (для локального стенда) |
| `FASAD_SCHEMA` | нет (схема встроена) | путь к своей схеме классов; канон встроенной — `config/schema.default.json` (config.rs:244) |
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
и `x-api-key` (proxy.rs:602), ключ демона не хранит.

```sh
FASAD_UPSTREAM_ALLOWLIST='api.openai.com' ./target/release/fasad
```

```sh
curl -s -X POST localhost:8765/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'Authorization: Bearer <ваш ключ, демон его не сохраняет>' \
  -H 'X-Upstream-URL: https://api.openai.com/v1/chat/completions' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ИНН 2482014338 — позвони Ушаковой Кире Саввичне"}]}'
```

Полный цикл проверен живьём на loopback-upstream (эхо-сервер на
`127.0.0.1:8199`, запуск с `FASAD_PROXY_LOOPBACK_HTTP=1` и
`FASAD_UPSTREAM_ALLOWLIST='127.0.0.1:8199'`): в тексте запроса ИНН ушёл наружу
замаркированным (`x-guard-redacted-count: 1`), в ответе разворачивается обратно,
`finish_reason: stop`. Без allowlist маршрут отдаёт `403` (промер):

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
3. Нормализатор каскада 0 не склеивает разделители внутри номера:
   `65707715421` находится, `657-077-154 21` — нет (issue #51).
4. Каскады 1–2 (ONNX-токеноклассификатор + LoRA-арбитр) живут в харнесе
   `crates/guard-onnx/examples/` и в CI-контуре на официальном dylib ORT 1.31.0,
   в демона не смонтированы — отсюда честная стадия `cascade-0-only` в баннере,
   в `/health` и в заголовке `X-Guard-Stage`
   ([docs/daemon-scope.md](docs/daemon-scope.md), §«Деградация каскада»). Монтаж
   каскадов в рантайм — отдельная задача, в main её нет.
5. UI-песочницы (`/ui`: раскраска по confidence, редактор схемы) в main нет —
   она идёт с PR #75.
6. Релизных бандлов и RAM-гейта по трём ОС в main тоже нет: это PR #76.
7. Планка recall (≥98 %, нижняя граница Вилсона, N≥150) на полном каскаде не
   закрыта — открытый трек #80; гейт-права датасета (#14) закрыты и зелёные.

## 5. Границы

1. Один пользователь, одна машина: bind вне loopback запрещён самим демоном.
2. Остаточный риск реверс-индекса назван числом в
   [docs/daemon-scope.md](docs/daemon-scope.md) («p ≈ 2⁻⁶⁴ на одно событие
   перенятого слота»); здесь оно не перепечатывается, ссылка — первичка.
3. Лимиты реестра: 256 сессий (FIFO), 1024 формы на сессию; переполнение —
   `422 too_many_forms`, а не тихая потеря формы (потерянная форма дала бы
   partial-restore, то есть fail-open на данных).
4. Отсутствие `X-Guard-Redacted-Count` на 2xx клиент обязан считать ошибкой:
   демон никогда не подменяет счётчик нулём, если не знает значения.
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
3. RAM релизного контура: docs/model-audit.md §9 «Release RSS» (секция придёт с
   PR #76; цифры там генерируются `just measure-rss --doc-rows`, не с клавиатуры).
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

Тяжёлые локальные прогоны — в щадящем режиме CPU (AGENTS §3, рюлинг оператора
21.10): `CARGO_BUILD_JOBS=2`, `cargo test -- --test-threads=2`,
`FASAD_THREADS=2`, `nice -n 10`, один прогон за раз. `OMP_NUM_THREADS` на нашей
сборке инертен (вендорный `libonnxruntime` osx-arm64 собран без OpenMP).

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
