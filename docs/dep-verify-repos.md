# Верификация первички по GitHub — fasad (локальный AI-гард)

Дата промера: **2026-10-18** (UTC-интервал 14:31–15:0x, `date -u`).
Объект верификации: сущности, на которые ссылается [docs/SPEC.md](SPEC.md) (§1, §7, §8, §9, §11).
Правило: SPEC — вторичный источник (LLM-транскрипт); здесь только **первичные промеры**.
Вердикт: `[CONFIRMED]` / `[REFUTED]` / `[PARTIAL]` / `[CORRECTED]` / `[LIVE]` / `[DEAD]` / `[PHANTOM]`.

## Транспорт и оговорки метода

1. `api.github.com` без токена — квота 60/ч. На старте сессии `remaining: 0`,
   `reset` был **14:46:09Z**, а не 17:26Z (ошибочный парсинг `reset: 1792334769`
   из сырого JSON — пересчитано по `date -u -r`). Промер ждал восстановления квоты.
2. Всё до квоты проверено вне API: `raw.githubusercontent.com/<owner>/<name>/HEAD/<path>`
   + `crates.io/api/v1/crates/<crate>` — на эти эндпоинты квота GitHub API не влияет.
3. Каждый запрос шёл с `-A "dsh-audit/1.0"` (и на crates.io тоже — без UA crates.io
   отдаёт HTML-заглушку). Пустой/HTML-ответ всегда повторялся с UA перед вердиктом «нет».
4. `curl` коды `000` в swept-циклах (транзитные сетевые сбои, не 404) — повторены,
   результат в таблице.
5. **`HEAD` на raw = дефолтная ветка**: у `microsoft/presidio` корневой `README.md`
   отсутствует, есть `readme.md` в lowercase… который тоже 404 — см. ниже, репо
   переехал. Плоский проб путей (`src/model/pipeline.rs` и т.п.) не даёт дерева —
   для кодовых путей использован API.

## 1. Таблица репо

| Репозиторий | HTTP | pushed_at | archived | license | claim-вердикт |
|---|---|---|---|---|---|
| microsoft/presidio → **data-privacy-stack/presidio** (id 132129752) | 301→200 | 2026-10-18T09:06:39Z | false | **MIT** | `[CORRECTED]` переехал из microsoft/; §8 совместимость реальна |
| fbilhaut/gline-rs | 200 | 2026-08-05T15:37:28Z | false | Apache-2.0 | `[CONFIRMED]` pins ort `=2.0.0-rc.9` + tokenizers `0.21.0` |
| fbilhaut/gliclass-rs | 200 | 2026-08-05T20:02:09Z | false | Apache-2.0 | `[CONFIRMED]` те же пины |
| fastino-ai/GLiNER2 | 200 | 2026-10-09T17:53:44Z | false | Apache-2.0 | `[CONFIRMED]` жив, ★2383; id моделей §1 подтверждены |
| tricktreat/DiffusionNER | 200 | **2023-08-29T04:36:38Z** | false | **нет файла LICENSE** | `[DEAD]` — у нас «не берём», риск нулевой |
| ML-GSAI/LLaDA | 200 | 2026-07-15T08:24:01Z | false | **нет файла LICENSE** | `[LIVE]` ★4001, но лицензия юридически не определена |
| mongodb/kingfisher | 200 | 2026-10-13T00:06:41Z | false | Apache-2.0 | `[LIVE]` референс каскада 0 валиден |
| praetorian-inc/noseyparker | 200 | 2026-02-21T13:04:04Z | **true** | Apache-2.0 | `[ARCHIVED]` — читать как эталон, не как живой источник |
| sirwart/ripsecrets | 200 | 2025-12-15T23:23:08Z | false | MIT | `[LIVE]` ★911 |
| **utilityai/llama-cpp-rs** | 200 | 2026-10-15T21:46:31Z | false | Apache-2.0 | `[LIVE]` ★656 — настоящие хозяева крейта `llama-cpp-2` |
| rust-dd/llama-cpp-2 | **404** | — | — | — | `[PHANTOM]` репозитория нет |
| DanKau (GitHub-пользователь) | **404** | — | — | — | `[PHANTOM]` на GitHub; это HF-only namespace |

Действия CI (§10/§9 SPEC), `refs/tags` через API:

| Действие | HTTP | major-теги |Latest | Вердикт |
|---|---|---|---|---|
| softprops/action-gh-release | 200 | v1, v2, **v3** | v3.0.3 | `[PARTIAL]` v2 существует, но просрочен |
| actions/checkout | 200 | v1…v6, **v7** | v7.0.1 | `[PARTIAL]` v4 существует, просрочен на 3 мажора |
| dtolnay/rust-toolchain | 200 | только `v1` (релизный train) | — | `[CONFIRMED]` конвенция `@master` |
| Swatinem/rust-cache | 200 | **v2** (v2.9.2 max) | v2.9.2 | `[CONFIRMED]` |

## 2. Разбор по пунктам задания

### п.1–2 microsoft/Presidio (форма `/anonymize` против SPEC §8)

1. **Репо переехало**: `microsoft/presidio` → `data-privacy-stack/presidio`
   (HTTP 301 `Moved Permanently`, `url: .../repositories/132129752`).
   Пути в SPEC/докрах вида «github.com/microsoft/presidio» работают только по редиректу.
2. **Лицензия = MIT, точно.** `license.spdx_id = "MIT"` из API + корневой `LICENSE`
   = «The MIT License (MIT) / Copyright (c) Presidio Contributors.» (1084 байта).
3. **红旗 AGPL не подтверждён**: AGPL у Presidio нигде не обнаружен. Формат
   «Presidio-формат» в §8 — это MIT, в граф сборки как зависимость не идёт (только контракт API).
4. **Форма контракта** (`presidio-anonymizer/README.md`, 154–186 строки, прочитано):
   - `RecognizerResult(entity_type, start, end, score)` — спан-модель, offsets символьные.
   - `operators={"PERSON": OperatorConfig("replace", {"new_value": "BIP"})}` —
     словарь по типу либо `"DEFAULT"`.
   - `DeanonymizeEngine.deanonymize(text, entities=[OperatorResult(start,end,entity_type)],
     operators={"DEFAULT": OperatorConfig("decrypt", {"key": ...})})`.
   - Есть `BatchDeanonymizeEngine.deanonymize_list(...)` — батч-режим.
   - Политика слияний пересекающихся спанов описана в README (строки 76–108):
     при полном пересечении берётся **более высокий score**; при частичном — анонимизируются
     оба независимо; «одна PII внутри другой» → берётся **более длинный текст, даже с более
     низким score**.
   - REST-слой живёт в `presidio-anonymizer/... /server` (в README показан Python-API,
     не HTTP) — точный URL-контракт `/api/v2/anonymize` в этой сессии **не промерен**
     (плоские пробы путей дали 404; нужен `contents` API на дерево). Помечаю как открытый хвост.
5. **Расхождение с SPEC §3/§8 (важно)**: Presidio `deanonymize` требует **ключ шифрования
   от клиента**, наш контракт — stateless `vault_token` (LZ4 + ChaCha20-Poly1305).
   Совместимы формой (спан + тип + оператор), не механизмом обратимости.
6. README корня `microsoft/presidio` на raw — 404 по всем 6 комбинациям регистра/ветки;
   после редиректа на новую оргу `presidio-anonymizer/README.md` = 200 (3762 б),
   `SECURITY.md` = 200. Т.е. 404 был следствием переезда, а не отсутствием репо.

### п.3 fbilhaut/gline-rs — Cargo.toml (raw)

Версии из первички, `https://raw.githubusercontent.com/fbilhaut/gline-rs/HEAD/Cargo.toml`:

| Пин | Значение | SPEC claim | Вердикт |
|---|---|---|---|
| пакет | `gline-rs` 1.1.0, edition 2021 | 1.1.0 (§7) | `[CONFIRMED]` |
| `ort` | `"=2.0.0-rc.9"` | ort 2.0.0-rc.9 | `[CONFIRMED]` (пин жёстче: `=`) |
| `ort-sys` | `"=2.0.0-rc.9"`, `default-features=false` | — | подтверждён обход issue #399 |
| `tokenizers` | `"0.21.0"`, features `["http"]` | ^0.21 | `[CONFIRMED]` |
| `license` | `Apache-2.0` | — | см. п.4 |
| прочее | ndarray 0.16.0, composable 1.0.0, orp 1.0.0 | — | контекст |

Комментарий в Cargo.toml отсылает к `github.com/pykeio/ort/issues/399` — то есть хозяин
`ort` = **pykeio**, не rust-dd.

### п.4 gline-rs / gliclass-rs — лицензии

1. Оба: `license = "Apache-2.0"` в Cargo.toml, `spdx_id = Apache-2.0` в API.
2. **Отдельного корневый `LICENSE`-файла нет (404)** у обоих — брейс для
   `cargo-deny check licenses` (§9 CI): метаданных достаточно, но file-based аудит
   не найдёт текста. Фиксирую как мелкое замечание, не риск.
3. Вердикт: совместимы с нашим MIT/Apache-сттеком; в граф зависимостей не идут
   (`[decided]` SPEC §AGENTS: только как референс кода декодирования) — Apache-2.0
   референс-чтение безопасно.

### п.4b Внешние (external-data) веса в gline-rs / gliclass-rs — приоритет от родителя

1. `Readme.md` gline-rs (242 строки, прочитан целиком): **ни одного упоминания**
   `onnx_data`, `external`, `save_as_external_data`. Ни раздела про крупные веса.
2. API загрузки: `GLiNER::<TokenMode>::new(params, runtime_params, "tokenizer.json",
   "model.onnx")` — одна строка пути, без опции внешнего data-файла.
3. Ожидаемая раскладка для примеров: `models/<name>/tokenizer.json` +
   `models/<name>/onnx/model.onnx` — единственный `.onnx`.
4. `doc/ORT.md` = HTTP 200, греп по `onnx_data|external|download-binaries|copy-dylibs`
   → **пусто** (0 совпадений).
5. `src/lib.rs` = HTTP 200, греп по `onnx_data|external|CommitOptions|Session` → пусто
   (логика сессий в крейте `orp`, не здесь).
6. Гличасс (Readme.md 2962 б) — тот же греп: пусто.
7. **Вердикт: `[REFUTED]` — ни один из двух крейтов не документирует и не демонстрирует
   обработку `.onnx_data`.** Значит паттерн «external-data веса → нужен отдельный файл
   рядом с `model.onnx`» у них **не подтверждается**; для наших подозрений к
   `onnx-community/GLiNER2.5-Decide-ONNX` это отсутствие референса, а не аргумент.
   Наш собственный ONNX-путь (§10 шаг 4: свой декодер поверх `ort` напрямую) обязан
   решать external-data сам: в `ort` за это отвечает ORT-рантайм, а не крейт-обёртка.
8. Открытый хвост (вне транспорта сессии): полный греп дерева `fbilhaut/orp`
   (`orp` = рантайм-обёртка gline-rs) через `contents` API — следующий промер.

### п.5 fastino-ai/GLiNER2

1. **Существует, живой.** `pushed_at` 2026-10-09T17:53:44Z, `archived=false`,
   ★2383, LICENSE = Apache-2.0 (201 строка, текст Apache v2, в `pyproject.toml`
   `license = "Apache-2.0"`, `license-files = ["LICENSE"]`, `name = "gliner2"`,
   `Repository = "https://github.com/fastino-ai/GLiNER2"`).
2. README 54 613 байт — содержит список моделей HF. **Подтверждены точные id из SPEC §1/§2:**
   - `fastino/gliner2.5-multi-v1` ✅ (строки 179, 207)
   - `fastino/GLiNER2.5-multi-Decide` ✅ (188)
   - `fastino/gliner2-privacy-filter-PII-multi` ✅ (197)
   - плюс `gliner2-base-v1`, `gliner2-large-v1`, `gliner2.5-base-v1`, `gliner2.5-small-v1`,
     `fastino/GLiNER2.5-Decide` (187), `fastino/fast-decisions`, `fastino/gliguard-LLMGuardrails-300M`,
     `fastino/GLiNER2-Guardrails-PII-Multi`.
3. Значит SPEC §11 п.1 («GLiNER 2.5 может не существовать», «могут не существовать под
   точными именами») — **снята для имён из транскрипта**: имена реальны в репо-первичке.
   Остаток риска — наличие **ONNX**-экспортов и лицензий на самих HF-карточках
   (HF API `DanKau/gliner-PII` вернул `Invalid username or password` = 401-класс,
   промер HF лежит на соседе, не повторяю).
4. Контроль: `fastino-ai/GLiNER` (без «2») → README 404, т.е. v1-репо под этим именем
   отсутствует; единственный живой — `GLiNER2`.

### п.6 tricktreat/DiffusionNER

Репозиторий **существует** (README 3077 б), `pushed_at` **2023-08-29** — мёртв ~3 года,
`archived=false`, **файла LICENSE нет** (probe LICENSE/LICENSE.txt/LICENSE.md — всё 404,
`spdx_id=null`). У нас позиция «не берём» — риск нулевой; если когда-нибудь понадобится
код как референс — взять нельзя, лицензии нет.

### п.7 ML-GSAI/LLaDA

Существует, живой (2026-07-15), ★4001, **LICENSE-файла тоже нет** (`spdx_id=null`).
Для SPEC §5.4 («диффузионные архитектуры не нужны») безразлично — не берём.
Фиксирую как факт: у обоих академических репо (DiffusionNER, LLaDA) лицензии нет,
в граф зависимостей они не попадут никогда.

### п.8 mongodb/kingfisher, praetorian-inc/noseyparker, sirwart/ripsecrets

1. `mongodb/kingfisher`: жив (2026-10-13), **Apache-2.0** (`kingfisher-bin` 2.13.0,
   `kingfisher-secret-scanner`, LICENSE = текст Apache v2, есть `license-files` с
   `THIRD_PARTY_NOTICES` + вендорный `Vectorscan`) → референс «Tree-sitter контекст» валиден.
2. `praetorian-inc/noseyparker`: **`archived=true`**, последний push 2026-02-21,
   Apache-2.0, ★2337, `version = "0.25.0-dev"`.
   **Отдельный红旗 в SPEC §2**: noseyparker помечен как референс архитектуры
   префикс-префильтра. Как эталон кода — годится (архив = заморозка, не удаление).
   Как источник обновлений правил — нет. В `cargo-deny` bans не добавлять: не зависимость.
3. `sirwart/ripsecrets`: жив (2025-12-15), **MIT**, ★911, 0.1.11.
4. Все три — только референсы архитектур, не зависимости → лицензионного конфликта нет.

### п.9 rust-dd/llama-cpp-2 vs utilityai/llama-cpp-rs

1. `rust-dd/llama-cpp-2` → **404, репозитория нет** (`[PHANTOM]`).
2. crates.io: `crate.repository` для **`llama-cpp-2` = `https://github.com/utilityai/llama-cpp-rs`**,
   newest `0.1.160`, updated **2026-10-15** → SPEC §1 формулировка «llama-cpp-2 из
   utilityai/llama-cpp-rs» **верна** (`[CONFIRMED]`).
3. Ловушка именованиЯ: крейт **`llama-cpp-rs`** существует и указывает на
   `mdrokz/rust-llama.cpp`, newest `0.3.0`, updated **2023-10-12** — то есть крейт с
   «правильным» именем мёртв 3 года. Не перепутать при `cargo add`.
4. `utilityai/llama-cpp-rs`: жив (2026-10-15), Apache-2.0, ★656 — опциональный
   feature-gate §5.2 реально поддержан живой первичкой.

### п.10 GitHub Actions (все 4 существуют, все теги существуют)

1. `softprops/action-gh-release` — 51 тег, мажорные v1/**v2**/v3, latest v3.0.3.
   SPEC §9 (`@v2`) валиден, но **просрочен**: есть v3 → перепинить на `@v3` при
   правке release.yml. `action.yml` на v2 читается, `runs.using: node20`, `name: "GH Release"`.
2. `actions/checkout` — мажорные до **v7** (v7.0.1), SPEC `@v4` существует, просрочен
   на 3 мажора. `action.yml` v4: `node20`.
3. `dtolnay/rust-toolchain` — тегов по мажорам нет (только служебный `v1`), конвенция
   автора — **`@master`**; SPEC ничего не пинит → `[CONFIRMED]`. `action.yml`: `composite`.
4. `Swatinem/rust-cache` — v2.9.2 макс; SPEC `@v2` актуален в рамках мажора.
   Замечание: `runs.using: node24` (v2) — требует свежий раннер; ubuntu-22.04/24.04 и
   windows-2022 из SPEC §9 совместимы, но на старых раннерах node24 недоступен.
5. `action.yml` всех четырёх прочитаны через raw по тегам (`@v2`/`@v4`/`@master`) —
   existence-чек пройден и на уровне ref, и на уровне содержимого манифеста.

### п.11 ort: репозиторий и feature-флаги

1. **Репо `ort` = `pykeio/ort`** (`crates.io: crate.repository =
   https://github.com/pykeio/ort`), не `rust-dd` (rust-dd — зеркало; его
   `llama-cpp-2` вообще 404). Homepage `https://ort.pyke.io/`.
2. Версии: `newest_version = max_version = 2.0.0-rc.14`, `updated_at = 2026-10-12`.
   Точечно по API `/crates/ort/<v>`: **rc.9** (2024-11-21), **rc.13** (2026-07-28),
   **rc.14** (2026-10-12) — все существуют, **ни одна не yanked**, лицензия у всех
   трёх **`MIT OR Apache-2.0`**.
3. Значит SPEC §7 «rc.13 — нет в registry» → **`[REFUTED]`**: rc.13 в реестре есть
   (и rc.14 тоже; rc.13 не latest).
4. **Feature-флаги §11 п.2 — `[CONFIRMED]` по rc.13** (`features` из JSON версии):
   - `download-binaries → ["ort-sys/download-binaries"]`
   - `copy-dylibs → ["ort-sys/copy-dylibs"]`
   - `half → ["dep:half"]`
   Все три существуют именно как флаги `ort`, делегируя в `ort-sys`
   (`ort-sys` rc.13: `download-binaries → dep:ureq, dep:lzma-rust2, dep:hmac-sha256`,
   `copy-dylibs → []`, плюс `disable-linking`). Итого релиз-артефакт §9
   (`libonnxruntime.so`/`onnxruntime.dll` рядом через `copy-dylibs`) реализуем.
   Всего у ort rc.13 53 флага (полный список в /tmp-дампе; включает `load-dynamic`,
   `cuda`, `directml`, `webgpu`, `training`, `api-17…api-28`).
5. `tokenizers` (crates.io): repository `huggingface/tokenizers`,
   `newest = 1.0.0-rc.2` (2026-09-21), ряд 0.21.0 / 0.21.4 / 0.22.x / 0.23.2 присутствуют.
   → **SPEC §7 «tokenizers 0.23 / 1.0.0-rc» почти верна**: 0.23.0 как таковой нет
   (есть 0.23.1/0.23.2), а **1.0.0-rc существует** → SPEC §11 п.3 («rc в реестре нет»)
   **`[REFUTED]`**. Пины gline-rs (`0.21.0`) при этом совместимы — они просто старее.

### п.12 redmadrobot-rnd/pii-guard (наводка оператора 19.10; вне SPEC — конкурент-реестр)

1. Репо: **`redmadrobot-rnd/pii-guard`** (org R&D-дочка, создана 2026-06-29); наводка
   «redmadrobot/pii-gaurd» → 404 по обоим признакам. Промер 2026-10-19T21:02–21:16Z, gh api.
2. Python, **Apache-2.0** (LICENSE 11358 Б канон + NOTICE; GPLv3 gender-guesser — только
   opt-in extra `latin-gender`, «NOT a dependency» NOTICE L66-81) → контаминации нашему
   MIT/Apache-стеку нет, деп-конфликта (torch/ort) нет.
3. Метод = наш гибрид в Python: Presidio, 16 типов правил+чексуммы, 4 типа ruBERT-base
   PII-NER 178M (678 МиБ safetensors, torch, ONNX-нет, окно 512/stride 128, скор 0.70),
   разрешитель конфликтов «правило важнее модели» (README L21) — независимое подтверждение
   нашего инварианта «валидатор = 1.0» (architecture.md L163-168).
4. Чексуммы сверены кодом (`contents/src/pii_guard/entities/`): ИНН-10/12 веса
   [2,4,10,3,5,9,4,6,8] mod11%10 / w1w2 — **совпали с dep-verify-algorithms §1**; СНИЛС
   веса 9..1 mod101 + нулевые случаи — §2 совпал; расчётный счёт 20 зн, [7,1,3]×7+[7,1]
   mod10, коррсчёт по BIK — §7 совпал; ОМС-16 = Luhn (наш вопрос к Плану счетов не снимает).
   **ОГРН/ОГРНИП/IBAN/Мир 22xxxx — отсутствуют полностью** (grep entities/ = 0).
5. Метрики нецитируемы: strict 87.1 / baseline 0.974513 — гейт-датасет приватный xlsx
   3857 кейсов реальных ПДн (tests/quality/README L34-38). Публичный
   `redmadrobot-rnd/pii_benchmark` (2841 текст, 21 тип) — кандидат кросс-референса границ
   спанов, НЕ замены data/golden (пересечение типов 10/13).
6. Статус: 3 коммита / 1 автор (a.ivanov@redmadrobot.com) / 0 releases/tags/PR, последний
   push 2026-09-09 — публикационный стенд под статьи redmadrobot.ai + habr/1080440
   (мотив вне ядра фактов); `[LIVE]` формально, фактически frozen.
7. Берём идеями (backlog, не зависимости): препроцессинг-обходы транслит/числительными/
   base64 в каскад-0 (FN фатален); арбитраж контекста расстоянием до ключевого слова
   (их измеренные бюджеты BIK=40, паспорт p99=83 → окно 80/160); trap-документация
   полумаски (config.py L89-96: дефолт Presidio 99 символов открыл 149 Б в 248-Б блобе —
   наш класс дефекта, маскировать len-безразлично).
8. Вердикт: угрозы нулевые (ниша — LLM-обвязка Python с открытым mapping наружу, не
   air-gap-демон <2 ГБ); в cargo-deny bans не нужен. Первенство идеологии не оспаривают.

## 3. Итог

### Мёртвые объекты

1. `praetorian-inc/noseyparker` — **архивирован** (2026-02-21). Референс, не зависимость.
2. `tricktreat/DiffusionNER` — не обновлялся с 2023-08-29, лицензии нет. «Не берём» — ок.
3. крейт `llama-cpp-rs` → `mdrokz/rust-llama.cpp` 0.3.0, 2023-10-12 — мёртв (не тот крейт!).

### Фантомные объекты

1. **`rust-dd/llama-cpp-2`** — репозитория нет (404). Хозяин крейта `llama-cpp-2` —
   `utilityai/llama-cpp-rs`.
2. **`DanKau` как GitHub** — пользователя нет (404). Имя существует только как
   HF-namespace; промер HF-карточки лежит на соседе (мне пришло: `nvidia/gliner-PII` —
   «other» — не повторял).
3. Корневой `microsoft/presidio` README — артефакт переезда орги, не фантом репо.

### Лицензионные риски

1. **AGPL-红旗 по Presidio СНЯТ: `spdx_id = MIT` точно** (API + корневой `LICENSE`,
   «The MIT License (MIT), Copyright (c) Presidio Contributors»). Никакого AGPL в
   промеренных файлах нет. Формат API §8 берётся из MIT-кода → совместим.
2. `fastino-ai/GLiNER2` = **Apache-2.0** — без ограничений на чтение/референс;
   лицензии HF-весов — отдельный вопрос (HF-промер соседа: `DanKau/gliner-PII` → «other»).
3. `kingfisher` (Apache-2.0), `noseyparker` (Apache-2.0), `ripsecrets` (MIT),
   `utilityai/llama-cpp-rs` (Apache-2.0), `gline-rs`/`gliclass-rs` (Apache-2.0),
   `ort`/`ort-sys` (MIT OR Apache-2.0) — всё чисто для `cargo-deny check licenses`
   **на правах референсов**; ни один в граф сборки не попадает по решению SPEC.
4. GPL-репо в зависимостях: **не найдено ни одного GPL-объекта** среди промеренных —
   красного флага «GPL в зависимостях» для текущего сsteка нет.
5. Мелочь: у `gline-rs`/`gliclass-rs` нет корневого `LICENSE`-файла (только поле
   Cargo.toml) — file-based аудит их не увидит.
6. Юридически мутные: `DiffusionNER` и `LLaDA` — `spdx_id=null`, файла лицензии нет.

### Вердикты по claims SPEC (сводка)

| Claim SPEC | Вердикт | Первичка |
|---|---|---|
| §7 ort 2.0.0-rc.9 (в gline-rs) | `[CONFIRMED]` | Cargo.toml fbilhaut/gline-rs |
| §7 tokenizers ^0.21 (в gline-rs) | `[CONFIRMED]` | `"0.21.0"` |
| §7 «rc.13 — нет в registry» | `[REFUTED]` | crates.io, 2026-07-28 |
| §11.3 «tokenizers 1.0.0-rc в реестре нет» | `[REFUTED]` | newest = 1.0.0-rc.2 |
| §11.2 download-binaries/copy-dylibs существуют | `[CONFIRMED]` | ort rc.13 features |
| §1/§2 id моделей GLiNER 2.5 | `[CONFIRMED]` | README fastino-ai/GLiNER2 |
| §1 llama-cpp-2 из utilityai/llama-cpp-rs | `[CONFIRMED]` | crates.io repository |
| §1 «rust-dd/llama-cpp-2» | `[PHANTOM]` | GitHub 404 |
| §8 Presidio-формат /anonymize | `[PARTIAL]` | Python-API прочитан, HTTP-контракт не промерен |
| §9 gh-release v2, checkout v4 | `[PARTIAL]` | существуют; актуальны v3 / v7 |
| §11.4 petrovich 0.2 | вне объёма сессии | не промерял (не в задании) |
| gline-rs/gliclass-rs поддерживают external-data | `[REFUTED]` | ни одного упоминания `.onnx_data` |

### Открытые хвосты (не закрыто в этой сессии)

1. HTTP-контракт Presidio REST (`/api/v2/anonymize`, точные поля JSON) — нужен
   `contents` API по дереву `presidio-anonymizer` (плоские raw-пробы путей не сработали).
2. Наличие ONNX-экспортов у `fastino/gliner2.5-multi-v1` и `GLiNER2.5-multi-Decide` —
   HF, не GitHub (лежит на HF-промере).
3. Полный греп дерева `fbilhaut/orp` на external-data — следующий промер.
4. Прочие версии §7 (`reqwest 0.13`, `axum 0.8`, `petrovich 0.2`) — не в этом задании.

*Промерено первичкой (GitHub API + raw + crates.io) в сессии 2026-10-18, транспорт
`curl -A "dsh-audit/1.0"`. Git-операций не выполнялось — создан только этот файл.*
