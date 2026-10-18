# fasad — локальный AI-гард: спецификация для сборщика-агента

> Статус: **гипотеза, вторичный источник**. Вся фактура ниже — из транскрипта
> диалога с LLM-ассистентом (носитель удалён; детали в `docs/source-note.md`) и не проверена по первичке.
> Каждый пункт помечен: `[claim]` = утверждение модели, требует кросс-чека перед
> тем как становиться кодом; `[decided]` = принятое командой направление.
> Правила fidelity: `process-rules-knowledge-wiki` (fact from secondary = claim),
> `process-rules-knowledge-wiki` § snapshot-is-prior-art (снапшот версий протухает).

## 0. Что это (одна строка)

Одиночный нативный демон-стендэлон (Linux + Windows), локальный «AI-брандмауэр»:
размечает входящий текст по категориям конфиденциальности, принимает решение
MASK/KEEP, обратимо подменяет секретные спаны, проксирует запросы к внешней LLM.
Полностью оффлайн, без Python/Docker-рантаймов, бюджет <2 ГБ, латентность 80–300 мс.

## 1. Рамки (constraints)

1. Язык ядра: **Rust**, Cargo workspace, edition 2024, MSRV 1.85+ `[decided]`
2. Целевые triple: `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` `[decided]`
3. Память: все модели resident, суммарно ≤1.8 ГБ; без поочерёдной выгрузки — cold
   reload стоит 300–1500 мс на запрос `[claim]`
4. UI: минимальная веб-песочница, зашитая в бинарник (`rust-embed`), фронт
   Svelte/Preact ~50 КБ; закрытая вкладка = 0 байт ОЗУ `[claim]`
5. Fail-Closed: таймаут/паника/нехватка памяти → запрос наружу НЕ уходит `[decided]`
6. Никакой телеметрии; весь разбор завершается на 127.0.0.1 до первой сокет-операции `[decided]`

## 2. Пайплайн (4 каскада)

### Каскад 0 — детерминированный (<1 мс) `[claim]`
- Regex O(n) (`rust-lang/regex`) + контрольные суммы: ИНН 10/12, СНИЛС mod101,
  ОГРН/ОГРНИП, карты Луна (вкл. «Мир» 2200–2204), р/с 40702/40817/30101+БИК, IBAN.
- Секреты по образцу сканеров: двухфазный префикс-префильтр (`AKIA`, `ghp_`, `sk-`,
  `eyJ`, `xoxb-`) через `aho-corasick` → тяжёлая regex в окне ±200 байт → энтропия
  Шеннона + Probability-of-Randomness. Референсы architectures: `mongodb/kingfisher`
  (Tree-sitter контекст: токен должен лежать в строковом литерале/присваивании,
  не быть именем функции или тестовой заглушкой), `praetorian-inc/noseyparker`,
  `sirwart/ripsecrets`. Live-верификацию токенов как у TruffleHog НЕ делаем (сеть
  нарушает air-gap и добавляет 300–2000 мс) `[claim]`.
- Автомат Ахо–Корасик: ОПФ (ООО/ПАО/АО/ИП/GmbH/B.V.), адресные маркеры, паспортные
  маркеры, суффиксы отчеств во всех падежах.
- Приоритет чексуммы = 1.0, нейросети его не пересматривают (абсолютное вето).
- PRE-компоненты (нормализация, чексуммы, префиксы) — есть; точные списки правил
  kingfisher/noseyparker — не сверены с репо `[claim-unverified]`.

### Каскад 1 — экстрактор (ONNX, 40–100 мс) `[claim]`
- Модель: `fastino/gliner2.5-multi-v1` (span-free boundary extraction,
  mDeBERTa-v3, ~300M), опц. спец-вариант `fastino/gliner2-privacy-filter-PII-multi`
  (42 PII-типа, SPY recall 0.718) `[claim]`
- Порог извлечения τ_low = 0.20–0.25 — намеренно низко: FN фатален, FP дёшев при
  обратимой типизированной токенизации `[decided]`
- Выход: спаны `[byte_start, byte_end]` + вектор классов + confidence.
- Чанкинг: 256–384 токена, overlap 32, length bucketing, B=1..4 на CPU;
  батчить 4096 токенов одним куском нельзя (O(L²) + padding waste) `[claim]`
- Кэш эмбеддингов схемы меток: тензор E ∈ R^{C×D} считается один раз на старте `[claim]`

### Каскад 2 — арбитр серой зоны (ONNX, 15–25 мс на батч спорных) `[claim]`
- Модель: `fastino/GLiNER2.5-multi-Decide` (~287M): вопросы yes/no, choice, score
  за 1 forward pass, 0 токенов генерации — «Jev-подобное» решение без генеративной LLM.
- Вызывается ТОЛЬКО для спанов 0.22 ≤ p1 < 0.80 и контекстно-зависимых классов
  (PERSON/ORG/КОММЕРЧЕСКАЯ_ТАЙНА) — short-circuit.
- Итоговый скор: S = 1.0 (чексумма) | S = p1 (p1 ≥ 0.80) | S = α·p1+(1−α)·p2 (серая зона).
- Риски в модели: порог 0.20–0.25 может давать FP-шум (арбитраж не всесилен), α не
  калибрована; SOTA-числа Fastino — самонаписанные карточки HF `[claim-unverified]`.

### Каскад 3 — трансформация
- Типизированные токены с ролью: `[CLIENT_PERSON_1]`, `[VENDOR_ORG_2]` — не слепой
  `[REDACTED]` (внешняя модель должна сохранять граф связей).
- Слияние пересекающихся спанов: interval tree, greedy leftmost-longest,
  min(start)..max(end), приоритет чексуммы не понижается.
- Semantic rewrite абзацев — опционально, отдельная генеративная модель (см. §5).

## 3. Обратимость (Vault) — три режима жизни данных

1. **Request-scoped ephemeral** (запрос без `X-Session-ID`): таблица живёт в задаче
   tokio, затирается `ZeroizeOnDrop` в момент отправки `[DONE]`.
2. **Session cache** (`moka`): sliding TTL 15 мин (time_to_idle), hard TTL 2 ч
   (time_to_live), eviction listener → `.zeroize()`. Нужен для многоходовых чатов:
   «Алексей Смирнов» в 1-м и «Алексею» в 5-м сообщении = один и тот же ID.
3. **Stateless vault_token** для `/v1/anonymize`: словарь → LZ4 →
   ChaCha20-Poly1305 (мастер-ключ 32 байта в mlock-памяти) → клиент сам носит токен;
   сервер в покое хранит 0 байт пользовательских данных.
- Память оригиналов: `mlock` (Linux) / `VirtualLock` (Windows) через крейт `region`.
  Обычный `drop` НЕ стирает байты — только помечает свободными; swap/dump = утечка `[claim]`
- TTL — не ради экономии (таблица <50 КБ), а ради криптогигиены и непрорастания кэша.
- In-memory vault хранит оригиналы в открытом виде: защита = zeroize + mlock
  против своп/дампа, а НЕ шифрование в RAM. Расшифровка stateless-токена идёт в
  mlock+zeroize-буфер `[decided]`

## 4. Морфология RU (без LLM)

- **Суррогаты:** спан → лемма (`rsmorphy`) → в Vault пишем лемму (дедуп падежных
  форм) → из пула берётся синтетическое имя того же рода, склоняется `petrovich`
  во все 6 падежей → все формы регистрируются в обратном `aho-corasick` с
  привязкой `(EntityId, Case)`. Внешняя LLM видит гладкий текст и сама склоняет;
  на обратном пути берём падеж из ответа и ставим оригинальную лемму в него.
- **Суффиксные капсулы** для кастомных терминов: основа отделена от флексии, в
  промпт уходит `Компания_1-ем`; при возврате парсим окончание и склеиваем с
  основой из Vault.
- Реальная латентность морфологии — не промерена; держать в бюджете `< 1 мс/запрос`
  как измерять-будет-задача `[claim-unverified]`

## 5. Решения по моделям (с откатами, против первоначальной версии)

1. **JevK5 в llama.cpp — НЕ нужен** `[decided]`. Обоснование: JevK5-2B рабочий квант
   Q8_0 = 2.01 ГБ (пробивает бюджет), Q4_K_M теряет точность (0.604→0.514 hard-tier,
   авторы не публиковали 4-бит) `[claim]`. Арбитраж делает энкодер Decide.
2. **llama.cpp + генеративная модель (Qwen 1.5–2B Q4_K_M, ~1 ГБ) — опциональный
   feature-gate** `[decided]`: нужен только для semantic rewrite абзацев и локального
   fallback-чата. Без него стек = только ONNX, RAM 400–650 МБ, сборка без Vulkan/GGUF.
   При включении: KV-кэш системного промпта пинится (prefill ×4–5 быстрее), GBNF-грамматика.
3. **KV-кэша у энкодеров нет** (attention без причинной маски, 1 forward pass) `[claim]`.
   Что кэшируем вместо: эмбеддинги меток, ORT mem-arena (`enable_mem_pattern`,
   `enable_cpu_mem_arena` — точные имена API сверить по ORT-доке), scratchpad-арена
   ~25–40 МБ под B4×384 фиксированная, LRU-мемоизация по xxHash абзацев.
4. «Диффузионные» архитектуры для разметки НЕ нужны — двунаправленный энкодер уже
   «раскрашивает» весь текст за 1 проход (матрица N×K) `[claim]`.
5. Держать **два ONNX-графа одновременно** (экстрактор + Decide) — только после
   замера RAM/VRAM; если не влезает, стартовать с `GLiNER2.5-multi-Decide` как
   универсала, который закрывает и извлечение, и решение `[claim-unverified]`
6. Точность-цель: recall ≥ 98 % на эталонных 50 RU/EU-примерах. Заметка о метрике:
   «99 %» на сайтах = 48/50 = 96 %, Wilson CI ≈ 86.5–98.9 %, гибридный пайплайн на
   типовых бизнес-текстах; академический SPY мёрится голой сеткой, цифры несопоставимы `[claim]`

## 6. Структура workspace

```
fasad/
├─ Cargo.toml              # [workspace] + [workspace.dependencies]
├─ crates/
│  ├─ guard-types/         # ByteSpan, AnnotatedSpan, DetectionSource, Verdict,
│  │                       #   SecretString(ZeroizeOnDrop, Debug=REDACTED)
│  ├─ guard-detectors/     # normalizer(OffsetMap), checksums(RF/EU), secrets,
│  │                       #   dictionary(aho-corasick)
│  ├─ guard-onnx/          # chunker, extractor, arbitrator, merger(IntervalTree)
│  ├─ guard-vault/         # morphology, session_store, stateless_token,
│  │                       #   stream_rewriter(SSE look-ahead FSM)
│  └─ guard-daemon/        # axum routes, rust-embed UI, tray (опц.), fail-closed mw
├─ ui/                     # Svelte/Preset → ui/dist
├─ models/                 # не в гите; download-скрипт + checksums-манифест
├─ config/                 # schema.default.json (категории + описания label)
├─ data/golden/            # 50 эталонных примеров RU/EU, recall gate
└─ .github/workflows/      # ci.yml, release.yml
```

## 7. Зависимости (снапшот версий от 18.10.2026 — ПЕРЕСЧИТАТЬ перед сборкой)

| Crate | Версия из транскрипта | Features / назначение | Реальность на 18.10.2026 |
|---|---|---|---|
| ort | 2.0.0-rc.13 | download-binaries, copy-dylibs, half; directml/win | rc.13 — нет в registry |
| tokenizers | 0.23 / 1.0.0-rc | default-features=false; tk-encode (3–30×) | 1.0.0-rc в registry нет, см. §11 |
| ndarray | 0.16 | декод границ спанов | |
| tokio | 1.5x | rt-multi-thread, net, sync, time, signal | |
| axum | 0.8.x | json, http1/2 | |
| tower-http | 0.6 | cors, trace, timeout, limit, catch-panic | |
| reqwest | 0.13 | rustls-tls, stream, json (без native-tls) | |
| aho-corasick | 1.1 | perf-literal | |
| regex | 1.13 | perf, unicode-perl | |
| petrovich | 0.2 | склонение ФИО | |
| rsmorphy | latest | лемматизация RU | |
| moka | 0.12 | future; TTL-кэш сессий | |
| zeroize | 1.8 | derive, ZeroizeOnDrop | |
| region | 4.0 | mlock / VirtualLock | |
| chacha20poly1305 | 0.10 | AEAD vault_token | |
| lz4_flex | 0.13 | сжатие словаря | |
| rust-embed | 8.x | compression; UI в бинарнике | |
| xxhash-rust / ahash | latest | мемоизация абзацев | |

Версии в таблице — **снапшот из транскрипта**, не сверялись в момент написания §7.
Промер crates.io выполнен 18.10.2026 → **§7.1** (истинные пины: `docs/dep-verify-crates.md`).

Конфликт, который уже известен: готовые обёртки `gline-rs` (1.1.0) и `gliclass-rs`
(1.0.0) зажаты на `ort 2.0.0-rc.9` + `tokenizers ^0.21`, а GLiNER 2.5 требует
кастомного декода границ → **пишем свой пре/postprocess поверх `ort` напрямую**,
gline-rs только как референс алгоритма `[decided]`

### 7.1 Промер первички 18.10.2026 (crates.io) → `docs/dep-verify-crates.md`

1. **Ложных версий в §7 нет** — все 18 имён отдают HTTP 200; заявленные числа
   существуют буквально или как префиксы реальных линеек. Ожидание «транскрипт
   наврал» опровергнуто; подтверждено «транскрипт протух»: 11 позиций отстали.
   Ранние пометки «petrovich только 0.1.0», «ort rc.13 нет в реестре», «tk-encode
   не резолвится» в source-note — **ошибки неполного промера**, отзываются.
2. `ort`: стабильной 2.0.0 нет, вся линейка 1.x yanked → единственный путь —
   пре-релиз; актуальная `2.0.0-rc.14` (12.10.2026), репозиторий `pykeio/ort`;
   флаги `download-binaries`/`copy-dylibs` входят в default (объявлять не нужно);
   дельта rc.13→rc.14 в дефолте `api-27`→`api-31`. Пинить rc, следить CHANGELOG.
3. Breaky-бампы (смена минорной, только через CI-матрицу): `tower-http 0.6→0.7.1`,
   `chacha20poly1305 0.10→0.11.0`, `lz4_flex 0.13→0.14.0`, `ndarray 0.16→0.17.2`.
4. Морфология: `petrovich 0.2.0` жив на полке, но мёртв с 04.2020; `rsmorphy 0.4.0`
   мёртв с 08.2018 → кандидаты на замену/форк; проверка лицензии и MSRV 1.85+ —
   отдельная задача (§10 шаг 5).
5. `tokenizers 1.0.0-rc.2` + `tk-encode 0.1.0-rc.2` (тот же репо, тот же день
   релиза 21.09.2026) — версии синхронизировать вручную.
6. Пинки в `Cargo.toml` — по `docs/dep-verify-crates.md`, не по §7.

## 8. API (по устоявшимся протоколам, не изобретаем)

| Метод | Совместимость | Назначение |
|---|---|---|
| POST `/v1/chat/completions` | OpenAI (+Anthropic-совм. `/v1/messages`) | прозрачный прокси: маска → upstream → SSE deanonymize |
| POST `/v1/analyze` | Presidio Analyzer / Lakera | спаны+offsets+векторы классов+вердикты, текст не меняет |
| POST `/v1/anonymize` / `/v1/deanonymize` | Presidio Anonymizer | двухшаговый, stateless `vault_token` |
| DELETE `/v1/sessions/{id}`, PUT `/v1/schema` | REST | сброс сессии / горячая смена схемы категорий |
| GET `/ui` | — | зашитая песочница (подсветка α=confidence) |

Заголовки: вход `X-Upstream-URL`, `X-Session-ID`, `X-Guard-Policy: mask|block|audit_only`;
выход `X-Guard-Redacted-Count`, `X-Guard-Max-Risk`, `X-Guard-Latency-Ms`.
SSE: look-ahead буфер до 32 байт — токен `[PERSON_1]` может прилететь нарезанным на
3 пакета; наивный replace по чанку ломает обратимость `[claim]`

## 9. CI/CD (GitHub)

**ci.yml** (push main + PR): job `lint-and-audit` (toolchain stable + fmt/clippy
`-D warnings -D clippy::unwrap_used`, cargo-deny check advisories/bans/licenses,
запретить `openssl-sys` и `native-tls` в дереве) + job `test-matrix`
(ubuntu-24.04 × windows-2022: build UI → `cargo test --workspace --release`,
golden-50 recall gate, property-тесты OffsetMap на рваной кириллице, стресс
stream_rewriter с нарезкой SSE по 1–2 байта).

**release.yml** (тег `v*.*.*`): матрица `ubuntu-22.04 → x86_64-unknown-linux-gnu`
(glibc 2.35 для старых рабочих станций) × `windows-2022 → x86_64-pc-windows-msvc`.
`[profile.release]`: `lto="fat"`, `codegen-units=1`, `panic="unwind"` (НЕ abort —
middleware должен переживать панику отдельного запроса), `strip="symbols"`,
`RUSTFLAGS="-C target-cpu=x86-64-v3"`. Артефакт: tar.gz/zip = бинарь +
`libonnxruntime.so`/`onnxruntime.dll` рядом (ort `copy-dylibs`) + `schema.default.json`
+ SHA256SUMS → `softprops/action-gh-release@v2`.

## 10. Порядок сборки для агента (атомарные шаги, по одному PR)

1. Scaffold workspace + `guard-types` + CI-заглушки → зелёный `cargo check` обеих ОС.
2. **Model-fetch spike**: скрипт скачивания ONNX + замеры реального RAM/латентности
   на нашей машине ДО написания рантайма (см. §11 — модели не подтверждены).
3. `guard-detectors`: нормализатор + OffsetMap (property-тесты) → чексуммы
   РФ/ЕС (таблицы весов проверить по первичке ФНС/iban.com) → secrets-сканер
   (референс kingfisher/noseyparker, свои тесты на false positives) → ахо-автомат.
4. `guard-onnx`: свой декодер boundary-голов GLiNER 2.5 по туториалу HF-карточки
   (референс gline-rs), chunker 256–384, батч-бакетинг, кэш эмбеддингов, merger.
5. `guard-vault`: морфология, ephemeral/session/stateless-три режима, FSM-стрим-рерайтер.
6. `guard-daemon` + `/v1/analyze` + `/v1/anonymize|deanonymize`; fail-closed mw.
7. Прокси `/v1/chat/completions` + SSE look-ahead.
8. UI-песочница (раскраска α=confidence, редактор схемы) + rust-embed.
9. Release-воркфлоу, кросс-сборки, профилирование пика RAM (цель ≤1.8 ГБ).

## 11. Открытые вопросы — ПЕРВИЧНАЯ ВЕРИФИКАЦИЯ ДО КОДА

1. **GLiNER 2.5 может не существовать.** В нашей карточке дозора (от 26.09.2026)
   по модели названа `GLiNER2.5-Decide`, а в HF-промере 17.10 — `♥357 / dl 53 625`,
   т.е. модель жива. Но `fastino/gliner2.5-multi-v1` и `gliner2-privacy-filter-PII-multi`
   в транскрипте **не имеют ни HF-URL, ни карточек** — под этими точными именами
   они могут не существовать. Первый промер — `GET https://huggingface.co/api/models?...`
   + карточки → записать реальные repo id, лицензии и наличие **ONNX**-экспортов
   (транскрипт сам себе противоречит: §1 говорит «GGUF в llama.cpp штатно не
   ложатся, энкодеру нужен ONNX», а §2 предлагает `JevK5-2B-GGUF` как арбитра).
2. **API `ort` 2.0.0-rc**: rc-контракты меняются от релиза к релизу. Пинить точный
   rc, прочитать CHANGELOG, сверить `download-binaries`/`copy-dylibs`.
3. **`tokenizers 1.0.0-rc` + `tk-encode`**: rc в реестре нет, `tk-encode` не
   резолвится → версия из транскрипта ложная. Взять актуальную `0.2x` (или то, что
   реально требует ort) и померить скорость самим; утверждение 3–30× не повторять в
   README как факт.
4. **petrovich 0.2**: на crates.io `petrovich = 0.1.0` (0.2.0 не опубликован);
   API-контракт транскрипта не сверен. Либо брать `rsmorphy` + свои таблицы,
   либо форк. Заодно проверить лицензию.
5. **Прочие версии**: `reqwest 0.13`, `ort rc.13` — из снапшота транскрипта; в
   нашей же заметке `inference-engines-census` llama.cpp/GGUF разобраны подробнее,
   а ONNX-рантаймы нет.
6. **Чексуммы РФ**: веса ИНН, mod101 СНИЛС, ОГРН — проверить по первоисточникам ФНС
   и ЦБ, не по пересказу LLM-транскрипта. Ошибиться в валидаторе = дырявая каскад-0 вето.
7. **Метрика recall ≥ 98 %**: собрать golden-50 СВОИМИ примерами (договоры, тикеты,
   анкеты, дампы) и мерить строгим span-match; чужие «99 %» — маркетинг на N=50.
8. **RAM-бюджет**: заявленные 350–600 МБ (ONNX-энкодер) и 1.0–1.2 ГБ (Q4 2B) —
   claims; померить RSS/VSS на нашей машине до того, как бюджет станет обещанием.

## 12. Связанные заметки wiki

- `llm/jev-mode-decoding` — что такое Jev/parallel-choice decode, наши дозоры, HF-промер
  GLiNER2.5-Decide, «System One», почему JevK5 не берём (Q8-размер)
- `llm/inference-engines-census` — каталог движков (llama.cpp-линия, серверные рантаймы)
- `security/guardrail-bypass-collections` — обходы гардрейлов (угроза модели, не стек)
- `llm/decode-speed-5090` — bandwidth-логика prefill vs decode (та же, что у KV-кэша)
- `process-rules-knowledge-wiki` — верификация, prior art, fidelity
- `process-rules-research-transport` — транспорт проб
