# Верификация крейтов Rust на crates.io — 2026-10-18

Первичный источник: REST API crates.io (`/api/v1/crates/<name>` и `/api/v1/crates/<name>/versions`).
Запросы: `curl -s -A "dsh-audit/1.0"` — без User-Agent crates.io отдаёт HTML-заглушку.
Промер выполнен 2026-10-18, все 18 имён ответили HTTP 200 (ни один крейт не выдуман).
Поле `crate.max_stable_version` = `None` у крейтов без стабильного релиза.
`вердикт` считается по заявлению SPEC: совпадает / заявленной нет / устарело.
Таблица — только API-факты, без домыслов.

| crate | заявлено в SPEC | max_stable | newest | вердикт |
|---|---|---|---|---|
| ort | 2.0.0-rc.13 | — (нет стабильного) | 2.0.0-rc.14 | устарело (rc.13 существует, есть rc.14) |
| tokenizers | 0.23 / 1.0.0-rc | 0.23.2 | 1.0.0-rc.2 | устарело (0.23 → 0.23.2; 1.0.0-rc → 1.0.0-rc.2) |
| ndarray | 0.16 | 0.17.2 | 0.17.2 | устарело (0.16.1 существовал, линейка снята с поддержки) |
| tokio | 1.53.2 | 1.53.3 | 1.53.3 | устарело (1.53.2 существует, есть 1.53.3) |
| axum | 0.8.9 | 0.8.9 | 0.8.9 | совпадает |
| tower-http | 0.6 | 0.7.1 | 0.7.1 | устарело (0.6.11 — потолок линейки 0.6, есть 0.7.x) |
| reqwest | 0.13.5 | 0.13.5 | 0.13.5 | совпадает |
| aho-corasick | 1.1.4 | 1.1.5 | 1.1.5 | устарело (1.1.4 существует, есть 1.1.5) |
| regex | 1.13.1 | 1.13.1 | 1.13.1 | совпадает |
| petrovich | 0.2.0 | 0.2.0 | 0.2.0 | совпадает (см. примечание о живучести) |
| rsmorphy | (не заявлено) | 0.4.0 | 0.4.0 | существует; всего 6 версий, максимум 0.4.0 |
| moka | 0.12 | 0.12.16 | 0.12.16 | устарело (0.12.16 — актуальный патч линейки 0.12) |
| zeroize | 1.8.2 | 1.9.1 | 1.9.1 | устарело (1.8.2 существует, есть 1.9.x) |
| region | 4.0.1 | 4.0.1 | 4.0.1 | совпадает |
| chacha20poly1305 | 0.10.1 | 0.11.0 | 0.11.0 | устарело (0.10.1 существует, есть 0.11.0) |
| lz4_flex | 0.13.1 | 0.14.0 | 0.14.0 | устарело (0.13.1 существует, есть 0.14.0) |
| rust-embed | 8.13.0 | 8.13.0 | 8.13.0 | совпадает |
| tk-encode | (отдельный крейт) | — (нет стабильного) | 0.1.0-rc.2 | существует, НЕ вымышлен |

## Отдельно: ort — линейка 2.0.0-rc.N

`repository` из API: <https://github.com/pykeio/ort> (репозиторий `pyke/ort` и `rust-dd/ort` не существуют — обе догадки ошибочны).

`max_stable_version` = `null`: стабильной 2.0.0 на crates.io нет ни одной.
Зато вся линейка 1.x **yanked** (1.14.8 … 1.16.3, у всех `yanked: true`), последний 1.16.3 опубликован 2023-11-12.
Практический вывод: единственный способ взять ort — пре-релиз 2.0.0-rc.N.

Все доступные rc (15 шт., ни один не yanked):

| версия | опубликована |
|---|---|
| 2.0.0-rc.14 | 2026-10-12 |
| 2.0.0-rc.13 | 2026-07-28 |
| 2.0.0-rc.12 | 2026-03-05 |
| 2.0.0-rc.11 | 2026-01-07 |
| 2.0.0-rc.10 | 2025-06-01 |
| 2.0.0-rc.9 | 2024-11-21 |
| 2.0.0-rc.8 | 2024-10-19 |
| 2.0.0-rc.7 | 2024-10-18 |
| 2.0.0-rc.6 | 2024-09-10 |
| 2.0.0-rc.5 | 2024-08-18 |
| 2.0.0-rc.4 | 2024-07-07 |
| 2.0.0-rc.3 | 2024-07-06 |
| 2.0.0-rc.2 | 2024-04-27 |
| 2.0.0-rc.1 | 2024-03-28 |
| 2.0.0-rc.0 | 2024-02-06 |

Максимальная rc: **2.0.0-rc.14** (updated_at крейта 2026-10-12, свежее SPEC на ~2.5 месяца).
2.0.0-alpha.1 … alpha.4 тоже существуют, все yanked — брать нельзя.

### Feature-флаги ort: `download-binaries` и `copy-dylibs`

Проверено по полю `versions[].features` endpoint'а `/api/v1/crates/ort/versions` (не по README).

- `2.0.0-rc.14`: `download-binaries = ["ort-sys/download-binaries"]`, `copy-dylibs = ["ort-sys/copy-dylibs"]` — оба присутствуют, оба делегируют в крейт `ort-sys`.
- `2.0.0-rc.13` (заявлена в SPEC): оба флага тоже присутствуют, сигнатуры идентичны.
- Оба флага входят в `default` rc.14: `["std","ndarray","tracing","download-binaries","tls-native","copy-dylibs","api-31"]`.
- Заявлять их в `[dependencies]` явно не требуется — дефолт их уже несёт.
- Разница `default` между rc.13 и rc.14: API-флаг `api-27` → `api-31` (в rc.14 доступна цепочка `api-17` … `api-31`).
- README репозитория (`main`, 57 строк) этих флагов не упоминает; источник фактов — API, не README.

## Отдельно: tk-encode и tokenizers

Крейт **существует**, вымыслом не является. API-запись:
- `repository`: <https://github.com/huggingface/tokenizers> — то есть тот же репозиторий, что у `tokenizers`.
- `documentation`: <https://docs.rs/tokenizers/>.
- `description`: «Inference (encode/decode) half of the 🤗 Tokenizers library … without any training code.»
- `created_at`: 2026-09-21, `updated_at`: 2026-09-21, всего 3 версии: `0.1.0-dev.0`, `0.1.0-rc.1`, `0.1.0-rc.2` (обе rc одного дня, 2026-09-21).
- `max_stable_version`: `null` — стабильного релиза нет, только пре-релизы.
- Вывод по факту данных: `tk-encode` — это inference-половинка, выпиленная из `tokenizers` при переходе на 1.0.0 (совпадает по дате с `tokenizers 1.0.0-rc.2`, 2026-09-21).

## Отдельно: petrovich и rsmorphy (морфология)

- `petrovich 0.2.0` — версия совпадает, крейт жив на полке, но `updated_at` = **2020-04-06**: крейт не обновлялся ~6,5 года, всего 3 версии за всю историю (0.1.0, 0.1.1, 0.2.0).
  **Крейт мёртв 6+ лет; проверка лицензионной чистоты и работоспособности на rustc 1.85+ — отдельная задача.**
  Числов по MSRV API не отдаёт в этом ответе — не заявляем.
- `rsmorphy` — SPEC версии не заявлял. max_stable = newest = **0.4.0**, `updated_at` = **2018-08-26**: мёртв ~8 лет, 6 версий, последняя 0.4.0. Это худший показатель живучести из всей выборки.

### Допромер 20.10 (`gh api`, токен; курсор снял rate-limit curl-ветки): «мёртв» верно только про ПУБЛИКАЦИЮ, репозитории живы

Прежний абзац мерил **crates.io** и остаётся верным на уровне публикации. На уровне
кода картина другая: оба дерева поддерживаются вне реестра, и по `petrovich` найден
прямой преемник. §11 п.4 переформулируется: «крейт мёртв» ≠ «кода нет».

1. **`petrovich` → живой форк `rodem/petrovich-rs`** (цепочка: Ruby-гем
   `petrovich/petrovich-ruby` — push 2026-06-19, MIT, 410★ — его порт
   `Latrasis/petrovich-rs` — застывший 2020-04-06 — и форк `rodem/…`). README порта
   дословно: «Rust implementation of Petrovich ruby gem» — то есть **да, это порт**,
   и апстрим-гем жив. Промер форка: push **2026-09-23**, 11 коммитов с 01.01.2026,
   `license = "MIT"`, `edition = "2024"`, имя либы осталось `petrovich` (drop-in к нашему
   пину), build-dep `serde_yaml 0.8.11` **заменён на `serde_yaml_ng 0.10`** (MIT,
   2024-05-26) — снимает yaml-цепочку RUSTSEC; в `Cargo.toml` объявлены `[[test]]
   golden_declension` + `golden_gender`, файлы на месте (`tests/*.rs`, `tests/data/`).
   Публикации нет: `petrovich-core` на crates.io → HTTP 404, README прямо называет
   «старая версия 0.2 — заброшенный форк», публикация — PLAN.md этап 5.
   → Подключение сегодня возможно **только git-зависимостью с пином rev** (не blob —
   закон source-capture соблюдается).
2. **`rsmorphy` → репо живёт: `irbis-labs/rsmorphy`** (crates.io field вёл на
   `alexander-irbis/rsmorphy`, редирект). push **2026-03-28**, коммиты 2026-01-02 /
   2024-06-01 / 2023-09-26 (фикс cast'а, переименования типов, миграция зависимостей) —
   релиза поверх 0.4.0 нет. Лицензия README: **MIT OR Apache-2.0** (в allow-листе deny),
   словарь в репо (`rust/dict/{ru,uk}`), отдельно `rsmorphy-dict-ru 0.1.0` объявлен MIT.
   → Тот же вывод: брать git-rev либо ничего; crate 0.4.0 ≠ master.
3. **Альтернативы из поиска (регистрация по правилу «любой новый источник → в трекинг»):**
   `rs-morphy4 0.1.3` (LdDl; релиз 2026-10-16, репо создан 2026-10-14, 0★) — лицензионное
   выражение `Apache-2.0 AND MIT AND CC-BY-SA-3.0`: **CC-BY-SA нет в allow-листе
   `deny.toml`, гейт краснеет** (copyleft на данных словаря OpenCorpora; код — Apache-2.0).
   `zaliznyak 0.2.0` (Chasmical; push 2026-08-10, MIT OR Apache-2.0, deps тощие —
   bitflags + thiserror): склонение существительных/прилагательных/местоимений по классам
   Зализняка, **API не про ФИО** (`firstname/lastname/middlename` нет). `morph-rs 0.2.0`
   (2024-03) — `non-standard` → отказ по лицензионному гейту. `quarb-lib-morph 0.38.1` —
   обёртка pymorphy3 = Python в продукте → отказ по рулингу 19.10.
4. **RUSTSEC-фон yaml-цепочки** (локальная копия advisory-db, HEAD `999ec89`):
   `yaml-rust` — RUSTSEC-2024-0320 `informational = "unmaintained"` (транзитив только
   `petrovich 0.1.x`, нам не светит); `serde_yaml` — RUSTSEC-2018-0005 (abort на
   рекурсии), patched ≥ 0.8.4, т.е. пин 0.8.11 чист; `serde_yml` — informational unsound;
   `serde_yaml_ng` и `yaml-rust2 0.13.0` (2026-09-11) — записей нет. Ни `petrovich`, ни
   `rsmorphy` самих в RUSTSEC не значатся.
5. **Следствие для SPEC §11 п.4 и шага 5.** Вместо «замена решается на шаге 5» — три
   конкретные ветки: (а) git-rev `rodem/petrovich-rs` (MIT, edition 2024) + git-rev
   `irbis-labs/rsmorphy`; (б) `rs-morphy4` — только если оператор отдельно примет
   CC-BY-SA на словарь; (в) **инлайн-таблица**: пул суррогатов — наши данные, все 6
   падежей выпекаются на билде, рантайм-движок склонения не нужен, из морфологии
   остаётся только снятие падежа/леммы с оригинала. (в) — единственная ветка, которая
   не тащит в дерево чужой код. `deny.toml:13 unmaintained = "workspace"` остаётся как есть.

## Итог

### Ложных версий в SPEC нет

Ни одна заявленная версия не выдумана.
Все 18 имён крейтов отдают HTTP 200.
Каждое заявленное число либо существует буквально, либо является префиксом реальной линейки (`0.23` → `0.23.2`, `0.6` → `0.6.11`, `0.12` → `0.12.16`, `0.16` → `0.16.1`).
Отдельно фиксируем: `ort 2.0.0-rc.13` — реальная версия, и `tk-encode` — реальный крейт, вопреки ожиданию, что это галлюцинация транскрипта.

### Протухшие (SPEC отстал, надо поднимать)

11 позиций:
`ort` (rc.13 → rc.14),
`tokenizers` (0.23 → 0.23.2; 1.0.0-rc → 1.0.0-rc.2),
`tokio` (1.53.2 → 1.53.3),
`aho-corasick` (1.1.4 → 1.1.5),
`zeroize` (1.8.2 → 1.9.1),
`tower-http` (0.6.11 → 0.7.1, **смена минорной**),
`chacha20poly1305` (0.10.1 → 0.11.0, **смена минорной**),
`lz4_flex` (0.13.1 → 0.14.0, **смена минорной**),
`ndarray` (0.16.1 → 0.17.2, **смена минорной**),
`moka` (0.12 → 0.12.16, патч внутри линейки),
`tk-encode` (в SPEC версии не было → актуальный `0.1.0-rc.2`).

### Совпадает (трогать не нужно)

6 позиций: `axum 0.8.9`, `reqwest 0.13.5`, `regex 1.13.1`, `region 4.0.1`, `rust-embed 8.13.0`, `petrovich 0.2.0`.

### Что ломает SPEC §7 при апдейте

- `ort`: весь 1.x yanked, стабильного 2.0.0 нет → проект обречён на пре-релиз; `api-27` → `api-31` в дефолтах rc.13→rc.14.
- 4 крейта со сменой минорной (`tower-http`, `chacha20poly1305`, `lz4_flex`, `ndarray`) — по semver это потенциально breaky, bump требует прогона CI-матрицы, а не правки цифры.
- `petrovich` и `rsmorphy` мертво (2020 и 2018) — кандидаты на замену, отдельная задача по MSRV/лицензиям.
- `tokenizers` + `tk-encode` живут в одном репо и зарелижены одним днём (2026-09-21); версии надо синхронизировать вручную, API связи между ними не даёт.

## 12. Промер шага 5 (20.10, agent-зонд /tmp/{petrovich-probe,pv-vendor,crypto-probe}; rustc 1.85.0 (4d91de4e4), aarch64-apple-darwin)

Родительские spot-check (тот же вечер, `~/.cargo/registry/src/…/Cargo.toml` + gh api):
`rust-version="1.85"` у aes-gcm-0.11.1/chacha20poly1305-0.11.0/hkdf-0.13.0/zeroize-1.9.1/sha2-0.11.0
и `1.75` у keyring-3.6.3 — подтверждено из реестр-кэша; LICENSE-файла в дереве rodem/petrovich-rs@019e06d
нет (gh api trees: корень = .gitignore Cargo.lock Cargo.toml PLAN.md README.md build.rs cli com examples
src tests web; `/license` → 404) — подтверждено.

**Морфология (§11 п.4, финальная ветка).** Ветка (а) принята: `petrovich-core` git-rev-пин
`rodem/petrovich-rs@019e06dd01c590ff4dd82c762b55465bea5c8d2b` (master tip на промер; тегов нет).
edition 2024 де-факто = MSRV наш пин; runtime-зависимостей 0 (yaml только build-deps,
serde_yaml_ng 0.10.0 без RUSTSEC-записей; advisory-db HEAD 999ec89, дата записи 2026-10-17,
на хосте клона нет — промер deny воспроизведён с авто-клоном); build на 1.85 зелёный,
форма пина под наш `deny.toml wildcards="deny"`: `{ version = "0.2.0", git = …, rev = … }`
(без version — bans FAILED «found 1 wildcard dependency»; с version — bans ok, lock = git+019e06d;
промер ревьюера 20.10).
golden-форка (прогнан ревьюером с нуля на пине, rustc 1.85.0): surnames 79 927/80 025 (99.878 %),
firstnames 63 088/63 680 (99.07 %), midnames 81 355/81 355 (100 %); расхождения сверяются с
зафиксированным дампом allowlist (surnames.allow.tsv 98 строк, firstnames.allow.tsv 592 —
паритет с ЭТАЛОНОМ-DUMP, не с живым Ruby-прогоном).
API под задачу restore есть: `lastname/firstname/middlename(Gender, &str, Case)→String`,
`Case` — 5 косвенных (именительный = лемма; формулировку SPEC §4 «все 6 падежей» читать так).
Ветки отклонены промером: (б) vendor git-dep = 23 МБ (15 МБ чужих корпусов); ручной vendor
промерян и работает (6 файлов+build.rs = 2 030 строк/61 КБ, golden зелёный) — остаётся
ЗАПАСНОЙ веткой на случай air-gap-билда; (в) self = переписать 78 правил (10 364 Б MIT-данных)
и потерять регрессионный гейт корпусов (3 золотых tsv = 275 031 строка, из них харнессом
проверяется 225 060; все tsv каталога = 322 080 — промеры ревьюера 20.10; цифра 275 148 из
первички зонда не воспроизвелась ни одной командой — отброшена). Гейт при ветке (а) живёт НЕ
в cargo graph (tests/ git-dep не входят в граф сборки) — запускать шагу 5 клон-прогон `cargo test -p
petrovich-core --test golden_declension` на пине; место интеграции (CI-джоба vs release-гейт)
— open point шага 5. Условие мержа: `THIRD-PARTY-NOTICES.md`
MIT © 2013–2014 Kozloff & Ustalov (файла LICENSE нет ни в форке, ни в оригинале, ни в .crate —
текст из апстрим petrovich/petrovich-ruby, MIT-LICENSE).
Остаток дыры: снятие падежа/леммы с ОРИГИНАЛА по-прежнему на мёртвом rsmorphy — отдельная
задача (issue #46), приоритетнее реализации vault-морфологии; род для кастомных ФИО через
`detect_gender` (gender.yml 10.8 КБ) — решение на шаге 5.
Риск-флаг: форку 35 дней (created 2026-09-15), 0★, дельту пишет 1 автор (contributors всего 4:
Latrasis 40, rodem 11, broadwaylamb 5, road21 коммит 1 — дерево пина несёт и чужой код) →
зеркало в собственные remotes перед шагом 5 + синхронная правка строки `petrovich | 0.2`
в SPEC §7 на git-rev форму.

**Крипто-стек (SPEC §3; режим 3 stateless_token = ChaCha20-Poly1305, AES-GCM там нет).**
Решение, не промер: runtime AEAD = chacha20poly1305 (уже пин). Новые пины-кандидаты:
aes-gcm 0.11.1, hkdf 0.13.0 — для AAD-связывания (домен-разделение ключей) на случай, если
шаг 5 выберет envelope с контекстом — тогда это amendment к SPEC §3, а не тихая замена.
Существующие пины верны: chacha20poly1305 0.11.0, zeroize 1.9.1, sha2 0.11.0 (действующий пин
workspace, Cargo.toml:52 — вторым ключом не дописывать); лицензия
Apache-2.0 OR MIT у всех, MSRV 1.85 = пин; RUSTSEC-записи по стеку есть, вне наших диапазонов
(aes-gcm RUSTSEC-2023-0096 patched ≥0.10.3; sha2 RUSTSEC-2021-0100 patched ≥0.9.8) — «advisories ok»
честно; roundtrip-прогон release на 1.85 чистый
(AES-256-GCM AAD PT38→CT54; XChaCha20 PT27→CT43; HKDF-SHA256→OKM32; ZeroizeOnDrop derive
работает ТОЛЬКО с `features=["derive"]` — без него `cannot find derive macro`).
`cargo tree -d` пуст, deny advisories/licenses ok. API-ньюанс: aead 0.6 — `&Nonce`,
`Array::from_slice` deprecated → `Nonce::try_from`.

**keyring (#31, отложить до шага 8).** Пин 3.6.3 (`apple-native`, rust-version 1.75, билд на
1.85 зелёный); линейка 4.0.0–4.2.0 = MSRV 1.88 — вне пина, bump MSRV = отдельное решение.
В SPEC keyring не назван (только «tray (опц.)» L236) → строка §7 пишется на шаге 8.

## 13. Промер шага 6 (21.10, `just check` rc=0 на tip `ec05ae5`; rustc 1.97.0 / канон 1.85, aarch64-apple-darwin)

**http-body-util (добавлен сверх SPEC §7).** Причина одна: `BodyExt::frame` —
собственный счётчик байт тела в `guard-daemon::http::read_body`, чтобы перелив
лимита (`413 body_too_large`) отличался от оборванного потока (`400 bad_body`).
Через `axum::body::to_bytes` различить нечем: `axum_core::Error` = прозрачная
обёртка над `BoxError`, `is_length_limit()` в 0.5.6 нет (промер
`~/.cargo/registry/src/*/axum-core-0.5.6/src/error.rs`).
Промер реестр-кэша `~/.cargo/registry/index/*/.cache/ht/tp/http-body-util`
запись `0.1.5`: `rust_version = "1.61"` (≤ пина 1.85 ✓), `yanked = false`,
`features.default = []` (дефолтов нам хватает, ничего не включали). Поле
`license` в записи кэша = `null` ⇒ лицензию из индекса **не подтверждаем**; по
объявлению крейта — Apache-2.0 OR MIT, как и весь http-стек (подтвердить
первичкой — LICENSE в `.crate`, на шаге 8 вместе с bump-прогоном).
Крейт уже в дереве axum 0.8.9 ⇒ `Cargo.lock` = ровно одна добавленная строка
имени в списке deps `guard-daemon`, ни одна версия не сдвинута (промер
`git diff Cargo.lock`). `just net-audit` зелёный: `FORBIDDEN_MANIFEST` =
reqwest/ureq/hyper/rustls/tonic, `http-body-util` не клиент и в запрещённых нет.
Чего НЕ брали вместо: `tower-http` (`features = ["timeout","limit","catch-panic"]`
уже подключены в workspace) — его 413/panic-ответы это plain text вне нашего
конверта `{"error":{code,message}}`, т.е. клиент, различающий 4xx по `code`,
на переполнении слепнет; отказ от слоя задокументирован в `read_body`.
Таймаут чтения тела этим выбором не закрыт: `tower-http::timeout` дал бы
`408` вне конверта, а штатного места поставить свою дедлайн-петлю в шаге 6 нет
(нужна отдельная переменная, `FASAD_TIMEOUT_MS` занята таймаутом наружу) —
риск открыт до шага 7, README §«Fail-closed: компас статусов» п.4.


## 14. Промер шага 7c (21.10, локально на tip ветки `step7c-sse`; rustc 1.99.1 по `rust-toolchain.toml`, aarch64-apple-darwin)

**ureq 3.4.2 — единственный клиент наружу, добавлен сверх SPEC §7.** Причина:
`X-Upstream-URL` требует HTTP-клиента, а инвариант «никаких сетевых вызовов,
кроме явного `X-Upstream-URL`» требует, чтобы клиент был один и был виден гейту.
Выбран `ureq`, а не `hyper`+`hyper-rustls`: `hyper` уже в дереве как **серверная**
половина axum, и второй роли того же пакета гейд по манифесту не различает;
`ureq` блокирующий, что здесь плюс — насос SSE живёт в `spawn_blocking` и не
держит тик-ток задачу.

Первичка (`.crate` в реестр-кэше, не индекс): `~/.cargo/registry/src/*/ureq-3.4.2/`
— `license = "MIT OR Apache-2.0"` из `Cargo.toml` плюс два файла лицензии
(`LICENSE-MIT`, `LICENSE-APACHE`) ⇒ лицензия **подтверждена**, в отличие от
`http-body-util` из §13 (там `license` в записи индекса = `null`).
`rust-version = "1.85"` — ровно наш MSRV-пол, ниже пина 1.99.1 ✓. Запись индекса
`3.4.2`: `yanked = false` ✓.

**Фичи:** `default-features = false, features = ["rustls"]`. Что включено на
самом деле: `rustls` → `rustls-no-provider` + `_ring` + `rustls-webpki-roots`
(корневые сертификаты в бинаре — оффлайн-построение доверия, без системного
хранилища и без `Security.framework`).

Что **не** включено и почему:

1. `gzip` (дефолт крейта) и `brotli`: прокси передаёт тело upstream как есть и
   разворачивает маркеры в JSON; декодер — ещё один парсер чужих байт внутри
   нашей границы. Клиентский `Accept-Encoding` мы не прокидываем (см. п.2
   §«Прокси» в `docs/daemon-scope.md`), и с выключенными фичами не просит его
   сам `ureq`: список `ACCEPTS` строится под `cfg(feature = …)` и без них пуст,
   а пустое значение `AutoHeaderValue::Default` даёт отсутствие заголовка
   (промер `ureq-3.4.2/src/run.rs:300-318` + `src/config.rs:848-856`). То есть
   приглашения сжатию нет ни с одной стороны; пришлёт upstream `Content-Encoding`
   невзирая — байты уйдут клиенту как есть, и релей честно засчитает
   `malformed=1`, а не промолчит.
2. `cookies`: cookie-jar — состояние между запросами, то есть канал
   идентификации клиента поверх нашего «ровно два заголовка».
3. `native-tls` (+`vendored`, `platform-verifier`): системный TLS-стек и
   системные корни ломают air-gap-модель и уводят доверие из-под сборки.
4. `_url`: разбор URL отдаётся нашему `Upstream::parse`, потому что именно на
   его результат вешается allowlist; сторонний нормайзер (`.`, `\`, userinfo)
   проверил бы один адрес, а отправил другой.
5. `socks-proxy`, `win-system-proxy`: прокси из окружения/реестра Windows — путь
   наружу в обход allowlist. Флаг `win-system-proxy` выключен осознанно, иначе
   CI на windows-раннере с системным прокси отправил бы ПДн не туда.
6. `json`, `multipart`, `charset`, `_test`, `_doc`: удобство, не нужное на этом
   пути (тело — байты, сериализация наша, `serde_json` в дереве уже).

**Пулы и переиспользование.** Дефолты крейта не тронуты: `max_idle_connections =
10`, `max_idle_connections_per_host = 3`, `max_idle_age = 15s` (промер
`ureq-3.4.2/src/config.rs:961-963`), размеры буферов ввода-вывода по 128 КиБ
(там же, 959-960). Для стендэлона с одним разрешённым upstream это разумно по
умолчанию; своим конфигуратором не открываем, пока нет замера, что эти буферы
мешают лимиту памяти.

**Дельта `Cargo.lock`: `+2/-0` строк** — две строки имени в списке зависимостей
`guard-daemon` (`ureq`, `futures-core`), ноль новых пакетов: `ureq 3.4.2` уже
был в лок-файле на `main` как опциональная зависимость `ort`/`ort-sys` (загрузка
моделей), `futures-core 0.3.34` — транзитив axum-core. Ни одна версия не
сдвинута (промер `git diff --numstat Cargo.lock`, `git diff Cargo.lock | grep
'^+name'` — пусто).

**futures-core 0.3.34 (тоже сверх §7).** Взята вместо `tokio-stream`: `Stream`
нужен ровно для одного типа — обёртки над `tokio::sync::mpsc::Receiver` в
`proxy::Incoming`, чтобы отдать тело ответа потоком. `tokio-stream` потянул бы
ещё один crate в дереве ради `impl Stream`, который здесь пишется за 15 строк и
который мы можем покрыть тестом на err-кадр. `futures-core` — 840 строк `src/**/*.rs` (промер `wc -l`; для сравнения `ureq` —
16 509), лицензия `MIT OR Apache-2.0` подтверждена файлами `LICENSE-MIT` и
`LICENSE-APACHE` в `.crate`, `rust-version = "1.36"` (≤ пина 1.85 ✓), запись
индекса `yanked = false` ✓, подключён с `default-features = false` (нужен один
трейт `Stream`).
Пакет уже в дереве через `axum-core`, поэтому дельта локов та же — одна строка
имени.

**Что гейт не различает (честно).** `TREE_MUST_EXIST = ["ureq"]` на дефолтных
фичах даёт ровно один вход `ureq` в дерево; с `--features ort-inference` у `ort`
появляется второй, законный. Проверка меряет дефолтный набор, комментарий у
константы в `tests/net_audit.rs` это фиксирует.

**Патч-бамп по advisory (20.10.2026, первичка `RustSec/advisory-db`).**
`rustls-webpki 0.103.15 → 0.103.16` (`RUSTSEC-2026-0382`, `patched = [">= 0.103.16,
< 0.104.0-alpha.1", ">= 0.104.0-alpha.8"]`) и `webpki-roots 1.0.9 → 1.0.10`
(`RUSTSEC-2026-0381`, `patched = [">= 1.0.10"]`). Обе категории `crypto-failure`,
дата 19–20.10.2026, одна первопричина `CVE-2026-111943` (emSign: проверка
сертификата принимала пути через отозванные промежуточные ключи, Mozilla
2083449). Для нас это риск MITM ровно на единственном пути наружу — канале
`X-Upstream-URL`, поэтому бамп не откладываем. Шапки `.crate`: rustls-webpki
0.103.16 = `4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281`,
webpki-roots 1.0.10 = `1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9`
(промер `shasum -a 256` по кэшу реестра, обе `yanked = false`). Транзитив обоих —
`ureq 3.4.2`, сам он не двигался; дельта `Cargo.lock` — 4 строки: две `version` и две
`checksum`. Whitelist в `deny.toml` не тронута: закрываем патчами, не замятием.

## 15. Промер шага 8 (22.10, `rust-embed` и статика песочницы; rustc 1.99.1 по `rust-toolchain.toml`, aarch64-apple-darwin)

**`rust-embed` в дереве был с шага 2** (строка SPEC §7, `features = ["compression"]`),
и до этого шага не использовался: кода, который его зовёт, не было. Шаг 8 —
момент, когда крейт становится поверхностью интеграции, поэтому промер первичкой
здесь полнее строки таблицы §2.

Первичка 1 — реестр (crates.io API, запрос этой сессии): `newest_version =
max_stable_version = 8.13.0`, запись `8.13.0`: `yanked = false`,
`license = "MIT"`, `crate_size = 903366`, `updated_at = 2026-10-07` ⇒ строка
таблицы §2 («8.13.0 | 8.13.0 | 8.13.0 | совпадает») на сегодня верна.

Первичка 2 — распакованный пакет в реестр-кэше
(`~/.cargo/registry/src/*/rust-embed-8.13.0/`): `license = "MIT"` и файл
`LICENSE` ✓; `rust-version = "1.80.0"` — ниже нашего пина 1.99.1, пол MSRV
не поднимает ✓; `#![forbid(unsafe_code)]` первой строкой и в `rust-embed`, и в
`rust-embed-utils` (по одному вхождению в каждом) ⇒ рантайм-поверхность — поиск по
статической таблице байтов, без `unsafe` и без сети.

**Фичи: `default-features = false, features = ["mime-guess"]` — это отступление от
SPEC §7, где у строки `rust-embed` стоит «compression».**

1. `compression` тянет `include-flate` → `libflate`/`zstd` (а `zstd` — это
   `zstd-sys`, то есть C-компилятор в сборке продукта). Пример на нашем дереве:
   `Cargo.lock` со `compression` = 250 узлов, без него = 232; из 18 выпавших узлов
   добавленных нет ни одного — только вычеркнутые (`zstd`, `zstd-safe`,
   `zstd-sys`, `include-flate*`, `libflate*`, `crc32fast`, `adler32`,
   `rle-decode-fast`, `no_std_io2`, `proc-macro-error3`, `hashbrown`, `foldhash`,
   `allocator-api2`, `jobserver`). Выгода сжатия — на 20 340 байтах статики
   (померено `wc -c`); цена — C-тулчейн в сборке и путь распаковки внутри
   границы, где крутятся ПДн. Меняемся неохотно: бюджет §1 п.4 (<2 ГБ) тесен не
   для 20 КБ.
2. `mime-guess` оставлен: `Metadata::mimetype()` существует только под этой
   фичей (`rust-embed-utils-8.13.0/src/lib.rs:138`, `#[cfg(feature =
   "mime-guess")]`), а content-type ассетов — часть контракта (тест
   `assets_are_served_with_types_and_schema_is_the_shipped_file`). `mime_guess`
   в дереве уже был (axum), нового узла не добавлен.
3. `axum-ex` не взят, хотя название манит: кода в нём нет — интеграция с axum
   лежит в `examples/axum.rs` (проверено в `Cargo.toml` пакета:
   `[[example]] name = "axum" required-features = ["axum-ex"]`), а зависимости
   `axum` + `tokio` крейт получил бы как прямые. Наш обработок — 40 строк в
   `src/ui.rs`, они и так есть.

`sha2`-ребро (`rust-embed-utils → sha2 0.11`) — то же, что зафиксировано в
корневом `Cargo.toml` (комментарий к issue #14): версия уже была в `Cargo.lock`,
новых узлов шаг 8 не внёс. `cargo deny` на итоговом дереве: rc=0,
RUSTSEC-строк 0 (промер `just deny` в этом же заходе).

**`debug-embed` включён — это не «для отладки», это гейт.** Без него отладочная
сборка читает `ui/` с диска (`rust-embed/src/lib.rs`, doc на `RustEmbed::get`: «the
information is read from the file system on each call»), и тесты песочницы
оказываются проверкой соседних файлов, а не содержимого бинарника: промерено — с
выключенным `debug-embed` тест `ui_payload_is_inside_the_binary` краснеет
(«в бинаре нет куска статики „fasad — песочница“»), а тесты «демон отдаёт
страницу/ассет» остаются зелёными. То есть без этой фичи утверждение «статика
зашита в бинарник» в CI не проверялось бы ничем. Побочный эффект для разработки:
правка `ui/**` пересобирает демон (`include_bytes!` регистрирует файл как
compile-time зависимость, промерено), горячей перезагрузки статики нет.

Белый список имён в `src/ui.rs` — не косметика: в debug-сборке `rust-embed`
читает файлы с диска (`rust-embed/src/lib.rs`, doc на `RustEmbed::get`: «the
information is read from the file system on each call»), и маршрут
`/assets/{path}` с путём из запроса в отладочном бинаре читал бы что угодно
вне каталога. Тест `asset_names_outside_the_allow_list_are_refused` держит это
и на `%2e%2e%2f`-поднятии.

## 16. Промер трея: `tray-icon` (22.10, issue #128; решение оператора в комментарии к #128; первичка crates.io API + `.crate`-деревья + gh api, user-agent `fasad-depverify`)

**Решение оператора (цитата, gh issue view 128, комментарий от tayuLuc):** «трей
ДЕЛАЕМ — сценарий: Linux-сервер = systemd-юнит (консольный демон, без трея),
Windows и macOS = трей (иконка статуса). dep-verify-строка tray-icon (0.26.1,
MIT/Apache-2.0, rust-version 1.90 — MSRV-bump канона 1.85→1.90 решение оператора
здесь же), фича tray DEFAULT OFF… linux-дефолт-фича libappindicator/muda gtk3
отключается дефолтами… Релизные бандлы: tray-бинарь для win/mac (feature on),
linux бандл = headless (systemd-контур, юнит-файл в доки)». MSRV-bump канона
`rust-version = "1.85"` (`Cargo.toml:38`) → 1.90 — решение оператора, вписано
в скоуп атома; прецедент формы — keyring §12:228-230 («bump MSRV = отдельное
решение», здесь оно и принято).

### Таблица промера (первичка этой сессии, запросы `crates.io/api/v1/...`)

| предмет | версия | дата релиза | лицензия | rust-version | yanked | первичка |
|---|---|---|---|---|---|---|
| tray-icon | 0.26.1 (newest = max_stable) | 2026-10-07 | MIT OR Apache-2.0 | **1.90** | false | API crate+version; `LICENSE-APACHE`/`LICENSE-MIT`/`LICENSE.spdx` в `.crate` (tar-лист) |
| muda (ед. runtime-зависимость меню) | 0.21.0 (пин tray-icon `^0.21`; newest 0.21.2 2026-10-08) | 2026-09-30 | Apache-2.0 OR MIT | **1.90** | false | API version/dependencies |
| libappindicator (feature `libappindicator`) | 0.9.0 — newest крейта | 2023-10-01 | Apache-2.0 OR MIT | — (нет поля) | false | API crate (newest 0.9.0, updated 2023-10-01); `.crate` |
| ksni (feature `ksni`, alt-бэкенд) | 0.3.7 | 2026-10-20 | Unlicense | 1.80 | false | API version |
| objc2-app-kit (mac-бэкенд) | 0.3.2 (пин `^0.3.2`) | 2025-10-04 | Zlib OR Apache-2.0 OR MIT | 1.71 | false | API version |
| windows-sys (win-бэкенд) | 0.61.2 (пин `>=0.60, <=0.61`) | 2025-10-06 | MIT OR Apache-2.0 | 1.71 | false | API version |
| png (linux+mac) | 0.18.1 | 2026-02-14 | MIT OR Apache-2.0 | 1.73 | false | API version |
| thiserror / once_cell / crossbeam-channel (общие) | 2.0.21 / 1.21.4 / 0.5.17 | 2026-09-23 / 2026-03-12 / 2026-09-05 | MIT OR Apache-2.0 | 1.77 / 1.65 / 1.60 | false | API version |

Репо-первичка (`gh api`, 22.10): `tauri-apps/tray-icon` — 411 ★, последний
коммит 2026-10-19 (`1100fbe`), открытые issues 35 (счёт по
`issues?state=open`, без PR; `open_issues_count`=47 включает PR), релизный
ритм: 0.24.2 → 2026-07-27, 0.25.0 → 2026-09-11, 0.25.1 → 2026-09-16,
0.26.0 → 2026-09-30, 0.26.1 → 2026-10-07 (живое сопровождение, 4 релиза за 10
недель); contributors: amrbashir 83 +Legend-Master 12 (ядро — мейнтейнер
tauri). `tauri-apps/muda` — 428 ★, push 2026-10-17, открытые issues 30,
релизы 0.21.0/0.21.1/0.21.2 — 30.09/07.10/08.10.2026. docs.rs:
`tray-icon/0.26.1`, `muda/0.21.0` — HTTP 200.

### Feature-карта linux (первичка: API `/dependencies` + `src/lib.rs` `.crate`)

`default = ["libappindicator"]`, и `libappindicator = [dep:dirs,
dep:libappindicator, muda-gtk3]`, `muda-gtk3 = ["muda/gtk3"]` ⇒ **дефолт
крейта на linux тянет GTK3-стек** (muda `default = ["gtk3"]` → `dep:gtk` +
`dep:libc`). При этом `src/lib.rs:128-138` (`.crate` 0.26.1):

```rust
#[cfg(all(target_os = "linux", not(any(feature = "libappindicator", feature = "ksni"))))]
compile_error!("either the `libappindicator` or `ksni` feature must be enabled on Linux and BSD");
```

То есть `default-features = false` на linux = **compile_error**, легальной
headless-сборки трея на linux нет ни одной фичей. Ровно это решение оператора
и фиксирует: linux-бандл без трея (systemd-контур, см. `docs/release.md`
§«Что в бандле» п.7), трей = feature-gated под win/mac.
`ksni`-фича (`ksni = [dep:ksni, muda-snapshot]`) как linux-лег не берётся:
`ksni 0.3.7` — лицензия **Unlicense**, её нет в allow-листе `deny.toml`
(`allow` = Apache-2.0/MIT/BSD/ISC/Unicode-3.0/CC0-1.0/Zlib/CDLA-Permissive-2.0,
`deny.toml:60-72` — расширять под неё allow = отдельное решение), плюс она
тянет zbus-контур (`zbus ^5` + `ashpd`, `gtk4`, `smol` — промер
`/dependencies` 0.3.7), а `zvariant`/`zbus_names`/`zvariant_derive` помечены
`informational = "unmaintained"` (RUSTSEC-2026-0370/-0371/-0372, дата
2026-10-16, `patched = []`; диапазоны unstated = весь актуальный ряд
4.x/5.x — первичка advisory-фронтов; записи открыты и в самих репо — issues
#381-#386 tauri-apps/tray-icon).

### Вердикт-кандидат

`tray-icon 0.26.1`, `default-features = false`, фича продукта `tray`
(default OFF, проброшена к `guard-daemon`) — по решению оператора. Лицензия
MIT OR Apache-2.0 — в allow-листе `deny.toml`, расширять не надо. MSRV:
`rust-version = "1.90"` у tray-icon 0.26.1 и у пинимого muda 0.21.x ⇒ канон
workspace `1.85` → `1.90` (решение оператора, цитата выше; toolchain-пин
`rust-toolchain.toml` = 1.99.1 ≥ 1.90 — сборочный пол не двигается, двигается
заявленный канон + текст SPEC §1 п.1 «MSRV 1.85+»). Фичи-флаг `tray` на linux
не собирается ни в какой конфигурации (compile_error выше) — CI-матрица
проверяет feature-off на ubuntu (linux-джобы не линкуют трей-код) и feature-on
на windows/macos.

Что включено на win/mac при `tray = ["tray-icon"]` (без default):
windows — `windows-sys` (5 Win32-фич: WindowsAndMessaging/Foundation/
SystemServices/Gdi/Shell); macos — `objc2*` (app-kit/foundation/
core-foundation/core-graphics, feature-списки NS*-модулей в `/dependencies`);
общие — `muda 0.21` (пин в `Cargo.toml.orig` 0.26.1: `muda = { version =
"0.21", default-features = false }` — промер `.crate`; gtk-деп у muda
opt-зафичен и на win/mac-цели не таргетится — промер `/dependencies`
target-полей), `crossbeam-channel`,
`once_cell`, `png` (linux+mac), `thiserror`. Все — non-optional-зависимости
0.26.1, из linux-цели выключены cfg-мишенями (промер `/dependencies`
target-полей).

### Риск-строки

1. **linux-дефолт GTK-ловушка (закрыта вердиктом).** `default =
   ["libappindicator"]` → `muda/gtk3` → `gtk 0.18` (build-dep `pkg-config` —
   первичка `.crate` gtk-0.18.2 `[build-dependencies] pkg-config ^0.3.7`) +
   системный `libappindicator3.so.1`/`libayatana-appindicator3.so.1`
   (runtime-load через `libloading` — первичка `libappindicator-sys-0.9.0/
   src/lib.rs`, `Library::new(...)`). Ubuntu-раннер CI без `-dev` пакетов
   краснеет на такой сборке; в `Cargo.lock` крейта GTK-кластер занимает место
   в 521-узловом дереве (промер `grep -c 'name ='` по `.crate/Cargo.lock`
   tray-icon 0.26.1 против 232 узлов нашего workspace). Лечится `default-features
   = false` + never-подключение linux-таргета — см. вердикт.
2. **muda-transitivity (MSRV).** MSRV 1.90 задают ДВА крейта (tray-icon 0.26.1
   и muda 0.21.0). Линейка с floor ≤1.73 — tray-icon 0.24.2 (`rust-version
   1.73`, последняя 1.73-линейка: 0.23.0…0.24.2, 2026-04-29…07-27) +
   muda 0.19.3 (1.73) — существует, но её linux-дефолт `["libxdo","gtk"]`
   (feature-карта API 0.19.3: `libxdo = [dep:libxdo]`) тянет системный libxdo,
   а сама ветка заморожена с 2026-07-27 (4 месяца без релиза на 22.10).
   Bump канона 1.85→1.90 — осознанная цена живой линейки; прецедент — keyring
   §12.
3. **cruft-профиль репо (низкий).** 411 ★, коммит 11 дней назад, 35 открытых
   issues из 47 (PR-фильтр gh api 22.10); RUSTSEC по tray-icon/muda/
   libappindicator/objc2/windows-sys/png/thiserror/once_cell/crossbeam-channel
   — 0 записей (первичка: локальный клон advisory-db HEAD
   `4b587f00996ebe5c05a73eaef105ef241e876414` от 2026-10-21, `find crates/`
   по всем девяти именам — пусто). Единственные RUSTSEC рядом с контуром —
   `informational=unmaintained` по zbus-ветке `ksni`, которую мы не берём.
   `libappindicator 0.9.0` мёртв с 2023-10-01 (newest крейта) — на linux-путь
   не влияет: linux-трея нет по решению; крейт в дерево не попадает при
   `default-features = false` (opt-зависимость за фичей).
4. **MSRV-канон 1.90 ≠ toolchain 1.99.1.** Билд на 1.99.1 зелёным считать
   нельзя заранее — проверка входит в phase-2 (code-атом: feature `tray` +
   `cargo check --features tray` на win/mac-джобах). Локально на этой машине
   трей не промеряется (feature-on собирается только под win/mac-таргеты;
   osx-arm64-промер `cargo check -p guard-daemon --features tray` возможен на
   mac-хосте оператора — фаза 2).
5. **`muda` newest = 0.21.2 (08.10.2026), пин tray-icon `^0.21`** ⇒ resolution
   возьмёт 0.21.2 (тот же MSRV 1.90, лицензии те же, features-карта
   идентична 0.21.0 — первичка API). Дельта патчей, bump не решение.
