# Сторонние лицензии и производные данные

Файл заведён шагом 5 (`guard-vault`, атом D) и пока покрывает **только** то, что
добавлено шагом 5. Полный аудит зависимостей — задача шага 10 (CI-джоба
`THIRD-PARTY-NOTICES`, SPEC §10 п.10); остальной стек (`moka`,
`chacha20poly1305`, `lz4_flex`, `region`, `zeroize`, `base64`, `thiserror`) там же.

## 1. `petrovich-core` 0.2.0 (фича `decliner` крейта `guard-vault`)

- Пакет: `petrovich-core`, версия `0.2.0`, `[lib] name = "petrovich"`.
- Источник: `git+https://github.com/rodem/petrovich-rs`, пин `rev =
  019e06dd01c590ff4dd82c762b55465bea5c8d2b` (master tip на промер 20.10, тегов
  нет). Запись в `Cargo.lock`: `source = "git+https://github.com/rodem/petrovich-rs?rev=019e06d…"`.
- Лицензия: **MIT** — объявлена в `Cargo.toml` пина (`license = "MIT"`, строка 13).
  Файла `LICENSE`/`COPYING` в дереве пина **нет** (промер `docs/dep-verify-crates.md`
  §12: `gh api trees` корень = `.gitignore Cargo.lock Cargo.toml PLAN.md README.md
  build.rs cli com examples src tests web`, `/license` → 404; повторено локально
  `ls` по checkout 20.10).
- Правообладатель в дереве пина не указан; `authors` в `Cargo.toml`: `latrasis`,
  `road21`, `broadwaylamb`. Это форк: поле `repository` внутри пина указывает на
  `https://github.com/Latrasis/petrovich-rs` (застывший 2020-04-06), который, в
  свою очередь, — порт Ruby-гема **petrovich**, `MIT-LICENSE` которого гласит
  `Copyright (c) 2013-2014 Boris Kozloff, Mikhail Ustalov` (первичка — апстрим
  `petrovich/petrovich-ruby`; цепочка записана в `docs/dep-verify-crates.md` §12).
  Текст MIT-лицензии берётся оттуда же; в репозиторий не клонируется намеренно
  (правило «код-источник = указатель, не блоб»).
- Условие мержа шага 5 из `docs/dep-verify-crates.md` §12 («THIRD-PARTY-NOTICES.md
  MIT © 2013–2014 Kozloff & Ustalov») — выполнено этим разделом.
- Дистрибутив: бинарь не распространяется (демон локальный), но при публикации
  артефакта раздел обязан остаться.

## 2. Производные морфологические данные `data/morph/`

- `table_tail3_genderstrict.tsv` (119 правил, 131 270 Б) и `exceptions.tsv`
  (80 исключений, 5 298 Б) — **производные** из golden-таблиц того же форка
  (`tests/data/{surnames,firstnames,midnames}.tsv`, 270 072 строки, MIT, см. §1).
  Значит на них распространяется та же MIT-лицензия; условие — сохранение
  уведомления об авторстве, что и делает этот раздел.
- Способ производства: обучение методом lcp-выравнивания лемма↔форма, конфиг
  `tail3+gstrict`, генератор — скрипт шага 4b3 `tools/morph-gen/proto2.py`
  (внесён в дерево коммитом `9efaa06`, sha256
  `07014d8f79cd973888445e463ae61b539ac722ab0b72da22e9312f0383ed32dd`; путь
  `/tmp/morph3/proto2.py` с той поры — не источник истины). Воспроизводится
  генератором только `table_tail3_genderstrict.tsv`: писатель отдаёт ровно
  `table_{lbl}.tsv`, а `exceptions.tsv` — ручной артефакт шага 4b3, скрипт его ни
  создаёт, ни проверяет; отклонение названо в `data/morph/README.md`
  (§«Что генератор воспроизводит, а что нет»), файл зафиксирован побайтово
  (длина + sha256 в `crates/guard-vault/src/morph.rs`). Хэши самих таблиц и
  порядок регенерации — там же.
- `fixture_golden_pairs.tsv` (240 строк, 11 463 Б) — срез первички для
  регрессионного теста (12 лемм на тип, стридом по файлу, все 6 падежей);
  лицензия та же MIT.

## 3. Прочие компоненты шага 5

Токен (`token.rs`), переписыватель (`rewriter.rs`) и кэш (`cache.rs`) написаны
нами; чужого кода в них нет, заимствований out-of-tree не было. Крипто-векторы —
эталонные значения из IETF-черновика (public domain-статус трактата CC-BY, см.
provenance-блок в `token.rs`), это не лицензионная нагрузка на бинарь.
