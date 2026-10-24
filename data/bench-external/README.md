# data/bench-external — внешний кросс-бенч границ (read-only мера)

Владелец контура кросс-референса на `redmadrobot-rnd/pii_benchmark` (issue #209).
**Это НЕ гейт recall.** Единственный эталон метрики recall — `data/golden/`
(AGENTS §4 «Дисциплина фактов» п.4 + рюлинг 24.10 ниже). Здесь меряется одно:
наши границы спанов на чужой живой разметке (обрезки 4508-класса, #200-контур),
«наш бенч не тронут, это кросс-мера».

## Рюлинг оператора 24.10 (пересмотр указатель-канала)

Данные внешнего бенча **тащим в git** (MIT-корпус read-only метрики): указатель
ненадёжен — датасет может быть изменён/удалён, воспроизводимость кросс-мера =
часть продукта. Условия соблюдены: license-контур рядом, sha256/revision-пины
ниже, snapshot зафиксирован, кросс-бенч остаётся read-only мерой. HF-кеш —
канал доставки на обновление версии, НЕ источник чтения (конвертер читает из
репо).

## Пины (промер живым GET первичка-контура 24.10)

| факт | значение | первичка |
|---|---|---|
| датасет | `redmadrobot-rnd/pii_benchmark` (HF) | GET `https://huggingface.co/api/datasets/redmadrobot-rnd/pii_benchmark` 24.10 |
| revision (HEAD = snapshot) | `f77ea831274daf980cc45c61a93c226be9d978d6` | живой API: `sha` = тот же = snapshot в кеше промера 20.10; `lastModified` 2026-06-09T12:53:01Z; revisions — 3 коммита 09.06 (промер commits/main) |
| license | `mit` (frontmatter карточки; license-файла в репо датасета НЕТ — промер `gh api repos/redmadrobot-rnd/pii_benchmark/contents` = 404, HF-карточка = первичка license) | карточка `README.md` в каталоге ниже, sha256-пин |
| `test.csv` | sha256 `6bf544a380a3ee5bec94b946124bea3afaecce49e734679ad0f0c0e7c12977bb`, 3 225 069 Б, 2841 строка + заголовок | `shasum -a 256` локально на snapshot (промер 24.10); пин проверяется конвертером fail-closed (`--no-sha-gate` только для ad-hoc) |
| license-контур | `LICENSE-pii-guard.txt` (Apache-2.0, текст репо конкурента) + `NOTICE-pii-guard.txt` | `raw.githubusercontent.com/redmadrobot-rnd/pii-guard/main/{LICENSE,NOTICE}` промер 24.10; датасет = MIT-frontmatter, текст MIT канонический не тащим (файла у них нет), лицензионный след конкурент-реестра закрывает §1 `docs/dep-verify-competitors.md` |
| формат полей | `text,tokens,ner_tags`; `tokens`/`ner_tags` — JSON-списки равной длины (расхождений 0), BIO 21 тип (`B-`/`I-`) + `O` | первичка `head -2` snapshot (промер 24.10) + счётчик типов по всему файлу (21 `B-` + 19 `I-` = 40 non-O токенов; §1 `docs/dep-verify-competitors.md`) |
| размер | 3.1 МиБ < 50 МиБ → в git без LFS (промер `stat -f %z`) | рюлинг 24.10: >50 МиБ = отдельный GO оператора |

Файлы каталога защищены от CRLF-конверсии windows-чек-аута правилом
`.gitattributes` (`data/bench-external/redmadrobot-pii-benchmark/** -text`) —
sha256-пин сверяется с байтами на всех трёх ОС матрицы (тот же класс, что
`data/golden/**`).

## Отображение их 21 типа → наши 8 (классы схемы `config/schema.default.json`)

`FIRST/LAST/MIDDLE_NAME`→`person_name`; `COUNTRY/REGION/DISTRICT/CITY/STREET/HOUSE`
→`address`; `INN`→`inn`; `SNILS`→`snils`; `CREDIT_CARD`→`card_pan`;
`PHONE`→`phone`; `EMAIL`→`email`; `PASSPORT`→`passport`. Out-of-schema
(считаются отдельно, в F1 по нашим 8 НЕ входят): `BIRTH_CERTIFICATE`,
`DRIVER_LICENSE`, `IP_ADDRESS`, `MILITARY_ID`, `OMS`, `URL` (у нас их классов
нет; `ogrn/ogrnip/iban` — у них наоборот, нет).

## Разметка и решения контура (что с ней делаем и чего НЕ делаем)

1. **Спан-объединение их `I-`-скобок** — объединяем соседние `I-<TYP>` в один
   спан (BIO). Соседние РАЗНЫЕ типы, дающие один наш класс (`FIRST+LAST`,
   `STREET+CITY`), НЕ склеиваем: их разметка = отдельные сущности, мы её не
   переписываем. Их карточка (§Evaluation metric): «adjacent same-category
   spans merged **on both sides**» — merge на их стороне matching, не в данных.
2. **Метрика = по-их-спанно.** `strict` = byte-exact границы + класс (наш
   контракт strict, `data/golden/README.md` §Метрика recall; их harness тоже
   имеет exact). `coverage` = пересечение ≥1 байта + класс (их overlap-семантика) —
   контур «наш спан покрыл их span-объединение». Обе меры печатаются всегда.
3. **Границы char→byte.** Их offsets = символы; наш контракт = байты
   (`crates/guard-types/src/span.rs`; витрина `README.md` §analyze отдаёт и
   `byte_start/byte_end`, и символьные `start/end`). Конверсия точная
   (`tools/bench/rrn_bench.py::char2byte`), тест на кириллице в `--selftest`;
   расхождения char/byte считаются мерителем отдельно (`BYTES|`-строка).
4. **Value_source-эталоны не берём** (issue #209: гейт приёмки = цифры до/после,
   NOT CI-golden; их разметка вторична для наших чексумм, AGENTS §3).

## Разрешение токенов в текст (промер 24.10 — формат коварен)

`text` ≠ конкатенация токенов и ≠ join(" "): токены склеены произвольными
пробельными разрывами; токен `#` в 193 строках канонизован токенизатором в `.`
(в тексте 44 литеральных `#` остались); 2 строки матчатся только регистронезависимо
(row1 `WWW` vs текст `www.`; row721 `İ` — Turkish dotted capital); 1 строка
кончается висячим пробелом (row1381); ровно 1 пустой токен (row1432, тег `O`).
Конвертер: DFS-выравнивание кандидатов (канон + сырой токен, exact → fold
фолбэк) с зазором = пробелы, полное покрытие `text`, валидация байтовых срезов
на каждой строке; невыравниваемая строка = fail-closed (молча не гадаем).
Промер: 2841/2841 выравнивается, счётчики тип-в-тип сходятся с их карточкой
(21 тип, 5614 спана; our-class-суммы: person_name 1264 = их PERSON, address
1252, passport 494, inn 263, email 221, card_pan 203, phone 173, snils 223;
out-of-schema: BIRTH_CERTIFICATE 341, DRIVER_LICENSE 371, IP_ADDRESS 155,
MILITARY_ID 278, OMS 170, URL 206).

## Контур воспроизводимости

```sh
scripts/rrn-bench.sh --mode cascade0            # debug-демон без весов (каскад-0)
scripts/rrn-bench.sh --mode full --model-dir ~/.cache/fasad-models   # debug + орт-dylib
```

Обёртка: selftest конвертера → генерация `crossref.jsonl` (производное, gitignored,
на лету) → debug-сборка (jobs=2, nice, TMPDIR=/tmp; release-сборки запрещены
рулингом 22.10) → демон `FASAD_THREADS=2` → `tools/bench/rrn_score.py` по 2841
строкам → артефакт `.local/bench/rrn-<дата>-<mode>.out`. Fail-closed: нет данных
бенча / нет весов для full / демон не поднялся / таймауты запросов = красным,
не молча. **CI НЕ монтируем**: внешняя сеть в CI = air-gap-контур (net-джоба
краснеет); прогон ручной, артефакт-дата в отчёте — как их quality-гейт вне CI
(`pii-guard/.github/workflows/ci.yml` L4-5 первичка: «needs the NER weights and
takes minutes»).

Артефакт-отчёт `.local/bench/rrn-<дата>.md` (вне git): цифры генерируются из
`SCORE|`-строк артефакта прогона, не с головы (правило «числа документа
генерятся из артефакта»).

## Baseline (промер 24.10, debug-демон, FASAD_THREADS=2, nice; артефакт `.local/bench/rrn-2026-10-24-*.out`)

_заполняется генератором из артефакта после прогонов (таблица по типам,
strict/coverage, их N=2841 / gold-спанов 4093 в наших 8 классах)_
