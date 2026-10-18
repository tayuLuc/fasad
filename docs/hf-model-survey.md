# HF-обзор: RU-NER/PII-энкодеры против GLiNER2.5 + доступность ONNX

Дата промера: 2026-10-19. Транспорт: `huggingface.co/api/models` + `/raw/main/*` + `curl -sIL` (HEAD).
User-Agent `dsh-audit/1.0`. Все числа ниже — из API/README карточек этого промера, не из памяти.

Область: чем **заменить или усилить** каскад-1 (экстрактор) / каскад-2 (решение MASK/KEEP)
с акцентом на русский; и есть ли **ONNX** под бюджет CPU ≤1.8 ГБ RAM.

Не дублирует `docs/dep-verify-models.md` (rubert-класс топ, gliner-топ-10, pii-deberta топ,
privacy-filter топ — там). Здесь докапываем глубже: RU-специфика, авторские реестры, external-data.

## 0. Методологические findings (важнее конкретных моделей)

1. **Поиск HF не ищет по кириллице.** `search=обезлич`, `search=анонимизация`,
   `search=персональные данные`, `search=NER русский` → **HTTP 200, 0 хитов**.
   Русскоязычные модели ищутся только по латинским токенам (`russian`, `ru`, `pii`, `нер` → нет).
   Вывод: «в экосистеме нет RU-анонимизаторов» из пустого `search` делать нельзя.
2. **`language:ru`-тег как фильтр работает и даёт больше, чем `search=ner russian`**:
   `api/models?pipeline_tag=token-classification&language=ru` — живой путь, но выдача
   замусорена (на топ-40 лишь ~6 моделей реально RU-NER).
3. **Ловушка external-data подтверждена и масштабирована.** Малый `*.onnx` (<300 КБ)
   при модели в гигабайтах = веса в `*.onnx_data`. `siblings[].size` **показывает**
   external-data при `?blobs=true`, но легко пропускается глазами. Проверено HEAD'ом:
   см. §2, колонка ONNX — все «маленькие onnx» оказались 0.5–7.6 ГБ внешних весов.
4. **ONNX-экспорт в этом классе — практика отдельных волонтёров, не вендоров.**
   Ни `fastino/*`, ни `OpenMed/*`, ни `urchade/*`, ни `knowledgator/*`, ни `redmadrobot-rnd/*`
   собственного ONNX не публикуют. Единственные найденные полные самостоятельные
   экспорты под нашу задачу: `lockR/rubert-base-pii-ner-onnx` и `onnx-community/*` (для
   не-RU-моделей).

## 1. Сводная таблица промеренного

Колонка «RU» — есть ли русский в `language`-тегах / README карточки.
Метрики только самонаписанные (self-report), с указанием источника.

| id | пайплайн | размер весов | ONNX? (файлы + размер + external-data) | лицензия | RU? | метрики (self-report) | вердикт |
|---|---|---|---|---|---|---|---|
| `redmadrobot-rnd/rubert-base-pii-ner` | token-classification (BertForTokenClassification) | 711 022 548 B = 0.711 GB (177 749 803 парам.) | **нет в родном репо** | apache-2.0 | **да** (`language: ru`) | span micro-F1 83.6 (P81.9/R85.5) на 14 классах; PERSON+LOC 94.7 F1; per-class: EMAIL 97.6, PASSPORT 81.3, INN 68.3, SNILS 78.5, CREDIT_CARD 87.9, PHONE 86.9, URL 89.7, IP 36.0. Бенчмарк свой (`pii_benchmark`, 2 841 предложений) | **усиление — главный кандидат**. Не замена GLiNER (нет zero-shot), а точный RU-детектор ПДн |
| `lockR/rubert-base-pii-ner-onnx` | token-classification | fp16 355 541 615 B = 0.356 GB; fp32 711 034 332 B = 0.711 GB | **да, честный единый граф, БЕЗ external-data** (HEAD content-length совпал с `siblings[].size`) | apache-2.0 | да | заявлено: FP16 vs PyTorch FP32, изменение span micro-F1 **−0.007 п.п.** на всех 2 841 текстах; 2.58× ниже медианная латентность (**на RTX 4070 Ti SUPER**, не CPU). opset 17, dynamo=false, attention=eager, динамические axes batch+sequence | **взять как есть** — ложится в `ort`/CPU/fp16, единственный промеренный RU-PII ONNX без внешних весов |
| `vladlinv/ru-pii-ner-gliner2.5` | token-classification (`lib: gliner2`, arch `BoundaryExtractor`) | 1 149 461 028 B = 1.149 GB (287 355 159 парам.) | **нет** | apache-2.0 | **да** (`language: ru`) | валид. 405 доков / 4 134 сущности, строгие границы: PERSON P93.28/R91.51/**F1 92.39**; PHONE 89.49; EMAIL 93.10; DATE 81.93; LOCATION 80.96; класс «PII» (все идентификаторы) 85.15; общее F1 86.18, coverage 84.06. Датасет **полностью синтетический** | **прямой конкурент нашего кандидата**: тот же энкодер, тот же размер. BUT recall 0.82 < наш порог FN-фатализма |
| `vladlinv/ru-pii-ner` | token-classification (PEFT-адаптер) | 10 636 480 B адаптер + CRF-хед 74 544 B; база `ai-forever/ruRoberta-large` (1 024 скр.) | **нет** (ни адаптера, ни базы) | apache-2.0 | да | метрик в карточке нет (только `best_epoch: 12`, `val_coverage: -1.0`) | отказ: база не в комплекте, ONNX нет, метрик нет |
| `OpenMed/privacy-filter-multilingual-v2` | token-classification (`openai_privacy_filter`) | **2 799 225 250 B = 2.80 GB** (1 399 604 809 парам.) | **нет в репо OpenMed**; сторонний `lemonade-sdk/openmed-privacy-filter-multilingual-v2-onnx`: `model.onnx` 2 402 586 B + **`model.onnx.data` 5 598 478 336 B = 5.60 GB** → ловушка external-data подтверждена | apache-2.0 | **НЕТ** | README: «54 категории / 16 языков». Языки из frontmatter: ar,bn,de,en,es,fr,hi,it,ja,ko,nl,pt,te,tr,vi,zh — **ru отсутствует**. Тег-лист API то же | **отказ**. Заявленная «54 категории/16 языков» SOTA нас не касается: русского нет, веса 2.8 ГБ > всего RAM-бюджета |
| `onnx-community/GLiNER2.5-Decide-ONNX` | text-classification (арбитр) | графы 285 759–341 889 B | `model.onnx` 285 759 B + **`model.onnx_data` 1 744 089 088 B = 1.744 GB**; fp16 → 872 044 544 B; q4 → 887 657 472 B; **q4f16 → 523 127 808 B = 0.523 GB** | apache-2.0 | нет (мультияз. энкодер mDeBERTa) | не промерялись | **открытая ветка**: external-data закрыл вопрос §6 `dep-verify-models`. CPU-путь — q4f16 (0.523 ГБ). Не скачан, паритет не проверялся |
| `onnx-community/gliner_multi-v2.1` (база `urchade/gliner_multi-v2.1`) | token-classification | 1 155 830 112 B = 1.156 GB (288 949 504 парам.) | **да, единые графы, без `.onnx_data`**: fp32 1 157 129 714 / fp16 579 717 643 / **int8 349 120 924 B = 0.349 GB** / q4 893 933 650 / q4f16 471 795 362 | apache-2.0 | только общий тег `multilingual`; в README-таблице — «Multilingual», **RU не назван** | в карточке нет | **усиление zero-shot** под кастомные категории (коммерческая тайна, tech-инфра): int8 349 МБ вписывается в бюджет, где GLiNER2.5-multi fp32 1.15 ГБ — нет |
| `onnx-community/multilang-pii-ner-ONNX` (база `Ar86Bat/multilang-pii-ner`) | token-classification, xlm-roberta | 1 109 943 940 B = 1.110 GB (277 479 971 парам.) | **да**: **int8 278 680 637 B = 0.279 GB**, fp16 555 283 812, fp32 1 110 243 449 | mit | **НЕТ** — теги en,de,fr,it | нет | отказ по языку; фиксировать как заготовку int8-XLMR-графa под возможный дообучаемый путь |
| `knowledgator/gliner-pii-large-v1.0` | token-classification (`lib: gliner`) | `pytorch_model.bin` 1 761 031 015 B = 1.761 GB | **да, полный**: `onnx/model.onnx` 1 763 443 637 B = 1.763 GB; `onnx/model_quint8.onnx` 647 870 050 B = 0.648 GB. **external-data нет** | apache-2.0 | **НЕТ** — теги `multilingual`, `en` | нет | отказ: quint8 648 МБ бюджет проходит, но EN-ориентация и нет DATE/документ-классов |
| `knowledgator/*` (реестр автора, `?author=knowledgator&limit=100` → 100 репо) | — | — | — | apache-2.0 (кроме линейки `gliner-x-*-v0.5` → cc-by-nc-sa-4.0) | нет | — | **`gliner-pii-large-v1.0` выпал из окна топ-100 по downloads** — реестр автора без `&sort` усечён; проверять точечным GET. Ни один gliner-вариант knowledgator не RU |
| `redmadrobot-rnd` авторский реестр | — | — | — | — | — | модели: `rubert-base-pii-ner`; датасеты: `pii_train`, `pii_benchmark` | датасет `pii_benchmark` **открыт (HTTP 200)** — годится в наш golden-набор (§дисциплина фактов п.4) как внешний RU-корпус |
| `r1char9/ner-rubert-tiny-news` (+ `onnx-community/ner-rubert-tiny-news-ONNX`) | token-classification, rubert-tiny2 | энкодер 25 млн | **да, единые графы**: **int8 29 252 719 B = 0.029 GB**, fp16 58 293 738, fp32 116 470 467 | mit | да (Collection3, новости) | метрик в карточке нет | **отказ как детектор**, но годится как дешёвый **PER/ORG/LOC/GEOPOLIT**-префильтр за 29 МБ; классы ПДн нет |
| `Gherman/bert-base-NER-Russian` | token-classification | 709 179 336 B = 0.709 GB (177 288 994 парам.) | есть `onnx-community/bert-base-NER-Russian-ONNX`: int8 **178 470 706 B = 0.178 GB**, fp16 354 886 065 | mit | да | нет | отказ: PER/ORG/LOC без ПДн; слабее rubert-base-pii по покрытию классов |
| `denis-gordeev/rured2-ner-microsoft-mdeberta-v3-base` | token-classification, deberta-v2 | 1 113 185 580 B = 1.113 GB (278 290 269 парам.) | **нет** | mit | да | свой eval: **F1 micro 0.5837** (!), per-type: B-person 0.9639, B-date 0.8386, B-norp 0.6190, B-country 0.6152 | отказ: **тот же энкодер, что у GLiNER2.5-multi, но F1 0.58** — сильный контраргумент «дообучим mDeBERTa сами и обойдём GLiNER» |
| `LLAIMlegal/ru-legal-ner` | token-classification | 116 424 620 B = 0.116 GB (29 104 563 парам.) | **нет** | mit | да | нет | отказ (узко-юридический, кастомный `llaim_ner.py`, ONNX нет) |
| `spacy/ru_core_news_lg` / `_md` / `_sm` | token-classification | — | **нет ONNX** (spaCy `.whl`, не HF-веса) | mit | да | нет | отказ: не ложится в `ort`; к тому же PER/ORG/LOC |
| `onnx-community/piiranha-v1-detect-personal-information-ONNX` | token-classification | — | **да**: int8 317 144 829 B = 0.317 GB, fp16 575 239 383 | — | нет (EN) | нет | отказ по языку |
| `E3-JSI/gliner-multi-pii-domains-v1` | token-classification (gliner) | 1 155 830 144 B = 1.156 GB | **нет** | apache-2.0 | **НЕТ** — теги en,fr,de,es,pt,it,sl,el,nl | нет | отказ по языку |
| `nisten/privacy-filter-nemotron-v2-ONNX` | token-classification | — | `model.onnx` 138 581 B + **`.onnx_data` 5 631 970 304 B**; fp16 → 2 815 985 152; mixed48 → 1 664 853 312; quantized → 1 984 162 052 | other | нет | нет | отказ + **ещё один подтверждённый external-data-трэп** |
| `jalbrethsen-highflame/privacy-filter-onnx` | token-classification | — | `model.onnx` 146 768 B + **3 куска данных**: 1 822 721 024 / 1 907 131 392 / 1 901 636 608 (fp32 ≈ 5.63 GB); q4f16 → 809 061 992 | apache-2.0 | нет | нет | отказ по бюджету; трэп multi-part external data |

## 2. Top-3 кандидата vs GLiNER2.5-multi-v1 (+ Decide)

Наш текущий выбор: `fastino/gliner2.5-multi-v1` (1.149 ГБ, mDeBERTa-v3-base, boundary-head)
+ `fastino/GLiNER2.5-Decide` (1.946 ГБ, deberta-v3-large) как арбитр MASK/KEEP.

### Кандидат A — `redmadrobot-rnd/rubert-base-pii-ner` + `lockR/...-onnx` (усиление, не замена)

**Лучше GLiNER2.5 в трёх конкретных местах:**
1. **Покрытие классов.** 21 тип / 43 BIO-метки, включая ровно наши RU-документы:
   `PASSPORT`, `INN`, `SNILS`, `OMS`, `CREDIT_CARD`, `DRIVER_LICENSE`, `MILITARY_ID`,
   `BIRTH_CERTIFICATE` — плюс `FIRST/LAST/MIDDLE_NAME` и полная адресная иерархия
   `COUNTRY/REGION/DISTRICT/CITY/STREET/HOUSE`. У GLiNER2.5 этих типов нет в онтологии —
   они требуют zero-shot-промпта.
2. **Экономика.** ONNX fp16 **355 МБ** против 1.149 ГБ fp32 у GLiNER — на 794 МБ меньше
   RAM-бюджета 1.8 ГБ остаётся живыми. Плюс BERT (не DeBERTa): обычный `attention`,
   `EmbedLayerNormalization`+12×`Attention`+12×`BiasGelu`+24×`SkipLayerNormalization`
   уже смёржены в графе (из `export_metadata.json`) — CPU-EP `ort` это ест нативно.
3. **Открытые данные.** `pii_train` (17 137 предложений / 39 687 спанов) и `pii_benchmark`
   (2 841, непересекающийся) — доступны. Это единственный найденный RU-корпус ПДн,
   пригодный в наш golden-набор N≥150.

**Хуже GLiNER2.5:**
1. **Нет zero-shot.** Никаких «коммерческая тайна», «tech-инфра» — каскад кастомных
   категорий на нём не строится; для них GLiNER остаётся единственным.
2. **Нет DATE.** В онтологии 21 типа дат нет вообще (в README прямо: `pii-guard` покрывает
   `DATE_TIME` правилами). Наш целевой класс DATE на нём не закрыть.
3. **`IP_ADDRESS` F1 36.0** — модель режет по точкам. У нас и так детерминированный
   валидатор IP из каскада 0 с приоритетом 1.0 — но факт фиксируем: на IP не опираемся.
4. **max_position_embeddings 512** против `max_len: 4096` у GLiNER2.5 — длинные документы
   потребуют скользящего окна (авторы используют `stride=128`, `min_confidence=0.3`).
5. Recall 85.5 на 14 классах — **выше** нашего low-threshold-принципа, но ниже GLiNER-порога
   0.20–0.25 по смыслу: это F1-оптимизированная модель, FN не минимизированы.
6. Экспорт `lockR` верифицирован автором **на GPU**, не на CPU. Прогон паритета fp32↔fp16
   на `ort`-CPU-EP и замер RSS — обязателен перед мержем (§порядок работы п.2).

### Кандидат B — `vladlinv/ru-pii-ner-gliner2.5` (прямая замена каскада-1, с оговорками)

**Лучше:** это **fine-tune ровно нашей базы** `fastino/gliner2.5-multi-v1` (frontmatter
`base_model`), идентичный размер файла 1 149 461 028 B, идентичный энкодер
(`microsoft/mdeberta-v3-base`, hidden 768, 12 сл., `dtype: float16`, `max_len 4096`,
`architecture: boundary`). Нулевой риск по формату декодирования: наш планировщик
`SKILL.md`-логики GLiNER2.5 применим без правок. RU-адаптация бесплатная: PERSON F1 92.39,
PHONE 89.49, EMAIL 93.10 на реальных русскоязычных документах — цифры, которых у
`fastino/gliner2.5-multi-v1` для RU вообще нет.

**Хуже:**
1. **Общий recall 81.98 %** — при нашем инварианте «FN фатален, FP дёшев» это хуже,
   чем у baseline-GLiNER с низким порогом; класс LOCATION recall 74.30, DATE 75.44.
2. **Валидация полностью синтетическая** (карточка: «Датасет полностью сгенерирован») —
   405 документов, и только ~6 % нерусские. На нашем golden-наборе цифра может сесть.
3. Онтология грубая: PERSON / LOCATION / DATE / PHONE / EMAIL / **PII** — то есть все
   госномера (паспорт, СНИЛС, ИНН, банковские реквизиты, медицинские, судебные) свалены
   в один класс `PII` (2 336 сущностей, F1 85.15). Для нас, где каскад 0 уже ловит
   ИНН/СНИЛС/паспорт чексуммами, неразличение внутри PII — минус.
4. ONNX нет; экспорт boundary-head придётся делать самим.
5. 1 293 скачивания, 2 лайка, последний коммит 2026-09-14 — тонкий след поддержки.

### Кандидат C — `onnx-community/gliner_multi-v2.1` (усиление по бюджету)

**Лучше:** **int8-граф 349 120 924 B = 0.349 ГБ единым файлом, без external-data**
(промер `?blobs=true`) — на 800 МБ легче нашего fp32 GLiNER2.5, впервые вписывается в
RAM-бюджет с запасом. Тот же класс zero-shot-архитектуры, что у текущего выбора →
кастомные категории (коммерческая тайна, tech-инфра) сохраняются. apache-2.0, 288.9 М
параметров, 171 лайк, живой репозиторий.

**Хуже:**
1. **GLiNER v2.1, а не 2.5** — старее поколение heads; у 2.5 заявлено лучшее
   абстинент-решение, которого здесь нет.
2. **RU не подтверждён**: карточка говорит только «Multilingual» (обучен на
   `urchade/pile-mistral-v0.1`), в отличие от `fastino/gliner2.5-multi-v1`, где
   мультиязычность — заявленная фича. Способность красить русские ПДн — **непроверена**.
3. Не имеет ни одного из наших document-классов; нужна пара с детектором A.
4. Готовый ONNX от `onnx-community` — квант чужой, паритет против PyTorch-референса
   не публикуется → parity-гейт по golden-набору обязателен.

### Итог сравнения

Тупика «нет готового ruBERT лучше GLiNER2.5» нет, но и замены целиком нет: GLiNER2.5
остаётся единственным, кто закрывает **zero-shot кастомные категории** и **DATE**.
Открытие промера — **каскад-1 можно раздвоить**: детерминированный RU-PII-детектор
`rubert-base-pii-ner` (ONNX 355 МБ, 21 тип с паспортами/СНИЛС/ИНН) как дешёвый точный
верхний слой, плюс GLiNER (или `gliner_multi-v2.1` int8 349 МБ) как zero-shot-слой.
Метрика 83.6 F1 на собственном бенчмарке — self-report, проверять на нашем golden.

## 3. Не промерено

1. **Фактическое исполнение ONNX в `ort`/CPU-EP и RSS** — ничего не скачивалось и не
   запускалось. Все «вписывается в бюджет» выше — арифметика по размеру файла,
   не измерение. Это §11 п.2 / `docs/model-audit.md`, вне этой задачи.
2. **Паритет fp32↔int8/fp16** — ни для одного графа не проверялся; заявления авторов
   (`−0.007 п.п.` у lockR, `max prob drift` у yethdev) остаются `[claim]`.
3. **RU-качество `gliner_multi-v2.1`** — не проверялось; промпт-таблица и поведенческий
   тест на русском не гонялись.
4. **Свойство external-data по HEAD'у** выбраночно: проверены HEAD'ом только
   `lockR/*` (2 файла) и `OpenMed/*` safetensors. Размеры `onnx-community/*` и
   `DanKau/*` взяты из `siblings[].size` — это тот же API-источник, но не независимый HEAD.
5. **sha256** ни одной модели не пересчитывался; `manifest.md` не обновлялся.
6. **Лицензионная чистота `openai/privacy-filter`-линейки и `license:other`**
   (`nisten/...`, `Babelscape/wikineural`, `afl-3.0` у `Davlan/*`) — не читались, только теги.
7. **Прямые GET по `gliner-pii-large-v1.0` вне окна топ-100** закрыли выпадение из
   реестра, но полный реестр knowledgator (≥100 репо) отсортирован не по имени —
   возможны ещё пропуски, кроме gliner- и onnx-префиксов.
8. **Кириллический сегмент HF** — принципиально недоступен через `search` (см. §0.1);
   альтернативный путь (фильтр `?language=ru`) промерен лишь на top-40.
9. **Datasets-линейка** (`redmadrobot-rnd/pii_train`, `pii_benchmark`) — только HEAD-200,
   содержимое/лицензия/объём не открывались.
10. **Ранние/альтернативные ветки Decide-арбитра** (`onnx-community/GLiNER2.5-Decide-mobile-ONNX`,
    `DanKau/gliner2.5-multi-decide-onnx`, `rdvt/GLiNER2.5-Decide-ONNX`,
    `nishparadox/gliner2.5-decide-onnx`) — найдены списком, по файлам не промерены.
11. **`squilla`-подобные и Sber/Kontur внутренние RU-NER** — пусто: `search=sber`,
    `search=gigachat ner`, `search=dadata`, `search=персональные данные` — ни одного
    RU-NER/PII-релевантного результата.

## 4. Что это меняет в SPEC / планах

1. §11 п.1 риск «могут не существовать» закрыт ранее; **закрывается и риск «ONNX не найти»**:
   для RU-PII-детектора единый честный ONNX существует (`lockR`), и для zero-shot-слоя
   int8-граф <350 МБ существует (`onnx-community/gliner_multi-v2.1`).
2. §5.2: добавить кандидатом каскада-1 **пару** `rubert-base-pii-ner`(ONNX) + GLiNER,
   вместо единственного GLiNER — с явным указанием, что zero-shot-категории остаются
   только за GLiNER.
3. §10 RAM-бюджет перестаёт требовать собственного экспорта как единственного пути:
   сравнить 3 варианта в `model-audit` — fp16-BERT 0.356 ГБ / int8-XLMR-gliner 0.349 ГБ /
   self-export int8 GLiNER2.5.
4. External-data — теперь формализованная проверка приёмки модели (см. §0.3), а не
   подозрение: три репо из промера (`lemonade`, `jalbrethsen-highflame`, `nisten`)
   показали 1.7–5.6 ГБ внешних весов при «маленьком» `model.onnx`.
5. `pii_benchmark` — кандидат в источник дописки нашего golden-набора (N≥150, §дисциплина
   фактов п.4), но с оговоркой: чужой бенчмарк ≠ наш, цитировать его F1 как свой запрещено.
