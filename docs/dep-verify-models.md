# Первичная верификация моделей с Hugging Face

Дата промеров: **2026-10-18**. Промер живьём, все цифры — из ответов HF API этого дня.

- Транспорт: `GET https://huggingface.co/api/models/<id>` и `?blobs=true`, заголовок `User-Agent: dsh-audit/1.0`.
- Размеры файлов — из поля `siblings[].size` (байты). Пересчёт в ГБ по **10⁹** (как в HF-UI),
  в скобках GiB по 2³⁰.
- Метод: только прямые промеры. Где промер не выполнялся — помечено явно.
- В git не коммитить.

## 1. Таблица вердиктов

| Заявленное имя (SPEC) | HTTP | Реальный id | dl / likes | Лицензия | ONNX в репо? | Вердикт |
|---|---|---|---|---|---|---|
| `fastino/GLiNER2.5-Decide` | 200 | совпадает (регистр букв точный) | 117 310 / 417 | apache-2.0 | **нет** (только `model.safetensors` 1.946 GB = 1.81 GiB) | жива, точное имя. ONNX-экспорта нет → брать `onnx-community/GLiNER2.5-Decide-ONNX` |
| `fastino/gliner2.5-multi-v1` | 200 | совпадает | 178 490 / 279 | apache-2.0 | **нет** (`model.safetensors` 1.149 GB = 1.07 GiB) | жива, точное имя. Экстрактор каскада 1 существует, но в safetensors |
| `fastino/gliner2-privacy-filter-PII-multi` | 200 | совпадает | 197 426 / 100 | apache-2.0 | **нет** (`model.safetensors` 1.228 GB = 1.14 GiB) | жива, точное имя. 9 файлов, онто-графа нет |
| `alibiserikbay/JevK5` | 200 | совпадает | 12 801 / 23 | apache-2.0 | нет (safetensors 8.412 GB, Qwen3.5-4B base) | жива |
| `alibiserikbay/JevK5-GGUF` | 200 | совпадает | 18 228 / 3 | apache-2.0 | нет (13 файлов, GGUF) | жива, кванты ниже |
| `yethdev/gliner2-pii-onnx` | 200 | совпадает | **0 / 0** | apache-2.0 | **да** — `model.quantized.onnx` 446 391 629 B = 0.446 GB (0.42 GiB) | существует, но **0 скачиваний**, последний коммит 2026-07-13. ONNX-референс рабочий, неофициальный форк |

Все 6 имён из спеки **существуют под точными именами**. Фантомов нет.

## 2. Что именно проверено по пунктам задачи

### 2.1 ONNX-файлов нет ни в одном репо `fastino/*`

Пример: `fastino/GLiNER2.5-Decide?blobs=true` → 10 файлов, ни одного `.onnx`:

```
.gitattributes, GLiNER-2.5-Decision-HF-Banner.png, README.md, SKILL.md,
config.json, encoder_config/config.json, model.safetensors (1 945 828 140 B),
special_tokens_map.json, tokenizer.json, tokenizer_config.json
```

Вывод для SPEC §11 п.1: противоречие «энкодеру нужен ONNX, а GGUF в llama.cpp не ложатся»
снимается в пользу **экспорта самим**. Fastino публикует только safetensors (`library_name:
transformers` / `gliner2`). Готовые ONNX-экспорты сторонние — раздел 4.

### 2.2 Реальные репозитории автора `fastino` (промер `?author=fastino&limit=100`, 16 репо)

Глинеровская линия, dl/likes:

1. `fastino/gliner2-base-v1` — 683 049 / 102
2. `fastino/gliner2-large-v1` — 223 418 / 103
3. `fastino/gliner2-privacy-filter-PII-multi` — 197 426 / 100
4. `fastino/gliner2.5-multi-v1` — 178 490 / 279
5. `fastino/GLiNER2.5-Decide` — 117 310 / 417
6. `fastino/gliner2.5-base-v1` — 113 300 / 40
7. `fastino/gliner2-multi-v1` — 86 280 / 88
8. `fastino/gliner2.5-small-v1` — 31 170 / 43
9. `fastino/GLiNER2.5-multi-Decide` — 18 471 / 66
10. `fastino/GLiNER2-Guardrails-PII-Multi` — 5 114 / 36
11. `fastino/GLiNER2.5-Decide-1B` — 2 744 / 22

Размеры `model.safetensors` (промер `?blobs=true`):

| Репо | safetensors |
|---|---|
| `gliner2.5-multi-v1` | 1 149 461 028 B = 1.15 GB |
| `GLiNER2.5-multi-Decide` | 1 149 461 028 B = 1.15 GB (байт в байт идентичный размер) |
| `gliner2-privacy-filter-PII-multi` | 1 228 421 964 B = 1.23 GB |
| `GLiNER2-Guardrails-PII-Multi` | 1 228 421 964 B = 1.23 GB |
| `GLiNER2.5-Decide` | 1 945 828 140 B = 1.95 GB |
| `GLiNER2.5-Decide-1B` | 4 755 208 228 B = 4.76 GB |

**Архитектуры по `config.json`** (промер `…/raw/main/config.json` + `…/raw/main/encoder_config/config.json`,
эндпоинт `/resolve/` пустой — нужен `-L` на `/raw/`):

| Репо | `architecture` | энкодер | hidden | layers | vocab | размер файла |
|---|---|---|---|---|---|---|
| `gliner2.5-multi-v1` | `boundary` | `microsoft/mdeberta-v3-base` | 768 | 12 | 250 112 | 1.149 GB |
| `GLiNER2.5-multi-Decide` | `boundary` | `microsoft/mdeberta-v3-base` | 768 | 12 | 250 112 | 1.149 GB |
| `GLiNER2.5-Decide` | `span` | `microsoft/deberta-v3-large` | 1024 | 24 | 128 011 | 1.946 GB |
| `GLiNER2.5-Decide-1B` | `span` | `jhu-clsp/ettin-enc-from-dec-1b` (modernbert) | 1792 | 28 | 50 378 | 4.755 GB |
| `gliner2-privacy-filter-PII-multi` | `extractor`, `counting_layer: count_lstm`, `max_width: 8`, `token_pooling: first` | `microsoft/mdeberta-v3-base` | — | — | — | 1.228 GB |

Голова boundary у обеих 2.5-multi-моделей идентична по config: `boundary_dim=128`,
`content_dim=64`, `pair_dim=128`, `record_dim=128`, `pool_size=192`,
`end_block_size=256`, `boundary_attention_layers=2`, `enable_count_head` присутствует.
Обе 2.5-модели — **один и тот же энкодер mDeBERTa-v3-base**; различие только в голове/задаче.

**Коррекция SPEC §5.2**: заявлено «`GLiNER2.5-multi-Decide` (~287M)».
`mdeberta-v3-base` (12 сл., h=768, vocab 250 112) — это ~278M, из них ~192M весит
таблица эмбеддингов. safetensors 1.149 ГБ / 4 B ≈ **287M параметров в fp32** —
цифра «~287M» **подтверждена арифметикой файла + config**.
Но **RAM-бюджет §10 «350–600 МБ (ONNX-энкодер)» под fp32-графом не выполняется**:
одна весовая часть 1.15 ГБ. Нужен fp16 (~575 МБ) или квант эмбеддингов —
ориентир: `yethdev/gliner2-pii-onnx` ужимает тот же mDeBERTa-base (vocab 250 112 × 768,
int8 per-row) до 446 МБ при drift max_prob 0.0057.

### 2.3 `alibiserikbay/JevK5-GGUF` — сверка заявленных размеров

Заявка SPEC §5.1: «JevK5-2B рабочий квант Q8_0 = 2.01 ГБ», «авторы не публиковали 4-бит».

Реальность (`?blobs=true`, 13 файлов, плюс `SHA256SUMS` в репо):

| Файл | Реальный размер | ГБ (10⁹) | GiB | Заявлено в SPEC |
|---|---|---|---|---|
| `jevk5-2b-v0.2-Q8_0.gguf` | 2 012 012 000 B | **2.01** | 1.87 | 2.01 ГБ ✅ совпало |
| `jevk5-4b-v0.3-Q4_K_M.gguf` | 2 708 804 000 B | **2.71** | 2.52 | 2.71 ГБ ✅ совпало |
| `jevk5-4b-v0.2-Q4_K_M.gguf` | 2 708 803 936 B | 2.71 | 2.52 | — |
| `jevk5-4b-v0.3-Q5_K_M.gguf` | 3 074 986 400 B | 3.07 | 2.86 | — |
| `jevk5-4b-v0.2-Q8_0.gguf` | 4 482 402 656 B | 4.48 | 4.17 | — |
| `jevk5-4b-v0.3-Q8_0.gguf` | 4 482 402 720 B | 4.48 | 4.17 | — |
| `jevk5-9b-v0.3-Q5_K_M.gguf` | 6 467 969 504 B | 6.47 | 6.02 | — |
| `jevk5-9b-v0.3.3-Q5_K_M.gguf` | 6 467 969 504 B | 6.47 | 6.02 | — |
| `jevk5-9b-v0.3-Q8_0.gguf` | 9 527 501 280 B | 9.53 | 8.87 | — |
| `jevk5-9b-v0.3.3-Q8_0.gguf` | 9 527 501 280 B | 9.53 | 8.87 | — |

Оба конкретных числа из спеки (2.01 ГБ и 2.71 ГБ) **подтверждены**.

**Опровергнута часть §5.1 «авторы не публиковали 4-бит»**: Q4_K_M опубликован и для
4B (v0.2 и v0.3). Из README репо (`/raw/main/README.md`): 4B v0.3 Q4_K_M = 221/231,
hard-tier 0.766 против 0.784 у Q8_0; 2B Q4_K_M **не опубликован** — в README дословно:
*"Not published: the 2B Q4_K_M changed 29 answers and dropped hard accuracy from 0.604 to..."*
(значение обрезано переносом строки, полная цифра в README не дочитана).
Числа SPEC (0.604→0.514) относятся к **2B**, не к 4B — в этом SPEC прав, но формулировка
«авторы не публиковали 4-бит» неверна как общая: 4-бит 4B опубликован.

`alibiserikbay/JevK5` (safetensors-репо): 10 файлов, `model.safetensors` 8 411 558 400 B
(8.41 ГБ), base `Qwen/Qwen3.5-4B`, чексуммы `SHA256SUMS` в репо есть.
Оба репо обновлены 2026-09-25.

## 3. Топ альтернатив на случай смерти `fastino`

Промер `api/models?search=gliner&sort=downloads&limit=20`, топ-10 по загрузкам:

| # | id | dl | likes | лицензия |
|---|---|---|---|---|
| 1 | `fastino/gliner2-base-v1` | 683 049 | 102 | apache-2.0 |
| 2 | `fastino/gliner2-large-v1` | 223 418 | 103 | apache-2.0 |
| 3 | `fastino/gliner2-privacy-filter-PII-multi` | 197 426 | 100 | apache-2.0 |
| 4 | `fastino/gliner2.5-multi-v1` | 178 490 | 279 | apache-2.0 |
| 5 | `urchade/gliner_large-v2` | 142 198 | 58 | apache-2.0 |
| 6 | `fastino/GLiNER2.5-Decide` | 117 310 | 417 | apache-2.0 |
| 7 | `fastino/gliner2.5-base-v1` | 113 300 | 40 | apache-2.0 |
| 8 | `fastino/gliner2-multi-v1` | 86 280 | 88 | apache-2.0 |
| 9 | `urchade/gliner_multi_pii-v1` | 70 807 | 177 | apache-2.0 |
| 10 | `urchade/gliner_multi-v2.1` | 44 272 | 171 | apache-2.0 |

Вне топ-10, релевантно как PII-замены: `nvidia/gliner-PII` (14 090 / 168, лицензия
**`other`** — для оффлайн-демона пересматривать юридически),
`knowledgator/gliner-pii-large-v1.0` (13 233 / 46, apache-2.0, **ONNX есть**),
`hivetrace/gliner-guard-omni` (5 647 / 23, apache-2.0).

## 4. Готовые ONNX-экспорты (критично: SPEC требует ONNX, fastino его не даёт)

| Репо | ONNX-файлы | Сумма ONNX | dl/likes | лицензия | Пригодность |
|---|---|---|---|---|---|
| `yethdev/gliner2-pii-onnx` | `model.quantized.onnx` | 0.446 GB | 0 / 0 | apache-2.0 | **Единственный промеренный единый граф PII-ONNX.** Вес-only квант: fp16-веса, таблица эмбеддингов 250112×768 в int8 с per-row symmetric scales. opset 17. `export_info.json` даёт sha256 `489edc52…3930` и заявляет parity с PyTorch: max prob drift fp32 1.29e-05, vs PyTorch 0.00567, span sets identical при порогах 0.3/0.5/0.7. **Заявления автора, независимого промера не было** |
| `DanKau/gliner2.5-multi-v1-onnx` | `onnx/encoder.onnx` 1.111 GB, `onnx/boundary.onnx` 4.92 MB, `onnx/classifier.onnx` 4.73 MB | 1.12 GB | 189 / 1 | apache-2.0 | Экстрактор (gliner2.5-multi-v1), раздельные графы encoder/boundary/classifier — ближе всего к нашей архитектуре |
| `jugaadsrl/gliner2-privacy-filter-PII-multi-onnx` | 24 файла, `encoder_fp32.onnx` 1.111 GB + `span_rep` / `count_lstm` / `classifier` / `scorer` отдельно, плюс зеркальный набор `fp16_v2` и `*_iobinding` | 2.46 GB | 0 / 0 | apache-2.0 | Самый полный декомпозиционный экспорт PII-модели; IO-binding-варианты — под наш latency-бюджет |
| `onnx-community/GLiNER2.5-Decide-ONNX` | `model.onnx` 285 759 B, `model_fp16.onnx` 288 706 B, `model_q4.onnx` 309 849 B, `model_q4f16.onnx` 341 889 B | ~1.2 MB | 866 / 2 | apache-2.0 | **Арбитр Decide.** ONNX-файлы **подозрительно малы** (286 КБ против 1.95 ГБ safetensors) — почти наверняка веса вынесены во external data, который в `siblings` не отображается. **Пропускная способность графа не проверена: перед использованием — скачать и промерить фактический размер external data** |
| `knowledgator/gliner-pii-large-v1.0` | `onnx/model.onnx` 1.763 GB, `onnx/model_quint8.onnx` 647.87 MB | 2.41 GB | 13 233 / 46 | apache-2.0 | Альтернатива вне fastino с настоящим полным ONNX-графом |
| `okasi/gliner2-privacy-filter-pii-multi-onnx` | `model_q4.onnx` 1.35 MB, `model_q8.onnx` 1.35 MB | ~2.7 MB | 36 / 2 | apache-2.0 | Те же признаки external-data, что у `onnx-community`. Не промерен по содержимому |

Прочие найденные ONNX-репо PII/GLiNER2.5 (не инспектировались по файлам):
`Raymakers/gliner2-pii-onnx` (0 dl), `MinDleSsFR/gliner2-pii-onnx` (32), `cilebre/gliner2-pii-ONNX` (14),
`jugaadsrl/GLiNER2-Guardrails-PII-Multi-onnx` (0), `prvn-ramesh/gliner-small-v2.5-onnx`,
`nicolasembleton/gliner2.5-{small,base,multi}-v1-onnx` (все 0 dl),
CoreML-экспорты: `FluidInference/gliner2-5-multi-coreml`, `ranzucker/gliner2-5-multi-coreml`,
`smdesai/GLiNER25-Multi-FP16-Core{ML,AI}`.

## 5. Итог

### 5.1 Фантомов нет — все 6 имён бьются точно

Все имена из спеки отдают **HTTP 200** под **буквально заявлённым написанием**
(включая смешанный регистр `GLiNER2.5-Decide` и `gliner2-privacy-filter-PII-multi`).
Все под лицензией **apache-2.0**, все `private: false`, `gated: false`, `disabled: false`.
SPEC §11 п.1 («GLiNER 2.5 может не существовать») — **закрыт, риск снят**.
Скачки по всем трём основным репо — six-figure, последний коммит 2026-10-08, модель активна.

### 5.2 Единственный реальный дефект спеки: ONNX

Ни один `fastino/*`-репо **не содержит ONNX**. Транскрипт §1 называет каскады «ONNX»,
первоисточник даёт только safetensors. Отсюда два пути (оба требуют промера, не решения на словах):

1. **Экспорт самим** — `torch.onnx.export` + head-декодер по `SKILL.md` из репо
   (в каждом fastino-репо есть `SKILL.md`, 6 511 B, идентичный по размеру — вероятно один шаблон).
2. **Готовый экспорт** — кандидаты по каскадам:
   - Каскад 1 (экстрактор `gliner2.5-multi-v1`) → `DanKau/gliner2.5-multi-v1-onnx`
     (encoder 1.11 GB + boundary + classifier, apache-2.0, 189 dl).
   - Каскад 1-опц (PII `gliner2-privacy-filter-PII-multi`) → `yethdev/gliner2-pii-onnx`
     (0.446 GB единый граф, единственный готовый в бюджете) или
     `jugaadsrl/gliner2-privacy-filter-PII-multi-onnx` (2.46 GB декомпозиция).
   - Каскад 2 (арбитр Decide) → `onnx-community/GLiNER2.5-Decide-ONNX`, **с предварительной
     проверкой external data** — размер 286 КБ не объясним без внешних весов.

### 5.3 Что поправить в SPEC

1. §5.1: «авторы не публиковали 4-бит» → неверно как общее утверждение.
   Опубликован `jevk5-4b-v0.3-Q4_K_M.gguf` (2.71 GB, 221/231, hard 0.766).
   Не опубликован только **2B** Q4_K_M. Размеры 2.01 ГБ и 2.71 ГБ — подтверждены байт-в-байт.
2. §5.2 «~287M» для `GLiNER2.5-multi-Decide`: файл 1.15 ГБ, fp32-размер.
   Число параметров не противоречит, но §10-бюджет «350–600 МБ RAM на ONNX-энкодер»
   при 1.15 ГБ весов **невыполним без квантизации** — пересчитать под int8/fp16-граф
   (`yethdev` даёт 0.446 GB на PII-энкодере — ориентир).
3. §11 п.1 формулировку «могут не существовать» заменить на «существуют, подтверждено
   2026-10-18», добавить: «ONNX-экспорта у вендора нет, нужен экспорт или сторонний репо».
4. §5.2: альтернатива арбитру — `fastino/GLiNER2.5-Decide-1B` (4.76 GB, 2 744 dl) и
   `fastino/GLiNER2-Guardrails-PII-Multi` (1.23 GB, 5 114 dl) — оба живые, в спеке не упомянуты.
5. Числа SOTA (SPY recall 0.718, «42 PII-типа») остаются `[claim-unverified]` —
   в этот промер не входило чтение карточек на предмет метрик; README
   `yethdev/gliner2-pii-onnx` приводит SPY-таблицу, где **у fastino-моделей своих чисел нет**
   (в таблице строка названа `fastino/gliner2-pii-v1`, а не `-privacy-filter-PII-multi` —
   possible name mismatch, не подтверждено).

## 6. Не промерено (границы этого промера)

- Число параметров — **промерено косвенно**: `config.json` получен через
  `…/raw/main/config.json` (см. §2.2), точный подсчёт по именованным тензорам
  safetensors-заголовка не делался. Цифра ~287M выведена из размер/4B + архитектуры энкодера.
- Фактическое наличие external-data у `onnx-community/GLiNER2.5-Decide-ONNX` и
  `okasi/gliner2-privacy-filter-pii-multi-onnx` — не проверялось (графы не скачивались).
- Метрики качества (SPY, JeVBench) — не сверялись с первичными бенчмарками, только с
  самонаписанными README карточек.
- Скачивание и замер RSS/латентности — вне этой задачи; это `docs/model-audit-inference.md` §I1 п.2.
- Чексуммы ONNX/GGUF — в репо лежат `SHA256SUMS` (JevK5-GGUF, JevK5) и `export_info.json`
  (yethdev); заявлению `489edc52…` локальный пересчёт не делался, файл не скачивался.
- Точное значение «hard accuracy 2B Q4_K_M» из README JevK5-GGUF — строка обрезана
  переносом, дочитать «0.514» по первичнику не удалось; цифра SPEC остаётся `[claim]`.

## 7. Техническая заметка по транспорту (для повторных промеров)

- `…/api/models/<id>` — 200 с полным JSON даже для репо без карточки-редкостей; метаданные
  (`downloads`, `likes`, `lastModified`, `tags`, `license`) берутся отсюда.
- `…/api/models/<id>?blobs=true` — единственный способ получить `siblings[].size` в байтах.
  Без `?blobs=true` sizes приходят `null`.
- `…/resolve/main/<file>` отдаёт **302 Temporary Redirect** телом без файла — нужен `curl -sL`.
  Именно из-за этого первая попытка прочитать `config.json` через `/resolve/` выглядела как
  «эндпоинт пустой». Правильный путь для raw-текстов — `…/raw/main/<file>` (200 сразу).
- `?author=fastino&limit=100` — полный список репо автора, надёжнее `search` (search
  ранжируется по downloads и не отдаёт все репо).
