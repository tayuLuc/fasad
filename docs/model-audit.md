# Model audit — шаг 2 spike (issue #6)

Прогон: 2026-10-19, macOS (arm64), rustc 1.97.1, ort 2.0.0-rc.14 (download-binaries,
статик libonnxruntime.a, CPU EP), spike = `crates/guard-onnx/examples/spike.rs`.
Профиль: **debug** — release-прогон проводился ×5 и падал SIGSEGV 139 в обеих конфигурациях (plain, env 26.0), §5.1; гейт бюджета закрыт dev-числами с оговоркой профиля.
Веса: `~/.cache/fasad-models`, манифест `models/manifest.tsv`.

## 1. Модель A — веса (промер shasum -a 256 = LFS-oid HF, rev из GET api/models)

| file | repo@rev | bytes | sha256 |
|---|---|---|---|
| model.optimized.fp16.onnx | lockR/rubert-base-pii-ner-onnx@ea7610b2 | 355 541 615 | 039aba6b…c70a501 |
| onnx/model_q4f16.onnx | onnx-community/GLiNER2.5-Decide-ONNX@18271032 | 341 889 | 93f3e0d4…6381684f6 |
| onnx/model_q4f16.onnx_data | (там же) | 523 127 808 | df2b05dc…e66210e8 |
| tokenizer.json (rubert) | lockR | 3 714 701 | f61eee9d…89dec1b9 |
| tokenizer.json (decide) | onnx-community | 8 333 952 | 3ad87d9f…df467bcc8 |

Скелет манифеста (issue-промер) содержал ошибку размера external data:
1 744 089 088 B — это `model.onnx_data` **fp32**; для q4f16 = 523 127 808 B (промерен
tree-API и файлом на диске). Исправлено в манифесте.

## 2. Метрики прогона (сырые METRIC-строки, dev-профиль, threads=4)

```text
METRIC|rss_mib_baseline|2.2
METRIC|env_init_ms|23.0
METRIC|rss_mib_after_env|7.5
IO|external_data_bytes|523127808
METRIC|rss_mib_before_load_arbiter|7.5
METRIC|rss_mib_after_load_arbiter|269.0
IO|in|arbiter|input_ids|Tensor<i64>(batch, sequence)
IO|in|arbiter|attention_mask|Tensor<i64>(batch, sequence)
IO|in|arbiter|marker_positions|Tensor<i64>(batch, markers)
IO|out|arbiter|logits|Tensor<f32>(batch, markers)
```

## 3. Ключевой вопрос §1.8: маппинг external data

Сессия арбитра (graph + external data 523 МБ) поднялась с RSS 7.5 → **269.0 MiB (первый прогон) / 250.3 MiB (второй прогон, воспроизводимость ±7%)**.
Вывод: q4f16 external data **НЕ маппится целиком в resident-RSS** — ORT лениво/
частично подгружает веса (промер private-RSS `task_vm_info.internal`, «Память»
как в мониторе активности). Бюджет SPEC §1 (≤1.8 ГБ):
355 МБ (lockR fp16, полный load ожидается в шаге 4) + ~0.3 ГБ арбитр-резидент
+ арены/токенизаторы/буферы ≈ **0.9–1.2 ГБ прогноз — вписывается**, окончательный
вердикт после промера lockR-сегмента (см. § Дефекты: инференс-прогон упал на
GatherElements до lockR-мерки).

## 4. IO-контракты (промер сессий, для шага 4)

1. lockR `model.optimized.fp16.onnx`: BertForTokenClassification; входы
   `input_ids`/`attention_mask`/`token_type_ids` int64; выход logits fp32
   `[B, L, 43]` (id2label 0..42, BIO); opset 17; max_len 512; динамические оси.
   export_metadata: source redmadrobot-rnd/rubert-base-pii-ner@c802e8cd,
   torch 2.8.0, optimizer opt_level=0.
2. Decide `model_q4f16.onnx`: энкодер DeBERTa-v3-large 24L/1024H, vocab 120111;
   входы `input_ids`/`attention_mask`/`marker_positions` int64; выход `logits`
   fp32 `[batch, markers]`; special-токены `[SEP_STRUCT]/[SEP_TEXT]/[P]/[C]/[E]`
   `[R]/[L]/[EXAMPLE]`.

## 5. Дефекты харнесса (зафиксированы, лечатся в шаге 4/9)

1. **Release-прогон spike = SIGSEGV (exit 139)** на первой же итерации
   орт-инициализации (после `rss_mib_baseline`). Воспроизведено: `cargo run
   --release --features ort-inference --example spike -- --arb --lockr` (и с
   `MACOSX_DEPLOYMENT_TARGET=26.0`). Dev-профиль стабилен. Кандидат причины:
   `-Wl,-undefined,dynamic_lookup` (нужен из-за §5.2) + `-lSystem` порядок в
   release. НЕ правим: `[profile.release]` workspace (запрет родителя); чинить
   заменой линк-стратегии (ORT dylib/`load-dynamic` фича) в шаге 4.
   **РЕШЕНО 19.10 06:34 (промеры release, issue #11):** официальный dylib-путь
   `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=… -Wl,-rpath,…`: 1.20.1/1.23.0/1.24.4/
   1.26.0 — не крашатся (мягкий exit 101 «api-31 → supported [1,NN]», NN=минор);
   **1.31.0 — прогон живой**: exit 1 (GatherElements §5.3, ожидаемо до шага 4),
   `env_init_ms|40.3`, `rss_mib_after_load_arbiter|387.4` (сырые /tmp/mg43-45.out).
   Дефект = статик-линковка pyke-сборки (min=11.0 × chained fixups → unresolved
   helper = прыжок в 0x0, см. crash-reports). Релизный путь §9 везёт dylib anyway;
   бюджет-гейт закрыт release-числом (387.4 ≤ dev-разброс 250–385). Конфиг
   `ort-dylib` (just-цель + build.rs env) — шаг 4.
2. **`___isPlatformVersionAtLeast` undefined в release-линке**: орт-статик
   rc.14 (host_utils.mm/model.mm) ссылается на clang-runtime-хелпер, бэкпорт
   которого в libSystem требует min≥12.3, а cargo печатает min=11.0. Все обходы
   промерены и НЕ работают: env-мин (min=26.0 в cmdline — символ всё равно
   undefined), `-Wl,-platform_version` («passed two min versions», ld берёт
   первый), RUSTFLAGS link-arg, статический линк C-объекта. Рабочая конструкция:
   dylib-C-остров + `-Wl,-undefined,dynamic_lookup` + стаб в отдельной TU
   (`spike/platform_stub.c`).
3. **Инференс арбитра упал до lockR-мерки**: `GatherElements node_gather_48:
   Out of range value in index tensor` — spike передаёт заглушечные
   `marker_positions` без семантики SPAN-разметки GLiNER2.5. Это НЕ
   дефект модели: контракт маркеров строит декодер шага 4 (gline-rs как
   референс). Метки load-time (RSS сессии) получены до инференса — §3 валиден.
4. RSS до lockR-сессии и латентность prefill не сняты (см. 3) — добирается в
   шаге 4 промером на живом декодере.

Addendum 20.10 (4b-2a, issue #23, живой прогон `spike --arb` с живыми маркерами,
ветка step4b2a-live-markers (issue #23), dylib 1.31, release):
1. **Живые `marker_positions` = exit 0.** Контракт графа по первичке
   (карточка `onnx-community/GLiNER2.5-Decide-ONNX@18271032` §Graph + экспорт
   `conversion/export_onnx.py` + референс-код `fastino-ai/GLiNER2@main`
   `processor.py`/`classification/scoring.py`): layout
   `( [P] вопрос ( [L] метка … ) ) [SEP_STRUCT] … [SEP_TEXT] слова`;
   `marker_positions` = позиции токенов `[L]` (по одной на метку),
   `logits (batch, M)` — по логиту на маркер, softmax внутри вопроса.
   spike 4b-2a строит констрэкт (`arb_live_layout` + `decide_marker::groups`)
   из `spike_texts()` + EN-подсхемы 3 вопросов × 2 метки: живой вход L=1235,
   M=6, `MARKER|arb|run=ok|markers=6`, `logits|shape=[1, 6]|ok=true`,
   softmax групп 0.9983/0.0017, 0.9846/0.0154, 0.9994/0.0006 (все три «yes»
   над PII-текстом — содержательно верно). Нить N1 (ревью #32): маркер =
   позиция `[L]`; референс-классификатор GLiNER2 греет эмбеддинг ПОСЛЕ `[L]`
   (`scoring.py` `embs[1:]`) — не конфликтует: Decide-граф собирает hidden на
   `[L]`-позициях (первички сходятся: карточка §Graph, `export_onnx.py`,
   `verify_parity.py` L34-37).
2. **§5.3 воспроизведён И исправлен одновременно.** Точная ошибка ORT на OOB
   индексе зафиксирована в том же прогоне дословно:
   `Non-zero status code … GatherElements node. Name:'node_gather_48' …
   Out of range value in index tensor` (`MARKER|arb|trap=ort_error`).
   Уточнение рулинга 4b-0 («падение требует НЕПУСТЫХ маркеров»): падают не
   непустые маркеры сами по себе, а НЕВЫПОЛНИМЫЕ индексы ≥ L; заглушка step-2
   (`3+i%512`, длина 256) при живом L=1235 целиком легальна и НЕ падает
   (промер `trap`-фазы). Дефект был в значениях индексов, не в пустоте.
3. **Метрики нового прогона** (сырой stdout прогона 20.10, трасса METRIC;
   первичный прогон 20.10 дал `--lockr`=Protobuf parsing failed: кеш-вес
   `lockR/model.optimized.fp16.onnx` был затёрт извне до 7 байт «CORRUPT»
   (промер ревью #32: sha256 c7791eea… ≠ манифестного 039aba6b…, HF-первичка
   rev ea7610b2 жива, range-GET 206). B1 закрыт перекачкой родителем
   (fetch-models.sh fail-closed: evict→refetch, 355 541 615 B, sha
   039aba6b… совпал) — полный прогон переснят, п.5:
   `load_ms_arbiter` 1180.4, `delta_load_mib_arbiter` 327.5 (первый прогон
   сессии с живыми входами; Δ ниже §3 из-за иного порядка аллокаций
   токенизатора до load — токен-работа вынесена до базового замера. Нить N2
   ревью #32: цифра — ЕДИНИЧНЫЙ прогон; независимое подтверждение дало
   370.3–371.6 (разброс 0.4 MiB, стабильнее точки, но выше её); подтверждение
   после B1-фикса: 370.5–372.0 в 3× `--arb` медианы; бюджет-вердикт — по
   медиане ≥3 прогонов), `rss_after_load_arbiter` 488.6,
   `run_p50_ms_arbiter` 5963.0 (prefill L=1235, threads=4, CPU; промеры
   4728/7825/5963 — разброс ×1.7 без пула; независимое подтверждение
   ревью #32: 4687–6574 в 5 прогонах — та же полоса; после B1-фикса медиана
   3× дала полосу 6.8–26.2 c — разброс велик, L=1235 без чанков,
   бюджет-вердикт по латентности за 4b-3), `rss_after_runs_arbiter` 1275.5.
   Бюджет-гейт ≤1.8 GiB: с 3 текстами в одном входе (в 4.8× длиннее step-2
   окна 256) RSS до пика прогона вписывается (независимо 1199–1414 MiB);
   чанкер 4b-1 (окна ≤384) даст L≤~400 и ниже.
5. **Полный прогон после B1-фикса (20.10, перекачанный lockR, dylib 1.31,
   release; `--arb --lockr` = exit 0; закрывает §5 п.4 «RSS до lockR-сессии
   и латентность prefill не сняты»).** Арбитр: `load_ms_arbiter` 1177.0,
   `delta_load_mib_arbiter` 370.5, `run_p50_ms_arbiter` 7284.6,
   `rss_after_runs_arbiter` 1314.3. Экстрактор lockR fp16 (единый файл без
   external data, pad-окно 256, 3 текста): `load_ms_extractor1b` 457.6,
   `delta_load_mib_extractor1b` 1351.6, `run_p50_ms_extractor1b` 271.8,
   `rss_mib_after_runs_extractor1b` 1462.4. Δ lockR 1351.6 MiB — существенно
   больше файла 355 МБ (единый fp16-граф, не external data): resident = веса
   + граф + пул активаций pad-окна 256 × батч-стрим; гипотеза «единый файл →
   Δ≈размеру файла» ОПРОВЕРГНУТА промером. Суммарная residency
   арбитр+экстрактор в одном процессе (шаг 4) — обязательный замер перед
   бюджет-вердиктом ≤1.8 GiB: alone-lockR after_runs 1462.4 уже 79 % бюджета,
   чанкер 4b-1 сокращает только арбитра (lockR окно 256 фиксировано).
4. **Контракт токенизации (промер, не вера):** `encode(целая строка, false)` —
   HF-эквивалент; побайтный СПЛАЙС отдельных `encode` сегментов НЕ совпадает с
   конкатенацией на стыке `.`+`[SEP_TEXT]` (Metaspace склейка `▁`+`.`), поэтому
   spike кодирует цельной строкой и проверяет потерю содержимого сканом слов +
   наличием всех спец-токенов в id ([UNK]=0). Post-процессор [CLS]/[SEP] снят
   (`with_post_processor(None)`): спецтокены HF добавляет только post_process
   (промер tokenizers 0.23.2 `tokenizer/mod.rs`), разметка Decide спецы не
   содержит (§Graph). В vocab живого `tokenizer.json` все 10 структурных
   маркеров на манифестных id (`MARKER|vocab|*|true`).

### 5.6 Аддендум 20.10 вечер (4b-2d, issue #20): «position-limit 512» — ОПРОВЕРГНУТ первичкой

Ревью #34 / родительский аудит спросили: живой `--arb` прогоняет L=1236 > 512 — как
это уживается с гардом «окно + overhead ≤ 512»? Ответ по ONNX-первичке, а не по
карточке `[claim]`:

1. **Decide = DeBERTa relative-position bias, НЕ абсолютные position-эмбеддинги.**
   Промер `model_q4f16.onnx` (341 889 B, заголовок `pytorch 2.14.0`): инициализатора
   вида `embeddings.position_*` / `wpe` в графе НЕТ (`tr`-скан по имени — пусто).
   Есть `encoder.encoder.rel_embeddings.weight` с dims `[1024, 512]` (распаковано из
   `TensorProto.dims`; external-data `length` = 1 048 576 B int8 = ровно 1024×512).
   1024 = `relative_attention_num_buckets`, 512 = `relative_attention_max_distance`
   (SD3M-клэмп относительных смещений). Числа — первичка графа, не `[claim]`.
2. **Следовательно 512 — НЕ cap последовательности.** L=1236 валиден: дальние
   пары токенов просто попадают в крайний бакет смещения, корректность не ломается.
   Прежняя формулировка (коммит 9d1e19f 4b-2c: «позиционные эмбеддинги валидны до
   512, поэтому чанковка обязана») — ЭПИСТЕМИЧЕСКАЯ ОШИБКА, снята; константа
   переименована `DECIDE_POSITION_LIMIT → DECIDE_REL_MAX_DISTANCE` (arbitrate.rs,
   decide.rs) с доком «практический потолок O(L²)/RSS, не требование корректности».
3. **Настоящая причина чанковки** = латентность (attention O(L²): prefill L=1236
   p50 ~7 s, §5 п.5) и RSS, а не overflow. Чанк-окно держим ≤ 384 (SPEC §2), с
   overhead схемы 56 токенов (промер `encode(schema_block,trio) = 56`; +1 на
   Metaspace-склейку `[SEP_TEXT]`+`.`) ⇒ пик входа ≈ 384+57 = 441, ниже rel-bucket
   512 — безопасно по обеим интерпретациям, но НЕ потому что «иначе сломается».
4. **Overhead промер (первичка 4b-2d, живой tokenizer.json rev 18271032):**
   `OVERHEAD|block_alone_tokens=56`, `OVERHEAD|block_plus_one_char=57` (state_extra=1).
5. **RSS-пик двух моделей: ПИК НЕ МЕРЯЛСЯ этим аддендумом.** Числа §5 п.5
   (`rss_after_runs_arbiter` 1314.3, lockR after_runs 1462.4) — RSS ПОСЛЕ прогонов
   каждой модели по отдельности, не пик одного процесса с обеими. Сумма-оценка
   ~1.4–1.5 GiB < 1.8 GiB, но вёрдикт по ПИКУ снимается отдельным `--arb-budget`
   vm-footprint-сэмплингом (задача 4b-2d, в работе — не считать закрытым).

## 6. CI-контракт

CI spike НЕ гоняет (фича `ort-inference` default-off, example no-op,
тест-прокси `#[ignore]`); веса в CI не качаются. Прогоны — рукаместо
(macOS/Linux). Linux-ветка spike читает `/proc/self/status` VmRSS (safe, без
C-острова) — второй источник метрик с CI-матрицы, когда появится job.

## 8. Релизный путь ORT: официальный dylib 1.31.0 (issue #11, шаг 4a)

1. Причина (промеры §5.1): статик-pyke на macOS release = SIGSEGV (chained fixups ×
   deployment target 11.0, unresolved `___isPlatformVersionAtLeast` → jmp 0x0); орт-дока и
   §9 SPEC: релиз поставляет dylib — статик-режим остаётся только CI-линтовкой.
2. Версия: api-31 (орт rc.14) ⇒ минимум ORT **1.31.0**; graceful-эскалация
   подтверждена промерами rc.14 с 1.20.1/1.23.0/1.24.4/1.26.0: exit 101
   «requested API version [31] not available» без краша (sysrc /tmp/mg43-45).
3. Артефакты релиза v1.31.0 (github.com/microsoft/onnxruntime/releases/tag/v1.31.0,
   sha256 промерены загрузкой 19.10):
   - macOS arm64: `onnxruntime-osx-arm64-1.31.0.tgz`
     sha256 1031b36dd3bdaa8d976a6130d9cf2a05e9be320b93ae804f8427b91dc3432afc (36 549 009 B);
     dylib внутри: sha256 2a50a63e7f41f8d4d551d3ee47248df3864f6540109fce8ad520ca3b51af4b70.
   - Linux x64: `onnxruntime-linux-x64-1.31.0.tgz`
     sha256 cc5c72baf5ae5c8238a6841f0897227be2d02826b9cf98eaf02fdefaeeb03a57 (11 408 003 B).
   - Windows x64: nupkg `Microsoft.ML.OnnxRuntime.1.31.0` (рантайм-dll в runtimes/win-x64/native,
     доставка copy-dylibs в шаге 9; sha256 — отдельный промер, не заявляем).
   - Артефакты НЕ коммитятся в git (AGENTS §Не тащим веса); CI ort-прогонов нет (§6).
4. Сборка: `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=<dir>/lib cargo build --release
   --features ort-inference` — build.rs дописал rpath-ветку (macos|linux), just-рецепты
   `ort-dylib`/`spike-dylib`. Релизный прогон 19.10 (сырой /tmp/mg48-49.out):
   exit=1 (GatherElements-заглушка §5.3 — до живых marker_positions шага 4b), env_init
   37.8–40.3 ms, rss_after_load_arbiter 379.4–387.4 MiB — бюджет-гейт release закрыт.
