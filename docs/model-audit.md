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
5. **RSS-пик двух моделей В ОДНОМ ПРОЦЕССЕ (`--arb-budget`, 3 прогона 19.10
   вечер, ФИНАЛЬНЫЙ билд 36c13db в изолированном worktree, 3 прогона). Пик =
   max по всем точкам (task_info RSS + vmmap footprint) каждого шага:
   `METRIC|rss_peak_mib_both_models|1330.9` / `1434.6` / `1434.4`, вердикт
   `BUDGET|verdict=ok|…<1843.2` 3/3. Семантика вердикта — КОНСЕРВАТИВНАЯ
   (бюджет safety-critical): держим **peak_max = 1434.6 MiB = 78 % бюджета
   1843.2** (не медиану 1434.4); разброс 1331–1435 =Pages-wired момент снимка
   на ОС-давлении (run1: после load lockR всего 782.7 — mapper-ленивость),
   не деградация. Пик ВСЕГДА достигается на фронтире двух load (after_run_1b),
   освобождение lockR-весов до after_both (732–861) подтверждает: residency
   двух моделей в рантайме НЕ сумма, но бюджет планировать по сумме (п.5 ниже).
   Нюанс ревью #34(в) ПОДТВЕРЖДЁН числами: после `after_run_extractor1b`
   1434.6, `after_load_arbiter` = 1288–1291, т.е. Δ второй сессии 1288.7 −
   1385.9 = −97…+175 MiB при alone-дельте 370–500: сессии НЕ шерят веса
   (отрицательные точки = ОС-вытеснение pages первой сессии), budget-план
   шага 5+ обязан считать сумму residency, не пересечение.
6. **Латентность чанковки: выигрыша НЕТ — при обоих профилях O(L²) (finding,
   ревью #34 N5; А/B в ОДНОМ ПРОЦЕССЕ `--arb-chunked --arb`, финальный билд
   7031137, 3 прогона):**
   - одиночный прогон L=1236: `run_p50_ms_arbiter` **5281.8 / 5900.1 / 7716.8**
     (полоса согласуется с ревью #34: 7433/6798/7284);
   - чанкировка того же текста (4 куска ≤459): `lat_chunked_p50_ms`
     **4066.8 / 4435.2 / 5910.7**, чистый инференс `runs_only` ≈ той же полосы
     (4262 при p50 4067) — токенизация не при чём;
   - линейная декомпозиция (L-сумма 1514 = 459+423+440+192 (первичка `IO|tokens`)
     против 1236 одного входа ⇒ ×1.225, прогноз ≈6470 мс по первой паре) НЕ
     подтвердилась (факт 4067 — с выигрышем, как предсказывает квадратичный
     профиль: 6× fewer attn-пар при 4× фикс-оверхед ≈ 1.67×); но и квадратичного
     ПРОИГРЫША нет: полоса one-run перекрывает худший chunked-прогон.
     O(L²) на этой модели threads=4 не доказан НИ В ОДНУ сторону; фикс-overhead
     прогона ≈1.0–1.5 c доминирует. Следствие: чанковка = ПОКРЫТИЕ входов
     >rel-бюджета, НЕ ускорение; upper-bound задержки стрима =
     ceil(L/384)×~1.2 c. Вопрос SPEC §2 — issue #41 (operator-level).
   - бюджет-строки того же прогона: `delta_mib_extractor1b` 688.2/437.6/565.0
     (моя машина, lazy-mapping не прогрет); рецензент #43 на другой машине:
     750.4/1375.9/1376.0. Полоса Δ₁b = **437–1376 MiB** зависит от прогрева
     lazy-mapping (alone 1351.6 §5 — верх полосы); КОНСЕРВАТИВНО для бюджета
     держим ВЕРХ полосы (1376 ≈ alone — совпало). `delta_mib_arbiter2nd`
     −234.8/+296.8/−93.6 — вторая сессия НЕ шерится (ревью #34 в числами),
     пик 1308.7/1185.2/1318.0 (вердикт по max **1434.6**, п.5).
7. **Chunker-гард живьём (промер B-окна):** `--arb-chunked --window 448` даёт
   чанк 1659 B → `IO|tokens|arbiter_chunked|516|487|415`, фактический L=516 >
   512 ⇒ `ChunkTooLong` (exit 1) — ровно как задумано (гард по ФАКТИЧЕСКОЙ
   длине, не байтовой оценке: 1659/4=415 недооценивал бы на 101 токен).
   Конфиг A 384: L_max_exact = 459 = бюджет 440 (окно 384 + overhead 56) **+19**
   — первичка расхождения: Metaspace-склейка стыка `[SEP_TEXT]`+`.`/PII-токенов
   даёт больше одного разделительного токена на реальном кириллическом входе
   (промер block+` a` = +1 — нижняя граница на ASCII-хвосте). ≤512, проход. `COVERAGE|hits|3|covered_bytes|4301|
   text_bytes|4301` (два прогона идентично) — union merged-хитов покрывает
   весь текст (все 3 вопроса сработали на всех кусках; coarse-container
   гранулярность — #41).
8. DUAL не прорегрессирован финальным билдом: `DUAL|maxdiff|2.577e-8` exit 0;
   `--arb-budget` BUDGET|decide_probs|3 (модульный путь живой).

### 5.7 Аддендум 20.10 (4b-3B/C, issue #20): парити fp32↔квант + recall каскада-2 на golden-v1.1

> **Пост-ревью перезамер (PR#49 блокер №1).** Первая редакция раздела страдала
> off-by-one в оракуле пересечения: `i0 = t0−1` при доказанном 1-в-1 `e.ids` ↔
> `e.offsets` (промер 20.10 twice: `len(ids)==len(offsets)==75` на g0001,
> `om[17]=(56,63)='Ушакова'` → байт 87 = gold `start_byte`; сдвиг брал `om[16]`
> = `':'` → b0=85). Смещение влево при критерии пересечения только **добавляло**
> хиты ⇒ абсолютные recall были завышены; Δ-паритет почти не тронут (смещение
> одинаково у fp32 и кванта). Оба харнеса исправлены (d6a9f45), все числа ниже —
> **перепрогон после фикса**; первичка: `/tmp/parityB_{lockr,decide}_fixed.txt`,
> `/tmp/recall_fixed2.txt` (debug, profile-контракт §5.1 — release-SIGSEGV
> воспроизвёлся на 06:07, crash-report `.ips`). Раунд-2 ревью добавил второй
> перезамер: B-decide перевыпущен в **рантайм-порядке блока схем**
> (`/tmp/parityB_decide_ro.txt`, байт-в-байт с независимым прогоном ревьюера
> `/tmp/r2_pyB_rustorder.txt`); алфавитные числа отозваны. Release-оговорка
> §5.1 ослаблена ревьюером (его релизный прогон exit 0, бит-в-бит с
> debug-первичкой; родитель повторить не смог — 139 и при rm-dylib-контракте,
> и при dylib рядом с бинарём; вывод: профиль на числа не влияет,
> воспроизводимость падения = открытый хвост §5.1).

Профиль: **debug** (см. релиз-оговорку выше), threads=8 (recall) / 4 (парити), macOS
arm64, ORT 1.31.0 dylib. Датасет: golden-v1.1 (204 ряда, split=recall 150, sha
`546d8c35…`), знаменатель 285 = span-level gold-вхождений 8 покрываемых классов
(ogrn/ogrnip/iban — вне ONNX-инвентаря моделей, исключены из метрики; 285 из 358
recall-спанов — оставшиеся 73 = iban 27 + ogrn 25 + ogrnip 21, см. README golden). Оракул —
`tools/verify/parity_golden.py` (python-харнес); Rust-пути
(`examples/parity_onnx`, `examples/recall_golden`) воспроизводят его контракт.

**B. Парити fp32 ↔ квант (4 порога × 2 модели; протокол = правка тикета
родителя 20.10: вердикт-агрегат AND только по рабочим τ ≤ 0.25 (SPEC §5.6
низкий порог экстрактора), τ>0.25 — informational):**

lockR fp16 (`model.optimized.fp16.onnx` vs fp32):
- `maxabs_logit_delta_f32 = 0.0262` (150 рядов, Δ logits — не квантовый шум fp16
  weight-only, а переэкзаменация graph-оптимизации; достаточна: argmax-теги не
  меняются)
- пороги 0.20/0.25/0.50: recall fp32=fp16=**86.32** (Δ=0.00, tp 246/285, per-class
  Δ=0.00 все 8; классы: address/email/phone/person_name 100.00, card_pan 81.25,
  inn 58.33, snils 58.62, passport 62.50); 0.70: 84.21 = 84.21 (Δ=0.00, tp 240) —
  **`PARITY|verdict|pass|model|lockr`**
- BUDGET rss (офлайн-гейт, не runtime-контракт)

Decide q4f16 (`model_q4f16.onnx` vs fp32, row-level «есть класс?»). **Второй
перепрогон (ревью PR#49 раунд-2, блокер «порядок схем»):** первый перезамер
стоял в АЛФАВИТНОМ порядке CLASS_LIST, прода (`recall_golden.rs::CLASSES`) —
в рантайм-порядке; u-вероятность Decide ЗАВИСИТ ОТ ПОРЯДКА ВОПРОСОВ (snils
62.07→37.93 только от перестановки!). Ниже — runtime-порядок
(`/tmp/parityB_decide_ro.txt`, байт-в-байт с независимым прогоном ревьюера
`/tmp/r2_pyB_rustorder.txt`); алфавитные цифры (95.44/96.84, snils −13.79)
ОТОЗВАНЫ как измерение не-прода конфигурации:
- 0.20: fp32 94.04 → q4f16 **95.09** (Δ −1.05 = квант ЛУЧШЕ; snils 44.83→55.17
  в пользу кванта −10.34 на этом пороге — fp32-аномалия p-банды, не деградация)
- 0.25: fp32 92.28 → q4f16 **93.33** (Δ −1.05; person_name 98.21=98.21 Δ0.00;
  snils 27.59→37.93 = в точности C-число Rust-харнеса — рассинхрон B↔C был
  ПОЛНОСТЬЮ порядком, №-субституция не даёт ничего) —
  **`PARITY|verdict|pass|model|decide`**
- 0.50: 86.32 = 86.32 (Δ **0.00**, 246/246 — «деградация +1.75» была алфавитным
  артефактом); breach только класс-гейт person_name Δ+1.79 (83.93→82.14)
- 0.70: 79.30 → 80.35 (Δ **−1.05**, квант ЛУЧШЕ на overall; person_name Δ+5.36
  остаётся breach) — informational
- BUDGET rss 1418.1 MiB runtime-порядковый прогон (офлайн-гейт)

**Формулировка вердикта (рулинг родителя, перезаписана по runtime-числам):**
q4f16 паритетен в рабочей точке арбитр-пайплайна (τ ∈ [0.22, 0.80) gray-zone,
SPEC §2; lib.rs:44 TODO GrayZone{lo:0.22, hi:0.80}) — на обеих рабочих τ Δ=−1.05
в пользу кванта, на 0.5 Δ=0.00; единственный устойчивый breach — class-gate
person_name выше τ=0.5 (+1.79/+5.36). Тикет на amendment quant-policy §3.2/§17
(гейт по рабочей τ, informational выше) жив ПО этому breach, а не по бывшему
overall +1.75; порядок блока схем — замероконтракт, см. issue #53.

**C. Recall каскада-2 (runtime lockR-fp16 + Decide-q4f16) на golden-v1.1, τ=0.25
(перепрогон после off-by-one фикса):**

```
RECALL|dataset|golden-v1.1|rows|150|thr|0.25
RECALL|per_class|person_name|n|56|lockr|100.00|decide|96.43
RECALL|per_class|inn|n|36|lockr|58.33|decide|100.00
RECALL|per_class|snils|n|29|lockr|58.62|decide|37.93
RECALL|per_class|card_pan|n|32|lockr|84.38|decide|100.00
RECALL|per_class|phone|n|36|lockr|100.00|decide|100.00
RECALL|per_class|email|n|40|lockr|100.00|decide|100.00
RECALL|per_class|address|n|40|lockr|100.00|decide|100.00
RECALL|per_class|passport|n|16|lockr|62.50|decide|100.00
RECALL|overall|lockr_fp16|86.67|wilson95_lower|82.23|k|247|n|285
RECALL|overall|decide_q4f16|92.98|wilson95_lower|89.41|k|265|n|285
```

Метод lockR-части: span-level, decode-контракт харнеса (см. токенизатор-блок
ниже). Парити Rust↔python-оракул после фикса: per-класс побайтово во всё,
кроме card_pan (84.38 vs fp32-оракул 81.25 = +1 tp: один CREDIT_CARD-спан на
PS-хвосте `##`, трим-контракт `id_to_token` vs python-`decode` расходится ровно
на нём — известный, задокументированный кейс); overall 247 vs 246 tp. Smoke
6 рядов post-fix: lockR 87.50 (k=14/16; inn 50.00, passport 0.00 — малые
знаменатели, informational), decide 100.00 (k=16/16) — старый «16/16
побайтовый» smoke был артефактом pre-fix смещения, отозван. Детерминизм: прогон
2× идентичные строки **при зафиксированном `--threads`**; первички — `--threads 8`
(дефолт харнеса 4 даёт decide 93.33/266 — ORT intra-op флипы в p-банде, lockR
инертен).

Метод decide-части: row-level union (decide_counts), блок схем 8 вопросов в
рантайм-порядке (issue #53), sanitize_state; перед прогоном `№` → пробел
(фактический код харнеса `recall_golden.rs:431-443`; прежняя фраза «raw text,
№ НЕ заменён» была ложью про собственный харнес — нит ревью PR#49; демоном №
не заменяется, на метрику не влияет: сырой текст в рантайм-порядке = те же
266/37.93 побайтово, промер ревьюера); гейт layout [P],[L] sizes=[2×8] не
сработал ни разу (0 layout_miss); hit = p ≥ τ включительно (контракт arbitrate). Decide overall
92.98 > lockR 86.67 (row-level union ловит классы без span-попадания lockR:
inn 100 vs 58.33); snils = известная слабость обеих (37.93/58.62) — FN
добирается каскадом-1 (чексуммы валидатора §4, issue #26 хвост).
`GOLDEN|verdict` печатается из фактических чисел: при Wilson-lower 89.41 < 98 —
`known-below-98-wilson;gate=#14-deferred-to-cascade-union` (гейт #14 — каскад
lockR ∨ чексуммы, не один Decide; SPEC §5 п.7).

> **Union каскада 0∨1∨2 на полном знаменателе снят 21.10 и живёт в
> `docs/golden-report.md`** (`just union-recall`, харнес `tools/metrics/union_recall.py`):
> там добавлены валидаторные классы (знаменатель 358, а не 285), каскад 0 меряется
> продуктовым демоном, есть Wilson CI per-class, сетка τ, отрицательный split и
> вердикт гейта #14B. Числа раздела C (τ=0.25: lockR fp16 86.67 / Decide q4f16 92.98
> при n=285) остаются базлайном для сверки; **знаменатели несравнимы** (285 vs 358) —
> прямое «выросло/упало» между этими таблицами не имеет смысла. Метод (включая
> оговорку про row-level кредит Decide и расхождение оракулов overlap/exact)
> владелится golden-report'ом; раздел C он не меняет.

Токенизатор-контракт Rust↔python (корневые находки 4b-3C + пост-ревью
перезамер, всё в комментариях `recall_golden.rs`): (1) `tokenizers` encode(true)
ПРИМЕНЯЕТ пост-процессор в обеих реализациях → ids/offsets 1-в-1 со спец-слотами
(0,0) (промер 75/75 g0001; ранний тезис «не применяет» опровергнут); (2)
Rust-оффсеты = БАЙТОВАЯ шкала (decode-постпроцессинг WordPiece переписывает
char→utf8: g0001 'Ушакова' char (56,63) = rust (87,101) = python-byte) ⇒
харнесная `len(text[:c].encode())` = прямой читок, char2byte поверх = двойная
конверсия; (3) `decode([CLS]) = ''` (не '[CLS]') ⇒ special-фильтр харнеса ЛОЖЕН
на спецах — O красит argmax модели (O@1.0), id-множество спец-id = эквивалент;
(4) `decode([PS]) = '##вич'` python, Rust decode ОДИНОЧНОГО id маркер ЧИСТИТ
('вич') ⇒ PS-трим по `id_to_token` (vocab) = python-эквивалент; (5) `i0 = t0`
без сдвига: om 1-в-1 с ids, `om[t0]` = старт гольд-окна (g0001: om[17]=
'Ушакова'→87=gold start_byte; сдвиг −1 = отозванная ошибка обеих первичек,
ревью PR#49); (6) `lockr_bio_group` возвращает ГОЛЫЙ класс — двойной strip
префикса обнулял карту классов (первая 0.00).

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

## 9. Release RSS (шаг 9, релизный контур, SPEC §10 п.9)

Замеры живые (21.10), метод печатается в каждой строке вывода
`scripts/measure-rss.sh`: контур каскада-0 = `ps -o rss` (KB→MiB) плюс macOS
`footprint phys_footprint` («Память» Activity Monitor); контур полного каскада
= in-process `task_info(TASK_VM_INFO).internal` из C-острова
`crates/guard-onnx/spike/rss_mach.c` (Linux-ветка — `/proc/self/status` VmRSS).

Хост: macOS arm64, rustc 1.99.1, профиль `release` (`lto="fat"`,
`codegen-units=1`, `panic="unwind"`, `strip="symbols"` — `[profile.release]`
в Cargo.toml). Замер при `FASAD_THREADS=2`, `CARGO_BUILD_JOBS=2` (рюлинг
оператора 21.10 «не грузить CPU ноута», прогоны по одному за раз). Настоящий
рычаг потоков демона — `FASAD_THREADS` (`crates/guard-daemon/src/config.rs:76`,
дефолт 8; граница монтажа — п.4: на `cascade-0-only` инертен, с #87 жив на пути
каскадов 1–2); харнеса — флаг `--threads` (`crates/guard-onnx/examples/spike.rs:158`
`unwrap_or(4)`). `OMP_NUM_THREADS` в методику НЕ входит: он инертен, вендорный
`libonnxruntime` osx-arm64 собран без OpenMP и переменную не читает (первичка
правки к рюлингу — `otool`/`strings` по dylib, ревью #73). Точки, инструменты
и семантика вердикта не менялись относительно §5.6.

1. **Каскад-0 (публикуемый бинарь `target/release/fasad`, HTTP-прогон).**
   `just measure-rss` поднимает демон на `FASAD_PORT=0`, прогревает 3×
   `/v1/analyze` и 1× `/v1/anonymize` (контракт `vault.rs::AnonymizeRequest =
   {text, spans}`: спаны берутся из ответа analyze, голый `{"text":…}` = 400 —
   промер живым POST 21.10) и снимает две точки. Сырые строки прогона при
   `FASAD_THREADS=2` (INFO: `env=FASAD_THREADS=2`):
   `RSS|cascade0|idle|2.7|ps -o rss (KB->MiB, resident)`,
   `RSS|cascade0|idle|1.4|footprint phys_footprint (macOS, «Память» Activity Monitor)`,
   `RSS|cascade0|after_warm|3.4|ps -o rss (KB->MiB, resident)`,
   `RSS|cascade0|after_warm|1.6|footprint phys_footprint (macOS, …)`,
   вердикт `BUDGET|cascade0|ok|peak_mib=3.4|budget_mib=1843.2`.
   Числа не перепечатаны от руки: их печатает `just measure-rss --cascade0
   --doc-rows` — флаг генерирует markdown-блок и `BUDGET`-строку из артефакта
   того же прогона (рюлинг kernel 21.10: «число, вписанное в документ от руки,
   — claim; цифры документа генерируются из артефакта»). Повторный прогон тем же
   флагом 20.10 воспроизвёл блок дословно: idle 2.7/1.4, after_warm 3.4/1.6,
   `peak_mib=3.4`.
   Прогон на демоне с дефолтом `FASAD_THREADS=8` — три запуска 21.10 тем же
   флагом, строки печатает скрипт (`INFO|cascade0|pid=…|env=FASAD_THREADS=8`):
   `peak_mib=3.3`, `peak_mib=3.3`, `peak_mib=3.4` при idle 2.7/1.4 все три раза.
   Прежнее число `peak_mib=2.8` (и idle 2.2) было ОДИНОЧНЫМ неавторитетным
   прогоном и не воспроизводится: ревьюер #76 получил 3.4, мои повторы —
   3.3/3.3/3.4 (ревью #76, F4).
   Разброс `ps` против `footprint` ≈ 1.2 MiB — это разные метрики (resident
   против phys_footprint), обе строки остаются в выводе, метод не выбирается
   в пользу одной. Пик = 0.15 % бюджета SPEC §1 (1843.2 MiB): контур демона
   бюджет не задействует.
2. **Полный каскад 1–2 (харнес spike, релизный профиль, официальный dylib ORT
   1.31.0, `--arb-budget --arb --lockr`; веса из кэша `~/.cache/fasad-models`
   по models/manifest.md):**
   `RSS|full|peak_both_models|976.3|spike task_info …` (метод в самой строке),
   вердикт
   `BUDGET|full|ok|peak_mib=976.3|budget_mib=1843.2` (53 % бюджета) при
   `--threads 4` (дефолт харнеса), wall-clock 2m42s. Прогон `--threads 2`
   (рюлинг 21.10): `RSS|full|peak_both_models|889.1`,
   `BUDGET|full|ok|peak_mib=889.1<1843.2` (48 % бюджета), wall-clock 10m20s.
   Для бюджета держим КОНСЕРВАТИВНУЮ точку 976.3 = max из двух (та же
   семантика, что в §5.6 п.5).
3. **Оговорка профиля (§5 п.1, §5.6 п.5) по этой точке снята.** Прежний
   бюджет-гейт был закрыт dev-числом `peak_max = 1434.6 MiB` (3 прогона 19.10,
   debug-профиль — заголовок §2 «dev-профиль», §5 п.1 про SIGSEGV release на
   статике pyke). Релизный профиль на официальном dylib = 976.3 MiB, на
   458.3 MiB меньше (арифметика над двумя промеренными числами):
   dev-консервативность подтверждена в безопасную сторону. Причина разницы
   (lto/codegen-units против раздувания обобщений ort/tokenizers в debug)
   не промерена и не заявляется.
4. **Потоки: на каскаде 1–2 влияют, на каскаде-0 не влияют (промер 21.10,
   N=4).** Полный каскад `--threads 4` = 976.3 MiB против `--threads 2` =
   889.1 MiB ⇒ −87.2 MiB (−9 % пика; арифметика над промеренными числами, оба
   прогона полные: wall-clock 2m42s и 10m20s). Механизм (арена/пул на поток в
   ort/tokenizers) не промерен. Каскад-0: прогоны `just measure-rss` дают 3.3/3.3/3.4 MiB
   (`FASAD_THREADS=8`), 3.4 MiB (`=2`, повтор 21.10 на head `7862d74`), idle
   2.7 против after_warm 3.4. Это ПОВТОРЫ ОДНОЙ конфигурации, а не сравнение
   двух: на стадии `cascade-0-only` рычаг `FASAD_THREADS` инертен —
   `config.rs:423` разбирает его в `cfg.threads`, единственным потребителем
   поля в демоне оставался тест `config.rs:638`, а в сессию ORT потоки идут из
   `guard-onnx::arbitrate` (`intra_threads`, arbitrate.rs:261-276), куда демон
   на этой стадии не доходит (первичка grep по `crates/` на `bfb0014`, 21.10;
   рюлинг AGENTS §3 п.3; её номера `:403`/`:610` сняты с той базы, на этом
   дереве то же самое лежит на `:423`/`:638` — переснято grep'ом, класс #93).
   На смонтированном пути каскадов 1–2 (#87) рычаг живой: `cascades.rs:558`
   берёт `cfg.threads` в `Spec`, и он уходит в `LockrExtractor::load(…,
   threads)` и `DecideArbiter::load(…, threads)` (`cascades.rs:675,677`) — это
   меряет §10, не этот раздел. Значит «8 против 2 = 0.1 MiB» не аргумент:
   конфигурация сравнивалась сама с собой. Разброс 3.0..3.5 (промер
   ревьюера) и 2.7..3.4 по фазам (мой) = шум повторов, и потолком шума он не
   подаётся (ревью #76, D5). Вывод «для контура демона потоки не фактор»
   держится на устройстве контура (на каскаде-0 нет сессий ORT; §5.6 п.5 про
   ленивость mapper’а), а не на этой паре чисел; сама пара становится
   осмысленной только с монтажом каскадов (#87). Прежняя пара «3.4 против 2.8»
   (п.1) строилась на одиночном прогоне и снята (ревью #76, F4): «−9 %» из неё было бы читательским обобщением с
   полного каскада на каскад-0. Следствие: число потоков — часть методики, оно
   печатается в INFO-строке; бюджет-вердикт считается по max из прогонов.
5. **Windows-контур не промерен.** `scripts/measure-rss.sh` на `MINGW*`/`MSYS*`
   падает с exit 2 и явной причиной (реализованы Darwin/Linux). PowerShell-метод
   (`Get-Process` `WorkingSet64`/`PrivateMemorySize64`) не реализован и не
   промерен; в CI шаг RAM-гейта на windows-2022 выключен условием
   `if: matrix.os != 'windows-2022'`. Числа для Windows = «не промерено»
   (docs/release.md §RAM).
6. **CI-coverage ветки.** Job `dist` матрицы прогоняет `just measure-rss
   --skip-build` на ubuntu-24.04 и macos-14 (Linux-ветка = `/proc/self/status`
   VmRSS, тот же контракт `RSS|…`-строк): это закрывает §6 («второй источник
   метрик с CI-матрицы, когда появится job») для каскада-0. Полный каскад в CI
   не гоняется и дальше (веса в CI не качаются, §6), его промеры — рукаместо.

## 10. Release RSS демона с примонтированными каскадами 1–2 (шаг 9A/9B, issue #14A)

Соседняя §9 (#76) — релизный контур на каскаде 0; эта секция при rebase на неё
передвинута с §9 на §10, содержимое не менялось, кроме пункта 8 (стык первичек
по `FASAD_THREADS`) и переименования метрики стационара (§10.2).

1. Конфигурация: `cargo build --release -p guard-daemon --features
   ort-inference` (продуктовый путь — dynamic-link официальный dylib 1.31.0,
   §8), `FASAD_THREADS=2` (рюлинг 21.10: ноут оператора; рычаг потоков
   инференса, `OMP_NUM_THREADS` на нашей сборке инертен),
   `FASAD_MODEL_DIR=~/.cache/fasad-models`, macOS arm64, один демон, один
   прогон за раз.
2. Метод: `scripts/measure-daemon-rss.sh` — опрос `ps -o rss=` с шагом 100 мс
   от `exec` демона до остановки (пик загрузки весов попадает в выборку),
   нагрузка N запросов `/v1/analyze` на текст со всеми классами (ФИО, паспорт,
   адрес, телефон, почта, ИНН, СНИЛС = каскады 0, 1 и 2 в одном запросе).
   Метрики: `rss_peak_mib` = максимум по всем сэмглам; стационар =
   `rss_steady_median_mib` = МЕДИАНА хвостовых 20 % сэмплов (минимум 5), то
   есть состояние после прогона, а не максимум per-request. Прежняя метрика
   называлась `rss_after_reqs_mib` и была максимумом снимков по запросам —
   пиком с именем «steady-state» (ревью #87); переименована, прогон переснят.
   `ps`-RSS = резидентные KiB вместе с общими страницами фреймворка, то есть
   консервативная верхняя оценка (то же семейство метрик, что `/proc/self/status`
   VmRSS на Linux). Сырые METRIC-строки прогонов — артефакт `/tmp/rss_9b_final.txt`.
3. Числа (сгенерированы из артефакта прогона на дереве `dbce8ca`, не набраны):
   - `METRIC|samples|72|rss_peak_mib|853.9` + `steady_samples|14|rss_steady_median_mib|398.8` (N=5);
   - `METRIC|samples|161|rss_peak_mib|936.2` + `steady_samples|32|rss_steady_median_mib|321.4` (N=20);
   - `METRIC|samples|338|rss_peak_mib|730.1` + `steady_samples|67|rss_steady_median_mib|366.2` (N=50).
   Вердикт гейта во всех трёх: `METRIC|budget|1843.2|verdict|ok`, и заголовки
   того же прогона: `stage_header|cascade-0+models|cascade2_header|ok`.
4. Против гейта SPEC §10 п.9 (≤1.8 GiB = 1843.2 MiB): консервативный пик
   936.2 MiB (максимум из трёх прогонов) = 50.8 % бюджета, запас 907.0 MiB.
   Стационар (медиана хвоста) = 321.4–398.8 MiB. Пик НЕ растёт с N (853.9 →
   936.2 → 730.1 при N=5/20/50), то есть это пик загрузки весов, а не
   накопление: прироста, который можно было бы читать утечкой, на этих трёх
   прогонах нет. Вывод прежней редакции («рост пика затухает: +369 за 15
   запросов, +48.5 за 30») снят — он построен на метрике, которая была пиком
   per-request, и на шуме шага опроса 100 мс.
5. Числа §5 п.5 (харнес: 1330.9/1434.6/1434.4 MiB) с этими НЕ сравнимы и не
   пересчитываются: там `task_info` private-RSS + `vmmap footprint` на
   threads=4 в прогоне харнеса, здесь `ps`-RSS демона на threads=2. Единый
   метод съёма для пары «харнес/демон» — задача релизного контура (#76),
   здесь зафиксирован собственный метод промера вместе с цифрой.
6. Проводной контроль fail-closed старта тем же бинарём:
   `FASAD_MODEL_DIR=/tmp/fasad-empty-models` (пустой каталог) →
   `exit=2`, stderr `fasad: старт невозможен: модельный каскад не загружен: нет
   файла /tmp/fasad-empty-models/lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx
   (каталог весов …, раскладка — scripts/fetch-models.sh)`, сокет не поднят.
   Молчаливого `cascade-0-only` на названном `model_dir` нет ни на одной ветке.
7. Дефект доставки, найденный этим промером: release-бинарь демона умирал до
   `main` (`Abort trap: 6: Library not loaded: @rpath/libonnxruntime.1.dylib …
   Reason: no LC_RPATH's found`). Причина: rpath печатает `build.rs` крейта
   `guard-onnx` через `cargo:rustc-link-arg-examples`, а link-args не
   распространяются на цели чужих пакетов; dev-тесты яму не видят, потому что в
   dev `ort` унифицируется в `load-dynamic` и грузит dylib через `dlopen`,
   которому `DYLD_LIBRARY_PATH` достаточно. Лечится
   `crates/guard-daemon/build.rs` (`cargo:rustc-link-arg-bins=-Wl,-rpath,
   $ORT_LIB_PATH`, macOS/Linux); Windows-ветка — `copy-dylibs` (#76).
8. Стык первичек по `FASAD_THREADS` (оба факта верны, граница — монтаж). На
   стадии `cascade-0-only` рычаг инертен: `config.rs:423` разбирает его в
   `cfg.threads` (дефолт 8 = `DEFAULT_THREADS`, `config.rs:76`), единственным
   потребителем поля в демоне оставался тест `config.rs:638`, а потоки в сессию
   ORT идут из `guard-onnx::arbitrate` (`intra_threads`, параметр
   `arbitrate.rs:261`, `.with_intra_threads(…)` `arbitrate.rs:276`), куда демон
   на этой стадии не доходит (первичка #76 — grep по `crates/` на `bfb0014`; её
   номера `:67`/`:403`/`:610` сняты с той базы, на этом дереве то же самое лежит
   на `:76`/`:423`/`:638`, переснято grep'ом). На смонтированном пути (этот PR)
   рычаг живой: `cascades.rs:558` берёт `cfg.threads` в `Spec`, и он уходит в
   `LockrExtractor::load(…, threads)` и `DecideArbiter::load(…, threads)`
   (`cascades.rs:675,677`), то есть в обе модельные legs. Все числа этого раздела сняты при `FASAD_THREADS=2`;
   сравнения «2 против 8» по смонтированному пути в разделе нет — оно не мерялось.

### 10.8 Покрытие продукта на полном golden (тот же бинарь, тот же метод)

Мера харнеса (§5.1 `docs/golden-report.md`) считает стадии по отдельности и на
всём датасете; продукту доступен только выход конвейера — набор спанов, который
уйдёт в маскирование. Прогон `product_coverage_on_the_whole_golden`
(`tests/cascade_parity.rs`, под `#[ignore]`: 98.4 с на threads=1, нужны веса):
взяты строки ≤200 символов — 185 из 204 (окно lockR = 256 токенов,
дальше продукт обязан отказать, #84). Тексты подаются как есть, без санитизации.

| класс | gold | overlap (мера `union`) | exact (байт-в-байт, гейт #77) |
|---|---|---|---|
| `person_name` | 42 | 42 (100.0 %) | 0 (0.0 %) |
| `phone` | 34 | 34 (100.0 %) | 26 (76.5 %) |
| `email` | 32 | 32 (100.0 %) | 0 (0.0 %) |
| `card_pan` | 31 | 27 (87.1 %) | 26 (83.9 %) |
| `address` | 29 | 29 (100.0 %) | 0 (0.0 %) |
| `iban` | 26 | 23 (88.5 %) | 23 (88.5 %) |
| `inn` | 26 | 26 (100.0 %) | 21 (80.8 %) |
| `snils` | 25 | 23 (92.0 %) | 23 (92.0 %) |
| `ogrn` | 24 | 21 (87.5 %) | 21 (87.5 %) |
| `ogrnip` | 23 | 21 (91.3 %) | 21 (91.3 %) |
| `passport` | 15 | 10 (66.7 %) | 0 (0.0 %) |
| `bik` | 2 | 0 (0.0 %) | 0 (0.0 %) |
| `bank_account` | 1 | 0 (0.0 %) | 0 (0.0 %) |
| **итого** | **310** | **288 (92.9 %)** | **161 (51.9 %)** |

1. Итог по мере пересечения (логика `union` из #80): 288 из 310 =
   92.9 %.
2. Итог по гейт-мере байт-в-байт (#77): 161 из 310 =
   51.9 %.
3. Разрыв между ними и есть #41: `person_name`/`email`/`address` накрыты целыми
   (100 % overlap) и при этом дают 0 exact — границы lockR не совпадают с
   разметкой байт в байт, а координат у Decide нет.
4. Лишних спанов (без пересечения с золотом): 51 при 534
   выпущенных — это цена порога 0.20 (FN фатален, FP дёшев, SPEC §3).
5. Числа сгенерированы из артефакта прогона (`/tmp/cover_product_9b.txt`, дерево
   `dbce8ca` после мержа #86, 98.4 с на threads=1, `FASAD_REQUIRE_MODELS=1`),
   не набраны.
6. Сдвиг против предыдущего прогона (261/117 = 84.2 %/37.7 %) — работа каскада 0
   из #86 (терпимость к разделителям + полная таблица IBAN): `iban` 5 → 23 exact,
   `snils` 9 → 23, `card_pan` 14 → 26. Модельные классы не сдвинулись ни на
   спан: `person_name` 42, `email` 32, `address` 29 overlap, 0 exact — то есть
   #86 модельный путь действительно не тронул, и приписывать эти проценты
   монтажу нельзя.
7. Строка `COVER|rows|185|of|204` — это окно lockR (256 токенов), а не фильтр по
   качеству: 19 строк продукту сегодня недоступны вообще (502 `Truncated`, #84).

### 10.9 Функциональный обрыв, найденный этим прогоном: «№»

Первый же прогон упал на строке `g0133` («Договор оказания услуг № 782/24 …») с
`502 cascade_unavailable: сбой инференса: decide: констрэкт разметки: 1 токенов
[UNK] в живом входе`. Хронология факта (промер `tokenizer.json` обоих весов в
этом раунде, правит неточность 4b-3C): у каскада 1 `№` ЕСТЬ в словаре (Spiber rubert, WordPiece 120138: `№` = id 248,
сплайс не ломается); у каскада 2 (Unigram 128000) ни один токен не содержит
`№`, а `[UNK]` = id 3 = ровно тот `UNK_ID`, который ветоит `check_splice`
(`arbitrate.rs:48,579`); запись 4b-3C «`№` = [507, UNK]» в
`recall_golden.rs:320` приписана Spiber, а 507 в словаре Decide = `▁` (в rubert
507 = `##́`) — то есть наблюдение сделано на Decide-токенизаторе. Харнес
подменяет `№` пробелом перед прогоном Decide (row-level мере координаты не
нужны, `unk_rows` в счётчике прогона), продукт подменить текст не может —
координаты спанов это байты оригинала. 16 строк из 185 (20 из 204, промер
`data/golden/golden-v1.jsonl`) содержат `№`, а пропуск зафиксирован один:
каскад 2 вызывается только в серой зоне.

Политика после правки (#87): `ArbError::Layout` = деградация каскада 2 (вердиктов
нет, серый спан остаётся на `p1 ≥ 0.22 > τ = 0.20` ⇒ спан не теряется, пропадает
только способность арбитра двигать оценку), остальные ветки `ArbError` = 502.
Отказывать такому входу 502 = не обслуживать весь класс договоров; это не
fail-closed, а отказ от работы. Полный прогон после правки: 185 строк, 1
пропуск Decide (та самая `g0133`), rc=0. Настоящее лечение — #88 (заведено по итогам этого прогона).
