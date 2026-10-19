# Model audit — шаг 2 spike (issue #6)

Прогон: 2026-10-19, macOS (arm64), rustc 1.97.1, ort 2.0.0-rc.14 (download-binaries,
статик libonnxruntime.a, CPU EP), spike = `crates/guard-onnx/examples/spike.rs`.
Профиль: **debug** (release-прогон сегфолтится — дефект харнесса, § Дефекты).
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

Сессия арбитра (graph + external data 523 МБ) поднялась с RSS 7.5 → **269.0 MiB**.
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
   `marker_positions` без構構構構構 semantics SPAN-разметки GLiNER2.5. Это НЕ
   дефект модели: контракт маркеров строит декодер шага 4 (gline-rs как
   референс). Метки load-time (RSS сессии) получены до инференса — §3 валиден.
4. RSS до lockR-сессии и латентность prefill не сняты (см. 3) — добирается в
   шаге 4 промером на живом декодере.

## 6. CI-контракт

CI spike НЕ гоняет (фича `ort-inference` default-off, example no-op,
тест-прокси `#[ignore]`); веса в CI не качаются. Прогоны — рукаместо
(macOS/Linux). Linux-ветка spike читает `/proc/self/status` VmRSS (safe, без
C-острова) — второй источник метрик с CI-матрицы, когда появится job.
