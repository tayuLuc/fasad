# Model manifest (fasad)

| роль | HF repo | revision | файл | sha256 | размер | статус |
|---|---|---|---|---|---|---|
| extractor-1b RU (готовый ONNX fp16) | lockR/rubert-base-pii-ner-onnx | ea7610b22808c509c0c8b7c7b0f6639c19684d08 | model.optimized.fp16.onnx | 039aba6be0c64f50f37c64ddc6c6d4e2fd91cbdcf5c9291056ec6bc96c70a501 | 355 541 615 B | verified 19.10 |
| arbitrator gray-zone (q4f16) | onnx-community/GLiNER2.5-Decide-ONNX | 18271032588167fe9a3fbb8c5a4900b1231f8119 | model_q4f16.onnx + .onnx_data | 93f3e0d4ed8bbd4858840f8a2e66028a70e86a482e1ff9822d2ac726381684f6 / df2b05dc97ff875e0d2b51ec21de0049b7b3e7feddaa5224d318dc79e66210e8 | 341 889 + 523 127 808 B (промерен; 1 945 314 448 было fp32, опровергнуто) | verified 19.10 |
| backup extractor (fp16 триплет) | DanKau/gliner2.5-multi-v1-onnx | — | onnx/*.onnx | TBD | encoder 1 111 MB | spike |
| backup zero-shot int8 | onnx-community/gliner_multi-v2.1 | — | model_int8.onnx | TBD | 349 120 924 B | spike |

revision = commit-шейма HF на момент скачивания (промер GET /api/models/<id> → sha).
Размеры — из промера 18.10 (`docs/dep-verify-models.md`, `docs/hf-model-survey.md`);
sha256 пересчитываются локально после скачивания, внедряются в этот файл.

## Финализация 19.10 (sha256 пересчитаны shasum -a 256 по кэшу, revision — GET api/models)

| file | revision | sha256 | bytes |
|---|---|---|---|
| lockR model.optimized.fp16.onnx | ea7610b2 | 039aba6be0c64f50f37c64ddc6c6d4e2fd91cbdcf5c9291056ec6bc96c70a501 | 355541615 |
| Decide model_q4f16.onnx | 18271032 | 93f3e0d4ed8bbd4858840f8a2e66028a70e86a482e1ff9822d2ac726381684f6 | 341889 |
| Decide model_q4f16.onnx_data | 18271032 | df2b05dc97ff875e0d2b51ec21de0049b7b3e7feddaa5224d318dc79e66210e8 | 523127808 |
| lockR tokenizer.json | ea7610b2 | f61eee9d0dc18f14c195321a37eadf9e5aeb3a323bc278dec689adeb89dec1b9 | 3714701 |
| Decide tokenizer.json | 18271032 | 3ad87d9ffe669147063e70850927dd2da90249e2acc5c8527f1eb65df467bcc8 | 8333952 |
