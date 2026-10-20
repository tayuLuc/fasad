# tools/verify — сверочные прогоны ПАРИТЕТА (вне дерева сборки)

Изолирован по AGENTS §Порядок п.6 (Python-рантайм не проникает в продукт) и
quant-policy §3/§17: fp32-vs-квант паритет — offline-гейт приёмки кванта,
НЕ рантайм-путь. Запуск (промер env parity_golden.py:31-35, `ort` — pip-имени нет,
пакет называется `onnxruntime`):
`uvx --python ~/.local/bin/python3.13 --with numpy --with onnxruntime \
 --with tokenizers --with psutil python tools/verify/parity_golden.py --model lockr|decide`.
Результат — строки `METRIC|parity|…` (формат 4b-3B) + `BUDGET|mode=offline-gate`.
Манифест-контракт: веса скачиваются `fetch_manifest_weights.sh` (curl из
scripts/fetch-models.sh — тот же --http1.1 паттерн), sha256 ПЕРЕСЧИТЫВАЕТСЯ
до использования (Fail-Closed), URL+revision пинуются по models/manifest.tsv.
