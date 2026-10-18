#!/usr/bin/env bash
# Снапшот конкурентов PII-guard: у микро-обёрток архивный след нулевой (урок inconify,
# docs/competitors/inconify.md). Раз в неделю гонять из любой сессии; снапшот локально
# всегда, Wayback по errors.
set -euo pipefail
UA="dsh-audit/1.0"
DIR="$(cd "$(dirname "$0")/.." && pwd)/docs/competitors/snapshots"
mkdir -p "$DIR"
STAMP="$(date -u +%Y-%m-%d)"
SOURCES=(
  "https://neuraldeep.ru/llms-full.txt"
  "https://redactum.ru"
  "https://docnull.ru"
  "https://cleardoc.ru"
  "https://aisearch.ru/obezlichivanie"
)
for u in "${SOURCES[@]}"; do
  name=$(echo "$u" | sed -E 's#https?://##; s#[/.]#_#g')
  if curl -sfL -A "$UA" --max-time 30 "$u" -o "$DIR/${name}.${STAMP}.html"; then
    echo "OK $u"
    # публичный снапшот только для живых 200
    curl -sf -A "$UA" --max-time 20 "https://web.archive.org/save/$u" >/dev/null 2>&1 || echo "wayback-save failed (не критично): $u"
  else
    echo "FAIL $u (пропуск, не снапшотим смерть)"
  fi
done
for f in "$DIR"/*; do [ -f "$f" ] && printf "%s\n" "${f##*/}"; done
