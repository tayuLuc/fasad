#!/usr/bin/env bash
# fp32-веса parity-гейта: скачивание по tools/verify/fp32-manifest.tsv
# (роль, repo@revision, файл, sha256) в кеш $FASAD_MODELS_DIR (по умолчанию
# ~/.cache/fasad-models). curl-паттерн scripts/fetch-models.sh (--http1.1:
# HF-CDN рвёт HTTP/2-стримы, промер 19.10). sha256 ПЕРЕСЧИТЫВАЕТСЯ до
# использования; несоответствие = exit 1 (Fail-Closed). Вне дерева сборки
# (AGENTS п.6): скрипт tools/verify/, продуктом не запускается.
set -euo pipefail
HOST="${FASAD_HF_HOST:-https://huggingface.co}"
CACHE="${FASAD_MODELS_DIR:-$HOME/.cache/fasad-models}"
MANIFEST="$(dirname "$0")/fp32-manifest.tsv"
[ -f "$MANIFEST" ] || { echo "FAIL: манифест $MANIFEST не найден"; exit 1; }

while IFS=$'\t' read -r role repo rev file sha size source; do
    case "$role" in ''|\#*) continue;; esac
    [ "$source" = "hf" ] || continue
    dest="$CACHE/$repo/$file"
    mkdir -p "$(dirname "$dest")"
    if [ -f "$dest" ]; then
        got=$(shasum -a 256 "$dest" | cut -d' ' -f1)
    else
        echo "fetch $role: $repo@${rev:0:8}/$file ($size B)"
        curl --fail --location --http1.1 --silent --show-error \
            --retry 3 --retry-delay 2 \
            "$HOST/$repo/resolve/$rev/$file" --output "$dest.part"
        mv "$dest.part" "$dest"
        got=$(shasum -a 256 "$dest" | cut -d' ' -f1)
    fi
    if [ "$got" != "$sha" ]; then
        echo "FAIL sha256 $role:ожидается $sha, промер $got"
        rm -f "$dest"
        exit 1
    fi
    sz=$(wc -c < "$dest" | tr -d ' ')
    if [ "$sz" != "$size" ]; then
        echo "FAIL size $role: манифест $size, файл $sz"; exit 1
    fi
    echo "OK $role sha256+size подтверждены"
done < "$MANIFEST"
