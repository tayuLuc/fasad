#!/usr/bin/env bash
# scripts/fetch-models.sh — скачивание ONNX-весов по манифесту (SPEC §10 шаг 2, issue #6).
#
# Контракт:
#   - источник истины — models/manifest.tsv (таб-сепаратор; человекочитаемая таблица
#     и вердикты — models/manifest.md);
#   - скачиваем ВСЕГДА по явному commit-шейа, а не по имени ветки: если в манифесте
#     `@auto`, сначала GET /api/models/<repo> (поле sha) и фиксируем полученный SHA;
#   - после загрузки пересчитываем sha256 и сверяем с манифестом. Несовпадение,
#     обрезанный хвост, HTTP-ошибка = exit 1 (Fail-Closed, AGENTS.md § Инженерные
#     инварианты: никогда fail-open);
#   - если sha256 в манифесте = `TBD`, файл считается, записывается в кеш И в
#     манифест (первое подтверждение: revision + sha + размер);
#   - кеш: $FASAD_MODEL_CACHE (по умолчанию ~/.cache/fasad-models/<repo>/<file>),
#     повторный запуск — без сети, только пересчёт чексуммы.
#
# Python в проекте запрещён (AGENTS.md п.6): разбор JSON здесь — grep/sed по HF API.
# Никакого рантайм-кода: это build-time расходник шага 2.

set -euo pipefail

UA="fasad-fetch/1.0"
HF_HOST="${FASAD_HF_HOST:-https://huggingface.co}"
CACHE_DIR="${FASAD_MODEL_CACHE:-$HOME/.cache/fasad-models}"
MANIFEST="${FASAD_MANIFEST:-}"
REWRITE_MANIFEST=1
DRY_RUN=0

usage() {
    cat <<'EOF'
использование: scripts/fetch-models.sh [опции]

  --manifest PATH   путь к манифесту (default: <repo>/models/manifest.tsv)
  --cache DIR       каталог кеша (default: $FASAD_MODEL_CACHE или ~/.cache/fasad-models)
  --no-rewrite      не переписывать manifest при первом подтверждении sha256
  --list            показать план скачивания и выйти (без сети)
  -h, --help        эта справка

переменные окружения: FASAD_MODEL_CACHE, FASAD_MANIFEST, FASAD_HF_HOST
EOF
}

die() {
    printf 'fetch-models: ОШИБКА: %s\n' "$*" >&2
    exit 1
}

log() {
    printf 'fetch-models: %s\n' "$*"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --manifest)
            [ "$#" -ge 2 ] || die "--manifest требует аргумент"
            MANIFEST="$2"
            shift 2
            ;;
        --cache)
            [ "$#" -ge 2 ] || die "--cache требует аргумент"
            CACHE_DIR="$2"
            shift 2
            ;;
        --no-rewrite) REWRITE_MANIFEST=0; shift ;;
        --list)       DRY_RUN=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage >&2; die "неизвестный аргумент: $1" ;;
    esac
done

if [ -z "$MANIFEST" ]; then
    # Каллер мог запустить скрипт из любого cwd — манифест ищем рядом со скриптом.
    MANIFEST="$(dirname -- "$0")/../models/manifest.tsv"
fi
[ -f "$MANIFEST" ] || die "манифест не найден: $MANIFEST"
# Абсолютизируем путь (без `CDPATH= cd` — shellcheck читает это как присваивание).
manifest_dir=$(dirname -- "$MANIFEST")
manifest_name=$(basename -- "$MANIFEST")
manifest_abs=$(cd "$manifest_dir" && pwd -P)
MANIFEST="$manifest_abs/$manifest_name"

# --- утилиты ---------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

sha256_of() {
    # $1 = файл; печатает lower-hex sha256 одной строкой, без имени файла.
    local out
    if have sha256sum; then
        out=$(sha256sum "$1") || die "sha256sum не смог прочитать $1 (fail-closed)"
    elif have shasum; then
        out=$(shasum -a 256 "$1") || die "shasum не смог прочитать $1 (fail-closed)"
    else
        die "нет sha256sum / shasum — чексумма не проверяема, выходим fail-closed"
    fi
    printf '%s\n' "${out%% *}"
}

file_size() {
    # Портативно: BSD stat (macOS) / GNU stat (Linux CI); fail-closed на ошибке чтения.
    local out
    if out=$(stat -f%z "$1" 2>/dev/null); then
        printf '%s\n' "$out"
    elif out=$(stat -c%s "$1" 2>/dev/null); then
        printf '%s\n' "$out"
    else
        die "не удалось измерить размер $1 (ни BSD, ни GNU stat)"
    fi
}

http_get() {
    # $1 = url, $2 = файл назначения. -L обязателен: HF отдаёт 302 на xet-CDN.
    # --http1.1: HF-CDN обрывает длинные HTTP/2-стримы (промер 19.10: `curl (92)
    # HTTP/2 stream not closed cleanly: CANCEL` на 355 МБ). Флаг перенаследуется
    # на редирект-коннект, контракт для HTTPS сохраняется (--proto).
    # Пишем в .part, атомарный mv — только после успешного curl --fail.
    curl --fail --location --http1.1 --silent --show-error \
        --proto '=https' --tlsv1.2 \
        --user-agent "$UA" \
        --retry 3 --retry-delay 2 --retry-all-errors \
        --max-time "${FASAD_CURL_MAX_TIME:-3600}" \
        --connect-timeout 30 \
        --continue-at - \
        --output "$2" \
        "$1"
}

# Разбор JSON HF API без Python: в /api/models/<id> поля "sha" и "size" — единственные
# числовые/хеш-значения, которые нам нужны; берём все их вхождения и выбираем первые.
grep_json_field() {
    # $1 = файл, $2 = имя поля (sha | size | oid)
    sed -n "s/.*\"\{1\}$2\"\{1\}[[:space:]]*:[[:space:]]*\"\{1\}\([0-9a-fA-F]*\)\"\{1\}.*/\1/p" "$1"
}

grep_json_sizes() {
    sed -n "s/.*\"size\"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p" "$1"
}

resolve_revision() {
    # $1 = repo, $2 = revision (@auto | явный SHA). Печатает явный commit-шейа.
    # Детерминизм: GET api/models/<id> ДО resolve (AGENTS/issue: читать sha-поле).
    case "$2" in
        @auto)
            local api tmp sha
            api="$HF_HOST/api/models/$1"
            tmp="${CACHE_DIR}/.api-$(printf '%s' "$1" | tr '/' '_').json"
            mkdir -p "$(dirname -- "$tmp")"
            http_get "$api" "$tmp" || die "HF API недоступен: $api (fail-closed, не угадываем revision)"
            sha=$(grep_json_field "$tmp" sha | head -n 1)
            [ -n "$sha" ] || die "в ответе $api нет поля sha (fail-closed)"
            case "$sha" in
                *[!0-9a-f]*) die "revision '$sha' не commit-шейа (fail-closed)" ;;
            esac
            printf '%s\n' "$sha"
            ;;
        *)
            case "$2" in
                *[!0-9a-f]*) die "revision '$2' не commit-шейа (fail-closed; или @auto)" ;;
            esac
            printf '%s\n' "$2"
            ;;
    esac
}

rewrite_manifest_row() {
    # $1 = role, $2 = revision, $3 = sha256, $4 = size — первое подтверждение.
    local awk_out
    awk_out="${MANIFEST}.tmp.$$"
    awk -F '\t' -v OFS='\t' -v role="$1" -v rev="$2" -v sha="$3" -v size="$4" '
        $1 == role && $5 == "TBD" { $3 = rev; $5 = sha; $6 = size }
        { print }
    ' "$MANIFEST" > "$awk_out" || { rm -f "$awk_out"; die "не удалось переписать манифест"; }
    if ! cmp -s "$MANIFEST" "$awk_out"; then
        mv -f "$awk_out" "$MANIFEST"
        pending_rows=$((pending_rows + 1))
        log "манифест: роль $1 → rev=$2 sha=$(printf '%.12s' "$3")… size=$4"
    else
        rm -f "$awk_out"
    fi
}

stamp_manifest_footer() {
    # Датированная отметка подтверждения — в комментарии, чтобы разбор строк не ломался.
    local date_str
    date_str=$(date -u '+%Y-%m-%d %H:%M UTC')
    {
        printf '# подтверждено: %s — sha256 пересчитаны scripts/fetch-models.sh, кеш %s\n' \
            "$date_str" "$CACHE_DIR"
    } >> "$MANIFEST"
    log "манифест: отметка $date_str ($pending_rows строк)"
}

# --- основной цикл --------------------------------------------------------

mkdir -p "$CACHE_DIR"

processed=0
pending_rows=0

finish() {
    # Отметка подтверждения — ТОЛЬКО при чистом завершении (замечание ревью #9
    # re-review: die → trap не должен ставить штамп «подтверждено» поверх
    # проваленного прогона).
    local rc=$?
    if [ "$rc" -eq 0 ] && [ "$processed" -gt 0 ]; then
        pending_rows=$processed stamp_manifest_footer
    fi
}
trap finish EXIT

while IFS= read -r line || [ -n "$line" ]; do
    # пропускаем комментарии и пустые строки; CR режем (файл eol=lf, но defensively)
    line=${line%$'\r'}
    case "$line" in
        ''|'#'*) continue ;;
    esac

    role=$(printf '%s\n' "$line" | cut -f1)
    repo=$(printf '%s\n' "$line" | cut -f2)
    revision=$(printf '%s\n' "$line" | cut -f3)
    file=$(printf '%s\n' "$line" | cut -f4)
    want_sha=$(printf '%s\n' "$line" | cut -f5)
    want_size=$(printf '%s\n' "$line" | cut -f6)
    source=$(printf '%s\n' "$line" | cut -f7)

    [ "$source" = "skip" ] && continue
    [ "$source" = "hf" ] || die "$role: source='$source' (пока только hf; local/skip — TODO)"

    case "$want_sha" in
        TBD) : ;;
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
            [ "${#want_sha}" -eq 64 ] || die "$role: sha256 длины ${#want_sha}, не 64"
            ;;
        *) die "$role: sha256='$want_sha' — не 64-hex и не TBD" ;;
    esac

    rev=$(resolve_revision "$repo" "$revision")
    url="$HF_HOST/$repo/resolve/$rev/$file"
    dest="$CACHE_DIR/$repo/$file"

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%-16s %-46s %s\n' "$role" "$repo/$file" "rev=$rev sha=$want_sha"
        continue
    fi

    mkdir -p "$(dirname -- "$dest")"

    tmp="${dest}.part"
    from_cache=0
    if [ -f "$dest" ] && [ "$want_sha" != "TBD" ]; then
        # Кеш валидируется пересчётом, а не доверием к существованию файла.
        log "$role: кеш-хит $dest — пересчёт sha256"
        from_cache=1
    else
        if [ -f "$tmp" ]; then
            log "$role: докачка ${tmp##*/} с $(file_size "$tmp") Б (обрыв сети — resume)"
        else
            log "$role: GET $url"
        fi
        # --continue-at -: докачка .part после обрыва (промер 19.10: HF-CDN рвёт
        # 355 МБ на ~180 МБ, curl (18)). Ключ `=-`: если сервер не принимает
        # Range, качаем с нуля; пустой .part resume безопасен.
        if ! http_get "$url" "$tmp"; then
            # resume на не-ресюмируемом сервере → retry с нуля: обрезаем .part.
            if [ -f "$tmp" ]; then
                log "$role: resume не сошелся — перезапуск скачивания с нуля"
                rm -f "$tmp"
                http_get "$url" "$tmp" || { rm -f "$tmp"; die "$role: скачивание не удалось (fail-closed)"; }
            else
                die "$role: скачивание не удалось (fail-closed)"
            fi
        fi
        # Проверка ПОСЛЕ скачивания, ДО mv (нит #10 ревью #9): неподтверждённый
        # файл не попадает в кеш под финальным именем.
        got_size=$(file_size "$tmp")
        got_sha=$(sha256_of "$tmp")
        if [ "$want_size" != "0" ] && [ "$got_size" != "$want_size" ]; then
            rm -f "$tmp"
            die "$role: размер $got_size ≠ манифест $want_size ($tmp) — обрезан или подмена"
        fi
        mv -f "$tmp" "$dest"
    fi

    got_size=$(file_size "$dest")
    got_sha=$(sha256_of "$dest")

    if [ "$want_size" != "0" ] && [ "$got_size" != "$want_size" ]; then
        die "$role: размер $got_size ≠ манифест $want_size ($dest) — обрезан или подмена"
    fi

    if [ "$want_sha" = "TBD" ]; then
        log "$role: первое подтверждение sha256=$got_sha size=$got_size rev=$rev"
        if [ "$REWRITE_MANIFEST" -eq 1 ]; then
            rewrite_manifest_row "$role" "$rev" "$got_sha" "$got_size"
        fi
    elif [ "$want_sha" != "$got_sha" ]; then
        # #194 нить 2 (UX-строка, паритет .ps1): красная ветка на кеш-хите —
        # файл чужой (битый/подмена), скрипт его НЕ сносит (не наш);
        # оператору — явное действие.
        if [ "$from_cache" -eq 1 ]; then
            printf 'fetch-models: ОШИБКА: %s: кеш-повреждён: sha256 %s не совпал с манифестом (факт: %s) — снеси файл и повтори: rm -f "%s"\n' \
                "$role" "$dest" "$got_sha" "$dest" >&2
            exit 1
        fi
        printf 'fetch-models: ОШИБКА: %s: sha256 рассинхронизация\n  манифест: %s\n  факт:    %s\n  файл:    %s\n' \
            "$role" "$want_sha" "$got_sha" "$dest" >&2
        exit 1
    else
        log "$role: sha256 совпал ($got_sha)"
    fi

    processed=$((processed + 1))
done < "$MANIFEST"

if [ "$DRY_RUN" -eq 1 ]; then
    exit 0
fi
[ "$processed" -gt 0 ] || die "манифест не содержит ни одной записи hf"
log "готово: $processed файл(ов) в $CACHE_DIR"
