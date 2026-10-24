#!/usr/bin/env bash
# rrn-bench.sh — контур воспроизводимости внешнего кросс-бенча (#209).
#
# Владелец контура: data/bench-external/README.md. Мера read-only (не гейт recall).
# Прогон РУЧНОЙ (контур как их quality-гейт вне CI: ci.yml L4-5 первичка —
# «нужны веса/минуты»; внешняя сеть в CI = air-gap-контур, net-джоба краснеет):
# артефакт-дата фиксируется в .local/bench/rrn-<дата>.md.
#
# Каскады (флаг --mode):
#   cascade0 — debug-демон БЕЗ feature ort-inference (каскад-0, детерминированный
#              путь: чексуммы/регулярки). Разрешённый measurement-not-build (21.10/22.10).
#   full     — debug-демон С feature ort-inference на вендорном dylib (контраонта
#              crates/guard-daemon/README.md §«Как включить монтаж»; env орт-пути
#              ниже). Тяжёлый: один прогон за раз, nice.
#
# Щадящий режим (рулинг 21.10): FASAD_THREADS=2, nice -n 10, TMPDIR=/tmp,
# один прогон за раз; сборки release запрещены (22.10) — здесь только debug.
#
# Fail-closed: нет данных бенча в git / нет бинаря / демон не поднялся = красным,
# не молча. Массивы — `${arr[@]+"${arr[@]}"}` (bash 3.2 macOS, #137-контур).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="cascade0"
MODEL_DIR="${FASAD_MODEL_DIR:-$HOME/.cache/fasad-models}"
ORT_DIR="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0/lib}"
BENCH_CSV="data/bench-external/redmadrobot-pii-benchmark/test.csv"
CROSSREF="data/bench-external/crossref.jsonl"
OUT_DIR=".local/bench"
THREADS=2
EXTRA_FLAGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="${2:?--mode требует cascade0|full}"; shift 2 ;;
        --model-dir) MODEL_DIR="${2:?--model-dir требует путь}"; shift 2 ;;
        --ort-dir) ORT_DIR="${2:?--ort-dir требует путь}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir требует путь}"; shift 2 ;;
        *) EXTRA_FLAGS[${#EXTRA_FLAGS[@]}]="$1"; shift ;;
    esac
done

# 1. Данные бенча = в git (рюлинг 24.10). Нет файла = красным (не молча).
if [ ! -f "$BENCH_CSV" ]; then
    echo "FAIL нет $BENCH_CSV — данные кросс-бенча тащим в git (рюлинг 24.10);
проверь checkout (git checkout -- data/bench-external/) или HEAD ветки." >&2
    exit 1
fi

# 2. Конверт генерируется на лету (производное, не коммитится).
uv run --locked python tools/bench/rrn_bench.py --selftest
uv run --locked python tools/bench/rrn_bench.py

# 3. Демон.
case "$MODE" in
    cascade0)
        BIN="target/debug/fasad"
        BUILD_ARGS=(-p guard-daemon --bin fasad)
        ;;
    full)
        BIN="target-ort/debug/fasad"
        BUILD_ARGS=(-p guard-daemon --features ort-inference --bin fasad
                    --target-dir target-ort)
        ;;
    *)
        echo "FAIL --mode = cascade0|full, получено '$MODE'" >&2
        exit 1
        ;;
esac

if [ ! -x "$BIN" ]; then
    echo "== сборка debug (measurement-not-build, jobs=2 nice): $BIN"
    ( CARGO_BUILD_JOBS=2 TMPDIR=/tmp nice -n 10 cargo build "${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}" )
fi
[ -x "$BIN" ] || { echo "FAIL бинарь $BIN не собрался" >&2; exit 1; }

if [ "$MODE" = "full" ] && [ ! -d "$MODEL_DIR" ]; then
    echo "FAIL нет каталога весов $MODEL_DIR (scripts/fetch-models.sh; контур
--model-dir = перепромер) — без весов full-прогон = ложная цифра каскада-0." >&2
    exit 1
fi

DAEMON_ENV=(env "FASAD_PORT=0" "FASAD_MLOCK=best_effort" "FASAD_VAULT_MODE=stateless"
            "FASAD_THREADS=$THREADS" "TMPDIR=/tmp" "OMP_NUM_THREADS=$THREADS")
if [ "$MODE" = "cascade0" ]; then
    # Каскад-0-бинарь (feature-off) на машине с HOME требует харнес-флаг
    # FASAD_TEST_CASCADE0=1: он отключает #192/#198-подстановки дефолта
    # FASAD_MODEL_DIR (config.rs:412-440 первичка, «харнес cascade-0» —
    # легальный контур stage=cascade-0-only, вёрстка wire_e2e/ui_sandbox).
    # env -u чистит названный каталог из среды (иначе зуб BuiltWithoutInference).
    DAEMON_ENV+=(FASAD_TEST_CASCADE0=1)
    DAEMON_ENV+=(-u FASAD_MODEL_DIR)
fi
if [ "$MODE" = "full" ]; then
    # §W2-контур: вендорный dylib (justfile ort-dylib / контраонта README демона).
    DAEMON_ENV+=(ORT_LIB_PATH="$ORT_DIR")
    DAEMON_ENV+=(FASAD_MODEL_DIR="$MODEL_DIR")
fi

LOG="$(mktemp "${TMPDIR:-/tmp}/rrn-bench-daemon-XXXXXX.log")"
cleanup() {
    if [ -n "${DPID:-}" ] && kill -0 "$DPID" 2>/dev/null; then
        kill "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "== запуск демона ($MODE): $BIN"
"${DAEMON_ENV[@]}" nice -n 10 "$BIN" >"$LOG" 2>&1 &
DPID=$!

URL=""
for _ in $(seq 1 400); do
    if grep -q 'listening on' "$LOG" 2>/dev/null; then
        URL="$(sed -nE 's#.*listening on (http://[0-9.]+:[0-9]+)/health.*#\1#p' "$LOG" | head -1)"
        break
    fi
    if ! kill -0 "$DPID" 2>/dev/null; then
        echo "FAIL демон умер на старте: $(cat "$LOG")" >&2
        exit 1
    fi
    sleep 0.25
done
if [ -z "$URL" ]; then
    echo "FAIL демон не поднялся за 100 с: $(cat "$LOG")" >&2
    exit 1
fi
echo "== демон: $URL (лог $LOG)"

# 4. Прогон мерителя.
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RAW="$OUT_DIR/rrn-$(date +%Y-%m-%d)-$MODE.out"
echo "== прогон мерителя (2841 строк, threads=$THREADS)"
# shellcheck disable=SC2086
uv run --locked python tools/bench/rrn_score.py --url "$URL" --input "$CROSSREF" \
    ${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"} > "$RAW"
RC=$?
cat "$RAW"

# 5. Стадия демона в заголовок артефакта (первичка /health, docs/daemon-scope.md).
STAGE="$(curl -s --max-time 5 "$URL/health" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("stage","?"))' 2>/dev/null \
    || echo '?')"
echo "META|mode|$MODE|stage|$STAGE|stamp|$STAMP|threads|$THREADS|bin|$BIN" >> "$RAW"
echo "== артефакт: $RAW (stage=$STAGE)"
exit "$RC"
