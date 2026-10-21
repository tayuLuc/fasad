#!/usr/bin/env bash
# Release RSS демона с примонтированными каскадами 1–2 (#14A, SPEC §10 п.9).
#
# Зачем отдельный скрипт, а не «померил на глаз»: цифра в docs/model-audit.md
# обязана быть сгенерирована из артефакта прогона, а не набрана руками, и метод
# замера обязан быть повторяемым (правило команды: числу из арифметики не
# верим, числу из артефакта — верим).
#
# Метод.
# 1. Бинарь release-сборки с фичей `ort-inference` (продовая конфигурация:
#    каскады 1–2 поднимаются на старте, FASAD_MODEL_DIR задан).
# 2. `FASAD_THREADS=2` — рюлинг 21.10 (ноут оператора не нагружать); потоки
#    инференса входят в RSS, поэтому метод замера обязан их называть.
# 3. Опрос `ps -o rss=` каждые 100 мс с момента exec и до остановки; считаем
#    peak (максимум сэмплов) и стационар (медиана хвостовых 20 % сэмплов,
#    минимум 5). `ps`-RSS = резидентные KiB, включая
#    общие страницы фреймворка — консервативная верхняя оценка (тот же семейство
#    метрики, что `/proc/self/status` VmRSS на Linux).
# 4. Нагрузка: N запросов /v1/analyze на текст, в котором есть и чексумма
#    (каскад 0), и ФИО/адрес/телефон (каскад 1), и серая зона (каскад 2).
#
# Запуск (нужны веса и dylib):
#   ORT_LIB_PATH=... DYLD_LIBRARY_PATH=... scripts/measure-daemon-rss.sh [N]
# Вывод — METRIC-строки; из них собирается §10 docs/model-audit.md.

set -euo pipefail

THREADS="${FASAD_THREADS:-2}"
REQS="${1:-5}"
BIN="${DSH_FASAD_BIN:-target/release/fasad}"
MODEL_DIR="${FASAD_MODEL_DIR:-$HOME/.cache/fasad-models}"
PORT="${FASAD_PORT:-18081}"
TXT="${TXT:-Иванов Пётр Сергеевич, паспорт 4507 123456, адрес: г. Ростов-на-Дону, улица Октябрьской Революции, дом 48, телефон +7 912 345-67-89, почта ivanov@example.ru, ИНН 2482014338, СНИЛС 65707715421}"

if [[ ! -x "$BIN" ]]; then
  echo "METRIC|error|бинарь не найден: $BIN (собери: cargo build --release -p guard-daemon --features ort-inference)"
  exit 2
fi
if [[ ! -d "$MODEL_DIR" ]]; then
  echo "METRIC|skip|нет каталога весов: $MODEL_DIR (scripts/fetch-models.sh)"
  exit 0
fi

LOG="$(mktemp -t fasad-rss.XXXXXX)"
RSS_LOG="$(mktemp -t fasad-rss-samples.XXXXXX)"
cleanup() {
  [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "${SAMPLER:-}" ]] && kill "$SAMPLER" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -f "$LOG" "$RSS_LOG"
}
trap cleanup EXIT

echo "METRIC|method|ps-rss-sampling-100ms|threads|$THREADS|reqs|$REQS|bin|$BIN"
FASAD_MODEL_DIR="$MODEL_DIR" FASAD_THREADS="$THREADS" FASAD_PORT="$PORT" \
  FASAD_BIND=127.0.0.1 FASAD_TIMEOUT_MS=30000 \
  "$BIN" >"$LOG" 2>&1 &
PID=$!

# Опрос RSS с самого exec: пик загрузки весов интереснее пика инференса.
(
  while kill -0 "$PID" 2>/dev/null; do
    rss=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
    [[ -n "$rss" ]] && echo "$rss" >>"$RSS_LOG"
    sleep 0.1
  done
) &
SAMPLER=$!

# Ждём баннер с портом (демон печатает фактический bind) — максимум 150 с.
ready=0
for _ in $(seq 1 1500); do
  if grep -q "listening" "$LOG" 2>/dev/null; then ready=1; break; fi
  if ! kill -0 "$PID" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  # Отказ старта — это тоже результат (fail-closed на старте): печатаем баннер.
  echo "METRIC|error|демон не слушает: лог старта ниже"
  cat "$LOG"
  exit 1
fi
# Порт берём из баннера, а не из переменной: демон печатает фактический bind,
# и замер обязан стучаться именно туда.
PORT=$(grep -o 'http://127.0.0.1:[0-9]*/health' "$LOG" | head -1 | sed 's/.*:\([0-9]*\).*/\1/')
echo "METRIC|port|$PORT"

peak=0
HEADERS="$(mktemp -t fasad-rss-hdr.XXXXXX)"
for i in $(seq 1 "$REQS"); do
  # Один запрос на итерацию: заголовки в файл, тело в файл. Прежний вариант
  # делал второй запрос только ради `x-guard-stage` и удваивал нагрузку,
  # о которой рапортовал как о `reqs|N`.
  code=$(curl -s -D "$HEADERS" -o /tmp/rss-body.json -w '%{http_code}' -X POST \
    -H 'content-type: application/json' -H 'x-guard-policy: audit_only' \
    --data "{\"text\":\"$TXT\"}" "http://127.0.0.1:$PORT/v1/analyze" || echo "000")
  spans=$(grep -o '"entity_type"' /tmp/rss-body.json 2>/dev/null | wc -l | tr -d ' ')
  stage=$(tr -d '\r' <"$HEADERS" | grep -i '^x-guard-stage:' | cut -d' ' -f2 || true)
  c2=$(tr -d '\r' <"$HEADERS" | grep -i '^x-guard-cascade2:' | cut -d' ' -f2 || true)
  rss=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
  [[ -z "$rss" ]] && rss=0
  (( rss > peak )) && peak=$rss
  echo "METRIC|req|$i|http|$code|spans|$spans|stage|${stage:-none}|cascade2|${c2:-none}|rss_kib|$rss"
done
rm -f "$HEADERS"
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
kill "$SAMPLER" 2>/dev/null || true
wait "$SAMPLER" 2>/dev/null || true

samples=$(wc -l <"$RSS_LOG" | tr -d ' ')
max_sampl=$(sort -n "$RSS_LOG" | tail -1)
peak_mib=$(awk -v k="$max_sampl" 'BEGIN{printf "%.1f", k/1024}')
# Стационар = МЕДИАНА последних хвостовых сэмплов (прогон закончен, демон жив,
# новых аллокаций загрузки весов нет). Прежняя `rss_after_reqs_mib` была
# максимумом per-request-снимков — это не стационар, а пик с другим именем, и
# бывший §9 (ныне §10) называл его steady-state (ревью #87).
TAIL_FRACTION=0.2
steady_n=$(awk -v n="$samples" 'BEGIN{k=int(n*0.2); if(k<5)k=5; if(k>n)k=n; print k}')
steady_median=$(tail -n "$steady_n" "$RSS_LOG" | sort -n | awk -v k="$steady_n" '{a[NR]=$1} END{printf "%d", (k%2) ? a[(k+1)/2] : (a[k/2]+a[k/2+1])/2}')
steady_mib=$(awk -v k="$steady_median" 'BEGIN{printf "%.1f", k/1024}')
echo "METRIC|samples|$samples|rss_peak_mib|$peak_mib"
echo "METRIC|steady_samples|$steady_n|rss_steady_median_mib|$steady_mib|tail_fraction|$TAIL_FRACTION"
echo "METRIC|budget|1843.2|verdict|$(awk -v p="$peak_mib" 'BEGIN{print (p<1843.2)?"ok":"over"}')"
echo "METRIC|stage_header|${stage:-none}|cascade2_header|${c2:-none}"
cp "$RSS_LOG" "/tmp/fasad-rss-samples.$(date +%s).txt" 2>/dev/null || true
