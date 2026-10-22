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
#
# Код возврата (контракт, тот же класс гейта, что scripts/measure-rss.sh):
#   0 = вердикт ok ЛИБО пропуск замера («нет весов» = skip, а не зелёный);
#   1 = вердикт over (бюджет превышен) ЛИБО демон не поднялся ЛИБО мусор в
#       числовом env (`BUDGET_MIB` не число — отказ до замера, ревью #98 R2);
#   2 = нет бинаря ЛИБО бинарь собран голым контуром без динамического орта
#       (preflight-зуб issue #170 б — «артефакт непригоден, прогон не
#       начинался»; тот же класс, что «нет бинаря»).
# До этой правки вердикт over только печатался, а скрипт выходил rc=0 — тот же
# класс false-green «print-only landing test» (реестр 15/18), что в
# measure-rss.sh. Скрипт НЕ вызывается из CI-контура: упоминается только в
# docs как метод промера — три файла, пять строк (grep `measure-daemon-rss`
# по дереву, переснято 21.10): crates/guard-daemon/README.md:110 (раздел про
# монтаж каскадов 1–2), docs/model-audit.md §10 (метод; §-ссылка вместо строковой) и
# docs/release.md §RAM п.8 (зуб preflight, #170 б), п.9 (зуб вердикта) и п.12 б
# (валидация BUDGET_MIB) — прежняя форма «release.md:274/308/313» была
# строковой и поехала на первой же правке документа (пересъёмка 22.10: из трёх
# ссылок ни одна не попадала в §RAM). Прежняя формулировка
# «только в README» была ложью о покрытии (ревью #98, нит 3; «мест три» —
# неточно по строкам: файлов три, строк пять, ревью #98 D6).
# Но живой гейт обязан быть единым: у двух скриптов с одним вердиктом
# должен быть один код возврата, иначе первый же вызов из CI получит зелёный
# провал.

set -euo pipefail

THREADS="${FASAD_THREADS:-2}"
# Бюджет SPEC §1 ≤1.8 ГБ = 1843.2 MiB; тот же рычаг из окружения, что в
# measure-rss.sh, — ради промера зуба (`BUDGET_MIB=0.001 → rc=1`) без правки
# кода. Значение по умолчанию = контракт, промеры его не меняют.
BUDGET_MIB="${BUDGET_MIB:-1843.2}"
# Валидация BUDGET_MIB (ревью #98 R2, тот же fail-open, что в measure-rss.sh):
# вердикт считает awk: не-числовой b переводит сравнение `p <= b` в
# лексикографику — «48.3» <= «abc» истинно ('4' < 'a') → при BUDGET_MIB=abc
# печаталось `METRIC|budget|abc|verdict|ok` и rc=0. Мусор в числовом env =
# отказ с именем переменной и значением (rc=1; docs/release.md §RAM п.12).
# Идём ДО проверки бинаря: сломанный env — диагноз про запуск, а не про среду.
if [[ ! "$BUDGET_MIB" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "measure-daemon-rss: ОШИБКА: BUDGET_MIB=$BUDGET_MIB: не число (ожидается вид 1843.2 — целое или десятичное, без разделителей и знака)" >&2
  exit 1
fi
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

# ── preflight-зуб на динамический орт (issue #170 б) ─────────────────────────
# Класс тот же, что в scripts/measure-rss.sh `preflight_spike_ort` (там — полная
# аргументация и промеры): скрипт берёт ГОТОВЫЙ бинарь и гоняет его с
# примонтированными каскадами 1–2. Бинарь, собранный «голым» контуром —
# `cargo build --release -p guard-daemon --features ort-inference` БЕЗ env
# `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=…` (контракт
# docs/model-audit-weights.md §W2 п.1) — несёт pyke-статику: в динамическом
# графе (`otool -L` на macOS, `readelf -d`/`ldd` на Linux) строки
# `libonnxruntime` нет, орт вшит в бинарь, прогон даёт SIGSEGV.
# ЗУБ ПРОМЕРЕН (issue #170 б, артефакты в теле PR): голый spike → rc=2 со
# строкой причины; с выключенным зубом тот же бинарь = `Segmentation fault: 11`
# и `METRIC|error|демон не слушает` — т.е. краснеет НЕПРАВИЛЬНЫЙ диагноз;
# релизный бинарь каскада-0 → зуб зелёный (см. вторую ногу ниже).
# ДВЕ НОГИ (важно): релизный каскад-0 (`just release-build`, фича
# `ort-inference` ВЫКЛЮЧЕНА) орта не содержит вообще — ни динамики, ни статики.
# Одноногая проверка «нет dylib = красный» краснила бы его rc=2, а это ровно
# тот ложно-красный класс, который зуб и закрывает (промер правки #170 на
# релизном бинаре: rc=2 → после второй ноги зелёный). Красный — только
# комбинация «статика pyke ЕСТЬ» + «динамического орта НЕТ».
# rc=2 = «артефакт непригоден, прогон не начинался» (тот же класс, что «нет
# бинаря» выше); rc=1 зарезервирован за вердиктом over и за упавшим прогоном.
# Инструмента нет = WARN-skip по динамической ноге (статическая нога — grep по
# бинарю — жива всегда): краснеть от отсутствия утилиты нельзя.
# Рычаг `FASAD_RSS_ORT_PREFLIGHT=0` — промер самого зуба на заведомо голом
# артефакте (показать, что краснит именно он), по умолчанию включён.
ORT_PREFLIGHT="${FASAD_RSS_ORT_PREFLIGHT:-1}"
if [[ "$ORT_PREFLIGHT" == "1" ]]; then
  static_pyke=0
  if LC_ALL=C grep -qa 'onnxruntime/core/session' "$BIN" 2>/dev/null; then
    static_pyke=1
  fi
  deps=""
  case "$(uname -s)" in
    Darwin)
      if command -v otool >/dev/null 2>&1; then
        deps="$(otool -L "$BIN" 2>/dev/null || true)"
      else
        echo "WARN|preflight|otool нет в PATH — динамическая нога зуба НЕ промерена (статическая жива)"
      fi
      ;;
    Linux)
      if command -v readelf >/dev/null 2>&1; then
        deps="$(readelf -d "$BIN" 2>/dev/null || true)"
      elif command -v ldd >/dev/null 2>&1; then
        deps="$(ldd "$BIN" 2>/dev/null || true)"
      else
        echo "WARN|preflight|ни readelf, ни ldd нет в PATH — динамическая нога зуба НЕ промерена (статическая жива)"
      fi
      ;;
    *)
      echo "WARN|preflight|OS=$(uname -s): динамическая нога зуба не реализована (реализованы Darwin/Linux)"
      ;;
  esac
  dynamic_ort=0
  if [[ -n "$deps" ]] && printf '%s\n' "$deps" | grep -qi 'libonnxruntime'; then
    dynamic_ort=1
  fi
  if [[ "$dynamic_ort" == "1" ]]; then
    echo "METRIC|preflight|ort_dynamic"
  elif [[ "$static_pyke" == "0" ]]; then
    echo "METRIC|preflight|no_ort|бинарь орта не содержит — релизный каскад-0, зуб не краснит"
  else
    echo "measure-daemon-rss: ОШИБКА: spike собран голым контуром (pyke-статика, §W2 п.1) — just build-ort" >&2
    echo "measure-daemon-rss: ОШИБКА: в $BIN вшита статика pyke (маркер onnxruntime/core/session) и нет динамического libonnxruntime — прогон с примонтированными каскадами 1–2 дал бы SIGSEGV (реестр ложно-красных: молча брать чужой бинарь = ложно-красный RAM-гейт)" >&2
    exit 2
  fi
fi

echo "METRIC|method|ps-rss-sampling-100ms|threads|$THREADS|reqs|$REQS|bin|$BIN"
FASAD_MODEL_DIR="$MODEL_DIR" FASAD_THREADS="$THREADS" FASAD_PORT="$PORT" \
  FASAD_BIND=127.0.0.1 FASAD_TIMEOUT_MS="${FASAD_TIMEOUT_MS:-30000}" \
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
  # Настоящий убийца прогона #84 (ревью #97, 22.10). `grep -o` отдаёт rc=1,
  # когда совпадений нет: тело `502 cascade_unavailable`, пустое тело, 200 с
  # нулём сущностей. Под `set -o pipefail` ненулевой статус ЛЮБОГО звена
  # становится статусом трубы, а `set -e` на ненулевом статусе присваивания
  # `spans=$(…)` валит скрипт МОЛЧА — до первой `METRIC|req`, без единой цифры.
  # Прежний диагноз («`[[ -z "$rss" ]] && rss=0` под `set -e` убивал прогон на
  # первом 200-ответе») опровергнут: команда слева от `&&` изъята из выхода,
  # идиом жив на bash 3.2.57 и 5.x (трассировки — в теле PR #97). Нулевой
  # счётчик — легальный исход запроса, поэтому фолбэк 0, а не аварап.
  spans=$(grep -o '"entity_type"' /tmp/rss-body.json 2>/dev/null | wc -l | tr -d ' ') || spans=0
  stage=$(tr -d '\r' <"$HEADERS" | grep -i '^x-guard-stage:' | cut -d' ' -f2 || true)
  c2=$(tr -d '\r' <"$HEADERS" | grep -i '^x-guard-cascade2:' | cut -d' ' -f2 || true)
  rss=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
  # Пустой снимок = демон умер между запросом и `ps`; фолбэк расширением
  # параметра, а не `&&`-списком: у него нет статуса команды, `set -e` не за что.
  rss=${rss:-0}
  # Живой идиом, не ловушка: `(( … ))` слева от `&&` изъят из выхода `set -e`
  # (промер ревью #97 — ложный диагноз этого же файла). Меняем коммент, не код.
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
# Вердикт = max по всем сэмплам (консервативный пик, та же семантика, что
# track_peak в measure-rss.sh: ok при peak <= budget, не строго «<» — 1843.2
# есть «≤1.8 ГБ» по SPEC §1, равенство бюджету не превышение).
verdict="$(awk -v p="$peak_mib" -v b="$BUDGET_MIB" 'BEGIN{print (p<=b)?"ok":"over"}')"
echo "METRIC|budget|$BUDGET_MIB|verdict|$verdict"
echo "METRIC|stage_header|${stage:-none}|cascade2_header|${c2:-none}"
cp "$RSS_LOG" "/tmp/fasad-rss-samples.$(date +%s).txt" 2>/dev/null || true
# Зуб: вердикт over обязан валить код возврата, а не только печататься
# (реестр false-green 15/18). Причину пишем в stderr — METRIC-строки выше
# остаются целым артефактом прогона.
if [[ "$verdict" == "over" ]]; then
  echo "measure-daemon-rss: ОШИБКА: RAM-гейт: вердикт over (peak=${peak_mib} MiB, budget=${BUDGET_MIB} MiB)" >&2
  exit 1
fi
