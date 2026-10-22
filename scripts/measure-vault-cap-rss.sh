#!/usr/bin/env bash
# RAM-промер потолка #120: сессии × спаны максимального размера.
#
# Зачем отдельный прогон, а не `measure-daemon-rss.sh`: тот грузит ОДИН текст
# через `/v1/analyze` (каскады) и меряет release-RSS демона с примонтированными
# весами — это бюджет SPEC §1 (≤1843.2 MiB). Вопрос #120 другой: сколько стоит
# ПОДНЯТЫЙ ПОТОЛОК (128 → 1024 Б) в session-режиме, где оригиналы спанов
# оседают в кэше движка. Нагрузка обязана быть `/v1/anonymize` с
# `X-Session-ID`: только этот путь кладёт оригинал в `SessionStore`
# (`guard-vault::cache`, вес записи = длина оригинала).
#
# Метод.
# 1. Дефолтный `Config` (стадия cascade-0-only, без весов): изолирует контур
#    хранилища от 976 MiB каскадов 1–2. Числа этого промера — про дельту
#    потолков, а не про бюджет SPEC §1; бюджет меряет measure-daemon-rss.sh.
# 2. `FASAD_VAULT_MODE=session`, `FASAD_THREADS=2` (рюлинг 21.10), `FASAD_MLOCK`
#    дефолт `strict` — залоченный пул (64 × 2176 Б) поднимается по-настоящему.
# 3. Нагрузка: N сессий × `/v1/anonymize`, в тексте 6 словесных реестровых
#    номеров (ИНН-12/ИНН-10/СНИЛС/ОГРН/ОГРНИП/карта = 1345 Б оригиналов,
#    промер байтов фикстур — в выводе). Спаны берём НЕ из `/v1/analyze`, а
#    прямым запросом: `/v1/analyze` на этом входе даёт 5 спанов (одинаковые
#    фразы ИНН-12 и карты с 12+ цифрами сливаются в один валидатор), а промер
#    обязан грузить все шесть классов, включая «худший» 280 Б.
# 4. Опрос `ps -o rss=` каждые 100 мс; peak = максимум сэмплов, стационар =
#    медиана хвостовых 20 % (минимум 5) — та же семантика, что у
#    measure-daemon-rss.sh (консервативный пик, не среднее).
# 5. Два замера в одном скрипте: `session` (нагрузка ложится в кэш) и
#    `stateless` (нагрузка не хранится на покое) — дельта и есть RAM-цена
#    потолков на живом коде, а не на рассуждении.
#
# Запуск:
#   FASAD_PORT=18250 scripts/measure-vault-cap-rss.sh [N_SESSIONS] [REQS_PER_SESSION]
# Вывод — METRIC-строки; из них собирается тело PR #120 и docs/release.md.
#
# Код возврата (тот же контракт, что у measure-daemon-rss.sh — реестр
# false-green 15/18, «print-only landing test»):
#   0 = вердикт ok;
#   1 = вердикт over ЛИБО демон не поднялся;
#   2 = нет бинаря ЛИБО мусор в числовом env («артефакт непригоден»:
#       решение #178, docs/release.md §RAM п.11 б — «не промерено» ≠ «не
#       прошло»; у measure-rss.sh / measure-daemon-rss.sh те же носители).

set -euo pipefail

THREADS="${FASAD_THREADS:-2}"
BUDGET_MIB="${BUDGET_MIB:-1843.2}"
BIN="${DSH_FASAD_BIN:-target/release/fasad}"
PORT="${FASAD_PORT:-18250}"
SESSIONS="${1:-256}"
REQS="${2:-4}"

if [[ ! "$BUDGET_MIB" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "measure-vault-cap-rss: ОШИБКА: артефакт непригоден: BUDGET_MIB=$BUDGET_MIB: не число (ожидается вид 1843.2)" >&2
  exit 2
fi
for v in SESSIONS REQS THREADS; do
  n="${!v}"
  if [[ ! "$n" =~ ^[0-9]+$ ]] || [[ "$n" == "0" ]]; then
    echo "measure-vault-cap-rss: ОШИБКА: артефакт непригоден: $v=$n: ожидается положительное целое" >&2
    exit 2
  fi
done
if [[ ! -x "$BIN" ]]; then
  echo "METRIC|error|бинарь не найден: $BIN (собери: just ort-dylib -- build --release -p guard-daemon --features ort-inference)"
  exit 2
fi

# Фикстура: 6 словесных реестровых номеров (фикстуры тестов слоя числительных).
TXT=$(python3 - <<'PY'
inn12="восемьсот двадцать пять миллиардов восемьдесят два миллиона четыреста девяносто две тысячи девятьсот шестьдесят четыре"
inn10="два миллиарда четыреста восемьдесят два миллиона четырнадцать тысяч триста тридцать восемь"
snils="шестьдесят пять миллиардов семьсот семь миллионов семьсот пятнадцать тысяч четыреста двадцать один"
ogrn="семь триллионов сто сорок шесть миллиардов шестьсот семнадцать миллионов сто семьдесят восемь тысяч пятьсот девяносто один"
ogrnip="триста тринадцать триллионов семьсот семьдесят семь миллиардов пятьсот сорок два миллиона пятьсот шестьдесят три тысячи триста двенадцать"
card="четыре тысячи пятьсот семьдесят пять триллионов пятьсот три миллиарда пятьсот девяносто миллионов триста пятьдесят две тысячи девятьсот девяносто три"
print(f"ИНН {inn12}; ИНН2 {inn10}; СНИЛС {snils}; ОГРН {ogrn}; ОГРНИП {ogrnip}; карта {card}")
PY
)
# Тело запроса целиком (текст + спаны) собирается один раз и переиспользуется:
# байты запроса должны быть ОДНИМИ во всех сессиях, иначе сравнение режимов
# сравнивает нагрузки, а не хранилища.
BODY=$(python3 - "$TXT" <<'PY'
import json,sys
t=sys.argv[1]
words=[("inn", "восемьсот двадцать пять миллиардов восемьдесят два миллиона четыреста девяносто две тысячи девятьсот шестьдесят четыре"),
       ("inn", "два миллиарда четыреста восемьдесят два миллиона четырнадцать тысяч триста тридцать восемь"),
       ("snils","шестьдесят пять миллиардов семьсот семь миллионов семьсот пятнадцать тысяч четыреста двадцать один"),
       ("ogrn","семь триллионов сто сорок шесть миллиардов шестьсот семнадцать миллионов сто семьдесят восемь тысяч пятьсот девяносто один"),
       ("ogrnip","триста тринадцать триллионов семьсот семьдесят семь миллиардов пятьсот сорок два миллиона пятьсот шестьдесят три тысячи триста двенадцать"),
       ("card_pan","четыре тысячи пятьсот семьдесят пять триллионов пятьсот три миллиарда пятьсот девяносто миллионов триста пятьдесят две тысячи девятьсот девяносто три")]
spans=[]
for cls,w in words:
    b=t.find(w)
    assert b>=0, w
    # Координаты БАЙТОВЫЕ (контракт `/v1/anonymize`, vault.rs): `b` — индекс в
    # Python-строке (символы!), и `b + len(w.encode())` дало бы пересечение
    # соседних спанов на кириллице (промер первой итерации: 422 bad_span на
    # всех шести). Байтовое смещение = len(t[:b].encode()).
    bs = len(t[:b].encode())          # байтовое смещение начала спана
    spans.append({"entity_type":cls,"byte_start":bs,"byte_end":bs+len(w.encode())})
spans.sort(key=lambda s: (s["byte_start"], s["byte_end"]))
for a,b in zip(spans, spans[1:]):
    assert a["byte_end"] <= b["byte_start"], f"пересечение спанов: {a} {b}"
print(json.dumps({"text":t,"spans":spans},ensure_ascii=False))
PY
)
SPAN_BYTES=$(python3 -c "
import json,sys
b=json.loads(sys.argv[1])
print(sum(s['byte_end']-s['byte_start'] for s in b['spans']))
" "$BODY")

# Убийца висяков (промер 22.10): демон обязан быть убит на ЛЮБОМ выходе из
# `run_mode`, включая `return 1` («не слушает») и аварийный выход по `set -e`.
# Прежняя схема убивала его только на двух явных ветках, и отказ средней ноги
# оставлял процесс на порту: следующий запуск не мог забиндиться, curl получал
# `000`, а промер рапортовал «демон не слушает» про чужой труп.
CUR_PID=""
CUR_SAMPLER=""
cleanup_mode() {
  [[ -n "$CUR_PID" ]] && kill -9 "$CUR_PID" 2>/dev/null || true
  [[ -n "$CUR_SAMPLER" ]] && kill -9 "$CUR_SAMPLER" 2>/dev/null || true
  # Подстраховка (промер 22.10): `kill "$pid"` в середине `run_mode` гонится с
  # сэмплером, и на ветке «демон умер между запросами и ps» процесс переживал
  # скрипт — два осиротевших `./target/release/fasad` держали порт 18250, и
  # следующий промер получал `000` вместо ответа. Добираем по полному argv из
  # `ps -ww`: совпадение строгое по argv демона запущенного из этого дерева (`$BIN` ->
  # абсолютный путь), поэтому соседние worktree (чужие
  # `/tmp/wt130r/target/release/fasad`) под удар не попадают — паттерн
  # совпадает только с нашим путём.
  local abs mine
  abs="$(cd "$(dirname "$BIN")" 2>/dev/null && pwd)/$(basename "$BIN")"
  for mine in $(ps -ww -o pid=,command= | awk -v bin="$abs" 'index($0, bin) {print $1}'); do
    kill -9 "$mine" 2>/dev/null || true
  done
  CUR_PID=""; CUR_SAMPLER=""
}
# EXIT + INT/TERM: `set -e` уходит по EXIT, Ctrl-C — по сигналу; без второй
# связки демон переживает прерванный промер и занимает порт (промер 22.10:
# осиротевший `./target/release/fasad` убивал следующий запуск `000`-ответами).
trap cleanup_mode EXIT INT TERM

run_mode() {
  # $1 = режим хранилища (session|stateless)
  local mode="$1"
  local log rsslog pid sampler peak=0 port code
  log="$(mktemp -t fasad-vaultcap.XXXXXX)"
  rsslog="$(mktemp -t fasad-vaultcap-rss.XXXXXX)"
  FASAD_VAULT_MODE="$mode" FASAD_THREADS="$THREADS" FASAD_PORT="$PORT" \
    FASAD_BIND=127.0.0.1 FASAD_TIMEOUT_MS="${FASAD_TIMEOUT_MS:-30000}" \
    "$BIN" >"$log" 2>&1 &
  pid=$!
  CUR_PID="$pid"
  (
    while kill -0 "$pid" 2>/dev/null; do
      local rss
      rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
      [[ -n "$rss" ]] && echo "$rss" >>"$rsslog"
      sleep 0.1
    done
  ) &
  sampler=$!
  CUR_SAMPLER="$sampler"
  local ready=0
  for _ in $(seq 1 1500); do
    if grep -q "listening" "$log" 2>/dev/null; then ready=1; break; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [[ "$ready" != 1 ]]; then
    echo "METRIC|error|$mode: демон не слушает: лог ниже"
    cat "$log"
    cleanup_mode
    rm -f "$log" "$rsslog"
    return 1
  fi
  # Порт из баннера, не из переменной (та же дисциплина, что measure-daemon-rss.sh).
  port=$(grep -o 'http://127.0.0.1:[0-9]*/health' "$log" | head -1 | sed 's/.*:\([0-9]*\).*/\1/')
  local ok=0 refused=0 other=0
  for i in $(seq 1 "$SESSIONS"); do
    for _ in $(seq 1 "$REQS"); do
      # Тело ответа пишется в общий файл, но читается ТОЛЬКО на отказе; хвост
      # 400 байт — чтобы 000 не выглядел как «успешный ответ без кода».
      code=$(curl -s -m "${CURL_MAX_TIME:-30}" -o /tmp/vaultcap-body.json -w '%{http_code}' -X POST \
        -H 'content-type: application/json' \
        -H "x-session-id: cap120-$i" \
        --data "$BODY" "http://127.0.0.1:$port/v1/anonymize" || echo "000")
      case "$code" in
        200) ok=$((ok+1)) ;;
        503) refused=$((refused+1)) ;;
        *) other=$((other+1))
           if (( other <= 3 )); then
             echo "METRIC|error|$mode: запрос дал $code (ожидались 200/503), сессия $i"
             head -c 300 /tmp/vaultcap-body.json; echo
           fi ;;
      esac
    done
    rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
    rss=${rss:-0}
    (( rss > peak )) && peak=$rss
    if (( i % 32 == 0 )); then
      echo "METRIC|ramp|$mode|sessions|$i|rss_kib|$rss"
    fi
  done
  # Хвостовой оконный промер: нагрузка из N×M запросов кончается за секунды, а
  # вопрос промера — СТАЦИОНАР с полным кэшем (все сессии уже нагуляли
  # оригиналы). Без хвоста сэмплер успевал снять 4–9 точек со старта процесса и
  # «стационар» считался по загрузке бинаря (промер первой итерации: samples|4,
  # steady 11.8 MiB = старт, не кэш). Держим демон живым и лочим 3 с после
  # последней нагрузки; сэмплер пишет всё это время.
  sleep 3
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true
  CUR_PID=""; CUR_SAMPLER=""
  local samples max_sampl peak_mib steady_n steady_median steady_mib
  samples=$(wc -l <"$rsslog" | tr -d ' ')
  max_sampl=$(sort -n "$rsslog" | tail -1)
  peak_mib=$(awk -v k="$max_sampl" 'BEGIN{printf "%.1f", k/1024}')
  local tail_fraction=0.25
  steady_n=$(awk -v n="$samples" -v f="$tail_fraction" 'BEGIN{k=int(n*f); if(k<15)k=15; if(k>n)k=n; print k}')
  steady_median=$(tail -n "$steady_n" "$rsslog" | sort -n | awk -v k="$steady_n" '{a[NR]=$1} END{printf "%d", (k%2) ? a[(k+1)/2] : (a[k/2]+a[k/2+1])/2}')
  steady_mib=$(awk -v k="$steady_median" 'BEGIN{printf "%.1f", k/1024}')
  echo "METRIC|mode|$mode|sessions|$SESSIONS|reqs_total|$((SESSIONS*REQS))|ok|$ok|refused_503|$refused|other|$other"
  echo "METRIC|mode|$mode|samples|$samples|rss_peak_mib|$peak_mib|rss_steady_median_mib|$steady_mib|tail_fraction|$tail_fraction"
  cp "$rsslog" "/tmp/fasad-vaultcap-$mode-samples.txt" 2>/dev/null || true
  rm -f "$log" "$rsslog"
  PEAK_OUT="$peak_mib"
}

echo "METRIC|method|ps-rss-sampling-100ms|threads|$THREADS|bin|$BIN"
echo "METRIC|fixture|spans|6|original_bytes|$SPAN_BYTES|max_span|280|body_bytes|$(printf '%s' "$BODY" | wc -c | tr -d ' ')"

peak_session=0
peak_stateless=0
run_mode session; peak_session="$PEAK_OUT"
run_mode stateless; peak_stateless="$PEAK_OUT"

echo "METRIC|delta_mib|$(awk -v a="$peak_session" -v b="$peak_stateless" 'BEGIN{printf "%.1f", a-b}')"
verdict="$(awk -v p="$peak_session" -v b="$BUDGET_MIB" 'BEGIN{print (p<=b)?"ok":"over"}')"
echo "METRIC|budget|$BUDGET_MIB|verdict|$verdict"
if [[ "$verdict" == "over" ]]; then
  echo "measure-vault-cap-rss: ОШИБКА: RAM-гейт: вердикт over (peak=${peak_session} MiB, budget=${BUDGET_MIB} MiB)" >&2
  exit 1
fi
