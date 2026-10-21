#!/usr/bin/env bash
# scripts/measure-rss.sh — RAM-гейт SPEC §10 п.9 («профилирование пика RAM, цель ≤1.8 ГБ»).
#
# Два контура, два способа замера — они НЕ смешиваются в одном числе:
#
#   cascade-0  релизный бинарь `fasad` (cargo build --release -p guard-daemon),
#              старт на loopback, прогрев живыми /v1/analyze, RSS процесса меряется
#              системными средствами: macOS `footprint -p PID` (phys_footprint =
#              «Память» из монитора активности) + `ps -o rss` (resident, KB);
#              Linux — `ps -o rss` и /proc/<pid>/status VmRSS. Метод печатается в
#              каждой строке вывода, потому что три числа про один процесс
#              отличаются в разы и «RSS» без метода — не измерение (memory law:
#              «formatted number is not a fact»).
#
#   full       полный каскад 1–2 (орт-сессии lockR + Decide): харнес `spike` из
#              guard-onnx, RSS считается внутри процесса (macOS task_info
#              TASK_VM_INFO.internal, Linux VmRSS) и печатается строками
#              `METRIC|rss_*`. Это example, а не бинарь: модельного пути в демоне
#              нет (crates/guard-daemon/src/pipeline.rs, заголовок модуля), поэтому
#              «полный каскад демона» физически неизмерим — измеряется харнес.
#
# Контракт dylib (docs/model-audit.md §5 п.1, §8; нить N6 ревью #32): сборка И
# прогон полных каскадов — ОДНИМИ env `ORT_PREFER_DYNAMIC_LINK=1
# ORT_LIB_PATH=…`, иначе ort-sys уходит на pyke-статику 1.23 + copy-dylibs
# затирает шейды рядом с бинарём = SIGSEGV 139.
#
# Выход: строки `RSS|<контур>|<точка>|<значение MiB>|<метод>` и вердикт
# `BUDGET|<контур>|ok|peak_mib=…|budget_mib=1843.2` (SPEC §1 ≤1.8 ГБ = 1843.2 MiB).
# Вердикт считается по КОНСЕРВАТИВНОМУ пику (max по точкам), не по медиане —
# бэджет safety-critical, см. docs/model-audit.md §5.6 п.5.
#
# use: scripts/measure-rss.sh [--cascade0] [--full] [--skip-build]
# env: FASAD_RSS_TARGET (default target/release), ORT_DIR (default
#      $HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0), FASAD_RSS_WARMUP
#      (число прогревающих /v1/analyze, default 3)

set -euo pipefail

TARGET_DIR="${FASAD_RSS_TARGET:-target/release}"
ORT_DIR="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0}"
WARMUP="${FASAD_RSS_WARMUP:-3}"
BUDGET_MIB=1843.2
# Пул потоков орт-харнеса (рюлинг оператора 21.10: не грузить CPU ноута; spike
# по умолчанию берёт 4, spike.rs:158). Это собственный рычаг харнеса:
# OMP_NUM_THREADS на вендорном libonnxruntime osx-arm64 инертен (первичка
# ревью #73: otool/strings), поэтому рулим флагом `--threads`.
SPIKE_THREADS="${FASAD_SPIKE_THREADS:-2}" # SPEC §1 п.1: «<2 ГБ», бюджет-гейт §5.6 = 1.8 GiB
RUN_CASCADE0=0
RUN_FULL=0
SKIP_BUILD=0
DOC_ROWS=0
# Рюлинг kernel 21.10: «число, вписанное в документ от руки, — claim; цифры
# документа генерируются из артефакта прогона». `--doc-rows` печатает готовый
# markdown-блок для docs/model-audit.md §9 из тех же строк, что ушли в stdout:
# цифры в документ попадают копипастом из артефакта, а не из головы.
ROWS_FILE="$(mktemp)"

die() {
    printf 'measure-rss: ОШИБКА: %s\n' "$*" >&2
    exit 1
}

# emit_line <строка> — строка и в stdout, и в артефакт прогона ($ROWS_FILE),
# из которого генерируется --doc-rows. Строку собирает вызывающий код, а не
# printf с форматом из переменной (SC2059; MegaLinter вызывает shellcheck без
# `-S` и краснеет от info-класса). Строка, начинающаяся с `# shellcheck `, —
# это директива линтера, в прозе её быть не должно (SC1072/SC1073, промер
# 21.10: собственный комментарий об этом и уронил парсер).
emit_line() {
    printf '%s\n' "$1"
    printf '%s\n' "$1" >>"$ROWS_FILE"
}

usage() {
    cat <<'EOF'
использование: scripts/measure-rss.sh [опции]

  --cascade0   контур каскада-0: релизный бинарь демона (default, если не указано ничего)
  --full       контур полного каскада: харнес spike --arb --lockr (нужны веса + dylib ORT)
  --skip-build не собирать, брать готовые артефакты в target/release
  --doc-rows   в конце напечатать markdown-строки для docs/model-audit.md §9
               (генерируются из артефакта прогона, не перепечатываются от руки)
  -h, --help   эта справка
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cascade0) RUN_CASCADE0=1 ;;
        --full) RUN_FULL=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --doc-rows) DOC_ROWS=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "неизвестный аргумент: $1"
            ;;
    esac
    shift
done
if [ "$RUN_CASCADE0" -eq 0 ] && [ "$RUN_FULL" -eq 0 ]; then
    RUN_CASCADE0=1
fi

OS="$(uname -s)"
case "$OS" in
    Darwin) RSS_TOOL="footprint+ps" ;;
    Linux) RSS_TOOL="ps+VmRSS" ;;
    *)
        # Windows: ps/footprint нет; method = PowerShell (Get-Process
        # WorkingSet64/PrivateMemorySize64) — НЕ реализован здесь, промер на
        # Windows-раннере = открытый хвост (docs/release.md §RAM).
        die "OS=$OS: метод замера не реализован (реализованы Darwin/Linux)"
        ;;
esac

# rss_mib <pid> — печать резидентной памяти процесса в MiB (ps, KB → MiB).
rss_mib() {
    pid="$1"
    kb="$(ps -o rss= -p "$pid" | tr -d ' ')"
    [ -n "$kb" ] || die "ps не вернул RSS для pid=$pid (процесс умер?)"
    awk -v kb="$kb" 'BEGIN { printf "%.1f", kb / 1024 }'
}

# footprint_mib <pid> — phys_footprint (macOS), «Память» как в мониторе
# активности. Формат первички (промер 21.10, `footprint -p <pid>`):
#   fasad [14387]: 64-bit    Footprint: 1425 KB (16384 bytes per page)
# т.е. парсим заголовок `Footprint: <n> <unit>`. На Linux footprint нет —
# строка не печатается, метод в выводе.
footprint_mib() {
    pid="$1"
    [ "$OS" = "Darwin" ] || return 0
    footprint -p "$pid" 2>/dev/null | awk '
        match($0, /Footprint: [0-9.]+ (Bytes|KB|MB|GB|KiB|MiB|GiB)/) {
            v = $0; sub(/.*Footprint: /, "", v); sub(/ .*/, "", v); v += 0
            u = $0; sub(/.*Footprint: [0-9.]+ /, "", u); sub(/ .*/, "", u)
            if (u == "GiB" || u == "GB") v = v * 1024
            else if (u == "MiB" || u == "MB") v = v
            else if (u == "KiB" || u == "KB") v = v / 1024
            else v = v / 1048576
            printf "%.1f", v
            exit
        }'
}

report_point() {
    contour="$1"
    point="$2"
    pid="$3"
    mib="$(rss_mib "$pid")"
    emit_line "RSS|$contour|$point|$mib|ps -o rss (KB->MiB, resident)"
    # В вердикт бюджета идёт чтение `ps` (оно есть на обеих реализованных ОС);
    # вторая строка (VmRSS на Linux / footprint на macOS) — перекрёстная
    # сверка метода, в peak не свёрнута намеренно: смешивать в одном peak'е
    # две несравнимые метрики (resident против phys_footprint) = фальшивый
    # максимум.
    PEAK_MIB="$mib"
    if [ "$OS" = "Darwin" ]; then
        fp="$(footprint_mib "$pid" || true)"
        if [ -n "$fp" ]; then
            emit_line \
                "RSS|$contour|$point|$fp|footprint phys_footprint (macOS, «Память» Activity Monitor)"
        fi
    fi
    if [ "$OS" = "Linux" ] && [ -r "/proc/$pid/status" ]; then
        vm="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status")"
        [ -n "$vm" ] || vm=0
        vm_mib="$(awk -v kb="$vm" 'BEGIN { printf "%.1f", kb / 1024 }')"
        emit_line "RSS|$contour|$point|$vm_mib|/proc/pid/status VmRSS (KB->MiB)"
    fi
}

track_peak() {
    # peak = max по всем точкам контура — консервативный вердикт (§5.6 п.5).
    value="$1"
    if [ -z "${PEAK:-}" ] || awk -v a="$value" -v b="$PEAK" 'BEGIN { exit !(a > b) }'; then
        PEAK="$value"
    fi
}

# ── контур 1: каскад-0 (релизный бинарь демона) ──────────────────────────────
run_cascade0() {
    bin="$TARGET_DIR/fasad"
    [ -x "$bin" ] || die "нет бинаря $bin — убери --skip-build или собери: cargo build --release -p guard-daemon"

    log="$(mktemp)"
    # FASAD_PORT=0 = «дай свободный», баннер печатает фактический адрес
    # (crates/guard-daemon/src/main.rs, local_addr).
    # FASAD_THREADS=2: рюлинг оператора 21.10 «не грузить CPU ноута»; флаг
    # реальный — `FASAD_THREADS` в crates/guard-daemon/src/config.rs:403,
    # дефолт `DEFAULT_THREADS = 8` (config.rs:67) — НАСТОЯЩИЙ рычаг потоков
    # демона. Поправка к рюлингу 21.10 (ревью #73, первичка otool/strings
    # вендорного libonnxruntime osx-arm64): `OMP_NUM_THREADS` инертен, в этом
    # дереве переменная не читается, так что в методику она не входит.
    # На каскаде-0 потоки не фактор: три прогона при FASAD_THREADS=8 дают
    # 3.3/3.3/3.4 MiB, прогон при =2 — 3.4 MiB (N=4, разница ≤ 0.1 MiB = шум
    # pages-wiring; docs/model-audit.md §9 п.4). Прежняя пара «2.8 и 3.4»
    # строилась на одиночном неавторитетном прогоне и снята ревью #76 (F4).
    # Метод замера не меняется, окружение печатается в INFO-строке.
    FASAD_PORT=0 FASAD_VAULT_MODE=stateless FASAD_THREADS="${FASAD_THREADS:-2}" \
        "$bin" >"$log" 2>&1 &
    pid="$!"
    # Ловушка одна и на EXIT: демон обязана убивать любая ветка выхода (die,
    # set -e, сигнал), иначе осиротевший процесс слушает порт и следующий прогон
    # ловит AddrInUse; wait дожимает убитый фон, не оставляя зомби (ревью #76, F6;
    # промер: контроль с осознанным провалом гейта leaving-демона не даёт —
    # `Terminated: 15` в логе прогона).
    # shellcheck disable=SC2064
    trap "kill '$pid' 2>/dev/null || true; wait '$pid' 2>/dev/null || true; rm -f '$log'" EXIT

    port=""
    i=0
    while [ "$i" -lt 100 ]; do
        port="$(sed -n 's#.*listening on http://127.0.0.1:\([0-9]*\)/health.*#\1#p' "$log" | head -1)"
        # «0» = запрос свободного порта (FASAD_PORT=0), не адрес: баннер с нулём
        # readiness не даёт. Промер 21.10: ноль принимался, curl уходил в rc=7
        # (connect refused), `set -e` ронял скрипт без единой строки причины.
        [ -n "$port" ] && [ "$port" != "0" ] && break
        kill -0 "$pid" 2>/dev/null || die "демон умер на старте: $(cat "$log")"
        i=$((i + 1))
        sleep 0.1
    done
    [ -n "$port" ] || die "демон не поднялся за 10 с: $(cat "$log")"

    printf 'INFO|cascade0|pid=%s|port=%s|bin=%s|env=FASAD_THREADS=%s\n' \
        "$pid" "$port" "$bin" "${FASAD_THREADS:-2}"
    report_point cascade0 idle "$pid"
    track_peak "$PEAK_MIB"

    # Прогрев: живой /v1/analyze текстом, на котором каскад-0 гарантированно
    # даёт ВСЕ ЧЕТЫРЕ чексумма-валидатора (inn10, inn12, snils, luhn; промер
    # живым POST 21.10: spans=4, у каждого score=1.0), плюс /v1/anonymize
    # (vault-путь: LZ4 + ChaCha20-Poly1305 + mlock-арены). Контракт /v1/anonymize
    # (`crates/guard-daemon/src/vault.rs`, `AnonymizeRequest { text, spans }`):
    # spans = топ-level JSON-массив из ответа /v1/analyze (промер живым POST
    # 21.10), голый `{"text":…}` = 400 — поэтому прогрев цепочкой, а не двумя
    # независимыми запросами.
    #
    # Прежний текст давал spans=1 (один ИНН): СНИЛС был в раздельной форме
    # «112-233-445 95» (не находится, issue #51), карта «4276 1234 5678 9012» не
    # проходит Luhn, 12-значного ИНН не было вовсе — три валидатора из четырёх
    # не прогревались, а RSS мерился по недогретому контуру (ревью #76, F5).
    # ИНН 300504899258 = валидный вектор из таблицы тестов
    # `crates/guard-detectors/src/checksums.rs:733` (первичка, docs §2).
    #
    # Реестровые слова (ООО, ул., наб., д., стр.) в тексте стоят для правды
    # трафика, а НЕ для прогрева словарного матчера: aho-автомат в контуре
    # демона не вызывается — `crates/guard-daemon/src/cascade0.rs:32-33`
    # импортирует из guard_detectors только `checksums` и `normalize`, grep
    # `aho|dictionary` по всему `crates/guard-daemon/` = 0 hits. Прежний
    # комментарий обещал прогрев «ахо-автомата», которого в процессе демона нет;
    # словарный матчер прогревается тестами guard-detectors, не этим прогоном.
    text='Ушаков Павел Сергеевич, паспорт 4510 123456, СНИЛС 65707715421, ИНН 7707083893, ИНН юрлица 300504899258, телефон +7 916 123-45-67, e-mail p.ushakov@example.ru, карта 4276123456789014. Адрес: 121099, Москва, Смоленская наб., 7. ООО «Ромашка», ул. Смоленская, д. 7, стр. 1.'
    payload="$(printf '{"text":"%s"}' "$text")"
    spans='[]'
    i=0
    while [ "$i" -lt "$WARMUP" ]; do
        spans="$(curl -s -X POST -H 'content-type: application/json' -H 'x-guard-policy: mask' \
            --data-binary "$payload" "http://127.0.0.1:$port/v1/analyze")" \
            || die "прогрев /v1/analyze не ответил (порт $port): curl rc=$?"
        [ -n "$spans" ] || die "прогрев /v1/analyze вернул пустое тело"
        case "$spans" in
            '['*) ;;
            *) die "прогрев /v1/analyze вернул не массив спанов: ${spans:0:80}" ;;
        esac
        i=$((i + 1))
    done
    nspans="$(printf '%s' "$spans" | tr -cd '{' | wc -c | tr -d ' ')"
    # Прогрев считается прогревом, только если на тексте сработали все четыре
    # чексумма-валидатора. «Хотя бы один спан» = ложно-зелёный прогрев: при
    # регрессе любого валидатора RSS мерился бы по недогретому контуру и
    # выглядел бы здоровым (ревью #76, F5).
    for validator in inn10 inn12 snils luhn; do
        printf '%s' "$spans" | grep -q "\"validator\":\"$validator\"" \
            || die "прогрев не задел валидатор $validator (spans=$nspans) — RSS по недогретому контуру невалиден"
    done
    anon_body="$(printf '{"text":"%s","spans":%s}' "$text" "$spans")"
    code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H 'content-type: application/json' \
        --data-binary "$anon_body" "http://127.0.0.1:$port/v1/anonymize")"
    [ "$code" = "200" ] || die "прогрев /v1/anonymize вернул HTTP $code (vault-путь не прогрет)"
    printf 'INFO|cascade0|warmed=%s analyze + 1 anonymize (HTTP 200, spans=%s)\n' "$WARMUP" "$nspans"

    report_point cascade0 after_warm "$pid"
    track_peak "$PEAK_MIB"

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    verdict="$(awk -v p="$PEAK" -v b="$BUDGET_MIB" 'BEGIN { print (p <= b) ? "ok" : "OVER" }')"
    emit_line "BUDGET|cascade0|$verdict|peak_mib=$PEAK|budget_mib=$BUDGET_MIB|tool=$RSS_TOOL"
    PEAK=""
}

# ── контур 2: полный каскад 1–2 (харнес spike, орт-сессии) ───────────────────
run_full() {
    ex="$TARGET_DIR/examples/spike"
    [ -x "$ex" ] || die "нет харнеса $ex — собери: just build-ort (spike --features ort-inference, dylib-контракт)"
    [ -d "$ORT_DIR/lib" ] || die "нет каталога dylib ORT: $ORT_DIR/lib (docs/model-audit.md §8 п.3)"
    lib="$(find "$ORT_DIR/lib" -maxdepth 1 -name 'libonnxruntime*.dylib' -o -maxdepth 1 -name 'libonnxruntime*.so' 2>/dev/null | head -1)"
    [ -n "$lib" ] || die "в $ORT_DIR/lib нет libonnxruntime* (docs/model-audit.md §8 п.3)"

    # --arb-budget = обе модели в ОДНОМ процессе, пик по всем точкам: контракт
    # docs/model-audit.md §5.6 п.5 (именно эта точка закрывает бюджет SPEC §1).
    # Пул потоков инференса = FASAD_SPIKE_THREADS (по умолчанию 2): ruling
    # оператора от 21.10 «не нагружать CPU ноута» (ORT-сессии спайка по
    # умолчанию гоняют threads=4, spike.rs:158 `unwrap_or(4)`; это собственный
    # рычаг харнеса — OMP_NUM_THREADS на вендорном onnxruntime инертен,
    # поправка ревью #73). Метод замера не меняется, но потоки — часть
    # методики: пик двух моделей на них реагирует (промер 21.10: threads=4 →
    # 976.3 MiB, threads=2 → 889.1 MiB, docs/model-audit.md §9 п.4), поэтому
    # число печатается в INFO-строке, а бюджет-вердикт считается по max.
    printf 'INFO|full|harness=spike --arb-budget --arb --lockr --threads %s|ort_dylib=%s\n' "$SPIKE_THREADS" "$lib"
    out="$(mktemp)"
    set +e
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="$ORT_DIR/lib" \
        "$ex" --arb-budget --arb --lockr --threads "$SPIKE_THREADS" >"$out" 2>&1
    rc="$?"
    set -e
    grep -E '^(METRIC\|rss|BUDGET\||ERROR)' "$out" || true
    [ "$rc" -eq 0 ] || die "харнес.full exited rc=$rc (см. docs/model-audit.md §5: SIGSEGV 139 = нарушен dylib-контракт)"
    peak="$(grep -oE 'METRIC\|rss_peak_mib_both_models\|[0-9.]+' "$out" | tail -1 | cut -d'|' -f3)"
    [ -n "$peak" ] || die "харнес не напечатал rss_peak_mib_both_models (контракт METRIC нарушен)"
    emit_line "RSS|full|peak_both_models|$peak|spike task_info TASK_VM_INFO.internal (macOS) / VmRSS (Linux)"
    verdict="$(awk -v p="$peak" -v b="$BUDGET_MIB" 'BEGIN { print (p <= b) ? "ok" : "OVER" }')"
    emit_line "BUDGET|full|$verdict|peak_mib=$peak|budget_mib=$BUDGET_MIB|tool=spike METRIC (in-process)"
    rm -f "$out"
}

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "BUILD|cargo build --release -p guard-daemon"
    cargo build --release -p guard-daemon
fi
[ "$RUN_CASCADE0" -eq 1 ] && run_cascade0
[ "$RUN_FULL" -eq 1 ] && run_full
if [ "$DOC_ROWS" -eq 1 ]; then
    printf '\n=== markdown для docs/model-audit.md §9 (сгенерировано прогоном) ===\n\n'
    printf '| контур | точка | MiB | метод |\n| --- | --- | --- | --- |\n'
    awk -F"|" '$1 == "RSS" { printf "| `%s` | `%s` | %s | %s |\n", $2, $3, $4, $5 }' "$ROWS_FILE"
    printf '\n'
    awk -F"|" '$1 == "BUDGET" { printf "`BUDGET|%s|%s|%s|%s|%s`\n", $2, $3, $4, $5, $6 }' "$ROWS_FILE"
    printf '\nпромер: %s, ОС %s/%s, метод: %s; потоки: демон FASAD_THREADS=%s, харнес FASAD_SPIKE_THREADS=%s\n' \
        "$(date -u +%F)" "$OS" "$(uname -m)" "$RSS_TOOL" "${FASAD_THREADS:-2}" "$SPIKE_THREADS"
    printf 'профиль сборки: [profile.release] (lto=fat, codegen-units=1) — docs/model-audit.md §9 п.3\n'
fi
rm -f "$ROWS_FILE"

echo "OK|measure-rss завершён|method=$RSS_TOOL"
