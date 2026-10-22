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
# Контракт dylib (docs/model-audit-weights.md §W2 п.1, docs/model-audit.md §8; нить N6 ревью #32): сборка И
# прогон полных каскадов — ОДНИМИ env `ORT_PREFER_DYNAMIC_LINK=1
# ORT_LIB_PATH=…`, иначе ort-sys уходит на pyke-статику 1.23 + copy-dylibs
# затирает шейды рядом с бинарём = SIGSEGV 139.
#
# Выход: строки `RSS|<контур>|<точка>|<значение MiB>|<метод>` и вердикт
# `BUDGET|<контур>|ok|peak_max_mib=…|budget_mib=1843.2` (SPEC §1 ≤1.8 ГБ =
# 1843.2 MiB). Вердикт считается по КОНСЕРВАТИВНОМУ пику — бэджет
# safety-critical, см. docs/model-audit-weights.md §W2.6 п.5.
#
# Контур `--full` (issue #170 а): прогон харнеса повторяется N раз
# (`FASAD_RSS_REPEATS`, default 3) и печатает ДВЕ свёртки —
# `RSS|full|peak_median|…` (репрезентативное число в документ: первичка #168
# показала полосу одиночных срезов до 550 MiB на ОДНОМ sha, одиночное число
# среди неё не является числом прогона) и `RSS|full|peak_max|…`
# (консервативная свёртка). ВЕРДИТ GATE — по peak_max, семантика гейта не
# менялась; медиана в гейт не входит никогда.
#
# Код возврата — часть контракта (класс false-green «print-only landing test»,
# реестр 15/18): вердикт OVER обязан валить скрипт, а не только печататься.
#   0 = все прогнанные контуры дали ok;
#   1 = хотя бы один контур дал OVER (строка `BUDGET|…|OVER|…` + причина в stderr)
#       ЛИБО отказ прогона (die);
#   2 = метод замера не реализован на этой ОС (docs/release.md §RAM п.5) ЛИБО
#       артефакт непригоден (preflight-зуб контура --full, §RAM п.7, issue #170 б;
#       с #178 — ТРЕТИЙ носитель: битый env гейта, BUDGET_MIB / FASAD_RSS_REPEATS,
#       §RAM п.11 б: строка «артефакт непригоден: <имя>»).
#       Ветка печатает причину в stderr и выходит двойкой НАПРЯМУЮ, минуя die:
#       die = exit 1, через неё обещание «2» было бы ложным (ревью #98 R1:
#       промер шимом `uname` = FreeBSD давал rc=1 при трёх местах,
#       утверждавших rc=2 — шапка, release.yml:111, docs §RAM п.5).
#       С #170 б у двойки появился ВТОРОЙ носитель (preflight spike-бинаря на
#       dylib-контракт §W2 п.1): тот же класс «артефакт непригоден, прогон не
#       начинался», §RAM п.7.
# Прежняя версия печатала OVER и выходила rc=0: шаг «RAM-гейт» в
# .github/workflows/release.yml зеленел при превышении бюджета (первичка: die()
# была единственным выходом с кодом, а verdict-строки в run_cascade0/run_full
# уходили только через emit_line).
#
# Полнота вывода при провале (ревью #98 п.2): хвост `OK|measure-rss
# завершён|gate=ok|…` (успех) / `FAIL|measure-rss завершён|gate=OVER|…`
# (провал) печатается на ОБОИХ ветках ПЕРЕД выходом: stdout проваленного
# прогона = stdout успешного с точностью до вердикт-строк (`BUDGET|…` + сам
# хвост), а не обрезан. `rc=1` вместо хвоста = нечем разбирать.
#
# rc не зависит от пути вызова (ревью #98 п.3): `just measure-rss` (рецепт
# зовёт `bash scripts/measure-rss.sh $@` под `set -euo pipefail`) и прямой
# запуск скрипта дают одинаковый rc — промер 21.10, обе ветки rc=1 при
# BUDGET_MIB=0.001. Флаг GATE_FAIL доходит до конца файла, потому что
# run_cascade0/run_full вызываются НАПРЯМУЮ (:419-420, переснято grep'ом
# 21.10), а не из командной подстановки; на случай refactor-в-подстановку
# добавлен бэкстоп — вердикт перечитывается из файл-артефакта (блок в конце).
# МЕРИТЬ rc надо от самой проверяющей команды (`cmd; echo $?`), а не от хвоста
# пайпа: `cmd | tail -1`/`| tee` отдаёт rc последнего звена = 0 при rc=1
# скрипта (промер 21.10: та же строка OVER, `$?` = 0) — ложно-красный диагноз
# «зуба нет» из способа замера, а не из кода.
#
# use: scripts/measure-rss.sh [--cascade0] [--full] [--skip-build]
# env: FASAD_RSS_TARGET (default target/release), ORT_DIR (default
#      $HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0), FASAD_RSS_WARMUP
#      (число прогревающих /v1/analyze, default 3), BUDGET_MIB (default 1843.2;
#      рычаг бюджета — нужен, чтобы зуб гейта промерялся живым прогоном:
#      `BUDGET_MIB=0.001 … → rc=1` без изменения кода). Значение валидируется
#      по `^[0-9]+([.][0-9]+)?$`; мусор = rc=1 с именем переменной (fail-open
#      закрыт ревью #98 R2: awk-сравнение «abc» = 0 = зелёный гейт), и
#      FASAD_RSS_REPEATS (default 3 — число повторов контура --full, валидация
#      по `^[1-9][0-9]*$`, мусор = rc=1; issue #170 а)

set -euo pipefail

TARGET_DIR="${FASAD_RSS_TARGET:-target/release}"
ORT_DIR="${ORT_DIR:-$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0}"
WARMUP="${FASAD_RSS_WARMUP:-3}"
# Бюджет SPEC §1: ≤1.8 ГБ = 1843.2 MiB. Рычаг из окружения оставлен не ради
# игры цифрами, а ради промера зуба: гейт, который нельзя посадить без правки
# кода, неотличим от гейта, у которого зуба нет (класс false-green «print-only
# landing test», реестр 15/18). Значение по умолчанию = контракт SPEC; CI его
# не переопределяет.
BUDGET_MIB="${BUDGET_MIB:-1843.2}"
# OVER ЛЮБОГО прогнанного контура = провал гейта. Флаг ставится в месте
# вердикта, а выходит скрипт в конце: вывод всех контуров обязан остаться
# целым (он артефакт прогона, из него генерируются --doc-rows).
GATE_FAIL=0
# Пул потоков орт-харнеса (рюлинг оператора 21.10: не грузить CPU ноута; spike
# по умолчанию берёт 4, spike.rs:158). Это собственный рычаг харнеса:
# OMP_NUM_THREADS на вендорном libonnxruntime osx-arm64 инертен (первичка
# ревью #73: otool/strings), поэтому рулим флагом `--threads`.
SPIKE_THREADS="${FASAD_SPIKE_THREADS:-2}" # SPEC §1 п.1: «<2 ГБ», бюджет-гейт §5.6 = 1.8 GiB
# Число повторов t2-прогона контура --full (issue #170 а). Первичка #168:
# полоса ОДИНОЧНЫХ срезов на ОДНОМ sha до 550 MiB (e02c203 = 870.3 / 1420.9),
# т.е. одиночное число = lucky slice и в документ не пишется. Значение по
# умолчанию 3 (медиана нечётной выборки = средний элемент, без арифметики);
# рычаг из env — ради экономии CPU на разведочных прогонах и ради промера
# свёрток (`FASAD_RSS_REPEATS=1` = одна точка, медиана = max = сам прогон).
# Значение валидируется ниже, ПОСЛЕ определения `die` (там же, где валидация
# BUDGET_MIB): промер правки #170 показал, что вызов `die` до её определения
# даёт `command not found` и rc=127 — «отказ с именем переменной» превращается
# в отказ без причины.
FULL_REPEATS="${FASAD_RSS_REPEATS:-3}"
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

# die_env <имя-переменной> — отказ на битом env гейта. rc=2, а не rc=1
# (решение #178, docs/release.md §RAM п.11 б с 22.10): класс = «артефакт
# непригоден, промер не начинался» (п.11 а: ОС-шим, п.7: preflight dylib),
# НЕ «прогон был и не прошёл». Прежний rc=1 подменял смысл: у OVER (превышение
# бюджета) тоже rc=1, и «не промерено» становилось неотличимо от «не прошло»
# ровно там, где оно опаснее — при превышении «не промерено» читается как
# «промерено и завалено», т.е. релиз идёт дальше по несуществующему промеру.
# Через die нельзя: die = exit 1 (ревью #98 R1 — та же причина, что у ОС-ветки).
die_env() {
    printf 'measure-rss: ОШИБКА: артефакт непригоден: %s\n' "$1" >&2
    exit 2
}

# Валидация BUDGET_MIB (ревью #98 R2). Без неё рычаг бюджета был FAIL-OPEN:
# вердикт считает awk (`p <= b`); «abc» — не strnum, сравнение становится
# лексикографическим: «3.4» <= «abc» истинно ('3' < 'a'), т.е.
# BUDGET_MIB=abc давало `BUDGET|cascade0|ok|budget_mib=abc` при rc=0 —
# опечатка в env (разделитель в «1,843.2») зелёнила релизный контур. Политика
# проекта: мусор в числовом env = отказ, а не молчаливый ноль (docs/release.md
# §RAM п.11 б). Отказ = rc=2 через die_env (решение #178): причина — сломанный
# env, артефакт непригоден, прогона не было; путать это с OVER (rc=1 + слово
# OVER в stderr = «промерен и превысил») нельзя.
# Формат = строка цифр с одной опциональной десятичной точкой: отрицательное,
# пустое, «1.», «.5», «1.2.3», «1e3» — отказ.
case "$BUDGET_MIB" in
    '' | *[!0-9.]* | .* | *. | *.*.*)
        die_env "BUDGET_MIB=$BUDGET_MIB: не число (ожидается вид 1843.2 — целое или десятичное, без разделителей и знака)"
        ;;
esac

# Валидация FASAD_RSS_REPEATS — тем же приёмом, что BUDGET_MIB выше (ревью #98
# R2: fail-open закрыт отказом с именем переменной, а не молчаливым фолбэком;
# rc=2 = тот же класс «артефакт непригоден», решение #178).
# Формат — натуральное число `^[1-9][0-9]*$`: ноль, «1.5», «-1», «abc», пустое =
# отказ. Мусор здесь дороже мусора в бюджете: `N=abc` в `[ "$i" -le "$N" ]`
# дал бы арифметическую ошибку bash (rc=1 без причины), `N=0` — ноль прогонов,
# медиану и max по ПУСТОЙ выборке и зелёный вердикт по несуществующему промеру
# (ложно-зелёный гейт, реестр 15/18).
case "$FULL_REPEATS" in
    '' | *[!0-9]* | 0*)
        die_env "FASAD_RSS_REPEATS=$FULL_REPEATS: не натуральное число (ожидается 1, 2, 3 … — целое положительное)"
        ;;
esac

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

# gate_fail_if_over <verdict> <контур> <peak> — ЗУБ гейта: вердикт OVER
# поднимает GATE_FAIL, а скрипт в конце выходит rc=1 (до этой правки OVER
# только печатался, и шаг release.yml «RAM-гейт каскада-0» зеленел при
# превышении бюджета — класс false-green «print-only landing test», реестр
# 15/18). Вызывается ПОСЛЕ emit_line: при провале вывод обязан быть полным
# (строки RSS + BUDGET = артефакт прогона), rc=1 без них бесполезен для
# разбора. Причина пишется в stderr словом OVER + числами — её нельзя спутать
# с die-путём (там текст про бинарь/демона/прогрев, слова OVER нет).
gate_fail_if_over() {
    if [ "$1" = "OVER" ]; then
        GATE_FAIL=1
        printf 'measure-rss: ОШИБКА: RAM-гейт: контур %s OVER: peak=%s MiB > budget=%s MiB (SPEC §1 ≤1.8 ГБ)\n' \
            "$2" "$3" "$BUDGET_MIB" >&2
    fi
}

usage() {
    cat <<'EOF'
использование: scripts/measure-rss.sh [опции]

  --cascade0   контур каскада-0: релизный бинарь демона (default, если не указано ничего)
  --full       контур полного каскада: харнес spike --arb --lockr (нужны веса + dylib ORT);
               гонит FASAD_RSS_REPEATS повторов (default 3), печатает peak_median
               (в документ) и peak_max (в гейт) и требует dylib-контракт §W2 п.1
               на spike-бинаре (голый контур = rc=2, лечится just build-ort)
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
        # rc=2 = контракт шапки и docs/release.md §RAM п.5: «метод не реализован»
        # отделён от «прогон не удался» (die = exit 1). Через die эта ветка
        # выдавала rc=1, т.е. все три места, обещавшие «2», врали (ревью #98 R1).
        printf 'measure-rss: ОШИБКА: OS=%s: метод замера не реализован (реализованы Darwin/Linux)\n' "$OS" >&2
        exit 2
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
    # peak = max по всем точкам контура — консервативный вердикт
    # (docs/model-audit-weights.md §W2.6 п.5).
    value="$1"
    if [ -z "${PEAK:-}" ] || awk -v a="$value" -v b="$PEAK" 'BEGIN { exit !(a > b) }'; then
        PEAK="$value"
    fi
}

# median_of <число> … — медиана по числовым аргументам, формат %.1f.
# Нечётное N = средний элемент; чётное = среднее двух средних — по числам
# прогона, арифметика ровно из того, что напечатали повторы (rule: выведенное
# число обязано называть схему; здесь схема = N-повторов-медиана, N в INFO).
median_of() {
    printf '%s\n' "$@" | sort -g | awk '
        { v[NR] = $1 }
        END {
            if (NR == 0) exit
            printf "%.1f", (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
        }'
}

# max_of <число> … — max по числовым аргументам, формат %.1f. Консервативная
# свёртка повторов того же контура: семантика «peak = max по точкам» (шапка
# скрипта, §W2.6 п.5) просто поднимается на уровень повторов — гейт обязан
# видеть худший срез, медиана гейтом быть не может (issue #170 а:
# полоса одиночных срезов до 550 MiB на ОДНОМ sha, первичка #168).
max_of() {
    printf '%s\n' "$@" | sort -g | awk '
        { if (m == "" || $1 > m) m = $1 }
        END { if (m != "") printf "%.1f", m }'
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
    gate_fail_if_over "$verdict" cascade0 "$PEAK"
    PEAK=""
}

# ── контур 2: полный каскад 1–2 (харнес spike, орт-сессии) ───────────────────

# preflight_spike_ort <путь-к-бинарю> — ЗУБ против ложно-красного контура
# (issue #170 б, первичка #168-бисек f4945c93, signal B).
#
# Причина зуба. Контур `--full` берёт ГОТОВЫЙ `target/release/examples/spike`
# и НЕ пересобирает его (`--skip-build`, да и без него строка сборки ниже
# трогает только guard-daemon). Бинарь, собранный «голым» `cargo build
# --release --example spike --features ort-inference` БЕЗ env
# `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=…` (контракт
# docs/model-audit-weights.md §W2 п.1), слинкован со СТАТИКОЙ pyke 1.23: в его
# динамическом графе (`otool -L`) строки `libonnxruntime` нет, а сам орт вшит в
# бинарь. Такой бинарь в прогоне даёт SIGSEGV rc=139 — контур краснеет по
# причине сборки, а не по RAM, и в реестре ложно-красных это ровно «молча взять
# чужой бинарь».
#
# Зуб ДВУХНОГИЙ (промер 22.10, артефакты в теле PR #170):
#   нога 1 (RED): в бинаре есть статика pyke — маркер `onnxruntime/core/session`
#     (путь из строк вендорного артефакта ort-sys; `LC_ALL=C grep -a` по бинарю:
#     голый spike = 4 совпадения, build-ort spike = 0, релизный каскад-0 = 0).
#     Есть статика + нет динамического dylib = голый контур → rc=2.
#   нога 2 (GREEN, молчаливая): динамического dylib нет И статики нет = бинарь
#     орта не содержит ВООБЩЕ (релизный каскад-0, `just release-build`: фича
#     `ort-inference` выключена, модельного пути в демоне нет —
#     crates/guard-daemon/src/pipeline.rs). Это НЕ голый контур, а другой
#     продукт: краснеть ему нельзя — релизный CI-контур (`just measure-rss
#     --skip-build`, release.yml:135) ходит сюда же и Today green именно потому,
#     что каскад-0 в орте не нуждается. Одноногая проверка («нет dylib =
#     красный») дала бы ложно-красный релизный гейт — промер этой правки на
#     релизном бинаре: rc=2, т.е. релиз перестал бы собираться.
#
# Зуб спрашивает САМ бинарь, а не env вызывающего: `ORT_PREFER_DYNAMIC_LINK`
# в окружении прогона может стоять любым, вердикт обязан зависеть от артефакта.
# Формулировка отказа называет лечимое действие (`just build-ort`), а не
# «прогон не удался» (kernel-закон «отказ обязан называть истинную причину»).
#
# Реализация: otool — штатный читатель Mach-O-графов на macOS (первичка ревью
# #73: тот же инструмент мерял `OMP_NUM_THREADS`-инертность вендорного dylib);
# на Linux — `readelf -d`, при его отсутствии `ldd`. Инструмента нет = явный
# WARN-skip, а не провал: краснеть от отсутствия утилиты = тот же ложно-красный
# класс, который зуб закрывает.
#
# Код возврата вызывающего: refusal = rc=2 — тот же класс, что «метод замера не
# реализован» (шапка скрипта, docs/release.md §RAM п.7): артефакт непригоден,
# прогон не начинался. die (rc=1) зарезервирован за «прогон не удался», путать
# сборочный диагноз с провалом прогона нельзя.
preflight_spike_ort() {
    bin="$1"
    # Нога 1: статика pyke в бинаре. `LC_ALL=C` — grep по бинарю с локалью
    # UTF-8 даёт «binary file matches» вместо кода совпадения на некоторых
    # реализациях; `-a` treating binary as text.
    if LC_ALL=C grep -qa 'onnxruntime/core/session' "$bin" 2>/dev/null; then
        static_pyke=1
    else
        static_pyke=0
    fi
    deps=""
    case "$OS" in
        Darwin)
            if command -v otool >/dev/null 2>&1; then
                deps="$(otool -L "$bin" 2>/dev/null || true)"
            else
                printf 'WARN|full|preflight=partial|otool нет в PATH — динамическая нога зуба НЕ промерена (статическая нога жива: pyke-статика ловится grep по бинарю)\n'
            fi
            ;;
        Linux)
            if command -v readelf >/dev/null 2>&1; then
                deps="$(readelf -d "$bin" 2>/dev/null || true)"
            elif command -v ldd >/dev/null 2>&1; then
                deps="$(ldd "$bin" 2>/dev/null || true)"
            else
                printf 'WARN|full|preflight=partial|ни readelf, ни ldd нет в PATH — динамическая нога зуба НЕ промерена (статическая нога жива)\n'
            fi
            ;;
    esac
    dynamic_ort=0
    [ -n "$deps" ] && printf '%s\n' "$deps" | grep -qi 'libonnxruntime' && dynamic_ort=1
    if [ "$dynamic_ort" -eq 1 ]; then
        printf 'INFO|full|preflight=ort_dynamic|бинарь линкуется на динамический libonnxruntime (контракт §W2 п.1 выполнен)\n'
        return 0
    fi
    if [ "$static_pyke" -eq 0 ]; then
        printf 'INFO|full|preflight=no_ort|бинарь орта не содержит (ни динамики, ни pyke-статики) — это релизный каскад-0, зуб его НЕ краснит\n'
        return 0
    fi
    printf 'measure-rss: ОШИБКА: spike собран голым контуром (pyke-статика, §W2 п.1) — just build-ort\n' >&2
    printf 'measure-rss: ОШИБКА: в %s вшита статика pyke (маркер onnxruntime/core/session) и нет динамического libonnxruntime — прогон дал бы SIGSEGV rc=139 (реестр ложно-красных: молча брать чужой бинарь = ложно-красный RAM-гейт)\n' "$bin" >&2
    return 2
}

# run_full_once — ОДИН прогон харнеса; печатает METRIC/BUDGET-строки харнеса и
# пишет в артефакт ($ROWS_FILE) ровно одну строку `RSS|full|peak_both_models|…`,
# которую видят `--doc-rows` и парсер повторов (issue #170 а: N повторов не
# должны размножать артефакт-строки — строка одна, их значения собираются в
# медиану и max).
# Возвращает через глобалы RUN_PEAK (число MiB) и RUN_RC (rc харнеса):
# 0 = прогон удался, 1 = прогон умер (харнес не напечатал peak / упал).
run_full_once() {
    ex="$1"
    lib="$2"
    peak=""
    out="$(mktemp)"
    set +e
    ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH="$ORT_DIR/lib" \
        "$ex" --arb-budget --arb --lockr --threads "$SPIKE_THREADS" >"$out" 2>&1
    RUN_RC="$?"
    set -e
    grep -E '^(METRIC\|rss|BUDGET\||ERROR)' "$out" || true
    if [ "$RUN_RC" -ne 0 ]; then
        printf 'measure-rss: ОШИБКА: харнес.full exited rc=%s (см. docs/model-audit-weights.md §W2: SIGSEGV 139 = нарушен dylib-контракт)\n' "$RUN_RC" >&2
        rm -f "$out"
        RUN_PEAK=""
        return 1
    fi
    peak="$(grep -oE 'METRIC\|rss_peak_mib_both_models\|[0-9.]+' "$out" | tail -1 | cut -d'|' -f3)"
    rm -f "$out"
    if [ -z "$peak" ]; then
        printf 'measure-rss: ОШИБКА: харнес не напечатал rss_peak_mib_both_models (контракт METRIC нарушен)\n' >&2
        RUN_PEAK=""
        return 1
    fi
    RUN_PEAK="$peak"
    emit_line "RSS|full|peak_both_models|$peak|spike task_info TASK_VM_INFO.internal (macOS) / VmRSS (Linux)"
    return 0
}

run_full() {
    ex="$TARGET_DIR/examples/spike"
    [ -x "$ex" ] || die "нет харнеса $ex — собери: just build-ort (spike --features ort-inference, dylib-контракт)"
    [ -d "$ORT_DIR/lib" ] || die "нет каталога dylib ORT: $ORT_DIR/lib (docs/model-audit.md §8 п.3)"
    lib="$(find "$ORT_DIR/lib" -maxdepth 1 -name 'libonnxruntime*.dylib' -o -maxdepth 1 -name 'libonnxruntime*.so' 2>/dev/null | head -1)"
    [ -n "$lib" ] || die "в $ORT_DIR/lib нет libonnxruntime* (docs/model-audit.md §8 п.3)"

    # ЗУБ (issue #170 б) — ДО прогонов: дешевле сдохнуть на сборочном диагнозе,
    # чем открутить N прогонов и выдать rc=139 как «RAM-проблему».
    preflight_spike_ort "$ex" || exit 2

    # N повторов (issue #170 а, первичка #168: на ОДНОМ sha полоса одиночных
    # срезов до 550 MiB — e02c203 870.3/1420.9; одиночное число посреди полосы
    # не является числом прогона). Каждый повтор = полный прогон харнеса;
    # свёртки ДВЕ и обе печатаются:
    #   peak_median — репрезентативное число в документ (rule kernel: медиана
    #     прогонов, не lucky slice);
    #   peak_max    — ГЕЙТ: консервативная свёртка, семантика не меняется
    #     (бэджет safety-critical, §W2.6 п.5; v0.1.0-бюджет = консервативный
    #     max, решение оператора #168).
    # Повтор не обязан быть зелёным: прогон умерший = отказ контура (rc=1), а не
    # «медиана по выжившим» — медиана по N-1 при N=3 была бы подменой выборки.
    # Массив, а не строка: свёртки вызываются как `median_of "${PEAKS[@]}"`,
    # т.е. каждое число = отдельный аргумент. Строка-накопитель требовала бы
    # НЕЗАКАВЫЧЕННОГО расширения (`median_of $peaks`), а это SC2086 — и нога CI
    # `BASH_SHELLCHECK` (MegaLinter, lint.yml:37, без `-S severity`) краснеет от
    # info-класса ровно как от warning (промер 22.10 локально: `shellcheck -x`
    # без `-S` даёт 3 × SC2086 на строке-накопителе).
    PEAKS=()
    i=1
    while [ "$i" -le "$FULL_REPEATS" ]; do
        printf 'INFO|full|run=%s/%s|harness=spike --arb-budget --arb --lockr --threads %s|ort_dylib=%s\n' \
            "$i" "$FULL_REPEATS" "$SPIKE_THREADS" "$lib"
        if run_full_once "$ex" "$lib"; then
            PEAKS+=("$RUN_PEAK")
        else
            die "прогон $i/$FULL_REPEATS не удался (rc=$RUN_RC) — свёртка по неполной выборке невозможна"
        fi
        i=$((i + 1))
    done

    [ "${#PEAKS[@]}" -eq "$FULL_REPEATS" ] ||
        die "собрано ${#PEAKS[@]} чисел повторов из $FULL_REPEATS — свёртка по неполной выборке невозможна"
    peak_median="$(median_of "${PEAKS[@]}")"
    peak_max="$(max_of "${PEAKS[@]}")"
    [ -n "$peak_median" ] && [ -n "$peak_max" ] ||
        die "свёртка дала пустое число (пики: ${PEAKS[*]})"
    # Список срезов через `;` — разделитель полей строки здесь `|`, а `;` — он же
    # терминатор команды в shell: вставлять в вывод список, собранный из чисел
    # прогона, нельзя (строка с `;` в выводе = подарок тому, кто её eval'ом
    # прочитает). Формат `1419.6 1789.7 1790.5`, разделитель — пробел.
    # `repeats=N` и ровно N чисел в `slices=` — парность поля проверяется
    # глазами по строке (parser'ы строк здесь нет, и заводить его под вывод =
    # вторая ложь при рассинхроне).
    printf 'INFO|full|repeats=%s|slices=%s\n' "$FULL_REPEATS" "${PEAKS[*]}"

    # Точка-значения (в артефакт → в --doc-rows): медиана и max отдельными
    # строками, обе с методом. Прежнее имя `peak_both_models` НЕ переиспользуется
    # под медиану: у него задокументированная семантика «пик одного прогона»
    # (docs/release.md §RAM п.6), подмена смысла под прежним именем = ложно
    # зелёное чтение старых строк из новых.
    emit_line "RSS|full|peak_median|$peak_median|median of $FULL_REPEATS spike runs, task_info TASK_VM_INFO.internal (macOS) / VmRSS (Linux)"
    emit_line "RSS|full|peak_max|$peak_max|max of $FULL_REPEATS spike runs (гейт-свёртка), task_info TASK_VM_INFO.internal (macOS) / VmRSS (Linux)"
    # Вердикт = по max, не по медиане (шапка скрипта: «вердикт считается по
    # КОНСЕРВАТИВНОМУ пику»; поле в строке так и названо — peak_max_mib).
    verdict="$(awk -v p="$peak_max" -v b="$BUDGET_MIB" 'BEGIN { print (p <= b) ? "ok" : "OVER" }')"
    emit_line "BUDGET|full|$verdict|peak_max_mib=$peak_max|peak_median_mib=$peak_median|repeats=$FULL_REPEATS|budget_mib=$BUDGET_MIB|tool=spike METRIC (in-process)"
    gate_fail_if_over "$verdict" full "$peak_max"
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
    awk -F"|" '$1 == "BUDGET" {
        s = sprintf("`BUDGET|%s|%s", $2, $3)
        for (i = 4; i <= NF; i++) s = s sprintf("|%s", $i)
        print s "`"
    }' "$ROWS_FILE"
    # Полоса срезов (issue #170 а): все N чисел прогона — то, что запрещает
    # называть одиночный срез числом прогона (первичка #168). Числа идут через
    # запятую: `;` в выводе = терминатор команды для любого, кто строку
    # eval'ом прочитает.
    awk -F"|" '$1 == "INFO" && $3 ~ /^repeats=/ {
        n = $3; sub(/^repeats=/, "", n)
        sl = $4; sub(/^slices=/, "", sl); gsub(/[[:space:]]+$/, "", sl); gsub(/[[:space:]]+/, " ", sl)
        printf "\nполоса срезов контура full: %s (N=%s, t2; медиана = peak_median, гейт = peak_max)\n", sl, n
    }' "$ROWS_FILE"
    printf '\n'
    printf '\nпромер: %s, ОС %s/%s, метод: %s; потоки: демон FASAD_THREADS=%s, харнес FASAD_SPIKE_THREADS=%s\n' \
        "$(date -u +%F)" "$OS" "$(uname -m)" "$RSS_TOOL" "${FASAD_THREADS:-2}" "$SPIKE_THREADS"
    printf 'профиль сборки: [profile.release] (lto=fat, codegen-units=1) — docs/model-audit.md §9 п.3\n'
fi
# Бэкстоп против пути вызова (ревью #98): GATE_FAIL живёт в оболочке и доходит
# до сюда только потому, что run_cascade0/run_full вызываются НАПРЯМУЮ
# (:419-420 — `[ "$RUN_CASCADE0" -eq 1 ] && run_cascade0`), а не из командной
# подстановки. Refactor вида `VAR=$(run_cascade0 …)` убил бы флаг вместе с
# подоболочкой, и гейт снова стал бы зелёным при OVER — ровно тот класс
# (print-only landing test, реестр 15/18), который закрывает этот PR. Зуб не
# должен зависеть от способа вызова функций: $ROWS_FILE — файл-артефакт, его
# пишет emit_line из ЛЮБОЙ оболочки (файл, не переменная подоболочки), поэтому
# вердикт перечитывается оттуда, а не из магического числа. Первичный механизм
# — флаг (он же несёт причину в stderr), бэкстоп — сверка с собственным
# артефактом прогона: два независимых пути к одному rc.
if [ "$GATE_FAIL" -eq 0 ] &&
    awk -F"|" '$1 == "BUDGET" && $3 == "OVER" { found = 1 } END { exit !found }' "$ROWS_FILE"; then
    GATE_FAIL=1
    printf 'measure-rss: ОШИБКА: RAM-гейт: вердикт OVER есть в артефакте прогона при сброшенном GATE_FAIL (функции уехали в командную подстановку?)\n' >&2
fi

if [ "$GATE_FAIL" -ne 0 ]; then
    # Зуб гейта: OVER = ненулевой код возврата САМОГО скрипта (шаг CI падает,
    # а не зеленеет). Строки RSS/BUDGET уже напечатаны — провал прогона должен
    # быть чем разбирать, в отличие от rc=1 без вывода.
    printf 'FAIL|RAM-гейт: вердикт OVER (строка BUDGET|…|OVER|… выше, числа — в stderr)\n' >&2
    # Хвост печатается ДО exit 1 (ревью #98 п.2): stdout проваленного прогона
    # обязан быть не короче stdout успешного — «rc=1 ПОСЛЕ полной печати», а не
    # «rc=1 вместо хвоста». Токен хвоста несёт вердикт: напечатать `OK|…` при
    # OVER означало бы завести новую ложно-зелёную поверхность (grep `^OK` по
    # stdout даёт OK при rc=1). Форма строки та же, поле `gate=` = OVER.
    printf 'FAIL|measure-rss завершён|gate=OVER|method=%s\n' "$RSS_TOOL"
    rm -f "$ROWS_FILE"
    exit 1
fi
rm -f "$ROWS_FILE"

printf 'OK|measure-rss завершён|gate=ok|method=%s\n' "$RSS_TOOL"
