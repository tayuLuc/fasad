#!/usr/bin/env bash
# scripts/verify-bundle.sh — проверка собранного релизного бандла (шаг 9).
#
# Зачем: `just dist` заканчивается на «архив создан». Гейт обязан отвечать на
# другой вопрос — «из архива достаётся рабочий демон?». Проверка идёт по
# распакованному архиву, а не по staging-каталогу: staging проходит те же
# chmod/cp, что и архиватор, но не проходит его упаковку (на Windows это
# Compress-Archive, и именно там теряются bit-прав исполняемости).
#
# Контракты, которые здесь проверяются (первичка — код, открытая в этой сессии):
#   /health  → {"version":…,"stage":"cascade-0-only","mode":…}
#              (crates/guard-daemon/src/http.rs, тест health_reports_version)
#   порт     → FASAD_PORT=0 = свободный, banner печатает реальный
#              (crates/guard-daemon/src/config.rs)
#   SHA256SUMS.txt → хэши всех файлов бандла, формат sha256sum -c
#              (scripts/make-bundle.sh)
#
# use: scripts/verify-bundle.sh [--dist DIR] [--keep] [--expect-version ТЕГ]
#
# --expect-version (он же env FASAD_EXPECT_VERSION) — зуб «тег == версия»
# (класс print-only-гейта без зуба в контуре публикации, находка ревью 21.10): в CI в
# job `dist` сюда приходит github.ref_name, и релиз v9.9.9 поверх
# [workspace.package] version = 0.1.0 краснеет ЗДЕСЬ, до публикации. До правки
# контур сверял архив↔демона (блок ver_archive/ver_health ниже) и тег↔коммит
# (`gh release create --verify-tag` в job `release`), а тег↔версию — никто:
# зелёный релиз с ассетами fasad-0.1.0-* под тегом v9.9.9 проходил весь контур.
# Локально аргумента нет → проверка ПЕЧАТАЕТ SKIPPED, а не молчит: молчаливый
# пропуск неотличим от выполненной проверки (тот же класс).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="dist"
KEEP=0
# Ожидание «тег == версия»: аргумент --expect-version ИЛИ env
# FASAD_EXPECT_VERSION (в CI job `dist` выставляет github.ref_name, и только
# на тег-триггере: на workflow_dispatch ref_name = имя ветки, не тег).
# Пусто = проверки нет, и это печатается строкой SKIPPED (см. ниже).
EXPECT_VERSION="${FASAD_EXPECT_VERSION:-}"

die() {
    # Контракт: die принимает ГОТОВУЮ строку. `printf '…%s\n' "$*"` форматирует
    # только первый аргумент, поэтому вызов вида `die "текст %s" "$x"` печатает
    # литеральный `%s` и сырое значение рядом (ревью #76, D1: в причине читалось
    # «…не найден бандлом: %s [{…}]»). shellcheck здесь слеп: SC2059 смотрит на
    # переменный формат, а формат-литерал с лишними аргументами не красит.
    printf 'verify-bundle: ОШИБКА: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dist)
            [ "$#" -ge 2 ] || die "--dist требует аргумент"
            DIST="$2"
            shift 2
            ;;
        --keep)
            KEEP=1
            shift
            ;;
        --expect-version)
            [ "$#" -ge 2 ] || die "--expect-version требует аргумент (имя тега, v0.1.0, или версия 0.1.0)"
            EXPECT_VERSION="$2"
            shift 2
            ;;
        -h | --help)
            echo "использование: scripts/verify-bundle.sh [--dist DIR] [--keep] [--expect-version ТЕГ]"
            exit 0
            ;;
        *)
            printf 'verify-bundle: ОШИБКА: неизвестный аргумент: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

# ── зуб «тег == версия» ──────────────────────────────────────────────────────
# Первичка версии — `[workspace.package] version` в Cargo.toml: из неё делают
# имя архива (scripts/make-bundle.sh) и версию в /health (crate-версия демона).
# Поэтому точка сверки одна, а обязана она ровно одному числу: тег, имя
# ассета и то, что печатает демон. Проверка идёт ДО распаковки и запуска
# демона: несоответствие тегов — это не вопрос бандла, его видно по метаданным
# за миллисекунды, и платить за отказ минутой прогона незачем.
if [ -n "$EXPECT_VERSION" ]; then
    cargo_ver="$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml \
        | sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$cargo_ver" ] || die "не извлёк версию из [workspace.package] в Cargo.toml"
    exp="${EXPECT_VERSION#v}"
    if [ "$exp" != "$cargo_ver" ]; then
        printf 'verify-bundle: ОШИБКА: тег %s (версия %s) ≠ [workspace.package] version = %s\n' \
            "$EXPECT_VERSION" "$exp" "$cargo_ver" >&2
        printf 'verify-bundle: ОШИБКА: ассеты выйдут fasad-%s-…, а релиз публикуется под %s. Поднимите версию в Cargo.toml (единый источник) или двигайте тег на коммит с этим подъёмом.\n' \
            "$cargo_ver" "$EXPECT_VERSION" >&2
        exit 1
    fi
    printf 'VERSION|ok|ref=%s|workspace.package=%s\n' "$EXPECT_VERSION" "$cargo_ver"
else
    # Пустое ожидание = проверки НЕТ. Печатается явно, молча не пропускается:
    # тишина неотличима от выполненной проверки (класс false-green, реестр).
    printf 'VERSION|SKIPPED|сверка тег↔версия не запрошена: передайте --expect-version ТЕГ (в CI её включает FASAD_EXPECT_VERSION=github.ref_name на тег-триггере)\n'
fi

# Архив ровно один: два архива в dist/ = два кандидата на релиз, и проверка
# не скажет, какой из них публикуется.
arch="$(find "$DIST" -maxdepth 1 -type f \( -name 'fasad-*.tar.gz' -o -name 'fasad-*.zip' \) | sort | head -2)"
n="$(printf '%s\n' "$arch" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "$n" -ne 1 ]; then
    printf 'verify-bundle: ОШИБКА: в %s найдено %s архивов fasad-*, нужен ровно один:\n%s\n' \
        "$DIST" "$n" "$arch" >&2
    exit 1
fi
arch="$(printf '%s\n' "$arch" | sed '/^$/d')"

tmp="$(mktemp -d)"
# Уборка за собой на ЛЮБОМ выходе — и на die, и на раннем отказе вне die (`set -e`
# на команде, которой нет в PATH, сигнал, таймаут): демон, поднятый скриптом, не
# имеет права пережить скрипт (осиротевший слушает порт, следующий прогон ловит
# AddrInUse), и убитый фон надо дожать, иначе зомби.
#
# Ловушка ОДНА: в bash второй `trap … EXIT` заменяет первый, а не дополняет —
# до ревью #76 (F6) здесь был trap, убирающий только $tmp, а демона убивал
# каждый die-путь сам (пять копий `kill "$pid"`), поэтому unplanned-отказ
# оставлял демон живым. Функция идемпотентна: двойной kill/wait безопасен.
cleanup() {
    if [ -n "${pid:-}" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    # Трей-бинарь (#128) поднимается после п.3: на любом раннем отказе ветки
    # трея (die между его стартом и kill) cleanup обязан убрать и его.
    if [ -n "${tray_pid:-}" ]; then
        kill "$tray_pid" 2>/dev/null || true
        wait "$tray_pid" 2>/dev/null || true
    fi
    if [ "$KEEP" -eq 0 ]; then
        rm -rf "$tmp"
    else
        printf 'verify-bundle: бандл оставлен в %s\n' "$tmp" >&2
    fi
    return 0
}
# shellcheck disable=SC2329 # вызывается ловушкой EXIT, а не из тела скрипта
trap cleanup EXIT

printf 'verify-bundle: архив %s\n' "$arch"
case "$arch" in
    *.tar.gz) tar -xzf "$arch" -C "$tmp" ;;
    *.zip)
        # Windows-раннер (git bash) обязан распаковать архив тем же семейством
        # инструментов, что его собрал: Expand-Archive. Python — НЕТ: AGENTS п.6
        # не пускает Python в контур сборки, а на windows-2022 `python3` в
        # Git Bash не гарантирован. Порядок: unzip (есть на macOS/Linux-разработке)
        # → powershell (Windows) → явный отказ.
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$arch" -d "$tmp"
        elif command -v powershell.exe >/dev/null 2>&1; then
            powershell.exe -NoProfile -Command \
                "Expand-Archive -LiteralPath '$(cygpath -w "$arch" 2>/dev/null || printf '%s' "$arch")' -DestinationPath '$(cygpath -w "$tmp" 2>/dev/null || printf '%s' "$tmp")'"
        else
            printf 'verify-bundle: ОШИБКА: нет ни unzip, ни powershell.exe — архив %s нечем распаковать\n' "$arch" >&2
            exit 1
        fi
        ;;
    *)
        printf 'verify-bundle: ОШИБКА: неизвестный формат архива: %s\n' "$arch" >&2
        exit 1
        ;;
esac

# Стад = каталог, в котором лежит bin/. Порядок поиска (промер 21.10 на
# синтетическом «плоском» архиве: `tar -czf … .` из стейджа даёт `./bin/…`, и
# наивный «первый каталог верхнего уровня» натыкается на $tmp/bin и теряет
# бинарь → FILE|missing):
#   1) названный каталог fasad-* верхнего уровня = штатный tar.gz layout;
#   2) корень распаковки = плоский layout (Compress-Archive без верхнего каталога);
#   3) любой каталог глубже, где есть bin/;
#   4) иначе — битый архив, красным.
stage="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d -name 'fasad-*' | head -1)"
if [ -n "$stage" ] && [ ! -d "$stage/bin" ]; then
    stage=""
fi
if [ -z "$stage" ] && [ -d "$tmp/bin" ]; then
    printf 'WARN|stage=archive-root (верхнего каталога нет, содержимое в корне)\n'
    stage="$tmp"
fi
if [ -z "$stage" ]; then
    for cand in $(find "$tmp" -mindepth 2 -maxdepth 3 -type d | sort); do
        if [ -d "$cand/bin" ]; then
            printf 'WARN|stage=%s (найден по наличию bin/)\n' "$cand"
            stage="$cand"
            break
        fi
    done
fi
if [ -z "$stage" ]; then
    printf 'verify-bundle: ОШИБКА: в архиве нет каталога с bin/ (битый состав)\n' >&2
    exit 1
fi

# 1. Состав бандла.
for f in bin/fasad bin/fasad.exe LICENSE README.md schema.default.json \
    THIRD-PARTY-LICENSES.txt SHA256SUMS.txt; do
    if [ -f "$stage/$f" ]; then
        printf 'FILE|ok|%s\n' "$f"
    elif printf '%s\n' "$f" | grep -q '\.exe$'; then
        : # экзешник называется fasad, не fasad.exe
    elif [ "$f" = "bin/fasad" ] && [ -f "$stage/bin/fasad.exe" ]; then
        printf 'FILE|ok|bin/fasad.exe\n'
    else
        printf 'FILE|missing|%s\n' "$f" >&2
        exit 1
    fi
done

# 2. Хэши: сверка SHA256SUMS.txt на распакованных файлах (не на staging).
if command -v shasum >/dev/null 2>&1; then
    ( cd "$stage" && shasum -a 256 -c SHA256SUMS.txt )
else
    ( cd "$stage" && sha256sum -c SHA256SUMS.txt )
fi

# 3. Бинарь извлекается, запускается и отвечает. Порт = 0 (свободный),
#    адрес берётся из banner'а.
bin="$stage/bin/fasad"
[ -x "$bin" ] || bin="$stage/bin/fasad.exe"
[ -x "$bin" ] || {
    printf 'verify-bundle: ОШИБКА: bin/fasad не исполняемый (потеряны права при упаковке)\n' >&2
    exit 1
}
log="$(mktemp)"
FASAD_PORT=0 "$bin" >"$log" 2>&1 &
pid="$!"
port=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    port="$(sed -n 's#.*listening on http://127\.0\.0\.1:\([0-9]*\)/health.*#\1#p' "$log" | head -1)"
    [ -n "$port" ] && break
    sleep 0.3
done
[ -n "$port" ] && [ "$port" != "0" ] || {
    printf 'verify-bundle: ОШИБКА: демон не поднялся, banner:\n' >&2
    cat "$log" >&2
    exit 1
}

health="$(curl -sS --fail --max-time 5 "http://127.0.0.1:${port}/health")"
printf 'HEALTH|%s\n' "$health"
# Контур бандла метится в двух местах: имя артефакта (-cascade-0) и /health.
# Расхождение = бандл подписан не тем, чем является.
printf '%s' "$health" | grep -q '"stage":"cascade-0-only"' || {
    die "/health не подтверждает контур cascade-0-only"
}
ver_archive="$(printf '%s' "$(basename "$arch")" | sed -n 's/^fasad-\([0-9][0-9.]*\)-.*/\1/p')"
ver_health="$(printf '%s' "$health" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ "$ver_archive" = "$ver_health" ] || {
    printf 'verify-bundle: ОШИБКА: версия архива %s ≠ версия демона %s\n' \
        "$ver_archive" "$ver_health" >&2
    exit 1
}
if [ -n "$EXPECT_VERSION" ]; then
    # Третья точка того же ожидания: версия, вкомпилированная в бинарь из
    # архива (crate-версия guard-daemon). Тег обязан совпасть и с ней, иначе
    # «Cargo.toml подняли после сборки» даёт свежий тег над старым бинарём.
    [ "$exp" = "$ver_health" ] || {
        die "тег $EXPECT_VERSION (версия $exp) ≠ версия демона в бандле $ver_health"
    }
    printf 'VERSION|ok|ref=%s|daemon=%s\n' "$EXPECT_VERSION" "$ver_health"
fi

# 4. Анализ прогона: спаны возвращаются, policy-заголовок живёт. Поле спана —
#    `entity_type` (промер живого ответа /v1/analyze 21.10:
#    `[{"entity_type":"inn","start":…,"score":1.0,"class":"inn","source":"checksum_rf",
#       "verdict":"mask_surrogate","validator":"inn10"}]`), а не `category`/`span_id`.
req='{"text":"ИНН 7707083893, телефон +79161234567, паспорт 45 09 123456"}'
# `curl --fail` при HTTP-ошибке возвращается 22, а под `set -euo pipefail` это
# обрывает скрипт на присваивании без единой строки диагностики (тот же класс,
# что у счётчика спанов ниже). Причина отказа обязана называться самим скриптом.
analyze="$(curl -sS --fail --max-time 10 -H 'content-type: application/json' \
    -H 'x-guard-policy: mask' -X POST "http://127.0.0.1:${port}/v1/analyze" -d "$req")" || {
    die "/v1/analyze от бандла не ответил (HTTP-ошибка или таймаут), порт $port"
}
# Голый `grep -o` без совпадения возвращается 1 и под pipefail убивает скрипт на
# присваивании: при нуле спанов собственное сообщение «вернул пустой список
# спанов» не печаталось (позитивный контроль 21.10 — ИНН с битой чексуммой,
# rc=1 без диагностики). Ноль — законное значение счётчика.
spans="$(printf '%s' "$analyze" | { grep -o '"entity_type"' || true; } | wc -l | tr -d ' ')"
printf 'ANALYZE|spans=%s\n' "$spans"
[ "$spans" -ge 1 ] || {
    die "/v1/analyze вернул пустой список спанов: $analyze"
}
# Счётчик спанов сам по себе слаб (ревью #76, F5): зелёным остаётся любой
# мусорный спан, а регресс ИНН-валидатора — главного цифрового класса нашей
# схемы — прошёл бы незамеченным. Требуем конкретный спан на заведомо валидном
# номере: класс inn И источник checksum_rf через валидатор inn10.
printf '%s' "$analyze" | grep -q '"entity_type":"inn"' || {
    die "ИНН 7707083893 (валидный inn10) не найден бандлом: $analyze"
}
printf '%s' "$analyze" | grep -q '"validator":"inn10"' || {
    die "inn-спан найден не чексумма-валидатором inn10: $analyze"
}
printf 'ANALYZE|inn10=ok\n'

kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

# 5. Платформенный контур (#128/#140): бандл обязан нести ровно то, что
#    обещает его ОС. Развилка — ОС ХОСТА ПРОВЕРКИ (бандл проверяется на своей
#    ячейке матрицы; cross-check чужого архива = проверка чужого раннера).
os="$(uname -s)"
case "$os" in
    Linux)
        # linux-бандл = systemd-контур: юнит обязан быть, трей — не может
        # (фича физически несобираема, §16): её наличие в архиве = кто-то
        # собрал linux-бинарь с чужими фичами.
        [ -f "$stage/contrib/systemd/fasad.service" ] \
            || die "linux-бандл без contrib/systemd/fasad.service (#140)"
        grep -q "MemoryMax=1843M" "$stage/contrib/systemd/fasad.service" \
            || die "юнит без MemoryMax=1843M (SPEC §1 ≤1.8 ГБ)"
        grep -q "LimitMEMLOCK=64K" "$stage/contrib/systemd/fasad.service" \
            || die "юнит без LimitMEMLOCK=64K (vault-пул 34 KiB, token.rs)"
        grep -q "Restart=on-failure" "$stage/contrib/systemd/fasad.service" \
            || die "юнит без Restart=on-failure"
        printf 'UNIT|ok|contrib/systemd/fasad.service\n'
        [ ! -e "$stage/bin/fasad-tray" ] \
            || die "linux-бандл нёс трей-бинарь: linux-сборка фичи tray невозможна (§16)"
        ;;
    Darwin | MINGW* | MSYS* | CYGWIN*)
        # win/mac-бандл = трей: бинарь обязан быть, исполняемым, запускаться
        # и отвечать (headless-бинарь проверяется п.3; этот = витрина).
        tray_bin="$stage/bin/fasad-tray"
        [ "$os" = Darwin ] || tray_bin="$stage/bin/fasad-tray.exe"
        [ -x "$tray_bin" ] || {
            [ -x "$stage/bin/fasad-tray.exe" ] || die "win/mac-бандл без bin/fasad-tray (#128)"
            tray_bin="$stage/bin/fasad-tray.exe"
        }
        tray_log="$(mktemp)"
        FASAD_PORT=0 "$tray_bin" >"$tray_log" 2>&1 &
        tray_pid="$!"
        tray_port=""
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            tray_port="$(sed -n 's#.*listening on http://127\.0\.0\.1:\([0-9]*\)/health.*#\1#p' "$tray_log" | head -1)"
            [ -n "$tray_port" ] && break
            sleep 0.3
        done
        [ -n "$tray_port" ] && [ "$tray_port" != "0" ] || {
            printf 'verify-bundle: ОШИБКА: трей-бинарь не поднялся, banner:\n' >&2
            cat "$tray_log" >&2
            exit 1
        }
        tray_health="$(curl -sS --fail --max-time 5 "http://127.0.0.1:${tray_port}/health")" || {
            die "трей-бинарь не ответил на /health (порт $tray_port)"
        }
        printf '%s' "$tray_health" | grep -q '"stage":"cascade-0-only"' || {
            die "трей-бинарь: /health не подтверждает cascade-0-only: $tray_health"
        }
        printf 'TRAY|ok|port=%s\n' "$tray_port"
        kill "$tray_pid" 2>/dev/null || true
        wait "$tray_pid" 2>/dev/null || true
        ;;
esac
rm -f "$log"
printf 'verify-bundle ok: бандл %s распакован, хэши совпали, демон отвечает (version=%s)\n' \
    "$(basename "$arch")" "$ver_health"
