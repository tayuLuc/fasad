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
# use: scripts/verify-bundle.sh [--dist DIR] [--keep]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="dist"
KEEP=0

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
        -h | --help)
            echo "использование: scripts/verify-bundle.sh [--dist DIR] [--keep]"
            exit 0
            ;;
        *)
            printf 'verify-bundle: ОШИБКА: неизвестный аргумент: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

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
rm -f "$log"
printf 'verify-bundle ok: бандл %s распакован, хэши совпали, демон отвечает (version=%s)\n' \
    "$(basename "$arch")" "$ver_health"
