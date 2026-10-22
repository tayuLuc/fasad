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
# Контур релиза #181 (рюлинг оператора 22.10: «нужно только фулл»): бандл =
# `full` — бинарь собран с `ort-inference`, см. docs/release.md §«Что в
# бандле». П.5 проверяет полный контур:
#   ЗУБ А (всегда): бинарь бандла содержит орт-контур — mac: динамическая
#     зависимость от libonnxruntime в otool -L (dylib-контракт); linux/win:
#     маркер орт-статики в теле бинаря (linux = download-binaries СТАТИКА,
#     ort-sys main.rs:177-183, CI-провен readelf run 39786761298, #188;
#     win = MSVC-линк, delivery = dll рядом с exe — build.rs rpath-ветка =
#     macos|linux).
#   ЗУБ Б (при mounted-контуре): FASAD_MODEL_DIR=<кеш весов> → демон стартует
#     и /health говорит "stage":"cascade-0+models" (fallback: нет весов в CI →
#     SKIPPED-строка, молчание = ложно-зелёная проверка, класс реестра).
#   ЗУБ В (win/linux): "FASAD_MODEL_DIR на cascade-0-бинаре = отказ старта" —
#     каскад-0-бинарь (собранный БЕЗ фичи) при названном model_dir краснеет
#     BuiltWithoutInference (cascades.rs:649-650, тест :1615-1631) = зуб
#     против каскад-0-артефакта под full-меткой в CI без весов; на full-
#     артефакте он обратный и НЕ запускается (staged-бинарь орт-контурный,
#     mounted-проверка = ЗУБ Б).
#   ЗУБ Г: FASAD_MODEL_DIR НЕ задан → stage=cascade-0-only — легальная стадия
#     полного бинаря без весов, не «контур бандла» (первичка config.rs:457).
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
    # Смонтированный демон ЗУБа Б (#181) — тот же контракт: die-путь ноги Б
    # не имеет права оставить демона с грузом 879 МБ живым.
    if [ -n "${mpid:-}" ]; then
        kill "$mpid" 2>/dev/null || true
        wait "$mpid" 2>/dev/null || true
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
        # инструментов, что его собрал (make-bundle: powershell
        # Compress-Archive). Python — НЕТ: AGENTS п.6 не пускает Python в
        # контур сборки, а на windows-2022 `python3` в Git Bash не гарантирован.
        # Порядок (#188): powershell (собиравший инструмент = канон) → bsdtar
        # (в составе Git for Windows: /usr/bin/bsdtar, libarchive умеет zip) →
        # unzip → явный отказ.
        # Почему powershell ПЕРВЫМ, а не unzip (провен релиз-репетиции run
        # 39810796923 dist-windows, шаг «Проверка бандла»):
        # `Compress-Archive` пишет разделители путей ОБРАТНЫМИ слэшами
        # (`bin\fasad.exe` как ИМЯ ФАЙЛА, а не каталог), а `unzip` на это
        # роняет warning и не раскладывает дерево — verify-bundle умирал
        # rc=1 на пустой распаковке («в архиве нет каталога бандла»), НЕ
        # доходя до зубов. Expand-Archive = тулинг, которым архив собран
        # (round-trip инвариант), он же нормализует сепараторы.
        if command -v powershell.exe >/dev/null 2>&1; then
            powershell.exe -NoProfile -Command \
                "Expand-Archive -LiteralPath '$(cygpath -w "$arch" 2>/dev/null || printf '%s' "$arch")' -DestinationPath '$(cygpath -w "$tmp" 2>/dev/null || printf '%s' "$tmp")'"
        elif command -v bsdtar >/dev/null 2>&1; then
            bsdtar -xf "$arch" -C "$tmp"
        elif command -v unzip >/dev/null 2>&1; then
            unzip -q "$arch" -d "$tmp"
        else
            printf 'verify-bundle: ОШИБКА: нет ни powershell.exe, ни bsdtar, ни unzip — архив %s нечем распаковать\n' "$arch" >&2
            exit 1
        fi
        # Зуб пустой распаковки (#188): молчаливая пустая распаковка = все
        # зубы ниже краснеют с неочевидной причиной; здесь — с именем архива.
        [ -n "$(ls -A "$tmp" 2>/dev/null)" ] \
            || die "архив $arch распаковался ПУСТО (инструмент: см. ветку выше) — бандл не проверялся"
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

# 3. Бинарь извлекается и проверяется живым прогоном. Порт = 0 (свободный),
#    адрес берётся из banner'а.
bin="$stage/bin/fasad"
[ -x "$bin" ] || bin="$stage/bin/fasad.exe"
[ -x "$bin" ] || {
    printf 'verify-bundle: ОШИБКА: bin/fasad не исполняемый (потеряны права при упаковке)\n' >&2
    exit 1
}
# ── ЗУБ Г (#185): full-бинарь БЕЗ FASAD_MODEL_DIR = отказ старта ─────────────
# Рюлинг оператора 22.10: каскад-0 — НЕ продукт; бандл метится `-full`, и его
# бинарь без названных весов обязан отказать (rc=2, ModelsNotConfigured), а не
# молча обслуживать cascade-0-only. Прежняя нога («старт без весов → баннер +
# /health stage=cascade-0-only как легальная стадия») убита правкой старта:
# тот же прогон красным = молчаливая деградация вернулась в релизный контур.
# Контура «бинарь бандла живой, stage=cascade-0-only» в релизе больше НЕТ:
# живой сокет доказывает ЗУБ Б (веса + FASAD_MODEL_DIR → cascade-0+models),
# дискриминатор «бинарь без орта» = ЗУБ В (BuiltWithoutInference).
# env `-u FASAD_MODEL_DIR`: на mac-контуре CI шаг fetch-models экспортирует
# кеш в GITHUB_ENV (он же нужен зубу Б ниже) — без удаления переменных зуб Г
# краснел бы на собственной машине (full-бинарь С весами стартует легально).
log="$(mktemp)"
env -u FASAD_MODEL_DIR FASAD_PORT=0 "$bin" >"$log" 2>&1 &
pid="$!"
rc=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.3
done
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$log"
    die "ЗУБ Г: full-бинарь бандла поднялся БЕЗ FASAD_MODEL_DIR (ожидание: отказ старта, #185) — молчаливая деградация в релизном контуре"
fi
# `wait` — без редиректа stderr (урок ЗУБа В 22.10: `2>/dev/null` на встроенной
# wait делает её «недожидной», следующая команда под `set -e` умирает молча);
# rc читаем через `|| rc=$?`, не присваиванием.
rc=0
wait "$pid" || rc=$?
if [ "$rc" -eq 0 ]; then
    rm -f "$log"
    die "ЗУБ Г: full-бинарь бандла без FASAD_MODEL_DIR завершился rc=0 (ожидание: 2, #185)"
fi
grep -q "FASAD_MODEL_DIR" "$log" \
    || { c0tail="$(head -c 400 "$log")"; rm -f "$log"; die "ЗУБ Г: отказ без FASAD_MODEL_DIR в stderr (причина не названа, #185): $c0tail"; }
grep -q "listening" "$log" \
    && { c0tail="$(head -c 400 "$log")"; rm -f "$log"; die "ЗУБ Г: баннер напечатан до отказа (#185): $c0tail"; }
rm -f "$log"
printf 'REFUSAL|ok|rc=%s|full-бинарь без FASAD_MODEL_DIR = отказ старта (#185, ModelsNotConfigured)\n' "$rc"
# ── ЗУБ А: бинарь бандла = орт-контур (full) ────────────────────────────────
# Та же логика, что full_probe в make-bundle.sh: mac — динамическая зависимость
# (dylib-контракт, rpath), linux/win — маркер орт-статики в теле бинаря
# (download-binaries/MSVC линкуют орт СТАТИКОЙ; доставка win-рантайма =
# onnxruntime.dll рядом с exe). Инструмент спрашивается у АРТЕФАКТА, env
# вызывающего не влияет (тот же принцип, что preflight measure-rss.sh #170 б).
case "$(uname -s)" in
    Darwin)
        otool -L "$bin" | grep -qi onnxruntime \
            || die "ЗУБ А: bin/fasad без libonnxruntime в графе = бандл не full (release-контур #181)"
        [ -f "$stage/lib/libonnxruntime.1.dylib" ] \
            || die "ЗУБ А: mac-full-бандл без lib/libonnxruntime.1.dylib (доставка рантайма, docs/release.md §Матрица)"
        otool -L "$stage/lib/libonnxruntime.1.dylib" | grep -q "current version 1.31.0" \
            || die "ЗУБ А: dylib в бандле не 1.31.0 (контракт ort-dylib: официальный архив 1.31.0)"
        printf 'ORT|ok|mac: dylib в бандле + rpath-контур (lib/libonnxruntime.1.dylib)\n'
        ;;
    Linux)
        # Форма зуба (#188) = маркер в теле, та же, что win-нога ниже.
        # Прежний readelf-гейт краснел ЛОЖНО: linux-контур релиза =
        # ort-sys download-binaries, а он линкует орт СТАТИКОЙ (первичка
        # ort-sys build/main.rs:177-183: static_link_prerequisites +
        # `rustc-link-lib=static=onnxruntime`), в ELF-графе onnxruntime НЕТ —
        # CI-провен run 39786761298 (ort-build linux, ci.yml): `readelf -d`
        # bin-цели = NEEDED libstdc++/libgcc_s/libm/libc/ld-linux, .so через
        # `ldd` нет. Дискриминатор маркера = тот же, что preflight
        # measure-rss.sh #170 б: релизный каскад-0 (бинарь БЕЗ фичи,
        # release.yml-шаг target-c0) = 0 совпадений, орт-бинарь = >0
        # (вендорные пути onnxruntime/core/… из static_link_prerequisites,
        # ort-sys main.rs:177, промер win-ноги #181/#184).
        LC_ALL=C grep -qa 'onnxruntime/core/session' "$bin" 2>/dev/null \
            || die "ЗУБ А: bin/fasad без орт-статики в теле = бандл не full (release-контур #181, linux = download-binaries статика, ort-sys main.rs:182)"
        printf 'ORT|ok|linux: маркер орт-статики в bin/fasad (download-binaries статика; readelf-д = CI-провен run 39786761298, NEEDED без onnxruntime)\n'
        ;;
    MINGW* | MSYS* | CYGWIN*)
        # #188 (провен релиз-репетиции run 39808790297 win-Бандл): маркер
        # `onnxruntime/core/session` = пути заголовков C++-объектов, в PE
        # bin-цели их НЕТ (win = pyke static_link: import-либы + C-ABI-линковка,
        # ort-sys static_link/mod.rs:42-54/117; строка `onnxruntime.dll` —
        # только в док-комментариях ort environment.rs:29,644, в код не
        # попадает). Живой маркер win-full = имена EP-либ из
        # static_link_prerequisites (`DirectML`, DX12-набор): full = есть,
        # каскад-0 (фича off) = нет (тот же дискриминатор, что full_probe в
        # make-bundle.sh, win-нога).
        LC_ALL=C grep -qai 'DirectML' "$bin" 2>/dev/null \
            || die "ЗУБ А: bin/fasad.exe без EP-либ win-контура (DirectML) = бандл не full (release-контур #181, win = pyke static_link, static_link/mod.rs:50-54, #188)"
        printf 'ORT|ok|win: маркер DirectML в bin/fasad.exe (win = pyke static_link_prerequisites, #188)\n'
        ;;
esac
# 4. Живой HTTP-контур бандла = смонтированный демон ЗУБа Б (weights +
#    `FASAD_MODEL_DIR`): после рюлинга #185 full-бинарь без весов не стартует
#    (ЗУБ Г выше), и каскад-0-сокета в релизном контуре больше нет. Версия
#    демона (`ver_health`) и анализ (`/v1/analyze`) берутся из mounted-ноги
#    (блок ЗУБ Б ниже, `$mhealth`/`$mport`); на win/linux без доставки весов
#    (SKIPPED-нога) живого сокета нет, и эти две проверки печатают SKIPPED с
#    причиной — молчание = ложно-зелёная проверка (класс реестра).
ver_archive="$(printf '%s' "$(basename "$arch")" | sed -n 's/^fasad-\([0-9][0-9.]*\)-.*/\1/p')"

# ── ЗУБ Б/В: полный контур с весами (FASAD_MODEL_DIR) ───────────────────────
# Контур #181: релизный бандл = full (рюлинг оператора 22.10), и гейт обязан
# видеть mounted-стадию live, а не только каскад-0. Первичка:
# `Config::stage()` (config.rs:457-462) = `cascade-0+models` при model_dir,
# отказ старта full-бинаря без весов = cascades.rs (`Load`, нет файла),
# отказ cascade-0-бинаря при model_dir = BuiltWithoutInference
# (cascades.rs:649-650).
#
# Две ноги, обе честные:
#   Б (live, если веси доступны): FASAD_MODEL_DIR=<кеш> → старт /health →
#     stage=cascade-0+models + живой модельный спан (person_name). Кеш =
#     $FASAD_MODEL_DIR (env вызывающего; в CI его экспортирует шаг доставки
#     весов job dist), дефолт ~/.cache/fasad-models. Нет весов в кеше
#     (файл-проверка ниже, раскладка cascades.rs:744-749) → SKIPPED-строка
#     с причиной, НЕ молчание (класс print-only/false-green).
#   В (на каждой ОС, до ноги Б): бинарь БЕЗ орт-контура при FASAD_MODEL_DIR
#     обязан ОТКАЗАТЬСЯ стартовать (CascadeFailure::BuiltWithoutInference,
#     cascades.rs:649-650; unit-доказательство :1615-1631). Живой промер
#     делает тот же дискриминатор, что unit: каскад-0-бинарь (собранный без
#     фичи) + названные веса = exit≠0, сокет не биндится. staged-бинарь
#     full-бандла этот тест не проходит (он орт-контурный), поэтому зуб В
#     гоняется на ЛОКАЛЬНОМ cascade-0-артефакте (`just release-build-cascade0`
#     = cargo build --release -p guard-daemon, без env-префикса), если он есть
#     в target/release; нет артефакта — SKIPPED-строка с причиной.
# Старт смонтированного демона = loading весов (STARTUP_LOAD_BUDGET_MS =
# 120 000, cascades.rs), бюджеты readiness = 30 с; убитый демонами trap
# идемпотентен ( cleanup() расширяется mpid-веткой).
model_dir="${FASAD_MODEL_DIR:-$HOME/.cache/fasad-models}"
lockr_model="$model_dir/lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx"
decide_model="$model_dir/onnx-community/GLiNER2.5-Decide-ONNX/onnx/model_q4f16.onnx"
weights_present=0
if [ -f "$lockr_model" ] && [ -f "$decide_model" ]; then
    weights_present=1
fi

# ── ЗУБ В: cascade-0-бинарь + FASAD_MODEL_DIR = отказ старта ────────────────
# Референс каскад-0-бинаря ИЩЕТСЯ, а не берётся по умолчанию из
# target/release/fasad: в релизном контуре #181 этот путь = ПОЛНЫЙ бинарь
# (`just release-build`), и гонять на нём «ожидание отказа» = ложно-красный
# промер (full-бинарь с весами стартует OK — промер 22.10: зуб В на
# полном target вис 90 с, цикл ожидания rc «навсегда»). Кандидаты:
#   1) $FASAD_CASCADE0_BIN (явный; CI-контур win/linux: шаг
#      `cargo build --release -p guard-daemon` (без env-префикса) кладёт
#      каскад-0-артефакт в target/release/fasad и экспортит путь сюда);
#   2) ./fasad-cascade0 в cwd (локальная подготовка:
#      `just release-build-cascade0` + cp артефакта).
# Отличение каскад-0-артефакта от орт-бинаря — тем же дискриминатором, что
# full_probe make-bundle.sh (win-нога: маркер орт-статики в теле; mac/linux:
# отсутствие динамической зависимости; `otool`/`readelf` есть только на своих
# ОС). Не найден/не распознан = SKIPPED-строка с причиной, не молчание.
c0bin="${FASAD_CASCADE0_BIN:-}"
[ -n "$c0bin" ] || c0bin="./fasad-cascade0"
if [ ! -x "$c0bin" ]; then
    c0bin=""
fi
if [ -n "$c0bin" ]; then
    c0_is_cascade0=0
    case "$(uname -s)" in
        Darwin)
            otool -L "$c0bin" 2>/dev/null | grep -qi onnxruntime || c0_is_cascade0=1
            ;;
        Linux)
            readelf -d -l "$c0bin" 2>/dev/null | grep -qi onnxruntime || c0_is_cascade0=1
            ;;
        MINGW* | MSYS* | CYGWIN*)
            LC_ALL=C grep -qa 'onnxruntime/core/session' "$c0bin" 2>/dev/null || c0_is_cascade0=1
            ;;
    esac
    if [ "$c0_is_cascade0" -eq 0 ]; then
        printf 'CASCADE0-GUARD|SKIPPED|%s содержит орт-контур = не каскад-0-референс (зуб В требует бинарь БЕЗ фичи: FASAD_CASCADE0_BIN / just release-build-cascade0)\n' "$c0bin"
    elif [ "$weights_present" -ne 1 ]; then
        printf 'CASCADE0-GUARD|SKIPPED|весов нет в %s: BuiltWithoutInference проверяется и на несуществующем каталоге, но контур держит единство кеша; промер с пустым каталогом = unit cascades.rs:1615-1631\n' "$model_dir"
    else
        c0log="$(mktemp)"
        # Отказ = фоновый запуск + цикл до смерти процесса; rc читаем из
        # `wait` через `|| c0rc=$?` (не `c0rc="$(wait …)"`: `set -e` валит
        # скрипт на nonzero-команде присваивания — промер 22.10: verify
        # краснел rc=2 на ЗЕЛЁНОМ зубе, код отказа утекал в код скрипта;
        # и не `cmd && a || b` с фоном: гонка `kill -0` до fork).
        # `wait` — без редиректа stderr: `2>/dev/null` на встроенной wait
        # переводит её в «недожидную» (bash: not waiting, промер 22.10),
        # следующая за ней команда под `set -e` умирала молча.
        FASAD_PORT=0 FASAD_MODEL_DIR="$model_dir" nice -n 10 "$c0bin" >"$c0log" 2>&1 &
        c0pid="$!"
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$c0pid" 2>/dev/null || break
            sleep 0.5
        done
        if kill -0 "$c0pid" 2>/dev/null; then
            # Живой сокет при FASAD_MODEL_DIR = зуб красным (каскад-0 не имеет
            # права обслуживать с обещанными весами). Убиваем и красим.
            kill "$c0pid" 2>/dev/null || true
            wait "$c0pid" 2>/dev/null || true
            rm -f "$c0log"
            die "CASCADE0-GUARD: бинарь без орт-контура поднялся с FASAD_MODEL_DIR = BuiltWithoutInference не сработал (cascades.rs:649)"
        fi
        # `wait` БЕЗ редиректа stderr: `2>/dev/null` на встроенной wait
        # переводит её в «недожидную» (bash: not waiting, промер 22.10),
        # следующая за ней команда под `set -e` умирала молча.
        c0rc=0
        wait "$c0pid" || c0rc=$?
        # Причина читается ДО удаления лога: `rm` до grep = «умер, но причину
        # нечем назвать» (grep по удалённому = die на правильном отказе,
        # промер 22.10).
        if [ "$c0rc" -eq 0 ]; then
            rm -f "$c0log"
            die "CASCADE0-GUARD: каскад-0-бинарь завершился rc=0 с FASAD_MODEL_DIR (ожидание: отказ старта)"
        fi
        c0tail="$(head -c 400 "$c0log")"
        grep -qi "ort-inference" "$c0log" \
            || die "CASCADE0-GUARD: каскад-0 при FASAD_MODEL_DIR умер (rc=$c0rc), но в stderr нет BuiltWithoutInference/ort-inference: $c0tail"
        rm -f "$c0log"
        printf 'CASCADE0-GUARD|ok|rc=%s|отказ старта с FASAD_MODEL_DIR (BuiltWithoutInference)\n' "$c0rc"
    fi
else
    printf 'CASCADE0-GUARD|SKIPPED|нет каскад-0-референса (FASAD_CASCADE0_BIN / ./fasad-cascade0; в win/linux-контуре CI его готовит шаг сборки, в mac-локальном прогоне — just release-build-cascade0 + cp)\n'
fi

# ── ЗУБ Б: live-промер смонтированного контура ──────────────────────────────
if [ "$weights_present" -eq 1 ]; then
    mlog="$(mktemp)"
    FASAD_PORT=0 FASAD_MODEL_DIR="$model_dir" FASAD_THREADS="${FASAD_THREADS:-2}" \
        FASAD_TIMEOUT_MS=10000 nice -n 10 "$bin" >"$mlog" 2>&1 &
    mpid="$!"
    # Контур trap-ловушки один (второй `trap … EXIT` заменяет первый — урок F6
    # этого скрипта), поэтому смонтированный демон регистрируется в общей
    # cleanup(): mpid объявлен до trap и убивается на ЛЮБОМ выходе, включая
    # die-пути ноги Б.
    mport=""
    for _ in $(seq 1 60); do
        mport="$(sed -n 's#.*listening on http://127\.0\.0\.1:\([0-9]*\)/health.*#\1#p' "$mlog" | head -1)"
        [ -n "$mport" ] && [ "$mport" != "0" ] && break
        kill -0 "$mpid" 2>/dev/null \
            || { cat "$mlog" >&2; die "ЗУБ Б: смонтированный демон умер на старте (кеш $model_dir)"; }
        sleep 0.5
    done
    [ -n "$mport" ] && [ "$mport" != "0" ] \
        || { cat "$mlog" >&2; die "ЗУБ Б: смонтированный демон не поднялся за 30 с (кеш $model_dir)"; }
    mhealth="$(curl -sS --fail --max-time 10 "http://127.0.0.1:${mport}/health")" \
        || die "ЗУБ Б: смонтированный демон не ответил на /health (порт $mport)"
    printf 'HEALTH|mounted|%s\n' "$mhealth"
    printf '%s' "$mhealth" | grep -q '"stage":"cascade-0+models"' \
        || die "ЗУБ Б: /health с FASAD_MODEL_DIR не подтверждает cascade-0+models: $mhealth"
    # Живой ФИО-промер (ГЛАВНЫЙ промер контура, #181): бинарь+веса+
    # FASAD_MODEL_DIR обязан ДАВАТЬ модельный спан, а не только честную метку.
    manalyze="$(curl -sS --fail --max-time 60 -H 'content-type: application/json' \
        -H 'x-guard-policy: mask' -X POST "http://127.0.0.1:${mport}/v1/analyze" \
        -d '{"text":"Иванов Пётр Сергеевич, паспорт 4507 123456, ИНН 2482014338"}')" \
        || die "ЗУБ Б: /v1/analyze смонтированного демона не ответил (порт $mport)"
    printf 'ANALYZE|mounted|%s\n' "$manalyze"
    printf '%s' "$manalyze" | grep -q '"person_name"' \
        || die "ЗУБ Б: ФИО-спан (person_name) не найден на смонтированном контуре — модельный путь не жив: $manalyze"
    printf 'MOUNTED|ok|stage=cascade-0+models|person_name=ok|кеш=%s\n' "$model_dir"
    # 4 (live-нога). Версия демона и чексумма-контур берутся от mounted-демона:
    # после #185 каскад-0-сокета в релизном контуре нет, живой HTTP = нога Б.
    ver_health="$(printf '%s' "$mhealth" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
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
    # Чексумма-контур (каскад 0 на смонтированном): спаны возвращаются,
    # policy-заголовок живёт. Поле спана — `entity_type` (промер живого ответа
    # /v1/analyze 21.10: `[{"entity_type":"inn","start":…,"score":1.0,"class":
    # "inn","source":"checksum_rf","verdict":"mask_surrogate","validator":
    # "inn10"}]`), а не `category`/`span_id`.
    # `curl --fail` при HTTP-ошибке возвращается 22, а под `set -euo pipefail` это
    # обрывает скрипт на присваивании без единой строки диагностики (тот же класс,
    # что у счётчика спанов ниже). Причина отказа обязана называться самим скриптом.
    analyze="$(curl -sS --fail --max-time 10 -H 'content-type: application/json' \
        -H 'x-guard-policy: mask' -X POST "http://127.0.0.1:${mport}/v1/analyze" \
        -d '{"text":"ИНН 7707083893, телефон +79161234567, паспорт 45 09 123456"}')" || {
        die "/v1/analyze от бандла не ответил (HTTP-ошибка или таймаут), порт $mport"
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
    rm -f "$mlog"
else
    # Нет весов. На mac это красным: mac-контур релиза обязан нести доставку
    # весов (шаг fetch-models в release.yml job dist, #181) — отсутствие =
    # дефект контура. На win/linux доставка весов в CI намеренно не
    # смонтирована (риск #181: win/linux HF-кеш в матрице = +900 МБ трафика
    # на каждый релиз-прогон), live-нога = SKIPPED c явной причиной; unit-
    # доказательство смонтированного контракта = cargo-тесты cascades/config.
    case "$(uname -s)" in
        Darwin)
            die "ЗУБ Б: mac без весов в кеше ($model_dir) — доставка весов в mac-контуре смонтирована (fetch-models шаг release.yml); отсутствие = красным, не SKIPPED"
            ;;
    esac
    printf 'MOUNTED|SKIPPED|весов нет в %s — win/linux-контур CI без доставки весов (#181); unit-доказательства: cascades.rs startup-тесты\n' "$model_dir"
    # Живого сокета нет (full-бинарь без весов не стартует, #185), и версия
    # демона из /health недоступна: обе live-проверки печатают SKIPPED с
    # причиной (молчание = ложно-зелёная проверка, класс реестра). Тег↔версия
    # на этой ноге покрывается второй точкой (Cargo.toml, блок EXPECT_VERSION
    # выше) и `gh release create --verify-tag` (job release).
    printf 'VERSION|SKIPPED|version демона читается из /health mounted-ноги (win/linux CI без весов = нет живой ноги, #185)\n'
    printf 'ANALYZE|SKIPPED|чексумма-контур меряется на mounted-демоне (win/linux CI без весов = нет живой ноги, #185)\n'
    ver_health="SKIPPED"
fi

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
        # win/mac-бандл = трей: бинарь обязан быть и исполняться (headless-
        # бинарь проверяется п.3; этот = витрина). #181: трей = тот же
        # main.rs + ort-контур, значит #185-отказ без весов обязан сработать
        # и здесь (headless-нога = ЗУБ Г выше, трей-бинарь = свой прогон).
        # Живой сокет трея меряется ТОЛЬКО с весами (нога weights_present=1):
        # на win/linux-ячейках доставки весов нет, и трей-контур =
        # refusal-проверка + SKIPPED-строка, а не красная ложь.
        tray_bin="$stage/bin/fasad-tray"
        [ "$os" = Darwin ] || tray_bin="$stage/bin/fasad-tray.exe"
        [ -x "$tray_bin" ] || {
            [ -x "$stage/bin/fasad-tray.exe" ] || die "win/mac-бандл без bin/fasad-tray (#128)"
            tray_bin="$stage/bin/fasad-tray.exe"
        }
        # Нога 1 (#185): трей без весов = отказ старта (rc≠0, причина, баннера нет).
        tray_log="$(mktemp)"
        env -u FASAD_MODEL_DIR FASAD_PORT=0 "$tray_bin" >"$tray_log" 2>&1 &
        tray_pid="$!"
        trc=0
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$tray_pid" 2>/dev/null || break
            sleep 0.3
        done
        if kill -0 "$tray_pid" 2>/dev/null; then
            kill "$tray_pid" 2>/dev/null || true
            wait "$tray_pid" 2>/dev/null || true
            rm -f "$tray_log"
            die "ЗУБ Г (трей): fasad-tray поднялся БЕЗ FASAD_MODEL_DIR (ожидание: отказ старта, #185 — трей = full-контур, #181)"
        fi
        trc=0
        wait "$tray_pid" || trc=$?
        [ "$trc" -ne 0 ] || { rm -f "$tray_log"; die "ЗУБ Г (трей): fasad-tray без весов завершился rc=0 (ожидание: 2, #185)"; }
        grep -q "FASAD_MODEL_DIR" "$tray_log" \
            || { tr0="$(head -c 400 "$tray_log")"; rm -f "$tray_log"; die "ЗУБ Г (трей): отказ без FASAD_MODEL_DIR в stderr: $tr0"; }
        rm -f "$tray_log"
        printf 'REFUSAL|ok|tray|rc=%s|трей без FASAD_MODEL_DIR = отказ старта (#185)\n' "$trc"
        # Нога 2 (только с весами): смонтированный трей обязан поднять сокет и
        # отдать cascade-0+models (pre-#185 контур «cascade-0-only» без весов
        # мёртв, живой трей-контур = product-контур с model_dir).
        if [ "$weights_present" -eq 1 ]; then
            tray_log="$(mktemp)"
            FASAD_PORT=0 FASAD_MODEL_DIR="$model_dir" FASAD_THREADS="${FASAD_THREADS:-2}" \
                FASAD_TIMEOUT_MS=10000 nice -n 10 "$tray_bin" >"$tray_log" 2>&1 &
            tray_pid="$!"
            tray_port=""
            for _ in $(seq 1 60); do
                tray_port="$(sed -n 's#.*listening on http://127\.0\.0\.1:\([0-9]*\)/health.*#\1#p' "$tray_log" | head -1)"
                [ -n "$tray_port" ] && [ "$tray_port" != "0" ] && break
                kill -0 "$tray_pid" 2>/dev/null \
                    || { cat "$tray_log" >&2; die "трей-бинарь (с весами) умер на старте: banner:"; }
                sleep 0.5
            done
            [ -n "$tray_port" ] && [ "$tray_port" != "0" ] || {
                printf 'verify-bundle: ОШИБКА: трей-бинарь не поднялся за 30 с, banner:\n' >&2
                cat "$tray_log" >&2
                exit 1
            }
            tray_health="$(curl -sS --fail --max-time 5 "http://127.0.0.1:${tray_port}/health")" || {
                die "трей-бинарь не ответил на /health (порт $tray_port)"
            }
            printf '%s' "$tray_health" | grep -q '"stage":"cascade-0+models"' || {
                die "трей-бинарь: /health не подтверждает cascade-0+models (трей = full-контур с весами, #181/#185): $tray_health"
            }
            printf 'TRAY|ok|port=%s|stage=cascade-0+models\n' "$tray_port"
            kill "$tray_pid" 2>/dev/null || true
            wait "$tray_pid" 2>/dev/null || true
            rm -f "$tray_log"
        else
            printf 'TRAY|SKIPPED|живой трей-контур требует весов (%s); отказ без весов промёрт, стадия не мерялась (#185)\n' "$model_dir"
        fi
        ;;
esac
# `$log` (refusal-нога) убран самим зубом Г; `$health` (версия) = mounted-нога
# (#185: живой каскад-0-сокет в релизе невозможен, «демон отвечает» = stage
# cascade-0+models).
printf 'verify-bundle ok: бандл %s распакован, хэши совпали, mounted-контур проверен (version=%s)\n' \
    "$(basename "$arch")" "$ver_health"
