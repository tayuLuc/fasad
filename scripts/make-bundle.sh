#!/usr/bin/env bash
# scripts/make-bundle.sh — упаковка релизного бандла (SPEC §10 п.9, шаг 9).
#
# Вызывается рецептом `just dist` (тот же контракт, что у CI-матрицы: §5.5.5 —
# CI зовёт те же команды, что оператор). Логика в скрипте, а не в just-рецепте,
# по двум причинам: (1) heredoc с текстом README на колонке 0 ломает парсер
# just (промер 21.10: `unknown start of token 'Л'` — тело рецепта заканчивается
# там, где заканчивается отступ), (2) скрипт линтуется shellcheck'ом в job
# `lint-actions` (BASH_SHELLCHECK), а тело just-рецепта — нет.
#
# Контент бандла (SPEC §9 «Артефакт: tar.gz/zip = бинарь + …»):
#   bin/fasad[.exe]        релизный бинарь ПОЛНОГО контура (орт-сборка, #181)
#   README.md              ссылка на исходники + запуск (генерится здесь)
#   LICENSE                Apache-2.0 (текст лицензии продукта)
#   schema.default.json    канон схемы (config/, FASAD_SCHEMA)
#   THIRD-PARTY-LICENSES.txt  сгенерированный `just deps-licenses`
#   SHA256SUMS.txt         хэши всех файлов бандла (кроме самого себя)
#   models/README.md       инструкция скачивания весов (веса в архив НЕ входят,
#                          879 МБ; раскладка = кеш scripts/fetch-models.sh)
#   scripts/fetch-models.sh + models/manifest.tsv  — скачивание с sha256-гейтом
#   lib/libonnxruntime*.dylib  (mac) — официальный dylib 1.31.0, доставка
#                          рантайма: бинарь после `-add_rpath @loader_path/../lib`
#                          грузит его из бандла (docs/model-audit.md §8: mac-контур)
#
# Формат архива: tar.gz (unix), zip (Windows: Git-for-Windows tar zip не умеет,
# архиватор = powershell Compress-Archive).
#
# use: scripts/make-bundle.sh [--binary PATH] [--out DIR]
#                          [--label full] [--tray-binary PATH] [--ort-dir DIR]
#
# Платформенный контур (#128 фаза 2, решение оператора: linux = systemd-юнит,
# win/mac = трей):
#   linux   → `contrib/systemd/fasad.service` в бандл (headless-бинарь, трея
#             физически нет: compile_error, docs/dep-verify-crates.md §16);
#   win/mac → второй бинарь `bin/fasad-tray[.exe]` (сборка с `--features
#             tray,ort-inference` — #181: трей = тот же main.rs, полный
#             контур в обоих бинарях архива).
#
# Метка контура в имени артефакта (`-full`) обязательна и НЕ двигается на
# `cascade-0`: рюлинг оператора 22.10 («Нужно только фулл», issue #181) —
# cascade-0-бандл в релизе не продаётся, бандл = бинарь полного контура +
# инструкция весов. Веса (879 МБ) в архив не кладём (решение (а) issue #181:
# оффлайн-раздача гигабайт LFS-весов через GitHub Release = удвоенный HF-трафик
# и раздутый ассет; бандл несёт скрипт скачивания с sha256-гейтом манифеста).
# names: fasad-<version>-<triple>-<label>.tar.gz / .zip

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN=""
TRAY_BIN=""
LICENSES="dist/THIRD-PARTY-LICENSES.txt"
OUT="dist"
# Метка контура по умолчанию = full (рюлинг оператора 22.10, #181). Явный
# `--label cascade-0` красным ниже (гард «только full»): откат метки = откат
# релизного контракта, а не опция сборки.
LABEL="full"
ORT_DIR="${ORT_DIR:-}"
ORT_DLL_SRC="${ORT_DLL:-}"

die() {
    printf 'make-bundle: ОШИБКА: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || die "--binary требует аргумент"
            BIN="$2"
            shift 2
            ;;
        --tray-binary)
            [ "$#" -ge 2 ] || die "--tray-binary требует аргумент"
            TRAY_BIN="$2"
            shift 2
            ;;
        --licenses)
            [ "$#" -ge 2 ] || die "--licenses требует аргумент"
            LICENSES="$2"
            shift 2
            ;;
        --out)
            [ "$#" -ge 2 ] || die "--out требует аргумент"
            OUT="$2"
            shift 2
            ;;
        --label)
            [ "$#" -ge 2 ] || die "--label требует аргумент"
            LABEL="$2"
            shift 2
            ;;
        --ort-dir)
            [ "$#" -ge 2 ] || die "--ort-dir требует аргумент (корень распакованного архива ORT, lib/ внутри)"
            ORT_DIR="$2"
            shift 2
            ;;
        --ort-dll)
            [ "$#" -ge 2 ] || die "--ort-dll требует аргумент (путь к onnxruntime.dll для win-бандла)"
            ORT_DLL_SRC="$2"
            shift 2
            ;;
        -h | --help)
            echo "использование: scripts/make-bundle.sh [--binary PATH] [--tray-binary PATH] [--licenses PATH] [--out DIR] [--label full] [--ort-dir DIR] [--ort-dll PATH]"
            exit 0
            ;;
        *)
            die "неизвестный аргумент: $1"
            ;;
    esac
done

# Гард «только full» (#181, рюлинг оператора 22.10): релизный контур = full,
# метка cascade-0 в имени артефакта запрещена ЯВНО — защита от откатов:
# кто-то вернёт LABEL=cascade-0 в дефолт, и релиз снова начнёт продавать
# каскад-0 под видом продукта. Откат возможен только через снятие этого
# блока + смену рюлинга (issue #181), не через флаг.
if [ "$LABEL" = "cascade-0" ] || [ "$LABEL" = "cascade0" ]; then
    die "метка '$LABEL' запрещена: релизный контур = ТОЛЬКО full (рюлинг оператора 22.10, issue #181)"
fi

# Версия: единый источник — `[workspace.package] version` в Cargo.toml
# (RELEASES.md п.1). Python в build-контур не пускаем (AGENTS п.6), поэтому
# извлечение = sed по секции, а не json-парсер.
version="$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml \
    | sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$version" ] || die "не извлёк версию из [workspace.package] в Cargo.toml"

triple="$(rustc -vV | sed -n 's/^host: //p')"
[ -n "$triple" ] || die "rustc -vV не вернул host-triple"

ext=""
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) ext=".exe" ;;
esac

[ -n "$BIN" ] || BIN="target/release/fasad${ext}"
[ -x "$BIN" ] || die "нет бинаря $BIN — сначала cargo build --release -p guard-daemon --features ort-inference (just release-build)"
[ -f "$LICENSES" ] || die "нет $LICENSES — сначала just deps-licenses"

# Зуб полного контура (mac/linux — динамический dylib, win — статик-линк).
# Контур бандла метится именем архива (`-full`); метка обязана быть правдой про
# бинарь, иначе «full» продаёт cascade-0. Проверка спрашивает У АРТЕФАКТА, а не
# у env вызывающего (тот же класс, что preflight в measure-rss.sh #170 б).
#   mac/linux: орт-контур = динамическая зависимость от libonnxruntime в
#     `otool -L` / `readelf -d -l`; голый бинарь без неё = собран без фичи.
#   windows: MSVC линкует орт СТАТИКОЙ (build.rs: rpath-ветка = macos|linux,
#     delivery на win = onnxruntime.dll рядом с exe), динамической зависимости
#     нет у обоих контуров — отличим только по маркеру pyke-статики в теле
#     бинаря (тот же маркер, что у preflight measure-rss.sh: `LC_ALL=C grep -a
#     'onnxruntime/core/session'`; релизный каскад-0 = 0 совпадений, орт-бинарь
#     = >0). Зуб win = компиляционный (полный живой промер win-контура =
#     первая релизная матрица, риск записан в #181); `strings` на win-раннере
#     не гарантирован, fallback: зуб пропускается ЯВНОЙ строкой (не молча).
full_probe() {
    probe="$1"
    case "$(uname -s)" in
        Darwin)
            otool -L "$probe" 2>/dev/null | grep -qi onnxruntime \
                || die "$probe: в динамическом графе нет libonnxruntime = бинарь собран БЕЗ ort-inference; метка full запрещена (just release-build)"
            ;;
        Linux)
            readelf -d -l "$probe" 2>/dev/null | grep -qi onnxruntime \
                || die "$probe: в динамическом графе нет libonnxruntime = бинарь собран БЕЗ ort-inference; метка full запрещена (just release-build)"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            # MSVC: динамической зависимости нет у обоих контуров (build.rs
            # rpath-ветка = macos|linux; доставка на win = onnxruntime.dll
            # рядом с exe — ort-sys copy_dylibs в target-каталог, первичка
            # build/dynamic_link.rs:14-24, промер этой сессии). Отличим по
            # вендорному маркеру: `static_link_prerequisites` (ort-sys
            # build/main.rs:59/66/177) прокидывает вендорные пути вида
            # onnxruntime/core/… в линкуемый образ — `LC_ALL=C grep -a` по
            # бинарю (тот же маркер, что preflight measure-rss.sh #170 б:
            # голый spike = 4 совпадения, релизный каскад-0 = 0).
            # Инструмент = bash-греп по байтам (свой код), НЕ `strings`: на
            # windows-раннере `strings` из Sysinternals не гарантирован, а
            # молча пропущенный зуб (WARN) = ложно-зелёный контур (реестр
            # false-green).
            #
            # ДИНАМИЧЕСКАЯ нога, если dll едет в архив: win-бандл несёт
            # bin/onnxruntime.dll (параметр --ort-dll) — на MSVC доставка
            # рантайма = dll рядом с exe (ort-дока «in PATH or next to the
            # exe»; в PE RUNPATH нет), и dylib-зависимость в графе exe при
            # этом НЕ появляется: DLL-имя грузится LoadLibrary из
            # import-дескрипторов. Отличить статик от динамики по `dumpbin`
            # нельзя (не гарантирован на раннере), поэтому проверяется
            # инвариант «dll в бандле = полный контур»: наличие dll рядом с
            # exe = заявка упаковки (--ort-dll из CI-шага), и она обязана
            # сопровождаться орт-маркером в самом exe.
            LC_ALL=C grep -qa 'onnxruntime/core/session' "$probe" 2>/dev/null \
                || die "$probe: в теле бинаря нет орт-статики = собран БЕЗ ort-inference; метка full запрещена (just release-build)"
            ;;
    esac
}
full_probe "$BIN"

# Контур платформы (см. usage). Окончание `.exe` общее (`ext`), путь — общий.
os="$(uname -s)"
is_win=0
case "$os" in
    MINGW* | MSYS* | CYGWIN*) is_win=1 ;;
esac
if [ "$is_win" -eq 0 ] && [ "$os" != "Darwin" ]; then
    # linux-бандл: systemd-юнит обязателен (headless-контур #140).
    [ -f "contrib/systemd/fasad.service" ]         || die "нет contrib/systemd/fasad.service — linux-бандл без юнита обещает контур, которого нет"
fi

stage="$OUT/fasad-$version-$triple-$LABEL"
rm -rf "$stage"
mkdir -p "$stage/bin"
cp "$BIN" "$stage/bin/"
if [ -n "$TRAY_BIN" ]; then
    # Второй бинарь: то же имя + суффикс `-tray` (`fasad-tray[.exe]`): суффикс
    # в ИМЕНИ ФАЙЛА — единственный носитель «собран с фичей», в метке архива
    # её нет (-full про контур детекции, не про GUI). #181: трей собирается с
    # `tray,ort-inference` — тот же main.rs, тот же модельный путь.
    [ -x "$TRAY_BIN" ] || die "нет бинаря $TRAY_BIN — сначала cargo build --release -p guard-daemon --features tray,ort-inference (just release-build-tray)"
    full_probe "$TRAY_BIN"
    cp "$TRAY_BIN" "$stage/bin/fasad-tray$ext"
fi
if [ "$os" = "Darwin" ]; then
    # mac-доставка рантайма ORT (#181): официальный dylib 1.31.0 едет В БАНДЛЕ
    # (docs/model-audit.md §8: mac-контур = dylib, pyke-статика в release
    # SIGSEGV'ит §W2 п.1). Бинарь линкуется на @rpath/libonnxruntime.1.dylib
    # (промер otool -D, 22.10); rpath `@loader_path/../lib` прописываем здесь
    # (install_name_tool = штатный читатель/правщик Mach-O, та же школа, что
    # otool в preflight measure-rss.sh): бандл самодостаточен по библиотеке,
    # установка ORT на машину пользователя не нужна.
    # Первичка copy_dylibs (ort-sys build/dynamic_link.rs:14-56, промер
    # 22.10): при dynamic-линке с ORT_LIB_PATH орт-sys кладёт в target/release/
    # СИМЛИНКИ на файлы ORT_DIR (иероглиф `l` в ls:
    # target/release/libonnxruntime.1.dylib -> $ORT_DIR/…), НЕ копии.
    # Релизовать симлинки обязан `cp -L`: архив, унесший симлинк на чужой
    # абсолютный путь, = «бандл, который не запускается у пользователя».
    # Поставщик библиотеки = $ORT_DIR (канон: распакованный официальный
    # архив 1.31.0, локально $HOME/onnxruntime-dylib/…, в CI шаг скачивания
    # job ort-dylib, sha256 которого проверяется); target/release/ — симлинки.
    # Имя источника = то, на что указывает LC_LOAD_DYLIB бинаря
    # (`@rpath/libonnxruntime.1.dylib` → `libonnxruntime.1.dylib`).
    [ -n "$ORT_DIR" ] || die "mac-бандл полного контура обязан нести dylib: передайте --ort-dir DIR (корень распакованного onnxruntime-osx-arm64-1.31.0, lib/ внутри) — локально ORT_DIR=\$HOME/onnxruntime-dylib/onnxruntime-osx-arm64-1.31.0, в CI шаг скачивания архива (job ort-dylib, release.yml)"
    dylib_src="$ORT_DIR/lib/libonnxruntime.1.dylib"
    [ -f "$dylib_src" ] || die "нет $dylib_src (симлинк на libonnxruntime.1.31.0.dylib) — ORT_DIR=$ORT_DIR"
    mkdir -p "$stage/lib"
    # -L разрешает СИМЛИНКИ в путях (mac-дефолт): копируется РЕЗОЛВЕННЫЙ
    # файл, в архиве — обычная библиотека.
    cp -L "$dylib_src" "$stage/lib/libonnxruntime.1.dylib"
    # Контроль разрешения: в стейдже обязан лежать НЕ симлинк (файл).
    [ ! -L "$stage/lib/libonnxruntime.1.dylib" ] \
        || die "lib/libonnxruntime.1.dylib в стейдже = симлинк (cp -L не сработал): архив унесёт битую ссылку"
    # rpath на оба бинаря (headless + трей): @loader_path = каталог бинаря
    # (bin/), ../lib = lib/ бандла. -add_rpath идемпотентность НЕ гарантирована
    # (повтор = дубль записи), поэтому проверка «rpath уже есть» перед добавкой.
    for b in "$stage/bin/fasad" "$stage/bin/fasad-tray"; do
        [ -f "$b" ] || continue
        if ! otool -l "$b" | grep -q "@loader_path/../lib"; then
            install_name_tool -add_rpath "@loader_path/../lib" "$b"
        fi
    done
    # Самопроверка: после правки граф бинаря обязан резолвиться из стейджа
    # (dyld видит dylib по rpath). otool -L = список load commands — этого
    # хватает: @rpath-запись + файл в lib/ = контракт доставки.
    otool -L "$stage/bin/fasad" | grep -q "libonnxruntime" \
        || die "после -add_rpath в графе bin/fasad нет libonnxruntime (неожиданно)"
fi
if [ "$is_win" -eq 1 ] && [ -n "$ORT_DLL_SRC" ]; then
    # win-доставка (первичка ort-sys copy-dylibs: на Windows рантайм = dll
    # РЯДОМ с exe, PE-локатор ищет каталог бинаря): bin/onnxruntime.dll.
    mkdir -p "$stage/bin"
    cp "$ORT_DLL_SRC" "$stage/bin/onnxruntime.dll"
fi
if [ "$is_win" -eq 0 ] && [ "$os" != "Darwin" ]; then
    mkdir -p "$stage/contrib/systemd"
    cp contrib/systemd/fasad.service "$stage/contrib/systemd/fasad.service"
fi
cp LICENSE "$stage/LICENSE"
cp config/schema.default.json "$stage/schema.default.json"
cp "$LICENSES" "$stage/THIRD-PARTY-LICENSES.txt"

# ── Контур моделей (#181): веса в архив НЕ входят (879 МБ LFS-файлов через
# GitHub Release = раздутый ассет и двойной HF-трафик; решение (а) issue #181),
# бандл несёт ИНСТРУКЦИЮ скачивания + сам скрипт + манифест с sha256:
#   scripts/fetch-models.sh  — скачивание по commit-шейа + сверка sha256
#                              (fail-closed: несовпадение = exit 1, первичка
#                              шапки скрипта), кеш $FASAD_MODEL_CACHE
#                              (дефолт ~/.cache/fasad-models), раскладка =
#                              <repo>/<путь-файла> (её же читает каскадный
#                              монтаж, cascades.rs:744-749);
#   models/manifest.tsv      — машиночитаемый манифест (revision + sha256 +
#                              размер), источник истины для скрипта.
# Скрипт копируется в бандл, а не ссылаемся на репозиторий: пользователь
# бандла запускает его БЕЗ клона репозитория.
mkdir -p "$stage/scripts" "$stage/models"
cp scripts/fetch-models.sh "$stage/scripts/fetch-models.sh"
cp models/manifest.tsv "$stage/models/manifest.tsv"
cat > "$stage/models/README.md" <<'EOF'
# Веса каскадов 1–2 (не входят в архив намеренно)

Бандл собран полным контуром (каскады 0+1+2). Чтобы каскады 1–2 поднялись,
нужны веса ONNX (~879 МБ, два репозитория Hugging Face) — они распространяются
с sha256-гейтом по манифесту и в архив не упакованы (политика репо: веса вне
git, `models/manifest.md`).

Скачивание из каталога бандла (нужна сеть до `huggingface.co`, разово):

    ./scripts/fetch-models.sh
    export FASAD_MODEL_DIR="$HOME/.cache/fasad-models"   # тот же кеш

Скрипт качает строго по commit-шейа revision, пересчитывает sha256 каждого
файла и сверяет с `models/manifest.tsv`; несовпадение/обрезок = отказ (exit 1),
fail-open нет. Повторный запуск = пересчёт чексумм по кешу, без сети.
Зеркало (например, при заблокированном HF): `FASAD_HF_HOST=https://hf-mirror.com
./scripts/fetch-models.sh`; кеш в другое место: `--cache DIR`.

Раскладка кеша (её читает демон, `cascades.rs`):

    $FASAD_MODEL_DIR/lockR/rubert-base-pii-ner-onnx/{model.optimized.fp16.onnx,tokenizer.json}
    $FASAD_MODEL_DIR/onnx-community/GLiNER2.5-Decide-ONNX/onnx/{model_q4f16.onnx,model_q4f16.onnx_data}
    $FASAD_MODEL_DIR/onnx-community/GLiNER2.5-Decide-ONNX/tokenizer.json

`FASAD_MODEL_DIR` не задан — демон работает каскадом 0 (легальный режим,
`/health` → `"stage":"cascade-0-only"`). Задан, а весов нет/битые/бинарь без
орт-контура — демон **не стартует** (код 2, причина в stderr, сокет не
биндится): молчаливой деградации при обещанных весах нет.
EOF

# README-ссылка: короткая ориентировка пользователя бандла. Метка контура —
# fact, а не витрина: бинарь собран с `ort-inference` (монтаж каскадов 1–2,
# `crates/guard-daemon/src/cascades.rs`), stage в `/health` = правда про
# собранный бинарь и смонтированные веса.
# README = базовый блок (общий) + блоки по ОС (отдельные heredoc-и, `>>`):
# mac/win несут второй бинарь `fasad-tray`, linux — systemd-юнит (#128/#140).
# Вложенные `$( ... <<X )` внутрь heredoc не класть: кавычки/подстановки
# считаются по правилам внешней оболочки и печатаются литералами (обожглось
# на этом PR).
cat > "$stage/README.md" <<EOF
# fasad $version ($triple, контур: $LABEL)

Локальный AI-гард: стендэлон-демон, оффлайн, loopback-only.

Контур этого бандла: **full** — детерминированные детекторы (чексуммы, regex,
ахо-автомат) + обратимое маскирование (vault) + модельный путь каскадов 1–2
(lockR-экстрактор + Decide-арбитр на ONNX, монтаж #14A). Бинарь собран с
\`ort-inference\`; каскады 1–2 поднимаются при \`FASAD_MODEL_DIR\` с весами
(скачивание — \`models/README.md\`, ~879 МБ, sha256-гейт). Без весов демон
работает каскадом 0 — легальный режим, честная стадия в \`/health\`
(\`"stage":"cascade-0-only"\`); с названным \`FASAD_MODEL_DIR\` и
несмонтировавшимися весами старт отказывает (fail-closed, код 2).

## Запуск

    bin/fasad${ext}                 # слушает http://127.0.0.1:8765/health
    FASAD_PORT=9000 bin/fasad${ext}  # порт через env

Конфигурация — переменные окружения \`FASAD_*\` (бинд строго loopback):
полный список держит \`docs/release.md\` §Запуск, первичка —
\`crates/guard-daemon/src/config.rs\`.

## Модели (каскады 1–2)

    ./scripts/fetch-models.sh                       # sha256-гейт по манифесту
    export FASAD_MODEL_DIR="\$HOME/.cache/fasad-models"

Детали, раскладка кеша, зеркало HF — \`models/README.md\`. Полный контур =
бинарь + веса + \`FASAD_MODEL_DIR\`; без весов работает каскад-0 (стадия видна
в \`/health\`).

## Файлы бандла

- \`LICENSE\` — Apache-2.0 (текст лицензии продукта)
- \`THIRD-PARTY-LICENSES.txt\` — сторонние лицензии (сгенерировано cargo-about)
- \`schema.default.json\` — канон схемы классов (\`FASAD_SCHEMA\`)
- \`scripts/fetch-models.sh\` + \`models/manifest.tsv\` + \`models/README.md\` —
  скачивание весов каскадов 1–2 по sha256-манифесту
- \`SHA256SUMS.txt\` — sha256 всех файлов бандла
EOF

if [ "$is_win" -eq 1 ] || [ "$os" = "Darwin" ]; then
    cat >>"$stage/README.md" <<EOF
- \`bin/fasad-tray${ext}\` — тот же демон с иконкой трея (#128): клик
  открывает \`http://127.0.0.1:<порт>/ui\` в браузере, меню = «Выход
  (graceful)». Headless \`bin/fasad\` — дефолт, трей = витрина рабочего стола.
EOF
else
    cat >>"$stage/README.md" <<'EOF'
- `contrib/systemd/fasad.service` — юнит linux-контура (#140): Static,
  `Restart=on-failure`, `MemoryMax=1843M` (SPEC §1 ≤1.8 ГБ),
  `LimitMEMLOCK=64K` (vault-пул 34 KiB), `User=fasad`, `NoNewPrivileges`.
EOF
fi

if [ "$is_win" -eq 0 ] && [ "$os" != "Darwin" ]; then
    cat >>"$stage/README.md" <<'EOF'

## Linux: systemd

Трея в linux-артефакте нет физически (`docs/dep-verify-crates.md` §16);
контур — консольный демон под systemd:

    useradd -r -s /usr/sbin/nologin -d /var/lib/fasad -m fasad
    install -Dm755 bin/fasad /usr/local/bin/fasad
    install -Dm644 contrib/systemd/fasad.service /etc/systemd/system/fasad.service
    systemctl start fasad.service

Конфиг юнита — `/etc/default/fasad` (`EnvironmentFile=-`, `FASAD_*`-переменные).
Юнит статический: `systemctl enable` — решение оператора машины.
EOF
fi

cat >>"$stage/README.md" <<EOF

## Исходники и документация

https://github.com/tayuLuc/fasad — спецификация (docs/SPEC.md), политика
версий (RELEASES.md), процедуры релиза (docs/release.md), метрики RAM
(docs/model-audit.md §Release RSS).
EOF

# SHA-инструмент: macOS и Git-for-Windows несут shasum, Linux — sha256sum.
if command -v shasum >/dev/null 2>&1; then
    sha_cmd="shasum"
    set -- -a 256
else
    sha_cmd="sha256sum"
    set --
fi

(
    cd "$stage"
    # SC2094 (info): «не читай и пиши один файл в пайплайне» — здесь ложняк:
    # SHA256SUMS.txt исключён из выборки (`! -name`), список фиксируется до
    # записи. shellcheck не видит семантику find-предиката, поэтому disables
    # точечный, с причиной (гейт `lint-actions` гоняет BASH_SHELLCHECK).
    # shellcheck disable=SC2094
    find . -type f ! -name SHA256SUMS.txt -print0 | sort -z \
        | xargs -0 "$sha_cmd" "$@" > SHA256SUMS.txt
)

mkdir -p "$OUT"
if [ -n "$ext" ]; then
    arch="$OUT/fasad-$version-$triple-$LABEL.zip"
    rm -f "$arch"
    win_stage="$(cygpath -w "$stage" 2>/dev/null || printf '%s' "$stage")"
    win_arch="$(cygpath -w "$arch" 2>/dev/null || printf '%s' "$arch")"
    # Катаргом кладём САМ каталог стейджа, а не `$win_stage\*`: с `\*`
    # Compress-Archive раскладывает файлы в корень архива, и layout
    # расходится с tar.gz-веткой (там верхний каталог `fasad-<ver>-<triple>-<label>/`
    # есть) — scripts/verify-bundle.sh именовал бы это «в архиве нет каталога
    # бандла». Самопроверка 21.10 на macOS это не ловит (там tar-ветка),
    # ловит только windows-2022.
    powershell.exe -NoProfile -Command \
        "Compress-Archive -Path '$win_stage' -DestinationPath '$win_arch'" >/dev/null
else
    arch="$OUT/fasad-$version-$triple-$LABEL.tar.gz"
    tar -czf "$arch" -C "$OUT" "fasad-$version-$triple-$LABEL"
fi
(
    cd "$OUT"
    "$sha_cmd" "$@" "$(basename "$arch")" > "$(basename "$arch").sha256"
)

printf 'make-bundle ok: %s (%s байт, версия %s, triple %s)\n' \
    "$arch" "$(wc -c < "$arch" | tr -d ' ')" "$version" "$triple"
