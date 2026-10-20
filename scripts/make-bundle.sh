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
#   bin/fasad[.exe]        релизный бинарь каскада-0 (see docs/release.md §Что в бандле)
#   README.md              ссылка на исходники + запуск (генерится здесь)
#   LICENSE                Apache-2.0 (текст лицензии продукта)
#   schema.default.json    канон схемы (config/, FASAD_SCHEMA)
#   THIRD-PARTY-LICENSES.txt  сгенерированный `just deps-licenses`
#   SHA256SUMS.txt         хэши всех файлов бандла (кроме самого себя)
#
# Формат архива: tar.gz (unix), zip (Windows: Git-for-Windows tar zip не умеет,
# архиватор = powershell Compress-Archive).
#
# use: scripts/make-bundle.sh [--binary PATH] [--licenses PATH] [--out DIR]
#                          [--label cascade-0]
#
# Метка контура в имени артефакта (`-cascade-0`) обязательна: бандл НЕ содержит
# модельного пути (каскады 1–2), и «просто fasad» читался бы как полный гард.
# names: fasad-<version>-<triple>-<label>.tar.gz / .zip

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN=""
LICENSES="dist/THIRD-PARTY-LICENSES.txt"
OUT="dist"
LABEL="cascade-0"

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
        -h | --help)
            echo "использование: scripts/make-bundle.sh [--binary PATH] [--licenses PATH] [--out DIR] [--label cascade-0]"
            exit 0
            ;;
        *)
            die "неизвестный аргумент: $1"
            ;;
    esac
done

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
[ -x "$BIN" ] || die "нет бинаря $BIN — сначала cargo build --release -p guard-daemon (just release-build)"
[ -f "$LICENSES" ] || die "нет $LICENSES — сначала just deps-licenses"

stage="$OUT/fasad-$version-$triple-$LABEL"
rm -rf "$stage"
mkdir -p "$stage/bin"
cp "$BIN" "$stage/bin/"
cp LICENSE "$stage/LICENSE"
cp config/schema.default.json "$stage/schema.default.json"
cp "$LICENSES" "$stage/THIRD-PARTY-LICENSES.txt"

# README-ссылка: короткая ориентировка пользователя бандла. Метка контура —
# fact, а не витрина: бинарь собирается без `ort-inference` (её нет у
# guard-daemon: crates/guard-daemon/Cargo.toml), модельного пути спанов в
# демоне нет (crates/guard-daemon/src/pipeline.rs, заголовок модуля).
cat > "$stage/README.md" <<EOF
# fasad $version ($triple, контур: $LABEL)

Локальный AI-гард: стендэлон-демон, оффлайн, loopback-only.

Контур этого бинаря: **каскад-0** — детерминированные детекторы (чексуммы,
regex, ахо-автомат) + обратимое маскирование (vault). Модельный путь
(каскады 1–2 на ONNX) в демоне ещё не сведён: \`guard-daemon\` не имеет фичи
\`ort-inference\`, и спаны из моделей в \`/v1/analyze\` не появляются
(промер: \`/health\` → \`"stage":"cascade-0-only"\`). Честная метка контура —
docs/release.md §«Что в бандле».

## Запуск

    bin/fasad${ext}                 # слушает http://127.0.0.1:8765/health
    FASAD_PORT=9000 bin/fasad${ext}  # порт через env

Конфигурация — переменные окружения \`FASAD_*\` (бинд строго loopback):
полный список держит \`docs/release.md\` §Запуск, первичка —
\`crates/guard-daemon/src/config.rs\`.

## Файлы бандла

- \`LICENSE\` — Apache-2.0 (текст лицензии продукта)
- \`THIRD-PARTY-LICENSES.txt\` — сторонние лицензии (сгенерировано cargo-about)
- \`schema.default.json\` — канон схемы классов (\`FASAD_SCHEMA\`)
- \`SHA256SUMS.txt\` — sha256 всех файлов бандла

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
    powershell.exe -NoProfile -Command \
        "Compress-Archive -Path '$win_stage\\*' -DestinationPath '$win_arch'" >/dev/null
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
