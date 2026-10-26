#!/usr/bin/env bash
# #180 решёточный тест .githooks/commit-msg: live-контейнер (git init temp-
# репо + реальные коммиты с core.hooksPath на проверяемый hook), не моки:
# дискриминатор = git-семантика (hook вызывается на commit-msg; --no-verify
# обходит = git-контракт, фиксируется кейсом). Кейсы (ТЗ #180 + инцидент
# authorship-trailers):
#   1 чистый коммит = rc 0
#   2 человек-трейлер (github noreply) = rc 0
#   3 внешний домен (anthropic) = rc 1
#   4 пустой уголк <> = rc 1
#   5 мусорный @local = rc 1
#   6 пустой user.email = rc 1
#   7 --no-verify = rc 0 (контракт-граница, док в hook)
#   8 CRLF-трейлер = rc 1 (git.exe-склейка win = \r; sed-нормализация hook)
# Вывод = строки «CASE|имя|rc=N|OK/FAIL», финаль «HOOKS|ok» + rc 0.
set -u
root="$(cd "$(dirname "$0")/../.." && pwd)"
hook="$root/.githooks/commit-msg"
[ -x "$hook" ] || { echo "HOOKS|FAIL|нет исполняемого $hook"; exit 1; }
t="$(mktemp -d "${TMPDIR:-/tmp}/fasad-hooks-XXXX")"
trap 'rm -rf "$t"' EXIT
cd "$t" && git init -q r && cd r || exit 1
# -c overrides = решёточный контракт НЕ зависит от global gitconfig
# (машина оператора может нести user.email глобально; empty_email-кейс
# обязан краснеть на любой машине)
echo a > a && git add a
fail=0
check() { # $1 имя, $2 ожидаемый rc, $3 сообщение [, $4 "--no-verify"]
    local got=0
    echo "$1" >> tracked   # каждый кейс = свой коммит (иначе «nothing to commit»)
    git add tracked
    if [ "${4:-}" = "--no-verify" ]; then
        git -c user.email=lattice@example.com -c core.hooksPath="$root/.githooks" commit -q --no-verify -m "$3" || got=$?
    else
        git -c user.email=lattice@example.com -c core.hooksPath="$root/.githooks" commit -q -m "$3" || got=$?
    fi
    if [ "$got" -eq "$2" ]; then
        echo "CASE|$1|rc=$got|OK"
    else
        echo "CASE|$1|rc=$got|ожидался $2|FAIL"
        fail=1
    fi
}
check clean 0 "clean commit"
check human_trailer 0 "feat: что-то

Co-authored-by: Jane Doe <jane@users.noreply.github.com>"
check external_anthropic 1 "fix

Co-authored-by: Claude <noreply@anthropic.com>"
check empty_angle 1 "fix

Co-authored-by: <>"
check local_domain 1 "fix

Co-authored-by: bot@local"
# пустой email АВТОРА: -c user.email= = автор «lattice <>» в ЭТОМ коммите
# (первичка hook-контракта #180: hook читает git var GIT_AUTHOR_IDENT,
# а не живой git config среды; env-override автора = тот же канал)
got=0
git -c user.email= -c core.hooksPath="$root/.githooks" commit -q -m "anon" || got=$?
if [ "$got" -eq 1 ]; then
    echo "CASE|empty_email|rc=1|OK"
else
    echo "CASE|empty_email|rc=$got|ожидался 1|FAIL"
    fail=1
fi
check no_verify_bypass 0 "bypass

Co-authored-by: Claude <noreply@anthropic.com>" --no-verify
# CRLF-сообщение (win-склейка): hook напрямую с MSG-файлом (git-клиент на
# unix сам CRLF не плодит, а win-среда = первичка #225-провена)
printf 'fix\r\n\r\nCo-authored-by: Claude <noreply@anthropic.com>\r\n' > "$t/msgcrlf"
if "$hook" "$t/msgcrlf" 2>/dev/null; then
    echo "CASE|crlf_trailer|rc=0|ожидался 1|FAIL"
    fail=1
else
    echo "CASE|crlf_trailer|rc=1|OK"
fi
if [ "$fail" -eq 0 ]; then
    echo "HOOKS|ok|8 кейсов"
    exit 0
else
    echo "HOOKS|FAIL"
    exit 1
fi
