#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# scan_lang — локальный язык-гейт текста репозитория: CJK-утечки и смешанный скрипт.
"""
Зачем: документы и комментарии проекта — русские (plus латинские термины), код —
латиница. Утечка CJK-иероглифа в русский текст и «склейка» кириллицы с латиницей
внутри одного слова (кирилльный корень + латинный хвост без разделителя) — типовой
артефакт LLM-генерации; он не виден глазу и не ловится ruff'ом.

Реализация — кодовые диапазоны, а не `grep -i`: на macOS BSD grep трактует классы
не по кодовым точкам и на CJK-диапазонах врёт (ложно-красный «161 хит» — промер
20.10, внесён в реестр ложно-зелёных как «locale-blind language gates»). Отсюда и
python, и явные числовые диапазоны.

Что ищет:
1. cjk   — символы CJK/Hangul/Kana/Fullwidth (U+3040-U+30FF, U+3400-U+4DBF,
           U+4E00-U+9FFF, U+AC00-U+D7AF, U+F900-U+FAFF, U+FF00-U+FFEF,
           U+20000-U+2FA1F).
2. mixed — в одном слове (алфавитно-цифровой токен, дефис = разделитель) есть и
           кириллица, и латиница: `fp16-квант` чисто (дефис разделяет два слова),
           слитное написание кириллической основы с латинской — нет. Примеры дефекта
           намеренно не приводятся литералом: документация о детекторе не должна
           сама быть его срабатыванием (иначе гейт краснеет на себе).

Исключение (минимальный механизм, #90): директива `scan-lang:` + `allow` (пишется
слитно) в той же строке, где легальный хит: полноширинные цифры в тесте, цитата
иероглифов в доке, намеренная склейка кириллицы с латиницей в тестовых данных
(предмет теста — двускриптный токен, «чинить» его нельзя).
Границы механизма: область действия = ровно одна строка (файловых и глобальных
исключений нет — они и есть способ потерять гейт); директива обязана стоять на
строке с хитом, «мёртвая» директива (на строке без хита) считается дефектом и
краснит прогон: мёртвое исключение — та же ложно-зелёная, что и мёртвый контроль.
Разрешённые учитываются в строке итога (`allowed|N`), то есть исключение видно в
отчёте, а не тонет.

Positive control (обязателен, иначе зелёное = ничто): `--self-test` прогоняет
детекторы по посаженным образцам, включая пару «директива с хитом» / «директива
без хита».

Control-строки собраны из escape-последовательностей, поэтому самого себя сканер
не пачкает: CJK-литералов в исходнике нет (иначе сканер был бы глух к собственному
классу дефекта).

Запуск:
  uv run --locked python scripts/scan_lang.py --self-test --all
  uv run --locked python scripts/scan_lang.py --self-test --files docs/golden-report.md tools/metrics/union_recall.py
  # `--self-test` БЕЗ входных файлов даёт rc 2 (проверка текста не выполнена) —
  # это намеренно: control жив, но обход не проверял ни одного файла (промер 21.10:
  # так же и на main, и после #105).
  # `--all` вместе с `--files`: выигрывает `--all`, список `--files` игнорируется
  # (строка о приоритете — в `--help` у обоих флагов, поведение не менялось).

rc-контракт (#105; та же легенда печатается в `--help`, текст — константа RC_LEGEND):
  0 = чисто.
  1 = найдены хиты.
  2 = проверка НЕ выполнена: positive control не сработал (сканер мёртв), на входе
      0 файлов, ни один входной файл не прочитан, либо git-инвентарь недоступен
      (`--all` в дереве без `.git` / без бинаря git — #116 F5). Это не «чисто» и
      не «упал тулинг» — это отсутствие контроля; в just-рецепте оно краснит прогон
      ровно своим кодом (just пробрасывает rc команды — промер 1.58.0).
      Доводить «дерево не под git» до rc 1 нельзя: rc 1 значит «найдены хиты», а
      здесь не найдено ничего — это ложь о причине отказа (#116 F5).

Обход `--all` берёт файлы и без расширения (#103): у Path("justfile").suffix пусто,
под фильтр TEXT_EXT такие файлы не попадали целиком (justfile, LICENSE, dotfiles).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

CYR_RANGE = (0x0400, 0x04FF)  # кириллица (включая укр./бел. литеры)
LATIN_RUN = re.compile(r"[A-Za-z]")
CYR_RUN = re.compile("[\u0400-\u04FF]")
CJK_RANGES = ((0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF),
              (0xF900, 0xFAFF), (0xFF00, 0xFFEF), (0x20000, 0x2FA1F))
WORD_RE = re.compile(r"[0-9A-Za-z\u0400-\u04FF]+")
# Литерал токена собран конкатенацией: строка с ним в этом файле была бы
# «мёртвой директивой» (красный прогон), а документация о директиве обязана её
# называть. Та же доктрина, что у control-строк: сканер не пачкает себя — и это
# не метафора: определение регулярки через литерал красило прогон на самом себе.
ALLOW_TOKEN = "scan-lang:" + "allow"
# Директива исключения: ровно в той же строке, что и легальный литерал. Форма
# строгая (без пробела после двоеточия): толерантность сделала бы «мёртвой
# директивой» любое прозаическое упоминание механизма в документации.
# Мета-символов в токене нет, `re.escape` не нужен; экранирование на месте —
# страховка от того, что в токен когда-нибудь впишут регексп-спецсимвол.
ALLOW_RE = re.compile(re.escape(ALLOW_TOKEN))
# Экраны внутри строковых литералов (JSON/исходники): `\n` в данных — НЕ буква `n`
# перед кириллицей. Без этого шага 169 хитов в golden-v1.jsonl были ложными (промер 21.10).
ESC_RE = re.compile(r"\\[nrtvbf]")


def _in(ch: str, lo: int, hi: int) -> bool:
    return lo <= ord(ch) <= hi


def scan_lines(text: str) -> tuple[list, list, list]:
    """(хиты, разрешённые, мёртвые директивы) — три списка кортежей.

    Область директивы = одна строка. Строка с директивой и хитами уходит в
    `allowed`, строка с директивой без хитов — в `dead` (дефект: исключение,
    которое ничего не исключает, переживает свой CJK и становится дырой, о
    которой никто не помнит).
    """
    hits: list[tuple[int, str, str]] = []
    allowed: list[tuple[int, str, str]] = []
    dead: list[tuple[int, str, str]] = []
    for ln, line in enumerate(ESC_RE.sub(" ", text).splitlines(), start=1):
        row: list[tuple[int, str, str]] = []
        for ch in line:
            if any(_in(ch, lo, hi) for lo, hi in CJK_RANGES):
                row.append((ln, "cjk", f"U+{ord(ch):04X}"))
        for w in WORD_RE.findall(line):
            # Дефис/подчёркивание НЕ входят в токен ⇒ `fp16-квант` = два слова
            # (чисто), а слитная склейка график — один токен с двумя скриптами.
            if LATIN_RUN.search(w) and CYR_RUN.search(w):
                row.append((ln, "mixed", w))
        if not row:
            if ALLOW_RE.search(line):
                dead.append((ln, "deadallow", ALLOW_TOKEN + " (на строке нет хита; "
                        "в тексте о самой директиве токен пишут разрывом)"))
            continue
        if ALLOW_RE.search(line):
            allowed.extend(row)
        else:
            hits.extend(row)
    return hits, allowed, dead


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Хиты (номер строки 1-база, вид, фрагмент).

    Символы перебираются напрямую: регексп-класс из диапазонов — то место, где
    сканер умер бы молча (positive control поймал ровно эту ошибку: класс из
    НАЧАЛ диапазонов ловил 0 из 2 посаженных иероглифов).
    """
    return scan_lines(text)[0]


def self_test() -> int:
    """Positive control: посаженные образцы обязаны быть пойманы, чистые — нет."""
    dirty_cjk = "проверка " + "\u6d4b\u8bd5" + " текста"  # 2 иероглифа, собранных из escapes
    dirty_mixed = "квант" + "fp16" + " без пробела"
    clean = ["fp16-квант через дефис", "golden-набор, onnxruntime 1.31.0",
             "тест на русском и UV run рядом", "U+0410 — это кириллица A"]
    ok = True
    for name, text, want in (("cjk", dirty_cjk, "cjk"), ("mixed", dirty_mixed, "mixed")):
        kinds = {k for _, k, _ in scan_text(text)}
        good = want in kinds
        ok = ok and good
        print(f"CONTROL|{name}|planted|{'caught' if good else 'MISSED'}|kinds|{sorted(kinds)}")
    for text in clean:
        got = scan_text(text)
        if got:
            ok = False
            print(f"CONTROL|clean|FALSE-POSITIVE|{text}|{got}")
    # Директива: живое исключение (хит есть, он разрешён) и мёртвое (хита нет).
    allow_line = "широкие цифры " + "\uff18\uff19" + " легальны # " + ALLOW_TOKEN
    h_al, a_al, d_al = scan_lines(allow_line)
    good = not h_al and len(a_al) == 2 and not d_al
    ok = ok and good
    print(f"CONTROL|allow|planted|{'caught' if good else 'MISSED'}"
          f"|hits|{len(h_al)}|allowed|{len(a_al)}|dead|{len(d_al)}")
    dead_line = "чистая строка без литералов # " + ALLOW_TOKEN
    h_d, a_d, d_d = scan_lines(dead_line)
    good = len(d_d) == 1 and not h_d and not a_d
    ok = ok and good
    print(f"CONTROL|deadallow|planted|{'caught' if good else 'MISSED'}|dead|{len(d_d)}")
    # Инвентарь (#103): файлы без suffix — прежняя слепая зона TEXT_EXT. Контроль
    # обязан ловить её возвращение: без этой пары строк гейт над justfile/LICENSE
    # стал бы молча зелёным ровно в тот момент, когда из фильтра выпадает имя.
    inventory = (("justfile", True), ("LICENSE", True), (".gitignore", True),
                 ("docs/x.md", True), ("Cargo.lock", False), ("models/w.onnx", False))
    bad = [n for n, want in inventory if _is_text_file(n) != want]
    good = not bad
    ok = ok and good
    print(f"CONTROL|inventory|planted|{'caught' if good else 'MISSED'}|bad|{bad}")
    # Обход (#116 F2): тот же состав обязан пройти через СТРОКУ ФИЛЬТРА внутри
    # git_text_files, а не только через предикат выше. Мутация call-site (фильтр
    # сведён к `suffix in TEXT_EXT`, предикат цел) ноги `inventory` не касается:
    # она печатала «caught» и `verdict|live`, пока обход терял файлы без suffix и
    # глушил посаженный CJK в justfile (промер ревью: files 141 → 134, clean, rc=0).
    # Пара «имя без suffix + lock» бьёт ровно по этой границе.
    try:
        traversal = git_text_files(["justfile", "Cargo.lock"])
        good = "justfile" in traversal and "Cargo.lock" not in traversal
    except Exception as e:  # широкий except: control обязан погаснуть, а не упасть
        traversal, good = f"исключение|{type(e).__name__}", False
    ok = ok and good
    print(f"CONTROL|traversal|planted|{'caught' if good else 'MISSED'}"
          f"|in|justfile,Cargo.lock|out|{traversal}")
    print(f"CONTROL|verdict|{'live' if ok else 'dead-scanner'}")
    return 0 if ok else 2


TEXT_EXT = {".md", ".rs", ".py", ".toml", ".yml", ".yaml", ".json", ".jsonl",
            ".tsv", ".sh", ".txt"}
# Файлы БЕЗ расширения (#103): у `Path("justfile").suffix` — пустая строка, т.е.
# под TEXT_EXT они не видимы сканеру ЦЕЛИКОМ, а комментарии justfile читаются
# чаще кода (прозаические хвосты их комментариев правили в #95 — сводки
# `just --list`). Список имён явный, а не эвристика «без suffix + размер/пробник»:
# whitelist виден в diff и не решает молча, что считать текстом. Cargo.lock тут
# НЕТ намеренно (промер #116: 3 lock-файла под git — `Cargo.lock`, `fuzz/Cargo.lock`,
# `uv.lock`; suffix `.lock`): машинный вывод разрешателя — шум, а не текст, который
# кто-то пишет по-русски.
TEXT_NAMES = {".gitattributes", ".gitignore", ".python-version", "Justfile",
              "LICENSE", "Makefile", "NOTICE", "makefile", "justfile"}


def _is_text_file(f: str) -> bool:
    """Файл под гейт: расширение из TEXT_EXT либо имя из TEXT_NAMES (#103)."""
    p = Path(f)
    return p.suffix in TEXT_EXT or p.name in TEXT_NAMES


REPO_ROOT = Path(__file__).resolve().parents[1]


class GitInventoryError(RuntimeError):
    """git-инвентарь недоступен: дерево без `.git` либо нет бинаря git (#116 F5)."""


def _git_ls_files() -> list[str]:
    """Файлы репозитория (`git ls-files` из корня дерева этого скрипта).

    Без обёртки `check=True` бросает `CalledProcessError` (rc 128), процесс
    выходит с rc 1, а rc 1 в контракте сканера значит «НАЙДЕНЫ ХИТЫ»: распакованный
    тарбол без `.git` выглядел бы как найденная CJK-утечка — ложь о причине отказа
    (absent, corrupt и «найдено» — три разных диагноза). Вызывающий переводит это в
    NOINPUT reason|no-git (rc 2 = «проверка не выполнена»), тип причины — в
    отдельную строку `LANG|git|…`, чтобы «нет бинаря» и «не git-дерево» не были
    одним словом.
    """
    try:
        out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=True)
    except FileNotFoundError as e:
        raise GitInventoryError("binary|git-not-found") from e
    except subprocess.CalledProcessError as e:
        first = (e.stderr or "").strip().splitlines()
        detail = first[0] if first else "нет stderr"
        raise GitInventoryError(f"not-a-git-repo|rc{e.returncode}|{detail}") from e
    return out.stdout.splitlines()


def git_text_files(paths: list[str] | None = None) -> list[str]:
    """Текстовые файлы обхода: из git-инвентаря (дефолт `--all`) либо из `paths`.

    Критерий «текстовый» = расширение из TEXT_EXT либо имя из TEXT_NAMES (#103:
    файлы без suffix иначе выпадают из инвентаря репозитория молча).

    Инъекция `paths` нужна не для удобства: positive control обязан прогонять
    СТРОКУ ФИЛЬТРА здесь (call-site), а не только предикат `_is_text_file` (#116 F2).
    До правки контроль мерил предикат, и мутация фильтра до `suffix in TEXT_EXT`
    (предикат цел!) роняла обход 141 → 134 файлов и глушила посаженный CJK в
    justfile: `CONTROL|verdict|live` + `LANG|verdict|clean` при живой утечке —
    ровно тот ложно-зелёный класс, ради которого делался #103. Пара
    `["justfile", "Cargo.lock"]` бьёт по границе списка: имя без suffix обязано
    войти, lock — не войти.
    """
    if paths is None:
        paths = _git_ls_files()
    return [f for f in paths if _is_text_file(f)]


RC_LEGEND = (
    "rc-контракт (#105, #116 F5):\n"
    "  0  чисто\n"
    "  1  найдены хиты\n"
    "  2  проверка НЕ выполнена: positive control мёртв (--self-test), на входе 0\n"
    "     файлов (--all по дереву без текстовых = сломанный glob), ни один входной\n"
    "     файл не прочитан (--files по несуществующим путям), git-инвентарь\n"
    "     недоступен (--all в дереве без .git / без бинаря git) = reason|no-git.\n"
    "     2 — не «чисто» и не «найдены хиты» (это 1).\n"
    "     just пробрасывает rc команды, поэтому в рецепте это красный прогон.\n"
    "Флаги входа: --all выигрывает у --files (вместе = обход git-инвентаря,\n"
    "  список --files игнорируется).\n")


def _noinput(reason: str) -> int:
    """Пустой обход = «проверка не выполнена», а не «чисто» (#105).

    Реестр ложно-зелёных: «зелёный = пустое множество проверенного». Печать идёт
    в stdout — на пути рецепта (`--self-test` первым) CONTROL-строки уже напечатаны,
    так что в логе видно и живой контроль, и то, что проверять было нечего.
    `reason|no-git` (#116 F5): git-инвентарь не собран (дерево без `.git`, бинарь
    git отсутствует) — обход не начинался, это тот же класс «нечего проверять»,
    поэтому код 2, а не 1 («найдены хиты») и не traceback.
    """
    print(f"LANG|verdict|NOINPUT|files|0|hits|-1|reason|{reason}")
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Язык-гейт текста репозитория: CJK-утечки и склейка кириллицы "
                    "с латиницей.",
        epilog=RC_LEGEND,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", nargs="*", default=[],
                    help="явный список файлов (на диффе PR); пустой список или "
                         "сплошь nonexistent-пути = rc 2, не «чисто»; вместе с "
                         "--all не применяется: --all выигрывает")
    ap.add_argument("--all", action="store_true",
                    help="весь текстовый tree под git (инвентарь репозитория; "
                         "пустой вход = rc 2; дерево без .git = rc 2 reason|no-git); "
                         "вместе с --files выигрывает: список --files игнорируется")
    ap.add_argument("--self-test", action="store_true",
                    help="positive control по посаженным образцам; мёртвый "
                         "контроль = rc 2")
    args = ap.parse_args()
    rc_control = self_test() if args.self_test else 0
    if rc_control != 0:
        return rc_control
    if args.all:
        # --all выигрывает у --files: список `--files` при `--all` игнорируется
        # (задокументировано в --help, поведение не менялось).
        try:
            files = git_text_files()
        except GitInventoryError as e:
            # Инвентаря нет (дерево без .git / бинарь git отсутствует) — обход не
            # начинался. Не rc 1 («хиты», как было до #116 F5: traceback
            # CalledProcessError) и не «чисто»: NOINPUT reason|no-git, rc 2.
            print(f"LANG|git|no-inventory|{e}")
            return _noinput("no-git")
    else:
        files = list(args.files)
    if not files:
        # Пустое множество входа — не «чисто», а «проверка не выполнена»
        # (реестр ложно-зелёных: «зелёный = пустое множество проверенного»).
        return _noinput("empty-input")
    total = 0
    n_allowed = 0
    n_scanned = 0
    for f in files:
        p = Path(f)
        if not p.is_file():
            print(f"LANG|skip|{f}|нет файла")
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            print(f"LANG|skip|{f}|{type(e).__name__}")
            continue
        n_scanned += 1
        hits, allowed, dead = scan_lines(text)
        for ln, kind, frag in hits:
            total += 1
            print(f"LANG|hit|{f}|line|{ln}|kind|{kind}|{frag}")
        for ln, kind, frag in dead:
            total += 1
            print(f"LANG|hit|{f}|line|{ln}|kind|{kind}|{frag}")
        # Разрешённые в отчёт попадают суммарно по строке: исключение должно
        # быть видно, а не тонеть в молчании.
        by_line: dict[int, int] = {}
        for ln, _kind, _frag in allowed:
            by_line[ln] = by_line.get(ln, 0) + 1
            n_allowed += 1
        for ln in sorted(by_line):
            print(f"LANG|allow|{f}|line|{ln}|count|{by_line[ln]}")
    if n_scanned == 0:
        # Все входы оказались skip'ами (путь мимо файла, бинарь не декодируется как
        # utf-8): обход не проверил ни байта — тот же ложно-зелёный класс, что и
        # пустой вход, поэтому и вердикт тот же: rc 2, не «чисто» (#105).
        return _noinput("no-readable-file")
    print(f"LANG|verdict|{'clean' if total == 0 else 'DIRTY'}|files|{len(files)}"
          f"|scanned|{n_scanned}|hits|{total}|allowed|{n_allowed}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
