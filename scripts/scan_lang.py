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
3. arabic / hebrew / devanagari (#121) — символы Arabic U+0600-U+06FF, Hebrew
           U+0590-U+05FF, Devanagari U+0900-U+097F. Тот же каркас, что у cjk:
           «в корпусе такой графики нет ни одной» — промер по дереву перед правкой:
           0 символов трёх диапазонов в 148 файлах под гейтом, значит любое её
           появление = утечка, а не текст.

Чего гейт НЕ красит (важно, #121 про это спрашивают): чистую кириллицу — нигде.
Правило про «случайную утечку в технические артефакты» (иероглиф, склейка
кириллицы с латиницей, арабский токен в доке), а не про язык prose: русские
UI-тексты (`ui/app.js` 1554, `about.hbs` 581, `index.html` 428, `ui/app.css` 118
кирилличных символов), `rss_mach.c` (569) и любой `.md` про русский — хитов не
дают (промер: hits=0 во всех пяти файлах, суффиксы которых добавлены в #119).
Разрешать их allow-директивой нечего: директива на строке/в файле без хита =
мёртвое исключение, та самая ложно-зелёная дыра, ради которой гейт и писался.

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
без хита», посад каждой из трёх новых график (#121), чистую кириллицу — как
чистую (#121: гейт про арабицу/иврит/деванагари, не про кириллицу в .md) и пару
инвентаря «app.js/.css/.html/.hbs/.c входят, .wasm/.onnx не входят» (#119).
#125 N2: у каждой из трёх график контроль сажает ТРИ символа — нижнюю границу
блока (U+0600/U+0590/U+0900), середину (#121) и верхнюю (U+06FF/U+05FF/U+097F),
по ОДНОМУ символу на ногу. Посад только середины мутацию границы не видит: сдвиг
Arabic lo 0x0600→0x0620 оставлял контроль зелёным, а U+0600 протекал (промёрено
22.10: базовый файл + мутация = зелёный, head + мутация = MISSED и rc 2).

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
      0 файлов, ни один входной файл не прочитан, git-инвентарь недоступен
      (`--all` в дереве без `.git` / без бинаря git — #116 F5), либо `--all` запущен
      не из корня репозитория (#116 N2: инвентарь строится от REPO_ROOT, пути обхода
      читаются относительно cwd → из подкаталога 143 skip'а и
      reason|no-readable-file; теперь reason|cwd-not-repo-root), либо getcwd
      недоступен — рабочий каталог удалён (#125 N1: `Path.cwd()` стоял СНАРУЖИ try,
      FileNotFoundError из-под getcwd уходил traceback'ом, процесс выходил с rc 1 =
      «найдены хиты»; теперь reason|cwd-unavailable. Достижимо НЕ только на Linux:
      промер 22.10 на macOS 26.6.2 (mkdir → chdir → rmdir, fd держим) — getcwd
      бросает FileNotFoundError и здесь, база давала traceback + rc 1, head даёт
      rc 2. Утверждение issue «macOS отдаёт устаревший путь → rc 2» промером
      опровергнуто). Это не «чисто» и не «упал тулинг» — это отсутствие контроля;
      в just-рецепте оно краснит прогон ровно своим кодом (just пробрасывает rc
      команды — промер 1.58.0).
      Доводить «дерево не под git» до rc 1 нельзя: rc 1 значит «найдены хиты», а
      здесь не найдено ничего — это ложь о причине отказа (#116 F5).

Обход `--all` берёт файлы и без расширения (#103): у Path("justfile").suffix пусто,
под фильтр TEXT_EXT такие файлы не попадали целиком (justfile, LICENSE, dotfiles).
Тот же класс слепой зоны закрыт в #119 суффиксами .js/.css/.html/.hbs/.c: под git
5 таких файлов (промер `git ls-files | grep -E '[.](js|css|html|hbs|c)$' | wc -l`),
обход вырос 143 → 148.
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
# #121: три новые графики (Arabic/Hebrew/Devanagari); в корпусе такой графики нет
# ни одной (промер перед правкой: 0 символов во всех 148 файлах под гейтом), значит
# её появление в файле = утечка. Тот же каркас, что CJK_RANGES, kind = имя диапазона
# (arabic/hebrew/devanagari). Границы — ровно свои Unicode-блоки (U+0600-U+06FF,
# U+0590-U+05FF, U+0900-U+097F: буквы, знаки препинания и цифры этих блоков), соседи
# за краем не трогаются. Литералов этих график в этом файле нет намеренно: строка
# с символом из диапазона была бы хитом на самом себе (доктрина control-строк) —
# образцы для контроля собраны из escape-последовательностей ниже. Кириллицу
# (CYR_RANGE) правило НЕ красит: она легальна в prose и в UI, #121 — не про неё.
SCRIPT_RANGES = (("arabic", 0x0600, 0x06FF), ("hebrew", 0x0590, 0x05FF),
                 ("devanagari", 0x0900, 0x097F))
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
            code = ord(ch)
            if any(_in(ch, lo, hi) for lo, hi in CJK_RANGES):
                row.append((ln, "cjk", f"U+{code:04X}"))
                continue
            # #121: тот же каркас для Arabic/Hebrew/Devanagari, один хит на символ.
            # Блоки не пересекаются с CJK, поэтому `continue` выше безопасен.
            for kind, lo, hi in SCRIPT_RANGES:
                if lo <= code <= hi:
                    row.append((ln, kind, f"U+{code:04X}"))
                    break
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
    # Образцы посажены эскейпами: литералом такой символ в этом файле был бы хитом
    # на самом себе (доктрина control-строк).
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
    # #121: посад каждого нового диапазона ОБЯЗАН дать ровно свой kind (сравнение
    # множества целиком, а не «want in kinds»: мутация, которая заводит араба в
    # CJK-ветку, дала бы «caught» и осталась зелёной).
    # N2 (#125): по граничному символу на блок (lo/hi), середины (#121) остаются.
    # Посад только середины (U+0637/U+05E9/U+0928) мутацию границы НЕ видит: сдвиг
    # Arabic lo 0x0600→0x0620 оставляет посаженное слово внутри диапазона, контроль
    # печатает «caught», а реальный протекающий символ (U+0600 — арабский знак
    # номера, типичный артефакт PDF-копий) уходит наружу. Промёрено: базовый файл +
    # эта мутация = зелёный; head + эта мутация = MISSED и rc 2.
    # Один символ на ногу — обязательно: lo и hi в ОДНОЙ строке переживают мутацию
    # любой из границ (вторая граница держит kind живым), т.е. был бы тот же
    # ложно-зелёный класс.
    for name, lo, hi, mid in (("arabic", "\u0600", "\u06ff", "\u0637\u0628\u0643\u0627"),
                              ("hebrew", "\u0590", "\u05ff", "\u05e9\u05dc\u05d5\u05dd"),
                              ("devanagari", "\u0900", "\u097f",
                               "\u0928\u092e\u0938\u094d\u0924\u0947")):
        for pos, token in (("lo", lo), ("mid", mid), ("hi", hi)):
            text = "русская строка " + token + " и конец строки"
            kinds = {k for _, k, _ in scan_text(text)}
            good = kinds == {name}
            ok = ok and good
            print(f"CONTROL|{name}-{pos}|planted|{'caught' if good else 'MISSED'}"
                  f"|kinds|{sorted(kinds)}")
    # #121 не про это, но проверяем ровно эту границу: чистая кириллица обязана
    # оставаться чистой (гейт ловит утечку в технические артефакты, а не язык prose).
    # Мутация «красить кириллицу» (CYR_RANGE в hit-правило) гасит этот контроль и
    # весь русскоязычный корпус разом.
    cyr_only = "полностью русская строка без латиницы: квант, чексумма, датасет"
    got_cyr = scan_text(cyr_only)
    good = not got_cyr
    ok = ok and good
    print(f"CONTROL|cyrillic-only|clean|{'ok' if good else 'FALSE-POSITIVE'}|hits|{len(got_cyr)}")
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
                 ("docs/x.md", True), ("Cargo.lock", False), ("models/w.onnx", False),
                 # #119: прежняя слепая зона whole-tree — суффиксы UI-каталога и
                 # C-харнеса. Пара из issue: app.js входит, бинарь .wasm — нет.
                 ("crates/guard-daemon/ui/app.js", True),
                 ("crates/guard-daemon/ui/app.css", True),
                 ("crates/guard-daemon/ui/index.html", True),
                 ("about.hbs", True), ("crates/guard-onnx/spike/rss_mach.c", True),
                 ("crates/guard-daemon/ui/model.wasm", False))
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
        want_in = ("justfile", "crates/guard-daemon/ui/app.js")
        traversal = git_text_files(list(want_in) + ["Cargo.lock"])
        good = all(w in traversal for w in want_in) and "Cargo.lock" not in traversal
    except Exception as e:  # широкий except: control обязан погаснуть, а не упасть
        traversal, good = f"исключение|{type(e).__name__}", False
    ok = ok and good
    print(f"CONTROL|traversal|planted|{'caught' if good else 'MISSED'}"
          f"|in|justfile,app.js,Cargo.lock|out|{traversal}")
    # N2 (#116): обход читает пути относительно cwd, а инвентарь строит от REPO_ROOT;
    # из подкаталога это давало 148 skip'ов и rc 2 no-readable-file — правда о
    # результате, ложь о причине. Предикат корня проверяется на паре путей, чтобы
    # мутация (`return True`) гасила контроль, а не делала ветку мёртвой.
    root_cases = ((REPO_ROOT, True), (REPO_ROOT / "docs", False), (Path("/"), False))
    bad_root = [str(c) for c, want in root_cases if _cwd_is_repo_root(c) != want]
    good = not bad_root
    ok = ok and good
    print(f"CONTROL|cwd-root|planted|{'caught' if good else 'MISSED'}|bad|{bad_root}")
    print(f"CONTROL|verdict|{'live' if ok else 'dead-scanner'}")
    return 0 if ok else 2


TEXT_EXT = {".md", ".rs", ".py", ".toml", ".yml", ".yaml", ".json", ".jsonl",
            ".tsv", ".sh", ".txt",
            # #119: слепая зона whole-tree — 5 файлов под git не попадали в обход
            # ни по суффиксу, ни по имени (промер `git ls-files | grep -E
            # '\.(js|css|html|hbs|c)$' | wc -l` = 5, ровно те, что названы в issue:
            # ui/app.js, ui/app.css, ui/index.html, about.hbs, spike/rss_mach.c).
            # Живая кириллица в них (1554/118/428/581/569 символов) — легальна:
            # hit-правило красит CJK, три новые графики и склейку кириллицы с
            # латиницей, а чистую кириллицу — нет (промер: hits=0 во всех пяти).
            # Значит allow-директивы им НЕ нужны: директива без хита = мёртвое
            # исключение, т.е. осознанно ослеплённый гейт на файлах, ради которых
            # покрытие и затевалось. `.c` проверен на «не бинарь-шум»: rss_mach.c =
            # C-исходник, декодируется как utf-8, 569 кирилличных символов в
            # комментариях харнеса.
            ".js", ".css", ".html", ".hbs", ".c"}
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


def _cwd_is_repo_root(cwd: Path) -> bool:
    """Корень ли репозитория — единственный валидный cwd для `--all` (N2 #116).

    Инвентарь (`git ls-files`) собирается от REPO_ROOT, а файлы обходятся путями
    ОТНОСИТЕЛЬНО cwd: промер до правки — запуск из `docs/` печатал 143 строки
    `LANG|skip|...|нет файла` и `rc 2 reason|no-readable-file`. Код верный
    (проверка не выполнена), а причина — ложь: её читают как «в дереве нет
    текстовых файлов», тогда как дерево целое,
    просто запущено не оттуда. Отдельный reason называет причину; сравнение
    `resolve()`-путей, а не «внутри ли REPO_ROOT»: из подкаталога относительные
    пути инвентаря всё равно не читаются.

    `cwd` приходит ПАРАМЕТРОМ (N1 #125): добывание пути (`Path.cwd()` = getcwd) —
    забота вызывающего, там же и try вокруг него. `except OSError` ниже закрывает
    ровно `resolve()` (символьные петли, нечитаемый путь) и больше не притворяется
    защитой от падения getcwd: `Path.cwd()` бросает FileNotFoundError ДО вызова
    этой функции, и внутренний try его не касался.
    """
    try:
        return cwd.resolve() == REPO_ROOT
    except OSError:  # нечитаемый cwd (удалённый каталог) = не корень, не traceback
        return False


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
    "rc-контракт (#105, #116 F5, #125 N1):\n"
    "  0  чисто\n"
    "  1  найдены хиты\n"
    "  2  проверка НЕ выполнена: positive control мёртв (--self-test), на входе 0\n"
    "     файлов (--all по дереву без текстовых = сломанный glob), ни один входной\n"
    "     файл не прочитан (--files по несуществующим путям), git-инвентарь\n"
    "     недоступен (--all в дереве без .git / без бинаря git) = reason|no-git,\n"
    "     запуск `--all` НЕ из корня репозитория = reason|cwd-not-repo-root (N2\n"
    "     #116: инвентарь строится от корня, пути читаются относительно cwd; до\n"
    "     правки случай давал reason|no-readable-file — правда о результате, ложь\n"
    "     о причине; из-под just ветка недостижима — just ставит cwd = каталог\n"
    "     justfile, она защищает прямой вызов `python scripts/scan_lang.py`),\n"
    "     рабочий каталог недоступен (getcwd упал: каталог удалён — бросает\n"
    "     FileNotFoundError и на Linux, и на macOS 26.6.2, промер 22.10) =\n"
    "     reason|cwd-unavailable (N1 #125: до правки Path.cwd() стоял вне try →\n"
    "     traceback → rc 1 = «найдены хиты»; промер: база из удалённого каталога —\n"
    "     traceback + rc 1, head — rc 2 reason|cwd-unavailable).\n"
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
    # cp1252-guard (CI windows-2022, python-golden): stdout раннера = cp1252,
    # кириллические print'ы (PRECHECK/METASENV/CONTROL/ANCHOR-тексты) падают
    # UnicodeEncodeError ДО вердикта = ложно-красный зуб (промер CI: red
    # python-golden windows на print("OK: хардкод-страж зелёный") #104-контура).
    # reconfigure utf-8 = стандарт CPython для класса; errors="replace" — запас
    # для узких кодовых страниц. В начале main(): закрывает print-пути всех
    # селфтест-веток; сканер #104 (литералы main) остаётся вне зоны (id 19-значн.).
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # stdout заменён (redirect_stdout в селфтестах) — не трогать
    ap = argparse.ArgumentParser(
        description="Язык-гейт текста репозитория: CJK/арабица/иврит/деванагари и "
                    "склейка кириллицы с латиницей.",
        epilog=RC_LEGEND,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", nargs="*", default=[],
                    help="явный список файлов (на диффе PR); пустой список или "
                         "сплошь nonexistent-пути = rc 2, не «чисто»; вместе с "
                         "--all не применяется: --all выигрывает")
    ap.add_argument("--all", action="store_true",
                    help="весь текстовый tree под git (инвентарь репозитория; "
                         "пустой вход = rc 2; дерево без .git = rc 2 reason|no-git; "
                         "запуск не из корня = rc 2 reason|cwd-not-repo-root); "
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
        # N1 (#125): cwd вычисляется ВНУТРИ try. До правки `Path.cwd()` стоял снаружи
        # (`except OSError` жил только внутри `_cwd_is_repo_root`, т.е. защищал
        # `resolve()`, а не `getcwd()`): getcwd() удалённого каталога бросает
        # FileNotFoundError ИМЕННО на этом вызове → traceback → rc 1 = «найдены
        # хиты», ровно тот класс «ложь о причине», против которого написан весь файл
        # (ср. #116 F5 про `CalledProcessError`). Достижимо и на macOS (утверждение
        # issue «macOS отдаёт устаревший путь → rc 2» промером 22.10 опровергнуто:
        # macOS 26.6.2, mkdir → chdir → rmdir при открытом fd → getcwd бросает
        # FileNotFoundError; база dce45f1 из такого cwd дала traceback `scan_lang.py:
        # 438 in main` и rc 1, head — rc 2 reason|cwd-unavailable). Один источник cwd:
        # то же значение уходит в предикат и в строку отчёта (второй `Path.cwd()` в
        # print был бы второй точкой падения).
        try:
            cwd = Path.cwd()
        except OSError as e:  # FileNotFoundError — подкласс OSError (Linux и macOS)
            # Рабочий каталог недоступен (его удалили) = «проверка не выполнена»,
            # не «хиты» (rc 1) и не traceback: своя причина в отчёте.
            print(f"LANG|cwd|unavailable|{type(e).__name__}")
            return _noinput("cwd-unavailable")
        if not _cwd_is_repo_root(cwd):
            # N2 (#116): раньше этот случай тонул в no-readable-file (инвентарь
            # собрался, все пути дали skip). Причина не «нет файлов», а запуск не из
            # корня: обход читает пути относительно cwd, а инвентарь строит от корня.
            print(f"LANG|cwd|not-repo-root|cwd|{cwd}|repo|{REPO_ROOT}")
            return _noinput("cwd-not-repo-root")
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
