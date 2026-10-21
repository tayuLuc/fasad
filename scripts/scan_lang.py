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

Positive control (обязателен, иначе зелёное = ничто): `--self-test` прогоняет
детекторы по посаженным образцам.

Control-строки собраны из escape-последовательностей, поэтому самого себя сканер
не пачкает: CJK-литералов в исходнике нет (иначе сканер был бы глух к собственному
классу дефекта).

Запуск:
  uv run --locked python scripts/scan_lang.py --self-test
  uv run --locked python scripts/scan_lang.py --files docs/golden-report.md tools/metrics/union_recall.py
rc: 0 = чисто, 1 = найдено, 2 = positive control не сработал (сканер мёртв).
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
# Экраны внутри строковых литералов (JSON/исходники): `\n` в данных — НЕ буква `n`
# перед кириллицей. Без этого шага 169 хитов в golden-v1.jsonl были ложными (промер 21.10).
ESC_RE = re.compile(r"\\[nrtvbf]")


def _in(ch: str, lo: int, hi: int) -> bool:
    return lo <= ord(ch) <= hi


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Хиты (номер строки 1-база, вид, фрагмент).

    Символы перебираются напрямую: регексп-класс из диапазонов — то место, где
    сканер умер бы молча (positive control поймал ровно эту ошибку: класс из
    НАЧАЛ диапазонов ловил 0 из 2 посаженных иероглифов).
    """
    hits: list[tuple[int, str, str]] = []
    for ln, line in enumerate(ESC_RE.sub(" ", text).splitlines(), start=1):
        for ch in line:
            if any(_in(ch, lo, hi) for lo, hi in CJK_RANGES):
                hits.append((ln, "cjk", f"U+{ord(ch):04X}"))
        for w in WORD_RE.findall(line):
            # Дефис/подчёркивание НЕ входят в токен ⇒ `fp16-квант` = два слова (чисто),
            # а слитная склейка график — один токен с двумя скриптами (хит).
            if LATIN_RUN.search(w) and CYR_RUN.search(w):
                hits.append((ln, "mixed", w))
    return hits


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
    print(f"CONTROL|verdict|{'live' if ok else 'dead-scanner'}")
    return 0 if ok else 2


TEXT_EXT = {".md", ".rs", ".py", ".toml", ".yml", ".yaml", ".json", ".jsonl",
            ".tsv", ".sh", ".txt"}


def git_text_files() -> list[str]:
    """Все текстовые файлы под git (дефолт `--all`: пустой список != зелёный)."""
    out = subprocess.run(["git", "ls-files"], cwd=Path(__file__).resolve().parents[1],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    return [f for f in out if Path(f).suffix in TEXT_EXT]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", nargs="*", default=[])
    ap.add_argument("--all", action="store_true",
                    help="весь текстовый tree под git (инвентарь репозитория)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    rc_control = self_test() if args.self_test else 0
    if rc_control != 0:
        return rc_control
    files = git_text_files() if args.all else list(args.files)
    if not files:
        # Пустое множество входа — не «чисто», а «проверка не выполнена»
        # (реестр ложно-зелёных: «зелёный = пустое множество проверенного»).
        print("LANG|verdict|NOINPUT|files|0|hits|-1")
        return 2
    total = 0
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
        for ln, kind, frag in scan_text(text):
            total += 1
            print(f"LANG|hit|{f}|line|{ln}|kind|{kind}|{frag}")
    print(f"LANG|verdict|{'clean' if total == 0 else 'DIRTY'}|files|{len(files)}|hits|{total}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
