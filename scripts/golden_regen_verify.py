#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""golden_regen_verify — побайтовая проверка воспроизводимости golden-датасета.

Запускает data/golden/golden_gen.py, считает SHA-256 вывода и сверяет его
с зашитой константой B2 в crates/guard-detectors/tests/golden_v1.rs
(GOLDEN_V1_SHA256 — единственный источник истины; копий хэша в скриптах нет).
Дополнительно сверяет байты вывода с закоммиченным golden-v1.jsonl.

Зачем: линт-правки/апгрейды генератора обязаны быть output-neutral (вывод
заморожен гейтом B2). Скрипт кросс-ОС (stdlib, без shell-редиректов — вывод
захватывается subprocess'ом, никаких CRLF-ловушек PowerShell).

Использование: uv run python scripts/golden_regen_verify.py
Выход: 0 — байт-в-байт; 1 — расхождение (с диагностированной дельтой).
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "data" / "golden" / "golden_gen.py"
DATASET = ROOT / "data" / "golden" / "golden-v1.jsonl"
RS_TEST = ROOT / "crates" / "guard-detectors" / "tests" / "golden_v1.rs"
CONST_RE = re.compile(r'GOLDEN_V1_SHA256:\s*&str\s*=\s*"([0-9a-f]{64})"')





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
    expected_match = CONST_RE.search(RS_TEST.read_text(encoding="utf-8"))
    if expected_match is None:
        print("FAIL: константа GOLDEN_V1_SHA256 не найдена в", RS_TEST, file=sys.stderr)
        return 1
    expected = expected_match.group(1)

    proc = subprocess.run(
        [sys.executable, str(GEN)],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        print("FAIL: генератор упал (exit=%d)" % proc.returncode, file=sys.stderr)
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 1
    fresh = proc.stdout

    digest = hashlib.sha256(fresh).hexdigest()
    print("regen sha256 = %s" % digest)
    print("B2    sha256 = %s" % expected)
    if digest != expected:
        print("FAIL: вывод генератора разошёлся с зашитым B2-хэшем", file=sys.stderr)
        print("      — правка меняет поведение; откат или golden-v1.1 (README «Правила добавления»)", file=sys.stderr)
        return 1

    committed = DATASET.read_bytes()
    if committed != fresh:
        # хэш совпал, но файл в репо отличается (CRLF-порча чекаута и т.п.)
        print("FAIL: байты не совпали при равном sha256 — чек-аут испортил файл (eol?)", file=sys.stderr)
        return 1
    print("OK: golden-v1.jsonl воспроизводится байт-в-байт (N=%d строк)" % fresh.count(b"\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
