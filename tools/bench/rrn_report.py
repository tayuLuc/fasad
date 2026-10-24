#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rrn_report — генератор README-таблиц из SCORE-артефактов кросс-бенча (#209).
"""Правило «числа документа генерятся из артефакта прогона»: markdown-секция
Baseline в `data/bench-external/README.md` печатается из `SCORE|`-строк
артефактов `.local/bench/rrn-*.out`, не с головы.

Формат входа: pipe-строки `tools/bench/rrn_score.py`
(`SCORE|class|<cls>|oracle|<o>|gold|…|P|…|R|…|F1|…`, `STAGE|`, `BYTES|`, `TIME|`).

Запуск:
  uv run --locked python tools/bench/rrn_report.py \\
      "до = релиз v0.1.2|.local/bench/rrn-2026-10-24-release-v012.out" \\
      "после = head b209 full|.local/bench/rrn-2026-10-24-full.out" ...
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUR_CLASSES = ["person_name", "inn", "snils", "card_pan", "phone",
               "email", "address", "passport"]


def parse(path: Path) -> dict:
    d: dict = {"rows": "?", "meta": {}, "stage": {}, "bytes": {},
               "strict": {}, "coverage": {}}
    for line in path.read_text(encoding="utf-8").splitlines():
        f = line.split("|")
        if f[0] == "SCORE" and f[1] == "rows":
            d["rows"] = f[2]
        elif f[0] == "SCORE" and len(f) > 5 and f[1] == "class":
            # SCORE|class|<cls>|oracle|<o>|gold|G|pred|P|tp|T|fp|F|fn|N|P|..|R|..|F1|..
            cls, oracle = f[2], f[4]
            kv = {f[i]: f[i + 1] for i in range(5, len(f) - 1, 2)}
            d[oracle][cls] = kv
        elif f[0] == "SCORE" and len(f) > 2 and f[1] in ("strict", "coverage"):
            d["total"] = d.get("total", {})
            d["total"][f[1]] = {f[i]: f[i + 1] for i in range(2, len(f) - 1, 2)}
        elif f[0] == "STAGE":
            d["stage"][f[1]] = f[3]
        elif f[0] == "BYTES":
            d["bytes"] = {f[i]: f[i + 1] for i in range(1, len(f) - 1, 2)}
        elif f[0] == "TIME":
            d["meta"]["time_s"] = f[3]
            d["meta"]["time_rows"] = f[5]
        elif f[0] == "FAIL":
            d["meta"][f[1]] = f[2]
    return d


def table(name: str, d: dict, oracle: str) -> str:
    stage = (", ".join(f"{k}={v}" for k, v in sorted(d["stage"].items()))
             if d["stage"] else "пусто: отказов не зафиксировано")
    out = [f"**{name}** — oracle `{oracle}` (строка STAGE: {stage})"]
    out.append("")
    out.append("| класс | gold | pred | TP | FP our-only | FN their-only | P | R | F1 |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cls in OUR_CLASSES:
        k = d[oracle].get(cls, {})
        out.append(f"| {cls} | {k.get('gold','?')} | {k.get('pred','?')} | "
                   f"{k.get('tp','?')} | {k.get('fp','?')} | {k.get('fn','?')} | "
                   f"{k.get('P','?')} | {k.get('R','?')} | {k.get('F1','?')} |")
    t = d.get("total", {}).get(oracle, {})
    out.append(f"| **итого** | {t.get('tp','?')}+{t.get('fn','?')} | "
               f"{t.get('tp','?')}+{t.get('fp','?')} | {t.get('tp','?')} | "
               f"{t.get('fp','?')} | {t.get('fn','?')} | {t.get('P','?')} | "
               f"{t.get('R','?')} | {t.get('F1','?')} |")
    out.append("")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    runs = []
    for arg in sys.argv[1:]:
        name, _, path = arg.split("=", 2)
        p = Path(path)
        if not p.is_absolute():
            p = ROOT / p
        if not p.is_file():
            sys.exit(f"FAIL нет артефакта {p}")
        runs.append((name, parse(p)))
    for oracle in ("strict", "coverage"):
        for name, d in runs:
            print(table(f"{name} (rows={d['rows']}, analyze {d['meta'].get('time_s','?')} с)",
                        d, oracle))
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
