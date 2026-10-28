"""Разведка направления смещения координат lockR относительно gold (первичка §6.4).

Зачем: union-метрика зависит от определения попадания (overlap vs byte-exact), и по
нему надо было сказать не «насколько», а «в какую сторону». Ответ генерируется из
`COORD|`-строк этого промера, прозой из головы он не является.

Выход (stdout, pipe-формат как у union_recall.py):
  COORD|matched_gold_spans|N|missed_gold|M
  COORD|relations|exact|E|subset_of_gold|S|superset|P|partial|Q
  COORD|d_start|median|…|mean|…|min|…|max|…|q25|…|q75|…
  COORD|d_end|median|…|…
  COORD|d_end_neg_share|…   (доля случаев, где конец предсказания раньше конца gold)
  COORD|d_start_pos_share|… (доля случаев, где начало предсказания позже начала gold)
  COORD|len_gold_median|…|len_pred_median|…
  COORD|pred_total_tau20|…

Сопоставление и карта классов — функции харнеса (union_recall.overlap,
union_recall.BIO_TO_GOLDEN): второй реализации оракула нет.

Запуск (артефакт нужен генератору отчёта; то же запиненное окружение промера,
что у union_recall — [dependency-groups] metrics / uv.lock, #81):
  nice -n 10 env OMP_NUM_THREADS=2 uv run --locked --group metrics \\
      python tools/metrics/probe_coords.py > /tmp/probe_coords.out
"""

from __future__ import annotations

import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "metrics"))

import union_recall as ur  # noqa: E402

THR = 0.20


def pct(xs: list[int], p: float) -> int:
    s = sorted(xs)
    return s[int(p * (len(s) - 1))]


def main() -> None:
    rows, _neg = ur.load_rows()
    lock = ur.run_lockr(rows, threads=2, batch=8)
    d0: list[int] = []
    d1: list[int] = []
    exact = sub = sup = part = matched = missed = 0
    for r in rows:
        preds = [p for p in lock.get(r["id"], []) if p["conf"] >= THR]
        for g in r["spans"]:
            g0, g1 = g["start_byte"], g["end_byte"]
            hits = [p for p in preds
                    if ur.BIO_TO_GOLDEN.get(p["cls"]) == g["category"]
                    and ur.overlap(p["b0"], p["b1"], g0, g1)]
            if not hits:
                missed += 1
                continue
            matched += 1
            near = min(hits, key=lambda p: abs((p["b0"] + p["b1"]) / 2 - (g0 + g1) / 2))
            d0.append(near["b0"] - g0)
            d1.append(near["b1"] - g1)
            for q in hits:
                if q["b0"] == g0 and q["b1"] == g1:
                    exact += 1
                elif q["b0"] >= g0 and q["b1"] <= g1:
                    sub += 1
                elif q["b0"] <= g0 and q["b1"] >= g1:
                    sup += 1
                else:
                    part += 1
    pl = [p["b1"] - p["b0"] for r in rows for p in lock.get(r["id"], []) if p["conf"] >= THR]
    gl = [g["end_byte"] - g["start_byte"] for r in rows for g in r["spans"]]
    print(f"COORD|matched_gold_spans|{matched}|missed_gold|{missed}")
    print(f"COORD|relations|exact|{exact}|subset_of_gold|{sub}|superset|{sup}|partial|{part}")
    print(f"COORD|d_start|median|{statistics.median(d0):.0f}|mean|{statistics.mean(d0):.1f}"
          f"|min|{min(d0)}|max|{max(d0)}|q25|{pct(d0, .25)}|q75|{pct(d0, .75)}")
    print(f"COORD|d_end|median|{statistics.median(d1):.0f}|mean|{statistics.mean(d1):.1f}"
          f"|min|{min(d1)}|max|{max(d1)}|q25|{pct(d1, .25)}|q75|{pct(d1, .75)}")
    print(f"COORD|d_end_neg_share|{sum(1 for x in d1 if x < 0) / len(d1) * 100:.1f}")
    print(f"COORD|d_start_pos_share|{sum(1 for x in d0 if x > 0) / len(d0) * 100:.1f}")
    print(f"COORD|len_gold_median|{statistics.median(gl):.0f}|len_pred_median"
          f"|{statistics.median(pl):.0f}")
    print(f"COORD|pred_total_tau20|{len(pl)}")


if __name__ == "__main__":
    main()
