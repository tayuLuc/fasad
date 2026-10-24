#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rrn_score — меритель внешнего кросс-бенча redmadrobot-rnd/pii_benchmark (#209).
"""Прогон `POST /v1/analyze` по кросс-корпусу и сведение границ спанов.

Мера = кросс-референс НАШИХ границ на ЧУЖой разметке (read-only, НЕ гейт recall:
единственный эталон recall — `data/golden/`, AGENTS §4 + рюлинг 24.10 в
`data/golden/README.md`). Вход — адрес демона (`--url`), analyze-only: сессия/
vault не нужны.

Оракулы (оба, молча не выбираем — определения владельца `data/golden/README.md`
§«Метрика recall» и их карточки «overlap matching»):
  strict   — байт-в-байт (`start_byte == start_char_pred` …) + равенство класса.
             Наш контракт strict = byte-exact; их harness «Exact-match scoring
             is also available» (их README §Evaluation metric, первичка).
  coverage — пересечение ≥1 байта + равенство класса: контур «наш спан покрыл их
             span-объединение» (их разметка coarse-склейка соседних одноимённых
             = OUR strict занижен, это ожидаемо и объясняется цифрами в README).
  their_strict — предсказание = ИХ спан (sanity: на их же разметке strict-F1 = 1).

Счётчики (по типам + всего): TP/FP/FN strict и coverage, `our-only` (FP),
`their-only` (FN), `both` (TP). Прочее:
  BYTES|char_only — предсказания, у которых char-координаты совпали с эталоном,
    а байтовые НЕТ (и наоборот): ловушка char/byte на нашем контракте
    (`crates/guard-types/src/span.rs` — байты первичны, char-поля есть;
    контракт витрины `README.md` §analyze: `byte_start`/`byte_end`).
  FAIL|requests — таймауты/5xx = КРАСНЫЙ счётчик, fail-closed: метрика с
    неполным прогоном не выдаётся (exit 1).

Выход — stdout pipe-таблица (генератор артефакта `.local/bench/rrn-*.md`
лепит из неё документ цифра-в-цифру):
  SCORE|rows|…|spans_gold|…|spans_pred|…
  SCORE|strict|P|…|R|…|F1|…
  SCORE|coverage|P|…|R|…|F1|…
  SCORE|class|<cls>|gold|G|pred|Pn|tp_strict|X|fp_strict|Y|fn_strict|Z|tp_cov|…
  BYTES|pred_total|…|byte_match|…|char_only|…|none|…
  TIME|analyze|s|…|rows|…

Запуск (см. scripts/rrn-bench.sh — обёртка с fail-closed):
  uv run --locked python tools/bench/rrn_score.py --url http://127.0.0.1:PORT \\
      [--input data/bench-external/crossref.jsonl] [--thr 0.2] [--timeout 60]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "data" / "bench-external" / "crossref.jsonl"
OUR_CLASSES = ["person_name", "inn", "snils", "card_pan", "phone",
               "email", "address", "passport"]
# Классы, которых нет в схеме демона (schema.default.json 8+3): предсказание
# таким классом придти не может; эталон по ним = their-only по построению.
CLASSES_OUT_OF_SCHEMA = ["ogrn", "ogrnip", "iban"]


def overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def score_row(gold: list[dict], pred: list[dict], thr: float,
              oracle: str) -> dict[str, tuple[int, int, int]]:
    """TP/FP/FN по классам для одной строки. Класс вне схемы = FN (насильно).

    oracle=strict: byte-exact совпадение границ + класс.
    oracle=coverage: пересечение ≥1 байта + класс (предсказание тратится один
    раз — greedy по порядку предсказаний, детерминированно).
    """
    out: dict[str, tuple[int, int, int]] = {}
    for cls in OUR_CLASSES:
        g = [s for s in gold if s["our_class"] == cls]
        p = [s for s in pred if s["class"] == cls and s["score"] >= thr]
        tp = 0
        used: set[int] = set()
        for sp in p:
            for gi, sg in enumerate(g):
                if gi in used:
                    continue
                hit = (sp["byte_start"] == sg["start_byte"]
                       and sp["byte_end"] == sg["end_byte"]) if oracle == "strict" \
                    else overlap(sp["byte_start"], sp["byte_end"],
                                 sg["start_byte"], sg["end_byte"])
                if hit:
                    used.add(gi)
                    tp += 1
                    break
        out[cls] = (tp, len(p) - tp, len(g) - tp)
    return out


def analyze(url: str, text: str, thr: float, timeout: float) -> list[dict]:
    body = json.dumps({"text": text, "score_threshold": thr}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/analyze", data=body,
        headers={"content-type": "application/json", "X-Guard-Policy": "audit_only"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — loopback
        return json.load(resp)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="адрес демона, http://127.0.0.1:PORT")
    ap.add_argument("--input", default=str(DEFAULT_INPUT))
    ap.add_argument("--thr", type=float, default=0.20,
                    help="порог запроса (= дефолт FASAD_TAU_LOW, README §analyze)")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--limit", type=int, default=0, help="первые N строк (smoke)")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.is_file():
        sys.exit(f"FAIL нет {in_path} — сначала конвертер: "
                 f"uv run --locked python tools/bench/rrn_bench.py")
    rows = [json.loads(line) for line in in_path.open(encoding="utf-8")]
    if args.limit:
        rows = rows[:args.limit]

    totals = {o: {c: [0, 0, 0] for c in OUR_CLASSES} for o in ("strict", "coverage")}
    pred_spans = gold_spans = 0
    fail_requests = 0
    byte_match = char_only = no_match = 0
    t0 = time.time()
    for r in rows:
        try:
            spans = analyze(args.url, r["text"], args.thr, args.timeout)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            fail_requests += 1
            continue
        pred_spans += len(spans)
        gold_spans += len(r["spans"])
        pred = [{"class": s["class"], "byte_start": s["byte_start"],
                 "byte_end": s["byte_end"], "score": s["score"]} for s in spans]
        for oracle in ("strict", "coverage"):
            per = score_row(r["spans"], pred, args.thr, oracle)
            for cls, (tp, fp, fn) in per.items():
                t = totals[oracle][cls]
                t[0] += tp
                t[1] += fp
                t[2] += fn
        # char/byte контракт: предсказание попало в эталон по char, не попало по byte
        gold_c = {(s["start_char"], s["end_char"], s["our_class"]) for s in r["spans"]}
        gold_b = {(s["start_byte"], s["end_byte"], s["our_class"]) for s in r["spans"]}
        for sp in pred:
            c = (sp.get("start"), sp.get("end"), sp["class"]) in gold_c
            b = (sp["byte_start"], sp["byte_end"], sp["class"]) in gold_b
            if b:
                byte_match += 1
            elif c:
                char_only += 1
            else:
                no_match += 1
    dt = time.time() - t0

    def prf(t: list[int]) -> tuple[str, str, str]:
        tp, fp, fn = t
        p = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * rec / (p + rec) if p + rec else 0.0
        return f"{100 * p:.2f}", f"{100 * rec:.2f}", f"{100 * f:.2f}"

    print(f"SCORE|rows|{len(rows)}|spans_gold|{gold_spans}|spans_pred|{pred_spans}"
          f"|thr|{args.thr}|classes|{','.join(OUR_CLASSES)}")
    for oracle in ("strict", "coverage"):
        tot = [sum(totals[oracle][c][i] for c in OUR_CLASSES) for i in range(3)]
        p, rc, f = prf(tot)
        print(f"SCORE|{oracle}|tp|{tot[0]}|fp|{tot[1]}|fn|{tot[2]}"
              f"|P|{p}|R|{rc}|F1|{f}")
        for cls in OUR_CLASSES:
            t = totals[oracle][cls]
            p, rc, f = prf(t)
            print(f"SCORE|class|{cls}|oracle|{oracle}|gold|{t[0] + t[2]}|pred|{t[0] + t[1]}"
                  f"|tp|{t[0]}|fp|{t[1]}|fn|{t[2]}|P|{p}|R|{rc}|F1|{f}"
                  f"|our_only|{t[1]}|their_only|{t[2]}|both|{t[0]}")
    print(f"BYTES|pred_total|{pred_spans}|byte_match|{byte_match}"
          f"|char_only|{char_only}|no_match|{no_match}")
    print(f"TIME|analyze|s|{dt:.2f}|rows|{len(rows) - fail_requests}")
    if fail_requests:
        print(f"FAIL|requests|{fail_requests}|метрика неполная (fail-closed, не молчим)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
