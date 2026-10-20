# -*- coding: utf-8 -*-
# parity_golden — приёмочный гейт кванта quant-policy §3.2 (атом 4b-3B, issue #20).
"""
Метод (ТЗ 4b-3B): ОДИН скрипт, ОБЕ модели, ОДИН прогон, батчи по golden-строкам
(split=recall), пороги {0.20,0.25,0.50,0.70} (quant-policy §3.2). Метрика:
  METRIC|parity|<model>|threshold|T|recall_fp32|X|recall_qat|Y|delta_pp|Z|gate=…
Гейт §3.2: суммарный recall-пад ≤0.5 п.п. И ни один класс не просел >1.0 п.п.
(fp32-поймал/квант-промахнулся = падение кванта; квант-конвентия не штраф.)

Первичка входов (промеры сессии 20.10, НЕ [claim]):
  lockR   fp32 model.optimized.fp32.onnx (sha eebed656…, tools/verify/
          fp32-manifest.tsv) vs квант model.optimized.fp16.onnx (sha 039aba6b…,
          models/manifest.tsv). ОБА графа: int64 input_ids/attention_mask/
          token_type_ids, выход logits tensor(float) [B,L,43] — промер Session
          API; id2label 0..42 — config.json@ea7610b2 (hf_hub_download). WordPiece
          [CLS]/[SEP], pad [PAD]=0 вправо до 256 (контракт spike --lockr).
          Декодер: argmax, BIO B/i-скобка, вероятность = softmax строки логитов.
          Зеркало Rust-декодера — crates/guard-onnx/src/decide.rs:34-107 (тот же
          ID2LABEL; GOLDEN_TO_BIO живёт в examples/recall_golden.rs::bio_to_class,
          множество классов идентично — промер ревью PR#49).
  Decide  fp32 onnx/model.onnx(+_data f5aef45f…) vs квант onnx/model_q4f16.onnx
          (93f3e0d4…): int64-входы, logits float (1,M) — промер Session API.
          Блок схем = зеркало arbitrate.rs::schema_block; один encode(concat,
          false) (Metaspace-контракт 4b-2a; пост-процессор снесён — арбитраж
          ревью #34); маркеры = ВСЕ [L] позиции; softmax внутри группы, yes=
          P[0]; батч=1 (контракт (1,M), spike-путь).

ОФЛАЙН-режим: BUDGET|mode=offline-gate — пик RSS процесса с fp32+квант в одном
процессе фиксируется цифрами; превышение рантайм-бюджета ≤1.8 GiB ДОПУСТИМО
(не runtime-путь, ТЗ 4b-3B).

Запуск (веса: scripts/fetch-models.sh, tools/verify/fetch_manifest_weights.sh):
  uvx --python ~/.local/bin/python3.13 --with numpy --with onnxruntime \\
      --with tokenizers --with psutil python tools/verify/parity_golden.py --model lockr
(py3.13: wheels onnxruntime ≤cp314; системный 3.9 не годится. psutil — RSS
пика (fallback vmmap/VmRSS). uvx — вне дерева сборки, AGENTS §Порядок п.6.)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

import numpy as np
import onnxruntime as rt
from tokenizers import Tokenizer

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path(os.environ.get("FASAD_MODELS_DIR", Path.home() / ".cache/fasad-models"))
GOLDEN = ROOT / "data" / "golden" / "golden-v1.jsonl"
THRESHOLDS = [0.20, 0.25, 0.50, 0.70]
# Вердикт PARITY|verdict = AND только по РАБОЧИМ порогам конвейера (≤ τ_раб
# 0.25, SPEC §5 п.6 / quant-policy §3.2); пороги выше рабочей точки —
# informational (рулинг 4b-3, тикет родителя): репортятся метрикой, не в
# агрегат. Деградация кванта выше τ — известная Characteristics (см. §5.7).
WORKING_THRESHOLDS = [0.20, 0.25]
RECALL_GATE_PP = 0.5
CLASS_GATE_PP = 1.0
LOCKR_PAD = 256
SEP_STRUCT_ID = 128001
SEP_TEXT_ID = 128002
L_ID = 128007

# id2label 0..42 — lockR/rubert-base-pii-ner-onnx@ea7610b2 config.json
# (hf_hub_download 20.10; первичка — карточка репо; зеркало lockr.rs).
ID2LABEL = ["O", "B-PASSPORT", "I-PASSPORT", "B-CREDIT_CARD", "I-CREDIT_CARD",
            "B-DRIVER_LICENSE", "I-DRIVER_LICENSE", "B-INN", "I-INN", "B-SNILS",
            "I-SNILS", "B-MILITARY_ID", "I-MILITARY_ID", "B-BIRTH_CERTIFICATE",
            "I-BIRTH_CERTIFICATE", "B-OMS", "I-OMS", "B-CITY", "B-COUNTRY",
            "B-DISTRICT", "B-EMAIL", "B-FIRST_NAME", "B-HOUSE", "B-IP_ADDRESS",
            "B-LAST_NAME", "B-MIDDLE_NAME", "B-PHONE", "B-REGION", "B-STREET",
            "B-URL", "I-CITY", "I-COUNTRY", "I-DISTRICT", "I-EMAIL",
            "I-FIRST_NAME", "I-HOUSE", "I-IP_ADDRESS", "I-LAST_NAME",
            "I-MIDDLE_NAME", "I-PHONE", "I-REGION", "I-STREET", "I-URL"]
B_TO_I = {t: "I-" + t[2:] for t in ID2LABEL if t.startswith("B-")}
# golden-класс → BIO-головы (онтология §14 ↔ 43 тег; address = иерархия
# CITY/STREET/HOUSE/REGION/COUNTRY README-§Категории; зеркало lockr.rs)
GOLDEN_TO_BIO = {
    "person_name": {"FIRST_NAME", "LAST_NAME", "MIDDLE_NAME"},
    "inn": {"INN"},
    "snils": {"SNILS"},
    "card_pan": {"CREDIT_CARD"},
    "phone": {"PHONE"},
    "email": {"EMAIL"},
    "address": {"CITY", "STREET", "HOUSE", "REGION", "COUNTRY"},
    "passport": {"PASSPORT"},
}
CLASS_LIST = sorted(GOLDEN_TO_BIO)
QUESTIONS = {
    "address": "Is there a postal address ?",
    # card_pan: spike-эталонная формулировка 4b-2a «a bank card number» (не
    # «payment card…»): переформулировка стоила 24 ложных FN на fp32 (промер
    # полного ранa 20.10 — сырьё в коммите) — вопрос в модели = контракт.
    "card_pan": "Is there a bank card number ?",
    "email": "Is there an e-mail address ?",
    "inn": "Is there a tax identification number ?",
    "passport": "Is there a passport series and number ?",
    "person_name": "Is there a full name of a person ?",
    "phone": "Is there a phone number ?",
    "snils": "Is there a pension insurance number ?",
}
SCHEMA = [(QUESTIONS[c], ["yes", "no"]) for c in CLASS_LIST]

SPEC = {
    "lockr": {
        "fp32": ("lockR/rubert-base-pii-ner-onnx", "model.optimized.fp32.onnx",
                 "eebed6562883ca6c59204da661ddb3edb1b334e91737f35d79ac74c75d371315"),
        "qat": ("lockR/rubert-base-pii-ner-onnx", "model.optimized.fp16.onnx",
                "039aba6be0c64f50f37c64ddc6c6d4e2fd91cbdcf5c9291056ec6bc96c70a501"),
        "tok": ("lockR/rubert-base-pii-ner-onnx", "tokenizer.json"),
    },
    "decide": {
        "fp32": ("onnx-community/GLiNER2.5-Decide-ONNX", "onnx/model.onnx",
                 "37af0b3a55a4199a798674cdf7786b88d4764df3e9575ebfcec3673cde0838be"),
        # квант — sha из models/manifest.tsv arbiter (93f3e0d4…, промер 19.10)
        "qat": ("onnx-community/GLiNER2.5-Decide-ONNX", "onnx/model_q4f16.onnx",
                "93f3e0d4ed8bbd4858840f8a2e66028a70e86a482e1ff9822d2ac726381684f6"),
        "tok": ("onnx-community/GLiNER2.5-Decide-ONNX", "tokenizer.json"),
    },
}
EXTERN_SHA = {
    ("onnx-community/GLiNER2.5-Decide-ONNX", "onnx/model.onnx_data"):
        "f5aef45f7892cf3acf277516e225d5e653d6b4946918d728b3c3ab0882ac8d58",
}


def rss_mib() -> float:
    """RSS процесса: psutil (per-call, быстро) → fallback vmmap/VmRSS, MiB."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:  # noqa: BLE001 — деградация: ниже запасные пути
        pass
    try:
        out = subprocess.run(["vmmap", str(os.getpid())], capture_output=True,
                             text=True, check=False).stdout
        m = re.search(r"Physical footprint:\s+([\d.]+)\s+(K|M|G)", out)
        if m:
            v, u = float(m.group(1)), m.group(2)
            return v / 1024 if u == "K" else (v * 1024 if u == "G" else v)
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return float(line.split()[1]) / 1024
    except Exception:  # noqa: BLE001 — офлайн-промер: деградация в nan допустима
        pass
    return float("nan")


class Peak:
    def __init__(self) -> None:
        self.peak = 0.0

    def sample(self) -> None:
        v = rss_mib()
        if not math.isnan(v):
            self.peak = max(self.peak, v)


def verify_weights() -> None:
    """sha256 пересчёт ДО использования (Fail-Closed, AGENTS §Порядок п.2)."""
    for model in SPEC:
        for k in ("fp32", "qat"):
            repo, fn, sha = SPEC[model][k]
            path = CACHE / repo / fn
            if not path.is_file():
                sys.exit(f"FAIL вес отсутствует: {path} (сначала fetch-скрипты)")
            got = hashlib.sha256(path.read_bytes()).hexdigest()
            if got != sha:
                sys.exit(f"FAIL sha256 {path.name}: {got} != {sha}")
    for (repo, fn), sha in EXTERN_SHA.items():
        path = CACHE / repo / fn
        if sha and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            sys.exit(f"FAIL sha256 external {path.name}")
    print("PRECHECK|weights|sha256-verified")


def load_rows(limit: int) -> list[dict]:
    rows = []
    with GOLDEN.open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            if r["split"] == "recall":
                rows.append(r)
                if limit and len(rows) >= limit:
                    break
    return rows


def softmax(v: list[float]) -> list[float]:
    m = max(v)
    e = [math.exp(x - m) for x in v]
    s = sum(e)
    return [x / s for x in e] if s > 0 and math.isfinite(s) else [0.0] * len(v)


# ── lockR ────────────────────────────────────────────────────────────────────
LOCKR_SPECIALS = {"[CLS]", "[SEP]", "[PAD]", "[MASK]", "[UNK]"}


def spans_bio_tags(lg_row: np.ndarray, real_len: int, ids: list[int], tok: Tokenizer):
    """(tag, prob) на позицию; prob = softmax строки логитов (argmax-тег).
    Special-позиции принудительно O ([CLS]/[SEP]/[PAD]…): декодер не открывает
    и не продлевает сущность через служебные токены."""
    out = []
    for t in range(real_len):
        row = lg_row[t].astype(np.float64)
        best = int(np.argmax(row))
        p = softmax(row.tolist())[best]
        tag = ID2LABEL[best]
        if t < len(ids) and tok.decode([ids[t]]) in LOCKR_SPECIALS:
            tag = "O"
        out.append((tag, p))
    return out


def spans_grouped(tags) -> list[tuple[str, int, int, float]]:
    """BIO B/i-скобка: (cls, tok0, tok1_excl, min_prob токенов). PS-токены
    помечены O (special-фильтр выше), цепочка на них обрывается автоматически."""
    spans = []
    cur = None
    for t, (tag, p) in enumerate(tags):
        if tag.startswith("B-"):
            if cur:
                spans.append(tuple(cur))
            cur = [tag[2:], t, t + 1, p]
        elif tag.startswith("I-") and cur and B_TO_I.get("B-" + cur[0]) == tag:
            cur[2] = t + 1
            cur[3] = min(cur[3], p)
        else:
            if cur:
                spans.append(tuple(cur))
            cur = None
    if cur:
        spans.append(tuple(cur))
    return spans


def run_lockr(rows, threads: int, peak: Peak, batch: int):
    opts = rt.SessionOptions()
    opts.intra_op_num_threads = threads
    tok = Tokenizer.from_file(str(CACHE / SPEC["lockr"]["tok"][0] / SPEC["lockr"]["tok"][1]))
    res = {v: [] for v in ("fp32", "qat")}
    for variant in ("fp32", "qat"):
        repo, fn, _ = SPEC["lockr"][variant]
        sess = rt.InferenceSession(str(CACHE / repo / fn), opts,
                                   providers=["CPUExecutionProvider"])
        peak.sample()
        for i in range(0, len(rows), batch):
            chunk = rows[i:i + batch]
            encs = [tok.encode(r["text"], add_special_tokens=True) for r in chunk]
            lens = [min(len(e), LOCKR_PAD) for e in encs]
            ids = np.zeros((len(chunk), LOCKR_PAD), np.int64)
            mask = np.zeros((len(chunk), LOCKR_PAD), np.int64)
            types = np.zeros((len(chunk), LOCKR_PAD), np.int64)
            for j, (e, ln) in enumerate(zip(encs, lens, strict=True)):
                ids[j, :ln] = e.ids[:ln]
                mask[j, :ln] = e.attention_mask[:ln]
            lg = sess.run(["logits"], {"input_ids": ids, "attention_mask": mask,
                                       "token_type_ids": types})[0]
            for j, r in enumerate(chunk):
                e = encs[j]
                ln = lens[j]
                spans = []
                tags = spans_bio_tags(lg[j], ln, list(e.ids), tok)
                ids_e = list(e.ids)
                for cls, t0, t1, conf in spans_grouped(tags):
                    om = e.offsets  # 1-в-1 с e.ids (промер 20.10: 75/75, спец=(0,0));
                    # индекс полного списка = индекс om, БЕЗ сдвига (рецидив −1:
                    # om[t0−1] давал ':' перед фамилией → b0=85 при gold b0=87,
                    # ревью PR#49 блокер №1).
                    # PS-хвосты (##piece) НЕ расширяют спан: последний НЕ-special
                    i1 = min(t1, len(ids_e)) - 1
                    while i1 >= t0 and tok.decode([ids_e[i1]]).startswith("##"):
                        i1 -= 1
                    i0 = t0
                    if i1 < i0 or i0 >= len(om) or i1 < 0:
                        continue
                    c0 = om[i0][0]
                    c1 = om[min(i1, len(om) - 1)][1]
                    b0 = len(r["text"][:c0].encode("utf-8"))
                    b1 = len(r["text"][:c1].encode("utf-8"))
                    if b1 > b0:
                        spans.append({"cls": cls, "b0": b0, "b1": b1, "conf": conf})
                res[variant].append((r, spans, lg[j][:ln].copy()))
        peak.sample()
        del sess
    return res


# ── Decide (зеркало crates/guard-onnx, spike-DUAL-путь) ─────────────────────
def schema_block_text(schema) -> str:
    out = []
    for i, (q, labels) in enumerate(schema):
        if i:
            out.append(" [SEP_STRUCT] ")
        out.append("( [P] " + q + " (")
        for lb in labels:
            out.append(" [L] " + lb)
        out.append(" ) )")
    out.append(" [SEP_TEXT]")
    return "".join(out)


# ── зеркало arbitrate.rs::DecideArbiter::sanitize_state / clean_state ────────
# (4b-3B: литералы спец-токенов в данных вне доверия вырезаются из состояния,
# переводы строк → пробел; блок схем до terminator'а не трогаем).
SP_LITERALS = ("[SEP_STRUCT]", "[SEP_TEXT]", "[P]", "[L]")


def sanitize_state(state: str) -> str:
    # зеркало Rust 4b-3B: литералы спец-токенов -> ПРОБЕЛ (не вырез): байтовый
    # диапазон состояния сохраняется, спец-токен из чужих данных не эмулируется.
    out = state.replace("\n", " ")
    for sp in SP_LITERALS:
        out = out.replace(sp, " ")
    return out


def clean_state(whole: str) -> str:
    term = " [SEP_TEXT] "  # terminator с пробелами = schema_block_text (Rust-зеркало)
    i = whole.rfind(term)
    if i < 0:
        return sanitize_state(whole)
    k = i + len(term)
    return whole[:k] + sanitize_state(whole[k:])


def decide_groups(ids: list[int]) -> list[list[int]]:
    """Зеркало decide::groups с МАРКЕРНОЙ ПАРОЙ [L],[L] (тот же вызов, что
    `DecideArbiter::prompts`: `decide::groups(&ids, [self.ids[L], self.ids[L]]`)
    — группа = подряд идущие [L] до границы [SEP_STRUCT]/[SEP_TEXT]; [P] не
    маркер live-пути, дропать нечего; контракт маркеров verify_parity.py
    L34–37 = флэт всех [L]. Фантомные группы из мусорных литералов режет
    clean_state/sanitize_state (данные вне доверия, 4b-3B)."""
    out, cur = [], []
    for pos, x in enumerate(ids):
        if x == L_ID:
            cur.append(pos)
        elif x in (SEP_STRUCT_ID, SEP_TEXT_ID) and cur:
            out.append(cur)
            cur = []
    if cur:
        out.append(cur)
    return out


def run_decide(rows, threads: int, peak: Peak):
    opts = rt.SessionOptions()
    opts.intra_op_num_threads = threads
    tok = Tokenizer.from_file(str(CACHE / SPEC["decide"]["tok"][0] / SPEC["decide"]["tok"][1]))
    tok.post_processor = None  # контракт арбитра: JSONL без TemplateProcessing
    block = schema_block_text(SCHEMA)
    res = {v: [] for v in ("fp32", "qat")}
    for variant in ("fp32", "qat"):
        repo, fn, _ = SPEC["decide"][variant]
        sess = rt.InferenceSession(str(CACHE / repo / fn), opts,
                                   providers=["CPUExecutionProvider"])
        peak.sample()
        for r in rows:  # батч=1: контракт маркеров (1,M), spike-путь
            # Клининг = зеркало Rust-пути арбитра (clean_state/sanitize_state
            # выше = arbitrate.rs 4b-3B): литералы спец-токенов в состоянии —
            # данные вне доверия (layout FAIL на g0177 до клининга — сырьё).
            ids = tok.encode(clean_state(block + " " + r["text"]),
                             add_special_tokens=False).ids
            # groups = зеркало decide::groups([L],[L]) (маркерная пара live-
            # пути арбитра — [P]-пару spike 4b-2a не гонял; группы из [L],
            # дропать нечего); контракт verify_parity.py L34–37.
            groups = decide_groups(ids)
            if len(groups) != len(SCHEMA):
                sys.exit(f"FAIL layout g{r['id']}: групп {len(groups)} ≠ {len(SCHEMA)}")
            sizes = [len(g) for g in groups]
            if sizes != [2] * len(SCHEMA):
                sys.exit(f"FAIL sizes g{r['id']}: {sizes[:3]}…")
            markers = [p for g in groups for p in g]
            lg = sess.run(["logits"],
                          {"input_ids": np.array([ids], np.int64),
                           "attention_mask": np.ones((1, len(ids)), np.int64),
                           "marker_positions": np.array([markers], np.int64)})[0]
            flat = lg.reshape(-1).astype(np.float64).tolist()
            probs, off = [], 0
            for g in groups:
                p = softmax(flat[off:off + len(g)])
                probs.append(p[0])
                off += len(g)
            if off != len(flat):
                sys.exit(f"FAIL logits|{off}≠{len(flat)}")
            res[variant].append((r, probs))
        peak.sample()
        del sess
    return res


# ── метрики ──────────────────────────────────────────────────────────────────
def lockr_logits_delta(samples_fp32, samples_qat):
    """max |Δlogit| пообщим позициям (B≤pad, реальные токены; fp32-vs-fp16)."""
    d = 0.0
    for (r1, _, l1), (r2, _, l2) in zip(samples_fp32, samples_qat, strict=True):
        assert r1["id"] == r2["id"]
        n = min(len(l1), len(l2))
        if n:
            d = max(d, float(np.max(np.abs(l1[:n] - l2[:n]))))
    return d


def lockr_counts(samples, thr):
    tp = {c: 0 for c in GOLDEN_TO_BIO}
    fn = {c: 0 for c in GOLDEN_TO_BIO}
    for r, spans, _lg in samples:
        for g in r["spans"]:
            cat = g["category"]
            if cat not in tp:
                continue
            hit = any(s["conf"] >= thr and s["cls"] in GOLDEN_TO_BIO[cat]
                      and s["b0"] < g["end_byte"] and s["b1"] > g["start_byte"]
                      for s in spans)
            (tp if hit else fn)[cat] += 1
    return tp, fn


def decide_counts(samples, thr):
    """Счёт ТОЛЬКО по порогам §3.2: hit = P ≥ threshold (включительно) —
    контракт `decide_probs`/`decisions` (arbitrate.rs, порог включительно).
    «Отдано на квант» (0.20≤p<0.75) — скоуп 4c (short-circuit), здесь мерится
    ровно §3.2."""
    tp = {c: 0 for c in CLASS_LIST}
    fn = {c: 0 for c in CLASS_LIST}
    for r, probs in samples:
        gold = {g["category"] for g in r["spans"]}
        for c, p in zip(CLASS_LIST, probs, strict=True):
            if c not in gold:
                continue
            (tp if p >= thr else fn)[c] += 1
    return tp, fn


def report(model, res, thr):
    line = {v: (lockr_counts(res[v], thr) if model == "lockr"
                else decide_counts(res[v], thr)) for v in ("fp32", "qat")}
    t1, f1 = line["fp32"]
    t2, f2 = line["qat"]
    n1 = sum(t1.values()) + sum(f1.values())
    r1 = 100.0 * sum(t1.values()) / n1 if n1 else 0.0
    r2 = 100.0 * sum(t2.values()) / n1 if n1 else 0.0
    d = r1 - r2
    ok = d <= RECALL_GATE_PP
    print(f"METRIC|parity|{model}|threshold|{thr}|recall_fp32|{r1:.2f}|recall_qat|{r2:.2f}"
          f"|delta_pp|{d:.2f}|gate={'pass' if ok else 'fail'}|tp_fp32|{sum(t1.values())}"
          f"|tp_qat|{sum(t2.values())}|n_spans|{n1}")
    all_ok = ok
    for c in sorted(t1):
        n = t1[c] + f1[c]
        if not n:
            continue
        rc1, rc2 = 100.0 * t1[c] / n, 100.0 * t2[c] / n
        dd = rc1 - rc2
        cls_ok = dd <= CLASS_GATE_PP
        all_ok &= cls_ok
        print(f"METRIC|parity|{model}|threshold|{thr}|class={c}|n={n}|recall_fp32|{rc1:.2f}"
              f"|recall_qat|{rc2:.2f}|delta_pp|{dd:.2f}|gate={'pass' if cls_ok else 'fail'}")
    return all_ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["lockr", "decide"], required=True)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--skip-sha", action="store_true", help="НЕ для гейта: отладка")
    args = ap.parse_args()
    if not args.skip_sha:
        verify_weights()
    rows = load_rows(args.limit)
    print(f"PRECHECK|rows|{len(rows)}|thresholds|{','.join(str(t) for t in THRESHOLDS)}")
    peak = Peak()
    res = (run_lockr(rows, args.threads, peak, args.batch) if args.model == "lockr"
           else run_decide(rows, args.threads, peak))
    print(f"BUDGET|mode=offline-gate|rss_peak_mib_both_models|{peak.peak:.1f}")
    if args.model == "lockr":
        d = lockr_logits_delta(res["fp32"], res["qat"])
        print(f"METRIC|parity|lockr|maxabs_logit_delta_f32|{d:.4f}|rows|{len(res['fp32'])}")
    # all() короткозамкнула бы протокол на первом fail (рецидив 4b-3B:
    # 0.7-строки терялись) — печатаем ВСЕ пороги, вердикт = AND по списку.
    oks = [report(args.model, res, t) for t in WORKING_THRESHOLDS]
    for t in THRESHOLDS:
        if t not in WORKING_THRESHOLDS:
            report(args.model, res, t)  # informational: печать без вердикта
    all_ok = all(oks)
    print(f"PARITY|verdict|{'pass' if all_ok else 'fail'}|model|{args.model}"
          f"|gates=pad_le_{RECALL_GATE_PP}pp_class_le_{CLASS_GATE_PP}pp")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
