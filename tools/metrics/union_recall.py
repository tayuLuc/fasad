#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# union_recall — гейт #14 часть B: union-recall ПОЛНОГО каскада на golden-v1.1.
"""
Метрика: SPEC §5 (в нумерации AGENTS/golden-README — «§5 п.7»; в файле это пункт 6,
docs/SPEC.md:142-147): «recall ≥ 98 % … **при N=50 планка ≥98 % непроверяема**
(50/50 → нижняя граница 92.9 %), golden-набор расширяется до N≥150 [verified 18.10]».
Формула Wilson — docs/dep-verify-algorithms.md §8 (z = 1.959963984540054), та же,
что в `crates/guard-onnx/examples/recall_golden.rs::wilson_lower`; здесь печатается
ОБОЕ плечо CI (харнес Rust печатал только нижнее).

Что такое «union» (отличие от харнеса каскада-2, который мерил одну стадию):
  каскад 0 — ПРОДУКТОВЫЙ путь: бинарь `fasad`, `POST /v1/analyze`
             (X-Guard-Policy: audit_only) = cascade0::scan + config/schema.default.json
             + RoutingCfg::single(τ). Не python-переписанные чексуммы: меряется тот
             код, что выпускается (инвариант шага 7b «мерим = гоняем»).
  каскад 1 — lockR fp16 (runtime-квант), span-level, byte-overlap.
  каскад 2 — Decide q4f16, row-level («есть ли класс в тексте»), координат не даёт
             ⇒ кредит НА ВСЕ gold-спанов этого класса в строке.
  union    — span засчитан, если его поймал ЛЮБОЙ каскад (определение выше).
  strict   — union БЕЗ row-level кредита Decide (только стадии с координатами:
             каскад 0 + lockR). Обе меры печатаются всегда: row-кредит завышает
             метрику, а маскировать в демоне можно только то, у чего есть координаты.

Оракул спана = пересечение байтовых диапазонов + равенство класса — контракт
`recall_golden.rs`/`parity_golden.py` (после фикса off-by-one, ревью PR#49 блокер №1).
data/golden/README.md §«Метрика recall» требует совпадения байт-в-байт — это СТРОЖЕ
харнеса; оба определения считаются и печатаются (`oracle=overlap|exact`), молча не
выбираем: расхождение двух владельцев одной метрики = находка, а не деталь.

Классы: все 11 категорий golden-v1.1 (recall-сплит). У iban/ogrn/ogrnip нет голов у
моделей (validator_only в схеме, docs/model-audit §14) — их закрывает только каскад 0,
поэтому знаменатель 358 (не 285, как у харнеса каскада-2).

Запуск (веса: scripts/fetch-models.sh; каскад 0 — собранный бинарь демона):
  cargo build --bin fasad
  nice -n 10 env OMP_NUM_THREADS=2 \\
  uv run --isolated --python ~/.local/bin/python3.13 \\
      --with numpy --with onnxruntime --with tokenizers \\
      python tools/metrics/union_recall.py --threads 2
(= `just union-recall`; рюлинг оператора 21.10 «не нагружать CPU ноутбука»:
nice, 2 треда, один прогон за раз, сетка τ — последовательно в одном процессе.)
Опции: `--limit N`, `--thr 0.20,0.25`, `--sweep 0.10,0.15,…` (поиск оптимума),
`--daemon PATH`, `--no-daemon` (каскад 0 пустой = меряем только модели).

Детерминированность: RNG в пайплайне нет (seed: n/a); фиксированы sha256 датасета
(гейт B2), sha256 весов (models/manifest.tsv), порядок онтологии (схема), `--threads`
(ORT intra-op: docs/model-audit §5.7 — на decide потоки двигают счёт на 1 tp).
Число потоков печатается в `UNION|env`. Повтор прогона при тех же `--threads`
обязан дать совпадающие строки `UNION|` (сверка diff'ом двух `--out`).
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# Рюлинг оператора 21.10 (локальные прогоны не нагружают CPU ноутбука) + поправка
# ревьюера #73 (первичка otool/strings): вендорный libonnxruntime.1.31.0 osx-arm64
# собран БЕЗ OpenMP ⇒ OMP_NUM_THREADS на инференс НЕ влияет (он равен 2 только для
# BLAS у numpy). Настоящий рычаг потоков инференса — intra/inter_op сессии
# (= `--threads`, как в recall_golden.rs / spike.rs) и FASAD_THREADS для демона
# (config.rs, дефолт 8). Запуск под nice -n 10, один прогон за раз.
os.environ.setdefault("OMP_NUM_THREADS", "2")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "verify"))

import numpy as np  # noqa: E402
import onnxruntime as rt  # noqa: E402
import parity_golden as pg  # noqa: E402  # контракт декодера: один источник (см. docstring)
from tokenizers import Tokenizer  # noqa: E402

GOLDEN = ROOT / "data" / "golden" / "golden-v1.jsonl"
MANIFEST = ROOT / "models" / "manifest.tsv"
B2_TEST = ROOT / "crates" / "guard-detectors" / "tests" / "golden_v1.rs"
SCHEMA_FILE = ROOT / "config" / "schema.default.json"
Z95 = 1.959963984540054  # docs/dep-verify-algorithms.md §8
BAR = 98.0  # SPEC §5: recall ≥ 98 %
N_MIN = 150  # SPEC §5: планка проверяема при N≥150

GOLDEN_CLASSES = ["person_name", "inn", "snils", "ogrn", "ogrnip", "iban",
                  "address", "card_pan", "phone", "email", "passport"]
DECIDE_CLASSES = list(pg.CLASS_LIST)  # порядок = контракт блока схем (issue #53)
BIO_TO_GOLDEN = {tag: cls for cls, tags in pg.GOLDEN_TO_BIO.items() for tag in tags}


def wilson(k: int, n: int) -> tuple[float, float]:
    """95 % Wilson CI, доля (не %). Формула docs/dep-verify-algorithms.md §8."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + Z95 * Z95 / n
    centre = (p + Z95 * Z95 / (2 * n)) / denom
    half = Z95 / denom * math.sqrt(p * (1 - p) / n + Z95 * Z95 / (4 * n * n))
    return (max(0.0, centre - half), min(1.0, centre + half))


def wilson_anchors() -> None:
    """Селф-тест формулы по таблицу §8: 48/50 → 86.540, 49/50 → 89.505, 50/50 → 92.865."""
    for k, n, lo, hi in ((48, 50, 86.540, 98.896), (49, 50, 89.505, 99.646),
                         (50, 50, 92.865, 100.000)):
        a, b = (100 * wilson(k, n)[0], 100 * wilson(k, n)[1])
        if abs(a - lo) > 0.01 or abs(b - hi) > 0.01:
            sys.exit(f"FAIL wilson {k}/{n}: {a:.3f},{b:.3f} != {lo},{hi}")
    print("PRECHECK|wilson|anchors|48/50+49/50+50/50|ok")


def k_for_bar(n: int) -> int:
    """Минимум k, при котором НИЖНЯЯ граница Wilson ≥ планки (CI-дисклоузер §8)."""
    for k in range(n + 1):
        if wilson(k, n)[0] * 100 >= BAR:
            return k
    return n + 1


def load_rows() -> tuple[list[dict], list[dict]]:
    rec, neg = [], []
    with GOLDEN.open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            (rec if r["split"] == "recall" else neg).append(r)
    return rec, neg


def verify_inputs() -> dict[str, str]:
    """Fail-Closed precheck: sha256 датасета (константа B2) + весов (manifest.tsv)."""
    shas: dict[str, str] = {}
    src = B2_TEST.read_text(encoding="utf-8")
    m = re.search(r'GOLDEN_V1_SHA256:\s*&str\s*=\s*"([0-9a-f]{64})"', src)
    if m is None:
        sys.exit(f"FAIL: GOLDEN_V1_SHA256 не найдена в {B2_TEST}")
    got = hashlib.sha256(GOLDEN.read_bytes()).hexdigest()
    shas["golden-v1.jsonl"] = got
    if got != m.group(1):
        sys.exit(f"FAIL golden sha256 {got} != B2 {m.group(1)} (дрейф правок датасета)")
    pins: dict[str, tuple[str, str, str, str, int]] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        f = line.split("\t")
        if len(f) >= 6:
            pins[f[0]] = (f[1], f[2], f[3], f[4], int(f[5]))
    for role in ("extractor1b", "arbiter", "arbiter-weights", "tok-extractor1b", "tok-arbiter"):
        repo, rev, fn, sha, size = pins[role]
        path = pg.CACHE / repo / fn
        if not path.is_file():
            sys.exit(f"FAIL вес отсутствует: {path} (scripts/fetch-models.sh)")
        if path.stat().st_size != size:
            sys.exit(f"FAIL размер {path.name}: {path.stat().st_size} != {size}")
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != sha:
            sys.exit(f"FAIL sha256 {path.name}: {got} != {sha}")
        shas[path.name] = got
        print(f"PRECHECK|weight|{role}|{fn}|rev|{rev[:10]}|sha|{got[:16]}")
    for model in ("lockr", "decide"):
        repo, fn, sha = pg.SPEC[model]["qat"]
        want = pins["extractor1b"] if model == "lockr" else pins["arbiter"]
        if (repo, fn, sha) != (want[0], want[2], want[3]):
            sys.exit(f"FAIL {model}: SPEC(qat) в parity_golden расходится с models/manifest.tsv")
    shas["schema.default.json"] = hashlib.sha256(SCHEMA_FILE.read_bytes()).hexdigest()
    print("PRECHECK|inputs|golden|weights|schema|sha256-verified|cross-check|manifest==SPEC")
    return shas


def daemon_start(binary: str) -> tuple[subprocess.Popen, str, str]:
    """Продуктовый демон на loopback: FASAD_PORT=0 → порт из баннера.

    Свой process group + reap на atexit/SIGTERM/SIGINT: SIGTERM харнесу не должен
    оставлять сироту-демона, слушающего loopback (промер 21.10: после убийства
    харнеса демон выживал — убирается здесь, а не руками оператора).
    """
    if not Path(binary).is_file():
        sys.exit(f"FAIL бинарь каскада 0 отсутствует: {binary} (cargo build --bin fasad)")
    log = tempfile.NamedTemporaryFile(prefix="union-recall-daemon-", suffix=".log",  # noqa: SIM115
                                      delete=False, mode="w", encoding="utf-8")
    env = dict(os.environ)
    env.update({"FASAD_PORT": "0", "FASAD_MLOCK": "best_effort", "FASAD_VAULT_MODE": "stateless",
                "FASAD_THREADS": "2"})
    proc = subprocess.Popen([binary], stdout=log, stderr=subprocess.STDOUT, env=env, cwd=ROOT,
                            start_new_session=True)

    def reap() -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    atexit.register(reap)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_a: (reap(), sys.exit(143)))
    banner = ""
    for _ in range(200):
        banner = Path(log.name).read_text(encoding="utf-8")
        if "listening on" in banner:
            break
        time.sleep(0.05)
    m = re.search(r"listening on http://([\d.]+):(\d+)/health", banner)
    if not m:
        reap()
        sys.exit(f"FAIL демон не поднялся: {banner!r} ({log.name})")
    return proc, f"http://{m.group(1)}:{m.group(2)}", log.name


def run_cascade0(rows: list[dict], base: str, thr: float) -> dict[str, list[dict]]:
    """Каскад 0 продуктовым путём: POST /v1/analyze на каждую строку.

    Скор чексумм = 1.0 (`Hit::score` = DetectionSource::DeterministicW), τ на него
    не действует: параметр запроса = эхо рабочей точки (эффективный порог
    max(τ_запроса, FASAD_TAU_LOW)).
    """
    out: dict[str, list[dict]] = {}
    t0 = time.time()
    for r in rows:
        body = json.dumps({"text": r["text"], "score_threshold": thr}).encode()
        req = urllib.request.Request(
            base + "/v1/analyze", data=body,
            headers={"content-type": "application/json", "X-Guard-Policy": "audit_only"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — loopback
            spans = json.load(resp)
        out[r["id"]] = [{"cls": s["class"], "b0": s["byte_start"], "b1": s["byte_end"],
                         "score": s["score"], "validator": s["validator"]} for s in spans]
    print(f"TIME|cascade0|s|{time.time() - t0:.2f}|rows|{len(rows)}|spans"
          f"|{sum(len(v) for v in out.values())}")
    return out


def _session(path: str, threads: int) -> "rt.InferenceSession":
    """Сессия ORT с зафиксированными потоками (детерминизм + щадящий режим 21.10).

    intra_op = inter_op = threads: число потоков — часть воспроизводимости метрики
    (docs/model-audit §5.7: на decide потоки двигают счёт на 1 tp из-за intra-op
    редукций), а 2 = верх границы, разрешённой рюлингом «не нагружать CPU ноутбука».
    """
    opts = rt.SessionOptions()
    opts.intra_op_num_threads = threads
    opts.inter_op_num_threads = threads
    return rt.InferenceSession(path, opts, providers=["CPUExecutionProvider"])


def run_lockr(rows: list[dict], threads: int, batch: int) -> dict[str, list[dict]]:
    """lockR fp16 (runtime-квант). Декодер = функции parity_golden (оракул PR#49)."""
    repo, fn, _ = pg.SPEC["lockr"]["qat"]
    tokrepo, tokfn = pg.SPEC["lockr"]["tok"]
    tok = Tokenizer.from_file(str(pg.CACHE / tokrepo / tokfn))
    sess = _session(str(pg.CACHE / repo / fn), threads)
    out: dict[str, list[dict]] = {}
    t0 = time.time()
    for i in range(0, len(rows), batch):
        chunk = rows[i:i + batch]
        encs = [tok.encode(r["text"], add_special_tokens=True) for r in chunk]
        lens = [min(len(e), pg.LOCKR_PAD) for e in encs]
        ids = np.zeros((len(chunk), pg.LOCKR_PAD), np.int64)
        mask = np.zeros((len(chunk), pg.LOCKR_PAD), np.int64)
        types = np.zeros((len(chunk), pg.LOCKR_PAD), np.int64)
        for j, (e, ln) in enumerate(zip(encs, lens, strict=True)):
            ids[j, :ln] = e.ids[:ln]
            mask[j, :ln] = e.attention_mask[:ln]
        lg = sess.run(["logits"], {"input_ids": ids, "attention_mask": mask,
                                   "token_type_ids": types})[0]
        for j, r in enumerate(chunk):
            e, ln = encs[j], lens[j]
            ids_e = list(e.ids)
            om = e.offsets  # 1-в-1 с ids (промер 20.10), сдвига НЕТ (рецидив −1)
            spans = []
            for cls, t_first, t_last, conf in pg.spans_grouped(
                    pg.spans_bio_tags(lg[j], ln, ids_e, tok)):
                i1 = min(t_last, len(ids_e)) - 1
                while i1 >= t_first and tok.decode([ids_e[i1]]).startswith("##"):
                    i1 -= 1
                if i1 < t_first or t_first >= len(om):
                    continue
                b0 = len(r["text"][:om[t_first][0]].encode("utf-8"))
                b1 = len(r["text"][:om[min(i1, len(om) - 1)][1]].encode("utf-8"))
                if b1 > b0:
                    spans.append({"cls": cls, "b0": b0, "b1": b1, "conf": conf})
            out[r["id"]] = spans
    print(f"TIME|lockr_fp16|s|{time.time() - t0:.2f}|rows|{len(rows)}|batch|{batch}"
          f"|threads|{threads}|spans|{sum(len(v) for v in out.values())}")
    del sess
    return out


def run_decide(rows: list[dict], threads: int) -> tuple[dict[str, dict[str, float]], int]:
    """Decide q4f16: P(yes) на 8 вопросов, row-level. Контракт = parity run_decide.

    `№` → пробел — та же подстановка, что в `recall_golden.rs` (Spiber '№' → UNK,
    промер 4b-3C; счётчик unk_rows обязан быть 0).
    """
    tokrepo, tokfn = pg.SPEC["decide"]["tok"]
    tok = Tokenizer.from_file(str(pg.CACHE / tokrepo / tokfn))
    tok.post_processor = None  # контракт арбитра: JSONL без TemplateProcessing
    block = pg.schema_block_text(pg.SCHEMA)
    repo, fn, _ = pg.SPEC["decide"]["qat"]
    sess = _session(str(pg.CACHE / repo / fn), threads)
    out: dict[str, dict[str, float]] = {}
    unk = 0
    t0 = time.time()
    for r in rows:
        text = r["text"].replace("№", " ")
        unk += int(tok.encode(text).tokens.count("[UNK]"))
        enc = tok.encode(pg.clean_state(block + " " + text), add_special_tokens=False)
        ids = list(enc.ids)
        groups = pg.decide_groups(ids)
        if len(groups) != len(pg.SCHEMA):
            sys.exit(f"FAIL layout {r['id']}: групп {len(groups)} ≠ {len(pg.SCHEMA)}")
        sizes = [len(g) for g in groups]
        if sizes != [2] * len(pg.SCHEMA):
            sys.exit(f"FAIL sizes {r['id']}: {sizes[:3]}…")
        markers = [p for g in groups for p in g]
        lg = sess.run(["logits"], {"input_ids": np.array([ids], np.int64),
                                   "attention_mask": np.ones((1, len(ids)), np.int64),
                                   "marker_positions": np.array([markers], np.int64)})[0]
        flat = lg.reshape(-1).astype(np.float64).tolist()
        probs: dict[str, float] = {}
        off = 0
        for ci, g in enumerate(groups):
            probs[DECIDE_CLASSES[ci]] = pg.softmax(flat[off:off + len(g)])[0]
            off += len(g)
        if off != len(flat):
            sys.exit(f"FAIL logits {r['id']}: {off} != {len(flat)}")
        out[r["id"]] = probs
    print(f"TIME|decide_q4f16|s|{time.time() - t0:.2f}|rows|{len(rows)}|unk_rows|{unk}"
          f"|threads|{threads}")
    del sess
    return out, unk


def overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def stage_hits(spans: list[dict], cls: str, g0: int, g1: int, thr: float,
               oracle: str, cls_of) -> bool:
    """Попадание стадии по спану: класс + (overlap | exact) + порог."""
    for s in spans:
        if cls_of(s) != cls:
            continue
        if s.get("conf", 1.0) < thr:
            continue
        if oracle == "exact":
            if s["b0"] == g0 and s["b1"] == g1:
                return True
        elif overlap(s["b0"], s["b1"], g0, g1):
            return True
    return False


def count(rows: list[dict], c0: dict, lock: dict, dec: dict, thr: float,
          oracle: str) -> tuple[dict, dict]:
    """Счётчики: per-class + агрегаты (span-level union/strict, row-level union)."""
    per = {c: dict(n=0, c0=0, lockr=0, dec=0, union=0, strict=0) for c in GOLDEN_CLASSES}
    span_n = span_u = span_s = row_n = row_h = 0
    for r in rows:
        s0, sl, probs = c0.get(r["id"], []), lock.get(r["id"], []), dec.get(r["id"], {})
        row_all = True
        for g in r["spans"]:
            cls, g0, g1 = g["category"], g["start_byte"], g["end_byte"]
            if cls not in per:
                continue
            h0 = stage_hits(s0, cls, g0, g1, 0.0, oracle, lambda s: s["cls"])
            hl = stage_hits(sl, cls, g0, g1, thr, oracle, lambda s: BIO_TO_GOLDEN.get(s["cls"]))
            hd = cls in probs and probs[cls] >= thr
            d = per[cls]
            d["n"] += 1
            d["c0"] += int(h0)
            d["lockr"] += int(hl)
            d["dec"] += int(hd)
            d["union"] += int(h0 or hl or hd)
            d["strict"] += int(h0 or hl)
            span_n += 1
            span_u += int(h0 or hl or hd)
            span_s += int(h0 or hl)
            row_all = row_all and (h0 or hl or hd)
        row_n += 1
        row_h += int(row_all)
    return per, dict(span_n=span_n, span_u=span_u, span_s=span_s, row_n=row_n, row_h=row_h)


def count_negative(neg: list[dict], c0: dict, lock: dict, thr: float) -> dict:
    """FP на negative-сплите: строки-бейты «ловить нельзя» (README датасета).

    Размеченные спаны negative-строк = валидные форматы вне области / невалидные
    чексуммы: любой выпущенный спан = FP (count-мера, не precision — знаменателя
    «всего ПДн в природе» у нас нет).
    """
    f_c0 = f_lk = bait_c0 = bait_lk = rows_any = 0
    for r in neg:
        gold = [(g["start_byte"], g["end_byte"]) for g in r["spans"]]
        s0 = c0.get(r["id"], [])
        sl = [s for s in lock.get(r["id"], []) if s["conf"] >= thr]
        for s in s0:
            f_c0 += 1
            bait_c0 += int(any(overlap(s["b0"], s["b1"], a0, a1) for a0, a1 in gold))
        for s in sl:
            if BIO_TO_GOLDEN.get(s["cls"]) in GOLDEN_CLASSES:
                f_lk += 1
                bait_lk += int(any(overlap(s["b0"], s["b1"], a0, a1) for a0, a1 in gold))
        rows_any += int(bool(s0 or sl))
    return dict(rows=len(neg), spans=len(gold), rows_any=rows_any, c0=f_c0, lockr=f_lk,
                union=f_c0 + f_lk, bait_c0=bait_c0, bait_lockr=bait_lk)


def emit_table(per: dict, agg: dict, thr: float, oracle: str) -> None:
    print(f"UNION|table|thr|{thr:.2f}|oracle|{oracle}|cols|class|n|c0|lockr|decide|union|strict|wilson_lo|wilson_hi")
    for c in GOLDEN_CLASSES:
        d = per[c]
        if d["n"] == 0:
            continue
        lo, hi = wilson(d["union"], d["n"])
        print(f"UNION|per_class|{c}|{d['n']}|{d['c0']}|{d['lockr']}|{d['dec']}|{d['union']}"
              f"|{d['strict']}|{100 * lo:.2f}|{100 * hi:.2f}")
    for name, k, n in (("union_span", agg["span_u"], agg["span_n"]),
                       ("strict_span", agg["span_s"], agg["span_n"]),
                       ("union_row", agg["row_h"], agg["row_n"])):
        lo, hi = wilson(k, n)
        pct = 100.0 * k / n if n else 0.0
        print(f"UNION|overall|thr|{thr:.2f}|oracle|{oracle}|agg|{name}|k|{k}|n|{n}"
              f"|recall|{pct:.2f}|wilson95_lo|{100 * lo:.2f}|wilson95_hi|{100 * hi:.2f}")


class Tee:
    """stdout + файл: `--out` обязан писать СЫРОЙ вывод прогона (приложение к docs).

    Первая версия открывала файл и не писала в него ни строки — raw-артефакт
    терялся, воспроизводимость таблицы повисала на перенаправлении shell'а.
    """

    def __init__(self, fh):
        self.fh = fh

    def write(self, s: str) -> None:
        # Flush на каждую строку: при редиректе stdout буферизируется блоками, и
        # долгий прогон выглядел как зависший (нулевых строк в логе 6 минут).
        self.fh.write(s)
        self.fh.flush()
        sys.__stdout__.write(s)
        sys.__stdout__.flush()

    def flush(self) -> None:
        if not self.fh.closed:
            self.fh.flush()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=2,
                    help="intra/inter_op потоков ORT (рюлинг 21.10: 2; часть воспроизводимости)")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--thr", default="0.20,0.25")
    ap.add_argument("--sweep", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--daemon", default=str(ROOT / "target" / "debug" / "fasad"))
    ap.add_argument("--no-daemon", action="store_true")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    out_fh = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    if out_fh:
        sys.stdout = Tee(out_fh)
    t_start = time.time()
    wilson_anchors()
    shas = verify_inputs()
    rec, neg = load_rows()
    if args.limit:
        rec, neg = rec[:args.limit], neg[:args.limit]
    n_spans = sum(len(r["spans"]) for r in rec)
    n_cls = {c: sum(1 for r in rec for g in r["spans"] if g["category"] == c) for c in GOLDEN_CLASSES}
    print(f"UNION|dataset|rows|{len(rec)}|spans|{n_spans}|negative_rows|{len(neg)}"
          f"|negative_spans|{sum(len(r['spans']) for r in neg)}")
    print("UNION|support|" + "|".join(f"{c}:{n_cls[c]}" for c in GOLDEN_CLASSES))
    print(f"UNION|N_gate|rows|{len(rec)}|spans|{n_spans}|n_min|{N_MIN}"
          f"|verdict|{'covered' if min(len(rec), n_spans) >= N_MIN else 'NOT-COVERED'}")
    for n in sorted({len(rec), n_spans, min(n_cls.values())}):
        print(f"UNION|ci_probe|n|{n}|k_for_bar_98|{k_for_bar(n)}|deficit_at_full|{n - k_for_bar(n)}")
    print(f"UNION|env|python|{platform.python_version()}|ort|{rt.__version__}|numpy|{np.__version__}"
          f"|platform|{platform.system()}-{platform.machine()}|threads|{args.threads}"
          f"|omp_num_threads|{os.environ.get('OMP_NUM_THREADS', 'unset')}"
          f"|niceness|{os.nice(0)}|seed|n/a-no-RNG")
    for k, v in shas.items():
        print(f"UNION|sha|{k}|{v}")
    print(f"UNION|bar|recall|{BAR}|ci|wilson95-lower|formula|docs/dep-verify-algorithms.md §8")

    proc = None
    base = ""
    if not args.no_daemon:
        proc, base, dlog = daemon_start(args.daemon)
        print(f"UNION|cascade0|binary|{args.daemon}|url|{base}|log|{dlog}")
    empty = {r["id"]: [] for r in rec + neg}
    c0 = run_cascade0(rec, base, 0.20) if proc else empty
    c0_neg = run_cascade0(neg, base, 0.20) if proc else empty
    lock = run_lockr(rec, args.threads, args.batch)
    dec, _unk = run_decide(rec, args.threads)
    lock_neg = run_lockr(neg, args.threads, args.batch)

    grid = [float(x) for x in args.thr.split(",") if x.strip()]
    for thr in grid:
        for oracle in ("overlap", "exact"):
            per, agg = count(rec, c0, lock, dec, thr, oracle)
            emit_table(per, agg, thr, oracle)
        ng = count_negative(neg, c0_neg, lock_neg, thr)
        print(f"UNION|negative|thr|{thr:.2f}|rows|{ng['rows']}|rows_any_fired|{ng['rows_any']}"
              f"|spans_c0|{ng['c0']}|spans_lockr|{ng['lockr']}|spans_union|{ng['union']}"
              f"|bait_c0|{ng['bait_c0']}|bait_lockr|{ng['bait_lockr']}")

    sweep = [float(x) for x in args.sweep.split(",") if x.strip()]
    best = None
    if sweep:
        print("UNION|sweep|thr|union|union_lo|strict|strict_lo|row|neg_fired")
        for thr in sweep:
            _, agg = count(rec, c0, lock, dec, thr, "overlap")
            ng = count_negative(neg, c0_neg, lock_neg, thr)
            u = 100.0 * agg["span_u"] / agg["span_n"]
            s = 100.0 * agg["span_s"] / agg["span_n"]
            lo = 100 * wilson(agg["span_u"], agg["span_n"])[0]
            lo_s = 100 * wilson(agg["span_s"], agg["span_n"])[0]
            print(f"UNION|sweep|{thr:.2f}|{u:.2f}|{lo:.2f}|{s:.2f}|{lo_s:.2f}"
                  f"|{100.0 * agg['row_h'] / agg['row_n']:.2f}|{ng['union']}")
            key = (agg["span_u"], agg["span_s"], -ng["union"], -thr)
            if best is None or key > best[0]:
                best = (key, thr, u, s, lo, lo_s)
        if best:
            _, thr_b, u, s, lo, lo_s = best
            print(f"UNION|optimum|thr|{thr_b:.2f}|union|{u:.2f}|union_lo|{lo:.2f}"
                  f"|strict|{s:.2f}|strict_lo|{lo_s:.2f}|grid|{','.join(f'{x:.2f}' for x in sweep)}")

    thr = min(grid)
    _, agg = count(rec, c0, lock, dec, thr, "overlap")
    lo_u = 100 * wilson(agg["span_u"], agg["span_n"])[0]
    lo_s = 100 * wilson(agg["span_s"], agg["span_n"])[0]
    k_need = k_for_bar(agg["span_n"])
    verdict = "meets-bar" if lo_u >= BAR else "known-below-bar"
    print(f"UNION|verdict|{verdict}|thr|{thr:.2f}|union|{100.0 * agg['span_u'] / agg['span_n']:.2f}"
          f"|union_k|{agg['span_u']}|union_n|{agg['span_n']}|union_wilson_lo|{lo_u:.2f}"
          f"|strict|{100.0 * agg['span_s'] / agg['span_n']:.2f}|strict_wilson_lo|{lo_s:.2f}"
          f"|row|{100.0 * agg['row_h'] / agg['row_n']:.2f}"
          f"|k_for_bar|{k_need}|deficit_spans|{max(0, k_need - agg['span_u'])}|bar|{BAR}")
    print(f"TIME|total|s|{time.time() - t_start:.2f}|threads|{args.threads}"
          f"|daemon|{'on' if proc else 'off'}")
    if proc:
        proc.terminate()
        proc.wait(timeout=10)
    if out_fh:
        # sys.stdout возвращаем ДО close: закрытый Tee даёт ValueError на финальном
        # flush интерпретатора = rc=120 при полностью успешном прогоне (промер 21.10).
        sys.stdout = sys.__stdout__
        out_fh.close()


if __name__ == "__main__":
    main()
