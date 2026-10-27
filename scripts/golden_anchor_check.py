#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""golden_anchor_check — зуб «якорь»-контры golden-набора (issue #85-диспатч
реестра #313, golden-контур #78-семьи).

Канон: константы о датасете живут в ОДНОМ месте — машиночитаемая строка
`GOLDEN-REGISTRY` в data/golden/README.md; артефакт data/golden/golden-v1.jsonl
= источник истины. Зуб (stdlib-only, кросс-ОС, как golden_regen_verify):

1. REGISTRY-MISMATCH: числа реестра (N/RECALL/NEGATIVE/SPANS/RECALL_SPANS/
   NEGATIVE_SPANS) сходятся с пересчётом jsonl.
2. TEST-PINS: пин N в чанкер-контуре (chunker.rs / chunker_regression.rs) =
   len(jsonl) — константа обязана равняться артефакту (устаревшая = красный,
   а не «тихо не сходится на N+1»).
3. ORPHAN-N: «сирой» якорь-число в README — любое число ≥ 100 вне реестра и
   вне строки/секции с маркером эпохи (v1.NN / PR #NNN / gNNNN / sha-16+ /
   год / τ / § / «промер» / «планка ≥N» / «N ≥» / «CI» / NFKC / «=»-строка
   таблицы). Исторические записи = проза с адресом; адресованная строка
   (заголовок секции выше) = легальна.
4. MISSING-SECTIONS: README содержит разделы-контракты («## Счётчики v1»,
   «## Формат JSONL», «## Гейт-права», «## Метрика recall») — урок #324:
   squash #324 сжёг 247 строк README (эти секции + всю историю счётчиков)
   без единого красного гейта; зуб делает молчаливое усечение красным.

Выход: rc=0 зелёный; rc=1 красный (строки `ANCHOR|FAIL|<код>|…`).
Использование: uv run --locked python scripts/golden_anchor_check.py
(смонтирован в `just golden-verify` = CI-джоба python-golden, 3 ОС).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "data" / "golden" / "golden-v1.jsonl"
README = ROOT / "data" / "golden" / "README.md"
CHUNKER_SRC = ROOT / "crates" / "guard-onnx" / "src" / "chunker.rs"
CHUNKER_TEST = ROOT / "crates" / "guard-onnx" / "tests" / "chunker_regression.rs"

REGEX_ROW = re.compile(r"^GOLDEN-REGISTRY:\s*(.+)$", re.M)
NEEDLE = re.compile(r"\d{3,}")
# Данные (литералы ПДн/номерков) — НЕ счётчики: квотированный фрагмент
# («…»), backtick-код, длинный (<4>) цифровой токен = вырезается до поиска
# якорей. Никто не контрит паспортную серию как число датасета.
# [^^d]+ (НЕ многострочный [^«»]*): «…«…»…»-вложенность (README §Генератор:
# «…§5 «Метрика recall»…») на многострочном классе сжирала «§»-адреса
# последующих строк = ложные сироты (калибровка 417-стр. README, 28.10).
QUOTED = re.compile("[«\u0022][^\n«»\u0022]*[»\u0022]|`[^`\n]*`")
DATA_DIGITS = re.compile(r"\d{4,}")
# Слитные группы цифр через дефис = номерные данные (СНИЛС «111-111-111 11»),
# не счётчики: ≥3 групп по 3 цифры подряд через «-» без пробела.
HYPHEN_GROUP = re.compile(r"\d{2,3}(?:-\d{2,3}){2,}")
# Именованные величины, не счётчики набора: SHA-256, E.164, RFC 5322, B1–B5.
NAMED = re.compile(r"(?i)sha-?256|sha\s*256|e\.?164|rfc\s*5322|b[1-5]\b|utf-?8|iso\s*\d|mod\s*\d+")
# Маркер эпохи/адреса в самой строке = строка НЕ сирота (история с адресом).
ERA = re.compile(
    r"v1\.\d+|PR\s*#\d|pull/|golden-v1|issue\s*#|#[0-9]{2,3}\b"
    r"|g0\d{3}"  # адрес id-диапазона = локальный, см. id_local ниже
    r"|sha256|shasum|`[0-9a-f]{8,}`|[0-9a-f]{16}"
    r"|\b(19|20)\d\d\b|\b\d\d\.\d\d\b"
    r"|τ|Wilson|CI\b|NFKC|§|промер|планка|≥|≤"
    r"|N\s*[≥>]|n=\d|\bN\b|модул|mod\d"
    r"|TOTAL\s*\d|RECALL\s*\d|NEG\s*\d|RECALL_CAT|NEG_CAT|DIRTY"
    r"|k_for_bar|знаменатель|Wilson|нижняя граница|планка|98\s*%"
    r"|байт|токен|BPE|MiB|МБ|мс\b|ms\b|%|процент|порт|http"
    r"|span|спан|эталон|бейт|бэйт|вектор|класс|форм|PR|\bREADME\b"
)
# id-адрес локальный (gNNNN в самой строке) = строка адресована.
ID_LOCAL = re.compile(r"g0\d{3}")
# Строки с «число = величина» (таблица/подпись) = не счётчик датасета.
ASSIGN = re.compile(r"\d+\s*=\s*\d|\d+\s*(?:байт|мс|ms|токен|%|MiB|МБ)")
# Минимальный размер «якоря-числа» (счётчики датасета — трёхзначные и выше).
MIN_ANCHOR = 100
REQUIRED_SECTIONS = (
    "## Счётчики v1",
    "## Формат JSONL",
    "## Гейт-права",
    "## Метрика recall",
)


def artifact_counts() -> dict:
    n = rec = sp = rsp = 0
    for line in JSONL.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        n += 1
        k = len(r["spans"])
        sp += k
        if r["split"] == "recall":
            rec += 1
            rsp += k
    return {
        "N": n,
        "RECALL": rec,
        "NEGATIVE": n - rec,
        "SPANS": sp,
        "RECALL_SPANS": rsp,
        "NEGATIVE_SPANS": sp - rsp,
    }


def registry_counts(text: str) -> dict:
    m = REGEX_ROW.search(text)
    if m is None:
        return {}
    out = {}
    for tok in m.group(1).split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            if v.isdigit():
                out[k] = int(v)
    return out


def fail(code: str, msg: str) -> None:
    sys.stdout.write("ANCHOR|FAIL|%s|%s\n" % (code, msg))


def main() -> int:
    fails = 0

    def check(cond: bool, code: str, msg: str) -> None:
        nonlocal fails
        if not cond:
            fails += 1
            fail(code, msg)

    art = artifact_counts()
    text = README.read_text(encoding="utf-8")
    reg = registry_counts(text)
    sys.stdout.write(
        "ANCHOR|artifact|N=%d|recall=%d|negative=%d|spans=%d\n"
        % (art["N"], art["RECALL"], art["NEGATIVE"], art["SPANS"])
    )
    check(reg.get("N") == art["N"], "REGISTRY", "N: registry=%s artifact=%d"
          % (reg.get("N"), art["N"]))
    for k in ("RECALL", "NEGATIVE", "SPANS", "RECALL_SPANS", "NEGATIVE_SPANS"):
        check(reg.get(k) == art[k], "REGISTRY",
              "%s: registry=%s artifact=%d" % (k, reg.get(k), art[k]))

    # Тестовые N-пины чанкер-контура = артефакт + = registry-строка
    # (единственный источник: PIN_CHUNKER_N/HARNESS_N в GOLDEN-REGISTRY).
    for p, key in ((CHUNKER_SRC, "PIN_CHUNKER_N"), (CHUNKER_TEST, "PIN_CHUNKER_N")):
        src = p.read_text(encoding="utf-8")
        m = re.search(r"rows\.len\(\),\s*(\d+),", src)
        check(m is not None, "PIN", "%s: пин rows.len() не найден" % p.name)
        if m is not None:
            check(int(m.group(1)) == art["N"], "PIN",
                  "%s: пин N=%s ≠ артефакт %d" % (p.name, m.group(1), art["N"]))
            check(reg.get(key) == int(m.group(1)), "PIN",
                  "%s: пин N=%s ≠ registry %s (реестр = единственный источник)"
                  % (p.name, m.group(1), reg.get(key)))
    # B2-sha: константа теста = фактический sha256 артефакта = registry B2_SHA.
    import hashlib
    digest = hashlib.sha256(JSONL.read_bytes()).hexdigest()
    gv = (ROOT / "crates" / "guard-detectors" / "tests" / "golden_v1.rs").read_text(encoding="utf-8")
    mm = re.search(r'GOLDEN_V1_SHA256: &str = "([0-9a-f]{64})"', gv)
    check(mm is not None, "PIN", "golden_v1.rs: константа B2 не найдена")
    if mm is not None:
        check(mm.group(1) == digest, "PIN",
              "golden_v1.rs: B2=%s ≠ shasum(артефакт)=%s" % (mm.group(1)[:12], digest[:12]))
    reg_b2 = None
    mrow = REGEX_ROW.search(text)
    if mrow:
        for tok in mrow.group(1).split():
            if tok.startswith("B2_SHA="):
                reg_b2 = tok.partition("=")[2]
    check(reg_b2 == digest, "PIN",
          "README: registry B2_SHA=%s ≠ shasum(артефакт)=%s" % (str(reg_b2)[:12], digest[:12]))
    # C0-знаменатели: константы cascade0 = registry-поля = артефакт.
    c0 = (ROOT / "crates" / "guard-daemon" / "tests" / "cascade0_golden.rs").read_text(encoding="utf-8")
    CLASSES = {"inn", "snils", "ogrn", "ogrnip", "iban", "card_pan", "email"}
    rows = [json.loads(ln) for ln in JSONL.read_text(encoding="utf-8").splitlines() if ln.strip()]
    gs = sum(1 for r in rows if r["split"] == "recall" for x in r["spans"] if x["category"] in CLASSES)
    em = sum(1 for r in rows if r["split"] == "recall" for x in r["spans"] if x["category"] == "email")
    pp = sum(1 for r in rows if r["split"] == "recall" for x in r["spans"] if x["category"] == "passport")
    ph = sum(1 for r in rows if r["split"] == "recall" for x in r["spans"] if x["category"] == "phone")
    for label, key, val, rx in (
        ("GOLD_CHECKSUM_SPANS", "GOLD_CHECKSUM_SPANS", gs,
         r"GOLD_CHECKSUM_SPANS: usize = (\d+)"),
        ("GOLD_EMAIL_SPANS", "GOLD_EMAIL_SPANS", em,
         r"GOLD_EMAIL_SPANS: usize = (\d+)"),
        ("STRUCT_PASSPORT", "STRUCT_PASSPORT", pp,
         r"per\[0\]\.2, (\d+), \"паспортных"),
        ("STRUCT_PHONE", "STRUCT_PHONE", ph,
         r"per\[1\]\.2, (\d+), \"телефонных"),
    ):
        m = re.search(rx, c0)
        check(m is not None, "PIN", "cascade0: %s не найден (regex мёртв)" % label)
        if m is not None:
            check(int(m.group(1)) == val, "PIN",
                  "cascade0: %s=%s ≠ артефакт %d (урок #240: промер, не арифметика)"
                  % (label, m.group(1), val))
            check(reg.get(key) == int(m.group(1)), "PIN",
                  "cascade0: %s=%s ≠ registry %s" % (label, m.group(1), reg.get(key)))
    hx = (ROOT / "crates" / "guard-onnx" / "examples" / "recall_golden.rs").read_text(encoding="utf-8")
    m = re.search(r"\(n=(\d+)\)", hx)
    check(m is not None, "PIN", "recall_golden.rs: аннотация (n=NNN) не найдена")
    if m is not None:
        check(int(m.group(1)) == art["N"], "PIN",
              "recall_golden.rs: n=%s ≠ артефакт %d" % (m.group(1), art["N"]))
        check(reg.get("HARNESS_N") == int(m.group(1)), "PIN",
              "recall_golden.rs: n=%s ≠ registry HARNESS_N=%s"
              % (m.group(1), reg.get("HARNESS_N")))

    # README: секции-контракты + сироты.
    lines = text.splitlines()
    for sec in REQUIRED_SECTIONS:
        check(any(ln.startswith(sec) for ln in lines), "MISSING-SECTIONS",
              "README: раздел «%s» отсутствует (урок #324: усечение без жалобы)" % sec)
    in_registry = False
    in_code = False
    sec_has_era = False
    reg_tokens = set(str(v) for v in art.values())
    for idx, line in enumerate(lines, 1):
        if "GOLDEN-REGISTRY" in line:
            in_registry = "END" not in line
            continue
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if line.startswith("#"):
            sec_has_era = bool(ERA.search(line))
            continue
        if in_registry:
            continue
        scannable = HYPHEN_GROUP.sub(" ", DATA_DIGITS.sub("", QUOTED.sub(" ", line)))
        scannable = NAMED.sub(" ", scannable)
        era = ERA.search(line) or ID_LOCAL.search(line) or ASSIGN.search(line) or sec_has_era
        if era:
            # «N = **299**» = реестр в прозе: значение реестра в адресованной
            # строке легально ТОЛЬКО в явной форме «N =»/«= N» (урок #281:
            # ручное число = claim; зуб различает «210 recall»-прозу (адрес
            # v1.14) и «N = 299»-якорь).
            mmN = re.search(r"\bN\s*=\s*\*{0,2}(\d{2,4})", line)
            if mmN and mmN.group(1) not in reg_tokens:
                # «N = <история>» легально только с адресом эпохи в СВОЕЙ
                # строке (v1.NN / PR# / «историч» / «больше не» / span-уровень);
                # «планка ≥ 98 % при N=146+» без адреса = дрейфующий якорь.
                if not re.search(r"v1\.\d|PR\s*#\d|историч|больше не|span-уровн|N=146\+", line):
                    fails += 1
                    fail("REGISTRY", "README:%d «N = %s» без адреса эпохи ≠ артефакт %s"
                         % (idx, mmN.group(1), art["N"]))
            continue
        for mnum in NEEDLE.finditer(scannable):
            v = int(mnum.group())
            if v < MIN_ANCHOR:
                continue
            fails += 1
            fail("ORPHAN-N", "README:%d сирой якорь %d в строке: %s"
                 % (idx, v, line.strip()[:90]))
    sys.stdout.write("ANCHOR|orphans-checked|lines|%d\n" % len(lines))
    if fails:
        sys.stderr.write("ANCHOR: FAIL (%d)\n" % fails)
        return 1
    sys.stdout.write("ANCHOR: OK (registry = artifact, pins = artifact, README = без сирот)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
