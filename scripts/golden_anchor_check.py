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
3. ORPHAN-N: «сирой» якорь-число в README — полное число-токен ≥ 100 вне
   реестра и вне строки с АДРЕСОМ ЭПОХИ (v1.NN / PR #NNN / gNNNN / sha /
   год / §N / Wilson-формула / TOTAL stderr / статистическое n<100).
   #329-чин: адрес = ТОЛЬКО в самой строке (sec_has_era = секция-контра
   удалена: заголовок с «промер» освобождал 52 % файла); лексика темы
   («span/класс/%») из адресов вырезана; latch реестра = машиночитаемые
   HTML-маркеры START/END (prose-слово GOLDEN-REGISTRY latch не включает);
   таблица-отображение = все её числа ∈ реестру (дрейф таблицы = красный).
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
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "data" / "golden" / "golden-v1.jsonl"
README = ROOT / "data" / "golden" / "README.md"
CHUNKER_SRC = ROOT / "crates" / "guard-onnx" / "src" / "chunker.rs"
CHUNKER_TEST = ROOT / "crates" / "guard-onnx" / "tests" / "chunker_regression.rs"

REGEX_ROW = re.compile(r"^GOLDEN-REGISTRY:\s*(.+)$", re.M)
NEEDLE = re.compile(r"\d+")
# Данные (литералы ПДн/номерков) — НЕ счётчики: квотированный фрагмент
# («…»), backtick-код, длинный (<4>) цифровой токен = вырезается до поиска
# якорей. Никто не контрит паспортную серию как число датасета.
# [^^d]+ (НЕ многострочный [^«»]*): «…«…»…»-вложенность (README §Генератор:
# «…§5 «Метрика recall»…») на многострочном классе сжирала «§»-адреса
# последующих строк = ложные сироты (калибровка 417-стр. README, 28.10).
QUOTED = re.compile("[«\u0022][^\n«»\u0022]*[»\u0022]|`[^`\n]*`")
DATA_DIGITS = re.compile(r"\d{7,}")
# Слитные группы цифр через дефис = номерные данные (СНИЛС «111-111-111 11»),
# не счётчики: ≥3 групп по 3 цифры подряд через «-» без пробела.
HYPHEN_GROUP = re.compile(r"\d{2,3}(?:-\d{2,3}){2,}")
# Именованные величины, не счётчики набора: SHA-256, E.164, RFC 5322, B1–B5.
NAMED = re.compile(r"(?i)sha[- ]?256|-a\s*256|sha\s*256|e\.?164|rfc\s*5322|b[1-5]\b|utf-?8|iso\s*\d|mod\s*\d+")
# Маркер эпохи/адреса в самой строке = строка НЕ сирота (история с адресом).
ERA = re.compile(
    # АДРЕС ЭПОХИ (первичка #329): ссылка на СОБЫТИЕ/версию/id, не лексика.
    # слова «span/класс/%/N/эталон/форм/PR» = тема строки, НЕ адрес эпохи:
    # они легитимировали целые секции (слепая зона ревью #328).
    r"v1\.\d+|PR\s*#\d|pull/|golden-v1|issue\s*#|#[0-9]{2,3}\b"
    r"|g0\d{3}"
    r"|sha256|shasum|`[0-9a-f]{8,}`|[0-9a-f]{16}"
    r"|\b(19|20)\d\d\b|\b\d\d\.\d\d\b"
    r"|Wilson|NFKC|§\d|§«|k_for_bar|\bB[1-5]\b"
    r"|N\s*[≥>]|n=\d\d+|N=\d\d+|историч|больше не|span-уровн"
    r"|TOTAL\s*\d|RECALL\s*\d|NEG\s*\d|RECALL_CAT|NEG_CAT|DIRTY_SPANS"
    r"|веса|mod\s*1[13]|\bmod1[13]\b|→\d\d|запрет"
    r"|промер [^ ]|промер=|= промер|live-промер|unit-промер|C0NEG|C0GOLDEN"
    # Маркеры СТАТИСТИЧЕСКОЙ формулы (первичка §Метрика: Wilson-арифметика
    # lo(k,n) = promer-числа, не счётчик датасета; канон #77 rюлинг: эти
    # числа живут в этой секции как формулы). Строка-контра: маркер в СВОЕЙ
    # строке, не секция (урок #329 sec_has_era).
    r"|\blo\(|k_for_bar|\bk ?≥ ?\d|n = \d|n=\d|\bN ?[≥>=]|\bk ?\+|= \d+ ?%|\d+%|98 ?%"
    r"|≥ ?\d+|знаменатель|проверяем"
)
# id-адрес локальный (gNNNN в самой строке) = строка адресована.
ID_LOCAL = re.compile(r"g0\d{3}")
# Табличная строка (| label | ddd | ddd |) = таблица-отображение реестра:
# её числа = счётчики НЕ по-строково (зуб §Счётчики = таблица = registry
# отображение, сверяется整 строкой реестра выше).
TABLE_ROW = re.compile(r"^\|[^|\n]*\|\s*(?:\d+\s*\|\s*){2,}")
# Число с хвостовым знаком класса/адреса («строки 171+») = адрес, не якорь.
TRAIL = re.compile(r"\d[+*](?![0-9])|\d[−+–]\d")
# Строки с «число = величина» (таблица/подпись) = не счётчик датасета.
ASSIGN = re.compile(r"\d+\s*=\s*\d|(?<!\d)\d+\s*(?:байт|мс|ms\b|токен|%|MiB|МБ)")
# Кванторы размера (247 строк/247-стр.) = проза-объём, не счётчик датасета.
# Квантор объёма носителя (не счётчик датасета): «247 строк», «247-стр.».
# НЕ «строок recall»/«строк с» = счётчики сплита (mut5-контра).
SIZE_QUANT = re.compile(
    r"(?<!\d)\d+[- ]?(?:строк|стр\.?|lines)(?!\s*\w*-строк)\b"
    r"|(?<!\d)\d+[- ]?(?:байт|мс|ms\b|токен|PR)\b",
    re.I,
)
# Минимальный размер «якоря-числа» (счётчики датасета — трёхзначные и выше).
MIN_ANCHOR = 100
# ЭПОХИ ДАТАСЕТА (первичка = git-история golden-v1.jsonl, коммит-веха =
# промер счётчиков каждой версии; #331: «v1.13 = 296» = легальный снимок
# ЭПОХИ, «v1.13 = 297» = RED: адрес эпохи легитимирует только ЗНАЧЕНИЯ из
# таблицы эпох, granulariy-контра ревью e889cd7d).
EPOCHS = {
    "v1.0": (200, 146, 54, 378),
    "v1.1": (204, 150, 54, 382),
    "v1.2": (226, 162, 64, 395),
    "v1.3": (238, 169, 69, 402),
    "v1.4": (247, 173, 74, 416),
    "v1.5": (262, 182, 80, 425),
    "v1.6": (270, 187, 83, 430),
    "v1.7": (278, 189, 89, 434),
    "v1.8": (282, 191, 91, 439),
    "v1.9": (285, 192, 93, 442),
    "v1.10": (287, 194, 93, 448),
    "v1.11": (292, 198, 94, 452),
    "v1.12": (297, 200, 97, 454),
    "v1.13": (296, 208, 88, 462),
    # v1.14 (#299, HEAD) = артефакт: значения = reg/art; таблица не нужна.
    "v1.14": (299, 210, 89, 466),
}
# #333(3): поле-контра — имя ключа → позиция кортежа эпохи
# (N,RECALL,NEGATIVE,SPANS): legality = ПОЛЕ, не множество кортежа.
FIELDS = {"N": 0, "RECALL": 1, "NEGATIVE": 2, "SPANS": 3}
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
    # GOLD_BASE64_DENOM (урок #329 п.6: реестр обещал — проверяем): константа
    # base64-прогона = формула `GOLD_CHECKSUM_SPANS − GOLD_EMAIL_SPANS − 5`
    # (email decode-контра + 5 = комментарий каскада) И живая stdout-строка
    # теста `C0B64|covered|<cov>/<denom>` (denom = константа формулы).
    m = re.search(r"GOLD_CHECKSUM_SPANS\s*-\s*GOLD_EMAIL_SPANS\s*-\s*(\d+)", c0)
    check(m is not None, "PIN", "cascade0: base64-формула не найдена")
    if m is not None:
        formula = gs - em - int(m.group(1))
        check(reg.get("GOLD_BASE64_DENOM") == formula, "PIN",
              "registry: GOLD_BASE64_DENOM=%s ≠ формула %d (245−49−%s)"
              % (reg.get("GOLD_BASE64_DENOM"), formula, m.group(1)))
    import os
    if os.environ.get("ANCHOR_LIVE_C0") == "1":
        r = subprocess.run(
            ["cargo", "test", "-q", "-p", "guard-daemon", "--test", "cascade0_golden",
             "--", "--nocapture", "--test-threads=2"],
            capture_output=True, text=True, cwd=str(ROOT))
        for key, rx in (("GOLD_CHECKSUM_SPANS", r"C0GOLDEN\|covered\|\d+/(\d+)"),
                        ("GOLD_BASE64_DENOM", r"C0B64\|covered\|\d+/(\d+)")):
            m = re.search(rx, r.stdout)
            check(m is not None, "LIVE", "живой C0: строка %s не найдена (rc=%d)" % (key, r.returncode))
            if m is not None:
                check(reg.get(key) == int(m.group(1)), "PIN",
                      "живой промер: %s stdout=%s ≠ registry %s"
                      % (key, m.group(1), reg.get(key)))
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
    reg_tokens = set(str(v) for v in art.values())
    prev_tail = ""
    for idx, line in enumerate(lines, 1):
        # Слип переноса «…shasum -a» / «256…»: leading-число + prev-хвост «-a»
        # = аргумент утилиты, не счётчик (иначе NAMED не видит wrap-разрыв).
        if line.lstrip().startswith("256") and prev_tail.endswith("-a"):
            line = "shasum " + line
        prev_tail = line.rstrip()[-8:]
        # Латч ТОЛЬКО машиночитаемых маркеров (урок #329: prose-строки с
        # word «GOLDEN-REGISTRY» включали latch навсегда = 52 % файла вне
        # скана: README:190/313/407). START = строка «GOLDEN-REGISTRY: …»
        # (= строка данных), END = HTML-комментарий маркер.
        stripped = line.strip()
        # #331 гранулярность: реестровые КЛЮЧЕВЫЕ слова (N=/SPANS=/RECALL=/
        # NEGATIVE=/PIN_/STRUCT_/GOLD_/B2_SHA) в prose = ПРОВЕРЯЮТСЯ ВСЕГДА,
        # адрес эпохи легитимирует только значение-из-эпохи:
        #   «v1.13 = 296» = GREEN (296 ∈ кортеж v1.13); «v1.13 = 297» = RED.
        # Порядок: раньше ERA-легализации (иначе адрес = дыра ревьюера).
        for ep, tup in EPOCHS.items():
            # #333(1): эпора = ЦЕЛОЕ число версии: «v1.1» ≠ префикс «v1.12»
            # (FP-класс ревью: легальная orient1 «v1.12 эпоха: N = 297»
            # матчилась v1.1-паттерном = RED).
            epn = r"(?<![\d.])" + re.escape(ep) + r"(?![\d])"
            legal = set(str(x) for x in tup)
            # #333(3): поле-контра — имя ключа → ПОЗИЦИЯ в кортеже эпохи
            # (N,RECALL,NEGATIVE,SPANS), legality = поле, НЕ множество
            # («SPANS = 287 (v1.10)» = N-значение v1.10 в SPANS = RED).
            legalf = {k: str(tup[i]) for k, i in FIELDS.items()}
            cur = str(art["N"])
            # окно = «от адреса эпохи до привязки»: «тексты v1.12, … N = 296»
            # = НЕ про v1.12 (N=296 привязан к своему «= v1.13»); «N = 296 =
            # v1.13» / «v1.13: N=296» = про v1.13.
            # форма «v1.NN … N = 296» / «v1.NN … спанов 452» — ключевое
            # слово-якорь ОБЯЗАТЕЛЬНО (N=/RECALL=/SPANS=); пары «292/198+94»
            # = форма X/xx+yy. PR# в окне = адрес события, не значение.
            # (нет этой ветки для НЕизвестных v1.NN — см. UNKNOWN-EPOCH ниже)
            # обе ориентации: «v1.13 … N = 296» и «N = 296 (v1.13 #312)»;
            # цифра-в-окне = адрес PR# не значение (skip через lookahead).
            KW = (r"\b(N|RECALL|NEGATIVE|SPANS|RECALL_SPANS|NEGATIVE_SPANS)"
                  r" ?\*{0,2}= ?\*{0,2}(\d{2,4})")

            def legal_kw(kw, num, legalf=legalf, tup=tup, legal=legal, cur=cur):
                # поле-контра: RECALL_SPANS/NEGATIVE_SPANS = поле-суффикс
                # (SPANS ← позиция 3 только для голого «SPANS»)
                if kw in legalf:
                    return num == legalf[kw] or num == cur
                if kw == "RECALL_SPANS":
                    return num == str(tup[3]) or num == str(art["RECALL_SPANS"])
                if kw == "NEGATIVE_SPANS":
                    return num == str(tup[3]) or num == str(art["NEGATIVE_SPANS"])
                return num in legal and num != cur

            for mN in re.finditer(epn + r"((?:(?!#\d)[^\n]){0,36}?)" + KW, line):
                win, kw, num = mN.group(1), mN.group(2), mN.group(3)
                if re.search(r"= ?\*{0,2}" + epn + r"\b", win):
                    continue  # «= v1.13 … N = 296» = привязано
                if not legal_kw(kw, num):
                    fails += 1
                    fail("EPOCH", "README:%d «%s … %s = %s» ∉ поле/эпоха %s (первичка EPOCHS)"
                         % (idx, ep, kw, num, ep))
            for mN2 in re.finditer(KW + r"[^\n]{0,24}?" + epn + r"\b", line):
                kw, num = mN2.group(1), mN2.group(2)
                if not legal_kw(kw, num):
                    fails += 1
                    fail("EPOCH", "README:%d «%s = %s (%s …)» ∉ поле/эпоха %s (привязка ПОСЛЕ значения)"
                         % (idx, kw, num, ep, ep))
            # #333(2): PR#-адрес между эпохой и «=» = часть адреса события
            # («golden-v1.12 #160 = 297/200+97» строка-8 истории).
            for mS in re.finditer(
                    epn + r" ?(#\d+ )?(=|—|:) ?(\d{2,4})/(\d{2,4})\+(\d{2,4})", line):
                # #333(2) решётка E3/E4: ВСЕ ТРИ значения пары = поле-контра
                # (N, RECALL, NEGATIVE кортежа эпохи), не только первое.
                vals = dict(zip(("N", "RECALL", "NEGATIVE"),
                                mS.groups()[2:5], strict=True))
                for k, v in vals.items():
                    if v != str(tup[FIELDS[k]]):
                        fails += 1
                        fail("EPOCH", "README:%d «%s %s= …%s… %s=%s» ∉ поле/эпоха %s"
                             % (idx, ep, mS.group(1) or "", "…", k, v, ep))
        # #331 гранулярность ревью e889cd7d: «v1.13 … N = 296» = снимок ЭПОХИ
        # (легально iff 296 ∈ кортеж v1.13); «v1.13 … N = 297» = RED. Привязка
        # в обе стороны: «v1.NN … K = X» и «K = X (v1.NN …)». HEAD-эпоха
        # (v1.14) = артефакт; НЕизвестная v1.NN (будущая/мёртвая) со значением
        # = RED (снимок будущего = claim, первичка = git-веха при появлении).
        cur_ep = "v1.14"  # HEAD-эпоха = артефакт (EPOCHS["v1.14"] = текущий)
        # #333(1): «v1.1» = НЕ префикс «v1.12» (word-boundary слева: без
        # `(?<![\d.])` finditer «v1.1» матчил v1.10–13 = FP-класс ревью
        # (легальная «v1.12 эпоха: N = 297» = RED).
        for mU in re.finditer(r"(?<![\d.])v1\.(\d{1,2})(?![\d])", line):
            ep = "v1." + mU.group(1)
            tail = re.sub(r"^ ?#\d+", " ", line[mU.end():mU.end() + 24])
            tail = re.sub(r"\d?g\d{4}", " ", tail)
            head = line[max(0, mU.start() - 24):mU.start()]
            mh = re.search(r"(\d{3,4})[^\d=]{0,6}= ?$", head)
            if ep in EPOCHS:
                tup = EPOCHS[ep]
                legal = set(str(x) for x in tup)
                # #333(3) поле-контра: имя ключа → позиция кортежа эпохи
                # (N,RECALL,NEGATIVE,SPANS); «SPANS = 287 (v1.10)» =
                # N-значение v1.10 в SPANS = RED (legality = поле, не множество).
                if ep == cur_ep:
                    legal |= set(str(v) for v in art.values())

                def okf(kw, num, tup=tup, legal=legal, FIELDS=FIELDS):
                    if kw in FIELDS:
                        return num == str(tup[FIELDS[kw]])
                    return num in legal
                mt = re.search(
                    r"\b(N|RECALL|NEGATIVE|SPANS|RECALL_SPANS|NEGATIVE_SPANS)"
                    r"[^\d]{0,6}(\d{3,4})", tail)
                if mt and not okf(mt.group(1), mt.group(2)):
                    fails += 1
                    fail("EPOCH", "README:%d «%s … %s=%s» ∉ поле/эпоха (первичка EPOCHS)"
                         % (idx, ep, mt.group(1), mt.group(2)))
                if mh and mh.group(1) not in legal:
                    fails += 1
                    fail("EPOCH", "README:%d «%s %s (v1.%s …)» ∉ эпоха"
                         % (idx, mh.group(1), "=", ep))
            else:
                legal_cur = set(str(v) for v in art.values())
                kw = re.search(
                    r"(N|RECALL|NEGATIVE|SPANS|RECALL_SPANS|NEGATIVE_SPANS)"
                    r" ?\*{0,2}= ?\*{0,2}(\d{2,4})[^\d=]{0,10}$", head)
                mt = re.search(
                    r"[^A-Za-z](N|RECALL|SPANS) ?\*{0,2}= ?\*{0,2}(\d{2,4})", tail)
                for mm in ((kw, "head"), (mt, "tail")):
                    if mm[0] and mm[0].group(2) not in legal_cur:
                        fails += 1
                        fail("UNKNOWN-EPOCH",
                             "README:%d «%s (v1.%s …)» = эпора вне EPOCHS"
                             % (idx, mm[0].group(2), mU.group(1)))
                        break
        # PIN_/STRUCT_/GOLD_ = реестровые имена: вне registry-блока prose-форма
        # «PIN_CHUNKER_N = 250» (любой адрес) = проверятся против реестра.
        mp = re.search(r"PIN_CHUNKER_N ?= ?(\d{2,4})", line)
        if mp and not stripped.startswith("<!--") and "GOLDEN-REGISTRY:" not in line:
            if mp.group(1) != str(art["N"]):
                fails += 1
                fail("EPOCH", "README:%d PIN_CHUNKER_N = %s ≠ артефакт %d (pin-имя = всегда сверка)"
                     % (idx, mp.group(1), art["N"]))
        if stripped.startswith("<!--") and "GOLDEN-REGISTRY:END" in line:
            in_registry = False
            continue
        if stripped.startswith("<!--") and "GOLDEN-REGISTRY" in line:
            in_registry = True  # открыт блок, ждём строку данных
            continue
        if in_registry:
            # Внутри блока сканируем ТОЛЬКО строку данных (она сама =
            # якорь, проверена registry-сверкой выше); остальное = комментарий.
            if REGEX_ROW.match(stripped):
                continue
            if stripped.startswith("<!--") or stripped.startswith("-->"):
                if stripped.endswith("-->"):
                    in_registry = False
                continue
            continue
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        tm = TABLE_ROW.match(line.strip())
        if tm:
            # Таблица счётчиков = человекочитаемое отображение реестра:
            # ЛЮБОЕ число строки вне reg_tokens = дрейф (mut2-контра:
            # «298» в таблице = красный). Формат-строки |---| пропускаем.
            for tok in re.findall(r"\d+", line):
                if int(tok) < MIN_ANCHOR:
                    continue
                if tok not in reg_tokens:
                    fails += 1
                    fail("REGISTRY", "README:%d таблица-отображение: %s ∉ реестр %s"
                         % (idx, tok, sorted(reg_tokens, key=int)))
            continue
        # (wrap-перенос обрабатывается в caller: prev_tail «-a» + leading «256».)
        # Данные: квотированный фрагмент (ПДн-литералы) и длинные токены
        # ВНЕ квот (≥7 цифр: ИНН/ОГРН вперемешку с прозой); 4–6-значные
        # ГОЛЫЕ числа = счётчики/ссылки = сканируются (урок #329: DATA_DIGITS
        # ≥4 сжирал «293» — bare-число как раз и есть якорь-кандидат).
        scannable = HYPHEN_GROUP.sub(" ", QUOTED.sub(" ", line))
        # цифра, примыкающая к «%» = статистика (9862 в «97.9862 %»), не счётчик
        scannable = re.sub(r"(?<!\d)\d+(?=\s*%)", " ", scannable)
        scannable = re.sub(r"%\s*[.,(]\s*(\d+)", "% \1", scannable)  # «98 %, lo(356…»
        scannable = DATA_DIGITS.sub(" ", scannable)
        scannable = NAMED.sub(" ", scannable)
        scannable = TRAIL.sub(" ", scannable)
        scannable = SIZE_QUANT.sub(" ", scannable)
        era = (ERA.search(line) or ID_LOCAL.search(line)
               or TRAIL.search(line)
               # «30 строк с НЕвалидными» = счётчик сплита с квантором
               # «строк с…» (не объём носителя «247 строк») = НЕ era-маркер
               # (mut5-контра #329: SIZE_QUANT не легитимирует строку).
               )
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
                # адрес эпохи в СВОЕЙ строке (легальный «N =»-историк) +
                # статистическая форма «N=50»/«n=67» (подпись, пробел опц.)
                if not re.search(
                        r"v1\.\d|PR\s*#\d|историч|больше не|span-уровн"
                        # «статистическая n=» = малые n (<100 = не счётчик
                        # датасета); \b-граница НЕ работает после кириллицы
                        # (unicode word char) = lookbehind по ASCII.
                        r"|N=146\+|(?<![A-Za-z0-9_])[nN] ?= ?\d{1,2}\b",
                        line):
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
