# /// script
# requires-python = ">=3.12"
# dependencies = ["python-docx", "openpyxl", "python-pptx", "striprtf",
#   "pikepdf", "pdfplumber", "pypdf", "reportlab"]
# ///
"""fasad-file: маска ПДн В ФАЙЛЕ через живой демон (#297, этап 1 R&D-полка).

Контур (R&D-первичка f620296e, артефакты /tmp/fasad-files):
  файл → извлечение (run/cell-карта) → POST /v1/analyze → POST /v1/anonymize
  (vault-сессия X-Session-ID) → байтовый slice по сегментам карты → masked-файл
  + ledger.json; возврат = /v1/deanonymize (штатный ход демона).

Координатный мост = БАЙТЫ (vault-контра: analyze/Anonymize отдаёт
byte_start/byte_end, канон #56; кириллица = 2 байта/символ).
Glue-контра: run'ы контейнера склеиваются БЕЗ разделителя (PII на стыке
обязана читаться целиком, pipeline.rs GLUE_MAX_GAP=8 не принимает \\n),
граница контейнеров = "\\n" (склейка через абзац запрещена контрой → FN,
промер FINAL-2para).
Fail-closed: файл не разобрался (PackageNotFoundError и прочее) = отказ rc 2,
НЕ тихая маска; пустые PII = no-op, файл не трогается.

Форматы этапа 1: docx (параграфы/таблицы(+col-major pass 2)/headers/footers;
DOCX-ограничения: (1)run'ы без текста (drawings) карта не видит — маска их
не касается, (2) textbox (w:txbxContent) = вне python-docx paragraphs =
НЕ маскируется (лимитация этапа 1, R&D tbox-контур = lxml, в полку не
вошёл), (3) pptx-таблицы = не обходятся, (4) склейка >1 MiB = отказ
(FASAD_MAX_BODY_BYTES канон, config.rs:34; чанкование overlap>=GLUE =
этап 2, НЕ здесь), xlsx (row-major pass 1 + col-major pass 2 по чистым
ячейкам — row-major = FN-класс первички f620296e), pptx (текстовые фреймы),
txt/md/csv (байтовые срезы), rtf (striprtf + rfind-контур).

Vault-режимы формы токена (#300 NIT-3, первичка vault.rs:883/1010 + live):
  mode 3 stateless (дефолт): [[F0#<nonce>]] (суррогат [[S0#…]]),
  mode 2 session (X-Session-ID): [КЛАСС_№_<nonce>], человекочитаемая метка.
Фильтр «уже замазано» (_is_masked) = режим-агностик регуляркой обеих форм.

PDF (этап 2, #302; R&D #294-первички + 7 первичек живого контура):
извлечение = pdfplumber постранично (страница = естественный чанк;
>1 MiB = _guard_body fail-closed = лимитация-док, чанкование = этап 3),
мост byte-спан → char-index = позиция frag в concat(chars) (проверка
согласованности; расхождение = fail-closed; multi-occurrence = все
вхождения, flag orig_all). Маска ДВУХслойная: (1) pikepdf stream-surgery
= побайтовый PAD (пробелы той же длины) в content stream = настоящая
redaction (побайтовый скан = PII 0); pypdf overlay НЕ redaction (текст
под rect читается = fail-open, R&D-промер) = (2) визуал: --mode black =
чёрный rect; --mode placeholder = белый rect + рамка. Контур токена
(первички #302): токен в content-поток НЕ пишется (78+ Б > PII-игла =
побайтовый контракт невыполним; двойные вхождения ph = иголки жрали
друг друга), overlay-тексты = яд restore (класс-метка «[phone]» = 7 Б =
резала токен-иголки; чистка токенов из overlay = ломает PDF-числа),
визуал = ГРАФИКА БЕЗ ТЕКСТОВ. Restore = pypdf-контра roundtrip.py
(pikepdf-открытие НЕ видит pypdf-writer-потоки; pikepdf.save =
FlateDecode = offsets маски = аудит-поле, не иголка): иголки = ctxs
(per-hit анкоры: 24 Б не-пробельного хвоста + разделители до PII,
пишет МАСКА) + ядро = ПЕРВЫЕ len(orig) пробелов после иголки (surgery-
контрака = PII-блок = len пробелов на хит; слияние pad-ранов соседних
PII = «Kontakt: <12sp>, INN <11sp>.» = ядро = первые len = промер-яд
tf-snils: return-эвристика от конца = [6..17)+[13..17) = пересечение =
двойная вставка = snils 3×); multi-occurrence = 1 запись на (page,
frag) со всеми ctxs (запись-на-span = дубликаты chosen = overlap-die,
кросс-страничный повтор = амбигюити «page=»); правки копятся в raws,
запись в конце (первичка: последовательная запись = возврат PII-0
съедал анкор PII-1).
DEANONYIZE-ДЕМОНОМ pdf НЕ меряем: токена в text-layer нет = ledger-контур
(как rtf). Black = ledger БЕЗ orig/ph = необратимость = restore-отказ
(честный rc, ДО ph_map). Зашифрованный/битый = PdfminerException/
PasswordError = rc 2 (тот же fail-closed, что PackageNotFoundError docx).
Ограничения этапа-2: PII на стыке show-операторов (куски Tj) = fail-closed
«нестандартная кодировка потока» (куски-слова = риск ложных pad =
сознательно); PII на границе Tj-скобки = fail-closed «pad-участки
перекрываются» (класс reportlab-базовый = WinAnsi-подмена кириллицы +
дробление Tj по перемычкам шрифтов: phone [302..313) и inn [302..312) =
shared-контекст «) Tj /F1 11 Tf 13.2 TL ( » = перекрывающиеся ядра =
обратимость НЕ доказана = контракт #305 п.1в; маскировка = полная,
leak-scan чист = PII 0, restore = честный rc 2, промер cyr-wa).
КИРИЛЛИЦА В PDF = ПРОМЕРЕНА #305 (два движка, свои PDF): (1) Type0
Identity-H (fpdf2/reportlab+TTF) = 2-байтные CID-индексы: PII-цифры =
ASCII-байты 1-байтных кодов = побайтовый needle = КОНТУР РАБОТАЕТ
(roundtrip cyr-rl = полный возврат); (2) WinAnsi cp1251-однобайтные =
кириллица НЕ в WinAnsi = подмена = needle не нужен; (3) Word-экспорт =
Type0 CIDToGIDMap Identity + ToUnicode = та же 1-байтная форма =
контур; (4) Hex-строки <CIPF..> = reportlab/fpdf2/hetvfdf НЕ эмитируют
(промер потоков = octal-escape в () = не Hex) = путь не встретился,
побайтовый needle не канон = не чиним (этап 3 по факту появления).
скан-PDF (растр) = OCR = этап 3, НЕ здесь.

Известные FN-классы ДЕТЕКТОРА (не обёртки, чин = каскад-0 issue, не здесь):
1) паспорт в соседстве «ИНН <10 цифр>» = inn-доминанта гасит паспортную
гипотезу (зуб реестра c0_inn_key_dominates_passport, cascade0.rs:337);
промер обёртки: ни row-, ни col-major склейка его не достают (до и после
маски) = leak-scan осознанно исключает такой кейс, тест-полка документирует.
2) ПАСПОРТ-ФОРМЫ БЕЗ КЛЮЧА = контракт канона #212, НЕ баг (промер #305
живым демоном 18804, таблица форм ниже). Ключевые слова-соседи =
«паспорт/Паспорт/документ НЕ канон: «документ 45 10 123456» = 0 span;
канон = «Паспорт <формы>» / «паспорт: <формы>» = ключ ДО номера,
регистр первой буквы канонен):
  «Паспорт 45 10 123456 выдан 01.01.2020» = span [8..20) hit
  «паспорт: 4510 123456» = span [9..20) hit
  «Паспорт 4510123456 выдан» = span [8..18) hit
  «паспорт 45 10 123456» = hit (8..20)
  «45 10 123456» (без ключа) = 0 span = контрактное молчание g0223-класса
  «4510123456» / «4510 123456» / «серия 45 номер 10 123456» / «45-10-123456»
    / «45/10/123456» = 0 span = вне канона (#212: ведущий ключ обязателен)
  «45 10 123456 ИНН 7707083893» = inn-10 hit, паспорт = 0 (класс 1)
  «ИНН 7707083893 и 45 10 123456» = inn-10 hit, паспорт = 0 (класс 1)
Обёртка = мёртвая зона детектора (file-контур = прозрачен: что демон не
увидел, то не замажет = leak-scan это же меряет = вторичный контракт).
3) person_name = 0 hits на cascade-0-only (промер #305: ФИО в txt/pdf =
ни span; ФИО = каскады 1–2, веса). file-контур × каскады 1/2 = CI-полка
(ort-build: смонтированный фасад-стенд; локально debug-бинарь =
cascade-0-only, ort-inference вне debug-сборки = AGENTS п.3: build = CI).

Запуск (uv single-file, AGENTS §6 gutter — продукт НЕ Rust-обвязка):
  uv run scripts/fasad-file.py mask  ФАЙЛ СЕССИЯ --out ФАЙЛ [--mode black|placeholder]
  uv run scripts/fasad-file.py restore ФАЙЛ СЕССИЯ --ledger ФАЙЛ --out ФАЙЛ
  (--url http://127.0.0.1:PORT, дефолт 8765)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

BRK = "\n"
GLUE = ""
DEFAULT_URL = "http://127.0.0.1:8765"


def die(msg: str, code: int = 2) -> None:
    """Fail-closed: причина в stderr, rc!=0, тихой маски нет (#185-контра)."""
    print(f"fasad-file: ОШИБКА: {msg}", file=sys.stderr)
    sys.exit(code)


def _json_size(body: dict) -> int:
    """Размер JSON-тела запроса (носитель меры _guard_body; ensure_ascii=
    False = UTF-8-байты, канон json.dumps без экранирования кириллицы)."""
    return len(json.dumps(body, ensure_ascii=False).encode("utf-8"))


def _guard_body(body: dict) -> None:
    """Fail-closed по body-лимиту демона: JSON-запрос (текст + спаны) больше
    лимита = отказ ДО обращения, симметрично 413 «body_too_large» демона
    (первичка http.rs:9 = DefaultBodyLimit меряет ТЕЛО запроса, не только
    текст; 413 = сетевой симметричный исход, наш — локальный честный текст
    раньше). Канон = config.rs:34 (1 MiB); запас 64 KiB покрывает
    JSON-обвязку спанов (промер #297: span-объект ≈ 150–200 Б на 10–15 Б
    значения = худший случай ×2 запаса). Чанкование overlap>=GLUE =
    этап 2 (README-лимитация), не здесь."""
    n = _json_size(body)
    if n > MAX_BODY_BYTES:
        die(
            f"тело запроса {n} Б > лимита демона {MAX_BODY_BYTES} Б "
            "(FASAD_MAX_BODY_BYTES, config.rs:34): чанкование = этап 2, "
            "файл НЕ маскируется (fail-closed)"
        )


def api(url: str, path: str, body: dict, sess: str | None = None) -> dict:
    _guard_body(body)
    h = {"Content-Type": "application/json"}
    if sess:
        h["X-Session-ID"] = sess
    req = urllib.request.Request(
        url + path, data=json.dumps(body).encode("utf-8"), headers=h, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        die(f"{path} HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        die(f"{path}: демон недоступен ({e.reason})")
    return {}  # die не возвращается; для mypy-чистоты


# ── извлечение: карта сегментов ─────────────────────────────────────────────
# Сегмент = (key, text, brk): key = адрес места записи (формат-специфичен),
# brk = разделитель ПОСЛЕ сегмента в склейке (GLUE внутри контейнера,
# BRK между контейнерами).

def _emit_runs(runs, keyfn, out):
    live = [(ri, r) for ri, r in enumerate(runs) if r.text]
    for i, (ri, r) in enumerate(live):
        out.append((keyfn(ri), r.text, GLUE if i < len(live) - 1 else BRK))


def extract_docx(d):
    out = []
    for pi, p in enumerate(d.paragraphs):
        _emit_runs(list(p.runs), lambda ri, pi=pi: ("body", pi, ri), out)
    for ti, t in enumerate(d.tables):
        for ci, row in enumerate(t.rows):
            for bi, cell in enumerate(row.cells):
                for pi2, p in enumerate(cell.paragraphs):
                    _emit_runs(
                        list(p.runs),
                        lambda ri, ti=ti, ci=ci, bi=bi, pi2=pi2: ("tbl", ti, ci, bi, pi2, ri),
                        out,
                    )
    for si, sec in enumerate(d.sections):
        for kind, hf in (("header", sec.header), ("footer", sec.footer)):
            for pi2, p in enumerate(hf.paragraphs):
                _emit_runs(
                    list(p.runs),
                    lambda ri, kind=kind, si=si, pi2=pi2: (kind, si, pi2, ri),
                    out,
                )
    return out


def set_docx(d, key, value):
    if key[0] == "body":
        d.paragraphs[key[1]].runs[key[2]].text = value
    elif key[0] == "tbl":
        d.tables[key[1]].rows[key[2]].cells[key[3]].paragraphs[key[4]].runs[key[5]].text = value
    elif key[0] == "tblcol":
        d.tables[key[1]].rows[key[2]].cells[key[3]].paragraphs[key[4]].runs[key[5]].text = value
    elif key[0] in ("header", "footer"):
        sec = d.sections[key[1]]
        hf = sec.header if key[0] == "header" else sec.footer
        hf.paragraphs[key[2]].runs[key[3]].text = value
    else:
        die(f"docx: неизвестный ключ сегмента {key}")


def extract_xlsx(wb, col_major: bool):
    """Порядок обхода = ПЕРВИЧКА f620296e: row-major = паспорт-FN (ключ
    «Паспорт/…/номер» в столбце не сосед), pass-2 col-major чинит контекст."""
    out = []
    for ws in wb.worksheets:
        rows = list(ws.iter_rows())
        if col_major:
            cols = ((c for c in col if c is not None) for col in zip(*rows, strict=False))
            iterator = ((c for c in column) for column in cols)
        else:
            iterator = iter(rows)
        for row in iterator:
            for c in row:
                if isinstance(c.value, str) and c.value.strip():
                    out.append(((ws.title, c.coordinate), c.value, BRK))
    return out


def extract_pptx(prs):
    out = []
    for si, sl in enumerate(prs.slides):
        for shi, sh in enumerate(sl.shapes):
            if not sh.has_text_frame:
                continue
            for pi, p in enumerate(sh.text_frame.paragraphs):
                _emit_runs(
                    list(p.runs),
                    lambda ri, si=si, shi=shi, pi=pi: ("slide", si, shi, pi, ri),
                    out,
                )
    return out


def set_pptx(prs, key, value):
    prs.slides[key[1]].shapes[key[2]].text_frame.paragraphs[key[3]].runs[key[4]].text = value


# Канон body-лимита демона (config.rs:34 DEFAULT_MAX_BODY_BYTES).
MAX_BODY_BYTES = 1_048_576

# Формы vault-токенов (#300 NIT-3, первичка vault.rs:883/1010 + live-промер):
#   mode 3 (stateless, дефолт): [[F0#<nonce>]] / surrogate [[S0#<nonce>]]
#   mode 2 (session):            [КЛАСС_№_<nonce>] (ASCII-класс)
MASK_TOKEN_RE = re.compile(r"\[\[[FPS]0#|\[[A-Z]+_\d+_")


def build_text(segs):
    """Склейка + байтовая карта сегментов [(key, b0, b1, text)].

    Fail-closed по body-лимиту демона (config.rs:34 = 1 MiB): склейка больше =
    отказ с указанием размера, НЕ тихий обрез/чанкование (чанкование
    overlap>=GLUE = этап 2, не здесь)."""
    text = ""
    map_ = []
    for key, t, brk in segs:
        b0 = len(text.encode("utf-8"))
        text += t + brk
        map_.append((key, b0, len(text.encode("utf-8")) - len(brk.encode("utf-8")), t))
    if len(text.encode("utf-8")) > MAX_BODY_BYTES:
        die(
            f"склейка {len(text.encode('utf-8'))} Б > лимита демона "
            f"{MAX_BODY_BYTES} Б (FASAD_MAX_BODY_BYTES): чанкование = этап 2, "
            "файл НЕ маскируется (fail-closed)"
        )
    return text, map_


def slice_map(text, map_, items):
    """Run-level байтовый slice (первичка runmask_lib): в первый покрытый
    сегмент встаёт replacement, в остальные — пусто; сортировка по -b0."""
    texts = [t for _, _, _, t in map_]
    for it in sorted(items, key=lambda x: -x["byte_start"]):
        covered = [
            (i, e0, e1) for i, (_, e0, e1, _) in enumerate(map_)
            if e0 < it["byte_end"] and it["byte_start"] < e1
        ]
        for j, (i, e0, e1) in enumerate(covered):
            cur = texts[i].encode("utf-8")
            o0 = max(it["byte_start"], e0) - e0
            o1 = min(it["byte_end"], e1) - e0
            rep = it["replacement"].encode("utf-8") if j == 0 else b""
            texts[i] = (cur[:o0] + rep + cur[o1:]).decode("utf-8", "replace")
    return texts


def mask_text_like(src, dst, sess, url):
    """txt/md/csv: весь файл = один контейнер; маска = байтовый срез текста;
    побайтовый roundtrip (срез по байтам UTF-8, decode-replace нет на путях
    границ: спаны демона каноничны по UTF-8, разрез символа невозможен)."""
    raw = open(src, "rb").read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        die(f"{src}: не UTF-8 (этап 1 = txt/md/csv UTF-8;кодировка не поддерживается)")
    spans = api(url, "/v1/analyze", {"text": text})
    if not spans:
        print("LEAKS|NONE (анализ пуст) | no-op")
        sys.exit(0)
    anon = api(
        url, "/v1/anonymize",
        {"text": text, "spans": [
            {"entity_type": s["entity_type"], "byte_start": s["byte_start"], "byte_end": s["byte_end"]}
            for s in spans]},
        sess=sess,
    )
    out = raw
    ledger = []
    for it in sorted(anon["items"], key=lambda x: -x["byte_start"]):
        b0, b1 = it["byte_start"], it["byte_end"]
        orig = raw[b0:b1].decode("utf-8", "replace")
        out = out[:b0] + it["replacement"].encode("utf-8") + out[b1:]
        ledger.append(
            {"class": it["entity_type"], "orig": orig, "ph": it["replacement"],
             "b0": b0, "b1": b1, "segs": 1}
        )
    open(dst, "wb").write(out)
    return len(ledger), ledger


# ── команды ─────────────────────────────────────────────────────────────────

def load_by_ext(src):
    ext = src.rsplit(".", 1)[-1].lower() if "." in src else ""
    if ext == "pdf":
        # Открываем pdfplumber-СРАЗУ (первичка #302: зашифрованный =
        # PasswordError, битый = PdfminerException = fail-closed; тот же
        # try/except, что PackageNotFoundError docx).
        try:
            import pdfplumber
            return "pdf", pdfplumber.open(src)
        except Exception as e:
            die(f"{src}: не разобрался ({type(e).__name__}: {e})")
    try:
        if ext == "docx":
            from docx import Document
            return "docx", Document(src)
        if ext == "xlsx":
            import openpyxl
            return "xlsx", openpyxl.load_workbook(src)
        if ext == "pptx":
            from pptx import Presentation
            return "pptx", Presentation(src)
        if ext == "rtf":
            return "rtf", open(src, encoding="utf-8").read()
        if ext in ("txt", "md", "csv"):
            return ext, None
    except Exception as e:
        # Fail-closed первички f620296e: PackageNotFoundError (битый/шифрованный
        # docx) = ОТКАЗ, не тихая маска.
        die(f"{src}: не разобрался ({type(e).__name__}: {e})")
    die(f"{src}: формат не поддержан (docx/xlsx/pptx/rtf/pdf/txt/md/csv)")


def cmd_mask(args):
    fmt, obj = load_by_ext(args.file)
    sess, url = args.session, args.url
    if fmt in ("txt", "md", "csv"):
        n, ledger = mask_text_like(args.file, args.out, sess, url)
    elif fmt == "rtf":
        n, ledger = _mask_rtf(args, obj)
    elif fmt == "pdf":
        obj.close()  # pdfplumber-ручка load-проверки; _mask_pdf = путь
        n, ledger = _mask_pdf(args, args.file)
    elif fmt == "docx":
        segs = extract_docx(obj)
        n, ledger = _mask_runs(
            obj, segs, sess, url,
            lambda k, v: set_docx(obj, k, v),
            args.out,
            colmajor_segs=_extract_docx_tables_colmajor(obj),
        )
    elif fmt == "pptx":
        segs = extract_pptx(obj)
        n, ledger = _mask_runs(obj, segs, sess, url, lambda k, v: set_pptx(obj, k, v), args.out)
    else:
        n, ledger = _mask_xlsx(obj, sess, url, args.out)
    if args.mode == "black":
        # Disk-irreversibility (#302): orig/ph из ledger-ФАЙЛА изымаются
        # = PII не сохраняется нигде на диске = restore-ход физически
        # невозможен (контракт black). Оперативный ledger маски = полный
        # (surgery-контракту нужен orig); диск = чистый (зуб: побайтовый
        # скан ledger-файла = PII 0).
        ledger = [{k: v for k, v in e.items() if k not in ("orig", "ph")}
                  for e in ledger]
    json.dump(ledger, open(args.ledger, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"MASKED|{fmt}|{n}|{args.out}|{args.ledger}")


def _mask_pass(segs, sess, url, setter):
    """Один проход: analyze+anonymize по склейке карты, запись по карте.
    Возвращает (число применённых items, ledger-строки)."""
    text, map_ = build_text(segs)
    spans = api(url, "/v1/analyze", {"text": text})
    anon = api(
        url, "/v1/anonymize",
        {"text": text, "spans": [
            {"entity_type": s["entity_type"], "byte_start": s["byte_start"], "byte_end": s["byte_end"]}
            for s in spans]},
        sess=sess,
    )
    items = anon["items"]
    texts = slice_map(text, map_, items)
    n = 0
    for i, (key, _, _, _) in enumerate(map_):
        if texts[i] != map_[i][3]:
            setter(key, texts[i])
            n += 1
    ledger = []
    tb = text.encode("utf-8")
    for it in items:
        covered = [m for m in map_ if m[1] < it["byte_end"] and it["byte_start"] < m[2]]
        # #300 NIT-1: orig = BYTE-slice (MaskItem = byte-координаты,
        # char-end у них ∄; образец mask_text_like). До кириллических
        # классов (address/name, каскад 1–2) char==byte для ASCII-цифр
        # (промер 4/4), с кириллицей char-slice = порча orig.
        orig = tb[it["byte_start"]:it["byte_end"]].decode("utf-8", "replace")
        ledger.append(
            {"class": it["entity_type"], "orig": orig,
             "ph": it["replacement"], "segs": len(covered)}
        )
    return len(items), ledger


def _mask_runs(obj, segs, sess, url, setter, out, colmajor_segs=None):
    # pass 1 = естественный порядок; pass 2 = col-major ТОЛЬКО таблицы
    # (FN-контра f620296e, xlsx-класс перенесён на docx: заголовок колонки
    # «Паспорт» = ключ-контекст номера ПОД ним; в row-major сетке ключ не
    # сосед = FN). Повторный analyze по замазанному тексту безопасен:
    # vault-токены цифр не содержат (промер: col-major-склейка masked-
    # таблицы даёт []), leak-scan это ловит.
    n1, ledger = _mask_pass(segs, sess, url, setter)
    n2 = 0
    if colmajor_segs:
        n2, led2 = _mask_pass(colmajor_segs, sess, url, setter)
        ledger += led2
    obj.save(out)
    return n1 + n2, ledger


def _extract_docx_tables_colmajor(d):
    """Таблицы, обход по ПОЛСЫМ; ключ = ("tblcol", ti, ri, ci, pi2, ri_)
    (та же запись, что row-major: заголовок-ключ колонки даёт контекст)."""
    out = []
    for ti, t in enumerate(d.tables):
        ncols = max((len(r.cells) for r in t.rows), default=0)
        for ci in range(ncols):
            for ri, row in enumerate(t.rows):
                if ci >= len(row.cells):
                    continue
                for pi2, p in enumerate(row.cells[ci].paragraphs):
                    _emit_runs(
                        list(p.runs),
                        lambda ri_, ti=ti, ri=ri, ci=ci, pi2=pi2: ("tblcol", ti, ri, ci, pi2, ri_),
                        out,
                    )
    return out


def _is_masked(t: str) -> bool:
    """#300 NIT-3: фильтр «ячейка уже замазана» = режим-агностик (таблица
    форм vault в шапке файла: mode 3 = `[[F0#<nonce>]]`, mode 2 =
    `[КЛАСС_№_nonce]` vault.rs:883/1010, live-первичка #300; surrogate
    mode 2 = `[[S0#…]]` = вложенная скобка, `[S0#` перекрывает).
    Прежний фильтр `[["F` = привязка к mode 3 = в mode 2 no-op = pass-2
    пересканировал маскированные ячейки."""
    return bool(MASK_TOKEN_RE.search(t))


def _mask_xlsx(wb, sess, url, out):
    # Pass 1 = row-major. Pass 2 = col-major: первичка f620296e — row-major
    # сетка гасит паспорт под заголовком столбца (ключ не сосед); col-major
    # = ключ-контекст. ВНИМАНИЕ (ограничение этапа 1, leak-scan-первичка):
    # на ВТОРОМ проходе в уже замазанном тексте инн/snils-окно рядом с
    # vault-токеном детектор ГАСИТ свой хит (токен съедает word-boundary
    # контекста) = col-major pass 2 не должен повторно маскировать то, что
    # уже закрыто: маскируем ТОЛЬКО ячейки без replacement-токенов
    # (фильтр по чистым ячейкам).
    total = 0
    ledger = []
    segs = extract_xlsx(wb, col_major=False)
    n, led = _mask_pass(segs, sess, url, lambda k, v: _set_xlsx(wb, k, v))
    total += n
    ledger += led
    segs2 = [(k, t, b) for (k, t, b) in extract_xlsx(wb, col_major=True)
             if not _is_masked(t)]
    if segs2:
        n2, led2 = _mask_pass(segs2, sess, url, lambda k, v: _set_xlsx(wb, k, v))
        ledger += led2
        total += n2
    wb.save(out)
    return total, ledger


def _set_xlsx(wb, key, value):
    sheet, coord = key
    wb[sheet][coord].value = value


def _mask_rtf(args, src_text):
    from striprtf.striprtf import rtf_to_text
    plain = rtf_to_text(src_text)
    spans = api(args.url, "/v1/analyze", {"text": plain})
    anon = api(
        args.url, "/v1/anonymize",
        {"text": plain, "spans": [
            {"entity_type": s["entity_type"], "byte_start": s["byte_start"], "byte_end": s["byte_end"]}
            for s in spans]},
        sess=args.session,
    )
    out = src_text.encode("utf-8")
    plain_b = plain.encode("utf-8")
    ledger = []
    for it in sorted(anon["items"], key=lambda x: -x["byte_start"]):
        # #300 NIT-2: ЕДИНАЯ координатная система = байты (MaskItem =
        # byte-координаты; прежний char-slice plain[start:end] + byte rfind
        # отменялись только на ASCII; кириллица = порча). orig/pos = byte-
        # арифметика, src = utf-8-байты (RTF-носитель ASCII-скелет +
        # кирилличные run'ы = поиск по байтам корректен).
        b0, b1 = it["byte_start"], it["byte_end"]
        orig = plain_b[b0:b1]
        pos = out.rfind(orig)
        if pos < 0:
            # rfind-контра f620296e: оригинал не найден в RTF-тексте =
            # расхождение извлечения = fail-closed, не «проглотили».
            die(f"rtf: оригинал {orig!r} не найден в исходнике (карта разошлась)")
        out = out[:pos] + it["replacement"].encode("utf-8") + out[pos + len(orig):]
        ledger.append(
            {"class": it["entity_type"], "orig": orig.decode("utf-8", "replace"),
             "ph": it["replacement"], "segs": 1, "mode": "rfind"}
        )
    open(args.out, "wb").write(out)
    return len(ledger), ledger


def _iter_texts(fmt, obj):
    """Все текстовые узлы для restore-обхода (docx/pptx/run'ы, xlsx/cells)."""
    if fmt == "docx":
        for pi, p in enumerate(obj.paragraphs):
            for ri, r in enumerate(p.runs):
                yield ("body", pi, ri), r
        for ti, t in enumerate(obj.tables):
            for ci, row in enumerate(t.rows):
                for bi, cell in enumerate(row.cells):
                    for pi2, p in enumerate(cell.paragraphs):
                        for ri, r in enumerate(p.runs):
                            yield ("tbl", ti, ci, bi, pi2, ri), r
        for si, sec in enumerate(obj.sections):
            for kind, hf in (("header", sec.header), ("footer", sec.footer)):
                for pi2, p in enumerate(hf.paragraphs):
                    for ri, r in enumerate(p.runs):
                        yield (kind, si, pi2, ri), r
    elif fmt == "pptx":
        for si, sl in enumerate(obj.slides):
            for shi, sh in enumerate(sl.shapes):
                if sh.has_text_frame:
                    for pi, p in enumerate(sh.text_frame.paragraphs):
                        for ri, r in enumerate(p.runs):
                            yield ("slide", si, shi, pi, ri), r


def _pdf_pad_len_unused(frag: str, raw: bytes, repl: bytes):
    """Сколько пробелов оставить рядом с токеном, чтобы суммарная длина
    замены равной длине PII (побайтовая контра R&D: pad = len(needle) -
    len(tok), tok длиннее = 0 и поток РАСТЁТ = restore урезает пробелы
    до исходной длины). Возвращает (needle, tail, pad); whole/piece
    порядок = канон _mask_pdf (иначе длины расходятся = restore fail)."""
    needle = frag.encode("utf-8")
    if needle in raw:
        return needle, needle, max(0, len(needle) - len(repl))
    pieces = [w.encode("utf-8") for w in frag.split() if w]
    tail = pieces[-1]
    return needle, tail, max(0, len(tail) - len(repl))


def _pdf_page_boxes(src, sess, url):
    """Мост #302: постранично (страница = чанк ≤1 MiB) extract_text →
    analyze/anonymize → byte-спан → char-index → bbox.

    Контра моста: concat(chars["text"]) обязан побайтово совпасть с
    extract_text (проверка byte-префиксов); расхождение = fail-closed
    «карта разошлась» (R&D NO-MAP-маркер усилен: тихого пропуска нет).
    Возвращает [(page, frag, repl, x0, y0, x1, y1)] + ledger-строки."""
    import pdfplumber
    boxes = []
    ledger = []
    with pdfplumber.open(src) as pdf:
        for pi, page in enumerate(pdf.pages):
            text = page.extract_text() or ""
            if not text.strip():
                continue
            _guard_body({"text": text, "spans": [{}] * 32})
            spans = api(url, "/v1/analyze", {"text": text})
            if not spans:
                continue
            anon = api(
                url, "/v1/anonymize",
                {"text": text, "spans": [
                    {"entity_type": s["entity_type"],
                     "byte_start": s["byte_start"], "byte_end": s["byte_end"]}
                    for s in spans]},
                sess=sess,
            )
            chars = page.chars
            concat = "".join(c["text"] for c in chars)
            tb = text.encode("utf-8")
            # char-index мост = R&D-первичка #294: позиция frag ищется в
            # concat(chars) (pdfplumber layout вставляет/убирает пробелы
            # относительно extract_text = live-промер #302: byte-позиция
            # текста ≠ индекс chars). Дискриминатор = единственный hit
            # (несколько = карта неоднозначна = fail-closed, НЕ первый).
            for it in anon["items"]:
                b0, b1 = it["byte_start"], it["byte_end"]
                frag = tb[b0:b1].decode("utf-8", "replace")
                positions = []
                c0 = concat.find(frag)
                while c0 >= 0:
                    positions.append(c0)
                    c0 = concat.find(frag, c0 + 1)
                if not positions:
                    die(f"{src}: страница {pi}: фрагмент {frag!r} не найден "
                        "в char-потоке страницы = карта разошлась, файл НЕ "
                        "маскируется (fail-closed, R&D NO-MAP усилен)")
                ph = page.height
                # ЗАПИСЬ НА (page, frag): ключ в PDF-слое = страница +
                #needle (multi-occurrence = список ctxs в ОДНОЙ записи =
                # restore ищет все анкоры; промер-яд tf-snils: запись-
                # на-span = 2 записи на 1 needle = дубликаты chosen =
                # overlap-die; кросс-страничные повторы = амбигюити
                # «page=» = 1 запись на страницу решают его честно).
                bboxes = []
                for _oi, c0 in enumerate(positions):
                    c1 = c0 + len(frag)
                    seg = chars[c0:c1]
                    if not seg:
                        die(f"{src}: страница {pi}: пустой char-сегмент у {frag!r}")
                    boxes.append((pi, frag, it["replacement"],
                                  seg[0]["x0"], min(ph - c["bottom"] for c in seg),
                                  seg[-1]["x1"], max(ph - c["top"] for c in seg)))
                    bboxes.append([round(seg[0]["x0"], 1),
                                   round(min(ph - c["bottom"] for c in seg), 1),
                                   round(seg[-1]["x1"], 1),
                                   round(max(ph - c["top"] for c in seg), 1)])
                if any(e["page"] == pi and e["orig"] == frag for e in ledger):
                    continue  # ключ (page, frag) = 1 запись (мульти-occ
                # позиции = stream-хиты surgery, не char-позиции)
                ledger.append(
                    {"class": it["entity_type"], "orig": frag,
                     "ph": it["replacement"], "page": pi, "segs": len(positions),
                     "bbox": bboxes[0], "bboxes": bboxes}
                )
    return boxes, ledger


def _mask_pdf(args, src):
    """Двухслойная маска (R&D #294): pikepdf stream-surgery (байты PII →
    пробелы той же длины = побайтовый скан чист) + overlay (black rect /
    белый rect + рамка + token-текст). Зашифрованный PDF = PasswordError →
    fail-closed в load_by_ext."""
    import io as _io

    import pikepdf
    boxes, ledger = _pdf_page_boxes(src, args.session, args.url)
    if not boxes:
        print("LEAKS|NONE (анализ пуст) | no-op")
        sys.exit(0)
    if args.mode == "black":
        # Необратимость = контра black: PII не сохраняется НИГДЕ (ledger
        # без orig = нет источника возврата; restore-ход pdf = ledger-
        # подмена = физически невозможен, это и есть контракт black).
        for e in ledger:
            e.pop("ph", None)
            # orig СОХРАНЯЕТСЯ в оперативке маски (= источник surgery-
            # сопоставления фактов и pad-контракта «участок = len(orig)»);
            # black-ledger на диске = ledger БЕЗ orig/ph (запись ниже);
            # irreversibility = disk-факт: restore-отказ = die ДО
            # ph_map-машинерии (контракт black).
    # 1. stream-surgery.
    pdf = pikepdf.open(src)
    # surgery-план = (page, needle, replacement, whole): whole = единая
    # подстрока (целый frag) или токен-вставка (placeholder, tail→токен).
    plan = []
    for pi, frag, repl, *_ in boxes:
        needle = frag.encode("utf-8")
        if args.mode == "placeholder":
            tail = frag.split()[-1].encode("utf-8")
            tok = repl.encode("utf-8")
            # Канон #302 (первички 1–4): (1) «токен+пробелы = needle»
            # невыполнима (токен 78+ Б > PII 10–14 Б); (2) токен В
            # content-потоке = промер-яд: restore-иголки ph+pad жрали
            # друг друга при pypdf-merge пересжатии (offsets плывут);
            # (3) класс-метка в overlay = яд: 7-байтная «[phone]» =
            # часть фразы = резала токен. КОНТУРА: content-поток =
            # ЧИСТЫЙ побайтовый pad (токена в text-layer НЕТ =
            # deanonymize-демоном pdf НЕ меряем = ledger-restore, как
            # rtf); визуал токена = overlay-текст (nonce-уникален =
            # ложных иголок нет); restore = overlay-токены побайтово
            # вон + pad-участки → orig по ledger offsets (stream-индекс
            # каноничен: merge_page дописывает overlay ПОСЛЕ).
            _ = tail, tok
            whole_rep = b" " * len(needle)
            plan.append((pi, frag, needle, tail, whole_rep, "pad", tok))
        else:
            plan.append((pi, frag, needle, needle, b" " * len(needle), "pad", None))
    facts = []  # (page, stream_index, [(off, len)], mode, ctx)
    # посев = occ-номер ledger-записи (порядок ledger = boxes = positions);
    # k-й хит needle в потоке = k-е вхождение PII на странице.
    # ЗАПИСЬ НА NEEDLE (dedupe): surgery = replace-all = все вхождения
    # закрываются одним pass'ом (mid-flight-мутация потока между
    # occurrences = промер-яд rep3: план_i=1 видел write план_i=0).
    seen_needles = set()
    plan_dedup = []
    for ent in plan:
        key = (ent[0], ent[2])  # (page, needle)
        if key in seen_needles:
            continue
        seen_needles.add(key)
        plan_dedup.append(ent)
    plan = plan_dedup
    for pi, frag, needle, _probe, rep, _kind, _tok in plan:
        c = pdf.pages[pi].get("/Contents")
        streams = [c] if not isinstance(c, pikepdf.Array) else list(c)
        # СНИМОК исходных байтов (промер-яд rep2: stream.write = пиринг,
        # read_bytes после write = СЫРЫЕ байты незакомпрессированного
        # объекта = needle не ищется = ложный «нестандартная кодировка»):
        # ищем по снимку, пишем в stream, raws = канон для census.
        raws = [st.read_bytes() for st in streams]
        hit = False
        for si, stream in enumerate(streams):
            raw = raws[si]
            if needle in raw:
                # replace(needle, rep) = ALL-вхождения: один PII-фрагмент
                # повторяется в потоке = все вхождения = pad-участки =
                # restore кладёт orig во ВСЕ (побайтовый возврат каждого;
                # ledger-флаг orig_all = count>1 = аудит-метка).
                hits = [m for m in range(len(raw)) if raw.startswith(needle, m)]
                offs = [(m, len(needle)) for m in hits]
                # Анкор ctx = 24 Б НЕпробельного хвоста ДО PII +
                # разделители до PII = единая иголка ctx+pad (промер-яд
                # fk: смежные PII = pad-раны СЛИВАЮТСЯ). MULTI-occurrence
                # = СПИСОК ctxs per-hit (промер-яд rep3: «Kontakt PII tel
                # / Drugoy PII fax» = разные ctx = 1 анкор = 1 возврат =
                # второе вхождение молча не восстановлено = fail-open;
                # restore ищет КАЖДЫЙ ctx = все возвраты).
                def _anchor(buf, hpos):
                    k = hpos
                    while k > 0 and buf[k - 1:k] == b" ":
                        k -= 1
                    return buf[max(0, k - 24):k] + buf[k:hpos]
                ctxs = [_anchor(raw, h) for h in hits]
                # SEGMENTATION (промер-яд tf-snils): return-эвристика
                # «PAD+orig от конца» на ran 17 (11+1+4) = [6..17)+
                # [13..17) = ПЕРЕСЕЧЕНИЕ = двойная вставка = snils 3×.
                # Канон: pad-блок = (hit-позиция, len(needle)) = ровно
                # то, что положил surgery (replace-all = PII-байты →
                # len(needle) пробелов на КАЖДЫЙ хит).
                pad_blocks = [(h, len(needle)) for h in hits]
                stream.write(raw.replace(needle, rep))
                hit = True
                facts.append((pi, si, offs, "whole", ctxs, needle,
                              pad_blocks))
                break
            # Токенизированный show: «89161234567, INN» не лежит единой
            # подстрокой (Tj-строки делятся по словам/спейсингу). Контра =
            # ТОКЕН-уровень: frag распадается на целые show-куски, каждый
            # обязан быть в потоке дословно (побайтовый pad = R&D-контра,
            # молчаливый пропуск = fail-open = запрещено).
            pieces = [w.encode("utf-8") for w in frag.split() if w]
            missing = [w.decode() for w in pieces if w not in raw]
            if not missing:
                offs = []
                for w in pieces:
                    # count=1: дубликат куска = fail-closed (кусок-слово
                    # может жить в контексте страницы).
                    if raw.count(w) > 1:
                        die(f"{src}: страница {pi}: кусок {w.decode()!r} "
                            "встречается в потоке >1 раза = неоднозначная "
                            "карта, fail-closed")
                    offs.append((raw.find(w), len(w)))
                    raw = raw.replace(w, b" " * len(w), 1)
                stream.write(raw)
                hit = True
                facts.append((pi, si, offs, "piece",
                              [raw[max(0, offs[0][0] - 24):offs[0][0]]],
                              needle, list(offs)))
                break
        if not hit:
            pieces_dbg = [w.encode("utf-8") for w in frag.split() if w]
            census = [sum(r.count(p) for p in pieces_dbg) for r in raws]
            die(f"{src}: страница {pi}: байты {frag!r} (куски {census}) не "
                "найдены в content stream (потоков: "
                f"{len(streams)}) = нестандартная кодировка потока, "
                "файл НЕ маскируется (fail-closed)")
    # dlen (restore: сколько пробелов срезать справа от токена) =
    # len(tok) - len(slot), slot = whole-needle или tail-piece (факт hit'а).
    # offset-контра restore (pad = пробелы, неотличимы в потоке = возврат
    # по позиции; R&D roundtrip.py-контра). facts = порядок plan-цикла =
    # порядок boxes = порядок ledger (strict).
    # Факт = 1 на UNIQUE needle (page+frag); ledger = 1 на item-page.
    # Фолбэк-записи (needle=frag) уникальны на page (1 span на PII на
    # страницу = daemon-контра); surgery-факты = план-порядок.
    # Сопоставление = (page, frag) ключ (не zip: промер-яд tf-snils —
    # multi-occurrence на page-2 = 1 факт на 2 ledger-записи = zip
    # короткий).
    # Факты одной (page, frag) = ОДИН PII на странице = ОБЪЕДИНЁННАЯ
    # карта (multi-fact: tf — snils-2x на page-2 даёт ФАКТ whole-ветки
    # с 2 ctxs; записи несут все ctxs + все offs; ctxs[0]-запись =
    # ядро-1 = snils 3× = DRIFT-промер).
    from collections import defaultdict
    fmap = defaultdict(lambda: {"si": None, "offs": [], "ctxs": [],
                                "pads": []})
    for pi_, si, offs, _mode, ctxs, frag_b, pads in facts:
        k = (pi_, frag_b)
        fmap[k]["si"] = si
        fmap[k]["offs"].extend(offs)
        fmap[k]["ctxs"].extend(ctxs)
        fmap[k]["pads"].extend(pads)
    facts_merged = [(pi_, fb, v["si"], v["offs"], v["ctxs"], v["pads"])
                    for (pi_, fb), v in fmap.items()]
    used: set = set()
    for pi_, frag_b, si, offs, ctxs, pads in facts_merged:
        # Факт-на-needle = закрывает ВСЕ ledger-записи (page, frag):
        # surgery = replace-all = все вхождения masked (промер-яд tf:
        # zip-сопоставка = 1 запись = ctx без ctxs = вторая запись =
        # «ledger без ctx-анкора» на верном файле = fail-open restore).
        lis = [j for j, e in enumerate(ledger)
               if j not in used and e["page"] == pi_
               and e["orig"].encode("utf-8") == frag_b]
        if not lis:
            die(f"pdf: surgery-факт {frag_b!r} стр.{pi_} без ledger-записи"
                " = карта разошлась (fail-closed)")
        # Все записи (page, frag) = один и тот же факт: ctxs = ПОЛНЫЙ
        # список (per-entry дедуп chosen = защита; промер-яд tf-snils:
        # 2 ctx × 2 pad = 4 chosen на 2 pad = overlap-die на верном
        # файле; merge-ctxs = canonical-представление = каждый pad
        # найден ровно один раз).
        for li in lis:
            e = ledger[li]
            e["stream"] = si
            e["offsets"] = [[o, ln] for o, ln in offs]
            e["ctx"] = ctxs[0].decode("utf-8", "replace")
            e["ctxs"] = [c.decode("utf-8", "replace") for c in ctxs]
            e["pads"] = [[o, ln] for o, ln in pads]
            e["orig_all"] = True
            e["segs"] = max(e.get("segs", 1), len(offs))
        used.update(lis)
    # Фолбэк-записи (нет surgery-факта = нет needle в потоке = char-only
    # page) = без ctx: restore на них = fail-closed honest-отказ.
    if len(used) < len(facts):
        die("pdf: фактов больше, чем записей = карта разошлась")
    assert len(boxes) >= len(facts)
    tmp = args.out + ".surgery.tmp"
    pdf.save(tmp)
    # 2. overlay.
    import pdfplumber
    from pypdf import PdfReader, PdfWriter
    from reportlab.lib.colors import black, white
    from reportlab.pdfgen import canvas
    with pdfplumber.open(src) as pl:
        sizes = [(p.width, p.height) for p in pl.pages]
    r = PdfReader(tmp)
    w = PdfWriter()
    w.append(r)
    buf = _io.BytesIO()
    # Побайтовый учёт pad-а (restore-контра #302: токен длиннее PII =
    # поток растёт; restore урезает ровно pad_len пробелов вокруг токена
    # = побайтовый возврат; без учёта surgery-контра «токен/оригинал
    # разной длины» краснеет намеренно = fail-closed, не тихий дрейф).
    by_page = {}
    seen_bbox = set()
    for b in boxes:
        key = b[:2] + b[3:]
        if key in seen_bbox:
            continue  # multi-occurrence = один rect на вхождение
        seen_bbox.add(key)
        by_page.setdefault(b[0], []).append(b)
    for pi, items in sorted(by_page.items()):
        cc = canvas.Canvas(buf, pagesize=sizes[pi])
        for (_p, _frag, _repl, x0, y0, x1, y1) in items:
            if args.mode == "black":
                cc.setFillColor(black)
                cc.rect(x0 - 1, y0 - 1, x1 - x0 + 2, y1 - y0 + 2, fill=1, stroke=0)
            else:
                # #302-контра (первички 1–5): overlay = ГРАФИКА БЕЗ
                # ТЕКСТОВ. Любой overlay-текст = яд: токен-визуал =
                # pdfplumber читает его из text-layer = leak-scan
                # флагает артефакт; класс-метка = 7-байтная фраза режет
                # restore-иголки (промер-яд «c[AF0P#…»); restore-чистка
                # токенов из overlay ломает PDF-числа склейками
                # («106.3644 766…» = промер-5). Визуал = белый rect +
                # чёрный rect поверх = black-out вида; обратимость =
                # ledger+offsets (content-поток); deanonymize-демоном
                # pdf НЕ меряем (токена в text-layer нет = ledger-контур,
                # как rtf) = ДОК-лимитация в шапке.
                cc.setFillColor(white)
                cc.setStrokeColor(black)
                cc.rect(x0 - 1, y0 - 1, x1 - x0 + 2, y1 - y0 + 2, fill=1, stroke=1)
                cc.setFillColor(black)
                cc.setStrokeColor(black)
                cc.rect(x0, y0, x1 - x0, y1 - y0, fill=1, stroke=0)
        cc.save()
        buf.seek(0)
        w.pages[pi].merge_page(PdfReader(buf).pages[0])
        buf = _io.BytesIO()
    with open(args.out, "wb") as f:
        w.write(f)
    os.unlink(tmp)
    return len(boxes), ledger


def cmd_restore(args):
    ledger = json.load(open(args.ledger, encoding="utf-8"))
    ext = args.file.rsplit(".", 1)[-1].lower() if "." in args.file else ""
    if ext == "pdf" and all("orig" not in e for e in ledger):
        # Black-return ДО любой ph-машинерии (первичка #302: black-
        # ledger = без ph/orig = KeyError в ph_map = некрасивый краш;
        # честный отказ = контракт black = необратимость). Файл НЕ
        # открывается = pdf-библиотек для отказа не нужно.
        die("pdf: black-режим необратим (ledger без orig = PII не "
            "сохранялась) = возврат невозможен, это контракт black")
    fmt, obj = load_by_ext(args.file)
    url, sess = args.url, args.session
    # pdf = ledger-контра без ph_map (токен в text-layer НЕ пишется =
    # restore по ctx/pad; black-отказ = выше, ДО этого места).
    ph_map = {e["ph"]: e["orig"] for e in ledger if fmt != "pdf"}
    if fmt in ("txt", "md", "csv"):
        raw = open(args.file, "rb").read().decode("utf-8")
        back = api(url, "/v1/deanonymize", {"text": raw}, sess=sess)
        open(args.out, "w", encoding="utf-8").write(back["text"])
        print(f"RESTORED|{fmt}|deanonymize")
        return
    if fmt == "pdf":
        # Restore = pypdf-контра roundtrip.py (первички #302 1–7:
        # pikepdf-открытие НЕ видит потоки после pypdf-writer =
        # roundtrip писал/читал pypdf-ем; ledger-стрим-индексы НЕ канон:
        # merge_page пересобирает /Contents = [overlay, content], промер
        # fgm; pikepdf.save = FlateDecode = offsets маски = аудит-поле,
        # не иголка). Обход = все content-потоки страницы, иголка =
        # ctx-анкор (24 Б НЕпробельного контекста до PII, пишется
        # МАСКОЙ) + pad-ран ровно len(orig) пробелов = fail-closed на
        # ложном месте; правки НАКОПЛЯЮТСЯ в raws (чистая запись в
        # объект = потеря иголок следующих PII, промер-яд gg).
        # Deanonymize-демоном pdf НЕ меряем: токена в text-layer нет
        # (graphics-only overlay) = ledger-контур, как rtf = ДОК-лимит.
        from pypdf import PdfReader, PdfWriter
        from pypdf.generic import ArrayObject
        writer = PdfWriter(clone_from=PdfReader(args.file))
        n = 0
        by_page = {}
        for e in ledger:
            by_page.setdefault(e["page"], []).append(e)
        for pi_, ents in sorted(by_page.items()):
            page = writer.pages[pi_]
            c = page.get("/Contents")
            c = c.get_object() if hasattr(c, "get_object") else c
            refs = list(c) if isinstance(c, ArrayObject) else [c]
            streams = [r.get_object() if hasattr(r, "get_object") else r
                       for r in refs]
            raws = [bytes(st.get_data()) for st in streams]
            # СБОР ВСЕХ pad-участков по всем записям (правки применяются
            # ПОСЛЕ сканирования: промер-яд fh — возврат PII-0 съел ctx-
            # анкор записи PII-1 = «карта разошлась» на верном файле).
            all_chosen = []  # (si, off, ln, orig_bytes)
            _touched = []  # (si, o, ln, orig) = применённые вставки
            # Restore = ctx-иголки + SEGMENTATION (промер-яд tf-snils:
            # return-эвристика от конца на ran 17 (11+1+4) = [6..17) +
            # [13..17) = ПЕРЕСЕЧЕНИЕ = двойная вставка = snils 3×;
            # pads-позиции маски = raw-координаты = FlateDecode-дрейф
            # (первичка 1–6) = «pad-блок не pad» на верном файле =
            # позиция НЕ канон). Канон: ядро = ПЕРВЫЙ len(orig) пробел
            # анкор-иголки (surgery кладёт ровно len пробелов на хит);
            # соседи = (1+pad) хвосты от конца; остальное = leading =
            # не вставляем. Анкор-иголки = ledger ctxs (маска, rep3) =
            # все позиции; «ctx» = фолбэк.
            for e in ents:
                orig = e["orig"].encode("utf-8")
                needles = [c.encode("utf-8") for c in e.get("ctxs", [])]
                needles = [x for x in needles if x] or [
                    e.get("ctx", "").encode("utf-8")]
                needles = [x for x in needles if x]
                if not needles:
                    die("pdf: ledger без ctx-анкора = маска не #302-формата "
                        "= fail-closed")
                chosen = []
                for si in range(len(raws)):
                    for needle in needles:
                        m = 0
                        while True:
                            # fresh-read (первичка #305 cyr-wa:
                            # enumerate-копия raw = stale: phone-вставка
                            # = «89161234567, » = inn-иголка «  , \017…»
                            # убита = scan=0 = die на ВЕРНОМ cyr-rl;
                            # fresh = ядро-после-вставки видно).
                            raw = raws[si]
                            j = raw.find(needle, m)
                            if j < 0:
                                break
                            o = j + len(needle)
                            # Pad-ран: len(orig)..∞ пробелов (ядро =
                            # первые len; слияние соседей = хвост).
                            k = o
                            while k < len(raw) and raw[k:k + 1] == b" ":
                                k += 1
                            if k - o >= len(orig):
                                # Ядро = первые len(orig) пробелов =
                                # позиция PII (surgery-контрака =
                                # PII-блок = len пробелов от хита).
                                # Сдвиг = fresh-read (первичка #305
                                # cyr-wa shared-контекст: ctx = общий
                                # Tj-перемычки = иголка phone найдена
                                # раньше инна = после phone-вставки
                                # inn-иголка = на len(orig) правее =
                                # инкремент = размер чужой вставки =
                                # контракт: len(orig-чужого) = len
                                # (pad-чужого) = сдвиг = len(orig).
                                chosen.append((si, o, len(orig)))
                            m = j + 1
                chosen = sorted(set(chosen), reverse=True)
                # Не-пересечение (multi = ран-слияние: ядро PII1 = [o1,
                # o1+L1) = ядро PII2 = [o2, o2+L2) НЕ пересекаются по
                # построению: surgery = раздельные хиты).
                pairs = sorted((o, ln) for _si, o, ln in chosen)
                for (o1, l1), (o2, _l2) in zip(pairs, pairs[1:], strict=False):
                    if o1 + l1 > o2:
                        die("pdf: ctx-ядра пересекаются = неоднозначная "
                            "карта (fail-closed)")
                if not chosen:
                    die(f"pdf: анкор {needles[0][:24]!r}+pad({len(orig)}) не "
                        "найден = карта разошлась (fail-closed)")
                if len(chosen) > 1 and not e.get("orig_all"):
                    die(f"pdf: анкор {needles[0][:24]!r} даёт {len(chosen)} "
                        "pad-участков = неоднозначная карта, fail-closed")
                for t in ((si, o, ln, orig) for si, o, ln in chosen):
                    if t not in all_chosen:
                        all_chosen.append(t)
            # Побайтовые пересечения = fail-closed (pad-раны разных PII
            # не должны перекрываться = маска даёт непересекающиеся).
            # all_chosen = аудит (в global-порядке = «pad-участки
            # перекрываются» = законные соседние ядра cyr-wa (302,11)+(302,10)
            # = die на ВЕРНОМ файле = глобальная = не контракт).
            # Применение = per-entry, chosen-порядок = reverse: ядро
            # scan-ится ПОСЛЕ вставок предшественников (fresh-иголка =
            # ядро за чужой вставкой = pad-контрака краснеет = honest-
            # отказ; cyr-wa: phone [302..313) = fresh-иголка = [313..323)
            # ∩ inn-ядро = die; cyr-rl: phone [109..120) = fresh-иголка
            # = « 89161234567, » = die) = ПЕРВИЧКА-ИСХОД = fail-closed
            # по классу shared-контекста (Tj-скобки/перемычки шрифтов).
            # Контракт применения (#305): ядро = из scan-а исходного
            # snapshot; применение = глобальный reverse-порядок =
            # позиции левее инвариантны (длина вставки = длина pad =
            # len(orig)); multi-occurrence = НЕСКОЛЬКО ядер одной
            # записи (all_chosen = дедуп по кортежу = все позиции
            # ctxs-иголок, первичка: 1 запись на (page,frag), все
            # вхождения = все ctxs).
            by_stream = {}
            for si, o, ln, orig in all_chosen:
                by_stream.setdefault(si, []).append((o, ln, orig))
            for si, spans in by_stream.items():
                spans.sort()
                # Побайтовые пересечения = fail-closed (pad-раны разных
                # PII не должны перекрываться = маска даёт
                # непересекающиеся; соседние ядра cyr-wa = (302,11)+
                # (302,10) = НЕ пересечение = законны (по построению
                # surgery = раздельные хиты).
                for (o1, l1, _a), (o2, _l2, _b) in zip(spans, spans[1:],
                                                       strict=False):
                    if o1 + l1 > o2:
                        die("pdf: pad-участки перекрываются = карта "
                            "разошлась (fail-closed)")
                for o, ln, orig in sorted(spans, reverse=True):
                    raw = raws[si]
                    if raw[o:o + ln] != b" " * ln:
                        die(f"pdf: ядро {o}+{ln} = {raw[o:o + 16]!r} не pad "
                            "= карта разошлась (fail-closed)")
                    raws[si] = raw[:o] + orig + raw[o + ln:]
                    _touched.append((si, o, ln, orig))
                    n += 1
            # Post-контрака (первичка #305): ядро после вставки = orig
            # = pad-блок на месте = контракт wa-порчи (wa-2: PII на
            # границе Tj-скобки = вставка len(orig) = leading-пробел
            # ВНЕ скобки = pad-блок ядра = не пробелы = die ДО вставки;
            # ядро = после вставки = orig = die). PII-scan потоков =
            # ЯД h1/s2f: shared-контекст = PII соседа в потоке =
            # законно (его ядро = его запись), overlay = rect-числа =
            # PII-цифры = ложное попадание; leak-scan = тест-полка
            # (extract + побайтовый raw = канон #302).
            for si, o, ln, orig in _touched:
                if raws[si][o:o + ln] != orig:
                    die("pdf: ядро после вставки != orig = карта разошлась "
                        "(fail-closed)")
            for st, raw in zip(streams, raws, strict=True):
                if bytes(st.get_data()) != raw:
                    st.set_data(raw)
        with open(args.out, "wb") as f:
            writer.write(f)
        print(f"RESTORED|pdf|{n}")
        return
    if fmt == "rtf":
        # rfind-контра маски: возврат = те же позиции плейсхолдеров в
        # RTF-исходнике (демона для rfn-хода не нужен: ledger несёт orig).
        # #300 NIT-2: байтовая система и на возврате (париток маски).
        out = open(args.file, "rb").read()
        for ph, orig in ph_map.items():
            phb, ob = ph.encode("utf-8"), orig.encode("utf-8")
            pos = out.rfind(phb)
            if pos < 0:
                die(f"rtf: плейсхолдер {ph!r} не найден (карта разошлась)")
            out = out[:pos] + ob + out[pos + len(phb):]
        open(args.out, "wb").write(out)
        print(f"RESTORED|rtf|{len(ph_map)}")
        return
    n = 0
    if fmt == "docx":
        for _key, node in _iter_texts("docx", obj):
            for ph, orig in ph_map.items():
                if ph in node.text:
                    node.text = node.text.replace(ph, orig)
                    n += 1
    elif fmt == "pptx":
        for _, node in _iter_texts("pptx", obj):
            for ph, orig in ph_map.items():
                if ph in node.text:
                    node.text = node.text.replace(ph, orig)
                    n += 1
    elif fmt == "xlsx":
        for ws in obj.worksheets:
            for row in ws.iter_rows():
                for c in row:
                    if isinstance(c.value, str):
                        v = c.value
                        for ph, orig in ph_map.items():
                            v = v.replace(ph, orig)
                        if v != c.value:
                            c.value = v
                            n += 1
    obj.save(args.out)
    print(f"RESTORED|{fmt}|{n}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fasad-file")
    ap.add_argument("--url", default=DEFAULT_URL)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mask")
    m.add_argument("file")
    m.add_argument("session")
    m.add_argument("--out", required=True)
    m.add_argument("--ledger", default="ledger.json")
    m.add_argument("--mode", choices=("black", "placeholder"), default="placeholder",
                   help="pdf-режим (остальные форматы = placeholder-контур)")
    m.set_defaults(fn=cmd_mask)
    r = sub.add_parser("restore")
    r.add_argument("file")
    r.add_argument("session")
    r.add_argument("--out", required=True)
    r.add_argument("--ledger", required=True)
    r.set_defaults(fn=cmd_restore)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
