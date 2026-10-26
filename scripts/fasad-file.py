# /// script
# requires-python = ">=3.12"
# dependencies = ["python-docx", "openpyxl", "python-pptx", "striprtf"]
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

Известный FN-класс ДЕТЕКТОРА (не обёртки, чин = каскад-0 issue, не здесь):
паспорт в соседстве «ИНН <10 цифр>» = inn-доминанта гасит паспортную
гипотезу (зуб реестра c0_inn_key_dominates_passport, cascade0.rs:337);
промер обёртки: ни row-, ни col-major склейка его не достают (до и после
маски) = leak-scan осознанно исключает такой кейс, тест-полка документирует.

Запуск (uv single-file, AGENTS §6 gutter — продукт НЕ Rust-обвязка):
  uv run scripts/fasad-file.py mask  ФАЙЛ СЕССИЯ --out ФАЙЛ
  uv run scripts/fasad-file.py restore ФАЙЛ СЕССИЯ --ledger ФАЙЛ --out ФАЙЛ
  (--url http://127.0.0.1:PORT, дефолт 8765)
"""

from __future__ import annotations

import argparse
import json
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
    die(f"{src}: формат этапа 1 не поддержан (docx/xlsx/pptx/rtf/txt/md/csv)")


def cmd_mask(args):
    fmt, obj = load_by_ext(args.file)
    sess, url = args.session, args.url
    if fmt in ("txt", "md", "csv"):
        n, ledger = mask_text_like(args.file, args.out, sess, url)
    elif fmt == "rtf":
        n, ledger = _mask_rtf(args, obj)
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


def cmd_restore(args):
    fmt, obj = load_by_ext(args.file)
    url, sess = args.url, args.session
    ledger = json.load(open(args.ledger, encoding="utf-8"))
    ph_map = {e["ph"]: e["orig"] for e in ledger}
    if fmt in ("txt", "md", "csv"):
        raw = open(args.file, "rb").read().decode("utf-8")
        back = api(url, "/v1/deanonymize", {"text": raw}, sess=sess)
        open(args.out, "w", encoding="utf-8").write(back["text"])
        print(f"RESTORED|{fmt}|deanonymize")
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
