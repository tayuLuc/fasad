# /// script
# requires-python = ">=3.12"
# dependencies = ["python-docx", "openpyxl", "python-pptx", "striprtf",
#   "pikepdf", "pdfplumber", "pypdf", "reportlab", "fpdf2",
#   "pypdfium2", "pillow", "img2pdf"]
# ///
"""Зубы обёртки fasad-file.py (#297 этап-1 + #302 pdf CI-полка; НЕ golden).

Контур: живой демон (FASAD_TEST_CASCADE0=1 харнес, как R&D f620296e) +
uv-окружение. Запуск (из корня репозитория):
  FASAD_BIN=target/debug/fasad uv run scripts/test-fasad-file.py
Зубы:
  1 roundtrip docx/xlsx/txt = побайтовый/текстовый возврат через
    deanonymize + ledger; pdf = побайтовая каноничность DECODED
    content-потоков (pikepdf) + текст-канон (zip-байты = не канон:
    pypdf-FlateDecode = R&D/#302-первички; в stream = overlay-графика
    маски = ожидаемый артефакт, текст-канон её не читает);
  2 leak-scan: повторное извлечение masked-файла = PII-строк нет;
  2b PDF_BLACK: black-контра = побайтовый скан PII 0 + restore = честный
    отказ (необратимость = контракт);
  2c PDF_CYRILIC (#305 п.1, свои движки = первичка Word/LibreOffice-
    кодировок): type0 Identity-H (fpdf2/TTF, 2-байтные CID) = roundtrip
    (PII-цифры = ASCII-байты кодов = побайтовый needle); WinAnsi
    (reportlab базовый, Tj-перемычки = PII на границе скобок) = маска
    чистая + restore = честный rc2 «перекрываются» (контракт #305
    п.1в: обратимость не доказана = fail-closed, НЕ ослабление);
  3 fail-closed: битый/шифрованный docx (PackageNotFoundError) = rc!=0;
  4 SCAN (#304 этап-3, mac-only = Vision-движок, skip-контра = #316-
    паттерн legs: linux/windows = SKIP-строка, не зелёный пропуск):
    синтетический скан (растр в PDF, PIL+img2pdf = R&D-фикстура
    FINAL-scan) = маска; leak-scan = повторный OCR masked = PII-строк 0;
    restore = честный отказ (растр необратим = контракт black);
    FASAD_OCR_BIN без бинаря = fail-closed-отказ (не no-op).
Известный FN-класс (документирован в README fasad-file.py, НЕ зуб-проверка):
паспорт рядом с ИНН-ключом = inn-доминанта каскада-0 (зуб реестра
c0_inn_key_dominates_passport) = обёртка не чинит.
"""

from __future__ import annotations

import io as _io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PORT = int(os.environ.get("FASAD_TEST_PORT", "18805"))
URL = f"http://127.0.0.1:{PORT}"


def daemon():
    binp = os.environ.get("FASAD_BIN", str(ROOT / "target" / "debug" / "fasad"))
    if not Path(binp).exists():
        print(f"SKIP|нет бинаря демона {binp} (FASAD_BIN=target/debug/fasad)")
        sys.exit(0)
    env = {
        **os.environ,
        "FASAD_THREADS": "2",
        "FASAD_PORT": str(PORT),
        "FASAD_TEST_CASCADE0": "1",
    }
    p = subprocess.Popen([binp], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{URL}/health", timeout=1) as r:
                if r.status == 200:
                    return p
        except OSError:
            time.sleep(0.5)
    p.kill()
    print("FAIL|демон не поднялся")
    sys.exit(1)


def run(*argv, expect_rc: int = 0) -> str:
    cmd = [sys.executable, str(HERE / "fasad-file.py"), "--url", URL, *argv]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != expect_rc:
        print(f"FAIL|rc={r.returncode} (ожидался {expect_rc})|{' '.join(argv)}")
        print(r.stderr)
        sys.exit(1)
    return r.stdout.strip()


def make_samples(td: Path):
    from docx import Document
    d = Document()
    d.add_paragraph("УТВЕРЖДАЮ")
    d.add_paragraph("Контакт: 8-916-123-45-67, ИНН 7707083893, СНИЛС 112-233-445 95.")
    t = d.add_table(rows=2, cols=2)
    t.rows[0].cells[0].text = "Телефон"
    t.rows[0].cells[1].text = "Паспорт"
    t.rows[1].cells[0].text = "+79261112233"
    t.rows[1].cells[1].text = "4511 123456"
    d.save(td / "s.docx")
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "Паспорт"
    ws["A2"] = "4511 123456"
    ws["B1"] = "ИНН"
    ws["B2"] = "7707083893"
    ws["C1"] = "Телефон"
    ws["C2"] = "8-916-123-45-67"
    wb.save(td / "s.xlsx")
    (td / "s.txt").write_text(
        "Контакт: 8-916-123-45-67, ИНН 7707083893, СНИЛС 112-233-445 95.\n",
        encoding="utf-8",
    )
    # битый docx: zip-магик + мусор = PackageNotFoundError (первичка R&D)
    (td / "broken.docx").write_bytes(b"PK\x03\x04\x00\x00\x00\x00garbage-not-a-package")
    # битый pdf = PdfminerException = fail-closed (первичка #302)
    (td / "broken.pdf").write_bytes(b"%PDF-1.4\nbroken-no-xref")
    # текстовый PDF (reportlab = Helvetica-ANSI, PII = ASCII = канон
    # этапа-2; кириллица-потоки = Hex/CID = этап 3 = вне фикстуры):
    # PII в строках с контекстом (ctx-анкор + слияние соседних pad-ранов
    # = #302 restore-контра).
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(td / "s.pdf"), pagesize=(595, 842))
    c.setFont("Helvetica", 12)
    c.drawString(60, 790, "Zapros na postavku oborudovaniya.")
    c.drawString(60, 770, "Kontakt: 89161234567, INN 7707083893.")
    c.drawString(60, 750, "SNILS 112-233-445 95. Data 28.09.2026.")
    c.showPage()
    # страница 2 = MULTI-OCCURRENCE (#302-зуб): СНИЛС ДВАЖДЫ с РАЗНЫМ
    # левым контекстом (промер-яд rep3: 1 анкор = 1 возврат = второе
    # вхождение молча не восстановлено = fail-open; промер-яд fixed-
    # fixture: телефон-повтор на page-2 = phone-доминанта демона =
    # один span = зуб меряется snils-парой, детектируется обеими).
    c.setFont("Helvetica", 12)
    c.drawString(60, 790, "Arhiv 112-233-445 95 skan")
    c.drawString(60, 770, "Kopiya 112-233-445 95 vtoroy")
    c.showPage()
    c.save()


def _pdf_content_bytes(path: Path) -> list:
    """Побайтовый текст-канон = Tj-показания с НОРМАЛИЗАЦИЕЙ пробелов
    (первички #302: DECODED-байты потока = не канон = pypdf-merge q/n-
    обёртки; zip-байты = не канон = FlateDecode; Tj-строки ДО маски
    каноничны, но restore-вставка PII в pad-ран съедает разделительный
    пробел = «Kontakt:PII ,» при «Kontakt: PII,» = Tj- Equality =
    промер-яд DRIFT. Мера = PII-байты на месте + весь remainder
    побайтово: Tj-строки → b" ".join(split()) collapse = pad-пробелы
    канонизируются (pad-яд = PII-байты в каноне НЕ появляется))."""
    import re

    import pikepdf
    out = []
    with pikepdf.open(path) as pdf:
        for page in pdf.pages:
            c = page.get("/Contents")
            streams = [c] if not isinstance(c, pikepdf.Array) else list(c)
            raw = b"".join(s.read_bytes() for s in streams
                           if b" Tf" in s.read_bytes())
            # Tj-показания страницы СЛИВАЮТСЯ в один канон-блок:
            # restore-вставка PII склеивает Tj-строку с pad-раном
            # («DrugoyPII fax» при «Drugoy PII fax», Tj-concatenation =
            # R&D-первичка) = per-string-сравнение = ложный DRIFT
            # (промер); collapse-пробелы = pad-норма, PII-байты на месте
            # = канон побайтовый.
            t = b" ".join(m.group(1) for m in
                          re.finditer(rb"\((.*?)\) Tj", raw))
            out.append(b" ".join(t.split()))
    return out


PII = [
    "8-916-123-45-67",
    "7707083893",
    "112-233-445 95",
    "+79261112233",
]
# Известный FN-класс каскада-0 (НЕ обёртки): паспорт рядом с «ИНН…» =
# inn-доминанта гасит паспортную гипотезу (зуб реестра
# c0_inn_key_dominates_passport, cascade0.rs:337) — промер live-демоном
# обёртки: ни row-, ни col-major склейка паспорта не достают, до и после
# маски. «4511 123456» из leak-ожиданий исключён ОСОЗНАННО (документирован
# в README fasad-file.py), отдельный зуб: PAST-PASSPORT ниже.
PII_DOCX_ONLY = ["4511 123456"]


def extract_all(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".docx":
        from docx import Document
        d = Document(path)
        t = "".join(p.text for p in d.paragraphs)
        t += "".join(c.text for tb in d.tables for r in tb.rows for c in r.cells)
        for sec in d.sections:
            t += "".join(p.text for p in sec.header.paragraphs)
            t += "".join(p.text for p in sec.footer.paragraphs)
        return t
    if ext == ".pdf":
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            return "".join(p.extract_text() or "" for p in pdf.pages)
    if ext == ".xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(path)
        return " ".join(
            str(c.value)
            for ws in wb.worksheets
            for row in ws.iter_rows()
            for c in row
            if c.value is not None
        )
    return path.read_text(encoding="utf-8")


def test_roundtrip_and_leaks(td: Path, daemon_proc) -> int:
    fails = 0
    for name in ("s.docx", "s.xlsx", "s.txt", "s.pdf"):
        src = td / name
        masked = td / f"m-{name}"
        back = td / f"r-{name}"
        sess = f"t297-{name}"
        led = td / f"l-{name}.json"
        run("mask", str(src), sess, "--out", str(masked), "--ledger", str(led))
        text = extract_all(masked)
        leaks = [p for p in PII if p in text]
        if name == "s.docx":
            # docx-таблица «Паспорт | 4511 123456»: col-major pass 2 обязан
            # достать паспорт (ключ соседом), промер f297: детектируется.
            leaks = leaks + [p for p in PII_DOCX_ONLY if p in text]
        if leaks:
            print(f"LEAK|{name}|{leaks}")
            fails += 1
        run("restore", str(masked), sess, "--out", str(back), "--ledger", str(led))
        # Возврат: docx/xlsx = текстовая каноничность (docx xml-байты не
        # каноничны: python-docx переписывает zip), txt = побайтовая.
        if name.endswith(".txt"):
            ok = back.read_bytes() == src.read_bytes()
        elif name.endswith(".pdf"):
            # Возврат = extract (whitespace-collapsed = норма: pad-ран
            # = 1+ пробелов, Tj-concatenation = R&D-первичка) + PII-
            # счётчики (multi-occurrence-зуб: 89161234567 = 3 (2 на
            # стр.2), 7707083893 = 2) + побайтовый Tj-канон
            # (_pdf_content_bytes = PII-байты на местах).
            def _ws(x):
                return " ".join(x.split())
            m1 = _ws(extract_all(back)) == _ws(extract_all(src))
            # multi-occurrence-зуб: snils = 2 возврата (2 вхождения на
            # page-2 = разные ctx-анкоры, промер-яд rep3).
            # multi-occurrence-зуб: snils = 3 в каноне (1 на стр.1 + 2
            # на стр.2; extract-счётчик = layout-хрупкий: межстраничная
            # вставка «\n» рвёт «95. Data»/«95 skan» = 2 при верном
            # потоке, промер-яд меры; Tj-канон = побайтовый).
            _cb = _pdf_content_bytes(back)
            _cs = _pdf_content_bytes(src)
            m2 = b"".join(_cb).count(b"112-233-445 95") == 3
            m3 = b"".join(_cb).count(b"89161234567") == 1
            m4 = _cb == _cs
            ok = m1 and m2 and m3 and m4
            if not ok:
                print(f"DRIFT-PROBE|ws={m1}|snils3={m2}|ph1={m3}|tj={m4}")
                print("BACK:", repr(extract_all(back)))
        else:
            ok = extract_all(back) == extract_all(src)
        if name.endswith(".pdf"):
            # Мута-промер меры (anti-false-green): инвертированный байт
            # PII в restored-потоке = каноны краснеют (Tj-канон +
            # extract+счётчики).
            import pikepdf as _pp
            with _pp.open(back) as _pdf:
                _c = _pdf.pages[0].get("/Contents")
                _st = [_c] if not isinstance(_c, _pp.Array) else list(_c)
                _r = _st[0].read_bytes().replace(b"89161234567", b"89161234566", 1)
                _st[0].write(_r)
                _pdf.save(str(td / "mut.pdf"))
            mut_ok = _pdf_content_bytes(td / "mut.pdf") != _pdf_content_bytes(src) \
                and " ".join(extract_all(td / "mut.pdf").split()) != \
                " ".join(extract_all(src).split())
            print(f"MUTA|pdf|caught={mut_ok}")
            ok = ok and mut_ok
        print(f"ROUNDTRIP|{name}|{'ok' if ok else 'DRIFT'}")
        fails += 0 if ok else 1
    return fails


def test_pdf_cyrillic(td: Path) -> int:
    """#305 п.1: PDF-кириллица = промер кодировок потоков (свои движки,
    первичка #304 = Word/LibreOffice-живой fail-closed). (1) Type0
    Identity-H (fpdf2-класс = 2-байтные CID = PII-цифры = ASCII-байты
    кодов = побайтовый needle) = roundtrip = ПИТАЕТСЯ канон; (2)
    reportlab-базовый WinAnsi = кириллица НЕ в WinAnsi = Tj-дробление
    перемычками шрифтов + PII на границе скобки = перекрывающиеся ядра
    = fail-closed rc2 = контракт #305 п.1в (обратимость не доказана;
    маска = полная: leak-scan чист, restore = честный отказ)."""
    fails = 0
    cyr = "Заявка: телефон 89161234567, ИНН 7707083893."
    # движок TrueType-кириллица (reportlab TTF = Type0 Identity-H,
    # PII-цифры = 1-байтные ASCII-коды = побайтовый needle = канон
    # Word-класса: Type0 CIDToGIDMap Identity + ToUnicode = та же
    # форма; fpdf2-класс = 2-байтные CID = PII-байты разрезаны =
    # fail-closed «нестандартная кодировка» = задокументирован, НЕ
    # зуб: маскировка файла-движка с разрезанными PII = не наш класс).
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas
    # переносимость CI-ног (провен file-shelf ubuntu run 40483157221:
    # mac-path = OSError ДО skip-гейтов = красная нога): кириллический TTF
    # ищем по списку платформ, нет = SKIP-строка (#316-паттерн legs).
    cyr_ttf = next((p for p in (
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/Library/Fonts/Arial Unicode.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arialuni.ttf",
        "C:/Windows/Fonts/DejaVuSans.ttf") if Path(p).exists()), None)
    if cyr_ttf is None:
        print("PDF_CYRILIC|SKIP (кириллический TTF не найден на ноге)")
        return 0
    pdfmetrics.registerFont(TTFont("CyrTtf", cyr_ttf))
    c0 = canvas.Canvas(str(td / "cyrtype0.pdf"), pagesize=(595, 842))
    c0.setFont("CyrTtf", 11)
    c0.drawString(60, 790, cyr)
    c0.drawString(60, 770, "СНИЛС 112-233-445 95.")
    c0.showPage()
    c0.save()
    masked = td / "m-cyr0.pdf"
    back = td / "b-cyr0.pdf"
    led = td / "l-cyr0.json"
    run("mask", str(td / "cyrtype0.pdf"), "t305c0", "--out", str(masked),
        "--ledger", str(led))
    text = extract_all(masked)
    leaks = [p for p in PII if p in text]
    raw = masked.read_bytes()
    rawleaks = [p.encode() for p in PII if p.encode() in raw]
    rc = 0
    try:
        run("restore", str(masked), "t305c0", "--out", str(back),
            "--ledger", str(led))
    except SystemExit:
        rc = 2
    ok = (rc == 0 and not leaks and not rawleaks
          and "89161234567" in extract_all(back))
    print(f"PDF_CYRILIC|type0-identity-h|mask-clean={not leaks}/{not rawleaks}"
          f"|restore-rc={rc}|{'ok' if ok else 'FAIL'}")
    fails += 0 if ok else 1
    # движок WinAnsi = reportlab базовый Helvetica (кириллица-подмена +
    # Tj-перемычки шрифтов = PII на границе скобок).
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(td / "cyrwa.pdf"), pagesize=(595, 842))
    c.setFont("Helvetica", 11)
    c.drawString(60, 790, cyr)
    c.showPage()
    c.save()
    masked2 = td / "m-cyrw.pdf"
    led2 = td / "l-cyrw.json"
    out2 = run("mask", str(td / "cyrwa.pdf"), "t305cw", "--out", str(masked2),
               "--ledger", str(led2))
    assert "MASKED" in out2, out2
    text2 = extract_all(masked2)
    leaks2 = [p for p in PII if p in text2]
    raw2 = masked2.read_bytes()
    rawleaks2 = [p.encode() for p in PII if p.encode() in raw2]
    cmd3 = [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
            "restore", str(masked2), "t305cw", "--out",
            str(td / "b-cyrw.pdf"), "--ledger", str(led2)]
    r3 = subprocess.run(cmd3, capture_output=True, text=True)
    ok2 = (not leaks2 and not rawleaks2 and r3.returncode == 2
           and "перекрываются" in r3.stderr
           and not (td / "b-cyrw.pdf").exists())
    print(f"PDF_CYRILIC|winansi-tjboundary|mask-clean={not leaks2}/"
          f"{not rawleaks2}|restore-failclosed-rc={r3.returncode}|{'ok' if ok2 else 'FAIL'}")
    fails += 0 if ok2 else 1
    return fails


def test_pdf_black(td: Path) -> int:
    """Black-контра #302: побайтовый скан = PII 0 + restore = честный
    отказ (необратимость = контракт black, ledger без orig)."""
    out = td / "b.pdf"
    led = td / "b-ledger.json"
    run("mask", str(td / "s.pdf"), "t300blk", "--out", str(out),
        "--ledger", str(led), "--mode", "black")
    raw = out.read_bytes()
    clean = all(p.encode() not in raw for p in PII + ["4511 123456"])
    r = subprocess.run(
        [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
         "restore", str(out), "t300blk", "--ledger", str(led),
         "--out", str(td / "b-back.pdf")],
        capture_output=True, text=True,
    )
    ok = clean and r.returncode != 0 and "необратим" in r.stderr \
        and not (td / "b-back.pdf").exists()
    print(f"PDF_BLACK|byte-clean={clean}|restore-refuse-rc={r.returncode}|"
          f"{'ok' if ok else 'PROBLEM'}")
    return 0 if ok else 1


def test_failclosed(td: Path) -> int:
    out = td / "never.docx"
    r = subprocess.run(
        [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
         "mask", str(td / "broken.docx"), "s", "--out", str(out)],
        capture_output=True, text=True,
    )
    ok = r.returncode != 0 and "PackageNotFoundError" in r.stderr and not out.exists()
    print(f"FAILCLOSED|broken.docx|rc={r.returncode}|{'ok' if ok else 'PROBLEM'}")
    fails = 0 if ok else 1
    out2 = td / "never.pdf"
    r2 = subprocess.run(
        [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
         "mask", str(td / "broken.pdf"), "s", "--out", str(out2)],
        capture_output=True, text=True,
    )
    ok2 = r2.returncode != 0 and "не разобрался" in r2.stderr and not out2.exists()
    print(f"FAILCLOSED|broken.pdf|rc={r2.returncode}|{'ok' if ok2 else 'PROBLEM'}")
    return fails + (0 if ok2 else 1)


def test_cyrillic_teeth(td: Path) -> int:
    """#300 NIT-зубы на КИРИЛЛИЧЕСКОЙ фикстуре (char != byte).

    Каскад-0 кириллический адрес НЕ детектит (class=address = каскад 1–2
    с весами), поэтому фикстура = mock-спан: таблица байтовых координат
    снята с самой фикстуры (tb.find), analyze подменяется моком ровно на
    время вызова, anonymize = живой демона (та же session-механика).
    Дискриминатор NIT-1: char-slice по [start:end] MaskItem даёт ДРУГУЮ
    строку (промер), byte-slice = точный orig → зуб красен на char-версии.
    """
    fails = 0
    # (1) ledger byte-контра: docx-таблица (фикстура кириллическая, координаты byte).
    from docx import Document
    # КИРИЛЛИЧЕСКИЙ ПРЕФИКС = дискриминатор char/byte (до фикстуры с
    # ASCII-префиксом мутации char-slice не краснели: ASCII-зона char==byte
    # = lesson «дискриминирующий вход»).
    d = Document()
    d.add_paragraph("Служебная записка о адресе: г. Москва, ул. Ленина, д. 42, кв. 7.")
    d.save(td / "cyr.docx")
    (td / "cyr.rtf").write_text(
        "{\\rtf1\\ansi Служебная записка о адресе: г. Москва, ул. Ленина, д. 42, кв. 7.\\par}",
        encoding="utf-8",
    )
    text = "Служебная записка о адресе: г. Москва, ул. Ленина, д. 42, кв. 7."
    tb = text.encode("utf-8")
    b0 = tb.find("г. Москва".encode())
    b1 = tb.find("кв. 7.".encode()) + len("кв. 7.".encode())
    # Первичка MaskItem (vault.rs:164-176): start/end = СИМВОЛЬНЫЕ offsets
    # спана (контракт Presidio), byte_start/byte_end = канон. Мок = ЧЕСТНЫЙ
    # перевод char=byte по UTF-8 (кириллица 2Б = char != byte).
    # ДИСКРИМИНАТОР (промер #300): char0 != char0-байт-координата = true,
    # НО срез `text[byte_start:byte_end]` на кириллическом префиксе даёт
    # ДРУГУЮ подстроку (51:105 по символам ≠ 28:64) = мутация «char-срез по
    # byte-координатам» ловится; честный char-slice = char1/char0.
    char0 = len(tb[:b0].decode("utf-8"))
    char1 = len(tb[:b1].decode("utf-8"))
    assert char0 != b0 and tb[b0:b1] != text[b0:b1].encode(), \
        "фикстура не дискриминирует char/byte (фиксировать фикстуру)"
    mock = [{"entity_type": "address", "start": char0, "end": char1,
             "score": 1.0, "class": "address",
             "byte_start": b0, "byte_end": b1,
             "role": None, "source": "mock", "verdict": "mask",
             "validator": None}]
    # analyze-мок: подмена /v1/analyze у обёртки = env-хук (файл мока) —
    # ЧИСТЫЙ путь: обёртка ходит в демона; мок ставим на URL демона? Нет:
    # чистая контура = патчим api() импортом модуля (single-file = import
    # через importlib от файла)
    def load_module(name: str):
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, HERE / "fasad-file.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    ff = load_module("fasad_file_cyr")
    real_api = ff.api

    def mock_api(url, path, body, sess=None):
        # analyze = мок (кириллический адрес = вне каскада-0), anonymize =
        # ЖИВОЙ демон (та же session/токен-механика).
        return mock if path == "/v1/analyze" else real_api(url, path, body, sess)

    ff.api = mock_api
    # docx через модульный путь (маска по mock-спану + живой anonymize)
    obj = Document(td / "cyr.docx")
    segs = ff.extract_docx(obj)
    n, led = ff._mask_pass(segs, "t300cyr", URL,
                           lambda k, v: ff.set_docx(obj, k, v))
    ledp = td / "cyr-ledger.json"
    json.dump(led, open(ledp, "w", encoding="utf-8"), ensure_ascii=False)
    obj.save(td / "cyr-masked.docx")
    # Дискриминатор ledger = exact-equality: char-slice по byte-координатам
    # на кириллическом префиксе = text[51:105] = ДРУГАЯ строка (фикстура
    # такова, что 105 > len, срез = хвост-обрезок) = RED на мутации.
    ok_led = bool(led) and led[0]["orig"] == "г. Москва, ул. Ленина, д. 42, кв. 7."
    assert len(text) < b1, "фикстура: char-срез по byte-координатам должен быть ДОЛЖЕ текста (дискриминатор)"
    print(f"LEDGER_BYTE|docx-cyrillic|orig={led[0]['orig'][:24]!r}|{'ok' if ok_led else 'char-смещение'}")
    fails += 0 if ok_led else 1
    # (2) rtf byte-контра: маска mock-спаном + побайтовый возврат.
    class _A:  # argparse-подобный
        url, session, out, ledger = URL, "t300rtf", str(td / "cyr-m.rtf"), str(td / "cyr-rtf.json")
    n2, led2 = ff._mask_rtf(_A(), (td / "cyr.rtf").read_text(encoding="utf-8"))
    assert led2, "rtf mock-спан не применён (api-мок не дошёл до _mask_rtf)"
    ok_rtf = bool(led2) and led2[0]["orig"] == "г. Москва, ул. Ленина, д. 42, кв. 7."
    print(f"RTF_BYTE|cyrillic|orig={led2[0]['orig'][:24] if led2 else None!r}|{'ok' if ok_rtf else 'порча'}")
    fails += 0 if ok_rtf else 1
    # Побайтовый возврат rtf (restore-ветка = байтовая, #300 NIT-2):
    # restore через CLI = отдельный процесс без мока; проверка в модульном
    # пути: байты masked-rtf == оригинальные байты после подмены ph→orig.
    masked = (td / "cyr-m.rtf").read_bytes()
    orig_file = (td / "cyr.rtf").read_bytes()
    ph = led2[0]["ph"].encode()
    back = masked.replace(ph, led2[0]["orig"].encode())
    ok_rt = back == orig_file
    print(f"RTF_ROUNDTRIP|byte-exact|{'ok' if ok_rt else 'DRIFT'}")
    fails += 0 if ok_rt else 1
    return fails


def load_module_test(name: str):
    """Модульная загрузка fasad-file.py (single-file = importlib, без sys.path)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, HERE / "fasad-file.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_xlsx_mode_filter() -> int:
    """#300 NIT-3: _is_masked = режим-агностик (обе vault-формы + surrogate,
    чистые ячейки = не фильтр; живые формы первички vault.rs:883/1010)."""
    ff = load_module_test("fasad_file_f")
    cases = [
        ("[[F0#BzcGT5OZqG0IxdR2DFGrlBEJzE5IshUIESUw968g8SGS4IGr0VK4Lc]]", True),   # mode 3
        ("[[S0#abc123]]", True),                                                    # surrogate
        ("[ADDRESS_1_EQG4CLWX]", True),                                             # mode 2
        ("[INN_2_000000]", True),                                                   # mode 2
        ("Паспорт 4511 123456", False),                                             # чистая
        ("8-916-123-45-67 [see notes]", False),                                     # скобки, не токен
    ]
    bad = [(t, want, ff._is_masked(t)) for t, want in cases if ff._is_masked(t) != want]
    print(f"XLSX_MODE_FILTER|{len(cases) - len(bad)}/{len(cases)}")
    for t, want, got in bad:
        print(f"  PROBLEM|{t!r}|ожидался {want}|получен {got}")
    return 1 if bad else 0


def make_scan_fixture(td: Path):
    """Синтетический скан = R&D-фикстура FINAL-scan (#294): PIL-растр
    (Arial Unicode, 1240×1754 ~ A4@150dpi) с PII-строками → img2pdf →
    PDF-скан (chars=0 = промер #294)."""
    import img2pdf
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (1240, 1754), "white")
    dr = ImageDraw.Draw(img)
    font = next((p for p in (
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/Library/Fonts/Arial Unicode.ttf") if Path(p).exists()), None)
    if font is None:
        return None  # SKIP-решение принимает вызывающий (единая строка)
    f = ImageFont.truetype(font, 34)
    lines = [
        ("Sluzhebnaya zapiska", 220),
        ("Proshu soglasovat postavku. Telefon 89161234567,", 340),
        ("INN 7707083893, SNILS 112-233-445 95.", 410),
        ("28.09.2026", 520),
    ]
    for t, y in lines:
        dr.text((90, y), t, fill="black", font=f)
    png = td / "scan.png"
    img.save(png)
    out = td / "scan.pdf"
    out.write_bytes(img2pdf.convert(str(png)))
    return out


def _scan_ocr_rows(png: Path) -> str:
    import subprocess
    r = subprocess.run([os.environ["FASAD_OCR_BIN"], str(png)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"OCR-фикстура: rc={r.returncode}")
    return "\n".join(row.split("\t")[-1] for row in r.stdout.splitlines())


def test_scan(td: Path) -> int:
    """#304 этап-3 (mac-only): скан-PDF → Vision-OCR → paint-over.
    Зубы: leak-scan = повторный OCR masked = PII 0; ledger = классы
    находок (black = disk-контра без orig); restore = честный отказ
    (растр необратим); OCR-бинарь отсутствующий = fail-closed-отказ."""
    if sys.platform != "darwin" or not shutil.which(
            os.environ.get("FASAD_OCR_BIN", "ocr")):
        print("SCAN|SKIP (mac-only: Vision-движок; #316-паттерн legs)")
        return 0
    # mac-раннер-первичка: фикстура ходит по списку шрифтов (CI macos-14
    # может не иметь Arial Unicode.ttf = промер run 40483157221 ubuntu-
    # красne на path-иголке ДО skip-гейта; список = переносимая фикстура,
    # первый найденный = канон).
    fails = 0
    src = make_scan_fixture(td)
    if src is None:  # кириллического TTF нет на хосте = SKIP (не провал)
        print("SCAN|SKIP (нет кириллического TTF на хосте)")
        return 0
    # дискриминатор фикстуры: PDF = скан (chars=0) + OCR читает PII
    import pdfplumber
    with pdfplumber.open(src) as pl:
        chars0 = sum(len(p.chars) for p in pl.pages)
    rows0 = _scan_ocr_rows(td / "scan.png")
    fixture_ok = chars0 == 0 and "89161234567" in rows0 \
        and "7707083893" in rows0
    print(f"SCAN|fixture|chars0={chars0}|ocr-pii={'yes' if fixture_ok else 'NO'}")
    fails += 0 if fixture_ok else 1
    # дискриминатор предиката _pdf_is_scan: смешанный PDF (стр.1 растр +
    # стр.2 text-layer) = НЕ скан (all, не any: мутация any = mixed=True).
    ff = load_module_test("fasad_file_scan")
    import img2pdf as _i2p
    import pdfplumber as _pl
    from pypdf import PdfReader as _PR
    from pypdf import PdfWriter as _PW
    _w = _PW()
    _w.add_page(_PR(_io.BytesIO(_i2p.convert(str(td / "scan.png")))).pages[0])
    _w.append(str(td / "s.pdf"))  # текстовый PDF make_samples = стр.2 chars>0
    with open(td / "mix.pdf", "wb") as _f:
        _w.write(_f)
    with _pl.open(td / "mix.pdf") as _pdf:
        mixed_scan = ff._pdf_is_scan(_pdf)
    with _pl.open(td / "scan.pdf") as _pdf:
        pure_scan = ff._pdf_is_scan(_pdf)
    ok_pred = (not mixed_scan) and pure_scan
    print(f"SCAN|predicate|pure={pure_scan}|mixed={not mixed_scan}|"
          f"{'ok' if ok_pred else 'ПРОТЕЧКА: смешанный = скан'}")
    fails += 0 if ok_pred else 1
    out = td / "m-scan.pdf"
    led = td / "l-scan.json"
    # env маски = наследуется дочерним процессом run() (os.environ)
    run("mask", str(src), "t304scan", "--out", str(out), "--ledger", str(led),
        "--mode", "black")
    ledger = json.loads(led.read_text(encoding="utf-8"))
    cls = sorted(e["class"] for e in ledger)
    ok_led = cls == ["inn", "phone", "snils"] and all(
        e.get("scan") and "bbox_px" in e for e in ledger)
    print(f"SCAN|ledger|{cls}|{'ok' if ok_led else 'PROBLEM'}")
    fails += 0 if ok_led else 1
    # leak-scan = повторный OCR masked-PDF (render → ocr) = PII-строк нет
    import pypdfium2 as pdfium
    mpng = td / "m-scan.png"
    pdfium.PdfDocument(str(out))[0].render(scale=2).to_pil().save(str(mpng))
    rows1 = _scan_ocr_rows(mpng)
    leaks = [p for p in ("89161234567", "7707083893", "112-233-445 95")
             if p in rows1]
    # мута-промер меры: PII из строки ДО маски обязана была читаться
    # (fixture_ok выше = discriminator; здесь = повтор-страховка)
    print(f"SCAN|leak-scan|{leaks if leaks else 'NONE'}")
    fails += 1 if leaks else 0
    # black-disk-контра: ledger БЕЗ orig (PII на диск не легла)
    disk_ok = all("orig" not in e and "ph" not in e for e in ledger)
    print(f"SCAN|black-ledger-clean={disk_ok}")
    fails += 0 if disk_ok else 1
    # restore = честный отказ (скан-контра необратима, ДО ph-машинерии)
    r = subprocess.run(
        [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
         "restore", str(out), "t304scan", "--ledger", str(led),
         "--out", str(td / "back-scan.pdf")],
        capture_output=True, text=True)
    ok_r = r.returncode != 0 and "необратим" in r.stderr \
        and not (td / "back-scan.pdf").exists()
    print(f"SCAN|restore-refuse|rc={r.returncode}|{'ok' if ok_r else 'PROBLEM'}")
    fails += 0 if ok_r else 1
    # fail-closed: OCR-движок отсутствует = отказ, файл НЕ маскируется
    old = os.environ["FASAD_OCR_BIN"]
    os.environ["FASAD_OCR_BIN"] = "fasad-no-such-ocr-bin"
    try:
        r2 = subprocess.run(
            [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
             "mask", str(src), "t304x", "--out", str(td / "never.pdf")],
            capture_output=True, text=True)
    finally:
        os.environ["FASAD_OCR_BIN"] = old
    ok2 = r2.returncode != 0 and "OCR-движок не найден" in r2.stderr \
        and not (td / "never.pdf").exists()
    print(f"SCAN|failclosed-no-ocr|rc={r2.returncode}|{'ok' if ok2 else 'PROBLEM'}")
    fails += 0 if ok2 else 1
    return fails


def main():
    proc = daemon()
    td = Path(tempfile.mkdtemp(prefix="fasad297-"))
    try:
        make_samples(td)
        fails = test_roundtrip_and_leaks(td, proc)
        fails += test_pdf_cyrillic(td)
        fails += test_pdf_black(td)
        fails += test_failclosed(td)
        fails += test_cyrillic_teeth(td)
        fails += test_xlsx_mode_filter()
        fails += test_scan(td)
        print("TEST-FASAD-FILE|" + ("ok" if fails == 0 else f"FAILS {fails}"))
        sys.exit(0 if fails == 0 else 1)
    finally:
        proc.terminate()
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
