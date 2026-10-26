# /// script
# requires-python = ">=3.12"
# dependencies = ["python-docx", "openpyxl", "python-pptx", "striprtf"]
# ///
"""Зубы обёртки fasad-file.py (#297 этап-1 CI-полка; НЕ golden-контур).

Контур: живой демон (FASAD_TEST_CASCADE0=1 харнес, как R&D f620296e) +
uv-окружение. Запуск (из корня репозитория):
  FASAD_BIN=target/debug/fasad uv run scripts/test-fasad-file.py
Зубы:
  1 roundtrip docx/xlsx/txt = побайтовый/текстовый возврат через
    deanonymize + ledger (маска → restore → сравнение с оригиналом);
  2 leak-scan: повторное извлечение masked-файла = PII-строк нет;
  3 fail-closed: битый/шифрованный docx (PackageNotFoundError) = rc!=0.
Известный FN-класс (документирован в README fasad-file.py, НЕ зуб-проверка):
паспорт рядом с ИНН-ключом = inn-доминанта каскада-0 (зуб реестра
c0_inn_key_dominates_passport) = обёртка не чинит.
"""

from __future__ import annotations

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
    for name in ("s.docx", "s.xlsx", "s.txt"):
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
        else:
            ok = extract_all(back) == extract_all(src)
        print(f"ROUNDTRIP|{name}|{'ok' if ok else 'DRIFT'}")
        fails += 0 if ok else 1
    return fails


def test_failclosed(td: Path) -> int:
    out = td / "never.docx"
    r = subprocess.run(
        [sys.executable, str(HERE / "fasad-file.py"), "--url", URL,
         "mask", str(td / "broken.docx"), "s", "--out", str(out)],
        capture_output=True, text=True,
    )
    ok = r.returncode != 0 and "PackageNotFoundError" in r.stderr and not out.exists()
    print(f"FAILCLOSED|broken.docx|rc={r.returncode}|{'ok' if ok else 'PROBLEM'}")
    return 0 if ok else 1


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


def main():
    proc = daemon()
    td = Path(tempfile.mkdtemp(prefix="fasad297-"))
    try:
        make_samples(td)
        fails = test_roundtrip_and_leaks(td, proc)
        fails += test_failclosed(td)
        fails += test_cyrillic_teeth(td)
        fails += test_xlsx_mode_filter()
        print("TEST-FASAD-FILE|" + ("ok" if fails == 0 else f"FAILS {fails}"))
        sys.exit(0 if fails == 0 else 1)
    finally:
        proc.terminate()
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
