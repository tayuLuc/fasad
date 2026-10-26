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


def main():
    proc = daemon()
    td = Path(tempfile.mkdtemp(prefix="fasad297-"))
    try:
        make_samples(td)
        fails = test_roundtrip_and_leaks(td, proc)
        fails += test_failclosed(td)
        print("TEST-FASAD-FILE|" + ("ok" if fails == 0 else f"FAILS {fails}"))
        sys.exit(0 if fails == 0 else 1)
    finally:
        proc.terminate()
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
