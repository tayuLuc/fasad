#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rrn_bench — конвертер внешнего кросс-бенча redmadrobot-rnd/pii_benchmark (issue #209).
"""`test.csv` → внутренний JSONL с байтовыми спанами (кросс-мера границ, не гейт).

Владелец контура: `data/bench-external/README.md` (пины, license, sha256, решения).
Рулинг оператора 24.10 (`data/golden/README.md` §«Рюлинг оператора 24.10»): внешние
MIT-бенчи тащим в git; данные лежат в `data/bench-external/redmadrobot-pii-benchmark/`,
здесь — только чтение из репозитория (HF-кеш = канал доставки, НЕ источник чтения).
Кросс-бенч = read-only мера; `data/golden/` остаётся единственным эталоном recall.

Первичка формата (промер 24.10 snapshot f77ea83…, файл в репо):
  cols `text,tokens,ner_tags`; `tokens`/`ner_tags` — JSON-списки равной длины
  (промер: расхождений 0 из 2841); BIO 21 тип + `O`.

Разрешение токенов (главная ловушка формата, промер 24.10):
  * `text` НЕ равен конкатенации токенов и не равен join(" "): токены склеены с
    произвольными пробельными разрывами (row1: `…УЛ . РОКОСС…` vs `…УЛ. РОКОСС…`);
  * токен `#` в `text` записан дословно (44 строки), а его канонизация `#`→`.`
    нужна в 193 строках (токенизатор свернул `#` в `.`);
  * 2 строки (`www.REMONT…`, «İ KASI») матчатся только регистронезависимо;
  * 1 строка заканчивается висячим пробелом (`…рт. ст. `).
  Алгоритм (промер: 2841/2841 покрывают файл): кандидаты токена = вхождения
  канона `#`→`.` (длина канона) + сырого токена (сырая длина) в `text`, DFS
  слева-направо с откатом, разрывы между токенами = только пробелы; при неудаче
  — второй проход casefold-кандидатами; покрытие = `text` целиком (хвостовой
  whitespace разрешён). Валидация каждой строки: exact-срез == токен, монотонность,
  gap-пробелы, полное покрытие; невалидная = `CONV|fail` и fail-closed.

Границы: offsets в `text` = СИМВОЛЫ; наш контракт = байты
(`crates/guard-types/src/span.rs`, SPEC §8: демон отдаёт и `byte_start`/`byte_end`,
и символьные `start`/`end`). Конверсия char→byte точная (`char2byte`), тест на
кириллице в `selftest`.

Span-объединение: соседние `I-<TYP>` продлевают `B-<TYP>`. Соседние РАЗНЫЕ типы,
дающие один наш класс (FIRST+LAST, STREET+CITY), НЕ склеиваются: их разметка =
отдельные спаны (их же README: «adjacent same-category spans merged» = coarse
merge на их стороне matching; у нас matching решает `rrn_score.py`).

Запуск (из корня репозитория):
  uv run --locked python tools/bench/rrn_bench.py            # конвертировать
  uv run --locked python tools/bench/rrn_bench.py --selftest # тесты конверсии
  uv run --locked python tools/bench/rrn_bench.py --audit    # счётчики без записи
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "data" / "bench-external" / "redmadrobot-pii-benchmark"
DEFAULT_CSV = BENCH_DIR / "test.csv"
DEFAULT_OUT = ROOT / "data" / "bench-external" / "crossref.jsonl"

# Пин живым GET первичка-контура (промер 24.10; README-владелец дублирует).
PIN_SHA256 = "6bf544a380a3ee5bec94b946124bea3afaecce49e734679ad0f0c0e7c12977bb"
PIN_REVISION = "f77ea831274daf980cc45c61a93c226be9d978d6"
N_ROWS = 2841  # карточка датасета: 2841 строк (сверятся с фактом, молча не доверяем)

# Отображение их 21 типа → наши 8 классов схемы (config/schema.default.json,
# первичка lockr_tags поля). Явный список: всё вне = None (out-of-schema),
# считается отдельно и в F1 по нашим 8 НЕ попадает.
THEIR_TYPES = [
    "BIRTH_CERTIFICATE", "CITY", "COUNTRY", "CREDIT_CARD", "DISTRICT",
    "DRIVER_LICENSE", "EMAIL", "FIRST_NAME", "HOUSE", "INN", "IP_ADDRESS",
    "LAST_NAME", "MIDDLE_NAME", "MILITARY_ID", "OMS", "PASSPORT", "PHONE",
    "REGION", "SNILS", "STREET", "URL",
]
TYPE_MAP: dict[str, str | None] = {
    "FIRST_NAME": "person_name",
    "LAST_NAME": "person_name",
    "MIDDLE_NAME": "person_name",
    "COUNTRY": "address",
    "REGION": "address",
    "DISTRICT": "address",
    "CITY": "address",
    "STREET": "address",
    "HOUSE": "address",
    "INN": "inn",
    "SNILS": "snils",
    "CREDIT_CARD": "card_pan",
    "PHONE": "phone",
    "EMAIL": "email",
    "PASSPORT": "passport",
    "BIRTH_CERTIFICATE": None,
    "DRIVER_LICENSE": None,
    "IP_ADDRESS": None,
    "MILITARY_ID": None,
    "OMS": None,
    "URL": None,
}
OUR_CLASSES = ["person_name", "inn", "snils", "card_pan", "phone",
               "email", "address", "passport"]

sys.setrecursionlimit(1_000_000)  # DFS по токенам: строка до ~900 токенов (промер)


def canon(tok: str) -> str:
    """`#`→`.` — единственная известная систематическая подмена токенизатора."""
    return tok.replace("#", ".")


def _find_all(hay: str, needle: str) -> list[int]:
    out: list[int] = []
    st = 0
    if not needle:
        return out
    while True:
        k = hay.find(needle, st)
        if k < 0:
            return out
        out.append(k)
        st = k + 1


def _occurrences(text: str, toks: list[str], fold: bool) -> list[list[tuple[int, int]]]:
    """Кандидаты `(start, len)` каждого токена в `text` (char-координаты).

    Пустой список у токена = «в тексте не встречается» (кроме пустого токена —
    у него кандидатов нет по построению, DFS обравляет его zero-width).
    """
    T = text.lower() if fold else text
    cands: list[list[tuple[int, int]]] = []
    for t in toks:
        s: set[tuple[int, int]] = set()
        if not t:
            # пустой токен (промер: ровно 1 в файле, row1432, тег O): zero-width,
            # в тексте отсутствует физически — кандидата нет, DFS ставит его в prev
            cands.append([])
            continue
        for needle in ({canon(t), t} if not fold else {canon(t).lower()}):
            nd = needle.lower() if fold else needle
            for k in _find_all(T, nd):
                s.add((k, len(needle)))
        cands.append(sorted(s))
    return cands


def align(text: str, toks: list[str]) -> tuple[list[int], list[int], int] | None:
    """char-начало и длина каждого токена в `text`; режим = 0 exact / 1 fold.

    DFS слева-направо: кандидат >= prev_end, разрыв = только пробелы; конец
    последнего токена = `len(text)` (допускается висячий хвостовой whitespace —
    промер: 1 строка). Пустой токен (промер: нули в файле) ломает выравнивание →
    строка в `parse_fail`, молча не проглатываем.
    """
    m = len(toks)
    n = len(text)
    targets = {n, len(text.rstrip())}
    for fold in (False, True):
        cands = _occurrences(text, toks, fold)
        starts = [0] * m
        lens = [0] * m

        def go(i: int, prev: int, cands=cands, starts=starts, lens=lens) -> bool:
            if i == m:
                return prev in targets
            if not toks[i]:  # пустой токен (промер: ровно 1 в файле, row1432, тег O)
                starts[i] = prev
                lens[i] = 0
                return go(i + 1, prev)
            for k, lc in cands[i]:
                if k < prev:
                    continue
                if text[prev:k].strip():
                    break
                starts[i] = k
                lens[i] = lc
                if go(i + 1, k + lc):
                    return True
            return False

        if go(0, 0):
            return starts, lens, (1 if fold else 0)
    return None

def spans_from_bio(toks: list[str], tags: list[str], starts: list[int],
                   lens: list[int]) -> tuple[list[dict], int]:
    """BIO → спаны (char-границы) + счётчик склеек I-к-B того же типа."""
    out: list[dict] = []
    merged = 0
    cur: dict | None = None
    for i, tag in enumerate(tags):
        if tag == "O":
            if cur is not None:
                out.append(cur)
                cur = None
            continue
        if not tag.startswith(("B-", "I-")):
            raise ValueError(f"нераспознанный тег {tag!r}")
        typ = tag[2:]
        start = starts[i]
        end = starts[i] + lens[i]
        if lens[i] == 0:
            # пустой токен (zero-width): span не двигает, I-к-B не продлевает
            continue
        if cur is not None and cur["their_type"] == typ and tag.startswith("I-"):
            cur["end_char"] = end
            merged += 1
            continue
        if cur is not None:
            out.append(cur)
        cur = {"their_type": typ, "our_class": TYPE_MAP[typ],
               "start_char": start, "end_char": end}
    if cur is not None:
        out.append(cur)
    return out, merged


def char2byte(text: str) -> list[int]:
    """Карта char-index → byte-offset (длина len(text)+1, терминальный слот)."""
    m: list[int] = [0] * (len(text) + 1)
    b = 0
    for i, ch in enumerate(text):
        m[i] = b
        b += len(ch.encode())
    m[len(text)] = b
    return m


def convert(text: str, tokens: list[str], tags: list[str]) -> dict:
    """Одна строка CSV → запись кросс-референса (байтовые границы в `spans`)."""
    al = align(text, tokens)
    if al is None:
        return {"text": text, "spans": [], "out_of_schema": [], "parse_fail": True,
                "fold": -1, "merged_i_tokens": 0}
    starts, lens, mode = al
    bio, merged = spans_from_bio(tokens, tags, starts, lens)
    m = char2byte(text)
    spans: list[dict] = []
    oos: list[dict] = []
    for s in bio:
        rec = {"start_char": s["start_char"], "end_char": s["end_char"],
               "start_byte": m[s["start_char"]], "end_byte": m[s["end_char"]],
               "their_type": s["their_type"], "our_class": s["our_class"]}
        (spans if s["our_class"] else oos).append(rec)
    return {"text": text, "spans": spans, "out_of_schema": oos,
            "parse_fail": False, "fold": mode, "merged_i_tokens": merged}


def _validate(rec: dict) -> bool:
    """Инварианты строки: байтовый срез == char-срез, монотонность, границы."""
    text = rec["text"]
    tb = text.encode()
    for s in rec["spans"] + rec["out_of_schema"]:
        cs, ce = s["start_char"], s["end_char"]
        bs, be = s["start_byte"], s["end_byte"]
        if not (0 <= cs < ce <= len(text)):
            return False
        if text[cs:ce].encode() != tb[bs:be]:
            return False
    allsp = sorted(rec["spans"] + rec["out_of_schema"], key=lambda x: x["start_char"])
    prev_end = -1
    for s in allsp:
        if s["start_char"] < prev_end:
            return False
        prev_end = s["end_char"]
    return True


def rows_from_csv(csv_path: Path):
    with csv_path.open(newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        assert rd.fieldnames is not None, "пустой CSV"
        if list(rd.fieldnames) != ["text", "tokens", "ner_tags"]:
            sys.exit(f"FAILcols {rd.fieldnames} — формат датасета поехал (первичка README)")
        for i, row in enumerate(rd, start=1):
            yield i, row


def audit(csv_path: Path, *, verbose: bool) -> dict:
    """Прогон конвертера по всему CSV со счётчиками (и для --audit, и для selftest)."""
    rows = 0
    fails: list[int] = []
    n_spans = n_oos = merged = fold_rows = 0
    per_type: dict[str, int] = {}
    per_class: dict[str, int] = {}
    for i, row in rows_from_csv(csv_path):
        rows += 1
        toks = json.loads(row["tokens"])
        tags = json.loads(row["ner_tags"])
        if len(toks) != len(tags):
            fails.append(i)
            continue
        rec = convert(row["text"], toks, tags)
        if rec["parse_fail"]:
            fails.append(i)
            continue
        if not _validate(rec):
            fails.append(i)
            continue
        n_spans += len(rec["spans"])
        n_oos += len(rec["out_of_schema"])
        merged += rec["merged_i_tokens"]
        fold_rows += 1 if rec["fold"] == 1 else 0
        for s in rec["spans"]:
            per_class[s["our_class"]] = per_class.get(s["our_class"], 0) + 1
        for s in rec["out_of_schema"]:
            per_type[s["their_type"]] = per_type.get(s["their_type"], 0) + 1
    stats = {"rows": rows, "parse_fail": len(fails), "fail_rows": fails[:10],
             "mapped_spans": n_spans, "oos_spans": n_oos,
             "merged_i_tokens": merged, "fold_rows": fold_rows,
             "per_class": per_class, "per_oos_type": per_type}
    if verbose:
        head = {k: v for k, v in stats.items()
                if k not in ("per_class", "per_oos_type", "fail_rows")}
        print("AUDIT|" + "|".join(f"{k}|{v}" for k, v in head.items()))
        for c in OUR_CLASSES:
            print(f"AUDIT|class|{c}|{per_class.get(c, 0)}")
        for t in THEIR_TYPES:
            if TYPE_MAP[t] is None:
                print(f"AUDIT|oos|{t}|{per_type.get(t, 0)}")
    return stats


def selftest() -> int:
    """Тесты конверсии: кириллица char→byte, BIO-склейка, #→., отображения."""
    fails = 0

    def check(name: str, ok: bool) -> None:
        nonlocal fails
        print(f"SELFTEST|{name}|{'ok' if ok else 'FAIL'}")
        fails += 0 if ok else 1

    # 1. Кириллица: байты ≠ символы. Спан «45 08 455561» = char 8..20 = byte 15..27.
    text = "Паспорт 45 08 455561 выдан"
    toks = ["Паспорт", " ", "45", " ", "08", " ", "455561", " ", "выдан"]
    tags = ["O", "O", "B-PASSPORT", "I-PASSPORT", "I-PASSPORT", "I-PASSPORT",
            "I-PASSPORT", "O", "O"]
    rec = convert(text, toks, tags)
    check("cyrillic_no_parse_fail", not rec["parse_fail"])
    sp = rec["spans"]
    check("one_span_after_merge", len(sp) == 1)
    s = sp[0]
    check("byte_slice_matches_text",
          text.encode()[s["start_byte"]:s["end_byte"]].decode() == "45 08 455561")
    check("class_mapping", s["our_class"] == "passport")
    check("byte_gt_char_on_cyrillic", s["start_byte"] > s["start_char"])

    # 2. FIRST + LAST рядом = ДВА спана (их разметка, не склеиваем).
    rec2 = convert("Иванов Иван", ["Иванов", " ", "Иван"],
                   ["B-LAST_NAME", "O", "B-FIRST_NAME"])
    check("adjacent_names_not_merged", len(rec2["spans"]) == 2)
    check("both_map_person_name",
          {x["our_class"] for x in rec2["spans"]} == {"person_name"})

    # 3. Out-of-schema: OMS уезжает в out_of_schema.
    rec3 = convert("Полис 1601195448188067", ["Полис", " ", "1601195448188067"],
                   ["O", "O", "B-OMS"])
    check("oms_out_of_schema", not rec3["spans"] and len(rec3["out_of_schema"]) == 1)

    # 4. #→. канон: канон токена «#» = «.»; в тексте остался литеральный «#» —
    #    матчит сырой токен (row1 «.RU»/«#RU»; row48 «.»/«#»).
    rec4 = convert("#дефолт код", ["#дефолт", "код"], ["B-CITY", "O"])
    check("hash_literal_matches_raw",
          not rec4["parse_fail"] and len(rec4["spans"]) == 1
          and rec4["spans"][0]["their_type"] == "CITY")
    rec4b = convert(".дефолт код", ["#дефолт", "код"], ["B-CITY", "O"])
    check("hash_canon_matches_dot",
          not rec4b["parse_fail"] and len(rec4b["spans"]) == 1)

    # 5. Регистронезависимый фолбэк (класс row1: токены «WWW…» в тексте «www…»:
    #    exact не находит, fold находит; span = «www» в регистре текста).
    rec5 = convert("ivan", ["IVAN"], ["B-FIRST_NAME"])
    check("casefold_fallback", not rec5["parse_fail"] and rec5["fold"] == 1
          and len(rec5["spans"]) == 1)
    check("casefold_span_text",
          not rec5["parse_fail"]
          and rec5["text"].encode()[rec5["spans"][0]["start_byte"]:
                                    rec5["spans"][0]["end_byte"]].decode()
          == "ivan")
    # 5b. Пустой токен (промер: ровно 1 в файле, row1432, тег O) = zero-width
    #     на конце строки: выравниваем, span не двигает.
    rec5b = convert("ПАО СБЕРБАНК", ["ПАО", "СБЕРБАНК", ""], ["O", "B-CITY", "O"])
    check("empty_token_zero_width",
          not rec5b["parse_fail"] and len(rec5b["spans"]) == 1)

    # 6. Невыравниваемая строка = parse_fail (fail-closed, не угадайка).
    rec6 = convert("совсем другой текст", ["совсем", " ", "НЕДРУГОЙ", " ", "текст"],
                   ["O", "O", "O", "O", "O"])
    check("unalignable_is_parse_fail", rec6["parse_fail"])

    # 7. Терминальный слот карты char→byte (кириллица 2 байта/символ, латиница 1).
    cyr = "абв"
    m = char2byte(cyr)
    check("char2byte_cyrillic", m[3] == 6)
    lat = "ivanabc"
    m2 = char2byte(lat + cyr)
    check("char2byte_mixed", m2[7] == 7 and m2[10] == 13)

    # 8. Висячий хвостовой пробел в text (row1381-класс).
    rec8 = convert("статья 750 мм рт. ст. ", ["статья", "750", "мм", "рт", ".", "ст", "."],
                   ["O", "O", "O", "O", "O", "O", "O"])
    check("trailing_space_ok", not rec8["parse_fail"])
    print(f"SELFTEST|total_fail|{fails}")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--audit", action="store_true",
                    help="только счётчики по всему CSV, без записи JSONL")
    ap.add_argument("--no-sha-gate", action="store_true",
                    help="не проверять sha256 (ad-hoc промеры; по умолчанию fail-closed)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    csv_path = Path(args.csv)
    if not csv_path.is_file():
        sys.exit(f"FAIL нет файла {csv_path} — данные бенча живут в git "
                 f"(data/bench-external/redmadrobot-pii-benchmark/); "
                 f"для обновления — `uvx --from huggingface_hub hf download "
                 f"redmadrobot-rnd/pii_benchmark --repo-type dataset` в HF-кеш "
                 f"и перенос snapshot-файлов (ревизия {PIN_REVISION})")
    digest = hashlib.sha256(csv_path.read_bytes()).hexdigest()
    if digest != PIN_SHA256 and not args.no_sha_gate:
        sys.exit(f"FAIL sha256 test.csv = {digest} != пин {PIN_SHA256} "
                 f"(дрейф первички: переснять revisions/last-modified, обновить "
                 f"пин в README + здесь; --no-sha-gate для ad-hoc)")
    stats = audit(csv_path, verbose=True)
    if stats["rows"] != N_ROWS:
        sys.exit(f"FAIL строк {stats['rows']} != {N_ROWS} (промер карточки)")
    if stats["parse_fail"]:
        sys.exit(f"FAIL нераспознанных строк {stats['parse_fail']} "
                 f"(первые {stats['fail_rows']}) — конвертер не гадаем")
    if args.audit:
        return 0
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as w:
        for i, row in rows_from_csv(csv_path):
            toks = json.loads(row["tokens"])
            tags = json.loads(row["ner_tags"])
            rec = convert(row["text"], toks, tags)
            if rec["parse_fail"] or not _validate(rec):
                sys.exit(f"FAIL строка {i}: выравнивание/валидация — молча не пишем")
            rec["id"] = f"rrn{i:05d}"
            del rec["parse_fail"], rec["merged_i_tokens"], rec["fold"]
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    print(f"CONV|wrote|{out_path}|rows|{n}|spans|{stats['mapped_spans']}"
          f"|oos|{stats['oos_spans']}|sha256|{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
