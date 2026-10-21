#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# restore_integrity — метрика #60 п.3: restoration-integrity ПОЛНОГО контура.
"""
Метрика (формулировка #60 п.3): доля побайтовых возвратов исходнику на
мультиымянном документе, рядом с recall (#14), который её не ловит вовсе.
Формула строки: строка прошла analyze → anonymize → deanonymize и вернула
РОВНО исходные байты. k/N по строкам recall-сплита golden-v1 (N=150 годных к
прогону; отрицательный сплит не гоняется: у него нет права на маскирование,
FP-контур union-recall'а).

Чем этот промер ОТЛИЧАЕТСЯ от `pool_probe -- integrity` (шаг 7d, #70):
  pool_probe мерит движок guard-vault на 27 годных ФИО в обход HTTP, в обход
  детекта, в обход меточного пути. #60 п.3 требует текстов N=204 и целостности
  ОБРАТНОГО ХОДА КОНТУРА (демон `/v1/anonymize` → `/v1/deanonymize`), с
  пер-классовым разрезом.

Продуктовый путь (инвариант #60 п.4 «мерим = гоняем»): демон `fasad`,
`POST /v1/analyze` (audit_only) → `POST /v1/anonymize` → `POST /v1/deanonymize`,
режим хранилища 2 (`FASAD_VAULT_MODE=session`) — единственный режим, где у
демона есть суррогатный путь ФИО; stateless (#3) разворачивает самовскрывающимся
маркером, и метрика суррогатной целостности к нему не относится (нулевая по
конструкции, SPEC §4, #70).

Fail-closed счёт: не-2xx на любом шаге = строка НЕ вернулась побайтово (в k не
идёт), код причины сохраним в разрез `refuse_codes`. Молчание = не-возврат.

Положительный контроль (доктрина ложно-зелёного: зелёная проверка без живого
контроля = ничто; контроль обязан быть НА ДИСКРИМИНИРУЮЩЕМ входе):
  1. `control|clean`    — живая сессия: подмена разворачивается, byte_exact=1;
  2. `control|sabotage` — та же подмена после DELETE сессии: разворот обязан
     ОТКАЗАТЬ (`422 unresolved_token`), byte_exact=0.
Контроль мёртв (rc=2, метрика не засчитывается) в любую сторону: clean не
развернулся (харнес считает не то) ИЛИ sabotage развернулся (отказ разворота
сломан = тихая потеря/подмена ПДн — ровно тот дефект, против которого
реверс-индекс #70).

Разрез по оператору маскирования (replace = гладкий суррогат ФИО, mask =
метка/маркер): «restoration-integrity 100 %» при полном уходе ФИО в метки была
бы пустой метрикой, поэтому доля суррогатного пути печатается числом.

Монтирование: union-recall в CI не смонтирован (промер: grep `.github/`
union-recall — ноль; тяжеловесы локальные, модель 879 МБ вне git), поэтому и
эта нога — локальная (`just check`), в CI не монтируется (решение по образцу
union-recall, записано в тело PR).

Запуск (щадящий режим 21.10: nice, 2 треда демона, один прогон за раз):
  cargo build --bin fasad
  nice -n 10 python3 tools/metrics/restore_integrity.py --out /tmp/restore_r1.jsonl
  # = `just restore-integrity` (нога cascade-0-only).
  # Нога на смонтированном весе (каскады 1–2 маскируют детектом) —
  # `just restore-integrity-full`: сборка `--features guard-daemon/ort-inference`
  # на dylib (контраонта crates/guard-daemon/README.md §«Как включить монтаж»),
  # FASAD_MODEL_DIR=~/.cache/fasad-models, FASAD_TIMEOUT_MS=10000 (на смонтированном
  # пути дефолт 3000 мс не вмещает Decide-чанк, README §env, промер ревью #97).
  # Стадия промера ПЕЧАТАЕТСЯ в `RESTORE|daemon|stage` по /health (первичка).
Опции: `--limit N`, `--thr`, `--daemon PATH`, `--out ФАЙЛ`.
Детерминированность: RNG в пайплайне нет (seed: n/a); входы — sha256 датасета
(гейт B2, пролог прогона) и схемы. Повтор прогона при тех же входах обязан дать
совпадающие строки `RESTORE|` (сверка diff'ом двух `--out`), кроме
`RESTORE|daemon` (порт и tmp-путь лога — заведомо недетерминированные поля, не
метрика; та же доктрина, что исключение `UNION|cascade0` из diff'а).
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
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "data" / "golden" / "golden-v1.jsonl"
B2_TEST = ROOT / "crates" / "guard-detectors" / "tests" / "golden_v1.rs"
SCHEMA_FILE = ROOT / "config" / "schema.default.json"
Z95 = 1.959963984540054  # docs/dep-verify-algorithms.md §8 (та же константа, что union_recall)

# Классы по README датасета §«Категории»: суррогатный путь (оператор replace)
# доступен только person_name; bik/bank_account — negative-бэйти, в recall их нет.
SURROGATE_CLASSES = {"person_name"}
LABEL_CLASSES = {"address", "email", "phone", "card_pan", "inn", "snils",
                 "ogrn", "ogrnip", "iban", "passport"}


def wilson(k: int, n: int) -> tuple[float, float]:
    """95 % Wilson CI, доля (не %). Формула docs/dep-verify-algorithms.md §8.

    Локальная, а не из union_recall: тот на уровне модуля тянет
    numpy/onnxruntime/tokenizers, которых нет в проектном .venv и которые этой
    метрике не нужны (инференса здесь нет). Якоря §8 промеряются на старте
    прогона (PRECHECK|wilson), расхождение > 0.01 % = красный rc=2.
    """
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + Z95 * Z95 / n
    centre = (p + Z95 * Z95 / (2 * n)) / denom
    half = Z95 / denom * math.sqrt(p * (1 - p) / n + Z95 * Z95 / (4 * n * n))
    return (max(0.0, centre - half), min(1.0, centre + half))


def byte_eq(got: str | None, want: str) -> bool:
    """ЕДИНСТВЕННАЯ точка побайтовой сверки метрики (ревью #139 64cb25c2).

    Мутационный промер: до этого compare стоял в трёх местах (run_row,
    control, perturbation leg-B), и подмена ЛЮБОГО из них на константу True
    оставляла остальные зелёными — positive control мерил свой же предикат, а
    не call-site (реестр ложно-зелёных #19). Теперь весь «exact» проходит
    через одну функцию, а `comparator_selftest()` каллит её на заведомо
    искажённом входе (подставленный deanonymize-ответ) и на побайтовом
    совпадении: зелёный без различения = rc=2.
    """
    return got is not None and got.encode("utf-8") == want.encode("utf-8")


def comparator_selftest() -> int:
    """Positive control ЕДИНОЙ сверки (реестр #19: контроль мерит call-site).

    Три обязательных исхода на фикстурах, которым мы верим по построению:
      равные строки            → True;
      байт в хвосте (не-побайт) → False;
      None (не-200 ответ)       → False.
    Подмена компаратора константой валит как минимум один из них.
    """
    a = "Клиент [[F0#abc]] ИНН 7714161210"
    checks = (byte_eq(a, a), byte_eq(a + "X", a), byte_eq(None, a))
    if checks != (True, False, False):
        print(f"RESTORE|comparator|DEAD|{checks} != (True,False,False)", file=sys.stderr)
        return 2
    print("RESTORE|comparator|ok|equal=True|tampered=False|none=False")
    return 0


def wilson_anchors() -> int:
    """Живость формулы по таблице §8: 48/50, 49/50, 50/50 (тот же контроль, что union)."""
    for k, n, lo, hi in ((48, 50, 86.540, 98.896), (49, 50, 89.505, 99.646),
                         (50, 50, 92.865, 100.000)):
        a, b = (100 * wilson(k, n)[0], 100 * wilson(k, n)[1])
        if abs(a - lo) > 0.01 or abs(b - hi) > 0.01:
            print(f"FAIL wilson {k}/{n}: {a:.3f},{b:.3f} != {lo},{hi}", file=sys.stderr)
            return 2
    print("PRECHECK|wilson|anchors|48/50+49/50+50/50|ok")
    return 0


class Tee:
    """stdout + файл сырого прогона (тот же контракт, что union_recall.Tee:
    flush на каждую строку, иначе долгий прогон выглядит зависшим)."""

    def __init__(self, fh):
        self.fh = fh

    def write(self, s: str) -> None:
        self.fh.write(s)
        self.fh.flush()
        sys.__stdout__.write(s)
        sys.__stdout__.flush()

    def flush(self) -> None:
        if not self.fh.closed:
            self.fh.flush()


def load_recall_rows() -> list[dict]:
    rows = []
    with GOLDEN.open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            if r["split"] == "recall":
                rows.append(r)
    return rows


def daemon_start(binary: str) -> tuple[subprocess.Popen, str, str]:
    """Продуктовый демон в режиме хранилища 2: FASAD_PORT=0, порт из баннера.

    От union_recall.daemon_start отличается ОДНИМ фактом — режимом vault:
    метрика обратного хода суррогатов живёт только в режиме 2 (stateless
    разворачивает самовскрывающимся маркером, SPEC §3.3). Копия, а не импорт:
    union_recall на уровне модуля тянет numpy/onnxruntime (их нет в проектном
    .venv), и ради одной строки env тянуть весь инференсный стек в метрику,
    инференса не меряющую, — путь к «метрика умерла, потому что ort-окружение
    сдвинулось» (#81). Свой process group + reap: сирота-демон на loopback
    после SIGTERM харнесу — промер 21.10, воспроизведён здесь же.
    """
    if not Path(binary).is_file():
        sys.exit(f"FAIL бинарь демона отсутствует: {binary} (cargo build --bin fasad)")
    log = tempfile.NamedTemporaryFile(prefix="restore-integrity-daemon-", suffix=".log",  # noqa: SIM115
                                      delete=False, mode="w", encoding="utf-8")
    env = dict(os.environ)
    env.update({"FASAD_PORT": "0", "FASAD_MLOCK": "best_effort",
                "FASAD_VAULT_MODE": "session", "FASAD_THREADS": "2"})
    proc = subprocess.Popen([binary], stdout=log, stderr=subprocess.STDOUT, env=env,
                            cwd=ROOT, start_new_session=True)

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
    # 20 с ожидания: смонтированный каскад грузит веса в отдельном потоке
    # инференса, и баннер print'ится ДО примонта (`cascades::startup` идёт
    # после печати listen-строки, main.rs:92); ждём ровно столько, сколько
    # нужно ему, а не баннеру (промер: монтаж ~3 с на warm cache).
    for _ in range(400):
        banner = Path(log.name).read_text(encoding="utf-8")
        if "listening on" in banner:
            break
        time.sleep(0.05)
    m = re.search(r"listening on http://([\d.]+):(\d+)/health", banner)
    if not m:
        rc = proc.poll()
        reap()
        sys.exit(f"FAIL демон не поднялся (rc={rc}): {banner!r} ({log.name})")
    return proc, f"http://{m.group(1)}:{m.group(2)}", log.name


class Api:
    """Тонкий HTTP-клиент продуктового демона. Без retry: отказ = событие промера."""

    def __init__(self, base: str):
        self.base = base

    def call(self, path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"content-type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 — loopback
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                return e.code, {"raw": raw[:200].decode("utf-8", "replace")}

    def delete(self, path: str) -> int:
        # Без data= (в отличие от POST-хелпера выше): пустое тело с
        # `Content-Type: application/json` — лишний риск для продуктового
        # разборщика, DELETE его не требует (первичка: invalidate_handler).
        req = urllib.request.Request(self.base + path, method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return resp.status


class _MutantApi:
    """Декоратор живого `Api`: «read кэша в обход реверс-индекса» (мутант v3).

    `deanonymize` отвечает побайтовым исходником при `restore_refused=0` —
    ровно то состояние, в котором метрика была бы ложно-зелёной, если б
    сверка мерила предикат, а не call-site (реестр #19). Остальные вызовы
    идут демону без изменений.
    """

    def __init__(self, inner: Api, original_text: str):
        self._inner = inner
        self._original = original_text

    def call(self, path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
        st, resp = self._inner.call(path, body, headers)
        if path == "/v1/deanonymize" and st == 200:
            return 200, {"text": self._original, "restore_refused": 0}
        return st, resp

    def delete(self, path: str) -> int:
        return self._inner.delete(path)


def control_on_mutant(api: Api) -> int:
    """Positive control CALL-SITE единой сверки (ревью #139 64cb25c2, реестр
    #19: «контроль мерит предикат, а не call-site»).

    Тот же `control(api)` на том же входе, но deanonymize подменён мутантом,
    возвращающим исходник при нулевом отказе. Честный компаратор sabotage-ногу
    НЕ краснит (отказ есть, exact=0); мутант её краснит (is sabotage exact=1 →
    control DEAD rc=2). Значит rc(control_on_mutant) == 2 — доказательство, что
    control-нога жива на реальном пути запроса; rc == 0 = сверка константа,
    метрике нельзя верить (rc=2).
    """
    rc = control(_MutantApi(api, CONTROL_TEXT))
    if rc == 0:
        print("RESTORE|comparator|mutant|DEAD: control на мутанте «read кэша»"
              " зелёный — побайтовая сверка мерит предикат, а не call-site",
              file=sys.stderr)
        return 2
    print("RESTORE|comparator|mutant|ok|control-на-мутанте-красный")
    return 0


def _prio(s: dict) -> tuple[int, int]:
    """Ключ порядка при снятии пересечений: чексумма важнее модели.

    Инверсия правила DETEKTA, а не наш вымысел: скор детерминированного
    валидатора = 1.0 и нейросеть его не понижает (AGENTS §Инженерные
    инварианты; первичка `Hit::score` = DetectionSource::DeterministicW,
    `validator` — непустое имя вето в ответе `/v1/analyze`,
    pipeline.rs:190/362). Поэтому: детерминированный спан (validator != null)
    бьёт модельный; внутри группы — по порядку схемы
    (config/schema.default.json), при равенстве — более длинный.
    """
    det = 0 if s.get("validator") else 1
    return (det, CLASS_ORDER.get(s["entity_type"], 99))


def _load_class_order() -> dict[str, int]:
    """Порядок классов продуктовой схемы; не хардкод — схема правится
    `PUT /v1/schema`, и хардкод разъехался бы с ней молча. validator_only
    (ogrn/ogrnip/iban) дописываются после модельных: их закрывает каскад 0."""
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    order = {c["id"]: i for i, c in enumerate(schema["classes"])}
    base = len(order)
    for i, c in enumerate(schema.get("validator_only", [])):
        order[c["id"]] = base + i
    return order


CLASS_ORDER = _load_class_order()


def resolve_overlap(api: Api, hdr: dict, payload: dict) -> tuple[int, dict, int]:
    """Клиентская декомпозиция пересечений спанов (контракт 422 bad_span).

    Возвращает (status, answer, сколько спанов отброшено). Правило: при
    пересечении байтов побеждает больший приоритет схемы, при равенстве —
    БОЛЕЕ ДЛИННЫЙ спан (стабильный порядок: сортировка (−prio, −len, индэкс)).
    Отброшенные спаны считаются — метрика не имеет права на «тихо убрали».
    """
    spans = sorted(payload["spans"], key=lambda s0: (_prio(s0),
                                                      -(s0["byte_end"] - s0["byte_start"])))
    kept: list[dict] = []
    dropped = 0
    taken: list[tuple[int, int]] = []
    for s0 in spans:
        if any(s0["byte_start"] < b1 and a1 < s0["byte_end"] for a1, b1 in taken):
            dropped += 1
            continue
        kept.append(s0)
        taken.append((s0["byte_start"], s0["byte_end"]))
    st, ans = api.call("/v1/anonymize", {**payload, "spans": kept}, hdr)
    return st, ans, dropped


def run_row(api: Api, session: str, row: dict, thr: float, stage: str) -> dict:
    """Полный контур на одной строке: analyze → anonymize → deanonymize.

    `verdict` ∈ {exact, mismatch, refused}: exact = побайтовое равенство
    исходнику; mismatch = 200, но НЕ побайтово (это дефект разворота, его и
    ищем); refused = не-2xx на любом шаге (fail-closed: не-возврат).
    """
    sid = f"{session}-{row['id']}"
    hdr = {"x-session-id": sid}
    st, spans = api.call("/v1/analyze", {"text": row["text"], "score_threshold": thr},
                         {"X-Guard-Policy": "audit_only"})
    if st != 200:  # noqa: SIM108 — ветка ниже с доком, single-return читается хуже
        return dict(verdict="refused", sur=0, lbl=0, sur_f=0, ov=0,
                    code=str(spans.get("error", {}).get("code", st)))
    # Детект на stage cascade-0-only НЕ находит person_name (каскад 1+,
    # docs/daemon-scope.md «Что каскад 0 находит и не находит» п.1). Метрика
    # #60 п.3 мерит ОБРАТНЫЙ ХОД; без имени в описи суррогатный путь на
    # cascade-0 был бы недостижим и «100 %» меряло бы только метки. Спан из
    # gold-разметки датасета (read-only, B2) добавляется ТОЛЬКО на cascade-0-only,
    # и промер строки g0001 (наш smoke-прогон) подтверждает: replace_spans=27 —
    # ровно 27 годных ФИО golden, тот же список, что мерит `pool_probe
    # -- integrity`. На смонтированной сборке (cascade-0+models) имя ищется
    # детектом, gold НЕ подмешиваем — иначе метрика меряла бы разметку.
    # На смонтированной сборке person_name из lockR детерминированным вето не
    # считается (`validator: null`) и в пересечении с детект-спаном проигрывает:
    # это поведение контура, а не харнеса (промер: replace_spans=0 на
    # cascade-0+models, 27 на cascade-0-only — обе строки печатаются).
    if stage == "cascade-0-only":
        names = [s0 for s0 in row["spans"] if s0["category"] in SURROGATE_CLASSES
                 and not any(p["class"] == "person_name"
                             and p["byte_start"] < s0["end_byte"]
                             and s0["start_byte"] < p["byte_end"] for p in spans)]
        spans = spans + [{"class": "person_name", "byte_start": s0["start_byte"],
                          "byte_end": s0["end_byte"], "validator": None}
                         for s0 in names]
    payload = {"text": row["text"],
               "spans": [{"entity_type": s["class"], "byte_start": s["byte_start"],
                          "byte_end": s["byte_end"],
                          # детерминированность спана едет с ним: вето 1.0
                          # (validator != null) бьёт модельный спан при съёме
                          # пересечений (первичка: AGENTS «чексумма = 1.0».
                          "validator": s.get("validator")} for s in spans]}
    # Клиентская декомпозиция пересечений — ВСЕГДА (не только на 422-ответе):
    # на g0004 перекрывающиеся card_pan/ogrnip дают 422 bad_span, а на g0007
    # детект возвращает вложенный inn(10) внутри address(37) и anonymize его
    # принимает — вложенный номер при этом НЕ маскируется (первичка: `anonymize`
    # маскирует ровно присланные спаны; пересечения — отказ, tests/wire_e2e.rs),
    # и строка с невозвращённым ИНН = событие метрики, а не шум.
    # Правило: приоритет класса СХЕМЫ (config/schema.default.json), при равенстве
    # — более длинный спан; отброшенные считаются и видны в `overlap_dropped`.
    st, anon, dropped = resolve_overlap(api, hdr, payload)
    if st != 200:
        return dict(verdict="refused", sur=0, lbl=0, sur_f=0, ov=dropped,
                    code=str(anon.get("error", {}).get("code", st)))
    items = anon.get("items", [])
    sur = sum(1 for i in items if i["operator"] == "replace")
    lbl = sum(1 for i in items if i["operator"] == "mask")
    st2, back = api.call("/v1/deanonymize", {"text": anon.get("text", "")}, hdr)
    if st2 == 200:
        restored = back.get("text", "")
        verdict = "exact" if byte_eq(restored, row["text"]) else "mismatch"
        return dict(verdict=verdict, sur=sur, lbl=lbl, ov=dropped,
                    sur_f=int(back.get("restore_refused", 0)), code="")
    return dict(verdict="refused", sur=sur, lbl=lbl, sur_f=0, ov=dropped,
                code=str(back.get("error", {}).get("code", st2)))


# Фикстура control-ноги: ФИО (суррогатный путь) + ИНН (меточный путь) в одном
# тексте. Одна константа на control и control_on_mutant: мутант обязан
# подставлять РОВНО тот «исходник», с которым сравнит вход живой control.
CONTROL_TEXT = "Клиент Ушакова Кира Саввична, ИНН 7714161210"


def control(api: Api) -> int:
    """Positive control на дискриминирующем входе. rc=0 жив, rc=2 мёртв.

    Один и тот же вход (ФИО суррогатом + ИНН меткой):
      clean    — живая сессия: разворот даёт исходник побайтово;
      sabotage — та же подмена после teardown сессии: разворот обязан отказать.
    Разные доли на одном входе = контроль дискриминирует (0.0 vs 1.0).
    Тот же control на мутантном deanonymize — `control_on_mutant` (реестр #19).
    """
    fio = "Ушакова Кира Саввична"
    inn = "7714161210"
    text = CONTROL_TEXT
    # Оффсеты — БАЙТОВЫЕ (контракт `/v1/anonymize`: byte_start/byte_end,
    # BadSpan на не-границе символа). `str.index` на кириллице был бы ложью
    # (русская буква = 2 байта UTF-8); дефект пойман smoke-прогоном:
    # spans пересекаются → 422 bad_span, контроль умер честно.
    b = text.encode("utf-8")
    i0, j0 = b.index(fio.encode("utf-8")), b.index(inn.encode("utf-8"))
    gold = [{"entity_type": "person_name", "byte_start": i0,
             "byte_end": i0 + len(fio.encode("utf-8"))},
            {"entity_type": "inn", "byte_start": j0, "byte_end": j0 + len(inn.encode("utf-8"))}]
    out = {}
    for tag, dead in (("clean", False), ("sabotage", True)):
        sid = f"ctl-{tag}"
        hdr = {"x-session-id": sid}
        st, anon = api.call("/v1/anonymize", {"text": text, "spans": gold}, hdr)
        if st != 200:
            print(f"RESTORE|control|{tag}|FAIL-anonymize|{st}|{anon}")
            return 2
        ops = sorted({i["operator"] for i in anon.get("items", [])})
        if "mask" not in ops:
            # Меточный путь тоже обязан быть представлен, иначе clean-нога
            # меряет только суррогаты, а `422 unresolved_token` на sabotage
            # приходит по другой причине, чем думает контроль.
            print(f"RESTORE|control|{tag}|FAIL-no-mask-path|ops|{ops}")
            return 2
        if "replace" not in ops:
            # Суррогатный путь обязан быть достижим на этом входе: без него
            # контроль меряет не метрику, а молчание морфы.
            print(f"RESTORE|control|{tag}|FAIL-no-surrogate-path|ops|{ops}")
            return 2
        if dead and api.delete(f"/v1/sessions/{sid}") != 200:
            print(f"RESTORE|control|{tag}|FAIL-teardown")
            return 2
        st2, back = api.call("/v1/deanonymize", {"text": anon["text"]}, hdr)
        got = back.get("text", "") if st2 == 200 else None
        exact = int(byte_eq(got, text))
        code = str(back.get("error", {}).get("code", st2)) if st2 != 200 else "-"
        out[tag] = (exact, code)
        print(f"RESTORE|control|{tag}|status|{st2}|byte_exact|{exact}|code|{code}"
              f"|ops|{','.join(ops)}")
    if out["clean"][0] != 1:
        print("RESTORE|control|verdict|DEAD|reason|clean-не-развернулся")
        return 2
    if out["sabotage"][0] == 1:
        print("RESTORE|control|verdict|DEAD|reason|sabotage-развернулся"
              " (отказ разворота сломан: тихая потеря ПДн)")
        return 2
    print(f"RESTORE|control|verdict|ok|discriminating|clean=1.0|sabotage=0.0"
          f"|sabotage_code|{out['sabotage'][1]}")
    return 0


def perturbation(api: Api) -> int:
    """Пертурбация-гейт: харнес СЛЫШИТ дефект разворота (краснеет на мутанте).

    Доктрина ложно-зелёного (реестр 18, «print-only landing test: assert BOTH
    legs — output and state»): 100 % метрики ничего не стоит, пока тот же код
    не покраснеет на built-в-прогоне дефекте.

    Состояние-мутант (промер 21.10, мутант v3/v11 «read кэша в обход
    реверс-индекса #70», /tmp-worktree): выдача имени W в сессии, затем
    `DELETE` сессии — ровно состояние idle-истечения 15 мин: запись кэша
    мертва, разворот обязан ОТКАЗАТЬСЯ вернуть исходник (SPEC §4: «разворот
    без доказательства был бы каналом утечки»; #70: `unrestored_mismatch`
    молчит на `Absent` — отказ должен быть ВИДЕН числом в ответе).

      · честный код: суррогат в выводе НЕ разворачивается, `substituted=0`,
        в суррогатной выдаче текст остаётся суррогатом (сравнение с
        исходником = НЕ равенство);
      · мутант read-кэша: форма разворачивается глобальным значением —
        побайтовый возврат исходника при `restore_refused=0`.

    Дискриминатор: «исходник вернулся побайтово при нулевом отказе» = red.
    На мутанте он срабатывает (промер v3: `200 + исходник + refused=0`),
    на честном коде — никогда.

    Меточная нога (ИНН) в этом состоянии валит весь ответ в `422
    unresolved_token` (первичка deanonymize: Unresolved — отказ, partial не
    отдаётся), поэтому контроль строит СУРРОГАТНУЮ фикстуру (один person_name,
    как в тесте #70 `divergent_form_refuses_restore_and_shows_in_counter`),
    а фикстура контроля `control` остаётся смешанной (суррогат + метка) и
    покрывает меточный путь.

    Нога A (честный мир) — обычный round-trip через `run_row`: exact.
    """
    w = "Ушакова Кира Саввична"
    text = f"Клиент {w}"
    b = text.encode("utf-8")
    i0 = b.index(w.encode("utf-8"))
    span = {"entity_type": "person_name", "byte_start": i0,
            "byte_end": i0 + len(w.encode("utf-8"))}
    row = {"id": "perturb", "text": text,
           "spans": [{"category": "person_name", "start_byte": i0,
                      "end_byte": i0 + len(w.encode("utf-8"))}]}
    r_ok = run_row(api, "perturb-a", row, 0.20, "cascade-0-only")
    if r_ok["verdict"] != "exact":
        print(f"RESTORE|perturbation|leg-a|FAIL|verdict|{r_ok['verdict']}"
              f"|code|{r_ok['code']}", file=sys.stderr)
        return 2
    sid = "perturb-dead"
    hdr = {"x-session-id": sid}
    st, anon = api.call("/v1/anonymize", {"text": text, "spans": [span]}, hdr)
    if st != 200:
        print(f"RESTORE|perturbation|leg-b|FAIL-anonymize|{st}", file=sys.stderr)
        return 2
    if all(it["operator"] != "replace" for it in anon.get("items", [])):
        print("RESTORE|perturbation|leg-b|FIXTURE-DEAD: фикстура не дала"
              " суррогат (морфа/пул сменились) — переснять", file=sys.stderr)
        return 2
    if api.delete(f"/v1/sessions/{sid}") != 200:
        print("RESTORE|perturbation|leg-b|FAIL-teardown", file=sys.stderr)
        return 2
    st2, back = api.call("/v1/deanonymize", {"text": anon["text"]}, hdr)
    out = back.get("text", "") if st2 == 200 else ""
    refused = int(back.get("restore_refused", 0))
    if byte_eq(out, text) and refused == 0:
        print("RESTORE|perturbation|leg-b|GREEN-when-must-be-RED: исходник"
              " вернулся побайтово после teardown сессии (разворот без"
              " свидетельства: read кэша в обход реверс-индекса #70),"
              " метрика не засчитывается", file=sys.stderr)
        return 2
    print("RESTORE|perturbation|clean|exact|broken|refusal-after-teardown"
          f"|status|{st2}|refused|{refused}|byte_exact|{int(byte_eq(out, text))}"
          f"|verdict|ok|discriminating")
    return 0


def run(args: argparse.Namespace) -> int:
    t0 = time.time()
    # Fail-Closed precheck входа: тот же B2-гейт, что у union-recall (sha256
    # датасета против константы в тестах). Датасет ТРОГАТЬ НЕЛЬЗЯ (blob B2).
    src = B2_TEST.read_text(encoding="utf-8")
    m = re.search(r'GOLDEN_V1_SHA256:\s*&str\s*=\s*"([0-9a-f]{64})"', src)
    if m is None:
        print(f"FAIL: GOLDEN_V1_SHA256 не найдена в {B2_TEST}", file=sys.stderr)
        return 2
    got = hashlib.sha256(GOLDEN.read_bytes()).hexdigest()
    print(f"RESTORE|sha|golden-v1.jsonl|{got}")
    print(f"RESTORE|sha|schema.default.json|"
          f"{hashlib.sha256(SCHEMA_FILE.read_bytes()).hexdigest()}")
    if got != m.group(1):
        print(f"FAIL golden sha256 {got} != B2 {m.group(1)} (дрейф датасета)", file=sys.stderr)
        return 2
    # `os.nice(0)` — это ЧТЕНИЕ niceness, а не выставление: под внешним
    # `nice -n 10` (рюлинг 21.10, just-рецепты) у процесса нет права понижать
    # любезность, и на macOS это PermissionError. Читаем в try/except, чтобы
    # prolog не валил прогон на diagnostics-строке (реестр: ложь о причине
    # отказа — здесь это был бы rc=1 «метрика красна» на ровном env).
    try:
        niceness = str(os.nice(0))
    except OSError as exc:  # PermissionError — внешний nice уже понизил
        niceness = f"n/a-external-nice({exc.strerror})"
    print(f"RESTORE|env|python|{platform.python_version()}|platform|{platform.system()}"
          f"-{platform.machine()}|niceness|{niceness}|threads|daemon-2"
          f"|vault|session|seed|n/a-no-RNG")

    rec = load_recall_rows()
    if args.limit:
        rec = rec[:args.limit]
    print(f"RESTORE|dataset|rows|{len(rec)}|spans|{sum(len(r['spans']) for r in rec)}"
          f"|surrogate_classes|{','.join(sorted(SURROGATE_CLASSES))}"
          f"|marker_classes|{len(LABEL_CLASSES)}")

    proc, base, dlog = daemon_start(args.daemon)
    api = Api(base)
    print(f"RESTORE|daemon|binary|{args.daemon}|url|{base}|log|{dlog}")
    try:
        st_h, health = api.call("/health", {})
        stage = str(health.get("stage", "?")) if st_h == 200 else "?"
        mode = str(health.get("mode", "?")) if st_h == 200 else "?"
        print(f"RESTORE|daemon|stage|{stage}|vault_mode|{mode}")
        if mode != "session":
            print(f"FAIL демон поднялся в режиме {mode!r}, ждали session", file=sys.stderr)
            return 2

        rc_ctl = comparator_selftest()
        if rc_ctl == 0:
            rc_ctl = control(api)
        if rc_ctl == 0:
            rc_ctl = control_on_mutant(api)
        if rc_ctl == 0:
            rc_ctl = perturbation(api)
        if rc_ctl == 0:
            rc_ctl = perturbation(api)
        if rc_ctl:
            print("RESTORE|verdict|CONTROL-DEAD|metric-не-засчитана", file=sys.stderr)
            return rc_ctl

        per_class: dict[str, dict[str, int]] = {}
        exact = refused = mismatch = 0
        sur = lbl = sur_f = ov = 0
        refuse_codes: dict[str, int] = {}
        t1 = time.time()
        for row in rec:
            r = run_row(api, "ri", row, args.thr, stage)
            exact += int(r["verdict"] == "exact")
            refused += int(r["verdict"] == "refused")
            mismatch += int(r["verdict"] == "mismatch")
            sur += r["sur"]
            lbl += r["lbl"]
            sur_f += r["sur_f"]
            ov += r["ov"]
            if r["verdict"] == "refused":
                refuse_codes[r["code"]] = refuse_codes.get(r["code"], 0) + 1
            # per-class: строка засчитывается каждому своему gold-классу
            # (мультиымянная строка входит в несколько разрезов — это разрез
            # строк класса, а не спанов; знаменатель печатается в n)
            for cat in {s["category"] for s in row["spans"]}:
                d = per_class.setdefault(cat, dict(k=0, n=0))
                d["n"] += 1
                d["k"] += int(r["verdict"] == "exact")
        n = len(rec)
        print(f"TIME|restore|s|{time.time() - t1:.2f}|rows|{n}")
        for cat in sorted(per_class):
            d = per_class[cat]
            lo, hi = wilson(d["k"], d["n"])
            print(f"RESTORE|per_class|{cat}|k|{d['k']}|n|{d['n']}"
                  f"|pct|{100.0 * d['k'] / d['n']:.2f}|wilson95_lo|{100 * lo:.2f}"
                  f"|wilson95_hi|{100 * hi:.2f}")
        # Разрез по оператору: без него 100 % при «всё уехало метками» было бы
        # пустой метрикой; доля суррогатного пути = replace-спаны.
        print(f"RESTORE|ops|replace_spans|{sur}|mask_spans|{lbl}"
              f"|restore_refused|{sur_f}|overlap_dropped|{ov}")
        lo, hi = wilson(exact, n)
        codes = json.dumps(refuse_codes, ensure_ascii=False, sort_keys=True) \
            if refuse_codes else "-"
        print(f"RESTORE|overall|mode|session|stage|{stage}|k|{exact}|n|{n}"
              f"|byte_exact|{100.0 * exact / n:.2f}|wilson95_lo|{100 * lo:.2f}"
              f"|wilson95_hi|{100 * hi:.2f}|refused|{refused}|mismatch|{mismatch}"
              f"|refuse_codes|{codes}")
        verdict = "pass" if (exact == n and refused == 0 and mismatch == 0
                             and sur_f == 0) else "fail"
        print(f"RESTORE|verdict|{verdict}|byte_exact|{100.0 * exact / n:.2f}"
              f"|thr|{args.thr:.2f}|k|{exact}|n|{n}|control|alive")
        print(f"TIME|total|s|{time.time() - t0:.2f}|rows|{n}|daemon|{stage}")
        return 0 if verdict == "pass" else 1
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--thr", type=float, default=0.20,
                    help="рабочая точка analyze (скор чексумм = 1.0, τ на неё не действует)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--daemon", default=str(ROOT / "target" / "debug" / "fasad"))
    ap.add_argument("--out", default="")
    ap.add_argument("--self-test", action="store_true",
                    help="только positive control'ы харнеса (wilson-якоря + "
                         "единая побайтовая сверка), без демона и датасета")
    args = ap.parse_args()
    if args.self_test:
        return comparator_selftest() if wilson_anchors() == 0 else 2
    out_fh = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    if out_fh:
        sys.stdout = Tee(out_fh)
    rc = 2
    try:
        rc = run(args)
    finally:
        if out_fh:
            # sys.stdout возвращаем ДО close: закрытый Tee даёт ValueError на
            # финальном flush = rc=120 при зелёном прогоне (промер 21.10,
            # union_recall.py).
            sys.stdout = sys.__stdout__
            out_fh.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
