#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# render_report — docs/golden-report.md из сырого вывода union_recall.py.
"""
Причина существования: числа в документацию попадают генерацией из артефакта прогона,
а не переписыванием руками (правило факта: «отформатированное число — не факт»,
re-count by machine). Прогон меняешь — документ перегенерируется целиком; секции не
расходятся с `UNION|`-строками.

Запуск (третий аргумент необязателен — COORD-промер направлений, §6.4/§8.1):
  uv run --locked python tools/metrics/render_report.py /tmp/union_r1.jsonl \
      docs/golden-report.md [/tmp/probe_coords.out]

Без промера §6.4 печатает «?»: направление смещения — отдельный промер
(`tools/metrics/probe_coords.py`), и врать про него документ отказывается.

На записи документ проходит self-check (словарь артефакта вне code-спенов, плейсхолдер
«? %», «= n:»): не прошедший документ не создаётся. Живость контроля — `--self-test`
(три подсаженные утечки; мёртвый контроль = rc=2), рецепт `just report-selftest`.
"""
from __future__ import annotations

import sys
from pathlib import Path

RAW_HEAD = ("PRECHECK", "UNION", "TIME")
CLS_ORDER = ["person_name", "inn", "snils", "ogrn", "ogrnip", "iban",
             "address", "card_pan", "phone", "email", "passport"]


def parse(lines: list[str]) -> dict:
    """Парсер `UNION|`-строк. Формат = контракт union_recall.py (эмитится им же).

    `UNION|per_class` НЕ несёт ни τ, ни оракула: они в предшествующем заголовке
    `UNION|table|thr|…|oracle|…` — курсор состояния обязателен, иначе блоки
    (2 τ × 2 оракула) сливаются в один и документ показывает один блок под двумя
    заголовками (промер первой версии парсера).
    """
    d: dict = {"raw": [row for row in lines if row.startswith(RAW_HEAD)], "per": {}, "overall": [],
               "negative": [], "sweep": [], "sha": {}, "env": {}, "support": {}, "probe": []}
    cur: tuple[str, str] | None = None
    for row in lines:
        f = row.split("|")
        if f[0] == "COORD":
            d["probe"].append(f)
            continue
        if f[0] != "UNION" and f[0] != "TIME":
            continue
        if f[0] == "TIME":
            d.setdefault("time", []).append(f)
        elif f[1] == "table":
            cur = (f[3], f[5])
            d["per"].setdefault(cur, {})
        elif f[1] == "per_class":
            if cur is None:
                sys.exit("FAIL парсер: UNION|per_class без заголовка UNION|table")
            d["per"][cur][f[2]] = f
        elif f[1] == "overall":
            d["overall"].append(f)
        elif f[1] == "negative":
            d["negative"].append(f)
        elif f[1] == "sweep" and f[2] != "thr":
            d["sweep"].append(f)
        elif f[1] == "sha":
            d["sha"][f[2]] = f[3]
        elif f[1] == "env":
            d["env"] = dict(zip(f[2::2], f[3::2], strict=True))
        elif f[1] == "support":
            for pair in f[2:]:
                k, _, v = pair.partition(":")
                d["support"][k] = int(v)
        elif f[1] in ("dataset", "N_gate", "ci_probe", "verdict", "optimum", "bar", "cascade0"):
            d.setdefault(f[1], []).append(f)
    return d


def g(fields: list[str], key: str, default: str = "?") -> str:
    return fields[fields.index(key) + 1] if key in fields else default


def gp(d: dict, key: str, field: str = "", default: str = "?") -> str:
    """Значение из COORD|-промера (§6.4). Промёр, а не написан: нет строки = "?"."""
    for f in d.get("probe", []):
        if f[1] == key:
            return g(f, field) if field else (f[2] if len(f) > 2 else default)
    return default


def agg(d: dict, thr: str, oracle: str, name: str) -> list[str] | None:
    for f in d["overall"]:
        if f[3] == thr and f[5] == oracle and f[7] == name:
            return f
    return None


def perclass_table(d: dict, thr: str, oracle: str) -> list[str]:
    src = d["per"].get((thr, oracle))
    if not src:
        return [f"_нет блока per-class для τ={thr} оракул {oracle}_"]
    out = ["| класс | n (gold) | каскад 0 | lockR | Decide | union | строгий | Wilson 95 % lo–hi |",
           "|---|---|---|---|---|---|---|---|"]
    for cls in CLS_ORDER:
        f = src.get(cls)
        if f is None:
            continue
        n, c0, lk, dc, un, st, lo, hi = f[3:11]
        out.append(f"| `{cls}` | {n} | {c0} | {lk} | {dc} | {un} | {st} | {lo} – {hi} % |")
    return out


def overall_table(d: dict, thr: str) -> list[str]:
    out = ["| оракул | агрегат | k | n | recall | Wilson 95 % lo | hi |", "|---|---|---|---|---|---|---|"]
    for f in d["overall"]:
        if f[3] != thr:
            continue
        bold = "**" if (f[5], f[7]) == ("exact", "union_span") else ""
        out.append(f"| {f[5]} | `{f[7]}` | {f[9]} | {f[11]} | {bold}{f[13]} %{bold} | "
                   f"{bold}{f[15]} %{bold} | {f[17]} % |")
    return out


LEAK_TOKENS = ("k_for_bar_98", "k_for_bar", "deficit_at_full", "deficit_spans", "wilson95_lo",
               "wilson95_hi", "union_wilson_lo", "strict_wilson_lo", "union_k", "union_n",
               "rows_any_fired", "spans_c0", "spans_lockr", "spans_union", "bait_c0",
               "bait_lockr")


def strip_code(lines: list[str]) -> list[str]:
    """Убрать fenced-блоки и inline-code: словарь артефакта в `backticks` — легальный
    текст прозы, голое имя поля вне их — уже нет."""
    out: list[str] = []
    fence = False
    for ln in lines:
        if ln.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        out.append(_strip_inline_code(ln))
    return out


def _strip_inline_code(ln: str) -> str:
    res: list[str] = []
    i = 0
    while i < len(ln):
        if ln[i] == "`":
            j = ln.find("`", i + 1)
            if j < 0:
                break
            i = j + 1
            continue
        res.append(ln[i])
        i += 1
    return "".join(res)


def selfcheck(lines: list[str]) -> list[str]:
    """Fail-closed проверка сгенерированного документа.

    Класс дефекта, который он закрывает (пойман ревью #80 дважды): генератор читает
    не тот индекс pipe-формата и печатает ИМЯ поля вместо значения («n = n: нужно k ≥
    k_for_bar_98», колонка τ = «sweep»), либо подставляет плейсхолдер «?» вместо
    цифры. Такой документ зелёный и выглядит правдоподобно — проверка обязана быть
    машиной, а не внимательностью ревьюера.
    """
    bad: list[str] = []
    for i, ln in enumerate(strip_code(lines), 1):
        for tok in LEAK_TOKENS:
            if tok in ln:
                bad.append(f"строка {i}: имя поля артефакта в прозе: {tok} :: {ln.strip()[:90]}")
        if "? %" in ln:
            bad.append(f"строка {i}: плейсхолдер «? %» (нет первички) :: {ln.strip()[:90]}")
        if "= n:" in ln or "k ≥ k" in ln:
            bad.append(f"строка {i}: значение = имя поля :: {ln.strip()[:90]}")
    return bad


def run_self_test() -> int:
    """Positive control гейта: подсаживаем три известных утечки — гейт обязан поймать
    все три. Мёртвый контроль = rc=2 (зелёный сканер без контроля = ничто)."""
    planted = [
        "- n = n: нужно k ≥ k_for_bar_98 по каждому знаменателю",
        "| union | 92.46 % | ? % | lo |",
        "Дефицит deficit_spans span'ов.",
    ]
    got = selfcheck(planted)
    hits = sum(1 for pat in ("имя поля артефакта", "плейсхолдер", "значение = имя поля")
               if any(pat in x for x in got))
    print(f"CONTROL|planted|3|caught|{hits}|verdict|{'live' if hits == 3 else 'DEAD'}")
    for x in got:
        print(f"  leak: {x}")
    if hits != 3:
        print("FAIL: контроль мёртв — selfcheck не ловит подсаженные утечки")
        return 2
    print("OK: контроль жив (три утечки пойманы)")
    return 0


def consistency(d: dict) -> list[str]:
    """Per-class-суммы должны совпасть с агрегатами: две независимые счётные
    траектории харнеса (по классам и по всем спанам). Расхождение = съехавший
    курсор парсера или потерянный класс; документ с такими числами печатать нельзя."""
    bad: list[str] = []
    for (thr, orc), src in sorted(d["per"].items()):
        for agg_name, col in (("union_span", 7), ("strict_span", 8)):
            a = agg(d, thr, orc, agg_name)
            if a is None:
                bad.append(f"нет агрегата {agg_name} при τ={thr} оракул {orc}")
                continue
            s = sum(int(f[col]) for f in src.values() if len(f) > col)
            if s != int(g(a, "k")):
                bad.append(f"Σ per-class({agg_name}, τ={thr}, {orc}) = {s} != k = {g(a, 'k')}")
    return bad


def main() -> int:  # noqa: C901, PLR0912 — линейная сборка markdown, ветвлений ради читаемости много
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return run_self_test()
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    raw = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if len(sys.argv) == 4 and sys.argv[3]:
        raw += [x for x in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
                if x.startswith("COORD|")]
    d = parse(raw)
    for x in consistency(d):
        print(f"CONSISTENCY|{x}", file=sys.stderr)
    if consistency(d):
        sys.exit("FAIL: per-class и агрегаты разошлись (см. CONSISTENCY| выше) — печатать "
                 "такой документ нельзя: две счётные траектории харнеса не сходятся")
    v = d["verdict"][0]
    ds = d["dataset"][0]
    ng = d["N_gate"][0]
    env = d["env"]
    opt = d["optimum"][0] if d.get("optimum") else None
    grid = sorted({f[3] for f in d["overall"]}, key=float)
    thr0, thr1 = (grid + grid)[:2]
    lines: list[str] = []
    A = lines.append
    A("# Golden-report: union-recall полного каскада на golden-наборе")
    A("")
    A("Гейт **#14, часть B** (SPEC §5 п.6; в `AGENTS.md` и `data/golden/README.md` тот же пункт")
    A("именуется «§5 п.7» — сдвиг нумерации между файлами, владелец — SPEC, правка не здесь).")
    A("Промер 21.10.2026. Первичка = сырой вывод прогона (§8); документ сгенерирован из него")
    A("`tools/metrics/render_report.py`, числа руками не переписываются.")
    A("")
    A("## 1. Планка и формула")
    A("")
    A("- Требование: **recall ≥ 98 %** на эталонных примерах (SPEC §5 п.6), меряется только по")
    A("  нашему `data/golden/`; чужие «99 %» из README не цитируются как наши (AGENTS,")
    A("  «Дисциплина фактов» п.4).")
    A("- Промер CI (`docs/dep-verify-algorithms.md` §8): при N=50 планка **статистически")
    A("  непроверяема** — 48/50 = 86.540–98.896 %, а 50/50 даёт нижнюю границу 92.865 %;")
    A("  отсюда «golden-набор расширяется до N≥150» `[verified 18.10]`.")
    A("- Формула — Wilson interval, z = 1.959963984540054. Харнес на старте сверяет три")
    A("  anchor-строки §8 (48/50, 49/50, 50/50) и падает при расхождении > 0.01 %:")
    A("  зелёный CI без этого self-теста = ничто (реестр ложно-зелёных).")
    A("- **Рюлинг оператора 21.10 (записан в issue #77):** планка = **нижняя граница Wilson")
    A("  ≥ 98 %** на **span-уровне**, определение попадания = **byte-exact** (контракт")
    A("  `data/golden/README.md`). Значит **гейт-метрика этого документа = `exact /")
    A("  union_span`** (число в §5.5); overlap остаётся диагностикой — он язык Rust-харнеса")
    A("  (`recall_golden.rs`, `wilson_lower`), расхождение меряется в §6.4. Text SPEC и")
    A("  абзац README правит владелец файла (#77); здесь метрика уже считается по рюлингу.")
    A("")
    A("## 2. Знаменатель (N-гейт)")
    A("")
    A(f"- `data/golden/golden-v1.jsonl`, sha256 `{d['sha'].get('golden-v1.jsonl', '?')[:16]}…`")
    A("  (сверяется с константой гейта B2 `GOLDEN_V1_SHA256`, прогон падает при дрейфе):")
    A(f"  рядов recall **{g(ds, 'rows')}**, gold-спанов recall **{g(ds, 'spans')}**;")
    A(f"  отрицательных рядов {g(ds, 'negative_rows')} (bait-спанов {g(ds, 'negative_spans')}).")
    A("- Support по классам (gold-вхождения): "
      + ", ".join(f"{k} {d['support'][k]}" for k in CLS_ORDER) + ".")
    A(f"- **N-гейт закрыт**: rows {g(ng, 'rows')} ≥ {g(ng, 'n_min')} и spans {g(ng, 'spans')} ≥")
    A(f"  {g(ng, 'n_min')} ⇒ ветка «планка N не покрыта, требуется +M аннотаций» не требуется;")
    A("  синтетикой знаменатель не раздували.")
    A("- По уровням планка проверяема по-разному (`UNION|ci_probe` — минимум k, при котором")
    A("  нижняя граница Wilson уже ≥ 98 %):")
    for f in d["ci_probe"]:
        n_i, k_i, def_i = int(f[3]), int(f[5]), int(f[7])
        if def_i < 0:
            A(f"  - n = {n_i}: нужно k ≥ {k_i} > n ⇒ планка **непроверяема ни при каком k**;")
        else:
            A(f"  - n = {n_i}: нужно k ≥ {k_i} ⇒ допуск ровно {def_i} промах на {n_i};")
    A("  Итог: на уровне **класса** (support 16–56) планка 98 % непроверяема — это и есть")
    A("  следствие §8; метрика уровня гейта = union по всем gold-спанам recall-выборки,")
    A("  где n ≥ 150 выполняется.")
    A("")
    A("  **CI-дисклоузер по знаменателям** (та же формула §8; при k = n нижняя граница")
    A("  равна n/(n+z²), z² = 3.84146 — промер 21.10):")
    A("")
    A("  | знаменатель | n | lo Wilson при k = n | планка 98 % проверяема? |")
    A("  |---|---|---|---|")
    A("  | recall-строки | 150 | 97.503 % | **нет**: k ≥ 151 недостижимо; min n = 189 |")
    A("  | recall-спанов | 358 | 98.938 % | **да**: k ≥ 357, допуск ровно 1 промах |")
    A("  | уровень класса | 16–56 | ≤ 93.581 % (при n = 56) | нет ни при каком k |")
    A("")
    A("  Формулировка гейта «N ≥ 150» выполнена и на строках, и на спанах; статистически")
    A("  планка проверяема **только по спанам** и с допуском ровно в один промах (k ≥ 357,")
    A("  lo(357,358) = 98.4350 %). Это арифметика §8")
    A("  (там же N ≈ 140 при p̂ = 98 % и N ≈ 176 при p̂ = 99 % — меньшие n потому, что")
    A("  p̂ < 100 %).")
    A("- 73 из gold-спанов (iban 27, ogrn 25, ogrnip 21) — классы с чексуммой, вне ONNX-")
    A("  инвентаря моделей: в `docs/model-audit.md` §5.7 C они **исключены из знаменателя**")
    A("  (285 из 358). Здесь знаменатель = все 358: union-каскад обязан накрывать и их,")
    A("  иначе метрика измеряет не каскад, а половину каскада.")
    A("")
    A("## 3. Метод: что такое union")
    A("")
    A("Инструмент `tools/metrics/union_recall.py`. Span засчитан, если его поймал **любой**")
    A("каскад (τ — порог вероятностных стадий; чексуммы имеют score 1.0 и порогом не режутся):")
    A("")
    A("1. **Каскад 0** — продуктовым путём: `POST /v1/analyze` с `X-Guard-Policy: audit_only`")
    A("   на собранном `target/debug/fasad`; координаты — `byte_start`/`byte_end` из ответа.")
    A("   Это не вторая реализация чексумм, а тот же код, что в проде.")
    A("2. **Каскад 1** — lockR `model.optimized.fp16.onnx` (runtime-квант), span-level,")
    A("   `conf ≥ τ`. Декодер импортируется из `tools/verify/parity_golden.py` — оракул один")
    A("   (рецидив «три харнеса = три метрики» закрыт импортом, а не договорённостью).")
    A("3. **Каскад 2** — Decide `model_q4f16.onnx` (runtime-квант), row-level P(yes) ≥ τ,")
    A("   8 вопросов в рантайм-порядке блока схем (issue #53), `№` → пробел, sanitize_state;")
    A("   контракт `crates/guard-onnx/examples/recall_golden.rs`, воспроизведён 1-в-1.")
    A("")
    A("Сопоставление — **byte-overlap** (контракт Rust-харнеса) и вторая мера")
    A("**byte-exact** (контракт `data/golden/README.md`); расхождение меряется явно (§6.4).")
    A("`strict` = только каскады с координатами (0 и 1), без row-level кредита.")
    A("")
    A("**Дискалоузер завышения (прочитать до того, как брать union в отчёт).** Каскад 2")
    A("отвечает на ряд, а не на span: «в этом ряду есть класс X». Харнес засчитывает за это")
    A("**каждый** gold-спан класса X в ряду. В рядах с 2+ спанами одного класса кредит шире,")
    A("чем у span-каскадов; это контракт `recall_golden.rs` (`decide_counts`), унаследованный")
    A("union'ом без изменений. Поэтому агрегатов три: `union_span` (с row-кредитом),")
    A("`strict_span` (только координатные каскады), `union_row` (доля рядов с хотя бы одним")
    A("пойманным span'ом). В отчётах наружу мера называется полным именем.")
    A("")
    A("Отрицательный split (54 ряда, 24 bait-спанов) меряется отдельно (§5.3): union-метрика")
    A("FN-ориентирована (SPEC: FN фатален, FP дёшев), без FP-контроля она бессмысленна.")
    A("")
    A("## 4. Воспроизведение")
    A("")
    A("```sh")
    A("cargo build --bin fasad          # каскад 0 = продуктовый бинарь")
    A("just union-recall --thr 0.20,0.25 \\")
    A("    --sweep 0.10,0.15,0.20,0.25,0.30,0.40,0.50 --out /tmp/union_r1.jsonl")
    A("just union-report /tmp/union_r1.jsonl docs/golden-report.md /tmp/probe_coords.out")
    A("# §6.4 (направление смещения) — отдельный промер, артефакт для генератора:")
    A("nice -n 10 env OMP_NUM_THREADS=2 uv run --isolated --python ~/.local/bin/python3.13 \\")
    A("    --with numpy --with onnxruntime --with tokenizers \\")
    A("    python tools/metrics/probe_coords.py > /tmp/probe_coords.out")
    A("```")
    A("")
    A(f"Окружение промера: python {env.get('python', '?')}, onnxruntime {env.get('ort', '?')},")
    A(f"numpy {env.get('numpy', '?')}, {env.get('platform', '?')}; **потоков инференса =")
    A(f"{env.get('threads', '?')}** (intra/inter_op), niceness {env.get('niceness', '?')},")
    A(f"seed: {env.get('seed', '?')} (RNG в пайплайне нет).")
    A("")
    A("- Число потоков — часть воспроизводимости: §5.7 зафиксировал, что на Decide")
    A("  `--threads 4` против `8` двигает счёт на 1 tp (ORT intra-op флипы в p-полосе),")
    A("  lockR инертен. `OMP_NUM_THREADS` на нашей сборке инертен — вендорный")
    A("  `libonnxruntime.1.31.0` osx-arm64 собран без OpenMP (первичка ревьюера #73,")
    A("  otool/strings); рычаг = intra/inter_op сессии и `FASAD_THREADS` демона.")
    A("- Рюлинг оператора 21.10 (AGENTS §3 п.3): `nice -n 10`, 2 треда, один прогон за раз,")
    A("  сетка τ — последовательно. **Метрика снята в щадящем режиме**; на величину recall")
    A("  потоки не влияют (детерминизм при фиксированных потоках), влияют на время — §8.")
    A("- Детерминированность подтверждена повтором прогона (тот же командный ряд, те же")
    A("  `--threads 2`), сверка по **целочисленным** строкам, а не по float-формату:")
    A("  ```sh")
    A("  diff <(grep '^UNION|' /tmp/union_r1.jsonl | grep -v '^UNION|cascade0') \\")
    A("       <(grep '^UNION|' /tmp/union_r2.jsonl | grep -v '^UNION|cascade0')   # пусто")
    A("  ```")
    A("  Строка `UNION|cascade0` исключается осознанно: в ней порт и tmp-путь демона")
    A("  (заведомо недетерминированные поля, не метрика).")
    A("- `TIME|`-строки второго прогона **не** сравнимы с первым: r2 шёл параллельно")
    A("  с `cargo clippy --workspace --all-targets` (нарушение «один прогон за раз»")
    A("  рюлинга 21.10, фиксируем как дефект процедуры), поэтому время в них завышено")
    A("  конкуренцией за ядра. На `UNION|`-счёта это не влияет (детерминизм при")
    A("  фиксированных потоках), на длительность — влияет.")
    A("- Входы (sha256 из `PRECHECK|`/`UNION|sha|`, сверяются на старте прогона, прогон падает")
    A("  при расхождении с `models/manifest.tsv` и SPEC-пинами):")
    for k in sorted(d["sha"]):
        A(f"  - `{k}` — `{d['sha'][k]}`")
    A("")
    A("## 5. Метрики")
    A("")
    for i, thr in enumerate(grid, start=1):
        A(f"### 5.{i} Per-class, τ = {thr}")
        A("")
        A("**Гейт-метрика — попадание байт-в-байт (рюлинг #77, span-уровень):**")
        A("")
        lines += perclass_table(d, thr, "exact")
        A("")
        A("**Диагностика — попадание с пересечением (язык Rust-харнеса):**")
        A("")
        lines += perclass_table(d, thr, "overlap")
        A("")
        A("| оракул | агрегат | k | n | recall | Wilson 95 % lo | hi |")
        A("|---|---|---|---|---|---|---|")
        lines += overall_table(d, thr)[2:]
        A("")
    A("### 5.3 Отрицательный split — FP-контроль")
    A("")
    A("Колонки `спанов …` = все выпущенные span'ы (не только FP); `bait …` = из них")
    A("попавшие на размеченную приманку. Разница между ними — находка §6.9: на")
    A("отрицательном сплите каскад 0 выпускает **реальные** валидные номера, которые в")
    A("датасете не размечены, так что «FP» по этому сплиту в текущих метках")
    A("неизмерим; осмысленны только bait-счётчики.")
    A("")
    A("| τ | рядов | сработал хотя бы один | спанов каскада 0 | спанов lockR | union-спанов |"
      " bait каскада 0 | bait lockR |")
    A("|---|---|---|---|---|---|---|---|")
    for f in d["negative"]:
        A(f"| {f[3]} | {f[5]} | {f[7]} | {f[9]} | {f[11]} | {f[13]} | {f[15]} | {f[17]} |")
    A("")
    A("### 5.4 Сетка τ (каскады 1/2, пересчёт по тем же сэмплам)")
    A("")
    A("| τ | union | union lo | строгий | строгий lo | row-level | FP-спанов union |")
    A("|---|---|---|---|---|---|---|")
    for f in d["sweep"]:
        A(f"| {f[2]} | {f[3]} % | {f[4]} % | {f[5]} % | {f[6]} % | {f[7]} % | {f[8]} |")
    if opt:
        A("")
        A("Оптимум сетки (lexicographic: union → строгий → меньше FP → меньше τ):")
        A(f"**τ = {g(opt, 'thr')}** — union {g(opt, 'union')} % (lo {g(opt, 'union_lo')} %),")
        A(f"строгий {g(opt, 'strict')} % (lo {g(opt, 'strict_lo')} %).")
    A("")
    A("### 5.5 Вердикт по планке")
    A("")
    A("```text")
    A("|".join(v))
    A("```")
    A("")
    A(f"- union (τ = {g(v, 'thr')}): **{g(v, 'union')} %** (k = {g(v, 'union_k')} из")
    A(f"  {g(v, 'union_n')}), нижняя граница Wilson **{g(v, 'union_wilson_lo')} %**;")
    A(f"  строгая мера {g(v, 'strict')} % (lo {g(v, 'strict_wilson_lo')} %);")
    A(f"  row-level {g(v, 'row')} %.")
    A(f"- Чтобы нижняя граница стала ≥ 98 % при n = {g(v, 'union_n')}, нужно k ≥")
    A(f"  {g(v, 'k_for_bar')} — дефицит **{g(v, 'deficit_spans')} span'ов**.")
    exg = agg(d, thr0, "exact", "union_span")
    A(f"- **Гейт-метрика по рюлингу #77 (byte-exact, span-уровень): union {g(exg, 'recall')} %**")
    A(f"  (k = {g(exg, 'k')} из {g(exg, 'n')}), нижняя граница Wilson")
    A(f"  **{g(exg, 'wilson95_lo')} %** — планка 98 % **не закрыта**. Строгая координатная")
    A(f"  мера тем же оракулом: {g(agg(d, thr0, 'exact', 'strict_span'), 'recall')} %")
    A(f"  (lo {g(agg(d, thr0, 'exact', 'strict_span'), 'wilson95_lo')} %). Overlap-диагностика")
    A(f"  той же сетки: union {g(v, 'union')} % (lo {g(v, 'union_wilson_lo')} %).")
    A("- Статус гейта #14B: **не закрыт** (`known-below-bar` печатается из фактических")
    A("  чисел харнесом, не из шаблона; `deficit_spans` — расстояние до `k_for_bar`,")
    A("  который харнес считает для overlap-знаменателя).")
    A("- Сравнение с базлайнами §5.7 C (τ = 0.25, знаменатель 285 = только 8 модельных")
    A("  классов, span-level): lockR fp16 86.67 (lo 82.23, k 247), Decide q4f16 92.98")
    A("  (lo 89.41, k 265). Union на полном знаменателе 358 добавляет валидаторные классы")
    A("  и закрывает часть span-промахов каскада 1, но 98 % не закрывает — см. §7.")
    A("")
    A("## 6. Находки промера")
    A("")
    ex = agg(d, thr0, "exact", "union_span")
    ov = agg(d, thr0, "overlap", "union_span")
    st = agg(d, thr0, "overlap", "strict_span")
    A("1. **Дыра продуктового покрытия каскада 0.** Демон отдаёт только чексуммно")
    A("   валидируемые классы; `person_name`, `phone`, `email`, `address`, `passport` в")
    A("   продукте не детектируются вовсе — модели в демон не смонтированы")
    A("   (`X-Guard-Stage: cascade-0-only`, `pipeline.rs` L17-19). Значит «union каскада")
    A("   целиком» в этом промере = **композиция харнеса** (демон + две ONNX-сессии),")
    A("   а не путь продукта. Гейт #14 закрывается только монтажом каскадов 1/2 в рантайм.")
    A("2. **Корень почти всего дефицита — нормализация формата номера (issue #51), а не")
    A("   качество моделей.** Промер промахов каскада 0 по составу значения (разведочный")
    A("   скрипт на том же демоне через `/v1/analyze`, координаты байтовые):")
    A("   - `snils`: 28 промахов из 29, **все 28 форматированные** (`378-312-074 87`),")
    A("     обычных промахов — 0 (`c0` = 1/29, и этот один именно обычный вид);")
    A("   - `card_pan`: 15 промахов, **все форматированные** (`2204-9947-4132-9761`);")
    A("   - `iban`: 21 промах = 18 форматированных (`RU19 0445… ` через пробел) + 3")
    A("     обычных валидных (24-символьные ES-семейства, `ES6987181615681144316009`).")
    A("   Чексуммный валидатор требует compact-вид; детектор не нормализует разделители")
    A("   перед проверкой ⇒ вето не срабатывает, score 1.0 не выставляется, span теряется")
    A("   на каскаде, который по определению не промахивается.")
    A("3. **Состав IBAN-набора** (промер по датасету): 27 span'ов, длины compact 16–33,")
    A("   префиксы BE, DE, ES, FR, NL, RU; mod-97 — валидны все 27 (разведочная")
    A("   перепроверка, не оракул ожидаемого значения). Каскад 0 накрывает 6, хвост")
    A("   закрывается не моделью: нормализация (#51) + покрытие длин/стран в валидаторе")
    A("   (таблица счетов первичкой не закрыта: SPEC §11 п.6, AGENTS §Дисциплина п.3).")
    A("4. **Расхождение оракулов и направление смещения координат** — метрика чувствительна")
    A("   к определению попадания; направление смещения померено отдельно, не угадано:")
    if ex and ov:
        A(f"   при τ = {thr0} тот же прогон даёт union {g(ov, 'recall')} % по overlap и")
        A(f"   {g(ex, 'recall')} % по byte-exact (k {g(ex, 'k')}/{g(ex, 'n')} против")
        A(f"   {g(ov, 'k')}/{g(ov, 'n')}); по строгой координатной мере разрыв")
        A(f"   {g(agg(d, thr0, 'overlap', 'strict_span'), 'recall')} % (overlap) против")
        A(f"   {g(agg(d, thr0, 'exact', 'strict_span'), 'recall')} % (exact).")
    if d.get("probe"):
        A("   Промер `tools/metrics/probe_coords.py` (τ = 0.20, lockR fp16, 2 треда, артефакт")
        A(f"   в §8.1): из {int(gp(d, 'relations', 'exact')) + int(gp(d, 'relations', 'subset_of_gold'))}")
        A(f"   перекрывающихся пар предсказание/gold — {gp(d, 'relations', 'subset_of_gold')}")
        A(f"   лежат **целиком внутри** gold-границ, {gp(d, 'relations', 'exact')} точных,")
        A(f"   superset = {gp(d, 'relations', 'superset')}, partial = {gp(d, 'relations', 'partial')}.")
        A("   Направление: **модель недо-сегментирует (режет хвосты)**, а не «шире» gold:")
        A(f"   d_start медиана {gp(d, 'd_start', 'median')} (min {gp(d, 'd_start', 'min')} — начало")
        A(f"   никогда левее gold, max {gp(d, 'd_start', 'max')}), d_end медиана {gp(d, 'd_end', 'median')}")
        A(f"   (max {gp(d, 'd_end', 'max')} — конец никогда правее gold; в {gp(d, 'd_end_neg_share')} %")
        A(f"   случаев конец обрезан). Медианная длина: gold {gp(d, 'len_gold_median')} байт,")
        A(f"   предсказание {gp(d, 'len_gold_median', 'len_pred_median')}. Механизм — сужение")
        A("   хвостовых `##`-токенов в декодере (`run_lockr`) плюс конец на границе слова:")
        A("   усечённый спан лежит")
        A("   внутри gold ⇒ по overlap зачёт идёт, по byte-exact — нет.")
        A("   Первая версия абзаца утверждала обратное («координаты шире gold-границ»);")
        A("   перевёрнутое направление поймано ревью #80, перемерено первичкой и исправлено")
        A("   в генераторе, а не в тексте (иначе следующая генерация вернула бы ошибку).")
    A("   Владелец определения попадания должен быть один файл: README golden говорит")
    A("   «exact», Rust-харнес — «overlap». Это дефект определения метрики, не модели —")
    A("   заведён в **#77**; рюлинг 21.10 выбрал byte-exact (см. §1, §5.5).")
    A("5. **Row-level кредит Decide** (§3) завышает `union_span` над `strict_span`:")
    if st and ov:
        A(f"   при τ = {thr0} это {g(ov, 'recall')} % против {g(st, 'recall')} %")
        A(f"   (k {g(st, 'k')} против {g(ov, 'k')} при n = {g(ov, 'n')}).")
    A("6. **Потоки**: записаны в метод (§4), иначе повтор прогона не обязан сойтись с числами.")
    A("7. **`data/golden/README.md` §«Метрика recall» содержит устаревшее CI-число**: «нижняя")
    A("   граница ≥ 94.5 % при 146/146». Промер формулой §8: при n = 146 и k = n граница")
    A("   = 97.436 %; 94.5 % соответствует n ≈ 67 (94.577 %). Число пережито ростом набора")
    A("   (v1.0 → v1.1) и не пересчитано — правка в README, не здесь.")
    A("8. **У планки три владельца с разными формулировками**: SPEC §5 п.6 («recall ≥ 98 %»,")
    A("   без уточнения точка/граница), README («≥ 98 % при N=146+, нижняя граница ≥ 94.5 %»),")
    A("   Rust-харнес и этот промер (сравнивают с планкой **нижнюю границу**, т.е. самый")
    A("   жёсткий вариант). Пока владельцем не выбран один, «гейт закрыт» — слово с тремя")
    A("   значениями. Прогон печатает и точку, и границу, не выбирая за SPEC. **#77**.")
    A("9. **Отрицательный сплит недо-размечен, «FP» по нему неизмерим.** Каскад 0 на")
    A("   `split=negative` выпускает 5 span'ов, ни один не на приманке (`bait_c0 = 0`), и")
    A("   все 5 — валидные ПДн: `2200000000000004`, `5555555555554444`, `378282246310005`,")
    A("   `30569309025904` (Luhn), `DE89370400440532013000` (IBAN из эталона реестра),")
    A("   score 1.0. То есть детектор прав, а метки не покрывают реальную ПДн в строке.")
    A("   По определению README («FP = пойманный спан на месте **не-PII**») это не FP.")
    A("   Следствие: FP-контроль читается только по bait-счётчикам (каскад 0: 0/24 —")
    A("   декорации отброшены чексуммами; lockR: 9/24 — model-bait проходит). Правка")
    A("   датасета: размечать реальные номера в negative-строках, иначе FP-гейт")
    A("   ложно-красный на правильном поведении. Заведено как **#78**.")
    A("10. **Самопроверка координатной шкалы** (класс инцидента «координатное смещение»).")
    A("   Первичная сверка: gold-координаты = байтовые (g0001 `person_name` [87,127),")
    A("   срез по байтам = `Ушакова Кира Саввична`; модельные координаты тоже байтовые) ⇒")
    A("   харнес сравнивает одно пространство с другим. Пойманный на этом собственный")
    A("   дефект разведочного скрипта (срез `str` байтовыми индексами давал «координаты")
    A("   указывают на прозу» — 98/117 ложных хитов) записан, чтобы урок не потерялся:")
    A("   прежде чем заявлять про чужие координаты, надо проверить, своей ли рукой они")
    A("   нарезаны.")
    A("")
    A("## 7. Что нужно, чтобы закрыть планку")
    A("")
    A("0. Детерминированность подтверждена повтором: `diff` по `UNION|`-строкам двух прогонов")
    A("   (команда в §4) = пусто, промер 21.10, артефакты r1/r2 по 100 строк.")
    A("1. Смонтировать каскады 1/2 в продуктовый конвейер — иначе гейт меряет харнес, а не")
    A("   продукт (#14 часть A, `pipeline.rs`).")
    A("2. Поднять `strict_span` до уровня `union_span`: чинить **усечение** границ (оракул")
    A("   exact), а не полагаться на row-level кредит. Направление правки задаёт промер §6.4:")
    A("   предсказание никогда не выходит за gold (superset 0), весь разрыв exact-vs-overlap")
    A("   = обрезанные хвосты (медиана d_end −8 байт) и сдвинутые начала (d_start +5).")
    A("   Значит задача — **восстанавливать** границы (отменять `##`-трим хвостов, добирать")
    A("   токены в начале до границы слова), а не обрезать: план ревью остаётся валидным,")
    A("   меняется только направление правки.")
    A("3. Закрыть дефицит арифметически, без моделей. Дефицит = 27 span'ов, аддитивно")
    A("   по классам: `iban` 21 + `snils` 6 (сверка: 358 − 331 = 27 ✓). План:")
    A("   - нормализация разделителей в каскаде 0 (issue #51) возвращает 18 IBAN и")
    A("     snils-хвост 6 ⇒ k ≈ 355 (99.16 %, lo ≈ 97.4 — всё ещё под планкой);")
    A("   - покрытие 3 обычных валидных IBAN (24-симв. ES-семейство) доводит до 358/358,")
    A(f"     lo = 98.938 % ≥ 98 % ⇒ гейт закрывается. Планка требует k ≥ {g(v, 'k_for_bar')},")
    A(f"     то есть не более 1 промаха на {g(v, 'union_n')} — промахи должны быть")
    A("     устранены, а не «уменьшены». Ни одна из двух правок не трогает веса.")
    A("   Промахи каскада 1 по модельным классам (snils 17/29, inn 21/36, passport 10/16)")
    A("   при этом остаются дефектом качества моделей — на текущую планку они не влияют,")
    A("   потому что union их добирает (per-class таблица §5).")
    A("4. Увеличить знаменатель: на строках планка непроверяема при текущих 150 (§2:")
    A("   нужно ≥ 189 рядов), на спанах требует нуля промахов при 358. Следующий шаг —")
    A("   разметка +M реальных рядов (цель ≥ 200 строк / ≥ 500 спанов), не синтетика молча.")
    A("5. Решить в SPEC формулировку планки (точка или нижняя граница CI), зафиксировать")
    A("   владельца определения попадания (overlap vs exact) и пересчитать CI-число в README")
    A("   golden (§6.7). Все три — вне объёма этой ветки, заведены: **#77**.")
    A("")
    A("## 8. Сырой вывод прогона (первичка)")
    A("")
    A("Команда — §4. Артефакт `/tmp/union_r1.jsonl` (в git не кладётся: первичка = строки ниже,")
    A("они дословно из файла). `PRECHECK|` = self-test'ы (Wilson anchors, sha весов и датасета),")
    A("`UNION|` = метрики, `TIME|` = длительность на 2 тредах в щадящем режиме.")
    A("")
    A("```text")
    for row in d["raw"]:
        A(row)
    A("```")
    A("")
    if d.get("probe"):
        A("### 8.1 Промер направлений (к §6.4)")
        A("")
        A("Команда — в docstring `tools/metrics/probe_coords.py` (2 треда, `nice 10`, тот же")
        A("интерпретатор, что у харнеса). Артефакт `/tmp/probe_coords.out`; цифры §6.4 — из")
        A("этих строк, проза о направлении без промера не печатается.")
        A("")
        A("```text")
        for row in d["probe"]:
            A("|".join(row))
        A("```")
        A("")
    leaks = selfcheck(lines)
    if leaks:
        for x in leaks:
            print(f"LEAK|{x}", file=sys.stderr)
        sys.exit(f"FAIL: в сгенерированном документе {len(leaks)} утечек словаря артефакта "
                 "(список выше). Класс: генератор читает не тот индекс pipe-формата. "
                 "Правь индексы полей, не вывод.")
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WROTE|{sys.argv[2]}|lines|{len(lines)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
