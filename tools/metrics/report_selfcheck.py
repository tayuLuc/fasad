#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# report_selfcheck — selfcheck + контра идемпотентности SHIPPED-документа (#351).
"""
Причина существования (issue #351). `render_report.py` собирает docs/golden-report.md
из артефакта прогона и самопроверяет СВОЙ вывод; CI мерил генератор только на
синтетике (`--self-test`). Shipped-файл в CI не перегенерировывался НИ РАЗУ:
первичка #349 — файл на HEAD до #349 не проходил `selfcheck()` собственного
генератора (2 утечки). Класс: документ = артефакт прогона, а уезжает от генератора
руками.

ЗУБЫ (stdlib-only, heavy-контур не нужен — рюлинг #81):

1. selfcheck(shipped) — словарные утечки и структурные вердикты из
   `render_report.selfcheck()`, прямо по shipped-файлу. Red-класс #349.

2. Контра идемпотентности: §8-артефакт извлекается из самого документа
   (`extract_report_artifact.py`), генератор прогоняется в tmp, вывод сравнивается
   с shipped. Документ = f(артефакт), руки в генерируемую область не лезут.
   Инструмент НИЧЕГО не пишет в документ: правка shipped-файла = перегон
   `just union-report` (иначе гейт стал бы рукописателем).

ОБЛАСТЬ СРАВНЕНИЯ = СЕКЦИИ, А НЕ ВСЁ ФАЙЛ (промер 28.10, первичка `git log -S` по
docs/golden-report.md). В shipped-файле живут РУЧНЫЕ ВСТАВКИ эпох v1.2/v1.3
(#200-A2 влит `8f1a909`, #78/#289 влит `dac5a89`, #217 влит `ad5f396`) — 59
строк, которых генератор не эмитирует НИ В ОДНОЙ из своих версий (проверено на
`a464cf4`, самом старом авторе документа):

  • вставки в середине §2/§5/§6 (разделы 5.3b/5.3c, «Срез устарел на v1.3»,
    #78-закрытие, покрывка каскада 0 #200-A2) — раздвигают нумерацию строк и
    роняют полновесовой diff на 60 −/6 + строк;
  • §6 п.1/п.9 и §7 п.5 у генератора — ГЛОССЫ: §6 п.1 к тому же спорит с
    реальностью («person_name, phone, email, address, passport в продукте не
    детектируются вовсе» против «детекторы паспорт/телефон» из заголовка #211).

Полнофайловое сравнение краснеет на этом как на «дрифте», где ни одна строка не
текущий дефект: это история срезов, которую рюлинг #182 п.1 (история = git+PR, не
док) велит из docs выносить, а не запекать в генератор. Молча подгонять генератор
= перенести в него спорную прозу; молча проглотить = ложно-зелёный гейт.

Поэтому сравнение идёт по разделам: разделы, смонтированные в генераторе
(есть в его выводе), сравниваются ЦЕЛИКОМ — вставка внутри раздела красна;
разделов, которых в выводе нет (= ручная вставка = граница эпохи), сравнение не
касается, и каждый из них печатается строкой `SCOPE|` — сужение области
записано, а не стало слепой зоной (реестр ложно-зелёных: гейт обязан называть,
что он НЕ меряет).

rc-контракт (тот же, что у `lang-scan` #105/#116 F5, `report-selftest`):
  0 = GREEN, оба зуба чисты;
  1 = RED: selfcheck-утечки в shipped-файле и/или дрифт перегенерации внутри
      смонтированных разделов — реальный дефект #351;
  2 = проверка НЕ ВЫПОЛНЕНА: артефакт не извлечён, пустой вывод генератора,
      пустая область сравнения, нет `## 1.`. «Успех» без проверки = ложь о
      причине отказа.

Живость контроля — `--self-test`: порченый shipped-файл обязан дать rc=1 (две
порчи: словарь-утечка и ручная правка числа), файл без артефакта — rc=2.
Мёртвый контроль = rc=2 (контракт `report-selftest`).

Использование:
  uv run --locked python tools/metrics/report_selfcheck.py [docs/golden-report.md]
"""
from __future__ import annotations

import difflib
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# `parent.parent` от ЭТОГО файла = tools/, а не корень репозитория: корень =
# parent³ (tools/metrics/report_selfcheck.py). Ошибка на этой строке даёт
# `tools/tools/metrics/render_report.py` = FileNotFoundError вместо вердикта
# (промер локального прогона 28.10) — ложь о причине отказа, rc 2 вместо rc 0/1.
ROOT = Path(__file__).resolve().parents[2]
TOOLSDIR = Path(__file__).resolve().parent
GEN = TOOLSDIR / "render_report.py"
EXTRACT = TOOLSDIR / "extract_report_artifact.py"

FIRST_SECTION = "## 1."
DIFF_BUDGET = 40  # строк unified-диффа в stderr; полный — во временном файле


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        sys.exit("DRIFT|rc|2|невозможно загрузить модуль selfcheck: " + str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def heads(lines: list[str]) -> list[tuple[int, str]]:
    """Заголовки разделов второго уровня: [(индекс, текст)]."""
    return [(i, ln) for i, ln in enumerate(lines) if ln.startswith("## ")]


def split_sections(lines: list[str]) -> dict[str, list[str]]:
    """{заголовок: строки раздела (заголовок + тело до следующего `## `)}."""
    hs = heads(lines)
    out: dict[str, list[str]] = {}
    for n, (i, h) in enumerate(hs):
        j = hs[n + 1][0] if n + 1 < len(hs) else len(lines)
        out[h] = lines[i:j]
    return out


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def regenerate(doc_path: Path, work: Path) -> list[str] | None:
    """Перегон документа из его же §8-артефакта. None = прогон невозможен (rc 2)."""
    raw = work / "raw.jsonl"
    probe = work / "probe.out"
    ex = run([sys.executable, str(EXTRACT), str(doc_path), str(raw), str(probe)])
    sys.stdout.write(ex.stdout)
    sys.stdout.write(ex.stderr)
    if ex.returncode != 0:
        print("DRIFT|rc|2|§8-артефакт не извлечён — проверка НЕ выполнена", file=sys.stderr)
        return None
    out = work / "regen.md"
    cmd = [sys.executable, str(GEN), str(raw), str(out)]
    if probe.read_text(encoding="utf-8").strip():
        cmd.append(str(probe))
    gen = run(cmd)
    sys.stdout.write(gen.stdout)
    sys.stdout.write(gen.stderr)
    if not out.is_file():
        # Генератор сам прошёл свой selfcheck и отказался писать файл из ЭТОГО
        # артефакта: утечки #349 живут в первичке, а не только в прозе файла.
        print(f"DRIFT|rc|1|генератор отказался писать документ из §8-артефакта "
              f"(rc={gen.returncode}) — первичка порождена утечками", file=sys.stderr)
        sys.exit(1)
    regen = out.read_text(encoding="utf-8").splitlines()
    if not regen:
        print("DRIFT|rc|2|пустой вывод генератора — проверка не выполнена", file=sys.stderr)
        return None
    return regen


def measure(doc_path: Path, work: Path) -> int:
    doc = doc_path.read_text(encoding="utf-8").splitlines()

    # Зуб 1: selfcheck shipped-файла словарями и структурными связями генератора.
    leaks = _load("rr_for_selfcheck", GEN).selfcheck(doc)

    regen = regenerate(doc_path, work)
    if regen is None:
        for x in leaks:
            print(f"LEAK|{x}", file=sys.stderr)
        return 2

    dsec = split_sections(doc)
    # Проверка «есть ли раздел ## 1.» НЕ через `FIRST_SECTION in dsec`: dsec —
    # dict, а его ключи = ПОЛНЫЕ заголовки («## 1. Планка и формула»), префикс
    # там не ищется ⇒ проверка краснела бы на любом валидном документе
    # (промер 28.10: rc=2 на shipped-файле, где §1 есть).
    if not any(h.startswith(FIRST_SECTION) for h in dsec):
        print("DRIFT|rc|2|нет раздела `## 1.` — документ не выход render_report.py",
              file=sys.stderr)
        return 2

    # СРАВНЕНИЕ = ПОЛНЫЙ ФАЙЛ (промер 28.10, первичка diff'а выше). Попытка
    # сузить область до разделов (`## `) мертва на этом документе: ручные вставки
    # эпох живут ВНУТРИ разделов §2/§5/§6 (`### 5.3b`, `### 5.3c`, проза после
    # абзацев), поэтому сравнение по разделам даёт ровно тот же 60−/6+ дрифт,
    # что и полный файл (промер: `SCOPE|compared|8/8|excluded|0`). Любой
    # сужающий фильтр здесь = молчаливое проглатывание правок чисел руками,
    # т.е. ложно-зелёный гейт. Полный diff и есть честный RED-лист (#351).
    body = list(difflib.unified_diff(regen, doc, fromfile="generated (f(§8-артефакт))",
                                    tofile=f"shipped {doc_path.name}", lineterm="", n=2))
    changed = [d for d in body if d[:1] in "+-" and d[:3] not in ("---", "+++")]
    removed = sum(1 for d in changed if d.startswith("-"))
    added = sum(1 for d in changed if d.startswith("+"))
    scope = classify(body)

    # Порядок: SCOPE (что гейт НЕ меряет) → LEAK (всё дерево) → дрифт (rc).
    for ln in scope:
        print(ln)
    for x in leaks:
        print(f"LEAK|{x}", file=sys.stderr)

    if changed:
        (work / "drift.diff").write_text("\n".join(body) + "\n", encoding="utf-8")
        print(f"DRIFT|rc|1|дрифт генератора vs shipped: {len(changed)} строк "
              f"({removed} в shipped нет, {added} сверх генератора), "
              f"{len(scope) - 1} блоков расхождения; полный дифф: {work / 'drift.diff'}",
              file=sys.stderr)
        for d in body[:DIFF_BUDGET]:
            print(d, file=sys.stderr)
        if len(body) > DIFF_BUDGET:
            print(f"... ещё {len(body) - DIFF_BUDGET} строк диффа — см. "
                  f"{work / 'drift.diff'}", file=sys.stderr)
        return 1
    if leaks:
        print(f"DRIFT|rc|1|selfcheck shipped-документа: {len(leaks)} утечек", file=sys.stderr)
        return 1
    print(f"DRIFT|rc|0|идемпотентность держится: документ == f(§8-артефакт), "
          f"selfcheck чист | doc_lines|{len(doc)}")
    return 0


def classify(body: list[str]) -> list[str]:
    """RED-лист расхождений: сводка + построчная классификация блоков diff'а.

    Классы = первичка `git log -S` по docs/golden-report.md (см. docstring):
      epoch-slice  = вставка со ссылкой на эпоху/промер (v1.x, #NN, «промер») —
                     история срезов датасета, рюлинг #182 п.1 велит выносить из дока;
      UNCLASSIFIED = расхождение без метки эпохи = кандидат на реальный дефект.
    Классификация ИНФОРМАЦИОННАЯ: rc=1 даёт любое расхождение, молча не
    проглатывается ничего (реестр ложно-зелёных: whitelist, который глотает, =
    ложь; здесь whitelist печатает, но не глушит).
    """
    epoch = re.compile(r"v1\.\d+|#\d{2,}|промер|PR #", re.IGNORECASE)
    blocks: list[tuple[str, list[str]]] = []
    tag, cur = "@@ ?", []
    for d in body:
        if d.startswith("@@"):
            if cur:
                blocks.append((tag, cur))
            tag, cur = d.split(" ")[1], []
        elif d[:1] in "+-" and d[:3] not in ("---", "+++"):
            cur.append(d)
    if cur:
        blocks.append((tag, cur))
    out = []
    for tag, grp in blocks:
        kind = "epoch-slice" if epoch.search(" ".join(grp)) else "UNCLASSIFIED"
        out.append(f"SCOPE|block|{tag}|{len(grp)} строк|{kind}")
    n_ep = sum(1 for o in out if o.endswith("epoch-slice"))
    out.insert(0, f"SCOPE|blocks|{len(out)}|epoch-slice|{n_ep}|unclassified|"
                  f"{len(out) - n_ep}|область=полный файл (сужение до разделов мертво: "
                  "вставки живут внутри §2/§5/§6)")
    return out


def _plant_leak(src: Path, dst: Path) -> None:
    """Порченый shipped-файл: голое имя поля артефакта в прозе (класс #349)."""
    lines = src.read_text(encoding="utf-8").splitlines()
    i = next(i for i, ln in enumerate(lines) if ln.startswith("## 2."))
    lines.insert(i + 2, "- дефицит = deficit_spans span'ов, планка 98 % закрыта")
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plant_drift(src: Path, dst: Path) -> None:
    """Порченый shipped-файл: число правится ВРУЧНУЮ в смонтированном разделе."""
    lines = src.read_text(encoding="utf-8").splitlines()
    i = next(i for i, ln in enumerate(lines) if "отрицательных рядов" in ln and "bait" in ln)
    lines[i] = re.sub(r"отрицательных рядов \d+", "отрицательных рядов 99", lines[i])
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_self_test(doc: Path) -> int:
    """Positive control: живой контроль ловит подсаженное, мёртвый = rc=2."""
    if not doc.is_file():
        print("CONTROL|shipped-документ не найден — контроль мёртв", file=sys.stderr)
        return 2
    dead = 0
    plan = [("planted-leak", _plant_leak, 1),
            ("planted-drift", _plant_drift, 1),
            ("no-artifact", None, 2)]
    with tempfile.TemporaryDirectory(prefix="report-selfcheck-ctl-") as tmp:
        for n, (name, plant, want) in enumerate(plan):
            work = Path(tmp) / f"v{n}"
            work.mkdir()
            path = work / "doc.md"
            if plant is None:
                path.write_text("# Пустышка\n\nбез §8\n", encoding="utf-8")
            else:
                plant(doc, path)
            rc = measure(path, work)
            if rc == want:
                print(f"CONTROL|{name}|caught|rc={rc} (ожидался {want})")
            else:
                print(f"CONTROL|{name}|MISSED|rc={rc}, ожидался {want} — контроль мёртв",
                      file=sys.stderr)
                dead = 2
    if dead:
        print("FAIL: positive control мёртв — гейт декларирован, но не жив",
              file=sys.stderr)
    return dead


def main() -> int:
    # cp1252-guard (CI windows-2022, python-golden): stdout раннера = cp1252,
    # кириллические print'ы падают UnicodeEncodeError ДО вердикта = ложно-красный
    # зуб (промер CI run 40666552999; канон = render_report.py:585-596, зуб
    # `CP1252-GUARD` в scripts/metrics_env_check.py). reconfigure utf-8 =
    # стандарт CPython для класса, errors="replace" — запас для узких страниц.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # stdout заменён (redirect_stdout в селфтестах) — не трогать
    target = ROOT / "docs" / "golden-report.md"
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return run_self_test(target)
    if len(sys.argv) == 2:
        target = Path(sys.argv[1])
    elif len(sys.argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    return measure(target, Path(tempfile.mkdtemp(prefix="report-selfcheck-")))


if __name__ == "__main__":
    sys.exit(main())
