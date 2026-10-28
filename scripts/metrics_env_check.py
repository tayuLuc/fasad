#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""metrics_env_check — зуб «python-окружение промера запинено» (issue #81).

Канон: окружение промера union-recall восстанавливается из АРТЕФАКТА
(pyproject/uv.lock/.python-version/justfile в git), а не из устного рассказа.
Дрифт onnxruntime = другой инференс = другие recall-числа; sha-префлайт
харнеса (union_recall.verify_inputs) меряет веса/датасет/схему, НО НЕ
библиотеку ⇒ единственная защита = пин в lockfile + этот зуб.

Доктрина ложно-зелёного (#100-семья): контра сверяет МНЕНИЯ файлов ДРУГ С
ДРУГОМ (pyproject ↔ uv.lock ↔ .python-version ↔ recipe), а не наличие слов;
wheel-контра (#5) — по первичке PyPI-архива, сеть мертва = SKIP-строка, не
зелёный пропуск (#316-паттерн legs).

Проверки (stdlib-only, кросс-ОС, как golden_anchor_check):
1. RECIPE: recipe `union-recall` = `uv run` c `--locked` и `--group metrics`;
   без `--isolated` (обходит пин, дыра #81.3), без `~/.local` (домашний путь
   интерпретатора, #81.1), без unpinned `--with numpy|onnxruntime|tokenizers`
   (резолв на лету, #81.2).
2. GROUPS: `[dependency-groups] metrics` = РОВНО numpy, onnxruntime, tokenizers,
   каждый с `==`-пином.
3. LOCK: uv.lock знает группу (`[package.metadata.requires-dev].metrics`) с теми
   же версиями, и `[[package]]` каждой метрики version == пину.
4. PYVER: `.python-version` (канон X.Y, источник интерпретатора uv/CI) входит в
   requires-python pyproject. Драйвер волны колёс (onnxruntime ≤cp314 — первичка
   PyPI 28.10, промер `uv lock` на HEAD: на 3.15 «No solution found») закрывается
   проверкой 5: wheel-контра по тегу интерпретатора НЕ проходит для ORT на 3.15.
5. WHEELS: wheel pinned версии по тегу интерпретатора есть на всех трёх ОС
   CI-матрицы python-golden (ci.yml:638: manylinux / win_amd64 /
   macosx_*_arm64; abi3 считается).

Выход: rc=0 зелёный; rc=1 красный (строки `METASENV|FAIL|<код>|…`).
Использование: uv run --locked python scripts/metrics_env_check.py
(смонтирован в `just python-lint` = CI-джоба python-golden, 3 ОС).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JUSTFILE = ROOT / "justfile"
PYPROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "uv.lock"
PYVER = ROOT / ".python-version"
CACHE_DIR = Path(os.environ.get("FASAD_LOCAL_DIR", ROOT / ".local")) / "cache" / "metrics_env_check"
CACHE_TTL_S = 3600

METRICS = ("numpy", "onnxruntime", "tokenizers")
# ОС-матрица python-golden (ci.yml:638): ubuntu-24.04 / windows-2022 / macos-14.
# macos-14 = Apple Silicon: mac-нога ищет arm64-колесо (x86_64-ряд numpy cp313+
# не publishes — волна колёс, ci.yml:691-700).
OS_MARKS = (("linux", "manylinux", "aarch64", "x86_64"),
            ("windows", "win_amd64", "amd64", ""),
            ("macos", "macosx", "arm64", ""))


def fail(code: str, msg: str) -> None:
    print(f"METASENV|FAIL|{code}|{msg}")
    sys.exit(1)


# ── парсеры (свой мини-разбор: tomllib = py3.11+, канон проекта ниже) ─────────


def recipe_body(text: str, name: str) -> str:
    """Тело just-рецепта `name`: от объявления до первой пустой строки/EOF."""
    m = re.search(rf"(?m)^{re.escape(name)}(?:[^:\n]*)?:\n", text)
    if m is None:
        fail("RECIPE-MISSING", f"рецепт {name} не найден в justfile")
    tail = text[m.end():]
    end = re.search(r"(?m)^\s*$", tail)
    return tail[: end.start()] if end else tail


def dependency_group_lines(text: str) -> str:
    """Тело [dependency-groups] целиком (до следующего заголовка секции)."""
    m = re.search(r"(?m)^\[dependency-groups\][^\n]*\n", text)
    if m is None:
        return ""
    tail = text[m.end():]
    nxt = re.search(r"(?m)^\[", tail)
    return tail[: nxt.start()] if nxt else tail


def lock_package(text: str, name: str, version: str | None = None) -> str:
    """Блок [[package]] с name (и version, если задана). '' = нет блока."""
    for blk in re.split(r"(?m)^\[\[package\]\]\s*\n", text)[1:]:
        end = re.search(r"(?m)^\[\[?package", blk)
        if end:
            blk = blk[: end.start()]
        n = re.search(r'(?m)^name = "([^"]+)"', blk)
        v = re.search(r'(?m)^version = "([^"]+)"', blk)
        if n and n.group(1).lower() == name.lower() and (version is None or (v and v.group(1) == version)):
            return blk
    return ""


# ── арифметика версий/диапазонов (PEP 440, подмножество под канон проекта) ────


def ver_tuple(v: str) -> tuple[int, int, int]:
    d = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return (d + [0, 0, 0])[:3]


def _norm(t: tuple[int, int, int]) -> tuple[int, ...]:
    """'3.14.0' == '3.14' (PEP 440): срезаем хвостовые нули."""
    while len(t) > 1 and t[-1] == 0:
        t = t[:-1]
    return t


def req_includes(req: str, version: str) -> bool:
    """`version` (X.Y.Z) удовлетворяет диапазону (клаузы через ',' = И).
    Канон проекта = простые ==X.Y.* / >=X.Y / ~=X.Y; сложный синтаксис красным
    (зуб обязан понимать, что проверяет, а не молча проглатывать)."""
    vt = _norm(ver_tuple(version))
    for clause in (c.strip() for c in req.split(",")):
        if not clause:
            continue
        m = re.match(r"(==|>=|<=|~=|>|<)\s*([0-9][0-9A-Za-z.*]*)$", clause)
        if not m:
            fail("REQ-SYNTAX", f"вне канона проекта (простые ==/>=/~=): {clause!r}")
        op, target = m.groups()
        star = target.endswith(".*")
        tt = _norm(ver_tuple(target))
        if op == "==":
            if (star and vt[: len(tt)] != tt) or (not star and vt != tt):
                return False
        elif op == ">=" and vt < tt:
            return False
        elif op == "<=" and vt > tt:
            return False
        elif op == ">" and vt <= tt:
            return False
        elif op == "<" and vt >= tt:
            return False
        elif op == "~=" and (vt[:2] != tt[:2] or vt < tt):
            return False
    return True


def py_minor_in_range(req: str, minor: tuple[int, int]) -> bool:
    """Есть ли в диапазоне допустимая версия вида X.minor (калибровка по 3 точкам:
    X.minor.0 / X.minor.50 / X.minor.99)."""
    return any(req_includes(req, f"{minor[0]}.{minor[1]}.{p}") for p in (0, 50, 99))


# ── первичка PyPI (кэш в .local; мёртвая сеть = SKIP, не зелёный пропуск) ─────


def pypi_json(name: str, ver: str) -> dict | None:
    """JSON релиза PyPI. Кэш .local TTL 1 ч. None = сеть недоступна."""
    cache = CACHE_DIR / f"{name}-{ver}.json"
    if cache.is_file() and time.time() - cache.stat().st_mtime < CACHE_TTL_S:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except OSError as exc:
        print(f"METASENV|SKIP|pypi-unreachable|{name}=={ver}|{type(exc).__name__}")
        return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data), encoding="utf-8")
    return data


def wheel_present(files: list[str], tag_minor: int, os_mark: str, arch_needles: tuple[str, ...]) -> str:
    """Имя колеса для (python-тег, ОС), '' = нет. Поле python-тега (третье в
    wheel-имени: {dist}-{ver}-{pytag}-{abitag}-{plat}). abi3-колесо годится при
    tagv ≤ minor; free-threaded (cpXYt) НЕ годится (наш канон = GIL-сборка)."""
    pytag = re.compile(rf"^cp{tag_minor}$")
    for f in files:
        if os_mark not in f:
            continue
        if arch_needles and not any(a in f for a in arch_needles):
            continue
        parts = f[: -len(".whl")].split("-")
        if len(parts) < 5:
            continue
        # Wheel spec: имя = {dist}-{ver}-{pytag}-{abitag}-{platform}; dist/ver
        # нормализованы без «-» ⇒ последние три поля = теги. py-тег = parts[-3].
        py, abi = parts[-3], parts[-2]
        if abi == "abi3":
            mm2 = re.match(r"cp(\d+)$", py)
            if mm2 and int(mm2.group(1)) <= tag_minor:
                return f
        elif pytag.match(py):
            return f
    return ""


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    just = JUSTFILE.read_text(encoding="utf-8")
    pp = PYPROJECT.read_text(encoding="utf-8")
    lock = LOCK.read_text(encoding="utf-8")
    pyver = PYVER.read_text(encoding="utf-8").strip()

    # 1. RECIPE: union-recall = uv run --locked --group metrics, без дыр #81.1–3.
    body = recipe_body(just, "union-recall")
    if not body:
        fail("RECIPE-MISSING", "union-recall: пустое тело рецепта")
    joined = " ".join(body.split())
    if "uv run" not in joined:
        fail("RECIPE-UV", f"union-recall: нет `uv run`: {joined[:80]!r}")
    if "--locked" not in joined:
        fail("RECIPE-UNLOCKED", "union-recall: `uv run` без --locked (расхождение lock/pyproject не краснеет)")
    if not re.search(r"--group\s+metrics\b", joined):
        fail("RECIPE-GROUP", "union-recall: нет `--group metrics` (метрик-группа не подключена)")
    if "--isolated" in joined:
        fail("RECIPE-ISOLATED", "union-recall: `--isolated` обходит project-пин (#81.3)")
    if ".local" in joined:
        fail("RECIPE-HOMEPATH", "union-recall: домашний путь интерпретатора (#81.1)")
    for pkg in METRICS:
        if re.search(rf"--with\s+{pkg}\b", joined):
            fail("RECIPE-UNPINNED-WITH", f"union-recall: unpinned `--with {pkg}` (#81.2)")
    print("METASENV|recipe|union-recall|uv-run|--locked|--group-metrics|no-isolated|no-homepath|no-unpinned-with|ok")

    # 2. GROUPS: metrics = ровно три ==-пина.
    gsec = dependency_group_lines(pp)
    mm = re.search(r'(?m)^metrics = \[(.*?)\]', gsec, re.S)
    if not mm:
        fail("GROUP-MISSING", "[dependency-groups] без metrics (pyproject.toml)")
    raw = mm.group(1)
    pins: dict[str, str] = {}
    for item in re.findall(r'"([^"]+)"', raw):
        m = re.match(r"^([A-Za-z0-9._-]+)==([0-9][0-9A-Za-z.]*)$", item.strip())
        if m:
            pins[m.group(1).lower()] = m.group(2)
        else:
            fail("GROUP-NOPIN", f"metrics: элемент {item!r} без `==`-пина (версия на резолв = дрейф)")
    if set(pins) != set(METRICS):
        fail("GROUP-SET", f"metrics = {sorted(pins)} != {sorted(METRICS)}")
    print("METASENV|groups|metrics|" + "|".join(f"{p}=={pins[p]}" for p in METRICS) + "|ok")

    # 3. LOCK: группа в metadata + пакеты по пинам.
    if not re.search(r"(?m)^metrics = ", lock):
        fail("LOCK-GROUP", "uv.lock: [package.metadata.requires-dev] без metrics (лок не знает группу)")
    for pkg, ver in pins.items():
        blk = lock_package(lock, pkg, ver)
        if not blk:
            have = re.findall(rf'(?m)^name = "{pkg}"\nversion = "([^"]+)"', lock)
            fail("LOCK-DRIFT", f"uv.lock: {pkg}=={ver} нет (в локе: {sorted(set(have)) or 'нет пакета'})")
        if not re.search(rf'\{{ name = "{pkg}", specifier = "=={re.escape(ver)}" \}}', lock):
            fail("LOCK-SPEC", f"uv.lock requires-dev.metrics: нет specifier =={ver} для {pkg}")
    print("METASENV|lock|requires-dev=metrics|packages==pins|ok")

    # 4. PYVER ∈ requires-python pyproject (uv.lock дублирует его строкой 3).
    m = re.match(r"^(\d+)\.(\d+)$", pyver)
    if not m:
        fail("PYVER-FMT", f".python-version не X.Y: {pyver!r} (канон uv: мажор.минор)")
    minor = (int(m.group(1)), int(m.group(2)))
    pp_req = (re.search(r'(?m)^requires-python = "([^"]+)"', pp) or [None, ""])[1]
    lock_req = (re.search(r'(?m)^requires-python = "([^"]+)"', lock) or [None, ""])[1]
    if not pp_req:
        fail("PYPROJECT-REQ", "pyproject: requires-python не найден")
    if lock_req != pp_req:
        fail("LOCK-REQ-DRIFT", f"uv.lock requires-python {lock_req!r} != pyproject {pp_req!r}")
    if not py_minor_in_range(pp_req, minor):
        fail("PYVER-REQ", f".python-version {pyver} вне requires-python {pp_req!r}")
    print(f"METASENV|pyver|{pyver}|in|requires-python|lock==pyproject|ok")

    # 5. WHEELS pinned версий на трёх ОС CI-матрицы по тегу интерпретатора
    # (первичка PyPI, кэш .local; сеть мертва = SKIP). Верх onnxruntime
    # (cp311–cp314) из requires-python пакета проверяется здесь же (#81.3:
    # .python-version вне волны = группа metrics не резолвится).
    missing = 0
    tag = int(f"{minor[0]}{minor[1]:02d}")  # wheel-тег: 3.13 → cp313
    ort_req_pkg = ""
    for pkg in METRICS:
        data = pypi_json(pkg, pins[pkg])
        if data is None:
            continue  # SKIP напечатан: сеть мертва ≠ зелёный
        files = [f["filename"] for f in data.get("urls", []) if f["filename"].endswith(".whl")]
        if pkg == "onnxruntime":
            ort_req_pkg = (data.get("info", {}) or {}).get("requires_python", "")
        for osname, mark, a0, a1 in OS_MARKS:
            arch = tuple(x for x in (a0, a1) if x)
            w = wheel_present(files, tag, mark, arch)
            print(f"METASENV|wheel|{pkg}=={pins[pkg]}|{osname}|cp{tag}|{w or 'MISSING'}")
            missing += not w
    if ort_req_pkg:
        if not py_minor_in_range(ort_req_pkg, minor):
            fail("PYVER-ORT", f".python-version {pyver} вне onnxruntime requires-python "
                 f"{ort_req_pkg!r} (первичка PyPI: группа metrics не резолвится)")
        print(f"METASENV|pyver|{pyver}|in|onnxruntime-requires-python|{ort_req_pkg}|ok")
    if missing:
        fail("WHEEL-MISSING", f"{missing} колёс(ОС) нет для {pins} на cp{tag} (строки MISSING выше)")
    print("METASENV|verdict|ok|recipe+groups+lock+pyver+wheels")


if __name__ == "__main__":
    main()
