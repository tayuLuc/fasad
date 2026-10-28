#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# extract_report_artifact — §8-артефакт ПРОГОНА из сгенерированного документа.
"""
Причина существования (#351): `render_report.py` умеет собирать документ из артефакта,
но CI мерил генератор только на синтетике (`--self-test`) — сам shipped-документ
`docs/golden-report.md` никто не перегенерировывал. Класс дефекта: документ =
артефакт прогона, а уезжает от генератора руками (первичка: #349 поймал 2 утечки,
которые жили в файле).

Сырой прогон в документ вкладывается ОДИНАРНЫМ fence ` ```text ` (первичка
`render_report.py:1028-1043`: §8 — строки `d["raw"]`, §8.1 — `d["probe"]`).
Внешних 4-backtick-обёрток в shipped-документе нет; закрывающая строка обязана
совпадать с открывающей по длине, иначе внутренний ` ```text ` проглотится
и блок выйдет обрезанным молча.

Stdlib-only, без зависимостей: python-golden-нога CI не поднимает heavy-контур.

Контракт rc:
  0 = извлечено; `RAW|<n>` и `COORD|<n>` в stdout, файлы записаны;
  2 = артефакт НЕ извлечён (нет §8 / нет §8.1 / пустой блок) — «успех» без
      содержимого = ложь о причине отказа, тот же rc-контракт, что у `lang-scan`
      (#105/#116 F5) и `report-selftest`.

Координатный блок §8.1 опционален: без него §6 п.4 печатает «?» (контракт
`render_report.py:956-965`).
"""
from __future__ import annotations

import sys
from pathlib import Path

RAW_HEADING = "## 8. Сырой вывод прогона"
COORD_HEADING = "### 8.1"


def fence_open(ln: str) -> str | None:
    """Формат открывающей fence-строки: 3+ backtick'а + опц. язык, без хвоста."""
    s = ln.rstrip()
    i = 0
    while i < len(s) and s[i] == " ":
        i += 1
    if not s[i:].startswith("```"):
        return None
    rest = s[i + 3:]
    n = 3
    while rest.startswith("`"):
        n += 1
        rest = rest[1:]
    if "`" in rest:
        return None
    return "`" * n


def block_after(doc: list[str], heading: str) -> list[str] | None:
    """Строки первого fenced-блока после заголовка `heading` (префикс-матч)."""
    start = next((i for i, ln in enumerate(doc) if ln.startswith(heading)), None)
    if start is None:
        return None
    # Первый fence ПОСЛЕ заголовка. `doc.index(opener)`-трюк недопустим: он ищет
    # по всему файлу и возвращает fence из §4/§5.5 (ложный артефакт = 1 строка).
    oidx = next((i for i in range(start, len(doc)) if fence_open(doc[i])), None)
    if oidx is None:
        return None
    marker = fence_open(doc[oidx])
    body: list[str] = []
    for ln in doc[oidx + 1:]:
        if ln.rstrip() == marker:
            return body
        body.append(ln)
    return None


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    doc = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    raw = block_after(doc, RAW_HEADING)
    if raw is None:
        print("FAIL: §8-артефакт не найден (нет заголовка/незакрытый fence) — "
              "документ не является выходом render_report.py", file=sys.stderr)
        return 2
    if not raw:
        print("FAIL: §8-блок пуст — извлекать нечего", file=sys.stderr)
        return 2
    Path(sys.argv[2]).write_text("\n".join(raw) + "\n", encoding="utf-8")
    print(f"RAW|{len(raw)}")
    coord = block_after(doc, COORD_HEADING)
    if coord is None:
        coord = []
    Path(sys.argv[3]).write_text("\n".join(coord) + ("\n" if coord else ""),
                                 encoding="utf-8")
    print(f"COORD|{len(coord)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
