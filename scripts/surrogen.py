#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""surrogen — генератор пула суррогатов `data/morph/surrogates.tsv`.

Пул суррогатов (`guard-vault`) был списком из 24 имён, по 4 леммы на позицию;
этого хватает ровно на несколько ФИО в сессии: на золотом наборе 347 пар из 351
делят хотя бы один слот (#60, шаг 7а). Скрипт собирает пул побольше из **той же
первички**, что и морф-таблица, — golden-таблиц форка
`rodem/petrovich-rs@019e06d` (`tests/data/{surnames,firstnames,midnames}.tsv`,
MIT, §2 `THIRD-PARTY-NOTICES.md`).

Отбор леммы (по порядку, счётчики — в stderr):

1. в первичке у леммы ровно один род и полный набор из шести падежей единственного
   числа (полная парадигма — иначе `inflect_typed` нечем будет согнуть);
2. род строго `мр` или `жр` (двуродные `мр-жр` и общий род отброшены: пул должен
   давать форму заданного рода, а не «какой повезёт»);
3. кириллица без `Ё` и дефисов, длина 4..18 (нормализация `Ё→Е` в движке делает
   `Ё`-леммы недостижимыми по ключу, составные — ломает гнёзда);
4. окончание из продуктивного семейства (фамилии `-ов/-ев/-ин/-ын/-ский/-цкий`,
   отчества `-ович/-евич`, `-овна/-евна`): непродуктивные формы — то же самое
   зеркало правил, которое мы сами же и используем для сгибания;
5. лемма не встречается среди токенов `person_name` в `data/golden/golden-v1.jsonl`
   (иначе суррогат мог бы совпасть с настоящим именем в том же документе и гейт P6
   `is_current_surrogate` отверг бы легитимный запрос как повторную анонимизацию);
6. леммы нет в `DROP` ниже — её отвергает **наша** морф-таблица (промерен тестом
   `surrogate_pool_declines_in_every_case`, не на глаз).

Отбор детерминирован: внутри корзины (тип, род) кандидаты сортируются по
`sha256(лемма)` и берётся первые `LIMIT` — не «первые по алфавиту», чтобы пул не
слипался в углу словаря. Порядок байтов в файле — `(тип, род, лемма)` по возрастанию.

Воспроизводимость вне этой машины: скрипт требует смонтированной первички (те же
предпосылки, что `tools/morph-gen/proto2.py`, и та же осознанная граница
gutter-инструмента по AGENTS п.6). Артефакт защищён от молчаливой правки длиной и
sha256 в `crates/guard-vault/src/pool.rs`, а его свойства (число лемм на корзину,
полное сгибание нашей таблицей, непересечение с golden) проверяются Rust-тестами —
то есть CI проверяет артефакт, не имея первички.

Запуск: `uv run --locked python scripts/surrogen.py [лимит]`.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict

DATA = pathlib.Path.home() / ".cargo/git/checkouts/petrovich-rs-a943224988e65988/019e06d/tests/data"
REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "data/morph/surrogates.tsv"
GOLDEN = REPO / "data/golden/golden-v1.jsonl"

LIMIT = 128
CASES = {"им": "nom", "рд": "gen", "дт": "dat", "вн": "acc", "тв": "ins", "пр": "pre"}
NEED = frozenset(CASES.values())
FILES = {"surname": "surnames.tsv", "firstname": "firstnames.tsv", "midname": "midnames.tsv"}
# Отвергнутые нашей таблицей: промер тестом `surrogate_pool_declines_in_every_case`.
DROP: frozenset[str] = frozenset(
    {
    "Авазхан",
    "Адилия",
    "Азамат",
    "Азриль",
    "Айсен",
    "Алвиан",
    "Алевтин",
    "Ализаде",
    "Алифер",
    "Алказар",
    "Алмамбет",
    "Альфинор",
    "Анани",
    "Анаталья",
    "Андриа",
    "Антони",
    "Антоно",
    "Анчел",
    "Аорет",
    "Арзен",
    "Артен",
    "Асения",
    "Асон",
    "Аурелья",
    "Аюлия",
    "Балдан",
    "Билель",
    "Валихан",
    "Васния",
    "Вилля",
    "Вильдан",
    "Владильен",
    "Галиуллин",
    "Гатаулин",
    "Говард",
    "Гузэлия",
    "Гюзалия",
    "Даниэль",
    "Дасия",
    "Джорджо",
    "Дильмат",
    "Дория",
    "Евфания",
    "Ерануш",
    "Заби",
    "Интерия",
    "Ирания",
    "Иумания",
    "Люман",
    "Меруджан",
    "Муддарис",
    "Музаффар",
    "Мухарби",
    "Мэтью",
    "Наджи",
    "Неонилия",
    "Отто",
    "Палинария",
    "Пауль",
    "Радван",
    "Рафаэль",
    "Рахимьян",
    "Самат",
    "Саудат",
    "Сафроний",
    "Свирид",
    "Терезия",
    "Фабрицио",
    "Федерико",
    "Феруз",
    "Фиринат",
    "Франсуа",
    "Эльфер",
    "Эрнестас",
    "Эффалия",
    }
)
ENDINGS = {
    "surname": {"m": ("ОВ", "ЕВ", "ИН", "ЫН", "СКИЙ", "ЦКИЙ"), "f": ("ОВА", "ЕВА", "ИНА", "ЫНА", "СКАЯ", "ЦКАЯ")},
    "firstname": {"m": None, "f": ("А", "Я")},
    "midname": {"m": ("ОВИЧ", "ЕВИЧ"), "f": ("ОВНА", "ЕВНА")},
}
CYR = re.compile(r"[А-Я]+")


def title(upper_lemma: str) -> str:
    """«ВЕТРОВА» -> «Ветрова»: заглавная плюс строчные остальное."""
    return upper_lemma[:1] + upper_lemma[1:].lower()


def golden_tokens() -> set[str]:
    """Токены ФИО из нашего golden-набора, в верхнем регистре без `Ё`."""
    out: set[str] = set()
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        for sp in rec.get("spans", []):
            if sp.get("category") != "person_name":
                continue
            value = sp.get("value_source") or rec["text"][sp["start_byte"] : sp["end_byte"]]
            for word in value.split():
                out.add(word.upper().replace("Ё", "Е"))
    return out


def buckets(stats: dict[str, int]) -> dict[tuple[str, str], set[str]]:
    """Кандидаты по корзинам `(тип, род)` с фильтрами 1..6."""
    golden = golden_tokens()
    pool: dict[tuple[str, str], set[str]] = defaultdict(set)
    for typ, fname in FILES.items():
        path = DATA / fname
        if not path.is_file():
            raise SystemExit(f"нет первички: {path} (нужен смонтированный клон petrovich-rs на пине)")
        genders: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        with path.open(encoding="utf-8-sig") as fh:
            fh.readline()  # заголовок lemma/word/grammemes
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                lemma, _, grammemes = parts[0], parts[1], parts[2]
                gender = case = None
                singular = False
                for tok in grammemes.split(","):
                    if tok in ("мр", "жр", "мр-жр"):
                        gender = tok
                    elif tok in CASES:
                        case = CASES[tok]
                    elif tok == "ед":
                        singular = True
                if gender is None or case is None or not singular:
                    continue
                genders[lemma][gender].add(case)
        for lemma, byg in genders.items():
            stats["всего лемм"] += 1
            if len(byg) != 1:
                stats["несколько родов"] += 1
                continue
            gender, caseset = next(iter(byg.items()))
            if gender == "мр-жр":
                stats["двуродные"] += 1
                continue
            if caseset != NEED:
                stats["неполная парадигма"] += 1
                continue
            flat = lemma.replace("Ё", "Е")
            if not CYR.fullmatch(flat) or not 4 <= len(flat) <= 18:
                stats["не кириллица или длина"] += 1
                continue
            if flat in golden:
                stats["пересекает golden-v1"] += 1
                continue
            gk = "m" if gender == "мр" else "f"
            allow = ENDINGS[typ][gk]
            if allow is not None and not any(flat.endswith(suf) for suf in allow):
                stats["непродуктивное окончание"] += 1
                continue
            if title(flat) in DROP:
                stats["в DROP"] += 1
                continue
            pool[(typ, gk)].add(title(flat))
            stats[f"ГОДНО {typ}/{gk}"] += 1
    return pool


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    limit = int(sys.argv[1]) if len(sys.argv) == 2 else LIMIT
    if limit < 4:
        raise SystemExit(f"лимит {limit} меньше прежнего пула (4) — это не расширение")
    stats: dict[str, int] = defaultdict(int)
    pool = buckets(stats)
    picked: list[tuple[str, str, str]] = []
    for (typ, gk), cands in sorted(pool.items()):
        ordered = sorted(cands, key=lambda w: (hashlib.sha256(w.encode()).hexdigest(), w))
        take = ordered[:limit]
        if len(take) < limit:
            raise SystemExit(f"корзина {typ}/{gk}: кандидатов {len(take)}, просим {limit}")
        picked.extend((typ, gk, w) for w in sorted(take))
    body = "\n".join(
        [
            "# Пул суррогатов: тип ⇥ род ⇥ лемма (шаг 7а, #60).",
            "# Сгенерировано scripts/surrogen.py из первички petrovich-rs@019e06d.",
            "# Леммы заглавными не пишутся: суррогат подставляется в текст как обычное имя.",
            f"# По {limit} лемм на корзину, всего {len(picked)}.",
        ]
        + [f"{typ}\t{gk}\t{word}" for typ, gk, word in picked]
        + [""],
    )
    OUT.write_text(body, encoding="utf-8", newline="\n")
    for key in sorted(stats):
        print(f"{key}: {stats[key]}", file=sys.stderr)
    print(f"{OUT}: {len(picked)} лемм, лимит {limit} на корзину", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
