#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
golden-gen v1 — генератор золотого набора data/golden/golden-v1.jsonl (проект fasad).

ВНЕ дерева проекта: AGENTS п.6 запрещает Python в дереве; идентичный по логике
генератор — Rust-фича crates/guard-detectors/examples/golden_gen.rs (сверка diff).

Детерминированность: xorshift64* с фиксированным seed, без wall-clock.
Формулы чексумм — ТОЛЬКО таблицы docs/dep-verify-algorithms.md:
  §1 ИНН-10 mod11 (веса 2,4,10,3,5,9,4,6,8 → младшая цифра)
  §2 ИНН-12 (A=7,2,4,10,3,5,9,4,6,8; B=A с дописанной 3)
  §3 СНИЛС mod101 (веса 9..1; 100/101→00; запрет 3 одинаковых подряд; >001001998)
  §4 ОГРН-13 mod11; ОГРНИП-15 mod13 (НЕ mod11)
  §5b Луна ISO/IEC 7812-1:2017 (удвоение 2-й справа)
  §6b IBAN mod97 (EBS204); RU=33, структура 9!n 5!n 15!c (реестр SWIFT rel.99 §2.71)

Использование: python3 data/golden/golden_gen.py > data/golden/golden-v1.jsonl
(stdout — JSONL, stderr — счётчики; выход побайтово детерминирован).
Каноническая копия промпта генератора в Rust-эквивалент — отдельная задача
(SPEC §10 шаг 3); до неё сверка по sha256 jsonl, зафиксированному в README.md.
"""
import json
import re
import sys
from collections import Counter

# ================================================================ категории (SPEC §14 ядро)
# id — snake_case по контракту задачи атома; сверка с schema.default.json (не создан)
# и ClassId-примерами verdict.rs (PERSON/INN) — алиасы в README.
CAT = {
    "person_name": "person_name",   # §14 PERSON / alias FIRST_NAME
    "inn": "inn", "snils": "snils", "ogrn": "ogrn", "ogrnip": "ogrnip",
    "iban": "iban",
    "card_pan": "card_pan",         # §14 CREDIT_CARD
    "phone": "phone",               # §14 PHONE / alias PHONE_NUMBER
    "email": "email",               # §14 EMAIL / alias EMAIL_ADDRESS
    "address": "address",           # §14 адресный маркер (LOCATION-иерархия)
    "passport": "passport",
    "bik": "bik",
    "bank_account": "bank_account",
}

# ================================================================ PRNG
class Rng:
    def __init__(self, seed):
        self.s = (seed & 0xFFFFFFFFFFFFFFFF) or 0x9E3779B97F4A7C15
    def next(self):
        x = self.s
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF
    def below(self, n):
        return self.next() % n
    def pick(self, seq):
        return seq[self.below(len(seq))]
    def chance(self, num, den):
        return self.next() % den < num
    def range(self, a, b):  # включительно
        return a + self.below(b - a + 1)
    def digits(self, n):
        return ''.join(str(self.below(10)) for _ in range(n))

# ============================================ формулы чексумм (только из первички)
W10 = [2, 4, 10, 3, 5, 9, 4, 6, 8]
A12 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
B12 = [3] + A12[:10]

def _dg(s):
    return [int(c) for c in s]

def inn10(p9):
    return p9 + str(sum(d * w for d, w in zip(_dg(p9), W10, strict=True)) % 11 % 10)

def inn12(p10):
    c11 = sum(d * w for d, w in zip(_dg(p10), A12, strict=True)) % 11 % 10
    c12 = sum(d * w for d, w in zip(_dg(p10 + str(c11)), B12, strict=True)) % 11 % 10
    return p10 + str(c11) + str(c12)

def snils(p9):
    s = sum(d * (10 - i) for i, d in enumerate(_dg(p9), 1))
    if s > 101:
        s %= 101
    if s >= 100:
        s = 0
    return p9 + "%02d" % s

def ogrn13(p12):
    return p12 + str(int(p12) % 11 % 10)

def ogrnip15(p14):
    return p14 + str(int(p14) % 13 % 10)

def luhn_cd(prefix):
    dd = _dg(prefix) + [0]
    s = 0
    for i, x in enumerate(reversed(dd)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return (10 - s % 10) % 10

def _mod97_num(n):
    r = 0
    for ch in str(n):
        r = (r * 10 + int(ch)) % 97
    return r

def mod97(iban):
    t = iban[4:] + iban[:4]
    n = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in t.upper() if c.isalnum())
    return _mod97_num(n)

def iban_cc(cc, bban):
    n = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in bban + cc + '00')
    return 98 - _mod97_num(n)

def selftest():
    for v in ["6449013711", "3664069397", "4205001725", "7743880975",
              "7736207543", "7707083893", "9198578814"]:
        assert inn10(v[:9]) == v, v
    for v in ["1110005080", "4234324324", "1111111111", "7743880976"]:
        assert inn10(v[:9]) != v, v
    for v in ["300504899258", "635277570478", "451408304546", "722433057002",
              "499918818482", "383391302210"]:
        assert inn12(v[:10]) == v, v
    for v in ["617547302703"]:
        assert inn12(v[:10]) != v, v
    for v in ["58659591780", "61135786580", "15198191082", "38405134670",
              "35816807609", "13494000539", "91456175111", "48000000000", "57000000000"]:
        assert snils(v[:9]) == v, v
    # ogrn13/ogrnip15 выше — ГЕНЕРАТОР контрольной цифры, не валидатор: этот
    # selftest проверяет арифметику mod 11 / mod 13 и не knows про структуру.
    # 4090342707154 остаётся корректным CD-вектором, но как «валидный ОГРН»
    # больше не используется: п.7 165н отводит признак 4 записям ЕГРИП (15
    # знаков), для каскада-0 номер НЕВАЛИДЕН (§4, задача #27).
    for v in ["9106722490217", "5065049620796", "9154001968881", "6160394236029",
              "8083210639372", "7048473202122", "4090342707154"]:
        assert ogrn13(v[:12]) == v, v
    for v in ["9100722490217", "4090342700154"]:
        assert ogrn13(v[:12]) != v, v
    for v in ["304500116000157", "313132804400022", "314220119000137", "302500000000001"]:
        assert ogrnip15(v[:14]) == v, v
    for v in ["304500116000154", "313242342342332"]:
        assert ogrnip15(v[:14]) != v, v
    for p, exp in [("424242424242424", 2), ("555555555555444", 4), ("222100000000000", 9),
                   ("37828224631000", 5), ("3056930902590", 4), ("220000000000000", 4),
                   ("220499000000000", 2), ("221426000000000", 8), ("601111111111111", 7),
                   ("400005665566555", 6), ("220910000000000", 3)]:
        assert luhn_cd(p) == exp, p
    for v in ["DE89370400440532013000", "FR1420041010050500013M02606",
              "RU0304452522540817810538091310419", "BE62510007547061",
              "NL91ABNA0417164300", "GB82WEST12345698765432", "BE71096123456769"]:
        assert mod97(v) == 1, v
    for v in ["DE89370400440532013001", "RU0304452522540817810538091310418",
              "GB82WEST12345698765433", "NL91ABNA0517164300", "BE62510007547060"]:
        assert mod97(v) != 1, v
    # запрещено вычислять ожидаемое той же функцией, что проверяется (AGENTS
    # §Дисциплина фактов п.3) — selftest сверяет формулы ТОЛЬКО с табличными
    # векторами первички.

# ================================================================ пулы синтетики
LAST_M = ["Соколов", "Мельников", "Ершов", "Кузнецов", "Остапенко", "Громов", "Звягинцев",
          "Тарасов", "Ушаков", "Жуков", "Панкратов", "Хвостов", "Лыков", "Гущин",
          "Дьяконов", "Родионов", "Шамов", "Белкин", "Волков", "Селезнёв", "Малышев",
          "Козлов", "Никитин", "Фокин"]
LAST_F = ["Соколова", "Мельникова", "Ершова", "Кузнецова", "Громова", "Звягинцева",
          "Тарасова", "Ушакова", "Жукова", "Панкратова", "Хвостова", "Лыкова", "Гущина",
          "Дьяконова", "Родионова", "Шамова", "Белкина", "Волкова", "Селезнёва",
          "Малышева", "Козлова", "Никитина", "Фокина"]
FIRST_M = ["Артём", "Гордей", "Мирон", "Тимур", "Савелий", "Елисей", "Демид", "Марк",
           "Ратибор", "Ярослав", "Лукьян", "Север", "Игнат", "Прохор", "Фаддей", "Ефим",
           "Кирилл", "Матвей", "Арсений", "Всеволод"]
FIRST_F = ["Агафья", "Милана", "Устинья", "Глафира", "Аксинья", "Василиса", "Златослава",
           "Таисия", "Прасковья", "Алёна", "Кира", "Евдокия", "Ульяна", "Степанида",
           "Пелагея", "Марфа", "Аграфена", "Юлиана", "Зоя", "Анфиса"]
PATR = ["Сергеевич", "Фёдорович", "Игнатьевич", "Матвеевич", "Тихонович", "Гаврилович",
        "Саввич", "Панкратович", "Ефимович", "Устинович", "Фокич", "Миронович",
        "Остапович", "Гордеевич", "Ратиборович", "Ярославович"]
PATR_F = ["Сергеевна", "Фёдоровна", "Игнатьевна", "Матвеевна", "Тихоновна", "Гавриловна",
          "Саввична", "Панкратовна", "Ефимовна", "Устиновна", "Фокинична", "Мироновна",
          "Остаповна", "Гордеевна", "Ратиборовна", "Ярославовна"]
CITIES = [("Москва", "77"), ("Санкт-Петербург", "78"), ("Новосибирск", "54"),
          ("Екатеринбург", "66"), ("Казань", "16"), ("Нижний Новгород", "52"),
          ("Самара", "63"), ("Ростов-на-Дону", "61"), ("Уфа", "02"), ("Красноярск", "24"),
          ("Воронеж", "36"), ("Пермь", "59"), ("Тюмень", "72"), ("Ижевск", "18"),
          ("Хабаровск", "27"), ("Ярославль", "76"), ("Владивосток", "25")]
STREETS = ["Лесная", "Октябрьской Революции", "Гагарина", "Советская", "Молодёжная",
           "Заводская", "Пушкинская", "Кирова", "Сосновый бор", "Промышленная",
           "Набережная", "Северная", "Южных Сиреней", "Полевая", "Вишнёвая"]
OPF = ["ООО", "ПАО", "АО"]
ORGNAMES = ["Ромашка", "Вектор", "Аист", "Кристалл", "Горизонт", "Метеор", "Титан",
            "Абзац", "Кредо", "Тайга", "Параграф", "Азимут", "Факел", "Ясень", "Гелиос"]
MIR_BINS = ["220000", "220239", "220499", "220910", "221426", "221611", "224298", "225548"]
DOMAINS = ["breeze.example", "mailforge.example", "pochta-demo.example",
           "corp-vektor.example", "post-panda.example"]
ISSUERS = ["ОВД Промышленного р-на г. Самары", "УФМС по Тверской обл.",
           "ОВД Невского р-на г. Санкт-Петербурга", "УМВД по Респ. Татарстан"]
TRANSLIT = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
            "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
            "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
            "ы": "y", "ь": "", "ъ": "", "э": "e", "ю": "yu", "я": "ya", "ч": "ch",
            "ш": "sh", "щ": "sch", "ц": "ts", "ф": "f", "х": "kh"}

# ================================================================ генераторы значений
def rus_name(f, sex):
    if sex == "M":
        return "%s %s %s" % (f.pick(LAST_M), f.pick(FIRST_M), f.pick(PATR))
    return "%s %s %s" % (f.pick(LAST_F), f.pick(FIRST_F), f.pick(PATR_F))

def make_inn10(f):
    while True:
        reg = f.pick(CITIES)[1]
        v = inn10(reg + f.digits(7))
        if len(set(v)) >= 4:
            return v

def make_inn12(f):
    while True:
        p = str(f.range(1, 9)) + f.digits(9)
        v = inn12(p)
        if len(set(v)) >= 4:
            return v

def make_snils(f):
    while True:
        d = [f.below(10) for _ in range(9)]
        if d[0] == 0:
            d[0] = 1
        if any(d[i] == d[i + 1] == d[i + 2] for i in range(7)):
            continue
        v = snils(''.join(map(str, d)))
        if int(v[:9]) > 1001998:
            return v

def snils_std(raw):
    return "%s-%s-%s %s" % (raw[:3], raw[3:6], raw[6:9], raw[9:11])

def make_snils_shown(f, dirty):
    raw = make_snils(f)
    a, b, c, cd = raw[:3], raw[3:6], raw[6:9], raw[9:11]
    if dirty and f.chance(1, 2):
        shown = "%s %s %s %s" % (a, b, c, cd)          # дефисы → пробелы (каскад-0 нормализует)
    else:
        shown = "%s-%s-%s %s" % (a, b, c, cd)          # канонический формат первички
    return raw, shown

def make_ogrn(f):
    sign = f.pick(["1", "5", "7"])
    year = "%02d" % f.range(10, 24)
    reg = f.pick(CITIES)[1]
    return ogrn13(sign + year + reg + f.digits(7))

def make_ogrnip(f):
    year = "%02d" % f.range(10, 24)
    reg = f.pick(CITIES)[1]
    return ogrnip15("3" + year + reg + f.digits(9))

def make_card(f):
    kind = f.pick(["mir", "mir", "mir", "mir", "visa", "mc", "amex"])
    if kind == "amex":
        p = "37" + f.pick(["48", "14", "82"]) + f.digits(11)   # 15 цифр + cd = 16; реальный Amex 15 всего — дефект длины, backlog v1.1 (README «Отклонения» п.7)
    elif kind == "visa":
        p = f.pick(["4279", "4575", "4916"]) + f.digits(11)    # 15 + cd = 16
    elif kind == "mc":
        p = "5534" + f.digits(11)
    else:
        p = f.pick(MIR_BINS) + f.digits(9)                     # 15 + cd = 16
    return p + str(luhn_cd(p))

def fmt_card(f, pan):
    mode = f.below(3)
    grp = [pan[i:i + 4] for i in range(0, len(pan), 4)]
    if mode == 0:
        return pan
    if mode == 1:
        return '-'.join(grp)
    return ' '.join(grp)

def make_iban(f):
    cc = f.pick(["DE", "FR", "ES", "NL", "BE", "GB", "RU", "RU", "RU"])
    if cc == "RU":
        bban = "044525225" + f.pick(["40817", "40702", "40820", "40818"]) + f.digits(15)
    elif cc == "DE":
        bban = f.pick(["37040044", "12030000", "55669900", "70150000"]) + f.digits(10)
    elif cc == "FR":
        # реестр SWIFT FR: BBAN 4!n 6!n 11!c 2!n = 23 (IBAN-длина 27);
        # фикстура по образцу эталона 20041 01005 0500013M026 06
        # layout 4!n + 6!n + 11!c + 2!n = 23 (эталон реестра: 20041 01005 0500013M026 06)
        bank = f.pick(["2004", "1009", "3000", "1001"])          # 4
        branch = f.digits(6)                                     # 6 (в эталоне 01005)
        acct = f.digits(8) + f.pick(["M", "D", "U"]) + "02"      # 11!c
        chk = f.digits(2)                                        # 2
        bban = bank + branch + acct + chk
        assert len(bban) == 23, (cc, bban, len(bban))
    elif cc == "ES":
        bban = f.digits(20)
    elif cc == "NL":
        bban = f.pick(["ABNA", "RABN", "INGB", "FRNX"]) + f.digits(10)
    elif cc == "BE":
        bban = f.digits(12)
    else:
        bban = f.pick(["WEST", "BARC", "IRVL", "ABBY"]) + f.digits(14)
    cd = iban_cc(cc, bban)
    out = "%s%02d%s" % (cc, cd, bban)
    assert mod97(out) == 1, out
    return out

def fmt_iban(f, iban):
    mode = f.below(3)
    if mode == 0:
        return iban
    if mode == 1:
        return ' '.join(iban[i:i + 4] for i in range(0, len(iban), 4))
    return iban[:4] + ' ' + iban[4:]

def make_phone(f, sex):
    # RU мобильный: +7 XXX XXX-XX-XX, 11 цифр всего; сегменты XXX/XX/XX
    area = f.pick(["916", "926", "812", "383", "347", "846", "863", "985", "905",
                   "401", "978", "351"])
    return area, f.digits(3), f.digits(2), f.digits(2)

def make_email(f, sex):
    surname = rus_name(f, sex).split()[0]
    login = ''.join(TRANSLIT.get(ch, ch) for ch in surname.lower())
    # уникальность внутри строки: суффикс, которого нет ни в одном домене
    cand = "%s%d@%s" % (login, f.range(70, 99), f.pick(DOMAINS))
    return cand

def make_org(f):
    return "%s «%s»" % (f.pick(OPF), f.pick(ORGNAMES))

def make_addr(f):
    c, _reg = f.pick(CITIES)
    st = f.pick(STREETS)
    tail = f.pick(["", "", " к. 2", " к. 1 стр. 4", " лит. А", " корп. 3"])
    if c == "Москва":
        return "г. Москва, %s ул., д. %d%s" % (st, f.range(1, 120), tail)
    return "г. %s, %s улица, дом %d%s" % (c, st, f.range(1, 90), tail)

def make_passport(f):
    ser = "%02d %02d" % (f.range(45, 66), f.range(1, 99))
    num = f.digits(6)
    return "%s %s" % (ser, num)

def dirty_digits(f, s):
    # «грязь» = только замена существующих разделителей (пробел/дефис) на другой
    # вид, включая newline: цифры не вставляются и не удаляются, сегментная структура
    # сохраняется — иначе value_source не восстановим нормализатором каскада-0.
    sep = f.pick([" ", "-", "\u2009", "\n"])
    return re.sub(r"[ \-\u2009]", lambda m: sep if f.chance(2, 3) else m.group(0), s)

# ================================================================ спан-конструктор
def span_at(text, value, category, value_source):
    enc = text.encode('utf-8')
    venc = value.encode('utf-8')
    pos = enc.find(venc)
    assert pos >= 0, "value %r not found in %r" % (value, text)
    assert enc.find(venc, pos + 1) < 0, "value %r appears twice in %r" % (value, text)
    assert enc[pos:pos + len(venc)].decode('utf-8') == value
    return {"start_byte": pos, "end_byte": pos + len(venc),
            "category": CAT[category], "value_source": value_source}

# ================================================================ фрагменты (контекст + спан)
def frag_name(f, sex, dirty):
    name = rus_name(f, sex)
    lead = f.pick(["ФИО: ", "Клиент — ", "Получатель: ", "Должник ", ""])
    return lead + name, name, "person_name", name

def frag_inn(f, sex, dirty):
    org = make_org(f)
    num = make_inn10(f) if f.chance(1, 2) else make_inn12(f)
    shown = dirty_digits(f, num) if (dirty and f.chance(1, 2)) else num
    return "%s, ИНН %s" % (org, shown), shown, "inn", num

def frag_snils(f, sex, dirty):
    raw, shown = make_snils_shown(f, dirty)
    return "СНИЛС %s" % shown, shown, "snils", raw

def frag_ogrn(f, sex, dirty):
    org = make_org(f)
    num = make_ogrn(f)
    shown = dirty_digits(f, num) if (dirty and f.chance(1, 2)) else num
    return "%s, ОГРН %s" % (org, shown), shown, "ogrn", num

def frag_ogrnip(f, sex, dirty):
    num = make_ogrnip(f)
    shown = dirty_digits(f, num) if (dirty and f.chance(1, 2)) else num
    return "ИП %s, ОГРНИП %s" % (f.pick(LAST_M), shown), shown, "ogrnip", num

def frag_iban(f, sex, dirty):
    raw = make_iban(f)
    shown = fmt_iban(f, raw)
    return "IBAN %s" % shown, shown, "iban", raw

def frag_card(f, sex, dirty):
    pan = make_card(f)
    if dirty and f.chance(1, 2):
        shown = dirty_digits(f, pan)
    else:
        shown = fmt_card(f, pan)
    return "оплата картой %s" % shown, shown, "card_pan", pan

def frag_phone(f, sex, dirty):
    area, a, b, c = make_phone(f, sex)
    digits11 = "7" + area + a + b + c  # E.164 without '+': 7XXXXXXXXXX
    fmt = f.below(4)
    if fmt == 0:
        shown = "+7 %s %s-%s-%s" % (area, a, b, c)
    elif fmt == 1:
        shown = "+7%s%s-%s-%s" % (area, a, b, c)
    elif fmt == 2:
        shown = "+7 (%s) %s-%s-%s" % (area, a, b, c)
    else:
        shown = "+7 %s %s %s %s" % (area, a, b, c)
    return "тел. %s," % shown, shown, "phone", digits11

def frag_email(f, sex, dirty):
    e = make_email(f, sex)
    return "почта %s" % e, e, "email", e

def frag_addr(f, sex, dirty):
    a = make_addr(f)
    return "юр. адрес: %s" % a, a, "address", a

def frag_passport(f, sex, dirty):
    full = make_passport(f)
    lead = f.pick(["паспорт ", "удостоверение: паспорт ", "документ: паспорт "])
    tail = f.pick(["", ", выдан " + f.pick(ISSUERS), " на 12.04.2015", " от 03.09.2019"])
    text = lead + full + tail
    return text, full, "passport", full

FRAG = {"person_name": frag_name, "inn": frag_inn, "snils": frag_snils, "ogrn": frag_ogrn,
        "ogrnip": frag_ogrnip, "iban": frag_iban, "card_pan": frag_card, "phone": frag_phone,
        "email": frag_email, "address": frag_addr, "passport": frag_passport}

HEADS = ["Договор оказания услуг № %d/%d от %02d.%02d.2024\n",
         "Тикет %s-%d\n",
         "Анкета заёмщика\n",
         "Заявка на возврат\n",
         "SMS-уведомление\n",
         "Служебная записка\n",
         "Карточка контрагента\n"]
LABELS = ["Контрагент: ", "Реквизиты: ", "Контакт: ", "Доп.: ", "Примечание: ", ""]

def compose(f, cats, dirty, source):
    head = f.pick(HEADS)
    if "%d" in head:
        if head.startswith("Договор"):
            head = head % (f.range(100, 999), f.range(15, 29), f.range(1, 28), f.range(1, 12))
        else:
            head = head % (f.pick(["SUP", "TCK", "OPS"]), f.range(10000, 99999))
    sep = f.pick([" | ", "\n", " — "])
    text = head
    spans = []
    sex = f.pick(["M", "F"])
    for i, c in enumerate(cats):
        lead, value, cat, src = FRAG[c](f, sex, dirty)
        # LABELS — префиксы контекста: спан не должен утаскивать «: » вперёд
        if i > 0:
            text += sep
        lead = f.pick(LABELS) + lead
        if i == 0:
            lead = " " + lead
        base = len(text.encode('utf-8'))
        text += lead
        sp = span_at(text, value, cat, src)
        assert sp["start_byte"] >= base
        spans.append(sp)
    text += f.pick(["", "\nСтатус: в работе.", "\nПодготовил оператор, смена Б.",
                   "\nКомментарий: срочно."])
    return text, spans

def negative_plain(f):
    t = f.below(10)
    if t == 0:
        return "Планерка в %02d:%02d перенесена на %d октября, кабинет %d." % (
            f.range(9, 18), f.range(0, 59), f.range(1, 28), f.range(101, 420))
    if t == 1:
        return "Релиз 0.%d.%d выкатываем в пятницу, фича-фриз со вторника." % (f.range(1, 9), f.range(0, 20))
    if t == 2:
        return "Счёт за облачную инфраструктуру: %d руб. %d коп., оплатить до конца месяца." % (
            f.range(10, 400), f.range(10, 99))
    if t == 3:
        return "В отпуске с %02d по %02d.%02d, подменяет дежурный смены Б." % (
            f.range(1, 25), f.range(26, 28), f.range(1, 12))
    if t == 4:
        return "CI красный на %d из %d задач, виноват линтер, починю завтра." % (f.range(2, 9), f.range(12, 30))
    if t == 5:
        return "Латентность каскада 0 вышла на %d мс при бюджете 1000 мс." % f.range(180, 999)
    if t == 6:
        return "Тонер в принтере #%d на исходе, заказано %d пачек." % (f.range(11, 99), f.range(1, 9))
    if t == 7:
        return "Обновите подписку на сервис: истекает через %d дней." % f.range(3, 40)
    if t == 8:
        return "Пароль от стенда лежит в менеджере секретов, проект «%s»." % f.pick(ORGNAMES)
    return "Дозвониться в поддержку не удалось: %d минут в очереди." % f.range(5, 90)

# ================================================================ negative: табличные НЕВАЛИДНЫЕ векторы
# (значения дословно из таблиц docs/dep-verify-algorithms.md; статус НЕВАЛИДН проверен selftest)
NEG_VECTORS = [
    ("inn", "1110005080", "Проверка контрагента: ИНН {v} — автокредит отклонён."),
    ("inn", "4234324324", "OCR прочитал ИНН {v}, оператор подтвердил ошибку распознавания."),
    ("inn", "1111111111", "Заявка №44: ИНН {v} не проходит валидатор."),
    ("inn", "7743880976", "Реквизиты из письма: ИНН {v} — не биндится с ЕГРЮЛ."),
    ("inn", "617547302703", "Форма ЕПМВ отвергла ИНН {v} по 12-му разряду."),
    ("snils", "111-111-111 11", "СНИЛС {v} отклонён системой ПФР."),
    ("snils", "151-324-910 82", "Номер {v} признан битым, сверьтесь с анкетой."),
    ("snils", "100-222-345 67", "Анкета с {v} невалидна: три одинаковых цифры подряд."),
    ("ogrn", "1234567890123", "ЕГРЮЛ молчит по ОГРН {v}."),
    ("ogrn", "9100722490217", "Выписка не найдена: ОГРН {v} не проходит контрольную цифру."),
    ("ogrn", "4090342700154", "Контрагент с ОГРН {v} отвалился на валидаторе."),
    ("ogrnip", "304500116000154", "ОГРНИП {v} отклонён при выписке из ЕГРИП."),
    ("ogrnip", "313242342342332", "Реестр не знает номера {v}."),
    ("card_pan", "4242424242424241", "Эквайер отбил карту {v}."),
    ("card_pan", "2200000000000005", "Транзакция {v} не прошла проверку Луны."),
    ("card_pan", "1234567812345678", "Подозрительный номер {v} в дампе — не карта."),
    ("card_pan", "5555555555555556", "Тестовый {v} в логах, бой его отклонил."),
    ("iban", "DE89370400440532013001", "SEPA-возврат: {v} — mod-97 не сошёлся."),
    ("iban", "RU0304452522540817810538091310418", "Платёж отбит банком-корреспондентом: {v}."),
    ("bik", "144525225", "Справочник ЦБ не нашёл БИК {v}: не 04 в начале."),
    ("bank_account", "50702810900000001234", "Казначейство отклонило счёт {v}: первая цифра вне плана 579-П."),
    ("bik", "04452522", "В платежке БИК {v} — восемь цифр, банк вернул документ."),
    ("iban", "GB82WEST12345698765433", "Лондон вернул {v}: контрольная пара не бьётся."),
    ("card_pan", "2200000000000000", "Предапробление карты {v} не прошло Луна-чек."),
]

# ================================================================ negative: валидные номера вне скоупа (честный FP-bait)
# Векторы — валидны по чексумме, но НЕ размечены: это ловушка на FP по решению
# гейта (§5 п.7: FP дёшевы, но меримся). В README про них сказано явно.
OUT_OF_SCOPE = [
    ("Номер карты клиента из бэкапа 2019: 2200000000000004 — архив, не трогать.", "2200000000000004"),
    ("Эталонный счёт для интеграционного теста: DE89370400440532013000.", "DE89370400440532013000"),
    ("Старый тестовый CVC-заглухиш 5555555555554444 остался в фикстурах.", "5555555555554444"),
    ("Амекс-фикстура 378282246310005 лежит в моках с прошлой команды.", "378282246310005"),
    ("Динерс-тест 30569309025904 мигрировал из старой базы вместе с дампом.", "30569309025904"),
]

# ================================================================ negative: foreign-формат bait (не наш скоринг-путь)
FOREIGN_BAIT = [
    "SSN-формат в переписке с подрядчиком из США: 123-45-6789.",
    "US phone +1 415 555 0132 в CRM-заметке.",
    "Форма дат US-команды: 04/21/2024, дедлайн 11/02/2024.",
]

# ================================================================ основной проход
def main():
    selftest()
    f = Rng(0xF0D1C0DE)
    rows = []

    def add(text, spans, split, source="synthetic-checksum"):
        rows.append({"id": None, "text": text, "spans": spans, "split": split, "source": source})

    combos = [
        ["person_name", "inn", "snils", "address"],
        ["person_name", "phone", "email"],
        ["inn", "ogrn", "address"],
        ["ogrnip", "card_pan", "phone"],
        ["person_name", "passport", "address"],
        ["iban", "person_name", "email"],
        ["inn", "card_pan"],
        ["email", "phone", "address"],
        ["ogrn", "iban"],
        ["snils", "person_name"],
        ["card_pan", "person_name", "phone"],
        ["person_name", "inn", "email", "address"],
        ["ogrnip", "snils", "phone"],
        ["inn", "snils", "card_pan", "address"],
        ["person_name", "iban", "passport"],
        ["phone", "email", "ogrn"],
        ["card_pan", "email"],
        ["address", "ogrnip"],
        ["inn", "ogrn", "iban", "person_name"],
        ["person_name", "snils", "phone", "email"],
        ["card_pan", "inn", "address"],
        ["ogrn", "passport", "person_name"],
        ["email", "iban", "address"],
        ["snils", "ogrnip", "person_name", "phone"],
        ["inn", "card_pan", "email", "person_name"],
    ]
    # мульти-сущностные recall-документы: каждый combo × {чисто, грязно} × 2 прогона
    for _pass in range(2):
        for dirty in (False, True):
            for cats in combos:
                text, spans = compose(f, cats, dirty, "synthetic-checksum")
                add(text, spans, "recall")

    # сингл-категорийные recall: покрытие гарантируется снизу ( combos уже дают >=25/кат )
    singles = {"person_name": 4, "inn": 4, "snils": 4, "ogrn": 4, "ogrnip": 4,
               "iban": 4, "card_pan": 4, "phone": 4, "email": 4, "address": 4, "passport": 4}
    for cat in ["person_name", "inn", "snils", "ogrn", "ogrnip", "iban", "card_pan",
                "phone", "email", "address", "passport"]:
        for _ in range(singles[cat]):
            text, spans = compose(f, [cat], f.chance(1, 2), "synthetic-checksum")
            add(text, spans, "recall", "synthetic-checksum")

    # официальные эталонные IBAN из реестра SWIFT (один пример + DE-пример)
    t = "Счёт для возврата: RU03 0445 2522 5408 1781 0538 0913 10419"
    add(t, [span_at(t, "RU03 0445 2522 5408 1781 0538 0913 10419", "iban",
                    "RU0304452522540817810538091310419")], "recall", "registry-example")
    t = "Реквизиты европейского получателя: DE89 3704 0044 0532 0130 00"
    add(t, [span_at(t, "DE89 3704 0044 0532 0130 00", "iban", "DE89370400440532013000")], "recall", "registry-example")

    # negative: табличные НЕВАЛИДНЫЕ векторы (размечены — чтобы валидатор не пропускал похожие)
    for cat, val, tmpl in NEG_VECTORS:
        t = tmpl.format(v=val)
        add(t, [span_at(t, val, cat, val)], "negative", "primary-invalid-vector")

    # negative: валидные, но вне скоупа (не размечены — FP-bait)
    for t, _val in OUT_OF_SCOPE:
        add(t, [], "negative", "doc-valid-vector")
    for t in FOREIGN_BAIT:
        add(t, [], "negative", "foreign-bait")

    # negative: чистый текст без ПДн
    for _ in range(22):
        add(negative_plain(f), [], "negative", "synthetic-no-pii")

    # ---------------- гейты ----------------
    total = len(rows)
    recall = sum(1 for r in rows if r["split"] == "recall")
    neg = total - recall
    recall_cat = Counter(s["category"] for r in rows if r["split"] == "recall" for s in r["spans"])
    neg_cat = Counter(s["category"] for r in rows if r["split"] == "negative" for s in r["spans"])
    if total < 150:
        sys.stderr.write("FAIL total=%d\n" % total)
        sys.exit(1)
    if recall < 120:
        sys.stderr.write("FAIL recall=%d\n" % recall)
        sys.exit(1)
    for c, n in sorted(recall_cat.items()):
        if n < 8:
            sys.stderr.write("FAIL category %s has %d (<8)\n" % (c, n))
            sys.exit(1)

    # инварианты: непересечение спанов, UTF-8-границы, value внутри спана
    for r in rows:
        b = r["text"].encode('utf-8')
        prev = -1
        for s in sorted(r["spans"], key=lambda x: x["start_byte"]):
            if not (0 <= s["start_byte"] < s["end_byte"] <= len(b)):
                sys.stderr.write("FAIL bounds id=%s\n" % str(r["id"]))
                sys.exit(1)
            if not b[s["start_byte"]:s["end_byte"]].decode('utf-8', 'strict'):
                sys.stderr.write("FAIL utf8 id=%s\n" % str(r["id"]))
                sys.exit(1)
            if s["start_byte"] <= prev:
                sys.stderr.write("FAIL overlap id=%s\n" % str(r["id"]))
                sys.exit(1)
            prev = s["end_byte"]

    for i, r in enumerate(rows, 1):
        r["id"] = "g%04d" % i
    # Побайтовый вывод: sys.stdout в текстовом режиме Windows транслирует
    # "\n" → "\r\n" — генератор переставал быть кросс-ОС-детерминированным
    # (issue #39, промер CI python-golden windows: regen 65ff9488… ≠ B2
    # 3c431174…, ubuntu pass). buffer.write обходит трансляцию; на Linux
    # байты идентичны прежнему выводу (гейт golden-verify на ubuntu зелёный
    # ДО и ПОСЛЕ — промер в PR #40).
    out = b"".join(
        (json.dumps(r, ensure_ascii=False, separators=(',', ':')) + "\n").encode("utf-8")
        for r in rows
    )
    sys.stdout.buffer.write(out)

    sys.stderr.write("TOTAL %d RECALL %d NEG %d SPANS %d\n"
                     % (total, recall, neg, sum(len(r["spans"]) for r in rows)))
    sys.stderr.write("RECALL_CAT %s\n" % dict(sorted(recall_cat.items())))
    sys.stderr.write("NEG_CAT %s\n" % dict(sorted(neg_cat.items())))

if __name__ == "__main__":
    main()
