#!/usr/bin/env uv run --python 3.13
"""fasad branch measurement: suffix-table + gender-pool classifier (no morph engine).

Rules DERIVED only from petrovich fork golden tsv. Variants: tail-context length (2/3),
gender-mandatory candidate filter. Outputs JSON metrics per config.
"""
import json, os, random, sys, csv, itertools
from collections import defaultdict, Counter
from pathlib import Path

DATA = Path.home() / ".cargo/git/checkouts/petrovich-rs-a943224988e65988/019e06d/tests/data"
GOLDEN = Path("/Users/user/Documents/dsh-projects/fasad-4b3/data/golden/golden-v1.jsonl")
OUT = Path("/tmp/morph3/out"); OUT.mkdir(exist_ok=True)
CASE_MAP = {"им": "nom", "рд": "gen", "дт": "dat", "вн": "acc", "тв": "ins", "пр": "pre"}
TYPES = ["surname", "firstname", "midname"]
TSV = {"surname": "surnames.tsv", "firstname": "firstnames.tsv", "midname": "midnames.tsv"}
ORDER = ["surname", "firstname", "midname"]

def norm(s): return s.upper().replace("Ё", "Е")

def load_paradigms(t):
    rows = []
    with open(DATA / TSV[t], encoding="utf-8-sig") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 3 or p[0] == "lemma": continue
            parts = p[2].split(",")
            if "ед" not in parts: continue
            g = "m" if "мр" in parts else ("f" if "жр" in parts else None)
            c = next((CASE_MAP[x] for x in parts if x in CASE_MAP), None)
            if g and c: rows.append((norm(p[0]), norm(p[1]), g, c))
    return rows

def load_gender(fn):
    d = {}
    with open(DATA / fn, encoding="utf-8-sig") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 2 or p[0] == "lemma": continue
            gv = {"мр": {"m"}, "жр": {"f"}, "мр-жр": {"m", "f"}}.get(p[1].strip())
            if gv is not None: d[norm(p[0])] = gv
    return d

def lcp_split(lemma, word):
    i = 0; n = min(len(lemma), len(word))
    while i < n and lemma[i] == word[i]: i += 1
    return word[i:], lemma[i:]

def train(rows_by_type, tailn):
    rules = {t: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {"count": 0, "tails": Counter(), "genders": Counter()}))) for t in TYPES}
    for t, rows in rows_by_type.items():
        for lemma, word, g, c in rows:
            wr, lr = lcp_split(lemma, word)
            r = rules[t][c][wr][lr]
            r["count"] += 1
            r["tails"][lemma[-tailn:] if len(lemma) >= tailn else lemma] += 1
            r["genders"][g] += 1
    return rules

def train_suffix_gender(rows_by_type, tailn):
    stat = {t: defaultdict(Counter) for t in TYPES}
    for t, rows in rows_by_type.items():
        lem_g = defaultdict(set)
        for lemma, word, g, c in rows: lem_g[lemma].add(g)
        for lemma, gs in lem_g.items():
            if len(lemma) >= tailn: stat[t][lemma[-tailn:]].update(gs)
    table = {}
    for t in TYPES:
        table[t] = {}
        for tail, cnt in stat[t].items():
            tot = sum(cnt.values()); top, n = cnt.most_common(1)[0]
            table[t][tail] = (top, tot, n / tot)
    return table

class Classifier:
    def __init__(self, rules, pools, sg, tailn, k_min=3, gender_strict=False, rows_by_type=None):
        self.pools, self.sg, self.tailn, self.gs = pools, sg, tailn, gender_strict
        self.exc = {}
        self.rules = {t: defaultdict(dict) for t in TYPES}
        for t in TYPES:
            for c, wrmap in rules[t].items():
                for wr, lrs in wrmap.items():
                    keep = {lr: {"tails": set(m["tails"]), "genders": set(m["genders"])}
                            for lr, m in lrs.items() if m["count"] >= k_min}
                    if keep: self.rules[t][c][wr] = keep
        if rows_by_type:
            for t, rows in rows_by_type.items():
                for lemma, word, g, c in rows:
                    if not any(l == lemma and cc == c for l, cc, _ in self._table_cands(word, t)):
                        self.exc.setdefault((word, t), set()).add((lemma, c, g))

    def _table_cands(self, W, t):
        out = set()
        for c, wrmap in self.rules[t].items():
            for wr, lrs in wrmap.items():
                if len(wr) > len(W) or not W.endswith(wr): continue
                stem = W[:len(W) - len(wr)]
                if wr and not stem: continue
                for lr, meta in lrs.items():
                    lem = stem + lr
                    if len(lr) < self.tailn:
                        need = lem[-self.tailn:] if len(lem) >= self.tailn else lem
                        if need not in meta["tails"]: continue
                    out.add((lem, c, frozenset(meta["genders"])))
        return out

    def gender(self, lem, t):
        p = self.pools.get(t, {}).get(lem)
        if p is not None: return set(p)
        key = lem[-self.tailn:] if len(lem) >= self.tailn else lem
        sg = self.sg.get(t, {}).get(key)
        if sg and sg[2] >= 0.9 and sg[1] >= 5: return {sg[0]}
        return None

    def classify(self, W, t):
        W = norm(W); out = set()
        for lem, c, gs in self._table_cands(W, t):
            g = self.gender(lem, t)
            if g is None and self.gs: continue
            out.add((lem, c, frozenset(g) if g else None))
        for lem, c, g in self.exc.get((W, t), ()):
            gg = self.gender(lem, t) or {g}
            if gg is None and self.gs: continue
            out.add((lem, c, frozenset(gg)))
        return out

    def classify_span(self, value, types):
        toks = value.split(); per = []
        for tok, t in zip(toks, types):
            cs = self.classify(tok, t)
            if not cs: return ("no-match", f"token «{tok}»", [])
            per.append(cs)
        sol = set()
        cases = set.intersection(*[{c for _, c, _ in cs} for cs in per])
        for c in cases:
            lists = [[(l, g) for l, cc, g in cs if cc == c] for cs in per]
            for combo in itertools.product(*lists):
                gs = [set(g) for _, g in combo if g]
                inter = set.intersection(*gs) if gs else (set() if self.gs else {"m", "f"})
                for gg in inter: sol.add((tuple(l for l, _ in combo), c, gg))
        if len(sol) == 1: return ("unique", None, list(sol)[0])
        if len(sol) > 1: return ("ambiguous", None, sorted(sol, key=str))
        return ("no-match", "case/gender contradiction", [])

def table_size(cl):
    lines = ["\t".join([t, c, wr, lr, ",".join(sorted(x[0] for x in m["genders"])), ",".join(sorted(m["tails"]))])
             for t in TYPES for c, wrmap in cl.rules[t].items() for wr, lrs in wrmap.items() for lr, m in lrs.items()]
    exc = ["\t".join([w, t, c, l, g]) for (w, t), v in cl.exc.items() for l, c, g in sorted(v)]
    return len(lines), sum(len(x.encode()) + 1 for x in lines), len(exc), sum(len(x.encode()) + 1 for x in exc)

def main():
    rnd = random.Random(42)
    rows_by_type = {t: load_paradigms(t) for t in TYPES}
    pools_full = {"surname": load_gender("surnames.gender.tsv"), "firstname": load_gender("firstnames.gender.tsv"), "midname": load_gender("midnames.gender.tsv")}
    pools_p200 = {"firstname": load_gender("firstnames.popular.gender.tsv")}
    pools_p200 = {**pools_p200, "midname": pools_full["midname"], "surname": pools_full["surname"]}
    vals = sorted({s["value_source"] for line in open(GOLDEN, encoding="utf-8") for s in json.loads(line).get("spans", []) if s["category"] == "person_name"})
    all_rows = [(t, r) for t in TYPES for r in rows_by_type[t]]
    sample = rnd.sample(all_rows, 500)
    # held-out lemma split
    hold_lems = set()
    for t in TYPES:
        lems = sorted({r[0] for r in rows_by_type[t]}); rnd.shuffle(lems)
        hold_lems |= {(t, l) for l in lems[len(lems)//2:]}
    hold_rows = [(t, r) for t in TYPES for r in rows_by_type[t] if (t, r[0]) in hold_lems]
    test = rnd.sample(hold_rows, 500)
    test_lems = {(t, r[0]) for t, r in test}
    train_rows = {t: [r for r in rows_by_type[t] if (t, r[0]) not in test_lems] for t in TYPES}
    # synthetic oblique spans pool (shared sample)
    lem_g = {t: defaultdict(set) for t in TYPES}; form = {}
    for t, rows in rows_by_type.items():
        for lemma, word, g, c in rows: lem_g[t][lemma].add(g); form[(t, lemma, c)] = word
    by_tgc = defaultdict(list)
    for (t, lemma, c), word in form.items(): by_tgc[(t, c)].append((lemma, word))
    spans = []
    rc = random.Random(7)
    cases6 = ["gen", "dat", "acc", "ins", "pre"]
    while len(spans) < 500:
        gender = rc.choice(["m", "f"]); case = rc.choice(cases6); picks = []; okb = True
        for t in TYPES:
            cands = [(l, w) for l, w in by_tgc[(t, case)] if gender in lem_g[t][l] and len(l) > 3]
            if not cands: okb = False; break
            picks.append(rc.choice(cands))
        if okb: spans.append((picks, case, gender))
    # oracle ceilings
    oracle = {t: defaultdict(set) for t in TYPES}
    for t, rows in rows_by_type.items():
        for lemma, word, g, c in rows: oracle[t][word].add((lemma, c, g))
    tok_uniq = tok_ok = 0
    for t, (lemma, word, g, c) in sample:
        cs = oracle[t].get(word, set())
        if len(cs) == 1: tok_uniq += 1; tok_ok += int(next(iter(cs)) == (lemma, c, g))
    o_lem = o_tri = 0
    for picks, case, gender in spans:
        cand = [oracle[t].get(norm(w), set()) for (l, w), t in zip(picks, TYPES)]
        if any(not x for x in cand): continue
        sols = set()
        for c2 in set.intersection(*[{cc for _, cc, _ in x} for x in cand]):
            lists = [[(l, g) for l, cc, g in x if cc == c2] for x in cand]
            for combo in itertools.product(*lists):
                inter = set.intersection(*[set(g) for _, g in combo])
                for gg in inter: sols.add((tuple(l for l, _ in combo), c2, gg))
        truth = (tuple(norm(l) for l, w in picks), case, gender)
        if len(sols) == 1 and next(iter(sols)) == truth: o_tri += 1
        lems = {s[0] for s in sols}
        if len(lems) == 1 and truth[0] in lems: o_lem += 1
    N = len(spans)
    print(json.dumps({"metric": "ORACLE", "token500_unique": tok_uniq, "token500_unique_correct": tok_ok,
                      "token_ceiling": round(tok_uniq/500*100, 1), "span500_strict_unique": o_tri,
                      "span500_lemma_unique": o_lem, "span500_lemma_ceiling_pct": round(o_lem/N*100, 1)}, ensure_ascii=False))

    def row_acc(clf, s):
        u = a = w = n = 0
        for t, (lemma, word, g, c) in s:
            cs = clf.classify(word, t)
            if not cs: n += 1; continue
            if len(cs) == 1 and next(iter(cs)) == (lemma, c, frozenset({g})): u += 1
            elif any(l == lemma and cc == c for l, cc, _ in cs): a += 1
            else: w += 1
        return {"uniq": u, "amb": a, "wrong": w, "nomatch": n}

    for tailn in (2, 3):
        rules = train(rows_by_type, tailn)
        sg = train_suffix_gender(rows_by_type, tailn)
        for gs in (False, True):
            cl = Classifier(rules, pools_full, sg, tailn, k_min=3, gender_strict=gs, rows_by_type=rows_by_type)
            rules_h = train({t: [r for r in rr] for t, rr in train_rows.items()}, tailn)
            cl_h = Classifier(rules_h, pools_full, train_suffix_gender(train_rows, tailn), tailn, 3, gs, train_rows)
            lbl = f"tail{tailn}{'_genderstrict' if gs else ''}"
            tl, tb, el, eb = table_size(cl)
            out = {"cfg": lbl, "table_lines": tl, "table_bytes": tb, "exc_lines": el, "exc_bytes": eb}
            out["A_tok500"] = row_acc(cl, sample)
            out["B_heldout500"] = row_acc(cl_h, test)
            cnt = Counter(); ex = defaultdict(list)
            for v in vals:
                st, why, payload = cl.classify_span(v, ORDER); cnt[st] += 1
                if st != "unique": ex[st].append((v, why, payload))
            out["C_real56"] = dict(cnt)
            out["C_coverage_pct"] = round(cnt["unique"]/len(vals)*100, 1)
            mism = sum(1 for v in vals if cl.classify_span(v, ORDER)[0] == "unique"
                       and tuple(cl.classify_span(v, ORDER)[2][0]) != tuple(norm(x) for x in v.split()))
            out["C_lemma_mismatch"] = mism
            du = dc = dt = dl_lemu = dcaseonly = dwrong = dn = 0
            exs = []
            for picks, case, gender in spans:
                words = [w for l, w in picks]
                st, why, payload = cl.classify_span(" ".join(words), ORDER)
                truth = (tuple(norm(l) for l, w in picks), case, gender)
                if st == "no-match": dn += 1; continue
                sol = {payload} if st == "unique" else {(tuple(s[0]), s[1], s[2]) for s in payload}
                if st == "unique": du += 1
                if truth in sol: dc += 1
                else: dwrong += 1
                if len(sol) > 1: dt += 1
                lems = {s[0] for s in sol}
                if len(lems) == 1 and truth[0] in lems:
                    dl_lemu += 1
                    if len(sol) == 2 and {s[1] for s in sol} == {"gen", "acc"}: dcaseonly += 1
                elif len(exs) < 3:
                    exs.append((" ".join(words), sorted(sol, key=str)[:4], truth))
            out["D_span500"] = {"N": N, "strict_unique": du, "unique_correct": dc, "truth_in_amb": dt,
                                "failed(≠truth)": dwrong, "nomatch": dn,
                                "lemma_unique_correct": dl_lemu, "lemma_unique_gen_acc_only": dcaseonly}
            out["D_lemma_coverage_pct"] = round(dl_lemu/N*100, 1)
            out["D_truth_recoverable_pct"] = round(dc/N*100, 1)
            pe = Counter(); pex = []
            with open(DATA / "people.tsv", encoding="utf-8-sig") as fh:
                for r in csv.DictReader(fh, delimiter="\t"):
                    infl = [r["lastname_expected"], r["firstname_expected"], r["middlename_expected"]]
                    lem = [r["lastname"], r["firstname"], r["midname"]]
                    pairs = [(x, y, tt) for x, y, tt in zip(infl, lem, ORDER) if x.strip()]
                    if not pairs: continue
                    c = next((CASEMAP2[x] for x in r["grammemes"].split(",") if x in CASEMAP2), None)
                    g = "m" if "мр" in r["grammemes"] else "f"
                    st, why, payload = cl.classify_span(" ".join(p[0] for p in pairs), [p[2] for p in pairs])
                    truth = tuple(norm(p[1]) for p in pairs)
                    if st == "unique" and payload[0] == truth and payload[1] == c and payload[2] == g: pe["ok"] += 1
                    elif st == "unique": pe["wrong"] += 1; pex.append(("WRONG", " ".join(p[0] for p in pairs), payload))
                    else:
                        pe[st] += 1
                        sol = {payload} if st == "unique" else set(payload)
                        if len({s[0] for s in sol}) == 1 and truth in {s[0] for s in sol}: pe["lemma_ok"] += 1
            out["E_people"] = dict(pe)
            print(json.dumps(out, ensure_ascii=False))
            for st, lst in ex.items():
                for v, why, payload in lst[:2]:
                    print(f"   [{lbl}/real-{st}] {v} :: {why} :: {str(payload)[:200]}", file=sys.stderr)
            for e in exs:
                print(f"   [{lbl}/D-lemamb] {json.dumps(e, ensure_ascii=False, default=str)[:260]}", file=sys.stderr)
            if gs and tailn == 3:
                tl_, tb_, el_, eb_ = table_size(cl)
                (OUT / f"table_{lbl}.tsv").write_text("\n".join(
                    "\t".join([t, c, wr, lr, ",".join(sorted(x[0] for x in m['genders'])), ",".join(sorted(m['tails']))])
                    for t in TYPES for c, wm in cl.rules[t].items() for wr, lrs in wm.items() for lr, m in lrs.items()), encoding="utf-8")

CASEMAP2 = {"им": "nom", "рд": "gen", "дт": "dat", "вн": "acc", "тв": "ins", "пр": "pre"}
if __name__ == "__main__":
    main()
