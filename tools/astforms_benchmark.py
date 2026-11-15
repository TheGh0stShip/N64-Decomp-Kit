#!/usr/bin/env python3
"""Mutation-recovery benchmark for ``n64dk.match.astforms`` with real compilers.

Modes (all deterministic for a given --seed):

  coverage   share of sampled exact files for which ``astforms.variants`` is non-empty,
             with ``diagnose`` reasons for the rest
  census     per family: share of single-step variants that change the compiled .text
  recover    perturb each exact file with ONE variant that changes the object, then run
             ``iterate.descend`` with the astforms families and count byte-exact recoveries
  m2c        like recover, but the perturbation is an m2c-style normal form
             (for -> init+do-while, while -> guarded do-while, early return -> nested if,
             condition spelled with explicit != 0 / == 0, masks/redundant casts, ``i += 1``,
             temporaries)

Projects are read-only: sources are compiled from temp directories.  Example:

  N64DK_TOOLCHAIN=... python tools/astforms_benchmark.py recover --project /path/nagano \\
      --manifest config/us/matching_ido_units.tsv --pipeline ido5.3 --n 75 --out results/x.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from n64dk.elf import Elf                                        # noqa: E402
from n64dk.match import astforms, astprep, iterate                # noqa: E402
from n64dk.match import compare as cmp                            # noqa: E402
from n64dk.match.pipeline import build, split_flags               # noqa: E402
from n64dk.match.toolchain import load_config                     # noqa: E402

M2C_PATTERNS = {
    "1 loop rotation": ("control: for -> init+do-while",),
    "2 guarded do-while": ("control: while -> if+do-while",),
    "3 early return": ("control: early return -> if-block",),
    "4 condition spelling": ("expr: != 0", "expr: ==0"),
    "5 mask/cast": ("cast: mask", "cast: (s32)", "cast: (u16)", "cast: (u8)", "cast: (s16)"),
    "6 increment": ("expr: x+=1",),
    "7 temporary": ("temp:",),
}


# ------------------------------------------------------------------------------ sampling
def read_manifest(project: Path, manifest: str) -> list[dict]:
    rows = []
    for line in (project / manifest).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append({"rom": parts[0], "size": int(parts[1], 0), "source": parts[2], "flags": parts[3].split(),
                     "manifest": manifest})
    return rows


def stratified(rows: list[dict], n: int, seed: int) -> list[dict]:
    rows = sorted(rows, key=lambda r: (r["size"], r["source"]))
    third = len(rows) // 3
    strata = [rows[:third], rows[third:2 * third], rows[2 * third:]]
    rng = random.Random(seed)
    out = []
    for k, stratum in enumerate(strata):
        stratum = list(stratum)
        rng.shuffle(stratum)
        for r in stratum[:n // 3 + (1 if k < n % 3 else 0)]:
            r = dict(r)
            r["stratum"] = ["small", "medium", "large"][k]
            out.append(r)
    return out


def function_name(text: str, stem: str = "") -> str | None:
    """The unit's function: the only definition, or the one named like the file."""
    try:
        funcs = astprep.list_functions(astprep.code_tokens(astprep.tokenize(text)))
    except astprep.PrepError:
        return None
    if len(funcs) == 1:
        return funcs[0][0]
    named = [f[0] for f in funcs if f[0] == stem]
    return named[0] if named else None


# ------------------------------------------------------------------------------ compiling
class Compiler:
    def __init__(self, project: Path, row: dict, pipeline: str, work: Path):
        self.project = project
        self.source = project / row["source"]
        flags = []
        for f in row["flags"]:
            if f.startswith("-I") and len(f) > 2 and not Path(f[2:]).is_absolute():
                f = "-I" + str((project / f[2:]).resolve())
            flags.append(f)
        self.spec = split_flags(flags, pipeline)
        self.includes = [str(self.source.parent), str(project / "include")] + \
            [f[2:] for f in flags if f.startswith("-I") and len(f) > 2]
        self.work = work
        self.cfg = load_config(work, None, None)
        self.cache: dict[str, bytes | None] = {}
        self.counter = 0
        self.lock = threading.Lock()
        self.builds = 0

    def text(self, source: str) -> bytes | None:
        key = hashlib.sha256(source.encode()).hexdigest()
        with self.lock:
            if key in self.cache:
                return self.cache[key]
            self.counter += 1
            folder = self.work / f"c{self.counter}"
        folder.mkdir(parents=True)
        path = folder / self.source.name
        path.write_text(source)
        try:
            obj = build(path, self.spec, self.cfg, folder, includes=[Path(p) for p in self.includes])
            data = cmp.find_section(Elf.load(obj), ".text").data
        except Exception:
            data = None
        with self.lock:
            self.builds += 1
            self.cache[key] = data
        return data


def score(candidate: bytes | None, reference: bytes) -> int | None:
    if candidate is None:
        return None
    words = max(len(candidate), len(reference)) // 4
    diff = sum(1 for k in range(words) if candidate[4 * k:4 * k + 4] != reference[4 * k:4 * k + 4])
    return diff + abs(len(candidate) - len(reference)) // 4


def evaluator(compiler: Compiler, reference: bytes):
    def evaluate(text: str) -> iterate.Evaluation:
        data = compiler.text(text)
        s = score(data, reference)
        if s is None:
            return iterate.Evaluation(None, error="build failed")
        return iterate.Evaluation(s, exact=data == reference,
                                  object_digest=hashlib.sha256(data).hexdigest())
    return evaluate


def install_hook(includes: list[str], limit: int) -> None:
    """Route ``iterate.descend``'s variant generation to astforms (integration stand-in)."""
    def hooked(source, name, families=iterate.FAMILIES, reach: int = 6):
        mine = tuple(f for f in families if f in astforms.FAMILIES)
        return astforms.variants(source, name, mine, limit=limit, includes=includes)
    iterate.variants = hooked


# ------------------------------------------------------------------------------ modes
def prepare_rows(args) -> list[tuple[dict, str, str]]:
    project = Path(args.project)
    rows = []
    for manifest in args.manifest:
        rows += read_manifest(project, manifest)
    sample = stratified(rows, args.n, args.seed)
    out = []
    for row in sample:
        text = (project / row["source"]).read_text(errors="replace")
        out.append((row, text, function_name(text, Path(row["source"]).stem)))
    return out


def mode_coverage(args, rows, work):
    reasons, records = Counter(), []
    for row, text, name in rows:
        if name is None:
            reasons["several functions, none named like the file"] += 1
            records.append({"source": row["source"], "ok": False, "reason": "several functions, none named like the file"})
            continue
        comp = Compiler(Path(args.project), row, args.pipeline, work / "cov")
        found = astforms.variants(text, name, astforms.FAMILIES, limit=16, includes=comp.includes)
        reason = None if found else astforms.diagnose(text, name, includes=comp.includes)
        mapped = (reason is None) or reason.startswith("ok")
        if reason:
            key = reason.split(":")[0] if not reason.startswith("ok") else "mapped, no applicable variant"
            reasons[key] += 1
        records.append({"source": row["source"], "ok": bool(found), "mapped": mapped, "reason": reason,
                        "stratum": row["stratum"]})
    ok = sum(1 for r in records if r["ok"])
    mapped = sum(1 for r in records if r.get("mapped"))
    return {"files": len(records), "nonempty": ok, "coverage": ok / max(1, len(records)),
            "mapped": mapped, "mapped_share": mapped / max(1, len(records)),
            "reasons": reasons.most_common(), "records": records}


def mode_census(args, rows, work):
    per_family = defaultdict(lambda: [0, 0, 0])      # changed, same, failed
    for index, (row, text, name) in enumerate(rows):
        if name is None:
            continue
        comp = Compiler(Path(args.project), row, args.pipeline, work / f"f{index}")
        ref = comp.text(text)
        if ref is None:
            continue
        found = astforms.variants(text, name, astforms.FAMILIES, limit=args.census_limit, includes=comp.includes)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(args.jobs) as pool:
            datas = list(pool.map(lambda v: comp.text(v.source), found))
        for v, data in zip(found, datas):
            cell = per_family[v.family]
            if data is None:
                cell[2] += 1
            elif data != ref:
                cell[0] += 1
            else:
                cell[1] += 1
        print(f"[census] {index + 1}/{len(rows)} {row['source']} variants={len(found)}", flush=True)
    return {fam: {"changed": c, "unchanged": s, "failed": f,
                  "share_changed": c / max(1, c + s)} for fam, (c, s, f) in sorted(per_family.items())}


def _perturb(comp, text, name, ref, rng, order, patterns=None, tries=6):
    found = astforms.variants(text, name, astforms.FAMILIES, limit=None, includes=comp.includes)
    by_family = defaultdict(list)
    for v in found:
        key = v.family
        if patterns is not None:
            key = next((p for p, prefixes in patterns.items() if v.label.startswith(prefixes)), None)
            if key is None:
                continue
        by_family[key].append(v)
    attempts = []
    for family in order:
        pool = list(by_family.get(family, []))
        rng.shuffle(pool)
        for v in pool[:tries]:
            data = comp.text(v.source)
            attempts.append((family, v.label, data is not None and data != ref))
            if data is not None and data != ref:
                return family, v, attempts
    return None, None, attempts


def mode_recover(args, rows, work, patterns=None):
    records = []
    keys = list(patterns) if patterns else [f for f in astforms.FAMILIES]
    for index, (row, text, name) in enumerate(rows):
        rec = {"source": row["source"], "stratum": row["stratum"], "manifest": row["manifest"]}
        records.append(rec)
        if name is None:
            rec["status"] = "not a single-function file"
            continue
        comp = Compiler(Path(args.project), row, args.pipeline, work / f"f{index}")
        ref = comp.text(text)
        if ref is None:
            rec["status"] = "reference build failed"
            continue
        if not astforms.variants(text, name, astforms.FAMILIES, limit=1, includes=comp.includes):
            rec["status"] = "unmapped: " + astforms.diagnose(text, name, includes=comp.includes)[:120]
            continue
        rng = random.Random(f"{args.seed}:{row['source']}")
        order = keys[index % len(keys):] + keys[:index % len(keys)]
        family, perturbed, attempts = _perturb(comp, text, name, ref, rng, order, patterns)
        rec["attempts"] = len(attempts)
        if perturbed is None:
            rec["status"] = "no single-step variant changes the object"
            continue
        rec.update({"family": family, "perturbation": perturbed.label})
        start = comp.builds
        install_hook(comp.includes, args.limit)
        t0 = time.time()
        result = iterate.descend(perturbed.source, name, evaluator(comp, ref), families=astforms.FAMILIES,
                                 budget=args.budget, jobs=args.jobs)
        rec.update({"status": "exact" if result.get("exact") else "not recovered",
                    "start_score": result.get("start_score"), "final_score": result.get("final_score"),
                    "evaluated": result.get("evaluated"), "builds": comp.builds - start,
                    "stopped": result.get("stopped_reason"), "seconds": round(time.time() - t0, 1),
                    "path": [e["label"] for e in result.get("edit_path", [])],
                    "recovered_text_equal": result.get("source") == text})
        if not result.get("exact"):
            rec["diagnosis"] = diagnose_failure(comp, text, name, perturbed, ref)
        print(f"[{args.mode}] {index + 1}/{len(rows)} {row['source']} {family} -> {rec['status']} "
              f"({rec.get('evaluated')} builds)", flush=True)
    return summarize(records)


def diagnose_failure(comp, original, name, perturbed, ref) -> dict:
    """Is the original one step away from the perturbed source?  Which family offers it?"""
    back = astforms.variants(perturbed.source, name, astforms.FAMILIES, limit=None, includes=comp.includes)
    exact_texts = [v for v in back if v.source == original]
    if exact_texts:
        position = None
        limited = astforms.variants(perturbed.source, name, astforms.FAMILIES, limit=160, includes=comp.includes)
        for k, v in enumerate(limited):
            if v.source == original:
                position = k
        return {"category": "beam budget / ordering" if position is not None else "inverse beyond the per-parent limit",
                "inverse": exact_texts[0].label, "position_in_limited": position, "candidates": len(back)}
    same_object = [v for v in back if comp.text(v.source) == ref] if len(back) <= 400 else []
    if same_object:
        return {"category": "beam budget / ordering (object-equal variant exists)", "inverse": same_object[0].label,
                "candidates": len(back)}
    return {"category": "inverse not generated (family gap or blocked by analysis)", "candidates": len(back)}


def summarize(records):
    by_family = defaultdict(Counter)
    builds = defaultdict(list)
    for r in records:
        if "family" not in r:
            continue
        by_family[r["family"]][r["status"]] += 1
        if r["status"] == "exact":
            builds[r["family"]].append(r["evaluated"])
    table = {}
    for fam, counts in sorted(by_family.items()):
        total = sum(counts.values())
        table[fam] = {"perturbed": total, "exact": counts["exact"], "rate": counts["exact"] / max(1, total),
                      "median_builds": statistics.median(builds[fam]) if builds[fam] else None}
    exact_all = [r["evaluated"] for r in records if r.get("status") == "exact"]
    perturbed = [r for r in records if "family" in r]
    return {"files": len(records), "perturbed": len(perturbed),
            "exact": len(exact_all), "rate": len(exact_all) / max(1, len(perturbed)),
            "median_builds": statistics.median(exact_all) if exact_all else None,
            "status": Counter(r["status"].split(":")[0] for r in records).most_common(),
            "failure_categories": Counter(r["diagnosis"]["category"] for r in records if "diagnosis" in r).most_common(),
            "by_family": table, "records": records}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["coverage", "census", "recover", "m2c"])
    ap.add_argument("--project", required=True)
    ap.add_argument("--manifest", action="append", required=True)
    ap.add_argument("--pipeline", required=True, help="ido5.3, ido7.1, kmc+builtin ...")
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--budget", type=int, default=300)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--limit", type=int, default=160, help="variants per parent source in descend")
    ap.add_argument("--census-limit", type=int, default=72)
    ap.add_argument("--patterns", default="", help="m2c: comma-separated pattern numbers to use (default all)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    rows = prepare_rows(args)
    with tempfile.TemporaryDirectory(prefix="astbench-") as tmp:
        work = Path(tmp)
        if args.mode == "coverage":
            result = mode_coverage(args, rows, work)
        elif args.mode == "census":
            result = mode_census(args, rows, work)
        elif args.mode == "recover":
            result = mode_recover(args, rows, work)
        else:
            keep = set(args.patterns.split(",")) if args.patterns else None
            patterns = {k: v for k, v in M2C_PATTERNS.items() if keep is None or k.split()[0] in keep}
            result = mode_recover(args, rows, work, patterns)
    result["args"] = vars(args)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1, default=str))
    summary = {k: v for k, v in result.items() if k not in ("records",)}
    print(json.dumps(summary, indent=1, default=str)[:4000])


if __name__ == "__main__":
    main()
