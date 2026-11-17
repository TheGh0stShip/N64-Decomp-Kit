"""Draft rewrites learned from verified pairs, accepted or rejected by measurement.

The kit's search edits a draft one step at a time (``astforms.variants``: loop forms, casts,
temporaries, statement order...).  It tries the steps in a fixed round-robin order, so a
function's budget of builds goes to whatever the generator yields first.  A verified pair
(``trainingcorpus``) says, for one function, which steps bring its draft closer to the C that
really produced the bytes.  Over many pairs that is a measured success rate per *kind* of step,
by compiler family: the kit can then try the steps that work first and leave out the ones that
never help.

* ``explore``   builds every single-step variant (up to a limit) of the drafts of a corpus and
                records how many words each one changes, by kind of step;
* ``learn``     turns observations into a registry: per kind and compiler family, tries,
                improvements, regressions, exact results, a score, and accepted or rejected with
                the reason;
* ``evaluate``  leave-one-title-out: rules learned on the other titles order the steps of the
                held-out title's drafts, against the generator's own order, under the same build
                budget.  The held-out title's observations serve only as the outcome of each
                build, never for learning.

A step is never trusted because it was learned: every candidate is still built and compared.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

MIN_IMPROVED = 3          # a rule is accepted only after it helped at least this often...
MIN_TRIES = 8             # ...in at least this many tries


def kind(label: str) -> str:
    """The kind of a variant step, without the place and the operand it applies to."""
    text = re.sub(r"'[^']*'", "E", label)
    text = re.sub(r"\s*#\d+$", "", text)
    text = re.sub(r"\bL\d+\b", "", text)
    text = re.sub(r"\b(up|down) \d+", r"\1", text)
    text = re.sub(r"\bx\d+\b", "", text)
    cast = re.match(r"cast: (\w+) \w+ (.+?) -> (.+)$", text)
    if cast:
        text = f"cast: {cast.group(1)} {cast.group(2).strip()} -> {cast.group(3).strip()}"
    text = re.sub(r"^(stmt-order|decl-order): move .*? (up|down|out to function block|into block)\b.*$",
                  r"\1: move \2", text)
    text = re.sub(r"^inline-temp: \w+ = E.*$", "inline-temp: inline", text)
    text = re.sub(r"\b0x[0-9A-Fa-f]+\b|\b\d+\b", "N", text)
    return re.sub(r"\s+", " ", text).strip()


def explore(records: list[dict], corpus: Path, cfg, limit: int = 16, sample: int | None = None,
            jobs: int = 2, condition: str = "plain", emit=None) -> list[dict]:
    """Observations: for each pair whose ``condition`` draft compiles but differs, every
    single-step variant (up to ``limit``), built and compared.  ``[{pair, kind, label, family,
    before, after, exact, compiles}]``, also appended to ``<corpus>/observations.jsonl``."""
    from concurrent.futures import ThreadPoolExecutor
    from . import astforms
    from .trainingcorpus import compile_and_compare
    from . import images as _images                    # noqa: F401  (imported for symmetry with build)
    emit = emit or (lambda *_a, **_k: None)
    corpus = Path(corpus)
    chosen = [record for record in records
              if (record.get("drafts", {}).get(condition) or {}).get("compiles")
              and (record["drafts"][condition] or {}).get("found")
              and not record["drafts"][condition].get("text_equal")]
    if sample and sample < len(chosen):
        step = len(chosen) / sample
        chosen = [chosen[int(k * step)] for k in range(sample)]
    targets = _targets(corpus)
    started = time.time()

    def one(record):
        draft = (corpus / "sources" / f"{record['drafts'][condition]['source_sha256']}.c").read_text()
        name = record["tree_function"]
        code = targets(record)
        if code is None:
            return []
        before = record["drafts"][condition]["differing_words"]
        out = []
        for variant in astforms.variants(draft, name, limit=limit):
            with tempfile.TemporaryDirectory(prefix="n64dk-rule-") as work:
                outcome = compile_and_compare(variant.source, name, record["pipeline"], record["flags"], cfg, code,
                                              int(record["vram"], 16), Path(work))
            out.append({"pair": f"{record['title_sha1'][:12]}:{record['image']}:{record['vram']}",
                        "title": record["title_sha1"], "family": record["compiler_family"],
                        "label": variant.label, "kind": kind(variant.label), "step_family": variant.family,
                        "before": before, "after": outcome.get("differing_words"),
                        "compiles": bool(outcome.get("compiles") and outcome.get("found")),
                        "exact": bool(outcome.get("text_equal")), "review": bool(variant.semantic_review)})
        return out

    observations = []
    with (corpus / "observations.jsonl").open("a") as sink, ThreadPoolExecutor(max(1, jobs)) as pool:
        for number, found in enumerate(pool.map(one, chosen)):
            for item in found:
                sink.write(json.dumps(item, sort_keys=True) + "\n")
            observations.extend(found)
            if number % 25 == 0:
                emit("explore", done=number, of=len(chosen), seconds=round(time.time() - started))
    return observations


def _targets(corpus: Path):
    """A function giving a record's target bytes, read from the project recorded with the
    corpus (``<corpus>/project.json``), checked against the record's digest."""
    from . import images as imagemod
    project = Path(json.loads((Path(corpus) / "project.json").read_text())["project"])
    cache: dict = {}

    def get(record):
        image = record["image"]
        if image not in cache:
            spec = imagemod.resolve(project, image)
            cache[image] = (spec.load(), spec.delta)
        data, delta = cache[image]
        vram = int(record["vram"], 16)
        code = data[vram - delta:vram - delta + record["size"]]
        return code if hashlib.sha256(code).hexdigest() == record["target_sha256"] else None
    return get


def load_observations(corpus: Path) -> list[dict]:
    path = Path(corpus) / "observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.is_file() else []


def learn(observations: list[dict]) -> dict:
    """``{(family, kind): rule}`` with tries, improved, worsened, unchanged, broken (does not
    compile), exact, mean change in differing words, score, accepted and the reason."""
    table: dict[tuple[str, str], Counter] = defaultdict(Counter)
    change: dict[tuple[str, str], list[int]] = defaultdict(list)
    for item in observations:
        key = (item["family"], item["kind"])
        counts = table[key]
        counts["tries"] += 1
        if not item["compiles"] or item["after"] is None:
            counts["broken"] += 1
            continue
        delta = item["after"] - item["before"]
        change[key].append(delta)
        counts["improved" if delta < 0 else "worsened" if delta > 0 else "unchanged"] += 1
        counts["exact"] += int(item["exact"])
    rules = {}
    for key, counts in table.items():
        tries = counts["tries"]
        score = (counts["improved"] - counts["worsened"] + 3 * counts["exact"]) / tries
        mean = sum(change[key]) / len(change[key]) if change[key] else None
        if tries < MIN_TRIES:
            accepted, reason = False, f"only {tries} tries"
        elif counts["improved"] < MIN_IMPROVED:
            accepted, reason = False, f"improved {counts['improved']} of {tries} tries"
        elif counts["improved"] + counts["exact"] <= counts["worsened"]:
            accepted, reason = False, f"worse more often ({counts['worsened']}) than better ({counts['improved']})"
        else:
            accepted, reason = True, f"better {counts['improved']}, worse {counts['worsened']} of {tries}"
        rules[key] = {"family": key[0], "kind": key[1], **{k: counts[k] for k in
                      ("tries", "improved", "worsened", "unchanged", "broken", "exact")},
                      "mean_change": None if mean is None else round(mean, 3), "score": round(score, 4),
                      "accepted": accepted, "reason": reason}
    return rules


def registry(rules: dict, trained_on: list[str]) -> dict:
    """The registry as written to disk: accepted and rejected rules, most useful first."""
    ordered = sorted(rules.values(), key=lambda rule: (not rule["accepted"], -rule["score"], rule["kind"]))
    return {"trained_on": sorted(trained_on), "accepted": [r for r in ordered if r["accepted"]],
            "rejected": [r for r in ordered if not r["accepted"]]}


def order(labels: list[str], family: str, rules: dict, only_accepted: bool = True) -> list[int]:
    """Indices of ``labels`` in the order the rules give: accepted kinds by score (ties keep the
    generator's order); kinds not accepted are left out when ``only_accepted``, else last."""
    ranked = []
    for index, label in enumerate(labels):
        rule = rules.get((family, kind(label)))
        if rule and rule["accepted"]:
            ranked.append((0, -rule["score"], index))
        elif not only_accepted:
            ranked.append((1, 0.0, index))
    return [index for _a, _b, index in sorted(ranked)]


def evaluate(observations: list[dict], held_out: str, budgets: tuple[int, ...] = (1, 2, 4, 8)) -> dict:
    """Leave one title out.  Rules are learned on every observation not of ``held_out``; on the
    held-out title's pairs, the first ``budget`` steps in (a) the generator's order and (b) the
    learned order are compared: pairs improved, pairs made exact, total words recovered."""
    train = [item for item in observations if item["title"] != held_out]
    test = [item for item in observations if item["title"] == held_out]
    rules = learn(train)
    by_pair: dict[str, list[dict]] = defaultdict(list)
    for item in test:
        by_pair[item["pair"]].append(item)
    out = {"held_out": held_out[:12], "trained_on": sorted({item["title"][:12] for item in train}),
           "train_observations": len(train), "test_pairs": len(by_pair), "test_observations": len(test),
           "accepted_rules": sum(1 for rule in rules.values() if rule["accepted"]),
           "rejected_rules": sum(1 for rule in rules.values() if not rule["accepted"]), "budgets": {}}

    def gain(item):
        if not item["compiles"] or item["after"] is None:
            return 0
        return max(0, item["before"] - item["after"])

    for budget in budgets:
        row = {}
        for strategy in ("generator", "learned", "learned+rest"):
            improved = exact = recovered = builds = 0
            for items in by_pair.values():
                if strategy == "generator":
                    picked = items[:budget]
                else:
                    idx = order([item["label"] for item in items], items[0]["family"], rules,
                                only_accepted=strategy == "learned")
                    picked = [items[i] for i in idx[:budget]]
                builds += len(picked)
                best = max((gain(item) for item in picked), default=0)
                improved += int(best > 0)
                exact += int(any(item["exact"] for item in picked))
                recovered += best
            row[strategy] = {"pairs_improved": improved, "pairs_exact": exact, "words_recovered": recovered,
                             "builds": builds}
        out["budgets"][str(budget)] = row
    everything = {"pairs_improved": sum(1 for items in by_pair.values() if any(gain(i) > 0 for i in items)),
                  "pairs_exact": sum(1 for items in by_pair.values() if any(i["exact"] for i in items)),
                  "builds": len(test)}
    out["every_step"] = everything
    return out
