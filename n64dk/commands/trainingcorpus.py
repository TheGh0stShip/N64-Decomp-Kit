"""Verified training pairs from imported source trees, and the draft rules learned from them.

``training-corpus-build``     pairs of one title (strict tree functions, drafts under conditions)
``training-corpus-audit``     rebuild pairs and check they still reproduce
``training-corpus-stats``     counts by title, compiler, optimisation, size, draft outcome
``training-corpus-explore``   build single-step draft variants, record their effect by kind
``training-corpus-evaluate``  controlled comparisons: drafts with and without the tree's
                              declarations; learned rules, leaving one title out
``training-corpus-export``    a shareable copy without sources
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from ..cli import command


def _cfg(out: Path, toolchain: str | None):
    from ..match.toolchain import load_config
    return load_config(out, None, toolchain or os.environ.get("N64DK_TOOLCHAIN"))


def _heavy(name: str, out: Path, args, body):
    from .. import safety
    try:
        with safety.heavy_job(name, out, wait_for_lock=args.wait_for_lock, force=args.force_resources,
                              argv=sys.argv[1:]):
            return body()
    except safety.Busy as error:
        raise SystemExit(str(error)) from None


def _emit(event, **fields):
    print(json.dumps({"event": event, **fields}), file=sys.stderr, flush=True)


@command("training-corpus-build", "Collect verified draft/source pairs of one title from an imported source tree")
def training_corpus_build(args):
    from ..match import trainingcorpus
    from ..resources import plan_jobs
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "project.json").write_text(json.dumps({"project": str(Path(args.project).resolve())}))

    def body():
        result = trainingcorpus.build(Path(args.project), Path(args.rom_run) if args.rom_run else None,
                                      Path(args.import_run), Path(args.donor_dir), out, _cfg(out, args.toolchain),
                                      tuple(args.conditions), args.draft_sample, plan_jobs(args.jobs).jobs, _emit)
        (out / "build.json").write_text(json.dumps(result, indent=1))
        return result
    return _heavy("training-corpus-build", out, args, body)


@command("training-corpus-audit", "Rebuild training pairs and check each still gives its target's bytes")
def training_corpus_audit(args):
    from ..match import trainingcorpus
    corpus = Path(args.corpus).resolve()
    project = Path(json.loads((corpus / "project.json").read_text())["project"])
    return _heavy("training-corpus-audit", corpus, args,
                  lambda: trainingcorpus.audit(corpus, project, _cfg(corpus, args.toolchain), args.sample,
                                               repair=args.repair))


@command("training-corpus-stats", "Count training pairs by title, compiler, optimisation, size and draft outcome")
def training_corpus_stats(args):
    from ..match import trainingcorpus
    records = [record for corpus in args.corpus for record in trainingcorpus.load(Path(corpus))]
    return trainingcorpus.stats(records)


@command("training-corpus-explore", "Build single-step variants of the corpus drafts and record their effect by kind")
def training_corpus_explore(args):
    from ..match import learnedrules, trainingcorpus
    from ..resources import plan_jobs
    corpus = Path(args.corpus).resolve()

    def body():
        records = trainingcorpus.load(corpus)
        found = learnedrules.explore(records, corpus, _cfg(corpus, args.toolchain), args.limit, args.sample,
                                     plan_jobs(args.jobs).jobs, args.condition, _emit)
        return {"observations": len(found), "pairs": len({item["pair"] for item in found})}
    return _heavy("training-corpus-explore", corpus, args, body)


@command("training-corpus-evaluate", "Controlled measurements on training pairs: declarations given to the "
                                     "decompiler, and learned draft rules with one title held out")
def training_corpus_evaluate(args):
    from ..match import learnedrules, trainingcorpus
    records, observations = [], []
    for corpus in args.corpus:
        records.extend(trainingcorpus.load(Path(corpus)))
        observations.extend(learnedrules.load_observations(Path(corpus)))
    out = {"pairs": len(records), "declarations": trainingcorpus.compare_conditions(records),
           "recovered_declarations": trainingcorpus.compare_conditions(records, "plain", "recovered"),
           "recovered_against_tree": trainingcorpus.compare_conditions(records, "recovered", "context")}
    titles = sorted({item["title"] for item in observations})
    if len(titles) >= 2:
        out["rules_leave_one_title_out"] = [learnedrules.evaluate(observations, title) for title in titles]
    elif observations:
        out["rules_leave_one_title_out"] = "needs observations from two titles"
    rules = learnedrules.learn(observations)
    out["registry"] = learnedrules.registry(rules, titles)
    if args.registry:
        Path(args.registry).write_text(json.dumps(out["registry"], indent=1))
    return out


@command("training-corpus-export", "Write a shareable copy of a training corpus (no sources, no ROM bytes)")
def training_corpus_export(args):
    from ..match import trainingcorpus
    return trainingcorpus.export(Path(args.corpus), Path(args.out))


def _guard(p):
    from .run import _guard_arguments
    _guard_arguments(p)
    p.add_argument("--toolchain", help="toolchain root (default: $N64DK_TOOLCHAIN)")


def _build_args(p):
    p.add_argument("--project", required=True, help="the title's project")
    p.add_argument("--import-run", required=True, help="decompile-run output that used the tree as donor")
    p.add_argument("--donor-dir", required=True, help="the tree donor's folder (source-donor output)")
    p.add_argument("--rom-run", help="a run of the same title without the tree, for what the ROM alone gave")
    p.add_argument("--out", required=True, help="corpus folder")
    p.add_argument("--conditions", nargs="*", default=["plain", "context"], choices=["plain", "context", "recovered"],
                   help="drafts made for each pair: plain (decompiler alone), context (the tree's own declarations), "
                        "recovered (the kit's whole-program recovery of structures, globals and prototypes)")
    p.add_argument("--draft-sample", type=int, help="draft only this many pairs, evenly spread")
    p.add_argument("--jobs", type=int, default=2)
    _guard(p)


def _audit_args(p):
    p.add_argument("--corpus", required=True)
    p.add_argument("--sample", type=int, help="audit this many pairs, evenly spread (default: every pair)")
    p.add_argument("--repair", action="store_true",
                   help="relabel pairs another function of their source reproduces; quarantine every other "
                        "failure so it never reaches training or evaluation")
    _guard(p)


def _stats_args(p):
    p.add_argument("--corpus", nargs="+", required=True)


def _explore_args(p):
    p.add_argument("--corpus", required=True)
    p.add_argument("--limit", type=int, default=16, help="variants per draft")
    p.add_argument("--sample", type=int, help="drafts to explore, evenly spread")
    p.add_argument("--condition", default="plain", choices=["plain", "context"])
    p.add_argument("--jobs", type=int, default=2)
    _guard(p)


def _evaluate_args(p):
    p.add_argument("--corpus", nargs="+", required=True)
    p.add_argument("--registry", help="write the learned rule registry here")


def _export_args(p):
    p.add_argument("--corpus", required=True)
    p.add_argument("--out", required=True)


training_corpus_build.arguments = _build_args
training_corpus_audit.arguments = _audit_args
training_corpus_stats.arguments = _stats_args
training_corpus_explore.arguments = _explore_args
training_corpus_evaluate.arguments = _evaluate_args
training_corpus_export.arguments = _export_args
