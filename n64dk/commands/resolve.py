"""``resolve-case``, ``resolve-hard`` and ``hard-queue``: the hard-function resolution engine."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..analysis import flow as flowmod
from ..analysis.catalogue import load as load_catalogue
from ..cli import command
from ..match import autodraft, m2c_bridge
from ..match import iterate as itermod
from ..match import resolve as resolvemod
from ..match.engine import match_source
from ..match.pipeline import split_flags
from .match import _common, _setup


def _int(text: str) -> int:
    return int(text, 0)


def _prepare(args):
    """(cfg, target, symbols) for a ROM with a boot segment, or for a linear image when
    ``--vram-delta`` is given (overlays, unpacked programs)."""
    from ..match import symbols as symmod
    from ..match.engine import Target
    from ..match.toolchain import load_config
    from ..rom import RomError
    try:
        cfg, target, syms, _files = _setup(args)
        return cfg, target, syms
    except (RomError, SystemExit) as error:
        if args.vram_delta is None:
            raise ValueError(f"{args.rom} is not a ROM with a boot segment ({error}); pass --vram-delta for a "
                             "linear image") from None
    cfg = load_config(args.project, getattr(args, "config", None), getattr(args, "toolchain_dir", None))
    if getattr(args, "include", None):
        cfg.include = list(dict.fromkeys([Path(cfg.project, value).resolve() for value in args.include] + cfg.include))
    data = Path(args.rom).read_bytes()
    files = [Path(value) for value in args.symbols] or cfg.symbols or symmod.discover(cfg.project)
    return cfg, Target(data, args.vram_delta, (0, len(data))), symmod.load(files)


def _state(args, cfg) -> Path:
    return Path(args.state).resolve() if args.state else Path(cfg.project) / ".n64dk" / "resolve"


def _image_label(args) -> str:
    return args.image_name or Path(args.rom).stem


def synthesize_context(target, functions, names: dict[int, str], out_dir: Path, label: str,
                       parts: tuple[str, ...] = ("structs", "globals", "prototypes"),
                       proto_confidence: float = 0.9) -> tuple[Path, str, dict]:
    """Recover provisional structs, global declarations and prototypes for a whole image and
    write them as an m2c context.  Returns (context path, declarations without typedefs for
    prepending to a draft, summary)."""
    from ..analysis import abi as abimod
    from ..analysis import layouts as layoutmod
    from ..analysis import values as valuemod

    facts = {}
    for _name, vram, size in functions:
        if size >= 8 and 0 <= vram - target.delta <= len(target.rom) - size:
            facts[vram] = valuemod.track(flowmod.analyse_in_image(target.rom, target.delta, vram, size))
    function_names = {vram: name for name, vram, _size in functions}
    layouts = layoutmod.recover(facts, {**names, **function_names})
    if "structs" not in parts:
        layouts.groups, layouts.param_group, layouts.return_group = [], {}, {}
    if "globals" not in parts:
        layouts.globals = []
    prototypes = abimod.solve(facts, function_names) if "prototypes" in parts else {}
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{label}.context.h"
    rendered = layoutmod.Declarations(layouts, prototypes, proto_confidence)
    path.write_text(rendered.full(typedefs=True))
    info = {**layoutmod.summary(layouts), "prototypes": len(rendered.confident)}
    return path, rendered.full(typedefs=False), info, rendered, facts


class _Runner:
    """Build/compare and draft services bound to one image and recipe."""

    def __init__(self, args, cfg, target, syms, work: Path):
        self.args, self.cfg, self.target, self.syms, self.work = args, cfg, target, syms, work
        self.spec = split_flags(shlex.split(args.flags), args.pipeline)
        self.context_path = Path(args.context) if args.context and args.context != "auto" else None
        self.declarations = ""
        self.rendered, self.facts = None, {}
        self.recipe_map = None
        # alternative m2c renderings tried by the draft portfolio
        self.draft_options = [tuple(o.split("+")) for o in getattr(args, "draft_options", "").split(",") if o]

    def auto_context(self, functions, names, state: Path, label: str) -> dict | None:
        if self.args.context != "auto":
            return None
        parts = tuple(p for p in self.args.context_parts.split(",") if p)
        self.context_path, self.declarations, info, self.rendered, self.facts = synthesize_context(
            self.target, functions, names, state / "context", label, parts, self.args.proto_confidence)
        return info

    def evaluator(self, vram: int, size: int, filename: str = "candidate.c", spec=None):
        spec = spec or self.spec

        def evaluate(text: str):
            folder = self.work / hashlib.sha256(
                f"{vram}:{spec.pipeline}:{spec.flags}:{text}".encode()).hexdigest()[:20]
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / filename
            path.write_text(text)
            try:
                outcome = match_source(path, spec, self.cfg, self.target, vram, size, self.syms, folder, None,
                                       strict_verification=True)
            except Exception as error:                       # a failed build is data for the case
                return itermod.Evaluation(None, error=str(error)[-400:]), None
            finally:
                # a sweep judges hundreds of thousands of candidates and the work directory is
                # often memory-backed: nothing in the folder is needed once the outcome exists
                shutil.rmtree(folder, ignore_errors=True)
            if outcome.error or outcome.result is None:
                return itermod.Evaluation(None, error=(outcome.error or "no comparison")[-400:]), None
            report = outcome.result.diff
            code = getattr(outcome.result, "compiled_text", b"") or None
            if report is None:
                return itermod.Evaluation(0 if outcome.exploratory_exact else 1, outcome.exact, None,
                                          outcome=outcome.as_dict()), code
            return itermod.Evaluation(report.score, outcome.exact, report.as_dict(limit=4096),
                                      outcome=outcome.as_dict()), code
        return evaluate

    def recipes(self, vram: int, size: int, filename: str, limit: int = 12):
        """Alternative build recipes of the detected compiler family, usual retail settings first."""
        from ..match.engine import default_pipelines, sweep_specs

        def alternatives(family):
            pipelines = [p for p in default_pipelines(self.cfg)
                         if (p.startswith("ido")) == (family == "ido") and p != self.spec.pipeline]
            if family is None:
                pipelines = [p for p in default_pipelines(self.cfg) if p != self.spec.pipeline]
            out, seen = [], set()
            if self.recipe_map is not None:
                for row in self.recipe_map.candidates(vram, 4):      # proven nearby, nearest first
                    spec = split_flags(list(row["flags"]), row["pipeline"])
                    key = (spec.pipeline, tuple(spec.flags))
                    if key in seen or key == (self.spec.pipeline, tuple(self.spec.flags)):
                        continue
                    seen.add(key)
                    spec.section_bases.update(self.spec.section_bases)
                    spec.symbols.update(self.spec.symbols)
                    out.append((f"{spec.pipeline} {' '.join(spec.flags)}", spec.pipeline,
                                self.evaluator(vram, size, filename, spec)))
            # The first alternatives must span the compilers, not one compiler's variations: a
            # title built with one compiler usually carries library code built with another, and
            # when the family of a function is uncertain every available compiler is a candidate.
            #   1. the current flags under each pipeline of the same dialect (the other IDO
            #      version, the other KMC lanes);
            #   2. the usual settings of every other pipeline, one each;
            #   3. the other optimisation levels of the current compiler and its dialect siblings
            #      (libraries at -O1 or -O3, a debug file);
            #   4. the remaining usual settings, in turn.
            def dialect(pipeline: str) -> str:
                return pipeline[:3] if pipeline[:3] in ("ido", "kmc") else pipeline
            ordered = [split_flags(list(self.spec.flags), pipeline) for pipeline in pipelines
                       if dialect(pipeline) == dialect(self.spec.pipeline)]
            swept = [sweep_specs([pipeline])[:max(1, limit // max(1, len(pipelines)))] for pipeline in pipelines]
            ordered += [specs[0] for specs in swept if specs]
            # optimisation levels: of the current recipe when its compiler is a candidate for this
            # function, and of each other candidate compiler's usual settings
            current_is_candidate = family is None or self.spec.pipeline.startswith("ido") == (family == "ido")
            bases = ([self.spec] if current_is_candidate else []) + list(ordered)
            for other in ("-O1", "-O3", "-O2"):
                for base in bases:
                    level = next((f for f in base.flags if re.fullmatch(r"-O\d?", f)), None)
                    if level is not None and level != other:
                        ordered.append(split_flags([other if f == level else f for f in base.flags], base.pipeline))
            for rank in range(1, max((len(specs) for specs in swept), default=0)):
                ordered += [specs[rank] for specs in swept if rank < len(specs)]
            for spec in ordered:
                key = (spec.pipeline, tuple(sorted(spec.flags)))
                if key in seen or (spec.pipeline, tuple(spec.flags)) in seen:
                    continue
                seen.add(key)
                spec.section_bases.update(self.spec.section_bases)
                spec.symbols.update(self.spec.symbols)
                out.append((f"{spec.pipeline} {' '.join(spec.flags)}", spec.pipeline,
                            self.evaluator(vram, size, filename, spec)))
            return out
        return alternatives

    def _draft(self, name, code, vram, compiler, context, declarations, names, tables, evaluate, extra=None):
        """One draft: m2c, self-contained preparation, recovered declarations, mechanical repairs."""
        result = m2c_bridge.draft(name, code, vram, compiler, context, names, tables, extra)
        if result.get("source") is None:
            return None, f"{result.get('status')}: {result.get('error')}"
        text = autodraft.prepare(result["source"])
        if declarations:
            # drop the draft's own guesses for anything the context already declares
            declared = set(re.findall(r"(?m)^(?:extern\s+)?[\w \*]+?\b(\w+)\s*(?:\(|\[|;)", declarations))
            kept = []
            for line in text[len(autodraft.PRELUDE):].split("\n"):
                found = re.match(r"^(?:extern\s+)?[\w \*]+?\b(\w+)\s*(?:\([^{]*\)|\[[^\]]*\])?;", line)
                if found and found.group(1) in declared and "{" not in line:
                    continue
                kept.append(line)
            text = autodraft.PRELUDE + "\n" + declarations + "\n".join(kept)
        for _attempt in range(12):                           # mechanical compile repairs only
            evaluation, _code = evaluate(text)
            if evaluation.score is not None:
                break
            fixed = autodraft.repair(text, evaluation.error or "")
            if fixed is None or fixed == text:
                break                                        # the baseline stage reports the build error
            text = fixed
        return text, None

    def drafter(self, name: str, vram: int, size: int, evaluate, names: dict[int, str]):
        def draft(family=None):
            offset = vram - self.target.delta
            code = self.target.rom[offset:offset + size]
            tables = m2c_bridge.find_jump_tables(self.target.rom, self.target.delta, vram, size)
            if family is None and self.args.pipeline.startswith("custom:"):
                from ..match import custom_pipeline
                family = custom_pipeline.family_of(self.args.pipeline, self.cfg.project)
            compiler = "ido" if family == "ido" else ("kmc" if family == "gcc" else self.args.pipeline)
            modes = [("plain", None, "", None)]
            if self.context_path is not None:
                modes.append(("context", self.context_path, self.declarations, None))
            if not self.args.draft_portfolio:
                # single draft: with the context when there is one, falling back to plain
                text, error = self._draft(name, code, vram, compiler, modes[-1][1], modes[-1][2], names, tables,
                                          evaluate)
                if text is None and len(modes) > 1:
                    text, error = self._draft(name, code, vram, compiler, None, "", names, tables, evaluate)
                return text, error
            if self.rendered is not None and vram in self.facts:
                # portfolio: declarations cut down to this function.  Callee prototypes tell the
                # decompiler how many arguments a call takes; the function's own prototype is the
                # least certain part, so it is offered as a separate variant.
                modes = [("plain", None, "", None)]
                folder = self.work / "context"
                folder.mkdir(parents=True, exist_ok=True)
                for label, include_self in (("callees", False), ("callees+self", True)):
                    text = self.rendered.focused(self.facts[vram], vram, include_self, typedefs=True)
                    if text.count("\n") <= 4:
                        continue                                     # nothing recovered for this function
                    path = folder / f"{name}.{label.replace('+', '_')}.h"
                    path.write_text(text)
                    modes.append((label, path, self.rendered.focused(self.facts[vram], vram, include_self,
                                                                     typedefs=False), None))
            modes += [("plain:" + "+".join(flags), None, "", list(flags)) for flags in self.draft_options]
            out, errors = [], []
            for label, context, declarations, extra in modes:
                text, error = self._draft(name, code, vram, compiler, context, declarations, names, tables,
                                          evaluate, extra)
                if text is not None and text not in [t for _l, t in out]:
                    out.append((label, text))
                elif error:
                    errors.append(error)
            if not out:
                return None, "; ".join(errors[:2]) or "m2c produced nothing"
            # normal forms of each draft (loops un-rotated, masks dropped, ...) join the portfolio
            from ..match import draftforms
            texts = {text for _label, text in out}
            for label, text in list(out)[:2]:
                for kind, normal, _review in draftforms.drafts(text, name):
                    if normal not in texts:
                        texts.add(normal)
                        out.append((f"{label}/{kind}", normal))
            return out
        return draft

    def strict(self, vram: int, size: int, filename: str, starts: set[int] | None):
        """Non-circular re-verification of an exact candidate with the recipe that produced it."""
        from ..elf import Elf
        from ..match import verify as verifymod
        from ..match.pipeline import build

        def check(text: str, recipe: str) -> dict:
            pipeline, _, flags = (recipe or f"{self.spec.pipeline} {' '.join(self.spec.flags)}").partition(" ")
            spec = split_flags(shlex.split(flags), pipeline)
            spec.section_bases.update(self.spec.section_bases)
            spec.symbols.update(self.spec.symbols)
            folder = self.work / ("strict-" + hashlib.sha256(f"{vram}:{recipe}:{text}".encode()).hexdigest()[:20])
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / filename
            path.write_text(text)
            try:
                elf = Elf.load(build(path, spec, self.cfg, folder))
            finally:
                shutil.rmtree(folder, ignore_errors=True)
            # only independently declared symbols: names in the candidate's own text prove nothing
            symbols = self.syms.copy()
            symbols.update(spec.symbols)
            return verifymod.strict_compare(elf, self.target.rom, self.target.vram_to_rom, vram, size, symbols,
                                            spec.section_bases, None, starts).as_dict()
        return check

    def label(self, spec=None) -> str:
        spec = spec or self.spec
        return f"{spec.pipeline} {' '.join(spec.flags)}"

    def learn_recipes(self, functions, matched_rows) -> dict | None:
        """Partition the image into probable objects and remember which recipe matched where."""
        from ..analysis import units as unitmod
        from ..match import causes as causemod

        def family(flow):
            found = causemod.compiler_family(flow)
            return found["family"] if found["confidence"] >= 0.8 else None
        self.recipe_map = unitmod.RecipeMap(unitmod.units(self.target.rom, self.target.delta, functions,
                                                          family_of=family))
        for vram, size, spec in matched_rows:
            self.recipe_map.add(vram, size, spec.pipeline, spec.flags)
        return self.recipe_map.summary() if matched_rows else None

    def spec_for(self, vram: int):
        """The recipe to start from: one proven inside the same object, else the command line's."""
        ranked = self.recipe_map.candidates(vram, 1) if self.recipe_map is not None and self.recipe_map.rows else []
        if ranked and ranked[0]["same_unit"]:
            spec = split_flags(list(ranked[0]["flags"]), ranked[0]["pipeline"])
            spec.section_bases.update(self.spec.section_bases)
            spec.symbols.update(self.spec.symbols)
            return spec
        return self.spec

    def flow(self, vram: int, size: int):
        return flowmod.analyse_in_image(self.target.rom, self.target.delta, vram, size)


def twin_source(text: str, source_name: str, new_name: str, source_sites, new_sites,
                names: dict[int, str]) -> str | None:
    """Rewrite an exact function's source for a machine-code twin at another address.

    ``*_sites`` are the relocation sites of both bodies (``transplant.mask``): the twin calls and
    references whatever stands at the corresponding sites, so each symbol is renamed to the one at
    the twin's address.  Returns None when the bodies do not correspond site for site."""
    if len(source_sites) != len(new_sites) or any(a[:2] != b[:2] for a, b in zip(source_sites, new_sites)):
        return None
    moved: dict[int, int] = {}
    called: set[int] = set()
    for (_i, kind, old), (_j, _kind, new) in zip(source_sites, new_sites):
        if kind in ("jal", "hi", "lo") and old != new:
            if moved.setdefault(old, new) != new:
                return None                                  # one symbol would need two addresses
            if kind == "jal":
                called.add(old)
    renames = {source_name: new_name}
    for old, new in moved.items():
        if old in names and names[old] != source_name:
            renames[names[old]] = names.get(new) or (f"func_{new:08X}" if old in called else f"D_{new:08X}")
    def swap(found):
        word = found.group(0)
        if word in renames:
            return renames[word]
        numbered = re.fullmatch(r"(func|D|jtbl)_([0-9A-Fa-f]{8})", word)
        if numbered and int(numbered.group(2), 16) in moved:
            return f"{numbered.group(1)}_{moved[int(numbered.group(2), 16)]:08X}"
        return word
    return re.sub(r"[A-Za-z_]\w*", swap, text)


def _twin_pass(store, image: str, todo, target, runner, names, emit, starts) -> list:
    """After a sweep: every unresolved function whose masked machine code equals an exact case's
    gets that case's source, renamed symbol by symbol, built with the same recipe and recorded
    through the normal ladder (so it is strictly verified like any other exact case)."""
    from ..match import transplant
    groups: dict[str, list] = {}
    for name, vram, size in todo:
        offset = vram - target.delta
        masked, sites = transplant.mask(target.rom[offset:offset + size], vram)
        groups.setdefault(f"{transplant.signature(masked)}:{len(masked)}", []).append((name, vram, size, sites))
    won = []
    for members in groups.values():
        if len(members) < 2:
            continue
        cases = {m[1]: store.get(resolvemod.case_id(image, m[1], m[2])) for m in members}
        donors = [m for m in members if cases[m[1]] is not None and cases[m[1]].status == "exact"]
        if not donors:
            continue
        donor = donors[0]
        donor_case = cases[donor[1]]
        text = store.source(donor_case.best_digest)
        if text is None:
            continue
        pipeline, _, flags = donor_case.recipe.partition(" ")
        spec = split_flags(shlex.split(flags), pipeline) if pipeline else runner.spec
        spec.section_bases.update(runner.spec.section_bases)
        spec.symbols.update(runner.spec.symbols)
        for name, vram, size, sites in members:
            case = cases[vram]
            if vram == donor[1] or (case is not None and case.status in ("exact", "blocked-boundary")):
                continue
            candidate = twin_source(text, donor[0], name, donor[3], sites, names)
            if candidate is None:
                continue
            evaluate = runner.evaluator(vram, size, f"{name}.c", spec)
            evaluation, _code = evaluate(candidate)
            if not evaluation.exact:
                continue
            offset = vram - target.delta
            result = resolvemod.resolve(store, image, name, vram, target.rom[offset:offset + size], evaluate,
                                        source=candidate, flow=runner.flow(vram, size), neighbours=starts,
                                        budget=4, jobs=1, force=True, emit=emit, pipeline=spec.pipeline,
                                        recipe_label=runner.label(spec), rom_offset=offset,
                                        strict=runner.strict(vram, size, f"{name}.c", starts))
            if result.status == "exact":
                result.stages.insert(0, {"stage": "twin", "of": donor[0]})
                store.put(result)
                won.append(result)
                if emit:
                    emit({"event": "twin-exact", "case": result.case_id, "name": name, "of": donor[0]})
    return won


_BASIC_TYPEDEF = re.compile(r"(?m)^[ \t]*typedef\s+[^;{}]*?\b(?:s8|u8|s16|u16|s32|u32|s64|u64|f32|f64)\s*;[ \t]*\n?")


def prepare_answer(text: str) -> str:
    """A refiner's answer as a buildable unit: the kit's typedef prelude in front, and the
    answer's own redefinitions of those basic types removed (a duplicate typedef is an error
    for these compilers)."""
    if "N64DK_M2C_PRELUDE" in text:
        return text
    return autodraft.PRELUDE + "\n" + _BASIC_TYPEDEF.sub("", text)


def _refine_pass(store, image: str, todo, target, runner, names, emit, starts, settings, args) -> dict:
    """Hand the cases the mechanical ladder left unresolved to the configured refiner
    (``n64dk.match.refine``), nearest first.  An answer that beats the case's best goes through
    the normal ladder, so it is searched, strictly verified and classified like any other
    source.  A case that already holds a ``refine`` stage is not asked about again."""
    from ..match import refine as refinemod
    settings.validate()
    signature = settings.signature()
    rows = []
    wanted = {n for item in (getattr(args, "refine_names", None) or []) for n in item.split(",") if n}
    for name, vram, size in todo:
        if wanted and name not in wanted:
            continue
        case = store.get(resolvemod.case_id(image, vram, size))
        if case is None or case.status not in settings.statuses or (settings.max_size and size > settings.max_size):
            continue
        if settings.max_score and (case.best_score is None or case.best_score > settings.max_score):
            continue
        if any(stage.get("stage") == "refine" and stage.get("signature") == signature
               for stage in case.stages) and not args.force:
            continue
        rows.append((case.best_score if case.best_score is not None else 1 << 30, size, name, vram))
    rows.sort()
    if settings.max_cases:
        rows = rows[:settings.max_cases]
    totals = {"attempted": 0, "improved": 0, "exact": 0, "assumed": 0, "calls": 0, "errors": 0}
    lock = threading.Lock()

    def one(row):
        _score, size, name, vram = row
        case = store.get(resolvemod.case_id(image, vram, size))
        pipeline, _, flags = (case.recipe or "").partition(" ")
        spec = split_flags(shlex.split(flags), pipeline) if pipeline else runner.spec
        spec.section_bases.update(runner.spec.section_bases)
        spec.symbols.update(runner.spec.symbols)
        primary = runner.evaluator(vram, size, f"{name}.c", spec)
        offset = vram - target.delta
        code = target.rom[offset:offset + size]
        flow = runner.flow(vram, size)
        won: dict[str, tuple] = {}                       # answer digest -> (label, pipeline, evaluator)

        def evaluate(text: str):
            """The case's recipe first; an answer that is not exact there is also built under the
            sibling recipes, because the case's recipe is itself only the best guess so far."""
            evaluation, built = primary(text)
            if evaluation.exact or args.no_recipes:
                return evaluation, built
            from ..match import causes as causemod
            family = causemod.compiler_family(flow)
            family = family["family"] if family["confidence"] >= 0.8 else None
            others = list(runner.recipes(vram, size, f"{name}.c")(family))[:resolvemod.CROSS_RECIPES]
            if runner.label(spec) != runner.label(runner.spec):          # the configured default, if not tried yet
                others.insert(0, (runner.label(runner.spec), runner.spec.pipeline,
                                  runner.evaluator(vram, size, f"{name}.c", runner.spec)))
            for label, pipeline, other in others:
                attempt, attempt_built = other(text)
                better = attempt.score is not None and (evaluation.score is None or attempt.score < evaluation.score
                                                        or (attempt.exact and not evaluation.exact))
                if better:
                    evaluation, built = attempt, attempt_built
                    won[hashlib.sha256(text.encode()).hexdigest()] = (label, pipeline, other)
                if evaluation.exact:
                    break
            return evaluation, built

        best_source = store.source(case.best_digest) if case.best_digest else None
        best = primary(best_source)[0] if best_source else None
        tables = m2c_bridge.find_jump_tables(target.rom, target.delta, vram, size)
        assembly = m2c_bridge.emit_asm(name, code, vram, names, tables)
        declarations = ""
        if runner.rendered is not None and vram in runner.facts:
            declarations = runner.rendered.focused(runner.facts[vram], vram, True, typedefs=False)
        result = refinemod.refine(name, settings, evaluate, assembly, case.recipe or runner.label(spec), best_source,
                                  best, case.causes, prepare=prepare_answer, declarations=declarations, emit=emit)
        stage = {"stage": "refine", "signature": signature,
                 "rounds": result["rounds"], "calls": result["calls"],
                 "history": result["history"], "improved": result["improved"], "errors": result["errors"][:2]}
        if result["improved"]:
            before = case.builds
            label, pipeline, chosen = won.get(hashlib.sha256(result["best_source"].encode()).hexdigest(),
                                              (case.recipe or runner.label(spec), spec.pipeline, primary))
            case = resolvemod.resolve(store, image, name, vram, code, chosen, source=result["best_source"],
                                      flow=flow, neighbours=starts, budget=args.budget, jobs=2,
                                      force=True, emit=emit, pipeline=pipeline, recipe_label=label, rom_offset=offset,
                                      strict=runner.strict(vram, size, f"{name}.c", starts),
                                      search_ceiling=getattr(args, "search_ceiling", resolvemod.SEARCH_CEILING))
            case.builds += before
        case.stages.append(stage)
        store.put(case)
        with lock:
            totals["attempted"] += 1
            totals["improved"] += bool(result["improved"])
            totals["calls"] += result["calls"]
            totals["errors"] += len(result["errors"])
            totals["exact"] += case.status == "exact" and bool(result["improved"])
            totals["assumed"] += case.status == "assumed" and bool(result["improved"])
        if emit:
            emit({"event": "refine-case", "name": name, "status": case.status, "score": case.best_score,
                  "improved": result["improved"]})
        return case

    with ThreadPoolExecutor(max(1, settings.jobs)) as pool:
        refined = [c for c in pool.map(one, rows)]
    totals["cases"] = {c.case_id: c for c in refined}
    return totals


def worker_count(requested: int | None, functions: int, memory_per_worker_mb: int = 0,
                 memory_reserve_mb: int = 0) -> int:
    """Worker processes for a sweep.  ``0`` means automatic: one per two hardware threads (a
    worker is one interpreter plus its compiler children), but no more than free memory allows
    and never more than there are functions to share out."""
    if not hasattr(os, "fork"):
        return 1
    if requested is None or requested < 0:
        requested = 1
    if requested == 0:
        requested = max(1, (os.cpu_count() or 4) // 2)
        try:
            with open("/proc/meminfo") as handle:
                available = next(int(line.split()[1]) for line in handle if line.startswith("MemAvailable:")) // 1024
            # Scale defaults from current resources instead of encoding one workstation's peak.
            reserve = memory_reserve_mb or max(256, available // 8)
            per_worker = memory_per_worker_mb or max(256, min(1024, available // max(2, requested)))
            requested = max(1, min(requested, max(1, (available - reserve) // per_worker)))
        except (OSError, StopIteration, ValueError):
            pass
    return max(1, min(requested, functions // 2 or 1))


def _events(path: str | None):
    if not path:
        return None, None
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    handle, lock = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644), threading.Lock()

    def emit(event: dict) -> None:
        payload = (json.dumps({"time": round(time.time(), 3), **event}) + "\n").encode()
        with lock:
            os.write(handle, payload)
    return emit, handle


@command("resolve-case", "Diagnose one unmatched function and climb the resolution ladder (draft, iterate, classify)")
def resolve_case(args):
    cfg, target, syms = _prepare(args)
    catalogue_vram = args.addr
    linked_vram = getattr(args, "_comparison_addr", catalogue_vram)
    coordinate_shift = catalogue_vram - linked_vram
    names = {address: name for name, address in syms.items()}
    name = args.name or names.get(linked_vram) or f"func_{catalogue_vram:08X}"
    store = resolvemod.CaseStore(_state(args, cfg))
    emit, handle = _events(args.events)
    try:
        with tempfile.TemporaryDirectory(prefix="n64dk-resolve-") as work:
            runner = _Runner(args, cfg, target, syms, Path(work))
            if args.context == "auto":
                if not args.catalogue:
                    raise SystemExit("--context auto needs --catalogue")
                runner.auto_context([(n, v - coordinate_shift, s) for n, v, s in load_catalogue(Path(args.catalogue))],
                                    names, store.root, _image_label(args))
            offset = linked_vram - target.delta
            code = target.rom[offset:offset + args.size]
            source = Path(args.source).read_text() if args.source else None
            evaluate = runner.evaluator(linked_vram, args.size, Path(args.source).name if args.source else f"{name}.c")
            starts = ({v - coordinate_shift for _n, v, _s in load_catalogue(Path(args.catalogue))}
                      if args.catalogue else None)
            case = resolvemod.resolve(store, _image_label(args), name, linked_vram, code, evaluate, source=source,
                                      draft=None if args.no_draft else runner.drafter(name, linked_vram, args.size,
                                                                                      evaluate, names),
                                      flow=runner.flow(linked_vram, args.size), neighbours=starts,
                                      search_ceiling=getattr(args, "search_ceiling", resolvemod.SEARCH_CEILING),
                                      budget=args.budget, jobs=args.jobs or 8, force=args.force, emit=emit,
                                      pipeline=args.pipeline, recipe_label=runner.label(),
                                      rom_offset=linked_vram - target.delta,
                                      strict=runner.strict(linked_vram, args.size,
                                                           Path(args.source).name if args.source else f"{name}.c",
                                                           starts),
                                      recipes=None if args.no_recipes else runner.recipes(
                                          linked_vram, args.size, Path(args.source).name if args.source else f"{name}.c"))
        result = case.as_dict()
        result["coordinates"] = {"image": _image_label(args),
                                 "catalogue_vram": f"0x{catalogue_vram:08X}",
                                 "linked_vram": f"0x{linked_vram:08X}",
                                 "size": args.size}
        if args.out and case.best_digest:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(store.source(case.best_digest) or "")
            result["written"] = args.out
        return result
    finally:
        store.close()
        if handle is not None:
            os.close(handle)


def _case_args(p):
    _common(p, rom_required=True)
    p.add_argument("source", nargs="?", help="existing candidate C file (omit to start from an m2c draft)")
    p.add_argument("--addr", type=_int, required=True)
    p.add_argument("--size", type=_int, required=True)
    p.add_argument("--name")
    _shared(p)
    p.add_argument("--out", help="write the best candidate here")


def _shared(p):
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--context", help="m2c context file, or `auto` to recover structs, globals and prototypes "
                   "from the image (needs --catalogue)")
    p.add_argument("--context-parts", default="structs,globals,prototypes")
    p.add_argument("--proto-confidence", type=float, default=0.9)
    p.add_argument("--catalogue", help="function catalogue: neighbouring starts for boundary evidence")
    p.add_argument("--budget", type=int, default=300, help="maximum builds per function")
    p.add_argument("--search-ceiling", type=int, default=resolvemod.SEARCH_CEILING,
                   help="skip the variant search when the best draft scores above this (0: always search)")
    p.add_argument("--state", help="case store directory (default: <project>/.n64dk/resolve)")
    p.add_argument("--events", help="append JSON-lines progress events to this file")
    p.add_argument("--no-draft", action="store_true", help="never generate an m2c draft")
    p.add_argument("--draft-portfolio", action="store_true",
                   help="build several drafts (plain, with context, alternative m2c renderings) and continue "
                        "from the closest")
    p.add_argument("--draft-options", default="",
                   help="comma-separated extra m2c renderings for the portfolio, e.g. --no-andor,--gotos-only")
    p.add_argument("--no-recipes", action="store_true", help="never try alternative compiler recipes")
    p.add_argument("--force", action="store_true", help="continue past boundary/ABI findings and redo exact cases")


resolve_case.arguments = _case_args


@command("resolve-hard", "Run the resolution ladder over every function without matching source and report the queue")
def resolve_hard(args):
    catalogue_functions = load_catalogue(Path(args.catalogue))
    # Give the canonical image resolver one real interval so a composite image obtains its
    # physical offset and catalogue-to-link transformation before the batch is constructed.
    probe_addr = probe_size = None
    if catalogue_functions:
        probe_addr, probe_size = catalogue_functions[0][1], catalogue_functions[0][2]
        args.addr, args.size = probe_addr, probe_size
    cfg, target, syms = _prepare(args)
    if probe_addr is not None:
        linked_probe = getattr(args, "_comparison_addr", probe_addr - args.catalogue_shift)
        coordinate_shift = probe_addr - linked_probe
    else:
        coordinate_shift = args.catalogue_shift
    names = {address: name for name, address in syms.items()}
    functions = [(n, v - coordinate_shift, s) for n, v, s in catalogue_functions]
    trimmed = {"functions": 0, "bytes": 0}
    if not getattr(args, "keep_padding", False):
        # A catalogue interval often runs to the next function and so includes the zero words
        # that align the next object.  No C produces them, so a function measured with them
        # can never be exact: the interval that is resolved ends at the code.
        from ..analysis import boundaries as boundmod
        fitted = []
        for name, vram, size in functions:
            offset = vram - target.delta
            padding = 0
            if size >= 12 and 0 <= offset <= len(target.rom) - size:
                try:
                    terminated, padding = boundmod._terminated(flowmod.analyse_in_image(target.rom, target.delta,
                                                                                         vram, size))
                except Exception:
                    terminated, padding = False, 0
                if not terminated or padding >= size:
                    padding = 0
            if padding:
                trimmed["functions"] += 1
                trimmed["bytes"] += padding
            fitted.append((name, vram, size - padding))
        functions = fitted
    starts = {v for _n, v, _s in functions}
    covered, matched_rows = [], []
    for item in args.manifest:
        path, _, pipeline = item.partition("=")
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if not line.startswith("#") and len(parts) >= 3:
                try:
                    covered.append((int(parts[0], 0), int(parts[1], 0)))
                except ValueError:
                    continue
                if pipeline and len(parts) >= 4 and not parts[2].endswith((".s", ".S")):
                    row = split_flags(shlex.split(parts[3]), pipeline)
                    matched_rows.append((int(parts[0], 0) + target.delta, int(parts[1], 0), row))
    inside = [f for f in functions if f[2] >= args.min_size and 0 <= f[1] - target.delta <= len(target.rom) - f[2]]
    if args.holdout > 1:
        # benchmark mode: every Nth function is treated as unmatched, whatever the manifests say,
        # and its own manifest row is withheld from the recipe map
        todo = sorted(inside, key=lambda f: f[1])[::args.holdout]
        held = {f[1] for f in todo}
        matched_rows = [r for r in matched_rows if not any(r[0] <= v < r[0] + r[1] for v in held)]
    else:
        todo = [f for f in inside if not any(a <= f[1] - target.delta < a + n for a, n in covered)]
    skip = set(getattr(args, "skip_vrams", None) or ())          # e.g. recovered by an earlier stage
    todo = [f for f in todo if f[1] not in skip]
    todo.sort(key=lambda f: f[2])
    if args.max_size:
        todo = [f for f in todo if f[2] <= args.max_size]
    if args.every > 1:
        todo = todo[::args.every]
    if args.limit:
        todo = todo[:args.limit]
    store = resolvemod.CaseStore(_state(args, cfg))
    emit, handle = _events(args.events)
    image, started = _image_label(args), time.time()
    inner = 4 if (args.jobs or 8) >= 8 else 2
    try:
        with tempfile.TemporaryDirectory(prefix="n64dk-resolve-") as work:
            runner = _Runner(args, cfg, target, syms, Path(work))
            context_info = runner.auto_context(functions, names, store.root, image)
            recipe_info = runner.learn_recipes(functions, matched_rows)

            def one(function, store=store, emit=emit, inner=inner):
                name, vram, size = function
                offset = vram - target.delta
                spec = runner.spec_for(vram)
                evaluate = runner.evaluator(vram, size, f"{name}.c", spec)
                try:
                    return resolvemod.resolve(store, image, name, vram, target.rom[offset:offset + size], evaluate,
                                              draft=None if args.no_draft else runner.drafter(name, vram, size,
                                                                                              evaluate, names),
                                              flow=runner.flow(vram, size), neighbours=starts, budget=args.budget,
                                              search_ceiling=getattr(args, "search_ceiling",
                                                                     resolvemod.SEARCH_CEILING),
                                              jobs=inner, force=args.force, emit=emit, pipeline=spec.pipeline,
                                              recipe_label=runner.label(spec), rom_offset=offset,
                                              strict=runner.strict(vram, size, f"{name}.c", starts),
                                              recipes=None if args.no_recipes else runner.recipes(vram, size,
                                                                                                  f"{name}.c"))
                except Exception as error:                   # one bad function must not stop the sweep
                    if emit:
                        emit({"event": "case-error", "name": name, "error": str(error)[-300:]})
                    return None

            workers = worker_count(getattr(args, "workers", 1), len(todo),
                                   getattr(args, "worker_memory_mb", 0),
                                   getattr(args, "memory_reserve_mb", 0))
            worker_errors = 0
            if workers > 1:
                # The search generates its variants in Python, so threads share one interpreter
                # lock.  Each worker process takes every Nth function (the list is sorted by size,
                # so shards are balanced), with its own store connection, event handle and work
                # directory; cases meet in the store, which is opened in WAL mode.
                store.close()
                # threads per worker are oversubscribed: most of their time is spent waiting for a
                # compiler process or for the interpreter lock
                share = max(4, (3 * (args.jobs or 8)) // (2 * workers))
                children = []
                for index in range(workers):
                    pid = os.fork()
                    if pid == 0:
                        status = 1
                        try:
                            own_store = resolvemod.CaseStore(_state(args, cfg))
                            own_emit, _own_handle = _events(args.events)
                            runner.work = Path(work) / f"worker{index}"
                            runner.work.mkdir(parents=True, exist_ok=True)
                            own_inner = 2
                            with ThreadPoolExecutor(max(2, share // own_inner)) as pool:
                                list(pool.map(lambda f: one(f, own_store, own_emit, own_inner), todo[index::workers]))
                            own_store.close()
                            status = 0
                        finally:
                            os._exit(status)                  # never run the parent's cleanup twice
                    children.append(pid)
                try:
                    for pid in children:
                        _pid, status = os.waitpid(pid, 0)
                        worker_errors += status != 0
                except BaseException:
                    for pid in children:
                        try:
                            os.kill(pid, 15)
                        except ProcessLookupError:
                            pass
                    for pid in children:
                        try:
                            os.waitpid(pid, 0)
                        except ChildProcessError:
                            pass
                    if emit:
                        emit({"event": "workers-cancelled", "count": len(children)})
                    raise
                store = resolvemod.CaseStore(_state(args, cfg))
                if worker_errors and emit:
                    emit({"event": "worker-failed", "count": worker_errors})
                cases = [c for c in (store.get(resolvemod.case_id(image, vram, size)) for _n, vram, size in todo)
                         if c is not None]
            else:
                with ThreadPoolExecutor(max(1, (args.jobs or 8) // inner)) as pool:
                    cases = [c for c in pool.map(one, todo) if c is not None]
            twins = _twin_pass(store, image, todo, target, runner, names, emit, starts)
            if twins:
                replaced = {c.case_id for c in twins}
                cases = [c for c in cases if c.case_id not in replaced] + twins
            refine_info = None
            from ..match import refine as refinemod
            settings = getattr(args, "refine", None) or refinemod.Settings.from_table(
                None, getattr(args, "refine_command", None))
            if settings is not None:
                for key in ("rounds", "max_cases", "jobs", "max_score"):
                    value = getattr(args, f"refine_{key}", None)
                    if value is not None:
                        setattr(settings, key, value)
                refine_info = _refine_pass(store, image, todo, target, runner, names, emit, starts, settings, args)
                refined = refine_info.pop("cases")
                cases = [c for c in cases if c.case_id not in refined] + list(refined.values())
        elapsed = time.time() - started
        queue = resolvemod.hard_queue(cases)
        exact = [c for c in cases if c.status == "exact"]
        return {"image": image, "functions": len(todo), "resolved_cases": len(cases), "statuses": queue["statuses"],
                "exact": [{"name": c.name, "size": c.size, "source": c.best_digest, "recipe": c.recipe,
                           "strict": (c.strict or {}).get("verdict")} for c in exact],
                "strict": {v: sum(1 for c in exact if (c.strict or {}).get("verdict") == v)
                           for v in sorted({(c.strict or {}).get("verdict") for c in exact}, key=str)},
                "exact_bytes": sum(c.size for c in exact), "builds": sum(c.builds for c in cases),
                "seconds": round(elapsed, 1),
                "exact_per_hour": round(len(exact) * 3600 / elapsed, 1) if elapsed else None,
                "context": context_info, "recipes": recipe_info, "twins": len(twins),
                "workers": workers, "worker_errors": worker_errors, "refine": refine_info,
                "padding_trimmed": trimmed,
                "queue": [{k: g[k] for k in ("cause", "meaning", "functions", "bytes", "expected_progress")}
                          | {"best": g["best"][:args.show]} for g in queue["queue"]],
                "state": str(store.root)}
    finally:
        store.close()
        if handle is not None:
            os.close(handle)


def _hard_args(p):
    _common(p, rom_required=True)
    p.add_argument("--catalogue", required=True)
    p.add_argument("--catalogue-shift", type=_int, default=0)
    p.add_argument("--manifest", action="append", default=[], metavar="FILE[=PIPELINE]",
                   help="manifest of already matched code (repeatable); with =PIPELINE its rows also teach the "
                        "per-unit recipe map")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-size", type=_int, default=0)
    p.add_argument("--min-size", type=_int, default=4)
    p.add_argument("--every", type=int, default=1, help="take every Nth function (sampling for benchmarks)")
    p.add_argument("--keep-padding", action="store_true",
                   help="resolve catalogue intervals as given, including trailing alignment padding")
    p.add_argument("--refine-command",
                   help="external author for the cases the ladder leaves unresolved: a command that reads "
                        "a prompt on stdin and prints C (see n64dk.match.refine); every answer is built and "
                        "strictly verified")
    p.add_argument("--refine-rounds", type=int, help="rounds of feedback per function (default 3)")
    p.add_argument("--refine-names", action="append", default=[],
                   help="ask only about these functions (comma separated, repeatable)")
    p.add_argument("--refine-max-cases", type=int, help="ask about at most this many cases, nearest first")
    p.add_argument("--refine-max-score", type=int, help="ask only about cases at most this far from the target")
    p.add_argument("--refine-jobs", type=int, help="refiner calls in parallel (default 4)")
    p.add_argument("--workers", type=int, default=1,
                   help="worker processes sharing the sweep (0: automatic, from hardware threads and free "
                        "memory); --jobs is divided among them")
    p.add_argument("--worker-memory-mb", type=int, default=0,
                   help="automatic-worker memory estimate (0: derive from currently available memory)")
    p.add_argument("--memory-reserve-mb", type=int, default=0,
                   help="memory held outside workers (0: one eighth of currently available memory)")
    p.add_argument("--holdout", type=int, default=0,
                   help="benchmark: treat every Nth catalogued function as unmatched even when a manifest "
                        "covers it, withholding its own row from the recipe map")
    p.add_argument("--show", type=int, default=3)
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--context", help="m2c context file, or `auto`")
    p.add_argument("--context-parts", default="structs,globals,prototypes")
    p.add_argument("--proto-confidence", type=float, default=0.9)
    p.add_argument("--budget", type=int, default=200)
    p.add_argument("--search-ceiling", type=int, default=resolvemod.SEARCH_CEILING,
                   help="skip the variant search when the best draft scores above this (0: always search)")
    p.add_argument("--state")
    p.add_argument("--events")
    p.add_argument("--no-draft", action="store_true")
    p.add_argument("--no-recipes", action="store_true")
    p.add_argument("--draft-portfolio", action="store_true",
                   help="build several drafts (plain, with context, alternative m2c renderings) and continue "
                        "from the closest")
    p.add_argument("--draft-options", default="",
                   help="comma-separated extra m2c renderings for the portfolio, e.g. --no-andor,--gotos-only")
    p.add_argument("--force", action="store_true")


resolve_hard.arguments = _hard_args


@command("hard-queue", "Group stored resolution cases by cause and rank them by expected progress")
def hard_queue(args):
    store = resolvemod.CaseStore(Path(args.state))
    try:
        cases = store.all()
        if args.image_name:
            cases = [c for c in cases if c.image == args.image_name]
        report = resolvemod.hard_queue(cases)
        for group in report["queue"]:
            group["best"] = group["best"][:args.show]
        return report
    finally:
        store.close()


def _queue_args(p):
    p.add_argument("--state", required=True, help="case store directory")
    p.add_argument("--image-name")
    p.add_argument("--show", type=int, default=5)


hard_queue.arguments = _queue_args


@command("resolve-export", "Write exact resolution cases as an integration queue (sources, manifest rows, assumptions)")
def resolve_export(args):
    store = resolvemod.CaseStore(Path(args.state))
    try:
        return resolvemod.export_queue(store, Path(args.out), args.image_name, not args.strict_only)
    finally:
        store.close()


def _export_args(p):
    p.add_argument("--state", required=True, help="case store directory")
    p.add_argument("--out", required=True, help="output directory (never inside a project source tree)")
    p.add_argument("--image-name")
    p.add_argument("--strict-only", action="store_true", help="leave out cases that still rest on assumptions")


resolve_export.arguments = _export_args
