# n64dk durable goal

**Mission.** Any N64 title can be run through `n64dk` and driven, unattended, toward a state where
every byte of every image is one of: exact ordinary C built by a historical compiler pipeline,
positively evidenced hand-written assembly, reconstructed data or asset, padding, a fragment
represented by its real owner, or a precisely diagnosed unresolved case with its exhausted
hypotheses on record. "Unknown" is temporary.

**The metric.** Independently verified exact bytes per wall-clock hour. Not candidates built, not
similarity, not compiler utilisation.

**Invariants (never traded for progress).**
1. Credit requires ordinary C, an unmodified historical toolchain and equality of every owned byte
   under `verify.strict_compare` (no address taken from the retail bytes being compared).
2. No copied bytes, raw instruction directives, inline or register assembly, function-specific
   output rewriting, weakened comparison or invalid boundaries.
3. Nothing in core is specific to one game: no names, addresses, directory or manifest conventions.
   A change is validated on at least two titles built with different compiler families.
4. Project trees are read-only to analysis; all generated state lives under one state directory.
5. Every claim in a report carries its numerator, denominator and provenance.

**Architecture (bottom up).**
| Layer | Modules | Integrated status |
|---|---|---|
| Facts from bytes | `analysis/flow.py` (CFG, liveness, frame, NOP roles, shapes), `analysis/values.py` (value tracking), `analysis/abi.py` (prototype evidence), `analysis/structures.py` (cross-function layout constraints), `analysis/fragments.py` | integrated; ABI/layout results are evidence, never truth |
| Proof | `match/verify.py` (strict oracle), `manifest-verify`, durable verification receipts, `match/reconcile.py` | integrated; only strict current-target receipts grant C coverage |
| Diagnosis | `match/causes.py` (stable taxonomy, typed residuals, compiler family), `match/hints.py` | integrated |
| Search | `match/iterate.py` + `match/families.py` (types, lifetime, volatile, globals, pointer, control), recipe stage | integrated with semantic-review flags and full-object ranking |
| Cases | `match/resolve.py` (durable cases, strict escalation ladder, hard queue), tranche JSONL events | integrated |
| Ownership | `match/ownership.py`, `ownership-ledger`, `progress-reconcile`, reversible `boundary-correct` transactions | integrated; corrections never count as decompilation gain |
| Context | `structure-context`, `tu-session-start`/`try`, `tu-reconstruct`, project gate policy | integrated as conservative, reviewable workflows |
| Coordinates | canonical raw/composite resolver, logical images, `image-map-explain`, `address-explain` | integrated; ambiguous mappings fail closed and linked/catalogue VRAM remain distinct |

These layers do not mean every hard function is automatically solvable. Translation-unit
reconstruction remains an evidence-guided experiment rather than a historical-source oracle, and
ABI/structure inference deliberately reports alternatives and conflicts. The durable case ledger
records those limits instead of silently presenting guesses as recovered source.

**How progress on the kit itself is measured.**
- *False-positive rate on finished projects*: every analysis that can block work (boundary, ABI,
  hand-written) is run on completed projects, where every function is known good.
- *From-scratch recovery rate*: `resolve-hard` on a sample of a finished project, treating its
  functions as unmatched; report exact count, builds and exact-per-hour, per compiler family.
- *Mutation recovery*: perturb one type/lifetime/qualifier in exact C and require `iterate` to
  recover it.
- *Strict share*: fraction of manifest units that are `exact` (not `assumed`) under
  `manifest-verify`.

**Order of work.** See `ROUND4_REPORT.md` section 6 (next steps) and the wishlist coverage table.
