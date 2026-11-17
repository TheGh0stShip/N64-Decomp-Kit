# Functions over the size threshold: a region-based method

Status: design with a measurement gate. Nothing here runs in `decompile-run` yet.

## What was measured

- Dr. Mario 64 has 75 functions over 0x400 bytes. Attempting all of them with the existing
  whole-function search took 964 builds and gave 0 exact (round 10, `bench/w6`).
- The whole-function search scores a candidate by one number: the difference over the whole
  function. For a 2 KB function, the small mismatches a good draft still has (a register swap in
  one loop, one reordered branch) are lost among the shifts they cause downstream. A mutation that
  fixes one region usually moves another, so the score gives no gradient.
- No further broad compile sweep over whole-function variants is planned (review item 8).

## The method

The function is split into **regions**: single-entry, single-exit groups of basic blocks in the
target, from the control-flow graph the kit already builds (`analysis/flow.py`). Typical regions
are loop bodies, the arms of an if/else, a switch case, or a straight stretch between two calls.

1. **Anchor the regions in the candidate.** Each region is bounded by evidence that survives
   register allocation and scheduling: call targets, references to distinct globals and
   constants, and branch structure. A candidate's object is split at the same anchors, so target
   region *k* is compared with candidate region *k*. Without a one-to-one anchor match the
   function stays whole-function (no region method).
2. **Score per region.** The existing relocation-aware, register-renaming-aware comparison runs
   on each region pair. The result is a vector of region scores, plus the region boundaries'
   agreement.
3. **Map statements to regions.** The candidate is compiled once more with line information that
   does not change code generation: GCC `-g` (KMC, SN, EGCS), IDO `-g3` together with the
   optimisation level. A probe in the recipe catalogue must first prove, per recipe, that the
   object's code is identical with and without the flag; recipes that fail the probe get no
   mapping. The line table then maps each C statement to the instructions it produced, hence to
   regions.
4. **Search per region.** The existing transformation families run only on the statements
   that map to the worst region, and a candidate is kept when that region improves **without any
   other region getting worse**. Regions already equal are frozen: no mutation touches their
   statements. This turns one high-dimensional search into a few small ones, and each build's
   result is attributable.
5. **Credit is unchanged.** Region equality is progress, never credit. A function is credited
   only when the whole object is strictly exact under the normal verifier. A function whose
   regions are all equal but which is still not exact (layout, alignment, literal pool order)
   goes to the hard queue with that cause.

## Gate before building the search

Steps 1–3 need no new search and are cheap. They are built and measured first:

- Over the 75 Dr. Mario 64 functions and the large functions of one IDO title, measure (a) the
  share that anchor one-to-one, and (b) for those, how the residual of the best existing draft is
  distributed over regions.
- **Go** if at least 30% of large functions anchor and, of those, at least half have their whole
  residual in one or two regions covering under a quarter of the function. Otherwise the result
  is recorded as a negative and step 4 is not built.
- If go, step 4 runs with a per-function build budget equal to the median spent on exact
  mid-size functions. It stops after three rounds without a region improving.

## Interfaces

- `analysis/flow.regions(cfg) -> [Region(start, end, entry, exits, anchors)]`
- `match/regions.compare(target, candidate_object, regions) -> RegionScores`
- `match/regions.statement_map(source, recipe) -> {line: [instruction offsets]} | None`
- Case store: region scores are a stage record (`{"stage": "regions", "scores": [...]}`), so
  status, dossiers and the solver's cause table ("large far-off" → region decomposition) read them.

## Risks

- Scheduling across region boundaries (the delay slot of a branch, a load hoisted into the
  previous block) blurs anchors. The anchors carry a tolerance of one instruction on each side,
  and boundary instructions are compared in both neighbouring regions.
- Line tables of 1990s compilers are imprecise for inlined or merged code. A statement mapping
  to several regions is mutable only when every region it maps to is unfrozen.
- If the debug-information probe changes code for a recipe, that recipe has no statement map and
  step 4 is unavailable to it. This is reported, not worked around.
