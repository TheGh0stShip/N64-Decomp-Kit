# Interval-aware autonomous tranches

The tranche workflow moves matching from repeated file edits toward a durable inventory of
independent experiments. Its unit of accounting is a VRAM interval, never a symbol name.
This matters when one C translation unit owns several catalogue functions, and when an
assembly row is only a shared tail, offset entry, call shim, or epilogue.

## Inventory and ranking

```bash
n64dk --format json match-inventory --project . --remaining \
  --output .n64dk/inventory.json
```

`match-inventory` reads `config/**/functions_*.toml`, all corresponding matching manifests,
and Splat configuration metadata. Manifest ROM intervals are mapped through catalogue
sections and tested for complete containment. The report separates `covered`, `remaining`,
and `excluded`, records the owning unit, and explains every decision. Aggregate translation
units cover every fully contained function. Shared tails, fragments, shims, data-like entries,
and intervals too short to contain a complete return are excluded from the denominator.

Remaining complete functions receive a stable ID and a reproducible quick-win rank. Rankings
prefer small complete functions and candidate sources already present in `.tmp`; rank is
only scheduling priority and never matching evidence.

## One-call context

```bash
n64dk --format json context-bundle --project . \
  --image .tmp/overlay1_with_resident_rodata.z64 --image-name overlay1 \
  --function func_800BD998 --vram-delta 0x8008F004 \
  --output .n64dk/context/func_800BD998.json
```

The bundle contains target disassembly, callers, callees, resolved global references, access
widths, repeated base/offset clusters, neighbouring catalogue functions, and the inventory
decision. For a catalogue-native image, omit `--vram-delta` and the catalogue ROM offset is
used directly.

## Persistent cross-function sweep

Create a tranche without compiling:

```bash
n64dk --format json quickwin-sweep --project . --all-images \
  --limit 500 --jobs 16 --report .n64dk/tranche.md
```

The SQLite state in `.n64dk/quickwin-sweeps` records the inventory digest, ranking, worker,
phase, heartbeat, recipe, timing, per-function state, and session ID. Planning uses the
ordered truth boundary `ownership → boundary → mapping → recipe → source identity`. Its
states include `ready_verified`, `boundary_rejected`, `already_owned`, `source_wrong_function`,
`recipe_unknown`, `source_missing`, and `mapping_ambiguous`. Resume with `--resume TRANCHE_ID`.
A changed inventory requires a new
tranche, preserving the denominator and ranking used by the earlier report.

One immutable `ProjectContext` is created per tranche. It parses configuration, symbols,
catalogues, manifests, mappings and recipes once; memory-maps each selected image and hashes
it once; and shares read-only evidence among workers. Recursive discovery excludes state,
scratch, compiler-output and repository-control trees. Historical stores are refreshed once,
not once per function. Compiled objects are content-addressed by source, compiler, flags,
include closure, definitions and section context; absolute/section-sensitive inputs remain
part of the key.

Candidate discovery uses `.n64dk/source-index.sqlite`. `--refresh-sources` performs an
incremental path/mtime/size scan and hashes only changed candidate files. Build, extraction,
bundle, archive, campaign, cache, and repository-control directories are ignored. Once a
tranche exists, `--run-ready-only --resume ID` reads stored source and section mappings and
does no inventory or source scan.

To launch independent baseline sessions, provide one loaded image per selected inventory
image:

```bash
n64dk --format json quickwin-sweep --project . --all-images --limit 500 --jobs 16 \
  --resume TRANCHE_ID --run \
  --image-file overlay1=.tmp/overlay1_with_resident_rodata.z64 \
  --image-file overlay2=.tmp/overlay2_with_resident_rodata.z64
```

Each ready function receives its own content-addressed transactional session under the sweep
project's standard session store. Workers are distributed across functions, exact baselines stop only their own
item, and near matches remain active with their session IDs. Re-running the tranche does not
relaunch active or exact items. Compiler recipes are selected per interval: the containing
verified translation unit wins, followed by a pinned SDK signature, a neighboring verified
unit, and finally an explicitly low-confidence image default. `--pipeline` and `--flags`
remain explicit overrides, not tranche-wide assumptions made by default.

Each phase transition and completed result is committed immediately. An interrupted run
resumes unfinished rows rather than repeating completed work. Status distinguishes exact,
near, rejected, missing, interrupted and stale-running rows; `matched` is never used as an
ambiguous synonym for “an observation exists.”

Before a worker is allocated, the mapping is recomputed from the containing catalogue
section. The preflight verifies the function lies inside both section intervals and the loaded
image, decodes the target, rejects data-like bytes, and verifies a return/tail or declared
fall-through boundary. Its receipt records the first and last instructions, validity ratio,
image digest, derived delta, and winning `catalogue-section` authority. A caller-supplied delta
that disagrees with the catalogue is rejected.

Compact inspection does not rerun inventory:

```bash
n64dk --format json quickwin-sweep-status TRANCHE_ID --summary-only
n64dk --format json quickwin-sweep-status TRANCHE_ID --status active --best-details
n64dk --format json quickwin-sweep-status TRANCHE_ID --needs-source --limit 50
```

Rows include the current score and residual counts, best historical session and score, and
whether the new observation improved, tied, regressed, or had no predecessor. Session IDs are
resolved through the project registry, including legacy tranche stores.

## Autonomous tranche orchestration

The ordinary multi-command loop is available as one bounded operation:

```bash
n64dk --format json tranche-run --project . --all-images --limit 500 --jobs 16 \
  --preflight --infer-recipes --run-ready --explore-top 25 --prepare-exact \
  --checkpoint-every 1 --image-file overlay2=.tmp/overlay2.z64
```

It returns independently retained exact winners, improved frontiers, rejection reasons,
boundary proposals, an exact-winner queue, remaining counts, cache reuse, and separate
context/discovery/compile/match timing. Scheduling quality is reported as verified exact
matches and frontier improvement per wall time rather than submitted candidate volume.

## Data-flow-aware exploration

Residual exploration models which call produced a value, transfers in the following call's
delay slot, values held across calls, overwritten-but-unused return registers, narrowing and
later branch/return consumers. This routes a call-barrier/register residual through result
ownership, prototypes, carrier lifetime, declaration scope and translation-unit context
before unrelated spelling families. Nested calls receive bounded staged forms rather than a
combinatorial rewrite.

Negative knowledge is keyed by compiler recipe, normalized residual mechanism and source
shape, so equivalent experiments can be skipped across sibling functions. The object cache
separately detects source forms that collapse to the same machine code.

## Source-less and translation-unit work

```bash
n64dk source-scaffold func_80001000 --project . --image overlay.bin --output candidate.c
n64dk structure-layout-infer --project . --image overlay.bin --image-name overlay2 \
  --function func_80001000 --function func_80001100
n64dk prototype-solve --project . --conflicts-only
n64dk tu-reconstruct src/overlay/unit.c --project .
```

`source-scaffold` emits ordinary, immediately compilable C plus a separate evidence receipt.
Shared-layout inference aggregates access width, signedness, read/write use and conflicting
offset hypotheses. Prototype solving reconciles declarations project-wide. TU reconstruction
preserves declaration/function ordering and defines the whole-unit function/data/relocation
comparison scope for later transactional experiments.

## Session transactions and exact winners

Start without a temporary candidate file:

```bash
printf '%s\n' '#include "types.h"' 's32 f(s32 x) { return x + 1; }' | \
  n64dk --format json match-session-start - --source-name f.c \
  --rom IMAGE --addr 80001000 --size C --summary-only
```

`match-session-try` crosses in-memory source variants with flag variants in one call. Compiler
capability evidence prevents repeated unsupported-option builds. Compact selectors expose
only the best candidate, one candidate, exact candidates, or summary counters. Typed residual
rules suggest a bounded next discriminator such as address formation, declaration lifetime,
dependency sequencing, signedness, or branch form.

An integration transaction is exact-only:

```bash
n64dk match-session-prepare-winner SESSION_ID .n64dk/winners/func_80001000
```

The command independently recompiles the retained candidate. Only another exact result emits
the source, evidence receipt, and export-queue row. It deliberately does not edit source,
manifests, catalogues, progress values, or documentation; those changes remain an auditable
project-owned review step.

## Coordinate and ownership truth

Every mapping receipt labels `loaded_image_offset`, `manifest_rom_offset`,
`physical_rom_offset`, `linked_vram`, `image_vram_delta`, `section_vram` and `section_rom`.
Ambiguous coordinate spaces fail closed. Inventory reconciliation separately reports
catalogue intervals, declared denominators, individual and aggregate C ownership, assembly,
fragments/data/padding, and truly remaining functions. SDK signatures identify pinned
library intervals before generic ranking. Boundary failures include bounded correction
proposals and never consume compile slots.

## Release coverage

The continuous tranche engine covers the complete requested workflow rather than only the
launcher. The corresponding durable mechanisms are:

| # | Capability | Implementation surface |
|---:|---|---|
| 1 | One project scan per tranche | Shared `ProjectContext` and bounded discovery |
| 2 | Per-function compiler selection | TU, SDK, neighbor and default recipe evidence |
| 3 | Preflight before tranche slots | Verified-ready queue and separate exclusion report |
| 4 | Durable progress | Per-phase commits, worker/heartbeat/timestamps and resumable states |
| 5 | Cross-call value ownership | Delay-slot-aware producer and consumer graph |
| 6 | Evidence-routed exploration | Residual mechanism routing and object-collapse advancement |
| 7 | Precise attribution | Ranked definitions, consumers, barriers and source spans |
| 8 | Call-chain decomposition | Bounded staged/ignored-return nested-call forms |
| 9 | Aggregate ownership truth | Individual, aggregate, assembly and remaining reconciliation |
| 10 | Explicit coordinates | Loaded, manifest, physical, linked and section address types |
| 11 | Post-integration refresh | Source, tranche, ownership and validity invalidation |
| 12 | Candidate identity | Symbol/template, size, calls, globals, digest and image checks |
| 13 | ROM reuse | One immutable snapshot and digest per distinct image |
| 14 | Bounded metadata concurrency | Shared history snapshot and serialized tranche writer |
| 15 | Separated timing | Discovery, context, compile/match, database and wall metrics |
| 16 | Safe object reuse | Content-addressed compiler/include/section-aware object cache |
| 17 | Boundary correction proposals | Prologue/terminator/delay-slot bounded candidates |
| 18 | Known libraries first | Pinned SDK signatures and compiler provenance |
| 19 | Cross-store frontier synthesis | Observation IDs, source recovery and current-target replay |
| 20 | Historical source recovery | Content-addressed source archive on every direct observation |
| 21 | Canonical winners | Catalogue-derived export filenames with original provenance |
| 22 | Alignment clarity | Owned/object sizes and verified trailing padding separately |
| 23 | Starter source generation | Ordinary-C `source-scaffold` plus evidence receipt |
| 24 | Shared structures | Width/signedness/read-write offset aggregation |
| 25 | Joint prototypes | Project declaration constraint and conflict solver |
| 26 | Translation units | Ordered declaration/function and whole-section comparison plan |
| 27 | Normalized corpus | Text, relocation, register, CFG, ABI and provenance dimensions |
| 28 | Shared negative knowledge | Recipe/residual/source-shape experiment signatures |
| 29 | Verified-yield metrics | Exact/frontier yield and duplicate/cache waste accounting |
| 30 | Autonomous operation | `tranche-run` orchestration and exact-winner queue |
| 31 | Unambiguous status | Exact, near, observation, rejected and missing counters |
| 32 | Functional doctor | Import, shared-library, SQLite, mapping and compile smoke probes |
