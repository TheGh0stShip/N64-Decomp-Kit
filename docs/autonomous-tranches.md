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

The SQLite state in `.n64dk/quickwin-sweeps` records the inventory digest, ranking, worker
allocation, per-function state, and session ID. Items with a candidate source are `ready`;
the rest are `needs-source`, so a missing semantic reconstruction is not disguised as a
compiler failure. Resume with `--resume TRANCHE_ID`. A changed inventory requires a new
tranche, preserving the denominator and ranking used by the earlier report.

To launch independent baseline sessions, provide one loaded image per selected inventory
image:

```bash
n64dk --format json quickwin-sweep --project . --all-images --limit 500 --jobs 16 \
  --resume TRANCHE_ID --run \
  --image-file overlay1=.tmp/overlay1_with_resident_rodata.z64 \
  --pipeline kmc+as --flags '-O2 -G0 -mips2 -Wa,-r4300_mul -Iinclude'
```

Each ready function receives its own content-addressed transactional session under the sweep
state root. Workers are distributed across functions, exact baselines stop only their own
item, and near matches remain active with their session IDs. Re-running the tranche does not
relaunch active or exact items.

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

## Current boundary

Splat metadata ingestion covers standard scalar options and list-form subsegments without a
new YAML dependency. Function boundaries still require a catalogue TOML. Corpus-scale source
AST indexing and source proposal generation are separate producers; the tranche scheduler
accepts their candidate files and retained sessions but does not invent semantic source.
