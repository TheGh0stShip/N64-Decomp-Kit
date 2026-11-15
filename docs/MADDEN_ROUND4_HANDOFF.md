# Madden operator handoff: strict resolver release

This is the concise operating note for an automated Madden worker after the Round 4 integration.

## What changed

- Treat `exact` as actionable only when `proof.verdict == "exact"`. Exploration scores and
  inferred relocation matches are not proof.
- Inventory coverage now comes from current strict verification receipts. A manifest row without
  such a receipt is `claimed`, not matched C.
- Composite mappings are canonical and image-aware. Overlay 1 and Overlay 4 catalogue addresses
  are translated to linked addresses automatically; do not manually subtract `0x4724` or
  `0x18A0` in source or scripts.
- Tranche limits count runnable targets only. Excluded fragments, ambiguous mappings, missing
  source and unknown recipes have separate counters.
- The durable resolver combines boundary/CFG evidence, m2c drafts, compiler recipe selection,
  typed cause diagnosis, bounded iteration and strict final proof.
- Cross-function layout/prototype evidence and real persistent TU sessions are available when a
  function-local search stagnates.
- Candidate-authored `LDSYM` addresses can make a draft link but cannot prove a winner.

## Recommended commands

First verify the environment and current ownership truth:

```sh
n64dk --format json doctor --project . --profile matching
n64dk --format json match-inventory --project . --summary-only --assert-consistent
n64dk --format json ownership-ledger --project . --summary-only
n64dk --format json progress-reconcile --project .
```

Explain a shifted or suspicious target before compiling it:

```sh
n64dk --format json image-map-explain \
  --project . --image overlay4 --function func_800E0B58
n64dk --format json address-explain \
  --project . --image-name overlay4 --addr 0x800E0B58
```

Run a durable all-image tranche with ready-only accounting, drafts, and strict hard-case
escalation (supply each project's actual image paths):

```sh
n64dk --format json tranche-run --project . --all-images \
  --image-file resident=build/us/audit/resident_composite.z64 \
  --image-file overlay2=build/us/audit/overlay_2_composite.z64 \
  --image-file overlay5=build/us/audit/overlay_5_composite.z64 \
  --limit 500 --jobs 16 --preflight --infer-recipes --run-ready \
  --explore-top 25 --resolve-hard-top 50 --resolve-budget 128 \
  --prepare-exact --checkpoint-every 1
```

Use the configured real paths and omit unavailable images rather than inventing them. Follow the
JSONL path returned as `events`; status is committed per function.

For one hard function:

```sh
n64dk --format json investigate FUNCTION --project . \
  --image build/us/audit/overlay_N_composite.z64 --image-name overlayN --all
n64dk --format json resolve-case CANDIDATE.c --project . \
  --rom build/us/audit/overlay_N_composite.z64 --image-name overlayN \
  --addr CATALOGUE_VRAM --size SIZE --pipeline kmc+builtin \
  --flags '-O2 -G0 -mips3 -mgp32 -mfp32' --budget 300 \
  --events .n64dk/resolve/FUNCTION.jsonl
```

When the cause is `tu.context`, create a real TU session instead of continuing local spelling
permutations:

```sh
n64dk --format json tu-session-start --project . --unit SRC \
  --rom IMAGE --image-name IMAGE_NAME --addr CATALOGUE_VRAM --size SIZE
n64dk --format json tu-session-try TU_SESSION_ID --project . --proposal EDITS.json
```

Before credit or integration:

```sh
n64dk --format json manifest-verify MANIFEST --project . \
  --rom IMAGE --image-name IMAGE_NAME --catalogue CATALOGUE
n64dk --format json exact-reconcile --project . --bind MANIFEST=IMAGE_NAME
n64dk --format json integrate-winner CANDIDATE_ID --project . --verify-twice
```

`integrate-winner` remains transactional: it verifies mapping/collisions, recompiles twice, stages
the canonical catalogue filename, simulates the manifest row, and requires the configured gate
policy before applying. Never integrate an `assumed`, stale, duplicate-location, or
mapping-ambiguous result.

## Known limits

- Prototype and structure output is ranked evidence, not a declaration oracle.
- `compare_object` can still show exploratory exactness using retail-derived addresses; only the
  strict verdict matters.
- TU reconstruction tests historically plausible context but cannot recover missing original
  headers/macros by itself.
- Boundary proposals are deliberately non-applying. Review the forward/reverse transaction and
  denominator accounting before changing catalogues.
