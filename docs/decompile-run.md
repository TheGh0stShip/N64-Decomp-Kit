# `decompile-run`: one unattended pass over a title

`decompile-run` takes a project that declares its images and runs every automatic stage the kit
has, in order, with a checkpoint after each. It writes only below `--out`; the project tree is
read, never changed. Nothing in it is specific to a game, a compiler or an address layout.

Madden 64 users can copy the reviewed raw-overlay declarations from
[`madden-images.example.toml`](madden-images.example.toml). Overlay 1 and Overlay 4 require
catalogue-to-link shifts; an unattended run should not guess a delta from their composite images.
The proof and acceptance details for this release are in
[`round5-integration.md`](round5-integration.md).

```sh
n64dk --format json decompile-run --project . --all-images --out out/run \
    --donors donors.toml --max-size 0x400 --budget 100 --jobs 8
```

## Configuration

```toml
[images.main]                       # one table per image; overlays get their own
path = "baserom.z64"                # `composite`, `raw` and `rom` are accepted as synonyms
catalogue = "config/functions.toml" # TOML, or TSV/CSV with a header row (name, vram, size)
manifests = ["config/matching_*.tsv"]   # optional: units already matched (skipped by the run)
# vram_delta = 0x7FFFF400           # for a linear image (overlay, unpacked program)
# catalogue_shift = 0x4724          # catalogue address minus link address, when they differ

[run]
pipeline = "ido5.3"                 # or kmc+as, kmc+asn64, ido7.1, sn, custom:<name>
flags = "-O2 -mips2 -non_shared -G 0"
symbols = ["symbol_addrs.txt"]

[run.images.main]                   # per-image overrides of [run], and per-unit recipes:
recipes = { "config/matching_ido7_units.tsv" = "ido7.1" }   # the pipeline each manifest's rows used

[pipelines.gcc281]                  # a compiler the kit has no built-in lane for
family = "gcc"                      # "gcc" or "ido": decompiler target and diagnosis rules
steps = ["{cc1} -quiet {flags} {source} -o {stem}.s", "{as} -EB -mips3 {stem}.s -o {object}"]
[pipelines.gcc281.vars]
cc1 = "/opt/gcc-2.8.1/cc1"
as = "mips-linux-gnu-as"
```

A function inside a unit named by a `recipes` manifest is built with that unit's pipeline and
flags; its neighbours in the same translation unit (16-byte alignment and padding decide where a
unit ends) inherit them. The lane declared under `[pipelines.gcc281]` is named `custom:gcc281` wherever a
pipeline name is accepted.

`docs/toolchains.md` lists which compiler each surveyed project uses and where its build
recipe differs from the built-in lanes.

## Stages

| stage | what it does | output |
|---|---|---|
| boundaries | reconciles catalogue starts with call targets, prologues, padding and fragment chains; proposes reversible operations only | `<image>/boundary_operations.json` |
| donors | looks every function up, relocation-masked, in the donor index; a hit is rebuilt from the donor's source with this title's symbols and compared | `<image>/donors/`, `stage_donors.json` |
| resolve | for each remaining function: declarations recovered from the machine code, a portfolio of drafts (plain, with callee/own prototypes, loop-normal, type-narrowed), compile repair, recipe selection, one search over all transformation families, twin reuse | `state/` (case store) |
| queue | exports what is finished | `queue/queue.tsv`, `queue/<image>/*.c` |
| ledger | one owner class per byte, with violations | `<image>/ownership.tsv` |

**Parallelism.** `--jobs` is the total number of parallel builds (default: every hardware
thread). The search generates its variants in Python, so the resolve stage splits the functions
among worker processes (`--workers`, default automatic: one per two hardware threads, fewer when
free memory is short; a worker peaks at about 450 MB). Cases meet in the case store. `resolve-hard`
takes the same `--workers` option (default 1).

**Where the search is not tried.** The variant search runs only when the best draft is within
`--search-ceiling` of the target (default 40, `[run] search_ceiling`, 0 to always search). Over
1,712 searches on an IDO title and a KMC GCC title, none that started above 40 reached an exact
match; they took 37% of the builds. Such a function needs a better draft, not more variants, and
its case says so.

The run can be interrupted and restarted: finished stages are read from their checkpoint
(`--redo` recomputes them) and finished cases from the case store. `--skip-stage NAME` omits a
stage; `--limit N` and `--max-size` bound a trial run.

## What "finished" means

A case is `exact` only when the engine's strict verifier accepts it: owned text and data equal,
every relocation resolved through an independently declared symbol. Those are in `queue.tsv`.

A case that is byte-identical but refers to an address nobody declared is `assumed`. It is listed
in `queue/assumed.tsv`; `queue/symbols.assumed.txt` holds the declarations that would settle
them, one `NAME = 0xADDRESS;` per symbol with the functions that use it. Declaring a symbol is a
decision about the project, so the run does not make it: review the file, append it to the
project's symbol file, and run again. Those cases are then verified strictly like any other.

Everything else is in the case store with a status (`near`, `open`, `does-not-build`,
`needs-tu`, `blocked-boundary`, `probable-handwritten`, `needs-source`) and a ranked cause;
`hard-queue --state <out>/state` prints them grouped by cause for whoever works on them next.

`report.md` and `report.json` summarise the run; `events.jsonl` is the stream of what happened.
