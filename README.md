# N64 Decomp Kit

`n64dk` is a game-agnostic command-line and Python toolkit for analysing Nintendo 64 ROMs,
recovering program structure and assets, identifying SDK code, and reproducing functions with
historical N64 toolchains.

Everything is derived from a retail ROM image plus optional project inputs (symbol lists,
manifests, sources); nothing is hard-coded to one game.

* **Boot and program image**: header, CIC and checksum; the entry routine (stack, BSS, hand-over);
  an R4300 boot emulator that follows loaders (PI DMA, decompression) and maps the program's
  RAM image back to its ROM sources.
* **Code**: function boundaries, jump tables and boundary audits; libultra/libaudio
  identification by masked signatures; compiler and microcode fingerprints.
* **Data**: cross-references, `.data`/`.rodata` split and ownership, typed data units.
* **Assets**: audio (libaudio banks, sequences, MIDI, libmus, VADPCM to WAV), graphics (F3D,
  F3DEX, F3DEX2, S2DEX display lists, textures to PNG, blob pools), compression (Yay0, Yaz0,
  MIO0, LZARI, deflate, with encoders) and loader tracing.
* **Matching**: build a C source with the original toolchain (KMC GCC, IDO 5.3/7.1, SN GCC),
  compare it relocated against the ROM with classified diffs, sweep pipelines and flags,
  re-verify whole manifests, diagnose the residual mechanism, explain GCC 2.7.x allocator
  dumps, enforce provenance, and use permutation only for the appropriate residual stage.
* **Autonomous tranches**: build interval-correct progress inventories, rank complete remaining
  functions, collect one-call context bundles, and distribute persistent matching sessions
  across functions while stopping exact winners independently.
* **Survey**: one command that runs everything and classifies every ROM byte in one interval
  ledger.

## Install

Python 3.11 or newer. The only required dependency is `rabbitizer`.

```bash
git clone https://github.com/TheGh0stShip/N64-Decomp-Kit.git
cd N64-Decomp-Kit
python3 -m venv .venv
.venv/bin/pip install -e .
```

ROM images are never part of the repository. Pass a path on the command line; tests and
fixtures find ROMs through `roms.toml` (ignored by git) or the `N64DK_ROMS` environment
variable (see [Tests](#tests)).

## Quick start

```bash
n64dk info baserom.z64
```

```bash
n64dk survey baserom.z64 --out out/survey
```

`survey` writes `report.md` (a summary with ranked next steps, then every analysis),
`report.json`, `ledger.tsv` (every ROM byte with a class, category and evidence),
`functions.toml`, `symbol_addrs.txt` and `main_segment.bin` (the program as loaded in RAM,
unpacked when the game packs it). Games whose boot loader unpacks the program with an
unknown codec are emulated, and the game's own routine is used as the codec. Add
`--require-complete` to fail while any byte is still `unknown`.

Every command accepts `--format json` before the command name for machine-readable output:

```bash
n64dk --format json sdk baserom.z64
```

For a persistent source-matching campaign, configure a project adapter and run:

```bash
n64dk --format json match-job-run path/to/PROJECT.toml \
  --unit UNIT --state-root .n64dk/match-jobs --budget 500 --verify
```

The job builds candidates in temporary workspaces, records failures and lineage, compares
all adapter-owned sections, and never edits project source. See
[Autonomous matching jobs](docs/autonomous-matching.md) for adapter requirements, resume,
export, and proof boundaries.

## Commands

| Command | What it does |
|---|---|
| `info ROM` | Header, CIC, checksum, main segment, stack, BSS, hand-over, staged boot |
| `disasm ROM VRAM SIZE` | Disassemble a range of the main segment |
| `survey ROM --out DIR [--image auto\|static\|emulated] [--require-complete]` | Everything below over the program image; report and ROM ledger |
| `boot-emu ROM [--max-steps N] [--after N]` | Emulate the entry code; DMAs, handoffs, thread dispatches, RAM segments with ROM sources |
| `functions ROM [--out DIR] [--truth FILE] [--audit FILE]` | Function catalogue, jump tables, `-O0`/hand-written detection; precision and recall against a reference |
| `datamap ROM [--matched TSV] [--symbols FILE] [--emit-units DIR] [--ledger TSV]` | Data cross-references, section split, ownership, initialized-data ledger, typed data units |
| `sdk ROM [--truth FILE]` | Name SDK library functions; SDK version, microcode, audio library, compiler verdict |
| `sdk-build-db RECIPE.toml [--out PATH]` | Rebuild the signature database from library sources and matched objects |
| `audio ROM [--out DIR] [--wav] [--midi]` | Audio inventory with byte-exact intervals; WAV and sequence export |
| `gfx ROM [--range A:B] [--ucode F] [--mode blobs\|scan\|walk] [--decompress] [--png --out DIR]` | Find and walk display lists; vertices, textures, PNG export |
| `assets-scan ROM [--out DIR] [--extract] [--verify]` | Compressed streams (with round-trip checks) and loader-referenced ROM ranges |
| `match SRC --rom ROM [--addr VRAM] [--sweep]` | Build one source and compare it relocated against the ROM; sweep pipelines and flags |
| `match-batch MANIFEST... --project DIR` | Rebuild and verify every unit of matching manifests in parallel |
| `match-permute SRC --rom ROM --addr VRAM` | Permutation search scored by the relocated diff |
| `match-session-start SRC --rom ROM ...` | Start a persistent standalone source-matching session |
| `match-session-try SESSION_ID` | Apply in-memory edits and compile a batch of source/flag variants |
| `match-session-status SESSION_ID` | Show the best result and nondominated residual frontier |
| `match-session-export SESSION_ID OUTPUT` | Export a retained candidate only when explicitly requested |
| `match-inventory --project DIR` | Reconcile catalogues and manifest intervals, including aggregate translation units |
| `context-bundle --project DIR --image IMAGE --function NAME` | Collect target code, callers, callees, globals and access patterns |
| `quickwin-sweep --project DIR --all-images --limit N --jobs N` | Create/resume a persistent ranked cross-function tranche |
| `quickwin-sweep-status ID [--status active]` | Filter tranche rows and inspect current versus historical best results |
| `match-session-explore ID --rounds N --jobs N` | Run bounded residual-guided source experiments over the frontier |
| `match-session-explain ID --from A --to B` | Explain residual and source changes between two candidates |
| `investigate FUNCTION --image IMAGE --all` | Build one verified dossier from layout, code, source, recipes, history and corpus evidence |
| `image-map-explain --project DIR --image NAME --function NAME` | Explain raw/composite/catalogue/linked mappings, byte digests, transforms and ownership collisions |
| `corpus-index PROJECT...` | Incrementally index local N64 assembly by exact and normalized signatures |
| `corpus-query --image IMAGE --addr A --size N --vram-delta D` | Find exact, relocation-only, register-renamed and opcode-shape analogues |
| `corpus-prototype SYMBOL` | Infer prototypes from indexed declarations, call arguments, return use and width evidence |
| `result-index --roots PATH...` / `result-query` | Mine historical JSON, logs, sessions and candidates while invalidating stale targets |
| `reproduce RESULT_ID` | Independently replay a digest-pinned source, toolchain, target and environment bundle |
| `residual-clusters --max-score N` | Group typed, address-independent residuals across related functions |
| `script-index PROJECT...` / `script-query` | Inventory scattered sweeps, audits, transforms, scorers and build wrappers |
| `operation-schema` / `automation-serve` | Expose typed operations over newline-delimited JSON for local controllers |
| `doctor --profile matching` | Validate ROM, host tools, original toolchains, paths, storage and optional research capabilities |
| `compiler-capabilities` | Inspect or selectively invalidate per-toolchain, stage and option capability evidence |
| `prototype-matrix` / `register-lifetime-explore` / `match-matrix` | Run bounded ABI, call-use, narrowing, value-lifetime and declarative experiment families |
| `control-flow-explore` / `clone-family-transfer` | Classify branch targets, test loop-exit forms and transfer sibling CFGs |
| `family-session-start` / `tu-session-start` | Preserve cross-function and real translation-unit experiment context |
| `frontier-synthesize` / `compiler-explain` / `residual-attribution` | Synthesize complementary candidates and explain one candidate or a causal pairwise compiler/residual difference |
| `code-query` / `asm-query` / `negatives-query` | Search source, manifests, historical failures and structural assembly without shell pipelines |
| `boundary-audit` / `boundary-correct` | Audit CFG/Splat/ownership evidence and prepare denominator-safe corrections |
| `integrate-winner` / `integration-audit` / `gate-delta` | Verify exact winners twice and prepare reviewable integration/gate transactions |
| `project-gate` | Run project-defined gates with compact image and failure summaries |
| `scheduler-plan` / `scheduler-status` | Persist separate discovery, exploitation, recovery, boundary, family and verification lanes |
| `workbench-snapshot` / `self-test` | Produce one-call function context and run canonical test discovery |
| `match-session-prepare-winner SESSION_ID DIR` | Independently recompile an exact winner and prepare an auditable export queue |
| `match-job-run PROJECT.toml --unit UNIT` | Create or resume a bounded, persistent candidate/compile/diagnose search job |
| `match-job-status JOB_ID` | Inspect job state, best result, failures and candidate lineage |
| `match-job-export JOB_ID OUTPUT` | Export a candidate and non-proof-grade evidence without editing project source |
| `match-diagnose COMPILED TARGET` | Rank boundary/toolchain/semantic/type/regalloc/reload/scheduling causes |
| `gcc27-regalloc FILE.lreg [--global-dump FILE.greg]` | Explain GCC 2.7.x pseudo priorities, ties and hard-register assignments |
| `toolchain-fingerprint --profile P --file ROLE=PATH...` | Content-hash the real compiler/assembler/linker identity |
| `provenance-audit SOURCE...` | Reject assembly escapes, unproven assembly and non-proof-grade credit |
| `research-audit SOURCES.tsv FINDINGS.tsv` | Reject unindexed, search-only or low-quality evidence before automation |

Run `n64dk COMMAND --help` for every option.

## Library use

```python
from n64dk import image, survey
from n64dk.analysis import functions
from n64dk.rom import Rom

rom = Rom.load("baserom.z64")
program = image.build(rom)                  # emulates the boot only when a loader runs
catalogue = functions.discover(rom, program=program)
report = survey.run(rom)["report"]
```

## Documentation

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): module map and conventions
* [docs/workbench.md](docs/workbench.md): ownership, bounded exploration, search, integration and scheduling
* [docs/boot.md](docs/boot.md): entry-routine analysis and boot emulation
* [docs/survey.md](docs/survey.md): program image, survey and ROM ledger
* [docs/functions.md](docs/functions.md), [docs/datamap.md](docs/datamap.md),
  [docs/sdk.md](docs/sdk.md): code and data analysis
* [docs/audio.md](docs/audio.md), [docs/graphics.md](docs/graphics.md),
  [docs/compression.md](docs/compression.md): assets
* [docs/matching.md](docs/matching.md): toolchains, pipelines and matching
* [docs/autonomous-matching.md](docs/autonomous-matching.md): persistent matching jobs,
  usage, evidence, verification boundary and limitations
* [docs/autonomous-tranches.md](docs/autonomous-tranches.md): interval inventories, context
  bundles, cross-function scheduling, compact session output and exact-winner preparation
* [docs/tooling-research.md](docs/tooling-research.md): upstream workflow concepts and the
  first-class operations that replace repeated searches, extraction and comparison calls
* [docs/AUTOMATION_HANDOFF.md](docs/AUTOMATION_HANDOFF.md): operating and reporting
  instructions for automated matching workers
* [docs/BRIEF.md](docs/BRIEF.md): rules for adding an analysis module

Each document ends with measured results on the fixture ROMs and known limitations.

## Matching toolchains

The original compilers are not included. `match` looks them up from `--toolchain-dir`,
`[toolchains]` in `n64dk.toml`, the `N64DK_TOOLCHAIN` environment variable,
`<project>/.toolchain` or `./.toolchain`; see [docs/matching.md](docs/matching.md) for the
expected layout. SN GCC additionally needs `wibo`.

Original compiler binaries, SDK files, and ROM images are not distributed by this project.
Users must provide legally obtained copies. Generated job state and local toolchain paths are
ignored by Git.

## Project adapters

Persistent campaigns use a title-specific adapter so the core never hard-codes a game's
layout or build system. A `PROJECT.toml` selects a Python factory:

```toml
[project]
adapter = "project_adapter:create"
python_path = "."
```

The factory implements `n64dk.project.ProjectAdapter`: unit discovery, immutable input and
toolchain files, owned target spans, workspace preparation, the authentic build command, and
built-span extraction. Candidate source must be staged at its project-relative path inside
the temporary workspace. See [Autonomous matching jobs](docs/autonomous-matching.md) for the
complete execution contract.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

Evidence-driven matching commands include `match-diagnose`, `gcc27-regalloc`,
`toolchain-fingerprint`, `provenance-audit`, `research-audit`,
`workbench-diagnose`, `transform-list`, and `transform-apply`.  Transformations
are applied only to a separate candidate file from a digest-pinned JSON proposal;
the command also writes a mechanical inverse proposal.

Tests that need a ROM skip when it is not configured. To enable them, create `roms.toml` in
the repository root (it is ignored by git):

```toml
[roms]
battletanx = "/path/to/battletanx.z64"
mk64 = "/path/to/mk64.z64"

[truth]                     # optional ground truth from decompilation projects
battletanx = {path = "/path/to/battletanx-project", rev = "2e6bc1c"}   # pinned to a commit
battletanx_ga = "/path/to/global-assault-project"                     # live working tree
```

A pinned entry (`rev`) makes the tests read the project's tracked files as of that commit:
`n64dk.fixtures` extracts them once with `git archive` into `build/truth/` and links the
project's git-ignored files (toolchains, generated headers, base ROMs) to the live ones, so
uncommitted edits in the project cannot break the tests. The project itself is only read.
Without `rev`, the live working tree is used. `N64DK_TRUTH_<NAME>` and
`N64DK_TRUTH_<NAME>_REV` override the file.

The known fixture images and their SHA-1 hashes are listed in `n64dk/fixtures.py`; a ROM whose
hash does not match is rejected. `N64DK_ROMS=name=path:name=path` works as well. Set
`N64DK_SLOW=1` to include the longest emulation test.

## Licence

GPL-3.0-or-later (see [COPYING](COPYING)). Parts are adapted from the BattleTanx and
BattleTanx: Global Assault decompilation projects (GPL-3.0); the modules concerned say so in
their docstrings.
