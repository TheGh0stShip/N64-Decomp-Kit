# n64dk architecture

Game-agnostic tooling for N64 decompilation. Everything works from a retail ROM image
plus optional project inputs (symbol lists, catalogues, sources); nothing is hard-coded
to one game. Regression fixtures are BattleTanx (NBXE), BattleTanx: Global Assault (NBQE)
and Mario Kart 64 (NKTE), located through `n64dk.fixtures` (roms.toml / N64DK_ROMS).

## Layers
| Module | Responsibility |
|---|---|
| `n64dk.rom` | byte order, header, IPL3/CIC, checksum |
| `n64dk.boot` | main-segment mapping (ROM 0x1000 -> header entry), stack, BSS bounds, hand-over, staged loaders |
| `n64dk.emu` | boot emulation: PI DMA, loader output, BSS -> RAM segment map with ROM sources |
| `n64dk.image` | program image: main segment (IPL3 copy, or a loader's DMA'd/unpacked output) and BSS, fed to the analyses |
| `n64dk.gamecodec` | a game's own decompressor, found from its loader and run through the emulator on other data |
| `n64dk.survey` | every analysis over the program image, one ROM interval ledger, report.md/json |
| `n64dk.mips` | rabbitizer decode, `scan_refs` (%hi/%lo pairing, calls), code heuristics |
| `n64dk.elf` | ELF32-BE sections/symbols/relocations; `Elf.relocate()` |
| `n64dk.ledger` | non-overlapping interval ledger, hole filling, totals, TSV |
| `n64dk.analysis.functions` | function boundaries, jump tables, code-segment extent |
| `n64dk.analysis.datamap` | xrefs, rodata/data ownership, strings, initialized-data ledger, typed data units |
| `n64dk.sdk` | libultra signature DB and matcher, microcode / audio library / compiler fingerprints |
| `n64dk.assets.compress` | Yay0/Yaz0/MIO0/LZARI/deflate codecs, stream scanner |
| `n64dk.assets.loaders` | PI/ROM address tracing, (start,end) tables, DMA call sites -> asset candidates |
| `n64dk.assets.gbi` | F3D/F3DEX/F3DEX2/S2DEX command decode, display-list walker |
| `n64dk.assets.texture` | N64 texture formats, PNG export, texture detection |
| `n64dk.assets.audio` | ALBankFile/ALSeqFile, ADPCM decode, MIDI, libmus detection |
| `n64dk.match` | toolchain profiles, build pipelines, relocated compare, flag/pipeline sweeps |
| `n64dk.project` | stable title-adapter protocol and image/section ownership spans |
| `n64dk.match.fingerprint` | compiler/build-closure content identities |
| `n64dk.match.cache` | local immutable content-addressed artifacts (never committed) |
| `n64dk.match.residual` | interpretable mechanism-first residual diagnoses |
| `n64dk.match.gcc27dump` | diagnostic-only GCC 2.7.x allocator dump explainer |
| `n64dk.match.experiments` | append-only causal experiment ledger |
| `n64dk.match.jobs` | persistent candidate lineage, bounded generation, beam search, resume and export |
| `n64dk.match.session` | transactional standalone edits, batched flag/source trials and residual frontier |
| `n64dk.match.layout` | authoritative catalogue-section mapping and code/boundary preflight |
| `n64dk.match.registry` | project-wide session resolution and historical target frontier |
| `n64dk.match.source_index` | incremental content-addressed candidate-source discovery |
| `n64dk.match.explore` | bounded residual-guided multi-round experiment loop and explanations |
| `n64dk.match.corpus` | incremental cross-project instruction and normalized-shape index |
| `n64dk.match.investigate` | verified function dossier, recipe evidence and candidate selection |
| `n64dk.match.results` | content-addressed historical observations, target validity and residual families |
| `n64dk.operations` | project-script discovery, typed operation schema and shell-free invocation gateway |
| `n64dk.match.provenance` | genuine-C and positive handwritten-assembly credit policy |
| `n64dk.research` | source/finding quality audit before research is automated |
| `n64dk.commands.*` | CLI subcommands (one module per area), registered with `@command` |

The operations layer classifies project-local Python tools without executing them and exposes
the kit through a provider-neutral newline-delimited JSON protocol. External schedulers call
the same validated commands as interactive users instead of constructing shell fragments or
parsing terminal prose.

The workbench command layer composes these primitives rather than introducing a second build
oracle. Doctor, matrices, family/TU sessions, source and assembly search, boundary correction,
winner integration and scheduling all retain content identities and emit non-applying
transactions. Exactness remains defined only by a fresh comparison against current target
bytes under an authoritative mapping.

## Conventions
* Pure functions over `bytes` + addresses; I/O only in commands. Every analysis returns
  dataclasses or lists of `Interval`s so results compose into one ledger.
* Addresses: `rom` = ROM offset, `vram` = virtual address. Use `BootInfo.rom_to_vram`.
* Analyses of the main code segment (`analysis.functions.discover`, `analysis.datamap.analyse`,
  `sdk.analyse`) take an optional `program=` (`n64dk.image.ProgramImage`); without it they
  use the IPL3 copy. For a packed main segment their offsets are into the unpacked segment.
* Big-endian everywhere; explicit `struct` formats; no host-endianness assumptions.
* Each command supports `--format json` (return a dict/list) for automation.
* Madden or any other title is an adapter and fixture, never a source of constants in core.
* Production proof uses the unmodified original toolchain and exact owned sections. Compiler
  traces and forced decisions are diagnostic only; function-specific output normalizers are
  not proof-grade.
* ROMs, compiler binaries, absolute private paths, credentials, remote-worker identities and
  local content caches stay outside Git.
* Tests: `python -m unittest discover -s tests -t .`; ROM-dependent tests skip when the
  fixture is not configured. Ground truth from the BattleTanx and Global Assault projects
  may be read at test time from paths given in roms.toml `[truth]` but never copied in.
* Licence GPL-3.0-or-later. Code adapted from the BattleTanx or Global Assault projects
  (both GPL-3.0) must say so in its module docstring.
