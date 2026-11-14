# SDK identification (`n64dk.sdk`)

One call names the SDK library functions in a ROM's main code segment and reports the
libultra build, RSP microcode, audio library and compiler:

    n64dk sdk ROM [--db PATH] [--min-confidence 0.5] [--range START:END [--vram ADDR]]
                  [--exclude-source TAG] [--truth SYMBOLS.toml] [--functions-compiler]
    n64dk --format json sdk ROM ...

    n64dk sdk-build-db RECIPE.toml [--out PATH] [--scratch build/sdk] [--jobs N]

## Modules

| Module | Role |
|---|---|
| `sdk.signature` | per-function signatures from ELF objects / `ar` archives (uses `n64dk.elf`) |
| `sdk.build` | compiles ultralib and project library sources from a recipe, collects signatures |
| `sdk.db` | the database (`n64dk/sdk/data/signatures.json.gz`) |
| `sdk.matcher` | ROM scan, ambiguity resolution, call-target inference, version ranking |
| `sdk.fingerprint` | microcode strings and RSP text, ALBankFile/ALSeqFile/libmus, compiler idioms |
| `sdk.validate` | precision/recall against a recomp-style symbol TOML |

## Signatures

Each function symbol in `.text` becomes one signature. The function size comes from the
symbol table, or from the next symbol when it is unset (IDO), with alignment padding
removed. The following fields are kept:

* `exact`: a hash of the instruction words with every relocated field masked
  (`R_MIPS_26` jump targets, `HI16`/`LO16`/`GPREL16` immediates, whole `R_MIPS_32` words).
* `canon`: a hash under a *canonical* mask that can also be applied to an unrelocated ROM
  image: `j`/`jal` targets, `lui` immediates, and the immediates of `addiu`/`ori` and
  loads/stores that do not use `$sp` as the base. A canonical-only match is reported as a
  `variant`, for example when a struct offset or constant differs between SDK revisions.
* `key`: a hash of the first four canonical words. It is the scan index.
* `prefix`: a hash of the first four raw words.
* The mask positions, the callee names at `jal` relocations, and the source tags
  (`ultralib:2.0L:libultra_rom`, `battletanx`, …) together with the compiler class.

The database stores only hashes, sizes, mask positions and names. It contains no instruction
bytes and no ROM data. A compiler-idiom model (feature counts per compiler) is stored with it.

## Matching

The scan covers the IPL3-loaded main segment by default, and `--range` selects another
region. At every word offset the canonical key is looked up. Each candidate is then
verified with its own relocation mask (`exact`) or the canonical mask (`variant`).
Confidence depends on the size (≥12 words 0.99, 8–11 words 0.85, 5–7 words 0.7, smaller
ones 0.5/0.3). Variants are scaled by 0.75. A small function whose name matches at several
places is halved. Overlapping hits are resolved by confidence and then by length.

Some functions differ only in relocated fields, for example `__osPiGetAccess` and
`__osSiGetAccess`, or `__ll_rem` and `__ull_rem`. These are resolved by call evidence:
unambiguous callers vote for the names of their `jal` targets. If no vote applies, the
first name is reported with the others in `alternatives`, and the confidence is divided by
the number of names. Targets of confident callers that no signature matched are named by
those callers' recorded callees (`kind: call`).

The SDK version is ranked over the ultralib builds. A build's score is its *support*
(matched hashes it contains) minus its *contradictions* (matched names that it builds
differently). Builds with identical contents are merged, so 2.0D–2.0H appear as one
group. Every build within 5% of the best score is reported as a candidate.

## Fingerprints

* **Microcode**: `RSP Gfx ucode …` / `RSP SW Version …` strings, parsed into family
  (F3DEX, F3DEX2, F3DLX, S2DEX, L3DEX, F3D, Turbo3D …), version and variant
  (fifo/xbus/dram/NoN). RSP text ranges are regions that use only RSP-legal opcodes and
  contain at least 15% vector operations (COP2/LWC2/SWC2), which VR4300 code never uses.
  Each microcode string is paired with the nearest RSP text range.
* **Audio**: `ALBankFile` (`B1`, with bank count, offsets and plausible bank headers),
  `ALSeqFile` (`S1`, with sorted offset/length table), and the libmus markers
  `N64 PtrTablesV2`, `N64 WaveTables` and `N64 SoundTables`.
* **Compiler**: 16 binary idiom features per function. These are the `move` encoding
  (`or` for IDO, `addu`/`daddu` for GCC), branch-likely use, `lui $at`, other `$at`
  use, where `$ra` is saved in the frame (top slot for IDO, lower slot for GCC), `sd`
  saves, `jr $ra` delay slot filled with the `$sp` restore or left as a `nop`,
  `teq`/`break 7` divide checks, a float compare followed by a `nop`, leaf functions,
  and argument home stores. A naive-Bayes model is trained on the compiled library C
  (IDO 5.3 libultra and KMC GCC 2.7.2 libgultra). It classifies every non-library
  function found as a call target. The overall verdict is the majority among
  functions with posterior ≥ 0.8.

## Building the database

`n64dk sdk-build-db RECIPE` compiles every input in parallel into `--scratch`, which is
ignored by git. The recipe format is documented in `n64dk/sdk/build.py`, and a
typical recipe looks like this:

```toml
[toolchains]
ido = "/path/ido5.3"
kmc = "/path/kmc-gcc-2.7.2"
sn = "/path/sn-gcc-2.8"            # optional

[ultralib]
path = "/path/ultralib"
versions = ["D", "E", "F", "G", "H", "I", "J", "K", "L"]
targets = ["libultra_rom", "libultra", "libgultra_rom", "libgultra"]

[[sources]]                         # matched library units listed in a project manifest
tag = "battletanx"
root = "/path/BattleTanx"
manifest = "config/us/matching_units.tsv"
pipeline = "ido"
include = ["src/libultra", "src/libgcc"]
cflags = "-Iinclude"

[[sources]]                         # or a glob compiled with one flag set
tag = "battletanx_ga"
root = "/path/VitaTanxGA"
glob = ["src/libmus/*.c", "src/n_audio/*.c", "src/libgcc/*.c"]
pipeline = "kmc"
cflags = "-O2 -G0 -mips3 -mgp32 -mfp32 -Iinclude -Isrc/code/include -Isrc/libmus -Isrc/n_audio"

[[objects]]                         # optional prebuilt relocatable objects / archives
tag = "vendor"
path = "/path/libgultra_rom.a"
```

The ultralib flag table mirrors ultralib's `makefiles/ido.mk` and `gcc.mk`, including the
per-directory optimisation levels, `-mips3 -32` for `ll*`/`exceptasm`, the GBI defines
and the mgu/gu split by version. When `base/<V>/<target>.txt` is present, it limits each
build to the objects that are actually in that archive.

The bundled database was built from:

* ultralib 2.0D–2.0L × `libultra_rom`, `libultra`, `libgultra_rom`, `libgultra`, with
  16,483 units compiled. Upstream ultralib supports only 2.0I–2.0L, so the 2.0D–2.0H
  builds are the same sources compiled with that era's flags. They are approximations
  and come out identical to each other.
* the BattleTanx matched `src/libultra` and `src/libgcc` units, through IDO, KMC and SN
  pipelines using the flags in the project's manifests;
* the Global Assault `src/libmus`, `src/n_audio` and `src/libgcc` sources (KMC GCC).

In total it holds 1,819 signatures for 811 names. Only names from symbol tables are kept;
placeholder names (`func_XXXXXXXX`) are dropped. A full rebuild takes about 4 minutes on
the reference machine.

## Measured results

Ground truth is each project's `config/us/recomp_function_boundaries.toml`. Truth names
are normalised by dropping address suffixes (`__osSiGetAccess_8010FBB0`) and leading
underscores (`_bcopy` = `bcopy`). *Precision* is computed over matches whose address has
an SDK name in the truth. *Recall* is computed over truth functions whose name is in the
database. "Held out" excludes signatures that occur only in the game's own sources, which
gives the result for an unseen game.

| ROM | DB | named | precision | recall (all) | recall (conf ≥ 0.8) |
|---|---|---|---|---|---|
| BattleTanx | full | 258 | 1.000 (250/250) | 0.839 (250/298) | 0.789 |
| BattleTanx | held out | 241 | 1.000 (233/233) | 0.795 (233/293) | 0.730 |
| Global Assault | full | 282 | 1.000 (270/270) | 0.816 (270/331) | 0.761 |
| Global Assault | held out | 208 | 1.000 (207/207) | 0.825 (207/251) | 0.785 |

Matches at addresses without an SDK name in the truth: BattleTanx has 8, which are
correct names the project left as placeholders or did not list (`alHeapInit` at
`func_801121A0`, `__osException`, `send_mesg`, `__ll_mod`, …). Global Assault has 1 when
held out.

The other reports:

* BattleTanx: game code `kmc` (82%), library `ido` (214 of 214 single-compiler
  matches). Version candidates are 2.0D–H and 2.0I `libultra_rom`; J, K and L are
  contradicted by about 95 functions. The microcode is `F3DEX 1.21` at ROM 0xD5550, and
  two `ALBankFile`s are found.
* Global Assault: game code `kmc` (88%), library `ido`, version group 2.0D–H/2.0I
  `libultra_rom` (Global Assault is built against 2.0I). The microcode is
  `F3DEX fifo 2.07` at 0xB5FF8, and libmus `N64 PtrTablesV2` / `N64 WaveTables` are
  present.
* Mario Kart 64: 151 named (138 with confidence ≥ 0.8). The library is IDO and the game
  code is `ido` (98%). Version candidates are 2.0D–H/2.0I (`libultra_rom` and
  `libultra`), and every J+ build is contradicted. The microcode is `F3DEX 0.95` and
  `F3DLX 0.95`. No ALBankFile is found, because MK64 uses its own sound format. MK64
  has no address-level symbol truth in the reference data, so precision is not measured.

The tests (`tests/test_sdk.py`) check the following:

* the canonical mask and archive reading;
* exact, variant and mismatch matching, and caller-vote disambiguation;
* the fingerprint detectors and the bundled database;
* on the fixtures: zero wrong names against the truth, held-out recall of at least 0.75,
  the compiler verdicts, microcode and libmus.

## Limitations

* Only the main segment is scanned by default. Overlays need `--range`/`--vram`.
* Recall is limited in the following cases:
  * functions shorter than 2 words are not matched;
  * a function that differs in non-relocated, non-canonical fields is missed (`$sp`
    frame layout, register allocation from a different compiler revision or flags);
  * libaudio statics such as `_getRate`, `read8` and `__handleMIDIMsg` were compiled
    differently in the games than in ultralib.
* ultralib cannot distinguish 2.0D–2.0H, and its pre-2.0I builds are approximations.
  The version answer is therefore a range such as "2.0I or earlier".
* The SN class has only 3 training functions (the BattleTanx libgcc units), so the
  compiler verdict effectively chooses between IDO and GCC.
* RSP text detection is a heuristic. Some vector-op-dense data in compressed regions
  is reported too, so pairing a string with the nearest text range is approximate.
* `ALBankFile` detection requires uncompressed `B1` headers with plausible bank records.

## Packaging

`pyproject.toml` ships `n64dk/sdk/data/*.json.gz` as package data, so the bundled database
is installed with the package.
