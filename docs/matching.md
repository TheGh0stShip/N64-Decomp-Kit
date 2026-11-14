# Matching engine (`n64dk.match`)

Removes the manual compile -> normalize -> assemble -> relocate -> diff -> tweak loop. One call
builds a source with an original toolchain, relocates the object at its retail address and
compares it against the ROM; `--sweep` searches toolchain pipelines and flags for the first
exact configuration and prints a ready manifest row; `match-batch` re-verifies whole manifests
in parallel; `match-permute` runs a random source-permutation search scored by the same diff.

## Modules

| Module | Responsibility |
|---|---|
| `toolchain.py` | profiles (KMC GCC 2.7.2, IDO 5.3, IDO 7.1, SN GCC 2.8, modern MIPS binutils), `n64dk.toml` loading |
| `pipeline.py` | build pipelines and manifest pseudo flags |
| `asn64.py` | ASN64-compatible GCC assembly converter for modern GNU as |
| `normalize.py` | built-in KMC normalizer and external normalizer hooks |
| `symbols.py` | splat `symbol_addrs.txt`, catalogue TOML, `LDSYM` markers, `__asm__` aliases, `func_`/`D_` inference |
| `compare.py` | relocation, ROM-derived section bases/symbols, constant-pool and code location, section compare |
| `diff.py` | aligned instruction diff with mismatch classes and a score |
| `manifest.py` | manifest parsing (source rows and unit rows), section maps |
| `engine.py` | single match, batch, sweep, manifest row |
| `permuter.py` | AST permutation search (optional, needs `pycparser`) |

## Toolchains and configuration

Toolchain directories are looked up in this order: `--toolchain-dir`, `[toolchains]` in
`n64dk.toml`, `N64DK_TOOLCHAIN`, `<project>/.toolchain`, `./.toolchain`. The default layout
inside a root is `kmc-gcc-2.7.2/`, `ido5.3/`, `ido7.1/`, `sn-gcc-2.8/` and `mips-binutils/`
(`usr/bin/mips-linux-gnu-as`; a `mips-linux-gnu-as` on `PATH` also works). Binaries are only
executed, never copied.

```toml
# n64dk.toml (paths relative to this file)
[toolchains]
root = ".toolchain"
[match]
include = ["include", "src/code/include"]
symbols = ["config/us/symbol_addrs.txt"]
normalizer = "python3 tools/normalize_asm.py {input} {output}"
rom = "baseroms/us/baserom.z64"
```

| Profile | Standard flags |
|---|---|
| KMC GCC 2.7.2 | `-O2 -G0 -mips3 -mgp32 -mfp32` |
| IDO 5.3 / 7.1 | `-O2 -mips2 -non_shared -G 0` |
| SN GCC 2.8 | `-O2 -G0 -mcpu=vr4300 -mips3 -mhard-float -meb` |

## Pipelines

| Name | Steps |
|---|---|
| `kmc+hook` | GCC `-S` -> project normalizer hook -> KMC `as -mips3 -G0` |
| `kmc+builtin` | GCC `-S` -> built-in normalizer (assembler reordering off, delay-slot `nop`s) -> KMC `as` |
| `kmc+as` | GCC `-S` -> KMC `as` with its own reordering |
| `kmc+asn64` | GCC `-S` -> ASN64 converter -> modern GNU as `-march=vr4300 -mabi=32 -EB -G0 --no-pad-sections -mips3` |
| `ido5.3`, `ido7.1` | `cc -c` (run in a private directory: IDO's `uld` pass writes `<stem>.u` into the working directory) |
| `sn` | host `cpp` -> `cc1n64.exe` -> `asn64.exe` -> `psyq-obj-parser` through `wibo` |
| `as` | assembly source -> KMC `as` |

Assemblers always run at `-G0`; small-data placement is the compiler's `-G`. Manifest pseudo
flags: `--assembler=asn64`, `--section-base=SEC:ADDR`, `--symbol=NAME:ADDR`,
`--normalizer-X` (passed to the hook as `--X`). The ASN64 converter and the built-in
normalizer are adapted from the BattleTanx / Global Assault projects (GPL-3.0); the converter
derives from RocketRet/modern-asn64 (Unlicense) and keeps its output-affecting quirks.

## Relocated comparison

1. Bases: `.text` = the given address; other sections from `--section-base`, else from a
   named symbol the section defines (`complete_bases`), else **voted from the ROM**: each
   compiled HI16/LO16 pair is read back from the retail words at the same offsets, giving the
   address the retail code used (covers jump-table loads that register tracking loses).
2. External symbols: symbol files, source markers, `func_XXXXXXXX`/`D_XXXXXX` names, symbols
   defined by other units of the same batch (second pass), and optionally ROM votes (single
   `match` by default; `match-batch --infer-externals`). Recovered names are reported.
3. `.rodata` placement without a ROM-voted base: the emitted constant pool is searched in the
   ROM (relocated words masked) and candidates are tried nearest first.
4. `.text` must equal the ROM for `--size` bytes with zero padding after; `.rodata`/`.data`
   with a known base are compared whole (trailing alignment padding tolerated, or limited by a
   section map).
5. Without `--addr`, the compiled `.text` is located in the ROM: the longest unrelocated run
   is searched and relocated words must agree on their untouched bits (opcode/registers).

Relocation uses `Elf.relocate`, except for objects whose HI16 relocations of different
symbols interleave (scheduled IDO code), which are relocated with per-symbol HI16/LO16
pairing in table order (see requested core change).

## Diff classes

`register`, `operand-order`, `immediate`, `branch` (target only), `hazard-nop`,
`scheduling` (instruction present nearby on the other side), `instruction`, `size`. A
consistent register bijection is reported as `register_swap`. Score = weighted count
(0 = identical); the permuter and sweep ranking use it.

## Sweep

`pipelines x -O2/-O1/-O3 x -g x -mips3/-mips2 x -G0/-G8` (IDO: `-g3`, `-mips3 -32`, `-G 0/8`),
pipeline-major in preference order, evaluated `--jobs` at a time; stops at the first exact
configuration. Non-axis flags from `--flags` (defines, `-nostdinc`, `-I`) are kept. The
result includes a BattleTanx-style manifest row with ROM-derived section bases and symbols.

## CLI

```
n64dk match SRC --rom ROM [--addr VRAM] [--size N] [--symbols FILE] [--pipeline P] [--flags F] [--sweep]
n64dk match-batch MANIFEST[=PIPELINE]... --project DIR [--normalizer CMD] [-I DIR] [--rodata-map TSV]
                  [--status-flags STATUS=FLAGS] [--source-template T] [--infer-externals] [--jobs N]
n64dk match-permute SRC --rom ROM --addr VRAM [--function NAME] [--iterations N] [--jobs N] [--out DIR]
```

All accept `--format json`. Manifests: source rows `ROM_START SIZE SOURCE FLAGS [SHA256]`
(pipeline from the header comment: IDO / SN / KMC) or unit rows `UNIT VRAM SIZE [STATUS]`
(source `src/code/{unit}.c` etc., flags from the profile or `--flags`).

Examples (run in the project directory):

```
n64dk match src/code/effects/break_object_into_debris.c --rom baseroms/us/baserom.z64 \
    --addr 800A0930 --size 1A4 --symbols config/us/recomp_function_boundaries.toml --sweep
n64dk match-batch config/us/matching_kmc_units.tsv config/us/matching_units.tsv \
    config/us/matching_asm_units.tsv config/us/matching_sn_units.tsv --project . \
    --normalizer "python3 tools/normalize_kmc_gcc_asm.py"
n64dk match-batch config/us/clean_normalized_units.tsv=kmc config/us/asn64_units.tsv=kmc+asn64 \
    config/us/normalizer_assisted_units.tsv=kmc --project . -I src/code/include \
    --normalizer "python3 tools/normalize_kmc_gcc_asm.py" --rodata-map config/us/unit_rodata.tsv \
    --symbols config/us/symbol_addrs.txt --status-flags matched-mcpu-r8000=-mcpu=r8000 \
    --status-flags compiler-normalizer-assisted-no-cse-skip-blocks=-fno-cse-skip-blocks --infer-externals
```

## Measured results (8 jobs)

| Fixture | Input | Result |
|---|---|---|
| BattleTanx | all four source manifests (KMC, IDO, asm, SN) | **1320/1320 exact**, every SHA-256 equal to the manifest: KMC+hook 1046/1046, KMC+asn64 99/99, IDO 5.3 155/155, asm 17/17, SN 3/3; 313216 code bytes, 153956 section bytes; 2 min 41 s |
| BattleTanx | KMC rows, built-in normalizer instead of the project hook | 828/1039 (79.7 %); raw KMC `as`: 228/1039 |
| BattleTanx | sweep `break_object_into_debris.c` @ 0x800A0930 | `kmc+asn64 -O2 -G0 -mips3 -mgp32 -mfp32` after 32 builds (1.4 s); row byte-identical to the project manifest |
| BattleTanx | sweep `audio_state_helpers.c` (jump table) | exact; `.rodata` 0x80073110 recovered from the ROM = manifest value |
| Global Assault | clean-normalized 299 + asn64 17 + normalizer-assisted 68 units | **384/384 exact** (text + owned `.rodata`); 380/384 without `--infer-externals` -- the 4 call `Steps_*` defined by a unit outside these manifests |
| Mario Kart 64 | 112 non-`GLOBAL_ASM` libultra C files (`src/os`), IDO 5.3, project flags, **no addresses** | 98 located, **98/98 exact**; 14 not located (data-only units or code absent from this image) |
| Mario Kart 64 | sweep `guRotateF.c` without address | `ido5.3 -O3 -mips2 -G 0` (project uses `-O3`); deterministic over repeated runs |
| BattleTanx | permuter on a one-site operand swap of `break_object_into_debris.c` | score 19 -> 0 in 8 candidates |

The project tools re-verify the same manifests with identical pass criteria (relocated
`.text` equal to the ROM and to the manifest SHA-256); their tools were not run here because
they write into the project tree.

## Limitations

* Normalizer behaviour specific to a project (BattleTanx/Global Assault keep ~6700 lines of
  evidence-gated rules) stays in that project and is used through the hook; the built-in
  normalizer is a general baseline.
* SN GCC 2.8 needs `wibo` and the Windows tools; verified only on the 3 BattleTanx libgcc units.
* ROM-voted symbols/bases make a structurally identical build verify against itself; batch
  mode therefore leaves external inference off unless asked.
* The statically recompiled IDO binaries occasionally crash under parallel load; crashed
  passes are retried (up to 4 times).
* Data-only manifests (`matching_data_units.tsv`) are not parsed; their sections are still
  compared when the owning code unit carries `--section-base`.
* The permuter uses a small, semantics-preserving mutation set (commute, flip comparison,
  swap declarations, swap independent assignments, invert if/else); `pycparser` is optional.

## Relocation pairing

Scheduled IDO code interleaves HI16s of different symbols (BattleTanx `os_vi_manager.c`:
`lui $t3` was off by one when HI16s were paired purely by offset), so
`n64dk.elf.Elf.relocate` pairs each HI16 with the next LO16 *of the same symbol* in
relocation-table order, as the MIPS ABI specifies; `compare.relocate` uses it for every
object.
