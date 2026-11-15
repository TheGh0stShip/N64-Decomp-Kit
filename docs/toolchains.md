# Toolchains and configured pipelines

Built-in pipelines: `kmc+builtin`, `kmc+as`, `kmc+asn64`, `kmc+hook` (KMC GCC 2.7.2), `ido5.3`,
`ido7.1`, `sn` (SN GCC under wibo), `as`.  Any other toolchain is declared in the project's
`n64dk.toml` and used as `custom:<name>` wherever a pipeline name is accepted
(`n64dk/match/custom_pipeline.py`):

```toml
[pipelines.egcs]
family = "gcc"                    # "gcc" or "ido": decompiler target and diagnosis rules
default_flags = ["-O2"]
timeout = 120
steps = [
  "{root}/gcc -B{root}/ -c -fno-PIC -mno-abicalls -mcpu=4300 -G 0 -nostdinc {flags} {includes} -o {object} {source}",
  "{binutils}/mips-linux-gnu-objcopy -N {source_name} {object}",
]
[pipelines.egcs.vars]
root = "/opt/n64-toolchains/egcs"
binutils = "/opt/n64-toolchains/egcs"
```

Placeholders: `{source}`, `{source_name}`, `{stem}`, `{object}`, `{workdir}`, `{flags}`,
`{includes}`, `{project}` and every key of `vars`.  Each step runs in a private build directory
under a timeout; the last step must leave `{object}` behind.  Post-compile steps that upstream
projects need (file-symbol stripping with `objcopy -N`, setting the o32 ABI bit on `-mips3 -32`
IDO objects, 64-bit patches for EGCS) are simply further steps.

## Which compilers upstream projects use

From a census of 21 public N64 decompilation projects (see the research notes): IDO 5.3/7.1
covers about 70% of them, KMC GCC 2.7.2 about 25%, and 12 of the 21 mix two or more compilers.
The rest are needed for specific titles: EGCS 2.91.66 (iQue builds), a modified GCC 2.8.1
(Paper Mario), SN GCC 2.8.1 and C++ front ends (IDO `NCC`/cfront, SN `cc1pln64`).

## Obtaining compilers the kit does not ship or assume

None of these were downloaded or run while writing this file; the recipes below are transcribed
from upstream build files and must be verified with `n64dk doctor` and a known-matching file.

```sh
T=/opt/n64-toolchains
mkdir -p $T/gcc2.8.1pm $T/egcs $T/sn281 $T/old-gcc-2.8.1
# Paper Mario GCC 2.8.1 + its binutils
curl -L https://github.com/pmret/gcc-papermario/releases/download/master/linux.tar.gz      | tar zx -C $T/gcc2.8.1pm
curl -L https://github.com/pmret/binutils-papermario/releases/download/master/linux.tar.gz | tar zx -C $T/gcc2.8.1pm
# EGCS 2.91.66 + binutils 2.9.5
curl -L https://github.com/decompals/mips-gcc-egcs-2.91.66/releases/download/0.7/mips-gcc-egcs-2.91.66-linux.tar.gz   | tar zx -C $T/egcs
curl -L https://github.com/decompals/mips-binutils-egcs-2.9.5/releases/download/0.6/mips-binutils-egcs-2.9.5-linux.tar.gz | tar zx -C $T/egcs
# SN GCC 2.8.1 (C and C++), run under wibo like the existing SN lane
for f in cc1n64.exe cc1pln64.exe asn64.exe; do
  curl -L -o $T/sn281/$f "https://github.com/marijnvdwerf/sn64/releases/download/1%2C0%2C0%2C2/$f"; done
# Other GCC 2.x cc1 builds (2.5.7 ... 2.95.2)
curl -L https://github.com/decompals/old-gcc/releases/download/0.17/gcc-2.8.1.tar.gz | tar zx -C $T/old-gcc-2.8.1
```

Upstream invocations to start from:

| Toolchain | Invocation (from upstream build files) |
|---|---|
| Paper Mario GCC 2.8.1 | `cpp -w -nostdinc -DOLD_GCC <in> \| <dir>/gcc -c -G0 -O2 -gdwarf-2 -x c -B <dir>/ -fforce-addr - -o <out>` |
| EGCS 2.91.66 | `<dir>/gcc -nostdinc -c -fno-PIC -mno-abicalls -mcpu=4300 -G 0 -B <dir>/ ...` |
| KMC GCC 2.7.2 (decompals build) | `COMPILER_PATH=<dir> <dir>/gcc -nostdinc -c -G0 -mgp32 -mfp32 -mips3 ...`, then `objcopy -N <in> <out>` |

## Per-file recipes

Most ROMs mix compilers and optimisation levels per object.  `resolve-hard` and `decompile-run`
partition each image into probable objects (16-byte text alignment plus padding,
`analysis/units.py`) and start every function from the recipe proven for a matched member of
the same object; give each manifest its pipeline (`--manifest FILE=PIPELINE`, or
`[run.images.<name>] recipes = { "file.tsv" = "ido5.3" }`) so its rows can teach that map.
