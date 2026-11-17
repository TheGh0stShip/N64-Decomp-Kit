# Toolchain components, recipes and probes

A lane name (`ido5.3`, `kmc+as`, `sn`) stands for a whole build: preprocessing, the front end,
the optimiser, the code generator, the assembler and its macro dialect, the object format and any
conversion after it. `n64dk/match/components.py` names the component of every stage, where it
comes from and what is known about it, and describes each lane as a recipe.

## `compiler-components`

```
n64dk compiler-components [--toolchain-dir DIR] [--out catalogue.json] [--recipe LANE]
                          [--compare LANE LANE] [--no-digests] [--verbose]
```

Lists every component with its role, version, provenance class, disposition, origin and source,
format, emulator, licence, known projects and flags, retail evidence and confidence, plus what the
toolchain root holds of it (files, formats, SHA-256). `--out` writes the whole machine-readable
catalogue. `--recipe` shows one lane stage by stage with its identity: a SHA-256 over the stage
order, components, file digests, flags and environment. `--compare` reports which stages two lanes
share and which differ.

Provenance classes: `authentic-n64`, `authentic-n64-component` (an authentic tool in a
combination its vendor did not ship), `authentic-assembler-linker`, `reconstructed`,
`comparative` (another platform's relative, such as PsyQ for PS1: never an N64 lane on its own),
`speculation`. Dispositions: `implemented-verified`, `comparative-only`, `rejected`,
`unavailable`, `undistributable-local`, `speculation`.

## `compiler-probes`

```
n64dk compiler-probes --out probes.json [--lane LANE]... [--probe NAME]... [--repeat 2]
```

Builds the synthetic probe suite (`n64dk/match/probes.py`: one small function per code-generation
feature, and a token-identical pair laid out on one line and on many) under every runnable recipe
and its usual flag sets, each probe twice in separate projects. The report holds the masked code
hash of every probe under every recipe, recipes whose two builds differ (non-deterministic),
equivalence classes (recipes no probe tells apart), pairwise distances, stage attribution (recipes
that share every stage but one differ only through that stage) and whether line layout changes
code. A heavy job: it takes the machine lock.

## Measured (round 10)

36 recipe and flag sets, 27 distinct behaviours, none non-deterministic. KMC cc1 with its own
assembler and with the ASN64 converter and GNU as differ on 19 of 35 probes, all through the
assembler. IDO 6.0 and the MIPSpro lane (`-32`, the ucode compilers) agree on every probe; SN
builds 0004 and 0006 agree with the rebuilt 970404 GCC. Only IDO 6.0 and MIPSpro at `-O2 -mips1`
compile the token-identical pair differently: equal preprocessed tokens do not make equal recipes.
Rebuilding held-out tree functions under every candidate, the true lane reproduces 72 of 80 in
SM64 and in Dr. Mario 64, but only 7 and 9 of 80 are reproduced by exactly one candidate: a recipe
is identified from many functions of a unit, not from one.

## Limitations

The SN lanes preprocess with the host's `gcc -E` instead of SN's `cppn64`; PsyQ PS1 compilers are
comparative only and not installed (proprietary); SN's psylink and the SDK's makerom are not
available, so link-level behaviour is not reproduced. No command yet assembles a dossier for a
region no installed recipe reproduces.
