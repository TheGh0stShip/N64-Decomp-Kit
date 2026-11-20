# Working on n64dk

`n64dk` is a toolkit, not a decompiled title: it holds no reconstructed game source. What it
does hold is every path that writes, searches, credits and exports such source, so the code
rules bind those paths. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/BRIEF.md](docs/BRIEF.md) and [docs/code-rules.md](docs/code-rules.md) first.

## The contract for anything that writes or credits C

1. **The bytes win.** Nothing changes what a compiler emits for the sake of style.
2. **Identical bytes alone are not a match.** A function is credited only when its bytes are
   identical and every [match] code rule passes (R1, R2, R4, R13, R17, R18). Otherwise it is
   `MATCH-PENDING`: reported, never counted.

In practice:

- A search may try anything. What it may claim is decided on the text of its result by
  `n64dk.match.coderules`, never by how the result was found.
- Credit goes through `provenance.judge_c`. `provenance.scan_c` only says whether a candidate is
  ordinary C and may be compiled.
- A new search family that writes a fakematch shape (a steering block, a meaningless temporary,
  a `volatile` carrier, padding) is added to `transform_classes.STEERING` in the same change.
- A report that counts functions gives both numbers, bytes identical and matched under the
  rules, with numerator, denominator and provenance. Hand-written assembly is `ORIGINAL-ASM`,
  in neither.
- A generator never writes a confident invented name. Placeholders (`func_80012345`,
  `D_80123456`, `arg0`) stay placeholders and are reported as open naming work.
- A [match] check must be mechanical. Add it with its test (one case that fires, one genuine
  construct that passes) and its row in `docs/code-rules.md`. Rule numbers are never reused.

## Profile of the sources the kit handles

- **Compilers and dialect:** IDO 5.3 and 7.1 (C89: declarations at the top of a block), KMC GCC
  and SN GCC (GCC 2.x: pre-C99 with that release's GNU extensions). No `stdint.h`, no
  `stdbool.h`, no declarations in a `for` header.
- **Types:** the SDK's own (`u8` … `u64`, `s8` … `s64`, `f32`, `f64`, `OSTime`, `OSMesg`).
  `volatile` is genuine on hardware registers and on data shared with an interrupt handler, and
  carries a `volatile: <evidence>` note anywhere else.
- **Parking:** none in the kit. A function without matching C is assembly under
  `asm_not_decompiled/` in an export and is never counted as C.
- **Naming and layout:** the title's own, recorded in that title's `AGENTS.md`. The kit assumes
  none; `decompile-export` writes a profile that says *not established* until evidence arrives.
- **Evidence sources:** SDK signatures, strings in the ROM, development records
  (`dev-records-scan`), donor units.
- **Rule changes:** `if (0)` and `if (1)` are [match] findings under R17, because the kit's own
  `ast-block` family writes them. A title relaxes or tightens rules in `[code_rules]` of its
  `n64dk.toml`, with the reason.

## Commands

```bash
python -m unittest discover -s tests -t .          # ROM-dependent tests skip when not configured
n64dk code-rules SRC... --project DIR --strict     # the rule checker
n64dk --format json provenance-audit SRC.c --exact --ownership-verified --size N
```

## Repository rules

- Nothing in core is specific to one game. ROMs, compiler binaries, private paths and generated
  state stay out of Git.
- Standard library plus `rabbitizer`; optional extras are imported where they are used.
- A module owns its command, its tests and its document; each document ends with measured
  results and limitations, and says so plainly when something was not measured.
