# Code rules: matched, and matched under the rules

A decompilation exists so that people can understand the original program. Identical bytes prove
that a source is faithful. They do not prove that it is the source: a dummy local, a `volatile`
carrier, an empty block or an offset cast can all steer a compiler to the retail bytes without
being anything the original programmer typed. Such a *fakematch* is a clue to the real source,
not a match.

`n64dk.match.coderules` makes that distinction mechanical, and the kit's credit, search and
export paths use it.

## The two laws

1. **The bytes win.** A change made for style must not change what the compiler emits. Where a
   rule and the bytes disagree, keep the bytes and record
   `RULE-EXCEPTION: <rule>, <reason the bytes give>` in a comment at the code. An exception bends
   a style rule. It never licenses fake code.
2. **Identical bytes alone are not a match.** A function counts as matched only when its bytes
   are identical *and* every [match] rule passes. Identical bytes with a [match] finding are
   `MATCH-PENDING`: reported, not counted.

Every rule serves one test: would a programmer on the original team have typed this, and can a
reader see what it does without opening the disassembly? The era's real idioms pass, however
dense they look today: `*dst++ = *src++`, `while (--count)`, `goto fail` cleanup, a search written
as `if (!(ent = Find(...)))`, a long function, a bug the original shipped.

## Tiers

| tier | meaning |
|---|---|
| `match` | blocks credit: the function is `MATCH-PENDING` |
| `advisory` | open work, never blocks a match: placeholder names, missing header comments, braceless bodies |
| `exception` | a `match` finding of a style rule (R1, R2, R4, R13) that the source records with `RULE-EXCEPTION`; also an inline-assembly helper the profile lists |
| `original-asm` | a function the evidence shows was written in assembly: listed apart, counted neither as matched nor in the total |

Rule numbers are stable identifiers. New rules take the next free number; none is renumbered.

## What blocks a match

Each check is narrow on purpose, so that genuine code passes. A [match] rule blocks a match
exactly where its check fires.

| rule | the checker reports | what passes |
|---|---|---|
| R1 one declaration per type | one type name defined in two files with different bodies; a struct that copies the leading fields of another and is reached through a cast (a layout view); a `class`/`struct` keyword mismatch | identical definitions; a type private to one unit; C's inheritance idiom (a struct that starts with another struct as its first member) |
| R2 one declaration per global | an `extern` object declared outside a header; one global declared with two types | `extern` in a header; arrays that differ only in their declared size |
| R4 typed members | a constant offset added to a byte-pointer cast and dereferenced through another cast, in code or in a macro; offset arithmetic on a cast of `this` | byte-pointer walks over data with no fixed struct (parsers, allocator headers); `offsetof` tables |
| R13 real vtables | a virtual named `pad…`/`dummy…` | every other virtual (the kit has no vtable data to compare slots against) |
| R17 no fake code | `volatile` on a local; `volatile` anywhere else without a `volatile: <evidence>` note; a local that is never used; a statement marked as a probe or as scaffolding (the kit's own frame-padding mark included); an empty `if`/`else` block; a bare `;`; `do { } while (0)` outside a macro; `if (0)` and `if (1)`; self-assignment; `+ 0` and `* 1`; a padding member (`pad`, `pad2`, `_pad…`) the SDK or file format does not name | `volatile` through a cast of a literal or macro address (a hardware register); a typedef that names a volatile type; empty loop bodies, `case X: ;` and `label: ;`; an unused local labelled as the original's (`NOTE:`, `BUG:`, `R36`); members named by offset (`unk_58`) |
| R18 no assembly bodies | inline assembly in a function body or at file scope; register bindings; `INCLUDE_ASM`, `GLOBAL_ASM` | a symbol alias on a declaration (`extern s32 x __asm__("D_80012345");`); a function marked `ORIGINAL-ASM`; a helper the profile lists |

R17 and R18 cannot be excepted or relaxed.

`if (0)` and `if (1)` are in the [match] tier here because the kit's own `ast-block` search
family writes `if (1) { }` wrappers. The check is mechanical, as a [match] rule has to be.

## Open work the checker also reports

| rule | finding |
|---|---|
| R7 | placeholder names: `func_80012345`, `D_80123456`, `argN`, `temp_v0`, `var_a0`, `sp1C`, `unk10`, `M2C_UNK`, `FUN_`/`DAT_`/`sub_` and address-like names |
| R4 | a constant offset from an integer cast of a pointer |
| R9 | a mask written in decimal |
| R22 | a declaration in a `for` header |
| R25 | a prototype outside a header |
| R33 | a function without a header comment |
| R35 | `if`/`else`/loop bodies without braces; an assignment inside a condition outside the search idiom |
| R37 | `#if 0` blocks |
| F | `!!x` and `(void)x;`, which are sometimes human and need a look |

Naming is deliberately not a [match] rule: a match with placeholder names is a real match whose
naming is still open. Never replace a placeholder with a confident invented name; use the
binary's own evidence first (error strings that start with a function name, SDK signatures).

## Where the kit applies the rules

* **Credit.** `provenance.scan_c` still answers whether a candidate is ordinary C, which is what
  a search needs before compiling it. `provenance.judge_c` answers whether byte-identical C may be
  credited, and returns `match-pending` when a [match] rule fires. `credit_bytes` and
  `proof.evaluate` grant nothing for it. `provenance-audit` uses `judge_c`.
* **Search.** A search may try anything; what it may claim is decided on the text of its result.
  `transform_classes.STEERING` names the families whose output is a known fakematch shape
  (`ast-block`, `frame-pad`, `volatile`, `ast-temp`, `ast-sameline`, `ast-cast`, `casts`), the
  rule each answers to and what the shape usually hides. `provenance(stages)` lists them under
  `steering`. A winner that came through one of them is a clue: look for the macro, type,
  variable or statement order it stands in for.
* **External authors.** The refiner's instructions say what is not counted, so a model or script
  is not asked for bytes at any price.
* **Dossiers.** `investigate` reports `code_rules` for the selected candidate source.
* **Export.** `decompile-export` checks every C source it writes and reports two numbers:
  *bytes identical from C* and *matched under the code rules*, the second being the headline.
  Only a strictly exact function can be matched under the rules: one that still awaits a symbol
  declaration is not, whatever the checker says about its source.
  `FUNCTIONS.tsv` and `MATCHED.tsv` carry a `rules` column (`pass`, `MATCH-PENDING: R2,R17`,
  `ORIGINAL-ASM`, `unchecked (donor)`); `RULES.tsv` lists every finding; `DECLARATIONS.tsv`
  lists every `extern` by name with each way it is declared; `AGENTS.md` is the project profile.
  Hand-written assembly is `ORIGINAL-ASM` and is left out of both the count and the total.
* **Trackers.** `tools/generate_tracker_progress.py` adds a `matched-under-rules` track when the
  inventory has a `rules` column.

A source exported by an unattended run declares what it needs in its own file. Under R2 a
function that names a global is therefore `MATCH-PENDING` until its declarations are gathered
into shared headers. `DECLARATIONS.tsv` is the work list; a name declared in two ways is a
conflict to settle first. Moving a declaration can move data, so rebuild and rerun the byte gate
after each such change.

## Commands

```bash
n64dk code-rules src include --project . --strict
```

prints one line per finding (`path:line: rule [tier] in function: message`) and a summary, and
exits 1 with `--strict` when a [match] rule fires. Pass a unit together with the headers it
includes so that the cross-file rules (R1, R2) see both. `--no-advisory` keeps only what blocks a
match; `--declarations` adds the `extern` table; `--format json` gives the same as a document,
with `pending_functions`.

```bash
n64dk --format json provenance-audit SRC.c --exact --ownership-verified --size N --project .
```

credits nothing for `match-pending` source and lists each blocking finding as evidence.

## The project profile

A project describes itself in two places. Its `AGENTS.md` holds the prose profile: compiler and
dialect, annotation and parking, naming and layout style, evidence sources, whether the binary
records line information, commands, and rule changes with their reasons. `decompile-export`
writes a first version that says *not established* wherever the run proved nothing.

The part the checker reads is `[code_rules]` in the project's `n64dk.toml`:

```toml
[code_rules]
tighten = ["R33"]                 # advisory rules this project requires for a match
sdk_padding = ["pad", "pad1"]     # padding member names the SDK or a file format defines
placeholders = ["gUnk\\w+"]       # further placeholder patterns (regular expressions)
naming_whitelist = ["COLOR_[0-9A-F]{6}"]
asm_helpers = ["MulHigh"]         # inline-assembly helpers the original had
original_asm = ["__osExceptionPreamble"]
braceless = false                 # true when surviving source writes braceless bodies
banners = true                    # false when the profile wants no function header comments

[code_rules.relax]
R2 = "the surviving SDK source declares its externs in each .c file"
```

A relaxed rule needs its reason. R17 and R18 cannot be relaxed. Move an advisory rule into the
[match] tier only when it is checked mechanically: a rule nobody can check turns "matched" into
an argument.

## Adding or changing a check

A [match] check is added together with its test in `tests/test_coderules.py` (one case that
fires, one genuine construct that must pass) and its row in this document. A new search family
that writes a fakematch shape is added to `STEERING` in the same change.

## Measured results and limitations

* `tests/test_coderules.py` (40 tests) and the export tests in `tests/test_export.py` run without
  a ROM or a toolchain. They cover every [match] check, the genuine constructs each must pass,
  the credit path and an end-to-end export of a synthetic project.
* The checker has **not** been measured on the fixture ROMs or on a finished decompilation
  project: no false-positive rate on known-good source is claimed. Run `code-rules` over a
  completed project before relying on a count from it, and record genuine findings as profile
  entries or exceptions rather than chasing a score.
* It reads text, not a parse tree. It does not expand macros or follow includes: a macro that
  hides a fake statement is not seen, and a local used only inside a macro's expansion can be
  reported as unused. A K&R-style definition is not recognised as a function.
* R1's layout-view check needs the cast and the other type's name in the same function. R13 has
  no vtable data and checks names only.
* Donor sources are not checked by the export: they belong to other projects and keep those
  projects' profiles.
