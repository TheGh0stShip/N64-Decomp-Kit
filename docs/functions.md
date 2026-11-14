# Function discovery (`n64dk.analysis.functions`)

Game-agnostic function boundaries, jump tables and boundary findings for the boot-loaded
main code segment. Input is the ROM image only; project catalogues are optional and used
for scoring (`--truth`) or auditing (`--audit`).

```
n64dk functions ROM [--out DIR] [--truth CATALOGUE]... [--audit CATALOGUE]... [--list N]
n64dk --format json functions ROM --out build/functions
```

`--out` writes:

| File | Content |
|---|---|
| `functions.toml` | recomp-style `[[section]]` + `functions = [ { name, vram, size } ]`, each line commented with its class and flags |
| `symbol_addrs.txt` | splat-style `func_X = 0x...; // type:func size:0x..` plus `jtbl_X ... type:jtbl` |
| `jump_tables.tsv` | table address, entry count, size, owning function, `jr` site, bounded-by-`sltiu`, first target |
| `findings.tsv` | address, kind, function, detail |
| `audit_<n>_<name>.tsv` | findings for each `--audit` catalogue |
| `summary.json` | everything printed by the command, including scores and audit counts |

Catalogues are read from recomp TOML (`name = "...", vram = 0x..., size = 0x...`) or from
splat `symbol_addrs.txt` (`type:func size:`).

## Method

1. **Image.** IPL3 copy (ROM 0x1000 -> header entry), clipped at the BSS start found in the
   entry routine (`n64dk.boot`).
2. **Call closure.** Seeds: the entry point, then every `jal` target, `j` tail target and
   `lui`/`addiu` + `jr reg` constant target in walked code, to a fixpoint.
3. **Walk.** Linear walk tracking the furthest in-function branch target (jump-table targets
   and local `bal` included). The function ends after the delay slot of the first terminator
   (`jr ra`, `jr reg`, `j`/`b`, `eret`, `break`) no branch skips. After an in-function loop
   jump or a trap, dead code that cannot be an entry (epilogue `lw ra`/`addiu sp,+N`, HI/LO
   reads, reads of unset temporaries) continues the function. Trailing zero words up to the
   next start are included in `size`; `body_end` excludes them.
4. **Text extent.** After the call closure the sweep continues past the highest function while
   bytes keep forming complete functions, bounded by the lowest load/store target above it.
   The result is where rodata/data begins.
5. **Gap sweep.** Gaps inside text are swept for unreferenced functions in strict mode
   (valid instructions, no writes to `$zero`, no never-taken branches on `$zero`, no `j`/`jal`
   outside RDRAM or into RSP-IMEM-style low addresses, must end in a terminator, no data
   load/store into the body). A candidate that reads a temporary nobody set, restores `ra`, or
   pops a frame is not an entry.
6. **Stray words / in-text data.** Up to 15 garbage words between functions are skipped
   (objects aligned to 16 bytes with non-zero fill are common). The aligned boundary is
   preferred when the words before it are demonstrably not a function start. Larger
   non-code runs are resynchronised on the next prologue, `jal` target or `jr ra` leaf after
   zero fill, and reported as `in_text_data`.
7. **Pointer seeds.** Code addresses taken by `%hi/%lo` pairs and 32-bit words in data that
   land on a gap or on a split point (after a terminator and its delay slot) add starts;
   jump-table extents and targets are excluded.
8. **Jump tables.** `lui`/(`addiu`)/`addu`/`lw`/`jr reg`, simulated forward from up to 4 KiB
   before the `jr` so loop-invariant table bases in saved registers resolve. The `sltiu`
   bound gives the count; otherwise entries are read while they point into the function.
9. **Classes.** `asm` (rabbitizer `isLikelyHandwritten` / `notEmittedByCompilers`, or COP0
   operations such as `mtc0`/`eret`/`cache`), `O0` (stack frame plus `fp = sp`),
   `stub` (no frame, no calls, at most four instructions), `leaf` (no frame, no calls), `c`.
   `seed` records the strongest evidence: `entry`, `call`, `pointer`, `tail`, `unreferenced`.

## Findings

| Kind | Meaning |
|---|---|
| `late_start` | control falls into the entry and its first instructions read a temporary set by the bytes before it (delay-slot or scheduler hoist) |
| `interior_alias` | entry reached only by branches from earlier code, never called or pointed to |
| `falls_through` | the preceding code does not end in a terminator (late start without a temporary read, or hand-written fall-through) |
| `start_in_delay_slot` | entry begins in a jump's delay slot |
| `overlap` | audited entry starts before the previous one ends |
| `shared_epilogue` / `cross_branch` / `branch_to_entry` / `branch_outside` | branches leaving an entry: into another entry's epilogue, interior, start, or into no entry |
| `stray_words` / `in_text_data` | non-code bytes inside text |
| `rejected_start` | a weak seed whose walk hit invalid code or fell into the next function |
| `not_code` | audited entry's first word is not a valid instruction |
| `junk_start` | audited entry's first word is valid but never compiler output at an entry (unaligned-access or misaligned operand, `ldr`-style bytes from strings) |

## Measured results

Scores count reference entries inside the discovered text extent. `exact_size` compares
sizes as emitted (trailing zero padding included); `body_size` compares with trailing
padding stripped from both sides.

| Fixture | Text | Functions | Jump tables (entries) | Reference | Precision | Recall | Exact size | Body size |
|---|---|---|---|---|---|---|---|---|
| BattleTanx (NBXE) | 0x80071000..0x80125550 | 1763 | 79 (1341) | `config/us/recomp_function_boundaries.toml`, 1770 | 0.984 | 0.979 | 0.933 | 0.996 |
| Global Assault (NBQE) | 0x80071000..0x8011449C | 1889 | 191 (3655) | `config/us/symbol_addrs.txt`, 1885 | 0.993 | 0.995 | 0.989 | 0.990 |
| Global Assault (NBQE) | | | | `config/us/recomp_function_boundaries.toml`, 1879 | 0.993 | 0.998 | 0.989 | 0.990 |
| Mario Kart 64 (NKTE) | 0x80000400..0x800D8FC4 | 2659 | 209 (3739) | none (counts only) | | | | |

Text extents equal the end of the last reference function for both BattleTanx games.
Run time is 5-12 s per ROM.

Class counts: BattleTanx c 1244, leaf 356, stub 122, asm 34, O0 7; Global Assault c 1268,
leaf 483, stub 98, asm 34, O0 6; Mario Kart 64 c 1947, leaf 488, stub 132, asm 30, O0 62.

In-text data found: BattleTanx 0x8007103C+0x4FC4 (data between the entry routine and the
first library function) and 0x8010E1B4+0x22CC (non-CPU code, no reference entries there);
Global Assault 0x80071040+0x6C00 and 0x800F8E04+0x206C; 58 / 83 stray-word runs.

### Where the references disagree

* **BattleTanx: all 38 missed reference starts are flagged by `--audit`** on the reference
  itself (20 `late_start` + `overlap`, 9 `falls_through` + `overlap`, 5 `falls_through`,
  4 with cross branches). They are hoisted-prologue entries (`lui a0; lw a0` or `lwc1`
  scheduled before `addiu sp`) and the known-bad interior entries; the discovered start is
  the earlier, correct one. The audit flags 45 reference entries in total (34 overlaps,
  22 late starts).
* BattleTanx extras are mostly real functions the reference omits or merges: exception-vector
  templates and `__osException` pieces (hand-written, 0x800770A0, 0x80111690...), unreferenced
  leaves after a `jr ra` that the reference folds into the previous entry, and starts one or
  two instructions before a reference late start.
* Global Assault: 10 missed against `symbol_addrs.txt`; 8 are flagged by the audit
  (`not_code`, `junk_start`, `start_in_delay_slot`, `falls_through`, `interior_alias`,
  `branch_outside`). The two unflagged ones are an ASCII fragment that decodes as `daddiu`
  (0x800E8378) and an exception-vector template where the reference starts one word later
  (0x80078CE4).

## Limitations

* One main segment. By default it is the IPL3 copy, so a game that runs a loader first gets
  just that loader; pass `program=` (an `n64dk.image.ProgramImage`, as `n64dk survey` does)
  to analyse the loader's unpacked or DMA'd program instead (Madden 64: 5 loader functions
  -> 1383 functions, 31 jump tables). Overlays loaded later are out of scope.
* The text end is where reached code stops forming functions. When calls from accepted
  functions (at least two sites) land past it, as when RSP microcode is linked into `.text`
  between CPU code, the text is extended and the phases run again (finding `text_extended`;
  Madden 64: text end 0x80050EFC -> 0x800649FC). An RSP block at the very end of `.text`
  (Mario Kart 64, Nagano) is not CPU code and stays outside the reported text.
* Strict sweep rejects functions whose only `j`/`jal` go outside RDRAM; such functions are
  still found when they are called.
* Dead `jr ra; nop` returns left after a compiler epilogue are reported as separate stubs
  unless they are reached by a branch.
* Jump-table extents without an `sltiu` bound stop at the first word that is not an in-function
  address; there is no independent jump-table ground truth, so only internal consistency (all
  targets inside the owning function, checked in tests) is measured.
* Hand-written exception code with fall-through between labels is split at every reachable
  label and reported with `falls_through`.
