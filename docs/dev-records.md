# Development records left in ROMs

Some ROMs keep pieces of their developers' build output. `n64dk/analysis/devrecords.py` reads
two kinds, fail-closed: a candidate is accepted only when every record decodes and is plausible,
and each rejection keeps its reason.

* **SN/PsyQ object files** (`LNK`, version 2): sections, code bytes, exported, imported and local
  symbols, uninitialised data, relocations with their patch expressions, source files, line
  records, function and block records, type definitions.
* **SN debug streams without their object**: runs of function, block and definition records. The
  class and type words are COFF's: parameters (with the register or stack slot), locals, structs,
  unions and enums with member offsets, typedefs, and file-level symbols with their linkage.

The record layout was established from the behaviour of a public reader of the format (see the
research log); the N64 records store array dimensions as 32-bit values.

## Commands

```
n64dk dev-records-scan (--project PROJECT | --rom ROM) [--image NAME]... --out evidence.json
n64dk dev-records-decode --file FILE --at OFFSET [--length BYTES]
```

`decompile-init` runs the scan as a survey stage: an accepted run owns its bytes in the ledger as
`debug_records` (the lowest priority: program, audio, codec and graphics evidence win), and the
facts go to `survey/devrecords.json`. Every fact keeps the image, the record's offset, the
record's digest, its kind, and whether it was read directly or inferred.

## Placement

Debug records carry offsets inside their object, not linked addresses, and a stream left in a
ROM often comes from a slightly different build than the code beside it: a function that changed
size moves everything after it. `devrecords.align` places a stream in a program image without
assuming the two builds are identical:

- **Anchors.** A function with a frame is anchored where the image holds its exact shape: a body
  of the recorded size ending in `jr ra` with `addiu sp, sp, +frame` in the delay slot, and
  `addiu sp, sp, -frame` within its first eight instructions.
- **Chain.** Per object, the longest chain of anchors in record order is kept, each displacement
  within 0x800 bytes of the previous one.
- **Agreement.** An anchor is placed only when a neighbour in the chain has the same displacement:
  two independent functions agree. A function without an anchor (frameless, or changed) is placed
  only between two placed anchors of equal displacement, and only where a return ends it at its
  recorded size. Everything else is reported as unplaced with the reason.

`devrecords.apply_to_catalogue` (run by `decompile-init`) names the catalogue function each
placement lands on. A placement that is not a catalogue start, or whose recorded size differs
from the catalogue body, is a listed conflict and changes nothing. It then renders the stream's
declarations as C (`render_declarations`):

- forward declarations of every struct and union tag the stream mentions;
- struct and union bodies whose recorded layout is consistent (members in offset order, sizes
  known, explicit padding where the record leaves a gap, total equal to the recorded size; others
  stay opaque);
- enums, typedefs, and prototypes of the named functions.

Anonymous tags (`.151fake`) become identifiers, and enum-typed members become `int`. The header is
written to `survey/devrecords_context.h` and listed under `[run] context_headers`. The automatic
context puts it ahead of the recovered declarations, and a recovered prototype never replaces a
recorded one. Outputs: `survey/devrecords_placed.json` (placements, conflicts, displacements per
sequence, declaration counts).

## Measured

Of 115 ROMs, none keeps an object file and one keeps a debug stream: Armorines, 183,710 bytes,
4,842 records (83 functions, 826 struct, union and enum definitions, 130 typedefs, 132 symbols).
The stage accepts nothing in the other 114.

The stream's front-end functions are in the main image at vram 0x002D9460. Round 10 reported
them as outside any decoded image; that was wrong. The catalogue stopped at 0x002A3C98 because
every call in this TLB-mapped program (run at 0x00200400) was rejected as a call outside RDRAM,
and its functions are reached through method tables. With calls checked against the image's own
8 MiB window and frame prologues after a function's end seeded, the catalogue grows from 765 to
4,272 functions to the datamap's text end, while SM64 and Dr. Mario 64 are unchanged. Of the 83
functions, 66 are placed at two displacements (0xD9060 and 0xD9068: one function grew by 8
bytes between the builds), 65 named, 1 reported as a boundary conflict. 65 of the 66 agree in
start and size with the catalogue, which was built without the records. The header (71 bodies,
41 opaque, 714 enums, 130 typedefs, 65 prototypes) compiles under KMC GCC with every body at its
recorded size.
