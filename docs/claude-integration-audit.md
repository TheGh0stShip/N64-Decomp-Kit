# Recovered Claude lab integration audit

This document records how the long-running Claude lab was recovered and evaluated. It is an
engineering ledger, not a benchmark claim. The lab measurements were made on different code
snapshots, title sets, compiler installations and definitions of “matched”; they are useful
experiment evidence but are not combined into a release percentage.

## Recovery boundary

The maintained repository was fast-forwarded from its pre-recovery snapshot to the lab's last
coherent commit. A backup ref preserves the old tip. Every committed lab module, side-branch
candidate and uncommitted generator file was then compared with the recovered tree.

| recovered area | disposition |
|---|---|
| m2c bridge, draft sweep, scoring, hints, fragment audit, similar queue | integrated; m2c invocation, constants, jump tables and lookup fixes retained |
| strict verification, entry/ABI/cause analysis, durable resolver, reconcile and workspace audit | integrated; strict receipts—not manifest containment—are inventory credit |
| byte ownership, logical images, boundary solver, TU/AST search and source splitting | integrated; newer coordinate and ledger APIs retained where side branches were older |
| bare-ROM initialization, loaded-segment discovery, boot emulation and compression paths | integrated; unknown bytes remain explicitly unknown rather than guessed |
| compiler catalogue, configured compiler lanes, SDK and cross-title donors | integrated; donor units are rebuilt against the recipient and donor assembly is no longer counted as C |
| debug/optimized GCC and IDO draft generators | integrated; recovered side-branch files were older than the committed versions; their focused suites pass |
| source-tree donor and one-function unit splitter | integrated; only C-authored functions enter C donor catalogues, with strict recipient verification |
| generated assembly/raw-word coverage | retained only as `not decompiled` coverage; excluded from C credit and clearly separated in exports |
| region-recipe retry | retained as opt-in; 3/126 measured return does not justify the default cost |
| nearest-unit recipe retry | retained as opt-in; 0/165 measured return rejects it as a default |
| unknown-toolchain search suppression | retained as opt-in; classifier output is advisory until independently validated across more compiler families |
| alternate decompiler renderings | available but off by default; 6/639 measured return did not justify default expansion |
| model/external refinement | integrated as an optional, bounded command interface; never silently enabled and every answer passes the strict verifier |

The boundary/ownership, AST-search and donor side branches were exercised against their original
tests. Where their implementations differed, the current tree was newer or the old API had been
replaced. The recovered uncommitted GCC/IDO generator files were byte-identical to, or older than,
the committed versions; they were not overlaid. Review reproductions for the multi-image donor
export were rerun against the final all-image export path, whose regression test covers the bug.

## Hardening added during integration

- `decompile-run` plans build concurrency from available memory, reserves 2 GiB, caps at four jobs
  by default and emits the decision. An unsafe override must be explicit.
- Compiler and assembler subprocesses run in process groups with timeouts; interruption cleans up
  descendants. Build identities include the include closure, tool binaries, recipe and relevant
  environment.
- Session candidate identity includes the evaluator environment, failed attempts remain retryable,
  and SQLite writes use bounded retry.
- Logical image selection fails closed on ambiguity. Extracted images may infer a linear delta only
  from mutually consistent catalogue section mappings.
- `match-inventory --verify` rebuilds configured manifest units, caches strict verdicts, invalidates
  on header/tool/target/symbol changes, and demotes deleted sources.
- Batch matching reports ambiguous address-less exact matches rather than choosing one.
- Transform output refuses stdout before reading or applying a proposal, preserving transaction
  semantics.
- Export numerators separate strict C, C awaiting symbols, donor assembly, positively identified
  handwritten assembly and generated assembly/raw-word fallback.

## Verification policy

There are three distinct claims:

1. **Strict C:** current source rebuilds to the target bytes and every relocation has independent
   authority. This is the only ordinary C completion credit.
2. **Awaiting symbols:** bytes are identical, but at least one address is not independently
   declared. It is evidence and exportable work, not strict completion.
3. **Assembly coverage:** proven original/donor assembly is reported separately; generated
   disassembly or raw words merely ensure every code range has a reproducible representation.

ROM-ledger completeness is also separate from decompilation. A byte may be mapped yet remain
unclassified media or unknown data. Reports give gaps, overlaps, byte classes and unknown ranges;
they do not convert mapped bytes into decompiled bytes.

## Evaluated limitations

These are explicit capability boundaries rather than hidden backlog:

- A retail compiler/assembler combination not present in the configured catalogue cannot be
  recreated by additional source permutations. The run reports compiler evidence and continues
  without treating the classifier as proof.
- A packed program using an unsupported codec may still be reached when boot emulation executes
  the title's loader; otherwise the packed range remains classified and unplaced, never guessed.
- RSP microcode and handwritten routines are identified and may be represented by verified
  assembly; they are not called C decompilation.
- Importing an existing public source tree is supported through `source-donor`, but copyright and
  licence decisions remain with the operator. The kit does not copy ROMs or toolchain binaries.
- One-shot 100% C recovery for arbitrary optimized game code is not a defensible promise. The
  pipeline instead guarantees explicit disposition: strict C, awaiting evidence, verified
  assembly, generated byte coverage, or unresolved/unknown—with no category silently promoted.

## Release gates

The recovered tree is accepted only after the standard-library suite with all four primary
toolchains configured, `compileall`, `n64dk self-test`, operation-schema serialization, a clean
workspace audit and bounded end-to-end trials. The exact command and final counts belong in the
release commit/CI output; title-wide historical percentages above are deliberately not release
gates.
