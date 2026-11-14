# N64 matching-tool workflow research

This review focused on operations that repeatedly become shell searches, temporary-file
edits, disassembly extraction, build calls and manual evidence reconciliation.

## Useful upstream concepts

- [Splat](https://github.com/ethteck/splat) makes binary ownership and generated project
  structure declarative. The kit therefore treats catalogue sections and manifest intervals
  as mapping authorities rather than inferring layout from a candidate address.
- [spimdisasm](https://github.com/Decompollaborate/spimdisasm) combines function detection,
  pointer discovery, HI/LO pairing, file-boundary analysis and read-only-data migration. The
  kit's dossier exposes the corresponding boundary, reference and literal evidence in one
  result, while preserving its stricter preflight boundary.
- [asm-differ](https://github.com/simonlindholm/asm-differ) removes the rebuild/diff command
  boundary, and [objdiff](https://github.com/encounter/objdiff) extends comparison to whole
  objects, data and progress. Transactional sessions retain that immediate feedback while
  keeping classified residuals and project-wide history.
- [decomp-permuter](https://github.com/simonlindholm/decomp-permuter) demonstrates bounded
  explicit alternatives, compiler-specific weighting, concurrent workers and distributed
  execution. The kit adopts bounded evidence-selected variants and compiled-object
  deduplication, but rejects unconstrained mutation as primary evidence.
- [CakeUnbake64](https://github.com/AbuN64/cake-unbake-64) separates compare, submission and
  landing, derives ownership from source layout, regenerates configuration deterministically,
  and proves every ROM version. The kit similarly keeps exploration non-mutating and exact
  integration prepare-only.
- [Hybrid Heaven Decomp](https://github.com/ogdanimal/HybridHeaven-Decomp) documents practical
  translation-unit boundaries, per-directory optimization levels, reversed IDO function
  ordering, context generation and first-pass source preparation. This motivated recipe
  evidence from adjacent exact manifest units instead of one global default compiler recipe.

## Repeated calls now collapsed

| Previous sequence | First-class operation |
|---|---|
| Search catalogues, manifests and scratch trees separately | `investigate FUNCTION` |
| Compute ROM/VRAM delta, disassemble and inspect the tail | mandatory layout preflight |
| Search several projects for similar functions | `corpus-index` then `corpus-query` |
| Extract one assembly function and copy a candidate | `investigate --bundle DIR` |
| Guess flags from nearby units | dossier `qualified_recipes` with distance and manifest evidence |
| Locate old session databases and compare scores | project session registry and historical frontier |
| Edit, compile and inspect one spelling at a time | `match-session-explore` |
| Search hundreds of undocumented project scripts | `script-index` then `script-query` |
| Synthesize commands and parse terminal prose | `operation-schema` and `automation-serve` |

The local survey found that the dominant reusable shapes are argument-parsed wrappers,
subprocess-driven compiler/scorer adapters, bounded source sweeps, residual classifiers, and
source normalizers. The safe consolidation path is discovery first and native implementation
second: indexing a script does not grant execution authority, while promoted operations
inherit target preflight, the session ledger, caching, and structured output contracts.

## Deliberate limits

The corpus index currently consumes assembly already present in local projects. It does not
download repositories, claim semantic equivalence from opcode shape, or compile arbitrary
foreign source. Match classes are explicit: textual exact, relocation-only,
register-renamed, and opcode-shape. Structural analogues remain leads, never proof.

The dossier's prototype is evidence, not a declaration oracle. It reports observed argument
registers and frame allocation; headers, callers and exact compilation remain authoritative.
Compiler recipes are ranked from neighboring manifest rows and retain their source path and
distance so the choice is auditable.
