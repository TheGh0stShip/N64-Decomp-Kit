# Round 4 integration and adversarial verification

This document records what was actually integrated from the Round 4 resolution/proof pack. The
delivered pack was treated as untrusted: its modules were reviewed, its reproducers were rerun,
and several proof, coordinate, persistence, and orchestration paths were strengthened before
acceptance.

## Proof boundary

`compare.compare_object` remains an intentionally permissive exploration oracle. It may infer an
unknown relocation from the retail instruction being compared, and therefore its `exact` bit is
not proof. Any state transition that grants credit uses `verify.strict_compare` instead.

Strict proof requires:

- an explicit address and complete owned interval;
- independently loaded symbol and section declarations (candidate-authored `LDSYM` markers,
  aliases, and address-bearing names cannot prove an address);
- equality of all owned `.text`, `.data`, and `.rodata` bytes;
- no non-zero emitted text beyond the owned range;
- current source, dependency closure, compiler, image, target, recipe, and coordinate identities.

The three strict verdicts are `exact`, `assumed`, and `mismatch`. An assumed address or
unverified data section can guide research but cannot enter a winner queue, verification receipt,
inventory numerator, or integration transaction.

## Adversarial review disposition

| Finding | Integrated disposition |
|---|---|
| F01–F02 | Retail-derived external/section addresses are assumptions in the strict oracle. Name-derived and candidate-source symbols are stripped from proof authority. Conflicting symbols and non-function call targets reject proof. |
| F03–F04 | Strict comparison checks declared owned data through its full size. Trailing-zero disagreement and unplaced non-empty data are mismatch/assumed, never exact. |
| F05 | Manifest rows are ownership claims. Only a current strict verification receipt produces `manifest_exact_unit/member`; missing or unverified source remains `manifest_nonexact`. |
| F06 | Function names are labels. Structural exclusion requires catalogue/status/ownership evidence, not words such as `data`, `call`, or `stub`. |
| F07 | Inventory accepts configured catalogue/manifest paths and content-based catalogue discovery, has no implicit ROM bias, reports unmapped claims, and marks a zero-function inventory inconsistent. |
| F08 | Session identity includes target, toolchain and dependency closure. Failed candidates are retried and every attempt is retained. |
| F09 | Object identity follows the effective include closure, including computed includes and `-isystem`, `-iquote`, `-idirafter`, forced includes, and command-line macros. Unrelated scratch files are not scanned. |
| F10 | Compiler processes run in private build directories; RTL dumps cannot leak into the project root. |
| F11 | Candidate bytes are staged with a language-bearing suffix, so extensionless cache objects compile as C. |
| F12 | Lifetime moves cannot cross calls, exits, labels, pointer writes, or non-local memory. Precedence-sensitive rewrites are parenthesized/bounded; semantic type/volatile/global/pointer edits require review. |
| F13 | Iteration ranks every significant emitted instruction, including non-zero code past the target range. |
| F14 | `--image-name` and configured logical images replace filename inference. Raw, loaded, linked, catalogue, and manifest coordinates are explicit; ambiguous mappings fail closed. |
| F15 | Address-less matching collects all exact locations and rejects duplicates instead of crediting the first one. |
| F16 | Tranche limits count only `ready_verified` targets. Boundary, source, recipe, mapping and ownership exclusions are reported separately. |
| F17 | The C scanner handles split return types, K&R definitions, CRLF input, comments, strings and character literals. |
| F18 | Compiler/pass subprocesses have bounded timeouts and timed-out process groups are killed. Project hooks and diagnostics are bounded as well. |
| F19 | Direct-history write failures are surfaced in command output; SQLite writers use WAL and a busy timeout. |
| F20 | Export/query `--output -` means returned/stdout content and never creates files named `-` or `-.evidence.json`. |
| F21 | `addiu` versus non-zero-base `ori` is diagnosed as addition versus bitwise OR, not unsigned-constant spelling. |
| F22 | Plain verified ownership reports a C translation-unit interval; padding-partition wording requires actual padding evidence. |

The supplied F01–F04 scripts still demonstrate the permissive exploration oracle. That behavior
is retained deliberately; embedded strict-oracle regressions prove that the same objects cannot
obtain proof. The other supplied reproducers now show transient failure retry, safe expression
rewrites, correct hinting, robust function spans, fresh computed/`-isystem` includes, and private
compiler output.

## Added workflows

- `entry-audit`, `abi-solve`, and `structure-context` provide CFG/liveness/frame, prototype, and
  shared-layout evidence.
- `manifest-verify` rebuilds units and reports strict verdicts.
- `resolve-case`, `resolve-hard`, and `hard-queue` retain one target-digest-pinned case per
  `IMAGE:LINKED_VRAM:SIZE`; an exact case includes a strict verdict.
- `ownership-ledger` and `progress-reconcile` partition bytes without converting claims into
  credit.
- `boundary-correct` emits forward and reverse catalogue patches and separates denominator
  changes from decompilation gain; it does not apply them silently.
- `tu-session-start`/`tu-session-try` use the normal persistent session store, preserve the real
  unit, stage edits in memory, and compare the complete owned TU scope.
- `exact-reconcile` uses explicit manifest-to-logical-image bindings and opens session stores
  read-only without creating SQLite sidecars.
- `workspace-audit`/`workspace-clean` identify only known generated compiler artifacts and refuse
  tracked files, symlinks, and paths outside the project.
- `gate-policy` makes required state-transition hooks explicit and fail-closed.
- `tranche-run --resolve-hard-top N` escalates selected unresolved rows through the strict
  resolver and appends durable JSONL events.

## Coordinate model

Every mapping report preserves, rather than conflates:

```text
logical image
catalogue VRAM and section base
linked VRAM and linked base
raw/manifest ROM offset
selected loaded-image offset
image and target digests
mapping authority and competing candidates
```

Composite payloads are anchored against their raw sibling. Madden's known shifted regions are
derived from bytes, not hard-coded: Overlay 1 resolves a catalogue-to-link shift of `0x4724` and
Overlay 4 resolves `0x18A0`. Entry analysis, disassembly, sessions, drafts, scaffolds, corpus
queries, winner checks, and verification receipts use linked coordinates while inventory retains
catalogue coordinates.

## Independent validation

The final local suite contains 389 tests and passes with 12 fixture-dependent skips. The supplied
adversarial reproducers were run from disposable directories. In addition to focused synthetic
tests, `entry-audit` was run read-only across two distinct finished projects:

- Nagano (IDO-heavy): 1,470 catalogue intervals; compiler evidence answered IDO for 770, GCC for
  2, and abstained for 698. Nonstandard libultra/entry/exception-handler cases remain evidence
  findings rather than automatic deletions.
- BattleTanx (GCC/KMC-heavy): 1,738 catalogue intervals; compiler evidence answered GCC for 977,
  IDO for 182, and abstained for 579. Again, boundary/ABI findings are advisory until reconciled
  with ownership and call-target evidence.

These runs validate game-independent decoding and compiler-family separation; they do not claim
that every heuristic classification is ground truth. ABI and prototype inference explicitly
retains confidence, alternatives, and conflicts.
