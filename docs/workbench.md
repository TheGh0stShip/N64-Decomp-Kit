# Matching workbench

The workbench turns the kit's inventory, session, corpus and provenance primitives into
bounded operations. It does not weaken exact-match proof requirements or silently edit a
project.

## Environment and capabilities

```bash
n64dk doctor --project . --profile matching
n64dk doctor --project . --profile gpu-research --fix-user
n64dk compiler-capabilities --project .
n64dk compiler-capabilities --project . --invalidate --pipeline kmc --option=-fno-example
```

Doctor separates required matching/build dependencies from optional corpus, GPU and asset
analysis capabilities. Paths are resolved before they enter cache or provenance identities.
Compiler options are cached individually by toolchain identity, pipeline stage, option and
argument; rejection of one experiment never invalidates its inherited recipe.

## Authoritative ownership and boundaries

Generic and image-qualified manifests are translation-unit intervals. Catalogue functions
inside a verified aggregate C interval are `manifest_exact_member`; a row equal to the unit is
`manifest_exact_unit`. Assembly has equivalent unit/member states but is not offered as a
quick-win C candidate. Partial overlaps and duplicate owners are conflicts.

```bash
n64dk match-inventory --project . --assert-consistent
n64dk match-inventory --project . --image resident --state remaining --count-only
n64dk match-inventory --project . --image overlay5 --state unowned \
  --fields name,vram,size,owner --limit 50
n64dk boundary-audit FUNCTION --project . --image IMAGE --strict
n64dk boundary-correct FUNCTION --project . --merge-with NEXT --output correction.json
```

Boundary evidence includes Splat metadata, authoritative ownership, incoming CFG edges,
fallthrough, stack-frame establishment, save/restore slots, semantic saved-register live-ins,
call targets and delay-slot ownership. Corrections report numerator and denominator changes
separately and remain non-applying.

## Bounded experiments

```bash
n64dk prototype-matrix SESSION --symbol helper --jobs 16
n64dk register-lifetime-explore SESSION --jobs 16
n64dk match-matrix SESSION matrix.yaml --jobs 16
n64dk frontier-synthesize SESSION --candidate A --candidate B --budget 32
n64dk compiler-explain SESSION --candidate A --candidate B --passes greg,lreg,sched
n64dk residual-attribution SESSION --candidate A
n64dk control-flow-explore SESSION --jobs 16 --budget 32 --stop-on-exact
n64dk clone-family-transfer --source-session A --target-session B
```

Matrices deduplicate source and object equivalence classes through the session engine. ABI
variants use narrowing evidence from shifts, masks and call sites. Lifetime exploration
records whether formal reuse, carrier ownership, scope shortening or return convergence
actually changed the object. Complementary synthesis constructs only the bounded cross-product
of source dimensions that differ between retained frontier candidates.

Branch residuals are decoded against retained target bytes and classified as same-block,
loop-latch, loop-exit, function-epilogue, shared-cleanup, or call-skipping join. The explorer
tests `goto` shared exit, `break`, `continue`, inverted and skip-body `if`, early return,
`while`, `do while`, `for`, and labelled-loop forms. Candidates changing residuals outside
the original block set are marked ineligible for the frontier.

## Translation units and families

```bash
n64dk family-session-start --project . --unit src/code/file.c --functions A,B,C
n64dk family-session-try FAMILY --proposal proposal.json --sessions A=SESSION1,B=SESSION2
n64dk tu-session-start src/code/file.c --project . --manifest-row config/matching.tsv:42
n64dk tu-session-try TU --project . --proposal edit.json --verify-command 'make match-unit'
```

The retained context includes source identity, declaration order and manifest evidence. TU
candidates are staged outside the project. Verification can cover every owned text/data range
and relocation, preventing a local improvement from silently regressing siblings.

## Indexed retrieval

```bash
n64dk code-query --project . --symbol helper --type-conflicts
n64dk asm-query --project . --sequence jal,move,sll,sra,bnel --all-projects
n64dk negatives-query --project . --residual branch-likely --compiler kmc
n64dk workbench-snapshot --project . --function FUNCTION --image IMAGE
```

Search results distinguish manifests, catalogues, definitions, declarations, candidates and
references. Structural assembly search indexes opcode sequences separately from register
names. Negative experiments are checked before allocating compilation work.

## Integration, gates and scheduling

```bash
n64dk integration-audit --project . --exact-unintegrated
n64dk integrate-winner CANDIDATE --session SESSION --project . \
  --verify-twice --output .n64dk/integration/CANDIDATE
n64dk gate-delta baseline.json current.json
n64dk scheduler-plan --project . --jobs 14
n64dk scheduler-status PLAN --project .
n64dk project-gate --project . --hook full_gate --machine
```

Only `exact_current_target` observations enter integration audit. Integration recompiles in
fresh directories, records target/source/compiler identities and prepares source, manifest,
catalogue, progress and provenance updates without applying them. Scheduler plans persist
discovery, exploitation, family propagation, recovery, boundary and verification lanes and
report selected, compiled, unique-source, unique-object, exact and frontier metrics.

Projects declare hooks and qualified interpreters in `n64dk.toml`:

```toml
[workbench.hooks]
attack = "make attack"
report = "make report"
affected_gate = "make match-overlay2"
full_gate = "make match-c"
project_tests = "make check"

[workbench.python]
matching = "../n64-decomp-kit/.venv/bin/python"
project_test = "../n64-decomp-kit/.venv/bin/python"

[workbench.dependencies]
project_test = ["numpy"]
gpu = []
```

Every hook receives a resolved virtual-environment path. Doctor probes each dependency with
the interpreter selected for that profile and emits user-local package commands. Ordinary
matching does not require optional GPU or host-compiler packages.

Canonical mapping reports raw-overlay and resident-composite offsets together. Overlay 2
address `0x800AEF84`, for example, maps to raw `0x246A4` and composite `0xAFB84`; manifest
rows always use the raw project offset. Investigation tries both mappings and retains
disassembly, source, callers and competing-layout evidence even when preflight rejects both.

`n64dk self-test` always supplies the kit root as unittest's top-level directory, so absolute
test discovery behaves the same from every working directory.

## Implementation coverage

The workbench release covers the complete requested surface rather than only its first
correctness slice:

| Area | Implemented interface |
|---|---|
| 1. Aggregate ownership | `match-inventory`, unit/member ownership and byte-level consistency |
| 2. Saved-register entry analysis | stack save/restore dataflow and path evidence |
| 3. Capability cache | `compiler-capabilities`, option/stage/toolchain keys |
| 4. Historical identity | stable observation identities and exact/stale/normalized classes |
| 5. Environment diagnosis | `doctor` profiles and user-local remediation |
| 6. Canonical environments | resolved prefixes and qualified hook interpreters |
| 7. Query consistency | project/state/database/limit/offset/summary selectors |
| 8. Bounded output | fields, filters, cursors, counts and artifact references |
| 9. ABI exploration | `prototype-matrix` |
| 10. Register lifetime | `register-lifetime-explore` |
| 11. Complementary frontiers | `frontier-synthesize` |
| 12. TU and family context | `tu-session-*` and `family-session-*` |
| 13. Declarative matrices | `match-matrix` |
| 14. Compiler passes | `compiler-explain` and retained pass artifacts |
| 15. Residual attribution | `residual-attribution` |
| 16. Unified source search | `code-query` |
| 17. Structural assembly search | `asm-query` |
| 18. Negative retrieval | `negatives-query` and pre-experiment session lookup |
| 19. Winner transaction | `integrate-winner` with two independent builds |
| 20. Gate deltas | `gate-delta` and `project-gate` |
| 21. Splat evidence | inventory and boundary dossiers retain Splat evidence |
| 22. CFG fragment exclusion | strict entry, fallthrough, live-in and delay-slot checks |
| 23. Boundary transactions | `boundary-audit` and `boundary-correct` |
| 24. Persistent scheduling | `scheduler-plan` and `scheduler-status` lanes |
| 25. Tranche quality | inventory/compile/object/frontier/wall-time metrics |
| 26. One-call context | `workbench-snapshot` |
| 27. Transaction semantics | transaction results/best, session best and object classes |
| 28. Test robustness | `self-test` with an explicit top-level directory |

The exact-winner follow-up is also covered: semantic branch targets and bounded control-flow
forms; one canonical raw/composite resolver; generated raw-offset manifest rows; configurable
regeneration/build/test hooks; qualified dependency profiles; graceful dossiers; archived
source lookup; direct-match result ingestion; clone-family transfer; compact gate artifacts;
and explicit target, compiler, source, section and relocation evidence. Integration snapshots
the pre-existing worktree and restores it on failure, including pre-existing tracked and
untracked edits.
