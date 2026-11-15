# Round 5 integration: unattended decompilation

Round 5 adds a bounded unattended path without weakening the kit's proof boundary. The main
entry point is `decompile-run`; lower-level commands remain available for inspection and replay.

## What is available

- Logical image registry and coordinate explanations (`image-registry`, `image-address`).
- Evidence-only boundary solving and reversible operations (`boundary-solve`).
- Cross-project donor indexing/transplant with strict target verification (`transplant-scan`).
- AST-backed, typed, lifetime, volatile, pointer, expression, and control-flow variants.
- Durable per-function resolution cases, compiler-recipe evidence, hard queues, and JSONL events.
- Byte ownership ledgers and reconciliation reports.
- `decompile-run`, which checkpoints boundary audit, donor recovery, resolution, strict queue, and
  ownership ledger stages.

`exact` always means a current strict verifier receipt. Byte-identical output that still needs a
symbol or section declaration is `assumed`, never exact. A manifest is an ownership claim, not
proof that the source was rebuilt. Donor addresses or section bases inferred from the target bytes
are diagnostics only and are never fed back into the strict verifier.

## Running it

```sh
n64dk doctor --project . --profile matching
n64dk --format json decompile-run \
  --project . --all-images --out .n64dk/decompile-run \
  --jobs 16 --workers 0 --budget 200
```

Stage checkpoints include the image digest, mappings, catalogue, manifests, and run settings.
Changing those inputs invalidates the checkpoint. Writes are atomic. A failed stage produces an
`incomplete` final status and is listed in `failed_stages`; it cannot contribute exact winners.
Generated output is rejected inside the source tree except below `.n64dk` unless
`--allow-project-output` is supplied explicitly.

Worker processes emit one append-only JSON record per event. Automatic process count derives from
current CPU and available memory; `--worker-memory-mb` and `--memory-reserve-mb` make constrained
hosts reproducible. Interrupting the parent terminates and reaps its workers.

## Madden 64

Copy the image and run tables from [`madden-images.example.toml`](madden-images.example.toml) into
Madden's `n64dk.toml`. They deliberately select raw overlays and encode the two known coordinate
corrections:

- Overlay 1: catalogue-to-link shift `0x4724`, raw delta `0x8008A8E0`.
- Overlay 4: catalogue-to-link shift `0x18A0`, raw delta `0x800C4F48`.

The integrated smoke trial audited all 950 Overlay 1 and 400 Overlay 4 catalogue rows, then ran
bounded resolver trials through both shifted mappings. Both completed without a mapping or stage
error. Use the same configuration for larger runs; do not substitute composite images and guess a
delta.

## Verification performed during integration

- Full suite: 527 tests passed, 17 skipped.
- Real donor transplant test: BattleTanx to Nagano passed under the IDO toolchain.
- Fresh Nagano sample: 40/40 selected functions were strictly exact, 320 bytes, in 7.5 seconds;
  all 40 entered the strict queue and none were assumed.
- Madden boundary/ledger smoke: Overlay 1 and Overlay 4 completed in 1.2 seconds with no failed
  stage; bounded shifted-coordinate resolver trials also completed.

The supplied large benchmark reports remain historical measurements from the pre-integration pack.
They are useful performance evidence, but their donor counts are not release proof because the
integration deliberately tightened circular symbol/section handling. Re-run a title to obtain
current figures.

## Optional and unverified capabilities

- `pycparser` enables AST transformations (`pip install -e '.[search]'`). Without it, those
  families are skipped and the rest of the resolver remains available.
- Custom EGCS and GCC 2.8 recipes are configuration examples until exercised with those exact
  toolchains and a known title.
- C++ front ends, IDO `.bss` ordering, a permuter near-match stage, and objdiff interchange remain
  future work; the command does not claim those capabilities.
