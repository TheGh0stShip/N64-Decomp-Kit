# Autonomous matching jobs

`n64dk match-job-*` turns a source-matching loop into a durable job.  It builds every
candidate through a project's real `ProjectAdapter`, compares every owned span, records
candidate lineage and failures, and never writes generated source into the project tree.

This facility is an experiment runner, not an automatic proof of original source.  An exact
candidate still needs an independent rebuild, provenance review, complete ownership, and the
project's normal verification process.

For ad hoc sources that are currently driven through `n64dk match`, use the complementary
`match-session-*` commands documented in [matching.md](matching.md). A session accepts source
edits and flag matrices as one JSON transaction, so exploratory candidates remain in memory
and in the content cache rather than requiring a temporary-file edit before every build.

## What is implemented

The job engine provides:

- candidate source injection into an adapter-prepared temporary workspace;
- content-addressed candidate and build artifacts;
- full project/toolchain/input/target closure identities;
- exact acceptance over all adapter-owned spans;
- per-build time and diagnostic-output bounds with process-group termination;
- durable SQLite jobs, candidates, errors, residuals, events, and candidate lineage;
- deterministic generation of bounded source-spelling experiments;
- residual-directed transformation ordering;
- a diversity-preserving beam that retains distinct transformation lineages;
- interruption-safe resume, explicit budgets, status inspection, and candidate export;
- independent uncached verification of exact candidates.

The initial automatic generator deliberately covers only local spelling changes whose
evaluation point is preserved: splitting or fusing a scalar declaration/initializer,
expanding or contracting simple compound assignments, and commuting simple scalar
comparisons in `if`/`while` conditions.  The transformation registry documents broader
families, but high-risk type, alias, loop, CFG, and statement-order edits require explicit
semantic evidence and are not silently generated.

## Adapter requirements

Jobs use the same `PROJECT.toml` and `ProjectAdapter` contract as `campaign-run`.  In
addition to declaring the complete inputs, toolchain, environment, targets and owned spans,
the adapter must stage the unit source at its project-relative path beneath the temporary
workspace.  For example, project source `src/game/foo.c` must become
`WORKSPACE/src/game/foo.c` during `prepare_workspace`.

The runner replaces that staged copy with candidate bytes.  The original project source is
read to establish the baseline and monitored for drift, but is never modified.

## Start a job

```bash
n64dk --format json match-job-run path/to/PROJECT.toml \
  --unit effects/break_object \
  --state-root .n64dk/match-jobs \
  --budget 500 \
  --beam-width 16 \
  --candidates-per-parent 32
```

Important options:

| Option | Meaning |
|---|---|
| `--budget` | Maximum retained candidates, including failures and the baseline |
| `--beam-width` | Number of diverse evaluated parents expanded per search round |
| `--candidates-per-parent` | Generator fan-out bound for each parent |
| `--timeout` | Hard wall-clock limit for one build |
| `--max-output-bytes` | Kill a build whose combined stdout/stderr exceeds this size |
| `--verify` | Independently rebuild an exact result outside the build cache |

The returned `job_id` is the durable handle.  State defaults to `.n64dk/match-jobs` and
contains `jobs.sqlite`, `experiments.sqlite`, and the immutable content cache.  This state is
local build evidence and should not be committed.

At creation, the job binds an adapter/build/target context digest covering declared inputs,
toolchain files, flags, command, allowed environment, oracle policy, ownership and target
bytes.  Resume refuses a changed context.  Start a new job after any such change so evidence
from different compilation problems is never mixed into one lineage.

## Resume and inspect

```bash
n64dk --format json match-job-run path/to/PROJECT.toml \
  --unit effects/break_object \
  --state-root .n64dk/match-jobs \
  --job-id JOB_ID
```

```bash
n64dk --format json match-job-status JOB_ID \
  --state-root .n64dk/match-jobs --candidates
```

Terminal states are:

- `exact`: at least one candidate equals every owned target span;
- `exhausted`: available qualified generators produced no unseen source;
- `budget-exhausted`: the configured candidate budget was consumed;
- `interrupted`: the process stopped unexpectedly and may be resumed.

Compile failures and limits are candidate results with `status=failed`; they do not vanish
or count as evidence of a match.  Re-running a job skips source identities already recorded.

## Export without applying

```bash
n64dk match-job-export JOB_ID build/candidates/foo.c \
  --state-root .n64dk/match-jobs
```

The command exports the best exact-or-lowest-score candidate and a neighboring
`foo.c.evidence.json`.  Select a specific candidate with `--candidate-id`.  Export never
changes the project source and the evidence explicitly marks the result as non-proof-grade.

Review the candidate, create a normal project patch, and run the project's own build and
matching checks.  Do not copy an exported file over a dirty source file without reviewing
the diff.

## Evidence and scoring

For code spans, the runner stores the aligned instruction diff, score, residual signature,
and ranked mechanism diagnoses.  Non-code spans use exact byte mismatches.  `exact` is raw
byte equality and exact length for every owned span; the diagnostic score cannot override
it.

Residual mechanisms influence which source family is tried first.  Register-allocation and
reload evidence prioritizes lifetime/expression boundaries; scheduling evidence prioritizes
compound and source-order shapes; semantic/CFG evidence points toward structural families.
Unsupported families are recommendations only, so the job may stop at `exhausted` rather
than make an unjustified edit.

The beam first retains a best candidate from each transformation lineage, then fills its
remaining slots by score.  This prevents one abundant source shape from immediately
eliminating all alternatives.  The current score remains a heuristic for exploration; it is
not a semantic-distance metric and is never used for final acceptance.

## Verification boundary

`--verify` performs a fresh build and checks that its complete encoded owned-span artifact
equals the cached artifact.  The resulting receipt intentionally says
`production_approved=false`.  Production approval additionally requires:

1. qualified compiler, assembler and linker identities;
2. a complete observed or enforced dependency closure;
3. trusted target extraction and complete ownership, including shared data;
4. genuine-C or positively evidenced handwritten-assembly provenance;
5. no function-specific output rewriting;
6. a clean project build and its independent matching checks.

## Current limitations

- Candidate execution is sequential; the cache and persistent format are ready for leased
  workers, but a multi-process lease backend is not yet implemented.
- The automatic source generator is intentionally small and lexical.  It does not regenerate
  whole files or discard macros and comments.
- Semantic equivalence is based on the narrow generator contracts, not a general C verifier.
- Residual diagnoses are heuristic and may abstain.  Register mappings do not yet prove
  whole-function liveness correspondence.
- Adapter code and target extraction remain trusted.  Independent verification establishes
  reproducibility, not absence of a malicious or incorrect adapter.
- A build workspace byte quota is not yet enforced; build time and diagnostic output are.

These limits are explicit so a useful exploratory system cannot accidentally be presented as
an original-source proof system.

## Architecture

`n64dk.match.runner` owns isolated execution, build closure validation, exact comparison,
and independent verification.  `n64dk.match.campaign` owns build caching and experiment
creation.  `n64dk.match.jobs` owns persistent job state, candidate source blobs, generation,
beam selection, resume, and failure retention.  `n64dk.match.experiments` remains the
append-only causal record of successful compiler/oracle executions.

The separation is intentional: other planners can submit candidate bytes through
`UnitRunner.evaluate(..., candidate_source=...)` without bypassing the authentic oracle.
