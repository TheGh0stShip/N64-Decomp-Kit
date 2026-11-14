# Autonomous matching implementation report

Date: 2026-11-14

## Outcome

The kit now contains an executable, persistent version of the repetitive decompilation loop:

```text
baseline → diagnose → generate bounded candidate → isolated build
         → compare all owned spans → retain evidence → select diverse parents → repeat
```

The implementation is deliberately an evidence-driven search foundation rather than an
unrestricted C rewriter.  It automates the mechanical compile/oracle loop and a qualified
local source grammar while leaving high-risk semantic reconstruction available through the
existing explicit transformation proposal workflow.

## Delivered components

### Candidate-aware authentic runner

`UnitRunner.evaluate` accepts candidate bytes or text.  The adapter first stages its normal
temporary build tree; the runner then replaces only the staged project-relative unit source.
The source in the project tree remains unchanged and continues to be monitored as part of
the baseline input closure.

Compiler execution now has a wall-clock timeout, combined-output limit, private process
group and group termination.  Output is written to a temporary disk-backed log rather than
captured without a memory bound.  Input and toolchain drift checks still occur before and
after the build.

### Persistent job engine

`n64dk.match.jobs` adds:

- `JobConfig`, `SourceCandidate`, and `GeneratedCandidate` records;
- a WAL-mode SQLite job, candidate and event store;
- candidate source storage in the existing immutable content cache;
- baseline creation and resumable job execution;
- a build/target context digest that rejects stale resume after any declared change;
- compile failure and timeout retention;
- candidate-to-candidate and experiment lineage;
- explicit candidate, beam and fan-out budgets;
- exact, exhausted, budget-exhausted and interrupted states;
- exact-candidate independent verification.

The job database and experiment ledger have different roles.  The job database retains every
search outcome, including builds that never produced an artifact.  The experiment ledger
retains causal observations that reached the build/oracle boundary.

### Search behavior

The implemented candidate grammar currently generates deterministic one-site variants for:

- declaration/initializer split and fusion;
- simple-name compound assignment expansion and contraction;
- simple scalar comparison commutation in an `if` or `while` condition.

Generation deduplicates candidates by source SHA-256.  Residual mechanisms rank relevant
transformation families first.  Parent selection preserves one best candidate per observed
transformation lineage before filling remaining beam slots by diagnostic score.

This is not a Cartesian-product flag and syntax search.  Each candidate has a parent and a
causal hypothesis.  The content cache prevents recompiling an identical source under an
identical build closure.

### CLI

Three commands were added:

- `match-job-run`: create or resume and optionally independently verify;
- `match-job-status`: inspect summary and full candidate history without compiling;
- `match-job-export`: write a selected candidate plus evidence without touching project
  source.

`campaign-run` and `match-job-run` expose compiler timeout and output limits.

### Documentation

- `docs/autonomous-matching.md`: operator usage, adapter contract, state, evidence,
  verification boundary, and limitations.
- `docs/AUTOMATION_HANDOFF.md`: commands, reasoning rules, residual routing, and the
  required completion report for automated matching workers.
- This report: implementation scope and validation record.
- `README.md` and `docs/ARCHITECTURE.md`: command and module discovery.

## Validation

Focused tests cover:

- generated source is observed in the temporary workspace;
- original project source is unchanged;
- complete owned-span equality remains the acceptance oracle;
- deterministic candidate generation;
- exact-candidate discovery and persisted lineage;
- build failure retention and duplicate-free resume;
- timeout termination;
- excessive-output termination;
- existing cache, drift, ownership and independent-verification behavior.

Validation command:

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

Result at implementation time:

```text
Ran 233 tests in 33.714s
OK (skipped=11)
```

## Proof boundary

An exact job result means that the candidate produced exact bytes and lengths for every span
owned by the adapter under the recorded closure.  It does not by itself prove:

- complete dynamic dependency capture;
- trustworthy adapter or target extraction;
- correct ownership of shared ranges;
- original-source provenance;
- absence of project-specific output rewriting;
- project-wide runtime correctness.

Independent verification intentionally retains `production_approved=false`.  The exported
evidence repeats this distinction.

## Deferred work

The following remain valuable next milestones, but are not represented as completed:

- multi-process candidate leases and parallel workers;
- workspace disk quotas and OS-level CPU/memory limits;
- source-preserving parser support for broader edits;
- semantic certificates or SMT checks for type, alias, statement-order, CFG and loop edits;
- block/dataflow-aware residual vectors and compiler-pass dump ingestion;
- candidate combinations beyond iterative one-site descendants;
- project fixture measurements of exact matches per CPU-hour;
- a visual workbench for lineage and residual-region comparison.

These are stated explicitly to prevent the existence of an autonomous loop from being
mistaken for complete automation of semantic decompilation.
