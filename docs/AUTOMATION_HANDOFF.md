# Automated matching worker handoff

Use this workflow when bringing a project-adapter unit closer to an exact match.

## Operating rules

1. Inspect the working tree first. Never overwrite existing changes.
2. Validate the ROM, unit, owned ranges, toolchain fingerprint, and baseline before
   interpreting a score.
3. Start or resume a job instead of reproducing its compile loop manually.
4. Treat residual diagnoses as hypotheses. Inspect the actual diff before proposing a risky
   type, alias, CFG, loop, volatile, or evaluation-order change.
5. Use a separate candidate file or structured `transform-apply` proposal for edits outside
   the built-in generator.
6. Submit candidate bytes through `UnitRunner.evaluate`; never patch compiler output or the
   temporary object.
7. An exact score is exploratory until independent verification and project-native checks
   pass.

## Standard invocation

```bash
n64dk --format json match-job-run PROJECT.toml --unit UNIT \
  --state-root .n64dk/match-jobs --budget 500 --beam-width 16 --verify
```

If interrupted, reuse the returned identifier:

```bash
n64dk --format json match-job-run PROJECT.toml --unit UNIT \
  --state-root .n64dk/match-jobs --job-id JOB_ID --verify
```

Inspect all attempts with:

```bash
n64dk --format json match-job-status JOB_ID \
  --state-root .n64dk/match-jobs --candidates
```

## When automation exhausts

Read the best candidate's `residual.spans[].diagnoses`, aligned diff, and candidate lineage.
Then formulate one causal hypothesis with:

- the compiler mechanism expected to change;
- the exact residual region expected to improve;
- semantic evidence permitting the edit;
- a stop condition if the prediction fails.

Use `transform-list` to find a relevant family and `transform-apply` for a digest-pinned,
reversible proposal. Evaluate the resulting bytes through the runner. Do not infer that an
edit is valid merely because its score improves.

Useful mechanism routing:

| Diagnosis | Investigate |
|---|---|
| boundary/ownership | function extent, overlay, padding, literals, jump-table ownership |
| toolchain/flags | compiler build, ABI, ISA, optimization, assembler and normalizer |
| semantics/CFG | operations, calls, loop count, branches, switch topology |
| types | widths, signedness, promotions, casts, pointer element type |
| register allocation | declaration order, scope, lifetime, temporaries, call-crossing values |
| reload/frame | address-taken locals, aliases, register pressure, spill lifetime |
| scheduling/delay slot | dependencies, statement order, expression boundaries |
| literal ownership | constant spelling, pooling, section base, shared-data owner |

## Completion report

Report:

- job ID and state directory;
- candidate and experiment IDs;
- attempts, failures, cache reuse, and elapsed costs;
- owned spans verified;
- residual before and after;
- exact versus merely best-scoring status;
- independent-verification result;
- provenance and ownership obligations still open;
- exported candidate/evidence paths;
- project-native commands run and their results.

Never report a completed match when only the diagnostic score reached zero, only `.text`
agrees, an output normalizer forced equality, or independent verification was not run. Use
“exploratory exact candidate” until all proof obligations are closed.
