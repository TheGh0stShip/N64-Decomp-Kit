# Where an end-to-end run spends its time, and whether native code would help

Status: measured. Every run was on the lab commit named in `bench/profile` and `bench/final`, under
the heavy-job wrapper (2 workers), with `decompile-run`'s stage profiles (`profile.jsonl`).

## Profiles

| Title | Kind | Wall | resolve share of wall | Parent Python CPU | External tools CPU | Kit Python in forked workers |
|---|---|---:|---:|---:|---:|---:|
| SM64 | IDO, source tree + SDK donors | 364 s | 87% | 43 s | 589 s (66%) | 259 s (29%) |
| Dr. Mario 64 | KMC GCC, source tree + SDK donors | 311 s | 92% | 27 s | 363 s (44%) | 439 s (53%) |
| Batman Beyond | blind, low coverage | 1,326 s | 80% (calibrate 19%) | 15 s | 2,136 s (56%) | 1,671 s (44%) |
| Armorines (65 functions) | SN, blind, debug records | 117 s | 62% (calibrate 30%) | 24 s | 107 s | 107 s |

Tool CPU by family (Batman): IDO under qemu 608 s, m2c 567 s, KMC/GCC 329 s, host cpp 251 s,
SN cc1n64 under wibo 88 s. Builds requested against distinct objects: 133,785 against
~124,000; 56,009 distinct source texts; cpp ran 50,437 times. The survey (`decompile-init`) is
separate. On Armorines (16 MB) it took 120 s, 74% of that in asset and codec probing.

## Where the kit's own Python went

A sampler over all threads in a bounded one-worker Dr. Mario 64 run (`bench/profile`) charged
**30% of the kit's busy Python to one function**: every build re-read and re-hashed every compiler
binary for its cache identity. Caching the digest by file size, mtime and inode (the identity is
unchanged; a changed tool still changes it) cut that run from 423 s to 363 s with all 400 case
outcomes identical. What remains is spread across orchestration: building candidates, starting
tools, polling tokens, writing the case store and temporary files. MIPS decoding, normalisation
and scoring together were under 1% of samples.

## Candidates

The rule applied: native code only for a subsystem that uses at least 10% of an important
end-to-end run, or for a reliability limit Python cannot enforce.

### 1. Resource and process supervisor: not needed

- **Current cost:** negligible.
- **Reliability:** the remaining gap is a parent killed by SIGKILL or the OOM killer. Tools run in
  their own sessions, so nothing in the parent can clean them up afterwards. Today the heavy-job
  wrapper's systemd scope kills the whole cgroup. Without the wrapper, Python can still close the
  gap with `prctl(PR_SET_PDEATHSIG, SIGKILL)` set in each tool's child before `exec` (ctypes,
  Linux). No native executable is needed.
- **Recommendation:** add the parent-death signal in `safety.run_tool`, `pipeline._run` and
  `custom_pipeline`, with a test that kills the parent with SIGKILL and checks the tool is gone.

### 2. MIPS decode, normalisation, scoring and corpus search: rejected

Under 1% of sampled kit Python, and far under 10% of the run. A native rewrite would save nothing
measurable.

### 3. Memory-mapped ROM scanning and binary-record parsing: rejected

Debug-record scanning took 0.5 s and the function catalogue 1.7 s of a 120 s survey on a 16 MB
ROM. Neither reaches 10% of anything.

### 4. Codecs (asset probing in the survey): deferred

- **Cost:** 74% of the survey, but the survey runs once per title. Against survey plus run for a
  blind title (Batman: about 100 s plus 1,326 s) that is about 6%, under the bar.
- **Reconsider when:** a title's survey dominates its run, as with very large ROMs and small code.
- **If built:** an isolated executable taking (codec, offset, length) and returning
  (decoded length, consumed length, status) as versioned JSON lines. The Python codecs stay as the
  differential oracle on every fixture.

### 5. Emulated IDO: the largest single tool cost, but not a Rust question

IDO under qemu is 16% of Batman's CPU and about 50% of SM64's tool CPU. The native answer is a
statically recompiled IDO, a toolchain component, not kit code. It needs:

- provenance (a public recompilation project, its licence, the exact compiler build it was made
  from);
- an identity probe proving its objects are byte-identical to the qemu build on the full probe
  suite and on a title's verified functions;
- registration as a recipe component with qemu as the fallback.

The component catalogue and the probe suite already provide the identity check
(`docs/toolchain-components.md`).

## Measured optimisations that are not native code

All are measured or measurable with the existing profiles, and none changes outcomes:

1. **Tool digest cache.** Done: −14% wall on the bounded run, outcomes identical.
2. **Host preprocessing once per context.** Mutated variants of a draft share the context header
   and differ only in the function text, which m2c writes without macros. Preprocess the context
   once per (context, recipe) and append the function text. Expected saving: most of cpp's 50,437
   runs (Batman 251 s CPU, 6.6%). Test: preprocessed text equals the separate preprocessing for
   every draft in a corpus sample.
3. **m2c in process.** m2c is Python, started as a subprocess about 4,000 times per Batman run
   (567 s CPU, about 140 ms each, much of it interpreter start-up and imports). A persistent m2c
   worker process fed over a pipe keeps the isolation and drops the start-up. Expected: half of m2c's
   CPU. Test: identical drafts on the corpus.
4. **Duplicate builds.** About 7% of requested builds repeat an object already built in the run.
   The object cache already serves them, so the remaining cost is per-request overhead only.
