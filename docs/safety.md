# Keeping the workstation usable

A sweep starts many short compiler processes from several workers.  On a machine with little
memory the failure is not an error message: memory runs out, the system swaps, the disk sits at
100% and everything stops.  The kit therefore enforces the following (`n64dk/safety.py`); each
setting is an environment variable, and `N64DK_SAFETY=off` switches all of it off.

| What | How | Setting |
|---|---|---|
| One heavy job at a time | `decompile-run`, `decompile-batch`, `source-donor` and the `training-corpus-*` builders take a machine-wide lock; a second one refuses to start (or waits with `--wait-for-lock`); a batch shares its lock with the titles it runs | `N64DK_STATE_DIR` (lock and leases; default `~/.cache/n64dk`) |
| Preflight | a heavy command does not start with less than 3 GiB available, memory pressure (PSI `some avg10`) above 10%, or less than 2 GiB free on the output disk; `--force-resources` overrides | `N64DK_MIN_AVAILABLE_MB`, `N64DK_MAX_MEMORY_PRESSURE`, `N64DK_MIN_FREE_DISK_MB` |
| Pause under pressure | before every compiler launch: while pressure is above 25% or less than 768 MB is available, wait (at most 600 s) | `N64DK_PAUSE_PRESSURE`, `N64DK_PAUSE_AVAILABLE_MB`, `N64DK_PAUSE_LIMIT_S` |
| Machine-wide worker tokens | every compiler, assembler, configured-lane step and project build command takes one `compile` token (emulated IRIX/Windows tools a `legacy` token, model calls a `model` token) from slots shared by every n64dk process on the machine, so independent invocations together never run more tools than the machine's ceiling; a waiting worker gives up after a deadline; a token held by a process that dies is released by the kernel; waits over a second and refusals go to `events.jsonl` in the state directory | `N64DK_TOKENS_COMPILE`, `N64DK_TOKENS_LEGACY` (default: the job ceiling), `N64DK_TOKENS_MODEL` (default 1), `N64DK_TOKEN_DEADLINE_S` (default 3600) |
| Memory ceiling per compiler | every compiler process gets an address-space limit; one that outgrows it fails alone. Emulators (qemu-irix reserves the 2 GB guest address space at start) get a separate, larger address-space ceiling | `N64DK_CHILD_MEMORY_MB` (default 2048; 0 for none), `N64DK_CHILD_MEMORY_MB_LEGACY` (default 8192) |
| Nested builds | a project build command runs with `MAKEFLAGS=-j1` unless the caller set its own, under one token | — |
| Two jobs on small machines | below 12 GiB of memory the default ceiling of parallel jobs is 2 | `N64DK_MAX_JOBS` |
| Leases | every heavy job registers pid, start time, process group and a heartbeat; SIGTERM unwinds it and releases lease and lock | — |
| `n64dk jobs` | lists registered jobs (`running`, `silent`, `stale`), `--cancel PID` stops a job's whole process group (SIGTERM, then SIGKILL), `--prune-stale` removes leftovers | — |
| Bounded caches | the importer's object cache and `ContentCache.prune` keep a cache under a size, least recently used first | `N64DK_CACHE_MAX_MB` (default 4096) |
| No side files on inspection | a finished run's case store is read without creating WAL/SHM files (`immutable` when no writer is active, read-only otherwise) | — |

Cancelling a job whose workers are mid-build lets the running builds finish their current
compile; `n64dk jobs --cancel` therefore sends SIGKILL to the whole group after `--grace`
seconds.
