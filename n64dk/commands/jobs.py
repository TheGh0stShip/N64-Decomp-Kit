"""``jobs``: the heavy n64dk jobs registered on this machine, and stopping one."""
from __future__ import annotations

from ..cli import command


@command("jobs", "List the heavy n64dk jobs running on this machine (stale ones marked), cancel one with its "
                 "whole process group, or remove stale records")
def jobs(args):
    from .. import safety
    if args.cancel:
        return safety.cancel(args.cancel, grace=args.grace)
    found = safety.leases(stale_after=args.stale_after)
    removed = 0
    if args.prune_stale:
        from pathlib import Path
        for record in found:
            if record["state"] == "stale":
                Path(record["lease"]).unlink(missing_ok=True)
                removed += 1
        found = [record for record in found if record["state"] != "stale"]
    return {"jobs": [{key: record.get(key) for key in ("pid", "pgid", "state", "command", "argv", "cwd", "started",
                                                        "heartbeat", "paused")} for record in found],
            "stale_removed": removed, "memory": safety.preflight(safety.state_dir())}


def _args(p):
    p.add_argument("--cancel", type=int, metavar="PID", help="stop this job: SIGTERM to its process group, then SIGKILL")
    p.add_argument("--grace", type=float, default=10.0, help="seconds between SIGTERM and SIGKILL")
    p.add_argument("--prune-stale", action="store_true", help="remove the records of jobs that are gone")
    p.add_argument("--stale-after", type=float, default=300.0,
                   help="seconds without a heartbeat after which a live job is reported silent")


jobs.arguments = _args
