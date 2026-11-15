"""Byte ownership and progress reconciliation commands."""
from __future__ import annotations

import json
from pathlib import Path

from ..cli import command
from ..match.inventory import build as build_inventory
from ..match.ownership import build, progress


def _args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--image")
    p.add_argument("--all", action="store_true", help="include every byte segment")
    p.add_argument("--output")


@command("ownership-ledger", "Partition every catalogue code byte by verified ownership state")
def ownership_ledger(args):
    inventory = build_inventory(args.project); result = build(inventory, args.image)
    if not args.all:
        for section in result["ledgers"]: section.pop("segments", None)
    if args.output and args.output != "-":
        path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["written"] = str(path)
    return result


ownership_ledger.arguments = _args


@command("progress-reconcile", "Separate verified progress from claims and denominator corrections")
def progress_reconcile(args):
    inventory = build_inventory(args.project); ledger = build(inventory, args.image)
    result = progress(inventory, ledger)
    result["ownership_problems"] = ledger["problems"]
    if args.output and args.output != "-":
        path = Path(args.output); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["written"] = str(path)
    return result


progress_reconcile.arguments = _args
