"""Exact-candidate reconciliation and workspace litter commands."""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

from ..cli import command
from ..match import reconcile as rec


def discover_manifests(project: Path, state_dir: str = ".n64dk") -> list[Path]:
    excludes = set(rec.DEFAULT_EXCLUDES) | {state_dir}
    found = []
    for root, dirs, files in os.walk(project):
        dirs[:] = sorted(d for d in dirs if not rec._excluded(d, excludes))
        found += [Path(root) / f for f in sorted(files)
                  if f.endswith(".tsv") and rec.is_manifest(Path(root) / f)]
    return found


def _safe_name(text) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text or "unnamed"))


def _reconcile_args(p):
    p.add_argument("--project", required=True)
    p.add_argument("--manifest", action="append", default=[])
    p.add_argument("--store", action="append", default=[])
    p.add_argument("--bind", action="append", default=[], metavar="MANIFEST=IMAGE",
                   help="explicit manifest-to-logical-image binding (repeatable)")
    p.add_argument("--export-dir")


@command("exact-reconcile", "Classify exact session candidates against manifests; list stranded ones")
def exact_reconcile(args):
    project = Path(args.project).resolve()
    manifests = [Path(m) for m in args.manifest] or discover_manifests(project)
    bindings = {}
    config = project / "n64dk.toml"
    if config.is_file():
        configured = tomllib.loads(config.read_text()).get("inventory", {}).get("manifests", {})
        if isinstance(configured, dict):
            for image, paths in configured.items():
                for value in paths:
                    path = (project / value).resolve()
                    bindings[str(path)] = image
                    bindings[str(project / value)] = image
    for value in args.bind:
        manifest, separator, image = value.partition("=")
        if not separator or not manifest or not image:
            raise ValueError("--bind requires MANIFEST=IMAGE")
        bindings[str(Path(manifest))] = image
        bindings[str(Path(manifest).resolve())] = image
    scan = rec.find_stores(project, [Path(s) for s in args.store])
    report = rec.stranded_exacts(project, manifests, scan, image_bytes=rec.file_image_bytes,
                                 bindings=bindings)
    result = {k: report[k] for k in ("summary", "exact_candidates", "uninterpreted",
                                     "stores", "skipped", "queue", "unbound_manifests")}
    result["manifests"] = len(manifests)
    if args.export_dir:
        out = Path(args.export_dir).resolve()
        state = project / ".n64dk"
        if out.is_relative_to(project) and not out.is_relative_to(state):
            return {"error": f"--export-dir must be outside {project} or under {state}"}
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for item in report["queue"]:
            text = rec.export_source(Path(item["store"]), item["session_id"], item["candidate_id"])
            if text is None:
                item["export"] = None
                continue
            target = out / f"{_safe_name(item['name'])}__{item['candidate_id'][:12]}.c"
            target.write_text(text)
            item["export"] = str(target)
            written.append(str(target))
        (out / "queue.json").write_text(json.dumps(report["queue"], indent=1, default=str))
        result["exported"] = written
    return result


exact_reconcile.arguments = _reconcile_args


def _audit_args(p):
    p.add_argument("--project", required=True)


@command("workspace-audit", "Report compiler dumps and stray objects outside the state directory")
def workspace_audit(args):
    return rec.workspace_audit(Path(args.project))


workspace_audit.arguments = _audit_args


def _clean_args(p):
    p.add_argument("--project", required=True)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--generated-only", action="store_true", help="accepted; the only mode")


@command("workspace-clean", "Remove untracked generated files (dry-run unless --apply)")
def workspace_clean(args):
    project = Path(args.project)
    return rec.workspace_clean(project, rec.workspace_audit(project)["plan"], apply=args.apply)


workspace_clean.arguments = _clean_args
