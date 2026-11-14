"""Inventory research artifacts without counting files as completed research rounds."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import defaultdict
from pathlib import Path


def inventory(roots):
    records = []
    seen = set()
    missing = []
    for value in roots:
        root = Path(value).resolve()
        if not root.exists():
            missing.append(str(root))
            continue
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            if not path.is_file() or path.suffix not in (".md", ".tsv", ".json", ".jsonl", ".txt", ".csv"):
                continue
            if path.is_symlink() or any(part in (".git", ".venv", "node_modules", "__pycache__")
                                        for part in path.parts):
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            data = path.read_bytes()
            row = {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                   "bytes": len(data), "review_status": "unreviewed", "records": None,
                   "round_ids": [], "error": None}
            try:
                text = data.decode("utf-8-sig")
                if path.suffix in (".tsv", ".csv"):
                    parsed = list(csv.DictReader(io.StringIO(text), delimiter="\t" if path.suffix == ".tsv" else ","))
                    row["records"] = len(parsed)
                    row["round_ids"] = [r["round_id"] for r in parsed if r.get("round_id")]
                elif path.suffix == ".jsonl":
                    row["records"] = sum(1 for line in text.splitlines() if line.strip() and json.loads(line) is not None)
                elif path.suffix == ".json":
                    parsed = json.loads(text)
                    row["records"] = len(parsed) if isinstance(parsed, list) else None
                    row["top_level_keys"] = sorted(parsed) if isinstance(parsed, dict) else []
            except (ValueError, UnicodeError, csv.Error) as error:
                row["error"] = str(error)
            records.append(row)
    groups = defaultdict(list)
    for row in records:
        groups[row["sha256"]].append(row["path"])
    return {"artifacts": records, "artifact_count": len(records), "missing_roots": missing,
            "identical_artifacts": [paths for paths in groups.values() if len(paths) > 1],
            "completed_rounds": None,
            "note": "Record counts and round labels do not prove executed searches or validated findings."}
