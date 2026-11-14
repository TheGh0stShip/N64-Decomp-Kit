"""Inspect fenced handoff artifacts as inert text; never import or execute them."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath


def inspect_handoff(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    lines = data.decode("utf-8").splitlines(keepends=True)
    heading = None
    fence = None
    content = []
    artifacts = []
    seen = set()
    payloads = {}
    start = 0
    for number, line in enumerate(lines, 1):
        stripped = line.rstrip("\r\n")
        if fence is not None:
            if stripped == fence:
                payload = "".join(content).encode("utf-8")
                name = heading or ""
                candidate = PurePosixPath(name)
                safe = bool(name and not candidate.is_absolute() and ".." not in candidate.parts
                            and "\\" not in name and ":" not in name)
                artifacts.append({"name": name, "start_line": start, "end_line": number,
                                  "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                                  "safe_relative_name": safe, "duplicate_name": name in seen,
                                  "review_status": "unreviewed"})
                seen.add(name)
                payloads.setdefault(name, payload)
                fence = None
                heading = None
            else:
                content.append(line)
        elif stripped.startswith("### "):
            heading = stripped[4:].strip()
        elif stripped.startswith("```") and heading is not None:
            count = len(stripped) - len(stripped.lstrip("`"))
            fence = "`" * count
            start = number + 1
            content = []
    if fence is not None:
        raise ValueError("unterminated artifact fence")
    return {"source": str(Path(path).resolve()), "sha256": hashlib.sha256(data).hexdigest(),
            "artifact_count": len(artifacts), "artifacts": artifacts,
            "executed": False, "checksums": _audit_checksums(payloads, artifacts)}


def _audit_checksums(payloads: dict[str, bytes], artifacts: list[dict]) -> dict:
    """Check exact fenced bytes, without normalizing line endings or trusting names.

    Self-supplied checksums establish internal consistency, never authenticity.
    Missing package members remain missing rather than being synthesized.
    """
    manifest = payloads.get("SHA256SUMS.txt")
    result = {"present": manifest is not None, "entries": [], "errors": [],
              "unlisted": [], "complete": False, "authenticity_verified": False}
    if manifest is None:
        return result
    listed = set()
    duplicates = {a["name"] for a in artifacts if a["duplicate_name"]}
    unsafe = {a["name"] for a in artifacts if not a["safe_relative_name"]}
    for number, line in enumerate(manifest.decode("utf-8").splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if not match:
            result["errors"].append(f"invalid checksum line {number}")
            continue
        expected, name = match.groups()
        path = PurePosixPath(name)
        if (name in listed or name in duplicates or name in unsafe or
                path.is_absolute() or ".." in path.parts or
                "\\" in name or ":" in name):
            result["errors"].append(f"ambiguous or unsafe checksum name: {name}")
            continue
        listed.add(name)
        actual = hashlib.sha256(payloads[name]).hexdigest() if name in payloads else None
        result["entries"].append({"name": name, "expected": expected, "actual": actual,
                                  "status": "missing" if actual is None else
                                  "match" if expected == actual else "mismatch"})
    result["unlisted"] = sorted(set(payloads) - listed - {"SHA256SUMS.txt"})
    result["complete"] = bool(result["entries"]) and not (
        result["errors"] or result["unlisted"] or duplicates or unsafe or
        any(entry["status"] != "match" for entry in result["entries"]))
    return result
