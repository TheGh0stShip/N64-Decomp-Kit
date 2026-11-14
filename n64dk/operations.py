"""Discovery and safe invocation primitives for project-local decompilation tools."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import warnings
from pathlib import Path


KINDS = {
    "sweep": ("sweep", "search", "permut", "variant"),
    "score": ("score", "compare", "diff", "match"),
    "transform": ("transform", "normalize", "rewrite", "convert"),
    "audit": ("audit", "check", "verify", "validate"),
    "extract": ("extract", "split", "dump", "scan"),
    "build": ("build", "compile", "assemble", "link"),
}


def classify(path: Path, imports: set[str], calls: set[str]) -> list[str]:
    haystack = path.stem.lower().replace("-", "_")
    result = [kind for kind, words in KINDS.items() if any(word in haystack for word in words)]
    if "subprocess" in imports or {"run", "Popen", "check_call", "check_output"} & calls:
        result.append("process-wrapper")
    if "argparse" in imports:
        result.append("cli")
    return sorted(set(result)) or ["uncategorized"]


def inspect_script(path: Path, root: Path) -> dict | None:
    try:
        raw = path.read_bytes()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(raw.decode("utf-8", "replace"))
    except (OSError, SyntaxError, ValueError):
        return None
    imports: set[str] = set()
    calls: set[str] = set()
    options: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
                if node.func.attr == "add_argument":
                    for argument in node.args:
                        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                            options.add(argument.value)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    stat = path.stat()
    return {
        "path": str(path.relative_to(root)), "absolute_path": str(path.resolve()),
        "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
        "sha256": hashlib.sha256(raw).hexdigest(), "kinds": classify(path, imports, calls),
        "imports": sorted(imports), "arguments": sorted(options),
        "has_main_guard": any(isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)
                              for node in tree.body),
    }


class ScriptIndex:
    def __init__(self, database: str | Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database)
        self.db.execute("""CREATE TABLE IF NOT EXISTS scripts (
          root TEXT NOT NULL, path TEXT NOT NULL, absolute_path TEXT NOT NULL,
          size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, sha256 TEXT NOT NULL,
          metadata TEXT NOT NULL, indexed_ns INTEGER NOT NULL,
          PRIMARY KEY(root, path))""")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def index(self, roots: list[str], refresh: bool = False) -> dict:
        scanned = changed = failed = 0
        by_kind: dict[str, int] = {}
        for root_value in roots:
            root = Path(root_value).resolve()
            root_key = str(root)
            seen: set[str] = set()
            for path in root.rglob("*.py"):
                if not path.is_file() or any(part in {".git", ".venv", "venv", "site-packages"}
                                             for part in path.parts):
                    continue
                scanned += 1
                relative = str(path.relative_to(root))
                seen.add(relative)
                stat = path.stat()
                old = self.db.execute("SELECT size,mtime_ns,metadata FROM scripts WHERE root=? AND path=?",
                                      (root_key, relative)).fetchone()
                if old and not refresh and old[0] == stat.st_size and old[1] == stat.st_mtime_ns:
                    metadata = json.loads(old[2])
                else:
                    metadata = inspect_script(path, root)
                    if metadata is None:
                        failed += 1
                        continue
                    changed += 1
                    self.db.execute("INSERT OR REPLACE INTO scripts VALUES (?,?,?,?,?,?,?,?)",
                                    (root_key, relative, metadata["absolute_path"], metadata["size"],
                                     metadata["mtime_ns"], metadata["sha256"],
                                     json.dumps(metadata, sort_keys=True), time.time_ns()))
                for kind in metadata["kinds"]:
                    by_kind[kind] = by_kind.get(kind, 0) + 1
            stale = self.db.execute("SELECT path FROM scripts WHERE root=?", (root_key,)).fetchall()
            for (relative,) in stale:
                if relative not in seen:
                    self.db.execute("DELETE FROM scripts WHERE root=? AND path=?", (root_key, relative))
        self.db.commit()
        total = self.db.execute("SELECT COUNT(*) FROM scripts").fetchone()[0]
        return {"database": str(self.database.resolve()), "scanned": scanned, "changed": changed,
                "failed": failed, "total": total, "kinds": dict(sorted(by_kind.items()))}

    def query(self, kind: str | None = None, text: str | None = None, limit: int = 100) -> list[dict]:
        values = [json.loads(row[0]) for row in self.db.execute("SELECT metadata FROM scripts")]
        if kind:
            values = [value for value in values if kind in value["kinds"]]
        if text:
            needle = text.lower()
            values = [value for value in values if needle in value["path"].lower()
                      or any(needle in option.lower() for option in value["arguments"])]
        values.sort(key=lambda value: (value["kinds"], value["path"]))
        return values[:limit]


def command_schema() -> dict:
    """Return a compact command catalogue without importing execution through a shell."""
    import argparse
    from .cli import COMMANDS, load_commands
    load_commands()
    commands = []
    for name, (fn, _unused, help_text) in sorted(COMMANDS.items()):
        if name == "automation-serve":
            continue
        parser = argparse.ArgumentParser(add_help=False)
        arguments = getattr(fn, "arguments", None)
        if arguments:
            arguments(parser)
        fields = []
        for action in parser._actions:
            fields.append({"dest": action.dest, "flags": action.option_strings,
                           "required": action.required, "default": action.default,
                           "choices": list(action.choices) if action.choices else None,
                           "multiple": action.nargs in ("+", "*") or action.nargs == argparse.REMAINDER})
        commands.append({"name": name, "description": help_text, "arguments": fields})
    return {"protocol": "n64dk.operations.v1", "commands": commands}


def invoke(argv: list[str], timeout: float = 1800.0) -> dict:
    if not argv or any("\x00" in value for value in argv):
        raise ValueError("argv must contain a command and no NUL bytes")
    started = time.monotonic()
    environment = dict(os.environ)
    proc = subprocess.run([sys.executable, "-m", "n64dk", "--format", "json", *argv],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env=environment)
    elapsed = time.monotonic() - started
    try:
        output = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        output = {"text": proc.stdout}
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
            "elapsed_seconds": round(elapsed, 6), "result": output,
            "stderr": proc.stderr[-12000:] if proc.stderr else ""}
