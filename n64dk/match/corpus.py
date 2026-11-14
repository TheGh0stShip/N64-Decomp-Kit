"""Durable local corpus index for N64 assembly and source idioms."""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from pathlib import Path

from .. import mips


_REGISTER = re.compile(r"\$(?:zero|at|v[01]|a[0-3]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra|\d+)", re.I)
_NUMBER = re.compile(r"(?<![A-Za-z_])(?:-?0x[0-9A-Fa-f]+|-?\d+)(?![A-Za-z_])")
_SYMBOL = re.compile(r"\b(?:func|D|jtbl|RO|B)_[0-9A-Fa-f]+\b")
_LABEL = re.compile(r"^[A-Za-z_.$][\w.$]*:\s*$")
_WORD = re.compile(r"^\.word\s+(0x[0-9A-Fa-f]+)")
_MNEMONIC = re.compile(r"^([a-z][a-z0-9.]*)\s*(.*)$", re.I)


def _digest(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def assembly_signature(text: str) -> dict:
    instructions = []
    calls = []
    globals_ = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ".set", ".text", ".align", ".globl", ".ent", ".end", ".section")):
            continue
        if _LABEL.match(line):
            continue
        comment = line.split("#", 1)[1].strip() if "#" in line else ""
        line = line.split("#", 1)[0].strip()
        word = _WORD.match(line)
        if word:
            decoded = mips.decode(int(word.group(1), 0), 0x80000000).disassemble()
            line = decoded if ".word" not in decoded else comment
        found = _MNEMONIC.match(line)
        if not found:
            continue
        opcode, operands = found.group(1).lower(), " ".join(found.group(2).split())
        if opcode in {"jal", "jalr", "j"}:
            calls += re.findall(r"[A-Za-z_]\w+", operands)
        if opcode.startswith(("l", "s")):
            globals_ += _SYMBOL.findall(operands)
        instructions.append(f"{opcode} {operands}".strip())
    neutral = [_SYMBOL.sub("SYM", _NUMBER.sub("IMM", _REGISTER.sub("$R", line)))
               for line in instructions]
    relocation = [_SYMBOL.sub("SYM", _NUMBER.sub("IMM", line)) for line in instructions]
    opcodes = [line.split(None, 1)[0] for line in instructions]
    return {"instructions": instructions, "instruction_count": len(instructions),
            "text_hash": _digest(instructions), "relocation_hash": _digest(relocation),
            "register_neutral_hash": _digest(neutral), "opcode_hash": _digest(opcodes),
            "calls": sorted(set(calls)), "globals": sorted(set(globals_))}


def binary_signature(code: bytes, vram: int) -> dict:
    return assembly_signature("\n".join(ins.disassemble() for ins in mips.instructions(code, vram)))


def assembly_units(text: str, fallback: str) -> list[tuple[str, str]]:
    starts = list(re.finditer(r"(?m)^\s*(?:\.ent\s+|glabel\s+)([A-Za-z_.$]\w*)", text))
    if not starts:
        return [(fallback, text)]
    result = []
    for index, found in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        result.append((found.group(1), text[found.start():end]))
    return result


class CorpusIndex:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS functions (
            project TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL, mtime_ns INTEGER NOT NULL,
            size INTEGER NOT NULL, source_digest TEXT NOT NULL, instruction_count INTEGER NOT NULL,
            text_hash TEXT NOT NULL, relocation_hash TEXT NOT NULL, register_neutral_hash TEXT NOT NULL,
            opcode_hash TEXT NOT NULL, calls TEXT NOT NULL, globals TEXT NOT NULL, updated_ns INTEGER NOT NULL,
            PRIMARY KEY(project, path, name))""")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def index(self, roots: list[str | Path]) -> dict:
        started = time.monotonic()
        scanned = changed = indexed = 0
        for value in roots:
            root = Path(value).expanduser().resolve()
            project = root.name
            for path in list(root.glob("src/**/*.s")) + list(root.glob("asm/**/*.s")):
                if not path.is_file():
                    continue
                if any(part in {"build", ".git", ".n64dk", "tools"} for part in path.parts):
                    continue
                scanned += 1
                relative = str(path.relative_to(root))
                stat = path.stat()
                old = self.db.execute("""SELECT mtime_ns, size FROM functions
                                         WHERE project = ? AND path = ? LIMIT 1""",
                                      (project, relative)).fetchone()
                if old and old == (stat.st_mtime_ns, stat.st_size):
                    continue
                changed += 1
                text = path.read_text(errors="replace")
                self.db.execute("DELETE FROM functions WHERE project = ? AND path = ?", (project, relative))
                for name, unit_text in assembly_units(text, path.stem):
                    signature = assembly_signature(unit_text)
                    if not signature["instruction_count"]:
                        continue
                    self.db.execute("""INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (project, relative, name, stat.st_mtime_ns, stat.st_size,
                         hashlib.sha256(unit_text.encode()).hexdigest(), signature["instruction_count"],
                         signature["text_hash"], signature["relocation_hash"],
                         signature["register_neutral_hash"], signature["opcode_hash"],
                         "\n".join(signature["calls"]), "\n".join(signature["globals"]), time.time_ns()))
                    indexed += 1
        self.db.commit()
        return {"roots": [str(Path(root).resolve()) for root in roots], "scanned": scanned,
                "changed": changed, "indexed": indexed,
                "total": self.db.execute("SELECT COUNT(*) FROM functions").fetchone()[0],
                "elapsed_seconds": round(time.monotonic() - started, 6)}

    def query(self, signature: dict, limit: int = 20) -> list[dict]:
        columns = ("text_hash", "relocation_hash", "register_neutral_hash", "opcode_hash")
        labels = ("textual-exact", "relocation-only", "register-renamed", "opcode-shape")
        found = {}
        for priority, (column, label) in enumerate(zip(columns, labels)):
            rows = self.db.execute(f"""SELECT project, path, name, instruction_count, calls, globals
                                      FROM functions WHERE {column} = ? LIMIT ?""",
                                   (signature[column], max(1, limit))).fetchall()
            for row in rows:
                key = (row[0], row[1], row[2])
                found.setdefault(key, {"project": row[0], "path": row[1], "name": row[2],
                    "instruction_count": row[3], "calls": row[4].splitlines(),
                    "globals": row[5].splitlines(), "match": label, "priority": priority})
        return sorted(found.values(), key=lambda row: (row["priority"],
                      abs(row["instruction_count"] - signature["instruction_count"]), row["project"], row["name"]))[:limit]
