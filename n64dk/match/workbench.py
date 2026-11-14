"""Optional bridge to the CC0 N64 Decomp Workbench.

The workbench remains an independent tool.  This bridge consumes its stable JSON
output so n64dk does not reimplement its mature relocation and mechanism views.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class WorkbenchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Workbench:
    executable: str

    @classmethod
    def discover(cls, executable: str | None = None) -> "Workbench":
        found = shutil.which(executable or "decomp-workbench")
        if found is None:
            raise WorkbenchError("decomp-workbench is not installed or configured")
        return cls(found)

    def version(self) -> str:
        proc = subprocess.run([self.executable, "--version"], capture_output=True,
                              text=True, timeout=10)
        if proc.returncode:
            raise WorkbenchError(proc.stderr.strip() or "workbench version probe failed")
        return proc.stdout.strip()

    def diagnose_dumps(self, target: str | Path, candidate: str | Path,
                       function: str | None = None) -> dict:
        command = [self.executable, "diagnose-dumps", str(target), str(candidate), "--json"]
        if function:
            command += ["--function", function]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if proc.returncode not in (0, 1):
            raise WorkbenchError(proc.stderr.strip() or proc.stdout.strip())
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as error:
            raise WorkbenchError(f"invalid workbench JSON: {error}") from error
