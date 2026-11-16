"""``--output`` conventions shared by commands: ``-`` means standard output, never a file."""
from __future__ import annotations

from pathlib import Path

STDOUT = "-"


def is_stdout(value) -> bool:
    return value is not None and str(value).strip() == STDOUT


def file_output(value, option: str = "--output") -> Path | None:
    """Path for a command that can only write files: refuses ``-`` (and an empty name)."""
    if value is None:
        return None
    if is_stdout(value) or not str(value).strip():
        raise ValueError(f"{option} {value!r}: this command writes files (and sidecar evidence); "
                         "give a real path, standard output is not supported here")
    return Path(value)
