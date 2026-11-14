"""Load an explicitly selected project adapter from a local Python module."""
from __future__ import annotations

import importlib
import sys
import tomllib
from pathlib import Path

from .project import ProjectAdapter


def load(path: str | Path) -> ProjectAdapter:
    config = Path(path).expanduser().resolve()
    data = tomllib.loads(config.read_text())
    project = data.get("project", {})
    entry = project.get("adapter")
    if not entry or ":" not in entry:
        raise ValueError("PROJECT.toml requires [project] adapter = 'module:factory'")
    module_name, factory_name = entry.split(":", 1)
    import_root = (config.parent / project.get("python_path", ".")).resolve()
    sys.path.insert(0, str(import_root))
    try:
        factory = getattr(importlib.import_module(module_name), factory_name)
        adapter = factory(config, data)
    finally:
        try:
            sys.path.remove(str(import_root))
        except ValueError:
            pass
    if not isinstance(adapter, ProjectAdapter):
        raise TypeError("adapter does not implement the complete ProjectAdapter protocol")
    return adapter
