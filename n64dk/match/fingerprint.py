"""Hermetic fingerprints for compilers and build closures."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolchainFile:
    role: str
    path_name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ToolchainFingerprint:
    profile: str
    files: tuple[ToolchainFile, ...]
    target: str
    flags: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    schema: int = 1

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @classmethod
    def create(cls, profile: str, files: Mapping[str, Path], target: str,
               flags: Iterable[str], environment: Mapping[str, str] | None = None,
               allowed_environment: Iterable[str] = ()) -> "ToolchainFingerprint":
        items = []
        for role, path in sorted(files.items()):
            p = Path(path).resolve()
            items.append(ToolchainFile(role, p.name, sha256_file(p), p.stat().st_size))
        env = environment or {}
        kept = tuple(sorted((key, env[key]) for key in allowed_environment if key in env))
        return cls(profile, tuple(items), target, tuple(flags), kept)


@dataclass(frozen=True)
class BuildClosure:
    adapter_id: str
    adapter_version: str
    unit_id: str
    toolchain_digest: str
    inputs: tuple[tuple[str, str], ...]
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    oracle_policy: str
    ownership_digest: str = ""
    schema: int = 1

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @classmethod
    def create(cls, adapter_id: str, adapter_version: str, unit_id: str,
               toolchain_digest: str, inputs: Mapping[str, Path], command: Iterable[str],
               environment: Mapping[str, str], oracle_policy: str,
               allowed_environment: Iterable[str] = (), ownership=None) -> "BuildClosure":
        hashed = tuple(sorted((name, sha256_file(Path(path))) for name, path in inputs.items()))
        kept = tuple(sorted((key, environment[key]) for key in allowed_environment
                            if key in environment))
        return cls(adapter_id, adapter_version, unit_id, toolchain_digest, hashed,
                   tuple(command), kept, oracle_policy,
                   canonical_digest(ownership) if ownership is not None else "")
