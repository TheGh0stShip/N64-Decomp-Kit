"""Build pipelines: C source -> relocatable MIPS ELF object with an original toolchain.

Pipelines
    kmc+hook     KMC GCC -S -> project normalizer hook -> KMC GNU as
    kmc+builtin  KMC GCC -S -> built-in normalizer -> KMC GNU as
    kmc+as       KMC GCC -S -> KMC GNU as (assembler reordering left on)
    kmc+asn64    KMC GCC -S -> ASN64-compatible converter -> modern GNU as --no-pad-sections
    ido5.3       IDO 5.3 cc -c
    ido7.1       IDO 7.1 cc -c
    as           assembly source -> KMC GNU as
    sn           host cpp -> SN cc1n64 -> asn64.exe -> psyq-obj-parser (via wibo)

Pseudo flags understood in flag lists (manifest conventions):
    --section-base=SECTION:ADDR  --symbol=NAME:ADDR  --assembler=asn64|normalizer
    --normalizer-NAME            forwarded to the normalizer hook as --NAME
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import asn64, custom_pipeline, normalize
from .toolchain import Config

PIPELINES = ("kmc+hook", "kmc+builtin", "kmc+as", "kmc+asn64", "ido5.3", "ido7.1", "sn", "as")
TOOLCHAIN_OF = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}
_CACHE_LOCK = threading.RLock()
_CACHE_STATS = {"hits": 0, "misses": 0, "stores": 0}
_PIPELINE_STATS = {"compiler_seconds": 0.0, "assembler_seconds": 0.0,
                   "object_conversion_seconds": 0.0, "tool_invocations": 0}
_INCLUDE_FILE_CACHE: dict[str, tuple[int, int, int, str, bytes]] = {}
_INCLUDE_RE = re.compile(
    rb"(?m)^\s*#\s*include\s*([<\"])([^>\"\r\n]+)[>\"]")
_COMPUTED_INCLUDE_RE = re.compile(rb"(?m)^\s*#\s*include\s+([A-Za-z_]\w*)\s*$")
_STRING_DEFINE_RE = re.compile(
    rb"(?m)^\s*#\s*define\s+([A-Za-z_]\w*)\s+([<\"])([^>\"\r\n]+)[>\"]\s*$")


def object_cache_stats() -> dict[str, int]:
    with _CACHE_LOCK:
        return dict(_CACHE_STATS)


def pipeline_stats() -> dict:
    with _CACHE_LOCK:
        return {key: round(value, 6) if isinstance(value, float) else value
                for key, value in _PIPELINE_STATS.items()}


class BuildError(RuntimeError):
    pass


@dataclass
class BuildSpec:
    pipeline: str
    flags: list[str]                       # compiler flags only
    section_bases: dict[str, int] = field(default_factory=dict)
    symbols: dict[str, int] = field(default_factory=dict)
    normalizer_args: list[str] = field(default_factory=list)

    def manifest_flags(self) -> str:
        """Flag column for a BattleTanx-style manifest row."""
        out = []
        if self.pipeline == "kmc+asn64":
            out.append("--assembler=asn64")
        out += [f"--section-base={k}:0x{v:08X}" for k, v in self.section_bases.items() if k != ".text"]
        out += [f"--symbol={k}:0x{v:08X}" for k, v in self.symbols.items()]
        out += [f"--normalizer-{a.lstrip('-')}" for a in self.normalizer_args]
        return " ".join(out + self.flags)


def split_flags(flags: list[str], pipeline: str) -> BuildSpec:
    spec = BuildSpec(pipeline, [])
    for flag in flags:
        if flag.startswith("--section-base="):
            sec, addr = flag.split("=", 1)[1].split(":", 1)
            spec.section_bases[sec] = int(addr, 0)
        elif flag.startswith("--symbol="):
            name, addr = flag.split("=", 1)[1].split(":", 1)
            spec.symbols[name] = int(addr, 0)
        elif flag.startswith("--assembler="):
            lane = flag.split("=", 1)[1]
            if lane == "asn64":
                spec.pipeline = "kmc+asn64"
            elif lane != "normalizer":
                raise BuildError(f"unsupported assembler lane {lane!r}")
        elif flag.startswith("--normalizer-"):
            spec.normalizer_args.append("--" + flag[len("--normalizer-"):])
        else:
            spec.flags.append(flag)
    return spec


def _run(argv, cwd, env=None, stdin=None, retries: int = 0, timeout: float | None = None):
    """Run a tool; ``retries`` re-runs it after a crash (a pass reported as killed by a signal),
    which the statically recompiled IDO binaries occasionally suffer under parallel load."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    started = time.monotonic()
    timeout = timeout or float(os.environ.get("N64DK_TOOL_TIMEOUT", "120"))
    for _attempt in range(retries + 1):
        proc = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=full_env,
                                stdin=subprocess.PIPE if stdin is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Compilers often leave pass executables behind.  Terminate the whole private
            # process group so a timed-out tranche worker cannot leak cc1/uopt/wibo children.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
            raise BuildError(f"{Path(str(argv[0])).name} timed out after {timeout:g}s")
        proc.stdout, proc.stderr = stdout, stderr
        crashed = proc.returncode < 0 or "died due to signal" in (proc.stderr or "")
        if not (proc.returncode and crashed):
            break
    if proc.returncode:
        raise BuildError(f"{Path(str(argv[0])).name} failed: {(proc.stderr or proc.stdout).strip()[-600:]}")
    executable = Path(str(argv[0])).name.lower()
    bucket = ("assembler_seconds" if executable in {"as", "asn64.exe"} or executable.endswith("-as") else
              "object_conversion_seconds" if "obj-parser" in executable else "compiler_seconds")
    with _CACHE_LOCK:
        _PIPELINE_STATS[bucket] += time.monotonic() - started
        _PIPELINE_STATS["tool_invocations"] += 1
    return proc


def _as_flags(flags: list[str]) -> list[str]:
    # The assembler always runs at -G0: small-data placement is decided by the compiler's -G
    # (assembler -G would turn absolute %hi/%lo accesses into $gp-relative ones).
    return ["-mips3", "-G0"]


def _cached_file(path: Path) -> tuple[str, bytes]:
    """Return a content digest and bytes, avoiding repeated header reads across a tranche."""
    resolved = str(path.resolve())
    stat = path.stat()
    with _CACHE_LOCK:
        cached = _INCLUDE_FILE_CACHE.get(resolved)
        if cached and cached[:3] == (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size):
            return cached[3], cached[4]
    data = path.read_bytes()
    value = hashlib.sha256(data).hexdigest()
    with _CACHE_LOCK:
        _INCLUDE_FILE_CACHE[resolved] = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, value, data)
    return value, data


def _include_closure_digest(source: Path, roots: tuple[Path, ...],
                            forced: tuple[str, ...] = (),
                            command_macros: dict[str, tuple[bytes, bytes]] | None = None) -> str:
    """Hash only recursively resolved includes, never entire include or scratch trees.

    The path and content of every resolved dependency are retained in the identity. Missing
    includes are also recorded so adding one invalidates the next invocation. Conditional
    includes may be conservatively retained, but unrelated files are never visited.
    """
    roots = tuple(dict.fromkeys(Path(value).resolve() for value in roots if Path(value).is_dir()))
    digest = hashlib.sha256()
    visited: set[Path] = set()

    def resolve(name: str, quote: bool, parent: Path | None) -> Path | None:
        candidates = ([parent / name] if quote and parent else []) + [root / name for root in roots]
        return next((item.resolve() for item in candidates if item.is_file()), None)

    def includes(data: bytes):
        macros = dict(command_macros or {})
        macros.update({found.group(1).decode(errors="surrogateescape"): (found.group(2), found.group(3))
                  for found in _STRING_DEFINE_RE.finditer(data)}
        )
        for found in _INCLUDE_RE.finditer(data):
            yield found.group(1), found.group(2)
        for found in _COMPUTED_INCLUDE_RE.finditer(data):
            value = macros.get(found.group(1).decode(errors="surrogateescape"))
            if value:
                yield value
            else:
                # Unknown computed includes cannot safely share an object-cache entry.
                digest.update(b"unresolved-computed:"); digest.update(found.group(1))

    def visit(path: Path) -> None:
        path = path.resolve()
        if path in visited or not path.is_file():
            return
        visited.add(path)
        value, data = _cached_file(path)
        digest.update(str(path).encode()); digest.update(value.encode())
        for delimiter, raw_name in includes(data):
            name = raw_name.decode(errors="surrogateescape")
            child = resolve(name, delimiter == b'"', path.parent)
            if child is None:
                digest.update(b"missing:"); digest.update(name.encode(errors="surrogateescape"))
            else:
                visit(child)

    # Source contents are already part of the object identity, but parsing it discovers roots.
    source_data = source.read_bytes()
    for delimiter, raw_name in includes(source_data):
        name = raw_name.decode(errors="surrogateescape")
        child = resolve(name, delimiter == b'"', source.parent)
        if child is None:
            digest.update(b"missing:"); digest.update(name.encode(errors="surrogateescape"))
        else:
            visit(child)
    for name in forced:
        child = resolve(name, True, source.parent)
        if child is None:
            digest.update(b"missing-forced:"); digest.update(name.encode(errors="surrogateescape"))
        else:
            visit(child)
    return digest.hexdigest()


def _compiler_digest(cfg: Config, pipeline: str) -> str:
    if custom_pipeline.is_custom(pipeline):
        # a configured lane is identified by its recipe text and the tools it names
        try:
            material = custom_pipeline.recipe_for(pipeline, cfg.project).digest_material()
        except custom_pipeline.CustomPipelineError:
            return "custom-pipeline-undefined"
        return hashlib.sha256(material.encode()).hexdigest()
    key = TOOLCHAIN_OF.get(pipeline, "kmc"); root = cfg.toolchain(key); digest = hashlib.sha256()
    if root:
        from .toolchain import PROFILES
        for name in PROFILES[key].required:
            path = root / name
            if path.is_file(): digest.update(path.read_bytes())
    if pipeline == "kmc+asn64":
        gas = cfg.gnu_as()
        if gas and Path(gas[0]).is_file(): digest.update(Path(gas[0]).read_bytes())
    return digest.hexdigest()


def toolchain_digest(cfg: Config, pipeline: str) -> str:
    """Public stable identity used by session and strict-verification receipts."""
    return _compiler_digest(cfg, pipeline)


def dependency_digest(source: Path, spec: BuildSpec, cfg: Config,
                      includes: list[Path] | None = None) -> str:
    """Identity of the source's reachable include closure and include-search configuration."""
    source = Path(source).resolve(); cwd = Path(cfg.project).resolve()
    roots = [Path(value) for value in (includes if includes is not None else cfg.include)]
    roots = [(cwd / path).resolve() if not path.is_absolute() else path.resolve() for path in roots]
    options = ("-I", "-isystem", "-iquote", "-idirafter")
    forced, command_macros, index = [], {}, 0
    while index < len(spec.flags):
        flag = spec.flags[index]
        if flag in options and index + 1 < len(spec.flags):
            path = Path(spec.flags[index + 1]); roots.append((cwd / path).resolve() if not path.is_absolute() else path.resolve())
            index += 2; continue
        for option in options:
            if flag.startswith(option) and len(flag) > len(option):
                path = Path(flag[len(option):]); roots.append((cwd / path).resolve() if not path.is_absolute() else path.resolve())
                break
        if flag == "-include" and index + 1 < len(spec.flags):
            forced.append(spec.flags[index + 1]); index += 1
        elif flag.startswith("-include") and len(flag) > len("-include"):
            forced.append(flag[len("-include"):])
        define = None
        if flag == "-D" and index + 1 < len(spec.flags):
            define = spec.flags[index + 1]; index += 1
        elif flag.startswith("-D") and len(flag) > 2:
            define = flag[2:]
        if define and "=" in define:
            name, value = define.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                command_macros[name] = (b'"', value[1:-1].encode())
            elif value.startswith("<") and value.endswith(">"):
                command_macros[name] = (b"<", value[1:-1].encode())
        index += 1
    roots.append(source.parent)
    payload = {"closure": _include_closure_digest(source, tuple(roots), tuple(forced), command_macros),
               "roots": [str(path) for path in roots], "forced": forced,
               "command_macros": {key: [delimiter.decode(), value.decode(errors="surrogateescape")]
                                  for key, (delimiter, value) in command_macros.items()},
               "flags": [flag for flag in spec.flags if flag.startswith(options)]}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def build(source: Path, spec: BuildSpec, cfg: Config, workdir: Path,
          includes: list[Path] | None = None, defines: list[str] | None = None) -> Path:
    """Compile ``source`` and return the object path inside ``workdir``.  Commands run in the
    project directory so relative ``-I`` flags behave as in the project's own build."""
    source = Path(source).resolve()
    cwd = Path(cfg.project).resolve()
    inc_paths = [Path(p) for p in (includes if includes is not None else cfg.include)]
    inc_paths = [(cwd / p).resolve() if not p.is_absolute() else p.resolve() for p in inc_paths]
    inc = [f"-I{p}" for p in inc_paths]
    inc += list(defines or [])
    tag = hashlib.sha1(f"{source}|{spec.pipeline}|{spec.flags}|{spec.normalizer_args}".encode()).hexdigest()[:12]
    unit_dir = (Path(workdir).resolve() / tag)   # private directory: compilers drop fixed-name temporaries
    unit_dir.mkdir(parents=True, exist_ok=True)
    stem = unit_dir / source.stem
    obj = Path(f"{stem}.o")
    pipe = spec.pipeline
    include_roots = list(inc_paths)
    include_options = ("-I", "-isystem", "-iquote", "-idirafter")
    index = 0
    while index < len(spec.flags):
        flag = spec.flags[index]
        value = None
        if flag in include_options and index + 1 < len(spec.flags):
            value = spec.flags[index + 1]; index += 1
        else:
            for option in include_options:
                if flag.startswith(option) and len(flag) > len(option):
                    value = flag[len(option):]; break
        if value:
            path = Path(value)
            include_roots.append((cwd / path).resolve() if not path.is_absolute() else path.resolve())
        index += 1
    include_roots.append(source.parent)
    forced = []
    for index, flag in enumerate(spec.flags):
        if flag == "-include" and index + 1 < len(spec.flags):
            forced.append(spec.flags[index + 1])
        elif flag.startswith("-include") and len(flag) > len("-include"):
            forced.append(flag[len("-include"):])
    normalizer_digest = None
    if cfg.normalizer and Path(cfg.normalizer).is_file():
        normalizer_digest = hashlib.sha256(Path(cfg.normalizer).read_bytes()).hexdigest()
    pipeline_code = hashlib.sha256(Path(__file__).read_bytes() +
        Path(asn64.__file__).read_bytes() + Path(normalize.__file__).read_bytes()).hexdigest()
    identity = json.dumps({"source": hashlib.sha256(source.read_bytes()).hexdigest(),
        "pipeline": pipe, "flags": spec.flags, "normalizer": spec.normalizer_args,
        "section_bases": spec.section_bases, "defines": defines or [],
        "includes": dependency_digest(source, spec, cfg, includes),
        "compiler": _compiler_digest(cfg, pipe),
        "normalizer_hook": normalizer_digest, "pipeline_code": pipeline_code},
        sort_keys=True)
    cache_key = hashlib.sha256(identity.encode()).hexdigest()
    cache = cfg.project / ".n64dk" / "object-cache" / cache_key[:2] / f"{cache_key}.o"
    with _CACHE_LOCK:
        if cache.is_file():
            _CACHE_STATS["hits"] += 1
            shutil.copy2(cache, obj)
            return obj
        _CACHE_STATS["misses"] += 1

    def retain() -> Path:
        with _CACHE_LOCK:
            cache.parent.mkdir(parents=True, exist_ok=True)
            if not cache.is_file():
                temporary = cache.with_name(f".{cache.name}.{os.getpid()}.{threading.get_ident()}.tmp")
                shutil.copy2(obj, temporary)
                os.replace(temporary, cache)
                _CACHE_STATS["stores"] += 1
        return obj
    def absolute_flags(flags: list[str]) -> list[str]:
        """Make path-bearing options stable when tools run in the private unit directory."""
        out, index = [], 0
        while index < len(flags):
            flag = flags[index]
            if flag in include_options and index + 1 < len(flags):
                path = Path(flags[index + 1])
                out += [flag, str((cwd / path).resolve() if not path.is_absolute() else path.resolve())]
                index += 2
                continue
            replaced = False
            for option in include_options:
                if flag.startswith(option) and len(flag) > len(option):
                    path = Path(flag[len(option):])
                    out.append(option + str((cwd / path).resolve() if not path.is_absolute() else path.resolve()))
                    replaced = True
                    break
            out.append(flag) if not replaced else None
            index += 1
        return out

    private_flags = absolute_flags(spec.flags)
    if pipe.startswith("kmc"):
        kmc = cfg.toolchain("kmc")
        if kmc is None:
            raise BuildError("KMC GCC 2.7.2 toolchain not found")
        raw = Path(f"{stem}.raw.s")
        # -x c makes archived/content-addressed candidates with no suffix compile as C.
        _run([kmc / "gcc", f"-B{kmc}/", "-x", "c", "-S", *private_flags, *inc,
              "-o", raw, source], unit_dir, env={"TMPDIR": str(unit_dir)})
        if not raw.is_file():
            raise BuildError("KMC compiler succeeded without producing assembly")
        if pipe == "kmc+asn64":
            gas = cfg.gnu_as()
            if gas is None:
                raise BuildError("modern MIPS GNU as not found")
            disabled = {
                arg[len("--disable-"):]
                for arg in spec.normalizer_args
                if arg.startswith("--disable-")
            }
            enabled = {
                arg[len("--enable-"):]
                for arg in spec.normalizer_args
                if arg.startswith("--enable-")
            }
            text = asn64.convert(raw.read_text(errors="replace"), disabled, enabled,
                                 spec.section_bases)
            _run([gas[0], *asn64.GNU_AS_FLAGS, "-", "-o", obj], unit_dir, env=gas[1], stdin=text)
            return retain()
        asm = raw
        if pipe == "kmc+hook":
            if not cfg.normalizer:
                raise BuildError("no normalizer hook configured")
            asm = Path(f"{stem}.s")
            # Hooks are project configuration and commonly contain project-relative script
            # paths.  The compiler itself stays isolated; only the normalizer runs at the
            # configured project root and receives absolute input/output paths.
            normalize.run_hook(cfg.normalizer, raw, asm, cwd, spec.normalizer_args)
        elif pipe == "kmc+builtin":
            asm = Path(f"{stem}.s")
            asm.write_text(normalize.builtin(raw.read_text(errors="replace")))
        _run([kmc / "as", *_as_flags(spec.flags), "-o", obj, asm], unit_dir)
        return retain()
    if pipe == "as":
        kmc = cfg.toolchain("kmc")
        if kmc is None:
            raise BuildError("KMC GNU as not found")
        _run([kmc / "as", *_as_flags(spec.flags), *inc, "-o", obj, source], unit_dir)
        return retain()
    if pipe in ("ido5.3", "ido7.1"):
        ido = cfg.toolchain(TOOLCHAIN_OF[pipe])
        if ido is None:
            raise BuildError(f"{pipe} toolchain not found")
        # IDO's -O3 pass (uld) writes <stem>.u into the working directory: run in the private
        # build directory and make relative include paths absolute.
        flags = private_flags
        _run([ido / "cc", "-c", *flags, *inc, "-o", obj, source], unit_dir,
             env={"TMPDIR": str(unit_dir)}, retries=4)
        return retain()
    if pipe == "sn":
        sn = cfg.toolchain("sn")
        if sn is None:
            raise BuildError("SN GCC 2.8 toolchain not found")
        pre, asm, psyq = Path(f"{stem}.i"), Path(f"{stem}.s"), Path(f"{stem}.obj")
        _run(["gcc", "-E", "-P", "-undef", "-D__GNUC__=2", "-D__GNUC_MINOR__=8", *inc, source, "-o", pre], unit_dir)
        _run([sn / "wibo", sn / "cc1n64.exe", "-quiet", *private_flags, pre, "-o", asm], unit_dir)
        _run([sn / "wibo", sn / "asn64.exe", "-o", psyq, asm], unit_dir)
        _run([sn / "psyq-obj-parser", psyq, "-b", "-n", "-o", obj], unit_dir)
        return retain()
    if custom_pipeline.is_custom(pipe):
        # a lane declared in the project's [pipelines.<name>] configuration
        local = unit_dir / (source.name if source.suffix else f"{source.name}.c")
        if local.resolve() != source:
            shutil.copyfile(source, local)
        try:
            recipe = custom_pipeline.recipe_for(pipe, cfg.project)
            built = custom_pipeline.build(recipe, local, [*private_flags, *inc], [], unit_dir, cfg.project)
        except custom_pipeline.CustomPipelineError as error:
            raise BuildError(str(error)) from None
        if built != obj:
            shutil.copyfile(built, obj)
        return retain()
    raise BuildError(f"unknown pipeline {pipe!r}")


def scratch_dir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="n64dk-match-")
