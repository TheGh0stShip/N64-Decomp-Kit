"""Refinement of hard cases by an external author, judged by the same oracle as everything else.

Drafting and mechanical search plateau: beyond the small functions, a draft is wrong in ways
that need understanding (the type a value really has, the idiom the programmer used), not more
variants.  This stage hands such a case to an *external command* and treats what comes back as
an untrusted candidate::

    prompt on stdin  ->  command  ->  C on stdout  ->  build, compare, strict verification

The command is a trusted executable selected by the user: a headless coding assistant, a local
model, or a script.  It has the invoking user's OS permissions; the temporary working directory is
not a security sandbox.  Nothing it returns is believed.  A candidate is kept only when it scores
better than the case's current best under the recipe that case was built with, and a case
becomes ``exact`` only through the strict verifier, exactly like a mechanical match.  Candidate
output is bounded and non-ordinary C is rejected before compilation.

One case is a short conversation.  Every round's prompt holds the target assembly, the best C
so far, what the compiler made of it (the classified instruction differences, or the compiler
diagnostic when it did not build), the diagnosed causes and the recipe; the command answers
with one complete translation unit.  ``rounds`` bounds the conversation.

The prompt contains disassembly of the image under analysis and candidate sources.  Whoever
configures the command decides where that text goes.
"""
from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .provenance import Verdict, scan_c

STATUSES = ("near", "open", "does-not-build")
_FENCE = re.compile(r"```[ \t]*(?:c|C|cpp|h)?[ \t]*\n(.*?)```", re.S)
_LOOKS_LIKE_C = re.compile(r"[;{}]")

INSTRUCTIONS = """\
You are matching one function of a Nintendo 64 game: write C that the stated compiler turns
into exactly the target machine code.

Rules:
- Answer with ONE fenced code block (```c ... ```) holding a complete translation unit: the
  typedefs and declarations it needs, then the function. Nothing outside the block is read.
- Ordinary C only: no inline assembly, no raw bytes, no compiler pragmas that inject code.
- Keep the function's name. Refer to other functions and data by the names used in the
  assembly listing (for example func_80012345, D_80123456); declare them `extern`.
- The basic typedefs (s8 u8 s16 u16 s32 u32 s64 u64 f32 f64) are provided for you.
- The compiler output is compared instruction by instruction. Registers, instruction order,
  stack frame size and stack offsets all have to agree, so the types, the order of declarations
  and statements, and the use of temporaries matter.
"""


class RefineError(RuntimeError):
    pass


@dataclass
class Settings:
    command: list[str]
    rounds: int = 3
    timeout: float = 600.0
    statuses: tuple[str, ...] = STATUSES
    max_size: int = 0x400
    max_cases: int = 0                    # 0: no limit
    jobs: int = 4
    max_score: int = 0                    # 0: no limit; otherwise only cases at most this far
    asm_limit: int = 400                  # instructions of target assembly shown
    diff_limit: int = 40                  # differing instructions shown per round
    prompt_limit: int = 512 * 1024        # bytes sent to one invocation
    output_limit: int = 512 * 1024        # combined stdout/stderr retained from one invocation
    source_limit: int = 256 * 1024        # one returned translation unit
    env: dict = field(default_factory=dict)

    @classmethod
    def from_table(cls, table: dict | None, command: str | None = None) -> "Settings | None":
        """Settings from a ``[run.refine]`` table and/or a command line; None when no command."""
        table = dict(table or {})
        raw = command or table.get("command")
        if not raw:
            return None
        argv = shlex.split(raw) if isinstance(raw, str) else [str(part) for part in raw]
        if not argv:
            return None
        return cls(command=argv, rounds=int(table.get("rounds", 3)), timeout=float(table.get("timeout", 600)),
                   statuses=tuple(table.get("statuses", STATUSES)), max_size=int(table.get("max_size", 0x400)),
                   max_cases=int(table.get("max_cases", 0)), jobs=int(table.get("jobs", 4)),
                   max_score=int(table.get("max_score", 0)), asm_limit=int(table.get("asm_limit", 400)),
                   diff_limit=int(table.get("diff_limit", 40)),
                   prompt_limit=int(table.get("prompt_limit", 512 * 1024)),
                   output_limit=int(table.get("output_limit", 512 * 1024)),
                   source_limit=int(table.get("source_limit", 256 * 1024)),
                   env={str(k): str(v) for k, v in (table.get("env") or {}).items()})

    def validate(self) -> None:
        if not self.command or any("\x00" in part for part in self.command):
            raise ValueError("refiner command is empty or contains NUL")
        if not 1 <= self.rounds <= 32:
            raise ValueError("refiner rounds must be between 1 and 32")
        if not 0 < self.timeout <= 86400:
            raise ValueError("refiner timeout must be between 0 and 86400 seconds")
        if not 1 <= self.jobs <= 64:
            raise ValueError("refiner jobs must be between 1 and 64")
        for name in ("max_size", "max_cases", "max_score", "asm_limit", "diff_limit"):
            if getattr(self, name) < 0:
                raise ValueError(f"refiner {name} must be non-negative")
        for name in ("prompt_limit", "output_limit", "source_limit"):
            if not 1024 <= getattr(self, name) <= 64 * 1024 * 1024:
                raise ValueError(f"refiner {name} must be between 1024 and 67108864 bytes")

    def signature(self) -> str:
        """Identity used for resumability. Environment values affect the identity but are never stored."""
        import hashlib
        import json
        payload = {"command": self.command, "rounds": self.rounds, "timeout": self.timeout,
                   "statuses": self.statuses, "max_size": self.max_size, "max_score": self.max_score,
                   "asm_limit": self.asm_limit, "diff_limit": self.diff_limit,
                   "prompt_limit": self.prompt_limit, "output_limit": self.output_limit,
                   "source_limit": self.source_limit,
                   "env_digest": hashlib.sha256(json.dumps(self.env, sort_keys=True).encode()).hexdigest()}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def extract_c(output: str) -> str | None:
    """The candidate in a refiner's answer: the last fenced block, else the whole answer when it
    looks like C.  None when there is nothing usable."""
    blocks = _FENCE.findall(output or "")
    if blocks:
        text = blocks[-1].strip("\n")
        return text + "\n" if text.strip() else None
    text = (output or "").strip()
    if text and "```" not in text and _LOOKS_LIKE_C.search(text) and re.search(r"\)\s*\{", text):
        return text + "\n"
    return None


def run_command(command: list[str], prompt: str, timeout: float, env: dict | None = None,
                cwd: str | None = None, output_limit: int = 512 * 1024) -> str:
    """Run the refiner with the prompt on stdin and return its stdout.  The process group is
    killed on timeout; a non-zero exit or empty output raises :class:`RefineError`."""
    label = Path(command[0]).name
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, cwd=cwd, env={**os.environ, **(env or {})})
    except OSError as error:
        raise RefineError(f"cannot start {label}: {error.strerror or error.__class__.__name__}") from None
    stdout, stderr = bytearray(), bytearray()
    overflow = threading.Event()
    output_lock = threading.Lock()

    def stop() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def read(stream, target) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            with output_lock:
                remaining = output_limit - len(stdout) - len(stderr)
                if remaining <= 0 or len(chunk) > remaining:
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    overflow.set()
                else:
                    target.extend(chunk)
            if overflow.is_set():
                stop()
                return

    def write() -> None:
        try:
            process.stdin.write(prompt.encode())
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    threads = [threading.Thread(target=read, args=(process.stdout, stdout), daemon=True),
               threading.Thread(target=read, args=(process.stderr, stderr), daemon=True),
               threading.Thread(target=write, daemon=True)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None and time.monotonic() < deadline and not overflow.is_set():
            time.sleep(0.02)
        if process.poll() is None:
            stop()
        process.wait()
    except BaseException:
        stop()
        process.wait()
        raise
    finally:
        for thread in threads:
            thread.join(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except (AttributeError, OSError):
                pass
    stdout_text = bytes(stdout).decode(errors="replace")
    if overflow.is_set():
        raise RefineError(f"{label} exceeded the {output_limit}-byte output limit")
    if time.monotonic() >= deadline and process.returncode:
        raise RefineError(f"{label} timed out after {timeout:g}s") from None
    if process.returncode != 0:
        # Refiner diagnostics may contain provider credentials or private paths; keep them out of
        # durable case state and event logs. The command can log its own diagnostics explicitly.
        raise RefineError(f"{label} exited {process.returncode}")
    if not stdout_text.strip():
        raise RefineError(f"{label} printed nothing")
    return stdout_text


def candidate_problem(source: str, limit: int = 256 * 1024) -> str | None:
    """Reject non-ordinary or externally including C before it reaches a project compiler."""
    if len(source.encode()) > limit:
        return f"candidate exceeds the {limit}-byte source limit"
    provenance = scan_c(source)
    if provenance.verdict == Verdict.FORBIDDEN:
        return "forbidden matching escape: " + ", ".join(provenance.reasons)
    directives = [line.strip() for line in source.splitlines() if line.lstrip().startswith("#")]
    bad = [line for line in directives if not re.fullmatch(r'#\s*include\s+"types\.h"', line)]
    if bad or re.search(r"\b_Pragma\s*\(", source):
        return "unsupported preprocessor directive in external candidate"
    return None


def describe_evaluation(evaluation, limit: int = 40) -> str:
    """What the compiler made of a candidate, as text for the next round."""
    if evaluation is None:
        return "not built yet"
    if evaluation.score is None:
        return "It does not compile:\n" + _strip_paths((evaluation.error or "unknown error").strip())[-1500:]
    report = evaluation.report or {}
    lines = [f"It compiles. Difference score {evaluation.score} (0 is identical)."]
    counts = report.get("counts") or {}
    if counts:
        lines.append("Differences by kind: " + ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items())))
    if report.get("compiled_size") is not None and report.get("target_size") is not None \
            and report["compiled_size"] != report["target_size"]:
        lines.append(f"Compiled size is {report['compiled_size']} bytes, target is {report['target_size']}.")
    entries = report.get("entries") or []
    if entries:
        lines.append("Differing instructions (offset: yours | target):")
        for entry in entries[:limit]:
            where = entry.get("target_offset", entry.get("offset"))
            where = f"0x{where:X}" if isinstance(where, int) else "?"
            lines.append(f"  {where}: {entry.get('compiled') or '(missing)'} | {entry.get('retail') or '(extra)'}")
        if len(entries) > limit:
            lines.append(f"  ... and {len(entries) - limit} more")
    if evaluation.score == 0 and not evaluation.exact:
        proof = (evaluation.outcome or {}).get("proof") or {}
        names = ", ".join(str(a.get("name")) for a in proof.get("assumptions", [])[:8])
        lines.append("The bytes are identical; the remaining step is declaring these addresses in the "
                     f"project's symbol file: {names or 'see the strict verdict'}.")
    return "\n".join(lines)


def _strip_paths(text: str) -> str:
    """Compiler diagnostics without the build directory, which means nothing to the author."""
    return re.sub(r"(?:/[\w.+-]+)+/([\w.+-]+\.[ch])", r"\1", text)


def build_prompt(name: str, recipe: str, assembly: str, best_source: str | None, best_text: str,
                 causes: list[dict], attempts: list[tuple[str, str]], asm_limit: int = 400,
                 declarations: str = "") -> str:
    """One round's prompt.  ``attempts`` are this conversation's earlier answers with what the
    compiler made of each (most recent last)."""
    listing = assembly.strip().split("\n")
    if len(listing) > asm_limit + 20:
        listing = listing[:asm_limit] + [f"... ({len(listing) - asm_limit} more lines not shown)"]
    parts = [INSTRUCTIONS, f"Function: {name}", f"Compiler and flags: {recipe or 'unknown'}", "",
             "## Target assembly", "```", *listing, "```"]
    if declarations.strip():
        parts += ["", "## Declarations recovered from the whole image (evidence, not truth)", "```c",
                  declarations.strip()[:6000], "```"]
    if best_source:
        parts += ["", "## Best C so far", "```c", best_source.strip(), "```", "", "## What the compiler made of it",
                  best_text]
    if causes:
        parts += ["", "## Diagnosed causes of the remaining difference"]
        for cause in causes[:5]:
            evidence = "; ".join(str(e) for e in (cause.get("evidence") or [])[:2])
            parts.append(f"- {cause.get('cause') or cause.get('id')}: {cause.get('meaning', '')}"
                         + (f" ({evidence})" if evidence else ""))
    for number, (source, result) in enumerate(attempts, 1):
        parts += ["", f"## Your attempt {number}", "```c", source.strip(), "```", result]
    parts += ["", "Write the next version now: one ```c block, the whole translation unit."]
    return "\n".join(parts) + "\n"


def refine(name: str, settings: Settings, evaluate, assembly: str, recipe: str, best_source: str | None,
           best_evaluation, causes: list[dict] | None = None, prepare=None, declarations: str = "",
           emit=None, run=run_command) -> dict:
    """Converse about one function.  ``evaluate(text) -> (Evaluation, code)``; ``prepare(text)``
    turns an answer into a buildable unit (typedef prelude).  Returns ``{"rounds", "calls",
    "errors", "best_source", "best", "improved", "history"}`` where ``best`` is the Evaluation of
    ``best_source`` and ``improved`` says whether an answer beat the case's previous best."""
    def rank(evaluation) -> tuple:
        if evaluation is None or evaluation.score is None:
            return (2, 0)
        return (0 if evaluation.exact else 1, evaluation.score)

    best_text, best = best_source, best_evaluation
    settings.validate()
    start = rank(best)
    attempts: list[tuple[str, str]] = []
    history, calls, errors = [], 0, []
    for round_number in range(1, settings.rounds + 1):
        prompt = build_prompt(name, recipe, assembly, best_text,
                              describe_evaluation(best, settings.diff_limit) if best_text else "",
                              causes or [], attempts[-2:], settings.asm_limit, declarations)
        if len(prompt.encode()) > settings.prompt_limit:
            errors.append(f"prompt exceeds the {settings.prompt_limit}-byte limit")
            history.append({"round": round_number, "error": errors[-1]})
            break
        calls += 1
        try:
            # The configured executable is trusted code and still has the user's OS permissions,
            # but it should not receive the project checkout as its accidental working directory.
            with tempfile.TemporaryDirectory(prefix="n64dk-refiner-") as cwd:
                answer = run(settings.command, prompt, settings.timeout, settings.env, cwd=cwd,
                             output_limit=settings.output_limit)
        except RefineError as error:
            errors.append(str(error))
            history.append({"round": round_number, "error": str(error)[-200:]})
            if emit:
                emit({"event": "refine-error", "name": name, "round": round_number, "error": str(error)[-200:]})
            break                                              # a failing command is not retried per case
        candidate = extract_c(answer)
        if candidate is None:
            attempts.append((answer.strip()[:400], "No C code block was found in the answer."))
            history.append({"round": round_number, "error": "no code block"})
            continue
        problem = candidate_problem(candidate, settings.source_limit)
        if problem:
            attempts.append((candidate[:400], problem))
            history.append({"round": round_number, "error": problem})
            continue
        unit = prepare(candidate) if prepare else candidate
        evaluation, _code = evaluate(unit)
        result = describe_evaluation(evaluation, settings.diff_limit)
        attempts.append((candidate, result))
        history.append({"round": round_number, "score": evaluation.score, "exact": bool(evaluation.exact)})
        if emit:
            emit({"event": "refine-round", "name": name, "round": round_number, "score": evaluation.score,
                  "exact": bool(evaluation.exact)})
        if rank(evaluation) < rank(best):
            best_text, best = unit, evaluation
        if evaluation.exact or (evaluation.score == 0):
            break
    return {"rounds": len(history), "calls": calls, "errors": errors, "best_source": best_text, "best": best,
            "improved": rank(best) < start, "history": history}
