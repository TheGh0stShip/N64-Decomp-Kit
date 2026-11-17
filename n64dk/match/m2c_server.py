"""A fork server for m2c (on by default; ``N64DK_M2C_SERVER=0`` uses the command line).

Measured (round 11): one m2c run on a small function takes about 110 ms, nearly all of it
importing m2c (Python itself starts in 19 ms); m2c was 15-20% of the resolve stage's child CPU.
The server is a single-threaded process that imports m2c once and then, per draft, forks a fresh
child that runs ``m2c.main.main()`` with the draft's arguments, so every draft still runs in a
process of its own with fresh module state, exactly as the command line would, minus the import.

Measured at run level (round 11, determinism matrix): a 300-function Dr. Mario 64 run with the
server is identical to one without it in every case's status, score and best source.

Safety: the server is started like every tool (``safety.run_tool``'s rules): its own session,
the per-child address-space ceiling (inherited by its children), registration so a SIGTERM to the
job kills its process group, and the parent-death signal.  Servers are pooled per process
(``N64DK_M2C_SERVERS``, default 4) and started from one launcher thread that lives as long as
the process, because the parent-death signal fires when the starting *thread* exits.  Each draft takes a light token, has
a timeout enforced by the server (the child is killed) and by the client (the server is killed),
and is accounted under the ``m2c`` family with the child's own CPU time.  Any protocol failure
disables the server for the process and the caller falls back to the command line."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import types

ENV = "N64DK_M2C_SERVER"

_BOOT = r'''
import json, os, sys, time, ctypes, signal
import m2c.main
libc = ctypes.CDLL(None, use_errno=True)
out = os.fdopen(os.dup(1), "w", buffering=1)
for line in sys.stdin:
    request = json.loads(line)
    started = time.monotonic()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)            # PR_SET_PDEATHSIG: die with the server
            os.chdir(request["cwd"])
            for fd, name in ((1, "stdout"), (2, "stderr")):
                handle = os.open(os.path.join(request["cwd"], "m2c." + name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(handle, fd); os.close(handle)
            sys.stdout = os.fdopen(1, "w"); sys.stderr = os.fdopen(2, "w")
            sys.argv = ["m2c", *request["argv"]]
            try:
                m2c.main.main()
                code = 0
            except SystemExit as stop:
                code = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
            except BaseException:
                import traceback; traceback.print_exc(); code = 1
            sys.stdout.flush(); sys.stderr.flush()
        finally:
            os._exit(code)
    deadline = started + float(request["timeout"])
    timed_out, status, usage = False, None, None
    while True:
        done, status, usage = os.wait4(pid, os.WNOHANG)
        if done:
            break
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL); _d, status, usage = os.wait4(pid, 0); timed_out = True
            break
        time.sleep(0.001)
    out.write(json.dumps({"rc": os.waitstatus_to_exitcode(status), "timeout": timed_out,
                          "cpu": usage.ru_utime + usage.ru_stime, "wall": time.monotonic() - started}) + "\n")
'''

_POOL: dict = {"pid": None, "idle": [], "count": 0, "launcher": None, "requests": None}
_DISABLED = {"pid": None}
_LOCK = threading.Condition()


def limit() -> int:
    """Servers per process at most (``N64DK_M2C_SERVERS``, default 4); drafting threads beyond
    it wait for a free one."""
    try:
        return max(1, int(os.environ.get("N64DK_M2C_SERVERS", "4")))
    except ValueError:
        return 4


def wanted(command: list[str]) -> bool:
    """Opted in, and the located m2c is the one this interpreter imports (a ``scripts`` entry of
    this environment, or the module itself)."""
    if os.environ.get(ENV, "1") != "1" or _DISABLED["pid"] == os.getpid():
        return False
    try:
        import importlib.util
        if importlib.util.find_spec("m2c") is None:
            return False
    except (ImportError, ValueError):
        return False
    exe = os.path.realpath(command[0]) if command else ""
    here = os.path.realpath(os.path.dirname(sys.executable))
    return (os.path.dirname(exe) == here and os.path.basename(exe) == "m2c") or \
        command[:2] == [sys.executable, "-m"] or (len(command) > 2 and command[1] == "-c" and "m2c.main" in command[2])


class _Server:
    def __init__(self):
        from .. import safety
        argv = [sys.executable, "-c", _BOOT]
        guard = True
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, start_new_session=True, preexec_fn=safety.child_setup(guard))
        safety.limit_child(self.process.pid, False)
        safety.register_tool(self.process.pid)

    def close(self) -> None:
        from .. import safety
        import signal
        if self.process.returncode is None and self.process.poll() is None:
            try:                                                  # not reaped yet: the pid is still its own
                os.killpg(self.process.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.process.wait(5)
        except subprocess.TimeoutExpired:
            pass
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        safety.unregister_tool(self.process.pid)

    def run(self, argv: list[str], cwd: str, timeout: float) -> dict:
        import select
        self.process.stdin.write(json.dumps({"argv": argv, "cwd": cwd, "timeout": timeout}) + "\n")
        self.process.stdin.flush()
        ready, _w, _x = select.select([self.process.stdout], [], [], timeout + 10)
        if not ready:
            raise RuntimeError("m2c server did not answer")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("m2c server exited")
        return json.loads(line)


def _launch() -> "_Server":
    """Start a server from the process's launcher thread, which lives as long as the process: the
    parent-death signal follows the thread that started a child, not the process."""
    import queue
    if _POOL["launcher"] is None or not _POOL["launcher"].is_alive():
        requests: queue.Queue = queue.Queue()

        def serve():
            while True:
                reply = requests.get()
                try:
                    reply.put(_Server())
                except BaseException as error:                    # noqa: BLE001 - handed to the caller
                    reply.put(error)
        _POOL["requests"] = requests
        _POOL["launcher"] = threading.Thread(target=serve, name="n64dk-m2c-launcher", daemon=True)
        _POOL["launcher"].start()
    reply: "queue.Queue" = queue.Queue()
    _POOL["requests"].put(reply)
    made = reply.get()
    if isinstance(made, BaseException):
        raise RuntimeError(f"could not start the m2c server: {made}")
    return made


def _acquire() -> "_Server":
    with _LOCK:
        if _POOL["pid"] != os.getpid():                          # a forked worker never uses its parent's
            _POOL.update(pid=os.getpid(), idle=[], count=0, launcher=None, requests=None)
        while True:
            while _POOL["idle"]:
                server = _POOL["idle"].pop()
                if server.process.poll() is None:
                    return server
                server.close()
                _POOL["count"] -= 1
            if _POOL["count"] < limit():
                _POOL["count"] += 1
                break
            _LOCK.wait(1.0)
    try:
        return _launch()
    except BaseException:
        with _LOCK:
            _POOL["count"] -= 1
            _LOCK.notify()
        raise


def _release(server: "_Server", broken: bool) -> None:
    with _LOCK:
        if broken or server.process.poll() is not None:
            server.close()
            _POOL["count"] -= 1
        else:
            _POOL["idle"].append(server)
        _LOCK.notify()


def run(argv: list[str], cwd: str, timeout: float) -> subprocess.CompletedProcess:
    """Run m2c with ``argv`` (without the program) in ``cwd``.  Raises ``subprocess.TimeoutExpired``
    on timeout and ``RuntimeError`` when the server fails (the caller falls back)."""
    from .. import safety
    safety.throttle()
    with safety.token("light"):
        try:
            server = _acquire()
        except RuntimeError:
            _DISABLED["pid"] = os.getpid()
            raise
        started = time.monotonic()
        try:
            reply = server.run([str(a) for a in argv], cwd, timeout)
        except (OSError, ValueError, RuntimeError) as error:
            _release(server, True)
            _DISABLED["pid"] = os.getpid()
            raise RuntimeError(f"m2c server: {error}") from error
        _release(server, False)
    usage = types.SimpleNamespace(ru_utime=float(reply.get("cpu") or 0.0), ru_stime=0.0)
    safety.record_usage("m2c", time.monotonic() - started, usage, bool(reply.get("timeout")))
    def read(name: str) -> str:
        try:
            with open(os.path.join(cwd, "m2c." + name), errors="replace") as handle:
                return handle.read()
        except OSError:
            return ""
    stdout, stderr = read("stdout"), read("stderr")
    for name in ("stdout", "stderr"):
        try:
            os.unlink(os.path.join(cwd, "m2c." + name))
        except OSError:
            pass
    if reply.get("timeout"):
        raise subprocess.TimeoutExpired(["m2c", *argv], timeout, stdout, stderr)
    return subprocess.CompletedProcess(["m2c", *argv], int(reply["rc"]), stdout, stderr)


def shutdown() -> None:
    """Stop this process's servers (at exit, and between measurements)."""
    with _LOCK:
        if _POOL["pid"] == os.getpid():
            for server in _POOL["idle"]:
                server.close()
            _POOL["count"] -= len(_POOL["idle"])
            _POOL["idle"] = []


def running() -> int:
    with _LOCK:
        return _POOL["count"] if _POOL["pid"] == os.getpid() else 0


import atexit                                                      # noqa: E402
atexit.register(shutdown)
