"""Tests run with their own state directory (machine lock, leases), so that a heavy job running
on the machine does not make them refuse to start, and with the resource preflight relaxed: the
safety tests exercise it with measured values of their own."""
import os
import tempfile

os.environ.setdefault("N64DK_STATE_DIR", tempfile.mkdtemp(prefix="n64dk-test-state-"))
os.environ.setdefault("N64DK_MIN_AVAILABLE_MB", "0")
os.environ.setdefault("N64DK_MIN_FREE_DISK_MB", "0")
os.environ.setdefault("N64DK_MAX_MEMORY_PRESSURE", "100")
