import hashlib
import tempfile
import unittest
from pathlib import Path

from n64dk.handoff import inspect_handoff


class HandoffTests(unittest.TestCase):
    def inspect(self, content):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "handoff.txt"
            path.write_bytes(content.encode())
            return inspect_handoff(path)["checksums"]

    def document(self, manifest, extra=""):
        return "### file.c\n```c\nx\n```\n" + extra + "### SHA256SUMS.txt\n```text\n" + manifest + "```\n"

    def test_exact_bytes_without_authenticity_claim(self):
        digest = hashlib.sha256(b"x\n").hexdigest()
        result = self.inspect(self.document(digest + "  file.c\n"))
        self.assertTrue(result["complete"])
        self.assertFalse(result["authenticity_verified"])

    def test_missing_and_mismatch_are_not_repaired(self):
        result = self.inspect(self.document("0" * 64 + "  file.c\n" + "0" * 64 + "  absent\n"))
        self.assertEqual([x["status"] for x in result["entries"]], ["mismatch", "missing"])
        self.assertFalse(result["complete"])

    def test_duplicate_fences_and_paths_fail(self):
        digest = hashlib.sha256(b"x\n").hexdigest()
        result = self.inspect(self.document(digest + "  file.c\n", "### file.c\n```c\nx\n```\n"))
        self.assertTrue(result["errors"])
        self.assertFalse(result["complete"])
        result = self.inspect(self.document(digest + "  ../file.c\n"))
        self.assertTrue(result["errors"])

    def test_unlisted_artifact_and_malformed_manifest_fail(self):
        result = self.inspect(self.document("not a checksum\n"))
        self.assertEqual(result["unlisted"], ["file.c"])
        self.assertTrue(result["errors"])
        self.assertFalse(result["complete"])
