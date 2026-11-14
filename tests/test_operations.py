import json
import tempfile
import unittest
from pathlib import Path

from n64dk.operations import ScriptIndex, command_schema, inspect_script


class OperationTests(unittest.TestCase):
    def test_script_inspection_and_incremental_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "sweep_types.py"
            script.write_text("import argparse, subprocess\n"
                              "p=argparse.ArgumentParser()\n"
                              "p.add_argument('--jobs')\n"
                              "subprocess.run(['true'])\n")
            metadata = inspect_script(script, root)
            self.assertEqual(metadata["arguments"], ["--jobs"])
            self.assertIn("sweep", metadata["kinds"])
            self.assertIn("process-wrapper", metadata["kinds"])
            index = ScriptIndex(root / "index.sqlite")
            try:
                first = index.index([str(root)])
                second = index.index([str(root)])
                rows = index.query("sweep")
            finally:
                index.close()
            self.assertEqual(first["changed"], 1)
            self.assertEqual(second["changed"], 0)
            self.assertEqual(rows[0]["path"], "sweep_types.py")

    def test_operation_schema_is_serializable(self):
        schema = command_schema()
        self.assertEqual(schema["protocol"], "n64dk.operations.v1")
        self.assertTrue(any(row["name"] == "investigate" for row in schema["commands"]))
        json.dumps(schema)


if __name__ == "__main__":
    unittest.main()
