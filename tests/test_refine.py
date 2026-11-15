import atexit
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from n64dk.match import iterate, refine


def _scratch() -> Path:
    path = tempfile.mkdtemp(prefix="n64dk-refine-test-")
    atexit.register(shutil.rmtree, path, True)
    return Path(path)


TARGET = b"".join(struct.pack(">I", w) for w in (0x84820004, 0x03E00008, 0x00000000))
EXACT = "s32 read(Thing *thing) {\n    s16 value;\n    value = thing->field;\n    return value;\n}\n"
NEAR = EXACT.replace("s16 value;", "u16 value;")
BROKEN = "s32 read(Thing *thing) {\n    return thing->;\n}\n"


def evaluate(text):
    """Pretend compiler: exact when ``value`` is s16, near when u16, an error when malformed."""
    if "thing->;" in text:
        return iterate.Evaluation(None, error="/tmp/build/abc/read.c, line 2: Syntax Error"), None
    if "s16 value;" in text:
        return iterate.Evaluation(0, True, {"counts": {}, "entries": []}), TARGET
    report = {"counts": {"instruction": 1}, "entries": [{"kind": "instruction", "target_offset": 0,
                                                         "compiled": "lhu $v0, 0x4($a0)", "retail": "lh $v0, 0x4($a0)"}]}
    return iterate.Evaluation(3, False, report), TARGET


def scripted(*answers):
    """A refiner that returns the given answers in turn and records every prompt."""
    prompts = []

    def run(command, prompt, timeout, env=None, cwd=None, **_kwargs):
        prompts.append(prompt)
        answer = answers[min(len(prompts), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer
    return run, prompts


def fenced(code):
    return "Here is the function.\n\n```c\n" + code + "```\nIt should match.\n"


class ExtractTest(unittest.TestCase):
    def test_last_fenced_block_wins(self):
        self.assertEqual(refine.extract_c("```c\nint a;\n```\ntext\n```c\nint b;\n```\n"), "int b;\n")

    def test_unfenced_c_is_accepted_and_prose_is_not(self):
        self.assertEqual(refine.extract_c("int f(void) {\n    return 1;\n}"), "int f(void) {\n    return 1;\n}\n")
        self.assertIsNone(refine.extract_c("I could not work this one out."))
        self.assertIsNone(refine.extract_c("```c\n\n```"))
        self.assertIsNone(refine.extract_c(""))


class ConversationTest(unittest.TestCase):
    SETTINGS = refine.Settings(command=["refiner"], rounds=3)

    def converse(self, *answers, best=None, rounds=3):
        run, prompts = scripted(*answers)
        settings = refine.Settings(command=["refiner"], rounds=rounds)
        best_eval = evaluate(best)[0] if best else None
        result = refine.refine("read", settings, evaluate, "lh $v0, 4($a0)\njr $ra\nnop", "ido5.3 -O2", best, best_eval,
                               [{"cause": "type.signedness", "meaning": "signed load", "evidence": ["0x0: lh vs lhu"]}],
                               run=run)
        return result, prompts

    def test_feedback_reaches_the_next_round_and_the_exact_answer_ends_the_conversation(self):
        result, prompts = self.converse(fenced(BROKEN), fenced(NEAR), fenced(EXACT), fenced(NEAR))
        self.assertTrue(result["best"].exact)
        self.assertEqual(result["best_source"], EXACT)
        self.assertEqual([h.get("score") for h in result["history"]], [None, 3, 0])
        self.assertEqual(len(prompts), 3)                                  # the fourth answer is never requested
        self.assertIn("It does not compile", prompts[1])
        self.assertIn("read.c, line 2: Syntax Error", prompts[1])
        self.assertNotIn("/tmp/build", prompts[1])                         # build paths are not shown
        self.assertIn("lhu $v0, 0x4($a0) | lh $v0, 0x4($a0)", prompts[2])   # the diff of the best so far
        self.assertIn("type.signedness", prompts[0])
        self.assertIn("Compiler and flags: ido5.3 -O2", prompts[0])

    def test_a_worse_answer_does_not_replace_the_best(self):
        result, _prompts = self.converse(fenced(BROKEN), fenced(BROKEN), best=NEAR, rounds=2)
        self.assertFalse(result["improved"])
        self.assertEqual(result["best_source"], NEAR)
        self.assertEqual(result["best"].score, 3)

    def test_an_answer_without_code_costs_a_round_and_nothing_else(self):
        result, prompts = self.converse("I am not sure.", fenced(EXACT))
        self.assertTrue(result["best"].exact)
        self.assertIn("No C code block was found", prompts[1])

    def test_a_failing_command_stops_the_conversation(self):
        result, prompts = self.converse(refine.RefineError("refiner exited 1: quota"), fenced(EXACT))
        self.assertEqual(len(prompts), 1)
        self.assertFalse(result["improved"])
        self.assertEqual(result["errors"], ["refiner exited 1: quota"])

    def test_long_assembly_is_truncated_in_the_prompt(self):
        text = refine.build_prompt("f", "kmc -O2", "\n".join(f"insn {i}" for i in range(2000)), None, "", [], [],
                                   asm_limit=100)
        self.assertIn("insn 99", text)
        self.assertNotIn("insn 150", text)
        self.assertIn("more lines not shown", text)


class CommandTest(unittest.TestCase):
    def script(self, body: str) -> list[str]:
        path = _scratch() / "refiner.py"
        path.write_text(body)
        return [sys.executable, str(path)]

    def test_prompt_goes_in_on_stdin_and_the_answer_comes_back(self):
        command = self.script("import sys\ntext = sys.stdin.read()\nprint('```c\\nint n = %d;\\n```' % len(text))\n")
        self.assertEqual(refine.extract_c(refine.run_command(command, "x" * 10, 30)), "int n = 10;\n")

    def test_failure_modes_raise(self):
        with self.assertRaisesRegex(refine.RefineError, "exited 3") as stopped:
            refine.run_command(self.script("import sys\nsys.stderr.write('no quota')\nsys.exit(3)\n"), "p", 30)
        self.assertNotIn("no quota", str(stopped.exception))       # external diagnostics are not persisted
        with self.assertRaisesRegex(refine.RefineError, "printed nothing"):
            refine.run_command(self.script("pass\n"), "p", 30)
        with self.assertRaisesRegex(refine.RefineError, "timed out"):
            refine.run_command(self.script("import time\ntime.sleep(30)\n"), "p", 0.5)
        with self.assertRaisesRegex(refine.RefineError, "cannot start"):
            refine.run_command(["/nonexistent/refiner"], "p", 5)

    def test_output_is_bounded(self):
        with self.assertRaisesRegex(refine.RefineError, "output limit"):
            refine.run_command(self.script("print('x' * 20000)\n"), "p", 5, output_limit=1024)

    def test_settings_from_configuration(self):
        self.assertIsNone(refine.Settings.from_table({}))
        built = refine.Settings.from_table({"command": "claude -p --model x", "rounds": 2, "max_cases": 50,
                                            "statuses": ["near"], "env": {"A": 1}})
        self.assertEqual(built.command, ["claude", "-p", "--model", "x"])
        self.assertEqual((built.rounds, built.max_cases, built.statuses, built.env), (2, 50, ("near",), {"A": "1"}))
        self.assertEqual(refine.Settings.from_table({"command": "a"}, "b c").command, ["b", "c"])

    def test_settings_are_bounded_and_signature_hides_environment_values(self):
        settings = refine.Settings(command=["a"], env={"TOKEN": "secret"})
        settings.validate()
        self.assertNotIn("secret", settings.signature())
        self.assertNotEqual(settings.signature(), refine.Settings(command=["b"]).signature())
        with self.assertRaisesRegex(ValueError, "rounds"):
            refine.Settings(command=["a"], rounds=0).validate()


class CandidateSafetyTest(unittest.TestCase):
    def test_external_candidate_must_be_ordinary_self_contained_c(self):
        self.assertIsNone(refine.candidate_problem(EXACT))
        self.assertIsNone(refine.candidate_problem('#include "types.h"\n' + EXACT))
        self.assertIn("forbidden", refine.candidate_problem('void f(void) { __asm__("nop"); }'))
        self.assertIn("preprocessor", refine.candidate_problem('#include "/tmp/answer.h"\n' + EXACT))
        self.assertIn("source limit", refine.candidate_problem(EXACT, 8))

    def test_forbidden_answer_costs_a_round_without_compiling(self):
        calls = []
        run, _prompts = scripted(fenced('void read(void) { __asm__("nop"); }'), fenced(EXACT))
        result = refine.refine("read", refine.Settings(command=["refiner"], rounds=2),
                               lambda text: calls.append(text) or evaluate(text), "jr $ra\nnop", "kmc -O2",
                               None, None, run=run)
        self.assertEqual(len(calls), 1)
        self.assertTrue(result["best"].exact)


class PrepareAnswerTest(unittest.TestCase):
    def test_prelude_is_added_and_duplicate_basic_typedefs_are_dropped(self):
        from n64dk.commands.resolve import prepare_answer
        text = prepare_answer("typedef unsigned char u8;\ntypedef struct { u8 a; } Thing;\nu8 f(Thing *t) { return t->a; }\n")
        self.assertIn("N64DK_M2C_PRELUDE", text)
        self.assertEqual(text.count("typedef unsigned char u8;"), 1)       # the prelude's, not the answer's
        self.assertNotIn("\ntypedef unsigned char u8;\n", text)
        self.assertIn("typedef struct { u8 a; } Thing;", text)
        self.assertEqual(prepare_answer(text), text)                       # idempotent


if __name__ == "__main__":
    unittest.main()
