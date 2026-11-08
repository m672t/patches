import importlib.util
import unittest
from pathlib import Path

PLUGIN_PATH = Path(__file__).parents[1] / "plugins" / "person2.py"
spec = importlib.util.spec_from_file_location("person2", PLUGIN_PATH)
person2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(person2)


class FakeConfig:
    base_dir = Path(".")
    def get(self, key, default=None):
        if key == "tests":
            return [
                {"id": "seed", "category": "functional", "role": "check",
                 "stdin": "hello\n", "args": ["--name", "alice"],
                 "files": {"input.bin": {"hex": "414243"}},
                 "expect": {"exit_code": 0}},
            ]
        return default


class FakeContext:
    cfg = FakeConfig()


class Person2Tests(unittest.TestCase):
    def test_generate_tests_from_all_transports(self):
        generated = person2.provide_tests(FakeContext())
        self.assertTrue(generated)
        self.assertLessEqual(len(generated), person2.MAX_CASES)
        self.assertTrue(all(t["role"] == "check" for t in generated))
        self.assertTrue(all(t["expect"] == {} for t in generated))
        self.assertTrue(any("stdin" in t for t in generated))
        self.assertTrue(any("args" in t and t["args"] != ["--name", "alice"] for t in generated))
        self.assertTrue(any("files" in t for t in generated))

    def test_asan_heap_uaf_is_confirmed(self):
        result = person2.classify_run({
            "stderr": "ERROR: AddressSanitizer: heap-use-after-free on address 0x1234\n",
            "frames": [], "app_frames": [],
        }, None)
        self.assertEqual(result["error_type"], "use-after-free")
        self.assertTrue(result["confirmed"])
        self.assertEqual(result["mechanism"], "sanitizer:asan")

    def test_ubsan_division_by_zero(self):
        result = person2.classify_run({
            "stderr": "x.c:10:2: runtime error: division by zero\n"
        }, None)
        self.assertEqual(result["error_type"], "divide-by-zero")
        self.assertTrue(result["confirmed"])

    def test_glibc_double_free(self):
        result = person2.classify_run({
            "stderr": "free(): double free detected in tcache 2\n"
        }, None)
        self.assertEqual(result["error_type"], "double-free")
        self.assertTrue(result["confirmed"])

    def test_bare_segv_is_not_confirmed(self):
        result = person2.classify_run({"stderr": "", "signal": "SIGSEGV"}, None)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
