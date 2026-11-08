import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from patchguard.analyzer import eval_functional, eval_security, same_bug
from patchguard.correlate import DiffIndex, correlate_frames, summarize_correlation
from patchguard.diffparse import make_tree_diff, parse_unified_diff
from patchguard.observation import classify_run
from patchguard.pipeline import run_pipeline
from patchguard.srcmap import find_functions, norm_func
from patchguard.verdict import decide

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo"
HAVE_GCC = shutil.which("gcc") is not None


def cell(kind, error_type=None, confirmed=True, func=None, exp=None):
    rep = {"error_type": error_type, "confirmed": confirmed, "top_function": func,
           "crash": kind == "crash", "app_frames": [], "frames": []}
    return {"kind": kind, "rep": rep, "expectation": exp or {"checked": False, "passed": None, "failures": []}}


class VerdictPriority(unittest.TestCase):
    def f(self, status):
        return {"status": status, "test_id": "t", "reason": "r"}

    def test_pass(self):
        v = decide([self.f("FIXED")], {"baseline_reproduced": True, "functional_tests_checked": 1}, [])
        self.assertEqual((v["exit_code"], v["label"]), (0, "PASS"))

    def test_order_30_10_20_40(self):
        flags = {"baseline_reproduced": True, "functional_tests_checked": 1}
        allf = [self.f("FIX_INCOMPLETE"), self.f("FUNC_REGRESSION"), self.f("INCONCLUSIVE")]
        self.assertEqual(decide(allf, flags, ["build failed"])["exit_code"], 30)
        v = decide(allf, flags, [])
        self.assertEqual(v["exit_code"], 10)
        self.assertEqual(v["contributing_codes"], [10, 20, 40])      # nothing is lost
        self.assertEqual(decide(allf[1:], flags, [])["exit_code"], 20)
        self.assertEqual(decide(allf[2:], flags, [])["exit_code"], 40)

    def test_issue_new_label(self):
        v = decide([self.f("ISSUE_NEW")], {"baseline_reproduced": True, "functional_tests_checked": 1}, [])
        self.assertEqual((v["exit_code"], v["label"]), (10, "ISSUE_NEW"))

    def test_incomplete_without_baseline_or_functional(self):
        self.assertEqual(decide([], {"baseline_reproduced": False, "functional_tests_checked": 1}, [])["exit_code"], 40)
        self.assertEqual(decide([], {"baseline_reproduced": True, "functional_tests_checked": 0}, [])["exit_code"], 40)

    def test_warning_never_changes_code(self):
        v = decide([self.f("WARNING")], {"baseline_reproduced": True, "functional_tests_checked": 1}, [])
        self.assertEqual(v["exit_code"], 0)


class SecurityLogic(unittest.TestCase):
    T = {"role": "target", "category": "exploit", "expect": {}}

    def test_fixed(self):
        self.assertEqual(eval_security(self.T, cell("crash", "heap-buffer-overflow", func="f"), cell("clean"))["status"], "FIXED")

    def test_remains_same_bug_even_if_line_moved(self):
        r = eval_security(self.T, cell("crash", "heap-buffer-overflow", func="f"), cell("crash", "heap-buffer-overflow", func="f"))
        self.assertEqual(r["status"], "FIX_INCOMPLETE")

    def test_different_error_is_new_issue_not_remains(self):
        r = eval_security(self.T, cell("crash", "heap-buffer-overflow", func="f"), cell("crash", "null-pointer-dereference", func="g"))
        self.assertEqual(r["status"], "ISSUE_NEW")

    def test_unclassified_crash_is_inconclusive(self):
        r = eval_security(self.T, cell("clean"), cell("crash", "unclassified-sigsegv", confirmed=False))
        self.assertEqual(r["status"], "INCONCLUSIVE")
        r = eval_security(self.T, cell("crash", "unclassified-sigsegv", confirmed=False), cell("clean"))
        self.assertEqual(r["status"], "INCONCLUSIVE")

    def test_unstable_and_timeout_are_inconclusive(self):
        self.assertEqual(eval_security(self.T, cell("unstable"), cell("clean"))["status"], "INCONCLUSIVE")
        self.assertEqual(eval_security(self.T, cell("crash", "x"), cell("timeout"))["status"], "INCONCLUSIVE")

    def test_clean_both_has_no_finding(self):
        self.assertIsNone(eval_security({"role": "check"}, cell("clean"), cell("clean"))["status"])

    def test_functional(self):
        ok = {"checked": True, "passed": True, "failures": []}
        bad = {"checked": True, "passed": False, "failures": ["exit_code 2 != 0"]}
        self.assertEqual(eval_functional({}, cell("clean", exp=ok), cell("clean", exp=bad))["status"], "FUNC_REGRESSION")
        self.assertEqual(eval_functional({}, cell("clean", exp=bad), cell("clean", exp=ok))["status"], "INCONCLUSIVE")
        self.assertIsNone(eval_functional({}, cell("clean", exp=ok), cell("clean", exp=ok))["status"])
        self.assertIsNone(eval_functional({}, cell("clean"), cell("clean"))["status"])


class Parsing(unittest.TestCase):
    ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2
WRITE of size 6 at 0x1 thread T0
    #0 0x1 in __interceptor_strcpy ../../libsanitizer/x.cpp:1
    #1 0x2 in greet /w/build/base/sanitized/greet.c:14:9
    #2 0x3 in main /w/build/base/sanitized/greet.c:30:12
"""

    def test_asan(self):
        o = classify_run({"stderr": self.ASAN, "signal": None, "timed_out": False}, "/w/build/base/sanitized")
        self.assertEqual((o["error_type"], o["mechanism"], o["confirmed"]), ("heap-buffer-overflow", "sanitizer:asan", True))
        self.assertEqual(o["top_function"], "greet")
        self.assertEqual(o["app_frames"][0]["file"], "greet.c")

    def test_signal_unclassified_and_declared(self):
        raw = {"stderr": "", "signal": "SIGSEGV", "timed_out": False}
        o = classify_run(raw)
        self.assertTrue(o["crash"] and not o["confirmed"])
        self.assertTrue(classify_run(raw, expect_signal="SIGSEGV")["confirmed"])

    def test_canary_and_timeout(self):
        o = classify_run({"stderr": "*** stack smashing detected ***: terminated", "signal": "SIGABRT", "timed_out": False})
        self.assertEqual((o["error_type"], o["mechanism"]), ("stack-buffer-overflow", "canary:__stack_chk_fail"))
        self.assertFalse(classify_run({"stderr": "", "signal": "SIGKILL", "timed_out": True})["crash"])

    def test_ubsan(self):
        o = classify_run({"stderr": "a.c:5:3: runtime error: division by zero\n", "signal": None, "timed_out": False})
        self.assertEqual(o["error_type"], "divide-by-zero")

    def test_funcs(self):
        src = "int a;\nstatic int f(int x)\n{\n  if (x) { return 1; }\n  return 0;\n}\nvoid g(void) { }\n"
        fs = {f.name: (f.start, f.end) for f in find_functions(src)}
        self.assertEqual(fs, {"f": (2, 6), "g": (7, 7)})
        self.assertEqual(norm_func("ns::A<int>::run(int, char*)"), "run")

    def test_diff_parse(self):
        d = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -3,2 +3,3 @@ int f()\n a\n-b\n+B\n+C\n")
        (fd,) = parse_unified_diff(d)
        h = fd.hunks[0]
        self.assertEqual((fd.path, h.removed, h.added, h.section), ("x.c", [4], [4, 5], "int f()"))


class Correlation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir(); b.mkdir()
        (a / "x.c").write_text("int f(int n)\n{\n  int k = 0;\n  k = n * 2;\n  return k;\n}\nint g(void)\n{\n  return 1;\n}\n")
        (b / "x.c").write_text("int f(int n)\n{\n  int k = 0;\n  k = n * 3;\n  return k;\n}\nint g(void)\n{\n  return 1;\n}\n")
        self.idx = DiffIndex(parse_unified_diff(make_tree_diff(a, b)), a, b)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_levels(self):
        fr = lambda fn, ln: [{"function": fn, "file": "build/x.c", "line": ln}]  # noqa: E731
        self.assertEqual(correlate_frames(fr("f", 4), self.idx, "base")["level"], "direct_line")
        self.assertEqual(correlate_frames(fr("f", 5), self.idx, "base")["level"], "changed_function")
        self.assertEqual(correlate_frames(fr("g", 9), self.idx, "base")["level"], "changed_file")
        self.assertIsNone(correlate_frames([{"function": "f", "file": "other.c", "line": 4}], self.idx, "base"))

    def test_caller_in_stack_counts(self):
        stack = [{"function": "g", "file": "x.c", "line": 9}, {"function": "f", "file": "x.c", "line": 5}]
        ev = correlate_frames(stack, self.idx, "base")
        self.assertEqual((ev["level"], ev["stack_depth"]), ("changed_function", 1))

    def test_weak_is_not_linked_and_unknown_is_honest(self):
        weak = summarize_correlation([{"level": "changed_file", "type": "stack_frame"}])
        self.assertEqual(weak["relation"], "weak")
        self.assertEqual(summarize_correlation([None])["level"], "unknown")


def _cfg(tmp: Path, **patch):
    c = json.loads((DEMO / "config.json").read_text())
    c["versions"]["base"]["path"] = str(DEMO / "base")
    c["versions"]["patched"]["path"] = str(DEMO / patch.pop("patched", "correct"))
    c["workdir"] = str(tmp / "wd")
    c.update(patch)
    p = tmp / "cfg.json"
    p.write_text(json.dumps(c))
    return p


@unittest.skipUnless(HAVE_GCC, "gcc required")
class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_case(self, patched):
        return run_pipeline(_cfg(self.tmp, patched=patched), {"repeats": 2})

    def test_four_scenarios(self):
        for name, code in (("correct", 0), ("incomplete", 10), ("regression", 20), ("newissue", 10)):
            with self.subTest(name):
                r = self.run_case(name)
                self.assertEqual(r["verdict"]["exit_code"], code, r["verdict"]["reasons"])
        # deterministic: identical evidence -> identical verdict
        a, b = self.run_case("incomplete"), self.run_case("incomplete")
        self.assertEqual(a["verdict"], b["verdict"])

    def test_incomplete_details(self):
        r = self.run_case("incomplete")
        by = {f["test_id"]: f for f in r["findings"]}
        self.assertEqual(by["poc_original"]["status"], "FIXED")
        self.assertEqual(by["poc_variant_20"]["status"], "FIX_INCOMPLETE")
        self.assertEqual(by["poc_variant_20"]["error"]["error_type"], "stack-buffer-overflow")
        self.assertEqual(by["poc_original"]["correlation"]["level"], "direct_line")

    def test_build_failure_is_30_even_with_other_states(self):
        c = json.loads((DEMO / "config.json").read_text())
        p = _cfg(self.tmp)
        c = json.loads(p.read_text())
        c["build"]["modes"]["sanitized"]["cmd"] = "false"
        p.write_text(json.dumps(c))
        r = run_pipeline(p)
        self.assertEqual(r["verdict"]["exit_code"], 30)
        self.assertEqual(r["verdict"]["independent_states"]["infrastructure"], "ERROR")

    def test_config_errors_are_30(self):
        p = self.tmp / "bad.json"
        p.write_text(json.dumps({"versions": {}, "build": {"modes": {}}, "tests": []}))
        self.assertEqual(run_pipeline(p)["verdict"]["exit_code"], 30)
        p.write_text("{not json")
        self.assertEqual(run_pipeline(p)["verdict"]["exit_code"], 30)
        self.assertEqual(run_pipeline(self.tmp / "missing.json")["verdict"]["exit_code"], 30)

    def test_baseline_not_reproduced_is_40(self):
        c = _cfg(self.tmp)
        d = json.loads(c.read_text())
        d["versions"]["base"]["path"] = str(DEMO / "correct")      # "base" is not vulnerable
        c.write_text(json.dumps(d))
        r = run_pipeline(c, {"repeats": 2})
        self.assertEqual(r["verdict"]["exit_code"], 40)

    def test_exit_codes_priority_build_over_vuln(self):
        # incomplete patch (10) + a coverage-less build failure of release => 30 wins
        p = _cfg(self.tmp, patched="incomplete")
        d = json.loads(p.read_text())
        d["build"]["modes"]["release"]["cmd"] = "exit 3"
        p.write_text(json.dumps(d))
        self.assertEqual(run_pipeline(p)["verdict"]["exit_code"], 30)

    def test_git_sources_and_patch_file_override(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        sh = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True)  # noqa: E731
        sh("git", "init", "-q")
        sh("git", "config", "user.email", "t@t"); sh("git", "config", "user.name", "t")
        shutil.copy(DEMO / "base" / "greet.c", repo / "greet.c")
        sh("git", "add", "."); sh("git", "commit", "-qm", "base")
        shutil.copy(DEMO / "correct" / "greet.c", repo / "greet.c")
        sh("git", "commit", "-qam", "fix")
        p = _cfg(self.tmp)
        d = json.loads(p.read_text())
        d["versions"] = {"base": {"git": {"repo": str(repo), "rev": "HEAD~1"}},
                         "patched": {"git": {"repo": str(repo), "rev": "HEAD"}}}
        d["diff"] = {"file": str(self.tmp / "p.diff")}
        (self.tmp / "p.diff").write_text(subprocess.run(["git", "diff", "HEAD~1", "HEAD"], cwd=repo,
                                         capture_output=True, text=True).stdout)
        p.write_text(json.dumps(d))
        r = run_pipeline(p, {"repeats": 2})
        self.assertEqual(r["verdict"]["exit_code"], 0, r["verdict"]["reasons"])
        self.assertEqual(r["versions"]["base"]["kind"], "git")
        self.assertTrue(r["diff"]["origin"].startswith("file:"))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAVE_GCC, "gcc required")
class PluginHooks(unittest.TestCase):
    def test_plugin_can_add_tests_findings_and_sections(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "plug.py").write_text(
                "def provide_tests(ctx):\n"
                "    return [{'id': 'gen_long', 'category': 'boundary', 'stdin': {'text': 'Q', 'repeat': 64, 'suffix': '\\n'}}]\n"
                "def classify_run(obs, ctx):\n"
                "    return {'plugin_seen': True}\n"
                "def post_analysis(ctx, report):\n"
                "    report['hardening'] = {'ok': True, 'tests': len(ctx.tests)}\n"
                "    report['findings'].append({'id': 'H1', 'status': 'WARNING', 'kind': 'hardening',\n"
                "                               'test_id': '-', 'reason': 'demo', 'modes': []})\n")
            p = _cfg(tmp, plugins=[str(tmp / "plug.py")])
            r = run_pipeline(p, {"repeats": 2})
            ids = [t["id"] for t in r["tests"]]
            self.assertIn("gen_long", ids)
            self.assertEqual(r["hardening"]["tests"], 8)
            self.assertEqual(r["verdict"]["exit_code"], 0)      # WARNING never changes the code
            self.assertEqual([t for t in r["tests"] if t["id"] == "gen_long"][0]["security_status"], "FIXED")  # plugin-made input found the base bug
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
