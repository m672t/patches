"""Execute the real target binary on one test case under identical limits and environment."""
from __future__ import annotations

import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .config import DEFAULT_SAN_ENV
from .observation import classify_run
from .util import materialize, sha256_bytes, truncate


def signal_name(returncode: int) -> str | None:
    if returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return f"SIG{-returncode}"
    return None


def prepare_inputs(test: dict, cfg_base: Path) -> dict:
    """Materialise stdin and files once per test (bytes), reused for every run."""
    files = {name: materialize(spec, cfg_base) for name, spec in (test.get("files") or {}).items()}
    return {"stdin": materialize(test.get("stdin"), cfg_base) if test.get("stdin") is not None else None,
            "files": files}


def _expand_args(args: list[str], cwd: Path, files: dict) -> list[str]:
    out = []
    for a in args:
        a = a.replace("{cwd}", str(cwd))
        a = re.sub(r"\{file:([^}]+)\}", lambda m: str(cwd / m.group(1)), a)
        out.append(a)
    return out


def _limits(run_cfg: dict, sanitized: bool):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cpu = int(run_cfg["cpu_seconds"])
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
        if not sanitized and run_cfg.get("memory_mb"):   # ASan needs a huge virtual space
            m = int(run_cfg["memory_mb"]) << 20
            resource.setrlimit(resource.RLIMIT_AS, (m, m))
    return apply


def run_once(binary: str, test: dict, inputs: dict, run_cfg: dict, mode: str, build_root: str,
             artifact_dir: Path | None = None, tag: str = "run") -> dict:
    sanitized = mode == "sanitized"
    cwd = Path(tempfile.mkdtemp(prefix="pg_run_"))
    try:
        for name, data in inputs["files"].items():
            (cwd / name).write_bytes(data)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C",
               "HOME": str(cwd), "TMPDIR": str(cwd), **DEFAULT_SAN_ENV,
               **{k: str(v) for k, v in run_cfg.get("env", {}).items()},
               **{k: str(v) for k, v in test.get("env", {}).items()}}
        argv = [*run_cfg.get("exec_prefix", []), binary, *_expand_args(test.get("args", []), cwd, inputs["files"])]
        timeout = float(test.get("timeout", run_cfg["timeout"]))
        t0 = time.monotonic()
        timed_out = False
        try:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, preexec_fn=_limits(run_cfg, sanitized))
            try:
                out, err = p.communicate(inputs["stdin"] if inputs["stdin"] is not None else b"", timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                out, err = p.communicate()
            rc = p.returncode
            launch_error = None
        except OSError as e:
            out, err, rc, launch_error = b"", b"", None, str(e)
        wall = int((time.monotonic() - t0) * 1000)
        cap = int(run_cfg["max_output_bytes"])
        out, err = out[:cap], err[:cap]
        raw = {
            "exit_code": rc if rc is not None and rc >= 0 else None,
            "signal": signal_name(rc) if rc is not None else None,
            "timed_out": timed_out, "launch_error": launch_error, "wall_ms": wall,
            "stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace"),
        }
        raw["stdout_sha256"] = sha256_bytes(out)
        if artifact_dir:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            (artifact_dir / f"{tag}.stdout").write_bytes(out)
            (artifact_dir / f"{tag}.stderr").write_bytes(err)
            raw["artifacts"] = {"stdout": str(artifact_dir / f"{tag}.stdout"),
                                "stderr": str(artifact_dir / f"{tag}.stderr")}
        raw["cmd"] = argv
        raw.update(classify_run(raw, build_root, (test.get("expect") or {}).get("signal")))
        return raw
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


def check_expectation(test: dict, obs: dict) -> dict:
    """Compare against the independent reference stored in the test (never against the patched output)."""
    exp = test.get("expect") or {}
    checks = {k: v for k, v in exp.items() if k != "signal"}
    if not checks:
        return {"checked": False, "passed": None, "failures": []}
    fails = []
    if obs.get("timed_out"):
        fails.append("timeout")
    if obs.get("crash"):
        fails.append(f"crash:{obs.get('error_type')}")
    if "exit_code" in checks and obs["exit_code"] != checks["exit_code"]:
        fails.append(f"exit_code {obs['exit_code']} != {checks['exit_code']}")
    if "exit_code_in" in checks and obs["exit_code"] not in checks["exit_code_in"]:
        fails.append(f"exit_code {obs['exit_code']} not in {checks['exit_code_in']}")
    out = obs.get("stdout", "")
    if "stdout" in checks and out != checks["stdout"]:
        fails.append("stdout differs from reference")
    if "stdout_strip" in checks and out.strip() != checks["stdout_strip"].strip():
        fails.append("stdout (stripped) differs from reference")
    if "stdout_contains" in checks and checks["stdout_contains"] not in out:
        fails.append(f"stdout lacks {checks['stdout_contains']!r}")
    if "stdout_regex" in checks and not re.search(checks["stdout_regex"], out):
        fails.append(f"stdout does not match /{checks['stdout_regex']}/")
    if "stderr_contains" in checks and checks["stderr_contains"] not in obs.get("stderr", ""):
        fails.append(f"stderr lacks {checks['stderr_contains']!r}")
    return {"checked": True, "passed": not fails, "failures": fails}


def fingerprint(o: dict, exp: dict):
    return (o["exit_code"], o["signal"], o["timed_out"], o.get("error_type"), o.get("top_function"),
            exp["passed"])


def run_cell(binary, test, inputs, run_cfg, mode, build_root, artifact_dir, hooks=None) -> dict:
    """Run one (version, mode, test) `repeats` times; aggregate into a cell."""
    runs = []
    for i in range(int(run_cfg["repeats"])):
        obs = run_once(binary, test, inputs, run_cfg, mode, build_root, artifact_dir, tag=f"run{i + 1}")
        if hooks:
            obs = hooks(obs)
        obs["expectation"] = check_expectation(test, obs)
        runs.append(obs)
    stable = len({fingerprint(o, o["expectation"]) for o in runs}) == 1
    rep = runs[0]
    if not stable:
        kind = "unstable"
    elif rep["timed_out"]:
        kind = "timeout"
    elif rep["crash"]:
        kind = "crash"
    else:
        kind = "clean"
    return {"kind": kind, "stable": stable, "runs": runs, "rep": rep, "expectation": rep["expectation"],
            "run_count": len(runs)}


def summarize_obs(cell: dict, text_limit: int = 2000) -> dict:
    o = cell["rep"]
    return {
        "kind": cell["kind"], "stable": cell["stable"], "runs": cell["run_count"],
        "exit_code": o["exit_code"], "signal": o["signal"], "timed_out": o["timed_out"],
        "wall_ms": o["wall_ms"], "crash": o["crash"], "error_type": o["error_type"],
        "mechanism": o["mechanism"], "confirmed": o["confirmed"],
        "top_function": o.get("top_function"), "top_file": o.get("top_file"), "top_line": o.get("top_line"),
        "frames": o["app_frames"][:8] if o.get("app_frames") else o["frames"][:8],
        "stdout": truncate(o["stdout"], text_limit), "stderr": truncate(o["stderr"], text_limit),
        "stdout_sha256": o["stdout_sha256"], "expectation": cell["expectation"],
        "artifacts": o.get("artifacts"), "cmd": o["cmd"],
    }
