"""Build every (version, mode) in its own source copy; record binary hashes and logs."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .util import sha256_file


def build_one(version: str, mode: str, mcfg: dict, src_dir: Path, workdir: Path, timeout: int) -> dict:
    tree = workdir / "build" / version / mode
    if tree.exists():
        shutil.rmtree(tree)
    shutil.copytree(src_dir, tree)
    env = {**os.environ, "LC_ALL": "C", **{k: str(v) for k, v in (mcfg.get("env") or {}).items()}}
    log = workdir / "logs" / f"build_{version}_{mode}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    res = {"version": version, "mode": mode, "cmd": mcfg["cmd"], "tree": str(tree), "log": str(log),
           "ok": False, "returncode": None, "binary": None, "binary_sha256": None, "error": None}
    try:
        p = subprocess.run(mcfg["cmd"], shell=True, cwd=tree, env=env, capture_output=True,
                           text=True, timeout=timeout)
        log.write_text(f"$ {mcfg['cmd']}\n--- stdout ---\n{p.stdout}\n--- stderr ---\n{p.stderr}\n")
        res["returncode"] = p.returncode
        binary = (tree / mcfg["binary"])
        if p.returncode != 0:
            res["error"] = f"build command exited with {p.returncode}"
        elif not binary.is_file():
            res["error"] = f"binary not produced: {mcfg['binary']}"
        else:
            res.update(ok=True, binary=str(binary), binary_sha256=sha256_file(binary))
    except subprocess.TimeoutExpired:
        res["error"] = f"build timed out after {timeout}s"
        log.write_text(f"$ {mcfg['cmd']}\nTIMEOUT\n")
    res["seconds"] = round(time.time() - t0, 2)
    return res


def build_all(versions: dict, modes: dict, workdir: Path, timeout: int, jobs: int = 4) -> list[dict]:
    """versions: name -> VersionSrc. Returns list of build results (deterministic order)."""
    todo = [(v, m) for v in versions for m in modes]
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        futs = [ex.submit(build_one, v, m, modes[m], versions[v].src_dir, workdir, timeout) for v, m in todo]
        return [f.result() for f in futs]
