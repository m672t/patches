"""Optional gcov-based execution-path evidence (mode named 'coverage', built with --coverage -O0)."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def collect(tree: str, run_fn) -> dict | None:
    """Reset counters, run the test once via run_fn(), then read executed lines via gcov JSON.

    Returns {file: [executed line numbers]} or None when unavailable (crash => no .gcda flushed).
    """
    root = Path(tree)
    for p in root.rglob("*.gcda"):
        p.unlink()
    obs = run_fn()
    if obs.get("crash") or obs.get("signal") or obs.get("timed_out"):
        return None
    gcdas = list(root.rglob("*.gcda"))
    if not gcdas or not shutil.which("gcov"):
        return None
    result: dict[str, set] = {}
    for g in gcdas:
        p = subprocess.run(["gcov", "--json-format", "--stdout", str(g.name)], cwd=g.parent,
                           capture_output=True, text=True)
        if p.returncode != 0:
            continue
        for line in p.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            for f in doc.get("files", []):
                name = f.get("file", "")
                hits = {l["line_number"] for l in f.get("lines", []) if l.get("count", 0) > 0}
                result.setdefault(name, set()).update(hits)
    return {k: sorted(v) for k, v in result.items()} if result else None
