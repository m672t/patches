"""Plugin loader: how persons 2-4 attach their code without editing the core.

A plugin is "package.module" or "path/to/file.py" listed in config["plugins"]. It may define any of:

  provide_tests(ctx)            -> list[dict]   extra test-case dicts (person 2: boundary inputs)
  classify_run(obs, ctx)        -> dict | None  extra/overriding fields for an observation (person 2)
  post_analysis(ctx, report)    -> None         may mutate `report` and append to report["findings"],
                                                add report["hardening"], bundles, ... (persons 2-4)
Statuses recognised by the verdict: FIX_INCOMPLETE, ISSUE_NEW, FUNC_REGRESSION, INCONCLUSIVE, FIXED
(+ "WARNING"/"INFO", which never change the exit code).
"""
from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path


def load_plugins(specs: list[str], base_dir: Path):
    mods = []
    for spec in specs or []:
        p = (base_dir / spec)
        if spec.endswith(".py") and p.is_file():
            s = importlib.util.spec_from_file_location(p.stem, p)
            mod = importlib.util.module_from_spec(s)
            s.loader.exec_module(mod)  # type: ignore[union-attr]
        else:
            mod = importlib.import_module(spec)
        mods.append(mod)
    return mods


def call_hook(mods, name: str, *args):
    results = []
    for m in mods:
        fn = getattr(m, name, None)
        if callable(fn):
            results.append(fn(*args))
    return results
