
"""Plugin loader for PatchGuard plugins."""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path




def load_plugins(specs: list[str], base_dir: Path):
    mods = []
    for spec in specs or []:
        p = Path(spec)

        if not p.is_absolute():
            candidate = (base_dir / p).resolve()

            if candidate.is_file():
                p = candidate
            else:
                # Fallback: locate plugin from project directory
                matches = list(Path.cwd().resolve().glob(
                    "**/" + p.name
                ))
                matches = [
                    x for x in matches
                    if "plugins" in x.parts
                ]
                if not matches:
                    raise FileNotFoundError(
                        f"Plugin not found: {spec}"
                    )
                p = matches[0]

        if p.suffix == ".py":
            if not p.is_file():
                raise FileNotFoundError(f"Plugin not found: {p}")

            name = f"patchguard_plugin_{p.stem}"
            s = importlib.util.spec_from_file_location(name, p)

            if s is None or s.loader is None:
                raise ImportError(f"Cannot load plugin: {p}")

            mod = importlib.util.module_from_spec(s)
            s.loader.exec_module(mod)
        else:
            mod = importlib.import_module(spec)

        mods.append(mod)

    return mods


def call_hook(mods, name: str, *args):
    results = []

    for mod in mods:
        fn = getattr(mod, name, None)

        if callable(fn):
            results.append(fn(*args))

    return results
