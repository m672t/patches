"""Command-line interface. Exit code == verdict code (0/10/20/30/40)."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .pipeline import run_pipeline
from .report import summary_text, write_json
from .verdict import EXIT_ERROR


def build_parser():
    p = argparse.ArgumentParser(prog="patchguard", description="Dynamic security-patch validation (CI/CD).")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="build, run and judge a patch (exit code = verdict)")
    v.add_argument("-c", "--config", required=True)
    v.add_argument("-o", "--json", dest="json_out", default=None,
                   help="JSON report path ('-' = stdout). Default: <workdir>/report.json")
    v.add_argument("--quiet", action="store_true", help="no human summary on stdout")
    g = v.add_argument_group("overrides (unseen patches / CI)")
    g.add_argument("--base-path"); g.add_argument("--patched-path")
    g.add_argument("--repo"); g.add_argument("--base-rev"); g.add_argument("--patched-rev")
    g.add_argument("--patch-file", help="use this unified diff instead of computing one")
    g.add_argument("--workdir"); g.add_argument("--repeats", type=int); g.add_argument("--jobs", type=int)

    c = sub.add_parser("check-config", help="validate a config file only (exit 30 on error)")
    c.add_argument("-c", "--config", required=True)

    d = sub.add_parser("diff", help="show how the patch maps to files/functions/lines")
    d.add_argument("-c", "--config", required=True)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "check-config":
        from .config import ConfigError, load_config
        try:
            cfg = load_config(a.config)
        except ConfigError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return EXIT_ERROR
        for e in cfg.errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print("config OK" if not cfg.errors else "config INVALID")
        return EXIT_ERROR if cfg.errors else 0

    ov = {k: getattr(a, k, None) for k in ("base_path", "patched_path", "repo", "base_rev", "patched_rev",
                                           "patch_file", "workdir", "repeats", "jobs")}
    if a.cmd == "diff":
        from .config import load_config
        from . import sources
        from .correlate import DiffIndex
        from .diffparse import parse_unified_diff
        from pathlib import Path
        cfg = load_config(a.config)
        wd = (cfg.base_dir / cfg["workdir"]).resolve()
        b = sources.prepare_version("base", cfg["versions"]["base"], wd, cfg.base_dir)
        p = sources.prepare_version("patched", cfg["versions"]["patched"], wd, cfg.base_dir)
        text, _ = sources.compute_diff(b, p, cfg["diff"], cfg.base_dir)
        print(json.dumps(DiffIndex(parse_unified_diff(text), b.src_dir, p.src_dir).summary(), indent=2))
        return 0

    report = run_pipeline(a.config, ov)
    out = a.json_out
    if out is None:
        from pathlib import Path
        try:
            from .config import load_config
            cfg = load_config(a.config, ov)
            wd = (cfg.base_dir / cfg["workdir"]).resolve()
            wd.mkdir(parents=True, exist_ok=True)
            out = str(wd / "report.json")
        except Exception:
            out = "patchguard-report.json"
    write_json(report, out)
    if not a.quiet and out != "-":
        print(summary_text(report))
        print(f"\nJSON report: {out}")
    return report["verdict"]["exit_code"]
