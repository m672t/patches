"""Orchestration: config -> sources -> diff -> build -> run matrix -> analyse -> verdict -> report."""
from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import analyzer, builder, coverage as covmod, report as rpt, sources
from .config import Config, ConfigError, load_config
from .correlate import DiffIndex
from .diffparse import parse_unified_diff
from .plugins import call_hook, load_plugins
from .runner import prepare_inputs, run_cell, run_once
from .verdict import EXIT_ERROR, decide


@dataclass
class Context:
    """Everything a plugin (persons 2-4) may need. Stable, documented attachment surface."""
    cfg: Config
    workdir: Path
    versions: dict = field(default_factory=dict)      # name -> sources.VersionSrc
    builds: dict = field(default_factory=dict)        # (version, mode) -> build result dict
    tests: list = field(default_factory=list)
    inputs: dict = field(default_factory=dict)        # test_id -> prepared inputs (bytes)
    cells: dict = field(default_factory=dict)         # (version, mode, test_id) -> cell
    diff_index: DiffIndex | None = None
    diff_text: str = ""
    modes: list = field(default_factory=list)         # modes used for the comparison matrix


def run_pipeline(cfg_path, overrides: dict | None = None) -> dict:
    report = rpt.new_report(cfg_path, None)
    try:
        cfg = load_config(cfg_path, overrides)
    except ConfigError as e:
        report["errors"].append(str(e))
        return _finish(report, [], {})
    report["target"] = cfg["name"]
    if cfg.errors:
        report["errors"] += [f"config: {e}" for e in cfg.errors]
        return _finish(report, [], {})
    try:
        return _run(cfg, report)
    except sources.SourceError as e:
        report["errors"].append(f"source: {e}")
    except Exception as e:  # tool/environment failure must never look like a verdict on the patch
        report["errors"].append(f"internal error: {type(e).__name__}: {e}")
        report["warnings"].append(traceback.format_exc())
    return _finish(report, [], {})


def _run(cfg: Config, report: dict) -> dict:
    workdir = (cfg.base_dir / cfg["workdir"]).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    ctx = Context(cfg=cfg, workdir=workdir)
    plugins = load_plugins(cfg["plugins"], cfg.base_dir)

    # 1. sources + diff -------------------------------------------------------------------------
    for side in ("base", "patched"):
        ctx.versions[side] = sources.prepare_version(side, cfg["versions"][side], workdir, cfg.base_dir)
        v = ctx.versions[side]
        report["versions"][side] = {"id": v.version_id, "kind": v.kind, "origin": v.origin}
    ctx.diff_text, origin = sources.compute_diff(ctx.versions["base"], ctx.versions["patched"],
                                                 cfg["diff"], cfg.base_dir)
    (workdir / "patch.diff").write_text(ctx.diff_text)
    ctx.diff_index = DiffIndex(parse_unified_diff(ctx.diff_text), ctx.versions["base"].src_dir,
                               ctx.versions["patched"].src_dir)
    report["diff"] = {"origin": origin, "path": str(workdir / "patch.diff"), **ctx.diff_index.summary()}
    if not ctx.diff_index.entries:
        report["warnings"].append("the diff between base and patched is empty")

    # 2. build ----------------------------------------------------------------------------------
    modes_cfg = cfg["build"]["modes"]
    builds = builder.build_all(ctx.versions, modes_cfg, workdir, cfg["build"]["timeout"])
    report["builds"] = builds
    ctx.builds = {(b["version"], b["mode"]): b for b in builds}
    failed = [b for b in builds if not b["ok"] and b["mode"] != "coverage"]
    for b in failed:
        report["errors"].append(f"build failed: {b['version']}/{b['mode']}: {b['error']}")
    for v in ("base", "patched"):
        report["versions"][v]["binaries"] = {b["mode"]: {"path": b["binary"], "sha256": b["binary_sha256"]}
                                             for b in builds if b["version"] == v and b["ok"]}
    if failed:
        return _finish(report, [], {}, plugins=None)

    ctx.modes = [m for m in modes_cfg if m != "coverage"]

    # 3. tests (config + plugin-provided) ------------------------------------------------------
    tests = list(cfg["tests"])
    for extra in call_hook(plugins, "provide_tests", ctx):
        for t in extra or []:
            t.setdefault("category", "boundary"); t.setdefault("role", "check")
            t.setdefault("args", []); t.setdefault("env", {}); t.setdefault("expect", {})
            tests.append(t)
    ctx.tests = tests
    ctx.inputs = {t["id"]: prepare_inputs(t, cfg.base_dir) for t in tests}
    # keep exact inputs on disk: person 3's reproducer bundle and regression tests start from these
    for t in tests:
        d = workdir / "artifacts" / "inputs" / t["id"]
        d.mkdir(parents=True, exist_ok=True)
        if ctx.inputs[t["id"]]["stdin"] is not None:
            (d / "stdin.bin").write_bytes(ctx.inputs[t["id"]]["stdin"])
        for name, data in ctx.inputs[t["id"]]["files"].items():
            (d / f"file_{name}").write_bytes(data)

    # 4. run matrix: every test x {base, patched} x modes, identical limits ---------------------
    run_cfg = cfg["run"]
    def classify_hook(obs):
        for upd in call_hook(plugins, "classify_run", obs, ctx):
            if isinstance(upd, dict):
                obs.update(upd)
        return obs

    def job(version, mode, t):
        b = ctx.builds[(version, mode)]
        art = workdir / "artifacts" / "runs" / version / mode / t["id"]
        return (version, mode, t["id"]), run_cell(b["binary"], t, ctx.inputs[t["id"]], run_cfg, mode,
                                                  b["tree"], art, classify_hook)
    jobs = [(v, m, t) for t in tests for m in ctx.modes for v in ("base", "patched")]
    with ThreadPoolExecutor(max_workers=max(1, int(run_cfg["jobs"]))) as ex:
        for key, cell in ex.map(lambda a: job(*a), jobs):
            ctx.cells[key] = cell

    # 5. optional execution-path coverage (single run each, normal exits only) ------------------
    cov = {}
    if "coverage" in modes_cfg and all(ctx.builds.get((v, "coverage"), {}).get("ok") for v in ("base", "patched")):
        for t in tests:
            for v in ("base", "patched"):
                b = ctx.builds[(v, "coverage")]
                cov[(v, t["id"])] = covmod.collect(
                    b["tree"], lambda b=b, t=t: run_once(b["binary"], t, ctx.inputs[t["id"]], run_cfg,
                                                          "coverage", b["tree"]))
    elif "coverage" in modes_cfg:
        report["warnings"].append("coverage build failed; execution-path evidence unavailable")

    # 6. analyse --------------------------------------------------------------------------------
    test_reports, findings, flags = analyzer.analyze(tests, ctx.cells, ctx.modes, ctx.diff_index, cov)
    report["tests"], report["findings"] = test_reports, findings
    report["config_snapshot"] = {"modes": ctx.modes, "repeats": run_cfg["repeats"],
                                 "timeout": run_cfg["timeout"], "coverage": bool(cov)}
    return _finish(report, findings, flags, plugins=plugins, ctx=ctx)


def _finish(report: dict, findings, flags, plugins=None, ctx=None) -> dict:
    # plugins (hardening, reproducer bundles, ...) may add findings / sections before the verdict
    if plugins and ctx:
        for _ in call_hook(plugins, "post_analysis", ctx, report):
            pass
    report["verdict"] = decide(report["findings"], flags, report["errors"])
    return report
