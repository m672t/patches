"""JSON report + human-readable summary."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import SCHEMA_VERSION, __version__

ORDER = ["FIX_INCOMPLETE", "ISSUE_NEW", "FUNC_REGRESSION", "INCONCLUSIVE", "FIXED"]
ICON = {"FIX_INCOMPLETE": "✗", "ISSUE_NEW": "✗", "FUNC_REGRESSION": "✗", "INCONCLUSIVE": "?", "FIXED": "✓"}


def new_report(cfg_path, target) -> dict:
    return {"schema_version": SCHEMA_VERSION, "tool": {"name": "patchguard", "version": __version__},
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "config": str(cfg_path) if cfg_path else None, "target": target,
            "versions": {}, "builds": [], "diff": {}, "tests": [], "findings": [], "errors": [],
            "warnings": [], "verdict": {}}


def write_json(report: dict, path: str):
    text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    if path == "-":
        print(text)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")


def summary_text(report: dict) -> str:
    v = report["verdict"]
    L = []
    L.append("=" * 72)
    L.append(f"PatchGuard  target={report['target']}  base={_short(report, 'base')}  patched={_short(report, 'patched')}")
    L.append("=" * 72)
    d = report.get("diff", {}).get("stats")
    if d:
        L.append(f"Diff: {d['files_changed']} file(s), -{d['lines_removed']} / +{d['lines_added']} lines")
    for b in report["builds"]:
        if not b["ok"]:
            L.append(f"BUILD FAILED  {b['version']}/{b['mode']}: {b['error']}  (log: {b['log']})")
    for e in report["errors"]:
        L.append(f"ERROR: {e}")
    findings = sorted(report["findings"], key=lambda f: ORDER.index(f["status"]) if f["status"] in ORDER else 99)
    if findings:
        L.append("")
        L.append("Findings")
        L.append("-" * 72)
    for f in findings:
        c = f.get("correlation", {})
        L.append(f"{ICON.get(f['status'], '-')} {f['id']} {f['status']:<15} test={f['test_id']} "
                 f"modes={','.join(f.get('modes', []))}")
        L.append(f"    {f['reason']}")
        if f["kind"] == "security" and f["error"].get("error_type"):
            e = f["error"]
            where = f" at {e['top_function']} ({e['top_file']}:{e['top_line']})" if e.get("top_function") else ""
            L.append(f"    error: {e['error_type']} via {e['mechanism']}{where}")
        L.append(f"    patch link: {c.get('level', 'unknown')} [{c.get('relation', 'unknown')}]"
                 + (f" - {c['note']}" if c.get("note") else ""))
        for ev in c.get("evidence", [])[:2]:
            if ev["type"] == "stack_frame":
                L.append(f"      ↳ {ev['side']} frame #{ev['stack_depth']} {ev['function']} "
                         f"{ev['file']}:{ev['line']} -> {ev['level']}")
    L.append("")
    ts = report["tests"]
    L.append(f"Tests: {len(ts)} run (security/functional status per test)")
    for t in ts:
        L.append(f"  {t['id']:<22} {t['category']:<10} security={t['security_status']:<15} functional={t['functional_status']}")
    L.append("")
    st = v["independent_states"]
    L.append(f"Independent states: security={st['security']} functional={st['functional']} "
             f"completeness={st['completeness']} infrastructure={st['infrastructure']}")
    for r in v["reasons"]:
        L.append(f"  {r}")
    L.append(f"VERDICT: {v['label']}  (exit code {v['exit_code']})")
    return "\n".join(L)


def _short(report, side):
    x = report["versions"].get(side, {})
    return (x.get("id") or "?")[:10]
