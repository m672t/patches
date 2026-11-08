"""Decision logic: per-test, per-mode outcomes -> findings (FIXED / FIX_INCOMPLETE / ISSUE_NEW /
FUNC_REGRESSION / INCONCLUSIVE). Pure functions over observed cells: same evidence => same result.
"""
from __future__ import annotations

from .correlate import DiffIndex, correlate_coverage, correlate_frames, summarize_correlation
from .runner import summarize_obs

# worst-first priority when several modes disagree about one test
PRIORITY = ["FIX_INCOMPLETE", "ISSUE_NEW", "FUNC_REGRESSION", "INCONCLUSIVE", "FIXED"]


def same_bug(b: dict, p: dict) -> bool:
    """Same error class, and same top application function when both are known."""
    if b.get("error_type") != p.get("error_type"):
        return False
    bf, pf = b.get("top_function"), p.get("top_function")
    return not (bf and pf) or bf == pf


def eval_security(test: dict, bcell: dict, pcell: dict) -> dict:
    """Outcome of one test in one build mode."""
    b, p = bcell["kind"], pcell["kind"]
    br, pr = bcell["rep"], pcell["rep"]
    if "unstable" in (b, p):
        side = "base" if b == "unstable" else "patched"
        return {"status": "INCONCLUSIVE", "why": f"unstable result on {side} (replays disagree)"}
    if b == "crash":
        if not br["confirmed"]:
            return {"status": "INCONCLUSIVE", "why": f"base stopped abnormally ({br['error_type']}) but is not "
                    "classified as a memory/security error"}
        if p == "clean":
            return {"status": "FIXED", "why": f"base: {br['error_type']}; patched: no error in this test's scope"}
        if p == "timeout":
            return {"status": "INCONCLUSIVE", "why": "patched exceeded the time limit (not a classified error)"}
        if same_bug(br, pr):
            return {"status": "FIX_INCOMPLETE", "why": f"{pr['error_type']} still occurs at "
                    f"{pr.get('top_function') or 'unknown location'}"}
        if pr["confirmed"]:
            return {"status": "ISSUE_NEW", "why": f"patched fails differently: {pr['error_type']} "
                    f"(base was {br['error_type']})", "base_error_gone": True}
        return {"status": "INCONCLUSIVE", "why": "patched stops abnormally without a classified error"}
    if b == "timeout":
        if p == "crash" and pr["confirmed"]:
            return {"status": "ISSUE_NEW", "why": f"patched: {pr['error_type']}; base timed out"}
        return {"status": "INCONCLUSIVE", "why": "base exceeded the time limit"}
    # base clean
    if p == "crash":
        if pr["confirmed"]:
            return {"status": "ISSUE_NEW", "why": f"new {pr['error_type']} in patched; base clean on this test"}
        return {"status": "INCONCLUSIVE", "why": "patched stops abnormally without a classified error"}
    if p == "timeout":
        return {"status": "INCONCLUSIVE", "why": "patched exceeded the time limit; base did not"}
    return {"status": None, "why": "clean in both"}


def eval_functional(test: dict, bcell: dict, pcell: dict, mode: str = "release") -> dict:
    be, pe = bcell["expectation"], pcell["expectation"]
    if not be["checked"]:
        return {"status": None, "why": "no reference expectation"}
    if "unstable" in (bcell["kind"], pcell["kind"]):
        return {"status": "INCONCLUSIVE", "why": "unstable functional result"}
    if mode != "release" and pcell["kind"] == "crash" and pcell["rep"]["confirmed"]:
        return {"status": None, "why": "instrumented-build abort is reported as a security finding, not as "
                "a functional deviation"}
    if bcell["kind"] == "crash":      # base itself crashes here: not a behaviour baseline
        return {"status": None, "why": "base crashes on this input; no behavioural baseline"}
    if not be["passed"]:
        return {"status": "INCONCLUSIVE", "why": "base does not satisfy the reference ("
                + "; ".join(be["failures"]) + ") - reference or test is invalid", "reference_mismatch": True}
    if pe["passed"]:
        return {"status": None, "why": "behaviour preserved"}
    return {"status": "FUNC_REGRESSION", "why": "base met the reference, patched violates it: "
            + "; ".join(pe["failures"]), "failures": pe["failures"]}


def _frames(cell: dict):
    o = cell["rep"]
    return o.get("app_frames") or []


def analyze(tests: list[dict], cells: dict, modes: list[str], index: DiffIndex,
            coverage: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    """cells[(version, mode, test_id)] -> cell. Returns (test_reports, findings, flags)."""
    coverage = coverage or {}
    findings: list[dict] = []
    reports: list[dict] = []
    baseline_reproduced = False
    functional_checked = 0
    fid = 0

    for t in tests:
        tid = t["id"]
        per_mode, sec_outs, fn_outs = {}, {}, {}
        for m in modes:
            b, p = cells[("base", m, tid)], cells[("patched", m, tid)]
            sec = eval_security(t, b, p)
            fn = eval_functional(t, b, p, m) if t["category"] != "exploit" or t["expect"] else {"status": None}
            sec_outs[m], fn_outs[m] = sec, fn
            per_mode[m] = {"base": summarize_obs(b), "patched": summarize_obs(p),
                           "security": sec, "functional": fn}
            if t["role"] == "target" and b["kind"] == "crash" and b["stable"] and b["rep"]["confirmed"]:
                baseline_reproduced = True
        if t["expect"] and t["category"] != "exploit" and any(
                cells[("base", m, tid)]["kind"] != "crash" and cells[("base", m, tid)]["expectation"]["checked"]
                for m in modes):
            functional_checked += 1

        # ---- group per-mode security outcomes into findings
        groups: dict[tuple, list[str]] = {}
        for m, o in sec_outs.items():
            if o["status"]:
                groups.setdefault((o["status"], ""), []).append(m)
        base_seen = any(cells[("base", m, tid)]["kind"] == "crash" and cells[("base", m, tid)]["stable"]
                        and cells[("base", m, tid)]["rep"]["confirmed"] for m in modes)
        if t["role"] in ("target", "variant") and not base_seen and not any(
                s == "INCONCLUSIVE" for (s, _w) in groups):
            groups[("INCONCLUSIVE", "base did not reproduce the expected error on this test")] = list(modes)
        for (status, why), ms in groups.items():
            fid += 1
            m0 = "sanitized" if "sanitized" in ms else ms[0]      # richest evidence first
            why = why or sec_outs[m0]["why"]
            b, p = cells[("base", m0, tid)], cells[("patched", m0, tid)]
            src_cell = p if status in ("FIX_INCOMPLETE", "ISSUE_NEW") else b
            ev = []
            # base stack vs what the patch removed/changed; patched stack vs what it added/changed
            for mm in ms:
                bc, pc = cells[("base", mm, tid)], cells[("patched", mm, tid)]
                ev.append(correlate_frames(_frames(bc), index, "base") if bc["kind"] == "crash" else None)
                ev.append(correlate_frames(_frames(pc), index, "patched") if pc["kind"] == "crash" else None)
            cb, cp = coverage.get(("base", tid)), coverage.get(("patched", tid))
            ev.append(correlate_coverage(cb, cp, index, outcome_differs=status in ("FIXED", "ISSUE_NEW")))
            corr = summarize_correlation(ev)
            if status == "ISSUE_NEW" and corr["relation"] == "linked":
                corr["note"] = ("newly observed error whose stack passes through code the patch changed; "
                                "association only - observing a new error does not by itself prove causation")
            elif status == "ISSUE_NEW":
                corr["note"] = corr.get("note") or "new error; causal link to the patch is not established"
            findings.append({
                "id": f"F{fid:03d}", "status": status, "kind": "security", "test_id": tid,
                "test_category": t["category"], "test_role": t["role"], "modes": ms, "reason": why,
                "error": {k: src_cell["rep"].get(k) for k in
                          ("error_type", "mechanism", "confirmed", "signal", "exit_code", "top_function",
                           "top_file", "top_line")},
                "correlation": corr,
                "base": per_mode[m0]["base"], "patched": per_mode[m0]["patched"],
            })

        # ---- functional findings
        fgroups: dict[tuple, list[str]] = {}
        for m, o in fn_outs.items():
            if o.get("status"):
                fgroups.setdefault((o["status"], ""), []).append(m)
        for (status, why), ms in fgroups.items():
            fid += 1
            m0 = "release" if "release" in ms else ms[0]
            why = fn_outs[m0]["why"]
            b, p = cells[("base", m0, tid)], cells[("patched", m0, tid)]
            ev = [correlate_coverage(coverage.get(("base", tid)), coverage.get(("patched", tid)), index,
                                     outcome_differs=status == "FUNC_REGRESSION")]
            findings.append({
                "id": f"F{fid:03d}", "status": status, "kind": "functional", "test_id": tid,
                "test_category": t["category"], "test_role": t["role"], "modes": ms, "reason": why,
                "reference": t.get("expect"), "correlation": summarize_correlation(ev),
                "base": per_mode[m0]["base"], "patched": per_mode[m0]["patched"],
            })

        sec_status = _worst([o["status"] for o in sec_outs.values()])
        fn_status = _worst([o.get("status") for o in fn_outs.values()])
        reports.append({
            "id": tid, "category": t["category"], "role": t["role"], "description": t.get("description"),
            "security_status": sec_status or ("OK" if t["role"] == "check" else "NO_EFFECT"),
            "functional_status": fn_status or ("OK" if t["expect"] and t["category"] != "exploit" else "N/A"),
            "modes": per_mode,
        })

    flags = {"baseline_reproduced": baseline_reproduced, "functional_tests_checked": functional_checked}
    return reports, findings, flags


def _worst(statuses):
    present = [s for s in statuses if s]
    for s in PRIORITY:
        if s in present:
            return s
    return None
