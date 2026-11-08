"""Exit-code policy. Priority when several states coexist: 30 > 10 > 20 > 40 > 0."""
from __future__ import annotations

EXIT_PASS, EXIT_VULN, EXIT_REGRESSION, EXIT_ERROR, EXIT_INCONCLUSIVE = 0, 10, 20, 30, 40
PRIORITY = [EXIT_ERROR, EXIT_VULN, EXIT_REGRESSION, EXIT_INCONCLUSIVE, EXIT_PASS]
LABELS = {0: "PASS", 20: "REGRESSION_FUNC", 30: "ERROR_CONFIG_OR_BUILD", 40: "INCONCLUSIVE"}


def decide(findings: list[dict], flags: dict, errors: list[str]) -> dict:
    st = [f["status"] for f in findings]
    reasons: list[str] = []
    codes: set[int] = set()

    if errors:
        codes.add(EXIT_ERROR)
        reasons += [f"[30] {e}" for e in errors]
    remains = [f for f in findings if f["status"] == "FIX_INCOMPLETE"]
    new = [f for f in findings if f["status"] == "ISSUE_NEW"]
    if remains or new:
        codes.add(EXIT_VULN)
        reasons += [f"[10] {f['status']} ({f['test_id']}): {f['reason']}" for f in remains + new]
    reg = [f for f in findings if f["status"] == "FUNC_REGRESSION"]
    if reg:
        codes.add(EXIT_REGRESSION)
        reasons += [f"[20] FUNC_REGRESSION ({f['test_id']}): {f['reason']}" for f in reg]
    inc = [f for f in findings if f["status"] == "INCONCLUSIVE"]
    incomplete = bool(inc)
    if inc:
        reasons += [f"[40] INCONCLUSIVE ({f['test_id']}): {f['reason']}" for f in inc]
    if not errors:
        if not flags.get("baseline_reproduced"):
            incomplete = True
            reasons.append("[40] the target error was not (stably) reproduced on the base version")
        if flags.get("functional_tests_checked", 0) == 0:
            incomplete = True
            reasons.append("[40] no functional test with an independent reference was evaluated")
    if incomplete:
        codes.add(EXIT_INCONCLUSIVE)
    if not codes:
        codes.add(EXIT_PASS)
        reasons.append("[0] target error reproduced on base, absent on patched; no other confirmed error; "
                       "all functional checks passed")

    exit_code = next(c for c in PRIORITY if c in codes)
    if exit_code == EXIT_VULN:
        label = "REMAINS_VULN" if remains else "ISSUE_NEW"
    else:
        label = LABELS[exit_code]
    independent = {
        "infrastructure": "ERROR" if errors else "OK",
        "security": ("REMAINS_VULN" if remains else "ISSUE_NEW" if new else "NO_CONFIRMED_ERROR_IN_PATCHED"),
        "functional": "REGRESSION_FUNC" if reg else "OK",
        "completeness": "INCOMPLETE" if (incomplete or errors) else "COMPLETE",
    }
    return {"label": label, "exit_code": exit_code, "contributing_codes": sorted(codes),
            "independent_states": independent, "reasons": reasons,
            "counts": {s: st.count(s) for s in sorted(set(st))}}
