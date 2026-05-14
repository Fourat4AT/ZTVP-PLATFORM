from typing import Any, Dict


def simulate_ha1(report: Dict[str, Any], users_to_fix: int) -> Dict[str, Any]:
    evidence = report.get("evidence") or {}

    total = int(evidence.get("synced_user_count") or 0)
    strong_before = int(evidence.get("users_with_strong_method_count") or 0)
    missing_before = int(evidence.get("users_missing_strong_method_count") or 0)

    users_to_fix = max(0, min(users_to_fix, missing_before))

    strong_after = strong_before + users_to_fix
    missing_after = missing_before - users_to_fix

    if total == 0:
        expected_status = "PARTIAL"
        expected_risk = "MEDIUM"
        message = "No enabled synced users were detected, so H-A1 cannot be fully validated."
    elif missing_after == 0:
        expected_status = "PASS"
        expected_risk = "LOW"
        message = "All enabled synced users would have strong authentication method evidence."
    elif missing_after <= max(1, round(total * 0.10)):
        expected_status = "PARTIAL"
        expected_risk = "LOW"
        message = "Most synced users would have strong methods, but a small remaining group still needs remediation."
    else:
        expected_status = "PARTIAL"
        expected_risk = "MEDIUM"
        message = "Some synced users would still be missing strong authentication method evidence."

    resolved_finding = users_to_fix > 0 and missing_after == 0

    return {
        "scenario": "H-A1",
        "change": f"Register strong authentication methods for {users_to_fix} synced user(s).",
        "before": {
            "synced_users": total,
            "with_strong_methods": strong_before,
            "missing_strong_methods": missing_before,
            "status": report.get("status"),
            "risk": report.get("risk"),
        },
        "after": {
            "synced_users": total,
            "with_strong_methods": strong_after,
            "missing_strong_methods": missing_after,
            "expected_status": expected_status,
            "expected_risk": expected_risk,
        },
        "finding_resolved": resolved_finding,
        "remaining_gap": message,
    }


def can_simulate(report: Dict[str, Any]) -> bool:
    return (report.get("scenario_id") or "").upper() == "H-A1"
