from __future__ import annotations

from typing import Any


def _text(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _lower(value: object) -> str:
    return _text(value).lower()


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _first(*values: object, default: str = "Unknown") -> str:
    for value in values:
        text = _text(value)
        if text and text.lower() not in {"none", "null", "unknown", "n/a", "not recorded"}:
            return text
    return default


def _policy_name(policy: Any) -> str:
    if not isinstance(policy, dict):
        return _text(policy)
    return _first(policy.get("displayName"), policy.get("display_name"), policy.get("name"), default="")


def _policy_result(policy: Any) -> str:
    if not isinstance(policy, dict):
        return ""
    return _first(policy.get("result"), policy.get("Result"), default="")


def _controls(policy: Any) -> list[str]:
    if not isinstance(policy, dict):
        return []
    values: list[str] = []
    for key in (
        "enforcedGrantControls",
        "enforced_grant_controls",
        "grantControls",
        "grant_controls",
        "sessionControls",
        "enforcedSessionControls",
        "enforced_session_controls",
    ):
        raw = policy.get(key)
        if isinstance(raw, dict):
            values.extend(_as_list(raw.get("builtInControls")))
            values.extend(_as_list(raw.get("customAuthenticationFactors")))
            values.extend(_as_list(raw.get("operator")))
        else:
            values.extend(_as_list(raw))
    return [_text(item) for item in values if _text(item)]


def _policy_blob(policy: Any) -> str:
    if not isinstance(policy, dict):
        return _text(policy)
    return " ".join([_policy_name(policy), _policy_result(policy), *(_controls(policy))])


def _is_report_only(policy: Any) -> bool:
    return _lower(_policy_result(policy)).startswith("reportonly")


def _is_enforced(policy: Any) -> bool:
    return _lower(_policy_result(policy)) in {"success", "failure"}


def _is_applied(policy: Any) -> bool:
    result = _lower(_policy_result(policy))
    return result in {"success", "failure"} or result.startswith("reportonlysuccess") or result.startswith("reportonlyfailure")


def _has_mfa(policy: Any) -> bool:
    return "mfa" in _lower(_policy_blob(policy)) or "multi" in _lower(_policy_blob(policy))


def _has_device_control(policy: Any) -> bool:
    blob = _lower(_policy_blob(policy))
    return "compliant" in blob or "hybrid" in blob or "managed" in blob or "device" in blob


def _has_block(policy: Any) -> bool:
    blob = _lower(_policy_blob(policy))
    return "block" in blob or _lower(_policy_result(policy)) == "failure"


def _policy_row(policy: Any, meaning: str) -> dict[str, str]:
    return {
        "Policy": _policy_name(policy) or "Unnamed policy",
        "Result": _policy_result(policy) or "Unknown",
        "Grant control": ", ".join(_controls(policy)) or "Not recorded",
        "Meaning": meaning,
    }


def _policy_key(policy: Any) -> str:
    if not isinstance(policy, dict):
        return _text(policy).lower()
    policy_id = _first(policy.get("id"), policy.get("policyId"), policy.get("policy_id"), default="")
    if policy_id:
        return f"id:{policy_id.lower()}"
    controls = ",".join(_controls(policy)).lower()
    return f"{_policy_name(policy).lower()}|{_policy_result(policy).lower()}|{controls}"


def _dedupe_policies(policies: object) -> list[Any]:
    deduped: list[Any] = []
    seen: set[str] = set()
    for policy in _as_list(policies):
        key = _policy_key(policy)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(policy)
    return deduped


def relevant_policies(policies: object, purpose: str = "mfa") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    purpose = purpose.lower()
    for policy in _dedupe_policies(policies):
        if not isinstance(policy, dict):
            continue
        result = _lower(_policy_result(policy))
        applies = _is_applied(policy)
        mfa = _has_mfa(policy)
        device = _has_device_control(policy)
        block = _has_block(policy)
        if not (applies or mfa or device or block):
            continue
        if purpose == "mfa" and not (mfa or applies or block):
            continue
        if purpose == "device" and not (device or block or applies):
            continue
        meaning = "Affected this sign-in"
        if result.startswith("reportonly"):
            meaning = "Report-only; did not enforce"
        elif mfa:
            meaning = "Required MFA"
        elif device:
            meaning = "Required device trust/compliance"
        elif block:
            meaning = "Blocked or failed access"
        rows.append(_policy_row(policy, meaning))
    return rows


def select_effective_policy(policies: object, purpose: str = "mfa") -> dict[str, str]:
    candidates = _dedupe_policies(policies)
    purpose = purpose.lower()
    scorings: list[tuple[int, Any]] = []
    for policy in candidates:
        if not isinstance(policy, dict):
            continue
        result = _lower(_policy_result(policy))
        score = 0
        if purpose == "mfa" and _is_enforced(policy) and _has_mfa(policy):
            score += 100
        elif purpose == "device" and _is_enforced(policy) and _has_device_control(policy):
            score += 100
        if _is_enforced(policy):
            score += 40
        elif result.startswith("reportonly"):
            score += 5
        if result == "failure":
            score += 20
        if result == "success":
            score += 15
        if purpose == "mfa" and _has_mfa(policy):
            score += 30
        if purpose == "device" and _has_device_control(policy):
            score += 30
        if _has_block(policy):
            score += 15
        if score:
            scorings.append((score, policy))
    if not scorings:
        return {"name": "None found", "result": "Not applied", "grant_control": "None", "report_only": "No"}
    policy = sorted(scorings, key=lambda item: item[0], reverse=True)[0][1]
    return {
        "name": _policy_name(policy) or "None found",
        "result": _policy_result(policy) or "Unknown",
        "grant_control": ", ".join(_controls(policy)) or "Not recorded",
        "report_only": "Yes" if _is_report_only(policy) else "No",
    }


def effective_policy_row(effective: dict[str, str], purpose: str = "mfa") -> list[dict[str, str]]:
    name = _text(effective.get("name"))
    if not name or name == "None found":
        return []
    result = _text(effective.get("result"), "Unknown")
    control = _text(effective.get("grant_control"), "Not recorded")
    meaning = "Required MFA" if purpose == "mfa" and "mfa" in control.lower() else "Affected this sign-in"
    if str(effective.get("report_only") or "").lower() == "yes":
        meaning = "Report-only; did not enforce"
    return [{"Policy": name, "Result": result, "Grant control": control, "Meaning": meaning}]


def _idc001_policies(report: dict[str, Any]) -> list[Any]:
    evidence = _as_list(report.get("evidence"))
    policies: list[Any] = []
    for row in evidence:
        if isinstance(row, dict):
            policies.extend(_as_list(row.get("ConditionalAccessPolicies")))
    return policies


def summarize_mfa_report(report: dict[str, Any]) -> dict[str, Any]:
    metrics = report.get("metrics") or {}
    attribution = report.get("policy_attribution") or {}
    evidence = _as_list(report.get("evidence"))
    policies = _dedupe_policies(_idc001_policies(report))
    effective = select_effective_policy(policies, "mfa")
    attributed_names = [str(x) for x in _as_list(attribution.get("conditional_access_mfa_policy_names")) if _text(x)]
    report_only_names = [str(x) for x in _as_list(attribution.get("report_only_mfa_policy_names")) if _text(x)]
    if attributed_names and effective["name"] == "None found":
        effective["name"] = attributed_names[0]
        effective["result"] = "Success"
        effective["grant_control"] = "Require multifactor authentication"
    elif report_only_names and effective["name"] == "None found":
        effective["name"] = report_only_names[0]
        effective["result"] = "Report-only"
        effective["grant_control"] = "Require multifactor authentication"
        effective["report_only"] = "Yes"

    matching_signin = bool(evidence)
    mfa_required = bool(attribution.get("conditional_access_mfa_policy_applied") or metrics.get("interactive_ca_mfa_applied_count") or metrics.get("mfa_evidence_count"))
    mfa_completed = bool(metrics.get("interactive_mfa_evidence_count") or metrics.get("mfa_evidence_count"))
    access_without_mfa = bool(metrics.get("successful_without_mfa_count") or metrics.get("password_only_privileged_success_count"))
    interrupted = bool(metrics.get("interactive_interrupted_count"))
    successful_interactive = bool(metrics.get("interactive_admin_resource_access_count"))
    status = str(report.get("status") or "").upper()
    effective_is_report_only = effective.get("report_only") == "Yes"
    enforced_mfa_policy_worked = (
        matching_signin
        and mfa_required
        and effective.get("name") != "None found"
        and _lower(effective.get("result")) in {"success", "failure"}
        and ("mfa" in _lower(effective.get("grant_control")) or "multi" in _lower(effective.get("grant_control")))
        and not effective_is_report_only
    )
    report_only_only = bool(effective_is_report_only and not enforced_mfa_policy_worked)

    if access_without_mfa:
        verdict = "FAIL"
        decision = "FAIL - Access succeeded without MFA."
    elif enforced_mfa_policy_worked and (mfa_completed or interrupted) and not access_without_mfa:
        verdict = "PASS"
        decision = "PASS - MFA was enforced."
    elif status.startswith("PASS") and interrupted:
        verdict = "PASS"
        decision = "PASS - Sign-in was challenged or interrupted before password-only access."
    else:
        verdict = "PARTIAL"
        decision = "PARTIAL - MFA evidence is incomplete."

    if access_without_mfa:
        conclusion = "ZTVP found a successful sign-in for the test user, but no effective MFA policy was applied. The user was able to access the target application without MFA."
    elif verdict == "PASS":
        conclusion = f"ZTVP found a matching sign-in where MFA was required. The effective policy was {effective['name']}. The user could not complete access without MFA."
    elif report_only_only:
        conclusion = "An MFA policy matched in report-only mode, but it did not enforce MFA. Report-only policies do not block or require MFA."
    else:
        conclusion = "ZTVP found the sign-in, but could not fully confirm whether MFA was enforced by an active Conditional Access policy."

    sign_in_result = "Success after MFA" if successful_interactive and mfa_completed and not access_without_mfa else "Success" if successful_interactive and not access_without_mfa else "Interrupted" if interrupted else "Failure" if matching_signin else "Unknown"
    risk = "HIGH" if verdict == "FAIL" else "LOW" if verdict == "PASS" else "MEDIUM"
    if verdict == "PASS":
        conclusion = f"ZTVP found a matching sign-in where MFA was required and completed. The effective enforced policy was {effective['name']}. The user did not access the target resource without MFA."
    return {
        "verdict": verdict,
        "decision": decision,
        "mfa_required": "Yes" if mfa_required else "No" if matching_signin else "Unknown",
        "mfa_completed": "Yes" if mfa_completed else "No" if mfa_required else "Not required" if matching_signin else "Unknown",
        "sign_in_result": sign_in_result,
        "access_without_mfa": "Yes" if access_without_mfa else "No" if matching_signin else "Unknown",
        "effective_policy": effective["name"],
        "policy_result": effective["result"],
        "grant_control": effective["grant_control"],
        "conditional_access_result": effective["result"] if effective["result"] != "Unknown" else _first(attribution.get("mfa_source"), default="Unknown"),
        "report_only_policy": "Yes" if effective_is_report_only else "No",
        "risk": risk,
        "conclusion": conclusion,
        "relevant_policies": effective_policy_row(effective, "mfa"),
        "other_policies": [row for row in relevant_policies(policies, "mfa") if row not in effective_policy_row(effective, "mfa")],
    }


def summarize_ca_access_report(report: dict[str, Any], purpose: str = "device") -> dict[str, Any]:
    sid = str(report.get("scenario_id") or "").upper()
    evidence = report.get("appdv004_evidence") or report.get("sign_in_log_evidence") or {}
    metrics = report.get("metrics") or {}
    matched = ((report.get("evidence") or {}).get("matched_signin") or evidence.get("selected_event") or evidence)
    policies = []
    if isinstance(matched, dict):
        policies = _as_list(matched.get("applied_conditional_access_policies") or matched.get("appliedConditionalAccessPolicies"))
    if not policies and isinstance(evidence, dict):
        policies = _as_list(evidence.get("applied_conditional_access_policies"))
    effective = select_effective_policy(policies, purpose)
    fallback_name = _first(
        evidence.get("applied_policy_name"),
        metrics.get("device_trust_policy_name"),
        metrics.get("blocking_policy_name"),
        evidence.get("device_trust_policy_name"),
        evidence.get("blocking_policy_name"),
        default="",
    )
    if fallback_name and effective["name"] == "None found":
        effective["name"] = fallback_name
        effective["result"] = _first(evidence.get("conditional_access_status"), metrics.get("conditional_access_status"), default="Unknown")

    signin_found = bool(evidence.get("signin_found") or evidence.get("meaningful_sign_in_count") or evidence.get("selected_event") or metrics.get("sign_in_log_found"))
    access_result = _first(evidence.get("access_result"), default="")
    success_count = int(metrics.get("successful_sign_in_count") or evidence.get("successful_sign_in_count") or 0)
    failed_count = int(metrics.get("failed_sign_in_count") or evidence.get("failed_sign_in_count") or 0)
    access_success = access_result == "success" or success_count > 0
    access_blocked = access_result == "blocked" or failed_count > 0 or _lower(evidence.get("conditional_access_status")) == "failure"
    ca_result = _first(evidence.get("conditional_access_status"), metrics.get("conditional_access_status"), effective.get("result"), default="Unknown")
    if not signin_found:
        sign_in_result = "Unknown"
    elif access_success:
        sign_in_result = "Success"
    elif access_blocked:
        sign_in_result = "Failure / Interrupted"
    else:
        sign_in_result = "Interrupted"

    if sid == "APP-DV-004":
        conclusion = (
            f"ZTVP found that Conditional Access affected the tested sign-in through {effective['name']}."
            if effective["name"] != "None found"
            else "ZTVP did not find an effective Conditional Access policy for this tested sign-in."
        )
    else:
        conclusion = (
            f"ZTVP found that unmanaged device access was blocked by {effective['name']}."
            if effective["name"] != "None found" and access_blocked
            else "ZTVP found that the user accessed the app without an effective device-trust policy."
            if access_success
            else "ZTVP could not fully confirm the effective Conditional Access policy for this sign-in."
        )
    return {
        "effective_policy": effective["name"],
        "policy_result": effective["result"],
        "grant_control": effective["grant_control"],
        "conditional_access_result": ca_result,
        "sign_in_result": sign_in_result,
        "access_without_required_control": "Yes" if access_success and effective["name"] == "None found" else "No" if signin_found else "Unknown",
        "report_only_policy": "Yes" if effective.get("report_only") == "Yes" else "No",
        "relevant_policies": relevant_policies(policies, purpose),
        "conclusion": conclusion,
    }


def mfa_recommendations(verdict: str) -> list[str]:
    verdict = str(verdict or "").upper()
    if verdict == "PASS":
        return [
            "Keep the MFA Conditional Access policy enabled.",
            "Keep break-glass exclusions reviewed.",
            "Periodically revalidate MFA enforcement.",
            "Monitor sign-in logs for password-only or legacy authentication access.",
            "Keep the privileged role test user in the intended policy scope during validation.",
        ]
    if verdict == "FAIL":
        return [
            "Create or fix a Conditional Access policy requiring MFA.",
            "Scope the policy to the correct users or groups.",
            "Target the correct cloud application.",
            "Exclude only emergency/break-glass accounts.",
            "Make sure the policy is On, not only Report-only.",
            "Check authentication strengths or MFA registration requirements.",
            "Rerun the scenario after remediation.",
        ]
    return [
        "Increase the monitoring window.",
        "Check Entra sign-in log delay.",
        "Open the sign-in manually and review the Conditional Access tab.",
        "Confirm the test user and target app were correct.",
        "Check whether the policy is report-only.",
        "Rerun with a fresh validation window.",
    ]
