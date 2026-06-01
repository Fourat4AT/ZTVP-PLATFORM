from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ca_summary import mfa_recommendations, summarize_ca_access_report, summarize_mfa_report


CLD_SHAREPOINT_IDS = {"APP-DV-008", "CLD-DV-001", "CLD-C-001"}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _first(*values: object, default: str = "") -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"unknown", "n/a", "none", "null", "not returned"}:
            return text
    return default


def _yes_no(value: object, unknown: str = "Unknown") -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if isinstance(value, str) and value.strip().lower() in {"yes", "true", "found"}:
        return "Yes"
    if isinstance(value, str) and value.strip().lower() in {"no", "false", "not found"}:
        return "No"
    return unknown


def normalize_verdict(status: object, fallback: object = None) -> str:
    text = str(status or fallback or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("PARTIAL") or text.startswith("NOT_RUN"):
        return "PARTIAL"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("ERROR"):
        return "ERROR"
    if text.startswith("CANCEL"):
        return "CANCELLED"
    if text.startswith("UNSUPPORTED"):
        return "UNSUPPORTED"
    return "ERROR" if "ERROR" in text else "PARTIAL"


def _tone(verdict: str) -> str:
    return {
        "PASS": "pass",
        "PARTIAL": "partial",
        "FAIL": "fail",
        "ERROR": "fail",
        "CANCELLED": "muted",
        "UNSUPPORTED": "muted",
    }.get(verdict, "partial")


def _risk_explanation(verdict: str, risk: str, report: dict[str, Any] | None = None) -> str:
    report = report or {}
    risk = (risk or "UNKNOWN").upper()
    if verdict == "PASS" and risk == "LOW":
        if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
            return "Risk is low because Microsoft Graph createLink did not create an anonymous sharing link for the controlled dummy file."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
            return "Risk is low because no device remained linked to the decoy user and no strong successful registration proof was found."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-001":
            return "Risk is low because the unmanaged or non-compliant device access attempt was blocked by device-trust Conditional Access enforcement."
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "Risk is low because Conditional Access blocked the unmanaged or non-compliant device access attempt."
        return "Risk is low because the expected tenant control blocked or detected the tested behavior."
    if verdict == "FAIL" and risk == "HIGH":
        if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
            return "Risk is high because SharePoint allowed an anonymous/public sharing link for the controlled dummy file."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
            return "Risk is high because registeredDevices confirmed a device linked to the normal decoy user."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-001":
            return "Risk is high because the decoy user accessed the target cloud app from an unmanaged or non-compliant device without a matching device-trust block."
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "Risk is high because the test user accessed the sensitive app from an unmanaged or non-compliant device without a matching Conditional Access block."
        return "Risk is high because the controlled exposure was created but no tenant detection or remediation evidence was found."
    if verdict == "PARTIAL":
        if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
            return "Risk remains medium because no anonymous link was created, but ZTVP could not confidently classify the createLink denial reason."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-001":
            if _is_devdv001_no_evidence(report):
                return "Risk remains medium because ZTVP could not confirm the unmanaged-device access attempt from tenant evidence."
            return "Risk remains medium because a sign-in was found, but the Conditional Access or device-trust evidence was incomplete."
        if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
            return "Risk remains medium because device registration activity was found, but the final linked-device state was removed or unclear."
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "Risk remains medium because the sign-in was found, but the Conditional Access/device evidence was incomplete."
        return "Risk remains medium because the local action completed, but tenant evidence was incomplete or delayed."
    if verdict in {"ERROR", "CANCELLED", "UNSUPPORTED"}:
        return "Risk could not be fully evaluated because the validation did not complete with a confirmed tenant evidence result."
    return f"Risk is {risk.lower()} based on the scenario verdict and available evidence."


def _what_was_tested(report: dict[str, Any]) -> str:
    sid = str(report.get("display_id") or report.get("scenario_id") or "").upper()
    name = str(report.get("scenario_name") or "").lower()
    if sid in {"APP-DV-003", "APP-C-003"} or "mdca" in name or "public file" in name:
        return "ZTVP created a harmless dummy SharePoint file, attempted to create an anonymous view link, then checked MDCA for alert or governance evidence."
    if sid in CLD_SHAREPOINT_IDS:
        return "ZTVP created a temporary dummy SharePoint file and attempted to create an anonymous/public sharing link using Microsoft Graph createLink. The test file was then cleaned up."
    if sid == "DEV-DV-006" or "eicar" in name:
        return "ZTVP used a safe EICAR test pattern to verify Defender detection and tenant-side evidence."
    if sid == "APP-DV-007" or "app registration" in name:
        return "ZTVP used a normal decoy user to attempt app registration creation through Microsoft Graph."
    if sid == "DEV-DV-008" or "tamper" in name:
        return "ZTVP attempted controlled Defender preference changes on a test endpoint, then checked local evidence and Defender XDR tenant telemetry."
    if sid == "DEV-DV-001":
        return "ZTVP created a temporary normal decoy user, asked the operator to access Microsoft 365 from Windows Sandbox or another unmanaged/non-compliant context, then checked Entra sign-in logs and Conditional Access device-trust evidence."
    if sid == "DEV-DV-004":
        return "ZTVP created a temporary normal decoy user, asked the operator to attempt Windows Sandbox work/school device registration, then checked registeredDevices, Entra audit logs, and supporting sign-in logs."
    if sid == "APP-DV-004" or "unmanaged device" in name:
        return "ZTVP asked the operator to access a sensitive cloud app from Windows Sandbox or another unmanaged/non-compliant endpoint, then checked Entra sign-in logs and Conditional Access results."
    return str(report.get("test_method") or report.get("control_tested") or "ZTVP ran a controlled validation and checked the configured tenant evidence source.")


def _verdict_reason(verdict: str, report: dict[str, Any]) -> str:
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
        metrics = report.get("metrics") or {}
        attempt = report.get("anonymous_link_attempt") or {}
        if metrics.get("anonymous_link_created") or attempt.get("link_created"):
            return "ZTVP successfully created an anonymous sharing link for the dummy file. This means the tested SharePoint target allows public anonymous links."
        if metrics.get("anonymous_link_denied") or attempt.get("link_denied"):
            return "ZTVP attempted to create an anonymous sharing link, but SharePoint denied the request. No anonymous link was created."
        return "No anonymous link was created, but ZTVP could not confidently classify the denial reason."
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-004" and report.get("what_ztvp_thinks_happened"):
        return str(report["what_ztvp_thinks_happened"])
    if _is_devdv001_no_evidence(report):
        sign_in = report.get("sign_in_log_evidence") or {}
        metrics = report.get("metrics") or {}
        polls = _first(metrics.get("poll_attempts"), sign_in.get("poll_count"), default="0")
        return f"ZTVP completed {polls} polling attempts over the configured monitoring window, but no matching sign-in event was found for the decoy user and selected target app after the validation start time. The scenario is marked PARTIAL because the platform could not confirm the unmanaged-device access attempt from tenant evidence."
    if report.get("final_claim"):
        return str(report["final_claim"])
    if verdict == "PASS":
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "The scenario passed because the sign-in attempt matched the test user and target app, and Conditional Access blocked access from the unmanaged/non-compliant device."
        return "The scenario passed because the controlled action was blocked or detected and the tenant provided matching evidence."
    if verdict == "FAIL":
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "The scenario failed because the test user accessed the sensitive app successfully and no matching Conditional Access block was found."
        return "The scenario failed because the controlled action exposed a gap or no matching tenant detection/remediation evidence was confirmed."
    if verdict == "PARTIAL":
        if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
            return "The scenario was partially validated because sign-in evidence was found, but the CA/device evidence was incomplete or unclear."
        return "The scenario was partially validated because one part of the test completed, but tenant evidence was incomplete, delayed, or inconclusive."
    if verdict == "CANCELLED":
        return "The scenario was cancelled before a final tenant evidence decision was made."
    return "The scenario did not produce a complete validation result."


def _target(report: dict[str, Any]) -> str:
    dummy = report.get("dummy_file") or {}
    decoy = report.get("decoy_user") or {}
    guest = report.get("guest_user") or {}
    evidence = report.get("evidence") or {}
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    local = evidence_dict.get("local") or {}
    tenant = (evidence_dict.get("tenant") or {}).get("api") or {}
    return _first(
        guest.get("external_email"),
        guest.get("user_principal_name"),
        report.get("target"),
        report.get("target_app"),
        report.get("test_user"),
        report.get("test_device"),
        (report.get("test_object") or {}).get("file_name"),
        (report.get("site") or {}).get("displayName"),
        dummy.get("file_name"),
        decoy.get("user_principal_name"),
        tenant.get("test_device_name_requested"),
        local.get("computer_name"),
        default="Not recorded",
    )


def _is_devdv001_no_evidence(report: dict[str, Any]) -> bool:
    if str(report.get("scenario_id") or "").upper() != "DEV-DV-001":
        return False
    status = str(report.get("status") or "").upper()
    sign_in = report.get("sign_in_log_evidence") or {}
    metrics = report.get("metrics") or {}
    return (
        status.startswith("PARTIAL_NO_SIGNIN")
        or (
            not bool(sign_in.get("meaningful_sign_in_count") or sign_in.get("selected_event"))
            and not bool(metrics.get("sign_in_log_found"))
        )
    )


def _polling_rows(report: dict[str, Any]) -> list[tuple[str, str]]:
    sign_in = report.get("sign_in_log_evidence") or {}
    metrics = report.get("metrics") or {}
    summary = report.get("polling_summary") or {}
    timer = report.get("timer") or {}
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
        return []
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in {"ID-DV-005", "ID-C-005"}:
        polling = report.get("evidence_polling") or []
        latest = report.get("latest_admin_portal_attempt") or {}
        attempts = _first(metrics.get("poll_attempts"), metrics.get("evidence_poll_count"), default=str(len(polling)))
        max_attempts = _first(metrics.get("max_poll_attempts"), default="N/A")
        last_poll = ""
        if polling:
            last = polling[-1] if isinstance(polling[-1], dict) else {}
            last_poll = last.get("checked_at_utc") or ""
        return [
            ("Poll interval seconds", _first(metrics.get("poll_interval_seconds"), default="Not recorded")),
            ("Polls used", f"{attempts} / {max_attempts}"),
            ("Total search time selected", _first(metrics.get("total_evidence_search_time_seconds"), default="Not recorded") + " seconds"),
            ("Validation start UTC", _first(report.get("validation_start_utc"), (report.get("validation_window") or {}).get("evidence_start_utc"), metrics.get("evidence_start_utc"), default="Not recorded")),
            ("Last poll UTC", _first(metrics.get("last_poll_utc"), last_poll, report.get("completed_utc"), default="Not recorded")),
            ("Matching sign-in found", "Yes" if latest else "No"),
            ("Result", "Evidence found" if latest else "Timeout / No fresh portal evidence found"),
        ]
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in {"ID-DV-004", "ID-C-004"}:
        attempts = _first(metrics.get("poll_attempts"), default="0")
        max_attempts = _first(metrics.get("max_poll_attempts"), default="N/A")
        return [
            ("Log propagation wait seconds", _first(metrics.get("log_propagation_wait_seconds"), default="Not recorded")),
            ("Poll interval seconds", _first(metrics.get("poll_interval_seconds"), default="Not recorded")),
            ("Polls used", f"{attempts} / {max_attempts}"),
            ("Total search time selected", _first(metrics.get("total_evidence_search_time_seconds"), default="Not recorded") + " seconds"),
            ("Last poll UTC", _first(metrics.get("last_poll_utc"), report.get("completed_utc"), default="Not recorded")),
            ("OAuth grant found", _yes_no(metrics.get("oauth_grant_created"))),
            ("Result", report.get("tenant_proof_text") or "Not recorded"),
        ]
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in {"ID-DV-002", "ID-C-002"}:
        found = bool(metrics.get("matching_signin_found") or report.get("matched_sign_in"))
        attempts = _first(metrics.get("evidence_poll_attempts"), metrics.get("poll_attempts"), default="0")
        max_attempts = _first(metrics.get("evidence_max_poll_attempts"), metrics.get("max_poll_attempts"), default="N/A")
        return [
            ("Poll interval seconds", _first(metrics.get("evidence_poll_interval_seconds"), default="15")),
            ("Polls used", f"{attempts} / {max_attempts}"),
            ("Validation start UTC", _first(metrics.get("evidence_start_utc"), report.get("validation_start_utc"), default="Not recorded")),
            ("Last poll UTC", _first(metrics.get("last_poll_utc"), report.get("completed_utc"), default="Not recorded")),
            ("Matching sign-in found", "Yes" if found else "No"),
            ("Result", "Evidence found" if found else "Timeout / No matching sign-in found"),
        ]
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
        attempts = _first(metrics.get("poll_attempts"), timer.get("poll_attempts"), default="0")
        max_attempts = _first(metrics.get("max_poll_attempts"), timer.get("max_poll_attempts"), default="N/A")
        return [
            ("Monitoring window minutes", _first(timer.get("monitoring_window_minutes"), default="Not recorded")),
            ("Retry interval seconds", _first(timer.get("retry_interval_seconds"), metrics.get("poll_interval_seconds"), default="Not recorded")),
            ("Polls used", f"{attempts} / {max_attempts}"),
            ("Elapsed time", _first(timer.get("elapsed_seconds"), metrics.get("elapsed_seconds"), default="Not recorded") + " seconds"),
            ("Stopped early", _yes_no(timer.get("stopped_early"), "Unknown")),
            ("Stop reason", _first(timer.get("stop_reason"), metrics.get("stop_reason"), default="Not recorded")),
        ]
    if not sign_in and not metrics and not summary:
        return []
    attempts = _first(metrics.get("poll_attempts"), sign_in.get("poll_count"), default="0")
    max_attempts = _first(metrics.get("max_poll_attempts"), sign_in.get("max_poll_attempts"), default="N/A")
    found = bool(sign_in.get("meaningful_sign_in_count") or sign_in.get("selected_event") or metrics.get("sign_in_log_found"))
    return [
        ("Poll interval seconds", _first(metrics.get("poll_interval_seconds"), sign_in.get("poll_seconds"), summary.get("poll_interval_seconds"), default="Not recorded")),
        ("Polls used", f"{attempts} / {max_attempts}"),
        ("Validation start UTC", _first(report.get("validation_start_utc"), sign_in.get("validation_window_start_utc"), summary.get("validation_start_utc"), default="Not recorded")),
        ("Last poll UTC", _first(metrics.get("last_poll_utc"), sign_in.get("last_poll_utc"), summary.get("last_poll_utc"), report.get("completed_utc"), default="Not recorded")),
        ("Matching sign-in found", "Yes" if found else "No"),
        ("Result", "Evidence found" if found else "Timeout / No evidence found"),
    ]


def _tenant(report: dict[str, Any]) -> str:
    return _first(report.get("tenant_display_name"), report.get("tenant"), report.get("tenant_id"), default="Not recorded")


def _value_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    return [text] if text else []


def _idc005_policy_name(row: dict[str, Any]) -> str:
    return str(row.get("displayName") or row.get("policy_control_name") or row.get("name") or "").strip()


def _idc005_policy_controls(row: dict[str, Any]) -> list[str]:
    return _value_list(row.get("enforcedGrantControls") or row.get("grantControls") or row.get("controls"))


def _idc005_policy_result(row: dict[str, Any]) -> str:
    return str(row.get("result") or row.get("classification") or "").strip().lower()


def _idc005_main_policy_control(report: dict[str, Any]) -> str:
    latest = report.get("latest_admin_portal_attempt") or {}
    policy = report.get("policy_attribution") or {}
    policies = latest.get("appliedConditionalAccessPolicies") or report.get("policy_control_table") or []

    for row in policies:
        controls = _idc005_policy_controls(row)
        if "failure" in _idc005_policy_result(row) and any("block" in control.lower() for control in controls):
            name = _idc005_policy_name(row)
            return f"{name} / Block" if name else "Block grant control"

    interruption_terms = ("mfa", "multi-factor", "multifactor", "compliant", "compliance", "terms", "tou")
    for row in policies:
        controls = _idc005_policy_controls(row)
        matching_control = next((control for control in controls if any(term in control.lower() for term in interruption_terms)), "")
        if "failure" in _idc005_policy_result(row) and matching_control:
            name = _idc005_policy_name(row)
            return f"{name} / {matching_control}" if name else matching_control

    names = _value_list(latest.get("blockingPolicyNames")) or _value_list(policy.get("block_policy_names"))
    if names:
        return names[0]

    return "No specific policy identified"


def _main_rows(report: dict[str, Any], verdict: str) -> list[tuple[str, str]]:
    metrics = report.get("metrics") or {}
    cleanup = report.get("cleanup") or {}
    link = report.get("anonymous_public_link_attempt") or {}
    mdca = report.get("mdca_detection_evidence") or {}
    app = report.get("app_registration_creation_evidence") or {}
    appdv004 = report.get("appdv004_evidence") or {}
    appdv004 = report.get("appdv004_evidence") or {}
    devdv001 = report.get("sign_in_log_evidence") or {} if str(report.get("scenario_id") or "").upper() == "DEV-DV-001" else {}
    devdv004 = report.get("evidence") or {} if str(report.get("scenario_id") or "").upper() == "DEV-DV-004" else {}
    evidence = report.get("evidence") or {}
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    local = evidence_dict.get("local") or {}
    tenant = (evidence_dict.get("tenant") or {}).get("api") or {}
    alert = tenant.get("tenant_defender_alert") or {}
    timeline = tenant.get("tenant_timeline_evidence") or {}
    sid = str(report.get("display_id") or report.get("scenario_id") or "").upper()

    if sid in CLD_SHAREPOINT_IDS:
        attempt = report.get("anonymous_link_attempt") or {}
        link_created = bool(metrics.get("anonymous_link_created") or attempt.get("link_created"))
        link_denied = bool(metrics.get("anonymous_link_denied") or attempt.get("link_denied"))
        cleanup_completed = metrics.get("cleanup_completed")
        if cleanup_completed is None:
            cleanup_completed = str(cleanup.get("status") or "").lower() == "completed"
        return [
            ("Anonymous link created", "Yes" if link_created else "No"),
            ("Link blocked/denied", "Yes" if link_denied else "No"),
            ("Denial reason", _first(attempt.get("error_message"), attempt.get("error_category"), default="Not applicable")),
            ("Cleanup completed", _yes_no(cleanup_completed)),
            ("Public URL stored", "No"),
            ("Verdict basis", _verdict_reason(verdict, report)),
        ]
    if sid in {"ID-DV-004", "ID-C-004"}:
        app_info = report.get("test_application") or {}
        return [
            ("OAuth grant created", _yes_no(metrics.get("oauth_grant_created"))),
            ("Grant count", _first(metrics.get("oauth_grant_count"), metrics.get("grant_count"), default="0")),
            ("Controlled app display name", _first(app_info.get("display_name"), default="Not recorded")),
            ("App ID", _first(app_info.get("app_id"), default="Not recorded")),
            ("Service principal ID", _first(app_info.get("service_principal_id"), default="Not recorded")),
            ("Requested scope", _first(app_info.get("requested_scope"), default="Not recorded")),
            ("Evidence source", _first(report.get("tenant_evidence_source"), default="Microsoft Graph oauth2PermissionGrant query")),
            ("Tenant proof", _first(report.get("tenant_proof_text"), default="Not recorded")),
            ("Manual browser observation", _first(report.get("observed_browser_outcome"), default="Not recorded")),
            ("Verdict basis", _verdict_reason(verdict, report)),
        ]

    if sid in {"ID-DV-001", "ID-C-001"}:
        mfa = summarize_mfa_report(report)
        rows = [
            ("MFA required", _first(mfa.get("mfa_required"), default="Unknown")),
            ("MFA completed", _first(mfa.get("mfa_completed"), default="Unknown")),
            ("Sign-in result", _first(mfa.get("sign_in_result"), default="Unknown")),
            ("Access without MFA", _first(mfa.get("access_without_mfa"), default="Unknown")),
            ("Effective policy", _first(mfa.get("effective_policy"), default="None found")),
            ("Conditional Access result", _first(mfa.get("conditional_access_result"), default="Unknown")),
            ("Grant control", _first(mfa.get("grant_control"), default="Not recorded")),
            ("Report-only policy detected", _first(mfa.get("report_only_policy"), default="No")),
            ("Verdict basis", _first(mfa.get("conclusion"), _verdict_reason(verdict, report))),
        ]
        polling = report.get("polling") or {}
        if polling:
            rows.append(("Polls used", f"{_first(polling.get('poll_attempts'), default='0')} / {_first(polling.get('max_poll_attempts'), default='N/A')}"))
        return rows

    if sid in {"ID-DV-002", "ID-C-002"}:
        matched = report.get("selected_evidence_row") or report.get("matched_sign_in") or {}
        policy = report.get("policy_attribution") or {}
        metrics = report.get("metrics") or {}
        tenant_found = bool(metrics.get("tenant_evidence_found") or policy.get("tenant_evidence_found") or matched)
        policy_name = _first(policy.get("main_blocking_policy_name"), metrics.get("main_blocking_policy_name"), default="Not attributed")
        return [
            ("Tenant evidence found", "Yes" if tenant_found else "No"),
            ("Matching sign-in found", "Yes" if matched else "No"),
            ("Meaningful sign-ins", _first(metrics.get("meaningful_sign_in_count"), metrics.get("device_code_evidence_count"), default="0")),
            ("Evidence time UTC", _first(matched.get("CreatedDateTime"), metrics.get("latest_matching_signin_time_utc"), default="Not recorded")),
            ("User", _first(matched.get("UserPrincipalName"), (report.get("decoy_user") or {}).get("user_principal_name"), default="Not recorded")),
            ("App", _first(matched.get("AppDisplayName"), default="Not recorded")),
            ("Resource", _first(matched.get("ResourceDisplayName"), default="Not recorded")),
            ("Client", _first(matched.get("ClientAppUsed"), default="Not recorded")),
            ("Status", _first(matched.get("Status"), default="Not recorded")),
            ("Error code", _first(matched.get("StatusCode"), default="Not recorded")),
            ("CA status", _first(matched.get("ConditionalAccessStatus"), default="Not recorded")),
            ("IP", _first(matched.get("IpAddress"), default="Not recorded")),
            ("Request ID", _first(matched.get("RequestId"), matched.get("SignInId"), default="Not recorded")),
            ("Main blocking policy", policy_name),
            ("Policy result", _first(policy.get("main_blocking_policy_result"), default="Not attributed")),
            ("Grant controls", ", ".join([str(x) for x in (policy.get("main_blocking_policy_grant_controls") or [])]) or "Not attributed"),
            ("Selected evidence reason", _first(report.get("selected_evidence_reason"), default="Not recorded")),
            ("Token issued", _yes_no(metrics.get("token_issued"))),
            ("Polls used", f"{_first(metrics.get('evidence_poll_attempts'), metrics.get('poll_attempts'), default='0')} / {_first(metrics.get('evidence_max_poll_attempts'), metrics.get('max_poll_attempts'), default='N/A')}"),
            ("Verdict basis", _first(report.get("final_claim"), _verdict_reason(verdict, report))),
        ]

    if sid in {"ID-DV-005", "ID-C-005"}:
        guest = report.get("guest_user") or {}
        latest = report.get("latest_admin_portal_attempt") or {}
        metrics = report.get("metrics") or {}
        cleanup_completed = str(cleanup.get("status") or "").lower() == "completed" or bool(cleanup.get("cleanup_completed"))
        tenant_found = bool(latest or report.get("admin_portal_evidence"))
        return [
            ("External guest", _first(guest.get("external_email"), guest.get("user_principal_name"), report.get("target"), default="Not recorded")),
            ("Tenant evidence found", "Yes" if tenant_found else "No"),
            ("Latest portal result", _first(latest.get("resultCategory"), metrics.get("latest_admin_portal_attempt_result"), default="PENDING")),
            ("App", _first(latest.get("appDisplayName"), default="Not recorded")),
            ("Resource", _first(latest.get("resourceDisplayName"), default="Not recorded")),
            ("Evidence time UTC", _first(latest.get("createdDateTimeUtc"), default="Not recorded")),
            ("CA status", _first(latest.get("conditionalAccessStatus"), default="Not recorded")),
            ("Error code", _first(latest.get("statusErrorCode"), default="Not recorded")),
            ("Failure/interruption reason", _first(latest.get("statusFailureReason"), default="Not recorded")),
            ("Main blocking/interruption policy or control", _idc005_main_policy_control(report)),
            ("Polls used", f"{_first(metrics.get('poll_attempts'), metrics.get('evidence_poll_count'), default='0')} / {_first(metrics.get('max_poll_attempts'), default='N/A')}"),
            ("Total search time selected", _first(metrics.get("total_evidence_search_time_seconds"), default="Not recorded") + " seconds"),
            ("Poll interval selected", _first(metrics.get("poll_interval_seconds"), default="Not recorded") + " seconds"),
            ("Cleanup status", _first(cleanup.get("status"), "Completed" if cleanup_completed else "Pending", default="Not recorded")),
            ("Verdict basis", _first(report.get("final_claim"), _verdict_reason(verdict, report))),
        ]

    if devdv001:
        device = devdv001.get("device_detail") or {}
        target = report.get("target") or {}
        no_evidence = _is_devdv001_no_evidence(report)
        ca = summarize_ca_access_report(report, "device")
        rows = [
            ("Decoy user", _first((report.get("decoy_user") or {}).get("user_principal_name"), devdv001.get("decoy_user"), default="Not recorded")),
            ("Target app", _first(target.get("name"), report.get("target_app"), default="Not recorded")),
            ("Access attempt found", "No" if no_evidence else _yes_no(bool(devdv001.get("meaningful_sign_in_count") or devdv001.get("selected_event") or metrics.get("sign_in_log_found")))),
            ("Tenant evidence found", "No" if no_evidence else _yes_no(bool(devdv001.get("meaningful_sign_in_count") or devdv001.get("selected_event")))),
            ("Conditional Access result", "Not available" if no_evidence else _first(ca.get("conditional_access_result"), metrics.get("conditional_access_status"), devdv001.get("conditional_access_status"), default="Unknown")),
            ("Effective policy", "Not available" if no_evidence else _first(ca.get("effective_policy"), metrics.get("device_trust_policy_name"), metrics.get("blocking_policy_name"), devdv001.get("device_trust_policy_name"), devdv001.get("blocking_policy_name"), default="None found")),
            ("Sign-in result", "Not available" if no_evidence else _first(ca.get("sign_in_result"), default="Unknown")),
            ("Detected blocking reason", "No matching sign-in evidence was found before timeout" if no_evidence else _first(metrics.get("detected_blocking_reason"), devdv001.get("status_failure_reason"), devdv001.get("status_additional_details"), default="Not found")),
            ("Device compliance/management state", "Unknown" if no_evidence else f"Compliant: {_first(metrics.get('device_is_compliant'), device.get('is_compliant'), default='unknown')}; Managed: {_first(metrics.get('device_is_managed'), device.get('is_managed'), default='unknown')}"),
        ]
        polls = _first(metrics.get("poll_attempts"), devdv001.get("poll_count"))
        max_polls = _first(metrics.get("max_poll_attempts"), devdv001.get("max_poll_attempts"))
        if polls:
            rows.append(("Polls used", f"{polls} / {max_polls or 'N/A'}"))
        if "polling_stopped_early" in metrics:
            rows.append(("Stopped early", _yes_no(metrics.get("polling_stopped_early"))))
        rows.append(("Verdict basis", _verdict_reason(verdict, report)))
        return rows

    if devdv004:
        found = report.get("what_ztvp_found") or {}
        final_state = report.get("final_device_state") or {}
        sources = report.get("evidence_sources") or {}
        rows = [
            ("Decoy user", _first((report.get("decoy_user") or {}).get("user_principal_name"), default="Not recorded")),
            ("registeredDevices query completed", _yes_no(found.get("registered_devices_query_completed"))),
            ("Registered devices linked to decoy user", _first(found.get("registered_devices_linked_to_decoy_user"), devdv004.get("registered_device_count_after_window"), default="0")),
            ("Audit events found", _yes_no(found.get("audit_events_found"))),
            ("Register device event found", _yes_no(found.get("register_device_event_found"))),
            ("Add device event found", _yes_no(found.get("add_device_event_found"))),
            ("Add owner/user event found", _yes_no(found.get("add_owner_or_user_event_found"))),
            ("Unregister/delete event found", _yes_no(found.get("unregister_or_delete_event_found"))),
            ("Sign-in evidence found", _yes_no(found.get("sign_in_evidence_found"))),
            ("Final device state", _first(found.get("final_device_state"), final_state.get("state"), default="Unknown")),
            ("Evidence confidence", _first(found.get("evidence_confidence"), report.get("evidence_quality"), default="Unknown")),
            ("Device linked to decoy", _first(final_state.get("device_linked_to_decoy"), default="Unknown")),
            ("Linked device IDs", ", ".join([str(x) for x in (final_state.get("linked_device_ids") or [])]) or "None"),
            ("registeredDevices evidence", f"{_yes_no((sources.get('registeredDevices') or {}).get('found'))} ({(sources.get('registeredDevices') or {}).get('count', 0)})"),
            ("Audit log evidence", f"{_yes_no((sources.get('audit_logs') or {}).get('found'))} ({(sources.get('audit_logs') or {}).get('count', 0)})"),
            ("Sign-in log evidence", f"{_yes_no((sources.get('sign_in_logs') or {}).get('found'))} ({(sources.get('sign_in_logs') or {}).get('count', 0)})"),
            ("Verdict basis", _verdict_reason(verdict, report)),
        ]
        return rows

    if appdv004:
        ca = summarize_ca_access_report(report, "device")
        rows = [
            ("Test user", _first(report.get("test_user"), default="Not recorded")),
            ("Target app", _first(report.get("target_app"), default="Not recorded")),
            ("Access result", _first(appdv004.get("access_result"), default="unknown")),
            ("Effective policy", _first(ca.get("effective_policy"), default="None found")),
            ("Conditional Access result", _first(ca.get("conditional_access_result"), default="Unknown")),
            ("Sign-in result", _first(ca.get("sign_in_result"), default="Unknown")),
            ("Device compliance/managed status", "Unmanaged or non-compliant" if appdv004.get("device_unmanaged_or_noncompliant") else "Unknown or not returned"),
        ]
        polls = _first(metrics.get("poll_attempts"))
        max_polls = _first(metrics.get("max_poll_attempts"))
        if polls:
            rows.append(("Polls used", f"{polls} / {max_polls or 'N/A'}"))
        if "polling_stopped_early" in metrics:
            rows.append(("Stopped early", _yes_no(metrics.get("polling_stopped_early"))))
        rows.append(("Verdict basis", _verdict_reason(verdict, report)))
        return rows

    controlled = (
        metrics.get("public_link_created")
        if "public_link_created" in metrics
        else link.get("public_link_created")
        if link
        else app.get("actual_create_attempt_performed")
        if app
        else bool(local.get("local_detection_found") or local.get("tamper_attempt_blocked_or_ignored") or local.get("defender_settings_remained_protected"))
    )
    tenant_found = bool(
        mdca.get("alert_detected")
        or mdca.get("governance_remediation_observed")
        or tenant.get("mde_cloud_evidence_found")
        or alert.get("alert_found")
        or alert.get("alert_evidence_found")
        or timeline.get("tamper_specific_evidence_found")
    )
    cleanup_completed = cleanup.get("cleanup_completed")
    if cleanup_completed is None:
        cleanup_completed = str(cleanup.get("status") or cleanup.get("cleanup_status") or "").lower() == "completed"

    rows = [
        ("Controlled action succeeded", _yes_no(controlled)),
        ("Tenant evidence found", _yes_no(tenant_found)),
        ("Cleanup completed", _yes_no(cleanup_completed)),
    ]
    polls = _first(metrics.get("poll_attempts"), mdca.get("poll_attempts"), tenant.get("mde_cloud_poll_attempts"))
    max_polls = _first(metrics.get("max_poll_attempts"), mdca.get("max_poll_attempts"))
    if polls:
        rows.append(("Polls used", f"{polls} / {max_polls or 'N/A'}"))
    stopped = metrics.get("polling_stopped_early")
    if stopped is None:
        stopped = mdca.get("polling_stopped_early")
    if stopped is not None:
        rows.append(("Stopped early", _yes_no(stopped)))
    detection = _first(metrics.get("detection_method"), mdca.get("detection_method"), alert.get("detection_source"))
    if detection:
        rows.append(("Detection method", detection))
    match = _first(metrics.get("matching_alert_title"), mdca.get("matching_alert_title"), alert.get("alert_title"))
    if match:
        rows.append(("Matching alert/policy", match))
    rows.append(("Verdict basis", _verdict_reason(verdict, report)))
    return rows


def _recommendations(report: dict[str, Any], verdict: str) -> list[str]:
    sid = str(report.get("display_id") or report.get("scenario_id") or "").upper()
    name = str(report.get("scenario_name") or "").lower()
    if sid in {"ID-DV-001", "ID-C-001"}:
        return mfa_recommendations(verdict)
    if sid in CLD_SHAREPOINT_IDS:
        if verdict == "PASS":
            return [
                "Keep anonymous/Anyone sharing disabled unless there is a documented business exception.",
                "Continue using organization-only or specific-people links for normal collaboration.",
                "Periodically rerun APP-DV-008 after sharing setting changes.",
                "Monitor SharePoint sharing audit events.",
            ]
        if verdict == "FAIL":
            return [
                "Go to SharePoint admin center -> Policies -> Sharing.",
                "Disable Anyone/anonymous links at tenant level.",
                "Review SharePoint admin center -> Sites -> Active sites -> tested site -> Sharing.",
                "Set the site to New and existing guests, Existing guests only, or Only people in your organization.",
                "Rerun APP-DV-008 after settings propagate.",
                "Monitor SharingLinkCreated / anonymous link activity.",
            ]
        return [
            "Review the createLink error details.",
            "Verify Graph and SharePoint permissions.",
            "Confirm tenant and site sharing settings manually.",
            "Rerun after a few minutes.",
        ]
    if verdict == "PASS":
        if sid == "DEV-DV-004":
            return [
                "Keep device registration restrictions enabled.",
                "Continue monitoring device registration audit events.",
                "Review allowed users/groups for device registration.",
                "Periodically rerun DEV-DV-004.",
            ]
        if sid == "DEV-DV-001":
            return [
                "Keep the device-trust Conditional Access policy enabled.",
                "Continue monitoring sign-in logs.",
                "Periodically rerun the validation.",
                "Verify decoy/test users remain in scope during future tests.",
            ]
        if sid == "APP-DV-004" or "unmanaged device" in name:
            return [
                "Keep the Conditional Access policy enabled.",
                "Keep monitoring sign-in logs.",
                "Periodically rerun the validation.",
                "Review exclusions and break-glass accounts regularly.",
            ]
        return [
            "Keep the current control enabled.",
            "Continue monitoring related alerts.",
            "Periodically rerun the validation.",
            "Keep cleanup and evidence collection procedures documented.",
        ]
    if verdict == "PARTIAL":
        if sid == "DEV-DV-004":
            return [
                "Increase the monitoring window.",
                "Check Entra Audit Logs manually.",
                "Confirm the decoy user was used.",
                "Check Entra Devices manually.",
                "Rerun with a fresh validation window.",
            ]
        if sid == "DEV-DV-001":
            if _is_devdv001_no_evidence(report):
                return [
                    "Increase the monitoring window to 30 or 60 minutes.",
                    "Verify the login was performed after clicking Start Fresh Validation Window.",
                    "Confirm the login was performed with the decoy user, not the admin account.",
                    "Confirm the selected target app matches the app opened in Sandbox.",
                    "Check Entra sign-in log delay manually.",
                    "If using My Apps, also try Microsoft 365 Portal or SharePoint Online depending on the selected target.",
                    "Rerun analysis after the sign-in appears in Entra logs.",
                ]
            return [
                "Increase monitoring window.",
                "Check Entra sign-in log delay.",
                "Verify target app selection.",
                "Confirm the login was performed with the decoy user.",
                "Check Conditional Access policy scope.",
            ]
        if sid == "APP-DV-004" or "unmanaged device" in name:
            return [
                "Increase monitoring window.",
                "Check sign-in log delay.",
                "Verify target app mapping.",
                "Check Conditional Access policy scope.",
                "Confirm the test was performed from an unmanaged/non-compliant device.",
            ]
        return [
            "Increase the monitoring window.",
            "Check connector/API permissions.",
            "Check whether the policy exists and is enabled.",
            "Review manual portal evidence.",
        ]
    if sid == "DEV-DV-004":
        return [
            "Restrict normal users from registering or joining devices.",
            "Review Entra device settings: Users may register devices and Users may join devices.",
            "Use Conditional Access user action Register or join devices with MFA or trusted conditions.",
            "Reduce maximum devices per user.",
            "Remove the registered test device.",
            "Rerun after remediation.",
        ]
    if sid in {"APP-DV-003", "APP-C-003"} or "mdca" in name or "public file" in name:
        return [
            "Create or enable an MDCA file policy for publicly shared SharePoint/OneDrive files.",
            "Enable alert creation for matching files.",
            "Review anonymous sharing settings in SharePoint admin center.",
            "Consider governance actions only after alert-only validation works.",
            "Rerun the scenario with a longer monitoring window.",
        ]
    if sid == "DEV-DV-006" or "eicar" in name:
        return [
            "Check Microsoft Defender Antivirus status.",
            "Confirm the device is onboarded to Defender for Endpoint.",
            "Verify cloud-delivered protection and sample submission settings.",
            "Check Defender XDR ingestion and alert visibility.",
        ]
    if sid == "APP-DV-007" or "app registration" in name:
        return [
            "Restrict normal users from creating app registrations.",
            "Review Entra user settings for app registration creation.",
            "Allow app creation only for approved developer groups.",
            "Monitor Entra audit logs for application creation.",
        ]
    if sid == "APP-DV-004" or "unmanaged device" in name:
        if sid == "DEV-DV-001":
            return [
                "Create or enable a Conditional Access policy requiring compliant or hybrid joined devices.",
                "Scope it first to a test group.",
                "Target Microsoft 365 / sensitive cloud apps.",
                "Exclude break-glass accounts only.",
                "Verify Intune compliance integration.",
                "Rerun DEV-DV-001 from Windows Sandbox or InPrivate.",
            ]
        return [
            "Create or fix a Conditional Access policy for sensitive apps.",
            "Scope it first to a test group.",
            "Require device to be marked as compliant or block unmanaged devices.",
            "Exclude break-glass accounts.",
            "Use report-only mode before enforcing broadly.",
            "Verify Intune compliance integration.",
            "Rerun APP-DV-004 from Windows Sandbox.",
        ]
    return [str(item) for item in (report.get("recommendations") or [])] or ["Review the failed control and rerun validation after remediation."]


def _evidence_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    metrics = report.get("metrics") or {}
    dummy = report.get("dummy_file") or {}
    mdca = report.get("mdca_detection_evidence") or {}
    app = report.get("app_registration_creation_evidence") or {}
    appdv004 = report.get("appdv004_evidence") or {}
    devdv001 = report.get("sign_in_log_evidence") or {} if str(report.get("scenario_id") or "").upper() == "DEV-DV-001" else {}
    devdv004 = report.get("evidence") or {} if str(report.get("scenario_id") or "").upper() == "DEV-DV-004" else {}
    evidence = report.get("evidence") or {}
    local = evidence.get("local") or {}
    tenant = (evidence.get("tenant") or {}).get("api") or {}
    alert = tenant.get("tenant_defender_alert") or {}
    timeline = tenant.get("tenant_timeline_evidence") or {}
    rows: list[dict[str, str]] = []
    sid = str(report.get("display_id") or report.get("scenario_id") or "").upper()
    if sid in CLD_SHAREPOINT_IDS:
        attempt = report.get("anonymous_link_attempt") or {}
        site = report.get("site") or {}
        test_object = report.get("test_object") or {}
        link_created = bool(metrics.get("anonymous_link_created") or attempt.get("link_created"))
        link_denied = bool(metrics.get("anonymous_link_denied") or attempt.get("link_denied"))
        rows.append(
            {
                "source": "Microsoft Graph createLink",
                "found": "Yes",
                "object": _first(test_object.get("file_name"), default="Dummy SharePoint file"),
                "timestamp": _first(report.get("generated_at"), report.get("completed_utc")),
                "notes": "Anonymous link created: {0}; blocked/denied: {1}; public URL stored: No".format("Yes" if link_created else "No", "Yes" if link_denied else "No"),
            }
        )
        rows.append(
            {
                "source": "SharePoint target",
                "found": _yes_no(bool(site)),
                "object": _first(site.get("displayName"), site.get("webUrl"), default="Not recorded"),
                "timestamp": _first(report.get("generated_at"), report.get("completed_utc")),
                "notes": _first(attempt.get("error_message"), attempt.get("error_category"), default="createLink completed"),
            }
        )
        return rows
    if sid in {"ID-DV-001", "ID-C-001"}:
        mfa = summarize_mfa_report(report)
        rows.append({"source": "Entra sign-in logs", "found": _yes_no(mfa.get("sign_in_result") != "Unknown"), "object": report.get("target_user") or "", "timestamp": _first(report.get("generated_at"), report.get("completed_utc")), "notes": mfa.get("sign_in_result") or ""})
        rows.append({"source": "Effective Conditional Access policy", "found": _yes_no(mfa.get("effective_policy") != "None found"), "object": mfa.get("effective_policy") or "", "timestamp": _first(report.get("generated_at"), report.get("completed_utc")), "notes": mfa.get("conditional_access_result") or ""})
        rows.append({"source": "MFA evidence", "found": _yes_no(mfa.get("mfa_required") == "Yes" or mfa.get("mfa_completed") == "Yes"), "object": mfa.get("grant_control") or "MFA", "timestamp": _first(report.get("generated_at"), report.get("completed_utc")), "notes": mfa.get("conclusion") or ""})
        return rows
    if sid in {"ID-DV-002", "ID-C-002"}:
        matched = report.get("selected_evidence_row") or report.get("matched_sign_in") or {}
        policy = report.get("policy_attribution") or {}
        policy_name = _first(policy.get("main_blocking_policy_name"), (report.get("metrics") or {}).get("main_blocking_policy_name"), default="Not attributed")
        rows.append(
            {
                "source": "Entra sign-in logs",
                "found": "Yes" if matched else "No",
                "object": _first(matched.get("UserPrincipalName"), (report.get("decoy_user") or {}).get("user_principal_name"), default="Decoy user"),
                "timestamp": _first(matched.get("CreatedDateTime"), default="Not found"),
                "notes": f"App: {_first(matched.get('AppDisplayName'), default='Not recorded')}; Resource: {_first(matched.get('ResourceDisplayName'), default='Not recorded')}; Status: {_first(matched.get('Status'), default='Not recorded')}; CA: {_first(matched.get('ConditionalAccessStatus'), default='Not recorded')}",
            }
        )
        rows.append(
            {
                "source": "Conditional Access policy table",
                "found": "Yes" if policy.get("main_blocking_policy_name") else "No",
                "object": policy_name,
                "timestamp": _first(matched.get("CreatedDateTime"), default="Not found"),
                "notes": f"Result: {_first(policy.get('main_blocking_policy_result'), default='Not attributed')}; Grant controls: {', '.join([str(x) for x in (policy.get('main_blocking_policy_grant_controls') or [])]) or 'Not attributed'}",
            }
        )
        return rows
    if sid in {"ID-DV-005", "ID-C-005"}:
        latest = report.get("latest_admin_portal_attempt") or {}
        guest = report.get("guest_user") or {}
        policy = report.get("policy_attribution") or {}
        rows.append(
            {
                "source": "Entra admin/management portal sign-in",
                "found": "Yes" if latest else "No",
                "object": _first(guest.get("external_email"), guest.get("user_principal_name"), default="External guest"),
                "timestamp": _first(latest.get("createdDateTimeUtc"), default="Not found"),
                "notes": _first(latest.get("resultCategory"), default="No fresh portal attempt found"),
            }
        )
        rows.append(
            {
                "source": "Latest portal attempt",
                "found": "Yes" if latest else "No",
                "object": _first(latest.get("appDisplayName"), default="Admin/management portal"),
                "timestamp": _first(latest.get("createdDateTimeUtc"), default="Not found"),
                "notes": f"Resource: {_first(latest.get('resourceDisplayName'), default='Not recorded')}; CA: {_first(latest.get('conditionalAccessStatus'), default='Not recorded')}; Error: {_first(latest.get('statusErrorCode'), default='Not recorded')}",
            }
        )
        rows.append(
            {
                "source": "Policy/control attribution",
                "found": "Yes" if latest.get("appliedConditionalAccessPolicies") or policy.get("policy_rows") else "No",
                "object": _idc005_main_policy_control(report),
                "timestamp": _first(latest.get("createdDateTimeUtc"), default="Not found"),
                "notes": _first(latest.get("statusFailureReason"), default="No failure/interruption reason returned"),
            }
        )
        return rows
    if sid in {"ID-DV-004", "ID-C-004"}:
        app_info = report.get("test_application") or {}
        grant_created = bool(metrics.get("oauth_grant_created"))
        rows.append(
            {
                "source": "Microsoft Graph oauth2PermissionGrant query",
                "found": "Yes" if grant_created else "No",
                "object": _first(app_info.get("display_name"), app_info.get("app_id"), default="Controlled OAuth test app"),
                "timestamp": _first(metrics.get("last_poll_utc"), report.get("completed_utc"), report.get("generated_at")),
                "notes": _first(report.get("tenant_proof_text"), default="OAuth grant evidence query completed."),
            }
        )
        rows.append(
            {
                "source": "Manual browser observation",
                "found": _first(report.get("observed_browser_outcome"), default="Not recorded"),
                "object": _first((report.get("decoy_user") or {}).get("user_principal_name"), default="Decoy user"),
                "timestamp": _first(report.get("completed_utc"), report.get("generated_at")),
                "notes": "Supporting evidence only; tenant OAuth grant evidence is primary.",
            }
        )
        return rows
    if dummy or mdca:
        rows.append({"source": "SharePoint/Graph", "found": _yes_no(bool(dummy)), "object": dummy.get("file_name") or "Dummy file", "timestamp": _first(report.get("generated_at"), report.get("generated_utc")), "notes": "Public URL stored: No"})
        rows.append({"source": "MDCA Alerts API", "found": _yes_no(bool(mdca.get("alert_detected") or mdca.get("governance_remediation_observed"))), "object": _first(metrics.get("matching_alert_title"), mdca.get("matching_alert_title"), default="No matching alert"), "timestamp": _first(metrics.get("alert_timestamp"), mdca.get("alert_timestamp"), default="Not found"), "notes": _first(metrics.get("detection_method"), mdca.get("detection_method"), default="None")})
    if app:
        rows.append({"source": "Microsoft Graph", "found": _yes_no(app.get("actual_create_attempt_performed")), "object": app.get("display_name") or "App registration attempt", "timestamp": _first(report.get("generated_at"), report.get("generated_utc")), "notes": "Secrets created: No; certificates created: No"})
    if appdv004:
        ca = summarize_ca_access_report(report, "device")
        rows.append({"source": "Entra sign-in logs", "found": _yes_no(appdv004.get("signin_found")), "object": report.get("target_app") or "", "timestamp": appdv004.get("signin_timestamp") or "", "notes": appdv004.get("access_result") or ""})
        rows.append({"source": "Effective Conditional Access policy", "found": _yes_no(ca.get("effective_policy") != "None found"), "object": ca.get("effective_policy") or "", "timestamp": appdv004.get("signin_timestamp") or "", "notes": ca.get("conditional_access_result") or ""})
        rows.append({"source": "Device detail/compliance context", "found": _yes_no(appdv004.get("device_unmanaged_or_noncompliant")), "object": report.get("test_user") or "", "timestamp": appdv004.get("signin_timestamp") or "", "notes": appdv004.get("failure_reason") or "Device detail returned by sign-in log if available."})
        rows.append({"source": "Graph API response", "found": _yes_no(bool(evidence_dict.get("matched_signin"))), "object": "signIns", "timestamp": _first(report.get("completed_utc"), report.get("generated_at")), "notes": "Raw response hidden in technical details."})
    if devdv001:
        target = report.get("target") or {}
        no_evidence = _is_devdv001_no_evidence(report)
        ca = summarize_ca_access_report(report, "device")
        rows.append({"source": "Entra sign-in logs", "found": "No" if no_evidence else _yes_no(devdv001.get("meaningful_sign_in_count") or devdv001.get("selected_event")), "object": _first(target.get("name"), report.get("target_app")), "timestamp": devdv001.get("created_date_time") or "", "notes": "No matching sign-in evidence was found before timeout" if no_evidence else _first(devdv001.get("status_failure_reason"), devdv001.get("status_additional_details"), default="No matching sign-in found")})
        rows.append({"source": "Effective Conditional Access policy", "found": _yes_no((ca.get("effective_policy") or "") != "None found"), "object": _first(ca.get("effective_policy"), metrics.get("device_trust_policy_name"), metrics.get("blocking_policy_name"), devdv001.get("device_trust_policy_name"), devdv001.get("blocking_policy_name")), "timestamp": devdv001.get("created_date_time") or "", "notes": _first(ca.get("conditional_access_result"), devdv001.get("conditional_access_status"), default="Not recorded")})
        rows.append({"source": "Device detail/compliance context", "found": _yes_no(bool(devdv001.get("device_detail"))), "object": _first((report.get("decoy_user") or {}).get("user_principal_name"), devdv001.get("decoy_user")), "timestamp": devdv001.get("created_date_time") or "", "notes": f"Compliant: {_first(metrics.get('device_is_compliant'), (devdv001.get('device_detail') or {}).get('is_compliant'), default='unknown')}; Managed: {_first(metrics.get('device_is_managed'), (devdv001.get('device_detail') or {}).get('is_managed'), default='unknown')}"})
    if devdv004:
        sources = report.get("evidence_sources") or {}
        rows.append({"source": "Microsoft Graph registeredDevices", "found": _yes_no((sources.get("registeredDevices") or {}).get("found")), "object": _first((report.get("decoy_user") or {}).get("user_principal_name")), "timestamp": _first((report.get("timer") or {}).get("last_poll_utc"), report.get("completed_utc")), "notes": f"Linked devices: {(sources.get('registeredDevices') or {}).get('count', 0)}"})
        rows.append({"source": "Entra audit logs", "found": _yes_no((sources.get("audit_logs") or {}).get("found")), "object": "Device registration activity", "timestamp": _first((report.get("timer") or {}).get("last_poll_utc"), report.get("completed_utc")), "notes": f"Events: {(sources.get('audit_logs') or {}).get('count', 0)}"})
        rows.append({"source": "Entra sign-in logs", "found": _yes_no((sources.get("sign_in_logs") or {}).get("found")), "object": _first((report.get("decoy_user") or {}).get("user_principal_name")), "timestamp": _first((report.get("timer") or {}).get("last_poll_utc"), report.get("completed_utc")), "notes": f"Supporting sign-ins: {(sources.get('sign_in_logs') or {}).get('count', 0)}"})
    if local or tenant:
        rows.append({"source": "Local endpoint JSON", "found": _yes_no(bool(local)), "object": _first(local.get("computer_name"), local.get("test_device_name_from_vm"), report.get("test_device"), default="Endpoint evidence"), "timestamp": _first(local.get("generated_utc"), local.get("timestamp_utc"), report.get("generated_utc")), "notes": _first(local.get("local_summary"), local.get("file_path"), default="Local evidence imported")})
        rows.append({"source": "Defender XDR Advanced Hunting", "found": _yes_no(bool(tenant.get("mde_cloud_evidence_found") or alert.get("alert_found") or timeline.get("tamper_specific_evidence_found"))), "object": _first(alert.get("alert_title"), timeline.get("blocked_setting"), tenant.get("test_device_name_requested"), default="Tenant telemetry"), "timestamp": _first(alert.get("alert_timestamp"), timeline.get("evidence_found_at_utc"), tenant.get("tenant_evidence_found_at_utc"), default="Not found"), "notes": _first(tenant.get("mde_cloud_query_status"), alert.get("detection_source"), default="Advanced Hunting result")})
    return rows or [{"source": "Scenario report", "found": "Unknown", "object": "Not recorded", "timestamp": _first(report.get("generated_at"), report.get("generated_utc")), "notes": "No structured evidence summary was available."}]


def _cleanup(report: dict[str, Any]) -> dict[str, str]:
    data = report.get("cleanup") or {}
    sid = str(report.get("display_id") or report.get("scenario_id") or "").upper()
    if sid in CLD_SHAREPOINT_IDS:
        completed = data.get("cleanup_completed")
        if completed is None:
            completed = str(data.get("status") or "").lower() == "completed"
        link_created = bool((report.get("metrics") or {}).get("anonymous_link_created") or (report.get("anonymous_link_attempt") or {}).get("link_created"))
        return {
            "required": "Yes" if link_created or (report.get("test_object") or {}).get("file_created") else "Not needed",
            "completed": _yes_no(completed),
            "remaining": "None" if completed else "Anonymous permission or dummy file may need review",
            "emergency": "No" if completed else "Yes",
        }
    if sid in {"ID-DV-005", "ID-C-005"}:
        completed = data.get("cleanup_completed")
        if completed is None:
            completed = str(data.get("status") or data.get("cleanup_status") or "").lower() == "completed"
        status = _first(data.get("status"), data.get("cleanup_status"), default="Pending")
        return {
            "required": "Yes",
            "completed": _yes_no(completed),
            "remaining": "None" if completed else status,
            "emergency": "No" if completed else "Review exact guest cleanup",
        }
    required = data.get("decoy_user_cleanup_required")
    if required is None:
        required = data.get("active_state_file") or data.get("state_file_active") or data.get("cleanup_required")
    completed = data.get("cleanup_completed")
    if completed is None:
        completed = str(data.get("status") or data.get("cleanup_status") or "").lower() == "completed"
    return {
        "required": _yes_no(bool(required) if required is not None else True),
        "completed": _yes_no(completed),
        "remaining": "None" if completed else "Needs attention",
        "emergency": "No" if completed else "Yes",
    }


def _scrub(data: Any) -> Any:
    blocked = {"password", "token", "secret", "privatekey", "private_key", "access_token", "refresh_token"}
    if isinstance(data, dict):
        clean = {}
        for key, value in data.items():
            lower = str(key).lower()
            if any(word in lower for word in blocked):
                clean[key] = "<redacted>"
            elif "web_url" in lower or lower == "url" or lower.endswith("_url"):
                clean[key] = "Hidden from HTML report."
            else:
                clean[key] = _scrub(value)
        return clean
    if isinstance(data, list):
        return [_scrub(item) for item in data]
    return data


def _write_devdv004_html_report(report: dict[str, Any], html_path: Path, stdout: str = "") -> Path:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    scenario_id = _first(report.get("display_id"), report.get("scenario_id"), default="DEV-DV-004")
    scenario_name = _first(report.get("scenario_name"), default="Sandbox Device Registration Abuse Probe")
    verdict = normalize_verdict(report.get("status"), report.get("verdict"))
    tone = _tone(verdict)
    risk = _first(report.get("risk"), default="UNKNOWN").upper()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    decoy = report.get("decoy_user") or {}
    metrics = report.get("metrics") or {}
    found = report.get("what_ztvp_found") or {}
    timer = report.get("timer") or {}
    final_state = report.get("final_device_state") or {}
    sources = report.get("evidence_sources") or {}
    cleanup = _cleanup(report)

    def card(label: str, value: object, css: str = "") -> str:
        return f'<div class="card {css}"><span>{_safe(label)}</span><strong>{_safe(value)}</strong></div>'

    top_cards = "".join(
        [
            card("Verdict", verdict, tone),
            card("Risk", risk),
            card("Decoy user", _first(decoy.get("user_principal_name"), default="Not recorded")),
            card("Final device state", _first(final_state.get("state"), metrics.get("final_device_state"), default="Unknown")),
            card("Linked devices", _first(metrics.get("registered_devices_linked_count"), found.get("registered_devices_linked_to_decoy_user"), default="0")),
            card("Temporary device observed", "Yes" if metrics.get("temporary_device_observed") or found.get("temporary_device_observed") else "No"),
            card("Audit lifecycle events", _first(metrics.get("audit_event_count"), found.get("lifecycle_events_count"), default="0")),
        ]
    )

    timer_rows = [
        ("Monitoring window", f"{_first(timer.get('monitoring_window_minutes'), default='Not recorded')} minutes"),
        ("Retry interval", f"{_first(timer.get('retry_interval_seconds'), metrics.get('poll_interval_seconds'), default='Not recorded')} seconds"),
        ("Polls used", f"{_first(timer.get('poll_attempts'), metrics.get('poll_attempts'), default='0')} / {_first(timer.get('max_poll_attempts'), metrics.get('max_poll_attempts'), default='N/A')}"),
        ("Elapsed time", f"{_first(timer.get('elapsed_seconds'), metrics.get('elapsed_seconds'), default='Not recorded')} seconds"),
        ("Stopped early", _yes_no(timer.get("stopped_early"), "Unknown")),
        ("Stop reason", _first(timer.get("stop_reason"), metrics.get("stop_reason"), default="Not recorded")),
    ]
    timer_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in timer_rows)

    found_rows = [
        ("registeredDevices query completed", _yes_no(found.get("registered_devices_query_completed"))),
        ("Temporary device observed", _yes_no(found.get("temporary_device_observed"))),
        ("Current registered devices linked", _first(found.get("current_registered_devices_linked"), found.get("registered_devices_linked_to_decoy_user"), default="0")),
        ("Final Graph registeredDevices count", _first(found.get("final_graph_registered_devices_count"), metrics.get("final_graph_registered_devices_count"), default="0")),
        ("Device still exists in /devices", _first(found.get("device_still_exists_in_devices"), metrics.get("device_still_exists_in_devices"), default="Unknown")),
        ("Device linked to decoy user", _first(found.get("device_linked_to_decoy_user"), final_state.get("device_linked_to_decoy"), default="Unknown")),
        ("Device lifecycle audit events", _first(found.get("lifecycle_events_count"), metrics.get("audit_event_count"), default="0")),
        ("Exact decoy audit matches", _first(found.get("exact_decoy_audit_events_count"), metrics.get("exact_decoy_audit_event_count"), default="0")),
        ("Register device event found", _yes_no(found.get("register_device_event_found"))),
        ("Add device event found", _yes_no(found.get("add_device_event_found"))),
        ("Add owner event found", _yes_no(found.get("add_owner_event_found"))),
        ("Add user event found", _yes_no(found.get("add_user_event_found"))),
        ("Unregister device event found", _yes_no(found.get("unregister_device_event_found"))),
        ("Delete device event found", _yes_no(found.get("delete_device_event_found"))),
        ("Detected device", _first(found.get("detected_device_name"), found.get("detected_device_id"), default="Not returned")),
        ("Evidence confidence", _first(found.get("evidence_confidence"), report.get("evidence_quality"), default="Unknown")),
        ("Sign-in logs checked as supporting evidence", _yes_no(found.get("sign_in_evidence_found"))),
    ]
    found_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in found_rows)

    source_cards = "".join(
        [
            card("registeredDevices", f"{_yes_no((sources.get('registeredDevices') or {}).get('found'))} ({(sources.get('registeredDevices') or {}).get('count', 0)})"),
            card("Audit logs", f"{_yes_no((sources.get('audit_logs') or {}).get('found'))} ({(sources.get('audit_logs') or {}).get('count', 0)})"),
            card("Sign-in logs", f"{_yes_no((sources.get('sign_in_logs') or {}).get('found'))} ({(sources.get('sign_in_logs') or {}).get('count', 0)})"),
        ]
    )

    final_device_rows = [
        ("Device linked to decoy", _first(final_state.get("device_linked_to_decoy"), default="Unknown")),
        ("Decoy user currently has registered devices", "Yes" if _first(final_state.get("device_linked_to_decoy"), default="Unknown") == "Yes" else "No" if _first(final_state.get("device_linked_to_decoy"), default="Unknown") == "No" else "Unknown"),
        ("Current registeredDevices count", _first(final_state.get("current_registered_device_count"), metrics.get("registered_devices_linked_count"), default="0")),
        ("Final Graph registeredDevices count", _first(final_state.get("final_graph_registered_devices_count"), metrics.get("final_graph_registered_devices_count"), default="0")),
        ("Device still exists in /devices", _first(final_state.get("device_still_exists_in_devices"), metrics.get("device_still_exists_in_devices"), default="Unknown")),
        ("User Devices tab equivalent", f"{_first(final_state.get('current_registered_device_count'), metrics.get('registered_devices_linked_count'), default='0')} devices"),
        ("Linked device IDs", ", ".join([str(x) for x in (final_state.get("linked_device_ids") or [])]) or "None"),
        ("Removed/unregistered evidence", _yes_no(final_state.get("removed_or_unregistered_evidence"), "Unknown")),
        ("Portal evidence alignment", "This matches the portal evidence where the decoy user has no devices listed." if _first(final_state.get("current_registered_device_count"), metrics.get("registered_devices_linked_count"), default="0") == "0" else "A current linked device was confirmed by Graph."),
    ]
    final_device_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in final_device_rows)

    rec_html = "".join(f"<li>{_safe(item)}</li>" for item in _recommendations(report, verdict))

    audit_trail = report.get("audit_trail") or []
    if audit_trail:
        audit_rows = "".join(
            "<tr>"
            f"<td>{_safe(row.get('time'))}</td>"
            f"<td>{_safe(row.get('service'))}</td>"
            f"<td>{_safe(row.get('activity'))}</td>"
            f"<td>{_safe(row.get('status'))}</td>"
            f"<td>{_safe(row.get('target'))}</td>"
            f"<td>{_safe(row.get('initiated_by'))}</td>"
            f"<td>{_safe(row.get('meaning') or row.get('why_it_matters'))}</td>"
            "</tr>"
            for row in audit_trail
        )
    else:
        audit_rows = '<tr><td colspan="7">No device registration audit trail rows were returned.</td></tr>'

    technical = json.dumps(_scrub(report), indent=2, ensure_ascii=False)
    if stdout:
        technical += f"\n\nPowerShell output:\n{stdout}"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_safe(scenario_id)} - {_safe(scenario_name)}</title>
<style>
body {{ margin:0; background:#f8fafc; color:#172033; font-family:Segoe UI,Arial,sans-serif; line-height:1.5; }}
.page {{ max-width:1120px; margin:0 auto; padding:32px 22px 48px; }}
.header {{ background:#ffffff; border:1px solid #dbe4ef; border-radius:10px; padding:22px; }}
h1 {{ margin:0 0 6px; font-size:28px; }}
h2 {{ margin:28px 0 10px; font-size:18px; }}
.muted {{ color:#607086; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:16px; }}
.card {{ border:1px solid #dbe4ef; border-radius:8px; padding:14px; background:#ffffff; }}
.card span {{ display:block; color:#607086; font-size:12px; font-weight:700; text-transform:uppercase; }}
.card strong {{ display:block; margin-top:5px; word-break:break-word; }}
.card.pass strong {{ color:#15803d; }}
.card.partial strong {{ color:#b45309; }}
.card.fail strong {{ color:#b91c1c; }}
.verdict {{ border-radius:10px; color:white; padding:18px 20px; margin-top:18px; }}
.verdict.pass {{ background:#15803d; }}
.verdict.partial {{ background:#b45309; }}
.verdict.fail {{ background:#b91c1c; }}
.verdict.muted {{ background:#6b7280; }}
.verdict h2 {{ margin:0 0 4px; color:white; }}
.section {{ background:#ffffff; border:1px solid #dbe4ef; border-radius:10px; padding:18px 20px; margin-top:18px; }}
table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
th,td {{ text-align:left; vertical-align:top; border-bottom:1px solid #e5edf7; padding:9px 10px; }}
th {{ width:280px; color:#334155; background:#f8fafc; }}
thead th {{ width:auto; }}
ul {{ margin-top:8px; }}
details {{ margin-top:18px; border:1px solid #dbe4ef; border-radius:10px; padding:12px 14px; background:#ffffff; }}
summary {{ cursor:pointer; font-weight:700; }}
pre {{ background:#101827; color:#e5edf7; padding:14px; border-radius:8px; overflow:auto; white-space:pre-wrap; }}
@media (max-width:850px) {{ .grid {{ grid-template-columns:1fr; }} th {{ width:auto; }} }}
</style>
</head>
<body>
<main class="page">
  <section class="header">
    <h1>{_safe(scenario_id)} - {_safe(scenario_name)}</h1>
    <div class="muted">Generated by Zero Trust Validation Platform at {_safe(generated)}</div>
    <div class="grid">{top_cards}</div>
  </section>
  <section class="verdict {_safe(tone)}"><h2>Decision: {_safe(verdict)}</h2><div>{_safe(_verdict_reason(verdict, report))}</div></section>
  <section class="section"><h2>Tenant Conclusion</h2><p>{_safe(report.get("what_ztvp_thinks_happened") or _verdict_reason(verdict, report))}</p></section>
  <section class="section"><h2>Final Tenant State</h2><table><tbody>{final_device_html}</tbody></table></section>
  <section class="section"><h2>Evidence Summary</h2><div class="grid">{source_cards}</div><table><tbody>{found_html}</tbody></table><h2>Timer And Polling</h2><table><tbody>{timer_html}</tbody></table></section>
  <section class="section"><h2>Device Lifecycle Audit Trail</h2><table><thead><tr><th>Time</th><th>Service</th><th>Activity</th><th>Status</th><th>Target</th><th>Initiated by</th><th>Meaning</th></tr></thead><tbody>{audit_rows}</tbody></table></section>
  <section class="section"><h2>Recommendations</h2><ul>{rec_html}</ul></section>
  <section class="section"><h2>Cleanup</h2><table><tbody>
    <tr><th>Cleanup required</th><td>{_safe(cleanup['required'])}</td></tr>
    <tr><th>Cleanup completed</th><td>{_safe(cleanup['completed'])}</td></tr>
    <tr><th>Remaining risk</th><td>{_safe(cleanup['remaining'])}</td></tr>
    <tr><th>Emergency cleanup needed</th><td>{_safe(cleanup['emergency'])}</td></tr>
  </tbody></table></section>
  <details><summary>Technical evidence details</summary><pre>{_safe(technical)}</pre></details>
</main>
</body>
</html>
"""
    html_path.write_text(html_doc, encoding="utf-8")
    return html_path


def _write_idc002_html_report(report: dict[str, Any], html_path: Path, stdout: str = "") -> Path:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    scenario_id = _first(report.get("display_id"), report.get("scenario_id"), default="ID-DV-002")
    scenario_name = _first(report.get("scenario_name"), default="Device Code Flow Block Validation")
    verdict = normalize_verdict(report.get("status"), report.get("verdict"))
    risk = _first(report.get("risk"), default="UNKNOWN").upper()
    tone = _tone(verdict)
    metrics = report.get("metrics") or {}
    policy = report.get("policy_attribution") or {}
    decoy = report.get("decoy_user") or {}
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    matched = report.get("selected_evidence_row") or report.get("matched_sign_in") or {}
    cleanup = _cleanup(report)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    target_user = _first(target.get("name"), target.get("user_principal_name"), decoy.get("user_principal_name"), report.get("test_user"), default="Not recorded")
    app = _first(matched.get("AppDisplayName"), target.get("app"), default="Not recorded")
    resource = _first(matched.get("ResourceDisplayName"), target.get("resource"), default="Not recorded")
    client = _first(matched.get("ClientAppUsed"), default="Not recorded")
    evidence_time = _first(matched.get("SignInCreatedUtc"), matched.get("CreatedDateTime"), metrics.get("latest_matching_signin_time_utc"), default="Not recorded")
    attempts = _first(metrics.get("evidence_poll_attempts"), metrics.get("poll_attempts"), default="0")
    max_attempts = _first(metrics.get("evidence_max_poll_attempts"), metrics.get("max_poll_attempts"), default="N/A")
    tenant_found = bool(metrics.get("tenant_evidence_found") or policy.get("tenant_evidence_found") or matched)
    matching_found = bool(metrics.get("matching_signin_found") or matched)
    grant_controls = ", ".join([str(x) for x in (policy.get("main_blocking_policy_grant_controls") or [])]) or "Not attributed"
    blocking_policy = _first(policy.get("main_blocking_policy_name"), metrics.get("main_blocking_policy_name"), default="Not attributed")
    policy_result = _first(policy.get("main_blocking_policy_result"), default="Not attributed")
    started = _first(report.get("started_utc"), (report.get("device_code_challenge") or {}).get("started_at"), metrics.get("evidence_start_utc"), report.get("validation_start_utc"), default="Not recorded")
    validation_start = _first(report.get("validation_start_utc"), metrics.get("evidence_start_utc"), default="Not recorded")

    if verdict == "PASS":
        decision_text = "Device code flow was blocked by Conditional Access."
    elif verdict == "FAIL":
        decision_text = "Device code flow succeeded and token/sign-in evidence was found."
    elif matched:
        decision_text = "Device-code sign-in evidence was found, but no enforced block policy was attributed."
    else:
        decision_text = "No matching device-code sign-in evidence was found before timeout."

    def _table(rows: list[tuple[str, object]]) -> str:
        return "<table><tbody>" + "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in rows) + "</tbody></table>"

    executive_rows = [
        ("Verdict", verdict),
        ("Risk", risk),
        ("Reason", decision_text),
        ("Tenant evidence found", "Yes" if tenant_found else "No"),
        ("Matching sign-in found", "Yes" if matching_found else "No"),
        ("Target decoy user", target_user),
        ("Started UTC", started),
        ("Validation start UTC", validation_start),
    ]
    tenant_rows = [
        ("Evidence time UTC", evidence_time),
        ("User", _first(matched.get("UserPrincipalName"), target_user, default="Not recorded")),
        ("App", app),
        ("Resource", resource),
        ("Client", client),
        ("Status", _first(matched.get("Status"), default="Not recorded")),
        ("Error code", _first(matched.get("StatusCode"), default="Not recorded")),
        ("Conditional Access status", _first(matched.get("ConditionalAccessStatus"), default="Not recorded")),
        ("IP", _first(matched.get("IpAddress"), default="Not recorded")),
        ("Request ID", _first(matched.get("RequestId"), matched.get("SignInId"), default="Not recorded")),
        ("Selected evidence reason", _first(report.get("selected_evidence_reason"), default="Not recorded")),
        ("Meaningful sign-ins", _first(metrics.get("meaningful_sign_in_count"), metrics.get("device_code_evidence_count"), default="0")),
    ]
    ca_rows = [
        ("Main blocking policy", blocking_policy),
        ("Policy result", policy_result),
        ("Grant controls", grant_controls),
        ("Block policy applied", _yes_no(policy.get("device_code_block_policy_applied"))),
        ("Configured enabled block policies", _first(metrics.get("configured_enabled_block_policy_count"), default="0")),
        ("Configured report-only block policies", _first(metrics.get("configured_report_only_block_policy_count"), default="0")),
    ]
    polling_rows = [
        ("Poll interval seconds", _first(metrics.get("evidence_poll_interval_seconds"), default="15")),
        ("Polls used / max polls", f"{attempts} / {max_attempts}"),
        ("Token issued", _yes_no(metrics.get("token_issued"))),
        ("Token outcome", _first((report.get("token_polling") or {}).get("token_outcome"), policy.get("token_outcome"), default="Not recorded")),
        ("Evidence stopped early", _yes_no(metrics.get("evidence_stopped_early"))),
        ("Polling stopped early", _yes_no(metrics.get("polling_stopped_early"))),
    ]
    cleanup_rows = [
        ("Cleanup required", cleanup["required"]),
        ("Cleanup completed", cleanup["completed"]),
        ("Remaining risk", cleanup["remaining"]),
        ("Emergency cleanup needed", cleanup["emergency"]),
    ]

    technical = json.dumps(_scrub(report), indent=2, ensure_ascii=False)
    if stdout:
        technical += f"\n\nPowerShell output:\n{stdout}"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_safe(scenario_id)} - {_safe(scenario_name)}</title>
<style>
body {{ margin:0; background:#f7f9fc; color:#172033; font-family:Segoe UI,Arial,sans-serif; line-height:1.55; }}
.page {{ max-width:1180px; margin:0 auto; padding:32px 24px 48px; }}
.header {{ background:#0f172a; color:white; border-radius:8px; padding:24px; }}
h1 {{ margin:0 0 6px; font-size:28px; }}
h2 {{ margin:30px 0 12px; font-size:20px; }}
.muted {{ color:#64748b; }}
.header .muted {{ color:#cbd5e1; }}
.decision {{ margin-top:18px; border-radius:8px; padding:18px; color:white; }}
.decision.pass {{ background:#15803d; }}
.decision.partial {{ background:#b45309; }}
.decision.fail {{ background:#b91c1c; }}
.decision.muted {{ background:#6b7280; }}
.section {{ background:white; border:1px solid #dbe4ef; border-radius:8px; padding:20px; margin-top:18px; }}
table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
th,td {{ text-align:left; vertical-align:top; border-bottom:1px solid #e5ebf3; padding:10px 12px; }}
th {{ width:280px; color:#475569; background:#f8fafc; }}
details {{ margin-top:18px; background:white; border:1px solid #dbe4ef; border-radius:8px; padding:14px 16px; }}
summary {{ cursor:pointer; font-weight:700; }}
pre {{ background:#101827; color:#e5edf7; padding:14px; border-radius:8px; overflow:auto; white-space:pre-wrap; }}
@media (max-width:850px) {{ th {{ width:auto; display:block; }} td {{ display:block; }} }}
</style>
</head>
<body>
<main class="page">
  <section class="header">
    <h1>{_safe(scenario_id)} - {_safe(scenario_name)}</h1>
    <div class="muted">Generated at {_safe(generated)}</div>
  </section>
  <section class="decision {_safe(tone)}"><strong>{_safe(verdict)} / Risk { _safe(risk) }</strong><br>{_safe(decision_text)}</section>
  <section class="section"><h2>1. Executive Result</h2>{_table(executive_rows)}</section>
  <section class="section"><h2>2. Tenant Evidence</h2>{_table(tenant_rows)}</section>
  <section class="section"><h2>3. Conditional Access Evidence</h2>{_table(ca_rows)}</section>
  <section class="section"><h2>4. Polling Summary</h2>{_table(polling_rows)}</section>
  <section class="section"><h2>5. Cleanup Status</h2>{_table(cleanup_rows)}</section>
  <details><summary>6. Technical Details</summary><pre>{_safe(technical)}</pre></details>
</main>
</body>
</html>
"""
    html_path.write_text(html_doc, encoding="utf-8")
    return html_path


def write_standard_html_report(report: dict[str, Any], html_path: Path, stdout: str = "") -> Path:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    scenario_id = _first(report.get("display_id"), report.get("scenario_id"), default="Unknown scenario")
    scenario_name = _first(report.get("scenario_name"), default="Unknown scenario")
    if str(scenario_id).upper() == "DEV-DV-004":
        return _write_devdv004_html_report(report, html_path, stdout=stdout)
    if str(scenario_id).upper() in {"ID-DV-002", "ID-C-002"}:
        return _write_idc002_html_report(report, html_path, stdout=stdout)
    verdict = normalize_verdict(report.get("status"), report.get("verdict"))
    tone = _tone(verdict)
    risk = _first(report.get("risk"), default="UNKNOWN").upper()
    started = _first(report.get("started_utc"), report.get("started_at"), report.get("validation_window_start_utc"), default="Not recorded")
    completed = _first(report.get("completed_utc"), report.get("generated_utc"), report.get("generated_at"), default="Not recorded")
    cleanup = _cleanup(report)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header_cards = [
        ("Scenario ID", scenario_id),
        ("Scenario name", scenario_name),
        ("Pillar", _first(report.get("pillar"), default="Not recorded")),
        ("Run ID", _first(report.get("run_id"), default="Not recorded")),
        ("Tenant", _tenant(report)),
        ("Target user/device/file/app", _target(report)),
        ("Started UTC", started),
        ("Completed UTC", completed),
    ]
    if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
        header_cards[5:6] = [
            ("Test user", _first(report.get("test_user"), default="Not recorded")),
            ("Target app", _first(report.get("target_app"), default="Not recorded")),
        ]
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-001":
        header_cards[5:6] = [
            ("Decoy user", _first((report.get("decoy_user") or {}).get("user_principal_name"), default="Not recorded")),
            ("Target app", _first((report.get("target") or {}).get("name"), report.get("target_app"), default="Not recorded")),
            ("Validation start UTC", _first(report.get("validation_start_utc"), (report.get("sign_in_log_evidence") or {}).get("validation_window_start_utc"), default="Not recorded")),
        ]
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
        header_cards[5:6] = [
            ("Decoy user", _first((report.get("decoy_user") or {}).get("user_principal_name"), default="Not recorded")),
            ("Final device state", _first((report.get("final_device_state") or {}).get("state"), (report.get("metrics") or {}).get("final_device_state"), default="Unknown")),
            ("Linked devices", _first((report.get("metrics") or {}).get("registered_devices_linked_count"), default="0")),
        ]
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
        header_cards[5:6] = [
            ("Site", _first((report.get("site") or {}).get("displayName"), (report.get("site") or {}).get("webUrl"), default="Not recorded")),
            ("Drive/library", _first((report.get("drive") or {}).get("name"), default="Not recorded")),
            ("Dummy file", _first((report.get("test_object") or {}).get("file_name"), default="Not recorded")),
        ]
    cards_html = "".join(f'<div class="card"><span>{_safe(k)}</span><strong>{_safe(v)}</strong></div>' for k, v in header_cards)
    main_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in _main_rows(report, verdict))
    effective_policy_section = ""
    if scenario_id.upper() in {"ID-DV-001", "ID-C-001"}:
        mfa = summarize_mfa_report(report)
        policy_rows = mfa.get("relevant_policies") or []
        policy_html = "".join(
            f"<tr><td>{_safe(row.get('Policy'))}</td><td>{_safe(row.get('Result'))}</td><td>{_safe(row.get('Grant control'))}</td><td>{_safe(row.get('Meaning'))}</td></tr>"
            for row in policy_rows
        ) or '<tr><td colspan="4">None found</td></tr>'
        effective_policy_section = (
            "<h2>Effective Policy</h2>"
            "<table><thead><tr><th>Policy</th><th>Result</th><th>Grant control</th><th>Meaning</th></tr></thead>"
            f"<tbody>{policy_html}</tbody></table>"
        )
    idc005_policy_section = ""
    if scenario_id.upper() in {"ID-DV-005", "ID-C-005"}:
        latest = report.get("latest_admin_portal_attempt") or {}
        policy_rows = latest.get("appliedConditionalAccessPolicies") or report.get("policy_control_table") or []
        rows_html = "".join(
            "<tr>"
            f"<td>{_safe(row.get('displayName') or row.get('policy_control_name'))}</td>"
            f"<td>{_safe(row.get('result'))}</td>"
            f"<td>{_safe(', '.join([str(x) for x in (row.get('enforcedGrantControls') or row.get('grantControls') or [])]))}</td>"
            f"<td>{_safe(row.get('classification') or 'Not recorded')}</td>"
            "</tr>"
            for row in policy_rows
            if isinstance(row, dict)
        ) or '<tr><td colspan="4">No Conditional Access policy/control rows were returned for the latest portal attempt.</td></tr>'
        idc005_policy_section = (
            "<h2>Policy / Control Attribution</h2>"
            "<table><thead><tr><th>Policy/control name</th><th>Result</th><th>Grant controls</th><th>Classification</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )
    polling_rows = _polling_rows(report)
    polling_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in polling_rows)
    polling_section = ""
    is_cld001 = scenario_id.upper() in CLD_SHAREPOINT_IDS or str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS
    if polling_html:
        sign_in = report.get("sign_in_log_evidence") or {}
        metrics = report.get("metrics") or {}
        poll_attempts = _first(metrics.get("poll_attempts"), sign_in.get("poll_count"), default="0")
        polling_result_text = "did not find matching sign-in evidence." if _is_devdv001_no_evidence(report) else "found matching sign-in evidence."
        polling_section = f"<h2>Polling Summary</h2><p>ZTVP completed {_safe(poll_attempts)} polling attempts and {polling_result_text}</p><table><tbody>{polling_html}</tbody></table>"
    execution_summary_section = ""
    controlled_target_section = ""
    if is_cld001:
        metrics = report.get("metrics") or {}
        attempt = report.get("anonymous_link_attempt") or {}
        site = report.get("site") or {}
        drive = report.get("drive") or {}
        test_object = report.get("test_object") or {}
        cleanup_data = report.get("cleanup") or {}
        link_created = bool(metrics.get("anonymous_link_created") or attempt.get("link_created"))
        link_denied = bool(metrics.get("anonymous_link_denied") or attempt.get("link_denied"))
        cleanup_completed = metrics.get("cleanup_completed")
        if cleanup_completed is None:
            cleanup_completed = str(cleanup_data.get("status") or "").lower() == "completed"
        execution_rows = [
            ("Validation type", "Direct SharePoint createLink test"),
            ("Target site", _first(site.get("displayName"), site.get("webUrl"), default="Not recorded")),
            ("Drive/library", _first(drive.get("name"), default="Not recorded")),
            ("Dummy file", _first(test_object.get("file_name"), default="Not recorded")),
            ("Requested link scope", _first(attempt.get("requested_scope"), default="anonymous")),
            ("Requested link type", _first(attempt.get("requested_type"), default="Not recorded")),
            ("Anonymous link created", "Yes" if link_created else "No"),
            ("Link blocked/denied", "Yes" if link_denied else "No"),
            ("Denial reason", _first(attempt.get("error_message"), attempt.get("error_category"), default="Not applicable")),
            ("Cleanup completed", _yes_no(cleanup_completed)),
        ]
        execution_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in execution_rows)
        execution_summary_section = f"<h2>Execution Summary</h2><table><tbody>{execution_html}</tbody></table>"
        target_rows = [
            ("Site", _first(site.get("displayName"), site.get("webUrl"), default="Not recorded")),
            ("Drive/library", _first(drive.get("name"), default="Not recorded")),
            ("Dummy file", _first(test_object.get("file_name"), default="Not recorded")),
        ]
        target_html = "".join(f"<tr><th>{_safe(k)}</th><td>{_safe(v)}</td></tr>" for k, v in target_rows)
        controlled_target_section = f"<h2>Controlled SharePoint Target</h2><table><tbody>{target_html}</tbody></table>"
    rec_html = "".join(f"<li>{_safe(item)}</li>" for item in _recommendations(report, verdict))
    evidence_html = "".join(
        f"<tr><td>{_safe(row['source'])}</td><td>{_safe(row['found'])}</td><td>{_safe(row['object'])}</td><td>{_safe(row['timestamp'])}</td><td>{_safe(row['notes'])}</td></tr>"
        for row in _evidence_rows(report)
    )
    audit_trail = report.get("audit_trail") or []
    audit_trail_html = ""
    if audit_trail:
        rows_html = "".join(
            "<tr>"
            f"<td>{_safe(row.get('time'))}</td>"
            f"<td>{_safe(row.get('service'))}</td>"
            f"<td>{_safe(row.get('activity'))}</td>"
            f"<td>{_safe(row.get('status'))}</td>"
            f"<td>{_safe(row.get('target'))}</td>"
            f"<td>{_safe(row.get('initiated_by'))}</td>"
            f"<td>{_safe(row.get('why_it_matters'))}</td>"
            "</tr>"
            for row in audit_trail
        )
        audit_trail_html = "<h2>Audit Trail</h2><table><thead><tr><th>Time</th><th>Service</th><th>Activity</th><th>Status</th><th>Target</th><th>Initiated by</th><th>Why it matters</th></tr></thead><tbody>" + rows_html + "</tbody></table>"
    technical = json.dumps(_scrub(report), indent=2, ensure_ascii=False)
    polling_details_section = "" if is_cld001 else f"<details><summary>Polling details</summary><pre>{_safe(stdout or 'No PowerShell polling output was captured.')}</pre></details>"
    if stdout:
        technical += f"\n\nPowerShell output:\n{stdout}"
    decision_label = verdict
    if scenario_id.upper() in CLD_SHAREPOINT_IDS:
        decision_label = {
            "PASS": "PASS - Anonymous sharing link blocked",
            "FAIL": "FAIL - Anonymous sharing link allowed",
            "PARTIAL": "PARTIAL - Anonymous link was not created, but the denial reason is unclear",
            "ERROR": "ERROR - SharePoint createLink setup failed",
        }.get(verdict, verdict)

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_safe(scenario_id)} - {_safe(scenario_name)}</title>
<style>
body {{ margin:0; background:#fff; color:#172033; font-family:Segoe UI,Arial,sans-serif; line-height:1.5; }}
.page {{ max-width:1120px; margin:0 auto; padding:30px 22px 44px; }}
h1 {{ margin:0 0 6px; font-size:28px; }}
h2 {{ margin:26px 0 10px; font-size:18px; }}
.muted {{ color:#607086; }}
.header {{ border-bottom:1px solid #dbe4ef; padding-bottom:18px; }}
.grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-top:16px; }}
.card {{ border:1px solid #dbe4ef; border-radius:8px; padding:14px; background:#fff; }}
.card span {{ display:block; color:#607086; font-size:12px; font-weight:700; text-transform:uppercase; }}
.card strong {{ display:block; margin-top:5px; word-break:break-word; }}
.verdict {{ border-radius:8px; color:white; padding:18px; margin-top:20px; }}
.verdict.pass {{ background:#15803d; }}
.verdict.partial {{ background:#b45309; }}
.verdict.fail {{ background:#b91c1c; }}
.verdict.muted {{ background:#6b7280; }}
.verdict h2 {{ margin:0 0 4px; color:white; }}
table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
th,td {{ text-align:left; vertical-align:top; border:1px solid #dbe4ef; padding:10px; }}
th {{ background:#f6f8fb; width:260px; }}
thead th {{ width:auto; }}
details {{ margin-top:24px; border:1px solid #dbe4ef; border-radius:8px; padding:12px 14px; }}
summary {{ cursor:pointer; font-weight:700; }}
pre {{ background:#101827; color:#e5edf7; padding:14px; border-radius:8px; overflow:auto; white-space:pre-wrap; }}
.ok {{ color:#15803d; font-weight:700; }}
.bad {{ color:#b91c1c; font-weight:700; }}
@media (max-width:850px) {{ .grid {{ grid-template-columns:1fr; }} th {{ width:auto; }} }}
</style>
</head>
<body>
<main class="page">
  <section class="header">
    <h1>{_safe(scenario_id)} - {_safe(scenario_name)}</h1>
    <div class="muted">Generated by Zero Trust Validation Platform at {_safe(generated)}</div>
    <div class="grid">{cards_html}</div>
  </section>
  <section class="verdict {_safe(tone)}"><h2>{_safe(decision_label)}</h2><div>{_safe(_verdict_reason(verdict, report))}</div></section>
  <h2>Risk Explanation</h2><p>{_safe(_risk_explanation(verdict, risk, report))}</p>
  <h2>What Was Tested</h2><p>{_safe(_what_was_tested(report))}</p>
  {execution_summary_section}
  <h2>Main Result</h2><table><tbody>{main_html}</tbody></table>
  {controlled_target_section}
  {effective_policy_section}
  {idc005_policy_section}
  {polling_section}
  <h2>Why This Verdict Was Selected</h2><p>{_safe(_verdict_reason(verdict, report))}</p>
  <h2>Remediation / Recommendation</h2><ul>{rec_html}</ul>
  <h2>Evidence Summary</h2>
  <table><thead><tr><th>Evidence source</th><th>Evidence found</th><th>Matched object</th><th>Timestamp</th><th>Notes</th></tr></thead><tbody>{evidence_html}</tbody></table>
  {audit_trail_html}
  <h2>Cleanup</h2>
  <table><tbody>
    <tr><th>Cleanup required</th><td>{_safe(cleanup['required'])}</td></tr>
    <tr><th>Cleanup completed</th><td class="{'ok' if cleanup['completed'] == 'Yes' else 'bad'}">{_safe(cleanup['completed'])}</td></tr>
    <tr><th>Remaining risk</th><td>{_safe(cleanup['remaining'])}</td></tr>
    <tr><th>Emergency cleanup needed</th><td>{_safe(cleanup['emergency'])}</td></tr>
  </tbody></table>
  {polling_details_section}
  <details><summary>Technical evidence details</summary><pre>{_safe(technical)}</pre></details>
</main>
</body>
</html>
"""
    html_path.write_text(html_doc, encoding="utf-8")
    return html_path
