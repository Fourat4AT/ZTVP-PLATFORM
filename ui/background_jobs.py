from __future__ import annotations

import math
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_state import ACTIVE_STATUSES, is_stale, latest_run_for_scenario, load_run, new_run_id, save_run, update_run, utc_now
from html_report import write_standard_html_report
from ca_summary import summarize_ca_access_report, summarize_mfa_report
from graph_connection import classify_graph_error, clean_graph_message, get_graph_context


_REGISTRY_LOCK = threading.Lock()
_REGISTRY: dict[str, subprocess.Popen[str] | None] = {}
_RUN_ARGS: dict[str, list[str]] = {}
CLD_SHAREPOINT_IDS = {"APP-DV-008", "CLD-DV-001", "CLD-C-001"}


SCENARIOS = {
    "ID-DV-001": {
        "name": "MFA Enforcement Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC001.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "ID-C-001" / "decoy-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "ID-C-001" / "decoy-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "ID-C-001-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "ID-C-001-result.html",
    },
    "DEV-DV-001": {
        "name": "Unmanaged Device Cloud Access Probe",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV001.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-001" / "devdv001-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-001" / "devdv001-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-001-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "DEV-DV-001-result.html",
    },
    "DEV-DV-006": {
        "name": "Defender EICAR Detection Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV006.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006" / "devdv006-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006" / "devdv006-local-evidence.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006-result.html",
    },
    "DEV-DV-008": {
        "name": "Hybrid Tamper Protection Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV008.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008" / "devdv008-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008" / "devdv008-local-evidence.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008-result.html",
    },
    "APP-DV-004": {
        "name": "Sensitive App Access From Unmanaged Device Probe",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-APPDV004.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "APP-DV-004" / "appdv004-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "APP-DV-004" / "appdv004-local-evidence.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "APP-DV-004-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "APP-DV-004-result.html",
    },
    "APP-DV-003": {
        "name": "MDCA Public File Sharing Detection Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Invoke-ZTVP-APPC003.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "APP-C-003" / "appc003-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "APP-C-003" / "appc003-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "APP-C-003-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "APP-C-003-result.html",
    },
    "APP-DV-008": {
        "name": "SharePoint Anonymous Sharing Link Exposure Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Invoke-ZTVP-CLD001.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "CLD-C-001" / "cld001-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "CLD-C-001" / "cld001-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "CLD-C-001-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "CLD-C-001-result.html",
    },
    "DEV-DV-004": {
        "name": "Sandbox Device Registration Abuse Probe",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV004.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-004" / "devdv004-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-004" / "devdv004-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-004-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "DEV-DV-004-result.html",
    },
    "ID-DV-005": {
        "name": "Guest Invitation / External User Access Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC005Guest.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "ID-C-005" / "guest-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "ID-C-005" / "guest-state.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "ID-C-005-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "ID-C-005-result.html",
    },
}


def _read_json(path: Path) -> dict[str, Any]:
    import json

    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _powershell_exe() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(win_ps) if win_ps.exists() else "powershell.exe"


def _powershell_env() -> dict[str, str]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    user_profile = os.environ.get("USERPROFILE", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    module_paths = [
        Path(user_profile) / "Documents" / "WindowsPowerShell" / "Modules",
        Path(user_profile) / "Documents" / "PowerShell" / "Modules",
        Path(program_files) / "WindowsPowerShell" / "Modules",
        Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules",
    ]
    env = os.environ.copy()
    env["PSModulePath"] = ";".join(str(p) for p in module_paths)
    return env


def _verdict_from_status(status: object) -> str | None:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("PARTIAL"):
        return "PARTIAL"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("NOT_RUN"):
        return "PARTIAL"
    if text.startswith("UNSUPPORTED"):
        return "UNSUPPORTED"
    if text.startswith("ERROR"):
        return "ERROR"
    return None


def _result_code_from_report(report: dict[str, Any]) -> str | None:
    return str(report.get("status") or "").strip() or None


def _local_status(local_evidence: dict[str, Any], scenario_id: str) -> str:
    if not local_evidence:
        return "Missing"
    summary = local_evidence.get("local_summary") or {}
    if scenario_id == "DEV-DV-008" and summary.get("settings_weakened") is True:
        return "Settings weakened"
    return "Found"


def _local_proof(local_evidence: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    summary = local_evidence.get("local_summary") or {}
    if scenario_id == "DEV-DV-008":
        tamper_enabled = bool(summary.get("tamper_protection_enabled_before") or summary.get("tamper_protection_enabled_after"))
        settings_weakened = bool(summary.get("settings_weakened"))
        protected = bool(summary.get("defender_settings_remained_protected") or summary.get("tamper_attempt_blocked_or_ignored")) and not settings_weakened
        return {
            "local_result": "Protected" if protected else "Settings weakened" if settings_weakened else "Unknown",
            "tamper_protection": "Enabled" if tamper_enabled else "Unknown",
            "settings_weakened": "Yes" if settings_weakened else "No",
        }
    return {
        "local_eicar_detection": "Found" if bool(summary.get("local_detection_found") or summary.get("eicar_read_blocked") or summary.get("defender_blocking_error_found")) else "Unknown",
    }


def _tenant_status(report: dict[str, Any]) -> str:
    if str(report.get("display_id") or report.get("scenario_id") or "").upper() in CLD_SHAREPOINT_IDS:
        metrics = report.get("metrics") or {}
        if metrics.get("anonymous_link_created") or metrics.get("anonymous_link_denied"):
            return "Found"
        return "Not found"
    if str(report.get("scenario_id") or "").upper() in {"ID-DV-001", "ID-C-001"}:
        summary = summarize_mfa_report(report)
        if summary.get("sign_in_result") != "Unknown":
            return "Found"
        return "Not found"
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-001":
        evidence = report.get("sign_in_log_evidence") or {}
        if evidence.get("meaningful_sign_in_count") or evidence.get("selected_event"):
            return "Found"
        if str(report.get("status") or "").upper().startswith("PARTIAL_NO_SIGNIN"):
            return "Not found"
        return "Not found"
    if str(report.get("scenario_id") or "").upper() == "APP-DV-004":
        evidence = report.get("appdv004_evidence") or {}
        if evidence.get("signin_found"):
            return "Found"
        if str(report.get("status") or "").upper().startswith("UNSUPPORTED"):
            return "Unsupported"
        return "Not found"
    if str(report.get("scenario_id") or report.get("display_id") or "").upper() in {"APP-DV-003", "APP-C-003"}:
        mdca = report.get("mdca_detection_evidence") or {}
        metrics = report.get("metrics") or {}
        if mdca.get("alert_detected") or mdca.get("governance_remediation_observed"):
            return "Found"
        if metrics.get("public_link_created") is False:
            return "Not found"
        return "Not found"
    if str(report.get("scenario_id") or "").upper() == "DEV-DV-004":
        metrics = report.get("metrics") or {}
        sources = report.get("evidence_sources") or {}
        if metrics.get("device_registered_or_linked") or metrics.get("audit_events_found") or metrics.get("sign_in_evidence_found"):
            return "Found"
        if (sources.get("registeredDevices") or {}).get("checked") or (sources.get("audit_logs") or {}).get("checked"):
            return "Not found"
        return "Waiting"
    tenant_api = ((report.get("evidence") or {}).get("tenant") or {}).get("api") or {}
    if tenant_api.get("mde_cloud_evidence_found"):
        return "Found"
    return str(tenant_api.get("mde_cloud_query_status") or "Waiting")


def _target_from_state(scenario_state: dict[str, Any], local_evidence: dict[str, Any]) -> str:
    if scenario_state.get("target"):
        return str((scenario_state.get("target") or {}).get("name") or (scenario_state.get("target") or {}).get("url") or "").strip()
    return str(scenario_state.get("target_app") or scenario_state.get("test_device_name") or local_evidence.get("computer_name") or "").strip()


def _tenant_from_state(scenario_state: dict[str, Any]) -> str:
    return str(scenario_state.get("tenant_display_name") or scenario_state.get("tenant_id") or "").strip()


def _decoy_user_from_state(scenario_state: dict[str, Any]) -> str:
    decoy = scenario_state.get("decoy_user") or {}
    if isinstance(decoy, dict):
        return str(decoy.get("user_principal_name") or "").strip()
    return ""


def _validation_start_from_state(scenario_state: dict[str, Any]) -> str:
    probe = scenario_state.get("unmanaged_probe") or {}
    if isinstance(probe, dict) and probe.get("validation_window_start_utc"):
        return str(probe.get("validation_window_start_utc") or "").strip()
    return str(scenario_state.get("validation_start_utc") or "").strip()


def _phase_for_scenario(scenario_id: str) -> str:
    if scenario_id in CLD_SHAREPOINT_IDS:
        return "Running SharePoint createLink test"
    if scenario_id == "ID-DV-001":
        return "Waiting for Entra sign-in / MFA evidence"
    if scenario_id in {"APP-DV-004", "DEV-DV-001"}:
        return "Waiting for Entra sign-in / Conditional Access evidence"
    if scenario_id == "DEV-DV-004":
        return "Checking registeredDevices and device lifecycle audit logs"
    if scenario_id == "APP-DV-003":
        return "Polling MDCA Alerts API"
    return "Waiting for tenant evidence"


def _pillar_for_scenario(scenario_id: str) -> str:
    if scenario_id.startswith("APP-") or scenario_id.startswith("CLD-"):
        return "Applications"
    if scenario_id.startswith("ID-"):
        return "Identity"
    return "Devices"


def _redact_powershell_args(args: list[str] | None) -> list[str]:
    redacted: list[str] = []
    secret_switches = {"-mdcaapitoken", "-token", "-accesstoken", "-clientsecret", "-password"}
    hide_next = False
    for value in args or []:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        redacted.append(str(value))
        if str(value).lower() in secret_switches:
            hide_next = True
    return redacted


def _appdv003_live_fields(project_root: Path, meta: dict[str, Any]) -> dict[str, Any]:
    state = _read_json(project_root / meta["state"])
    if not state:
        return {}
    link = state.get("link") or state.get("public_link") or {}
    cleanup = state.get("cleanup") or {}
    updates: dict[str, Any] = {}
    if state.get("dummy_file") or state.get("test_object"):
        updates["dummy_file_created"] = "Yes"
    if isinstance(link, dict) and "public_link_created" in link:
        updates["public_link_created"] = "Yes" if link.get("public_link_created") else "No"
    elif link:
        updates["public_link_created"] = "Yes"
    if isinstance(cleanup, dict) and cleanup.get("status"):
        updates["cleanup_status"] = cleanup.get("status")
    return updates


def _cld001_live_fields(project_root: Path, meta: dict[str, Any]) -> dict[str, Any]:
    state = _read_json(project_root / meta["state"])
    if not state:
        return {}
    site = state.get("site") or {}
    test_object = state.get("test_object") or {}
    cleanup = state.get("cleanup") or {}
    permission = state.get("anonymous_permission") or {}
    attempt_status = "Created" if permission.get("link_created") else "Testing createLink"
    if str(cleanup.get("status") or "").lower() == "completed" and not permission.get("link_created"):
        attempt_status = "Blocked/Denied or not created"
    return {
        "target_site": site.get("displayName") or site.get("webUrl"),
        "dummy_file": test_object.get("file_name"),
        "anonymous_link_attempt_status": attempt_status,
        "cleanup_status": cleanup.get("status") or "Pending",
    }


def _idc001_managed_decoy(project_root: Path) -> dict[str, Any]:
    state = _read_json(project_root / SCENARIOS["ID-DV-001"]["state"])
    if not state:
        return {}
    return {
        "run_id": state.get("run_id"),
        "lifecycle": state.get("lifecycle"),
        "prepared_at": state.get("prepared_at"),
        "decoy_user": state.get("decoy_user", {}),
        "role_profile": state.get("role_profile", {}),
        "role_assignment": state.get("role_assignment", {}),
        "cleanup": state.get("cleanup", {}),
    }


def _idc001_target_upn(project_root: Path, extra_args: list[str] | None = None) -> str:
    args = list(extra_args or [])
    for index, value in enumerate(args):
        if str(value).lower() == "-decoyuserprincipalname" and index + 1 < len(args):
            return str(args[index + 1]).strip()
    state = _read_json(project_root / SCENARIOS["ID-DV-001"]["state"])
    decoy = state.get("decoy_user") or {}
    if isinstance(decoy, dict):
        return str(decoy.get("user_principal_name") or "").strip()
    return ""


def _idc001_lookback(extra_args: list[str] | None, wait_minutes: int) -> int:
    args = list(extra_args or [])
    for index, value in enumerate(args):
        if str(value).lower() == "-lookbackminutes" and index + 1 < len(args):
            try:
                return max(5, int(args[index + 1]))
            except Exception:
                return max(5, int(wait_minutes))
    return max(5, int(wait_minutes))


def _initial_message(scenario_id: str, max_attempts: int) -> str:
    if scenario_id in CLD_SHAREPOINT_IDS:
        return "Creating dummy file and attempting anonymous createLink."
    if scenario_id == "ID-DV-001":
        return f"Waiting for Entra sign-in / MFA evidence. Attempt 1 of {max_attempts}."
    if scenario_id == "DEV-DV-001":
        return "Waiting for unmanaged-device sign-in evidence."
    if scenario_id == "APP-DV-004":
        return f"Waiting for Entra sign-in / Conditional Access evidence. Attempt 1 of {max_attempts}."
    if scenario_id == "DEV-DV-004":
        return "Checking registeredDevices for the DEV-DV-004 decoy user."
    if scenario_id == "APP-DV-003":
        return "APP-DV-003 started. Creating dummy public link, then polling MDCA Alerts API."
    return f"Waiting for tenant evidence. Attempt 1 of {max_attempts}."


def _poll_message(scenario_id: str, attempt: int, max_attempts: int, poll_seconds: int) -> tuple[str, str]:
    if scenario_id in CLD_SHAREPOINT_IDS:
        return "Microsoft Graph createLink", "Testing anonymous/public sharing link creation and cleanup."
    if scenario_id == "ID-DV-001":
        return "Entra sign-in logs + MFA evidence", f"Checking Entra sign-in logs, MFA evidence, and effective Conditional Access policy. Attempt {attempt} of {max_attempts}."
    if scenario_id == "DEV-DV-001":
        return "Entra sign-in logs", f"Waiting for unmanaged-device sign-in evidence. Attempt {attempt} of {max_attempts}."
    if scenario_id == "APP-DV-004":
        return "sign-in logs + Conditional Access", f"Waiting for Entra sign-in / Conditional Access evidence. Attempt {attempt} of {max_attempts}."
    if scenario_id == "DEV-DV-004":
        step = (attempt - 1) % 3
        if step == 0:
            return "registeredDevices", "Checking registeredDevices for the DEV-DV-004 decoy user."
        if step == 1:
            return "Entra audit logs", "Checking Entra audit logs for device registration lifecycle events."
        return "registeredDevices + audit logs", f"No device is currently linked to the decoy user. Poll {attempt} of {max_attempts}; retrying in {poll_seconds} seconds."
    if scenario_id == "APP-DV-003":
        return "MDCA Alerts API", f"Polling MDCA Alerts API. Attempt {attempt} of {max_attempts}."
    return "tenant evidence", f"Waiting for tenant evidence. Attempt {attempt} of {max_attempts}."


def _max_attempts(wait_minutes: int, poll_seconds: int) -> int:
    if wait_minutes <= 0:
        return 1
    return max(1, int(math.ceil((wait_minutes * 60) / max(1, poll_seconds))))


def _write_run_report(
    project_root: Path,
    scenario_id: str,
    run_id: str,
    report: dict[str, Any],
    stdout: str = "",
) -> tuple[Path | None, Path | None]:
    meta = SCENARIOS[scenario_id]
    dynamic_report_path = project_root / meta["report"]
    dynamic_html_path = project_root / meta["html"]
    active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
    active_dir.mkdir(parents=True, exist_ok=True)
    active_report_path = active_dir / f"{run_id}-result.json"
    active_html_path = active_dir / f"{run_id}-result.html"

    dynamic_report_path.parent.mkdir(parents=True, exist_ok=True)
    dynamic_report_path.write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
    write_standard_html_report(report, dynamic_html_path, stdout=stdout)
    shutil.copy2(dynamic_report_path, active_report_path)
    shutil.copy2(dynamic_html_path, active_html_path)
    return active_report_path, active_html_path


def _terminal_report(
    project_root: Path,
    scenario_id: str,
    run_id: str,
    status: str,
    verdict: str,
    risk: str,
    message: str,
    error: str | None = None,
) -> dict[str, Any]:
    meta = SCENARIOS[scenario_id]
    scenario_state = _read_json(project_root / meta["state"])
    decoy_user = _decoy_user_from_state(scenario_state)
    target = _target_from_state(scenario_state, {})
    validation_start = _validation_start_from_state(scenario_state)
    now = utc_now()
    return {
        "scenario_id": scenario_id,
        "display_id": scenario_id,
        "scenario_name": meta["name"],
        "pillar": "Devices" if scenario_id.startswith("DEV-") else "Identity" if scenario_id.startswith("ID-") else "Applications",
        "scope": "Cloud",
        "run_id": run_id,
        "status": status,
        "verdict": verdict,
        "risk": risk,
        "started_utc": validation_start,
        "validation_start_utc": validation_start,
        "completed_utc": now,
        "generated_at": now,
        "tenant_id": scenario_state.get("tenant_id"),
        "decoy_user": {
            "user_principal_name": decoy_user,
            "password_stored_in_report": False,
            "created_by_ztvp": True,
        },
        "target": scenario_state.get("target") or {"name": target},
        "target_app": ((scenario_state.get("target") or {}).get("name") if isinstance(scenario_state.get("target"), dict) else target),
        "executive_summary": message,
        "final_claim": message,
        "evidence_quality": "Run ended before a final tenant evidence decision.",
        "sign_in_log_evidence": {
            "validation_window_start_utc": validation_start,
            "decoy_user": decoy_user,
            "target_app": target,
            "sign_in_found": False,
            "meaningful_sign_in_count": 0,
        },
        "metrics": {
            "sign_in_log_found": False,
            "poll_attempts": 0,
            "max_poll_attempts": 0,
        },
        "cleanup": {
            "decoy_user_cleanup_required": bool(decoy_user),
            "cleanup_completed": False,
            "status": "Pending" if decoy_user else "Not required",
        },
        "recommendations": [
            "Restart the validation if tenant evidence is still needed.",
            "Confirm the decoy user and validation window before rerunning.",
        ],
        "error": error,
    }


def _idc005_report(
    project_root: Path,
    run_id: str,
    status: str,
    verdict: str,
    risk: str,
    message: str,
    graph_status: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    state = _read_json(project_root / SCENARIOS["ID-DV-005"]["state"])
    invitation = state.get("invitation") or {}
    guest = state.get("guest_user") or {}
    external = state.get("external_identity") or {}
    category = classify_graph_error(error or message) if error or verdict == "ERROR" else None
    now = utc_now()
    invite_succeeded = bool(invitation.get("invite_redeem_url") or guest.get("id"))
    tenant_blocked = False
    if category in {"GRAPH_SESSION_EXPIRED", "GRAPH_MISSING_SCOPES", "GRAPH_INSUFFICIENT_PRIVILEGES"}:
        invite_attempted = True
    else:
        invite_attempted = bool(invitation or external)
        tenant_blocked = bool(not invite_succeeded and error)
    return {
        "scenario_id": "ID-DV-005",
        "display_id": "ID-DV-005",
        "scenario_name": SCENARIOS["ID-DV-005"]["name"],
        "pillar": "Identity",
        "scope": "Cloud",
        "run_id": run_id,
        "status": status,
        "verdict": verdict,
        "risk": risk,
        "started_utc": state.get("prepared_at") or now,
        "completed_utc": now,
        "generated_at": now,
        "tenant_id": state.get("tenant_id") or (graph_status or {}).get("tenant_id"),
        "tenant_display_name": state.get("tenant_display_name") or (graph_status or {}).get("tenant_display_name"),
        "operator": (graph_status or {}).get("account"),
        "external_test_email": external.get("external_email"),
        "guest_user": {key: value for key, value in guest.items() if "redeem" not in key.lower()},
        "graph_connection_status": (graph_status or {}).get("status"),
        "error_category": category,
        "guest_invitation_attempted": invite_attempted,
        "guest_invitation_succeeded": invite_succeeded,
        "tenant_blocked_invite": tenant_blocked,
        "cleanup": state.get("cleanup") or {"status": "Pending", "cleanup_completed": False},
        "executive_summary": message,
        "final_claim": message,
        "evidence_quality": "Technical execution evidence" if verdict == "ERROR" else "Guest invitation evidence was collected.",
        "recommendations": [
            "Go to Home, click Connect Microsoft Graph, then rerun if this was an authentication/session error.",
            "Review external collaboration settings if guest invitations succeeded unexpectedly.",
            "Delete or disable any controlled guest object after saving evidence.",
        ],
        "metrics": {
            "guest_invitation_attempted": invite_attempted,
            "guest_invitation_succeeded": invite_succeeded,
            "tenant_blocked_invite": tenant_blocked,
        },
        "error": error,
    }


def _update_graph_error_run(project_root: Path, scenario_id: str, run_id: str, graph_status: dict[str, Any]) -> None:
    message = clean_graph_message(graph_status)
    report = (
        _idc005_report(project_root, run_id, "ERROR_GRAPH_SESSION_EXPIRED" if graph_status.get("error_category") == "GRAPH_SESSION_EXPIRED" else "ERROR", "ERROR", "UNKNOWN", message, graph_status, graph_status.get("error"))
        if scenario_id == "ID-DV-005"
        else _terminal_report(project_root, scenario_id, run_id, "ERROR", "ERROR", "UNKNOWN", message, error=graph_status.get("error"))
    )
    report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report)
    update_run(
        project_root,
        run_id,
        status="error",
        verdict="ERROR",
        risk="UNKNOWN",
        phase="Graph preflight",
        progress_percent=100,
        current_message=message,
        graph_connection_status=graph_status.get("status"),
        error_category=graph_status.get("error_category"),
        error=graph_status.get("error"),
        report_path=str(report_json) if report_json else None,
        report_json_path=str(report_json) if report_json else None,
        html_report_path=str(report_html) if report_html else None,
        report_html_path=str(report_html) if report_html else None,
        completed_utc=utc_now(),
        final_summary=message,
    )


def is_live(run_id: str) -> bool:
    with _REGISTRY_LOCK:
        proc = _REGISTRY.get(run_id)
    return proc is not None and proc.poll() is None


def get_active_run(project_root: Path | str, scenario_id: str, run_id: str | None = None) -> dict[str, Any] | None:
    if run_id:
        run = load_run(project_root, str(run_id))
        if run and str(run.get("scenario_id") or "").upper() != str(scenario_id or "").upper():
            run = None
    else:
        run = latest_run_for_scenario(project_root, scenario_id)
    if run and str(run.get("status") or "").lower() in ACTIVE_STATUSES and not is_stale(run):
        return run
    return None


def start_scenario_job(
    project_root: Path | str,
    scenario_id: str,
    wait_minutes: int,
    poll_seconds: int,
    run_id: str | None = None,
    resume: bool = False,
    extra_args: list[str] | None = None,
    target: str | None = None,
    tenant: str | None = None,
) -> dict[str, Any]:
    project_root = Path(project_root)
    scenario_id = scenario_id.upper()
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Background jobs are not wired for {scenario_id}.")

    existing = get_active_run(project_root, scenario_id)
    if existing and not resume:
        return existing

    scenario_state = _read_json(project_root / SCENARIOS[scenario_id]["state"])
    state_run_id = str(scenario_state.get("run_id") or "").strip()
    always_new = {"APP-DV-003", "APP-DV-008", "CLD-DV-001", "ID-DV-005"}
    run_id = run_id or (str(existing.get("run_id")) if resume and existing else state_run_id if scenario_id not in always_new else "" or new_run_id(scenario_id))
    if is_live(run_id):
        return load_run(project_root, run_id)

    meta = SCENARIOS[scenario_id]
    local_evidence = _read_json(project_root / meta["local_evidence"])
    max_attempts = _max_attempts(wait_minutes, poll_seconds)
    now = utc_now()
    state = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario_name": meta["name"],
        "pillar": _pillar_for_scenario(scenario_id),
        "scope": "Cloud",
        "status": "running" if scenario_id in CLD_SHAREPOINT_IDS else "polling",
        "phase": _phase_for_scenario(scenario_id),
        "verdict": None,
        "risk": None,
        "started_utc": now if not resume else load_run(project_root, run_id).get("started_utc", now),
        "last_updated_utc": now,
        "wait_minutes": int(wait_minutes),
        "poll_seconds": int(poll_seconds),
        "poll_attempts": 0,
        "max_poll_attempts": max_attempts,
        "progress_percent": 0,
        "target": target or _target_from_state(scenario_state, local_evidence),
        "tenant": tenant or _tenant_from_state(scenario_state),
        "test_user": scenario_state.get("test_user") or _decoy_user_from_state(scenario_state),
        "decoy_user": _decoy_user_from_state(scenario_state),
        "target_app": scenario_state.get("target_app") or ((scenario_state.get("target") or {}).get("name") if isinstance(scenario_state.get("target"), dict) else None),
        "validation_start_utc": _validation_start_from_state(scenario_state),
        "local_evidence_status": _local_status(local_evidence, scenario_id),
        "tenant_evidence_status": "Waiting",
        "monitoring_window_minutes": int(wait_minutes),
        "retry_interval_seconds": int(poll_seconds),
        "elapsed_seconds": 0,
        "remaining_seconds": int(wait_minutes) * 60,
        "current_evidence_source": "registeredDevices + audit logs" if scenario_id == "DEV-DV-004" else "Entra sign-in logs" if scenario_id in {"APP-DV-004", "DEV-DV-001"} else "tenant evidence",
        "final_device_state": None,
        "registered_devices_linked_count": None,
        "audit_events_found": None,
        "current_message": _initial_message(scenario_id, max_attempts),
        "report_path": None,
        "report_json_path": None,
        "html_report_path": None,
        "report_html_path": None,
        "error": None,
        "cancel_requested": False,
        "final_summary": _initial_message(scenario_id, max_attempts),
        "resume_count": int(load_run(project_root, run_id).get("resume_count") or 0) + (1 if resume else 0),
    }
    if scenario_id == "ID-DV-001":
        target_upn = _idc001_target_upn(project_root, extra_args)
        state.update(
            {
                "phase": _phase_for_scenario(scenario_id),
                "current_message": _initial_message(scenario_id, max_attempts),
                "current_evidence_source": "Entra sign-in logs + MFA evidence",
                "test_user": target_upn,
                "decoy_user": target_upn,
                "target_app": target or "Azure Portal / Microsoft 365 admin resources",
                "validation_start_utc": now,
                "tenant_evidence_status": "Waiting",
            }
        )
    state.update(_local_proof(local_evidence, scenario_id))
    if scenario_id == "APP-DV-003":
        state.update(
            {
                "local_evidence_status": "Not applicable",
                "current_evidence_source": "MDCA Alerts API",
                "dummy_file_created": "Starting",
                "public_link_created": "Starting",
                "cleanup_status": "Not completed yet",
            }
        )
    if scenario_id in CLD_SHAREPOINT_IDS:
        state.update(
            {
                "phase": _phase_for_scenario(scenario_id),
                "current_message": _initial_message(scenario_id, max_attempts),
                "current_evidence_source": "Microsoft Graph createLink",
                "target_site": target or "Root site",
                "dummy_file": "Pending",
                "anonymous_link_attempt_status": "Starting",
                "cleanup_status": "Not completed yet",
                "tenant_evidence_status": "Waiting",
                "progress_percent": 5,
            }
        )
    if scenario_id == "ID-DV-005":
        arg_map = dict(zip((extra_args or [])[0::2], (extra_args or [])[1::2]))
        state.update(
            {
                "status": "running",
                "phase": "Preparing guest invitation",
                "current_message": "Starting ID-DV-005 guest invitation in the background.",
                "current_evidence_source": "Microsoft Graph invitations",
                "local_evidence_status": "Not applicable",
                "tenant_evidence_status": "Waiting",
                "external_test_email": arg_map.get("-ExternalEmail"),
                "guest_display_name_prefix": arg_map.get("-GuestDisplayNamePrefix"),
                "redirect_url": arg_map.get("-InviteRedirectUrl"),
                "guest_invitation_attempted": False,
                "guest_invitation_succeeded": False,
                "tenant_blocked_invite": False,
                "operator": None,
                "tenant_id": None,
                "progress_percent": 5,
            }
        )
    redacted_extra_args = _redact_powershell_args(extra_args)

    state["powershell_command"] = " ".join(
        [
            _powershell_exe(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC005.ps1") if scenario_id == "ID-DV-005" else str(project_root / meta["script"]),
            *(
                [
                    "-LookbackHours",
                    str(int(scenario_state.get("lookback_hours") or max(1, int(math.ceil(wait_minutes / 60))))),
                    "-PollSeconds",
                    str(int(poll_seconds)),
                    "-WaitMinutes",
                    str(int(wait_minutes)),
                    "-WindowStartUtc",
                    _validation_start_from_state(scenario_state),
                    "-RunId",
                    run_id,
                ]
                if scenario_id == "DEV-DV-001"
                else redacted_extra_args
                if scenario_id in {"APP-DV-003", "APP-DV-008", "CLD-DV-001", "ID-DV-005"} and redacted_extra_args
                else [
                    *(
                        ["-RunId", run_id]
                        if scenario_id == "DEV-DV-004"
                        else []
                    ),
                    "-WaitMinutes",
                    str(int(wait_minutes)),
                    "-PollSeconds",
                    str(int(poll_seconds)),
                ]
            ),
        ]
    )
    if extra_args:
        with _REGISTRY_LOCK:
            _RUN_ARGS[run_id] = list(extra_args)
    save_run(project_root, state)

    thread = threading.Thread(
        target=_run_job,
        args=(project_root, scenario_id, run_id, int(wait_minutes), int(poll_seconds)),
        daemon=True,
        name=f"ztvp-{scenario_id}-{run_id}",
    )
    with _REGISTRY_LOCK:
        _REGISTRY[run_id] = None
    thread.start()
    return state


def _run_iddv001_polling_job(project_root: Path, run_id: str, wait_minutes: int, poll_seconds: int) -> None:
    scenario_id = "ID-DV-001"
    meta = SCENARIOS[scenario_id]
    script_path = project_root / meta["script"]
    report_path = project_root / meta["report"]
    html_path = project_root / meta["html"]
    max_attempts = _max_attempts(wait_minutes, poll_seconds)
    started = datetime.now(timezone.utc)
    stdout_all: list[str] = []
    stderr_all: list[str] = []

    with _REGISTRY_LOCK:
        extra_args = list(_RUN_ARGS.get(run_id) or [])

    target_upn = _idc001_target_upn(project_root, extra_args)
    lookback = _idc001_lookback(extra_args, wait_minutes)
    ps_args = [
        _powershell_exe(),
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-DecoyUserPrincipalName",
        target_upn,
        "-LookbackMinutes",
        str(lookback),
    ]

    try:
        for attempt in range(1, max_attempts + 1):
            current = load_run(project_root, run_id)
            if current.get("cancel_requested"):
                report = _terminal_report(project_root, scenario_id, run_id, "CANCELLED", "CANCELLED", "UNKNOWN", "Run cancelled by user.")
                report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
                update_run(
                    project_root,
                    run_id,
                    status="cancelled",
                    verdict="CANCELLED",
                    phase="Cancelled",
                    current_message="Run cancelled by user.",
                    completed_utc=utc_now(),
                    report_path=str(report_json) if report_json else None,
                    report_json_path=str(report_json) if report_json else None,
                    html_report_path=str(report_html) if report_html else None,
                    report_html_path=str(report_html) if report_html else None,
                    final_summary="Run cancelled by user.",
                )
                return

            elapsed = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
            remaining = max(0, int((wait_minutes * 60) - elapsed))
            source, message = _poll_message(scenario_id, attempt, max_attempts, poll_seconds)
            update_run(
                project_root,
                run_id,
                status="polling",
                phase=_phase_for_scenario(scenario_id),
                current_message=message,
                current_evidence_source=source,
                progress_percent=min(95, int((attempt / max_attempts) * 100)),
                poll_attempts=attempt,
                max_poll_attempts=max_attempts,
                monitoring_window_minutes=int(wait_minutes),
                retry_interval_seconds=int(poll_seconds),
                elapsed_seconds=elapsed,
                remaining_seconds=remaining,
                tenant_evidence_status="Waiting",
                test_user=target_upn,
                target_app="Azure Portal / Microsoft 365 admin resources",
            )

            completed = subprocess.run(
                ps_args,
                cwd=str(project_root),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(180, min(900, poll_seconds + 240)),
                env=_powershell_env(),
            )
            stdout_all.append(completed.stdout or "")
            stderr_all.append(completed.stderr or "")

            if completed.returncode != 0:
                error_text = (completed.stderr or completed.stdout or f"PowerShell exited with {completed.returncode}")[-6000:]
                report = _terminal_report(project_root, scenario_id, run_id, "ERROR", "ERROR", "UNKNOWN", "Run stopped because an error occurred.", error=error_text)
                report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
                update_run(
                    project_root,
                    run_id,
                    status="error",
                    verdict="ERROR",
                    phase="Error",
                    current_message="Run stopped because an error occurred.",
                    error=error_text,
                    completed_utc=utc_now(),
                    report_path=str(report_json) if report_json else None,
                    report_json_path=str(report_json) if report_json else None,
                    html_report_path=str(report_html) if report_html else None,
                    report_html_path=str(report_html) if report_html else None,
                    final_summary="Run stopped because an error occurred.",
                )
                return

            report = _read_json(report_path)
            if report:
                managed = _idc001_managed_decoy(project_root)
                if managed:
                    report["managed_decoy"] = managed
                report["scenario_id"] = "ID-DV-001"
                report["display_id"] = "ID-DV-001"
                report["run_id"] = run_id
                report["polling"] = {
                    "poll_attempts": attempt,
                    "max_poll_attempts": max_attempts,
                    "monitoring_window_minutes": int(wait_minutes),
                    "retry_interval_seconds": int(poll_seconds),
                    "elapsed_seconds": elapsed,
                    "remaining_seconds": remaining,
                }
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
                mfa = summarize_mfa_report(report)
                tenant_status = "Found" if mfa.get("sign_in_result") != "Unknown" else "Not found"
                update_run(
                    project_root,
                    run_id,
                    tenant_evidence_status=tenant_status,
                    mfa_required=mfa.get("mfa_required"),
                    mfa_completed=mfa.get("mfa_completed"),
                    sign_in_result=mfa.get("sign_in_result"),
                    access_without_mfa=mfa.get("access_without_mfa"),
                    effective_policy=mfa.get("effective_policy"),
                    conditional_access_status=mfa.get("conditional_access_result"),
                    risk=str(mfa.get("risk") or report.get("risk") or "").upper() or None,
                    current_message=mfa.get("conclusion") if tenant_status == "Found" else message,
                )
                if tenant_status == "Found" or attempt >= max_attempts:
                    verdict = str(mfa.get("verdict") or _verdict_from_status(report.get("status")) or "PARTIAL").upper()
                    final_message = str(mfa.get("conclusion") or report.get("final_claim") or "ID-DV-001 completed.")
                    write_standard_html_report(report, html_path, stdout="\n".join(stdout_all))
                    active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
                    active_dir.mkdir(parents=True, exist_ok=True)
                    archived_report_path = active_dir / f"{run_id}-result.json"
                    archived_html_path = active_dir / f"{run_id}-result.html"
                    shutil.copy2(report_path, archived_report_path)
                    if html_path.exists():
                        shutil.copy2(html_path, archived_html_path)
                    update_run(
                        project_root,
                        run_id,
                        status="completed",
                        phase="Completed",
                        verdict=verdict,
                        result_code=report.get("status"),
                        progress_percent=100,
                        poll_attempts=attempt,
                        max_poll_attempts=max_attempts,
                        elapsed_seconds=elapsed,
                        remaining_seconds=0,
                        tenant_evidence_status=tenant_status,
                        current_message=final_message,
                        report_path=str(archived_report_path),
                        report_json_path=str(archived_report_path),
                        html_report_path=str(archived_html_path) if archived_html_path.exists() else None,
                        report_html_path=str(archived_html_path) if archived_html_path.exists() else None,
                        completed_utc=utc_now(),
                        risk=str(mfa.get("risk") or report.get("risk") or "").upper() or None,
                        final_summary=final_message,
                        error=None,
                    )
                    return

            if attempt < max_attempts:
                time.sleep(max(1, int(poll_seconds)))

        report = _terminal_report(
            project_root,
            scenario_id,
            run_id,
            "PARTIAL_NO_SIGNIN_LOG_FOUND",
            "PARTIAL",
            "MEDIUM",
            "No matching MFA sign-in evidence was found before timeout.",
        )
        report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
        update_run(
            project_root,
            run_id,
            status="completed",
            verdict="PARTIAL",
            risk="MEDIUM",
            phase="Completed",
            current_message="No matching MFA sign-in evidence was found before timeout.",
            progress_percent=100,
            poll_attempts=max_attempts,
            max_poll_attempts=max_attempts,
            remaining_seconds=0,
            tenant_evidence_status="Not found",
            report_path=str(report_json) if report_json else None,
            report_json_path=str(report_json) if report_json else None,
            html_report_path=str(report_html) if report_html else None,
            report_html_path=str(report_html) if report_html else None,
            completed_utc=utc_now(),
            final_summary="No matching MFA sign-in evidence was found before timeout.",
        )

    except Exception as exc:
        report = _terminal_report(project_root, scenario_id, run_id, "ERROR", "ERROR", "UNKNOWN", "Run stopped because an error occurred.", error=str(exc))
        try:
            report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
        except Exception:
            report_json = None
            report_html = None
        update_run(
            project_root,
            run_id,
            status="error",
            verdict="ERROR",
            phase="Error",
            current_message="Run stopped because an error occurred.",
            error=str(exc),
            completed_utc=utc_now(),
            report_path=str(report_json) if report_json else None,
            report_json_path=str(report_json) if report_json else None,
            html_report_path=str(report_html) if report_html else None,
            report_html_path=str(report_html) if report_html else None,
            final_summary="Run stopped because an error occurred.",
        )
    finally:
        with _REGISTRY_LOCK:
            _REGISTRY.pop(run_id, None)
            _RUN_ARGS.pop(run_id, None)


def _run_iddv005_job(project_root: Path, run_id: str, wait_minutes: int, poll_seconds: int) -> None:
    scenario_id = "ID-DV-005"
    meta = SCENARIOS[scenario_id]
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC005.ps1"
    report_path = project_root / meta["report"]
    html_path = project_root / meta["html"]
    with _REGISTRY_LOCK:
        stored_args = list(_RUN_ARGS.get(run_id) or [])
    proc: subprocess.Popen[str] | None = None
    stdout_all: list[str] = []
    graph_status = get_graph_context()

    try:
        scenario_state = _read_json(project_root / meta["state"])
        external = scenario_state.get("external_identity") or {}
        guest = scenario_state.get("guest_user") or {}
        update_run(
            project_root,
            run_id,
            status="running",
            phase="Collecting guest sign-in evidence",
            current_message="Polling Entra guest sign-in evidence for ID-DV-005.",
            graph_connection_status=graph_status.get("status"),
            tenant_id=graph_status.get("tenant_id"),
            operator=graph_status.get("account"),
            progress_percent=10,
            guest_invitation_attempted=True,
            guest_invitation_succeeded=True,
            external_test_email=external.get("external_email"),
            target=external.get("external_email") or guest.get("user_principal_name"),
        )
        invoke_args = [
            _powershell_exe(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(invoke_script),
            *(
                stored_args
                if stored_args
                else [
                    "-ObservedOutcome",
                    "AUTO_DETECT",
                    "-LookbackMinutes",
                    str(max(15, int(wait_minutes))),
                    "-EvidenceWaitSeconds",
                    str(max(0, int(poll_seconds))),
                ]
            ),
        ]
        proc = subprocess.Popen(invoke_args, cwd=str(project_root), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_powershell_env())
        with _REGISTRY_LOCK:
            _REGISTRY[run_id] = proc
        while proc.poll() is None:
            current = load_run(project_root, run_id)
            if current.get("cancel_requested"):
                proc.terminate()
                stdout, stderr = proc.communicate(timeout=10)
                stdout_all.append(stdout or "")
                report = _idc005_report(project_root, run_id, "CANCELLED", "CANCELLED", "UNKNOWN", "Run cancelled by user.", graph_status, stderr or None)
                report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
                update_run(project_root, run_id, status="cancelled", verdict="CANCELLED", phase="Cancelled", current_message="Run cancelled by user.", completed_utc=utc_now(), report_path=str(report_json), report_json_path=str(report_json), html_report_path=str(report_html), report_html_path=str(report_html))
                return
            update_run(project_root, run_id, phase="Collecting guest sign-in evidence", current_message="Polling Entra guest sign-in evidence for ID-DV-005.", progress_percent=80)
            time.sleep(2)
        stdout, stderr = proc.communicate(timeout=10)
        stdout_all.append(stdout or "")
        if proc.returncode != 0:
            error_text = (stderr or stdout or f"PowerShell exited with {proc.returncode}")[-6000:]
            category = classify_graph_error(error_text)
            message = "Microsoft Graph session expired. Go to Home and click Connect Microsoft Graph, then rerun." if category == "GRAPH_SESSION_EXPIRED" else "ID-DV-005 evidence collection did not complete."
            report = _idc005_report(project_root, run_id, "ERROR_GRAPH_SESSION_EXPIRED" if category == "GRAPH_SESSION_EXPIRED" else "ERROR", "ERROR", "UNKNOWN", message, graph_status, error_text)
            report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
            update_run(project_root, run_id, status="error", verdict="ERROR", phase="Evidence collection error", current_message=message, progress_percent=100, graph_connection_status=graph_status.get("status"), error_category=category, error=error_text, report_path=str(report_json), report_json_path=str(report_json), html_report_path=str(report_html), report_html_path=str(report_html), completed_utc=utc_now(), final_summary=message)
            return

        report = _read_json(report_path)
        if not report:
            report = _idc005_report(project_root, run_id, "PARTIAL_EVIDENCE_INCOMPLETE", "PARTIAL", "MEDIUM", "ID-DV-005 completed, but the scenario report was not found.", graph_status)
        report["run_id"] = run_id
        report.setdefault("display_id", "ID-DV-005")
        report.setdefault("scenario_id", "ID-DV-005")
        report.setdefault("scenario_name", meta["name"])
        report.setdefault("graph_connection_status", graph_status.get("status"))
        write_standard_html_report(report, html_path, stdout="\n".join(stdout_all))
        active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
        active_dir.mkdir(parents=True, exist_ok=True)
        archived_report_path = active_dir / f"{run_id}-result.json"
        archived_html_path = active_dir / f"{run_id}-result.html"
        report_path.write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
        shutil.copy2(report_path, archived_report_path)
        shutil.copy2(html_path, archived_html_path)
        verdict = _verdict_from_status(report.get("status")) or str(report.get("verdict") or "PARTIAL").upper()
        metrics = report.get("metrics") or {}
        message = str(report.get("final_claim") or report.get("executive_summary") or f"ID-DV-005 completed. Verdict: {verdict}.")
        update_run(
            project_root,
            run_id,
            status="completed",
            verdict=verdict,
            risk=str(report.get("risk") or "MEDIUM").upper(),
            phase="Completed",
            current_message=message,
            progress_percent=100,
            guest_invitation_attempted=True,
            guest_invitation_succeeded=bool(metrics.get("guest_invitation_succeeded", True)),
            tenant_blocked_invite=bool(metrics.get("tenant_blocked_invite", False)),
            graph_connection_status=graph_status.get("status"),
            report_path=str(archived_report_path),
            report_json_path=str(archived_report_path),
            html_report_path=str(archived_html_path),
            report_html_path=str(archived_html_path),
            completed_utc=utc_now(),
            final_summary=message,
        )
    except Exception as exc:
        error_text = str(exc)
        category = classify_graph_error(error_text)
        message = "Microsoft Graph session expired. Go to Home and click Connect Microsoft Graph, then rerun." if category == "GRAPH_SESSION_EXPIRED" else "ID-DV-005 stopped because an error occurred."
        try:
            report = _idc005_report(project_root, run_id, "ERROR", "ERROR", "UNKNOWN", message, graph_status, error_text)
            report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout="\n".join(stdout_all))
        except Exception:
            report_json = None
            report_html = None
        update_run(project_root, run_id, status="error", verdict="ERROR", phase="Error", current_message=message, error_category=category, error=error_text, report_path=str(report_json) if report_json else None, report_json_path=str(report_json) if report_json else None, html_report_path=str(report_html) if report_html else None, report_html_path=str(report_html) if report_html else None, completed_utc=utc_now(), final_summary=message)
    finally:
        with _REGISTRY_LOCK:
            _REGISTRY.pop(run_id, None)
            _RUN_ARGS.pop(run_id, None)


def _run_job(project_root: Path, scenario_id: str, run_id: str, wait_minutes: int, poll_seconds: int) -> None:
    meta = SCENARIOS[scenario_id]
    script_path = project_root / meta["script"]
    report_path = project_root / meta["report"]
    html_path = project_root / meta["html"]
    max_attempts = _max_attempts(wait_minutes, poll_seconds)
    started = datetime.now(timezone.utc)
    proc: subprocess.Popen[str] | None = None
    stdout = ""
    stderr = ""

    try:
        if scenario_id == "ID-DV-001":
            _run_iddv001_polling_job(project_root, run_id, wait_minutes, poll_seconds)
            return
        if scenario_id == "ID-DV-005":
            _run_iddv005_job(project_root, run_id, wait_minutes, poll_seconds)
            return
        update_run(
            project_root,
            run_id,
            status="polling",
            poll_attempts=1,
            progress_percent=1,
            phase=_phase_for_scenario(scenario_id),
            current_message=_initial_message(scenario_id, max_attempts),
            current_evidence_source="registeredDevices" if scenario_id == "DEV-DV-004" else None,
            tenant_evidence_status="Waiting",
        )
        scenario_state = _read_json(project_root / meta["state"])
        if scenario_id == "DEV-DV-001":
            ps_args = [
                _powershell_exe(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-LookbackHours",
                str(int(scenario_state.get("lookback_hours") or max(1, int(math.ceil(wait_minutes / 60))))),
                "-PollSeconds",
                str(poll_seconds),
                "-WaitMinutes",
                str(wait_minutes),
                "-WindowStartUtc",
                _validation_start_from_state(scenario_state),
                "-RunId",
                run_id,
            ]
        elif scenario_id == "DEV-DV-004":
            ps_args = [
                _powershell_exe(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-WaitMinutes",
                str(wait_minutes),
                "-PollSeconds",
                str(poll_seconds),
                "-RunId",
                run_id,
            ]
        elif scenario_id in {"APP-DV-003", "APP-DV-008", "CLD-DV-001"}:
            with _REGISTRY_LOCK:
                stored_args = list(_RUN_ARGS.get(run_id) or [])
            ps_args = [
                _powershell_exe(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                *stored_args,
            ]
        else:
            ps_args = [
                _powershell_exe(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-WaitMinutes",
                str(wait_minutes),
                "-PollSeconds",
                str(poll_seconds),
            ]
        proc = subprocess.Popen(
            ps_args,
            cwd=str(project_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_powershell_env(),
        )
        with _REGISTRY_LOCK:
            _REGISTRY[run_id] = proc

        while proc.poll() is None:
            current = load_run(project_root, run_id)
            if current.get("cancel_requested"):
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate(timeout=10)
                update_run(
                    project_root,
                    run_id,
                    status="cancelled",
                    verdict="CANCELLED",
                    progress_percent=int(current.get("progress_percent") or 0),
                    current_message="Run cancelled by user.",
                    completed_utc=utc_now(),
                    error=None,
                )
                report = _terminal_report(
                    project_root,
                    scenario_id,
                    run_id,
                    "CANCELLED",
                    "CANCELLED",
                    "UNKNOWN",
                    "Run cancelled by user.",
                )
                report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout=stdout)
                update_run(
                    project_root,
                    run_id,
                    report_path=str(report_json) if report_json else None,
                    report_json_path=str(report_json) if report_json else None,
                    html_report_path=str(report_html) if report_html else None,
                    report_html_path=str(report_html) if report_html else None,
                    tenant_evidence_status="Not found",
                    final_summary="Run cancelled by user.",
                )
                return

            elapsed = max(0, (datetime.now(timezone.utc) - started).total_seconds())
            attempt = min(max_attempts, max(1, int(elapsed // max(1, poll_seconds)) + 1))
            progress = min(95, int((attempt / max_attempts) * 100))
            evidence_source, poll_message = _poll_message(scenario_id, attempt, max_attempts, poll_seconds)
            remaining = max(0, int((wait_minutes * 60) - elapsed))
            loop_updates = {
                "status": "running" if scenario_id in CLD_SHAREPOINT_IDS else "polling",
                "poll_attempts": attempt,
                "progress_percent": progress,
                "elapsed_seconds": int(elapsed),
                "remaining_seconds": remaining,
                "monitoring_window_minutes": int(wait_minutes),
                "retry_interval_seconds": int(poll_seconds),
                "phase": _phase_for_scenario(scenario_id),
                "tenant_evidence_status": "Waiting",
                "current_evidence_source": evidence_source,
                "current_message": poll_message,
            }
            if scenario_id == "APP-DV-003":
                loop_updates.update(_appdv003_live_fields(project_root, meta))
            if scenario_id in CLD_SHAREPOINT_IDS:
                loop_updates.update(_cld001_live_fields(project_root, meta))
            update_run(project_root, run_id, **loop_updates)
            time.sleep(2)

        stdout, stderr = proc.communicate(timeout=10)
        if proc.returncode != 0:
            error_text = (stderr or stdout or f"PowerShell exited with {proc.returncode}")[-6000:]
            report = _terminal_report(
                project_root,
                scenario_id,
                run_id,
                "ERROR",
                "ERROR",
                "UNKNOWN",
                "Run stopped because an error occurred.",
                error=error_text,
            )
            report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report, stdout=stdout)
            update_run(
                project_root,
                run_id,
                status="error",
                phase="Error",
                verdict="ERROR",
                error=error_text,
                current_message="Run stopped because an error occurred.",
                report_path=str(report_json) if report_json else None,
                report_json_path=str(report_json) if report_json else None,
                html_report_path=str(report_html) if report_html else None,
                report_html_path=str(report_html) if report_html else None,
                completed_utc=utc_now(),
                final_summary="Run stopped because an error occurred.",
            )
            return

        report = _read_json(report_path)
        verdict = _verdict_from_status(report.get("status"))
        tenant_status = _tenant_status(report)
        if tenant_status == "Found":
            final_message = "Entra sign-in / Conditional Access evidence found. Run completed." if scenario_id == "APP-DV-004" else "Tenant evidence found. Run completed."
            if scenario_id == "DEV-DV-001":
                final_message = str(report.get("final_claim") or "Matching unmanaged-device sign-in evidence found. Run completed.")
        elif verdict == "PARTIAL":
            final_message = "Wait window expired. Tenant evidence not found."
            if scenario_id == "DEV-DV-001":
                final_message = str(report.get("final_claim") or "Monitoring window ended. ZTVP did not find a matching unmanaged-device sign-in after the validation start time.")
        else:
            final_message = f"Run completed. Verdict: {verdict or 'Unknown'}."
        if scenario_id == "APP-DV-004":
            final_message = str(report.get("final_claim") or final_message)
        if scenario_id == "APP-DV-003":
            final_message = str(report.get("final_claim") or report.get("executive_summary") or final_message)
        if scenario_id in CLD_SHAREPOINT_IDS:
            final_message = str(report.get("final_claim") or report.get("executive_summary") or final_message)
        if scenario_id == "DEV-DV-004":
            timer = report.get("timer") or {}
            final_state = ((report.get("final_device_state") or {}).get("state") or (report.get("metrics") or {}).get("final_device_state") or "Unknown")
            if timer.get("stopped_early"):
                final_message = f"Evidence is sufficient. Stopping early and generating report. Final device state: {final_state}."
            else:
                final_message = str(report.get("final_claim") or final_message)
        ca_summary = summarize_ca_access_report(report, "device") if scenario_id in {"DEV-DV-001", "APP-DV-004"} else {}
        cld_metrics = report.get("metrics") or {}
        cld_attempt = report.get("anonymous_link_attempt") or {}
        cld_cleanup = report.get("cleanup") or {}
        cld_site = report.get("site") or {}
        cld_test_object = report.get("test_object") or {}
        if report:
            write_standard_html_report(report, html_path, stdout=stdout)
        archived_report_path = report_path
        archived_html_path = html_path
        active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
        active_dir.mkdir(parents=True, exist_ok=True)
        if report_path.exists():
            archived_report_path = active_dir / f"{run_id}-result.json"
            shutil.copy2(report_path, archived_report_path)
        if html_path.exists():
            archived_html_path = active_dir / f"{run_id}-result.html"
            shutil.copy2(html_path, archived_html_path)
        update_run(
            project_root,
            run_id,
            status="completed",
            phase="Completed",
            verdict=verdict,
            result_code=_result_code_from_report(report),
            poll_attempts=int((report.get("metrics") or {}).get("poll_attempts") or ((((report.get("evidence") or {}).get("tenant") or {}).get("api") or {}).get("mde_cloud_poll_attempts")) or max_attempts),
            max_poll_attempts=int((report.get("metrics") or {}).get("max_poll_attempts") or max_attempts),
            elapsed_seconds=int((report.get("metrics") or {}).get("elapsed_seconds") or 0),
            remaining_seconds=0,
            monitoring_window_minutes=int(wait_minutes),
            retry_interval_seconds=int(poll_seconds),
            current_evidence_source="completed",
            final_device_state=(report.get("metrics") or {}).get("final_device_state"),
            registered_devices_linked_count=(report.get("metrics") or {}).get("registered_devices_linked_count"),
            temporary_device_observed=(report.get("metrics") or {}).get("temporary_device_observed"),
            final_graph_registered_devices_count=(report.get("metrics") or {}).get("final_graph_registered_devices_count"),
            device_still_exists_in_devices=(report.get("metrics") or {}).get("device_still_exists_in_devices"),
            audit_events_found=(report.get("metrics") or {}).get("audit_events_found"),
            effective_policy=ca_summary.get("effective_policy"),
            conditional_access_status=ca_summary.get("conditional_access_result"),
            sign_in_result=ca_summary.get("sign_in_result"),
            mfa_required=ca_summary.get("mfa_required"),
            target_site=cld_site.get("displayName") or cld_site.get("webUrl"),
            dummy_file=cld_test_object.get("file_name"),
            anonymous_link_created="Yes" if cld_metrics.get("anonymous_link_created") else "No" if scenario_id in CLD_SHAREPOINT_IDS else None,
            link_blocked_denied="Yes" if cld_metrics.get("anonymous_link_denied") else "No" if scenario_id in CLD_SHAREPOINT_IDS else None,
            denial_reason=cld_attempt.get("error_message") or cld_attempt.get("error_category"),
            cleanup_completed="Yes" if cld_metrics.get("cleanup_completed") else "No" if scenario_id in CLD_SHAREPOINT_IDS else None,
            anonymous_link_attempt_status="Allowed" if cld_metrics.get("anonymous_link_created") else "Blocked/Denied" if cld_metrics.get("anonymous_link_denied") else None,
            cleanup_status=(report.get("cleanup") or {}).get("status"),
            dummy_file_created="Yes" if report.get("dummy_file") or report.get("test_object") else None,
            public_link_created=(report.get("metrics") or {}).get("public_link_created"),
            polling_stopped_early=(report.get("metrics") or {}).get("polling_stopped_early") or ((report.get("mdca_detection_evidence") or {}).get("polling_stopped_early")),
            early_stop_reason=(report.get("metrics") or {}).get("early_stop_reason") or ((report.get("mdca_detection_evidence") or {}).get("early_stop_reason")),
            detection_method=(report.get("metrics") or {}).get("detection_method") or ((report.get("mdca_detection_evidence") or {}).get("detection_method")),
            progress_percent=100,
            tenant_evidence_status=tenant_status,
            current_message=final_message,
            report_path=str(archived_report_path) if archived_report_path.exists() else None,
            report_json_path=str(archived_report_path) if archived_report_path.exists() else None,
            html_report_path=str(archived_html_path) if archived_html_path.exists() else None,
            report_html_path=str(archived_html_path) if archived_html_path.exists() else None,
            completed_utc=utc_now(),
            risk=str(report.get("risk") or "").upper() or None,
            final_summary=final_message,
            error=None,
        )
    except Exception as exc:
        report = _terminal_report(
            project_root,
            scenario_id,
            run_id,
            "ERROR",
            "ERROR",
            "UNKNOWN",
            "Run stopped because an error occurred.",
            error=str(exc),
        )
        try:
            report_json, report_html = _write_run_report(project_root, scenario_id, run_id, report)
        except Exception:
            report_json = None
            report_html = None
        update_run(
            project_root,
            run_id,
            status="error",
            phase="Error",
            verdict="ERROR",
            error=str(exc),
            current_message="Run stopped because an error occurred.",
            report_path=str(report_json) if report_json else None,
            report_json_path=str(report_json) if report_json else None,
            html_report_path=str(report_html) if report_html else None,
            report_html_path=str(report_html) if report_html else None,
            completed_utc=utc_now(),
            final_summary="Run stopped because an error occurred.",
        )
    finally:
        with _REGISTRY_LOCK:
            _REGISTRY.pop(run_id, None)
            _RUN_ARGS.pop(run_id, None)
