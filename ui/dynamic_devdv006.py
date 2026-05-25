from __future__ import annotations

import html
import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from background_jobs import get_active_run, start_scenario_job
from run_state import latest_run_for_scenario


STATUS_LABELS = {
    "READY": "READY",
    "NOT_RUN_CONTROLLED_ACTION_NOT_EXECUTED": "NOT RUN - Controlled Action Not Executed",
    "PASS_DEFENDER_EICAR_DETECTED": "PASS - Defender EICAR Detected",
    "PARTIAL_DEFENDER_REACTION_INCOMPLETE": "PARTIAL - Defender Reaction Incomplete",
    "FAIL_DEFENDER_EICAR_NOT_DETECTED": "FAIL - Defender EICAR Not Detected",
}

DEFAULT_PUBLIC_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
DEFENDER_XDR_SCOPE = "https://api.security.microsoft.com/AdvancedHunting.Read"
DEFENDER_XDR_RESOURCE = "https://api.security.microsoft.com"
DEFENDER_XDR_ADVANCED_HUNTING_ENDPOINT = "https://api.security.microsoft.com/api/advancedhunting/run"
DEFENDER_XDR_TEST_QUERY = "DeviceInfo | take 1"


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _tenant_context(project_root: Path, state: dict | None = None) -> dict:
    state = state or {}
    preflight = _load_json(project_root / "powershell" / "Reports" / "Preflight-discovery.json")
    org = preflight.get("organization") or {}
    tenant_id = str(state.get("tenant_id") or preflight.get("tenant_id") or org.get("id") or "").strip()
    client_id = str(state.get("client_id") or preflight.get("client_id") or DEFAULT_PUBLIC_CLIENT_ID).strip()
    client_source = str(state.get("client_id_source") or "Microsoft Graph PowerShell public client / interactive public client")
    return {
        "tenant_id": tenant_id,
        "tenant_display_name": str(state.get("tenant_display_name") or org.get("displayName") or "").strip(),
        "client_id": client_id,
        "client_id_source": client_source,
        "preflight_exists": preflight != {},
    }


def _defender_xdr_connect_command(tenant_id: str, client_id: str) -> str:
    return (
        ".\\powershell\\Auth\\Connect-ZTVP-DefenderXDR.ps1 "
        f'-TenantId "{tenant_id}" '
        f'-ClientId "{client_id or DEFAULT_PUBLIC_CLIENT_ID}"'
    )


def _manual_msal_token_cache_command(tenant_id: str, client_id: str) -> str:
    tenant_value = tenant_id or "<real tenant id>"
    client_value = client_id or DEFAULT_PUBLIC_CLIENT_ID
    return f"""Import-Module MSAL.PS

$TenantId = "{tenant_value}"
$ClientId = "{client_value}"
$Scope = "https://api.security.microsoft.com/AdvancedHunting.Read"

$token = Get-MsalToken `
  -TenantId $TenantId `
  -ClientId $ClientId `
  -Scopes $Scope `
  -Interactive `
  -Prompt SelectAccount

$cachePath = ".\\powershell\\Auth\\ztvp-defenderxdr-token-cache.json"
$cache = [PSCustomObject]@{{
  access_token = $token.AccessToken
  tenant_id = $TenantId
  client_id = $ClientId
  resource = "https://api.security.microsoft.com"
  scope = $Scope
  created_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  auth_method = "Manual working MSAL.PS token"
}}
$cache | ConvertTo-Json -Depth 5 | Set-Content -Path $cachePath -Encoding UTF8"""


def _format_msal_expires_on(result: dict) -> str:
    expires_on = result.get("expires_on")
    if expires_on:
        try:
            return datetime.fromtimestamp(int(expires_on), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return str(expires_on)

    expires_in = result.get("expires_in")
    if expires_in:
        try:
            return (datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return ""

    return ""


def _advanced_hunting_test(access_token: str) -> dict:
    body = json.dumps({"Query": DEFENDER_XDR_TEST_QUERY}).encode("utf-8")
    request = urllib.request.Request(
        DEFENDER_XDR_ADVANCED_HUNTING_ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(response_body) if response_body else {}
            return {
                "ok": True,
                "status": getattr(response, "status", 200),
                "result_count": len(parsed.get("Results") or []),
                "raw": parsed,
            }
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "status": exc.code,
            "reason": f"HTTP {exc.code} {exc.reason}".strip(),
            "body": response_body,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "reason": str(exc),
            "body": "",
        }


def _save_defender_xdr_token_cache(cache_path: Path, tenant_id: str, client_id: str, result: dict) -> None:
    expires_on = _format_msal_expires_on(result)
    cache = {
        "access_token": result["access_token"],
        "tenant_id": tenant_id,
        "client_id": client_id or DEFAULT_PUBLIC_CLIENT_ID,
        "resource": DEFENDER_XDR_RESOURCE,
        "scope": DEFENDER_XDR_SCOPE,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "auth_method": "Python MSAL interactive",
    }
    if expires_on:
        cache["expires_on"] = expires_on

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _validate_defender_xdr_token_cache(cache_path: Path) -> dict:
    if not cache_path.exists():
        return {"ok": False, "status": "missing", "message": "Defender XDR API connection required."}

    try:
        cache = _load_json(cache_path)
    except Exception as exc:
        return {"ok": False, "status": "invalid", "message": f"Defender XDR token cache could not be read: {exc}"}

    access_token = str(cache.get("access_token") or "").strip()
    if not access_token:
        return {"ok": False, "status": "invalid", "message": "Defender XDR token cache does not contain an access token."}

    if cache.get("resource") and cache.get("resource") != DEFENDER_XDR_RESOURCE:
        return {"ok": False, "status": "invalid", "message": "Defender XDR token cache was saved for the wrong resource."}

    if cache.get("scope") != DEFENDER_XDR_SCOPE:
        return {"ok": False, "status": "invalid", "message": "Defender XDR token cache was saved for the wrong scope."}

    expires_on = cache.get("expires_on")
    if expires_on:
        try:
            expires_utc = datetime.fromisoformat(str(expires_on).replace("Z", "+00:00"))
            if expires_utc <= datetime.now(timezone.utc) + timedelta(minutes=5):
                return {"ok": False, "status": "expired", "message": "Defender XDR token expired or invalid. Click Connect Defender XDR API again."}
        except Exception:
            pass

    test = _advanced_hunting_test(access_token)
    if test["ok"]:
        return {"ok": True, "status": "ready", "message": "Defender XDR API connection ready.", "test": test}

    if test.get("status") == 401:
        return {"ok": False, "status": "unauthorized", "message": "Defender XDR token expired or invalid. Click Connect Defender XDR API again.", "test": test}

    detail = test.get("body") or test.get("reason") or "Advanced Hunting test query failed."
    return {"ok": False, "status": "invalid", "message": f"Defender XDR token expired or invalid. Click Connect Defender XDR API again. Reason: {detail}", "test": test}


def connect_defender_xdr_api(tenant_id: str, client_id: str, cache_path: Path) -> dict:
    if not tenant_id:
        return {"ok": False, "error": "missing_tenant", "error_description": "Tenant ID not found. Run ZTVP tenant connection/preflight discovery first."}

    try:
        import msal
    except Exception as exc:
        return {
            "ok": False,
            "error": "msal_not_available",
            "error_description": f"Python package 'msal' is not installed or could not be loaded: {exc}",
        }

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = [DEFENDER_XDR_SCOPE]
    app = msal.PublicClientApplication(
        client_id=client_id or DEFAULT_PUBLIC_CLIENT_ID,
        authority=authority,
    )

    try:
        result = app.acquire_token_interactive(
            scopes=scopes,
            prompt="select_account",
        )
    except Exception as exc:
        return {"ok": False, "error": "interactive_login_failed", "error_description": str(exc)}

    if "access_token" not in result:
        return {
            "ok": False,
            "error": result.get("error", "token_missing"),
            "error_description": result.get("error_description", "Microsoft sign-in completed but no access token was returned."),
            "correlation_id": result.get("correlation_id", ""),
        }

    test = _advanced_hunting_test(result["access_token"])
    if not test["ok"]:
        return {
            "ok": False,
            "error": "advanced_hunting_test_failed",
            "error_description": test.get("body") or test.get("reason") or "DeviceInfo test query failed.",
            "correlation_id": result.get("correlation_id", ""),
            "test": test,
        }

    _save_defender_xdr_token_cache(cache_path, tenant_id, client_id, result)
    return {
        "ok": True,
        "message": "Defender XDR API connection ready.",
        "correlation_id": result.get("correlation_id", ""),
        "test": test,
    }


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe = str(win_ps) if win_ps.exists() else "powershell.exe"

    return subprocess.run(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), *args],
        cwd=str(project_root),
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _friendly_status(value: object) -> str:
    return STATUS_LABELS.get(str(value or ""), str(value or "Unknown"))


def _tone(value: object) -> str:
    text = str(value or "").upper()
    if text.startswith("PASS"):
        return "good"
    if text.startswith("FAIL"):
        return "bad"
    return "warn"


def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero { background: linear-gradient(135deg,#0f172a,#2563eb); color:white; padding:1.45rem 1.6rem; border-radius:24px; margin-bottom:1rem; }
.ztvp-hero h2 { margin:0 0 .35rem 0; color:white; font-size:1.35rem; font-weight:900; }
.ztvp-hero p { margin:0; color:#dbeafe; }
.ztvp-alert { border-radius:16px; padding:.9rem 1rem; margin:.75rem 0 1rem 0; font-weight:650; line-height:1.5; }
.ztvp-info { background:#eff6ff; border:1px solid #3b82f6; color:#1e3a8a; }
.ztvp-good { background:#ecfdf5; border:1px solid #10b981; color:#064e3b; }
.ztvp-warn { background:#fffbeb; border:1px solid #f59e0b; color:#78350f; }
.ztvp-bad { background:#fef2f2; border:1px solid #ef4444; color:#7f1d1d; }
.ztvp-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:.85rem; margin-bottom:1rem; }
.ztvp-grid-3 { display:grid; grid-template-columns:repeat(3,1fr); gap:.85rem; margin-bottom:1rem; }
.ztvp-metric { background:white; border:1px solid #dbe3ef; border-radius:18px; padding:1rem; box-shadow:0 8px 18px rgba(15,23,42,.05); }
.ztvp-metric span { display:block; color:#64748b; font-size:.78rem; font-weight:800; margin-bottom:.45rem; }
.ztvp-metric strong { color:#0f172a; font-size:1.02rem; font-weight:950; word-break:break-word; }
.ztvp-metric.good strong { color:#15803d; }
.ztvp-metric.warn strong { color:#b45309; }
.ztvp-metric.bad strong { color:#b91c1c; }
div.stButton > button, div.stDownloadButton > button { border-radius:14px !important; min-height:44px !important; font-weight:850 !important; }
@media (max-width:900px) { .ztvp-grid, .ztvp-grid-3 { grid-template-columns:1fr; } }
</style>
""",
        unsafe_allow_html=True,
    )


def _alert(message: str, tone: str = "info") -> None:
    st.markdown(f'<div class="ztvp-alert ztvp-{tone}">{_safe(message)}</div>', unsafe_allow_html=True)


def _metric(label: str, value: object, tone: str = "") -> str:
    return f"""
<div class="ztvp-metric {tone}">
  <span>{_safe(label)}</span>
  <strong>{_safe(value)}</strong>
</div>
"""


def _bullet_card(title: str, items: list[str]) -> None:
    body = "".join(f"<li>{_safe(item)}</li>" for item in items)
    st.markdown(
        f"""
<div class="ztvp-alert ztvp-info">
  <strong>{_safe(title)}</strong>
  <ul style="margin:.55rem 0 0 1.1rem; padding:0; font-weight:650;">
    {body}
  </ul>
</div>
""",
        unsafe_allow_html=True,
    )


def _render_defender_xdr_connect_command(tenant_id: str, client_id: str) -> None:
    with st.expander("Advanced troubleshooting - PowerShell token helper", expanded=False):
        st.caption("Optional fallback only. The normal DEV-DV-006 connection uses Python MSAL directly from Streamlit.")
        st.code(_defender_xdr_connect_command(tenant_id, client_id), language="powershell")
        st.caption("Manual cache command for hosts where the PowerShell helper cannot import MSAL.PS.")
        st.code(_manual_msal_token_cache_command(tenant_id, client_id), language="powershell")


def _render_manual_tenant_evidence_form(path: Path, scenario_dir: Path) -> None:
    existing_manual = _load_json(path) if path.exists() else {}

    with st.expander("Optional fallback — record Defender portal evidence manually", expanded=False):
        st.caption("Use this only when API evidence is unauthorized, unavailable, or not found after the wait window.")
        tenant_portal_found = st.checkbox(
            "Tenant portal evidence found",
            value=bool(existing_manual.get("tenant_portal_evidence_found", False)),
            key="devdv006_manual_found",
        )
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            alert_title = st.text_input(
                "Defender alert title",
                value=str(existing_manual.get("alert_title", "")),
                placeholder="'EICAR_Test_File' malware was prevented",
                key="devdv006_manual_alert_title",
            )
            alert_status = st.text_input(
                "Alert status",
                value=str(existing_manual.get("alert_status", "")),
                placeholder="New / In progress",
                key="devdv006_manual_alert_status",
            )
            evidence_location = st.text_input(
                "Evidence location",
                value=str(existing_manual.get("evidence_location", "")),
                placeholder="Microsoft Defender portal → Incidents & alerts → Alerts",
                key="devdv006_manual_location",
            )
        with col_m2:
            severities = ["Informational", "Low", "Medium", "High", "Unknown"]
            current_severity = str(existing_manual.get("alert_severity", "Unknown") or "Unknown")
            severity_index = severities.index(current_severity) if current_severity in severities else 4
            alert_severity = st.selectbox(
                "Alert severity",
                severities,
                index=severity_index,
                key="devdv006_manual_severity",
            )
            alert_category = st.text_input(
                "Alert category",
                value=str(existing_manual.get("alert_category", "")),
                placeholder="Malware",
                key="devdv006_manual_category",
            )
            screenshot_reference = st.text_input(
                "Optional screenshot/reference",
                value=str(existing_manual.get("screenshot_reference", "")),
                placeholder="Screenshot reference or report note",
                key="devdv006_manual_reference",
            )

        evidence_notes = st.text_area(
            "Evidence notes",
            value=str(existing_manual.get("evidence_notes", "")),
            placeholder="Alert appeared in Defender portal after running DEV-DV-006.",
            key="devdv006_manual_notes",
        )

        if st.button("Save Tenant Portal Evidence", use_container_width=True, key="devdv006_save_manual_tenant"):
            scenario_dir.mkdir(parents=True, exist_ok=True)
            manual_payload = {
                "tenant_portal_evidence_found": bool(tenant_portal_found or alert_title.strip()),
                "alert_title": alert_title,
                "alert_severity": alert_severity,
                "alert_status": alert_status,
                "alert_category": alert_category,
                "evidence_location": evidence_location,
                "evidence_notes": evidence_notes,
                "screenshot_reference": screenshot_reference,
                "saved_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            path.write_text(json.dumps(manual_payload, indent=2), encoding="utf-8")
            _alert("Tenant portal evidence saved. Run Step 4 again to include it in the verdict.", "good")


def _open_active_runs() -> None:
    st.session_state.main_navigation = "Active Runs"


def _render_active_run_summary(run: dict, scenario_label: str) -> None:
    status = str(run.get("status") or "unknown").lower()
    tone = "good" if status == "completed" else "bad" if status == "error" else "warn" if status == "cancelled" else "info"
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Background status", status.title(), tone)}
  {_metric("Progress", f"{int(run.get('progress_percent') or 0)}%")}
  {_metric("Poll attempts", f"{run.get('poll_attempts') or 0} of {run.get('max_poll_attempts') or 0}")}
  {_metric("Verdict", run.get('verdict') or "Pending")}
</div>
""",
        unsafe_allow_html=True,
    )
    if status in {"running", "polling", "queued"}:
        st.progress(max(0, min(100, int(run.get("progress_percent") or 0))))
        _alert(str(run.get("current_message") or "Waiting for tenant evidence."), "info")
        st.caption(f"{scenario_label} continues in the background. You can leave this page and monitor it in Active Runs.")
    elif status == "completed":
        _alert(f"Run completed. Verdict: {run.get('verdict') or 'Unknown'}.", "good")
    elif status == "error":
        _alert("Run stopped because an error occurred. Open Active Runs to review the stored error/logs.", "bad")
    elif status == "cancelled":
        _alert("Run cancelled by user.", "warn")


def _render_report(
    report: dict,
    report_path: Path,
    html_path: Path,
    key_prefix: str = "devdv006",
    tenant_id: str = "",
    client_id: str = DEFAULT_PUBLIC_CLIENT_ID,
) -> None:
    status = report.get("status")
    evidence = report.get("evidence", {}) or {}
    local = evidence.get("local", {}) or {}
    tenant = evidence.get("tenant", {}) or {}
    tenant_api = tenant.get("api", {}) or {}
    tenant_manual = tenant.get("portal_manual", {}) or {}
    alert_summary = tenant_api.get("tenant_defender_alert") or {}
    device_summary = tenant_api.get("tenant_device_evidence") or {}

    api_status = tenant_api.get("mde_cloud_query_status", "Unknown")
    api_error = tenant_api.get("mde_cloud_error", "")
    events = tenant_api.get("mde_cloud_events") or []
    alerts = tenant_api.get("mde_cloud_alerts") or []
    joined = tenant_api.get("mde_cloud_joined_alert_evidence") or []
    file_events = tenant_api.get("mde_cloud_file_events") or []
    alert_found = bool(alert_summary.get("alert_found"))
    alert_evidence_found = bool(alert_summary.get("alert_evidence_found"))
    alert_info_title_found = bool(alert_summary.get("alert_info_title_found"))
    alert_title = alert_summary.get("alert_title") or ""
    device_found = bool(device_summary.get("device_evidence_found"))
    local_detection = bool(local.get("local_detection_found") or local.get("defender_blocking_error_found") or local.get("file_removed_or_quarantined"))
    local_imported = bool(local.get("imported_local_evidence_present"))
    tenant_evidence_found = bool(tenant_api.get("mde_cloud_evidence_found") or alert_found or device_found)
    token_problem = api_status in ["Unauthorized", "Unavailable", "Defender XDR API connection required"]
    not_found = api_status in ["Not found", "Unavailable", "Defender XDR API connection required", "Unauthorized"]
    device_name = device_summary.get("device_name") or tenant_api.get("test_device_name_requested") or report.get("test_device", "Unknown")
    detection_source = alert_summary.get("detection_source") or device_summary.get("detection_source") or "Not returned"
    category = alert_summary.get("alert_category") or "Not returned"
    alert_name = alert_title or ("Tenant alert evidence was found, but AlertInfo did not return the title." if alert_found else "Not found")

    if str(status or "").startswith("NOT_RUN"):
        result_title = "Validation not completed"
        result_tone = "warn"
        display_verdict = "NOT RUN"
        scenario_result = "Waiting for test action"
        result_message = "The validation window was armed, but no fresh endpoint evidence was imported and no tenant-side evidence was found for this run."
        clean_conclusion = "Validation has not been completed. No VM test evidence was imported for this run, and no tenant-side evidence was found after the current validation window."
        recommendations = [
            "Generate the controlled EICAR action.",
            "Run it inside the controlled VM as Administrator.",
            "Import the VM JSON evidence.",
            "Rerun analysis.",
        ]
    elif local_detection and tenant_evidence_found:
        result_title = "Validation successful"
        result_tone = "good"
        display_verdict = "PASS"
        scenario_result = "Successful"
        if alert_found and alert_info_title_found:
            result_message = "Defender detected the EICAR test file on the endpoint, and Microsoft Defender XDR captured the alert in the tenant."
            clean_conclusion = "PASS - Defender reacted locally and Microsoft Defender XDR captured the EICAR alert."
        else:
            result_message = "Defender detected the EICAR test file locally, and tenant-side Defender evidence was found. The alert title was not returned by the query, but tenant evidence exists."
            clean_conclusion = "PASS - Defender reacted locally and tenant-side Defender evidence was found."
        recommendations = [
            "Keep Defender real-time protection enabled.",
            "Keep MDE onboarding healthy.",
            "Keep monitoring Defender alerts and endpoint telemetry.",
            "Use this result as evidence that endpoint malware protection reacted and tenant telemetry was captured.",
        ]
    elif local_detection and token_problem:
        result_title = "Validation partially successful"
        result_tone = "warn"
        display_verdict = "PARTIAL"
        scenario_result = "Partially successful"
        result_message = "Defender reacted locally, but tenant-side evidence could not be queried because Defender XDR API connection is missing or unauthorized."
        clean_conclusion = "PARTIAL - Defender reacted locally, but tenant-side API validation could not be completed."
        recommendations = [
            "Connect Defender XDR API from DEV-DV-006.",
            "Sign in and consent to AdvancedHunting.Read.",
            "Rerun Step 4 after connection is ready.",
            "Confirm the token cache is valid.",
            "Use manual portal evidence only as fallback.",
        ]
    elif local_detection and not_found:
        result_title = "Validation partially successful"
        result_tone = "warn"
        display_verdict = "PARTIAL"
        scenario_result = "Partially successful"
        result_message = "Defender reacted locally, but ZTVP did not find tenant-side Defender XDR evidence within the selected wait window."
        clean_conclusion = "PARTIAL - Defender reacted locally, but tenant-side evidence was not found."
        recommendations = [
            "Wait a few more minutes and rerun tenant evidence analysis.",
            "Confirm the device appears in Microsoft Defender portal -> Assets -> Devices.",
            "Confirm Sense service is running.",
            "Confirm the endpoint is onboarded to Microsoft Defender for Endpoint.",
            "Confirm Advanced Hunting permissions are valid.",
            "Confirm Defender XDR API connection is ready.",
            "Confirm device name matches Defender portal.",
            "Check Incidents & alerts manually.",
        ]
    elif str(status or "").startswith("PARTIAL"):
        result_title = "Validation partially successful"
        result_tone = "warn"
        display_verdict = "PARTIAL"
        scenario_result = "Partially successful"
        result_message = report.get("outcome_text") or "Fresh evidence exists for this run, but ZTVP could not complete a full PASS/FAIL decision."
        clean_conclusion = report.get("clean_conclusion") or "PARTIAL - Defender evidence is incomplete."
        recommendations = report.get("recommendations") or [
            "Rerun tenant evidence analysis after a few minutes.",
            "Confirm the VM evidence JSON is complete.",
            "Confirm the device name matches Defender portal.",
            "Check Incidents & alerts manually.",
        ]
    elif not local_detection and not tenant_evidence_found:
        result_title = "Validation failed"
        result_tone = "bad"
        display_verdict = "FAIL"
        scenario_result = "Failed"
        result_message = "ZTVP did not find local Defender reaction and did not find tenant-side Defender XDR evidence for the EICAR test."
        clean_conclusion = "FAIL - Defender did not provide local or tenant-side evidence for the EICAR validation."
        recommendations = [
            "Confirm Microsoft Defender Antivirus is enabled.",
            "Confirm real-time protection is enabled.",
            "Confirm Defender is not running in passive mode.",
            "Review AV policy deployment.",
            "Check whether the test folder or EICAR file is excluded.",
            "Remove incorrect exclusions.",
            "Confirm the WinDefend service is running.",
            "Confirm the endpoint is onboarded to MDE.",
            "Confirm Sense service is running.",
            "Rerun the validation after policy correction.",
        ]
    else:
        result_title = "Validation partially successful"
        result_tone = "warn"
        display_verdict = "PARTIAL"
        scenario_result = "Partially successful"
        result_message = "ZTVP found partial Defender evidence, but the local and tenant-side evidence do not yet tell a complete story."
        clean_conclusion = "PARTIAL - Defender evidence is incomplete."
        recommendations = [
            "Rerun tenant evidence analysis after a few minutes.",
            "Confirm the VM evidence JSON is complete.",
            "Confirm the device name matches Defender portal.",
            "Check Incidents & alerts manually.",
        ]

    local_reaction_label = "Detected" if local_detection else ("Missing evidence" if not local_imported else "Not detected")
    tenant_alert_label = "Found" if alert_found else ("Not queried" if api_status in ["Defender XDR API connection required", "Unauthorized", "Unavailable"] else "Not found")
    if display_verdict == "NOT RUN":
        local_reaction_label = "Missing"
        tenant_alert_label = "Not found for this run"

    st.markdown(f"### {result_title}")
    _alert(result_message, result_tone)
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", display_verdict, result_tone)}
  {_metric("Run status" if display_verdict == "NOT RUN" else "Scenario result", scenario_result, result_tone)}
  {_metric("Local endpoint evidence" if display_verdict == "NOT RUN" else "Local Defender reaction", local_reaction_label, "good" if local_detection else "warn")}
  {_metric("Tenant evidence" if display_verdict == "NOT RUN" else "Tenant alert", tenant_alert_label, "good" if alert_found else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Alert name", alert_name)}
  {_metric("Device", device_name)}
  {_metric("Detection source", detection_source)}
  {_metric("Next action" if display_verdict == "NOT RUN" else "Category", "Run VM script and import JSON" if display_verdict == "NOT RUN" else category)}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Key evidence")
    st.markdown(f"- Local endpoint detection: `{'Found' if local_detection else 'Not found'}`")
    st.markdown(f"- Tenant alert: `{'Found' if alert_found else 'Not found'}`")
    st.markdown(f"- Alert name: `{_safe(alert_name)}`")
    st.markdown(f"- Device: `{_safe(device_name)}`")
    st.markdown(f"- Detection source: `{_safe(detection_source)}`")
    st.markdown(f"- Category: `{_safe(category)}`")
    st.markdown(f"- Tenant API status: `{_safe(api_status)}`")

    st.markdown("#### Clean conclusion")
    _alert(clean_conclusion, result_tone)

    st.markdown("#### Recommended follow-up" if display_verdict != "FAIL" else "#### Recommended remediation")
    for rec in recommendations:
        st.markdown(f"- {_safe(rec)}")

    if api_error and api_status in ["Unauthorized", "Unavailable", "Defender XDR API connection required"]:
        _alert(f"Defender XDR API message: {api_error}", "warn")
        _render_defender_xdr_connect_command(tenant_id, client_id)

    guidance = tenant_api.get("api_permission_guidance") or {}
    if guidance and api_status in ["Unauthorized", "Unavailable", "Defender XDR API connection required"]:
        with st.expander("Defender XDR API permission details", expanded=False):
            for item in guidance.get("required_api_permission") or []:
                st.markdown(f"- `{_safe(item)}`")
            st.markdown(f"API endpoint: `{_safe(guidance.get('api_endpoint', ''))}`")
            st.markdown(f"Token audience/resource: `{_safe(guidance.get('token_audience', ''))}`")
            if guidance.get("token_scope"):
                st.markdown(f"Token scope: `{_safe(guidance.get('token_scope', ''))}`")
            st.caption(guidance.get("defender_access_note", ""))

    with st.expander("Local endpoint evidence details", expanded=False):
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("VM evidence imported", local_imported, "good" if local_imported else "warn")}
  {_metric("Real-time protection", local.get("real_time_protection_enabled", "Unknown"), "good" if local.get("real_time_protection_enabled") is True else "warn")}
  {_metric("File still exists", local.get("file_still_exists", "Unknown"), "bad" if local.get("file_still_exists") is True else "good")}
  {_metric("EICAR read blocked", local.get("eicar_read_blocked", "Unknown"), "good" if local.get("eicar_read_blocked") else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Local detection found", local.get("local_detection_found", "Unknown"), "good" if local.get("local_detection_found") else "warn")}
  {_metric("Threat names", ", ".join([str(x) for x in (local.get("threat_names") or [])]) or "None")}
  {_metric("EICAR file path", local.get("file_path") or report.get("eicar_file_path", ""))}
  {_metric("VM device", local.get("test_device_name_from_vm", "Unknown"))}
</div>
""",
            unsafe_allow_html=True,
        )
        st.caption(local.get("local_summary", ""))

    with st.expander("Tenant Defender evidence details", expanded=False):
        if tenant_evidence_found:
            _alert("Microsoft Defender XDR captured tenant-side evidence for this validation.", "good")
        elif alert_found:
            _alert("Tenant alert evidence was found, but AlertInfo did not return the title.", "good")
        elif api_status == "Not found":
            _alert("Tenant-side evidence was not found within the selected wait window.", "warn")
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("API query status", "Unauthorized" if api_status == "Unauthorized" else api_status, "good" if api_status == "Found" else "warn")}
  {_metric("Evidence count", tenant_api.get("mde_cloud_evidence_count", 0))}
  {_metric("Alert found", alert_found, "good" if alert_found else "warn")}
  {_metric("Alert evidence found", alert_evidence_found, "good" if alert_evidence_found else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Alert title", alert_title or "Alert title not returned by AlertInfo lookup")}
  {_metric("Alert ID", alert_summary.get("alert_id", ""))}
  {_metric("Alert timestamp", alert_summary.get("alert_timestamp", ""))}
  {_metric("Severity", alert_summary.get("alert_severity", ""))}
</div>
<div class="ztvp-grid">
  {_metric("Category", category)}
  {_metric("Service source", alert_summary.get("service_source", ""))}
  {_metric("Device evidence linked to alert", bool(device_found and alert_found), "good" if device_found and alert_found else "warn")}
  {_metric("Device searched", tenant_api.get("test_device_name_requested", ""))}
</div>
""",
            unsafe_allow_html=True,
        )

    with st.expander("Raw Advanced Hunting rows", expanded=False):
        if events:
            st.markdown("##### Raw device events and alert evidence")
            raw_df = pd.DataFrame(events).astype(str)
            preferred_cols = [
                "Timestamp",
                "AlertId",
                "AlertTitle",
                "DeviceName",
                "EntityType",
                "EvidenceRole",
                "FileName",
                "FolderPath",
                "DetectionSource",
            ]
            for col in preferred_cols:
                if col not in raw_df.columns:
                    raw_df[col] = ""
            extra_cols = [col for col in raw_df.columns if col not in preferred_cols]
            st.dataframe(raw_df[preferred_cols + extra_cols], use_container_width=True, hide_index=True)
        else:
            st.caption("No raw device or alert evidence rows were returned.")

        if file_events:
            st.markdown("##### File events")
            st.dataframe(pd.DataFrame(file_events).astype(str), use_container_width=True, hide_index=True)

        if alerts:
            st.markdown("##### Alerts")
            st.dataframe(pd.DataFrame(alerts).astype(str), use_container_width=True, hide_index=True)

    manual_found = bool(tenant_manual.get("tenant_portal_evidence_found"))
    if manual_found and not bool(tenant_api.get("mde_cloud_evidence_found")):
        with st.expander("Manual portal evidence", expanded=False):
            st.markdown(
                f"""
<div class="ztvp-grid">
  {_metric("Portal Evidence Recorded", "Found" if manual_found else "Not recorded", "good" if manual_found else "warn")}
  {_metric("Alert Title", tenant_manual.get("alert_title", ""))}
  {_metric("Severity", tenant_manual.get("alert_severity", ""))}
  {_metric("Status", tenant_manual.get("alert_status", ""))}
</div>
<div class="ztvp-grid-3">
  {_metric("Category", tenant_manual.get("alert_category", ""))}
  {_metric("Evidence Location", tenant_manual.get("evidence_location", ""))}
  {_metric("Screenshot / Reference", tenant_manual.get("screenshot_reference", ""))}
</div>
""",
                unsafe_allow_html=True,
            )
            if tenant_manual.get("evidence_notes"):
                st.caption(tenant_manual.get("evidence_notes"))

    with st.expander("Full JSON evidence"):
        st.json(report)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "DEV-DV-006-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json_download",
        )
    with col2:
        if html_path.exists():
            st.download_button(
                "Download HTML Report",
                html_path.read_bytes(),
                "DEV-DV-006-result.html",
                "text/html",
                use_container_width=True,
                key=f"{key_prefix}_html_download",
            )


def render_devdv006_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV006.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV006.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV006.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-006"
    state_path = scenario_dir / "devdv006-state.json"
    template_path = scenario_dir / "devdv006-local-evidence-template.ps1"
    local_evidence_path = scenario_dir / "devdv006-local-evidence.json"
    manual_tenant_evidence_path = scenario_dir / "devdv006-tenant-manual-evidence.json"
    defender_token_cache_path = project_root / "powershell" / "Auth" / "ztvp-defenderxdr-token-cache.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-006-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-006-result.html"
    existing_state = _load_json(state_path) if state_path.exists() else {}
    tenant_ctx = _tenant_context(project_root, existing_state)

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-006 — Defender EICAR Detection Validation</h2>
  <p>ZTVP validates whether Defender reacts to a harmless EICAR test file by generating a controlled VM-side action, collecting endpoint evidence, querying tenant-side Defender evidence, and producing a PASS/FAIL/PARTIAL verdict.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Controlled action", "EICAR test file")}
  {_metric("Execution", "Manual VM script")}
  {_metric("Evidence", "Local Defender + tenant MDE")}
  {_metric("Decision", "PASS / FAIL / PARTIAL")}
</div>
""",
        unsafe_allow_html=True,
    )

    with st.expander("Test assumptions and safety notes"):
        st.markdown(
            """
- Use a controlled Windows VM or test endpoint.
- Microsoft Defender Antivirus should be enabled.
- Real-time protection should be enabled.
- MDE onboarding is recommended for tenant-side cloud evidence.
- Run the generated VM script inside the VM as Administrator.
- Do not run on production endpoints without approval.
- This uses the harmless EICAR antivirus test string only, not real malware.
- ZTVP runs on the host and cannot directly create files inside the VM unless remote execution is configured.
"""
        )

    st.markdown("### Step 1 — Arm Validation Window")
    st.caption("ZTVP records the start time so only new Defender evidence from this test is evaluated.")
    if tenant_ctx["tenant_id"]:
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Tenant", tenant_ctx["tenant_display_name"] or "Discovered")}
  {_metric("Tenant ID", tenant_ctx["tenant_id"], "good")}
  {_metric("Client ID", tenant_ctx["client_id"], "good")}
  {_metric("Client Source", tenant_ctx["client_id_source"])}
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        _alert("Tenant ID not found. Run ZTVP tenant connection/preflight discovery first.", "warn")
    col1, col2 = st.columns(2)
    with col1:
        test_folder = st.text_input("Default test folder", value=existing_state.get("test_folder", r"C:\Users\Public\ZTVP-DEV-DV-006"), key="devdv006_test_folder")
        test_device_name = st.text_input(
            "Test device name in Defender portal",
            value=existing_state.get("test_device_name", ""),
            placeholder="DESKTOP-AP708VD",
            key="devdv006_test_device_name",
            help="Use the device name exactly as it appears in Microsoft Defender portal -> Assets -> Devices.",
        )
        st.caption("Use the device name exactly as it appears in Microsoft Defender portal → Assets → Devices.")
    with col2:
        test_file = st.text_input("Default test file", value=existing_state.get("test_file", r"C:\Users\Public\ZTVP-DEV-DV-006\eicar.com.txt"), key="devdv006_test_file")
        modes = ["Tenant + Local Evidence", "Local Evidence Only"]
        existing_mode = existing_state.get("cloud_evidence_mode", "Tenant + Local Evidence")
        cloud_evidence_mode = st.selectbox(
            "Tenant cloud evidence mode",
            modes,
            index=modes.index(existing_mode) if existing_mode in modes else 0,
            key="devdv006_cloud_evidence_mode",
        )

    if st.button("Step 1 - Arm Validation Window", type="primary", use_container_width=True, key="devdv006_prepare_button"):
        with st.spinner("Preparing DEV-DV-006 validation window and VM script template..."):
            completed = _run_powershell(
                project_root,
                prepare_script,
                [
                    "-TestFolder", test_folder.strip(),
                    "-TestFile", test_file.strip(),
                    "-TestDeviceName", test_device_name.strip(),
                    "-TenantId", tenant_ctx["tenant_id"],
                    "-ClientId", tenant_ctx["client_id"],
                    "-CloudEvidenceMode", cloud_evidence_mode,
                ],
                timeout=300,
            )

        if completed.returncode != 0:
            _alert("DEV-DV-006 preparation failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            return

        _alert("Fresh validation window started and VM-side script generated.", "good")
        st.code(completed.stdout or "No PowerShell output captured.", language="text")
        st.rerun()

    if state_path.exists():
        state = _load_json(state_path)
        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Validation Window", state.get("validation_window_start_utc", "N/A"), "good")}
  {_metric("Cloud Evidence Mode", state.get("cloud_evidence_mode", "Tenant + Local Evidence"), "good")}
</div>
<div class="ztvp-grid-3">
  {_metric("Tenant ID", state.get("tenant_id", ""))}
  {_metric("Client ID", state.get("client_id", ""))}
  {_metric("Tenant Name", state.get("tenant_display_name", ""))}
</div>
""",
            unsafe_allow_html=True,
        )
        if not state.get("local_evidence_imported"):
            _alert("Validation window armed. Controlled action has not been executed yet.", "warn")
    else:
        _alert("No active DEV-DV-006 validation window exists yet.", "warn")

    st.markdown("### Step 2 — Generate Controlled EICAR Action")
    st.caption("ZTVP generates the exact PowerShell action to run inside the controlled VM.")
    if template_path.exists():
        script_text = template_path.read_text(encoding="utf-8-sig")
        st.text_area("Copy this script and run it inside the VM/test endpoint", script_text, height=360, key="devdv006_vm_script_text")
        st.download_button(
            "Download VM-side PowerShell Script",
            script_text,
            "devdv006-local-evidence-template.ps1",
            "text/plain",
            use_container_width=True,
            key="devdv006_template_download",
        )
        if st.button("Step 2 - Confirm VM Script Generated", use_container_width=True, key="devdv006_mark_script_generated"):
            state = _load_json(state_path) if state_path.exists() else {}
            state["vm_script_generated"] = True
            state["current_run_status"] = "VM_SCRIPT_GENERATED"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            _alert("VM script generation recorded for the current run.", "good")
            st.rerun()
    else:
        _alert("Start a fresh validation window first. ZTVP will write the VM-side script template in Step 1.", "warn")

    st.markdown("### Step 3 — Import Endpoint Evidence")
    st.caption("Paste the JSON produced by the VM script. This proves what happened locally on the endpoint.")
    pasted = st.text_area(
        "Paste devdv006-local-evidence.json content printed by the VM script",
        height=260,
        key="devdv006_pasted_evidence",
    )

    if st.button("Step 3 - Validate and Save VM Evidence", use_container_width=True, key="devdv006_save_evidence_button"):
        try:
            parsed = json.loads(pasted)
        except Exception as exc:
            _alert(f"Invalid JSON evidence: {exc}", "bad")
        else:
            if parsed.get("scenario_id") != "DEV-DV-006":
                _alert("Imported evidence is not for DEV-DV-006 and was not saved.", "bad")
                return
            scenario_dir.mkdir(parents=True, exist_ok=True)
            local_evidence_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
            state = _load_json(state_path) if state_path.exists() else {}
            state["local_evidence_imported"] = True
            state["local_evidence_path"] = str(local_evidence_path)
            state["local_evidence_timestamp_utc"] = parsed.get("timestamp_utc")
            state["local_evidence_imported_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            state["current_run_status"] = "LOCAL_EVIDENCE_IMPORTED"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            _alert(f"Local VM evidence saved to {local_evidence_path}", "good")
            st.rerun()

    current_state_for_evidence = _load_json(state_path) if state_path.exists() else {}
    if local_evidence_path.exists() and current_state_for_evidence.get("local_evidence_imported"):
        evidence = _load_json(local_evidence_path)
        summary = evidence.get("local_summary", {}) or {}
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Imported Device", evidence.get("computer_name", "Unknown"))}
  {_metric("Evidence Timestamp", evidence.get("timestamp_utc", "Unknown"))}
  {_metric("File Still Exists", evidence.get("file_still_exists", "Unknown"))}
  {_metric("Real-time Protection", summary.get("defender_realtime_enabled", "Unknown"))}
</div>
<div class="ztvp-grid-3">
  {_metric("EICAR Read Blocked", summary.get("eicar_read_blocked", "Unknown"))}
  {_metric("Local Detection Found", summary.get("local_detection_found", "Unknown"))}
  {_metric("Threat Names", ", ".join([str(x) for x in (summary.get("threat_names") or [])]) or "None")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("### Step 4 — Analyze Defender Evidence")
    st.caption("ZTVP evaluates local Defender evidence and tenant-side Defender evidence to decide whether Defender reacted.")
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        wait_minutes = st.slider("Wait for tenant evidence minutes", min_value=1, max_value=30, value=10, step=1, key="devdv006_wait_minutes")
    with col_w2:
        poll_seconds = st.slider("Retry every seconds", min_value=10, max_value=120, value=30, step=10, key="devdv006_poll_seconds")

    st.info(f"ZTVP will wait up to {wait_minutes} minutes and retry every {poll_seconds} seconds for tenant-side Defender evidence.")
    if cloud_evidence_mode != "Local Evidence Only":
        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Tenant", tenant_ctx["tenant_display_name"] or "Discovered")}
  {_metric("Tenant ID", tenant_ctx["tenant_id"] or "Missing", "good" if tenant_ctx["tenant_id"] else "warn")}
  {_metric("Client ID", tenant_ctx["client_id"] or DEFAULT_PUBLIC_CLIENT_ID, "good")}
</div>
""",
            unsafe_allow_html=True,
        )

        token_state = _validate_defender_xdr_token_cache(defender_token_cache_path)
        if token_state["ok"]:
            _alert("Defender XDR API connection ready.", "good")
        elif token_state["status"] == "missing":
            _alert("Defender XDR API connection required.", "warn")
        else:
            _alert(token_state["message"], "warn")

        if st.button("Connect Defender XDR API", use_container_width=True, key="devdv006_connect_defender_button"):
            if not tenant_ctx["tenant_id"]:
                _alert("Tenant ID not found. Run ZTVP tenant connection/preflight discovery first.", "bad")
            else:
                with st.spinner("Opening Microsoft sign-in and testing Defender XDR Advanced Hunting..."):
                    connection = connect_defender_xdr_api(
                        tenant_ctx["tenant_id"],
                        tenant_ctx["client_id"],
                        defender_token_cache_path,
                    )
                if connection["ok"]:
                    _alert("Defender XDR API connection ready.", "good")
                    st.caption(f"Token cache saved to {defender_token_cache_path}")
                    if connection.get("correlation_id"):
                        st.caption(f"Correlation ID: {connection['correlation_id']}")
                    st.rerun()
                else:
                    _alert("Defender XDR API connection failed.", "bad")
                    st.markdown(f"Error: `{_safe(connection.get('error', 'unknown'))}`")
                    st.write(connection.get("error_description", "Microsoft sign-in or Advanced Hunting validation failed."))
                    if connection.get("correlation_id"):
                        st.caption(f"Correlation ID: {connection['correlation_id']}")

        _render_defender_xdr_connect_command(tenant_ctx["tenant_id"], tenant_ctx["client_id"])

    current_run = get_active_run(project_root, "DEV-DV-006") or latest_run_for_scenario(project_root, "DEV-DV-006")
    if current_run:
        _render_active_run_summary(current_run, "DEV-DV-006")
        if st.button("Open Active Runs", use_container_width=True, key="devdv006_open_active_runs"):
            _open_active_runs()
            st.rerun()

    if st.button("Start Tenant Evidence Analysis", use_container_width=True, key="devdv006_analyze_button"):
        state = _load_json(state_path) if state_path.exists() else {}
        if not state.get("local_evidence_imported"):
            _alert("Cannot produce PASS/FAIL yet. No fresh test evidence exists for this run.", "warn")
        else:
            run = start_scenario_job(project_root, "DEV-DV-006", int(wait_minutes), int(poll_seconds))
            if str(run.get("status") or "").lower() in {"queued", "running", "polling"} and int(run.get("poll_attempts") or 0) > 0:
                _alert("An existing scenario run is already active. ZTVP will keep polling in the background and update Active Runs.", "info")
            else:
                _alert("Scenario run started. You can leave this page. ZTVP will keep polling in the background and update Active Runs.", "good")
            st.caption(f"Run ID: {run.get('run_id')}")
            if st.button("Open Active Runs", use_container_width=True, key="devdv006_open_active_runs_after_start"):
                _open_active_runs()
                st.rerun()

    if report_path.exists():
        latest_report = _load_json(report_path)
        current_run_id = str(existing_state.get("run_id") or "")
        report_run_id = str(latest_report.get("run_id") or "")
        if current_run_id and report_run_id != current_run_id:
            st.markdown("### Previous DEV-DV-006 report")
            previous_label = report_run_id or "an older run without a run_id"
            _alert(f"Previous report is from {previous_label}. Current armed run is {current_run_id}, so the old result is not used for this validation window.", "warn")
            with st.expander("Show previous report", expanded=False):
                _render_report(
                    latest_report,
                    report_path,
                    html_path,
                    key_prefix="devdv006_previous",
                    tenant_id=tenant_ctx["tenant_id"],
                    client_id=tenant_ctx["client_id"],
                )
        else:
            st.markdown("### Latest DEV-DV-006 report")
            _render_report(
                latest_report,
                report_path,
                html_path,
                key_prefix="devdv006_latest",
                tenant_id=tenant_ctx["tenant_id"],
                client_id=tenant_ctx["client_id"],
            )
            tenant_api = ((latest_report.get("evidence") or {}).get("tenant") or {}).get("api") or {}
            if tenant_api.get("mde_cloud_query_status") in ["Unauthorized", "Unavailable", "Not found", "Defender XDR API connection required"]:
                if tenant_api.get("mde_cloud_query_status") in ["Unavailable", "Defender XDR API connection required"]:
                    _render_defender_xdr_connect_command(tenant_ctx["tenant_id"], tenant_ctx["client_id"])
                _render_manual_tenant_evidence_form(manual_tenant_evidence_path, scenario_dir)

    st.markdown("### Step 5 — Cleanup")
    if st.button("Step 5 - Cleanup DEV-DV-006 Temporary Files", use_container_width=True, key="devdv006_cleanup_button"):
        with st.spinner("Cleaning DEV-DV-006 temporary files..."):
            completed = _run_powershell(project_root, cleanup_script, [], timeout=300)

        if completed.returncode != 0:
            _alert("DEV-DV-006 cleanup failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
        else:
            _alert("DEV-DV-006 cleanup completed.", "good")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            st.rerun()

