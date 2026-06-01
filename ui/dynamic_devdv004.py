from __future__ import annotations

import html
import json
import os
import subprocess
from pathlib import Path

import pandas as pd
import streamlit as st

from background_jobs import get_active_run, start_scenario_job
from html_report import write_standard_html_report
from run_state import ACTIVE_STATUSES, is_stale, latest_run_for_scenario, request_cancel, selected_run_for_scenario, update_run


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "FAIL_NORMAL_USER_REGISTERED_DEVICE": "FAIL — A Current Device Remains Linked",
    "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION": "PASS — No Registered Device Remains Linked",
    "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED": "PARTIAL — Lifecycle Observed, No Final Linked Device Confirmed",
}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _safe_existing_path(project_root: Path, raw_path: object) -> Path | None:
    if raw_path is None:
        return None
    text = str(raw_path).strip()
    if text in {"", ".", "None", "none", "null", "NULL"}:
        return None
    path = Path(text)
    if not path.is_absolute():
        path = project_root / path
    try:
        path = path.resolve()
    except Exception:
        return None
    return path if path.exists() and path.is_file() else None


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    user_profile = os.environ.get("USERPROFILE", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe = str(win_ps) if win_ps.exists() else "powershell.exe"

    module_paths = [
        Path(user_profile) / "Documents" / "WindowsPowerShell" / "Modules",
        Path(user_profile) / "Documents" / "PowerShell" / "Modules",
        Path(program_files) / "WindowsPowerShell" / "Modules",
        Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules",
    ]

    env = os.environ.copy()
    env["PSModulePath"] = ";".join(str(p) for p in module_paths)

    return subprocess.run(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), *args],
        cwd=str(project_root),
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
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


def _write_html_report(report: dict, html_path: Path) -> None:
    write_standard_html_report(report, html_path)


def _fmt_seconds(value: object) -> str:
    try:
        seconds = max(0, int(float(value or 0)))
    except Exception:
        return "Not recorded"
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{sec:02d}"
    return f"{minutes:02d}:{sec:02d}"


def _polls_label(run_or_report: dict) -> str:
    metrics = run_or_report.get("metrics", {}) or {}
    timer = run_or_report.get("timer", {}) or {}
    attempts = run_or_report.get("poll_attempts") or metrics.get("poll_attempts") or timer.get("poll_attempts")
    max_attempts = run_or_report.get("max_poll_attempts") or metrics.get("max_poll_attempts") or timer.get("max_poll_attempts")
    if attempts in [None, ""] or max_attempts in [None, "", 0, "0"]:
        return "Not recorded"
    return f"{attempts} / {max_attempts}"


def _render_active_run(project_root: Path, run: dict) -> None:
    _alert("DEV-DV-002 validation is currently running.", "info")
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Elapsed", _fmt_seconds(run.get("elapsed_seconds")))}
  {_metric("Remaining", _fmt_seconds(run.get("remaining_seconds")))}
  {_metric("Monitoring window", str(run.get("monitoring_window_minutes") or run.get("wait_minutes") or "N/A") + " min")}
  {_metric("Retry interval", str(run.get("retry_interval_seconds") or run.get("poll_seconds") or "N/A") + " sec")}
</div>
<div class="ztvp-grid">
  {_metric("Poll attempts", _polls_label(run))}
  {_metric("Current phase", run.get("phase", "N/A"))}
  {_metric("Current check", run.get("current_evidence_source", "N/A"))}
  {_metric("Evidence status", run.get("tenant_evidence_status", "Waiting"))}
</div>
""",
        unsafe_allow_html=True,
    )
    _alert(str(run.get("current_message") or "Waiting for tenant evidence."), "info")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", use_container_width=True, key="devdv004_open_active_runs"):
            st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
            st.rerun()
    with col2:
        if st.button("Cancel DEV-DV-002 run", use_container_width=True, key="devdv004_cancel_run"):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()
    import time
    time.sleep(2)
    st.rerun()


def _render_completed_run_output(project_root: Path, run: dict) -> bool:
    report_path = _safe_existing_path(project_root, run.get("report_path"))
    html_path = _safe_existing_path(project_root, run.get("html_report_path"))
    if report_path is None:
        _alert("DEV-DV-002 completed, but the JSON report file is not available.", "warn")
        return False
    report = _load_json(report_path)
    if html_path is None:
        candidate = report_path.with_suffix(".html")
        html_path = candidate if candidate.exists() else None
    _render_report(report, report_path, html_path or (project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-004-result.html"), key_prefix="devdv004_final")
    return True


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "devdv004") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    detected = report.get("detected_device", {}) or {}
    evidence = report.get("evidence", {}) or {}
    found = report.get("what_ztvp_found", {}) or {}
    timer = report.get("timer", {}) or {}
    final_state = report.get("final_device_state", {}) or {}

    _alert("DEV-DV-002 report loaded.", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Device linked to decoy user", found.get("device_linked_to_decoy_user") or final_state.get("device_linked_to_decoy") or "Unknown", "bad" if metrics.get("device_registered_or_linked") else "good")}
  {_metric("Final device state", metrics.get("final_device_state") or final_state.get("state") or "Unknown", _tone(status))}
</div>
<div class="ztvp-grid">
  {_metric("Temporary device observed", "Yes" if found.get("temporary_device_observed") or metrics.get("temporary_device_observed") else "No")}
  {_metric("Current registered devices linked", found.get("current_registered_devices_linked", evidence.get("current_registered_devices_linked", 0)), "bad" if metrics.get("device_registered_or_linked") else "good")}
  {_metric("Final Graph registeredDevices count", found.get("final_graph_registered_devices_count", evidence.get("final_graph_registered_devices_count", 0)))}
  {_metric("Device still exists in /devices", found.get("device_still_exists_in_devices", metrics.get("device_still_exists_in_devices", "Unknown")))}
</div>
<div class="ztvp-grid">
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Decoy user Devices tab equivalent", str(evidence.get("decoy_user_devices_tab_equivalent", final_state.get("decoy_user_devices_tab_equivalent", 0))) + " devices")}
  {_metric("Device lifecycle audit events", evidence.get("registration_like_audit_count_after_window", 0))}
  {_metric("Evidence confidence", found.get("evidence_confidence", report.get("evidence_quality", "Unknown")))}
</div>
<div class="ztvp-grid">
  {_metric("Elapsed", _fmt_seconds(timer.get("elapsed_seconds") or metrics.get("elapsed_seconds")))}
  {_metric("Polls used", _polls_label(report))}
  {_metric("Monitoring window", str(timer.get("monitoring_window_minutes") or "N/A") + " min")}
  {_metric("Retry interval", str(timer.get("retry_interval_seconds") or metrics.get("poll_interval_seconds") or "N/A") + " sec")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### What ZTVP found")
    found_rows = [
        {"Item": "Registered devices linked to decoy user", "Value": found.get("registered_devices_linked_to_decoy_user", evidence.get("registered_device_count_after_window", 0))},
        {"Item": "Device linked to decoy user", "Value": found.get("device_linked_to_decoy_user", final_state.get("device_linked_to_decoy", "Unknown"))},
        {"Item": "Temporary device observed", "Value": found.get("temporary_device_observed", metrics.get("temporary_device_observed", False))},
        {"Item": "Current registered devices linked", "Value": found.get("current_registered_devices_linked", evidence.get("current_registered_devices_linked", 0))},
        {"Item": "Final Graph registeredDevices count", "Value": found.get("final_graph_registered_devices_count", evidence.get("final_graph_registered_devices_count", 0))},
        {"Item": "Device still exists in /devices", "Value": found.get("device_still_exists_in_devices", metrics.get("device_still_exists_in_devices", "Unknown"))},
        {"Item": "Decoy user Devices tab equivalent", "Value": str(evidence.get("decoy_user_devices_tab_equivalent", final_state.get("decoy_user_devices_tab_equivalent", 0))) + " devices"},
        {"Item": "Device lifecycle audit events", "Value": found.get("lifecycle_events_count", evidence.get("registration_like_audit_count_after_window", 0))},
        {"Item": "Exact decoy audit matches", "Value": found.get("exact_decoy_audit_events_count", evidence.get("exact_decoy_registration_like_audit_count_after_window", 0))},
        {"Item": "Add device event found", "Value": found.get("add_device_event_found", False)},
        {"Item": "Register device event found", "Value": found.get("register_device_event_found", False)},
        {"Item": "Add owner event found", "Value": found.get("add_owner_event_found", False)},
        {"Item": "Add user event found", "Value": found.get("add_user_event_found", False)},
        {"Item": "Unregister device event found", "Value": found.get("unregister_device_event_found", False)},
        {"Item": "Delete device event found", "Value": found.get("delete_device_event_found", False)},
        {"Item": "Detected device", "Value": found.get("detected_device_name") or found.get("detected_device_id") or "Not returned"},
        {"Item": "Final device state", "Value": found.get("final_device_state", "Unknown")},
        {"Item": "Evidence confidence", "Value": found.get("evidence_confidence", report.get("evidence_quality", "Unknown"))},
        {"Item": "Sign-in logs checked as supporting evidence", "Value": found.get("sign_in_evidence_found", False)},
    ]
    st.dataframe(pd.DataFrame(found_rows).astype(str), use_container_width=True, hide_index=True)

    st.markdown("#### What ZTVP thinks happened")
    st.write(report.get("what_ztvp_thinks_happened") or report.get("final_claim") or report.get("executive_summary", ""))

    st.markdown("#### Decision")
    if str(status or "").startswith("FAIL"):
        _alert("FAIL: a current device remains linked to the normal decoy user.", "bad")
    elif str(status or "").startswith("PASS"):
        _alert("PASS: no current device remains linked to the normal decoy user.", "good")
    else:
        _alert("PARTIAL: device lifecycle activity was observed, but no final linked device remains or confidence is incomplete.", "warn")

    rows = [
        {"Evidence": "Validation window", "Value": report.get("validation_window_start_utc", ""), "Meaning": "Only evidence after this time was analyzed."},
        {"Evidence": "Decoy user", "Value": decoy.get("user_principal_name", ""), "Meaning": "Normal temporary user used inside Sandbox."},
        {"Evidence": "Primary Graph check", "Value": "GET /users/{decoyUserId}/registeredDevices", "Meaning": "Primary proof for whether the decoy user currently has a linked registered device."},
        {"Evidence": "Final device existence check", "Value": "GET /devices/{deviceId}", "Meaning": "Every final registeredDevices result must still exist as a current Entra device object."},
        {"Evidence": "Detected device", "Value": detected.get("display_name", "None"), "Meaning": detected.get("trust_type", "No device object is currently linked to the decoy user.") if detected else "No device object is currently linked to the decoy user."},
        {"Evidence": "Current registered devices linked", "Value": evidence.get("current_registered_devices_linked", evidence.get("registered_device_count_after_window", 0)), "Meaning": "0 means no final linked device is currently associated with the decoy user."},
        {"Evidence": "Final Graph registeredDevices count", "Value": evidence.get("final_graph_registered_devices_count", 0), "Meaning": "Raw final registeredDevices result before /devices existence verification."},
        {"Evidence": "Device lifecycle audit events", "Value": evidence.get("registration_like_audit_count_after_window", 0), "Meaning": "Add/Register/Owner/User/Unregister/Delete lifecycle events in the validation window."},
        {"Evidence": "Exact decoy audit matches", "Value": evidence.get("exact_decoy_registration_like_audit_count_after_window", 0), "Meaning": "Lifecycle rows where the decoy UPN or object ID is directly present in Graph audit fields."},
        {"Evidence": "Supporting sign-ins", "Value": evidence.get("sign_in_count_after_window", 0), "Meaning": "Optional context only. Conditional Access is not the main evidence for DEV-DV-002."},
        {"Evidence": "Stop reason", "Value": timer.get("stop_reason") or metrics.get("stop_reason") or "", "Meaning": "Why polling stopped."},
    ]


    st.markdown("#### Tenant conclusion")

    if str(status or "").startswith("PASS"):
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — No current device remains linked to the decoy user.</strong><br>
Microsoft Graph registeredDevices shows no device currently linked to the normal decoy user.
If lifecycle activity was observed, the audit trail shows it was later unregistered or deleted.
</div>
""",
            unsafe_allow_html=True,
        )
    elif str(status or "").startswith("FAIL"):
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — A current device remains linked to the normal decoy user.</strong><br>
A device object is linked to the decoy user. This means the tenant allowed this normal user to introduce a new device identity.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — Device lifecycle activity was observed.</strong><br>
ZTVP could not confidently prove the final device ownership/link state from registeredDevices plus lifecycle audit evidence.
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### Evidence summary")
    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    devices = (evidence.get("registered_devices") or [])
    if devices:
        st.markdown("#### Registered / linked devices")
        st.dataframe(pd.DataFrame(devices).astype(str), use_container_width=True, hide_index=True)

    signins = (evidence.get("sign_ins") or [])
    if signins:
        st.markdown("#### Sign-ins after validation window")
        st.dataframe(pd.DataFrame(signins).astype(str), use_container_width=True, hide_index=True)

    audits = (evidence.get("audit_events") or [])
    if audits:
        st.markdown("#### Device-related audit events")
        st.dataframe(pd.DataFrame(audits).astype(str), use_container_width=True, hide_index=True)

    recs = report.get("recommendations", []) or []
    if recs:
        st.markdown("#### Recommended follow-up")
        if str(status or "").startswith("PASS"):
            st.caption("These are follow-up actions, not emergency fixes. The validation passed because the tenant did not allow the normal decoy user to complete device registration.")
        elif str(status or "").startswith("FAIL"):
            st.caption("These are remediation actions because the decoy user successfully registered or linked a device.")
        else:
            st.caption("These are investigation actions because the result was not fully classified.")

        for rec in recs:
            st.markdown(f"- {rec}")

    st.markdown("#### Clean conclusion")

    if str(status or "").startswith("FAIL"):
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — Device registration succeeded.</strong><br>
The decoy user created or linked a new device object. This means a normal user was able to introduce a device identity into Entra ID.
</div>
""",
            unsafe_allow_html=True,
        )
    elif str(status or "").startswith("PASS"):
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — Final device state is not linked.</strong><br>
The primary registeredDevices check shows no device currently linked to the decoy user.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — More evidence required.</strong><br>
ZTVP found some evidence, but the result could not be fully classified.
</div>
""",
            unsafe_allow_html=True,
        )
    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button("View HTML report", html_path.read_bytes(), "DEV-DV-002-result.html", "text/html", use_container_width=True, key=f"{key_prefix}_view_html")

    with col2:
        st.download_button("Download HTML Report", html_path.read_bytes(), "DEV-DV-002-result.html", "text/html", use_container_width=True, key=f"{key_prefix}_html")

    with col3:
        st.download_button("Download JSON evidence", report_path.read_bytes(), "DEV-DV-002-result.json", "application/json", use_container_width=True, key=f"{key_prefix}_json")


def render_devdv004_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV004.ps1"
    launch_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Launch-ZTVP-DEVDV004Sandbox.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV004.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV004.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-004"
    state_path = scenario_dir / "devdv004-state.json"
    prepare_path = scenario_dir / "devdv004-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-004-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-004-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-002 — Sandbox Device Registration Abuse Probe</h2>
  <p>Create a decoy user, manually use Windows Sandbox for Access work or school registration, then wait for Entra evidence.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("This is the real normal-user device registration validation from the Devices → Cloud catalog. Windows Sandbox must be enabled on the host.", "info")

    requested_run_id = str(st.session_state.get("ztvp_dynamic_open_run_id") or "")
    selected_run = selected_run_for_scenario(project_root, "DEV-DV-002", requested_run_id)
    active_run = get_active_run(project_root, "DEV-DV-002", requested_run_id) if requested_run_id else get_active_run(project_root, "DEV-DV-002")
    if active_run:
        _render_active_run(project_root, active_run)
        return

    latest_run = selected_run or latest_run_for_scenario(project_root, "DEV-DV-002")
    if latest_run and str(latest_run.get("status") or "").lower() in ACTIVE_STATUSES and is_stale(latest_run):
        update_run(
            project_root,
            str(latest_run.get("run_id") or ""),
            status="stale",
            phase="Interrupted",
            current_message="Run was interrupted because the app process stopped.",
        )
        latest_run = selected_run_for_scenario(project_root, "DEV-DV-002", requested_run_id) or latest_run_for_scenario(project_root, "DEV-DV-002")
    if latest_run and str(latest_run.get("status") or "").lower() == "stale":
        _alert("DEV-DV-002 run was interrupted because the app process stopped. You can restart analysis with a fresh run.", "warn")
    elif latest_run and str(latest_run.get("status") or "").lower() in {"completed", "cancelled", "error", "timeout"}:
        _render_completed_run_output(project_root, latest_run)

    st.markdown("### 1. Prepare decoy user")

    if not state_path.exists():
        col1, col2 = st.columns(2)
        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-devdv004-decoy", key="devdv004_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP DEV-DV-002 Sandbox Device Registration Decoy User", key="devdv004_display_name")
        with col2:
            tenant_domain = st.text_input("Tenant domain optional", value="", placeholder="Leave empty to auto-detect", key="devdv004_tenant_domain")

        if st.button("Step 1 — Prepare DEV-DV-002 Decoy User", type="primary", use_container_width=True):
            args = ["-UserPrefix", user_prefix.strip(), "-DisplayName", display_name.strip()]
            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            with st.spinner("Creating DEV-DV-002 decoy user..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("Decoy preparation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            _alert("Decoy user prepared.", "good")
            st.rerun()
    else:
        _alert("Decoy user is already prepared.", "good")

    if prepare_path.exists():
        prep = _load_json(prepare_path)
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Tenant ID", prep.get("tenant_id", ""))}
  {_metric("Operator", prep.get("operator_account", ""))}
  {_metric("Decoy UPN", prep.get("decoy_user_principal_name", ""))}
  {_metric("Temporary Password", prep.get("decoy_temporary_password", ""), "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("### 2. Start fresh validation window and open Sandbox manually")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        window = state.get("validation_window_start_utc", "")

        _alert(
            "Open Windows Sandbox manually. ZTVP will only start the validation timestamp and then wait for Entra evidence.",
            "info",
        )

        if window:
            _alert(f"Current validation window: {window}", "good")
        else:
            _alert("No validation window yet. Click the button below before doing the Sandbox registration attempt.", "warn")

        if st.button("Step 2 — Start Fresh Validation Window", use_container_width=True):
            import time
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state["validation_window_start_utc"] = now_utc
            state.setdefault("sandbox", {})
            state["sandbox"]["launched"] = False
            state["sandbox"]["manual_mode"] = True
            state["sandbox"]["manual_window_started_at"] = now_utc

            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            _alert(f"Fresh validation window started at {now_utc}. Now open Windows Sandbox manually.", "good")
            st.rerun()

        st.code(
            f"Manual Sandbox flow:\n\n"
            f"1. Open Windows Sandbox yourself from the Start menu.\n"
            f"2. Inside Sandbox, open Settings.\n"
            f"3. Go to Accounts → Access work or school.\n"
            f"4. Click Connect.\n"
            f"5. Sign in using this decoy user:\n   {decoy.get('user_principal_name', '')}\n   {decoy.get('temporary_password', '')}\n"
            f"6. Try to complete the work/school registration flow.\n"
            f"7. Come back to ZTVP and click Step 3 — Wait for Device Registration Evidence.",
            language="text",
        )

    st.markdown("### 3. Analyze device registration evidence")

    col_timer, col_retry, col_est = st.columns(3)
    with col_timer:
        wait_minutes = st.slider(
            "Monitoring window minutes",
            min_value=2,
            max_value=90,
            value=15,
            step=1,
            key="devdv004_wait_minutes",
            help="Maximum time ZTVP will wait for Entra device/audit evidence before stopping.",
        )
    with col_retry:
        poll_seconds = st.slider(
            "Retry interval seconds",
            min_value=10,
            max_value=120,
            value=30,
            step=10,
            key="devdv004_poll_seconds",
            help="How often ZTVP checks Microsoft Graph and Entra logs.",
        )
    with col_est:
        estimated_checks = max(1, int((wait_minutes * 60 + poll_seconds - 1) / poll_seconds))
        st.metric("Estimated checks", estimated_checks)
    st.caption(f"ZTVP will check for up to {wait_minutes} minutes, every {poll_seconds} seconds, for about {estimated_checks} attempts.")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    elif not (_load_json(state_path).get("validation_window_start_utc")):
        _alert("Start a fresh validation window before analyzing evidence.", "warn")
    elif st.button("Analyze device registration evidence", use_container_width=True, type="primary"):
        run = start_scenario_job(project_root, "DEV-DV-002", int(wait_minutes), int(poll_seconds))
        _render_active_run(project_root, run)
        st.stop()

    if report_path.exists() and not (latest_run and latest_run.get("report_path")):
        st.markdown("### Latest DEV-DV-002 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="devdv004_latest")

    st.markdown("### 4. Cleanup")

    delete_device = st.checkbox("Also delete detected test device if ZTVP found one", value=False, key="devdv004_delete_device")

    if not state_path.exists():
        _alert("No active DEV-DV-002 state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        detected = state.get("detected_device", {}) or {}

        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Detected Device", detected.get("display_name", "None") if detected else "None", "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Step 4 — Cleanup DEV-DV-002 Objects", use_container_width=True):
            args = []
            if delete_device:
                args.append("-DeleteDetectedDevice")

            with st.spinner("Cleaning DEV-DV-002 objects..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("DEV-DV-002 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("DEV-DV-002 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()

