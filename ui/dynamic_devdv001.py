from __future__ import annotations

import html
import json
import os
import subprocess
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from background_jobs import get_active_run, start_scenario_job
from ca_summary import summarize_ca_access_report
from html_report import write_standard_html_report
from run_state import ACTIVE_STATUSES, is_stale, latest_run_for_scenario, request_cancel, selected_run_for_scenario, update_run


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "PASS_UNMANAGED_DEVICE_BLOCKED_BY_DEVICE_TRUST": "PASS — Unmanaged Device Blocked by Device Trust",
    "FAIL_UNMANAGED_DEVICE_ACCESS_ALLOWED_POLICY_NOT_ENFORCED": "FAIL — Device-Trust Policy Not Enforced",
    "PARTIAL_SIGNIN_FOUND_UNCLASSIFIED": "PARTIAL — Sign-in Found, Unclassified",
    "PARTIAL_BLOCKED_BY_NON_DEVICE_OR_UNCLASSIFIED_POLICY": "PARTIAL — Blocked by Non-Device or Unclassified Policy",
    "PARTIAL_ACCESS_ALLOWED_DEVICE_STATE_NOT_UNMANAGED": "PARTIAL — Access Allowed but Device State Not Unmanaged",
    "PARTIAL_SIGNIN_FAILED_UNCLASSIFIED": "PARTIAL — Sign-in Failed, Unclassified",
    "PARTIAL_NO_SIGNIN_LOG_FOUND": "PARTIAL — No Sign-in Log Found",
}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


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




def _fmt_graph_time(value: object) -> str:
    text = "" if value is None else str(value)

    if text.startswith("/Date(") and text.endswith(")/"):
        try:
            import datetime
            ms = int(text[6:-2])
            return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return text

    return text


def _friendly_status(value: object) -> str:
    return STATUS_LABELS.get(str(value or ""), str(value or "Unknown"))


def _tone(value: object) -> str:
    text = str(value or "").upper()
    if text.startswith("PASS") or text == "DECOY_READY":
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
div[data-testid="stWidgetLabel"] label,
div[data-testid="stWidgetLabel"] p,
label,
.stTextInput label,
.stSelectbox label,
.stNumberInput label,
.stTextArea label {
    color:#0f172a !important;
    opacity:1 !important;
    font-weight:750 !important;
}
div[data-testid="stCaptionContainer"],
div[data-testid="stCaptionContainer"] p,
.stCaption,
small,
div[data-baseweb="form-control"] div {
    color:#64748b !important;
}
input,
textarea,
div[data-baseweb="select"] span {
    color:#f8fafc !important;
}
input::placeholder,
textarea::placeholder {
    color:#94a3b8 !important;
    opacity:1 !important;
}
input:disabled,
textarea:disabled,
div[aria-disabled="true"],
div[aria-disabled="true"] * {
    color:#64748b !important;
    -webkit-text-fill-color:#64748b !important;
    opacity:1 !important;
}
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


def _open_active_runs() -> None:
    st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
    st.rerun()


def _render_active_run(project_root: Path, run: dict) -> None:
    _alert("DEV-DV-001 validation is running.", "info")
    polls = f"{run.get('poll_attempts', 0)} / {run.get('max_poll_attempts', 'N/A')}"
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Phase", run.get("phase", "N/A"))}
  {_metric("Poll attempts", polls)}
  {_metric("Tenant evidence", run.get("tenant_evidence_status", "Waiting"))}
  {_metric("Progress", str(run.get("progress_percent", 0)) + "%")}
</div>
<div class="ztvp-grid">
  {_metric("Decoy user", run.get("decoy_user") or run.get("test_user") or "N/A")}
  {_metric("Target app", run.get("target_app") or run.get("target") or "N/A")}
  {_metric("Validation start UTC", run.get("validation_start_utc", "N/A"))}
  {_metric("Message", run.get("current_message", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", use_container_width=True, key="devdv001_open_active_runs"):
            _open_active_runs()
    with col2:
        if st.button("Cancel DEV-DV-001 run", use_container_width=True, key="devdv001_cancel_run"):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()
    st.caption("This panel refreshes while the background analysis is running.")
    time.sleep(2)
    st.rerun()


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


def _verdict_from_report(report: dict) -> str:
    text = str(report.get("verdict") or report.get("status") or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("CANCEL"):
        return "CANCELLED"
    if text.startswith("ERROR"):
        return "ERROR"
    if text.startswith("UNSUPPORTED"):
        return "UNSUPPORTED"
    return "PARTIAL"


def _access_result(report: dict) -> str:
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    selected = sign_in.get("selected_event", {}) or {}
    if selected.get("is_success") is True:
        return "Success"
    if selected.get("device_trust_policies") or sign_in.get("device_trust_policies"):
        return "Blocked"
    if selected.get("blocking_policies") or sign_in.get("blocking_policies") or sign_in.get("conditional_access_status") == "failure":
        return "Interrupted / blocked"
    if selected.get("is_failure") is True:
        return "Interrupted"
    return "Unknown"


def _matched_sign_in_app(sign_in: dict) -> str:
    selected = sign_in.get("selected_event", {}) or {}
    if not selected:
        rejected = sign_in.get("rejected_sign_ins", []) or []
        selected = next(
            (event for event in rejected if str(event.get("match_reason") or "").lower() == "wrong app"),
            {},
        )
    app = sign_in.get("app_display_name") or selected.get("app_display_name") or ""
    resource = sign_in.get("resource_display_name") or selected.get("resource_display_name") or ""
    if app and resource:
        return f"{app} -> {resource}"
    return app or resource or "Not found"


def _has_target_app_mismatch(sign_in: dict) -> bool:
    if bool(sign_in.get("target_app_mismatch")):
        return True

    if sign_in.get("selected_event"):
        return False

    rejected = sign_in.get("rejected_sign_ins", []) or []
    return any(str(event.get("match_reason") or "").lower() == "wrong app" for event in rejected)


def _is_no_signin_evidence(report: dict) -> bool:
    status = str(report.get("status") or "").upper()
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    metrics = report.get("metrics", {}) or {}
    return (
        status.startswith("PARTIAL_NO_SIGNIN")
        or (
            str(report.get("scenario_id") or "").upper() == "DEV-DV-001"
            and not bool(sign_in.get("meaningful_sign_in_count") or sign_in.get("selected_event"))
            and not bool(metrics.get("sign_in_log_found"))
        )
    )


def _polling_summary(report: dict, run: dict | None = None) -> dict:
    run = run or {}
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    metrics = report.get("metrics", {}) or {}
    summary = report.get("polling_summary", {}) or {}
    attempts = metrics.get("poll_attempts") or sign_in.get("poll_count") or run.get("poll_attempts") or 0
    max_attempts = metrics.get("max_poll_attempts") or sign_in.get("max_poll_attempts") or run.get("max_poll_attempts") or "N/A"
    poll_seconds = metrics.get("poll_interval_seconds") or sign_in.get("poll_seconds") or run.get("poll_seconds") or summary.get("poll_interval_seconds") or "N/A"
    validation_start = report.get("validation_start_utc") or sign_in.get("validation_window_start_utc") or run.get("validation_start_utc") or summary.get("validation_start_utc") or "N/A"
    last_poll = metrics.get("last_poll_utc") or sign_in.get("last_poll_utc") or summary.get("last_poll_utc") or report.get("completed_utc") or run.get("completed_utc") or "N/A"
    window_minutes = sign_in.get("monitoring_window_minutes") or run.get("wait_minutes") or "N/A"
    found = bool(sign_in.get("meaningful_sign_in_count") or sign_in.get("selected_event") or metrics.get("sign_in_log_found"))
    result = "Evidence found" if found else "Timeout / No evidence found"
    return {
        "poll_seconds": poll_seconds,
        "polls": f"{attempts} / {max_attempts}",
        "validation_start": validation_start,
        "last_poll": last_poll,
        "window_minutes": window_minutes,
        "found": "Yes" if found else "No",
        "result": result,
    }


def _render_polling_summary(report: dict, run: dict | None = None) -> None:
    summary = _polling_summary(report, run)
    st.markdown(
        f"""
<div class="ztvp-grid-3">
  {_metric("Poll interval seconds", summary["poll_seconds"])}
  {_metric("Polls used", summary["polls"])}
  {_metric("Validation start UTC", summary["validation_start"])}
</div>
<div class="ztvp-grid-3">
  {_metric("Last poll UTC", summary["last_poll"])}
  {_metric("Monitoring window", str(summary["window_minutes"]) + " minutes")}
  {_metric("Matching sign-in found", summary["found"], "good" if summary["found"] == "Yes" else "warn")}
</div>
<div class="ztvp-grid-3">
  {_metric("Result", summary["result"], "good" if summary["found"] == "Yes" else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )


def _no_evidence_recommendations() -> list[str]:
    return [
        "Increase the monitoring window to 30 or 60 minutes.",
        "Verify the login was performed after clicking Start Fresh Validation Window.",
        "Confirm the login was performed with the decoy user, not the admin account.",
        "Confirm the selected target app matches the app opened in Sandbox.",
        "Check Entra sign-in log delay manually.",
        "If using My Apps, also try Microsoft 365 Portal or SharePoint Online depending on the selected target.",
        "Rerun analysis after the sign-in appears in Entra logs.",
    ]


def _render_polling_details(report: dict) -> None:
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    details = {
        "summary": sign_in.get("polling_summary") or report.get("polling_summary") or {},
        "match_diagnostics": sign_in.get("match_diagnostics") or [],
        "rejected_sign_ins": sign_in.get("rejected_sign_ins") or [],
    }
    with st.expander("Polling details", expanded=False):
        st.json(details)


def _render_final_run_output(project_root: Path, run: dict) -> bool:
    report_path = _safe_existing_path(project_root, run.get("report_path"))
    html_path = _safe_existing_path(project_root, run.get("html_report_path"))
    if report_path is None:
        st.markdown("### DEV-DV-001 result")
        _alert("Report file was not generated.", "warn")
        return False

    report = _load_json(report_path)
    if html_path is None:
        candidate = report_path.with_suffix(".html")
        html_path = candidate if candidate.exists() else None

    no_evidence = _is_no_signin_evidence(report)
    ca = summarize_ca_access_report(report, "device")
    st.markdown("### PARTIAL — No matching tenant sign-in evidence found" if no_evidence else "### DEV-DV-001 result")
    verdict = _verdict_from_report(report)
    tone = {"PASS": "good", "FAIL": "bad", "ERROR": "bad", "PARTIAL": "warn", "CANCELLED": "warn"}.get(verdict, "warn")
    metrics = report.get("metrics", {}) or {}
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    ca = summarize_ca_access_report(report, "device")
    policy_name = ca.get("effective_policy") or metrics.get("device_trust_policy_name") or metrics.get("blocking_policy_name") or sign_in.get("device_trust_policy_name") or sign_in.get("blocking_policy_name") or ("Not available" if no_evidence else "Not found")
    access_found = False if no_evidence else bool(metrics.get("sign_in_log_found") or sign_in.get("meaningful_sign_in_count") or sign_in.get("selected_event"))
    device_block = bool(metrics.get("device_trust_policy_found") or sign_in.get("device_trust_policies"))
    polls = f"{metrics.get('poll_attempts') or sign_in.get('poll_count') or run.get('poll_attempts') or 0} / {metrics.get('max_poll_attempts') or sign_in.get('max_poll_attempts') or run.get('max_poll_attempts') or 'N/A'}"
    tenant_evidence = run.get("tenant_evidence_status") or ("Found" if access_found else "Not found")
    target = report.get("target") or {}
    matched_app = _matched_sign_in_app(sign_in)
    access_result = "Not available" if no_evidence else _access_result(report)

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", verdict, tone)}
  {_metric("Risk", report.get("risk", "Unknown"), tone)}
  {_metric("Access attempt found", "Yes" if access_found else "No", "good" if access_found else "warn")}
  {_metric("Access result", access_result, "warn" if no_evidence else tone)}
</div>
<div class="ztvp-grid">
  {_metric("Device-trust block found", "Yes" if device_block else "No", "good" if device_block else "warn")}
  {_metric("Effective policy", policy_name)}
  {_metric("Tenant evidence", tenant_evidence)}
  {_metric("Polls used", polls)}
</div>
<div class="ztvp-grid-3">
  {_metric("Target app selected", target.get("name") or report.get("target_app") or "N/A")}
  {_metric("Target URL used", target.get("url") or "N/A")}
  {_metric("Matched sign-in app", matched_app)}
</div>
<div class="ztvp-grid-3">
  {_metric("Decoy user", (report.get("decoy_user") or {}).get("user_principal_name") or "N/A")}
  {_metric("Completed UTC", report.get("completed_utc") or run.get("completed_utc") or "N/A")}
</div>
""",
        unsafe_allow_html=True,
    )

    if no_evidence:
        _alert("Monitoring window ended. ZTVP did not find a matching unmanaged-device sign-in after the validation start time.", "warn")
        st.write(
            "ZTVP waited for the configured monitoring window, but Entra did not return a matching unmanaged-device sign-in for the decoy user and target app. "
            "The test action may not have been performed, may have used the wrong account/app, or the sign-in log may be delayed."
        )
        _alert("Nothing was confirmed from tenant evidence. Increase the monitoring window, verify that the decoy user performed the login, and confirm the selected target app.", "warn")
        _render_polling_summary(report, run)
        _render_polling_details(report)
        st.markdown("#### Recommended next step")
        for item in _no_evidence_recommendations():
            st.markdown(f"- {item}")
    elif verdict == "PASS":
        _alert("PASS — Unmanaged device access was blocked by device-trust enforcement.", "good")
    elif verdict == "FAIL":
        _alert("FAIL — The decoy user accessed the target cloud app without a matching device-trust Conditional Access block.", "bad")
    elif verdict == "CANCELLED":
        _alert("CANCELLED — Run cancelled by user.", "warn")
    elif verdict == "ERROR":
        _alert("ERROR — The validation stopped because a technical error occurred.", "bad")
    else:
        _alert("PARTIAL — A sign-in was found, but the Conditional Access or device-trust evidence was incomplete.", "warn")

    if _has_target_app_mismatch(sign_in):
        _alert("Sign-in was found, but it did not match the selected target app.", "warn")

    if not no_evidence:
        st.write(ca.get("conclusion") or report.get("final_claim") or report.get("executive_summary") or "")

    col1, col2, col3 = st.columns(3)
    with col1:
        if html_path is not None:
            st.download_button("View HTML report", html_path.read_bytes(), html_path.name, "text/html", use_container_width=True, key="devdv001_final_view_html")
        else:
            st.button("View HTML report", disabled=True, use_container_width=True, key="devdv001_final_view_html_missing")
    with col2:
        if html_path is not None:
            st.download_button("Download HTML report", html_path.read_bytes(), html_path.name, "text/html", use_container_width=True, key="devdv001_final_download_html")
        else:
            st.button("Download HTML report", disabled=True, use_container_width=True, key="devdv001_final_download_html_missing")
    with col3:
        st.download_button("Download JSON evidence", report_path.read_bytes(), report_path.name, "application/json", use_container_width=True, key="devdv001_final_download_json")

    with st.expander("Technical evidence details", expanded=False):
        st.json(report)
    return True


def _write_html_report(report: dict, html_path: Path) -> None:
    write_standard_html_report(report, html_path)


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "devdv001") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    selected = sign_in.get("selected_event", {}) or {}
    device = sign_in.get("device_detail", {}) or selected.get("device_detail", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    target = report.get("target", {}) or {}
    matched_app = _matched_sign_in_app(sign_in)
    no_evidence = _is_no_signin_evidence(report)

    successful_count = int(metrics.get("successful_sign_in_count") or sign_in.get("successful_sign_in_count") or 0)
    failed_count = int(metrics.get("failed_sign_in_count") or sign_in.get("failed_sign_in_count") or 0)
    matching_count = int(metrics.get("matching_sign_in_count") or sign_in.get("matching_sign_in_count") or 0)
    device_trust_failures = int(metrics.get("device_trust_failure_count") or sign_in.get("device_trust_failure_count") or 0)

    is_fail = str(status or "").startswith("FAIL")
    is_pass = str(status or "").startswith("PASS")

    _alert("DEV-DV-001 report loaded.", _tone(status))
    if no_evidence:
        st.markdown("### PARTIAL — No matching tenant sign-in evidence found")
        _alert("Monitoring window ended. ZTVP did not find a matching unmanaged-device sign-in after the validation start time.", "warn")
        st.write(
            "ZTVP waited for the configured monitoring window, but Entra did not return a matching unmanaged-device sign-in for the decoy user and target app. "
            "The test action may not have been performed, may have used the wrong account/app, or the sign-in log may be delayed."
        )

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Access Attempt Found", "No" if no_evidence else metrics.get("sign_in_log_found", False), "warn" if no_evidence or not metrics.get("sign_in_log_found") else "good")}
  {_metric("Successful Access", "Not available" if no_evidence else successful_count, "warn" if no_evidence else "bad" if successful_count else "good")}
</div>
<div class="ztvp-grid">
  {_metric("Matching Sign-ins", matching_count, "warn" if no_evidence else "")}
  {_metric("Failed / Interrupted", "Not available" if no_evidence else failed_count, "warn" if no_evidence or failed_count else "")}
  {_metric("Device-Trust Blocks", "Not available" if no_evidence else device_trust_failures, "warn" if no_evidence else "good" if device_trust_failures else "bad")}
  {_metric("Effective policy", "Not available" if no_evidence else ca.get("effective_policy") or "None", "warn" if no_evidence else "good" if ca.get("effective_policy") and ca.get("effective_policy") != "None found" else "bad")}
</div>
<div class="ztvp-grid-3">
  {_metric("Target app selected", target.get("name") or report.get("target_app") or "N/A")}
  {_metric("Target URL used", target.get("url") or "N/A")}
  {_metric("Matched sign-in app", matched_app)}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")

    if no_evidence:
        _alert("Nothing was confirmed from tenant evidence. Increase the monitoring window, verify that the decoy user performed the login, and confirm the selected target app.", "warn")
        _render_polling_summary(report)
        _render_polling_details(report)
        st.markdown("#### Recommended next step")
        for item in _no_evidence_recommendations():
            st.markdown(f"- {item}")
    elif is_fail:
        _alert(
            "FAIL: The decoy user successfully accessed Microsoft 365/My Apps. No enforced compliant-device or managed-device policy blocked this unmanaged/unknown device access path.",
            "bad",
        )
    elif is_pass:
        _alert(
            "PASS: The unmanaged-device access attempt was blocked by an enforced device-trust Conditional Access policy.",
            "good",
        )
    else:
        _alert(
            "PARTIAL: ZTVP found sign-in evidence, but the result could not be fully classified as a device-trust pass or fail.",
            "warn",
        )

    if _has_target_app_mismatch(sign_in):
        _alert("Sign-in was found, but it did not match the selected target app.", "warn")

    if not no_evidence:
        st.write(report.get("executive_summary", ""))
        st.caption(report.get("final_claim", ""))

    rows = [
        {
            "Evidence": "Main result",
            "Value": _friendly_status(status),
            "Meaning": "This is the validation verdict.",
        },
        {
            "Evidence": "Expected behavior",
            "Value": "Unmanaged or non-compliant device access should be blocked.",
            "Meaning": "ZTVP detects the actual blocking reason from Entra sign-in logs and Conditional Access evidence.",
        },
        {
            "Evidence": "Detected blocking reason",
            "Value": "No matching sign-in evidence was found before timeout" if no_evidence else str(sign_in.get("status_failure_reason") or sign_in.get("status_additional_details") or selected.get("status_failure_reason") or "Not found"),
            "Meaning": "This is the reason reported by Entra for the selected sign-in, when available.",
        },
        {
            "Evidence": "Conditional Access result",
            "Value": "Not available" if no_evidence else str(sign_in.get("conditional_access_status") or selected.get("conditional_access_status") or "Unknown"),
            "Meaning": "This is the Conditional Access status on the selected sign-in.",
        },
        {
            "Evidence": "Successful sign-ins",
            "Value": str(successful_count),
            "Meaning": "If this is greater than 0, the unmanaged access path was allowed.",
        },
        {
            "Evidence": "Device-trust blocks",
            "Value": str(device_trust_failures),
            "Meaning": "PASS requires at least one enforced compliant-device / managed-device block and no successful access.",
        },
        {
            "Evidence": "Effective device policy",
            "Value": "Not available" if no_evidence else str(ca.get("effective_policy") or "None"),
            "Meaning": "None means no enforced device-trust policy protected this sign-in.",
        },
        {
            "Evidence": "MFA result",
            "Value": "MFA satisfied" if "MFA" in str(sign_in.get("status_additional_details", "")) or "MFA" in str(selected.get("status_additional_details", "")) else "Not the main control",
            "Meaning": "MFA can succeed, but MFA is not device compliance or device management.",
        },
        {
            "Evidence": "Device managed",
            "Value": "Unknown" if no_evidence else str(device.get("is_managed") or "Not proven / unknown"),
            "Meaning": "Empty/None means Entra did not prove this was a managed device.",
        },
        {
            "Evidence": "Device compliant",
            "Value": "Unknown" if no_evidence else str(device.get("is_compliant") or "Not proven / unknown"),
            "Meaning": "Empty/None means Entra did not prove this was a compliant device.",
        },
        {
            "Evidence": "Target app selected",
            "Value": target.get("name", ""),
            "Meaning": "Configured app for this DEV-DV-001 run.",
        },
        {
            "Evidence": "Target URL used",
            "Value": target.get("url", ""),
            "Meaning": target.get("url", ""),
        },
        {
            "Evidence": "Matched sign-in app from Entra logs",
            "Value": matched_app,
            "Meaning": f"{sign_in.get('app_display_name', '')} → {sign_in.get('resource_display_name', '')}",
        },
        {
            "Evidence": "Selected sign-in time",
            "Value": _fmt_graph_time(sign_in.get("created_date_time", "")),
            "Meaning": "Timestamp of the selected Entra sign-in event.",
        },
    ]

    st.markdown("#### Evidence summary")
    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    all_events = sign_in.get("all_matching_sign_ins", []) or []
    if all_events:
        st.markdown("#### Sign-ins used by ZTVP")

        event_rows = []
        for e in all_events:
            success = bool(e.get("is_success"))
            error = str(e.get("status_error_code", ""))
            reason = str(e.get("status_failure_reason", ""))

            if success:
                meaning = "Access allowed"
            elif error == "50140" or "Keep me signed in" in reason:
                meaning = "Login prompt interruption, not a device-trust block"
            elif e.get("device_trust_policies"):
                meaning = "Blocked by device-trust policy"
            elif e.get("blocking_policies"):
                meaning = "Blocked by non-device or unclassified CA policy"
            else:
                meaning = "Failed / interrupted"

            event_rows.append({
                "Time": _fmt_graph_time(e.get("created_date_time")),
                "App": e.get("app_display_name"),
                "Resource": e.get("resource_display_name"),
                "Success": success,
                "CA status": e.get("conditional_access_status"),
                "Error": error,
                "Meaning": meaning,
            })

        st.dataframe(pd.DataFrame(event_rows).astype(str), use_container_width=True, hide_index=True)

    policies = sign_in.get("applied_conditional_access_policies", []) or []
    if policies:
        enforced = []
        report_only = []
        not_applied = []

        for p in policies:
            result = str(p.get("result", ""))
            row = {
                "Policy": p.get("display_name"),
                "Result": result,
                "Grant controls": ", ".join([str(x) for x in (p.get("enforced_grant_controls") or [])]),
                "Session controls": ", ".join([str(x) for x in (p.get("enforced_session_controls") or [])]),
            }

            if result in ("success", "failure"):
                enforced.append(row)
            elif result.startswith("reportOnly"):
                report_only.append(row)
            else:
                not_applied.append(row)

        st.markdown("#### Conditional Access interpretation")

        if enforced:
            st.markdown("**Policies that actually applied**")
            st.dataframe(pd.DataFrame(enforced).astype(str), use_container_width=True, hide_index=True)
            st.caption("Only policies that affected the tested sign-in are shown here. MFA alone does not prove device trust.")
        else:
            _alert("No enforced Conditional Access policy applied to this selected sign-in.", "bad")

        if report_only:
            st.markdown("**Report-only policies detected**")
            st.dataframe(pd.DataFrame(report_only).astype(str), use_container_width=True, hide_index=True)
            st.caption("Report-only policies do not block access. They are visibility-only.")

        with st.expander("Policies that did not apply"):
            if not_applied:
                st.dataframe(pd.DataFrame(not_applied).astype(str), use_container_width=True, hide_index=True)
            else:
                st.write("No not-applied policies listed.")

    recs = report.get("recommendations", []) or []
    if recs:
        st.markdown("#### What to fix")
        for rec in recs:
            st.markdown(f"- {rec}")

    st.markdown("#### Clean conclusion")
    if is_fail:
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — Device-trust policy not enforced.</strong><br>
The test user reached Microsoft 365 from an unmanaged or unknown device context.
To make this scenario PASS, create or enforce a Conditional Access policy requiring a compliant or managed device for this user and target app.
</div>
""",
            unsafe_allow_html=True,
        )
    elif is_pass:
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — Unmanaged device access blocked.</strong><br>
The unmanaged-device access path was blocked by device-trust enforcement.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — More evidence required.</strong><br>
The test produced evidence, but the final device-trust decision is not fully proven.
</div>
""",
            unsafe_allow_html=True,
        )

    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "DEV-DV-001-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json",
        )

    with col2:
        st.download_button(
            "Download HTML Report",
            html_path.read_bytes(),
            "DEV-DV-001-result.html",
            "text/html",
            use_container_width=True,
            key=f"{key_prefix}_html",
        )



def render_devdv001_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV001.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV001.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV001.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-001"
    state_path = scenario_dir / "devdv001-state.json"
    prepare_path = scenario_dir / "devdv001-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-001-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-001-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-001 — Unmanaged Device Cloud Access Probe</h2>
  <p>Create a decoy user, attempt Microsoft 365 access from a clean unmanaged VM or InPrivate browser, then inspect Entra sign-in logs.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("This validates device trust. Use a clean VM or InPrivate browser that is not Entra joined, not Intune enrolled, and not compliant.", "info")

    requested_run_id = str(st.session_state.get("ztvp_dynamic_open_run_id") or "")
    selected_run = selected_run_for_scenario(project_root, "DEV-DV-001", requested_run_id)
    active_run = get_active_run(project_root, "DEV-DV-001", requested_run_id) if requested_run_id else get_active_run(project_root, "DEV-DV-001")
    if active_run:
        _render_active_run(project_root, active_run)
        return

    latest_run = selected_run or latest_run_for_scenario(project_root, "DEV-DV-001")
    if latest_run and str(latest_run.get("status") or "").lower() in ACTIVE_STATUSES and is_stale(latest_run):
        update_run(
            project_root,
            str(latest_run.get("run_id") or ""),
            status="stale",
            phase="Interrupted",
            current_message="Run was interrupted because the app process stopped.",
        )
        latest_run = selected_run_for_scenario(project_root, "DEV-DV-001", requested_run_id) or latest_run_for_scenario(project_root, "DEV-DV-001")
    if latest_run and str(latest_run.get("status") or "").lower() == "stale":
        _alert("Run was interrupted because the app process stopped. You can start a fresh analysis window or resume from Active Runs if available.", "warn")
    elif latest_run and str(latest_run.get("status") or "").lower() in {"completed", "cancelled", "error", "timeout"}:
        _render_final_run_output(project_root, latest_run)

    target_summary = "Microsoft 365 Portal"
    if state_path.exists():
        state_for_summary = _load_json(state_path)
        target_summary = (state_for_summary.get("target") or {}).get("name") or target_summary
    else:
        target_option_summary = str(st.session_state.get("devdv001_target_name", target_summary))
        if target_option_summary == "Custom URL / custom app name":
            target_summary = str(st.session_state.get("devdv001_custom_target_name", "Custom Microsoft 365 app"))
        elif target_option_summary in {
            "Microsoft 365 Portal",
            "Microsoft 365 My Apps",
            "SharePoint Online",
            "Exchange Online",
            "Entra Portal",
        }:
            target_summary = target_option_summary

    st.markdown("### Step 1 — Create decoy user")
    st.write("ZTVP will create a temporary normal test user for this validation.")
    st.markdown(f"**Target app:** {target_summary}")
    st.markdown("**Expected behavior:** access from an unmanaged or non-compliant device should be blocked.")

    if not state_path.exists():
        target_map = {
            "Microsoft 365 Portal": "https://microsoft365.com",
            "Microsoft 365 My Apps": "https://myapps.microsoft.com",
            "SharePoint Online": "",
            "Exchange Online": "https://outlook.office.com",
            "Entra Portal": "https://entra.microsoft.com",
        }

        user_prefix = "ztvp-devdv001-decoy"
        display_name = "ZTVP DEV-DV-001 Unmanaged Device Decoy User"
        tenant_domain = ""
        target_name = "Microsoft 365 Portal"
        target_url = target_map[target_name]
        expected_policy = ""

        user_prefix = str(st.session_state.get("devdv001_user_prefix", user_prefix))
        display_name = str(st.session_state.get("devdv001_display_name", display_name))
        tenant_domain = str(st.session_state.get("devdv001_tenant_domain", tenant_domain))
        target_option = str(st.session_state.get("devdv001_target_name", target_name))
        if target_option == "Custom URL / custom app name":
            target_name = str(st.session_state.get("devdv001_custom_target_name", "Custom Microsoft 365 app"))
            target_url = str(st.session_state.get("devdv001_custom_target_url", "https://microsoft365.com"))
        elif target_option == "SharePoint Online":
            target_name = target_option
            target_url = str(st.session_state.get("devdv001_sharepoint_target_url", "")).strip()
        else:
            target_name = target_option if target_option in target_map else target_name
            target_url = target_map[target_name]

        expected_policy_option = str(st.session_state.get("devdv001_expected_policy_option", "Let ZTVP detect from sign-in logs"))
        if expected_policy_option == "Any device-trust Conditional Access policy":
            expected_policy = "device trust"
        elif expected_policy_option != "Let ZTVP detect from sign-in logs":
            expected_policy = expected_policy_option

        if st.button("Create decoy user", type="primary", use_container_width=True):
            args = [
                "-UserPrefix", user_prefix.strip(),
                "-DisplayName", display_name.strip(),
                "-TargetName", target_name,
                "-TargetUrl", target_url,
            ]

            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            if expected_policy.strip():
                args.extend(["-ExpectedBlockingPolicy", expected_policy.strip()])

            with st.spinner("Creating DEV-DV-001 decoy user..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("Decoy preparation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            _alert("Decoy user prepared.", "good")
            st.rerun()

        with st.expander("Advanced settings", expanded=False):
            user_prefix = st.text_input(
                "Decoy username prefix",
                value=user_prefix,
                key="devdv001_user_prefix",
                help="Used to generate the temporary test user's UPN.",
            )
            display_name = st.text_input(
                "Decoy display name",
                value=display_name,
                key="devdv001_display_name",
                help="Shown on the temporary Entra user object.",
            )
            tenant_domain = st.text_input(
                "Tenant domain override optional",
                value="",
                placeholder="",
                key="devdv001_tenant_domain",
                help="Leave empty unless auto-detection fails.",
            )
            st.caption("Leave empty unless auto-detection fails.")
            target_option = st.selectbox(
                "Target app override",
                ["Microsoft 365 Portal", "Microsoft 365 My Apps", "SharePoint Online", "Exchange Online", "Entra Portal", "Custom URL / custom app name"],
                index=0,
                key="devdv001_target_name",
                help="Used only to match the correct sign-in log.",
            )
            st.caption("Used only to match the correct Entra sign-in log.")

            if target_option == "Custom URL / custom app name":
                target_name = st.text_input(
                    "Custom app name",
                    value="Custom Microsoft 365 app",
                    key="devdv001_custom_target_name",
                    help="Used in the report and sign-in matching context.",
                )
                target_url = st.text_input(
                    "Custom URL",
                    value="https://microsoft365.com",
                    key="devdv001_custom_target_url",
                    help="Open this URL during the unmanaged access attempt.",
                )
            elif target_option == "SharePoint Online":
                target_name = target_option
                target_url = st.text_input(
                    "SharePoint URL override optional",
                    value=target_url,
                    placeholder="https://<tenant-name>.sharepoint.com",
                    key="devdv001_sharepoint_target_url",
                    help="Leave empty so ZTVP derives the tenant SharePoint root URL after tenant detection.",
                )
                st.caption("Leave empty to use the tenant SharePoint root URL, for example https://<tenant>.sharepoint.com.")
            else:
                target_name = target_option
                target_url = target_map[target_option]

            expected_policy_option = st.selectbox(
                "Expected blocking override",
                [
                    "Let ZTVP detect from sign-in logs",
                    "Any device-trust Conditional Access policy",
                    "Require compliant device",
                    "Require hybrid joined device",
                    "Require managed device",
                    "Block unmanaged devices",
                    "Require approved client app",
                    "Require app protection policy",
                    "Require MFA + compliant device",
                ],
                index=0,
                key="devdv001_expected_policy_option",
                help="Use only for troubleshooting. ZTVP normally detects the actual Conditional Access/device-trust result automatically.",
            )
            st.caption("Use only for troubleshooting. ZTVP normally detects the actual Conditional Access/device-trust result automatically.")

            if expected_policy_option == "Any device-trust Conditional Access policy":
                expected_policy = "device trust"
            elif expected_policy_option != "Let ZTVP detect from sign-in logs":
                expected_policy = expected_policy_option
    else:
        pass

    if prepare_path.exists():
        prep = _load_json(prepare_path)
        instructions = (
            "1. Open Windows Sandbox or an InPrivate browser.\n"
            f"2. Go to {prep.get('target_name', 'Target app')}: {prep.get('target_url', '')}\n"
            f"3. Sign in as the decoy user:\n   {prep.get('decoy_user_principal_name', '')}\n   {prep.get('decoy_temporary_password', '')}\n"
            "4. Confirm whether access is blocked.\n"
            "5. Return to ZTVP."
        )
        _alert("Decoy user ready", "good")
        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Decoy UPN", prep.get("decoy_user_principal_name", ""))}
  {_metric("Temporary Password", prep.get("decoy_temporary_password", ""), "warn")}
  {_metric("Target URL", prep.get("target_url", ""))}
</div>
""",
            unsafe_allow_html=True,
        )
        st.markdown("**Copy Sandbox login instructions**")
        st.code(instructions, language="text")
        with st.expander("Technical details", expanded=False):
            st.markdown(
                f"""
<div class="ztvp-grid-3">
  {_metric("Tenant ID", prep.get("tenant_id", ""))}
  {_metric("Target app", prep.get("target_name", "Microsoft 365 Portal"))}
  {_metric("State file", state_path)}
</div>
""",
                unsafe_allow_html=True,
            )

    st.markdown("### Step 2 — Start validation window and perform unmanaged access")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        target = state.get("target", {}) or {}
        probe = state.get("unmanaged_probe", {}) or {}
        window_start = probe.get("validation_window_start_utc", "")

        _alert(
            "Important: before every new test, start a fresh validation window. ZTVP will ignore old sign-ins and only analyze logs after that time.",
            "info",
        )

        if window_start:
            _alert(f"Fresh validation window active: {window_start}", "good")
        else:
            _alert("No fresh validation window active yet. Click the button below before doing the VM login.", "warn")

        if st.button("Start fresh validation window", type="primary", use_container_width=True):
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state.setdefault("unmanaged_probe", {})
            state["unmanaged_probe"]["validation_window_start_utc"] = now_utc
            state["unmanaged_probe"]["validation_window_started_at_local"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _write_json(state_path, state)
            _alert(f"Fresh validation window started at {now_utc}. Now do the VM/InPrivate login.", "good")
            st.rerun()

        st.code(
            f"1. Open Windows Sandbox or an InPrivate browser.\n"
            f"2. Go to {target.get('name', 'Target app')}: {target.get('url', '')}\n"
            f"3. Sign in as the decoy user:\n   {decoy.get('user_principal_name', '')}\n   {decoy.get('temporary_password', '')}\n"
            f"4. Confirm whether access is blocked.\n"
            f"5. Return to ZTVP.",
            language="text",
        )

    st.markdown("### Step 3 — Analyze sign-in logs")

    state_for_analysis = _load_json(state_path) if state_path.exists() else {}
    probe_for_analysis = state_for_analysis.get("unmanaged_probe", {}) or {}
    validation_window_start = probe_for_analysis.get("validation_window_start_utc", "")

    col_l1, col_l2, col_l3 = st.columns(3)

    with col_l1:
        lookback_hours = st.slider(
            "Lookback hours",
            min_value=1,
            max_value=72,
            value=4,
            step=1,
            key="devdv001_lookback_hours",
            help="ZTVP checks Entra logs during this time window and ignores logs older than the fresh validation window.",
        )
        st.caption("ZTVP checks Entra logs during this time window.")

    with col_l2:
        wait_minutes = st.slider(
            "Monitoring window minutes",
            min_value=2,
            max_value=90,
            value=15,
            step=1,
            key="devdv001_wait_minutes",
            help="ZTVP keeps polling until matching evidence is found or this window ends.",
        )
        st.caption("ZTVP stops early when matching evidence is found.")

    with col_l3:
        poll_seconds = st.slider(
            "Check logs every seconds",
            min_value=10,
            max_value=60,
            value=30,
            step=10,
            key="devdv001_poll_seconds",
            help="ZTVP keeps checking until the new sign-in log appears.",
        )
        st.caption("Controls how often ZTVP checks for the fresh sign-in event.")

    if validation_window_start:
        _alert(
            f"Ready. ZTVP will wait until a new meaningful sign-in appears after: {validation_window_start}",
            "good",
        )
    else:
        _alert("Start a Fresh Validation Window in Step 2 first. Then do the VM login. Then analyze.", "bad")

    if st.button("Analyze sign-in logs", use_container_width=True):
        if not validation_window_start:
            _alert("Start a fresh validation window first, then do the VM login, then analyze.", "bad")
            return

        state_for_analysis["lookback_hours"] = int(lookback_hours)
        state_for_analysis["wait_minutes"] = int(wait_minutes)
        state_for_analysis["poll_seconds"] = int(poll_seconds)
        _write_json(state_path, state_for_analysis)
        run = start_scenario_job(project_root, "DEV-DV-001", int(wait_minutes), int(poll_seconds))
        _render_active_run(project_root, run)
        st.stop()

    if report_path.exists() and not (latest_run and latest_run.get("report_path")):
        st.markdown("### Latest DEV-DV-001 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="devdv001_latest")

    st.markdown("### Step 4 — Cleanup")

    if not state_path.exists():
        _alert("No active DEV-DV-001 decoy state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}

        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Cleanup", "Pending", "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Delete decoy user", use_container_width=True):
            with st.spinner("Cleaning DEV-DV-001 decoy user..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)

            if completed.returncode != 0:
                _alert("DEV-DV-001 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("DEV-DV-001 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()



