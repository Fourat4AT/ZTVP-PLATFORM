from __future__ import annotations

import html
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from background_jobs import start_scenario_job
from run_state import ACTIVE_STATUSES, request_cancel, selected_run_for_scenario


STATUS_LABELS = {
    "PASS_USER_CONSENT_BLOCKED": "PASS — User Consent Blocked",
    "PASS_NO_OAUTH_GRANT_CREATED": "PASS — No OAuth Grant Created",
    "FAIL_USER_CONSENT_ALLOWED": "FAIL — User Consent Allowed",
    "PARTIAL_SIGNIN_INTERRUPTED": "PARTIAL — Sign-in Interrupted",
    "PARTIAL_ACCEPTED_BUT_NO_GRANT_FOUND": "PARTIAL — Accepted but No Grant Found",
    "PARTIAL_NO_ATTEMPT_EVIDENCE": "PARTIAL — No Attempt Evidence",
}

OBSERVED_OUTCOMES = {
    "Not recorded yet": "NOT_RECORDED",
    "Microsoft showed: Need admin approval / approval required": "ADMIN_APPROVAL_REQUIRED",
    "Microsoft showed: consent blocked / organization does not allow it": "CONSENT_BLOCKED",
    "User accepted consent and reached redirect page": "USER_ACCEPTED_CONSENT",
    "Sign-in was interrupted before consent decision": "SIGNIN_INTERRUPTED",
}


def _safe(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _friendly_status(status: object) -> str:
    return STATUS_LABELS.get(str(status or ""), str(status or "Unknown"))


def _tone_for_status(status: object) -> str:
    text = str(status or "").upper()

    if text.startswith("PASS"):
        return "good"

    if text.startswith("FAIL"):
        return "bad"

    return "warn"


def _normalize_records(value: Any) -> list[dict]:
    if value is None:
        return []

    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    if isinstance(value, dict):
        return [value]

    return []


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 1200) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            *args,
        ],
        cwd=str(project_root),
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero {
    background: linear-gradient(135deg, #111827 0%, #7c3aed 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #ede9fe; line-height: 1.55; }
.ztvp-step { display: flex; align-items: center; gap: 0.75rem; margin: 1.35rem 0 0.75rem 0; }
.ztvp-step-number { width: 34px; height: 34px; border-radius: 999px; background: #7c3aed; color: #ffffff; display: inline-flex; align-items: center; justify-content: center; font-weight: 900; }
.ztvp-step h3 { margin: 0; color: #0f172a; font-size: 1.16rem; font-weight: 900; }
.ztvp-alert { border-radius: 16px; padding: 0.92rem 1rem; margin: 0.75rem 0 1rem 0; font-weight: 650; line-height: 1.5; }
.ztvp-info { background: #f5f3ff; border: 1px solid #8b5cf6; color: #2e1065; }
.ztvp-warn { background: #fffbeb; border: 1px solid #f59e0b; color: #78350f; }
.ztvp-good { background: #ecfdf5; border: 1px solid #10b981; color: #064e3b; }
.ztvp-bad { background: #fef2f2; border: 1px solid #ef4444; color: #7f1d1d; }
.ztvp-field-note { color: #475569; font-size: 0.86rem; line-height: 1.45; margin: 0.45rem 0 0.25rem 0; }
.ztvp-roadmap { background: #ffffff; border: 1px solid #ddd6fe; border-radius: 16px; padding: 1rem; margin: 0.9rem 0 1rem 0; }
.ztvp-roadmap h3 { margin: 0 0 0.6rem 0; color: #2e1065; font-size: 1rem; font-weight: 900; }
.ztvp-roadmap-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; }
.ztvp-roadmap-item { border-left: 4px solid #7c3aed; background: #faf5ff; padding: 0.75rem; border-radius: 10px; color: #312e81; line-height: 1.4; }
.ztvp-roadmap-item strong { display: block; color: #111827; font-size: 0.9rem; margin-bottom: 0.2rem; }
.ztvp-roadmap-proof { margin: 0.85rem 0 0 0; color: #334155; line-height: 1.5; }
.ztvp-codebox { background: #0f172a; color: #ffffff; border-radius: 16px; padding: 0.95rem 1rem; font-family: Consolas, monospace; font-size: 0.93rem; overflow-x: auto; margin: 0.75rem 0; }
.ztvp-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.85rem; margin-bottom: 1rem; }
.ztvp-grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.85rem; margin-bottom: 1rem; }
.ztvp-metric { background: #ffffff; border: 1px solid #dbe3ef; border-radius: 18px; padding: 1rem; box-shadow: 0 8px 18px rgba(15, 23, 42, 0.05); }
.ztvp-metric span { display: block; color: #64748b; font-size: 0.78rem; font-weight: 800; margin-bottom: 0.45rem; }
.ztvp-metric strong { color: #0f172a; font-size: 1.10rem; font-weight: 950; word-break: break-word; }
.ztvp-metric.good strong { color: #15803d; }
.ztvp-metric.warn strong { color: #b45309; }
.ztvp-metric.bad strong { color: #b91c1c; }
div.stButton > button,
div[data-testid="stButton"] button,
div.stDownloadButton > button,
div[data-testid="stDownloadButton"] button {
    border-radius: 14px !important;
    min-height: 44px !important;
    font-weight: 850 !important;
}
div.stButton > button,
div[data-testid="stButton"] button,
button[kind="primary"],
button[data-testid="baseButton-primary"],
button[data-testid="stBaseButton-primary"] {
    background: #7c3aed !important;
    color: #ffffff !important;
    border: 1px solid #7c3aed !important;
}
div.stButton > button:hover,
div[data-testid="stButton"] button:hover,
button[kind="primary"]:hover,
button[data-testid="baseButton-primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #6d28d9 !important;
    border-color: #6d28d9 !important;
    color: #ffffff !important;
}
div.stDownloadButton > button,
div[data-testid="stDownloadButton"] button {
    background: #ffffff !important;
    color: #6d28d9 !important;
    border: 1px solid #ddd6fe !important;
}
@media (max-width: 900px) { .ztvp-grid, .ztvp-grid-3, .ztvp-roadmap-grid { grid-template-columns: 1fr; } }
</style>
""",
        unsafe_allow_html=True,
    )


def _step(number: int, title: str) -> None:
    st.markdown(
        f"""
<div class="ztvp-step">
    <div class="ztvp-step-number">{number}</div>
    <h3>{_safe(title)}</h3>
</div>
""",
        unsafe_allow_html=True,
    )


def _alert(message: str, tone: str = "info") -> None:
    st.markdown(
        f"""
<div class="ztvp-alert ztvp-{tone}">
{_safe(message)}
</div>
""",
        unsafe_allow_html=True,
    )


def _field_note(message: str) -> None:
    st.markdown(f'<div class="ztvp-field-note">{_safe(message)}</div>', unsafe_allow_html=True)


def _metric(label: str, value: object, tone: str = "") -> str:
    return f"""
<div class="ztvp-metric {tone}">
    <span>{_safe(label)}</span>
    <strong>{_safe(value)}</strong>
</div>
"""


def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    grants = _normalize_records(report.get("oauth_grants"))
    signins = _normalize_records(report.get("sign_in_evidence"))
    warnings = report.get("warnings", []) or []
    display_status = _friendly_status(report.get("status"))

    grant_rows = ""

    for row in grants:
        grant_rows += f"""
<tr>
<td>{_safe(row.get("consentType"))}</td>
<td>{_safe(row.get("scope"))}</td>
<td>{_safe(row.get("principalId"))}</td>
<td>{_safe(row.get("resourceId"))}</td>
</tr>
"""

    if not grant_rows:
        grant_rows = '<tr><td colspan="4">No OAuth permission grant was found for the controlled test app.</td></tr>'

    signin_rows = ""

    for row in signins:
        signin_rows += f"""
<tr>
<td>{_safe(row.get("createdDateTime"))}</td>
<td>{_safe(row.get("appDisplayName"))}</td>
<td>{_safe(row.get("resourceDisplayName"))}</td>
<td>{_safe(row.get("conditionalAccessStatus"))}</td>
<td>{_safe(row.get("errorCode"))}</td>
<td>{_safe(row.get("failureReason"))}</td>
</tr>
"""

    if not signin_rows:
        signin_rows = '<tr><td colspan="6">No matching decoy sign-in evidence was found yet.</td></tr>'

    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated.</li>"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#111827,#7c3aed); color:white; padding:34px; border-radius:26px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:20px; }}
.metric,.card {{ background:white; border:1px solid #dbe3ef; border-radius:20px; padding:20px; margin-top:18px; }}
.metric span {{ color:#64748b; font-size:13px; font-weight:700; }}
.metric strong {{ display:block; font-size:22px; margin-top:8px; }}
table {{ width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; }}
th {{ background:#0f172a; color:white; text-align:left; padding:10px; }}
td {{ border-bottom:1px solid #e2e8f0; padding:10px; }}
pre {{ background:#0f172a; color:#e5e7eb; padding:18px; border-radius:16px; overflow:auto; }}
.footer {{ color:#64748b; font-size:13px; margin-top:24px; }}
</style>
</head>
<body>
<div class="container">
<div class="hero">
<h1>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</h1>
<p>OAuth App Consent Exposure Evidence Report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(display_status)}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>OAuth Grant Created</span><strong>{_safe(metrics.get("oauth_grant_created", False))}</strong></div>
<div class="metric"><span>Grant Count</span><strong>{_safe(metrics.get("oauth_grant_count", 0))}</strong></div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
<p><b>Evidence Quality:</b> {_safe(report.get("evidence_quality"))}</p>
</div>

<div class="card">
<h2>Test Application</h2>
<pre>{_safe(json.dumps(report.get("test_application", {}), indent=2))}</pre>
</div>

<div class="card">
<h2>OAuth Permission Grants</h2>
<table>
<thead>
<tr>
<th>Consent Type</th>
<th>Scope</th>
<th>Principal ID</th>
<th>Resource ID</th>
</tr>
</thead>
<tbody>
{grant_rows}
</tbody>
</table>
</div>

<div class="card">
<h2>Sign-in Evidence</h2>
<table>
<thead>
<tr>
<th>Created</th>
<th>App</th>
<th>Resource</th>
<th>CA Status</th>
<th>Error</th>
<th>Reason</th>
</tr>
</thead>
<tbody>
{signin_rows}
</tbody>
</table>
</div>

<div class="card">
<h2>Warnings</h2>
<ul>{warning_rows}</ul>
</div>

<div class="card">
<h2>Metrics</h2>
<pre>{_safe(json.dumps(metrics, indent=2))}</pre>
</div>

<div class="footer">
Generated by Zero Trust Validation Platform on {generated_at}.
</div>
</div>
</body>
</html>
"""

    html_path.write_text(html_doc, encoding="utf-8")


def _render_report(report: dict, report_path: Path, html_path: Path, stdout: str) -> None:
    metrics = report.get("metrics", {}) or {}
    grants = _normalize_records(report.get("oauth_grants"))
    signins = _normalize_records(report.get("sign_in_evidence"))
    audits = _normalize_records(report.get("directory_audit_evidence"))
    warnings = report.get("warnings", []) or []

    display_status = _friendly_status(report.get("status"))
    tone = _tone_for_status(report.get("status"))

    _alert("OAuth app consent validation completed.", "good" if tone == "good" else tone)

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", display_status, tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("OAuth grant created", "Yes" if metrics.get("oauth_grant_created") else "No", "bad" if metrics.get("oauth_grant_created") else "good")}
    {_metric("Grant count", metrics.get("oauth_grant_count", metrics.get("grant_count", 0)), "bad" if metrics.get("oauth_grant_created") else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    app = report.get("test_application", {}) or {}

    st.markdown("#### Tenant Evidence")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Controlled app display name", app.get("display_name", "N/A"))}
    {_metric("App ID", app.get("app_id", "N/A"))}
    {_metric("Service principal ID", app.get("service_principal_id", "N/A"))}
    {_metric("Requested scope", app.get("requested_scope", "N/A"))}
    {_metric("Evidence source", report.get("tenant_evidence_source", "Microsoft Graph oauth2PermissionGrant query"))}
    {_metric("Polls used", f"{metrics.get('poll_attempts', 0)} / {metrics.get('max_poll_attempts', 'N/A')}")}
</div>
""",
        unsafe_allow_html=True,
    )
    st.write(report.get("tenant_proof_text") or report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Evidence Interpretation")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Evidence Quality", report.get("evidence_quality", "Unknown"))}
    {_metric("Manual browser observation", report.get("observed_browser_outcome", "N/A"))}
    {_metric("Total search time", f"{metrics.get('total_evidence_search_time_seconds', 'N/A')} seconds")}
    {_metric("Poll interval", f"{metrics.get('poll_interval_seconds', 'N/A')} seconds")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### OAuth Permission Grant Evidence")

    if grants:
        df = pd.DataFrame(grants)
        cols = [c for c in ["consentType", "scope", "principalId", "resourceId", "applies_to_decoy"] if c in df.columns]
        st.dataframe(df[cols] if cols else df, use_container_width=True, hide_index=True)

        with st.expander("OAuth grant details"):
            st.json(grants)
    else:
        _alert("No OAuth permission grant was found for the controlled test app.", "good")

    st.markdown("#### Decoy Sign-in Evidence")

    if signins:
        df_signins = pd.DataFrame(signins)
        st.dataframe(df_signins, use_container_width=True, hide_index=True)
    else:
        _alert("No matching decoy sign-in evidence was found yet.", "warn")

    st.markdown("#### Directory Audit Evidence")

    if audits:
        df_audits = pd.DataFrame(audits)
        cols = [c for c in ["activityDateTime", "activityDisplayName", "category", "result", "resultReason"] if c in df_audits.columns]
        st.dataframe(df_audits[cols] if cols else df_audits, use_container_width=True, hide_index=True)

        with st.expander("Directory audit raw details"):
            st.json(audits)
    else:
        _alert("No matching directory audit evidence was found yet.", "info")

    if warnings:
        st.markdown("#### Warnings")
        for warning in warnings:
            _alert(warning, "warn")

    st.markdown("#### Export Evidence")

    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="ID-DV-004-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="ID-DV-004-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def _render_background_run_summary(project_root: Path, run: dict) -> None:
    status = str(run.get("status") or "").lower()
    if status in ACTIVE_STATUSES:
        st.info("ID-DV-004 OAuth grant evidence collection is running in Active Runs.")
    else:
        st.info("ID-DV-004 run state restored.")

    cols = st.columns(4)
    cols[0].metric("Phase", run.get("phase") or "Unknown")
    cols[1].metric("Progress", f"{int(run.get('progress_percent') or 0)}%")
    cols[2].metric("Polls", f"{run.get('poll_attempts') or 0} / {run.get('max_poll_attempts') or 'N/A'}")
    cols[3].metric("Tenant evidence", run.get("tenant_evidence_status") or "Waiting")
    st.caption(f"Evidence source: {run.get('current_evidence_source') or 'Microsoft Graph oauth2PermissionGrant query'}")
    if run.get("current_message"):
        st.write(run.get("current_message"))

    col_active, col_cancel = st.columns(2)
    if col_active.button("Open Active Runs", use_container_width=True, key=f"idc004_open_active_runs_{run.get('run_id') or 'latest'}"):
        st.session_state["pending_navigation"] = {"main_navigation": "Active Runs", "pending_main_navigation": "Active Runs"}
        st.session_state.pop("ztvp_dynamic_open_run_id", None)
        st.rerun()
    if status in ACTIVE_STATUSES and col_cancel.button("Cancel", use_container_width=True, key=f"idc004_cancel_active_run_{run.get('run_id') or 'latest'}"):
        request_cancel(project_root, str(run.get("run_id") or ""))
        st.rerun()

    if status in ACTIVE_STATUSES:
        return

    report_path = Path(str(run.get("report_json_path") or run.get("report_path") or ""))
    html_path = Path(str(run.get("report_html_path") or run.get("html_report_path") or ""))
    if report_path.exists():
        report = _load_json(report_path)
        if report:
            _render_report(report, report_path, html_path, "")


def render_idc004_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>ID-DV-004 — OAuth App Consent Exposure Validation</h2>
    <p>This validation creates a controlled test app and proves whether a standard decoy user can grant OAuth delegated permissions without administrator approval.</p>
</div>
<div class="ztvp-roadmap">
    <h3>Client Workflow</h3>
    <div class="ztvp-roadmap-grid">
        <div class="ztvp-roadmap-item"><strong>1. ZTVP prepares</strong>Creates a temporary user and a temporary test app.</div>
        <div class="ztvp-roadmap-item"><strong>2. Client tests</strong>Open the Microsoft consent link and sign in as the temporary user.</div>
        <div class="ztvp-roadmap-item"><strong>3. ZTVP verifies</strong>Checks if Microsoft created an app permission grant.</div>
        <div class="ztvp-roadmap-item"><strong>4. Report proves</strong>Shows whether normal users can approve apps without admin review.</div>
    </div>
    <p class="ztvp-roadmap-proof">Secure result: Microsoft blocks consent or asks for admin approval. Risky result: the user can accept and an OAuth grant is created.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    state_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-004"
    state_path = state_dir / "consent-state.json"
    secret_once_path = state_dir / "decoy-secret-once.json"

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC004Decoy.ps1"
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC004.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDC004Decoy.ps1"

    requested_run_id = st.session_state.get("ztvp_dynamic_open_run_id")
    active_or_selected_run = selected_run_for_scenario(project_root, "ID-DV-004", requested_run_id)
    if active_or_selected_run and str(active_or_selected_run.get("status") or "").lower() in ACTIVE_STATUSES:
        _render_background_run_summary(project_root, active_or_selected_run)
        return
    if active_or_selected_run and (requested_run_id or str(active_or_selected_run.get("status") or "").lower() == "completed"):
        _render_background_run_summary(project_root, active_or_selected_run)
        st.session_state.pop("ztvp_dynamic_open_run_id", None)
        st.session_state.pop("ztvp_dynamic_open_run_status", None)
        st.session_state.pop("ztvp_dynamic_open_report_path", None)

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    app = state.get("test_application", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    _step(1, "Create temporary user and test app")

    if has_active:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("Test Scope", app.get("requested_scope", "N/A"))}
    {_metric("Cleanup", cleanup.get("status", "Pending"), "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        st.markdown("**Exact decoy user**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(decoy.get("user_principal_name", ""))}</div>', unsafe_allow_html=True)

        st.markdown("**Controlled test application**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(app.get("display_name", ""))}<br>App ID: {_safe(app.get("app_id", ""))}</div>', unsafe_allow_html=True)

        with st.expander("View active ID-DV-004 state"):
            st.json(state)
    else:
        _alert("No active ID-DV-004 run exists. Generate a fresh decoy and temporary OAuth test app.", "info")

        with st.container(border=True):
            _alert("ZTVP will create two temporary things: a test user and a test app. You can usually leave these values unchanged.", "info")
            _field_note("Start of the temporary user's email/sign-in name. Leave the default unless you want a different test-user name.")
            prefix = st.text_input("Temporary user email prefix", value="ztvp-idc004-oauthconsent", key="idc004_prefix")
            _field_note("Name shown for the temporary user in Entra. This does not change the test.")
            display = st.text_input("Temporary user display name", value="ZTVP ID-DV-004 OAuth Consent Decoy User", key="idc004_display")
            _field_note("Name shown for the temporary test app. Leave the default so it is easy to find and clean up.")
            app_prefix = st.text_input("Temporary app name prefix", value="ZTVP ID-DV-004 OAuth Consent Test App", key="idc004_app_prefix")
            _field_note("Country code Microsoft requires before assigning a license. Keep TN for Tunisia. Use US for United States.")
            usage = st.text_input("Country code", value="TN", max_chars=2, key="idc004_usage")
            _field_note("Permission the test app will ask for. Leave User.Read; it only asks to read the signed-in user's basic profile.")
            requested_scope = st.text_input("Permission to request", value="https://graph.microsoft.com/User.Read", key="idc004_scope")

            if st.button("Generate Temporary User and Test App", type="primary", use_container_width=True):
                args = [
                    "-DecoyAliasPrefix", prefix.strip() or "ztvp-idc004-oauthconsent",
                    "-DecoyDisplayName", display.strip() or "ZTVP ID-DV-004 OAuth Consent Decoy User",
                    "-AppDisplayNamePrefix", app_prefix.strip() or "ZTVP ID-DV-004 OAuth Consent Test App",
                    "-UsageLocation", usage.strip().upper() or "TN",
                    "-RequestedScope", requested_scope.strip() or "https://graph.microsoft.com/User.Read",
                ]

                with st.spinner("Creating decoy user, app registration, service principal, and consent URL..."):
                    completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

                if completed.returncode != 0:
                    _alert("ID-DV-004 preparation failed.", "bad")
                    error_output = f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}"
                    st.code(error_output.strip() or "No PowerShell output captured.", language="text")
                else:
                    _alert("ID-DV-004 preparation completed.", "good")
                    st.code(completed.stdout, language="text")

                    if secret_once_path.exists():
                        secret = _load_json(secret_once_path)
                        st.session_state["idc004_temp_upn"] = secret.get("user_principal_name")
                        st.session_state["idc004_temp_password"] = secret.get("temporary_password")

                        try:
                            secret_once_path.unlink()
                        except Exception:
                            pass

                    st.rerun()

    if st.session_state.get("idc004_temp_password"):
        _alert("Temporary password is shown once. Copy it now. It will not be stored in the report.", "warn")
        st.markdown(
            f"""
<div class="ztvp-codebox">
UPN: {_safe(st.session_state.get("idc004_temp_upn"))}<br>
Password: {_safe(st.session_state.get("idc004_temp_password"))}
</div>
""",
            unsafe_allow_html=True,
        )

    _step(2, "Open Microsoft consent link")

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    app = state.get("test_application", {}) or {}
    consent = state.get("consent_attempt", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active:
        _alert("Generate the decoy and test app first.", "warn")
    else:
        _alert("Open the consent URL in a private browser. Sign in with the exact decoy user, not your admin account.", "info")

        consent_url = consent.get("consent_url", "")

        st.markdown("**Consent URL**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(consent_url)}</div>', unsafe_allow_html=True)

        if consent_url:
            st.markdown(
                f'<a href="{_safe(consent_url)}" target="_blank">Open Microsoft Consent URL</a>',
                unsafe_allow_html=True,
            )

        st.markdown("**Expected secure browser result**")
        st.markdown(
            """
<div class="ztvp-alert ztvp-good">
Microsoft should show admin approval required, consent blocked, or your organization does not allow user consent. No OAuth grant should be created.
</div>
""",
            unsafe_allow_html=True,
        )

    _step(3, "Check whether consent was allowed")

    if not has_active:
        _alert("This step unlocks after the decoy and test app exist.", "warn")
    else:
        _field_note("After you open the Microsoft consent link, choose what you saw on the screen.")
        outcome_label = st.selectbox(
            "What did the browser show?",
            options=list(OBSERVED_OUTCOMES.keys()),
            index=0,
            key="idc004_observed_outcome",
        )

        _field_note("How many minutes of OAuth and sign-in logs to search. 240 means the last 4 hours.")
        lookback = st.number_input(
            "Evidence lookback minutes",
            min_value=15,
            max_value=720,
            value=240,
            step=15,
            key="idc004_lookback",
        )

        poll_cols = st.columns(3)
        with poll_cols[0]:
            log_wait_seconds = st.number_input(
                "Log propagation wait seconds",
                min_value=0,
                max_value=600,
                value=30,
                step=10,
                key="idc004_log_propagation_wait_seconds",
            )
        with poll_cols[1]:
            total_search_seconds = st.number_input(
                "Total evidence search time seconds",
                min_value=30,
                max_value=3600,
                value=300,
                step=30,
                key="idc004_total_evidence_search_time_seconds",
            )
        with poll_cols[2]:
            poll_interval_seconds = st.number_input(
                "Poll interval seconds",
                min_value=5,
                max_value=300,
                value=20,
                step=5,
                key="idc004_poll_interval_seconds",
            )

        run_left, run_center, run_right = st.columns([0.24, 0.52, 0.24])

        with run_center:
            run_validation = st.button(
                "Check whether consent was allowed",
                type="primary",
                use_container_width=True,
            )

        if run_validation:
            observed_code = OBSERVED_OUTCOMES[outcome_label]

            args = [
                "-ObservedOutcome", observed_code,
                "-LookbackMinutes", str(int(lookback)),
                "-LogPropagationWaitSeconds", str(int(log_wait_seconds)),
                "-TotalEvidenceSearchTimeSeconds", str(int(total_search_seconds)),
                "-PollIntervalSeconds", str(int(poll_interval_seconds)),
            ]
            run = start_scenario_job(
                project_root,
                "ID-DV-004",
                wait_minutes=max(1, int(total_search_seconds // 60) or 1),
                poll_seconds=max(1, int(poll_interval_seconds)),
                extra_args=args,
                target=app.get("display_name") or "ID-DV-004 OAuth test app",
            )
            st.session_state["ztvp_dynamic_open_run_id"] = run.get("run_id")
            _alert("ID-DV-004 evidence polling started as a background Active Run.", "good")
            st.rerun()

    _step(4, "Clean up temporary user and app")

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    app = state.get("test_application", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active:
        _alert("No active ID-DV-004 run exists.", "info")
        return

    with st.container(border=True):
        _alert("After saving the report, cleanup deletes OAuth grants, the service principal, app registration, decoy user, and local secret files.", "warn")

        st.markdown("**Exact decoy user**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(decoy.get("user_principal_name", ""))}</div>', unsafe_allow_html=True)

        st.markdown("**Exact test app**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(app.get("display_name", ""))}<br>App ID: {_safe(app.get("app_id", ""))}</div>', unsafe_allow_html=True)

        _field_note("Check this only if you want to keep the temporary user disabled instead of deleting it.")
        disable_user = st.checkbox("Disable user instead of delete", value=False, key="idc004_disable_user")

        if st.button("Delete This Exact OAuth Consent Test Run", use_container_width=True):
            args = []

            if disable_user:
                args.append("-DisableUserInsteadOfDelete")

            with st.spinner("Cleaning OAuth grants, app registration, service principal, decoy user, and local state..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("ID-DV-004 cleanup failed.", "bad")
                error_output = f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}"
                st.code(error_output.strip() or "No PowerShell output captured.", language="text")
            else:
                _alert("ID-DV-004 cleanup completed.", "good")
                st.code(completed.stdout, language="text")

                for key in ["idc004_temp_upn", "idc004_temp_password"]:
                    st.session_state.pop(key, None)

                st.rerun()
