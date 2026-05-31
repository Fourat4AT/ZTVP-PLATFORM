from __future__ import annotations

import html
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

from background_jobs import get_active_run, start_scenario_job
from html_report import write_standard_html_report
from run_state import ACTIVE_STATUSES, request_cancel, selected_run_for_scenario


STATUS_LABELS = {
    "PASS_ANONYMOUS_SHARING_LINK_BLOCKED": "PASS — Anonymous sharing link blocked",
    "FAIL_ANONYMOUS_SHARING_LINK_ALLOWED": "FAIL — Anonymous sharing link allowed",
    "PARTIAL_ANONYMOUS_LINK_NOT_CREATED": "PARTIAL — Anonymous link was not created, but the denial reason is unclear",
    "PARTIAL_TEST_ERROR": "PARTIAL — Test Error",
    "ERROR_TEST_SETUP_FAILED": "ERROR — SharePoint createLink setup failed",
}


def _safe(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _friendly_status(value: object) -> str:
    return STATUS_LABELS.get(str(value or ""), str(value or "Unknown"))


def _tone_for_status(value: object) -> str:
    text = str(value or "").upper()

    if text.startswith("PASS"):
        return "good"
    if text.startswith("FAIL"):
        return "bad"
    return "warn"


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
    background: linear-gradient(135deg, #0f172a 0%, #9333ea 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #f3e8ff; line-height: 1.55; }
.ztvp-alert { border-radius: 16px; padding: 0.92rem 1rem; margin: 0.75rem 0 1rem 0; font-weight: 650; line-height: 1.5; }
.ztvp-info { background: #f5f3ff; border: 1px solid #8b5cf6; color: #4c1d95; }
.ztvp-good { background: #ecfdf5; border: 1px solid #10b981; color: #064e3b; }
.ztvp-warn { background: #fffbeb; border: 1px solid #f59e0b; color: #78350f; }
.ztvp-bad { background: #fef2f2; border: 1px solid #ef4444; color: #7f1d1d; }
.ztvp-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.85rem; margin-bottom: 1rem; }
.ztvp-grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.85rem; margin-bottom: 1rem; }
.ztvp-metric { background: #ffffff; border: 1px solid #dbe3ef; border-radius: 18px; padding: 1rem; box-shadow: 0 8px 18px rgba(15, 23, 42, 0.05); }
.ztvp-metric span { display: block; color: #64748b; font-size: 0.78rem; font-weight: 800; margin-bottom: 0.45rem; }
.ztvp-metric strong { color: #0f172a; font-size: 1.08rem; font-weight: 950; word-break: break-word; }
.ztvp-metric.good strong { color: #15803d; }
.ztvp-metric.warn strong { color: #b45309; }
.ztvp-metric.bad strong { color: #b91c1c; }
div.stButton > button, div.stDownloadButton > button { border-radius: 14px !important; min-height: 44px !important; font-weight: 850 !important; }
div.stButton > button { background: #9333ea !important; color: #ffffff !important; border: 1px solid #9333ea !important; }
div.stDownloadButton > button { background: #ffffff !important; color: #6d28d9 !important; border: 1px solid #ddd6fe !important; }
@media (max-width: 900px) { .ztvp-grid, .ztvp-grid-3 { grid-template-columns: 1fr; } }
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


def _yes_no(value: object, unknown: str = "Unknown") -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    text = str(value or "").strip().lower()
    if text in {"true", "yes", "1"}:
        return "Yes"
    if text in {"false", "no", "0"}:
        return "No"
    return unknown


def _safe_existing_path(project_root: Path, raw_path: object) -> Path | None:
    if raw_path is None:
        return None
    text = str(raw_path).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    path = Path(text)
    if not path.is_absolute():
        path = project_root / path
    return path if path.exists() and path.is_file() else None


def _status_verdict(status: object) -> str:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("ERROR"):
        return "ERROR"
    return "PARTIAL"


def _render_active_run_panel(project_root: Path, run: dict) -> None:
    if not run:
        return
    status = str(run.get("status") or "").lower()
    elapsed = int(run.get("elapsed_seconds") or 0)
    remaining = int(run.get("remaining_seconds") or 0)
    _alert("APP-DV-008 validation is currently running." if status in ACTIVE_STATUSES else f"APP-DV-008 run is {status}.", "info" if status in ACTIVE_STATUSES else "warn")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Phase", run.get("phase", "N/A"))}
    {_metric("Progress", f"{int(run.get('progress_percent') or 0)}%")}
    {_metric("Tenant evidence", run.get("tenant_evidence_status", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Target site", run.get("target_site") or run.get("target") or "Root site")}
    {_metric("Dummy file", run.get("dummy_file", "Pending"))}
    {_metric("Link attempt", run.get("anonymous_link_attempt_status", "Starting"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Cleanup", run.get("cleanup_status", "Not completed yet"))}
    {_metric("Elapsed", f"{elapsed}s")}
    {_metric("Remaining", f"{remaining}s")}
</div>
<div class="ztvp-grid">
    {_metric("Message", run.get("current_message", "N/A"))}
    {_metric("Run ID", run.get("run_id", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", key="cld001_open_active_runs", use_container_width=True):
            st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
            st.rerun()
    with col2:
        if status in ACTIVE_STATUSES and st.button("Cancel APP-DV-008 run", key="cld001_cancel_run", use_container_width=True):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()


def _render_selected_run(project_root: Path, run: dict) -> bool:
    report_path = _safe_existing_path(project_root, run.get("report_path") or run.get("report_json_path"))
    html_path = _safe_existing_path(project_root, run.get("html_report_path") or run.get("report_html_path"))
    if report_path is None:
        return False
    report = _load_json(report_path)
    if html_path is None:
        html_path = report_path.with_suffix(".html")
        if not html_path.exists():
            write_standard_html_report(report, html_path)
    st.markdown("### Selected APP-DV-008 run")
    _render_report(report, report_path, html_path, "")
    return True


def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    site = report.get("site", {}) or {}
    drive = report.get("drive", {}) or {}
    attempt = report.get("anonymous_link_attempt", {}) or {}
    cleanup = report.get("cleanup", {}) or {}
    warnings = report.get("warnings", []) or []
    recommendations = report.get("recommendations", []) or []
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated.</li>"
    recommendation_rows = "".join([f"<li>{_safe(r)}</li>" for r in recommendations]) or "<li>No recommendations generated.</li>"

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>APP-DV-008 - SharePoint Anonymous Sharing Link Exposure Validation</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#0f172a,#9333ea); color:white; padding:34px; border-radius:26px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:20px; }}
.metric,.card {{ background:white; border:1px solid #dbe3ef; border-radius:20px; padding:20px; margin-top:18px; }}
.metric span {{ color:#64748b; font-size:13px; font-weight:700; }}
.metric strong {{ display:block; font-size:22px; margin-top:8px; }}
pre {{ background:#0f172a; color:#e5e7eb; padding:18px; border-radius:16px; overflow:auto; }}
.footer {{ color:#64748b; font-size:13px; margin-top:24px; }}
</style>
</head>
<body>
<div class="container">
<div class="hero">
<h1>APP-DV-008 - SharePoint Anonymous Sharing Link Exposure Validation</h1>
<p>Cloud Apps evidence report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(_friendly_status(report.get("status")))}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Anonymous Link Created</span><strong>{_safe(metrics.get("anonymous_link_created"))}</strong></div>
<div class="metric"><span>Cleanup Completed</span><strong>{_safe(metrics.get("cleanup_completed"))}</strong></div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
<p><b>Evidence Quality:</b> {_safe(report.get("evidence_quality"))}</p>
</div>

<div class="card">
<h2>Controlled Cloud App Target</h2>
<p><b>Site:</b> {_safe(site.get("displayName"))}</p>
<p><b>Site URL:</b> {_safe(site.get("webUrl"))}</p>
<p><b>Drive:</b> {_safe(drive.get("name"))}</p>
</div>

<div class="card">
<h2>Anonymous Link Attempt</h2>
<pre>{_safe(json.dumps(attempt, indent=2))}</pre>
</div>

<div class="card">
<h2>Cleanup</h2>
<pre>{_safe(json.dumps(cleanup, indent=2))}</pre>
</div>

<div class="card">
<h2>Recommendations</h2>
<ul>{recommendation_rows}</ul>
</div>

<div class="card">
<h2>Warnings</h2>
<ul>{warning_rows}</ul>
</div>

<div class="footer">
Generated by Zero Trust Validation Platform on {generated}.
</div>
</div>
</body>
</html>
"""

    html_path.write_text(html_doc, encoding="utf-8")


def _render_report(report: dict, report_path: Path, html_path: Path, stdout: str) -> None:
    metrics = report.get("metrics", {}) or {}
    site = report.get("site", {}) or {}
    drive = report.get("drive", {}) or {}
    test_object = report.get("test_object", {}) or {}
    attempt = report.get("anonymous_link_attempt", {}) or {}
    cleanup = report.get("cleanup", {}) or {}
    warnings = report.get("warnings", []) or []

    status = report.get("status")
    tone = _tone_for_status(status)
    link_created = bool(metrics.get("anonymous_link_created") or attempt.get("link_created"))
    link_denied = bool(metrics.get("anonymous_link_denied") or attempt.get("link_denied"))
    denial_reason = attempt.get("error_message") or attempt.get("error_category") or "Not applicable"
    cleanup_completed = bool(metrics.get("cleanup_completed") or str(cleanup.get("status") or "").lower() == "completed")

    _alert("Cloud app anonymous sharing validation completed.", "good" if tone == "good" else tone)

    if status == "FAIL_ANONYMOUS_SHARING_LINK_ALLOWED":
        _alert("Simple result: SharePoint allowed an anonymous/public sharing link for the dummy file. This is a FAIL for this scenario.", "bad")
    elif status == "PASS_ANONYMOUS_SHARING_LINK_BLOCKED":
        _alert("Simple result: SharePoint blocked anonymous/public sharing link creation. This is a PASS for this scenario.", "good")
    else:
        _alert("Simple result: no anonymous link was created, but the result needs review because the denial was not fully classified.", "warn")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Verdict", _friendly_status(status), tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("Anonymous link created", "Yes" if link_created else "No", "bad" if link_created else "good")}
    {_metric("Link blocked/denied", "Yes" if link_denied else "No", "good" if link_denied else "bad" if link_created else "warn")}
</div>
<div class="ztvp-grid-3">
    {_metric("Denial reason", denial_reason, "good" if link_denied else "warn")}
    {_metric("Cleanup completed", "Yes" if cleanup_completed else "No", "good" if cleanup_completed else "bad")}
    {_metric("Public URL stored", "No", "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Controlled Cloud App Target")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Site", site.get("displayName", "N/A"))}
    {_metric("Drive", drive.get("name", "N/A"))}
    {_metric("Dummy File", test_object.get("file_name", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )

    if warnings:
        st.markdown("#### Warnings")
        for warning in warnings:
            _alert(warning, "warn")

    st.markdown("#### Recommendations")
    for rec in report.get("recommendations", []) or []:
        st.markdown(f"- {rec}")

    st.markdown("#### Export Evidence")
    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="APP-DV-008-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="APP-DV-008-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("Technical evidence details"):
        st.markdown("Anonymous Link Attempt")
        st.json(attempt)
        st.markdown("Cleanup Record")
        st.json(cleanup)
        st.markdown("Full evidence JSON")
        st.json(report)

    if stdout:
        with st.expander("PowerShell output"):
            st.code(stdout or "No PowerShell output captured.", language="text")


def render_cld001_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    requested_run_id = st.session_state.get("ztvp_dynamic_open_run_id")
    active_run = get_active_run(project_root, "APP-DV-008", str(requested_run_id or "") or None)
    selected_run = selected_run_for_scenario(project_root, "APP-DV-008", str(requested_run_id or "") or None)
    if active_run:
        _render_active_run_panel(project_root, active_run)
        return
    if selected_run and str(selected_run.get("status") or "").lower() not in ACTIVE_STATUSES:
        rendered_selected = _render_selected_run(project_root, selected_run)
        if requested_run_id and rendered_selected:
            return
        if rendered_selected:
            st.markdown("---")
            st.markdown("### Start a new APP-DV-008 run")

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>APP-DV-008 — SharePoint Anonymous Sharing Link Exposure Validation</h2>
    <p>This validation creates a temporary dummy SharePoint file, attempts to create an anonymous sharing link, and cleans up the test object.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert(
        "This scenario writes only a temporary dummy test file. It does not touch business files and it does not change Conditional Access policies.",
        "info",
    )

    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-CLD001.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-CLD001.ps1"
    state_path = project_root / "powershell" / "Reports" / "Dynamic" / "CLD-C-001" / "cld001-state.json"

    if not invoke_script.exists():
        _alert(f"Missing engine script: {invoke_script}", "bad")
        return

    st.markdown("### 1. Configure controlled SharePoint target")

    with st.container(border=True):
        site_mode = st.selectbox(
            "Site target",
            options=["Root site", "Custom site ID"],
            index=0,
            key="cld001_site_mode",
        )

        site_id = ""

        if site_mode == "Custom site ID":
            site_id = st.text_input(
                "Custom SharePoint site ID",
                value="",
                placeholder="Graph site ID",
                key="cld001_site_id",
            )

        link_type = st.selectbox(
            "Requested anonymous link type",
            options=["view", "edit"],
            index=0,
            key="cld001_link_type",
        )

        st.caption("Recommended first test: Root site + view link.")

    st.markdown("### 2. Run controlled anonymous sharing test")

    if st.button("Run SharePoint Anonymous Sharing Validation", type="primary", use_container_width=True):
        if site_mode == "Custom site ID" and not site_id.strip():
            _alert("Custom site ID mode requires a SharePoint site ID.", "warn")
            return

        args = [
            "-SiteMode", site_mode,
            "-SiteId", site_id.strip(),
            "-RequestedLinkType", link_type,
        ]

        target_label = "Root site" if site_mode == "Root site" else site_id.strip()
        run = start_scenario_job(
            project_root,
            "APP-DV-008",
            wait_minutes=5,
            poll_seconds=5,
            extra_args=args,
            target=target_label,
            tenant="Microsoft 365 tenant",
        )
        st.session_state["ztvp_dynamic_open_run_id"] = run.get("run_id")
        _alert("APP-DV-008 started as a background Active Run. You can leave this page while it finishes.", "good")
        st.rerun()

    st.markdown("### 3. Emergency cleanup")

    if state_path.exists():
        _alert("An active APP-DV-008 cleanup state exists. Use emergency cleanup if automatic cleanup failed.", "warn")

        if st.button("Run Emergency Cleanup for APP-DV-008", use_container_width=True):
            with st.spinner("Cleaning up temporary SharePoint test object..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)

            if completed.returncode != 0:
                _alert("Emergency cleanup failed.", "bad")
                error_output = f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}"
                st.code(error_output.strip() or "No PowerShell output captured.", language="text")
            else:
                _alert("Emergency cleanup completed.", "good")
                st.code(completed.stdout, language="text")
                st.rerun()
    else:
        _alert("No active APP-DV-008 cleanup state exists.", "good")

