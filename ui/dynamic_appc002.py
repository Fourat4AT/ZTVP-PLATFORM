from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st


STATUS_LABELS = {
    "PASS_EXTERNAL_MAIL_FORWARDING_BLOCKED": "PASS — External Mail Forwarding Blocked",
    "FAIL_EXTERNAL_MAIL_FORWARDING_ALLOWED": "FAIL — External Mail Forwarding Allowed",
    "PARTIAL_MAILBOX_NOT_READY": "PARTIAL — Mailbox Not Ready",
    "PARTIAL_EXCHANGE_MODULE_MISSING": "PARTIAL — Exchange Module Missing",
    "PARTIAL_EXCHANGE_CONNECTION_FAILED": "PARTIAL — Exchange Connection Failed",
    "PARTIAL_TEST_ERROR": "PARTIAL — Test Error",
    "NOT_APPLICABLE_NO_EXCHANGE_LICENSE": "NOT APPLICABLE — No Exchange License",
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


def _archive_and_remove_local_state(state_path: Path) -> Path | None:
    if not state_path.exists():
        return None

    history_dir = state_path.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive_path = history_dir / f"appc002-state-local-reset-{stamp}.json"
    shutil.copy2(state_path, archive_path)
    state_path.unlink()
    return archive_path


def _latest_archived_state(state_path: Path) -> tuple[Path | None, dict]:
    history_dir = state_path.parent / "history"
    if not history_dir.exists():
        return None, {}

    candidates = sorted(
        history_dir.glob("appc002-state*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for candidate in candidates:
        archived = _load_json(candidate)
        decoy = archived.get("decoy_user", {}) or {}
        if decoy.get("id") or decoy.get("user_principal_name"):
            return candidate, archived

    return None, {}


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 2400) -> subprocess.CompletedProcess:
    import os

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    user_profile = os.environ.get("USERPROFILE", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe = str(win_ps) if win_ps.exists() else "powershell.exe"

    # Clean module path.
    # This avoids loading broken PowerShell 7 PackageManagement modules during ExchangeOnlineManagement import.
    module_paths = [
        Path(user_profile) / "Documents" / "WindowsPowerShell" / "Modules",
        Path(user_profile) / "Documents" / "PowerShell" / "Modules",
        Path(program_files) / "WindowsPowerShell" / "Modules",
        Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules",
    ]

    env = os.environ.copy()
    env["PSModulePath"] = ";".join(str(p) for p in module_paths)

    return subprocess.run(
        [
            exe,
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
        env=env,
    )

def _friendly_status(value: object) -> str:
    return STATUS_LABELS.get(str(value or ""), str(value or "Unknown"))


def _tone_for_status(value: object) -> str:
    text = str(value or "").upper()

    if text.startswith("PASS"):
        return "good"

    if text.startswith("FAIL"):
        return "bad"

    if text.startswith("NOT_APPLICABLE"):
        return "info"

    return "warn"


def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero {
    background: linear-gradient(135deg, #0f172a 0%, #0f766e 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #ccfbf1; line-height: 1.55; }
.ztvp-alert { border-radius: 16px; padding: 0.92rem 1rem; margin: 0.75rem 0 1rem 0; font-weight: 650; line-height: 1.5; }
.ztvp-info { background: #f0fdfa; border: 1px solid #14b8a6; color: #134e4a; }
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
.ztvp-metric.info strong { color: #0f766e; }
div.stButton > button, div.stDownloadButton > button { border-radius: 14px !important; min-height: 44px !important; font-weight: 850 !important; }
div.stButton > button { background: #0f766e !important; color: #ffffff !important; border: 1px solid #0f766e !important; }
div.stDownloadButton > button { background: #ffffff !important; color: #0f766e !important; border: 1px solid #99f6e4 !important; }
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


def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    decoy = report.get("decoy_mailbox", {}) or {}
    mailbox_attempt = report.get("mailbox_forwarding_attempt", {}) or {}
    rule_attempt = report.get("inbox_rule_attempt", {}) or {}
    cleanup = report.get("forwarding_artifact_cleanup", {}) or {}
    warnings = report.get("warnings", []) or []
    recommendations = report.get("recommendations", []) or []
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    warnings_html = "".join([f"<li>{_safe(x)}</li>" for x in warnings]) or "<li>No warnings were generated.</li>"
    recs_html = "".join([f"<li>{_safe(x)}</li>" for x in recommendations]) or "<li>No recommendations generated.</li>"

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>APP-C-002 - Exchange External Mail Forwarding Exposure Validation</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#0f172a,#0f766e); color:white; padding:34px; border-radius:26px; }}
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
<h1>APP-C-002 - Exchange External Mail Forwarding Exposure Validation</h1>
<p>Applications / Cloud evidence report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(_friendly_status(report.get("status")))}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Mailbox Forwarding Allowed</span><strong>{_safe(metrics.get("mailbox_forwarding_allowed"))}</strong></div>
<div class="metric"><span>Inbox Rule Allowed</span><strong>{_safe(metrics.get("inbox_rule_allowed"))}</strong></div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
<p><b>Evidence Quality:</b> {_safe(report.get("evidence_quality"))}</p>
</div>

<div class="card">
<h2>Controlled Decoy Mailbox</h2>
<p><b>UPN:</b> {_safe(decoy.get("user_principal_name"))}</p>
<p><b>License:</b> {_safe(decoy.get("assigned_license"))}</p>
<p><b>External Target:</b> {_safe(report.get("external_target"))}</p>
</div>

<div class="card">
<h2>Mailbox Forwarding Attempt</h2>
<pre>{_safe(json.dumps(mailbox_attempt, indent=2))}</pre>
</div>

<div class="card">
<h2>Inbox Rule Attempt</h2>
<pre>{_safe(json.dumps(rule_attempt, indent=2))}</pre>
</div>

<div class="card">
<h2>Forwarding Artifact Cleanup</h2>
<pre>{_safe(json.dumps(cleanup, indent=2))}</pre>
</div>

<div class="card">
<h2>Recommendations</h2>
<ul>{recs_html}</ul>
</div>

<div class="card">
<h2>Warnings</h2>
<ul>{warnings_html}</ul>
</div>

<div class="footer">
Generated by Zero Trust Validation Platform on {generated}. This validation does not send real email.
</div>
</div>
</body>
</html>
"""

    html_path.write_text(html_doc, encoding="utf-8")


def _render_report(report: dict, report_path: Path, html_path: Path, stdout: str) -> None:
    metrics = report.get("metrics", {}) or {}
    decoy = report.get("decoy_mailbox", {}) or {}
    mailbox_readiness = report.get("mailbox_readiness", {}) or {}
    mailbox_attempt = report.get("mailbox_forwarding_attempt", {}) or {}
    rule_attempt = report.get("inbox_rule_attempt", {}) or {}
    cleanup = report.get("forwarding_artifact_cleanup", {}) or {}
    warnings = report.get("warnings", []) or []

    status = report.get("status")
    tone = _tone_for_status(status)

    _alert("Exchange external mail forwarding validation completed.", "good" if tone == "good" else tone)

    if status == "FAIL_EXTERNAL_MAIL_FORWARDING_ALLOWED":
        _alert("Simple result: Exchange accepted at least one automatic external forwarding configuration. This is a FAIL. ZTVP attempted to remove the forwarding artifact immediately.", "bad")
    elif status == "PASS_EXTERNAL_MAIL_FORWARDING_BLOCKED":
        _alert("Simple result: Exchange did not allow the tested automatic external forwarding paths. This is a PASS.", "good")
    elif status == "NOT_APPLICABLE_NO_EXCHANGE_LICENSE":
        _alert("Simple result: no Exchange-capable license is available, so this scenario is not applicable yet.", "info")
    else:
        _alert("Simple result: ZTVP could not make a strong PASS/FAIL decision. Review the warnings and evidence details.", "warn")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", _friendly_status(status), tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("Mailbox Forwarding Allowed", metrics.get("mailbox_forwarding_allowed", False), "bad" if metrics.get("mailbox_forwarding_allowed") else "good")}
    {_metric("Inbox Rule Allowed", metrics.get("inbox_rule_allowed", False), "bad" if metrics.get("inbox_rule_allowed") else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Mailbox Ready", metrics.get("mailbox_ready", False), "good" if metrics.get("mailbox_ready") else "warn")}
    {_metric("Artifacts Cleaned", metrics.get("forwarding_artifacts_cleanup_completed", False), "good" if metrics.get("forwarding_artifacts_cleanup_completed") else "bad")}
    {_metric("Test Mode", metrics.get("test_mode", report.get("test_mode", "N/A")))}
    {_metric("External Target", report.get("external_target", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Controlled Decoy Mailbox")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Mailbox", decoy.get("user_principal_name", "N/A"))}
    {_metric("License", decoy.get("assigned_license", "N/A"))}
    {_metric("Mailbox Ready", mailbox_readiness.get("ready", False), "good" if mailbox_readiness.get("ready") else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    rows = [
        {
            "Attempt": "Mailbox-level forwarding",
            "Attempted": mailbox_attempt.get("attempted"),
            "Accepted": mailbox_attempt.get("accepted"),
            "Error": mailbox_attempt.get("error_message"),
        },
        {
            "Attempt": "Inbox rule redirect",
            "Attempted": rule_attempt.get("attempted"),
            "Accepted": rule_attempt.get("accepted"),
            "Error": rule_attempt.get("error_message"),
        },
    ]

    st.markdown("#### Forwarding Attempt Evidence")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Mailbox forwarding attempt details"):
        st.json(mailbox_attempt)

    with st.expander("Inbox rule attempt details"):
        st.json(rule_attempt)

    st.markdown("#### Final Forwarding State")
    st.json(report.get("final_forwarding_state", {}) or {})

    st.markdown("#### Forwarding Artifact Cleanup")
    st.json(cleanup)

    if warnings:
        st.markdown("#### Warnings")
        for warning in warnings:
            _alert(str(warning), "warn")

    st.markdown("#### Recommendations")
    for rec in report.get("recommendations", []) or []:
        st.markdown(f"- {rec}")

    st.markdown("#### Export Evidence")
    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="APP-C-002-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="APP-C-002-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def render_appc002_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>APP-C-002 — Exchange External Mail Forwarding Exposure Validation</h2>
    <p>This validation creates a temporary Exchange mailbox and attempts to configure automatic external forwarding to a controlled external address.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert(
        "This scenario does not send email and does not read mailbox data. It only tests whether automatic external forwarding can be configured on a controlled decoy mailbox.",
        "info",
    )

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-APPC002.ps1"
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-APPC002.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-APPC002.ps1"

    state_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-002" / "appc002-state.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-002-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "APP-C-002-result.html"

    state = _load_json(state_path) if state_path.exists() else {}

    st.markdown("### 1. Create licensed Exchange decoy mailbox")

    if state:
        decoy = state.get("decoy_user", {}) or {}
        license_info = state.get("assigned_license", {}) or {}

        _alert("Active APP-C-002 run exists. Use this exact decoy mailbox for the validation, then clean it up.", "good")

        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("Decoy Mailbox", decoy.get("user_principal_name", "N/A"))}
    {_metric("License", license_info.get("sku_part_number", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )

        with st.expander("View active APP-C-002 state"):
            st.json(state)
    else:
        col1, col2 = st.columns(2)

        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-appc002-forwarding", key="appc002_user_prefix")
            display_name = st.text_input("Display name", value="ZTVP APP-C-002 Exchange Forwarding Decoy Mailbox", key="appc002_display_name")

        with col2:
            usage_location = st.text_input("Usage location", value="TN", max_chars=2, key="appc002_usage_location")
            st.caption("Tunisia = TN. Keep this unless your tenant licensing country is different.")

        if st.button("Create Licensed Exchange Decoy Mailbox", type="primary", use_container_width=True):
            args = [
                "-UserPrefix", user_prefix.strip(),
                "-DisplayName", display_name.strip(),
                "-UsageLocation", usage_location.strip().upper(),
            ]

            with st.spinner("Creating decoy user and assigning an Exchange-capable license..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("APP-C-002 preparation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            if report_path.exists() and not state_path.exists():
                report = _load_json(report_path)
                _write_html_report(report, html_path)
                _render_report(report, report_path, html_path, completed.stdout)
                return

            _alert("APP-C-002 preparation completed.", "good")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            st.rerun()

    st.markdown("### 2. Run controlled external forwarding exposure test")

    state = _load_json(state_path) if state_path.exists() else {}

    if not state:
        _alert("Create the Exchange decoy mailbox first.", "warn")
    else:
        _alert(
            "Use an external email address you control. ZTVP will try to configure forwarding to this address, but it will not send email.",
            "info",
        )

        external_target = st.text_input(
            "External forwarding target email",
            value="",
            placeholder="your.test@gmail.com",
            key="appc002_external_target",
        )

        col3, col4 = st.columns(2)

        with col3:
            test_mode = st.selectbox(
                "Test mode",
                options=["Both recommended", "Mailbox forwarding only", "Inbox rule only"],
                index=0,
                key="appc002_test_mode",
            )

        with col4:
            wait_minutes = st.number_input(
                "Mailbox readiness wait minutes",
                min_value=1,
                max_value=60,
                value=10,
                step=1,
                key="appc002_wait_minutes",
            )

        exchange_admin = st.text_input(
            "Exchange admin UPN optional",
            value=state.get("connected_account", ""),
            placeholder="fourat@tenant.onmicrosoft.com",
            key="appc002_exchange_admin",
        )

        with st.expander("If ExchangeOnlineManagement is missing"):
            st.code("Install-Module ExchangeOnlineManagement -Scope CurrentUser", language="powershell")

        if st.button("Run External Forwarding Validation", type="primary", use_container_width=True):
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", external_target.strip()):
                _alert("Enter a valid external email address first.", "warn")
                return

            args = [
                "-ExternalTargetEmail", external_target.strip(),
                "-TestMode", test_mode,
                "-MailboxWaitMinutes", str(int(wait_minutes)),
                "-ExchangeAdminUPN", exchange_admin.strip(),
            ]

            with st.spinner("Connecting to Exchange Online, waiting for mailbox readiness, testing forwarding configuration, and cleaning forwarding artifacts..."):
                completed = _run_powershell(project_root, invoke_script, args, timeout=2400)

            if completed.returncode != 0:
                _alert("APP-C-002 validation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            if not report_path.exists():
                _alert("Validation completed, but the JSON report was not found.", "warn")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                return

            report = _load_json(report_path)
            _write_html_report(report, html_path)
            _render_report(report, report_path, html_path, completed.stdout)

    st.markdown("### 3. Delete exact decoy mailbox and close test")

    state = _load_json(state_path) if state_path.exists() else {}

    if not state:
        _alert("No active APP-C-002 decoy mailbox exists.", "good")
        archived_state_path, archived_state = _latest_archived_state(state_path)

        if archived_state_path and archived_state:
            archived_decoy = archived_state.get("decoy_user", {}) or {}
            archived_license = archived_state.get("assigned_license", {}) or {}

            with st.expander("Recovery cleanup for latest archived APP-C-002 decoy", expanded=True):
                _alert(
                    "Use this if the page state was cleared but the exact APP-C-002 decoy still appears in Entra deleted users or Microsoft 365.",
                    "warn",
                )
                st.markdown(
                    f"""
<div class="ztvp-grid-3">
    {_metric("Archived Decoy", archived_decoy.get("user_principal_name", "N/A"))}
    {_metric("License", archived_license.get("sku_part_number", "N/A"))}
    {_metric("Run ID", archived_state.get("run_id", "N/A"))}
</div>
""",
                    unsafe_allow_html=True,
                )
                archived_exchange_admin = st.text_input(
                    "Exchange admin UPN for archived cleanup optional",
                    value=archived_state.get("connected_account", ""),
                    placeholder="fourat@tenant.onmicrosoft.com",
                    key="appc002_archived_cleanup_exchange_admin",
                )
                confirm_archived_cleanup = st.checkbox(
                    f"I understand this will purge only this archived APP-C-002 decoy: {archived_decoy.get('user_principal_name', 'unknown decoy')}.",
                    key="appc002_confirm_archived_cleanup",
                )

                if st.button(
                    "Purge Latest Archived APP-C-002 Decoy",
                    use_container_width=True,
                    disabled=not confirm_archived_cleanup,
                ):
                    args = [
                        "-ExchangeAdminUPN",
                        archived_exchange_admin.strip(),
                        "-StatePathOverride",
                        str(archived_state_path),
                    ]

                    with st.spinner("Purging archived APP-C-002 decoy from tenant deleted users..."):
                        completed = _run_powershell(project_root, cleanup_script, args, timeout=1800)

                    if completed.returncode != 0:
                        _alert("Archived APP-C-002 cleanup failed.", "bad")
                        st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                    else:
                        _alert("Archived APP-C-002 cleanup completed.", "good")
                        st.code(completed.stdout or "No PowerShell output captured.", language="text")
    else:
        decoy = state.get("decoy_user", {}) or {}
        license_info = state.get("assigned_license", {}) or {}

        _alert("After saving the report, cleanup removes the exact decoy user, license assignment, remaining forwarding artifacts, and local state.", "warn")

        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Decoy Mailbox", decoy.get("user_principal_name", "N/A"))}
    {_metric("License", license_info.get("sku_part_number", "N/A"))}
    {_metric("Run ID", state.get("run_id", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )

        exchange_admin_cleanup = st.text_input(
            "Exchange admin UPN for cleanup optional",
            value=state.get("connected_account", ""),
            placeholder="fourat@tenant.onmicrosoft.com",
            key="appc002_cleanup_exchange_admin",
        )

        if st.button("Delete This Exact Decoy Mailbox and Close Run", use_container_width=True):
            args = ["-ExchangeAdminUPN", exchange_admin_cleanup.strip()]

            with st.spinner("Cleaning up APP-C-002 test objects..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1800)

            if completed.returncode != 0:
                _alert("APP-C-002 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("APP-C-002 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()

        with st.expander("Local reset if tenant cleanup is already handled", expanded=False):
            _alert(
                "This only clears the APP-C-002 page state on this machine. It does not delete any tenant user, mailbox, license, inbox rule, or Exchange contact.",
                "warn",
            )
            st.write(
                "Use this only if you already deleted the decoy in the tenant, cleanup cannot authenticate, or you intentionally want to abandon this local run and start a fresh test."
            )
            confirm_local_reset = st.checkbox(
                f"I understand this only clears local APP-C-002 state for {decoy.get('user_principal_name', 'the current decoy')}.",
                key="appc002_confirm_local_reset",
            )
            if st.button("Clear Local APP-C-002 Page State Only", use_container_width=True, disabled=not confirm_local_reset):
                archive_path = _archive_and_remove_local_state(state_path)
                if archive_path is not None:
                    _alert(f"Local APP-C-002 state was archived and cleared: {archive_path}", "good")
                else:
                    _alert("No local APP-C-002 state file existed.", "info")
                st.rerun()
