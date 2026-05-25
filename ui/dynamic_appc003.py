from __future__ import annotations

import html
import json
import subprocess
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st


STATUS_LABELS = {
    "PASS_PUBLIC_FILE_EXPOSURE_DETECTED": "PASS — Public File Exposure Detected",
    "PASS_PUBLIC_FILE_EXPOSURE_REMEDIATED": "PASS — Public File Exposure Remediated",
    "FAIL_PUBLIC_FILE_EXPOSURE_NOT_DETECTED": "FAIL — Public File Exposure Not Detected",
    "PARTIAL_PUBLIC_LINK_COULD_NOT_BE_CREATED": "PARTIAL — Public Link Could Not Be Created",
    "PARTIAL_MDCA_EVIDENCE_NOT_ACCESSIBLE": "PARTIAL — MDCA Evidence Not Accessible",
    "PARTIAL_TEST_ERROR": "PARTIAL — Test Error",
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


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    import os

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
    return "warn"




def _clean_mdca_token(value: str) -> str:
    token = (value or "").strip()

    if token.lower().startswith("token "):
        token = token[6:].strip()

    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    return token


def _looks_like_fake_mdca_token(value: str) -> bool:
    token = (value or "").strip().lower()

    if not token:
        return True

    fake_values = {
        "<token>",
        "<your_token>",
        "paste_token_here",
        "paste_the_raw_mdca_token_here",
        "your_token_here",
    }

    if token in fake_values:
        return True

    if token.startswith("https://"):
        return True

    return False



def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero {
    background: linear-gradient(135deg, #0f172a 0%, #7c3aed 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #ede9fe; line-height: 1.55; }
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
div.stButton > button { background: #7c3aed !important; color: #ffffff !important; border: 1px solid #7c3aed !important; }
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


def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    site = report.get("site", {}) or {}
    drive = report.get("drive", {}) or {}
    dummy = report.get("dummy_file", {}) or {}
    link = report.get("anonymous_public_link_attempt", {}) or {}
    mdca = report.get("mdca_detection_evidence", {}) or {}
    cleanup = report.get("cleanup", {}) or {}
    warnings = report.get("warnings", []) or []
    recommendations = report.get("recommendations", []) or []
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    warnings_html = "".join([f"<li>{_safe(x)}</li>" for x in warnings]) or "<li>No warnings were generated.</li>"
    recs_html = "".join([f"<li>{_safe(x)}</li>" for x in recommendations]) or "<li>No recommendations generated.</li>"

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>APP-C-003 - MDCA Public File Sharing Detection Validation</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#0f172a,#7c3aed); color:white; padding:34px; border-radius:26px; }}
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
<h1>APP-C-003 - MDCA Public File Sharing Detection Validation</h1>
<p>Applications / Cloud evidence report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(_friendly_status(report.get("status")))}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Public Link Created</span><strong>{_safe(metrics.get("public_link_created"))}</strong></div>
<div class="metric"><span>MDCA Alert Detected</span><strong>{_safe(metrics.get("mdca_alert_detected"))}</strong></div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
<p><b>Evidence Quality:</b> {_safe(report.get("evidence_quality"))}</p>
</div>

<div class="card">
<h2>Controlled SharePoint Target</h2>
<p><b>Site:</b> {_safe(site.get("displayName"))}</p>
<p><b>Site URL:</b> {_safe(site.get("webUrl"))}</p>
<p><b>Drive:</b> {_safe(drive.get("name"))}</p>
<p><b>Dummy file:</b> {_safe(dummy.get("file_name"))}</p>
</div>

<div class="card">
<h2>Anonymous Public Link Attempt</h2>
<pre>{_safe(json.dumps(link, indent=2))}</pre>
</div>

<div class="card">
<h2>MDCA Detection Evidence</h2>
<pre>{_safe(json.dumps(mdca, indent=2))}</pre>
</div>

<div class="card">
<h2>Cleanup</h2>
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
Generated by Zero Trust Validation Platform on {generated}. Public URLs are not stored.
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
    dummy = report.get("dummy_file", {}) or {}
    link = report.get("anonymous_public_link_attempt", {}) or {}
    mdca = report.get("mdca_detection_evidence", {}) or {}
    cleanup = report.get("cleanup", {}) or {}
    warnings = report.get("warnings", []) or []

    status = report.get("status")
    tone = _tone_for_status(status)

    _alert("MDCA public file sharing validation completed.", "good" if tone == "good" else tone)

    if status == "PASS_PUBLIC_FILE_EXPOSURE_DETECTED":
        _alert("Simple result: the public file exposure was created and MDCA detected it automatically.", "good")
    elif status == "PASS_PUBLIC_FILE_EXPOSURE_REMEDIATED":
        _alert("Simple result: the public file exposure was created and the public permission disappeared before ZTVP cleanup. This indicates governance/remediation occurred.", "good")
    elif status == "FAIL_PUBLIC_FILE_EXPOSURE_NOT_DETECTED":
        _alert("Simple result: the dummy file became public, but no matching MDCA alert/remediation was found. Add or fix the MDCA file policy, then rerun.", "bad")
    else:
        _alert("Simple result: ZTVP could not complete a full MDCA detection decision. Review warnings.", "warn")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", _friendly_status(status), tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("Public Link Created", metrics.get("public_link_created", False), "bad" if metrics.get("public_link_created") else "warn")}
    {_metric("MDCA Alert Detected", metrics.get("mdca_alert_detected", False), "good" if metrics.get("mdca_alert_detected") else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Governance Observed", metrics.get("governance_remediation_observed", False), "good" if metrics.get("governance_remediation_observed") else "warn")}
    {_metric("Cleanup Completed", metrics.get("cleanup_completed", False), "good" if metrics.get("cleanup_completed") else "bad")}
    {_metric("Monitoring Window", str(metrics.get("monitoring_window_minutes", "N/A")) + " min")}
    {_metric("Poll Interval", str(metrics.get("poll_interval_seconds", "N/A")) + " sec")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Controlled SharePoint Target")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Site", site.get("displayName", "N/A"))}
    {_metric("Drive", drive.get("name", "N/A"))}
    {_metric("Dummy File", dummy.get("file_name", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Public Link and MDCA Evidence")

    rows = [
        {
            "Evidence": "Anonymous public link",
            "Value": link.get("public_link_created"),
            "Detail": link.get("error_message") or "No public URL stored.",
        },
        {
            "Evidence": "MDCA alert",
            "Value": mdca.get("alert_detected"),
            "Detail": (mdca.get("matched_alert") or {}).get("title") if isinstance(mdca.get("matched_alert"), dict) else "",
        },
        {
            "Evidence": "Governance/remediation",
            "Value": mdca.get("governance_remediation_observed"),
            "Detail": "Public permission removed before cleanup." if mdca.get("governance_remediation_observed") else "",
        },
    ]

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Anonymous public link attempt details"):
        st.json(link)

    with st.expander("MDCA automatic detection evidence"):
        st.json(mdca)

    with st.expander("Cleanup record"):
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
            file_name="APP-C-003-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="APP-C-003-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def render_appc003_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>APP-C-003 — MDCA Public File Sharing Detection Validation</h2>
    <p>This validation creates a harmless dummy SharePoint public link and automatically checks whether MDCA detects or remediates it.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert(
        "This scenario does not touch business files and does not store the public URL. It creates one dummy file, polls MDCA Alerts API, then removes the public link and file.",
        "info",
    )

    st.markdown("### 1. Configure automatic MDCA detection test")

    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-APPC003.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-APPC003.ps1"
    test_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Test-ZTVP-APPC003MdcaToken.ps1"

    state_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-003" / "appc003-state.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-003-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "APP-C-003-result.html"

    if state_path.exists():
        _alert("An active APP-C-003 state exists. Run emergency cleanup before starting a new test.", "warn")
        with st.expander("View active APP-C-003 state"):
            st.json(_load_json(state_path))

    col1, col2 = st.columns(2)

    with col1:
        site_mode = st.selectbox("Site target", options=["Root site", "Custom site ID"], index=0, key="appc003_site_mode")
        custom_site_id = ""

        if site_mode == "Custom site ID":
            custom_site_id = st.text_input("Custom site ID", value="", key="appc003_custom_site_id")

        link_type = st.selectbox("Requested anonymous link type", options=["view"], index=0, key="appc003_link_type")
        monitoring_window = st.number_input("Monitoring window minutes", min_value=2, max_value=60, value=15, step=1, key="appc003_monitoring_window")
        poll_interval = st.number_input("MDCA poll interval seconds", min_value=15, max_value=300, value=60, step=15, key="appc003_poll_interval")

    with col2:
        mdca_api_base = st.text_input(
            "MDCA API base URL",
            value="",
            placeholder="Example: https://m365x07179530.us2.portal.cloudappsecurity.com",
            key="appc003_mdca_api_base",
            help="Paste the MDCA portal/API base URL. Do not paste the token here.",
        )

        mdca_api_token = st.text_input(
            "MDCA API token — paste the raw token value here",
            value="",
            placeholder="Paste token here. Do not include 'Token' or 'Bearer'.",
            type="password",
            key="appc003_mdca_api_token",
            help="Paste only the generated API token value. ZTVP does not store it in reports.",
        )

        token_clean_preview = _clean_mdca_token(mdca_api_token)

        if token_clean_preview:
            _alert("MDCA token field has a value. It is hidden for safety.", "info")
        else:
            _alert("Paste the MDCA API token in the field above. The field is intentionally masked.", "warn")

        clear_col, test_col = st.columns(2)

        with clear_col:
            if st.button("Clear token field", key="appc003_clear_token", use_container_width=True):
                st.session_state["appc003_mdca_api_token"] = ""
                st.rerun()

        with test_col:
            if st.button("Test MDCA token only", key="appc003_test_token", use_container_width=True):
                token_for_test = _clean_mdca_token(mdca_api_token)

                if not mdca_api_base.strip():
                    _alert("Paste the MDCA API base URL first.", "warn")
                elif not token_for_test or _looks_like_fake_mdca_token(token_for_test):
                    _alert("Paste the real raw MDCA API token first. Do not paste the token name, URL, 'Token ...', or 'Bearer ...'.", "warn")
                else:
                    args = [
                        "-MdcaApiBaseUrl", mdca_api_base.strip(),
                        "-MdcaApiToken", token_for_test,
                    ]

                    with st.spinner("Testing MDCA API token without creating a public link..."):
                        completed = _run_powershell(project_root, test_script, args, timeout=300)

                    if completed.returncode == 0:
                        _alert("MDCA API token test succeeded. You can run the full validation.", "good")
                    else:
                        _alert("MDCA API token test failed. Fix the token before running the full validation.", "bad")

                    output_text = (
                        f"Return code: {completed.returncode}\n\n"
                        f"--- STDERR ---\n{completed.stderr or ''}\n\n"
                        f"--- STDOUT ---\n{completed.stdout or ''}"
                    )

                    st.code(output_text, language="text")

        mdca_policy_name = st.text_input(
            "Expected MDCA policy name",
            value="ZTVP - Detect Public SharePoint File Sharing",
            key="appc003_policy_name",
        )

        with st.expander("Where to get MDCA API URL and token"):
            st.markdown(
                """
Go to Microsoft Defender portal:

1. **Settings → Cloud Apps → System → About**  
   Copy the MDCA portal/API URL.

2. **Settings → Cloud Apps → System → API tokens**  
   Generate a token.

Paste:
- the URL in **MDCA API base URL**
- the token value in **MDCA API token — paste the raw token value here**

Do **not** paste:
- `Token xxxxx`
- `Bearer xxxxx`
- the token name
- the API URL into the token field
"""
            )

    st.markdown("### 2. Run automatic validation")

    if st.button("Run MDCA Public File Sharing Detection Validation", type="primary", use_container_width=True):
        if site_mode == "Custom site ID" and not custom_site_id.strip():
            _alert("Custom site ID mode requires a site ID.", "warn")
            return

        token_for_run = _clean_mdca_token(mdca_api_token)

        if not mdca_api_base.strip() or not token_for_run:
            _alert("Automatic MDCA detection requires both MDCA API base URL and MDCA API token.", "warn")
            return

        if _looks_like_fake_mdca_token(token_for_run):
            _alert("The MDCA token value does not look valid. Paste the raw token only, not the token name, URL, 'Token ...', or 'Bearer ...'.", "warn")
            return

        args = [
            "-SiteMode", site_mode,
            "-SiteId", custom_site_id.strip(),
            "-RequestedLinkType", link_type,
            "-MonitoringWindowMinutes", str(int(monitoring_window)),
            "-PollIntervalSeconds", str(int(poll_interval)),
            "-MdcaApiBaseUrl", mdca_api_base.strip(),
            "-MdcaApiToken", token_for_run,
            "-MdcaPolicyName", mdca_policy_name.strip(),
        ]

        with st.spinner("Creating dummy public link, polling MDCA automatically, and cleaning up test artifacts..."):
            completed = _run_powershell(project_root, invoke_script, args, timeout=4200)

        if completed.returncode != 0:
            _alert("APP-C-003 validation failed.", "bad")
            st.code(
                f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}",
                language="text",
            )
            return

        if not report_path.exists():
            _alert("Validation completed, but the JSON report was not found.", "warn")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            return

        report = _load_json(report_path)
        _write_html_report(report, html_path)
        _render_report(report, report_path, html_path, completed.stdout)

    st.markdown("### 3. Emergency cleanup")

    if not state_path.exists():
        _alert("No active APP-C-003 cleanup state exists.", "good")
    else:
        _alert("Emergency cleanup removes the anonymous permission and deletes the dummy folder/file.", "warn")

        if st.button("Run Emergency Cleanup for APP-C-003", use_container_width=True):
            with st.spinner("Running APP-C-003 emergency cleanup..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1800)

            if completed.returncode != 0:
                _alert("APP-C-003 emergency cleanup failed.", "bad")
                st.code(
                    f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}",
                    language="text",
                )
            else:
                _alert("APP-C-003 emergency cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()
