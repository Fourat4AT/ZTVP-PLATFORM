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
    "PASS_LEGACY_AUTH_BLOCKED_STRONG": "PASS — Legacy Auth Blocked",
    "PASS_LEGACY_AUTH_BLOCKED": "PASS — Legacy Auth Blocked",
    "FAIL_LEGACY_AUTH_ALLOWED": "FAIL — Legacy Auth Allowed",
    "PARTIAL_MAILBOX_NOT_READY": "PARTIAL — Mailbox Not Ready",
    "PARTIAL_NO_PROTOCOLS_TESTED": "PARTIAL — No Protocols Tested",
    "PARTIAL_INCONCLUSIVE": "PARTIAL — Inconclusive",
}


EVIDENCE_COLUMNS = [
    "CreatedDateTime",
    "UserPrincipalName",
    "AppDisplayName",
    "ResourceDisplayName",
    "ClientAppUsed",
    "AuthenticationProtocol",
    "ConditionalAccessStatus",
    "LegacyBlockPolicyApplied",
    "Success",
    "Blocked",
    "IpAddress",
]


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


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _normalize_records(value: Any) -> list[dict]:
    if value is None:
        return []

    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    if isinstance(value, dict):
        return [value]

    return []


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
    background: linear-gradient(135deg, #111827 0%, #dc2626 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #fee2e2; line-height: 1.55; }
.ztvp-step { display: flex; align-items: center; gap: 0.75rem; margin: 1.35rem 0 0.75rem 0; }
.ztvp-step-number { width: 34px; height: 34px; border-radius: 999px; background: #dc2626; color: #ffffff; display: inline-flex; align-items: center; justify-content: center; font-weight: 900; }
.ztvp-step h3 { margin: 0; color: #0f172a; font-size: 1.16rem; font-weight: 900; }
.ztvp-alert { border-radius: 16px; padding: 0.92rem 1rem; margin: 0.75rem 0 1rem 0; font-weight: 650; line-height: 1.5; }
.ztvp-info { background: #eff6ff; border: 1px solid #3b82f6; color: #172554; }
.ztvp-warn { background: #fffbeb; border: 1px solid #f59e0b; color: #78350f; }
.ztvp-good { background: #ecfdf5; border: 1px solid #10b981; color: #064e3b; }
.ztvp-bad { background: #fef2f2; border: 1px solid #ef4444; color: #7f1d1d; }
.ztvp-field-note { color: #475569; font-size: 0.86rem; line-height: 1.45; margin: 0.45rem 0 0.25rem 0; }
.ztvp-checkbox-note { color: #475569; font-size: 0.86rem; line-height: 1.45; padding-top: 0.35rem; }
.ztvp-checkbox-note strong { color: #0f172a; font-weight: 850; }
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
    background: #dc2626 !important;
    color: #ffffff !important;
    border: 1px solid #dc2626 !important;
}
div.stButton > button:hover,
div[data-testid="stButton"] button:hover,
button[kind="primary"]:hover,
button[data-testid="baseButton-primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #b91c1c !important;
    border-color: #b91c1c !important;
    color: #ffffff !important;
}
div.stDownloadButton > button,
div[data-testid="stDownloadButton"] button {
    background: #ffffff !important;
    color: #b91c1c !important;
    border: 1px solid #fecaca !important;
}
@media (max-width: 900px) { .ztvp-grid, .ztvp-grid-3 { grid-template-columns: 1fr; } }
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
    attempts = _normalize_records(report.get("protocol_attempts"))
    evidence = _normalize_records(report.get("evidence"))
    warnings = report.get("warnings", []) or []

    attempt_rows = ""

    for row in attempts:
        attempt_rows += f"""
<tr>
<td>{_safe(row.get("protocol"))}</td>
<td>{_safe(row.get("target"))}</td>
<td>{_safe(row.get("success"))}</td>
<td>{_safe(row.get("blocked_or_denied"))}</td>
<td>{_safe(row.get("outcome"))}</td>
<td>{_safe(row.get("evidence_summary"))}</td>
</tr>
"""

    if not attempt_rows:
        attempt_rows = '<tr><td colspan="6">No protocol attempts were recorded.</td></tr>'

    evidence_rows = ""

    for row in evidence:
        evidence_rows += f"""
<tr>
<td>{_safe(row.get("CreatedDateTime"))}</td>
<td>{_safe(row.get("AppDisplayName"))}</td>
<td>{_safe(row.get("ClientAppUsed"))}</td>
<td>{_safe(row.get("ConditionalAccessStatus"))}</td>
<td>{_safe(row.get("LegacyBlockPolicyApplied"))}</td>
<td>{_safe(row.get("Success"))}</td>
<td>{_safe(row.get("Blocked"))}</td>
<td>{_safe(row.get("IpAddress"))}</td>
</tr>
"""

    if not evidence_rows:
        evidence_rows = '<tr><td colspan="8">No Entra legacy sign-in evidence was found yet.</td></tr>'

    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated.</li>"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    display_status = _friendly_status(report.get("status"))

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#111827,#dc2626); color:white; padding:34px; border-radius:26px; }}
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
<p>Controlled Legacy Authentication Exposure Report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(display_status)}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Protocol Successes</span><strong>{_safe(metrics.get("protocol_success_count", 0))}</strong></div>
<div class="metric"><span>Blocked / Denied</span><strong>{_safe(metrics.get("protocol_blocked_or_denied_count", 0))}</strong></div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
</div>

<div class="card">
<h2>Protocol Authentication Attempts</h2>
<table>
<thead>
<tr>
<th>Protocol</th>
<th>Target</th>
<th>Success</th>
<th>Blocked / Denied</th>
<th>Outcome</th>
<th>Summary</th>
</tr>
</thead>
<tbody>
{attempt_rows}
</tbody>
</table>
</div>

<div class="card">
<h2>Entra Sign-in Evidence</h2>
<table>
<thead>
<tr>
<th>Created</th>
<th>App</th>
<th>Client App</th>
<th>CA Status</th>
<th>Legacy Block Policy</th>
<th>Success</th>
<th>Blocked</th>
<th>IP</th>
</tr>
</thead>
<tbody>
{evidence_rows}
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
    attempts = _normalize_records(report.get("protocol_attempts"))
    evidence = _normalize_records(report.get("evidence"))
    warnings = report.get("warnings", []) or []
    mailbox = report.get("mailbox_readiness", {}) or {}
    policy = report.get("policy_attribution", {}) or {}

    display_status = _friendly_status(report.get("status"))
    tone = _tone_for_status(report.get("status"))

    _alert("Controlled legacy-authentication validation completed.", "good" if tone == "good" else tone)

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", display_status, tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("Protocol Successes", metrics.get("protocol_success_count", 0), "bad" if metrics.get("protocol_success_count", 0) else "good")}
    {_metric("Blocked / Denied", metrics.get("protocol_blocked_or_denied_count", 0), "good" if metrics.get("protocol_blocked_or_denied_count", 0) else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Mailbox Readiness")
    final_mailbox = mailbox.get("final", {}) if isinstance(mailbox, dict) else {}

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Mailbox Ready", metrics.get("mailbox_ready", final_mailbox.get("ready", False)), "good" if metrics.get("mailbox_ready") else "warn")}
    {_metric("Exchange Plan Enabled", final_mailbox.get("exchange_plan_enabled", ""))}
    {_metric("Mail", final_mailbox.get("mail", ""))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Protocol Authentication Attempts")

    if attempts:
        df_attempts = pd.DataFrame(attempts)
        cols = [c for c in ["protocol", "target", "success", "blocked_or_denied", "outcome", "evidence_summary"] if c in df_attempts.columns]
        st.dataframe(df_attempts[cols] if cols else df_attempts, use_container_width=True, hide_index=True)

        with st.expander("Protocol server responses"):
            for row in attempts:
                st.markdown(f"##### {row.get('protocol')}")
                st.code(row.get("server_response", ""), language="text")
    else:
        _alert("No protocol attempts were recorded.", "warn")

    st.markdown("#### Entra Policy Attribution")

    names = policy.get("legacy_block_policy_names", []) or []
    names_text = ", ".join([str(x) for x in names]) if names else "None attributed"

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Legacy Block Policy Applied", "Yes" if policy.get("legacy_block_policy_applied") else "No", "good" if policy.get("legacy_block_policy_applied") else "warn")}
    {_metric("Policy Names", names_text)}
    {_metric("Blocked Evidence Rows", policy.get("sign_in_blocked_evidence_count", 0))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Entra Sign-in Evidence")

    if evidence:
        df = pd.DataFrame(evidence)
        cols = [c for c in EVIDENCE_COLUMNS if c in df.columns]
        st.dataframe(df[cols] if cols else df, use_container_width=True, hide_index=True)

        with st.expander("Evidence row details"):
            for index, row in enumerate(evidence, start=1):
                st.markdown(f"##### Evidence event {index}")
                st.json(row)
    else:
        _alert("No matching Entra legacy sign-in evidence was found yet.", "warn")

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
            file_name="ID-DV-003-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="ID-DV-003-result.html",
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
        st.info("ID-DV-003 legacy authentication validation is running in Active Runs.")
    else:
        st.info("ID-DV-003 run state restored.")

    cols = st.columns(4)
    cols[0].metric("Phase", run.get("phase") or "Unknown")
    cols[1].metric("Progress", f"{int(run.get('progress_percent') or 0)}%")
    cols[2].metric("Polls", f"{run.get('poll_attempts') or 0} / {run.get('max_poll_attempts') or 'N/A'}")
    cols[3].metric("Tenant evidence", run.get("tenant_evidence_status") or "Waiting")
    if run.get("current_message"):
        st.write(run.get("current_message"))

    col_active, col_cancel = st.columns(2)
    run_key = str(run.get("run_id") or "latest")
    if col_active.button("Open Active Runs", use_container_width=True, key=f"idc003_open_active_runs_{run_key}"):
        st.session_state["pending_navigation"] = {"main_navigation": "Active Runs", "pending_main_navigation": "Active Runs"}
        st.session_state.pop("ztvp_dynamic_open_run_id", None)
        st.rerun()
    if status in ACTIVE_STATUSES and col_cancel.button("Cancel", use_container_width=True, key=f"idc003_cancel_active_run_{run_key}"):
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


def render_idc003_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>ID-DV-003 — Controlled Legacy Authentication Exposure Validation</h2>
    <p>This creates a licensed Exchange decoy mailbox and tests whether old username/password mail protocols can authenticate.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    state_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-003"
    state_path = state_dir / "decoy-state.json"
    secret_once_path = state_dir / "decoy-secret-once.json"

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC003Decoy.ps1"
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC003.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDC003Decoy.ps1"

    requested_run_id = st.session_state.get("ztvp_dynamic_open_run_id")
    active_or_selected_run = selected_run_for_scenario(project_root, "ID-DV-003", requested_run_id)
    if active_or_selected_run and str(active_or_selected_run.get("status") or "").lower() in ACTIVE_STATUSES:
        _render_background_run_summary(project_root, active_or_selected_run)
        return
    if active_or_selected_run and (requested_run_id or str(active_or_selected_run.get("status") or "").lower() == "completed"):
        _render_background_run_summary(project_root, active_or_selected_run)
        st.session_state.pop("ztvp_dynamic_open_run_id", None)
        st.session_state.pop("ztvp_dynamic_open_run_status", None)
        st.session_state.pop("ztvp_dynamic_open_report_path", None)
        st.markdown("---")

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    _step(1, "Create temporary mailbox user")

    if has_active:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("License", (state.get("license", {}) or {}).get("sku_part_number", "N/A"), "good")}
    {_metric("Cleanup", cleanup.get("status", "Pending"), "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        st.markdown("**Exact decoy user for this run**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(decoy.get("user_principal_name", ""))}</div>', unsafe_allow_html=True)

        with st.expander("View active ID-DV-003 state"):
            st.json(state)
    else:
        _alert("No active ID-DV-003 decoy exists. Generate a fresh licensed decoy to start the test.", "info")

        with st.container(border=True):
            _alert("ZTVP will create a temporary test user with an Exchange mailbox. You can usually leave these values unchanged.", "info")
            _field_note("Start of the temporary user's email/sign-in name. Leave the default unless you want a different test-user name.")
            prefix = st.text_input("Temporary user email prefix", value="ztvp-idc003-legacyauth", key="idc003_prefix")
            _field_note("Name shown for the temporary user in Entra. This does not change the test.")
            display = st.text_input("Temporary user display name", value="ZTVP ID-DV-003 Legacy Auth Decoy User", key="idc003_display")
            _field_note("Country code Microsoft requires before assigning a license. Keep TN for Tunisia. Use US for United States.")
            usage = st.text_input("Country code", value="TN", max_chars=2, key="idc003_usage")

            if st.button("Generate Temporary Mailbox User", type="primary", use_container_width=True):
                args = [
                    "-DecoyAliasPrefix", prefix.strip() or "ztvp-idc003-legacyauth",
                    "-DisplayName", display.strip() or "ZTVP ID-DV-003 Legacy Auth Decoy User",
                    "-UsageLocation", usage.strip().upper() or "TN",
                ]

                with st.spinner("Creating decoy user and assigning Exchange-capable license..."):
                    completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

                if completed.returncode != 0:
                    _alert("Decoy creation or license assignment failed.", "bad")
                    st.code(completed.stderr or completed.stdout, language="text")
                else:
                    _alert("Licensed decoy created.", "good")
                    st.code(completed.stdout, language="text")

                    if secret_once_path.exists():
                        secret = _load_json(secret_once_path)
                        st.session_state["idc003_temp_upn"] = secret.get("user_principal_name")
                        st.session_state["idc003_temp_password"] = secret.get("temporary_password")

                        try:
                            secret_once_path.unlink()
                        except Exception:
                            pass

                    st.rerun()

    if st.session_state.get("idc003_temp_password"):
        _alert("Temporary password is shown once. ZTVP keeps a private local copy only until cleanup so the protocol test can run.", "warn")
        st.markdown(
            f"""
<div class="ztvp-codebox">
UPN: {_safe(st.session_state.get("idc003_temp_upn"))}<br>
Password: {_safe(st.session_state.get("idc003_temp_password"))}
</div>
""",
            unsafe_allow_html=True,
        )

    _step(2, "Test old mail login methods")

    if not has_active:
        _alert("Generate a licensed decoy first. This step unlocks after the decoy exists.", "warn")
    else:
        _alert("ZTVP will only test authentication. It will not send email and will not read mailbox data.", "info")

        _field_note("Choose which old mail login methods to test. Leave all selected for the strongest check.")
        protocols = st.multiselect(
            "Protocols to test",
            options=["SMTP", "IMAP", "POP"],
            default=["SMTP", "IMAP", "POP"],
            key="idc003_protocols",
        )

        col1, col2 = st.columns(2)

        with col1:
            _field_note("How long to wait for the mailbox to appear. More time helps avoid a false 'mailbox not ready' result.")
            wait_minutes = st.number_input(
                "Mailbox readiness wait minutes",
                min_value=0,
                max_value=60,
                value=20,
                step=1,
                key="idc003_wait_minutes",
            )

        with col2:
            _field_note("How many minutes of Entra sign-in logs to search. 240 means the last 4 hours.")
            lookback_minutes = st.number_input(
                "Entra sign-in log lookback minutes",
                min_value=15,
                max_value=720,
                value=240,
                step=15,
                key="idc003_lookback_minutes",
            )


        run_left, run_center, run_right = st.columns([0.24, 0.52, 0.24])

        with run_center:
            run_validation = st.button(
                "Run Controlled Legacy Auth Validation",
                type="primary",
                use_container_width=True,
            )

        if run_validation:
            if not protocols:
                _alert("Select at least one protocol.", "warn")
            else:
                args = [
                    "-Protocols", ",".join(protocols),
                    "-MailboxWaitMinutes", str(int(wait_minutes)),
                    "-LookbackMinutes", str(int(lookback_minutes)),
                ]
                run = start_scenario_job(
                    project_root,
                    "ID-DV-003",
                    wait_minutes=max(1, int(wait_minutes) or 1),
                    poll_seconds=30,
                    extra_args=args,
                    target=decoy.get("user_principal_name") or "ID-DV-003 decoy mailbox",
                )
                st.session_state["ztvp_dynamic_open_run_id"] = run.get("run_id")
                _alert("ID-DV-003 legacy authentication validation started as a background Active Run.", "good")
                st.rerun()

    _step(3, "Clean up temporary user")

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active:
        _alert("No active ID-DV-003 decoy exists.", "info")
        return

    with st.container(border=True):
        exact_upn = decoy.get("user_principal_name", "")

        _alert("After saving the report, delete the exact active decoy. This also removes the license and deletes local secret files.", "warn")
        st.markdown(f'<div class="ztvp-codebox">{_safe(exact_upn)}</div>', unsafe_allow_html=True)

        _field_note("Check this only if you want to keep the temporary user disabled instead of deleting it.")
        cleanup_choice_col, cleanup_note_col = st.columns([0.38, 0.62])

        with cleanup_choice_col:
            disable_instead = st.checkbox("Disable instead of delete", value=False, key="idc003_disable_instead")

        with cleanup_note_col:
            st.markdown(
                """
<div class="ztvp-checkbox-note">
Removes the Exchange-capable license and local secret files, then leaves the decoy account disabled instead of deleting it.
</div>
""",
                unsafe_allow_html=True,
            )

        if st.button("Delete This Exact Legacy-Auth Decoy and Close Run", use_container_width=True):
            args = []

            if disable_instead:
                args.append("-DisableInsteadOfDelete")

            with st.spinner("Removing license, deleting decoy, and deleting local secret files..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("Cleanup failed.", "bad")
                st.code(completed.stderr or completed.stdout, language="text")
            else:
                _alert("ID-DV-003 cleanup completed.", "good")
                st.code(completed.stdout, language="text")

                for key in ["idc003_temp_upn", "idc003_temp_password"]:
                    st.session_state.pop(key, None)

                st.rerun()
