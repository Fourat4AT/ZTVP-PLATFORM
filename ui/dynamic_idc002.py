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
    "PARTIAL_NO_MATCHING_SIGNIN": "PARTIAL - No Matching Sign-in",
    "PASS_DEVICE_CODE_BLOCKED_STRONG": "PASS — Device Code Blocked",
    "PASS_DEVICE_CODE_BLOCKED": "PASS — Device Code Blocked",
    "PASS_BLOCKED_TOKEN_ENDPOINT": "PASS — Token Not Issued",
    "FAIL_DEVICE_CODE_ALLOWED": "FAIL — Device Code Allowed",
    "PARTIAL_DEVICE_CODE_EVIDENCE": "PARTIAL — Evidence Unclear",
    "CONFIGURED_NOT_VALIDATED": "CONFIGURED — Not Validated",
    "REPORT_ONLY_NOT_ENFORCED": "REPORT-ONLY — Not Enforced",
    "NO_EVIDENCE": "NO EVIDENCE",
}

EVIDENCE_COLUMNS = [
    "CreatedDateTime",
    "EvidenceType",
    "UserPrincipalName",
    "AppDisplayName",
    "ResourceDisplayName",
    "Status",
    "AuthenticationProtocol",
    "ClientAppUsed",
    "DeviceCodeEvidence",
    "ConditionalAccessStatus",
    "BlockPolicyApplied",
    "BlockPolicyNames",
    "Success",
    "Blocked",
    "TokenLikelyIssuedFromLogs",
    "IpAddress",
    "RequestId",
    "Location",
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

    if text.startswith("PARTIAL") or text.startswith("CONFIGURED") or text.startswith("REPORT"):
        return "warn"

    return "neutral"


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _normalize_records(value: Any) -> list[dict]:
    if value is None:
        return []

    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    if isinstance(value, dict):
        return [value]

    return []


def _run_powershell(project_root: Path, script_path: Path, args: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
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


def _clear_session_keys() -> None:
    for key in [
        "idc002_temp_password",
        "idc002_temp_upn",
        "idc002_decoy_upn",
        "idc002_evidence_start_utc",
    ]:
        st.session_state.pop(key, None)


def _compact_evidence(evidence: list[dict]) -> pd.DataFrame:
    if not evidence:
        return pd.DataFrame()

    df = pd.DataFrame(evidence)
    cols = [col for col in EVIDENCE_COLUMNS if col in df.columns]
    return df[cols] if cols else df


def _css() -> None:
    st.markdown(
        """
<style>
.block-container {
    max-width: 1180px;
    padding-top: 1.1rem;
}

.ztvp-hero {
    background: linear-gradient(135deg, #111827 0%, #6d28d9 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}

.ztvp-hero h2 {
    margin: 0 0 0.35rem 0;
    font-size: 1.35rem;
    font-weight: 900;
    color: #ffffff;
}

.ztvp-hero p {
    margin: 0;
    color: #ede9fe;
    line-height: 1.55;
}

.ztvp-next {
    background: #f5f3ff;
    border: 1px solid #8b5cf6;
    color: #2e1065;
    border-radius: 18px;
    padding: 1rem 1.1rem;
    margin: 0.75rem 0 1.1rem 0;
    font-weight: 750;
    line-height: 1.5;
}

.ztvp-step {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 1.35rem 0 0.75rem 0;
}

.ztvp-step-number {
    width: 34px;
    height: 34px;
    border-radius: 999px;
    background: #7c3aed;
    color: #ffffff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
}

.ztvp-step h3 {
    margin: 0;
    color: #0f172a;
    font-size: 1.16rem;
    font-weight: 900;
}

.ztvp-alert {
    border-radius: 16px;
    padding: 0.92rem 1rem;
    margin: 0.75rem 0 1rem 0;
    font-weight: 650;
    line-height: 1.5;
}

.ztvp-info {
    background: #f5f3ff;
    border: 1px solid #8b5cf6;
    color: #2e1065;
}

.ztvp-warn {
    background: #fffbeb;
    border: 1px solid #f59e0b;
    color: #78350f;
}

.ztvp-good {
    background: #ecfdf5;
    border: 1px solid #10b981;
    color: #064e3b;
}

.ztvp-bad {
    background: #fef2f2;
    border: 1px solid #ef4444;
    color: #7f1d1d;
}

.ztvp-codebox {
    background: #0f172a;
    color: #ffffff;
    border-radius: 16px;
    padding: 0.95rem 1rem;
    font-family: Consolas, monospace;
    font-size: 0.93rem;
    overflow-x: auto;
    margin: 0.75rem 0;
}

.ztvp-big-code {
    text-align: center;
    font-size: 2.25rem;
    letter-spacing: 0.08em;
    font-weight: 950;
    background: #111827;
    color: #ffffff;
    padding: 1.2rem;
    border-radius: 20px;
    margin: 0.8rem 0;
}

.ztvp-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.85rem;
    margin-bottom: 1rem;
}

.ztvp-grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.85rem;
    margin-bottom: 1rem;
}

.ztvp-metric {
    background: #ffffff;
    border: 1px solid #dbe3ef;
    border-radius: 18px;
    padding: 1rem;
    box-shadow: 0 8px 18px rgba(15, 23, 42, 0.05);
}

.ztvp-metric span {
    display: block;
    color: #64748b;
    font-size: 0.78rem;
    font-weight: 800;
    margin-bottom: 0.45rem;
}

.ztvp-metric strong {
    color: #0f172a;
    font-size: 1.15rem;
    font-weight: 950;
    word-break: break-word;
}

.ztvp-metric.good strong {
    color: #15803d;
}

.ztvp-metric.warn strong {
    color: #b45309;
}

.ztvp-metric.bad strong {
    color: #b91c1c;
}

div.stButton > button,
div.stDownloadButton > button {
    border-radius: 14px !important;
    min-height: 44px !important;
    font-weight: 850 !important;
}

div.stButton > button {
    background: #7c3aed !important;
    color: #ffffff !important;
    border: 1px solid #7c3aed !important;
}

div.stButton > button:hover {
    background: #6d28d9 !important;
    border-color: #6d28d9 !important;
    color: #ffffff !important;
}

div.stButton > button:disabled {
    background: #e5e7eb !important;
    color: #6b7280 !important;
    border-color: #d1d5db !important;
    opacity: 1 !important;
}

div.stDownloadButton > button {
    background: #ffffff !important;
    color: #6d28d9 !important;
    border: 1px solid #ddd6fe !important;
}

[data-testid="stTextInput"] label,
[data-testid="stNumberInput"] label,
[data-testid="stCheckbox"] label {
    color: #0f172a !important;
    font-weight: 850 !important;
}

[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #cbd5e1 !important;
}

@media (max-width: 900px) {
    .ztvp-grid,
    .ztvp-grid-3 {
        grid-template-columns: 1fr;
    }

    .ztvp-big-code {
        font-size: 1.5rem;
    }
}
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
    evidence = _normalize_records(report.get("evidence"))
    attribution = report.get("policy_attribution", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    warnings = report.get("warnings", []) or []

    rows = ""

    for row in evidence:
        rows += f"""
<tr>
<td>{_safe(row.get("CreatedDateTime"))}</td>
<td>{_safe(row.get("UserPrincipalName"))}</td>
<td>{_safe(row.get("AppDisplayName"))}</td>
<td>{_safe(row.get("ResourceDisplayName"))}</td>
<td>{_safe(row.get("Status"))}</td>
<td>{_safe(row.get("AuthenticationProtocol"))}</td>
<td>{_safe(row.get("ConditionalAccessStatus"))}</td>
<td>{_safe(row.get("BlockPolicyNames"))}</td>
<td>{_safe(row.get("Success"))}</td>
<td>{_safe(row.get("Blocked"))}</td>
<td>{_safe(row.get("TokenLikelyIssuedFromLogs"))}</td>
<td>{_safe(row.get("IpAddress"))}</td>
<td>{_safe(row.get("RequestId"))}</td>
</tr>
"""

    if not rows:
        rows = '<tr><td colspan="13">No sign-in evidence found in the selected window.</td></tr>'

    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated.</li>"
    policy_names = attribution.get("block_policy_names", []) or []
    policy_names_text = ", ".join([str(x) for x in policy_names]) if policy_names else "None attributed"
    matched = report.get("matched_sign_in", {}) or {}
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
.hero {{ background:linear-gradient(135deg,#111827,#7c3aed); color:white; padding:34px; border-radius:26px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:20px; }}
.metric,.card {{ background:white; border:1px solid #dbe3ef; border-radius:20px; padding:20px; margin-top:18px; }}
.metric span {{ color:#64748b; font-size:13px; font-weight:700; }}
.metric strong {{ display:block; font-size:26px; margin-top:8px; }}
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
<p>Device Code Flow Block Evidence Report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(display_status)}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Token Issued</span><strong>{_safe(metrics.get("token_issued", False))}</strong></div>
<div class="metric"><span>Blocked Evidence</span><strong>{_safe(metrics.get("blocked_evidence_count", 0))}</strong></div>
</div>

<div class="card">
<h2>Control Tested</h2>
<p>{_safe(report.get("control_tested"))}</p>
<p><b>Expected Result:</b> {_safe(report.get("expected_result"))}</p>
<p><b>Failure Condition:</b> {_safe(report.get("failure_condition"))}</p>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Final Claim:</b> {_safe(report.get("final_claim"))}</p>
</div>

<div class="card">
<h2>Policy Attribution</h2>
<p><b>Block Policy Applied:</b> {_safe(attribution.get("device_code_block_policy_applied"))}</p>
<p><b>Attributed Block Policies:</b> {_safe(policy_names_text)}</p>
<p><b>Token Outcome:</b> {_safe(attribution.get("token_outcome"))}</p>
<p>{_safe(attribution.get("interpretation"))}</p>
</div>

<div class="card">
<h2>Warnings</h2>
<ul>{warning_rows}</ul>
</div>

<div class="card">
<h2>Decoy Context</h2>
<p><b>Decoy User:</b> {_safe(decoy.get("user_principal_name"))}</p>
<p><b>User ID:</b> {_safe(decoy.get("id"))}</p>
</div>

<div class="card">
<h2>Evidence Metrics</h2>
<pre>{_safe(json.dumps(metrics, indent=2))}</pre>
</div>

<div class="card">
<h2>Latest Matched Sign-in</h2>
<p><b>Time:</b> {_safe(matched.get("CreatedDateTime"))}</p>
<p><b>User:</b> {_safe(matched.get("UserPrincipalName"))}</p>
<p><b>App:</b> {_safe(matched.get("AppDisplayName"))}</p>
<p><b>Resource:</b> {_safe(matched.get("ResourceDisplayName"))}</p>
<p><b>Status:</b> {_safe(matched.get("Status"))}</p>
<p><b>Conditional Access:</b> {_safe(matched.get("ConditionalAccessStatus"))}</p>
<p><b>Request ID:</b> {_safe(matched.get("RequestId") or matched.get("SignInId"))}</p>
<p><b>IP:</b> {_safe(matched.get("IpAddress"))}</p>
<p><b>Blocking Policy:</b> {_safe(attribution.get("main_blocking_policy_name") or "Not attributed")}</p>
</div>

<div class="card">
<h2>Sign-in Evidence</h2>
<table>
<thead>
<tr>
<th>Created</th>
<th>User</th>
<th>App</th>
<th>Resource</th>
<th>Status</th>
<th>Protocol</th>
<th>CA Status</th>
<th>Blocking Policy</th>
<th>Success</th>
<th>Blocked</th>
<th>Token Likely Issued</th>
<th>IP</th>
<th>Request ID</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
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
    evidence = _normalize_records(report.get("evidence"))
    attribution = report.get("policy_attribution", {}) or {}
    warnings = report.get("warnings", []) or []
    configured = _normalize_records(report.get("configured_device_code_block_policies"))

    display_status = _friendly_status(report.get("status"))
    status_tone = _tone_for_status(report.get("status"))

    _alert("Device-code validation completed.", "good" if status_tone == "good" else "warn")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", display_status, status_tone)}
    {_metric("Risk", report.get("risk", "Unknown"), "good" if report.get("risk") == "LOW" else "warn")}
    {_metric("Token Issued", metrics.get("token_issued", False), "bad" if metrics.get("token_issued") else "good")}
    {_metric("Blocked Evidence", metrics.get("blocked_evidence_count", 0), "good" if metrics.get("blocked_evidence_count", 0) else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Control Tested")
    st.markdown(
        f"""
<div class="ztvp-alert ztvp-info">
<b>{_safe(report.get("control_tested", ""))}</b><br><br>
<b>Expected result:</b> {_safe(report.get("expected_result", ""))}<br>
<b>Failure condition:</b> {_safe(report.get("failure_condition", ""))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Validation Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    st.markdown("#### Policy Attribution")

    policy_names = attribution.get("block_policy_names", []) or []
    policy_names_text = ", ".join([str(x) for x in policy_names]) if policy_names else "None attributed"

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Block Policy Applied", "Yes" if attribution.get("device_code_block_policy_applied") else "No", "good" if attribution.get("device_code_block_policy_applied") else "warn")}
    {_metric("Block Policy Names", policy_names_text)}
    {_metric("Token Outcome", attribution.get("token_outcome", "Unknown"), "bad" if attribution.get("token_issued") else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.info(attribution.get("interpretation", ""))

    if configured:
        st.markdown("#### Configured Device-Code Block Policies")
        df_policy = pd.DataFrame(configured)
        cols = [c for c in ["displayName", "mode", "enforces", "reportOnly", "state"] if c in df_policy.columns]
        st.dataframe(df_policy[cols] if cols else df_policy, use_container_width=True, hide_index=True)

    if warnings:
        st.markdown("#### Warnings")
        for warning in warnings:
            _alert(warning, "warn")

    st.markdown("#### Evidence Metrics")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Target Sign-ins", metrics.get("target_signins_inside_lookback", 0))}
    {_metric("Device-Code Evidence", metrics.get("device_code_evidence_count", 0))}
    {_metric("Tenant Evidence Found", "Yes" if metrics.get("tenant_evidence_found") else "No", "good" if metrics.get("tenant_evidence_found") else "warn")}
    {_metric("Matching Sign-in Found", "Yes" if metrics.get("matching_signin_found") else "No", "good" if metrics.get("matching_signin_found") else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    matched = report.get("matched_sign_in") or {}
    if matched:
        st.markdown("#### Matched Sign-in")
        st.markdown(
            f"""
<div class="ztvp-grid">
    {_metric("Time", matched.get("CreatedDateTime"))}
    {_metric("User", matched.get("UserPrincipalName"))}
    {_metric("App", matched.get("AppDisplayName"))}
    {_metric("Resource", matched.get("ResourceDisplayName"))}
    {_metric("Status", matched.get("Status"))}
    {_metric("CA Status", matched.get("ConditionalAccessStatus"))}
    {_metric("Request ID", matched.get("RequestId") or matched.get("SignInId"))}
    {_metric("IP", matched.get("IpAddress"))}
    {_metric("Blocking Policy", attribution.get("main_blocking_policy_name") or "Not attributed", "good" if attribution.get("main_blocking_policy_name") else "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### Sign-in Evidence")

    if evidence:
        df = _compact_evidence(evidence)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            height=max(180, min(460, 90 + 38 * len(df))),
        )

        with st.expander("Evidence row details"):
            for index, row in enumerate(evidence, start=1):
                st.markdown(f"##### Evidence event {index}")
                st.json(row)
    else:
        _alert("No matching sign-in evidence was found for this exact decoy run.", "warn")

    st.markdown("#### Export Evidence")

    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="ID-DV-002-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="ID-DV-002-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def _render_background_run_summary(project_root: Path, run: dict) -> None:
    status = str(run.get("status") or "").lower()
    verdict = run.get("verdict") or "Pending"
    phase = run.get("phase") or "Running"
    message = run.get("current_message") or run.get("final_summary") or ""
    polls = f"{run.get('poll_attempts', 0)} / {run.get('max_poll_attempts', 'N/A')}"

    _alert(message or f"ID-DV-002 background run is {status}.", "good" if status == "completed" else "info")
    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", status.title() or "Unknown")}
    {_metric("Verdict", verdict)}
    {_metric("Phase", phase)}
    {_metric("Polls", polls)}
</div>
""",
        unsafe_allow_html=True,
    )

    col_active, col_cancel = st.columns(2)
    with col_active:
        if st.button("Open Active Runs", use_container_width=True, key=f"idc002_open_active_{run.get('run_id')}"):
            st.session_state["pending_navigation"] = {
                "main_navigation": "Active Runs",
                "pending_main_navigation": "Active Runs",
            }
            st.rerun()
            st.stop()
    with col_cancel:
        if status in ACTIVE_STATUSES:
            if st.button("Cancel This Run", use_container_width=True, key=f"idc002_cancel_{run.get('run_id')}"):
                request_cancel(project_root, str(run.get("run_id") or ""))
                st.rerun()

    report_path = Path(str(run.get("report_json_path") or run.get("report_path") or ""))
    html_path = Path(str(run.get("report_html_path") or run.get("html_report_path") or ""))
    if status == "completed" and report_path.exists():
        report = _load_json(report_path)
        if not html_path.exists():
            html_path = report_path.with_suffix(".html")
            _write_html_report(report, html_path)
        _render_report(report, report_path, html_path, "")


def render_idc002_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>ID-DV-002 — Device Code Flow Block Validation</h2>
    <p>This validates whether Microsoft Entra blocks a real OAuth device-code sign-in attempt before a token is issued.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    state_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-002"
    state_path = state_dir / "decoy-state.json"
    secret_path = state_dir / "decoy-secret-once.json"
    public_challenge_path = state_dir / "device-code-challenge-public.json"

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC002Decoy.ps1"
    start_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Start-ZTVP-IDC002DeviceCode.ps1"
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC002.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDC002Decoy.ps1"

    state = _load_json(state_path)
    challenge = _load_json(public_challenge_path)
    requested_run_id = st.session_state.get("ztvp_dynamic_open_run_id")
    selected_run = selected_run_for_scenario(project_root, "ID-DV-002", str(requested_run_id or "") or None)

    if selected_run and str(selected_run.get("status") or "").lower() in ACTIVE_STATUSES:
        _render_background_run_summary(project_root, selected_run)
        return

    if selected_run and (requested_run_id or str(selected_run.get("status") or "").lower() == "completed"):
        _render_background_run_summary(project_root, selected_run)
        st.session_state.pop("ztvp_dynamic_open_run_id", None)
        st.session_state.pop("ztvp_dynamic_open_run_status", None)
        st.session_state.pop("ztvp_dynamic_open_report_path", None)
        st.markdown("---")

    decoy = state.get("decoy_user", {}) or {}
    cleanup = state.get("cleanup", {}) or {}

    has_active_decoy = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active_decoy:
        current_action = "Generate a fresh decoy user"
        current_detail = "Start by creating a temporary test user. The password will be shown once."
    elif not challenge:
        current_action = "Start the device-code challenge"
        current_detail = "The decoy user exists. Now ask Microsoft Entra for a temporary device login code."
    else:
        current_action = "Complete the device-code attempt, then collect evidence"
        current_detail = "Open Microsoft device login, enter the code, sign in with the decoy user, then run validation."

    st.markdown(
        f"""
<div class="ztvp-next">
<b>Current action:</b> {_safe(current_action)}<br>
{_safe(current_detail)}
</div>
""",
        unsafe_allow_html=True,
    )

    _step(1, "Create or review the active decoy")

    if has_active_decoy:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("Cleanup", cleanup.get("status", "Pending"), "warn")}
    {_metric("Device Code", "Created" if challenge else "Not started", "good" if challenge else "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        st.markdown("**Exact decoy user for this run**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(decoy.get("user_principal_name", ""))}</div>', unsafe_allow_html=True)

        with st.expander("View active ID-DV-002 state"):
            st.json(state)

    else:
        _alert("No active decoy exists. Generate one below to start a clean test run.", "info")

        with st.container(border=True):
            st.markdown("#### Generate fresh device-code decoy")

            alias_prefix = st.text_input(
                "Decoy username prefix",
                value="ztvp-idc002-devicecode",
                key="idc002_prepare_alias_prefix",
            )

            display_name = st.text_input(
                "Display name",
                value="ZTVP ID-DV-002 Device Code Decoy User",
                key="idc002_prepare_display_name",
            )

            if st.button("Generate Fresh Device-Code Decoy", type="primary", use_container_width=True):
                args = [
                    "-DecoyAliasPrefix",
                    alias_prefix.strip() or "ztvp-idc002-devicecode",
                    "-DisplayName",
                    display_name.strip() or "ZTVP ID-DV-002 Device Code Decoy User",
                ]

                with st.spinner("Generating fresh ID-DV-002 decoy user..."):
                    completed = _run_powershell(project_root, prepare_script, args, timeout=900)

                if completed.returncode != 0:
                    _alert("Fresh decoy generation failed.", "bad")
                    st.code(completed.stderr or completed.stdout, language="text")
                else:
                    _alert("Fresh device-code decoy user created.", "good")
                    st.code(completed.stdout, language="text")

                    if secret_path.exists():
                        secret = _load_json(secret_path)
                        password = secret.get("temporary_password")

                        if password:
                            st.session_state["idc002_temp_password"] = password
                            st.session_state["idc002_temp_upn"] = secret.get("user_principal_name")

                        try:
                            secret_path.unlink()
                        except Exception:
                            pass

                    st.rerun()

    if st.session_state.get("idc002_temp_password"):
        _alert("Temporary password is shown once. Copy it now. It will not be stored in the report.", "warn")
        st.markdown(
            f"""
<div class="ztvp-codebox">
UPN: {_safe(st.session_state.get("idc002_temp_upn"))}<br>
Password: {_safe(st.session_state.get("idc002_temp_password"))}
</div>
""",
            unsafe_allow_html=True,
        )

    with st.expander("Emergency local reset"):
        _alert("Use this only if the tenant user was already deleted manually and ZTVP is still showing old local state.", "warn")

        if st.button("Reset Local ID-DV-002 State Only", use_container_width=True):
            for p in [
                state_path,
                secret_path,
                public_challenge_path,
                state_dir / "device-code-challenge-private.json",
                state_dir / "decoy-cleanup-result.json",
            ]:
                try:
                    p.unlink()
                except Exception:
                    pass

            _clear_session_keys()
            _alert("Local ID-DV-002 state reset.", "good")
            st.rerun()

    _step(2, "Start the device-code challenge")

    if not has_active_decoy:
        _alert("Generate a fresh decoy first. This step will unlock after the decoy exists.", "warn")

    elif challenge:
        _alert("A device-code challenge already exists for this run. Use the code shown in the next step.", "good")

    else:
        with st.container(border=True):
            _alert("This asks Microsoft Entra for a temporary device login code. ZTVP is not signing in as the user.", "info")

            client_id = st.text_input(
                "Device-code test client ID",
                value="14d82eec-204b-4c2f-b7e8-296a70dab67e",
                help="Default: Microsoft Graph PowerShell public client.",
                key="idc002_client_id",
            )

            scope = st.text_input(
                "Requested OAuth scope",
                value="https://graph.microsoft.com/User.Read",
                key="idc002_scope",
            )

            if st.button("Start Device-Code Challenge", type="primary", use_container_width=True):
                args = [
                    "-ClientId",
                    client_id.strip(),
                    "-Scope",
                    scope.strip(),
                ]

                with st.spinner("Requesting device-code challenge from Microsoft Entra..."):
                    completed = _run_powershell(project_root, start_script, args, timeout=300)

                if completed.returncode != 0:
                    _alert("Device-code challenge creation failed.", "bad")
                    st.code(completed.stderr or completed.stdout, language="text")
                else:
                    _alert("Device-code challenge created.", "good")
                    st.code(completed.stdout, language="text")
                    st.session_state.pop("idc002_evidence_start_utc", None)
                    st.rerun()

    _step(3, "Complete the controlled device-code attempt")

    state = _load_json(state_path)
    challenge = _load_json(public_challenge_path)
    decoy_upn = ((state.get("decoy_user", {}) or {}).get("user_principal_name") or "")

    if not challenge:
        _alert("Start the device-code challenge first. Then this step will show the Microsoft URL and user code.", "warn")

    else:
        verification_uri = challenge.get("verification_uri") or "https://microsoft.com/devicelogin"
        user_code = challenge.get("user_code", "")

        st.markdown("#### Use this Microsoft device login code")
        st.markdown(f'<div class="ztvp-big-code">{_safe(user_code)}</div>', unsafe_allow_html=True)

        st.markdown("**Before opening Microsoft device login**")
        mark_col, marker_col = st.columns([0.35, 0.65])
        with mark_col:
            if st.button("Mark Evidence Start Time", type="primary", use_container_width=True, key="idc002_mark_evidence_start"):
                st.session_state["idc002_evidence_start_utc"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                st.rerun()
                st.stop()
        with marker_col:
            marked_at = st.session_state.get("idc002_evidence_start_utc")
            if marked_at:
                _alert(f"Evidence search will start at {marked_at}. Now complete the Microsoft device login, then run validation.", "good")
            else:
                _alert("Click Mark Evidence Start Time first. Then do the Microsoft device login. Then run validation.", "warn")

        st.markdown("**Open this Microsoft page**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(verification_uri)}</div>', unsafe_allow_html=True)

        st.link_button("Open Microsoft Device Login", verification_uri, use_container_width=True)

        st.markdown("**Sign in with this exact decoy user**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(decoy_upn)}</div>', unsafe_allow_html=True)

        _alert(
            "Expected secure behavior: Microsoft Entra blocks the flow before a token is issued. Mark the evidence start time before the browser login so ZTVP searches the right sign-in window.",
            "info",
        )

        with st.expander("View device-code challenge details"):
            st.json(challenge)

    _step(4, "Collect token outcome and Entra evidence")

    if not challenge:
        _alert("This step is locked until a device-code challenge exists.", "warn")

    else:
        col1, col2 = st.columns(2)

        with col1:
            poll_minutes = st.number_input(
                "Token polling window minutes",
                min_value=1,
                max_value=15,
                value=8,
                step=1,
                key="idc002_poll_minutes",
            )

        with col2:
            lookback_minutes = st.number_input(
                "Sign-in log lookback minutes",
                min_value=5,
                max_value=720,
                value=240,
                step=15,
                key="idc002_lookback_minutes",
            )

        if st.button("Run Device-Code Enforcement Validation", type="primary", use_container_width=True):
            evidence_start_utc = st.session_state.get("idc002_evidence_start_utc")
            if not evidence_start_utc:
                _alert("Mark Evidence Start Time before running validation, then complete the device-code login.", "warn")
                st.stop()
            run = start_scenario_job(
                project_root,
                "ID-DV-002",
                wait_minutes=int(poll_minutes),
                poll_seconds=15,
                extra_args=[
                    "-PollMinutes",
                    str(int(poll_minutes)),
                    "-LookbackMinutes",
                    str(int(lookback_minutes)),
                    "-EvidenceStartUtc",
                    evidence_start_utc,
                ],
                target=decoy_upn,
            )
            _alert("ID-DV-002 is running in Active Runs. You can leave this page; polling will continue.", "good")
            _render_background_run_summary(project_root, run)
            st.rerun()

    _step(5, "Delete exact decoy and close test")

    state = _load_json(state_path)
    decoy = state.get("decoy_user", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active_decoy = bool(decoy.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active_decoy:
        _alert("No active ID-DV-002 decoy exists, so there is nothing to clean up.", "info")
        return

    with st.container(border=True):
        exact_upn = decoy.get("user_principal_name", "")

        _alert("After saving the report, delete the exact active decoy user below.", "warn")

        if exact_upn:
            st.markdown(f'<div class="ztvp-codebox">{_safe(exact_upn)}</div>', unsafe_allow_html=True)

        disable_instead = st.checkbox(
            "Disable instead of delete",
            value=False,
            key="idc002_cleanup_disable_instead",
        )

        if st.button("Delete This Exact Device-Code Decoy and Close Run", use_container_width=True):
            args = []

            if disable_instead:
                args.append("-DisableInsteadOfDelete")

            with st.spinner("Cleaning up ID-DV-002 decoy user and local state..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=900)

            if completed.returncode != 0:
                _alert("Cleanup failed.", "bad")
                st.code(completed.stderr or completed.stdout, language="text")
            else:
                _alert("ID-DV-002 cleanup completed.", "good")
                st.code(completed.stdout, language="text")
                _clear_session_keys()
                st.rerun()
