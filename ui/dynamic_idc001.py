from __future__ import annotations

import html
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


EVIDENCE_COLUMNS = [
    "CreatedDateTime",
    "EvidenceType",
    "AppDisplayName",
    "ResourceDisplayName",
    "AdminResourceAccessed",
    "AuthenticationRequirement",
    "ConditionalAccessStatus",
    "ConditionalAccessMfaPolicyApplied",
    "Success",
    "Interrupted",
    "RegistrationOnly",
    "MfaObserved",
    "MfaObservedForAccess",
    "PasswordOnlyPrivilegedSuccess",
    "IpAddress",
    "Location",
]


ROLE_OPTIONS = {
    "No role assignment": {
        "assign": False,
        "role": "",
        "risk": "None",
        "description": "Fresh decoy user without a directory role. Use this when a Conditional Access test group targets the user.",
    },
    "Directory Reader": {
        "assign": True,
        "role": "Directory Reader",
        "risk": "Low",
        "description": "Low-impact read-only directory role.",
    },
    "Reports Reader": {
        "assign": True,
        "role": "Reports Reader",
        "risk": "Low",
        "description": "Low-impact read-only reporting role.",
    },
    "Security Reader recommended": {
        "assign": True,
        "role": "Security Reader",
        "risk": "Medium",
        "description": "Recommended default. Security-sensitive read-only privileged role.",
    },
    "Global Reader": {
        "assign": True,
        "role": "Global Reader",
        "risk": "Medium",
        "description": "Broad read-only tenant visibility.",
    },
    "Conditional Access Administrator advanced": {
        "assign": True,
        "role": "Conditional Access Administrator",
        "risk": "High",
        "description": "Advanced role. Use only in approved test scope.",
    },
}


STATUS_LABELS = {
    "PASS_STRONG": "PASS — Strong Evidence",
    "PASS_CHALLENGED": "PASS — Challenge Observed",
    "FAIL": "FAIL — Password-only Privileged Access",
    "PARTIAL_REGISTRATION_ONLY": "PARTIAL — Registration Only",
    "PARTIAL_INTERACTIVE_NO_MFA_EVIDENCE": "PARTIAL — MFA Evidence Unclear",
    "PARTIAL_CORROBORATED": "PARTIAL — Supporting Evidence",
    "PARTIAL_NONINTERACTIVE_ONLY": "PARTIAL — Non-interactive Only",
    "PARTIAL_OUTSIDE_WINDOW": "PARTIAL — Outside Lookback",
    "NO_EVIDENCE": "NO EVIDENCE",
    "NO_SIGNIN_EVIDENCE_POLICY_CONFIGURED": "NO SIGN-IN EVIDENCE — MFA Policy Configured",
    "NO_SIGNIN_EVIDENCE_REPORT_ONLY_POLICY": "NO SIGN-IN EVIDENCE — Report-only MFA Policy",
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

    if text == "FAIL":
        return "bad"

    if text.startswith("PARTIAL"):
        return "warn"

    return "neutral"


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


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


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


def _compact_evidence(evidence: list[dict]) -> pd.DataFrame:
    if not evidence:
        return pd.DataFrame()

    df = pd.DataFrame(evidence)
    available = [column for column in EVIDENCE_COLUMNS if column in df.columns]

    if available:
        return df[available]

    return df


def _state_pending_cleanup(state: dict) -> bool:
    if not state:
        return False

    decoy = state.get("decoy_user", {}) or {}
    cleanup = state.get("cleanup", {}) or {}

    return bool(decoy.get("id")) and cleanup.get("status") != "Completed"


def _clear_session_decoy_keys() -> None:
    for key in ["idc001_temp_password", "idc001_temp_upn", "idc001_decoy_upn"]:
        st.session_state.pop(key, None)


def _css() -> None:
    st.markdown(
        """
<style>
.block-container {
    max-width: 1180px;
    padding-top: 1.2rem;
}

.ztvp-hero {
    background: linear-gradient(135deg, #0f172a 0%, #1d4ed8 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.2rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}

.ztvp-hero h2 {
    margin: 0 0 0.4rem 0;
    font-size: 1.35rem;
    font-weight: 900;
    color: #ffffff;
}

.ztvp-hero p {
    margin: 0;
    color: #dbeafe;
    line-height: 1.55;
}

.ztvp-card {
    background: #ffffff;
    border: 1px solid #dbe3ef;
    border-radius: 22px;
    padding: 1.2rem 1.3rem;
    margin-bottom: 1rem;
    box-shadow: 0 12px 28px rgba(15, 23, 42, 0.07);
}

.ztvp-step {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 1.45rem 0 0.8rem 0;
}

.ztvp-step-number {
    width: 34px;
    height: 34px;
    border-radius: 999px;
    background: #2563eb;
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
    padding: 0.95rem 1rem;
    margin: 0.75rem 0 1rem 0;
    font-weight: 650;
    line-height: 1.5;
}

.ztvp-info {
    background: #eff6ff;
    border: 1px solid #3b82f6;
    color: #172554;
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

.ztvp-upn {
    background: #0f172a;
    color: #ffffff;
    border-radius: 16px;
    padding: 0.95rem 1rem;
    font-family: Consolas, monospace;
    font-size: 0.92rem;
    overflow-x: auto;
    margin: 0.75rem 0;
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
    font-size: 1.18rem;
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

.ztvp-small {
    color: #64748b;
    font-size: 0.9rem;
    line-height: 1.55;
}

div.stButton > button,
div.stDownloadButton > button {
    border-radius: 14px !important;
    min-height: 44px !important;
    font-weight: 850 !important;
}

div.stButton > button {
    background: #2563eb !important;
    color: #ffffff !important;
    border: 1px solid #2563eb !important;
}

div.stButton > button:hover {
    background: #1d4ed8 !important;
    border-color: #1d4ed8 !important;
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
    color: #1d4ed8 !important;
    border: 1px solid #bfdbfe !important;
}

[data-testid="stTextInput"] label,
[data-testid="stNumberInput"] label,
[data-testid="stSelectbox"] label,
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

[data-baseweb="select"] > div {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #cbd5e1 !important;
}

@media (max-width: 900px) {
    .ztvp-grid,
    .ztvp-grid-3 {
        grid-template-columns: 1fr;
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


def _render_active_state(state: dict) -> None:
    if not state:
        _alert("No active decoy run exists. Generate a fresh decoy user for this validation.", "info")
        return

    decoy = state.get("decoy_user", {}) or {}
    role = state.get("role_assignment", {}) or {}
    cleanup = state.get("cleanup", {}) or {}

    active_upn = decoy.get("user_principal_name", "Unknown")
    cleanup_status = cleanup.get("status", "Pending")

    if cleanup_status == "Completed":
        _alert("Previous decoy run is closed. You can generate a new fresh decoy.", "good")
    else:
        _alert("Active fresh decoy found. Use this exact user for the validation, then delete it after evidence collection.", "warn")

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Active Run ID", state.get("run_id", "N/A"))}
    {_metric("Role", role.get("role_name", "None"))}
    {_metric("Cleanup", cleanup_status, "warn" if cleanup_status != "Completed" else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("**Exact active decoy UPN**")
    st.markdown(f'<div class="ztvp-upn">{_safe(active_upn)}</div>', unsafe_allow_html=True)

    if state.get("prepared_at"):
        st.caption(f"Prepared at: {state.get('prepared_at')}")

    with st.expander("View full active decoy state"):
        st.json(state)


def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    evidence = _normalize_records(report.get("evidence"))
    managed = report.get("managed_decoy", {}) or {}
    decoy = managed.get("decoy_user", {}) or {}
    role = managed.get("role_assignment", {}) or {}
    warnings = report.get("warnings", []) or []
    attribution = report.get("policy_attribution", {}) or {}

    rows = ""

    for row in evidence:
        rows += f"""
<tr>
<td>{_safe(row.get("CreatedDateTime"))}</td>
<td>{_safe(row.get("EvidenceType"))}</td>
<td>{_safe(row.get("AppDisplayName"))}</td>
<td>{_safe(row.get("ResourceDisplayName"))}</td>
<td>{_safe(row.get("AuthenticationRequirement"))}</td>
<td>{_safe(row.get("ConditionalAccessStatus"))}</td>
<td>{_safe(row.get("ConditionalAccessMfaPolicyApplied"))}</td>
<td>{_safe(row.get("Success"))}</td>
<td>{_safe(row.get("MfaObserved"))}</td>
<td>{_safe(row.get("PasswordOnlyPrivilegedSuccess"))}</td>
<td>{_safe(row.get("IpAddress"))}</td>
</tr>
"""

    if not rows:
        rows = '<tr><td colspan="11">No sign-in evidence found in the selected window.</td></tr>'

    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated for this run.</li>"
    policy_names = attribution.get("conditional_access_mfa_policy_names", []) or []
    policy_names_text = ", ".join([str(x) for x in policy_names]) if policy_names else "None attributed"

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    display_status = _friendly_status(report.get("status"))

    html_content = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</title>
<style>
body {{
    background: #f4f7fb;
    color: #0f172a;
    font-family: Segoe UI, Arial, sans-serif;
    margin: 0;
}}
.container {{
    max-width: 1180px;
    margin: 32px auto;
    padding: 0 24px;
}}
.hero {{
    background: linear-gradient(135deg, #0f172a, #2563eb);
    color: white;
    padding: 34px;
    border-radius: 26px;
}}
.metrics {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-top: 20px;
}}
.metric, .card {{
    background: white;
    border: 1px solid #dbe3ef;
    border-radius: 20px;
    padding: 20px;
    margin-top: 18px;
}}
.metric span {{
    color: #64748b;
    font-size: 13px;
    font-weight: 700;
}}
.metric strong {{
    display: block;
    font-size: 26px;
    margin-top: 8px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 14px;
    font-size: 13px;
}}
th {{
    background: #0f172a;
    color: white;
    text-align: left;
    padding: 10px;
}}
td {{
    border-bottom: 1px solid #e2e8f0;
    padding: 10px;
}}
pre {{
    background: #0f172a;
    color: #e5e7eb;
    padding: 18px;
    border-radius: 16px;
    overflow: auto;
}}
.footer {{
    color: #64748b;
    font-size: 13px;
    margin-top: 24px;
}}
</style>
</head>
<body>
<div class="container">
<div class="hero">
<h1>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</h1>
<p>Privileged Access MFA Enforcement Evidence Report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(display_status)}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Interactive Sign-ins</span><strong>{_safe(metrics.get("interactive_signins_count", 0))}</strong></div>
<div class="metric"><span>Password-only Privileged Success</span><strong>{_safe(metrics.get("password_only_privileged_success_count", 0))}</strong></div>
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
<p>{_safe(report.get("validation_explanation"))}</p>
</div>

<div class="card">
<h2>Policy Attribution</h2>
<p><b>MFA Source:</b> {_safe(attribution.get("mfa_source"))}</p>
<p><b>CA MFA Policy Applied:</b> {_safe(attribution.get("conditional_access_mfa_policy_applied"))}</p>
<p><b>Attributed CA MFA Policies:</b> {_safe(policy_names_text)}</p>
<p>{_safe(attribution.get("interpretation"))}</p>
</div>

<div class="card">
<h2>Warnings and Interpretation</h2>
<ul>{warning_rows}</ul>
</div>

<div class="card">
<h2>Fresh Decoy Context</h2>
<p><b>Run ID:</b> {_safe(managed.get("run_id", ""))}</p>
<p><b>Exact Decoy User:</b> {_safe(decoy.get("user_principal_name", report.get("target_user")))}</p>
<p><b>Selected Role:</b> {_safe(role.get("role_name", "None"))}</p>
<p><b>Role Assigned:</b> {_safe(role.get("assigned", False))}</p>
</div>

<div class="card">
<h2>Evidence Metrics</h2>
<pre>{_safe(json.dumps(metrics, indent=2))}</pre>
</div>

<div class="card">
<h2>Sign-in Evidence</h2>
<table>
<thead>
<tr>
<th>Created</th>
<th>Type</th>
<th>App</th>
<th>Resource</th>
<th>Auth Requirement</th>
<th>CA Status</th>
<th>CA MFA Policy</th>
<th>Success</th>
<th>MFA</th>
<th>Password-only Success</th>
<th>IP</th>
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

    html_path.write_text(html_content, encoding="utf-8")


def _render_report(report: dict, report_path: Path, html_path: Path, stdout: str) -> None:
    configured_policies = _normalize_records(report.get("configured_mfa_policies"))
    metrics = report.get("metrics", {}) or {}
    evidence = _normalize_records(report.get("evidence"))
    warnings = report.get("warnings", []) or []
    managed = report.get("managed_decoy", {}) or {}
    role = managed.get("role_assignment", {}) or {}
    attribution = report.get("policy_attribution", {}) or {}

    display_status = _friendly_status(report.get("status"))
    status_tone = _tone_for_status(report.get("status"))

    _alert("Probe completed successfully.", "good")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", display_status, status_tone)}
    {_metric("Risk", report.get("risk", "Unknown"), "good" if report.get("risk") == "LOW" else "warn")}
    {_metric("Interactive Sign-ins", metrics.get("interactive_signins_count", 0))}
    {_metric("Password-only Privileged Success", metrics.get("password_only_privileged_success_count", 0), "bad" if metrics.get("password_only_privileged_success_count", 0) else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Control Tested")
    st.markdown(
        f"""
<div class="ztvp-card">
    <p><b>{_safe(report.get("control_tested", ""))}</b></p>
    <p><b>Expected result:</b> {_safe(report.get("expected_result", ""))}</p>
    <p><b>Failure condition:</b> {_safe(report.get("failure_condition", ""))}</p>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Actual Validation Decision")
    st.markdown(
        f"""
<div class="ztvp-card">
    <p>{_safe(report.get("executive_summary", ""))}</p>
    <p><b>Final claim:</b> {_safe(report.get("final_claim", ""))}</p>
    <p class="ztvp-small">{_safe(report.get("validation_explanation", ""))}</p>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Policy Attribution")

    policy_names = attribution.get("conditional_access_mfa_policy_names", []) or []
    policy_names_text = ", ".join([str(x) for x in policy_names]) if policy_names else "None attributed"

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("MFA Source", attribution.get("mfa_source", "Unknown"))}
    {_metric("CA MFA Policy Applied", "Yes" if attribution.get("conditional_access_mfa_policy_applied") else "No", "good" if attribution.get("conditional_access_mfa_policy_applied") else "warn")}
    {_metric("CA MFA Policy Names", policy_names_text)}
</div>
<div class="ztvp-card">
    <p>{_safe(attribution.get("interpretation", ""))}</p>
</div>
""",
        unsafe_allow_html=True,
    )


    if configured_policies:
        st.markdown("#### Configured Conditional Access MFA Policies")

        policy_df = pd.DataFrame(configured_policies)
        visible_cols = [
            col for col in [
                "displayName",
                "mode",
                "enforces",
                "reportOnly",
                "targetsAllUsers",
                "targetsAllApps",
                "state",
            ]
            if col in policy_df.columns
        ]

        if visible_cols:
            st.dataframe(policy_df[visible_cols], use_container_width=True, hide_index=True)
        else:
            st.json(configured_policies)

    if warnings:
        st.markdown("#### Warnings and Interpretation")
        for warning in warnings:
            _alert(warning, "warn")

    st.markdown("#### Fresh Decoy Context")

    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", managed.get("run_id", "N/A"))}
    {_metric("Decoy Role", role.get("role_name", "None"))}
    {_metric("Role Assigned", "Yes" if role.get("assigned") else "No", "good" if role.get("assigned") else "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Evidence Metrics")

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Graph Sign-ins Scanned", metrics.get("graph_signins_scanned", 0))}
    {_metric("Target Sign-ins", metrics.get("target_signins_inside_lookback", 0))}
    {_metric("Interactive Admin Access", metrics.get("interactive_admin_resource_access_count", 0))}
    {_metric("MFA Evidence", metrics.get("mfa_evidence_count", 0), "good" if metrics.get("mfa_evidence_count", 0) else "warn")}
</div>
<div class="ztvp-grid-3">
    {_metric("Registration-only Sign-ins", metrics.get("interactive_registration_only_count", 0), "warn" if metrics.get("interactive_registration_only_count", 0) else "")}
    {_metric("Post-registration MFA Evidence", metrics.get("interactive_mfa_evidence_count", 0), "good" if metrics.get("interactive_mfa_evidence_count", 0) else "warn")}
    {_metric("Interactive Interruptions", metrics.get("interactive_interrupted_count", 0), "good" if metrics.get("interactive_interrupted_count", 0) else "warn")}
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
        _alert("No sign-in evidence was found inside the selected lookback window.", "warn")

    st.markdown("#### Export Evidence")

    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="ID-C-001-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="ID-C-001-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def render_idc001_runner(project_root: Path) -> None:
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>ID-C-001 — Privileged Access MFA Enforcement Validation</h2>
    <p>This validation checks whether a temporary privileged identity can access Azure/admin resources with password-only authentication, or whether the tenant enforces MFA before access is granted.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    state_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-001"
    state_path = state_dir / "decoy-state.json"
    secret_path = state_dir / "decoy-secret-once.json"
    verify_path = state_dir / "decoy-verify-result.json"

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC001Decoy.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDC001Decoy.ps1"
    verify_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Verify-ZTVP-IDC001Decoy.ps1"
    probe_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC001.ps1"

    state = _load_json(state_path)
    pending_cleanup = _state_pending_cleanup(state)

    _step(1, "Active Decoy Run")
    _render_active_state(state)

    col_verify, col_reset = st.columns(2)

    with col_verify:
        if st.button("Verify Exact Decoy Exists", use_container_width=True, disabled=not bool(state)):
            try:
                verify_path.unlink()
            except Exception:
                pass

            with st.spinner("Verifying exact active decoy user in Entra ID..."):
                completed = _run_powershell(project_root, verify_script, [], timeout=900)

            if completed.returncode != 0:
                _alert("Verification failed.", "bad")
                st.code(completed.stderr or completed.stdout, language="text")
            else:
                _alert("Verification completed.", "good")
                st.code(completed.stdout, language="text")

                if verify_path.exists():
                    st.json(_load_json(verify_path))

    with col_reset:
        with st.expander("Emergency local reset"):
            _alert("Use this only if the tenant user was already deleted manually and ZTVP is still showing old local state.", "warn")

            if st.button("Reset Local Decoy State Only", use_container_width=True, key="idc001_reset_local_state"):
                for path in [
                    state_path,
                    secret_path,
                    state_dir / "decoy-cleanup-result.json",
                    verify_path,
                ]:
                    try:
                        path.unlink()
                    except Exception:
                        pass

                _clear_session_decoy_keys()
                _alert("Local decoy state reset.", "good")
                st.rerun()

    _step(2, "Generate Fresh Privileged Decoy")

    with st.container(border=True):
        alias_prefix = st.text_input(
            "Decoy username prefix",
            value="ztvp-idc001-decoy",
            help="ZTVP appends timestamp and a random suffix automatically.",
            key="idc001_prepare_alias_prefix",
        )

        display_name = st.text_input(
            "Display name",
            value="ZTVP ID-C-001 Decoy Privileged User",
            key="idc001_prepare_display_name",
        )

        role_label = st.selectbox(
            "Role profile for this temporary decoy",
            list(ROLE_OPTIONS.keys()),
            index=3,
            key="idc001_role_profile",
        )

        selected_role = ROLE_OPTIONS[role_label]

        st.markdown(
            f"""
<div class="ztvp-alert ztvp-info">
<b>Selected role:</b> {_safe(selected_role["description"])}<br>
<b>Sensitivity:</b> {_safe(selected_role["risk"])}
</div>
""",
            unsafe_allow_html=True,
        )

        if selected_role["risk"] == "High":
            advanced_confirm = st.checkbox(
                "I understand this is an advanced administrative role and the user will be deleted after the test.",
                key="idc001_advanced_role_confirm",
            )
        else:
            advanced_confirm = True

        if pending_cleanup:
            _alert("Close or delete the active decoy before generating a new one.", "warn")

        if st.button(
            "Generate Fresh Decoy User",
            type="primary",
            use_container_width=True,
            disabled=pending_cleanup,
            key="idc001_generate_fresh_decoy",
        ):
            if not advanced_confirm:
                _alert("Confirm the advanced role warning before generating this decoy.", "bad")
                return

            args = [
                "-DecoyAliasPrefix",
                alias_prefix.strip() or "ztvp-idc001-decoy",
                "-DisplayName",
                display_name.strip() or "ZTVP ID-C-001 Decoy Privileged User",
            ]

            if selected_role["assign"]:
                args += ["-AssignRole", "-RoleName", selected_role["role"]]

            with st.spinner("Generating fresh decoy user and temporary password..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=900)

            if completed.returncode != 0:
                _alert("Fresh decoy generation failed.", "bad")
                st.code(completed.stderr or completed.stdout, language="text")
            else:
                _alert("Fresh decoy user created.", "good")
                st.code(completed.stdout, language="text")

                if secret_path.exists():
                    secret = _load_json(secret_path)
                    password = secret.get("temporary_password")

                    if password:
                        st.session_state["idc001_temp_password"] = password
                        st.session_state["idc001_temp_upn"] = secret.get("user_principal_name")

                    try:
                        secret_path.unlink()
                    except Exception:
                        pass

                st.rerun()

    if st.session_state.get("idc001_temp_password"):
        _alert("Temporary password is shown once. Copy it now. It will not be stored in the report.", "warn")
        st.markdown(
            f"""
<div class="ztvp-upn">
UPN: {_safe(st.session_state.get("idc001_temp_upn"))}<br>
Password: {_safe(st.session_state.get("idc001_temp_password"))}
</div>
""",
            unsafe_allow_html=True,
        )

    state = _load_json(state_path)
    decoy_upn = ((state.get("decoy_user", {}) or {}).get("user_principal_name") or "")

    _step(3, "Register MFA, Sign Out, Then Run the Real Login Test")

    _alert(
        "The first sign-in for a new user can be MFA/security-info registration. That setup step does not count as MFA enforcement. Complete registration if prompted, sign out fully, then start a fresh private/incognito browser and sign in again to test real privileged access.",
        "info",
    )

    if decoy_upn:
        st.markdown(f'<div class="ztvp-upn">{_safe(decoy_upn)}</div>', unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown("#### Phase A - Initial setup only")
        st.markdown(
            "Use the decoy user once to complete password/security-info/MFA registration if Microsoft asks for it. This phase only prepares the account."
        )
        col_setup_1, col_setup_2 = st.columns(2)
        with col_setup_1:
            st.link_button("Open Office Portal for Setup", "https://portal.office.com", use_container_width=True)
        with col_setup_2:
            st.link_button("Sign Out After Setup", "https://login.microsoftonline.com/common/oauth2/v2.0/logout", use_container_width=True)

    with st.container(border=True):
        st.markdown("#### Phase B - Actual MFA enforcement test")
        st.markdown(
            "After signing out, open a fresh private/incognito browser and sign in again with the same decoy user. This second sign-in is the evidence ZTVP uses to prove MFA enforcement."
        )

        ready_for_validation = st.checkbox(
            "I completed any first-time registration, signed out, and will now perform the second login test.",
            key="idc001_post_registration_ready",
        )

        col_office, col_azure = st.columns(2)

        with col_office:
            st.link_button("Open Office Portal Login Test", "https://portal.office.com", use_container_width=True, disabled=not ready_for_validation)

        with col_azure:
            st.link_button("Open Azure Portal Login Test", "https://portal.azure.com", use_container_width=True, disabled=not ready_for_validation)

    _step(4, "Collect Microsoft Entra Evidence")

    if decoy_upn:
        st.session_state["idc001_decoy_upn"] = decoy_upn

    col_upn, col_lookback = st.columns([2, 1])

    with col_upn:
        upn = st.text_input(
            "Decoy privileged user UPN",
            placeholder="Generate a fresh decoy first",
            key="idc001_decoy_upn",
        )

    with col_lookback:
        lookback = st.number_input(
            "Lookback minutes",
            min_value=5,
            max_value=720,
            value=240,
            step=15,
            key="idc001_lookback",
        )

    post_registration_ready = bool(st.session_state.get("idc001_post_registration_ready"))
    if not post_registration_ready:
        _alert("Complete registration if prompted, sign out, then perform the second login test before collecting evidence.", "warn")

    if st.button("Run Enforcement Evidence Validation", type="primary", use_container_width=True, key="run_idc001_probe_button", disabled=not post_registration_ready):
        target_upn = upn.strip()

        if not target_upn:
            _alert("Generate a fresh decoy user first or enter the decoy UPN.", "bad")
            return

        with st.spinner("Collecting Microsoft Entra sign-in evidence through Microsoft Graph..."):
            completed = _run_powershell(
                project_root,
                probe_script,
                [
                    "-DecoyUserPrincipalName",
                    target_upn,
                    "-LookbackMinutes",
                    str(int(lookback)),
                ],
                timeout=900,
            )

        report_path = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-001-result.json"
        html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "ID-C-001-result.html"

        if completed.returncode != 0:
            _alert("ID-C-001 failed.", "bad")
            st.code(completed.stderr or completed.stdout, language="text")
            return

        if not report_path.exists():
            _alert("Probe completed, but the JSON report was not found.", "warn")
            st.code(completed.stdout, language="text")
            return

        report = _load_json(report_path)
        managed_state = _load_json(state_path)

        if managed_state:
            report["managed_decoy"] = {
                "run_id": managed_state.get("run_id"),
                "lifecycle": managed_state.get("lifecycle"),
                "prepared_at": managed_state.get("prepared_at"),
                "decoy_user": managed_state.get("decoy_user", {}),
                "role_profile": managed_state.get("role_profile", {}),
                "role_assignment": managed_state.get("role_assignment", {}),
                "cleanup": managed_state.get("cleanup", {}),
            }
            _write_json(report_path, report)

        _write_html_report(report, html_path)
        _render_report(report, report_path, html_path, completed.stdout)

    _step(5, "Delete Exact Decoy and Close Test")

    with st.container(border=True):
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        exact_upn = decoy.get("user_principal_name", "")

        _alert("This action deletes the exact active decoy user shown below and closes the current validation run.", "warn")

        if exact_upn:
            st.markdown(f'<div class="ztvp-upn">{_safe(exact_upn)}</div>', unsafe_allow_html=True)

        disable_instead = st.checkbox(
            "Disable instead of delete",
            value=False,
            key="idc001_cleanup_disable_instead",
        )

        if st.button("Delete This Exact Decoy and Close Run", use_container_width=True):
            args = []

            if disable_instead:
                args.append("-DisableInsteadOfDelete")

            with st.spinner("Removing the exact fresh decoy user from the tenant..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=900)

            if completed.returncode != 0:
                _alert("Cleanup failed.", "bad")
                st.code(completed.stderr or completed.stdout, language="text")
            else:
                _alert("Exact decoy cleanup completed.", "good")
                st.code(completed.stdout, language="text")

                cleanup_path = state_dir / "decoy-cleanup-result.json"

                if cleanup_path.exists():
                    with st.expander("Cleanup result"):
                        st.json(_load_json(cleanup_path))

                _clear_session_decoy_keys()
                st.rerun()

