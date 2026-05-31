from __future__ import annotations

import html
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from background_jobs import start_scenario_job
from run_state import ACTIVE_STATUSES, load_run, request_cancel, selected_run_for_scenario


STATUS_LABELS = {
    "PASS_LATEST_GUEST_ATTEMPT_BLOCKED_OR_INTERRUPTED": "PASS — Latest Guest Attempt Blocked or Interrupted",
    "PASS_GUEST_ADMIN_PORTAL_BLOCKED_LATEST": "PASS — Guest Admin Portal Blocked",
    "PASS_GUEST_SIGNIN_BLOCKED_OR_INTERRUPTED": "PASS — Latest Guest Attempt Blocked or Interrupted",
    "PASS_GUEST_ADMIN_PORTAL_BLOCKED_STRONG": "PASS — Guest Admin Portal Blocked",
    "PASS_GUEST_ADMIN_PORTAL_BLOCKED": "PASS — Guest Admin Portal Blocked",
    "PASS_GUEST_ADMIN_PORTAL_BLOCKED_BROWSER": "PASS — Guest Admin Portal Blocked",
    "PARTIAL_CONFLICT_BROWSER_REACHED_TELEMETRY_BLOCKED": "CONFLICT — Browser Reached Portal but Latest Telemetry Blocked",
    "FAIL_GUEST_ADMIN_PORTAL_ALLOWED": "FAIL — Guest Admin Portal Allowed",
    "FAIL_GUEST_ADMIN_PORTAL_ALLOWED_BROWSER": "FAIL — Guest Admin Portal Allowed",
    "FAIL_BROWSER_OBSERVED_TELEMETRY_PENDING": "FAIL — Browser Reached Admin Portal, Telemetry Pending",
    "PARTIAL_BROWSER_BLOCKED_TELEMETRY_PENDING": "PARTIAL — Browser Blocked, Telemetry Pending",
    "PARTIAL_NO_ADMIN_PORTAL_TELEMETRY": "PARTIAL — No Admin Portal Telemetry Found",
    "PARTIAL_INVITATION_NOT_REDEEMED": "PARTIAL — Invitation Not Redeemed",
    "PARTIAL_SIGNIN_INTERRUPTED": "PARTIAL — Sign-in Interrupted",
    "PARTIAL_NO_ADMIN_PORTAL_EVIDENCE": "PARTIAL — No Admin Portal Evidence",
    "PARTIAL_NO_GUEST_SIGNIN_EVIDENCE": "PARTIAL — No Guest Sign-in Evidence",
}

OBSERVED_OUTCOMES = {
    "Auto-detect from Entra sign-in evidence": "AUTO_DETECT",
    "Microsoft showed: access blocked / you cannot access this app": "ACCESS_BLOCKED",
    "Guest reached Azure Portal or admin portal": "REACHED_ADMIN_PORTAL",
    "Sign-in was interrupted before portal access decision": "SIGNIN_INTERRUPTED",
    "Invitation was not redeemed": "INVITATION_NOT_REDEEMED",
}

EVIDENCE_COLUMNS = [
    "createdDateTimeUtc",
    "signInType",
    "userPrincipalName",
    "userId",
    "appDisplayName",
    "resourceDisplayName",
    "statusErrorCode",
    "statusFailureReason",
    "conditionalAccessStatus",
    "appliedPolicyNames",
    "ipAddress",
    "matchedIdentifier",
    "resultCategory",
]


def _safe(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _friendly_status(status: object) -> str:
    return STATUS_LABELS.get(str(status or ""), str(status or "Unknown"))


def _tone_for_status(status: object) -> str:
    text = str(status or "").upper()

    if "CONFLICT" in text:
        return "warn"

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



def _format_graph_datetime(value: object) -> str:
    text = str(value or "")

    match = re.search(r"/Date\((\d+)\)/", text)

    if match:
        try:
            milliseconds = int(match.group(1))
            return datetime.utcfromtimestamp(milliseconds / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return text

    if "T" in text:
        return text.replace("T", " ").replace("Z", " UTC")

    return text


def _boolish(value: object) -> bool:
    return str(value).strip().lower() in ["true", "1", "yes"]


def _row_value(row: dict, *names: str) -> Any:
    for name in names:
        if name in row:
            return row.get(name)
    return None


def _as_records(report: dict, key: str) -> list[dict]:
    return _normalize_records(report.get(key))


def _join_values(value: object) -> str:
    if isinstance(value, list):
        return ", ".join([str(item) for item in value if str(item).strip()])
    if value is None:
        return ""
    return str(value)


def _result_tone(result: object) -> str:
    text = str(result or "").upper()

    if text == "SUCCESS":
        return "bad"

    if text == "BLOCKED_OR_INTERRUPTED":
        return "good"

    return "warn"


def _simple_guest_result(row: dict) -> str:
    result = str(_row_value(row, "resultCategory", "ResultCategory") or "").upper()

    if result == "SUCCESS" or _boolish(_row_value(row, "success", "Success")):
        return "Allowed"

    if result == "BLOCKED_OR_INTERRUPTED" or _boolish(_row_value(row, "blockedOrInterrupted", "Blocked")):
        return "Blocked / Interrupted"

    return "Observed"


def _simple_policy_names(row: dict) -> str:
    names = _row_value(row, "blockingPolicyNames", "BlockPolicyNames", "appliedPolicyNames")

    if isinstance(names, list) and names:
        return ", ".join([str(x) for x in names if str(x).strip()])

    return ""


def _simple_evidence_rows(evidence: list[dict]) -> list[dict]:
    rows = []

    for row in evidence:
        rows.append(
            {
                "createdDateTimeUtc": _format_graph_datetime(_row_value(row, "createdDateTimeUtc", "CreatedDateTime")),
                "signInType": _row_value(row, "signInType", "SignInType"),
                "userPrincipalName": _row_value(row, "userPrincipalName", "UserPrincipalName"),
                "userId": _row_value(row, "userId", "UserId"),
                "appDisplayName": _row_value(row, "appDisplayName", "AppDisplayName"),
                "resourceDisplayName": _row_value(row, "resourceDisplayName", "ResourceDisplayName"),
                "status.errorCode": _row_value(row, "statusErrorCode", "StatusCode"),
                "status.failureReason": _row_value(row, "statusFailureReason", "FailureReason"),
                "conditionalAccessStatus": _row_value(row, "conditionalAccessStatus", "ConditionalAccessStatus"),
                "appliedPolicyNames": _simple_policy_names(row),
                "ipAddress": _row_value(row, "ipAddress", "IpAddress"),
                "matchedIdentifier": _row_value(row, "matchedIdentifier", "MatchedIdentifier"),
                "resultCategory": _row_value(row, "resultCategory", "ResultCategory") or _simple_guest_result(row),
                "evidenceSource": _row_value(row, "evidenceSource", "EvidenceSource"),
            }
        )

    return rows



def _idc005_attempt_window_path(project_root: Path) -> Path:
    return Path(project_root) / "powershell" / "Reports" / "Dynamic" / "ID-C-005" / "guest-attempt-window.json"


def _load_idc005_attempt_window(project_root: Path) -> dict:
    path = _idc005_attempt_window_path(project_root)

    if not path.exists():
        return {}

    try:
        return _load_json(path)
    except Exception:
        return {}


def _save_idc005_attempt_window(project_root: Path) -> dict:
    path = _idc005_attempt_window_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "attempt_started_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "note": "Only sign-in evidence created after this timestamp should be used for the retest decision.",
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload



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


def _render_background_run_summary(project_root: Path, run: dict) -> None:
    status = str(run.get("status") or "").lower()
    st.info("ID-DV-005 validation is currently running." if status in ACTIVE_STATUSES else "ID-DV-005 run state restored.")
    cols = st.columns(4)
    cols[0].metric("Phase", run.get("phase") or "Unknown")
    cols[1].metric("Progress", f"{int(run.get('progress_percent') or 0)}%")
    cols[2].metric("Graph", run.get("graph_connection_status") or "Unknown")
    cols[3].metric("External email", run.get("external_test_email") or "Not recorded")
    st.caption(f"Started UTC: {run.get('started_utc') or 'Not recorded'} | Last updated UTC: {run.get('last_updated_utc') or 'Not recorded'}")
    if run.get("current_message"):
        st.write(run.get("current_message"))
    col_active, col_cancel = st.columns(2)
    if col_active.button("Open Active Runs", use_container_width=True, key="idc005_open_active_runs"):
        st.session_state["pending_navigation"] = {"main_navigation": "Active Runs", "pending_main_navigation": "Active Runs"}
        st.rerun()
    if status in ACTIVE_STATUSES and col_cancel.button("Cancel", use_container_width=True, key="idc005_cancel_active_run"):
        request_cancel(project_root, str(run.get("run_id") or ""))
        st.rerun()
    if status not in ACTIVE_STATUSES:
        st.markdown("#### Final output")
        final_cols = st.columns(4)
        final_cols[0].metric("Verdict", run.get("verdict") or "Unknown")
        final_cols[1].metric("Risk", run.get("risk") or "Unknown")
        final_cols[2].metric("Invitation attempted", "Yes" if run.get("guest_invitation_attempted") else "No")
        final_cols[3].metric("Invitation succeeded", "Yes" if run.get("guest_invitation_succeeded") else "No")
        st.write(f"Tenant blocked invite: {'Yes' if run.get('tenant_blocked_invite') else 'No'}")
        if run.get("error_category"):
            st.write(f"Error category: `{run.get('error_category')}`")
        html_path = Path(str(run.get("html_report_path") or run.get("report_html_path") or ""))
        json_path = Path(str(run.get("report_json_path") or run.get("report_path") or ""))
        c1, c2 = st.columns(2)
        if html_path.exists():
            c1.download_button("View HTML report", html_path.read_bytes(), html_path.name, "text/html", use_container_width=True, key="idc005_final_html")
        if json_path.exists():
            c2.download_button("Download JSON evidence", json_path.read_bytes(), json_path.name, "application/json", use_container_width=True, key="idc005_final_json")


def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero {
    background: linear-gradient(135deg, #111827 0%, #0891b2 100%);
    color: #ffffff;
    padding: 1.45rem 1.6rem;
    border-radius: 24px;
    margin-bottom: 1.1rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.18);
}
.ztvp-hero h2 { margin: 0 0 0.35rem 0; font-size: 1.35rem; font-weight: 900; color: #ffffff; }
.ztvp-hero p { margin: 0; color: #cffafe; line-height: 1.55; }
.ztvp-step { display: flex; align-items: center; gap: 0.75rem; margin: 1.35rem 0 0.75rem 0; }
.ztvp-step-number { width: 34px; height: 34px; border-radius: 999px; background: #0891b2; color: #ffffff; display: inline-flex; align-items: center; justify-content: center; font-weight: 900; }
.ztvp-step h3 { margin: 0; color: #0f172a; font-size: 1.16rem; font-weight: 900; }
.ztvp-alert { border-radius: 16px; padding: 0.92rem 1rem; margin: 0.75rem 0 1rem 0; font-weight: 650; line-height: 1.5; }
.ztvp-info { background: #ecfeff; border: 1px solid #06b6d4; color: #164e63; }
.ztvp-warn { background: #fffbeb; border: 1px solid #f59e0b; color: #78350f; }
.ztvp-good { background: #ecfdf5; border: 1px solid #10b981; color: #064e3b; }
.ztvp-bad { background: #fef2f2; border: 1px solid #ef4444; color: #7f1d1d; }
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
    background: #0891b2 !important;
    color: #ffffff !important;
    border: 1px solid #0891b2 !important;
}
div.stButton > button:hover,
div[data-testid="stButton"] button:hover,
button[kind="primary"]:hover,
button[data-testid="baseButton-primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #0e7490 !important;
    border-color: #0e7490 !important;
    color: #ffffff !important;
}
div.stDownloadButton > button,
div[data-testid="stDownloadButton"] button {
    background: #ffffff !important;
    color: #0e7490 !important;
    border: 1px solid #a5f3fc !important;
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


def _metric(label: str, value: object, tone: str = "") -> str:
    return f"""
<div class="ztvp-metric {tone}">
    <span>{_safe(label)}</span>
    <strong>{_safe(value)}</strong>
</div>
"""



def _guest_identity_values(report: dict) -> dict:
    guest = report.get("guest_user", {}) or {}

    return {
        "external_email": guest.get("external_email", "N/A"),
        "guest_upn": guest.get("user_principal_name", "N/A"),
        "guest_id": guest.get("id", "N/A"),
        "external_state": guest.get("external_user_state", "N/A"),
    }


def _html_evidence_rows(rows: list[dict], empty_message: str) -> str:
    if not rows:
        return f'<tr><td colspan="13">{_safe(empty_message)}</td></tr>'

    html_rows = ""

    for row in rows:
        html_rows += f"""
<tr>
<td>{_safe(_format_graph_datetime(_row_value(row, "createdDateTimeUtc", "CreatedDateTime")))}</td>
<td>{_safe(_row_value(row, "signInType", "SignInType"))}</td>
<td>{_safe(_row_value(row, "userPrincipalName", "UserPrincipalName"))}</td>
<td>{_safe(_row_value(row, "userId", "UserId"))}</td>
<td>{_safe(_row_value(row, "appDisplayName", "AppDisplayName"))}</td>
<td>{_safe(_row_value(row, "resourceDisplayName", "ResourceDisplayName"))}</td>
<td>{_safe(_row_value(row, "statusErrorCode", "StatusCode"))}</td>
<td>{_safe(_row_value(row, "statusFailureReason", "FailureReason"))}</td>
<td>{_safe(_row_value(row, "conditionalAccessStatus", "ConditionalAccessStatus"))}</td>
<td>{_safe(_simple_policy_names(row))}</td>
<td>{_safe(_row_value(row, "ipAddress", "IpAddress"))}</td>
<td>{_safe(_row_value(row, "matchedIdentifier", "MatchedIdentifier"))}</td>
<td>{_safe(_row_value(row, "resultCategory", "ResultCategory"))}</td>
</tr>
"""

    return html_rows


def _evidence_table_header() -> str:
    return """
<thead>
<tr>
<th>createdDateTimeUtc</th>
<th>signInType</th>
<th>userPrincipalName</th>
<th>userId</th>
<th>appDisplayName</th>
<th>resourceDisplayName</th>
<th>status.errorCode</th>
<th>status.failureReason</th>
<th>conditionalAccessStatus</th>
<th>appliedPolicyNames</th>
<th>ipAddress</th>
<th>matchedIdentifier</th>
<th>resultCategory</th>
</tr>
</thead>
"""



def _write_html_report(report: dict, html_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = report.get("metrics", {}) or {}
    admin_evidence = _as_records(report, "admin_portal_evidence")
    invitation_evidence = _as_records(report, "invitation_redemption_evidence")
    historical_evidence = _as_records(report, "historical_portal_evidence")
    warnings = report.get("warnings", []) or []
    policy = report.get("policy_attribution", {}) or {}
    guest_identity = _guest_identity_values(report)
    display_status = _friendly_status(report.get("status"))
    latest_attempt = report.get("latest_admin_portal_attempt", {}) or {}
    browser = report.get("browser_observation", {}) or {}
    window = report.get("validation_window", {}) or {}
    warning_rows = "".join([f"<li>{_safe(w)}</li>" for w in warnings]) or "<li>No warnings were generated.</li>"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    policy_names = policy.get("block_policy_names", []) or []
    all_policy_names = policy.get("all_policy_names", []) or []
    policy_text = ", ".join([str(x) for x in policy_names]) or ", ".join([str(x) for x in all_policy_names]) or "No policy names present in matching admin portal rows."

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</title>
<style>
body {{ background:#f4f7fb; color:#0f172a; font-family:Segoe UI,Arial,sans-serif; margin:0; }}
.container {{ max-width:1180px; margin:32px auto; padding:0 24px; }}
.hero {{ background:linear-gradient(135deg,#111827,#0891b2); color:white; padding:34px; border-radius:26px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-top:20px; }}
.metric,.card {{ background:white; border:1px solid #dbe3ef; border-radius:20px; padding:20px; margin-top:18px; }}
.metric span {{ color:#64748b; font-size:13px; font-weight:700; }}
.metric strong {{ display:block; font-size:22px; margin-top:8px; }}
table {{ width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; }}
th {{ background:#0f172a; color:white; text-align:left; padding:10px; }}
td {{ border-bottom:1px solid #e2e8f0; padding:10px; }}
pre {{ background:#0f172a; color:#e5e7eb; padding:18px; border-radius:16px; overflow:auto; }}
.footer {{ color:#64748b; font-size:13px; margin-top:24px; }}
.banner {{ border-radius:18px; padding:16px 18px; margin-top:18px; font-weight:700; }}
.good {{ background:#ecfdf5; border:1px solid #10b981; color:#064e3b; }}
.warn {{ background:#fffbeb; border:1px solid #f59e0b; color:#78350f; }}
.bad {{ background:#fef2f2; border:1px solid #ef4444; color:#7f1d1d; }}
</style>
</head>
<body>
<div class="container">
<div class="hero">
<h1>{_safe(report.get("scenario_id"))} - {_safe(report.get("scenario_name"))}</h1>
<p>External Guest Admin Portal Block Evidence Report</p>
</div>

<div class="metrics">
<div class="metric"><span>Status</span><strong>{_safe(display_status)}</strong></div>
<div class="metric"><span>Risk</span><strong>{_safe(report.get("risk"))}</strong></div>
<div class="metric"><span>Admin Portal Rows</span><strong>{_safe(metrics.get("admin_portal_evidence_count", 0))}</strong></div>
<div class="metric"><span>Latest Admin Result</span><strong>{_safe(metrics.get("latest_admin_portal_attempt_result", "PENDING"))}</strong></div>
</div>

<div class="card">
<h2>1. Final Decision</h2>
<p>{_safe(report.get("executive_summary"))}</p>
<p><b>Actual Decision:</b> {_safe(report.get("actual_decision") or report.get("final_claim"))}</p>
<p><b>Evidence Quality:</b> {_safe(report.get("evidence_quality"))}</p>
</div>

<div class="card">
<h2>2. Latest Admin Portal Attempt</h2>
<p><b>Time:</b> {_safe(latest_attempt.get("createdDateTimeUtc", "No admin portal telemetry found"))}</p>
<p><b>Result:</b> {_safe(latest_attempt.get("resultCategory", "PENDING"))}</p>
<p><b>User:</b> {_safe(latest_attempt.get("userPrincipalName", ""))}</p>
<p><b>App / Resource:</b> {_safe(latest_attempt.get("appDisplayName", ""))} / {_safe(latest_attempt.get("resourceDisplayName", ""))}</p>
<p><b>Evidence source:</b> {_safe(latest_attempt.get("evidenceSource", ""))}</p>
</div>

<div class="card">
<h2>3. Browser Observation</h2>
<p><b>Outcome:</b> {_safe(browser.get("outcome", report.get("observed_browser_outcome")))}</p>
<p><b>Treated as evidence:</b> {_safe(browser.get("treated_as_evidence"))}</p>
</div>

<div class="card">
<h2>Controlled Guest Identity</h2>
<p><b>External email used for redemption:</b> {_safe(guest_identity.get("external_email"))}</p>
<p><b>Guest user principal name in tenant:</b> {_safe(guest_identity.get("guest_upn"))}</p>
<p><b>Guest object ID:</b> {_safe(guest_identity.get("guest_id"))}</p>
<p><b>External user state:</b> {_safe(guest_identity.get("external_state"))}</p>
</div>

<div class="card">
<h2>4. Admin Portal Evidence</h2>
<table>
{_evidence_table_header()}
<tbody>
{_html_evidence_rows(admin_evidence, "No Azure/admin portal telemetry was found in the decision window.")}
</tbody>
</table>
</div>

<div class="card">
<h2>5. Invitation / Redemption Evidence</h2>
<table>
{_evidence_table_header()}
<tbody>
{_html_evidence_rows(invitation_evidence, "No invitation/redemption telemetry was found in the decision window.")}
</tbody>
</table>
</div>

<div class="card">
<h2>6. Historical Portal Evidence outside decision window</h2>
<table>
{_evidence_table_header()}
<tbody>
{_html_evidence_rows(historical_evidence, "No historical portal evidence outside the decision window was collected.")}
</tbody>
</table>
</div>

<div class="card">
<h2>7. Policy Attribution</h2>
<p><b>Block policy applied:</b> {_safe(policy.get("block_policy_applied"))}</p>
<p><b>Policy names:</b> {_safe(policy_text)}</p>
</div>

<div class="card">
<h2>8. Evidence Window</h2>
<p><b>Start:</b> {_safe(window.get("evidence_start_utc"))}</p>
<p><b>Mode:</b> {_safe(window.get("evidence_start_mode"))}</p>
<p><b>Older rows ignored for decision:</b> {_safe(window.get("older_rows_ignored_for_decision"))}</p>
</div>

<div class="card">
<h2>9. Warnings</h2>
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
    admin_evidence = _as_records(report, "admin_portal_evidence")
    invitation_evidence = _as_records(report, "invitation_redemption_evidence")
    historical_evidence = _as_records(report, "historical_portal_evidence")
    other_evidence = _as_records(report, "other_guest_evidence")
    warnings = report.get("warnings", []) or []
    policy = report.get("policy_attribution", {}) or {}

    display_status = _friendly_status(report.get("status"))
    tone = _tone_for_status(report.get("status"))
    latest_attempt = report.get("latest_admin_portal_attempt", {}) or {}
    latest_success = report.get("latest_successful_admin_portal_attempt", {}) or {}
    latest_block = report.get("latest_blocked_admin_portal_attempt", {}) or {}
    browser = report.get("browser_observation", {}) or {}

    _alert("External guest admin portal validation completed.", "good" if tone == "good" else tone)

    if report.get("status") == "PARTIAL_CONFLICT_BROWSER_REACHED_TELEMETRY_BLOCKED":
        _alert(
            "Conflict: the consultant recorded that the guest reached Azure/admin portal, but the latest matching Entra admin portal telemetry is blocked or interrupted. Do not treat this as PASS; start a fresh retest window and repeat the portal attempt.",
            "warn",
        )
    elif latest_attempt.get("resultCategory") == "SUCCESS":
        _alert(
            "Simple result: latest matching Azure Portal / Azure Resource Manager telemetry succeeded. This is a FAIL for this scenario.",
            "bad",
        )
    elif latest_attempt.get("resultCategory") == "BLOCKED_OR_INTERRUPTED":
        _alert(
            "Simple result: latest matching admin portal telemetry was blocked or interrupted.",
            "good",
        )
    elif report.get("status") == "FAIL_BROWSER_OBSERVED_TELEMETRY_PENDING":
        _alert(
            "Telemetry pending: the browser observation says the guest reached Azure/admin portal, so ZTVP is treating this as a FAIL until fresh telemetry proves otherwise.",
            "bad",
        )
    else:
        if invitation_evidence and not admin_evidence:
            _alert(
                "Invitation evidence found, but no Azure/admin portal access telemetry found. Invitation rows are displayed below but do not decide PASS or FAIL.",
                "warn",
            )
        else:
            _alert(
                "ZTVP did not find admin portal telemetry in the active decision window.",
                "warn",
            )

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Status", display_status, tone)}
    {_metric("Risk", report.get("risk", "Unknown"), tone)}
    {_metric("Admin Portal Rows", metrics.get("admin_portal_evidence_count", 0), "warn" if not metrics.get("admin_portal_evidence_count", 0) else "")}
    {_metric("Latest Admin Result", metrics.get("latest_admin_portal_attempt_result", "PENDING"), _result_tone(metrics.get("latest_admin_portal_attempt_result")))}
</div>
""",
        unsafe_allow_html=True,
    )

    success_count = int(metrics.get("successful_admin_portal_evidence_count", 0) or 0)
    blocked_count = int(metrics.get("blocked_admin_portal_evidence_count", 0) or 0)

    if success_count > 0:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Successful Portal Access", success_count, "bad")}
    {_metric("Latest Success Time", latest_success.get("createdDateTimeUtc", "N/A"), "bad")}
    {_metric("Matched By", latest_success.get("matchedIdentifier", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )
    elif blocked_count > 0:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Blocked / Interrupted Portal Rows", blocked_count, "good" if report.get("status", "").startswith("PASS") else "warn")}
    {_metric("Latest Block Time", latest_block.get("createdDateTimeUtc", "N/A"))}
    {_metric("Matched By", latest_block.get("matchedIdentifier", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### 1. Final Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("actual_decision") or report.get("final_claim", ""))
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Evidence Quality", report.get("evidence_quality", "Unknown"))}
    {_metric("Browser Outcome", metrics.get("browser_outcome", report.get("observed_browser_outcome", "N/A")))}
    {_metric("Evidence Polls", metrics.get("evidence_poll_count", 0))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### 2. Latest Admin Portal Attempt")
    if latest_attempt:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Time", latest_attempt.get("createdDateTimeUtc", "N/A"))}
    {_metric("Result", latest_attempt.get("resultCategory", "N/A"), _result_tone(latest_attempt.get("resultCategory")))}
    {_metric("Evidence Source", latest_attempt.get("evidenceSource", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("User", latest_attempt.get("userPrincipalName", "N/A"))}
    {_metric("App", latest_attempt.get("appDisplayName", "N/A"))}
    {_metric("Resource", latest_attempt.get("resourceDisplayName", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("IP", latest_attempt.get("ipAddress", "N/A"))}
    {_metric("CA Status", latest_attempt.get("conditionalAccessStatus", "N/A"))}
    {_metric("Matched By", latest_attempt.get("matchedIdentifier", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        _alert("No Azure/admin portal telemetry was found in the active decision window.", "warn")

    if latest_success:
        _alert(
            f"Latest successful portal row: {latest_success.get('createdDateTimeUtc', 'N/A')} | {latest_success.get('userPrincipalName', 'N/A')} | {latest_success.get('appDisplayName', 'N/A')} / {latest_success.get('resourceDisplayName', 'N/A')} | IP {latest_success.get('ipAddress', 'N/A')}",
            "bad",
        )

    if latest_block:
        names = _join_values(latest_block.get("blockingPolicyNames") or latest_block.get("appliedPolicyNames"))
        _alert(
            f"Latest blocked/interrupted portal row: {latest_block.get('createdDateTimeUtc', 'N/A')} | CA {latest_block.get('conditionalAccessStatus', 'N/A')} | Policies: {names or 'No policy name in row'}",
            "good" if report.get("status", "").startswith("PASS") else "warn",
        )

    st.markdown("#### 3. Browser Observation")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Manual Outcome", browser.get("outcome", report.get("observed_browser_outcome", "N/A")), "bad" if browser.get("reached_admin_portal") else "warn" if browser.get("treated_as_evidence") else "")}
    {_metric("Treated as Evidence", "Yes" if browser.get("treated_as_evidence") else "No")}
    {_metric("Reached Portal", "Yes" if browser.get("reached_admin_portal") else "No", "bad" if browser.get("reached_admin_portal") else "")}
</div>
""",
        unsafe_allow_html=True,
    )

    guest_identity = _guest_identity_values(report)

    st.markdown("#### Controlled Guest Identity")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("External Email", guest_identity.get("external_email", "N/A"))}
    {_metric("Guest UPN", guest_identity.get("guest_upn", "N/A"))}
    {_metric("Guest Object ID", guest_identity.get("guest_id", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )

    def render_evidence_section(title: str, rows: list[dict], empty_message: str, tone_if_empty: str = "warn") -> None:
        st.markdown(f"#### {title}")

        if rows:
            simple_rows = _simple_evidence_rows(rows)
            df = pd.DataFrame(simple_rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            _alert(empty_message, tone_if_empty)

    render_evidence_section(
        "4. Admin Portal Evidence",
        admin_evidence,
        "No Azure/admin portal access telemetry found in the active decision window.",
    )

    if any(str(row.get("evidenceSource", "")).startswith("non-interactive") for row in admin_evidence):
        _alert("At least one admin portal row came from the non-interactive sign-in log.", "info")

    render_evidence_section(
        "5. Invitation / Redemption Evidence",
        invitation_evidence,
        "No invitation/redemption telemetry found in the active decision window.",
        "info",
    )

    render_evidence_section(
        "6. Historical Portal Evidence outside decision window",
        historical_evidence,
        "No historical Azure/admin portal rows were collected outside the active decision window.",
        "info",
    )

    names = policy.get("block_policy_names", []) or []
    all_names = policy.get("all_policy_names", []) or []
    names_text = ", ".join([str(x) for x in names]) or ", ".join([str(x) for x in all_names]) or "No policy names present in matching admin portal rows"

    st.markdown("#### 7. Policy Attribution")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Block Policy Applied", "Yes" if policy.get("block_policy_applied") else "No", "good" if policy.get("block_policy_applied") else "warn")}
    {_metric("Policy Names", names_text)}
    {_metric("Blocked Rows", policy.get("blocked_admin_portal_evidence_count", 0))}
</div>
""",
        unsafe_allow_html=True,
    )

    validation_window = report.get("validation_window", {}) or {}

    if validation_window:
        st.markdown("#### 8. Evidence Window")
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Evidence Start", validation_window.get("evidence_start_utc", "N/A"))}
    {_metric("Mode", validation_window.get("evidence_start_mode", "N/A"))}
    {_metric("Meaning", "Older sign-ins ignored" if validation_window.get("evidence_start_mode") == "FreshRetestWindow" else "Lookback window")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### 9. Warnings")
    if warnings:
        for warning in warnings:
            _alert(warning, "warn")
    else:
        _alert("No warnings were generated.", "good")

    if other_evidence:
        with st.expander("Other guest sign-in evidence"):
            st.dataframe(pd.DataFrame(_simple_evidence_rows(other_evidence)), use_container_width=True, hide_index=True)

    with st.expander("Raw categorized evidence"):
        st.json(
            {
                "admin_portal_evidence": admin_evidence,
                "invitation_redemption_evidence": invitation_evidence,
                "historical_portal_evidence": historical_evidence,
                "other_guest_evidence": other_evidence,
            }
        )

    st.markdown("#### Export Evidence")

    col_json, col_html = st.columns(2)

    with col_json:
        st.download_button(
            "Download JSON Report",
            data=report_path.read_bytes(),
            file_name="ID-DV-005-result.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_html:
        st.download_button(
            "Download HTML Report",
            data=html_path.read_bytes(),
            file_name="ID-DV-005-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("View full evidence JSON"):
        st.json(report)

    with st.expander("PowerShell output"):
        st.code(stdout or "No PowerShell output captured.", language="text")


def render_idc005_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    st.markdown(
        """
<div class="ztvp-hero">
    <h2>ID-DV-005 — External Guest Admin Portal Block Validation</h2>
    <p>This validation invites a controlled external guest and proves whether guest access to Azure/admin portals is blocked.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    state_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-C-005"
    state_path = state_dir / "guest-state.json"

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDC005Guest.ps1"
    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-IDC005.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDC005Guest.ps1"
    requested_run_id = st.session_state.get("ztvp_dynamic_open_run_id")
    active_or_selected_run = selected_run_for_scenario(project_root, "ID-DV-005", requested_run_id)
    if active_or_selected_run and str(active_or_selected_run.get("status") or "").lower() in ACTIVE_STATUSES:
        _render_background_run_summary(project_root, active_or_selected_run)
        return
    elif active_or_selected_run and requested_run_id:
        _render_background_run_summary(project_root, active_or_selected_run)
        st.markdown("---")

    state = _load_json(state_path)
    guest = state.get("guest_user", {}) or {}
    external = state.get("external_identity", {}) or {}
    invitation = state.get("invitation", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(guest.get("id")) and cleanup.get("status", "Pending") != "Completed"

    _step(1, "Invite controlled external guest")

    if has_active:
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("External Email", external.get("external_email", "N/A"))}
    {_metric("Cleanup", cleanup.get("status", "Pending"), "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        st.markdown("**Exact guest user in tenant**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(guest.get("user_principal_name", ""))}<br>ID: {_safe(guest.get("id", ""))}</div>', unsafe_allow_html=True)

        with st.expander("View active ID-DV-005 state"):
            st.json(state)
    else:
        _alert("Use a real external test email that you control and that can sign in through Microsoft guest redemption. Do not use your tenant admin account. Cleanup will delete the created guest object.", "info")

        with st.container(border=True):
            external_email = st.text_input(
                "External test email",
                value="",
                placeholder="example@gmail.com or example@outlook.com",
                key="idc005_external_email",
            )

            display_prefix = st.text_input(
                "Guest display name prefix",
                value="ZTVP ID-DV-005 External Guest",
                key="idc005_display_prefix",
            )

            redirect_url = st.text_input(
                "Invitation redirect URL",
                value="https://portal.azure.com",
                key="idc005_redirect_url",
            )

            send_email = st.checkbox(
                "Send Microsoft invitation email",
                value=False,
                help="Leave off for lab use. ZTVP will show the invite redeem URL directly.",
                key="idc005_send_invitation_email",
            )

            if st.button("Invite External Guest", type="primary", use_container_width=True):
                if not external_email.strip():
                    _alert("Enter an external email address first.", "warn")
                    return

                args = [
                    "-ExternalEmail", external_email.strip(),
                    "-GuestDisplayNamePrefix", display_prefix.strip() or "ZTVP ID-DV-005 External Guest",
                    "-InviteRedirectUrl", redirect_url.strip() or "https://portal.azure.com",
                ]

                if send_email:
                    args.append("-SendInvitationMessage")

                with st.spinner("Inviting external guest and preparing admin portal test..."):
                    completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

                if completed.returncode != 0:
                    _alert("ID-DV-005 guest invitation failed.", "bad")
                    error_output = f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}"
                    st.code(error_output.strip() or "No PowerShell output captured.", language="text")
                else:
                    _alert("External guest invitation prepared.", "good")
                    st.code(completed.stdout, language="text")
                    st.rerun()

    _step(2, "Redeem invitation and attempt admin portal access")

    state = _load_json(state_path)
    guest = state.get("guest_user", {}) or {}
    external = state.get("external_identity", {}) or {}
    invitation = state.get("invitation", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(guest.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active:
        _alert("Invite an external guest first.", "warn")
    else:
        _alert("Open the invitation redeem URL in a private browser. Sign in with the external account, not your tenant admin account.", "info")

        redeem_url = invitation.get("invite_redeem_url", "")
        portal_url = "https://portal.azure.com"

        st.markdown("**Invitation redeem URL**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(redeem_url)}</div>', unsafe_allow_html=True)

        if redeem_url:
            st.markdown(f'<a href="{_safe(redeem_url)}" target="_blank">Open guest invitation redeem URL</a>', unsafe_allow_html=True)

        st.markdown("**Admin portal URL to test after redemption**")
        st.markdown(f'<div class="ztvp-codebox">{_safe(portal_url)}</div>', unsafe_allow_html=True)
        st.markdown(f'<a href="{_safe(portal_url)}" target="_blank">Open Azure Portal</a>', unsafe_allow_html=True)

        st.markdown("#### Fresh retest window")

        attempt_window = _load_idc005_attempt_window(project_root)
        current_start = attempt_window.get("attempt_started_at_utc")

        if current_start:
            _alert(
                f"Current retest window starts at {current_start}. Evidence collection will ignore older sign-ins.",
                "good",
            )
        else:
            _alert(
                "No fresh retest window has been marked yet. For remediation retests, click the button below before opening Azure Portal again.",
                "warn",
            )

        if st.button("Start Fresh Retest Window Now", use_container_width=True, key="idc005_start_fresh_retest_window"):
            saved_window = _save_idc005_attempt_window(project_root)
            _alert(
                f"Fresh retest window started at {saved_window.get('attempt_started_at_utc')}. Now open Azure Portal again as the guest, then collect evidence.",
                "good",
            )
            st.rerun()

    _step(3, "Collect Entra evidence")

    if not has_active:
        _alert("This step unlocks after the external guest is invited.", "warn")
    else:
        _alert(
            "Easy mode: after redeeming the invitation and opening Azure Portal as the external guest, leave Auto-detect selected. ZTVP will decide from Entra sign-in logs.",
            "info",
        )

        attempt_window = _load_idc005_attempt_window(project_root)
        attempt_start = attempt_window.get("attempt_started_at_utc")

        if attempt_start:
            _alert(
                f"Fresh retest mode is active. ZTVP will only evaluate sign-ins after {attempt_start}.",
                "good",
            )
        else:
            _alert(
                "No fresh retest window is active. ZTVP will use the lookback window, which can include older successful sign-ins.",
                "warn",
            )

        outcome_label = st.selectbox(
            "Evidence mode",
            options=list(OBSERVED_OUTCOMES.keys()),
            index=0,
            key="idc005_observed_outcome",
        )

        if OBSERVED_OUTCOMES[outcome_label] == "REACHED_ADMIN_PORTAL":
            _alert(
                "This manual observation will be treated as evidence. ZTVP will not output PASS unless Entra admin portal telemetry supports a block after this observation.",
                "warn",
            )

        col1, col2 = st.columns(2)

        with col1:
            lookback = st.number_input(
                "Evidence lookback minutes",
                min_value=15,
                max_value=720,
                value=240,
                step=15,
                key="idc005_lookback",
            )

        with col2:
            wait_seconds = st.number_input(
                "Evidence polling wait seconds",
                min_value=0,
                max_value=300,
                value=60,
                step=15,
                key="idc005_wait_seconds",
            )

        _alert(
            "Next action: collect Entra sign-in evidence and let ZTVP decide whether the guest was blocked or reached the admin portal.",
            "info",
        )

        collect_left, collect_center, collect_right = st.columns([0.22, 0.56, 0.22])

        with collect_center:
            collect_evidence = st.button(
                "Collect Evidence and Decide",
                type="primary",
                use_container_width=True,
                key="idc005_collect_evidence",
            )

        if collect_evidence:
            observed_code = OBSERVED_OUTCOMES[outcome_label]

            args = [
                "-ObservedOutcome", observed_code,
                "-LookbackMinutes", str(int(lookback)),
                "-EvidenceWaitSeconds", str(int(wait_seconds)),
            ]

            attempt_window = _load_idc005_attempt_window(project_root)
            attempt_start = attempt_window.get("attempt_started_at_utc")

            if attempt_start:
                args.extend(["-EvidenceStartUtc", attempt_start])

            run = start_scenario_job(
                project_root,
                "ID-DV-005",
                wait_minutes=max(1, int(lookback)),
                poll_seconds=max(0, int(wait_seconds)),
                extra_args=args,
                target=external.get("external_email") or guest.get("user_principal_name") or "ID-DV-005 guest",
            )
            st.session_state["ztvp_dynamic_open_run_id"] = run.get("run_id")
            _alert("ID-DV-005 evidence collection started as a background Active Run.", "good")
            st.rerun()

    _step(4, "Delete exact guest and close test")

    state = _load_json(state_path)
    guest = state.get("guest_user", {}) or {}
    external = state.get("external_identity", {}) or {}
    cleanup = state.get("cleanup", {}) or {}
    has_active = bool(guest.get("id")) and cleanup.get("status", "Pending") != "Completed"

    if not has_active:
        _alert("No active ID-DV-005 guest run exists.", "info")
        return

    with st.container(border=True):
        _alert("After saving the report, delete the exact guest user created for this validation.", "warn")

        st.markdown("**Exact guest to remove**")
        st.markdown(
            f'<div class="ztvp-codebox">External email: {_safe(external.get("external_email", ""))}<br>Guest UPN: {_safe(guest.get("user_principal_name", ""))}<br>Guest ID: {_safe(guest.get("id", ""))}</div>',
            unsafe_allow_html=True,
        )

        disable_instead = st.checkbox("Disable instead of delete", value=False, key="idc005_disable_instead")

        if st.button("Delete This Exact Guest and Close Run", use_container_width=True):
            args = []

            if disable_instead:
                args.append("-DisableInsteadOfDelete")

            with st.spinner("Cleaning up guest user and local state..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("ID-DV-005 cleanup failed.", "bad")
                error_output = f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}"
                st.code(error_output.strip() or "No PowerShell output captured.", language="text")
            else:
                _alert("ID-DV-005 cleanup completed.", "good")
                st.code(completed.stdout, language="text")
                st.rerun()
