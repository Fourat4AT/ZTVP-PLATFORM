from __future__ import annotations

import html
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from html_report import write_standard_html_report
from background_jobs import get_active_run, start_scenario_job
from run_state import request_cancel, selected_run_for_scenario

SCENARIO_ID = "ID-DV-006"

STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "PASS_RISKY_SIGNIN_BLOCKED": "PASS — Risky Sign-in Blocked",
    "PASS_RISKY_SIGNIN_CHALLENGED": "PASS — Risky Sign-in Challenged (MFA / Strong Auth)",
    "FAIL_RISKY_SIGNIN_ALLOWED": "FAIL — Risky Sign-in Allowed With No Control",
    "FAIL_NO_SIGNIN_RISK_POLICY": "FAIL — No Enabled Sign-in Risk CA Policy",
    "PARTIAL_NOT_CLASSIFIED_RISKY": "PARTIAL — Attempts Found But Not Classified Risky",
    "PARTIAL_CA_RESPONSE_UNCLEAR": "PARTIAL — CA Response Unclear",
    "PARTIAL_NO_RISK_SIGNIN_EVIDENCE": "PARTIAL — No Matching Sign-in Found Yet",
}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    _alert("ID-DV-006 evidence polling is running. Sign-in logs can take a few minutes to appear.", "info")
    polls = f"{run.get('poll_attempts', 0)} / {run.get('max_poll_attempts', 'N/A')}"
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Phase", run.get("phase", "N/A"))}
  {_metric("Polls used", polls)}
  {_metric("Tenant evidence", run.get("tenant_evidence_status", "Waiting"))}
  {_metric("Progress", str(run.get("progress_percent", 0)) + "%")}
</div>
<div class="ztvp-grid">
  {_metric("Decoy user", run.get("decoy_user", "N/A"))}
  {_metric("Evidence source", run.get("current_evidence_source", "Entra sign-in logs"))}
  {_metric("Last poll", run.get("last_updated_utc", "N/A"))}
  {_metric("Message", run.get("current_message", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", use_container_width=True, key="idv006_open_active_runs"):
            _open_active_runs()
    with col2:
        if st.button("Cancel ID-DV-006 run", use_container_width=True, key="idv006_cancel_run"):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "idv006") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    sie = report.get("sign_in_risk_evidence", {}) or {}
    selected = sie.get("selected_event") or {}

    _alert(f"ID-DV-006 result: {_friendly_status(status)}", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Risk detected", "Yes" if report.get("risk_detected") else "No", "bad" if report.get("risk_detected") else "good")}
  {_metric("CA action", report.get("ca_action", "None"))}
</div>
<div class="ztvp-grid">
  {_metric("Sign-in risk level", selected.get("riskLevelDuringSignIn", "N/A"))}
  {_metric("Risk state / detail", f"{selected.get('riskState', 'N/A')} / {selected.get('riskDetail', 'N/A')}")}
  {_metric("Policy found", "Yes" if report.get("policy_found") else "No", "good" if report.get("policy_found") else "bad")}
  {_metric("Applied policy", report.get("applied_policy_name") or "None")}
</div>
<div class="ztvp-grid">
  {_metric("Tenant evidence found", "Yes" if metrics.get("tenant_evidence_found") else "No")}
  {_metric("Matching sign-in found", "Yes" if sie.get("matching_sign_in_found") else "No")}
  {_metric("User", report.get("expected_decoy_user", "N/A"))}
  {_metric("Polls used / max", f"{metrics.get('poll_attempts', 0)} / {metrics.get('max_poll_attempts', 'N/A')}")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    if selected:
        st.markdown("#### Selected sign-in evidence")
        srows = [
            {"Field": "Time (UTC)", "Value": str(selected.get("createdDateTime", ""))},
            {"Field": "App / resource", "Value": f"{selected.get('appDisplayName', '')} / {selected.get('resourceDisplayName', '')}"},
            {"Field": "Status (errorCode)", "Value": str(selected.get("errorCode", ""))},
            {"Field": "CA status", "Value": str(selected.get("conditionalAccessStatus", ""))},
            {"Field": "CA action", "Value": str(selected.get("ca_action", ""))},
            {"Field": "IP / location", "Value": f"{selected.get('ipAddress', '')} / {selected.get('location', '')}"},
            {"Field": "Request ID", "Value": str(selected.get("requestId", ""))},
        ]
        st.dataframe(pd.DataFrame(srows).astype(str), use_container_width=True, hide_index=True)

    events = sie.get("all_events") or []
    if events:
        st.markdown("#### Tenant sign-in risk evidence (all matching events)")
        erows = [
            {
                "Time (UTC)": str(ev.get("createdDateTime", "")),
                "Error": str(ev.get("errorCode", "")),
                "Risk (sign-in)": str(ev.get("riskLevelDuringSignIn", "")),
                "Risk state": str(ev.get("riskState", "")),
                "CA status": str(ev.get("conditionalAccessStatus", "")),
                "CA action": str(ev.get("ca_action", "")),
                "IP": str(ev.get("ipAddress", "")),
            }
            for ev in events
        ]
        st.dataframe(pd.DataFrame(erows).astype(str), use_container_width=True, hide_index=True)

    policies = report.get("conditional_access_policy_evidence") or []
    st.markdown("#### Conditional Access policy evidence")
    if policies:
        prows = [
            {
                "Policy": str(p.get("policy_name", "")),
                "State": str(p.get("state", "")),
                "Sign-in risk levels": ", ".join(p.get("sign_in_risk_levels", []) or []),
                "Grant controls": ", ".join(p.get("grant_controls", []) or []),
                "Auth strength": str(p.get("authentication_strength") or ""),
            }
            for p in policies
        ]
        st.dataframe(pd.DataFrame(prows).astype(str), use_container_width=True, hide_index=True)
    else:
        st.caption("No Conditional Access policies targeting sign-in risk were found.")

    with st.expander("Full JSON evidence (technical details)"):
        st.json(report)

    write_standard_html_report(report, html_path)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button("Download JSON Report", report_path.read_bytes(), "ID-DV-006-result.json", "application/json", use_container_width=True, key=f"{key_prefix}_json")
    with col2:
        st.download_button("Download HTML Report", html_path.read_bytes(), "ID-DV-006-result.html", "text/html", use_container_width=True, key=f"{key_prefix}_html")


def render_idv006_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-IDV006Decoy.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-IDV006Decoy.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "ID-DV-006"
    state_path = scenario_dir / "idv006-state.json"
    prepare_path = scenario_dir / "idv006-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "ID-DV-006-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "ID-DV-006-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>ID-DV-006 — Sign-in Risk Conditional Access Validation</h2>
  <p>Validate whether the tenant has an effective Conditional Access response for risky sign-ins, proven with fresh Entra sign-in evidence.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("### 1. Prepare decoy user")

    if not state_path.exists():
        col1, col2 = st.columns(2)
        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-idv006-decoy", key="idv006_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP ID-DV-006 Sign-in Risk Decoy User", key="idv006_display_name")
        with col2:
            tenant_domain = st.text_input("Tenant domain optional", value="", placeholder="Leave empty to auto-detect", key="idv006_tenant_domain")

        if st.button("Step 1 — Prepare Decoy User", type="primary", use_container_width=True):
            args = ["-UserPrefix", user_prefix.strip(), "-DisplayName", display_name.strip()]
            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])
            with st.spinner("Creating ID-DV-006 decoy user..."):
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
  {_metric("Decoy UPN", prep.get("decoy_user_principal_name", ""))}
  {_metric("Temporary Password", prep.get("decoy_temporary_password", ""), "warn")}
  {_metric("Status", prep.get("status", ""))}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("### 2. Start evidence window and run the risky sign-in test")

    active_run = get_active_run(project_root, SCENARIO_ID)

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    elif active_run:
        _render_active_run(project_root, active_run)
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        decoy_upn = str(decoy.get("user_principal_name", ""))
        decoy_password = str(decoy.get("temporary_password", ""))
        evidence_start = state.get("evidence_start_utc")

        st.code(f"Decoy UPN: {decoy_upn}\nTemporary password: {decoy_password}", language="text")

        _alert(
            "Order matters: press 'Start evidence window' FIRST, then perform the risky sign-in test so ZTVP only analyzes fresh activity.\n"
            "1) Use TOR / VPN / an unusual location if available.\n"
            "2) Try several WRONG passwords for the decoy.\n"
            "3) Then sign in with the CORRECT password.",
            "warn",
        )

        if st.button("Start evidence window", type="primary", use_container_width=True, key="idv006_start_window"):
            state["evidence_start_utc"] = _utc_now()
            _write_json(state_path, state)
            _alert("Evidence window started. Now run the risky sign-in test, then start evidence polling below.", "good")
            st.rerun()

        if evidence_start:
            _alert(f"Evidence window started at {evidence_start} (UTC). ZTVP will search from 5 minutes before this time.", "info")

            col_w, col_p = st.columns(2)
            with col_w:
                wait_minutes = st.number_input("Total evidence search time (minutes)", min_value=2, max_value=120, value=15, step=1, key="idv006_wait")
            with col_p:
                poll_seconds = st.number_input("Poll interval (seconds)", min_value=15, max_value=300, value=30, step=15, key="idv006_poll")

            if st.button("Start Evidence Polling (active run)", type="primary", use_container_width=True, key="idv006_start_active"):
                state["wait_minutes"] = int(wait_minutes)
                state["poll_seconds"] = int(poll_seconds)
                _write_json(state_path, state)
                run = start_scenario_job(project_root, SCENARIO_ID, int(wait_minutes), int(poll_seconds))
                _alert("ID-DV-006 evidence polling started. You can leave this page and watch it under Active Runs.", "good")
                st.caption(f"Run ID: {run.get('run_id')}")
                st.rerun()
        else:
            _alert("Press 'Start evidence window' before running the risky sign-in test.", "warn")

    selected_run = selected_run_for_scenario(project_root, SCENARIO_ID)
    if report_path.exists():
        st.markdown("### Latest ID-DV-006 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="idv006_latest")

    st.markdown("### 3. Cleanup")

    if not state_path.exists():
        _alert("No active ID-DV-006 decoy state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Evidence window", state.get("evidence_start_utc", "Not started"))}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Step 3 — Cleanup ID-DV-006 Decoy User", use_container_width=True, key="idv006_cleanup"):
            with st.spinner("Cleaning ID-DV-006 decoy user..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)
            if completed.returncode != 0:
                _alert("ID-DV-006 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("ID-DV-006 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()
