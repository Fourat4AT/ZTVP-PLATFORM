from __future__ import annotations

import html
import json
import os
import subprocess
import time
import urllib.parse
import webbrowser
from pathlib import Path

import pandas as pd
import streamlit as st

from html_report import write_standard_html_report
from background_jobs import get_active_run, start_scenario_job
from run_state import latest_run_for_scenario, request_cancel, selected_run_for_scenario

SCENARIO_ID = "APP-DV-001"


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "PASS_UNASSIGNED_USER_BLOCKED": "PASS — Unassigned User Blocked",
    "FAIL_UNASSIGNED_USER_GRANTED_ACCESS": "FAIL — Unassigned User Granted Access",
    "PARTIAL_MFA_BEFORE_ASSIGNMENT": "PARTIAL — MFA Gated Before Assignment Check",
    "PARTIAL_BLOCKED_BY_CONDITIONAL_ACCESS": "PARTIAL — Blocked by Conditional Access",
    "PARTIAL_NO_SIGNIN": "PARTIAL — No Decoy Sign-in Found Yet",
    "PARTIAL_SIGN_IN_INCONCLUSIVE": "PARTIAL — Sign-in Inconclusive",
}


def _build_authorize_url(tenant_id: str, app_id: str, decoy_upn: str) -> str:
    # OIDC authorize request with the controlled app as the audience, so Entra
    # evaluates appRoleAssignmentRequired during the decoy sign-in. An unassigned
    # user is blocked with AADSTS50105 before any MFA challenge.
    params = {
        "client_id": app_id,
        "response_type": "code",
        "redirect_uri": "http://localhost",
        "response_mode": "query",
        "scope": "openid profile",
        "prompt": "login",
        "login_hint": decoy_upn,
    }
    base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    return base + "?" + urllib.parse.urlencode(params)


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


def _write_html_report(report: dict, html_path: Path) -> None:
    write_standard_html_report(report, html_path)


def _open_active_runs() -> None:
    st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
    st.rerun()


def _render_active_run(project_root: Path, run: dict) -> None:
    _alert("APP-DV-001 evidence polling is running. Sign-in logs can take a few minutes to appear.", "info")
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
  {_metric("Decoy user", run.get("decoy_user", "N/A"))}
  {_metric("Target app", run.get("target_app", "N/A"))}
  {_metric("Evidence source", run.get("current_evidence_source", "Entra sign-in logs"))}
  {_metric("Message", run.get("current_message", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", use_container_width=True, key="appdv001_open_active_runs"):
            _open_active_runs()
    with col2:
        if st.button("Cancel APP-DV-001 run", use_container_width=True, key="appdv001_cancel_run"):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "appdv001") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    evidence = report.get("assignment_enforcement_evidence", {}) or {}
    decoy = report.get("decoy_user", {}) or {}

    _alert("APP-DV-001 probe report loaded.", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Status", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Probe Used Decoy", metrics.get("probe_used_decoy_user", False), "good" if metrics.get("probe_used_decoy_user") else "bad")}
  {_metric("Sign-in Attempt", evidence.get("actual_sign_in_attempt_performed", False), "good" if evidence.get("actual_sign_in_attempt_performed") else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Access Granted", evidence.get("access_granted", False), "bad" if evidence.get("access_granted") else "good")}
  {_metric("Assignment Blocked", evidence.get("assignment_required_blocked", False), "good" if evidence.get("assignment_required_blocked") else "warn")}
  {_metric("Sign-in Error Code", evidence.get("sign_in_error_code", "N/A"), "good" if evidence.get("sign_in_error_code") == 50105 else ("bad" if evidence.get("sign_in_error_code") == 0 else "warn"))}
  {_metric("Target App", evidence.get("target_app_display_name", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    rows = [
        {"Evidence": "Expected decoy user", "Value": str(report.get("expected_decoy_user", "")), "Detail": "The unassigned account used for the controlled sign-in."},
        {"Evidence": "Target enterprise app", "Value": str(evidence.get("target_app_display_name", "")), "Detail": f"appRoleAssignmentRequired = {evidence.get('app_role_assignment_required')}"},
        {"Evidence": "Evidence source", "Value": str(evidence.get("evidence_source", "Entra sign-in logs")), "Detail": "Authoritative ground truth, immune to browser redirect behavior."},
        {"Evidence": "Sign-in error code", "Value": str(evidence.get("sign_in_error_code")), "Detail": "50105 = unassigned user blocked (PASS); 0 = success (FAIL)."},
        {"Evidence": "Sign-in failure reason", "Value": str(evidence.get("sign_in_failure_reason") or "N/A"), "Detail": str(evidence.get("sign_in_time") or "")},
        {"Evidence": "Resource signed into", "Value": str(evidence.get("resource_signed_into") or "N/A"), "Detail": f"Conditional Access: {evidence.get('conditional_access_status') or 'N/A'}"},
        {"Evidence": "Access granted", "Value": str(evidence.get("access_granted")), "Detail": "True means the unassigned user got in."},
        {"Evidence": "Assignment-required block", "Value": str(evidence.get("assignment_required_blocked")), "Detail": "True means assignment enforcement worked."},
    ]

    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    # Raw Entra sign-in records that justify the verdict.
    sign_in_evidence = report.get("sign_in_log_evidence", {}) or {}
    events = sign_in_evidence.get("all_events") or []
    if events:
        st.markdown("#### Justifying Entra sign-in records")
        st.caption("Raw sign-in events for the decoy against the controlled app (error 50105 = blocked, 0 = success).")
        event_rows = [
            {
                "Time (UTC)": str(ev.get("createdDateTime", "")),
                "Error code": str(ev.get("errorCode", "")),
                "Failure reason": str(ev.get("failureReason", "") or ""),
                "Resource": str(ev.get("resourceDisplayName", "") or ""),
                "CA status": str(ev.get("conditionalAccessStatus", "") or ""),
                "Client app": str(ev.get("clientAppUsed", "") or ""),
            }
            for ev in events
        ]
        st.dataframe(pd.DataFrame(event_rows).astype(str), use_container_width=True, hide_index=True)
    elif sign_in_evidence:
        st.caption("No decoy sign-in records have appeared in the Entra sign-in logs yet.")

    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "APP-DV-001-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json",
        )

    with col2:
        st.download_button(
            "Download HTML Report",
            html_path.read_bytes(),
            "APP-DV-001-result.html",
            "text/html",
            use_container_width=True,
            key=f"{key_prefix}_html",
        )


def render_appdv001_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-APPDV001.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-APPDV001.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "APP-DV-001"
    state_path = scenario_dir / "appdv001-state.json"
    prepare_path = scenario_dir / "appdv001-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-DV-001-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-DV-001-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>APP-DV-001 — Enterprise App Assignment Enforcement Probe</h2>
  <p>Prepare a decoy user and a controlled assignment-required enterprise app, sign in normally with browser MFA support, then prove whether an unassigned user is denied access.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("Step 2 opens a real sign-in to the controlled app as the decoy user, then reads the authoritative result from the Entra sign-in logs.", "info")

    st.markdown("### 1. Prepare decoy user and controlled enterprise app")

    if not state_path.exists():
        col1, col2 = st.columns(2)

        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-appdv001-decoy", key="appdv001_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP APP-DV-001 Enterprise App Assignment Decoy User", key="appdv001_display_name")

        with col2:
            tenant_domain = st.text_input(
                "Tenant domain optional",
                value="",
                placeholder="Leave empty to auto-detect, or enter tenant.onmicrosoft.com",
                key="appdv001_tenant_domain",
            )

        if st.button("Step 1 — Prepare Decoy User and App", type="primary", use_container_width=True):
            args = ["-UserPrefix", user_prefix.strip(), "-DisplayName", display_name.strip()]
            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            with st.spinner("Creating APP-DV-001 decoy user and controlled enterprise app..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("Decoy preparation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            _alert("Decoy user and controlled app prepared. Use the shown UPN/password in Step 2.", "good")
            st.rerun()
    else:
        _alert("Decoy user and controlled app are already prepared.", "good")

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
<div class="ztvp-grid">
  {_metric("Target App", prep.get("target_app_display_name", ""))}
  {_metric("Target App ID", prep.get("target_app_id", ""))}
  {_metric("Assignment Required", prep.get("target_app_role_assignment_required", True), "good")}
  {_metric("Decoy Assigned", prep.get("decoy_assigned_to_app", False), "good" if not prep.get("decoy_assigned_to_app") else "bad")}
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        _alert("No decoy prepared yet.", "warn")

    st.markdown("### 2. Run controlled decoy sign-in and collect evidence")

    invoke_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Invoke-ZTVP-APPDV001.ps1"

    active_run = get_active_run(project_root, SCENARIO_ID)

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    elif active_run:
        _render_active_run(project_root, active_run)
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        target_app = state.get("target_app", {}) or {}

        decoy_upn = str(decoy.get("user_principal_name", ""))
        decoy_password = str(decoy.get("temporary_password", ""))
        tenant_id = str(state.get("tenant_id", ""))
        app_id = str(target_app.get("app_id", ""))

        st.code(
            f"Decoy UPN: {decoy_upn}\nTemporary password: {decoy_password}\nTarget app: {target_app.get('display_name', '')}",
            language="text",
        )

        st.markdown("**Step 2a — Sign in once as the decoy user to the controlled app.**")
        _alert(
            "Use a private/InPrivate browser window. Sign in with the decoy UPN and password above. "
            "If the unassigned user is denied, you will see an 'AADSTS50105 — not assigned to a role for the application' page. That is the expected secure result.",
            "warn",
        )

        authorize_url = _build_authorize_url(tenant_id, app_id, decoy_upn)
        st.link_button("Open decoy sign-in to the controlled app", authorize_url, use_container_width=True)
        with st.expander("Sign-in URL (copy into an InPrivate window if needed)"):
            st.code(authorize_url, language="text")

        if st.button("Open sign-in in the default browser", use_container_width=True, key="appdv001_open_browser"):
            try:
                webbrowser.open(authorize_url)
                _alert("Browser opened. Complete the decoy sign-in, then start evidence polling in Step 2b.", "info")
            except Exception as e:
                _alert(f"Could not auto-open the browser: {e}. Use the link above.", "warn")

        st.markdown("**Step 2b — Start the active run that polls Entra sign-in logs for the verdict.**")
        _alert(
            "Sign-in logs can take a few minutes to appear. The active run keeps polling in the background until the "
            "decoy's sign-in shows up, then writes the verdict plus the raw sign-in record to this page and to Active Runs.",
            "info",
        )

        col_w, col_p = st.columns(2)
        with col_w:
            wait_minutes = st.number_input("Monitoring window (minutes)", min_value=2, max_value=90, value=15, step=1, key="appdv001_wait")
        with col_p:
            poll_seconds = st.number_input("Poll interval (seconds)", min_value=15, max_value=300, value=30, step=15, key="appdv001_poll")

        if st.button("Step 2b — Start Evidence Polling (active run)", type="primary", use_container_width=True, key="appdv001_start_active"):
            # Persist the chosen window/interval so the background job picks them up.
            state["wait_minutes"] = int(wait_minutes)
            state["poll_seconds"] = int(poll_seconds)
            _write_json(state_path, state)
            run = start_scenario_job(project_root, SCENARIO_ID, int(wait_minutes), int(poll_seconds))
            _alert("APP-DV-001 evidence polling started. You can leave this page and watch it under Active Runs.", "good")
            st.caption(f"Run ID: {run.get('run_id')}")
            st.rerun()

        with st.expander("Quick check — read the sign-in log once now (no background run)"):
            st.caption("Use this if you already completed the decoy sign-in and the log has had a moment to ingest.")
            if st.button("Collect Sign-in Evidence once now", use_container_width=True, key="appdv001_quick_once"):
                with st.spinner("Reading Entra sign-in logs once for the decoy attempt..."):
                    completed = _run_powershell(project_root, invoke_script, [], timeout=600)
                if completed.returncode != 0:
                    _alert("APP-DV-001 one-shot evidence collection failed.", "bad")
                    st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                else:
                    _alert("APP-DV-001 evidence collected.", "good")
                    st.rerun()

    if report_path.exists():
        st.markdown("### Latest APP-DV-001 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="appdv001_latest")

    st.markdown("### 3. Cleanup")

    if not state_path.exists():
        _alert("No active APP-DV-001 decoy state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        target_app = state.get("target_app", {}) or {}

        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Target App", target_app.get("display_name", "N/A"))}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Step 3 — Cleanup APP-DV-001 Test Objects", use_container_width=True):
            with st.spinner("Cleaning APP-DV-001 enterprise app and decoy user..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)

            if completed.returncode != 0:
                _alert("APP-DV-001 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("APP-DV-001 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()
