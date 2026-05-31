from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from ca_summary import summarize_ca_access_report
from background_jobs import get_active_run, start_scenario_job
from html_report import write_standard_html_report
from run_state import latest_run_for_scenario, new_run_id, request_cancel, save_run, selected_run_for_scenario, utc_now


SCENARIO_ID = "APP-DV-004"
SCENARIO_NAME = "Sensitive App Access From Unmanaged Device Probe"

APP_DEFAULTS = {
    "SharePoint Online": "https://www.office.com/launch/sharepoint",
    "Office 365": "https://www.office.com",
    "Exchange Online": "https://outlook.office.com/mail/",
    "Azure portal": "https://portal.azure.com",
    "Custom app name/resource": "",
}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _css() -> None:
    st.markdown(
        """
<style>
.ztvp-hero { background:linear-gradient(135deg,#0f172a,#2563eb); color:white; padding:1.45rem 1.6rem; border-radius:20px; margin-bottom:1rem; }
.ztvp-hero h2 { margin:0 0 .35rem 0; color:white; font-size:1.35rem; font-weight:900; }
.ztvp-hero p { margin:0; color:#dbeafe; }
.ztvp-alert { border-radius:14px; padding:.9rem 1rem; margin:.75rem 0 1rem 0; font-weight:650; line-height:1.5; }
.ztvp-info { background:#eff6ff; border:1px solid #3b82f6; color:#1e3a8a; }
.ztvp-good { background:#ecfdf5; border:1px solid #10b981; color:#064e3b; }
.ztvp-warn { background:#fffbeb; border:1px solid #f59e0b; color:#78350f; }
.ztvp-bad { background:#fef2f2; border:1px solid #ef4444; color:#7f1d1d; }
.ztvp-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:.85rem; margin-bottom:1rem; }
.ztvp-grid-3 { display:grid; grid-template-columns:repeat(3,1fr); gap:.85rem; margin-bottom:1rem; }
.ztvp-metric { background:#fff; border:1px solid #dbe3ef; border-radius:14px; padding:1rem; box-shadow:0 8px 18px rgba(15,23,42,.05); }
.ztvp-metric span { display:block; color:#64748b; font-size:.78rem; font-weight:800; margin-bottom:.45rem; }
.ztvp-metric strong { color:#0f172a; font-size:1.02rem; font-weight:900; word-break:break-word; }
.ztvp-metric.good strong { color:#15803d; }
.ztvp-metric.warn strong { color:#b45309; }
.ztvp-metric.bad strong { color:#b91c1c; }
div.stButton > button, div.stDownloadButton > button { border-radius:12px !important; min-height:42px !important; font-weight:820 !important; }
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


def _verdict(status: object) -> str:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("UNSUPPORTED"):
        return "UNSUPPORTED"
    if text.startswith("ERROR"):
        return "ERROR"
    if text.startswith("CANCEL"):
        return "CANCELLED"
    return "PARTIAL"


def _tone(verdict: str) -> str:
    return {"PASS": "good", "FAIL": "bad", "ERROR": "bad", "PARTIAL": "warn"}.get(verdict, "warn")


def _open_active_runs() -> None:
    st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
    st.rerun()


def _render_active_run(project_root: Path, run: dict[str, Any]) -> None:
    _alert("This scenario is currently running.", "info")
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
  {_metric("Test user", run.get("test_user", "N/A"))}
  {_metric("Target app", run.get("target_app", "N/A"))}
  {_metric("Validation start UTC", run.get("validation_start_utc", "N/A"))}
  {_metric("Message", run.get("current_message", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", use_container_width=True, key="appdv004_open_active_runs"):
            _open_active_runs()
    with col2:
        if st.button("Cancel APP-DV-004 run", use_container_width=True, key="appdv004_cancel_run"):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()


def _render_report(report: dict[str, Any], report_path: Path, html_path: Path) -> None:
    write_standard_html_report(report, html_path)
    verdict = _verdict(report.get("status"))
    tone = _tone(verdict)
    evidence = report.get("appdv004_evidence") or {}
    metrics = report.get("metrics") or {}
    ca = summarize_ca_access_report(report, "device")

    _alert(f"APP-DV-004 completed with verdict: {verdict}", tone)
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", verdict, tone)}
  {_metric("Risk", report.get("risk", "Unknown"), tone)}
  {_metric("Sign-in result", ca.get("sign_in_result"), tone)}
  {_metric("Access without control", ca.get("access_without_required_control"), "bad" if ca.get("access_without_required_control") == "Yes" else "good" if ca.get("access_without_required_control") == "No" else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Test user", report.get("test_user", "N/A"))}
  {_metric("Target app", report.get("target_app", "N/A"))}
  {_metric("Effective policy", ca.get("effective_policy"))}
  {_metric("Conditional Access result", ca.get("conditional_access_result"))}
</div>
""",
        unsafe_allow_html=True,
    )
    st.write(ca.get("conclusion") or report.get("final_claim", ""))

    rows = [
        {"Evidence source": "Entra sign-in logs", "Found": "Yes" if evidence.get("signin_found") else "No", "Matched object": report.get("target_app", ""), "Timestamp": evidence.get("signin_timestamp", ""), "Notes": evidence.get("access_result", "")},
        {"Evidence source": "Effective Conditional Access policy", "Found": "Yes" if ca.get("effective_policy") != "None found" else "No", "Matched object": ca.get("effective_policy", ""), "Timestamp": evidence.get("signin_timestamp", ""), "Notes": ca.get("conditional_access_result", "")},
        {"Evidence source": "Device detail/compliance context", "Found": "Yes" if evidence.get("device_unmanaged_or_noncompliant") else "No", "Matched object": report.get("test_user", ""), "Timestamp": evidence.get("signin_timestamp", ""), "Notes": evidence.get("failure_reason", "")},
    ]
    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    relevant = ca.get("relevant_policies") or []
    if relevant:
        st.markdown("#### Relevant Conditional Access policies")
        st.dataframe(pd.DataFrame(relevant).astype(str), use_container_width=True, hide_index=True)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button("Download JSON evidence", report_path.read_bytes(), report_path.name, "application/json", use_container_width=True)
    with col2:
        st.download_button("View HTML report", html_path.read_bytes(), html_path.name, "text/html", use_container_width=True)

    with st.expander("Technical evidence details", expanded=False):
        st.json(report)


def render_appdv004_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / SCENARIO_ID
    state_path = scenario_dir / "appdv004-state.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / f"{SCENARIO_ID}-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / f"{SCENARIO_ID}-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>APP-DV-004 - Sensitive App Access From Unmanaged Device Probe</h2>
  <p>Guide a manual Windows Sandbox access attempt, then collect Entra sign-in and Conditional Access evidence.</p>
</div>
""",
        unsafe_allow_html=True,
    )
    _alert(
        "ZTVP does not create or modify Conditional Access policies. The policy should already exist. This scenario only collects sign-in and CA evidence.",
        "info",
    )

    requested_run_id = str(st.session_state.get("ztvp_dynamic_open_run_id") or "")
    selected_run = selected_run_for_scenario(project_root, SCENARIO_ID, requested_run_id)
    active_run = get_active_run(project_root, SCENARIO_ID, requested_run_id) if requested_run_id else get_active_run(project_root, SCENARIO_ID)
    if active_run:
        _render_active_run(project_root, active_run)
        return

    st.markdown("### Step 1 - Configure validation")
    col1, col2 = st.columns(2)
    with col1:
        test_user = st.text_input("Test user UPN", key="appdv004_test_user", placeholder="user@tenant.com")
        target_app = st.selectbox("Target app", list(APP_DEFAULTS.keys()), key="appdv004_target_app")
        custom_app = ""
        if target_app == "Custom app name/resource":
            custom_app = st.text_input("Custom app name/resource", key="appdv004_custom_app")
    with col2:
        default_url = APP_DEFAULTS.get(target_app, "")
        target_url = st.text_input("Target app URL", value=default_url, key=f"appdv004_target_url_{target_app}")
        expected_policy = st.text_input(
            "Optional expected Conditional Access policy name",
            value="CA-P1-M365-Block-Unmanaged-Device-SensitiveApps",
            key="appdv004_expected_policy",
            help="Leave empty to accept any blocking CA policy for this test user/app after the validation start.",
        )
        wait_minutes = st.number_input("Monitoring window minutes", min_value=2, max_value=90, value=15, step=1, key="appdv004_wait")
        poll_seconds = st.number_input("Poll interval seconds", min_value=15, max_value=300, value=60, step=15, key="appdv004_poll")

    _alert(
        "Use Windows Sandbox or any unmanaged/non-compliant endpoint. Sign in as the test user and open the target app. The expected result is that Conditional Access blocks access because the device is not compliant or unmanaged.",
        "warn",
    )

    selected_app_name = custom_app.strip() if target_app == "Custom app name/resource" else target_app

    if st.button("Start validation window", type="primary", use_container_width=True, key="appdv004_start_window"):
        if not test_user.strip() or not selected_app_name.strip() or not target_url.strip():
            _alert("Test user, target app, and target app URL are required.", "bad")
        else:
            run_id = new_run_id(SCENARIO_ID)
            now = utc_now()
            state = {
                "run_id": run_id,
                "scenario_id": SCENARIO_ID,
                "scenario_name": SCENARIO_NAME,
                "test_user": test_user.strip(),
                "target_app": selected_app_name.strip(),
                "target_app_url": target_url.strip(),
                "expected_policy_name": expected_policy.strip(),
                "validation_start_utc": now,
                "started_utc": now,
                "wait_minutes": int(wait_minutes),
                "poll_seconds": int(poll_seconds),
            }
            _write_json(state_path, state)
            st.session_state["appdv004_state_started"] = True
            st.success("Validation window started. Perform the unmanaged device test, then start tenant evidence analysis.")
            st.rerun()

    state = _load_json(state_path)
    st.markdown("### Step 2 - Manual unmanaged device test")
    checklist = [
        "Open Windows Sandbox.",
        "Open Microsoft Edge.",
        f"Go to: {state.get('target_app_url') or target_url or '<target app URL>'}",
        f"Sign in as: {state.get('test_user') or test_user or '<test user>'}",
        "Confirm whether access is blocked.",
        "Return to ZTVP and click Start tenant evidence analysis.",
    ]
    st.code("\n".join(f"[ ] {item}" for item in checklist), language="text")

    st.markdown("### Step 3 - Start tenant evidence analysis")
    if not state:
        _alert("Start the validation window before polling Entra sign-in logs.", "warn")
    else:
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Test user", state.get("test_user"))}
  {_metric("Target app", state.get("target_app"))}
  {_metric("Validation start UTC", state.get("validation_start_utc"))}
  {_metric("Target URL", state.get("target_app_url"))}
</div>
""",
            unsafe_allow_html=True,
        )
        if st.button("Start tenant evidence analysis", type="primary", use_container_width=True, key="appdv004_start_analysis"):
            run = start_scenario_job(project_root, SCENARIO_ID, int(state.get("wait_minutes") or wait_minutes), int(state.get("poll_seconds") or poll_seconds))
            _alert("APP-DV-004 evidence polling started. You can leave this page and monitor it in Active Runs.", "good")
            st.caption(f"Run ID: {run.get('run_id')}")
            if st.button("Open Active Runs", use_container_width=True, key="appdv004_open_active_after_start"):
                _open_active_runs()

    latest = selected_run or latest_run_for_scenario(project_root, SCENARIO_ID)
    if latest and str(latest.get("status") or "").lower() in {"cancelled", "error", "timeout", "stale"}:
        _alert(f"Selected APP-DV-004 run is {latest.get('status')}.", "warn" if str(latest.get("status")).lower() != "error" else "bad")
    if latest and str(latest.get("status") or "").lower() == "completed" and latest.get("report_path"):
        saved_report = Path(str(latest.get("report_path")))
        saved_html = Path(str(latest.get("html_report_path") or saved_report.with_suffix(".html")))
        if saved_report.exists():
            st.markdown("### Latest APP-DV-004 report")
            _render_report(_load_json(saved_report), saved_report, saved_html)
    elif report_path.exists():
        st.markdown("### Latest APP-DV-004 report")
        _render_report(_load_json(report_path), report_path, html_path)
