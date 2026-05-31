from __future__ import annotations

import html
import json
import math
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

from html_report import write_standard_html_report
from background_jobs import start_scenario_job
from run_state import ACTIVE_STATUSES, is_stale, list_runs, load_run, new_run_id, request_cancel, save_run, selected_run_for_scenario, update_run, utc_now


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


def _first_value(*values: object) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"unknown", "n/a", "none", "null"}:
            return text
    return ""


def _nested(data: dict, *keys: str) -> object:
    current: object = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _yes_no(value: object) -> str:
    return "Yes" if bool(value) else "No"


def _bool_label(value: object, unknown: str = "Unknown") -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return unknown


def _cleanup_action_status(cleanup: dict, keyword: str) -> str:
    actions = " ".join(str(item) for item in (cleanup.get("actions") or [])).lower()
    errors = " ".join(str(item) for item in (cleanup.get("errors") or [])).lower()
    keyword = keyword.lower()
    if keyword in actions:
        return "Yes"
    if keyword in errors:
        return "No"
    return "Unknown"


def _scenario_result(status: object, cleanup: dict) -> str:
    text = str(status or "").upper()
    cleanup_completed = str(cleanup.get("status") or cleanup.get("cleanup_status") or "").lower() == "completed"
    if not cleanup_completed:
        return "Cleanup issue"
    if text.startswith("PASS"):
        return "Detected"
    if text.startswith(("FAIL", "PARTIAL")):
        return "Not detected"
    return "Review needed"


def _simple_recommendations() -> list[str]:
    return [
        "Create or verify an MDCA file policy for publicly shared SharePoint/OneDrive files.",
        "Optional example policy name: MDCA-P1-M365-SharePoint-PublicSharing-Monitor.",
        "Start with alert-only mode.",
        "After validation, consider governance/remediation policy.",
    ]


def _latest_appc003_active_run(project_root: Path, run_id: str | None = None) -> dict:
    if run_id:
        run = selected_run_for_scenario(project_root, "APP-DV-003", run_id) or {}
        if (
            str(run.get("scenario_id") or "").upper() in {"APP-DV-003", "APP-C-003"}
            and str(run.get("status") or "").lower() in ACTIVE_STATUSES
            and not is_stale(run)
        ):
            return run
    runs = [
        run
        for run in list_runs(project_root)
        if str(run.get("scenario_id") or "").upper() in {"APP-DV-003", "APP-C-003"}
        and str(run.get("status") or "").lower() in ACTIVE_STATUSES
        and not is_stale(run)
    ]
    return runs[0] if runs else {}


def _cleanup_status_is_completed(state: dict, cleanup: dict) -> bool:
    if not cleanup:
        return False
    state_run_id = str(state.get("run_id") or "").strip()
    cleanup_run_id = str(cleanup.get("run_id") or "").strip()
    if state_run_id and cleanup_run_id and state_run_id != cleanup_run_id:
        return False
    status = str(cleanup.get("cleanup_status") or cleanup.get("status") or "").strip().lower()
    return status == "completed" or cleanup.get("cleanup_completed") is True or cleanup.get("state_file_deleted") is True


def _cleanup_state_blocks_run(state_path: Path, cleanup_path: Path) -> tuple[bool, dict, dict]:
    state = _load_json(state_path) if state_path.exists() else {}
    cleanup = _load_json(cleanup_path) if cleanup_path.exists() else {}
    if not state:
        return False, state, cleanup
    return not _cleanup_status_is_completed(state, cleanup), state, cleanup


def _archive_completed_cleanup_state(state_path: Path) -> Path | None:
    if not state_path.exists():
        return None
    history_dir = state_path.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive_path = history_dir / f"appc003-state-completed-ui-clear-{stamp}.json"
    shutil.copy2(state_path, archive_path)
    state_path.unlink()
    return archive_path


def _max_attempts(wait_minutes: int, poll_seconds: int) -> int:
    return max(1, int(math.ceil((max(1, wait_minutes) * 60) / max(1, poll_seconds))))


def _verdict_from_status(status: object) -> str | None:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("PARTIAL"):
        return "PARTIAL"
    return None


def _render_stale_state_panel(state_path: Path, cleanup_path: Path, state: dict) -> None:
    link = state.get("anonymous_public_link_attempt", {}) or {}
    test_object = state.get("test_object", {}) or {}
    site = state.get("site", {}) or {}
    cleanup = _load_json(cleanup_path) if cleanup_path.exists() else {}
    cleanup_status = _first_value(cleanup.get("cleanup_status"), "Cleanup required")

    _alert("An unfinished APP-C-003 run exists. Cleanup is required before starting a new run.", "warn")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Run ID", state.get("run_id", "N/A"))}
    {_metric("Site", _first_value(site.get("displayName"), site.get("webUrl"), "N/A"))}
    {_metric("File name", test_object.get("file_name", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Link created", _yes_no(link.get("public_link_created")))}
    {_metric("Created UTC", _first_value(state.get("started_at"), state.get("started_utc"), "N/A"))}
    {_metric("Cleanup status", cleanup_status)}
</div>
""",
        unsafe_allow_html=True,
    )
    with st.expander("Technical evidence details", expanded=False):
        st.write(f"state path: `{state_path}`")
        st.json(state)
        if cleanup:
            st.json(cleanup)


def _render_active_run_panel(project_root: Path, run: dict) -> None:
    if not run:
        return

    polls = f"{run.get('poll_attempts', 0)} / {run.get('max_poll_attempts', 'N/A')}"
    _alert("APP-DV-003 validation is currently running.", "info")
    st.markdown(
        f"""
<div class="ztvp-grid-3">
    {_metric("Phase", run.get("phase", "N/A"))}
    {_metric("Polls", polls)}
    {_metric("Tenant evidence", run.get("tenant_evidence_status", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Dummy file created", run.get("dummy_file_created", "Not recorded"))}
    {_metric("Public link created", run.get("public_link_created", "Not recorded"))}
    {_metric("Cleanup status", run.get("cleanup_status", "Not completed yet"))}
</div>
<div class="ztvp-grid">
    {_metric("Current message", run.get("current_message", "N/A"))}
    {_metric("Started UTC", run.get("started_utc", "N/A"))}
    {_metric("Last updated UTC", run.get("last_updated_utc", "N/A"))}
    {_metric("Run ID", run.get("run_id", "N/A"))}
</div>
""",
        unsafe_allow_html=True,
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Open Active Runs", key="appc003_open_active_runs", use_container_width=True):
            st.session_state["pending_navigation"] = {"main_navigation": "Active Runs"}
            st.rerun()
    with col2:
        if st.button("Cancel APP-DV-003 run", key="appc003_cancel_run", use_container_width=True):
            request_cancel(project_root, str(run.get("run_id") or ""))
            st.rerun()


def _run_powershell_with_active_run(
    project_root: Path,
    script_path: Path,
    args: list[str],
    monitoring_window_minutes: int,
    poll_interval_seconds: int,
    report_path: Path,
    html_path: Path,
    target: str,
    tenant: str,
    timeout: int = 4200,
) -> tuple[subprocess.CompletedProcess, str]:
    import os

    run_id = new_run_id("APP-DV-003")
    max_attempts = _max_attempts(monitoring_window_minutes, poll_interval_seconds)
    now = utc_now()
    redacted_args = ["<redacted>" if previous == "-MdcaApiToken" else value for previous, value in zip(["", *args[:-1]], args)]
    command = " ".join(
        [
            str(script_path),
            *redacted_args,
        ]
    )

    save_run(
        project_root,
        {
            "run_id": run_id,
            "scenario_id": "APP-DV-003",
            "scenario_name": "MDCA Public File Sharing Detection Validation",
            "status": "polling",
            "phase": "Polling MDCA Alerts API",
            "verdict": None,
            "started_utc": now,
            "last_updated_utc": now,
            "wait_minutes": int(monitoring_window_minutes),
            "poll_seconds": int(poll_interval_seconds),
            "poll_attempts": 0,
            "max_poll_attempts": max_attempts,
            "progress_percent": 0,
            "target": target,
            "tenant": tenant,
            "local_evidence_status": "Not applicable",
            "tenant_evidence_status": "Waiting",
            "current_message": "APP-C-003 started. Creating dummy public link, then polling MDCA Alerts API.",
            "dummy_file_created": "Starting",
            "public_link_created": "Starting",
            "cleanup_status": "Not completed yet",
            "report_path": None,
            "html_report_path": None,
            "error": None,
            "cancel_requested": False,
            "powershell_command": command,
        },
    )

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

    proc = subprocess.Popen(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), *args],
        cwd=str(project_root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    started = time.monotonic()
    timed_out = False
    cancelled = False

    while proc.poll() is None:
        current = load_run(project_root, run_id)
        if current.get("cancel_requested"):
            proc.terminate()
            cancelled = True
            update_run(
                project_root,
                run_id,
                status="cancelled",
                phase="Cancelled",
                verdict="CANCELLED",
                current_message="APP-C-003 run cancelled from Active Runs.",
            )
            break
        if time.monotonic() - started > timeout:
            proc.kill()
            timed_out = True
            break
        elapsed = max(0, time.monotonic() - started)
        attempt = min(max_attempts, max(1, int(elapsed // max(1, poll_interval_seconds)) + 1))
        progress = min(95, int((attempt / max_attempts) * 100))
        update_run(
            project_root,
            run_id,
            status="polling",
            phase="Polling MDCA Alerts API",
            poll_attempts=attempt,
            progress_percent=progress,
            tenant_evidence_status="Waiting",
            dummy_file_created="Yes",
            public_link_created="Checking",
            current_message=f"Polling MDCA Alerts API. Attempt {attempt} of {max_attempts}.",
        )
        time.sleep(2)

    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=10)
        timed_out = True

    completed = subprocess.CompletedProcess(proc.args, -1 if timed_out else int(proc.returncode or 0), stdout, stderr)
    if cancelled:
        return completed, run_id

    if timed_out:
        update_run(
            project_root,
            run_id,
            status="error",
            phase="Timeout",
            verdict="ERROR",
            error="APP-C-003 exceeded the UI timeout.",
            current_message="APP-C-003 timed out before completion.",
        )
        return completed, run_id

    if completed.returncode != 0:
        update_run(
            project_root,
            run_id,
            status="error",
            phase="Error",
            verdict="ERROR",
            error=(stderr or stdout or f"PowerShell exited with {completed.returncode}")[-6000:],
            current_message="APP-C-003 stopped because an error occurred.",
        )
        return completed, run_id

    report = _load_json(report_path)
    if report:
        _write_html_report(report, html_path)
    metrics = report.get("metrics", {}) or {}
    mdca = report.get("mdca_detection_evidence", {}) or {}
    verdict = _verdict_from_status(report.get("status"))
    poll_attempts = int(metrics.get("poll_attempts") or mdca.get("poll_attempts") or max_attempts)
    max_report_attempts = int(metrics.get("max_poll_attempts") or mdca.get("max_poll_attempts") or max_attempts)
    evidence_found = bool(mdca.get("alert_detected") or mdca.get("governance_remediation_observed"))
    stopped_early = bool(metrics.get("polling_stopped_early") or mdca.get("polling_stopped_early"))
    tenant_status = "Found" if evidence_found else "Not found"
    final_message = (
        "MDCA evidence found. Polling stopped early and cleanup completed."
        if evidence_found
        else f"APP-C-003 completed. Verdict: {verdict or 'Unknown'}."
    )
    active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
    active_dir.mkdir(parents=True, exist_ok=True)
    archived_report_path = report_path
    archived_html_path = html_path
    if report_path.exists():
        archived_report_path = active_dir / f"{run_id}-result.json"
        shutil.copy2(report_path, archived_report_path)
    if html_path.exists():
        archived_html_path = active_dir / f"{run_id}-result.html"
        shutil.copy2(html_path, archived_html_path)
    update_run(
        project_root,
        run_id,
        status="completed",
        phase="Completed",
        verdict=verdict,
        result_code=report.get("status"),
        poll_attempts=poll_attempts,
        max_poll_attempts=max_report_attempts,
        progress_percent=100,
        tenant_evidence_status=tenant_status,
        current_message=final_message,
        report_path=str(archived_report_path) if archived_report_path.exists() else None,
        html_report_path=str(archived_html_path) if archived_html_path.exists() else None,
        completed_utc=utc_now(),
        cleanup_status=(report.get("cleanup") or {}).get("status"),
        dummy_file_created="Yes" if report.get("dummy_file") else "Not recorded",
        public_link_created=metrics.get("public_link_created"),
        polling_stopped_early=stopped_early,
        early_stop_reason=metrics.get("early_stop_reason") or mdca.get("early_stop_reason"),
        detection_method=metrics.get("detection_method") or mdca.get("detection_method"),
        error=None,
    )
    return completed, run_id


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
    write_standard_html_report(report, html_path)


def _render_report(report: dict, report_path: Path, html_path: Path, stdout: str) -> None:
    if not html_path.exists():
        _write_html_report(report, html_path)
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
    verdict = _verdict_from_status(status) or "REVIEW"
    cleanup_completed = (cleanup.get("status") == "Completed") or bool(metrics.get("cleanup_completed"))
    public_link_created = bool(metrics.get("public_link_created") or link.get("public_link_created"))
    alert_detected = bool(metrics.get("mdca_alert_detected") or mdca.get("alert_detected"))
    governance_observed = bool(metrics.get("governance_remediation_observed") or mdca.get("governance_remediation_observed"))
    stopped_early = bool(metrics.get("polling_stopped_early") or mdca.get("polling_stopped_early"))
    polls_used = f"{metrics.get('poll_attempts', mdca.get('poll_attempts', 'N/A'))} / {metrics.get('max_poll_attempts', mdca.get('max_poll_attempts', 'N/A'))}"
    scenario_result = _scenario_result(status, cleanup)
    detection_method = _first_value(metrics.get("detection_method"), mdca.get("detection_method"), "None")
    matching_title = _first_value(metrics.get("matching_alert_title"), mdca.get("matching_alert_title"), "")
    matching_policy = _first_value(metrics.get("matching_policy_name"), mdca.get("matching_policy_name"), "")
    alert_timestamp = _first_value(metrics.get("alert_timestamp"), mdca.get("alert_timestamp"), "")
    api_rows_checked = _first_value(metrics.get("mdca_api_rows_checked"), mdca.get("mdca_api_rows_checked"), "Not recorded")
    matching_fields = metrics.get("matching_fields") or mdca.get("matching_fields") or []
    if isinstance(matching_fields, list):
        matching_fields_text = ", ".join(str(item) for item in matching_fields) or "N/A"
    else:
        matching_fields_text = str(matching_fields or "N/A")
    why_matched = _first_value(metrics.get("why_matched"), mdca.get("why_matched"), mdca.get("early_stop_reason"), "N/A")

    explanation = (
        "ZTVP created a harmless dummy SharePoint public link. MDCA detected the exposure, so the tenant provided detection evidence. Cleanup completed."
        if verdict == "PASS"
        else "ZTVP created the harmless dummy public link and cleaned it up, but MDCA did not return matching alert or remediation evidence during the monitoring window."
    )

    _alert("MDCA public file sharing validation completed.", "good" if tone == "good" else tone)

    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Verdict", verdict, tone)}
    {_metric("Scenario result", scenario_result, "good" if scenario_result == "Detected" else "warn" if scenario_result == "Not detected" else "bad")}
    {_metric("Public link created", _bool_label(public_link_created), "warn" if public_link_created else "")}
    {_metric("MDCA alert detected", _bool_label(alert_detected), "good" if alert_detected else "warn")}
</div>
<div class="ztvp-grid">
    {_metric("Governance observed", _bool_label(governance_observed), "good" if governance_observed else "warn")}
    {_metric("Cleanup completed", _bool_label(cleanup_completed), "good" if cleanup_completed else "bad")}
    {_metric("Polls used", polls_used)}
    {_metric("Stopped early", _bool_label(stopped_early), "good" if stopped_early else "")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.write(explanation)

    st.markdown("#### Controlled SharePoint Target")
    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Site name", site.get("displayName", "N/A"))}
    {_metric("Drive / library", drive.get("name", "N/A"))}
    {_metric("Dummy file name", dummy.get("file_name", "N/A"))}
    {_metric("Link type requested", link.get("requested_type", "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Public link created", _bool_label(public_link_created), "warn" if public_link_created else "")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Detection Evidence")
    if alert_detected or governance_observed:
        st.markdown(
            f"""
<div class="ztvp-grid">
    {_metric("Matching alert found", _bool_label(alert_detected or governance_observed), "good")}
    {_metric("Detection method", detection_method, "good")}
    {_metric("Matching policy name", matching_policy or "N/A")}
    {_metric("Matching alert title", matching_title or "N/A")}
</div>
<div class="ztvp-grid-3">
    {_metric("Alert timestamp", alert_timestamp or "N/A")}
    {_metric("MDCA API rows checked", api_rows_checked)}
    {_metric("Early stop reason", _first_value(metrics.get("early_stop_reason"), mdca.get("early_stop_reason"), "N/A"))}
</div>
<div class="ztvp-grid-3">
    {_metric("Matching fields", matching_fields_text)}
    {_metric("Why it matched", why_matched)}
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        _alert("No matching MDCA alert/remediation evidence was returned during the monitoring window.", "warn")
        st.markdown(
            f"""
<div class="ztvp-grid-3">
    {_metric("Matching alert found", "No", "warn")}
    {_metric("Detection method", "None")}
    {_metric("MDCA API rows checked", api_rows_checked)}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### Cleanup")
    anonymous_removed = "Yes" if not mdca.get("permission_still_exists_before_cleanup") and public_link_created else _cleanup_action_status(cleanup, "anonymous")
    dummy_deleted = _cleanup_action_status(cleanup, "dummy")
    emergency_needed = "No" if cleanup_completed else "Yes"
    st.markdown(
        f"""
<div class="ztvp-grid">
    {_metric("Cleanup completed", _bool_label(cleanup_completed), "good" if cleanup_completed else "bad")}
    {_metric("Anonymous link removed", anonymous_removed)}
    {_metric("Dummy file/folder deleted", dummy_deleted)}
    {_metric("Emergency cleanup needed", emergency_needed, "bad" if emergency_needed == "Yes" else "good")}
</div>
""",
        unsafe_allow_html=True,
    )

    if warnings and not cleanup_completed:
        for warning in warnings:
            _alert(str(warning), "warn")

    st.markdown("#### Recommendations")
    for rec in _simple_recommendations():
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

    with st.expander("Technical evidence details", expanded=False):
        st.write(f"run_id: `{report.get('run_id') or 'N/A'}`")
        st.write(f"tenant_id: `{report.get('tenant_id') or 'N/A'}`")
        st.write(f"connected account: `{report.get('connected_account') or 'N/A'}`")
        st.write(f"site ID: `{site.get('id') or 'N/A'}`")
        st.write(f"drive ID: `{drive.get('id') or 'N/A'}`")
        st.write(f"file ID: `{dummy.get('file_id') or 'N/A'}`")
        st.write(f"item/folder ID: `{dummy.get('folder_id') or 'N/A'}`")
        st.write(f"permission ID: `{link.get('permission_id') or 'N/A'}`")
        st.write(f"state path: `powershell/Reports/Dynamic/APP-C-003/appc003-state.json`")
        st.write(f"report path: `{report_path}`")
        st.json(report)
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
    cleanup_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-003" / "appc003-cleanup-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-003-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-C-003-result.html"

    requested_run_id = str(st.session_state.get("ztvp_dynamic_open_run_id") or "")
    selected_run = selected_run_for_scenario(project_root, "APP-DV-003", requested_run_id)
    active_run = _latest_appc003_active_run(project_root, requested_run_id)
    _render_active_run_panel(project_root, active_run)
    if active_run:
        return

    if selected_run and str(selected_run.get("status") or "").lower() in {"completed", "cancelled", "error", "timeout", "stale"}:
        raw_report = str(selected_run.get("report_path") or "").strip()
        selected_report = Path(raw_report) if raw_report else Path("__missing_appc003_report__.json")
        selected_html = Path(str(selected_run.get("html_report_path") or selected_report.with_suffix(".html")))
        if selected_report.exists() and selected_report.is_file():
            st.markdown("### Selected APP-DV-003 run")
            _render_report(_load_json(selected_report), selected_report, selected_html, "")
        else:
            _alert(f"Selected run is {selected_run.get('status')}, but no report file is available yet.", "warn")

    cleanup_blocks_run, existing_state, cleanup_result = _cleanup_state_blocks_run(state_path, cleanup_path)

    if state_path.exists() and not cleanup_blocks_run:
        archive_path = _archive_completed_cleanup_state(state_path)
        _alert("Previous APP-C-003 cleanup completed. You can start a new validation.", "good")
        if archive_path:
            st.caption(f"Completed cleanup state was archived: `{archive_path}`")
        existing_state = {}

    if cleanup_blocks_run:
        _render_stale_state_panel(state_path, cleanup_path, existing_state)
        if st.button("Run emergency cleanup now", key="appc003_cleanup_now_top", use_container_width=True):
            with st.spinner("Running APP-C-003 emergency cleanup..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1800)

            if completed.returncode != 0:
                _alert("APP-C-003 emergency cleanup failed. State path is shown above.", "bad")
                st.code(
                    f"State path: {state_path}\nReturn code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}",
                    language="text",
                )
            else:
                _alert("APP-C-003 emergency cleanup completed. Refreshing so you can start a new run.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()

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
            "Optional policy name filter",
            value="",
            key="appc003_policy_name",
            help="Leave empty to let ZTVP accept any MDCA alert matching the dummy public SharePoint exposure. Use this only if you want to restrict matching to one policy.",
            placeholder="Example: MDCA-P1-M365-SharePoint-PublicSharing-Monitor",
        )
        st.caption("Leave empty to let ZTVP accept any MDCA alert matching the dummy public SharePoint exposure. Example policy name: MDCA-P1-M365-SharePoint-PublicSharing-Monitor.")
        _alert("Make sure an MDCA file policy exists to alert on publicly shared SharePoint/OneDrive files.", "info")

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
        cleanup_blocks_run, _, _ = _cleanup_state_blocks_run(state_path, cleanup_path)
        if cleanup_blocks_run:
            _alert("APP-C-003 did not start because an old cleanup state exists. Run Emergency cleanup first.", "bad")
            st.caption(f"State file blocking this run: `{state_path}`")
            return

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

        start_scenario_job(
            project_root,
            "APP-DV-003",
            int(monitoring_window),
            int(poll_interval),
            extra_args=args,
            target="Root site" if site_mode == "Root site" else custom_site_id.strip(),
            tenant="Microsoft 365 tenant",
        )
        _alert("APP-DV-003 started in the background. It is now visible in Active Runs and will keep polling if you leave this page.", "good")
        st.rerun()

    st.markdown("### 3. Emergency cleanup")

    cleanup_blocks_run, existing_state, cleanup_result = _cleanup_state_blocks_run(state_path, cleanup_path)

    if not existing_state:
        _alert("No active APP-C-003 cleanup state exists.", "good")
    elif not cleanup_blocks_run:
        _alert("Previous APP-C-003 cleanup completed. Emergency cleanup is not required.", "good")
        with st.expander("Technical evidence details", expanded=False):
            st.json(cleanup_result)
    else:
        _alert("Emergency cleanup removes the anonymous permission and deletes the dummy folder/file.", "warn")

        if st.button("Run emergency cleanup now", key="appc003_cleanup_now_bottom", use_container_width=True):
            with st.spinner("Running APP-C-003 emergency cleanup..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1800)

            if completed.returncode != 0:
                _alert("APP-C-003 emergency cleanup failed. The old state file is still blocking new runs.", "bad")
                st.code(
                    f"State path: {state_path}\nReturn code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}",
                    language="text",
                )
            else:
                _alert("APP-C-003 emergency cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()
