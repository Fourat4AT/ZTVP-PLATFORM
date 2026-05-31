from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from background_jobs import SCENARIOS as BACKGROUND_SCENARIOS, is_live, start_scenario_job
from ca_summary import summarize_ca_access_report, summarize_mfa_report
from run_state import ACTIVE_STATUSES, is_stale, list_runs, remove_run, request_cancel, scenario_nav_key, scenario_route, update_run


FAILED_STATUSES = {"error", "cancelled", "stale", "timeout"}
CLD_SHAREPOINT_IDS = {"APP-DV-008", "CLD-DV-001", "CLD-C-001"}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _css() -> None:
    st.markdown(
        """
<style>
.ztvp-run-card-marker { display: none; }
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) {
    background: #ffffff !important;
    border: 1px solid #dbe5f3 !important;
    border-radius: 18px !important;
    box-shadow: 0 14px 34px rgba(15, 23, 42, 0.08) !important;
    margin: 0 0 18px 0 !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) > div {
    padding: 18px 20px 16px 20px !important;
}
.ztvp-run-card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 8px;
}
.ztvp-run-card-title {
    color: #0f172a;
    font-size: 1.05rem;
    line-height: 1.3;
    font-weight: 900;
}
.ztvp-run-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 92px;
    border-radius: 999px;
    padding: 5px 10px;
    font-size: 0.76rem;
    font-weight: 850;
    white-space: nowrap;
}
.ztvp-run-badge-running { background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; }
.ztvp-run-badge-completed { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
.ztvp-run-badge-failed { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
.ztvp-run-badge-stale { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
.ztvp-run-badge-partial { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
.ztvp-run-badge-muted { background: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }
.ztvp-run-card-meta {
    color: #64748b;
    font-size: 0.82rem;
    line-height: 1.45;
    margin-bottom: 14px;
}
.ztvp-run-metric-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin: 8px 0 14px 0;
}
.ztvp-run-metric {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 10px 12px;
    min-height: 68px;
}
.ztvp-run-metric span {
    display: block;
    color: #64748b;
    font-size: 0.74rem;
    font-weight: 800;
    margin-bottom: 5px;
}
.ztvp-run-metric strong {
    display: block;
    color: #0f172a;
    font-size: 0.98rem;
    font-weight: 900;
    line-height: 1.25;
    word-break: break-word;
}
.ztvp-run-message {
    border-radius: 12px;
    padding: 11px 13px;
    margin: 6px 0 14px 0;
    font-weight: 760;
    line-height: 1.45;
}
.ztvp-run-message-info { background: #eff6ff; border: 1px solid #bfdbfe; color: #1e3a8a; }
.ztvp-run-message-good { background: #ecfdf5; border: 1px solid #bbf7d0; color: #14532d; }
.ztvp-run-message-warn { background: #fffbeb; border: 1px solid #fde68a; color: #78350f; }
.ztvp-run-message-bad { background: #fef2f2; border: 1px solid #fecaca; color: #7f1d1d; }
.ztvp-run-action-marker { display: none; }
div[data-testid="stButton"] button {
    background: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    color: #0f172a !important;
    box-shadow: 0 6px 14px rgba(15, 23, 42, 0.06) !important;
}
div[data-testid="stButton"] button:hover {
    background: #eff6ff !important;
    border-color: #93c5fd !important;
    color: #1d4ed8 !important;
}
div[data-testid="stButton"] button:disabled,
div[data-testid="stButton"] button:disabled p {
    background: #f8fafc !important;
    border-color: #e2e8f0 !important;
    color: #94a3b8 !important;
    opacity: 1 !important;
}
div[data-testid="stDownloadButton"] button {
    background: #ffffff !important;
    border: 1px solid #bfdbfe !important;
    color: #1d4ed8 !important;
    box-shadow: 0 6px 14px rgba(15, 23, 42, 0.06) !important;
}
div[data-testid="stDownloadButton"] button:hover {
    background: #eff6ff !important;
    border-color: #93c5fd !important;
    color: #1e40af !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) div[data-testid="stButton"] button,
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) div[data-testid="stDownloadButton"] button {
    min-height: 42px !important;
    border-radius: 10px !important;
    font-weight: 820 !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) div[data-testid="stButton"] button p,
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) div[data-testid="stDownloadButton"] button p {
    color: inherit !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) button[data-testid="stBaseButton-primary"] {
    background: #2563eb !important;
    border-color: #2563eb !important;
    color: #ffffff !important;
}
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"],
div[data-testid="stButton"] button[kind="primary"] {
    background: #2563eb !important;
    border-color: #2563eb !important;
    color: #ffffff !important;
    box-shadow: 0 8px 20px rgba(37, 99, 235, 0.20) !important;
}
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"]:hover,
div[data-testid="stButton"] button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    border-color: #1d4ed8 !important;
    color: #ffffff !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-run-card-marker) button[data-testid="stBaseButton-primary"] p {
    color: #ffffff !important;
}
.ztvp-run-empty-state {
    background: #f8fafc;
    border: 1px dashed #cbd5e1;
    border-radius: 14px;
    color: #64748b;
    padding: 18px 20px;
    font-weight: 750;
    margin: 10px 0 16px 0;
}
.ztvp-run-toolbar-marker,
.ztvp-run-table-marker {
    display: none;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) {
    gap: 0.45rem !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stHorizontalBlock"] {
    align-items: end !important;
    gap: 0.75rem !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stSelectbox"] {
    margin-bottom: 0 !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stSelectbox"] label {
    color: #334155 !important;
    font-size: 0.8rem !important;
    font-weight: 850 !important;
    padding-bottom: 0.18rem !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stCaptionContainer"] {
    color: #64748b !important;
    line-height: 1.35 !important;
    padding-bottom: 0.42rem !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stButton"] button {
    min-height: 38px !important;
    border-radius: 10px !important;
    font-weight: 850 !important;
}
.ztvp-recent-runs-heading {
    color: #0f172a;
    font-size: 1rem;
    font-weight: 900;
    line-height: 1.2;
    margin: 0.85rem 0 0.35rem 0;
}
.ztvp-run-toolbar-help {
    color: #64748b;
    font-size: 0.82rem;
    font-weight: 720;
    line-height: 1.35;
    padding: 1.55rem 0 0.35rem 0;
    text-align: center;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-table-marker) {
    gap: 0.35rem !important;
}
div[data-testid="stVerticalBlock"]:has(.ztvp-run-table-marker) div[data-testid="stDataFrame"] {
    margin-bottom: 0.45rem !important;
}
div[data-testid="stTabs"] button[role="tab"],
div[data-testid="stTabs"] button[role="tab"] p {
    color: #2563eb !important;
}
div[data-testid="stTabs"] button[role="tab"]:hover,
div[data-testid="stTabs"] button[role="tab"]:hover p,
div[data-testid="stTabs"] button[role="tab"][aria-selected="true"],
div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] p {
    color: #2563eb !important;
}
div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
    background-color: #2563eb !important;
}
div[data-testid="stButton"] button p,
div[data-testid="stDownloadButton"] button p {
    color: inherit !important;
}
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"] p,
div[data-testid="stButton"] button[kind="primary"] p {
    color: #ffffff !important;
}
@media (max-width: 900px) {
    .ztvp-run-card-header { display: block; }
    .ztvp-run-badge { margin-top: 8px; }
    .ztvp-run-metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stHorizontalBlock"] {
        gap: 0.45rem !important;
    }
    div[data-testid="stVerticalBlock"]:has(.ztvp-run-toolbar-marker) div[data-testid="stCaptionContainer"] {
        padding-bottom: 0 !important;
    }
    .ztvp-run-toolbar-help {
        padding: 0.1rem 0 0.25rem 0;
        text-align: left;
    }
}
@media (max-width: 560px) {
    .ztvp-run-metric-grid { grid-template-columns: 1fr; }
    .ztvp-recent-runs-heading {
        margin-top: 0.7rem;
    }
}
</style>
""",
        unsafe_allow_html=True,
    )


def _tone(status: str) -> str:
    status = status.lower()
    if status == "completed":
        return "complete"
    if status == "error":
        return "error"
    return "running"


def _verdict_badge_tone(verdict: object) -> str | None:
    text = str(verdict or "").upper()
    if text in {"PASS", "VALIDATED"}:
        return "completed"
    if text == "PARTIAL":
        return "partial"
    if text in {"FAIL", "ERROR"}:
        return "failed"
    if text in {"CANCELLED", "UNSUPPORTED"}:
        return "muted"
    return None


def _badge_tone(status: str, stale: bool, verdict: object = None) -> str:
    if stale or status in {"stale", "timeout"}:
        return "stale"
    verdict_tone = _verdict_badge_tone(verdict)
    if verdict_tone:
        return verdict_tone
    if status == "completed":
        return "completed"
    if status in FAILED_STATUSES:
        return "failed"
    return "running"


def _message_tone(status: str, stale: bool, verdict: object = None) -> str:
    verdict_text = str(verdict or "").upper()
    if stale or status in {"stale", "timeout", "cancelled"}:
        return "warn"
    if verdict_text in {"PASS", "VALIDATED"}:
        return "good"
    if verdict_text == "PARTIAL":
        return "warn"
    if verdict_text in {"FAIL", "ERROR"}:
        return "bad"
    if verdict_text in {"CANCELLED", "UNSUPPORTED"}:
        return "info"
    if status == "completed":
        return "info"
    if status == "error":
        return "bad"
    return "info"


def _display_status(run: dict) -> str:
    status = str(run.get("status") or "unknown").lower()
    verdict = str(run.get("verdict") or "").upper()
    if status == "completed" and verdict:
        return verdict
    if status == "stale":
        return "Stale"
    return status.replace("_", " ").title()


def _is_run_stale(run: dict) -> bool:
    return is_stale(run) and not is_live(str(run.get("run_id") or ""))


def _open_scenario(run: dict) -> bool:
    scenario_id = str(run.get("scenario_id") or "").upper()
    route = scenario_route(scenario_id)
    nav_key = scenario_nav_key(scenario_id)
    if not route or not nav_key:
        st.warning(f"Scenario route not found for {scenario_id}.")
        return False

    st.session_state["pending_navigation"] = {
        "main_navigation": "Dynamic Validation",
        "pending_main_navigation": "Dynamic Validation",
        "home_mode": "dynamic",
        "ztvp_dynamic_open_scenario": nav_key,
        "ztvp_dynamic_pillar": route["pillar"],
        "ztvp_dynamic_scope": route["scope"],
        "pending_pillar": route["pillar"],
        "pending_scope": route["scope"],
        "pending_scenario_id": route["scenario_id"],
        "pending_run_id": str(run.get("run_id") or ""),
        "pending_run_status": str(run.get("status") or ""),
        "pending_report_path": str(run.get("report_path") or ""),
        "dynamic_scenario_id": route["scenario_id"],
    }
    return True


def _safe_report_path(project_root: Path, raw_path: object) -> Path | None:
    if raw_path is None:
        return None
    raw = str(raw_path).strip()
    if raw in {"", ".", "None", "none", "null", "NULL"}:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = project_root / path
    try:
        path = path.resolve()
    except Exception:
        return None
    if not path.exists() or not path.is_file():
        return None
    return path


def _load_report(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _first_value(*values: object) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"unknown", "n/a", "none", "null"}:
            return text
    return ""


def _enrich_run(project_root: Path, run: dict) -> dict:
    enriched = dict(run)
    report_path = _safe_report_path(project_root, enriched.get("report_path"))
    if report_path is not None and not _safe_report_path(project_root, enriched.get("html_report_path")):
        candidate = report_path.with_suffix(".html")
        if candidate.exists():
            enriched["html_report_path"] = str(candidate)
    report = _load_report(report_path)
    evidence = report.get("evidence") or {}
    local = evidence.get("local") or {}
    tenant_api = ((evidence.get("tenant") or {}).get("api") or {})
    scenario_id = str(enriched.get("scenario_id") or "").upper()

    if str(enriched.get("status") or "").lower() == "completed" and enriched.get("verdict"):
        enriched["progress_percent"] = 100
    if report:
        enriched["target"] = _first_value(enriched.get("target"), report.get("test_device"), tenant_api.get("test_device_name_requested"), local.get("computer_name"))
        enriched["tenant"] = _first_value(enriched.get("tenant"), report.get("tenant_display_name"), report.get("tenant_id"))
        enriched["completed_utc"] = _first_value(enriched.get("completed_utc"), report.get("completed_utc"), report.get("generated_utc"))
        if not enriched.get("local_evidence_status"):
            enriched["local_evidence_status"] = "Found" if local else "Not recorded"
        if not enriched.get("tenant_evidence_status"):
            if tenant_api.get("mde_cloud_evidence_found"):
                enriched["tenant_evidence_status"] = "Found"
            else:
                enriched["tenant_evidence_status"] = _first_value(tenant_api.get("mde_cloud_query_status"), "Not recorded")
        if scenario_id == "DEV-DV-008":
            if not enriched.get("local_result"):
                settings_weakened = bool(local.get("settings_weakened"))
                protected = bool(local.get("defender_settings_remained_protected") or local.get("tamper_attempt_blocked_or_ignored")) and not settings_weakened
                if protected:
                    enriched["local_result"] = "Protected"
                elif settings_weakened:
                    enriched["local_result"] = "Settings weakened"
            if not enriched.get("tamper_protection") and local:
                enriched["tamper_protection"] = "Enabled" if local.get("tamper_protection_enabled") else "Disabled or not returned"
            if not enriched.get("settings_weakened") and "settings_weakened" in local:
                enriched["settings_weakened"] = "Yes" if local.get("settings_weakened") else "No"
        elif scenario_id == "DEV-DV-006" and not enriched.get("local_eicar_detection"):
            enriched["local_eicar_detection"] = "Found" if local.get("local_detection_found") or local.get("defender_blocking_error_found") or local.get("file_removed_or_quarantined") else "Not recorded"
        elif scenario_id in {"ID-DV-001", "ID-C-001"}:
            mfa = summarize_mfa_report(report)
            enriched["tenant_evidence_status"] = "Found" if mfa.get("sign_in_result") != "Unknown" else _first_value(enriched.get("tenant_evidence_status"), "Not found")
            enriched["mfa_required"] = mfa.get("mfa_required")
            enriched["mfa_completed"] = mfa.get("mfa_completed")
            enriched["sign_in_result"] = mfa.get("sign_in_result")
            enriched["access_without_mfa"] = mfa.get("access_without_mfa")
            enriched["effective_policy"] = mfa.get("effective_policy")
            enriched["conditional_access_status"] = mfa.get("conditional_access_result")
        elif scenario_id == "APP-DV-003":
            metrics = report.get("metrics") or {}
            mdca = report.get("mdca_detection_evidence") or {}
            if not enriched.get("tenant_evidence_status"):
                enriched["tenant_evidence_status"] = "Found" if mdca.get("alert_detected") or mdca.get("governance_remediation_observed") else "Not found"
            if not enriched.get("poll_attempts"):
                enriched["poll_attempts"] = metrics.get("poll_attempts") or mdca.get("poll_attempts")
            if not enriched.get("max_poll_attempts"):
                enriched["max_poll_attempts"] = metrics.get("max_poll_attempts") or mdca.get("max_poll_attempts")
            if not enriched.get("current_message") and (metrics.get("polling_stopped_early") or mdca.get("polling_stopped_early")):
                enriched["current_message"] = "MDCA evidence found. Polling stopped early and cleanup completed."
            if not enriched.get("detection_method"):
                enriched["detection_method"] = metrics.get("detection_method") or mdca.get("detection_method")
        elif scenario_id in CLD_SHAREPOINT_IDS:
            metrics = report.get("metrics") or {}
            attempt = report.get("anonymous_link_attempt") or {}
            cleanup = report.get("cleanup") or {}
            site = report.get("site") or {}
            test_object = report.get("test_object") or {}
            link_created = bool(metrics.get("anonymous_link_created") or attempt.get("link_created"))
            link_denied = bool(metrics.get("anonymous_link_denied") or attempt.get("link_denied"))
            cleanup_done = bool(metrics.get("cleanup_completed") or str(cleanup.get("status") or "").lower() == "completed")
            enriched["target"] = _first_value(enriched.get("target"), site.get("displayName"), site.get("webUrl"), "SharePoint")
            enriched["target_site"] = _first_value(enriched.get("target_site"), site.get("displayName"), site.get("webUrl"))
            enriched["dummy_file"] = _first_value(enriched.get("dummy_file"), test_object.get("file_name"))
            enriched["anonymous_link_created"] = "Yes" if link_created else "No"
            enriched["link_blocked_denied"] = "Yes" if link_denied else "No"
            enriched["denial_reason"] = _first_value(attempt.get("error_message"), attempt.get("error_category"), "Not applicable")
            enriched["cleanup_completed"] = "Yes" if cleanup_done else "No"
            enriched["tenant_evidence_status"] = "Found" if link_created or link_denied else _first_value(enriched.get("tenant_evidence_status"), "Not found")
            enriched["anonymous_link_attempt_status"] = "Allowed" if link_created else "Blocked/Denied" if link_denied else _first_value(enriched.get("anonymous_link_attempt_status"), "Not created")
        elif scenario_id == "APP-DV-004":
            evidence = report.get("appdv004_evidence") or {}
            metrics = report.get("metrics") or {}
            ca = summarize_ca_access_report(report, "device")
            enriched["test_user"] = _first_value(enriched.get("test_user"), report.get("test_user"))
            enriched["target_app"] = _first_value(enriched.get("target_app"), report.get("target_app"))
            enriched["validation_start_utc"] = _first_value(enriched.get("validation_start_utc"), report.get("started_utc"))
            enriched["tenant_evidence_status"] = "Found" if evidence.get("signin_found") else _first_value(enriched.get("tenant_evidence_status"), "Not found")
            enriched["access_result"] = evidence.get("access_result")
            enriched["ca_evidence_found"] = "Yes" if ca.get("effective_policy") != "None found" else "No"
            enriched["policy_name"] = ca.get("effective_policy")
            enriched["effective_policy"] = ca.get("effective_policy")
            enriched["conditional_access_status"] = ca.get("conditional_access_result")
            enriched["sign_in_result"] = ca.get("sign_in_result")
            enriched["polling_stopped_early"] = metrics.get("polling_stopped_early")
        elif scenario_id == "DEV-DV-001":
            evidence = report.get("sign_in_log_evidence") or {}
            metrics = report.get("metrics") or {}
            ca = summarize_ca_access_report(report, "device")
            decoy = report.get("decoy_user") or {}
            target = report.get("target") or {}
            enriched["decoy_user"] = _first_value(enriched.get("decoy_user"), decoy.get("user_principal_name"), evidence.get("decoy_user"))
            enriched["test_user"] = _first_value(enriched.get("test_user"), enriched.get("decoy_user"))
            enriched["target_app"] = _first_value(enriched.get("target_app"), target.get("name"), report.get("target_app"))
            enriched["validation_start_utc"] = _first_value(enriched.get("validation_start_utc"), report.get("validation_start_utc"), evidence.get("validation_window_start_utc"))
            enriched["tenant_evidence_status"] = "Found" if evidence.get("meaningful_sign_in_count") or evidence.get("selected_event") else _first_value(enriched.get("tenant_evidence_status"), "Not found")
            if not (evidence.get("meaningful_sign_in_count") or evidence.get("selected_event")):
                enriched["conditional_access_status"] = "Not available"
                enriched["blocking_policy_name"] = "Not available"
                enriched["device_state"] = "Unknown"
            else:
                enriched["conditional_access_status"] = _first_value(ca.get("conditional_access_result"), metrics.get("conditional_access_status"), evidence.get("conditional_access_status"), "Not available")
                enriched["blocking_policy_name"] = _first_value(ca.get("effective_policy"), metrics.get("device_trust_policy_name"), metrics.get("blocking_policy_name"), evidence.get("device_trust_policy_name"), evidence.get("blocking_policy_name"), "Not available")
                enriched["effective_policy"] = enriched["blocking_policy_name"]
                enriched["sign_in_result"] = ca.get("sign_in_result")
                enriched["device_state"] = "Compliant: {0}; Managed: {1}".format(
                    _first_value(metrics.get("device_is_compliant"), ((evidence.get("device_detail") or {}).get("is_compliant")), "Unknown"),
                    _first_value(metrics.get("device_is_managed"), ((evidence.get("device_detail") or {}).get("is_managed")), "Unknown"),
                )
            if not enriched.get("poll_attempts"):
                enriched["poll_attempts"] = metrics.get("poll_attempts") or evidence.get("poll_count")
            if not enriched.get("max_poll_attempts"):
                enriched["max_poll_attempts"] = metrics.get("max_poll_attempts") or evidence.get("max_poll_attempts")
        elif scenario_id == "DEV-DV-004":
            metrics = report.get("metrics") or {}
            evidence = report.get("evidence") or {}
            found = report.get("what_ztvp_found") or {}
            timer = report.get("timer") or {}
            decoy = report.get("decoy_user") or {}
            final_state = report.get("final_device_state") or {}
            enriched["decoy_user"] = _first_value(enriched.get("decoy_user"), decoy.get("user_principal_name"))
            enriched["tenant_evidence_status"] = "Found" if metrics.get("device_registered_or_linked") or metrics.get("audit_events_found") or metrics.get("sign_in_evidence_found") else _first_value(enriched.get("tenant_evidence_status"), "Not found")
            enriched["final_device_state"] = _first_value(enriched.get("final_device_state"), metrics.get("final_device_state"), final_state.get("state"))
            enriched["registered_devices_linked_count"] = _first_value(enriched.get("registered_devices_linked_count"), metrics.get("registered_devices_linked_count"), evidence.get("registered_device_count_after_window"), found.get("registered_devices_linked_to_decoy_user"), "0")
            enriched["temporary_device_observed"] = "Yes" if metrics.get("temporary_device_observed") or found.get("temporary_device_observed") else "No"
            enriched["final_graph_registered_devices_count"] = _first_value(metrics.get("final_graph_registered_devices_count"), found.get("final_graph_registered_devices_count"), evidence.get("final_graph_registered_devices_count"), "0")
            enriched["device_still_exists_in_devices"] = _first_value(metrics.get("device_still_exists_in_devices"), found.get("device_still_exists_in_devices"), evidence.get("device_still_exists_in_devices"), "Unknown")
            enriched["audit_events_found"] = "Yes" if metrics.get("audit_events_found") or found.get("audit_events_found") else "No"
            enriched["audit_event_count"] = _first_value(metrics.get("audit_event_count"), found.get("lifecycle_events_count"), evidence.get("registration_like_audit_count_after_window"), "0")
            enriched["current_evidence_source"] = _first_value(enriched.get("current_evidence_source"), "completed")
            if not enriched.get("poll_attempts"):
                enriched["poll_attempts"] = metrics.get("poll_attempts") or timer.get("poll_attempts")
            if not enriched.get("max_poll_attempts"):
                enriched["max_poll_attempts"] = metrics.get("max_poll_attempts") or timer.get("max_poll_attempts")
            enriched["elapsed_seconds"] = _first_value(enriched.get("elapsed_seconds"), metrics.get("elapsed_seconds"), timer.get("elapsed_seconds"))
            enriched["retry_interval_seconds"] = _first_value(enriched.get("retry_interval_seconds"), metrics.get("poll_interval_seconds"), timer.get("retry_interval_seconds"))
            enriched["monitoring_window_minutes"] = _first_value(enriched.get("monitoring_window_minutes"), timer.get("monitoring_window_minutes"))
    return enriched


def _polls_label(run: dict) -> str:
    attempts = run.get("poll_attempts")
    max_attempts = run.get("max_poll_attempts")
    if attempts in [None, ""] or max_attempts in [None, "", 0, "0"]:
        return "Not recorded"
    return f"{attempts} / {max_attempts}"


def _fmt_seconds(value: object) -> str:
    try:
        seconds = max(0, int(float(value or 0)))
    except Exception:
        return "Not recorded"
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{sec:02d}"
    return f"{minutes:02d}:{sec:02d}"


def _show_metric_if_value(column, label: str, value: object) -> None:
    text = _first_value(value)
    if text:
        column.metric(label, text)


def _empty_state(message: str) -> None:
    st.markdown(f'<div class="ztvp-run-empty-state">{_safe(message)}</div>', unsafe_allow_html=True)


def _metric_tile(label: str, value: object) -> str:
    text = _first_value(value)
    if not text:
        return ""
    return f"""
<div class="ztvp-run-metric">
  <span>{_safe(label)}</span>
  <strong>{_safe(text)}</strong>
</div>
"""


def _run_metric_tiles(run: dict, scenario_id: str, status: str) -> str:
    tiles = [
        _metric_tile("Progress", f"{int(run.get('progress_percent') or 0)}%"),
        _metric_tile("Polls", _polls_label(run)),
        _metric_tile("Verdict", run.get("verdict") or "-"),
        _metric_tile("Tenant evidence", _first_value(run.get("tenant_evidence_status")) or "Not recorded"),
        _metric_tile("Local evidence", run.get("local_evidence_status")),
    ]
    if scenario_id == "DEV-DV-004":
        tiles.extend(
            [
                _metric_tile("Elapsed", _fmt_seconds(run.get("elapsed_seconds"))),
                _metric_tile("Remaining", _fmt_seconds(run.get("remaining_seconds")) if status in ACTIVE_STATUSES else "00:00"),
                _metric_tile("Monitoring window", f"{run.get('monitoring_window_minutes') or run.get('wait_minutes') or 'N/A'} min"),
                _metric_tile("Retry interval", f"{run.get('retry_interval_seconds') or run.get('poll_seconds') or 'N/A'} sec"),
                _metric_tile("Current check", run.get("current_evidence_source")),
                _metric_tile("Final device state", run.get("final_device_state")),
                _metric_tile("Temporary device observed", run.get("temporary_device_observed")),
                _metric_tile("Linked devices", run.get("registered_devices_linked_count")),
                _metric_tile("Final Graph devices", run.get("final_graph_registered_devices_count")),
                _metric_tile("/devices exists", run.get("device_still_exists_in_devices")),
                _metric_tile("Audit lifecycle events", run.get("audit_event_count") or run.get("audit_events_found")),
            ]
        )
    elif scenario_id == "DEV-DV-008":
        tiles.extend(
            [
                _metric_tile("Local result", run.get("local_result")),
                _metric_tile("Tamper Protection", run.get("tamper_protection")),
                _metric_tile("Settings weakened", run.get("settings_weakened")),
            ]
        )
    elif scenario_id == "DEV-DV-006":
        tiles.append(_metric_tile("Local EICAR detection", run.get("local_eicar_detection") or run.get("local_evidence_status")))
    elif scenario_id in {"ID-DV-001", "ID-C-001"}:
        tiles.append(_metric_tile("MFA required", run.get("mfa_required")))
        tiles.append(_metric_tile("MFA completed", run.get("mfa_completed")))
        tiles.append(_metric_tile("Sign-in result", run.get("sign_in_result")))
        tiles.append(_metric_tile("Effective policy", run.get("effective_policy")))
    elif scenario_id in {"ID-DV-005", "ID-C-005"}:
        tiles.append(_metric_tile("External email", run.get("external_test_email")))
        tiles.append(_metric_tile("Graph status", run.get("graph_connection_status")))
        tiles.append(_metric_tile("Invitation attempted", "Yes" if run.get("guest_invitation_attempted") else "No"))
        tiles.append(_metric_tile("Invitation succeeded", "Yes" if run.get("guest_invitation_succeeded") else "No"))
        tiles.append(_metric_tile("Tenant blocked invite", "Yes" if run.get("tenant_blocked_invite") else "No"))
    elif scenario_id == "APP-DV-003":
        tiles.append(_metric_tile("Stopped early", "Yes" if run.get("polling_stopped_early") else "No"))
        tiles.append(_metric_tile("Detection method", run.get("detection_method")))
    elif scenario_id in CLD_SHAREPOINT_IDS:
        tiles.append(_metric_tile("Target site", run.get("target_site") or run.get("target")))
        tiles.append(_metric_tile("Dummy file", run.get("dummy_file")))
        tiles.append(_metric_tile("Anonymous link created", run.get("anonymous_link_created")))
        tiles.append(_metric_tile("Link blocked", run.get("link_blocked_denied")))
        tiles.append(_metric_tile("Denial reason", run.get("denial_reason")))
        tiles.append(_metric_tile("Cleanup completed", run.get("cleanup_completed") or run.get("cleanup_status")))
    elif scenario_id == "APP-DV-004":
        tiles.append(_metric_tile("Test user", run.get("test_user")))
        tiles.append(_metric_tile("Target app", run.get("target_app")))
        tiles.append(_metric_tile("Sign-in result", run.get("sign_in_result") or run.get("access_result")))
        tiles.append(_metric_tile("Effective policy", run.get("effective_policy") or run.get("policy_name")))
        tiles.append(_metric_tile("CA result", run.get("conditional_access_status")))
    elif scenario_id == "DEV-DV-001":
        tiles.append(_metric_tile("Decoy user", run.get("decoy_user") or run.get("test_user")))
        tiles.append(_metric_tile("Target app", run.get("target_app")))
        tiles.append(_metric_tile("Sign-in result", run.get("sign_in_result")))
        tiles.append(_metric_tile("CA result", run.get("conditional_access_status")))
        tiles.append(_metric_tile("Effective policy", run.get("effective_policy") or run.get("blocking_policy_name")))
        tiles.append(_metric_tile("Device state", run.get("device_state")))
    if status in ACTIVE_STATUSES:
        tiles.append(_metric_tile("Phase", run.get("phase")))
    return "\n".join(tile for tile in tiles if tile)


def _run_message(run: dict, status: str) -> str:
    if status == "error" and run.get("error"):
        return f"Run failed: {run.get('error')}"
    return _first_value(run.get("current_message"), run.get("phase"), "No run message recorded.")


def _render_run(project_root: Path, run: dict, render_key: str) -> None:
    run = _enrich_run(project_root, run)
    run_id = str(run.get("run_id") or "")
    scenario_id = str(run.get("scenario_id") or "")
    status = str(run.get("status") or "unknown").lower()
    stale = _is_run_stale(run)
    title = f"{scenario_id} - {run.get('scenario_name') or 'Scenario'}"
    status_label = "Stale / interrupted" if stale else _display_status(run)
    badge_tone = _badge_tone(status, stale, run.get("verdict"))
    message_tone = _message_tone(status, stale, run.get("verdict"))
    completed = _first_value(run.get("completed_utc"))
    target = _first_value(run.get("target"))
    tenant = _first_value(run.get("tenant"))
    meta_parts = [
        f"Target: {target or 'Not recorded'}",
        f"Tenant: {tenant or 'Not recorded'}",
        f"Started UTC: {_first_value(run.get('started_utc')) or 'Not recorded'}",
        f"Last updated UTC: {_first_value(run.get('last_updated_utc')) or 'Not recorded'}",
    ]
    if completed:
        meta_parts.append(f"Completed UTC: {completed}")

    with st.container(border=True):
        st.markdown(
            f"""
<div class="ztvp-run-card-marker"></div>
<div class="ztvp-run-card-header">
  <div class="ztvp-run-card-title">{_safe(title)}</div>
  <div class="ztvp-run-badge ztvp-run-badge-{_safe(badge_tone)}">{_safe(status_label)}</div>
</div>
<div class="ztvp-run-card-meta">{_safe(" | ".join(meta_parts))}</div>
<div class="ztvp-run-metric-grid">
  {_run_metric_tiles(run, scenario_id, status)}
</div>
<div class="ztvp-run-message ztvp-run-message-{_safe(message_tone)}">{_safe(_run_message(run, status))}</div>
""",
            unsafe_allow_html=True,
        )

        if run.get("error"):
            with st.expander("Error / logs", expanded=False):
                st.code(str(run.get("error")), language="text")

        st.markdown('<div class="ztvp-run-action-marker"></div>', unsafe_allow_html=True)
        action_cols = st.columns([1.25, 1.05, 0.85, 1.15, 0.85])
        with action_cols[0]:
            if st.button("Open scenario", key=f"open_{render_key}_{run_id}", use_container_width=True, type="primary"):
                if _open_scenario(run):
                    st.rerun()
        with action_cols[1]:
            report_path = _safe_report_path(project_root, run.get("report_path"))
            html_report_path = _safe_report_path(project_root, run.get("html_report_path"))
            if html_report_path is not None:
                st.download_button(
                    "View HTML report",
                    html_report_path.read_bytes(),
                    html_report_path.name,
                    "text/html",
                    key=f"html_report_{render_key}_{run_id}",
                    use_container_width=True,
                )
                if report_path is not None:
                    st.download_button(
                        "Download JSON evidence",
                        report_path.read_bytes(),
                        report_path.name,
                        "application/json",
                        key=f"json_report_{render_key}_{run_id}",
                        use_container_width=True,
                    )
            elif report_path is not None:
                st.download_button(
                    "Download JSON evidence",
                    report_path.read_bytes(),
                    report_path.name,
                    "application/json",
                    key=f"json_report_only_{render_key}_{run_id}",
                    use_container_width=True,
                )
            else:
                st.button("View report", key=f"report_disabled_{render_key}_{run_id}", use_container_width=True, disabled=True)
                if status == "completed":
                    st.caption("Completed, but archived report file is not available.")
                else:
                    st.caption("Report file not available yet.")
        with action_cols[2]:
            if status in ACTIVE_STATUSES:
                if st.button("Cancel", key=f"cancel_{render_key}_{run_id}", use_container_width=True):
                    request_cancel(project_root, run_id)
                    st.rerun()
            else:
                st.button("Cancel", key=f"cancel_disabled_{render_key}_{run_id}", use_container_width=True, disabled=True)
        with action_cols[3]:
            if stale and scenario_id.upper() in BACKGROUND_SCENARIOS and scenario_id.upper() != "APP-DV-003":
                if st.button("Resume polling", key=f"resume_{render_key}_{run_id}", use_container_width=True):
                    start_scenario_job(
                        project_root,
                        scenario_id,
                        int(run.get("wait_minutes") or 5),
                        int(run.get("poll_seconds") or 30),
                        run_id=run_id,
                        resume=True,
                    )
                    st.rerun()
            else:
                st.button("Resume polling", key=f"resume_disabled_{render_key}_{run_id}", use_container_width=True, disabled=True)
        with action_cols[4]:
            if status in ACTIVE_STATUSES and stale:
                if st.button("Mark stopped", key=f"stop_{render_key}_{run_id}", use_container_width=True):
                    update_run(
                        project_root,
                        run_id,
                        status="stale",
                        phase="Stopped",
                        current_message="Run marked stopped after the background job was interrupted.",
                    )
                    st.rerun()
            elif status not in ACTIVE_STATUSES:
                if st.button("Remove", key=f"remove_{render_key}_{run_id}", use_container_width=True):
                    remove_run(project_root, run_id)
                    st.rerun()
            else:
                st.button("Remove", key=f"remove_disabled_{render_key}_{run_id}", use_container_width=True, disabled=True)

        with st.expander("Technical details", expanded=False):
            st.write(f"run_id: `{run_id}`")
            st.write(f"state JSON path: `{run.get('_path') or ''}`")
            st.write(f"report path: `{run.get('report_path') or ''}`")
            st.write(f"HTML report path: `{run.get('html_report_path') or ''}`")
            st.write(f"current message: `{run.get('current_message') or ''}`")
            st.write(f"PowerShell process command: `{run.get('powershell_command') or ''}`")
            st.write(f"last error: `{run.get('error') or ''}`")
            st.write(f"raw status: `{run.get('status') or ''}`")
            st.write(f"updated UTC: `{run.get('last_updated_utc') or ''}`")


def render_active_runs_page(project_root: Path | str, hero=None) -> None:
    _css()
    project_root = Path(project_root)
    if hero:
        hero("Active Runs", "Monitor background validation runs, cancel polling, resume stale runs, and open completed reports.")
    else:
        st.title("Active Runs")

    runs = list_runs(project_root)
    for run in runs:
        status = str(run.get("status") or "").lower()
        run_id = str(run.get("run_id") or "")
        if status in ACTIVE_STATUSES and _is_run_stale(run):
            update_run(
                project_root,
                run_id,
                status="stale",
                verdict=run.get("verdict"),
                phase="Interrupted",
                current_message="Run was interrupted because the app process stopped.",
            )
    runs = list_runs(project_root)
    if not runs:
        _empty_state("No active run files exist yet. Start tenant evidence analysis from a scenario page.")
        return

    has_live_runs = any(str(run.get("status") or "").lower() in ACTIVE_STATUSES and not _is_run_stale(run) for run in runs)

    with st.container():
        st.markdown('<div class="ztvp-run-toolbar-marker"></div>', unsafe_allow_html=True)
        filter_col, note_col, refresh_col, clear_col = st.columns([0.24, 0.34, 0.18, 0.24])
        with filter_col:
            completed_limit = st.selectbox("Show recent completed runs", [10, 20, 50], index=0, format_func=lambda value: f"Last {value}", key="active_runs_completed_limit")
        with note_col:
            helper = "Live runs update when you refresh this page." if has_live_runs else "Completed cleanup removes Active Runs JSON entries only. Report files are kept."
            st.markdown(f'<div class="ztvp-run-toolbar-help">{_safe(helper)}</div>', unsafe_allow_html=True)
        with refresh_col:
            if st.button("Refresh runs", use_container_width=True):
                st.rerun()
        with clear_col:
            if st.button("Clear completed run states", use_container_width=True):
                for run in runs:
                    if str(run.get("status") or "").lower() == "completed":
                        remove_run(project_root, str(run.get("run_id") or ""))
                st.rerun()

    enriched_runs = [_enrich_run(project_root, run) for run in runs]

    rows = [
        {
            "Scenario": run.get("scenario_id"),
            "Status": "Stale / interrupted" if _is_run_stale(run) else _display_status(run),
            "Verdict": run.get("verdict") or "",
            "Target": _first_value(run.get("target")),
            "Tenant evidence": _first_value(run.get("tenant_evidence_status")),
            "Updated UTC": run.get("last_updated_utc"),
        }
        for run in enriched_runs[:20]
    ]
    with st.container():
        st.markdown('<div class="ztvp-run-table-marker"></div>', unsafe_allow_html=True)
        st.markdown('<div class="ztvp-recent-runs-heading">Recent runs</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    active = [run for run in enriched_runs if str(run.get("status") or "").lower() in ACTIVE_STATUSES and not _is_run_stale(run)]
    completed = [run for run in enriched_runs if str(run.get("status") or "").lower() == "completed" and str(run.get("verdict") or "") in {"PASS", "PARTIAL", "FAIL"}][: int(completed_limit)]
    failed = [run for run in enriched_runs if str(run.get("status") or "").lower() in FAILED_STATUSES or _is_run_stale(run)]

    tab_active, tab_completed, tab_failed = st.tabs(["Active / Running Now", "Completed", "Failed / Cancelled / Stale"])
    with tab_active:
        if not active:
            _empty_state("No running or polling scenarios.")
        for index, run in enumerate(active):
            _render_run(project_root, run, f"active_{index}")
    with tab_completed:
        if not completed:
            _empty_state("No completed scenarios yet.")
        for index, run in enumerate(completed):
            _render_run(project_root, run, f"completed_{index}")
    with tab_failed:
        if not failed:
            _empty_state("No failed, cancelled, or stale scenarios.")
        for index, run in enumerate(failed):
            _render_run(project_root, run, f"failed_{index}")
