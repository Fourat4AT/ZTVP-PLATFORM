from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from dynamic_devdv006 import (
    DEFAULT_PUBLIC_CLIENT_ID,
    _alert,
    _css,
    _load_json,
    _metric,
    _open_active_runs,
    _render_active_run_summary,
    _render_defender_xdr_connect_command,
    _run_powershell,
    _safe,
    _tenant_context,
    _validate_defender_xdr_token_cache,
    connect_defender_xdr_api,
)
from background_jobs import get_active_run, start_scenario_job
from html_report import write_standard_html_report
from run_state import latest_run_for_scenario, selected_run_for_scenario


STATUS_LABELS = {
    "PASS_TAMPER_PROTECTION_VALIDATED": "PASS",
    "PARTIAL_TAMPER_PROTECTION_LOCAL_ONLY": "PARTIAL",
    "PARTIAL_TAMPER_TENANT_ONLY": "PARTIAL",
    "FAIL_TAMPER_PROTECTION_NOT_EFFECTIVE": "FAIL",
    "NOT_RUN_CONTROLLED_ACTION_NOT_EXECUTED": "NOT RUN",
}


def _tone(status: object) -> str:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "good"
    if text.startswith("FAIL"):
        return "bad"
    return "warn"


def _display_verdict(status: object) -> str:
    return STATUS_LABELS.get(str(status or ""), str(status or "Unknown"))


def _has_value(value: object) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "null", "not returned", "not found", "n/a", "unknown", "0"}


def _proof_line(label: str, value: object) -> str:
    return f"- **{_safe(label)}:** {_safe(value)}"


def _first_value(rows: list, *names: str) -> str:
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in names:
            value = row.get(name)
            if _has_value(value):
                return str(value)
    return ""


def _compact_join(*values: object) -> str:
    parts: list[str] = []
    for value in values:
        if not _has_value(value):
            continue
        text = str(value).strip()
        if text not in parts:
            parts.append(text)
    return " / ".join(parts)


def _tenant_evidence_card(source: str, fields: list[tuple[str, object]]) -> str:
    rows = []
    for label, value in fields:
        if _has_value(value):
            rows.append(
                f"""
<div class="ztvp-tenant-row">
  <span>{_safe(label)}</span>
  <strong>{_safe(value)}</strong>
</div>
"""
            )
    if not rows:
        return ""
    return f"""
<div style="background:#ffffff;border:1px solid #dbe5f3;border-radius:18px;box-shadow:0 12px 30px rgba(15,23,42,.07);padding:18px 20px;margin:.75rem 0 1rem 0;">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
    <div style="font-weight:900;color:#0f172a;font-size:1rem;">Tenant evidence found</div>
    <div style="background:#eef4ff;border:1px solid #bfdbfe;color:#1d4ed8;border-radius:999px;padding:6px 10px;font-size:.78rem;font-weight:850;">Evidence source: {_safe(source)}</div>
  </div>
  <div style="display:grid;grid-template-columns:1fr;gap:9px;">
    {''.join(rows)}
  </div>
</div>
<style>
.ztvp-tenant-row {{ display:grid; grid-template-columns:190px 1fr; gap:12px; align-items:start; }}
.ztvp-tenant-row span {{ color:#64748b; font-size:.84rem; font-weight:850; }}
.ztvp-tenant-row strong {{ color:#0f172a; font-size:.96rem; font-weight:850; word-break:break-word; }}
@media (max-width:700px) {{ .ztvp-tenant-row {{ grid-template-columns:1fr; gap:2px; }} }}
</style>
"""


def _parse_utc(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _device_matches(expected: str, actual: str) -> bool:
    expected = str(expected or "").strip().lower()
    actual = str(actual or "").strip().lower()
    if not expected or not actual:
        return True
    expected_short = expected.split(".")[0]
    actual_short = actual.split(".")[0]
    return expected == actual or expected_short == actual_short


def _evidence_debug_message(reason: str, current_run_id: str, evidence_run_id: str, window_start: datetime | None, evidence_time: datetime | None) -> str:
    diff = "Unknown"
    if window_start and evidence_time:
        diff = str(int((evidence_time - window_start).total_seconds()))
    return (
        f"{reason}\n\n"
        f"Current run_id: {current_run_id or 'Missing'}\n"
        f"Evidence run_id: {evidence_run_id or 'Missing'}\n"
        f"Validation window UTC: {window_start.strftime('%Y-%m-%dT%H:%M:%SZ') if window_start else 'Invalid or missing'}\n"
        f"Evidence timestamp UTC: {evidence_time.strftime('%Y-%m-%dT%H:%M:%SZ') if evidence_time else 'Invalid or missing'}\n"
        f"Time difference seconds: {diff}\n"
        "Times are shown in UTC. Local time may differ."
    )


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "devdv008") -> None:
    write_standard_html_report(report, html_path)

    status = report.get("status")
    tone = _tone(status)
    evidence = report.get("evidence") or {}
    local = evidence.get("local") or {}
    tenant = (evidence.get("tenant") or {}).get("api") or {}
    alert = tenant.get("tenant_defender_alert") or {}
    timeline = tenant.get("tenant_timeline_evidence") or {}

    tamper_enabled = bool(local.get("tamper_protection_enabled"))
    settings_protected = bool(local.get("defender_settings_remained_protected"))
    blocked_or_ignored = bool(local.get("tamper_attempt_blocked_or_ignored"))
    settings_weakened = bool(local.get("settings_weakened"))
    tenant_found = bool(tenant.get("mde_cloud_evidence_found"))
    timeline_events_found = bool(timeline.get("timeline_events_found"))
    tamper_timeline_found = bool(timeline.get("tamper_specific_evidence_found"))
    alert_found = bool(alert.get("alert_evidence_found") or alert.get("alert_found"))
    device = report.get("test_device") or tenant.get("test_device_name_requested") or "Unknown"
    parsed_tamper_rows = tenant.get("mde_cloud_parsed_tamper_timeline_evidence") or []
    tamper_event_rows = tenant.get("mde_cloud_tamper_timeline_events") or []
    first_parsed_tamper = parsed_tamper_rows[0] if parsed_tamper_rows else {}
    first_tamper_event = tamper_event_rows[0] if tamper_event_rows else {}
    tenant_result = (
        timeline.get("blocked_result")
        or first_parsed_tamper.get("Status")
        or ("Blocked" if timeline.get("blocked_modification_found") else "")
    )
    tamper_action_type = timeline.get("tamper_action_type") or first_parsed_tamper.get("ActionType") or ""
    tampering_action = timeline.get("tampering_action") or first_parsed_tamper.get("TamperingAction") or ""
    blocked_setting = timeline.get("blocked_setting") or first_parsed_tamper.get("BlockedSetting") or "Protected Defender setting"
    tamper_event_count = timeline.get("tamper_timeline_event_count", 0)
    wait_window = timeline.get("wait_window_minutes", tenant.get("mde_cloud_wait_minutes", ""))
    poll_interval = timeline.get("poll_interval_seconds", tenant.get("mde_cloud_poll_seconds", ""))
    effective_search_start = timeline.get("effective_search_start_utc") or tenant.get("effective_search_start_utc") or ""
    poll_attempts = timeline.get("poll_attempts", tenant.get("mde_cloud_poll_attempts", 0))
    evidence_found_at = timeline.get("evidence_found_at_utc") or tenant.get("tenant_evidence_found_at_utc") or "Not found"
    wait_seconds = timeline.get("time_spent_waiting_seconds", tenant.get("tenant_time_spent_waiting_seconds", 0))
    try:
        wait_approx = f"{int(wait_seconds) // 60}m {int(wait_seconds) % 60}s"
    except Exception:
        wait_approx = str(wait_seconds or "0s")
    wait_window_label = f"{wait_window} minutes" if wait_window != "" else "Not configured"
    poll_interval_label = f"{poll_interval} seconds" if poll_interval != "" else "Not configured"
    alert_title = alert.get("alert_title") or ""
    alert_category = alert.get("alert_category") or ""
    alert_detection_source = alert.get("detection_source") or ""
    alert_product = alert.get("product_name") or alert.get("service_source") or ""
    alert_impacted_asset = alert.get("impacted_asset") or ""
    alert_user = alert.get("user") or ""
    alert_timestamp = alert.get("alert_timestamp") or ""
    alert_severity = alert.get("alert_severity") or ""
    timeline_block_found = bool(tamper_timeline_found and (timeline.get("blocked_modification_found") or str(tenant_result).lower() == "blocked"))
    command_row = next(
        (
            row
            for row in tamper_event_rows
            if isinstance(row, dict)
            and str(row.get("ActionType", "")) == "PowerShellCommand"
            and any(token in str(row.get("InitiatingProcessCommandLine", "")) for token in ["Set-MpPreference", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableBlockAtFirstSeen"])
        ),
        {},
    )
    command_found = bool(timeline.get("script_command_evidence_found") or command_row)
    tenant_evidence_found = bool(alert_found or timeline_block_found or command_found or tamper_timeline_found)
    tenant_result_summary = "Alert found" if alert_found else "Blocked timeline event" if timeline_block_found else "Command telemetry" if command_found else "Found" if tamper_timeline_found else "Not found within wait window"

    if str(status or "").startswith("PASS"):
        title = "Validation successful"
        message = "Tamper Protection protected the endpoint locally, and Microsoft Defender XDR recorded the tampering activity as tenant evidence."
        scenario_result = "Successful"
        local_label = "Blocked or ignored"
        tenant_label = "Found"
    elif str(status or "").startswith("FAIL"):
        title = "Validation failed"
        message = "Defender settings were weakened or Tamper Protection was not enabled."
        scenario_result = "Failed"
        local_label = "Changed or weakened"
        tenant_label = "Found" if tenant_found else "Not found"
    elif str(status or "").startswith("NOT_RUN"):
        title = "Validation not completed"
        if not report.get("vm_script_generated") and not report.get("local_evidence_imported"):
            message = "The controlled tamper attempt script has not been generated or executed for this run."
        else:
            message = "The validation window was armed, but no fresh endpoint evidence was imported and no tenant-side evidence was found for this run."
        scenario_result = "Waiting for test action"
        local_label = "Missing"
        tenant_label = "Not found for this run"
    else:
        title = "Validation partially successful"
        message = "Tamper Protection protected the endpoint locally, but ZTVP did not find tamper-specific tenant evidence within the selected wait window."
        scenario_result = "Partially successful"
        local_label = "Worked" if settings_protected else "Incomplete"
        tenant_label = "Found" if tenant_evidence_found else "Generic events only" if timeline_events_found else tenant.get("mde_cloud_query_status", "Not found")

    st.markdown(f"### {title}")
    _alert(message, tone)
    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _display_verdict(status), tone)}
  {_metric("Scenario result", scenario_result, tone)}
  {_metric("Tamper Protection", "Enabled" if tamper_enabled else "Disabled or not returned", "good" if tamper_enabled else "bad")}
  {_metric("Local tamper attempt", local_label, "good" if blocked_or_ignored else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("Settings weakened", "Yes" if settings_weakened else "No", "bad" if settings_weakened else "good")}
  {_metric("Tenant tamper evidence", tenant_label, "good" if tenant_evidence_found else "warn")}
  {_metric("Tenant result", tenant_result_summary, "good" if tenant_evidence_found else "warn")}
  {_metric("Device", device)}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Local endpoint proof")
    st.markdown(
        "\n".join(
            [
                "- The script attempted to disable Defender protections.",
                f"- Defender settings remained protected after the attempt: {_safe('Yes' if settings_protected else 'No')}.",
                f"- Tamper Protection was enabled: {_safe('Yes' if tamper_enabled else 'No or not returned')}.",
                f"- Settings weakened: {_safe('Yes' if settings_weakened else 'No')}.",
            ]
        )
    )

    st.markdown("#### Tenant result from Microsoft Defender XDR")
    evidence_sources = []
    if alert_found:
        evidence_sources.append("alert")
    if timeline_block_found:
        evidence_sources.append("timeline")
    if command_found:
        evidence_sources.append("command")

    if evidence_sources:
        if len(evidence_sources) > 1:
            _alert("Microsoft Defender XDR recorded the tampering activity through multiple evidence sources.", "good")
        else:
            _alert("Microsoft Defender XDR recorded the tampering activity in the tenant.", "good")

        if alert_found:
            additional_info = _compact_join(alert_category, alert_severity)
            st.markdown(
                _tenant_evidence_card(
                    "AlertInfo / AlertEvidence",
                    [
                        ("Event time", alert_timestamp),
                        ("Event", alert_title),
                        ("Additional information", additional_info),
                        ("Detection source", alert_detection_source),
                        ("Service source", alert_product),
                        ("Impacted asset", alert_impacted_asset),
                    ],
                ),
                unsafe_allow_html=True,
            )

        if timeline_block_found:
            timeline_event = "Tamper protection blocked the modification"
            if not (str(tenant_result).lower() == "blocked" or timeline.get("blocked_modification_found")) and _has_value(tamper_action_type):
                timeline_event = f"Event of type [{tamper_action_type}] observed on device"
            timeline_additional = _compact_join(
                first_parsed_tamper.get("Technique") or first_tamper_event.get("Technique"),
                tenant_result,
                tampering_action,
            )
            st.markdown(
                _tenant_evidence_card(
                    "DeviceEvents",
                    [
                        ("Event time", first_parsed_tamper.get("Timestamp") or first_tamper_event.get("Timestamp")),
                        ("Event", timeline_event),
                        ("Additional information", timeline_additional),
                        ("Target/blocked setting", blocked_setting),
                        ("Service source", first_parsed_tamper.get("ServiceSource") or first_tamper_event.get("ServiceSource")),
                        ("Device", first_parsed_tamper.get("DeviceName") or first_tamper_event.get("DeviceName") or device),
                    ],
                ),
                unsafe_allow_html=True,
            )

        if command_found:
            command_line = str(command_row.get("InitiatingProcessCommandLine", ""))
            command_summary = "Set-MpPreference attempt" if "Set-MpPreference" in command_line else "Controlled tamper command telemetry"
            st.markdown(
                _tenant_evidence_card(
                    "DeviceEvents",
                    [
                        ("Event time", command_row.get("Timestamp")),
                        ("Event", "PowerShell tamper command observed"),
                        ("Additional information", command_summary),
                        ("Service source", command_row.get("ServiceSource")),
                        ("Device", command_row.get("DeviceName") or device),
                    ],
                ),
                unsafe_allow_html=True,
            )
    else:
        _alert("ZTVP did not find tamper-specific Defender XDR evidence within the selected wait window.", "warn")
        st.markdown(
            "\n".join(
                [
                    _proof_line("Wait window", wait_window_label),
                    _proof_line("Poll interval", poll_interval_label),
                    _proof_line("Search start UTC", effective_search_start),
                    _proof_line("Poll attempts", poll_attempts),
                    _proof_line("Time spent waiting", wait_approx),
                ]
            )
        )

    if str(status or "").startswith("PASS") and alert_found:
        clean_conclusion = "PASS - Defender settings stayed protected, and the tenant captured the tampering activity as a Defender XDR alert."
    elif str(status or "").startswith("PASS") and timeline_block_found:
        clean_conclusion = "PASS - Defender settings stayed protected, and the tenant recorded the blocked tamper attempt in the device timeline."
    elif str(status or "").startswith("PASS") and command_found:
        clean_conclusion = "PASS - Defender settings stayed protected, and the tenant recorded command telemetry for the tamper attempt."
    elif str(status or "").startswith("FAIL"):
        clean_conclusion = "FAIL - Defender settings were weakened or Tamper Protection was not enabled."
    elif str(status or "").startswith("PARTIAL") and not tenant_evidence_found:
        clean_conclusion = "PARTIAL - local protection worked, but tenant-side tamper evidence was not found within the wait window."
    else:
        clean_conclusion = report.get("clean_conclusion", "")

    st.markdown("#### Clean conclusion")
    _alert(clean_conclusion, tone)

    if str(status or "").startswith("PASS"):
        recs = [
            "Keep Tamper Protection enabled.",
            "Keep MDE onboarding healthy.",
            "Keep monitoring Defender XDR device timeline and endpoint telemetry.",
            "Use this result as evidence that both endpoint enforcement and tenant visibility worked.",
        ]
    elif str(status or "").startswith("FAIL"):
        recs = [
            "Enable Tamper Protection in Microsoft Defender portal: Settings -> Endpoints -> General -> Advanced features -> Tamper protection.",
            "If Intune manages the device, enable it through Intune Endpoint Security policy.",
            "Confirm Defender AV and real-time protection are enabled.",
            "Confirm Real-time protection, behavior monitoring, and IOAV protection are enabled.",
            "Confirm MDE onboarding and Sense service.",
            "Review conflicting policies or exclusions.",
            "Rerun the validation.",
        ]
    elif str(status or "").startswith("PARTIAL_TAMPER_TENANT_ONLY"):
        recs = [
            "Rerun the VM script and import local JSON evidence.",
            "Confirm local evidence timestamp is after validation_window_start_utc.",
        ]
    elif str(status or "").startswith("NOT_RUN"):
        recs = [
            "Generate the controlled tamper attempt script.",
            "Run it inside the controlled VM as Administrator.",
            "Import the JSON evidence.",
            "Rerun analysis.",
        ]
    else:
        recs = [
            "Check Defender portal -> Assets -> Devices -> Timeline -> search Tamper.",
            "Confirm Defender XDR API connection.",
            "Confirm Sense service is running.",
            "Rerun tenant evidence analysis after a few minutes.",
            "Rerun tenant analysis with a longer wait window if needed.",
        ]
    if recs:
        st.markdown("#### Recommended remediation" if str(status or "").startswith("FAIL") else "#### Recommended follow-up")
        for rec in recs:
            st.markdown(f"- {_safe(rec)}")

    api_error = tenant.get("mde_cloud_error")
    if api_error and tenant.get("mde_cloud_query_status") in ["Unauthorized", "Unavailable", "Defender XDR API connection required"]:
        _alert(f"Defender XDR API message: {api_error}", "warn")

    with st.expander("Local endpoint evidence details", expanded=False):
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Evidence imported", local.get("imported_local_evidence_present", False), "good" if local.get("imported_local_evidence_present") else "warn")}
  {_metric("Accepted for current run", local.get("local_evidence_accepted_for_current_run", False), "good" if local.get("local_evidence_accepted_for_current_run") else "warn")}
  {_metric("Tamper protection", "Enabled" if tamper_enabled else "Disabled or unknown")}
  {_metric("Settings protected", settings_protected, "good" if settings_protected else "bad")}
</div>
<div class="ztvp-grid">
  {_metric("Blocked or ignored", blocked_or_ignored, "good" if blocked_or_ignored else "warn")}
  {_metric("Settings weakened", settings_weakened, "bad" if settings_weakened else "good")}
  {_metric("Evidence timestamp", local.get("local_evidence_timestamp_utc", ""))}
  {_metric("VM device", local.get("test_device_name_from_vm", ""))}
</div>
""",
            unsafe_allow_html=True,
        )
        if local.get("local_evidence_invalid_reason"):
            _alert(local.get("local_evidence_invalid_reason"), "warn")
        attempts = local.get("tamper_attempts") or []
        if attempts:
            st.markdown("##### Controlled tamper attempts")
            st.dataframe(pd.DataFrame(attempts).astype(str), use_container_width=True, hide_index=True)
        with st.expander("Before / after Defender state", expanded=False):
            st.json(
                {
                    "before_status": local.get("before_status"),
                    "before_preference": local.get("before_preference"),
                    "after_status": local.get("after_status"),
                    "after_preference": local.get("after_preference"),
                    "restore_attempts": local.get("restore_attempts"),
                }
            )

    with st.expander("Tenant evidence details", expanded=False):
        if tamper_timeline_found:
            _alert("Microsoft Defender XDR captured tamper-specific tenant timeline evidence for this validation.", "good")
        elif timeline_events_found:
            _alert("Only generic device timeline rows were found. They do not count as tenant tamper evidence.", "warn")
        clean_columns = [
            "Timestamp",
            "DeviceName",
            "ActionType",
            "Status",
            "TamperingAction",
            "BlockedSetting",
            "InitiatingProcessFileName",
        ]
        if parsed_tamper_rows:
            parsed_df = pd.DataFrame(parsed_tamper_rows).astype(str)
            visible_columns = [column for column in clean_columns if column in parsed_df.columns]
            st.dataframe(parsed_df[visible_columns], use_container_width=True, hide_index=True)
        elif not str(status or "").startswith("PASS"):
            st.caption("No parsed tamper timeline evidence was returned.")

    with st.expander("Raw Advanced Hunting rows", expanded=False):
        rows = {
            "DeviceEvents timeline rows": tenant.get("mde_cloud_device_events") or [],
            "Tamper-specific DeviceEvents": tenant.get("mde_cloud_tamper_timeline_events") or [],
            "DeviceRegistryEvents": tenant.get("mde_cloud_registry_events") or [],
            "AlertEvidence": tenant.get("mde_cloud_alert_evidence") or [],
            "Joined AlertEvidence + AlertInfo": tenant.get("mde_cloud_joined_alert_evidence") or [],
            "AlertInfo": tenant.get("mde_cloud_alerts") or [],
        }
        for title, data in rows.items():
            st.markdown(f"##### {title}")
            if data:
                st.dataframe(pd.DataFrame(data).astype(str), use_container_width=True, hide_index=True)
            elif not str(status or "").startswith("PASS"):
                st.caption("No rows returned.")

    with st.expander("Full JSON evidence", expanded=False):
        st.json(report)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "DEV-DV-008-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json_download",
        )
    with col2:
        if html_path.exists():
            st.download_button(
                "Download HTML Report",
                html_path.read_bytes(),
                "DEV-DV-008-result.html",
                "text/html",
                use_container_width=True,
                key=f"{key_prefix}_html_download",
            )


def render_devdv008_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV008.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV008.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV008.ps1"
    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-008"
    state_path = scenario_dir / "devdv008-state.json"
    template_path = scenario_dir / "devdv008-local-evidence-template.ps1"
    local_evidence_path = scenario_dir / "devdv008-local-evidence.json"
    defender_token_cache_path = project_root / "powershell" / "Auth" / "ztvp-defenderxdr-token-cache.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-008-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-008-result.html"

    existing_state = _load_json(state_path) if state_path.exists() else {}
    tenant_ctx = _tenant_context(project_root, existing_state)

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-008 - Hybrid Tamper Protection Validation</h2>
  <p>ZTVP attempts controlled Defender preference changes on a test endpoint, imports endpoint evidence, and checks Microsoft Defender XDR for tenant-side tamper evidence.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("### Step 1 - Arm Validation Window")
    col1, col2 = st.columns(2)
    with col1:
        test_folder = st.text_input("Default test folder", value=existing_state.get("test_folder", r"C:\Users\Public\ZTVP-DEV-DV-008"), key="devdv008_test_folder")
        test_device_name = st.text_input("Test device name in Defender portal", value=existing_state.get("test_device_name", ""), key="devdv008_test_device_name")
    with col2:
        cloud_mode = st.selectbox(
            "Tenant cloud evidence mode",
            ["Tenant + Local Evidence", "Local Evidence Only"],
            index=0 if existing_state.get("cloud_evidence_mode", "Tenant + Local Evidence") != "Local Evidence Only" else 1,
            key="devdv008_cloud_mode",
        )
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Tenant", tenant_ctx["tenant_display_name"] or "Discovered")}
  {_metric("Tenant ID", tenant_ctx["tenant_id"] or "Missing", "good" if tenant_ctx["tenant_id"] else "warn")}
  {_metric("Client ID", tenant_ctx["client_id"] or DEFAULT_PUBLIC_CLIENT_ID, "good")}
  {_metric("Support", "SUPPORTED", "good")}
</div>
""",
            unsafe_allow_html=True,
        )

    if st.button("Step 1 - Arm Validation Window", type="primary", use_container_width=True, key="devdv008_prepare_button"):
        with st.spinner("Preparing DEV-DV-008 validation window and VM script template..."):
            completed = _run_powershell(
                project_root,
                prepare_script,
                [
                    "-TestFolder",
                    test_folder.strip(),
                    "-TestDeviceName",
                    test_device_name.strip(),
                    "-TenantId",
                    tenant_ctx["tenant_id"],
                    "-ClientId",
                    tenant_ctx["client_id"],
                    "-CloudEvidenceMode",
                    cloud_mode,
                ],
                timeout=300,
            )
        if completed.returncode != 0:
            _alert("DEV-DV-008 preparation failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            return
        _alert("Validation window armed. Controlled action has not been executed yet.", "warn")
        st.code(completed.stdout or "No PowerShell output captured.", language="text")
        st.rerun()

    if state_path.exists():
        state = _load_json(state_path)
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Validation Window", state.get("validation_window_start_utc", "N/A"), "good")}
  {_metric("VM script generated", state.get("vm_script_generated", False), "good" if state.get("vm_script_generated") else "warn")}
  {_metric("Local evidence imported", state.get("local_evidence_imported", False), "good" if state.get("local_evidence_imported") else "warn")}
</div>
""",
            unsafe_allow_html=True,
        )
        if not state.get("local_evidence_imported"):
            _alert("Validation window armed. Controlled action has not been executed yet.", "warn")
        if not state.get("vm_script_generated"):
            _alert("Click Step 2 to generate the controlled tamper attempt script.", "warn")

    st.markdown("### Step 2 - Generate Controlled Tamper Attempt")
    current_state_for_script = _load_json(state_path) if state_path.exists() else {}
    script_generated_for_current_run = bool(current_state_for_script.get("vm_script_generated"))
    if st.button("Generate VM Tamper Attempt Script", use_container_width=True, key="devdv008_generate_script"):
        if not state_path.exists():
            _alert("Start a fresh validation window first.", "warn")
        else:
            with st.spinner("Generating current-run VM tamper attempt script..."):
                completed = _run_powershell(
                    project_root,
                    prepare_script,
                    [
                        "-GenerateVmScript",
                        "-TestFolder",
                        current_state_for_script.get("test_folder", test_folder.strip()),
                        "-TestDeviceName",
                        current_state_for_script.get("test_device_name", test_device_name.strip()),
                        "-TenantId",
                        current_state_for_script.get("tenant_id", tenant_ctx["tenant_id"]),
                        "-ClientId",
                        current_state_for_script.get("client_id", tenant_ctx["client_id"]),
                        "-CloudEvidenceMode",
                        current_state_for_script.get("cloud_evidence_mode", cloud_mode),
                    ],
                    timeout=300,
                )
            if completed.returncode != 0:
                _alert("DEV-DV-008 VM script generation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("VM tamper attempt script generated for the current run.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()

    if script_generated_for_current_run and template_path.exists():
        script_text = template_path.read_text(encoding="utf-8-sig")
        st.text_area("Copy this script and run it inside the VM/test endpoint as Administrator", script_text, height=360, key="devdv008_vm_script")
        st.download_button("Download VM-side PowerShell Script", script_text, "devdv008-local-evidence-template.ps1", "text/plain", use_container_width=True, key="devdv008_template_download")
    elif state_path.exists():
        _alert("No script generated for the current run yet.", "warn")
        st.caption("Click Step 2 to generate the controlled tamper attempt script.")
    else:
        _alert("Start a fresh validation window first.", "warn")

    st.markdown("### Step 3 - Import Endpoint Evidence")
    pasted = st.text_area("Paste devdv008-local-evidence.json content printed by the VM script", height=260, key="devdv008_pasted_evidence")
    if st.button("Step 3 - Validate and Save VM Evidence", use_container_width=True, key="devdv008_save_evidence"):
        try:
            parsed = json.loads(pasted)
        except Exception as exc:
            _alert(f"Invalid JSON evidence: {exc}", "bad")
        else:
            if parsed.get("scenario_id") != "DEV-DV-008":
                _alert("Imported evidence is not for DEV-DV-008 and was not saved.", "bad")
                return
            state = _load_json(state_path) if state_path.exists() else {}
            current_run_id = str(state.get("run_id") or "")
            evidence_run_id = str(parsed.get("run_id") or "")
            window_start = _parse_utc(state.get("validation_window_start_utc"))
            evidence_time = _parse_utc(parsed.get("timestamp_utc"))
            if not evidence_time:
                _alert(_evidence_debug_message("Evidence rejected because timestamp_utc is missing or invalid.", current_run_id, evidence_run_id, window_start, evidence_time), "bad")
                return
            if evidence_run_id and current_run_id and evidence_run_id != current_run_id:
                _alert(_evidence_debug_message("Evidence rejected because run_id does not match current run.", current_run_id, evidence_run_id, window_start, evidence_time), "bad")
                return
            has_matching_run_id = bool(evidence_run_id and current_run_id and evidence_run_id == current_run_id)
            if window_start and not has_matching_run_id and evidence_time < (window_start - timedelta(minutes=5)):
                minutes_old = int(abs((evidence_time - window_start).total_seconds()) // 60)
                _alert(_evidence_debug_message(f"Evidence rejected because timestamp is {minutes_old} minutes older than current validation window tolerance.", current_run_id, evidence_run_id, window_start, evidence_time), "bad")
                return
            if not _device_matches(state.get("test_device_name"), parsed.get("computer_name")):
                _alert("Imported evidence device name does not match the current DEV-DV-008 test device name.", "bad")
                return
            scenario_dir.mkdir(parents=True, exist_ok=True)
            local_evidence_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
            state["local_evidence_imported"] = True
            state["local_evidence_path"] = str(local_evidence_path)
            state["local_evidence_timestamp_utc"] = parsed.get("timestamp_utc")
            state["local_evidence_imported_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            state["current_run_status"] = "LOCAL_EVIDENCE_IMPORTED"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            _alert("Local VM evidence saved for the current run.", "good")
            st.markdown(
                f"""
Evidence accepted for current run: `True`  
Evidence run_id: `{_safe(evidence_run_id or 'Not provided')}`  
Current run_id: `{_safe(current_run_id)}`  
Evidence timestamp UTC: `{_safe(parsed.get('timestamp_utc', ''))}`  
Validation window UTC: `{_safe(state.get('validation_window_start_utc', ''))}`  
Times are shown in UTC. Local time may differ.
"""
            )

    current_state_for_evidence = _load_json(state_path) if state_path.exists() else {}
    if local_evidence_path.exists() and current_state_for_evidence.get("local_evidence_imported"):
        evidence = _load_json(local_evidence_path)
        summary = evidence.get("local_summary") or {}
        st.markdown(
            f"""
<div class="ztvp-grid">
  {_metric("Imported Device", evidence.get("computer_name", "Unknown"))}
  {_metric("Evidence Timestamp", evidence.get("timestamp_utc", "Unknown"))}
  {_metric("Tamper Protection Before", summary.get("tamper_protection_enabled_before", "Unknown"))}
  {_metric("Settings Weakened", summary.get("settings_weakened", "Unknown"), "bad" if summary.get("settings_weakened") else "good")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("### Step 4 - Analyze Local + Tenant Defender Evidence")
    _alert("Defender XDR timeline events can take a few minutes to appear. ZTVP will re-query until evidence is found or the wait window expires.", "info")
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        wait_minutes = st.selectbox("Wait for tenant evidence", [1, 3, 5, 10, 15], index=2, format_func=lambda value: f"{value} minutes", key="devdv008_wait_minutes")
    with col_w2:
        poll_seconds = st.selectbox("Poll every", [15, 30, 60], index=1, format_func=lambda value: f"{value} seconds", key="devdv008_poll_seconds")

    troubleshooting_state = _load_json(state_path) if state_path.exists() else {}
    troubleshooting_evidence = _load_json(local_evidence_path) if local_evidence_path.exists() else {}
    troubleshooting_window = _parse_utc(troubleshooting_state.get("validation_window_start_utc"))
    troubleshooting_evidence_time = _parse_utc(troubleshooting_evidence.get("timestamp_utc"))
    troubleshooting_start = troubleshooting_window
    if troubleshooting_evidence_time and (not troubleshooting_start or troubleshooting_evidence_time < troubleshooting_start):
        troubleshooting_start = troubleshooting_evidence_time
    if troubleshooting_start:
        troubleshooting_start = troubleshooting_start - timedelta(minutes=5)
    troubleshooting_start_label = troubleshooting_start.strftime("%Y-%m-%dT%H:%M:%SZ") if troubleshooting_start else "<effective_search_start_utc>"
    troubleshooting_device = str(troubleshooting_state.get("test_device_name") or troubleshooting_evidence.get("computer_name") or "<test_device_name>")
    troubleshooting_short = troubleshooting_device.split(".")[0] if troubleshooting_device and troubleshooting_device != "<test_device_name>" else "<short_device_name>"
    with st.expander("Advanced troubleshooting - Defender XDR hunting queries", expanded=False):
        st.caption("These queries use the current run effective search start, not ago(1d).")
        st.code(
            f"""let effective_start = datetime({troubleshooting_start_label});
let test_device = "{troubleshooting_device}";
let short_device = "{troubleshooting_short}";
AlertEvidence
| where Timestamp >= effective_start
| where DeviceName contains short_device or DeviceName contains test_device
| join kind=leftouter (
    AlertInfo
    | where Timestamp >= effective_start
    | project AlertId, AlertTimestamp=Timestamp, Title, Severity, Category, ServiceSource, AlertDetectionSource=DetectionSource
) on AlertId
| where Title has_any ("Microsoft Defender Antivirus tampering", "tampering", "Defender tampering", "Antivirus tampering")
   or Category has_any ("DefenseEvasion", "Defense Evasion")
   or AlertDetectionSource has_any ("EDR", "Antivirus")
   or ServiceSource has "Microsoft Defender for Endpoint"
| project Timestamp, AlertTimestamp, AlertId, Title, Severity, Category, EvidenceDetectionSource=DetectionSource, AlertDetectionSource, ServiceSource, DeviceName, EntityType, EvidenceRole, AccountName, AccountDomain

DeviceEvents
| where Timestamp >= effective_start
| where DeviceName contains short_device or DeviceName contains test_device
| where ActionType has_any ("TamperingAttempt", "TamperProtectionConfigChangeAttempt", "PowerShellCommand")
   or AdditionalFields has_any ("Tamper", "TamperProtection", "Blocked", "RegistryModification", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableBlockAtFirstSeen")
   or InitiatingProcessCommandLine has_any ("Set-MpPreference", "reg add", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableBlockAtFirstSeen")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc""",
            language="kusto",
        )

    if cloud_mode != "Local Evidence Only":
        token_state = _validate_defender_xdr_token_cache(defender_token_cache_path)
        if token_state["ok"]:
            _alert("Defender XDR API connection ready.", "good")
        elif token_state["status"] == "missing":
            _alert("Defender XDR API connection required.", "warn")
        else:
            _alert(token_state["message"], "warn")

        if st.button("Connect Defender XDR API", use_container_width=True, key="devdv008_connect_defender"):
            with st.spinner("Opening Microsoft sign-in and testing Defender XDR Advanced Hunting..."):
                connection = connect_defender_xdr_api(tenant_ctx["tenant_id"], tenant_ctx["client_id"], defender_token_cache_path)
            if connection["ok"]:
                _alert("Defender XDR API connection ready.", "good")
                st.rerun()
            else:
                _alert("Defender XDR API connection failed.", "bad")
                st.markdown(f"Error: `{_safe(connection.get('error', 'unknown'))}`")
                st.write(connection.get("error_description", "Microsoft sign-in or Advanced Hunting validation failed."))
        _render_defender_xdr_connect_command(tenant_ctx["tenant_id"], tenant_ctx["client_id"])

    requested_run_id = str(st.session_state.get("ztvp_dynamic_open_run_id") or "")
    current_run = (
        get_active_run(project_root, "DEV-DV-008", requested_run_id)
        or selected_run_for_scenario(project_root, "DEV-DV-008", requested_run_id)
        or latest_run_for_scenario(project_root, "DEV-DV-008")
    )
    if current_run:
        _render_active_run_summary(current_run, "DEV-DV-008")
        if st.button("Open Active Runs", use_container_width=True, key="devdv008_open_active_runs"):
            _open_active_runs()

    if st.button("Start Tenant Evidence Analysis", use_container_width=True, key="devdv008_analyze"):
        state = _load_json(state_path) if state_path.exists() else {}
        if not state.get("vm_script_generated") and not state.get("local_evidence_imported"):
            _alert("Validation not completed. The controlled tamper attempt script has not been generated or executed for this run.", "warn")
        elif not state.get("local_evidence_imported"):
            _alert("Cannot produce PASS/FAIL yet. No fresh endpoint test evidence exists for this run.", "warn")
        else:
            st.markdown(f"Tenant wait window: `{wait_minutes}` minutes  \nPoll interval: `{poll_seconds}` seconds")
            run = start_scenario_job(project_root, "DEV-DV-008", int(wait_minutes), int(poll_seconds))
            if str(run.get("status") or "").lower() in {"queued", "running", "polling"} and int(run.get("poll_attempts") or 0) > 0:
                _alert("An existing scenario run is already active. ZTVP will keep polling in the background and update Active Runs.", "info")
            else:
                _alert("Analysis started. You can leave this page and monitor it in Active Runs.", "good")
            st.caption(f"Run ID: {run.get('run_id')}")
            if st.button("Open Active Runs", use_container_width=True, key="devdv008_open_active_runs_after_start"):
                _open_active_runs()

    if report_path.exists():
        latest_report = _load_json(report_path)
        current_run_id = str(existing_state.get("run_id") or "")
        report_run_id = str(latest_report.get("run_id") or "")
        if current_run_id and report_run_id != current_run_id:
            st.markdown("### Previous DEV-DV-008 report")
            previous_label = report_run_id or "an older run without a run_id"
            _alert(f"Previous report is from {previous_label}. Current armed run is {current_run_id}, so the old result is not used for this validation window.", "warn")
            with st.expander("Show previous report", expanded=False):
                _render_report(latest_report, report_path, html_path, key_prefix="devdv008_previous")
        else:
            st.markdown("### Latest DEV-DV-008 report")
            _render_report(latest_report, report_path, html_path, key_prefix="devdv008_latest")

    st.markdown("### Step 5 - Cleanup")
    if st.button("Step 5 - Cleanup and Reset DEV-DV-008", use_container_width=True, key="devdv008_cleanup"):
        with st.spinner("Cleaning DEV-DV-008 temporary files..."):
            completed = _run_powershell(project_root, cleanup_script, [], timeout=300)
        if completed.returncode != 0:
            _alert("DEV-DV-008 cleanup failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
        else:
            _alert("DEV-DV-008 cleanup completed. The scenario is reset and ready to start again from Step 1.", "good")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            st.rerun()
