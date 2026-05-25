from __future__ import annotations

import html
import json
import os
import subprocess
import time
from pathlib import Path

import pandas as pd
import streamlit as st


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "PASS_UNMANAGED_DEVICE_BLOCKED_BY_DEVICE_TRUST": "PASS — Unmanaged Device Blocked by Device Trust",
    "FAIL_UNMANAGED_DEVICE_ACCESS_ALLOWED_POLICY_NOT_ENFORCED": "FAIL — Device-Trust Policy Not Enforced",
    "PARTIAL_SIGNIN_FOUND_UNCLASSIFIED": "PARTIAL — Sign-in Found, Unclassified",
    "PARTIAL_BLOCKED_BY_NON_DEVICE_OR_UNCLASSIFIED_POLICY": "PARTIAL — Blocked by Non-Device or Unclassified Policy",
    "PARTIAL_ACCESS_ALLOWED_DEVICE_STATE_NOT_UNMANAGED": "PARTIAL — Access Allowed but Device State Not Unmanaged",
    "PARTIAL_SIGNIN_FAILED_UNCLASSIFIED": "PARTIAL — Sign-in Failed, Unclassified",
    "PARTIAL_NO_SIGNIN_LOG_FOUND": "PARTIAL — No Sign-in Log Found",
}


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




def _fmt_graph_time(value: object) -> str:
    text = "" if value is None else str(value)

    if text.startswith("/Date(") and text.endswith(")/"):
        try:
            import datetime
            ms = int(text[6:-2])
            return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return text

    return text


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
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(
        "<html><body><h1>DEV-DV-001 Report</h1><pre>"
        + _safe(json.dumps(report, indent=2))
        + "</pre></body></html>",
        encoding="utf-8",
    )


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "devdv001") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    sign_in = report.get("sign_in_log_evidence", {}) or {}
    selected = sign_in.get("selected_event", {}) or {}
    device = sign_in.get("device_detail", {}) or selected.get("device_detail", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    target = report.get("target", {}) or {}

    successful_count = int(metrics.get("successful_sign_in_count") or sign_in.get("successful_sign_in_count") or 0)
    failed_count = int(metrics.get("failed_sign_in_count") or sign_in.get("failed_sign_in_count") or 0)
    matching_count = int(metrics.get("matching_sign_in_count") or sign_in.get("matching_sign_in_count") or 0)
    device_trust_failures = int(metrics.get("device_trust_failure_count") or sign_in.get("device_trust_failure_count") or 0)

    is_fail = str(status or "").startswith("FAIL")
    is_pass = str(status or "").startswith("PASS")

    _alert("DEV-DV-001 report loaded.", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Access Attempt Found", metrics.get("sign_in_log_found", False), "good" if metrics.get("sign_in_log_found") else "warn")}
  {_metric("Successful Access", successful_count, "bad" if successful_count else "good")}
</div>
<div class="ztvp-grid">
  {_metric("Matching Sign-ins", matching_count)}
  {_metric("Failed / Interrupted", failed_count, "warn" if failed_count else "")}
  {_metric("Device-Trust Blocks", device_trust_failures, "good" if device_trust_failures else "bad")}
  {_metric("Enforced Device Policy", metrics.get("device_trust_policy_name") or "None", "good" if metrics.get("device_trust_policy_name") else "bad")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")

    if is_fail:
        _alert(
            "FAIL: The decoy user successfully accessed Microsoft 365/My Apps. No enforced compliant-device or managed-device policy blocked this unmanaged/unknown device access path.",
            "bad",
        )
    elif is_pass:
        _alert(
            "PASS: The unmanaged-device access attempt was blocked by an enforced device-trust Conditional Access policy.",
            "good",
        )
    else:
        _alert(
            "PARTIAL: ZTVP found sign-in evidence, but the result could not be fully classified as a device-trust pass or fail.",
            "warn",
        )

    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    rows = [
        {
            "Evidence": "Main result",
            "Value": _friendly_status(status),
            "Meaning": "This is the validation verdict.",
        },
        {
            "Evidence": "Successful sign-ins",
            "Value": str(successful_count),
            "Meaning": "If this is greater than 0, the unmanaged access path was allowed.",
        },
        {
            "Evidence": "Device-trust blocks",
            "Value": str(device_trust_failures),
            "Meaning": "PASS requires at least one enforced compliant-device / managed-device block and no successful access.",
        },
        {
            "Evidence": "Enforced device policy",
            "Value": str(metrics.get("device_trust_policy_name") or "None"),
            "Meaning": "None means no enforced device-trust policy protected this sign-in.",
        },
        {
            "Evidence": "MFA result",
            "Value": "MFA satisfied" if "MFA" in str(sign_in.get("status_additional_details", "")) or "MFA" in str(selected.get("status_additional_details", "")) else "Not the main control",
            "Meaning": "MFA can succeed, but MFA is not device compliance or device management.",
        },
        {
            "Evidence": "Device managed",
            "Value": str(device.get("is_managed") or "Not proven / unknown"),
            "Meaning": "Empty/None means Entra did not prove this was a managed device.",
        },
        {
            "Evidence": "Device compliant",
            "Value": str(device.get("is_compliant") or "Not proven / unknown"),
            "Meaning": "Empty/None means Entra did not prove this was a compliant device.",
        },
        {
            "Evidence": "Target",
            "Value": target.get("name", ""),
            "Meaning": target.get("url", ""),
        },
        {
            "Evidence": "Selected sign-in",
            "Value": _fmt_graph_time(sign_in.get("created_date_time", "")),
            "Meaning": f"{sign_in.get('app_display_name', '')} → {sign_in.get('resource_display_name', '')}",
        },
    ]

    st.markdown("#### Evidence summary")
    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    all_events = sign_in.get("all_matching_sign_ins", []) or []
    if all_events:
        st.markdown("#### Sign-ins used by ZTVP")

        event_rows = []
        for e in all_events:
            success = bool(e.get("is_success"))
            error = str(e.get("status_error_code", ""))
            reason = str(e.get("status_failure_reason", ""))

            if success:
                meaning = "Access allowed"
            elif error == "50140" or "Keep me signed in" in reason:
                meaning = "Login prompt interruption, not a device-trust block"
            elif e.get("device_trust_policies"):
                meaning = "Blocked by device-trust policy"
            elif e.get("blocking_policies"):
                meaning = "Blocked by non-device or unclassified CA policy"
            else:
                meaning = "Failed / interrupted"

            event_rows.append({
                "Time": _fmt_graph_time(e.get("created_date_time")),
                "App": e.get("app_display_name"),
                "Resource": e.get("resource_display_name"),
                "Success": success,
                "CA status": e.get("conditional_access_status"),
                "Error": error,
                "Meaning": meaning,
            })

        st.dataframe(pd.DataFrame(event_rows).astype(str), use_container_width=True, hide_index=True)

    policies = sign_in.get("applied_conditional_access_policies", []) or []
    if policies:
        enforced = []
        report_only = []
        not_applied = []

        for p in policies:
            result = str(p.get("result", ""))
            row = {
                "Policy": p.get("display_name"),
                "Result": result,
                "Grant controls": ", ".join([str(x) for x in (p.get("enforced_grant_controls") or [])]),
                "Session controls": ", ".join([str(x) for x in (p.get("enforced_session_controls") or [])]),
            }

            if result in ("success", "failure"):
                enforced.append(row)
            elif result.startswith("reportOnly"):
                report_only.append(row)
            else:
                not_applied.append(row)

        st.markdown("#### Conditional Access interpretation")

        if enforced:
            st.markdown("**Policies that actually applied**")
            st.dataframe(pd.DataFrame(enforced).astype(str), use_container_width=True, hide_index=True)
            st.caption("In your current result, MFA applied successfully. That does not mean device trust was enforced.")
        else:
            _alert("No enforced Conditional Access policy applied to this selected sign-in.", "bad")

        if report_only:
            st.markdown("**Report-only policies detected**")
            st.dataframe(pd.DataFrame(report_only).astype(str), use_container_width=True, hide_index=True)
            st.caption("Report-only policies do not block access. They are visibility-only.")

        with st.expander("Policies that did not apply"):
            if not_applied:
                st.dataframe(pd.DataFrame(not_applied).astype(str), use_container_width=True, hide_index=True)
            else:
                st.write("No not-applied policies listed.")

    recs = report.get("recommendations", []) or []
    if recs:
        st.markdown("#### What to fix")
        for rec in recs:
            st.markdown(f"- {rec}")

    st.markdown("#### Clean conclusion")
    if is_fail:
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — Device-trust policy not enforced.</strong><br>
The test user reached Microsoft 365 from an unmanaged or unknown device context.
To make this scenario PASS, create or enforce a Conditional Access policy requiring a compliant or managed device for this user and target app.
</div>
""",
            unsafe_allow_html=True,
        )
    elif is_pass:
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — Unmanaged device access blocked.</strong><br>
The unmanaged-device access path was blocked by device-trust enforcement.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — More evidence required.</strong><br>
The test produced evidence, but the final device-trust decision is not fully proven.
</div>
""",
            unsafe_allow_html=True,
        )

    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "DEV-DV-001-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json",
        )

    with col2:
        st.download_button(
            "Download HTML Report",
            html_path.read_bytes(),
            "DEV-DV-001-result.html",
            "text/html",
            use_container_width=True,
            key=f"{key_prefix}_html",
        )



def render_devdv001_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV001.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV001.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV001.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-001"
    state_path = scenario_dir / "devdv001-state.json"
    prepare_path = scenario_dir / "devdv001-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-001-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-001-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-001 — Unmanaged Device Cloud Access Probe</h2>
  <p>Create a decoy user, attempt Microsoft 365 access from a clean unmanaged VM or InPrivate browser, then inspect Entra sign-in logs.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("This validates device trust. Use a clean VM or InPrivate browser that is not Entra joined, not Intune enrolled, and not compliant.", "info")

    st.markdown("### 1. Prepare decoy user")

    if not state_path.exists():
        col1, col2 = st.columns(2)

        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-devdv001-decoy", key="devdv001_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP DEV-DV-001 Unmanaged Device Decoy User", key="devdv001_display_name")

        with col2:
            tenant_domain = st.text_input("Tenant domain optional", value="", placeholder="Leave empty to auto-detect", key="devdv001_tenant_domain")
            target_name = st.selectbox(
                "Target cloud app",
                ["Microsoft 365 My Apps", "Microsoft 365 Portal", "Entra Portal"],
                index=0,
                key="devdv001_target_name",
            )

        target_map = {
            "Microsoft 365 My Apps": "https://myapps.microsoft.com",
            "Microsoft 365 Portal": "https://portal.office.com",
            "Entra Portal": "https://entra.microsoft.com",
        }

        expected_policy_option = st.selectbox(
            "Expected blocking control",
            [
                "Require compliant device",
                "Require hybrid joined device",
                "Require managed device",
                "Block unmanaged devices",
                "Require approved client app",
                "Require app protection policy",
                "Require MFA + compliant device",
                "Any device-trust Conditional Access policy",
                "Unknown / let ZTVP detect from sign-in logs",
            ],
            index=0,
            key="devdv001_expected_policy_option",
            help="Choose what you expect should block unmanaged device access. ZTVP will still verify the actual blocking policy from sign-in logs.",
        )

        expected_policy_custom = ""

        if expected_policy_option == "Unknown / let ZTVP detect from sign-in logs":
            expected_policy = ""
        elif expected_policy_option == "Any device-trust Conditional Access policy":
            expected_policy = "device trust"
        else:
            expected_policy = expected_policy_option

        if st.button("Step 1 — Prepare DEV-DV-001 Decoy User", type="primary", use_container_width=True):
            args = [
                "-UserPrefix", user_prefix.strip(),
                "-DisplayName", display_name.strip(),
                "-TargetName", target_name,
                "-TargetUrl", target_map[target_name],
            ]

            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            if expected_policy.strip():
                args.extend(["-ExpectedBlockingPolicy", expected_policy.strip()])

            with st.spinner("Creating DEV-DV-001 decoy user..."):
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
  {_metric("Target URL", prep.get("target_url", ""))}
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        _alert("No decoy prepared yet.", "warn")

    st.markdown("### 2. Run unmanaged VM / browser access attempt")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        target = state.get("target", {}) or {}
        probe = state.get("unmanaged_probe", {}) or {}
        window_start = probe.get("validation_window_start_utc", "")

        _alert(
            "Important: before every new test, start a fresh validation window. ZTVP will ignore old sign-ins and only analyze logs after that time.",
            "info",
        )

        if window_start:
            _alert(f"Fresh validation window active: {window_start}", "good")
        else:
            _alert("No fresh validation window active yet. Click the button below before doing the VM login.", "warn")

        if st.button("Start Fresh Validation Window", type="primary", use_container_width=True):
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state.setdefault("unmanaged_probe", {})
            state["unmanaged_probe"]["validation_window_start_utc"] = now_utc
            state["unmanaged_probe"]["validation_window_started_at_local"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _write_json(state_path, state)
            _alert(f"Fresh validation window started at {now_utc}. Now do the VM/InPrivate login.", "good")
            st.rerun()

        st.code(
            f"Correct flow:\n\n"
            f"1. Click Start Fresh Validation Window above.\n"
            f"2. Open clean VM / Windows Sandbox / InPrivate browser.\n"
            f"3. Confirm unmanaged state: dsregcmd /status should show AzureAdJoined: NO.\n"
            f"4. Go to: {target.get('url', '')}\n"
            f"5. Sign in with this decoy user:\n   {decoy.get('user_principal_name', '')}\n   {decoy.get('temporary_password', '')}\n"
            f"6. Do NOT enroll/register/connect the device.\n"
            f"7. Come back and click Step 3 Analyze. ZTVP will wait for the new logs and decide PASS/FAIL.",
            language="text",
        )

    st.markdown("### 3. Analyze sign-in logs")

    state_for_analysis = _load_json(state_path) if state_path.exists() else {}
    probe_for_analysis = state_for_analysis.get("unmanaged_probe", {}) or {}
    validation_window_start = probe_for_analysis.get("validation_window_start_utc", "")

    col_l1, col_l2 = st.columns(2)

    with col_l1:
        lookback_hours = st.slider(
            "Lookback hours",
            min_value=1,
            max_value=72,
            value=4,
            step=1,
            key="devdv001_lookback_hours",
            help="Graph search range. ZTVP still ignores logs older than the fresh validation window.",
        )

    with col_l2:
        poll_seconds = st.slider(
            "Check logs every seconds",
            min_value=10,
            max_value=60,
            value=30,
            step=10,
            key="devdv001_poll_seconds",
            help="ZTVP keeps checking until the new sign-in log appears.",
        )

    if validation_window_start:
        _alert(
            f"Ready. ZTVP will wait until a new meaningful sign-in appears after: {validation_window_start}",
            "good",
        )
    else:
        _alert("Start a Fresh Validation Window in Step 2 first. Then do the VM login. Then analyze.", "bad")

    if st.button("Step 3 — Wait for New Sign-in Log and Analyze", use_container_width=True):
        if not validation_window_start:
            _alert("Start a fresh validation window first, then do the VM login, then analyze.", "bad")
            return

        with st.spinner("Waiting for the new Entra sign-in log. This will keep loading until the log appears..."):
            completed = _run_powershell(
                project_root,
                analyze_script,
                [
                    "-LookbackHours", str(lookback_hours),
                    "-Top", "200",
                    "-PollSeconds", str(poll_seconds),
                    "-WindowStartUtc", validation_window_start,
                    "-WaitUntilLogFound",
                ],
                timeout=86400,
            )

        if completed.returncode != 0:
            _alert("Sign-in log analysis failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
        else:
            _alert("New sign-in log found and analyzed.", "good")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            st.rerun()

    if report_path.exists():
        st.markdown("### Latest DEV-DV-001 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="devdv001_latest")

    st.markdown("### 4. Cleanup")

    if not state_path.exists():
        _alert("No active DEV-DV-001 decoy state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}

        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Cleanup", "Pending", "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Step 4 — Cleanup DEV-DV-001 Decoy User", use_container_width=True):
            with st.spinner("Cleaning DEV-DV-001 decoy user..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)

            if completed.returncode != 0:
                _alert("DEV-DV-001 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("DEV-DV-001 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()



