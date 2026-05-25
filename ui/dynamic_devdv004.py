from __future__ import annotations

import html
import json
import os
import subprocess
from pathlib import Path

import pandas as pd
import streamlit as st


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "FAIL_NORMAL_USER_REGISTERED_DEVICE": "FAIL — Normal User Registered Device",
    "PASS_TENANT_BLOCKED_NORMAL_USER_DEVICE_REGISTRATION": "PASS — Tenant Blocked Normal User Device Registration",
    "PARTIAL_EVIDENCE_FOUND_UNCLASSIFIED": "PARTIAL — Evidence Found, Unclassified",
}


def _safe(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


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
    if text.startswith("PASS"):
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
        "<html><body><h1>DEV-DV-004 Report</h1><pre>"
        + _safe(json.dumps(report, indent=2))
        + "</pre></body></html>",
        encoding="utf-8",
    )


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "devdv004") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    detected = report.get("detected_device", {}) or {}
    evidence = report.get("evidence", {}) or {}

    _alert("DEV-DV-004 report loaded.", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Verdict", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Device Created/Linked", metrics.get("device_registered_or_linked", False), "bad" if metrics.get("device_registered_or_linked") else "good")}
  {_metric("Validation Method", "Manual Sandbox", "good")}
</div>
<div class="ztvp-grid">
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Registered Devices", evidence.get("registered_device_count_after_window", 0), "bad" if evidence.get("registered_device_count_after_window", 0) else "good")}
  {_metric("Blocking Sign-ins", evidence.get("blocking_sign_in_count_after_window", 0))}
  {_metric("Audit Events", evidence.get("registration_like_audit_count_after_window", 0))}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")
    if str(status or "").startswith("FAIL"):
        _alert("FAIL: the decoy user appears to have registered or linked a new device identity after the validation window.", "bad")
    elif str(status or "").startswith("PASS"):
        _alert("PASS: the tenant did not allow the normal decoy user to complete device registration. No device object was created or linked to this user.", "good")
    else:
        _alert("PARTIAL: evidence exists, but the registration result is not fully classified.", "warn")

    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    rows = [
        {"Evidence": "Validation window", "Value": report.get("validation_window_start_utc", ""), "Meaning": "Only evidence after this time was analyzed."},
        {"Evidence": "Decoy user", "Value": decoy.get("user_principal_name", ""), "Meaning": "Normal temporary user used inside Sandbox."},
        {"Evidence": "Detected device", "Value": detected.get("display_name", "None"), "Meaning": detected.get("trust_type", "No device object was created or linked to the decoy user.") if detected else "No device object was created or linked to the decoy user."},
        {"Evidence": "Registered devices", "Value": evidence.get("registered_device_count_after_window", 0), "Meaning": "0 means the decoy user did not successfully register a device."},
        {"Evidence": "Blocking sign-ins", "Value": evidence.get("blocking_sign_in_count_after_window", 0), "Meaning": "Failed/blocked sign-ins after the window."},
        {"Evidence": "Device-related audit events", "Value": evidence.get("registration_like_audit_count_after_window", 0), "Meaning": "Shows that something happened during the registration flow, even though no device was created."},
    ]


    st.markdown("#### Tenant conclusion")

    if str(status or "").startswith("PASS"):
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — Tenant blocked normal-user device registration.</strong><br>
The normal decoy user attempted the registration flow from Windows Sandbox, but no Entra device object was created or linked to that user.
This means the tenant did not allow this normal user to complete device registration.
</div>
""",
            unsafe_allow_html=True,
        )
    elif str(status or "").startswith("FAIL"):
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — Normal user registered a device.</strong><br>
A device object was created or linked to the decoy user. This means the tenant allowed this normal user to introduce a new device identity.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — More evidence required.</strong><br>
ZTVP found some evidence, but the result could not be fully classified.
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("#### Evidence summary")
    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    devices = (evidence.get("registered_devices") or [])
    if devices:
        st.markdown("#### Registered / linked devices")
        st.dataframe(pd.DataFrame(devices).astype(str), use_container_width=True, hide_index=True)

    signins = (evidence.get("sign_ins") or [])
    if signins:
        st.markdown("#### Sign-ins after validation window")
        st.dataframe(pd.DataFrame(signins).astype(str), use_container_width=True, hide_index=True)

    audits = (evidence.get("audit_events") or [])
    if audits:
        st.markdown("#### Device-related audit events")
        st.dataframe(pd.DataFrame(audits).astype(str), use_container_width=True, hide_index=True)

    recs = report.get("recommendations", []) or []
    if recs:
        st.markdown("#### Recommended follow-up")
        if str(status or "").startswith("PASS"):
            st.caption("These are follow-up actions, not emergency fixes. The validation passed because the tenant did not allow the normal decoy user to complete device registration.")
        elif str(status or "").startswith("FAIL"):
            st.caption("These are remediation actions because the decoy user successfully registered or linked a device.")
        else:
            st.caption("These are investigation actions because the result was not fully classified.")

        for rec in recs:
            st.markdown(f"- {rec}")

    st.markdown("#### Clean conclusion")

    if str(status or "").startswith("FAIL"):
        st.markdown(
            """
<div style="background:#7f1d1d;color:#ffffff;border:1px solid #ef4444;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>FAIL — Device registration succeeded.</strong><br>
The decoy user created or linked a new device object. This means a normal user was able to introduce a device identity into Entra ID.
</div>
""",
            unsafe_allow_html=True,
        )
    elif str(status or "").startswith("PASS"):
        st.markdown(
            """
<div style="background:#064e3b;color:#ffffff;border:1px solid #10b981;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PASS — Device registration blocked or not completed.</strong><br>
The decoy user attempted registration from Windows Sandbox, but no device object was created or linked. The normal user did not successfully introduce a new device identity.
</div>
""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
<div style="background:#78350f;color:#ffffff;border:1px solid #f59e0b;border-radius:14px;padding:1rem;font-weight:750;line-height:1.55;">
<strong>PARTIAL — More evidence required.</strong><br>
ZTVP found some evidence, but the result could not be fully classified.
</div>
""",
            unsafe_allow_html=True,
        )
    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button("Download JSON Report", report_path.read_bytes(), "DEV-DV-004-result.json", "application/json", use_container_width=True, key=f"{key_prefix}_json")

    with col2:
        st.download_button("Download HTML Report", html_path.read_bytes(), "DEV-DV-004-result.html", "text/html", use_container_width=True, key=f"{key_prefix}_html")


def render_devdv004_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-DEVDV004.ps1"
    launch_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Launch-ZTVP-DEVDV004Sandbox.ps1"
    analyze_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV004.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-DEVDV004.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-004"
    state_path = scenario_dir / "devdv004-state.json"
    prepare_path = scenario_dir / "devdv004-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "DEV-DV-004-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "DEV-DV-004-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>DEV-DV-004 — Sandbox Device Registration Abuse Probe</h2>
  <p>Create a decoy user, manually use Windows Sandbox for Access work or school registration, then wait for Entra evidence.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("This is the real normal-user device registration validation from the Devices → Cloud catalog. Windows Sandbox must be enabled on the host.", "info")

    st.markdown("### 1. Prepare decoy user")

    if not state_path.exists():
        col1, col2 = st.columns(2)
        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-devdv004-decoy", key="devdv004_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP DEV-DV-004 Sandbox Device Registration Decoy User", key="devdv004_display_name")
        with col2:
            tenant_domain = st.text_input("Tenant domain optional", value="", placeholder="Leave empty to auto-detect", key="devdv004_tenant_domain")

        if st.button("Step 1 — Prepare DEV-DV-004 Decoy User", type="primary", use_container_width=True):
            args = ["-UserPrefix", user_prefix.strip(), "-DisplayName", display_name.strip()]
            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            with st.spinner("Creating DEV-DV-004 decoy user..."):
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
  {_metric("Operator", prep.get("operator_account", ""))}
  {_metric("Decoy UPN", prep.get("decoy_user_principal_name", ""))}
  {_metric("Temporary Password", prep.get("decoy_temporary_password", ""), "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("### 2. Start fresh validation window and open Sandbox manually")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        window = state.get("validation_window_start_utc", "")

        _alert(
            "Open Windows Sandbox manually. ZTVP will only start the validation timestamp and then wait for Entra evidence.",
            "info",
        )

        if window:
            _alert(f"Current validation window: {window}", "good")
        else:
            _alert("No validation window yet. Click the button below before doing the Sandbox registration attempt.", "warn")

        if st.button("Step 2 — Start Fresh Validation Window", use_container_width=True):
            import time
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state["validation_window_start_utc"] = now_utc
            state.setdefault("sandbox", {})
            state["sandbox"]["launched"] = False
            state["sandbox"]["manual_mode"] = True
            state["sandbox"]["manual_window_started_at"] = now_utc

            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            _alert(f"Fresh validation window started at {now_utc}. Now open Windows Sandbox manually.", "good")
            st.rerun()

        st.code(
            f"Manual Sandbox flow:\n\n"
            f"1. Open Windows Sandbox yourself from the Start menu.\n"
            f"2. Inside Sandbox, open Settings.\n"
            f"3. Go to Accounts → Access work or school.\n"
            f"4. Click Connect.\n"
            f"5. Sign in using this decoy user:\n   {decoy.get('user_principal_name', '')}\n   {decoy.get('temporary_password', '')}\n"
            f"6. Try to complete the work/school registration flow.\n"
            f"7. Come back to ZTVP and click Step 3 — Wait for Device Registration Evidence.",
            language="text",
        )

    st.markdown("### 3. Wait for device registration evidence")

    poll_seconds = st.slider("Check Entra evidence every seconds", min_value=10, max_value=60, value=30, step=10, key="devdv004_poll_seconds")

    if st.button("Step 3 — Wait for Device Registration Evidence", use_container_width=True):
        with st.spinner("Waiting for device/audit/sign-in evidence. This keeps loading until evidence appears..."):
            completed = _run_powershell(
                project_root,
                analyze_script,
                ["-PollSeconds", str(poll_seconds), "-WaitUntilEvidence"],
                timeout=86400,
            )

        if completed.returncode != 0:
            _alert("Evidence analysis failed.", "bad")
            st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
        else:
            _alert("Evidence found and analyzed.", "good")
            st.code(completed.stdout or "No PowerShell output captured.", language="text")
            st.rerun()

    if report_path.exists():
        st.markdown("### Latest DEV-DV-004 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="devdv004_latest")

    st.markdown("### 4. Cleanup")

    delete_device = st.checkbox("Also delete detected test device if ZTVP found one", value=False, key="devdv004_delete_device")

    if not state_path.exists():
        _alert("No active DEV-DV-004 state exists.", "good")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}
        detected = state.get("detected_device", {}) or {}

        st.markdown(
            f"""
<div class="ztvp-grid-3">
  {_metric("Run ID", state.get("run_id", "N/A"))}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Detected Device", detected.get("display_name", "None") if detected else "None", "warn")}
</div>
""",
            unsafe_allow_html=True,
        )

        if st.button("Step 4 — Cleanup DEV-DV-004 Objects", use_container_width=True):
            args = []
            if delete_device:
                args.append("-DeleteDetectedDevice")

            with st.spinner("Cleaning DEV-DV-004 objects..."):
                completed = _run_powershell(project_root, cleanup_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("DEV-DV-004 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("DEV-DV-004 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()

