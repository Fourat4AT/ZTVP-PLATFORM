from __future__ import annotations

import html
import json
import os
import subprocess
import time
from pathlib import Path

import msal
import pandas as pd
import requests
import streamlit as st


STATUS_LABELS = {
    "DECOY_READY": "DECOY READY",
    "PASS_DECOY_USER_CANNOT_CREATE_APP_REGISTRATION": "PASS — Decoy User Cannot Create App Registration",
    "FAIL_DECOY_USER_CAN_CREATE_APP_REGISTRATION": "FAIL — Decoy User Can Create App Registration",
    "PARTIAL_WRONG_ACCOUNT_USED": "PARTIAL — Wrong Account Used",
    "PARTIAL_LOGIN_OR_CONSENT_BLOCKED": "PARTIAL — Login or Consent Blocked",
    "PARTIAL_CREATE_ATTEMPT_INCONCLUSIVE": "PARTIAL — Create Attempt Inconclusive",
    "PARTIAL_CLEANUP_REQUIRED": "PARTIAL — Cleanup Required",
}

DEFAULT_PUBLIC_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
DEFAULT_GRAPH_SCOPE = "https://graph.microsoft.com/Application.ReadWrite.All"


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


def _authorization_blocked(message: str) -> bool:
    msg = (message or "").lower()
    markers = [
        "authorization_requestdenied",
        "insufficient privileges",
        "forbidden",
        "403",
        "not authorized",
        "permission",
        "does not have permission",
    ]
    return any(x in msg for x in markers)


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
        "<html><body><h1>APP-DV-007 Report</h1><pre>"
        + _safe(json.dumps(report, indent=2))
        + "</pre></body></html>",
        encoding="utf-8",
    )


def _graph_get_me(access_token: str) -> dict:
    r = requests.get(
        "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=60,
    )
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()


def _graph_create_application(access_token: str, display_name: str) -> dict:
    r = requests.post(
        "https://graph.microsoft.com/v1.0/applications",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json={
            "displayName": display_name,
            "signInAudience": "AzureADMyOrg",
        },
        timeout=60,
    )
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()


def _graph_delete_application(access_token: str, object_id: str) -> None:
    r = requests.delete(
        f"https://graph.microsoft.com/v1.0/applications/{object_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=60,
    )
    if r.status_code not in (204, 404):
        raise RuntimeError(f"{r.status_code} {r.text}")


def _build_report(
    state: dict,
    status: str,
    risk: str,
    summary: str,
    final_claim: str,
    evidence_quality: str,
    connected_account: str,
    used_decoy: bool,
    create_attempted: bool,
    app_created: bool,
    app_display_name: str,
    app_id: str | None,
    app_object_id: str | None,
    create_error: str | None,
    app_cleanup_completed: bool,
    cleanup_actions: list[str],
    cleanup_errors: list[str],
    warnings: list[str],
    auth_error: str | None = None,
) -> dict:
    decoy = state.get("decoy_user", {}) or {}

    return {
        "scenario_id": "APP-DV-007",
        "display_id": "APP-DV-007",
        "scenario_name": "App Registration Permission Probe",
        "pillar": "Applications",
        "scope": "Cloud",
        "mode": "Three-Step Managed Decoy Normal Browser Login",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tenant_id": state.get("tenant_id"),
        "expected_decoy_user": decoy.get("user_principal_name"),
        "connected_probe_account": connected_account,
        "status": status,
        "risk": risk,
        "executive_summary": summary,
        "final_claim": final_claim,
        "evidence_quality": evidence_quality,
        "warnings": warnings,
        "decoy_user": {
            "id": decoy.get("id"),
            "user_principal_name": decoy.get("user_principal_name"),
            "display_name": decoy.get("display_name"),
            "password_stored_in_report": False,
            "created_by_ztvp": True,
        },
        "decoy_authentication_evidence": {
            "method": "MSAL normal browser interactive login",
            "token_acquired": auth_error is None and connected_account not in ("", "Unknown"),
            "error_message": auth_error,
        },
        "app_registration_creation_evidence": {
            "actual_create_attempt_performed": create_attempted,
            "graph_endpoint": "POST https://graph.microsoft.com/v1.0/applications",
            "app_registration_created": app_created,
            "display_name": app_display_name,
            "app_id": app_id,
            "object_id": app_object_id,
            "error_message": create_error,
            "secrets_created": False,
            "certificates_created": False,
            "api_permissions_added": False,
            "redirect_uris_added": False,
        },
        "cleanup": {
            "app_cleanup_completed": app_cleanup_completed,
            "decoy_user_cleanup_required": True,
            "state_file_active": True,
            "actions": cleanup_actions,
            "errors": cleanup_errors,
        },
        "metrics": {
            "probe_used_decoy_user": used_decoy,
            "actual_create_attempt_performed": create_attempted,
            "app_registration_created": app_created,
            "app_cleanup_completed": app_cleanup_completed,
            "decoy_user_cleanup_required": True,
            "secrets_created": False,
            "certificates_created": False,
            "api_permissions_added": False,
        },
        "recommendations": [
            "If the decoy user can create app registrations, restrict normal user app registration creation in Entra ID.",
            "Allow app registration only for approved developers or controlled groups.",
            "Monitor Entra audit logs for application creation.",
            "Review existing app registrations for unknown owners.",
            "Require admin consent workflow for application permissions.",
            "Run cleanup to delete the APP-DV-007 decoy user.",
        ],
        "limitations": [
            "This validation requires the operator to sign in as the decoy user during Step 2.",
            "No secrets, certificates, redirect URIs, or API permissions are created.",
            "The decoy user is temporary and must be cleaned up.",
        ],
    }


def _render_report(report: dict, report_path: Path, html_path: Path, key_prefix: str = "appdv007") -> None:
    status = report.get("status")
    metrics = report.get("metrics", {}) or {}
    creation = report.get("app_registration_creation_evidence", {}) or {}
    decoy = report.get("decoy_user", {}) or {}
    cleanup = report.get("cleanup", {}) or {}

    _alert("APP-DV-007 probe report loaded.", _tone(status))

    st.markdown(
        f"""
<div class="ztvp-grid">
  {_metric("Status", _friendly_status(status), _tone(status))}
  {_metric("Risk", report.get("risk", "Unknown"), _tone(status))}
  {_metric("Probe Used Decoy", metrics.get("probe_used_decoy_user", False), "good" if metrics.get("probe_used_decoy_user") else "bad")}
  {_metric("Create Attempt", creation.get("actual_create_attempt_performed", False), "good" if creation.get("actual_create_attempt_performed") else "warn")}
</div>
<div class="ztvp-grid">
  {_metric("App Created", creation.get("app_registration_created", False), "bad" if creation.get("app_registration_created") else "good")}
  {_metric("App Cleanup", cleanup.get("app_cleanup_completed", False), "good" if cleanup.get("app_cleanup_completed") else "warn")}
  {_metric("Decoy User", decoy.get("user_principal_name", "N/A"))}
  {_metric("Decoy Cleanup Required", cleanup.get("decoy_user_cleanup_required", True), "warn")}
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("#### Decision")
    st.write(report.get("executive_summary", ""))
    st.caption(report.get("final_claim", ""))

    rows = [
        {"Evidence": "Expected decoy user", "Value": str(report.get("expected_decoy_user", "")), "Detail": "This is the account that must be used in Step 2."},
        {"Evidence": "Connected probe account", "Value": str(report.get("connected_probe_account", "")), "Detail": "Must match expected decoy user."},
        {"Evidence": "POST /applications attempted", "Value": str(creation.get("actual_create_attempt_performed")), "Detail": str(creation.get("graph_endpoint", ""))},
        {"Evidence": "App registration created", "Value": str(creation.get("app_registration_created")), "Detail": str(creation.get("error_message") or creation.get("object_id") or "")},
    ]

    st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)

    with st.expander("Full JSON evidence"):
        st.json(report)

    _write_html_report(report, html_path)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Download JSON Report",
            report_path.read_bytes(),
            "APP-DV-007-result.json",
            "application/json",
            use_container_width=True,
            key=f"{key_prefix}_json",
        )

    with col2:
        st.download_button(
            "Download HTML Report",
            html_path.read_bytes(),
            "APP-DV-007-result.html",
            "text/html",
            use_container_width=True,
            key=f"{key_prefix}_html",
        )


def _run_msal_probe(state: dict, report_path: Path) -> dict:
    tenant_id = str(state.get("tenant_id", ""))
    run_id = str(state.get("run_id", ""))
    decoy = state.get("decoy_user", {}) or {}
    decoy_upn = str(decoy.get("user_principal_name", "")).lower()
    app_display_name = f"ZTVP-APP-DV-007-AppRegistration-Probe-{run_id}"

    client_id = st.session_state.get("appdv007_client_id", DEFAULT_PUBLIC_CLIENT_ID).strip()
    scope = st.session_state.get("appdv007_scope", DEFAULT_GRAPH_SCOPE).strip()

    warnings = []
    cleanup_actions = []
    cleanup_errors = []

    authority = f"https://login.microsoftonline.com/{tenant_id}"

    public_app = msal.PublicClientApplication(
        client_id=client_id,
        authority=authority,
    )

    auth_error = None
    result = None

    try:
        result = public_app.acquire_token_interactive(
            scopes=[scope],
            prompt="select_account",
            login_hint=decoy_upn,
        )
    except Exception as e:
        auth_error = str(e)

    if not result or "access_token" not in result:
        if result:
            auth_error = json.dumps(result, ensure_ascii=False)
        report = _build_report(
            state=state,
            status="PARTIAL_LOGIN_OR_CONSENT_BLOCKED",
            risk="MEDIUM",
            summary="The decoy browser login or consent flow did not return a usable Graph token.",
            final_claim="ZTVP could not run POST /applications because the decoy login/token acquisition was blocked.",
            evidence_quality="Partial - login or consent blocked.",
            connected_account="Unknown",
            used_decoy=False,
            create_attempted=False,
            app_created=False,
            app_display_name=app_display_name,
            app_id=None,
            app_object_id=None,
            create_error=None,
            app_cleanup_completed=False,
            cleanup_actions=[],
            cleanup_errors=[],
            warnings=[auth_error or "No access token returned."],
            auth_error=auth_error or "No access token returned.",
        )
        _write_json(report_path, report)
        return report

    access_token = result["access_token"]

    connected_account = "Unknown"
    try:
        me = _graph_get_me(access_token)
        connected_account = str(me.get("userPrincipalName", "Unknown"))
    except Exception as e:
        warnings.append(f"Could not read /me: {e}")

    used_decoy = connected_account.lower() == decoy_upn

    create_attempted = False
    app_created = False
    app_id = None
    app_object_id = None
    create_error = None
    app_cleanup_completed = False

    if used_decoy:
        try:
            create_attempted = True
            created = _graph_create_application(access_token, app_display_name)
            app_created = True
            app_id = created.get("appId")
            app_object_id = created.get("id")

            state.setdefault("app_probe", {})
            state["app_probe"]["attempted"] = True
            state["app_probe"]["app_registration_created"] = True
            state["app_probe"]["app_object_id"] = app_object_id
            state["app_probe"]["app_id"] = app_id
            state["app_probe"]["display_name"] = app_display_name
            state["app_probe"]["error_message"] = None

            state_path = Path("powershell") / "Reports" / "Dynamic" / "APP-DV-007" / "appdv007-state.json"
            _write_json(state_path, state)

            try:
                _graph_delete_application(access_token, app_object_id)
                app_cleanup_completed = True
                cleanup_actions.append("Deleted temporary app registration using decoy token.")
            except Exception as e:
                cleanup_errors.append(f"Could not delete app registration using decoy token: {e}")

        except Exception as e:
            create_attempted = True
            create_error = str(e)

            state.setdefault("app_probe", {})
            state["app_probe"]["attempted"] = True
            state["app_probe"]["app_registration_created"] = False
            state["app_probe"]["display_name"] = app_display_name
            state["app_probe"]["error_message"] = create_error

            state_path = Path("powershell") / "Reports" / "Dynamic" / "APP-DV-007" / "appdv007-state.json"
            _write_json(state_path, state)

    if not used_decoy:
        status = "PARTIAL_WRONG_ACCOUNT_USED"
        risk = "MEDIUM"
        summary = "The probe did not run with the prepared decoy user."
        final_claim = "Sign in with the exact decoy UPN/password from Step 1 and rerun Step 2."
        evidence_quality = "Partial - wrong account used."
        warnings.append(f"Expected {decoy_upn}, got {connected_account}.")
    elif app_created:
        status = "FAIL_DECOY_USER_CAN_CREATE_APP_REGISTRATION"
        risk = "HIGH"
        summary = "The managed decoy normal user successfully created an Entra ID app registration."
        final_claim = "A normal decoy user can create app registrations in this tenant."
        evidence_quality = "Strong - real POST /applications succeeded using the decoy user's browser-authenticated token."
        if not app_cleanup_completed:
            status = "PARTIAL_CLEANUP_REQUIRED"
            warnings.append("App registration was created but was not cleaned by the probe. Run cleanup.")
    elif create_attempted and create_error and _authorization_blocked(create_error):
        status = "PASS_DECOY_USER_CANNOT_CREATE_APP_REGISTRATION"
        risk = "LOW"
        summary = "The managed decoy normal user attempted to create an app registration and was blocked."
        final_claim = "A normal decoy user cannot create app registrations in this tenant."
        evidence_quality = "Strong - real POST /applications attempt was blocked."
    else:
        status = "PARTIAL_CREATE_ATTEMPT_INCONCLUSIVE"
        risk = "MEDIUM"
        summary = "The decoy user signed in, but the create attempt failed for an unclear reason."
        final_claim = "ZTVP could not classify the result from this error alone."
        evidence_quality = "Partial - ambiguous create failure."
        if create_error:
            warnings.append(f"Create error: {create_error}")

    report = _build_report(
        state=state,
        status=status,
        risk=risk,
        summary=summary,
        final_claim=final_claim,
        evidence_quality=evidence_quality,
        connected_account=connected_account,
        used_decoy=used_decoy,
        create_attempted=create_attempted,
        app_created=app_created,
        app_display_name=app_display_name,
        app_id=app_id,
        app_object_id=app_object_id,
        create_error=create_error,
        app_cleanup_completed=app_cleanup_completed,
        cleanup_actions=cleanup_actions,
        cleanup_errors=cleanup_errors,
        warnings=warnings,
        auth_error=None,
    )

    _write_json(report_path, report)
    return report


def render_appdv007_runner(project_root: Path) -> None:
    project_root = Path(project_root)
    _css()

    prepare_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Prepare-ZTVP-APPDV007.ps1"
    cleanup_script = project_root / "powershell" / "Engines" / "DynamicValidation" / "Cleanup-ZTVP-APPDV007.ps1"

    scenario_dir = project_root / "powershell" / "Reports" / "Dynamic" / "APP-DV-007"
    state_path = scenario_dir / "appdv007-state.json"
    prepare_path = scenario_dir / "appdv007-prepare-result.json"
    report_path = project_root / "powershell" / "Reports" / "Dynamic" / "APP-DV-007-result.json"
    html_path = project_root / "powershell" / "Reports" / "Dynamic" / "Html" / "APP-DV-007-result.html"

    st.markdown(
        """
<div class="ztvp-hero">
  <h2>APP-DV-007 — App Registration Permission Probe</h2>
  <p>Prepare a decoy user, sign in normally with browser MFA support, then perform a real POST /applications attempt.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    _alert("Step 2 uses normal browser login with MSAL. Sign in as the decoy user, not your admin account.", "info")

    st.markdown("### 1. Prepare decoy user")

    if not state_path.exists():
        col1, col2 = st.columns(2)

        with col1:
            user_prefix = st.text_input("Decoy username prefix", value="ztvp-appdv007-decoy", key="appdv007_user_prefix")
            display_name = st.text_input("Decoy display name", value="ZTVP APP-DV-007 App Registration Decoy User", key="appdv007_display_name")

        with col2:
            tenant_domain = st.text_input(
                "Tenant domain optional",
                value="",
                placeholder="Leave empty to auto-detect, or enter tenant.onmicrosoft.com",
                key="appdv007_tenant_domain",
            )

        if st.button("Step 1 — Prepare Decoy User", type="primary", use_container_width=True):
            args = ["-UserPrefix", user_prefix.strip(), "-DisplayName", display_name.strip()]
            if tenant_domain.strip():
                args.extend(["-TenantDomain", tenant_domain.strip()])

            with st.spinner("Creating APP-DV-007 decoy user..."):
                completed = _run_powershell(project_root, prepare_script, args, timeout=1200)

            if completed.returncode != 0:
                _alert("Decoy preparation failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
                return

            _alert("Decoy user prepared. Use the shown UPN/password in Step 2.", "good")
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
    else:
        _alert("No decoy prepared yet.", "warn")

    st.markdown("### 2. Run browser login probe as decoy user")

    if not state_path.exists():
        _alert("Prepare the decoy user first.", "warn")
    else:
        state = _load_json(state_path)
        decoy = state.get("decoy_user", {}) or {}

        decoy_upn = str(decoy.get("user_principal_name", ""))
        decoy_password = str(decoy.get("temporary_password", ""))

        st.code(
            f"Decoy UPN: {decoy_upn}\nTemporary password: {decoy_password}",
            language="text",
        )

        # Internal MSAL settings. Hidden from the operator to keep the scenario simple.
        st.session_state["appdv007_client_id"] = DEFAULT_PUBLIC_CLIENT_ID
        st.session_state["appdv007_scope"] = DEFAULT_GRAPH_SCOPE

        _alert("When the Microsoft login opens, choose the decoy user. MFA is okay. If it auto-selects your admin, sign out in the browser and retry.", "warn")

        if st.button("Step 2 — Login as Decoy and Try App Registration", use_container_width=True):
            with st.spinner("Opening browser login. Complete sign-in as the decoy user, then ZTVP will try POST /applications..."):
                try:
                    report = _run_msal_probe(state, report_path)
                    _alert("APP-DV-007 probe completed.", _tone(report.get("status")))
                    st.rerun()
                except Exception as e:
                    _alert(f"APP-DV-007 MSAL probe crashed: {e}", "bad")
                    return

    if report_path.exists():
        st.markdown("### Latest APP-DV-007 report")
        report = _load_json(report_path)
        _render_report(report, report_path, html_path, key_prefix="appdv007_latest")

    st.markdown("### 3. Cleanup")

    if not state_path.exists():
        _alert("No active APP-DV-007 decoy state exists.", "good")
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

        if st.button("Step 3 — Cleanup APP-DV-007 Test Objects", use_container_width=True):
            with st.spinner("Cleaning APP-DV-007 app registration and decoy user..."):
                completed = _run_powershell(project_root, cleanup_script, [], timeout=1200)

            if completed.returncode != 0:
                _alert("APP-DV-007 cleanup failed.", "bad")
                st.code(f"Return code: {completed.returncode}\n\n--- STDERR ---\n{completed.stderr or ''}\n\n--- STDOUT ---\n{completed.stdout or ''}", language="text")
            else:
                _alert("APP-DV-007 cleanup completed.", "good")
                st.code(completed.stdout or "No PowerShell output captured.", language="text")
                st.rerun()
