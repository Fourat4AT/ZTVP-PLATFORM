from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCENARIO_REQUIRED_SCOPES: dict[str, list[str]] = {
    "ID-DV-001": ["AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All"],
    "ID-C-001": ["AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All"],
    "ID-DV-005": ["User.Invite.All", "User.ReadWrite.All", "Directory.ReadWrite.All", "AuditLog.Read.All", "Policy.Read.All"],
    "ID-C-005": ["User.Invite.All", "User.ReadWrite.All", "Directory.ReadWrite.All", "AuditLog.Read.All", "Policy.Read.All"],
    "DEV-DV-001": ["AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All"],
    "DEV-DV-002": ["Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"],
    "DEV-DV-003": ["DeviceManagementManagedDevices.Read.All", "SecurityEvents.Read.All"],
    "DEV-DV-004": ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"],
    "DEV-DV-006": ["DeviceManagementManagedDevices.Read.All", "SecurityEvents.Read.All"],
    "DEV-DV-008": ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"],
    "CLD-DV-001": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
    "CLD-C-001": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
    "APP-DV-008": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
    "APP-DV-003": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
    "APP-C-003": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
    "APP-DV-007": ["Application.ReadWrite.All", "Directory.Read.All"],
}

GRAPH_SCENARIOS = set(SCENARIO_REQUIRED_SCOPES)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ui_state_path() -> Path:
    return Path(__file__).resolve().parents[1] / "powershell" / "Reports" / "graph-connection-ui-state.json"


def load_graph_ui_state() -> dict[str, Any]:
    path = _ui_state_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_graph_ui_state(status: dict[str, Any]) -> None:
    payload = {
        "connected": True,
        "account": status.get("account"),
        "tenant_id": status.get("tenant_id"),
        "tenant_name": status.get("tenant_display_name") or status.get("tenant_name"),
        "timestamp": utc_now(),
    }
    path = _ui_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def clear_graph_ui_state() -> None:
    try:
        _ui_state_path().unlink(missing_ok=True)
    except Exception:
        pass


def _powershell_exe() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(win_ps) if win_ps.exists() else "powershell.exe"


def _run_graph_script(script: str, timeout: int = 120) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [_powershell_exe(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "started": True,
            "timed_out": False,
            "return_code": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "started": True,
            "timed_out": True,
            "return_code": None,
            "stdout": _decode_timeout_output(exc.stdout),
            "stderr": _decode_timeout_output(exc.stderr),
            "error": "Reconnect did not complete. Try reconnecting Microsoft Graph again or run the manual command in PowerShell.",
        }
    except Exception as exc:
        return {
            "started": False,
            "timed_out": False,
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "error": f"PowerShell command failed to start. {exc}",
        }


def _decode_timeout_output(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _attach_command_result(payload: dict[str, Any], command_result: dict[str, Any], prefix: str) -> dict[str, Any]:
    payload[f"{prefix}_stdout"] = command_result.get("stdout") or ""
    payload[f"{prefix}_stderr"] = command_result.get("stderr") or ""
    payload[f"{prefix}_return_code"] = command_result.get("return_code")
    payload[f"{prefix}_timed_out"] = bool(command_result.get("timed_out"))
    payload[f"{prefix}_started"] = bool(command_result.get("started"))
    return payload


def _json_or_empty(text: str) -> dict[str, Any]:
    if "ZTVP_GRAPH_JSON_BEGIN" in text and "ZTVP_GRAPH_JSON_END" in text:
        text = text.split("ZTVP_GRAPH_JSON_BEGIN", 1)[1].split("ZTVP_GRAPH_JSON_END", 1)[0].strip()
    try:
        data = json.loads(text or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def classify_graph_error(error_text: object) -> str:
    text = str(error_text or "")
    lower = text.lower()
    if not text.strip():
        return "GRAPH_UNKNOWN_ERROR"
    if "your session is no longer valid" in lower or "invalidauthenticationtoken" in lower or "access token has expired" in lower:
        return "GRAPH_SESSION_EXPIRED"
    if "get-mgcontext" in lower and ("null" in lower or "not connected" in lower):
        return "GRAPH_NOT_CONNECTED"
    if "connect-mggraph" in lower or "authentication" in lower and "required" in lower:
        return "GRAPH_NOT_CONNECTED"
    if "interactionrequired" in lower or "aadsts" in lower:
        return "GRAPH_SESSION_EXPIRED"
    if "scope" in lower or "consent" in lower:
        return "GRAPH_MISSING_SCOPES"
    if "insufficient privileges" in lower or "authorization_requestdenied" in lower or "forbidden" in lower:
        return "GRAPH_INSUFFICIENT_PRIVILEGES"
    if "policy" in lower and ("denied" in lower or "blocked" in lower):
        return "GRAPH_TENANT_POLICY_DENIED"
    if "unauthorized" in lower or "401" in lower:
        return "GRAPH_SESSION_EXPIRED"
    return "GRAPH_UNKNOWN_ERROR"


def get_graph_context() -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'Stop'
$ctx = Get-MgContext
if ($null -eq $ctx) {
  @{ status='Not connected'; error_category='GRAPH_NOT_CONNECTED'; current_scopes=@(); last_checked_utc=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Depth 6
  exit 0
}
@{
  status='Context found'
  account=$ctx.Account
  tenant_id=$ctx.TenantId
  tenant_display_name=$ctx.TenantName
  current_scopes=@($ctx.Scopes)
  auth_type=$ctx.AuthType
  context_scope=$ctx.ContextScope
  client_id=$ctx.ClientId
  last_checked_utc=(Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 6
"""
    try:
        completed = _run_graph_script(script, timeout=45)
    except Exception as exc:
        return {"status": "Error", "error": str(exc), "error_category": classify_graph_error(str(exc)), "last_checked_utc": utc_now(), "current_scopes": []}
    payload = _json_or_empty(str(completed.get("stdout") or ""))
    if completed.get("return_code") != 0 or not completed.get("started"):
        return _attach_command_result({"status": "Error", "error": (completed.get("error") or completed.get("stderr") or completed.get("stdout") or "").strip(), "error_category": classify_graph_error(completed.get("stderr") or completed.get("stdout") or completed.get("error")), "last_checked_utc": utc_now(), "current_scopes": []}, completed, "check")
    return _attach_command_result(payload or {"status": "Error", "error": "Microsoft Graph context was not returned.", "error_category": "GRAPH_UNKNOWN_ERROR", "last_checked_utc": utc_now(), "current_scopes": []}, completed, "check")


def check_graph_connection() -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'Stop'
$ctx = Get-MgContext
if ($null -eq $ctx) {
  Write-Output 'ZTVP_GRAPH_JSON_BEGIN'
  @{
    status='Not connected'
    live_context=$false
    error='No active Graph context is available in this validation process. Click Connect Microsoft Graph to refresh the session.'
    error_category='GRAPH_NOT_CONNECTED'
    last_checked_utc=(Get-Date).ToUniversalTime().ToString('o')
  } | ConvertTo-Json -Depth 6
  Write-Output 'ZTVP_GRAPH_JSON_END'
  exit 0
}
$org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName'
$me = $null
try { $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,displayName' } catch { }
$tenant = @($org.value)[0]
Write-Output 'ZTVP_GRAPH_JSON_BEGIN'
@{
  status='Connected'
  live_context=$true
  account=$ctx.Account
  tenant_id=if ($tenant.id) { $tenant.id } else { $ctx.TenantId }
  tenant_display_name=$tenant.displayName
  current_scopes=@($ctx.Scopes)
  auth_type=$ctx.AuthType
  connection_mode=if ($ctx.AuthType -eq 'AppOnly') { 'App-only Graph credential' } else { 'Delegated Microsoft Graph PowerShell session' }
  me=$me
  last_checked_utc=(Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 8
Write-Output 'ZTVP_GRAPH_JSON_END'
"""
    try:
        completed = _run_graph_script(script, timeout=90)
    except Exception as exc:
        return {"status": "Error", "error": str(exc), "error_category": classify_graph_error(str(exc)), "last_checked_utc": utc_now(), "current_scopes": []}
    if completed.get("return_code") != 0 or completed.get("timed_out") or not completed.get("started"):
        error = (completed.get("error") or completed.get("stderr") or completed.get("stdout") or "").strip()
        category = classify_graph_error(error)
        status = "Expired" if category == "GRAPH_SESSION_EXPIRED" else "Not connected" if category == "GRAPH_NOT_CONNECTED" else "Error"
        context = get_graph_context()
        context.update({"status": status, "error": error, "error_category": category, "last_checked_utc": utc_now()})
        return _attach_command_result(_with_saved_ui_state(context), completed, "check")
    payload = _json_or_empty(str(completed.get("stdout") or ""))
    payload.setdefault("status", "Connected")
    payload.setdefault("last_checked_utc", utc_now())
    return _attach_command_result(_with_saved_ui_state(payload), completed, "check")


def _with_saved_ui_state(status: dict[str, Any]) -> dict[str, Any]:
    if status.get("status") == "Connected":
        return status
    saved = load_graph_ui_state()
    if not saved:
        return status
    merged = dict(status)
    merged["status"] = "Last connected"
    merged["last_connected"] = True
    merged["connected"] = False
    merged["account"] = saved.get("account")
    merged["tenant_id"] = saved.get("tenant_id")
    merged["tenant_display_name"] = saved.get("tenant_name")
    merged["last_connected_utc"] = saved.get("timestamp")
    merged["error"] = status.get("error") or "No active Graph context is available in this validation process. Click Connect Microsoft Graph to refresh the session."
    return merged


def test_graph_connection() -> dict[str, Any]:
    return check_graph_connection()


def get_required_scopes_for_scenario(scenario_id: str) -> list[str]:
    return list(SCENARIO_REQUIRED_SCOPES.get(str(scenario_id or "").upper(), []))


def check_required_scopes(scenario_id: str) -> dict[str, Any]:
    required = get_required_scopes_for_scenario(scenario_id)
    status = test_graph_connection()
    current = {str(scope).lower() for scope in status.get("current_scopes") or []}
    missing = [scope for scope in required if scope.lower() not in current]
    if required and status.get("status") == "Connected" and missing:
        status["status"] = "Missing scopes"
        status["error_category"] = "GRAPH_MISSING_SCOPES"
    status["required_scopes"] = required
    status["missing_scopes"] = missing
    return status


def connect_graph(scopes: list[str] | str) -> dict[str, Any]:
    scope_list = [str(item).strip() for item in (scopes if isinstance(scopes, list) else str(scopes).split()) if str(item).strip()]
    quoted_scopes = ",".join(f'"{scope}"' for scope in scope_list)
    script = f"""
$ErrorActionPreference = 'Stop'
try {{ Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }} catch {{ }}
$null = Connect-MgGraph -Scopes {quoted_scopes}
$ctx = Get-MgContext
if ($null -eq $ctx) {{ throw 'Connect-MgGraph completed, but Get-MgContext returned no active context.' }}
$org = $null
try {{ $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName' }} catch {{ }}
$tenant = @($org.value)[0]
Write-Output 'ZTVP_GRAPH_JSON_BEGIN'
@{{
  status='Connected'
  live_context=$true
  account=$ctx.Account
  tenant_id=if ($tenant.id) {{ $tenant.id }} else {{ $ctx.TenantId }}
  tenant_display_name=$tenant.displayName
  current_scopes=@($ctx.Scopes)
  auth_type=$ctx.AuthType
  connection_mode=if ($ctx.AuthType -eq 'AppOnly') {{ 'App-only Graph credential' }} else {{ 'Delegated Microsoft Graph PowerShell session' }}
  last_checked_utc=(Get-Date).ToUniversalTime().ToString('o')
}} | ConvertTo-Json -Depth 8
Write-Output 'ZTVP_GRAPH_JSON_END'
"""
    timeout = 180
    completed = _run_graph_script(script, timeout=timeout)
    if completed.get("return_code") != 0 or completed.get("timed_out") or not completed.get("started"):
        text = (completed.get("error") or completed.get("stderr") or completed.get("stdout") or "").strip()
        payload = {
            "ok": False,
            "status": "Error",
            "error": text or "Command failed. See output below.",
            "error_category": classify_graph_error(text),
            "last_checked_utc": utc_now(),
            "current_scopes": [],
            "required_scopes": scope_list,
            "manual_command": manual_reconnect_command(scope_list),
        }
        return _attach_command_result(payload, completed, "reconnect")
    payload = _json_or_empty(str(completed.get("stdout") or ""))
    if not payload:
        payload = {
            "status": "Error",
            "ok": False,
            "error": "Connect Microsoft Graph completed, but the tenant/account details were not returned.",
            "last_checked_utc": utc_now(),
        }
    payload["ok"] = payload.get("status") == "Connected"
    payload["required_scopes"] = scope_list
    payload["manual_command"] = manual_reconnect_command(scope_list)
    _attach_command_result(payload, completed, "reconnect")
    if payload.get("ok"):
        save_graph_ui_state(payload)
    return payload


def reconnect_graph(scopes: list[str] | str) -> dict[str, Any]:
    return connect_graph(scopes)


def disconnect_graph() -> dict[str, Any]:
    completed = _run_graph_script("Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null", timeout=45)
    payload = {"ok": completed.get("return_code") == 0, "status": "Not connected", "error": (completed.get("stderr") or completed.get("error") or "").strip(), "last_checked_utc": utc_now()}
    clear_graph_ui_state()
    return _attach_command_result(payload, completed, "reconnect")


def manual_reconnect_command(scopes: list[str] | str) -> str:
    scope_text = ",".join(f'"{scope}"' for scope in (scopes if isinstance(scopes, list) else str(scopes).split()))
    return f"Disconnect-MgGraph\nConnect-MgGraph -Scopes {scope_text}"


def clean_graph_message(status: dict[str, Any]) -> str:
    category = status.get("error_category")
    if category == "GRAPH_SESSION_EXPIRED":
        return "Microsoft Graph session expired. Go to Home and click Connect Microsoft Graph, then rerun the scenario."
    if category == "GRAPH_MISSING_SCOPES" or status.get("missing_scopes"):
        return "This scenario requires additional Microsoft Graph scopes."
    if category == "GRAPH_NOT_CONNECTED":
        return "Microsoft Graph is not connected. Go to Home and click Connect Microsoft Graph, then rerun the scenario."
    if category == "GRAPH_INSUFFICIENT_PRIVILEGES":
        return "Microsoft Graph connected, but the signed-in account lacks privileges for this operation."
    return str(status.get("error") or "Microsoft Graph is not ready.")


def _connection_center_css() -> None:
    import streamlit as st

    st.markdown(
        """
<style>
div[data-testid="stAlert"] {
    color: #111827 !important;
}
div[data-testid="stAlert"] * {
    color: #111827 !important;
}
div[data-testid="stButton"] button {
    background: #ffffff !important;
    color: #111827 !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 10px !important;
    font-weight: 800 !important;
}
div[data-testid="stButton"] button:hover {
    background: #f8fafc !important;
    color: #0f172a !important;
    border-color: #94a3b8 !important;
}
div[data-testid="stButton"] button[kind="primary"],
button[data-testid="stBaseButton-primary"] {
    background: #2563eb !important;
    color: #ffffff !important;
    border-color: #2563eb !important;
}
div[data-testid="stButton"] button[kind="primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #1d4ed8 !important;
    color: #ffffff !important;
    border-color: #1d4ed8 !important;
}
div[data-testid="stButton"] button p {
    color: inherit !important;
}
</style>
""",
        unsafe_allow_html=True,
    )


def render_graph_connection_summary(status: dict[str, Any]) -> None:
    import streamlit as st

    raw_label = status.get("status") or "Not connected"
    label = "Connected" if raw_label in {"Connected", "Context found", "Missing scopes"} and status.get("account") else "Last connected" if raw_label == "Last connected" and status.get("account") else "Not connected"
    if label == "Connected":
        st.success("Status: Connected")
    elif label == "Last connected":
        st.info("Status: Last connected")
    else:
        st.warning("Status: Not connected")
    cols = st.columns(3)
    cols[0].metric("Account", status.get("account") or "Not connected")
    cols[1].metric("Tenant ID", status.get("tenant_id") or "Unknown")
    cols[2].metric("Tenant", status.get("tenant_display_name") or "Unknown")
    if status.get("error"):
        if label == "Last connected":
            st.info("No active Graph context is available in this validation process. Click Connect Microsoft Graph to refresh the session.")
        else:
            st.error("Not connected. Try again.")


def _sync_graph_session_state(status: dict[str, Any]) -> None:
    import streamlit as st

    st.session_state["graph_connection_status"] = status
    st.session_state["graph_status"] = status.get("status")
    st.session_state["graph_account"] = status.get("account")
    st.session_state["graph_tenant_id"] = status.get("tenant_id")
    st.session_state["graph_tenant_name"] = status.get("tenant_display_name")
    st.session_state["graph_scopes"] = status.get("current_scopes") or []
    st.session_state["graph_missing_scopes"] = status.get("missing_scopes") or []
    st.session_state["graph_last_checked_utc"] = status.get("last_checked_utc")
    st.session_state["graph_last_error"] = status.get("error")
    st.session_state["graph_last_stdout"] = status.get("check_stdout") or status.get("reconnect_stdout") or ""
    st.session_state["graph_last_stderr"] = status.get("check_stderr") or status.get("reconnect_stderr") or ""
    st.session_state["graph_last_return_code"] = status.get("check_return_code") if "check_return_code" in status else status.get("reconnect_return_code")


def _render_command_output(title: str, status: dict[str, Any], prefix: str) -> None:
    import streamlit as st

    stdout = status.get(f"{prefix}_stdout") or ""
    stderr = status.get(f"{prefix}_stderr") or ""
    return_code = status.get(f"{prefix}_return_code")
    timed_out = status.get(f"{prefix}_timed_out")
    started = status.get(f"{prefix}_started")
    with st.expander(title, expanded=bool(stdout or stderr or timed_out or started is False)):
        st.write(f"Return code: `{return_code}`")
        if started is False:
            st.error("PowerShell command failed to start.")
        if timed_out:
            st.warning("Reconnect did not complete. Try reconnecting Microsoft Graph again or run the manual command in PowerShell.")
        st.markdown("**stdout**")
        st.code(stdout or "No stdout captured.", language="text")
        st.markdown("**stderr**")
        st.code(stderr or "No stderr captured.", language="text")


def _sanitized_command_summary(status: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {
        "return_code": status.get(f"{prefix}_return_code"),
        "status": status.get("status") or "Unknown",
        "account": status.get("account") or "Not connected",
        "tenant_id": status.get("tenant_id") or "Unknown",
        "tenant_display_name": status.get("tenant_display_name") or "Unknown",
        "error": status.get("error") or "",
    }


def _scope_profiles() -> dict[str, list[str]]:
    return {
        "Base read": ["Directory.Read.All", "AuditLog.Read.All", "Policy.Read.All"],
        "Identity validation": ["Directory.Read.All", "AuditLog.Read.All", "Policy.Read.All", "User.ReadWrite.All"],
        "Guest invitation": SCENARIO_REQUIRED_SCOPES["ID-DV-005"],
        "Device validation": ["Directory.Read.All", "Device.Read.All", "AuditLog.Read.All"],
        "SharePoint validation": ["Sites.ReadWrite.All", "Files.ReadWrite.All", "Directory.Read.All"],
        "App registration validation": ["Application.ReadWrite.All", "Directory.Read.All"],
    }


def render_connection_center(default_scopes: list[str] | None = None) -> None:
    import streamlit as st

    _connection_center_css()
    st.markdown("### Microsoft Graph / Tenant Connection")
    scopes = list(default_scopes or ["Directory.Read.All", "AuditLog.Read.All", "Policy.Read.All", "User.Read.All"])
    status = st.session_state.get("graph_connection_status") or _with_saved_ui_state(get_graph_context())
    render_graph_connection_summary(status)
    col_check, col_reconnect, col_disconnect = st.columns(3)
    if col_reconnect.button("Connect Microsoft Graph", use_container_width=True, type="primary"):
        with st.spinner("Opening Microsoft Graph login..."):
            result = connect_graph(scopes)
        _sync_graph_session_state(result)
        st.rerun()
    if col_check.button("Check connection", use_container_width=True):
        with st.spinner("Checking Microsoft Graph connection..."):
            checked = check_graph_connection()
        _sync_graph_session_state(checked)
        st.rerun()
    if col_disconnect.button("Disconnect Microsoft Graph", use_container_width=True):
        _sync_graph_session_state(disconnect_graph())
        st.rerun()
    with st.expander("Advanced output", expanded=False):
        st.markdown("**Connection check output**")
        st.json(_sanitized_command_summary(status, "check"), expanded=False)
        st.markdown("**Connect output**")
        st.json(_sanitized_command_summary(status, "reconnect"), expanded=False)
        with st.expander("Raw debug output", expanded=False):
            st.markdown("**Connection check stdout**")
            st.code(status.get("check_stdout") or "No stdout captured.", language="text")
            st.markdown("**Connection check stderr**")
            st.code(status.get("check_stderr") or "No stderr captured.", language="text")
            st.markdown("**Connect stdout**")
            st.code(status.get("reconnect_stdout") or "No stdout captured.", language="text")
            st.markdown("**Connect stderr**")
            st.code(status.get("reconnect_stderr") or "No stderr captured.", language="text")
