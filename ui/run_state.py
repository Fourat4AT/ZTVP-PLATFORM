from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVE_STATUSES = {"armed", "script_generated", "local_evidence_imported", "running", "polling"}
FINAL_STATUSES = {"completed", "timeout", "error", "cancelled", "stale"}
ALLOWED_VERDICTS = {"PASS", "PARTIAL", "FAIL", "NOT_RUN", "ERROR", "CANCELLED", "UNSUPPORTED", None}


SCENARIO_ROUTE_ALIASES = {
    "APP-C-002": "APP-DV-002",
    "APP-C-003": "APP-DV-003",
    "CLD-C-001": "APP-DV-008",
    "CLD-DV-001": "APP-DV-008",
    "DEV-DV-006": "DEV-DV-003",
    "DEV-DV-008": "DEV-DV-004",
    "ID-C-001": "ID-DV-001",
    "ID-C-002": "ID-DV-002",
    "ID-C-003": "ID-DV-003",
    "ID-C-004": "ID-DV-004",
    "ID-C-005": "ID-DV-005",
}


SCENARIO_ROUTE_MAP = {
    "DEV-DV-001": {"pillar": "Devices", "scope": "Cloud", "scenario_id": "DEV-DV-001"},
    "DEV-DV-002": {"pillar": "Devices", "scope": "Cloud", "scenario_id": "DEV-DV-002"},
    "DEV-DV-003": {"pillar": "Devices", "scope": "Cloud", "scenario_id": "DEV-DV-003"},
    "DEV-DV-004": {"pillar": "Devices", "scope": "Cloud", "scenario_id": "DEV-DV-004"},
    "APP-DV-002": {"pillar": "Applications", "scope": "Cloud", "scenario_id": "APP-DV-002"},
    "APP-DV-003": {"pillar": "Applications", "scope": "Cloud", "scenario_id": "APP-DV-003"},
    "APP-DV-004": {"pillar": "Applications", "scope": "Cloud", "scenario_id": "APP-DV-004"},
    "APP-DV-007": {"pillar": "Applications", "scope": "Cloud", "scenario_id": "APP-DV-007"},
    "APP-DV-008": {"pillar": "Applications", "scope": "Cloud", "scenario_id": "APP-DV-008"},
    "ID-DV-001": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-001"},
    "ID-DV-002": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-002"},
    "ID-DV-003": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-003"},
    "ID-DV-004": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-004"},
    "ID-DV-005": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-005"},
    "ID-DV-006": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-006"},
    "ID-DV-007": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-007"},
    "ID-DV-008": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-008"},
    "ID-DV-009": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-009"},
    "ID-DV-010": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-010"},
    "ID-DV-011": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-011"},
    "ID-DV-012": {"pillar": "Identity", "scope": "Cloud", "scenario_id": "ID-DV-012"},
}


def canonical_device_scenario_id(scenario_id: object, scenario_name: object = "") -> str:
    sid = str(scenario_id or "").upper().strip()
    name = str(scenario_name or "").lower()
    if "sandbox" in name and ("device registration" in name or "registration abuse" in name):
        return "DEV-DV-002"
    if "eicar" in name:
        return "DEV-DV-003"
    if "tamper" in name:
        return "DEV-DV-004"
    if sid == "DEV-DV-006":
        return "DEV-DV-003"
    if sid == "DEV-DV-008":
        return "DEV-DV-004"
    return SCENARIO_ROUTE_ALIASES.get(sid, sid)


def _run_matches_scenario(run: dict[str, Any], scenario_id: str) -> bool:
    wanted = canonical_device_scenario_id(scenario_id)
    run_sid = canonical_device_scenario_id(run.get("scenario_id"), run.get("scenario_name"))
    return run_sid == wanted


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def active_runs_dir(project_root: Path | str) -> Path:
    return Path(project_root) / "powershell" / "Reports" / "ActiveRuns"


def run_state_path(project_root: Path | str, run_id: str) -> Path:
    return active_runs_dir(project_root) / f"{run_id}.json"


def new_run_id(scenario_id: str) -> str:
    prefix = "".join(ch.lower() for ch in scenario_id if ch.isalnum()) or "run"
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return normalize_run_state(json.loads(path.read_text(encoding="utf-8-sig")))
    except Exception:
        return {}


def is_result_json_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith("-result.json") or name.endswith("result.json") or name.endswith("report.json")


def is_run_state_payload(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    required = ["run_id", "scenario_id", "status"]
    if not all(payload.get(key) not in [None, ""] for key in required):
        return False
    if "report_path" in payload or "poll_attempts" in payload or "progress_percent" in payload or "current_message" in payload:
        return True
    # Scenario reports also have run_id/scenario_id/status, but they do not carry Active Runs state fields.
    return False


def verdict_from_result_code(value: object) -> str | None:
    text = str(value or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("PARTIAL"):
        return "PARTIAL"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("NOT_RUN"):
        return "NOT_RUN"
    if text.startswith("ERROR"):
        return "ERROR"
    if text.startswith("CANCEL"):
        return "CANCELLED"
    if text.startswith("UNSUPPORTED"):
        return "UNSUPPORTED"
    return None


def _invalid_path_value(value: object) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return text in {"", ".", "None", "none", "null", "NULL"}


def normalize_run_state(state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {}
    normalized = dict(state)
    status_text = str(normalized.get("status") or "").strip()
    status_lower = status_text.lower()
    verdict = normalized.get("verdict")
    result_code = normalized.get("result_code")

    if status_text.upper().startswith(("PASS", "PARTIAL", "FAIL", "NOT_RUN")):
        normalized["result_code"] = result_code or status_text
        normalized["status"] = "completed"
        normalized["verdict"] = verdict or verdict_from_result_code(status_text)
    elif status_lower in {"queued"}:
        normalized["status"] = "polling"
    elif status_lower in {"stopped"}:
        normalized["status"] = "stale"
    elif status_lower in ACTIVE_STATUSES or status_lower in FINAL_STATUSES:
        normalized["status"] = status_lower
    elif status_text:
        normalized["status"] = status_lower
    else:
        normalized["status"] = "stale"

    if normalized.get("status") == "error" and not normalized.get("verdict"):
        normalized["verdict"] = "ERROR"
    if normalized.get("status") == "cancelled":
        normalized["verdict"] = "CANCELLED"
    if normalized.get("verdict") not in ALLOWED_VERDICTS:
        normalized["verdict"] = verdict_from_result_code(normalized.get("verdict"))
    if normalized.get("status") in FINAL_STATUSES:
        normalized["progress_percent"] = 100
    if not normalized.get("report_path") and normalized.get("report_json_path"):
        normalized["report_path"] = normalized.get("report_json_path")
    if not normalized.get("report_json_path") and normalized.get("report_path"):
        normalized["report_json_path"] = normalized.get("report_path")
    if not normalized.get("html_report_path") and normalized.get("report_html_path"):
        normalized["html_report_path"] = normalized.get("report_html_path")
    if not normalized.get("report_html_path") and normalized.get("html_report_path"):
        normalized["report_html_path"] = normalized.get("html_report_path")
    if not normalized.get("final_summary") and normalized.get("current_message"):
        normalized["final_summary"] = normalized.get("current_message")
    if not normalized.get("monitoring_window_minutes") and normalized.get("wait_minutes") is not None:
        normalized["monitoring_window_minutes"] = normalized.get("wait_minutes")
    if not normalized.get("retry_interval_seconds") and normalized.get("poll_seconds") is not None:
        normalized["retry_interval_seconds"] = normalized.get("poll_seconds")

    for path_key in ("report_path", "report_json_path", "html_report_path", "report_html_path", "details_path"):
        raw_path = normalized.get(path_key)
        if _invalid_path_value(raw_path):
            normalized[path_key] = None
            continue
        try:
            path = Path(str(raw_path))
            if path.exists() and not path.is_file():
                normalized[path_key] = None
        except Exception:
            normalized[path_key] = None
    return normalized


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, path)


def load_run(project_root: Path | str, run_id: str) -> dict[str, Any]:
    return normalize_run_state(read_json(run_state_path(project_root, run_id)))


def save_run(project_root: Path | str, state: dict[str, Any]) -> None:
    state = normalize_run_state(state)
    state["last_updated_utc"] = utc_now()
    atomic_write_json(run_state_path(project_root, str(state["run_id"])), state)


def update_run(project_root: Path | str, run_id: str, **updates: Any) -> dict[str, Any]:
    state = load_run(project_root, run_id)
    if not state:
        state = {"run_id": run_id, "started_utc": utc_now()}
    state.update(updates)
    save_run(project_root, state)
    return state


def list_runs(project_root: Path | str) -> list[dict[str, Any]]:
    folder = active_runs_dir(project_root)
    if not folder.exists():
        return []
    runs = []
    for path in folder.glob("*.json"):
        if is_result_json_path(path):
            continue
        raw_state = read_json(path)
        if raw_state and is_run_state_payload(raw_state):
            state = normalize_run_state(raw_state)
            state["_path"] = str(path)
            runs.append(state)
    return sorted(runs, key=lambda item: str(item.get("started_utc") or ""), reverse=True)


def find_runs(project_root: Path | str, scenario_id: str | None = None, statuses: set[str] | None = None) -> list[dict[str, Any]]:
    runs = list_runs(project_root)
    if scenario_id:
        runs = [run for run in runs if _run_matches_scenario(run, scenario_id)]
    if statuses:
        runs = [run for run in runs if str(run.get("status") or "").lower() in statuses]
    return runs


def latest_run_for_scenario(project_root: Path | str, scenario_id: str) -> dict[str, Any] | None:
    matches = find_runs(project_root, scenario_id=scenario_id)
    return matches[0] if matches else None


def selected_run_for_scenario(project_root: Path | str, scenario_id: str, run_id: str | None = None) -> dict[str, Any] | None:
    requested = str(run_id or "").strip()
    aliases = {
        "DEV-DV-002": {"DEV-DV-002"},
        "DEV-DV-003": {"DEV-DV-003"},
        "DEV-DV-004": {"DEV-DV-004"},
        "DEV-DV-006": {"DEV-DV-003"},
        "DEV-DV-008": {"DEV-DV-004"},
        "APP-DV-003": {"APP-DV-003", "APP-C-003"},
        "APP-C-003": {"APP-DV-003", "APP-C-003"},
        "APP-DV-002": {"APP-DV-002", "APP-C-002"},
        "APP-C-002": {"APP-DV-002", "APP-C-002"},
        "APP-DV-008": {"APP-DV-008", "CLD-DV-001", "CLD-C-001"},
        "CLD-DV-001": {"APP-DV-008", "CLD-DV-001", "CLD-C-001"},
        "CLD-C-001": {"APP-DV-008", "CLD-DV-001", "CLD-C-001"},
        "ID-DV-001": {"ID-DV-001", "ID-C-001"},
        "ID-C-001": {"ID-DV-001", "ID-C-001"},
        "ID-DV-002": {"ID-DV-002", "ID-C-002"},
        "ID-C-002": {"ID-DV-002", "ID-C-002"},
        "ID-DV-003": {"ID-DV-003", "ID-C-003"},
        "ID-C-003": {"ID-DV-003", "ID-C-003"},
        "ID-DV-005": {"ID-DV-005", "ID-C-005"},
        "ID-C-005": {"ID-DV-005", "ID-C-005"},
    }
    wanted = aliases.get(str(scenario_id or "").upper(), {canonical_device_scenario_id(scenario_id)})
    if requested:
        run = load_run(project_root, requested)
        if run and canonical_device_scenario_id(run.get("scenario_id"), run.get("scenario_name")) in wanted:
            return run
    for candidate in wanted:
        run = latest_run_for_scenario(project_root, candidate)
        if run:
            return run
    return None


def request_cancel(project_root: Path | str, run_id: str) -> dict[str, Any]:
    return update_run(
        project_root,
        run_id,
        status="cancelled",
        verdict="CANCELLED",
        phase="Cancelled",
        cancel_requested=True,
        progress_percent=100,
        current_message="Run cancelled by user.",
        completed_utc=utc_now(),
    )


def remove_run(project_root: Path | str, run_id: str) -> bool:
    path = run_state_path(project_root, run_id)
    if path.exists():
        path.unlink()
        return True
    return False


def is_stale(state: dict[str, Any]) -> bool:
    status = str(state.get("status") or "").lower()
    if status == "stale":
        return True
    if status not in ACTIVE_STATUSES:
        return False
    last_updated = str(state.get("last_updated_utc") or state.get("started_utc") or "")
    try:
        last_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return True
    age_seconds = (datetime.now(timezone.utc) - last_dt).total_seconds()
    poll_seconds = int(state.get("poll_seconds") or 30)
    stale_after = max(300, poll_seconds * 2)
    return age_seconds > stale_after


def scenario_nav_key(scenario_id: str) -> str:
    route = scenario_route(scenario_id)
    if not route:
        return ""
    sid = route["scenario_id"]
    runtime_id = {
        "APP-DV-002": "APP-C-002",
        "APP-DV-003": "APP-C-003",
        "APP-DV-008": "CLD-C-001",
        "ID-DV-001": "ID-C-001",
        "ID-DV-002": "ID-C-002",
        "ID-DV-003": "ID-C-003",
        "ID-DV-004": "ID-C-004",
        "ID-DV-005": "ID-C-005",
    }.get(sid, sid)
    names = {
        "DEV-DV-001": "Unmanaged Device Cloud Access Probe",
        "DEV-DV-002": "Sandbox Device Registration Abuse Probe",
        "DEV-DV-003": "Defender EICAR Detection Validation",
        "DEV-DV-004": "Hybrid Tamper Protection Validation",
        "APP-DV-002": "Exchange External Mail Forwarding Exposure Validation",
        "APP-DV-003": "MDCA Public File Sharing Detection Validation",
        "APP-DV-004": "Sensitive App Access From Unmanaged Device Probe",
        "APP-DV-007": "App Registration Permission Probe",
        "APP-DV-008": "SharePoint Anonymous Sharing Link Exposure Validation",
        "ID-DV-001": "Privileged Access MFA Enforcement Validation",
        "ID-DV-002": "Device Code Flow Block Validation",
        "ID-DV-003": "Controlled Legacy Authentication Exposure Validation",
        "ID-DV-004": "OAuth App Consent Exposure Validation",
        "ID-DV-005": "External Guest Admin Portal Block Validation",
        "ID-DV-006": "User Consent Enforcement Probe",
        "ID-DV-007": "App Registration Permission Probe",
        "ID-DV-008": "Risk-Based Access Enforcement Probe",
        "ID-DV-009": "PIM Role Activation Enforcement Probe",
        "ID-DV-010": "Break-Glass Monitoring Probe",
        "ID-DV-011": "Disabled Synced Account Cloud Access Probe",
        "ID-DV-012": "MDI Suspicious Identity Activity Probe",
    }
    return f"{route['pillar']}|{route['scope']}|{sid}|{runtime_id}|{names.get(sid, sid)}"


def scenario_route(scenario_id: str) -> dict[str, str] | None:
    sid = str(scenario_id or "").upper().strip()
    sid = SCENARIO_ROUTE_ALIASES.get(sid, sid)
    route = SCENARIO_ROUTE_MAP.get(sid)
    return dict(route) if route else None
