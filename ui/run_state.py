from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVE_STATUSES = {"queued", "running", "polling"}
FINAL_STATUSES = {"completed", "error", "cancelled", "stopped"}


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
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, path)


def load_run(project_root: Path | str, run_id: str) -> dict[str, Any]:
    return read_json(run_state_path(project_root, run_id))


def save_run(project_root: Path | str, state: dict[str, Any]) -> None:
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
        state = read_json(path)
        if state:
            state["_path"] = str(path)
            runs.append(state)
    return sorted(runs, key=lambda item: str(item.get("started_utc") or ""), reverse=True)


def find_runs(project_root: Path | str, scenario_id: str | None = None, statuses: set[str] | None = None) -> list[dict[str, Any]]:
    runs = list_runs(project_root)
    if scenario_id:
        runs = [run for run in runs if str(run.get("scenario_id") or "").upper() == scenario_id.upper()]
    if statuses:
        runs = [run for run in runs if str(run.get("status") or "").lower() in statuses]
    return runs


def latest_run_for_scenario(project_root: Path | str, scenario_id: str) -> dict[str, Any] | None:
    matches = find_runs(project_root, scenario_id=scenario_id)
    return matches[0] if matches else None


def request_cancel(project_root: Path | str, run_id: str) -> dict[str, Any]:
    return update_run(
        project_root,
        run_id,
        cancel_requested=True,
        current_message="Cancel requested. Waiting for the background job to stop.",
    )


def remove_run(project_root: Path | str, run_id: str) -> bool:
    path = run_state_path(project_root, run_id)
    if path.exists():
        path.unlink()
        return True
    return False


def is_stale(state: dict[str, Any]) -> bool:
    status = str(state.get("status") or "").lower()
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
    return {
        "DEV-DV-006": "Devices|Cloud|DEV-DV-006|DEV-DV-006|Defender EICAR Detection Validation",
        "DEV-DV-008": "Devices|Cloud|DEV-DV-008|DEV-DV-008|Hybrid Tamper Protection Validation",
    }.get(str(scenario_id).upper(), "")
