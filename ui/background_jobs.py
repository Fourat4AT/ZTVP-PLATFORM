from __future__ import annotations

import math
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_state import ACTIVE_STATUSES, latest_run_for_scenario, load_run, new_run_id, save_run, update_run, utc_now


_REGISTRY_LOCK = threading.Lock()
_REGISTRY: dict[str, subprocess.Popen[str] | None] = {}


SCENARIOS = {
    "DEV-DV-006": {
        "name": "Defender EICAR Detection Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV006.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006" / "devdv006-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006" / "devdv006-local-evidence.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-006-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "DEV-DV-006-result.html",
    },
    "DEV-DV-008": {
        "name": "Hybrid Tamper Protection Validation",
        "script": Path("powershell") / "Engines" / "DynamicValidation" / "Analyze-ZTVP-DEVDV008.ps1",
        "state": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008" / "devdv008-state.json",
        "local_evidence": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008" / "devdv008-local-evidence.json",
        "report": Path("powershell") / "Reports" / "Dynamic" / "DEV-DV-008-result.json",
        "html": Path("powershell") / "Reports" / "Dynamic" / "Html" / "DEV-DV-008-result.html",
    },
}


def _read_json(path: Path) -> dict[str, Any]:
    import json

    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def _powershell_exe() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    win_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(win_ps) if win_ps.exists() else "powershell.exe"


def _verdict_from_status(status: object) -> str | None:
    text = str(status or "").upper()
    if text.startswith("PASS"):
        return "PASS"
    if text.startswith("PARTIAL"):
        return "PARTIAL"
    if text.startswith("FAIL"):
        return "FAIL"
    if text.startswith("NOT_RUN"):
        return "PARTIAL"
    return None


def _local_status(local_evidence: dict[str, Any], scenario_id: str) -> str:
    if not local_evidence:
        return "Missing"
    summary = local_evidence.get("local_summary") or {}
    if scenario_id == "DEV-DV-008" and summary.get("settings_weakened") is True:
        return "Settings weakened"
    return "Found"


def _tenant_status(report: dict[str, Any]) -> str:
    tenant_api = ((report.get("evidence") or {}).get("tenant") or {}).get("api") or {}
    if tenant_api.get("mde_cloud_evidence_found"):
        return "Found"
    return str(tenant_api.get("mde_cloud_query_status") or "Waiting")


def _target_from_state(scenario_state: dict[str, Any], local_evidence: dict[str, Any]) -> str:
    return str(scenario_state.get("test_device_name") or local_evidence.get("computer_name") or "").strip()


def _tenant_from_state(scenario_state: dict[str, Any]) -> str:
    return str(scenario_state.get("tenant_display_name") or scenario_state.get("tenant_id") or "").strip()


def _max_attempts(wait_minutes: int, poll_seconds: int) -> int:
    if wait_minutes <= 0:
        return 1
    return max(1, int(math.ceil((wait_minutes * 60) / max(1, poll_seconds))))


def is_live(run_id: str) -> bool:
    with _REGISTRY_LOCK:
        proc = _REGISTRY.get(run_id)
    return proc is not None and proc.poll() is None


def get_active_run(project_root: Path | str, scenario_id: str) -> dict[str, Any] | None:
    run = latest_run_for_scenario(project_root, scenario_id)
    if run and str(run.get("status") or "").lower() in ACTIVE_STATUSES:
        return run
    return None


def start_scenario_job(
    project_root: Path | str,
    scenario_id: str,
    wait_minutes: int,
    poll_seconds: int,
    run_id: str | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    project_root = Path(project_root)
    scenario_id = scenario_id.upper()
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Background jobs are not wired for {scenario_id}.")

    existing = get_active_run(project_root, scenario_id)
    if existing and not resume:
        return existing

    run_id = run_id or (str(existing.get("run_id")) if resume and existing else new_run_id(scenario_id))
    if is_live(run_id):
        return load_run(project_root, run_id)

    meta = SCENARIOS[scenario_id]
    scenario_state = _read_json(project_root / meta["state"])
    local_evidence = _read_json(project_root / meta["local_evidence"])
    max_attempts = _max_attempts(wait_minutes, poll_seconds)
    now = utc_now()
    state = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario_name": meta["name"],
        "status": "queued",
        "phase": "Waiting for tenant evidence",
        "verdict": None,
        "started_utc": now if not resume else load_run(project_root, run_id).get("started_utc", now),
        "last_updated_utc": now,
        "wait_minutes": int(wait_minutes),
        "poll_seconds": int(poll_seconds),
        "poll_attempts": 0,
        "max_poll_attempts": max_attempts,
        "progress_percent": 0,
        "target": _target_from_state(scenario_state, local_evidence),
        "tenant": _tenant_from_state(scenario_state),
        "local_evidence_status": _local_status(local_evidence, scenario_id),
        "tenant_evidence_status": "Waiting",
        "current_message": "Scenario run started. You can leave this page. ZTVP will keep polling in the background and update Active Runs.",
        "report_path": None,
        "html_report_path": None,
        "error": None,
        "cancel_requested": False,
        "resume_count": int(load_run(project_root, run_id).get("resume_count") or 0) + (1 if resume else 0),
    }
    save_run(project_root, state)

    thread = threading.Thread(
        target=_run_job,
        args=(project_root, scenario_id, run_id, int(wait_minutes), int(poll_seconds)),
        daemon=True,
        name=f"ztvp-{scenario_id}-{run_id}",
    )
    with _REGISTRY_LOCK:
        _REGISTRY[run_id] = None
    thread.start()
    return state


def _run_job(project_root: Path, scenario_id: str, run_id: str, wait_minutes: int, poll_seconds: int) -> None:
    meta = SCENARIOS[scenario_id]
    script_path = project_root / meta["script"]
    report_path = project_root / meta["report"]
    html_path = project_root / meta["html"]
    max_attempts = _max_attempts(wait_minutes, poll_seconds)
    started = datetime.now(timezone.utc)
    proc: subprocess.Popen[str] | None = None
    stdout = ""
    stderr = ""

    try:
        update_run(
            project_root,
            run_id,
            status="polling",
            poll_attempts=1,
            progress_percent=1,
            current_message=f"Waiting for tenant evidence. Attempt 1 of {max_attempts}.",
        )
        proc = subprocess.Popen(
            [
                _powershell_exe(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-WaitMinutes",
                str(wait_minutes),
                "-PollSeconds",
                str(poll_seconds),
            ],
            cwd=str(project_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with _REGISTRY_LOCK:
            _REGISTRY[run_id] = proc

        while proc.poll() is None:
            current = load_run(project_root, run_id)
            if current.get("cancel_requested"):
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate(timeout=10)
                update_run(
                    project_root,
                    run_id,
                    status="cancelled",
                    verdict=None,
                    progress_percent=int(current.get("progress_percent") or 0),
                    current_message="Run cancelled by user",
                    error=None,
                )
                return

            elapsed = max(0, (datetime.now(timezone.utc) - started).total_seconds())
            attempt = min(max_attempts, max(1, int(elapsed // max(1, poll_seconds)) + 1))
            progress = min(95, int((attempt / max_attempts) * 100))
            update_run(
                project_root,
                run_id,
                status="polling",
                poll_attempts=attempt,
                progress_percent=progress,
                current_message=f"Waiting for tenant evidence. Attempt {attempt} of {max_attempts}.",
            )
            time.sleep(2)

        stdout, stderr = proc.communicate(timeout=10)
        if proc.returncode != 0:
            update_run(
                project_root,
                run_id,
                status="error",
                phase="Error",
                error=(stderr or stdout or f"PowerShell exited with {proc.returncode}")[-6000:],
                current_message="Run stopped because an error occurred.",
            )
            return

        report = _read_json(report_path)
        verdict = _verdict_from_status(report.get("status"))
        archived_report_path = report_path
        archived_html_path = html_path
        active_dir = project_root / "powershell" / "Reports" / "ActiveRuns"
        active_dir.mkdir(parents=True, exist_ok=True)
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
            poll_attempts=int((((report.get("evidence") or {}).get("tenant") or {}).get("api") or {}).get("mde_cloud_poll_attempts") or max_attempts),
            progress_percent=100,
            tenant_evidence_status=_tenant_status(report),
            current_message=f"Run completed. Verdict: {verdict or 'Unknown'}.",
            report_path=str(archived_report_path) if archived_report_path.exists() else None,
            html_report_path=str(archived_html_path) if archived_html_path.exists() else None,
            error=None,
        )
    except Exception as exc:
        update_run(
            project_root,
            run_id,
            status="error",
            phase="Error",
            error=str(exc),
            current_message="Run stopped because an error occurred.",
        )
    finally:
        with _REGISTRY_LOCK:
            _REGISTRY.pop(run_id, None)
