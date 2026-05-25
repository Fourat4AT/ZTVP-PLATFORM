from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from background_jobs import is_live, start_scenario_job
from run_state import ACTIVE_STATUSES, is_stale, list_runs, remove_run, request_cancel, scenario_nav_key, update_run


def _tone(status: str) -> str:
    status = status.lower()
    if status == "completed":
        return "complete"
    if status == "error":
        return "error"
    return "running"


def _open_scenario(scenario_id: str) -> None:
    nav_key = scenario_nav_key(scenario_id)
    if nav_key:
        st.session_state.main_navigation = "Home"
        st.session_state.home_mode = "dynamic"
        st.session_state["ztvp_dynamic_open_scenario"] = nav_key


def _render_run(project_root: Path, run: dict) -> None:
    run_id = str(run.get("run_id") or "")
    scenario_id = str(run.get("scenario_id") or "")
    status = str(run.get("status") or "unknown")
    stale = is_stale(run) and not is_live(run_id)
    title = f"{scenario_id} - {run.get('scenario_name') or 'Scenario'}"

    with st.container(border=True):
        cols = st.columns([0.34, 0.16, 0.14, 0.18, 0.18])
        with cols[0]:
            st.markdown(f"**{title}**")
            st.caption(run_id)
        with cols[1]:
            st.status("Stale / interrupted" if stale else status.title(), state=_tone("error" if stale else status))
        with cols[2]:
            st.metric("Progress", f"{int(run.get('progress_percent') or 0)}%")
        with cols[3]:
            st.metric("Polls", f"{run.get('poll_attempts') or 0} / {run.get('max_poll_attempts') or 0}")
        with cols[4]:
            st.metric("Verdict", run.get("verdict") or "-")

        st.progress(max(0, min(100, int(run.get("progress_percent") or 0))))
        st.write(run.get("current_message") or run.get("phase") or "")
        st.caption(
            f"Target: {run.get('target') or 'N/A'} | Tenant: {run.get('tenant') or 'N/A'} | "
            f"Local evidence: {run.get('local_evidence_status') or 'Unknown'} | "
            f"Tenant evidence: {run.get('tenant_evidence_status') or 'Unknown'}"
        )
        if run.get("error"):
            with st.expander("Error / logs", expanded=False):
                st.code(str(run.get("error")), language="text")

        action_cols = st.columns(5)
        with action_cols[0]:
            if st.button("Open scenario", key=f"open_{run_id}", use_container_width=True):
                _open_scenario(scenario_id)
                st.rerun()
        with action_cols[1]:
            report_path = Path(str(run.get("report_path") or ""))
            if report_path.exists():
                st.download_button(
                    "View report",
                    report_path.read_bytes(),
                    report_path.name,
                    "application/json",
                    key=f"report_{run_id}",
                    use_container_width=True,
                )
            else:
                st.button("View report", key=f"report_disabled_{run_id}", use_container_width=True, disabled=True)
        with action_cols[2]:
            if status.lower() in ACTIVE_STATUSES:
                if st.button("Cancel", key=f"cancel_{run_id}", use_container_width=True):
                    request_cancel(project_root, run_id)
                    st.rerun()
            else:
                st.button("Cancel", key=f"cancel_disabled_{run_id}", use_container_width=True, disabled=True)
        with action_cols[3]:
            if stale:
                if st.button("Resume polling", key=f"resume_{run_id}", use_container_width=True):
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
                st.button("Resume polling", key=f"resume_disabled_{run_id}", use_container_width=True, disabled=True)
        with action_cols[4]:
            if status.lower() in ACTIVE_STATUSES and stale:
                if st.button("Mark stopped", key=f"stop_{run_id}", use_container_width=True):
                    update_run(
                        project_root,
                        run_id,
                        status="stopped",
                        phase="Stopped",
                        current_message="Run marked stopped after the background job was interrupted.",
                    )
                    st.rerun()
            elif status.lower() not in ACTIVE_STATUSES:
                if st.button("Remove", key=f"remove_{run_id}", use_container_width=True):
                    remove_run(project_root, run_id)
                    st.rerun()
            else:
                st.button("Remove", key=f"remove_disabled_{run_id}", use_container_width=True, disabled=True)


def render_active_runs_page(project_root: Path | str, hero=None) -> None:
    project_root = Path(project_root)
    if hero:
        hero("Active Runs", "Monitor background validation runs, cancel polling, resume stale runs, and open completed reports.")
    else:
        st.title("Active Runs")

    runs = list_runs(project_root)
    if not runs:
        st.info("No active run files exist yet. Start tenant evidence analysis from a scenario page.")
        return

    rows = [
        {
            "Scenario": run.get("scenario_id"),
            "Status": "Stale / interrupted" if is_stale(run) and not is_live(str(run.get("run_id") or "")) else run.get("status"),
            "Verdict": run.get("verdict") or "",
            "Progress": f"{int(run.get('progress_percent') or 0)}%",
            "Polls": f"{run.get('poll_attempts') or 0}/{run.get('max_poll_attempts') or 0}",
            "Updated UTC": run.get("last_updated_utc"),
        }
        for run in runs
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    active = [run for run in runs if str(run.get("status") or "").lower() in ACTIVE_STATUSES]
    completed = [run for run in runs if str(run.get("status") or "").lower() == "completed"]
    failed = [run for run in runs if str(run.get("status") or "").lower() in {"error", "cancelled", "stopped"}]

    tab_active, tab_completed, tab_failed = st.tabs(["Active", "Completed", "Failed / Cancelled"])
    with tab_active:
        if not active:
            st.caption("No running or polling scenarios.")
        for run in active:
            _render_run(project_root, run)
    with tab_completed:
        if not completed:
            st.caption("No completed scenarios yet.")
        for run in completed:
            _render_run(project_root, run)
    with tab_failed:
        if not failed:
            st.caption("No failed, cancelled, or stopped scenarios.")
        for run in failed:
            _render_run(project_root, run)
