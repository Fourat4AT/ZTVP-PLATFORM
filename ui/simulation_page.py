
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import streamlit as st


def _inject_simulation_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: #f4f7fb !important;
        }

        .block-container {
            padding-top: 1.4rem !important;
            max-width: 1180px !important;
        }

        .ztvp-hero {
            background: linear-gradient(120deg, #0f172a 0%, #1d4ed8 100%);
            color: white !important;
            padding: 1.4rem 1.5rem;
            border-radius: 20px;
            margin-bottom: 1.1rem;
            box-shadow: 0 18px 36px rgba(30, 64, 175, 0.22);
        }

        .ztvp-hero-title {
            color: white !important;
            font-size: 1.35rem;
            font-weight: 900;
            margin-bottom: 0.35rem;
        }

        .ztvp-hero-subtitle {
            color: #dbeafe !important;
            font-size: 0.94rem;
            font-weight: 650;
            margin: 0;
        }

        .ztvp-mini-card {
            background: #ffffff;
            border: 1px solid #dbe3ef;
            border-radius: 16px;
            padding: 1rem;
            min-height: 112px;
            box-shadow: 0 8px 20px rgba(15, 23, 42, 0.045);
        }

        .ztvp-mini-title {
            color: #0f172a !important;
            font-weight: 900;
            font-size: 0.95rem;
            margin-bottom: 0.35rem;
        }

        .ztvp-mini-text {
            color: #475569 !important;
            font-weight: 600;
            font-size: 0.86rem;
            line-height: 1.35;
        }

        .ztvp-section-title {
            color: #0f172a !important;
            font-size: 1.25rem;
            font-weight: 950;
            margin: 1.25rem 0 0.65rem 0;
        }

        .ztvp-section-subtitle {
            color: #475569 !important;
            font-size: 0.9rem;
            font-weight: 650;
            margin: -0.25rem 0 1rem 0;
        }

        .ztvp-warning {
            background: #fffbeb;
            border: 1px solid #f59e0b;
            color: #7c2d12 !important;
            border-radius: 14px;
            padding: 0.85rem 1rem;
            font-weight: 700;
            margin: 1rem 0;
        }

        .ztvp-safe {
            background: #ecfdf5;
            border-left: 5px solid #10b981;
            color: #064e3b !important;
            border-radius: 12px;
            padding: 0.8rem 1rem;
            font-weight: 800;
            margin: 1rem 0;
        }

        .ztvp-label {
            color: #0f172a !important;
            font-size: 0.82rem;
            font-weight: 900;
            margin: 0.25rem 0 0.32rem 0;
        }

        .ztvp-result-card {
            background: #ffffff;
            border: 1px solid #dbe3ef;
            border-radius: 18px;
            padding: 1rem 1.1rem;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.055);
            margin: 0.75rem 0;
        }

        .ztvp-decision {
            background: #ffffff;
            border: 1px solid #dbe3ef;
            border-left: 7px solid #2563eb;
            border-radius: 18px;
            padding: 1.1rem 1.25rem;
            box-shadow: 0 12px 26px rgba(15, 23, 42, 0.07);
            margin: 1rem 0;
        }

        .ztvp-decision-high {
            border-left-color: #dc2626;
        }

        .ztvp-decision-medium {
            border-left-color: #f59e0b;
        }

        .ztvp-decision-low {
            border-left-color: #10b981;
        }

        .ztvp-decision-title {
            color: #0f172a !important;
            font-size: 1.18rem;
            font-weight: 950;
            margin-bottom: 0.35rem;
        }

        .ztvp-decision-text {
            color: #334155 !important;
            font-size: 0.93rem;
            font-weight: 650;
            line-height: 1.45;
        }

        .ztvp-badge {
            display: inline-block;
            padding: 0.28rem 0.55rem;
            border-radius: 999px;
            font-weight: 900;
            font-size: 0.78rem;
            margin-left: 0.35rem;
        }

        .ztvp-badge-high {
            background: #fee2e2;
            color: #991b1b;
        }

        .ztvp-badge-medium {
            background: #fef3c7;
            color: #92400e;
        }

        .ztvp-badge-low {
            background: #d1fae5;
            color: #065f46;
        }

        .ztvp-badge-neutral {
            background: #dbeafe;
            color: #1e40af;
        }

        .ztvp-explain {
            background: #ffffff;
            border: 1px solid #dbe3ef;
            border-radius: 14px;
            padding: 0.9rem 1rem;
            margin: 0.8rem 0;
            color: #0f172a !important;
            font-weight: 650;
        }

        .ztvp-risk-list {
            background: #fff7ed;
            border: 1px solid #fed7aa;
            border-radius: 16px;
            padding: 1rem 1.15rem;
            margin: 0.7rem 0;
            color: #7c2d12 !important;
            font-weight: 700;
        }

        .ztvp-evidence {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 16px;
            padding: 1rem 1.15rem;
            margin: 0.7rem 0;
            color: #0f172a !important;
            font-weight: 650;
        }

        [data-testid="stWidgetLabel"] {
            display: none !important;
        }

        div[data-baseweb="select"] > div,
        textarea,
        input {
            background-color: #ffffff !important;
            color: #0f172a !important;
            border: 1px solid #94a3b8 !important;
            border-radius: 11px !important;
            font-weight: 700 !important;
        }

        div[data-baseweb="select"] span,
        div[data-baseweb="select"] div {
            color: #0f172a !important;
            font-weight: 700 !important;
        }

        textarea::placeholder,
        input::placeholder {
            color: #64748b !important;
            opacity: 1 !important;
        }

        [data-testid="stCheckbox"] *,
        [data-testid="stCheckbox"] p,
        [data-testid="stCheckbox"] label {
            color: #0f172a !important;
            font-weight: 750 !important;
            opacity: 1 !important;
        }

        [data-testid="stFormSubmitButton"] button,
        .stButton > button,
        [data-testid="stDownloadButton"] button {
            background: linear-gradient(90deg, #1d4ed8, #2563eb) !important;
            color: white !important;
            border: none !important;
            border-radius: 14px !important;
            min-height: 3rem !important;
            font-weight: 950 !important;
            box-shadow: 0 12px 26px rgba(37, 99, 235, 0.25) !important;
        }

        [data-testid="stFormSubmitButton"] button *,
        .stButton > button *,
        [data-testid="stDownloadButton"] button * {
            color: white !important;
            font-weight: 950 !important;
        }

        div[data-baseweb="popover"] *,
        div[role="listbox"] *,
        ul[role="listbox"] *,
        li[role="option"] * {
            color: #0f172a !important;
            background: #ffffff !important;
            opacity: 1 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _label(text: str) -> None:
    st.markdown(f'<div class="ztvp-label">{text}</div>', unsafe_allow_html=True)


def _split_csv(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.replace("\\n", ",").split(",") if item.strip()]


def _find_powershell() -> str:
    return shutil.which("pwsh") or shutil.which("powershell") or "powershell"


def _run_engine(project_root: Path, inputs: Dict[str, Any]) -> Dict[str, Any]:
    engine = project_root / "powershell" / "Engines" / "Simulation" / "Invoke-ZTVP-CAPolicyChangeSimulation.ps1"

    if not engine.exists():
        return {
            "ok": False,
            "error": f"Simulation engine not found: {engine}",
            "stdout": "",
            "stderr": "",
            "returncode": 404,
        }

    ps = _find_powershell()

    cmd = [
        ps,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(engine),
        "-ProjectRoot",
        str(project_root),
        "-ProposedControl",
        inputs["proposed_control"],
        "-TargetScope",
        inputs["target_scope"],
        "-ResourceScope",
        inputs["resource_scope"],
        "-ClientCondition",
        inputs["client_condition"],
        "-LookbackDays",
        str(inputs["lookback_days"]),
        "-SelectedGroup",
        inputs.get("selected_group", ""),
        "-SelectedUsers",
        ",".join(inputs.get("selected_users", [])),
        "-ExcludedUsers",
        ",".join(inputs.get("excluded_users", [])),
        "-ExcludedGroups",
        ",".join(inputs.get("excluded_groups", [])),
        "-BreakGlassKeywords",
        ",".join(inputs.get("breakglass_keywords", [])),
        "-ServiceAccountKeywords",
        ",".join(inputs.get("service_keywords", [])),
    ]

    completed = subprocess.run(
        cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )

    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "cmd": cmd,
    }


def _load_json_report(project_root: Path) -> Dict[str, Any] | None:
    report_path = project_root / "powershell" / "Reports" / "Simulation" / "CA-Policy-Change-Sandbox-result.json"

    if not report_path.exists():
        return None

    try:
        return json.loads(report_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"error": f"Could not read JSON report: {exc}"}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _clean_value(value: Any) -> str:
    if value is None:
        return "Not specified"
    if isinstance(value, list):
        if not value:
            return "Not specified"
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    text = str(value)
    if not text or text.lower() == "none":
        return "Not specified"
    return text


def _impact_class(impact: str) -> str:
    value = str(impact or "").upper()
    if value == "HIGH":
        return "ztvp-decision-high"
    if value == "MEDIUM":
        return "ztvp-decision-medium"
    if value == "LOW":
        return "ztvp-decision-low"
    return ""


def _badge_class(value: str) -> str:
    value = str(value or "").upper()
    if value == "HIGH":
        return "ztvp-badge-high"
    if value == "MEDIUM":
        return "ztvp-badge-medium"
    if value == "LOW":
        return "ztvp-badge-low"
    return "ztvp-badge-neutral"


def _confidence_reason(confidence: str) -> str:
    value = str(confidence or "UNKNOWN").upper()
    if value == "HIGH":
        return "High confidence means ZTVP resolved the target scope and found enough recent tenant signals to support the prediction."
    if value == "MEDIUM":
        return "Medium confidence means ZTVP resolved useful tenant data, but some conditions may still depend on assumptions, exclusions, device state, location, or incomplete logs."
    if value == "LOW":
        return "Low confidence means ZTVP could not find enough recent or complete evidence. Review with longer lookback, report-only mode, or manual verification."
    return "Confidence explains how reliable the prediction is based on available tenant data. It is not the same as impact."


def _rollout_explanation(mode: str) -> str:
    text = str(mode or "").lower()
    if "report-only" in text:
        return "Report-only first means test the policy without enforcing it, then review sign-in impact before blocking or requiring controls."
    if "pilot" in text:
        return "Pilot first means test the policy on a small controlled group before applying it broadly to production users."
    if "lookback" in text:
        return "Extend lookback means check a longer activity window, such as 30 days, because short windows may miss infrequent usage."
    return "Rollout mode explains the safest way to test or deploy the proposed policy."


def _extract_risk_findings(report: Dict[str, Any]) -> List[str]:
    counts = report.get("counts", {})
    prediction = report.get("prediction", {})
    impact = str(prediction.get("predictedImpact", "")).upper()

    findings: List[str] = []

    if impact == "HIGH":
        findings.append("The proposed policy has HIGH impact and should not be enforced directly.")

    if counts.get("privilegedUsersInScope", 0):
        findings.append(f"{counts.get('privilegedUsersInScope')} privileged user(s) are in scope, creating administrator lockout risk.")

    if counts.get("breakGlassAccountsDetected", 0):
        findings.append(f"{counts.get('breakGlassAccountsDetected')} break-glass-like account(s) were detected and must be documented.")

    if counts.get("serviceLikeAccountsDetected", 0):
        findings.append(f"{counts.get('serviceLikeAccountsDetected')} service-like account(s) may be affected by the proposed control.")

    if counts.get("guestUsersInScope", 0):
        findings.append(f"{counts.get('guestUsersInScope')} guest/external user(s) are in scope.")

    if counts.get("overlappingPolicies", 0):
        findings.append(f"{counts.get('overlappingPolicies')} existing Conditional Access policy overlap(s) were detected.")

    if counts.get("legacyAuthSimulation") and counts.get("recentLegacyAuthenticationSignals", 0) == 0:
        findings.append("No recent legacy authentication activity was detected in the selected lookback period.")

    if not findings:
        findings.append("No major risk finding was detected from the available tenant data.")

    return findings


def _why_result(report: Dict[str, Any]) -> str:
    counts = report.get("counts", {})
    inputs = report.get("inputs", {})
    prediction = report.get("prediction", {})

    control = inputs.get("proposedControl", "the proposed control")
    target = inputs.get("targetScope", "the selected target")
    resource = inputs.get("resourceScope", "the selected resource")
    client = inputs.get("clientCondition", "the selected condition")
    impact = str(prediction.get("predictedImpact", "UNKNOWN")).upper()

    if counts.get("legacyAuthSimulation"):
        if counts.get("recentLegacyAuthenticationSignals", 0) == 0:
            return (
                f"ZTVP classified the impact as {impact} because the policy targets {counts.get('inScopeIdentities', 0)} "
                f"identity/identities, but no recent legacy authentication activity was found in the selected lookback period."
            )
        return (
            f"ZTVP classified the impact as {impact} because recent legacy authentication activity was found for "
            f"{counts.get('recentlyAffectedIdentities', counts.get('potentiallyAffectedIdentities', 0))} identity/identities."
        )

    if str(control).lower() == "block access" and str(target).lower() == "all users" and str(resource).lower() == "all cloud apps":
        return (
            f"ZTVP classified the impact as {impact} because the proposed policy blocks browser access to all cloud apps "
            f"for all users. This includes {counts.get('privilegedUsersInScope', 0)} privileged user(s), "
            f"{counts.get('guestUsersInScope', 0)} guest user(s), and {counts.get('serviceLikeAccountsDetected', 0)} service-like account(s)."
        )

    return (
        f"ZTVP classified the impact as {impact} based on the proposed control ({control}), target ({target}), "
        f"resource ({resource}), condition ({client}), in-scope identities, recent signals, and policy overlap."
    )


def _prepare_identity_rows(rows: Any) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []

    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue

        output.append(
            {
                "Display Name": row.get("displayName", ""),
                "User Principal Name": row.get("userPrincipalName", ""),
                "User Type": row.get("userType", ""),
                "Privileged": row.get("isPrivileged", False),
                "Privileged Roles": row.get("privilegedRoles", ""),
                "Guest": row.get("isGuest", False),
                "Service-like": row.get("isServiceLike", False),
                "Break-glass": row.get("isBreakGlass", False),
                "Recent Sign-ins": row.get("recentRelevantSignIns", 0),
                "Successful Sign-ins": row.get("recentSuccessfulRelevantSignIns", 0),
                "Scope Reason": row.get("scopeReason", ""),
            }
        )

    return output


def _prepare_risky_rows(rows: Any) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []

    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue

        output.append(
            {
                "Display Name": row.get("displayName", ""),
                "User Principal Name": row.get("userPrincipalName", ""),
                "User Type": row.get("userType", ""),
                "Privileged Roles": row.get("privilegedRoles", ""),
                "Risk Reasons": row.get("reasons", ""),
                "Recent Sign-ins": row.get("recentRelevantSignIns", 0),
                "Successful Sign-ins": row.get("recentSuccessfulRelevantSignIns", 0),
            }
        )

    return output


def _prepare_overlap_rows(rows: Any) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []

    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue

        output.append(
            {
                "Policy Name": row.get("policyName", ""),
                "State": row.get("state", ""),
                "Overlap": row.get("overlapType", ""),
                "Score": row.get("score", ""),
                "Grant Controls": row.get("grantControls", ""),
                "Client App Types": row.get("clientAppTypes", ""),
                "Policy ID": row.get("policyId", ""),
            }
        )

    return output


def _prepare_signal_rows(rows: Any) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []

    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue

        output.append(
            {
                "Time": row.get("createdDateTime", ""),
                "User Principal Name": row.get("userPrincipalName", ""),
                "App": row.get("appDisplayName", ""),
                "Resource": row.get("resourceDisplayName", ""),
                "Client": row.get("clientAppUsed", ""),
                "Status Code": row.get("statusCode", ""),
                "Status Reason": row.get("statusReason", ""),
            }
        )

    return output[:200]


def _show_table(title: str, rows: List[Dict[str, Any]]) -> None:
    st.markdown(f'<div class="ztvp-section-title">{title}</div>', unsafe_allow_html=True)

    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No data found for this section.")


def _write_professional_reports(project_root: Path, report: Dict[str, Any]) -> None:
    import html as _html

    json_path = project_root / "powershell" / "Reports" / "Simulation" / "CA-Policy-Change-Sandbox-result.json"
    html_path = project_root / "powershell" / "Reports" / "Simulation" / "Html" / "CA-Policy-Change-Sandbox-result.html"

    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    prediction = report.get("prediction", {})
    counts = report.get("counts", {})
    inputs = report.get("inputs", {})
    raw = report.get("rawEvaluation", {})
    recommendations = _as_list(report.get("recommendations", []))
    limitations = _as_list(report.get("limitations", []))
    risk_findings = _extract_risk_findings(report)
    why = _why_result(report)

    def esc(value: Any) -> str:
        return _html.escape(_clean_value(value))

    def rows_from_dict(data: Dict[str, Any]) -> str:
        return "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in data.items())

    rec_html = "".join(f"<li>{esc(item)}</li>" for item in recommendations)
    lim_html = "".join(f"<li>{esc(item)}</li>" for item in limitations) or "<li>No major limitation returned by the engine.</li>"
    risk_html = "".join(f"<li>{esc(item)}</li>" for item in risk_findings)

    count_rows = {
        "Predicted impact": prediction.get("predictedImpact", "UNKNOWN"),
        "Confidence": prediction.get("confidence", "UNKNOWN"),
        "In-scope identities": counts.get("inScopeIdentities", 0),
        "Potentially affected identities": counts.get("potentiallyAffectedIdentities", 0),
        "Recent relevant sign-ins": counts.get("recentRelevantSignIns", 0),
        "Privileged users": counts.get("privilegedUsersInScope", 0),
        "Guest users": counts.get("guestUsersInScope", 0),
        "Service-like accounts": counts.get("serviceLikeAccountsDetected", 0),
        "Overlapping policies": counts.get("overlappingPolicies", 0),
    }

    evidence_rows = {
        "Users read": raw.get("totalUsersRead", "Not available"),
        "Enabled users read": raw.get("enabledUsersRead", "Not available"),
        "Sign-ins read": raw.get("signInsRead", "Not available"),
        "Relevant sign-ins": raw.get("relevantSignIns", counts.get("recentRelevantSignIns", 0)),
        "Policies read": raw.get("policiesRead", "Not available"),
        "Privileged principals detected": raw.get("privilegedPrincipalIdsDetected", "Not available"),
        "Privileged UPNs detected": raw.get("privilegedUpnsDetected", "Not available"),
    }

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ZTVP Simulation Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#f8fafc; color:#0f172a; margin:32px; }}
h1 {{ margin-bottom: 8px; }}
.card {{ background:white; border:1px solid #dbe3ef; border-radius:14px; padding:18px; margin-bottom:18px; }}
.badge {{ display:inline-block; background:#dbeafe; border-radius:10px; padding:8px 12px; font-weight:bold; }}
.badge-high {{ background:#fee2e2; color:#991b1b; }}
.badge-medium {{ background:#fef3c7; color:#92400e; }}
.badge-low {{ background:#d1fae5; color:#065f46; }}
table {{ width:100%; border-collapse:collapse; margin-top: 8px; }}
td, th {{ border:1px solid #e2e8f0; padding:8px; text-align:left; }}
th {{ background:#eff6ff; }}
.warning {{ color:#7c2d12; font-weight:bold; }}
.small {{ color:#475569; }}
</style>
</head>
<body>
<h1>Simulation — Conditional Access Policy Change Sandbox</h1>
<p class="small">Simulation prediction only. No policy was created, modified, or enforced.</p>

<div class="card">
<h2>1. Executive Decision Summary</h2>
<p><strong>Predicted impact:</strong> <span class="badge badge-{esc(prediction.get('predictedImpact', 'neutral')).lower()}">{esc(prediction.get('predictedImpact', 'UNKNOWN'))}</span></p>
<p><strong>Confidence:</strong> {esc(prediction.get('confidence', 'UNKNOWN'))}</p>
<p><strong>Recommended rollout:</strong> {esc(prediction.get('recommendedRolloutMode', 'Review before enforcement'))}</p>
<p>{esc(prediction.get('summary', 'No summary returned.'))}</p>
</div>

<div class="card">
<h2>2. Why ZTVP Reached This Result</h2>
<p>{esc(why)}</p>
<p><strong>Confidence meaning:</strong> {esc(prediction.get('confidenceReason', ''))}</p>
<p><strong>Rollout meaning:</strong> {esc(prediction.get('rolloutExplanation', ''))}</p>
</div>

<div class="card">
<h2>3. Proposed Policy Summary</h2>
<table>{rows_from_dict(inputs)}</table>
</div>

<div class="card">
<h2>4. Impact Overview</h2>
<table>{rows_from_dict(count_rows)}</table>
</div>

<div class="card">
<h2>5. Risk Findings</h2>
<ul>{risk_html}</ul>
</div>

<div class="card">
<h2>6. Evidence Used</h2>
<table>{rows_from_dict(evidence_rows)}</table>
</div>

<div class="card">
<h2>7. Recommended Rollout Plan</h2>
<ul>{rec_html}</ul>
</div>

<div class="card">
<h2>8. Limitations</h2>
<ul>{lim_html}</ul>
</div>
</body>
</html>"""

    html_path.write_text(html_doc, encoding="utf-8")


def _render_results(project_root: Path, report: Dict[str, Any]) -> None:
    report = dict(report)
    _write_professional_reports(project_root, report)

    prediction = report.get("prediction", {})
    counts = report.get("counts", {})
    raw = report.get("rawEvaluation", {})

    impact = prediction.get("predictedImpact", "UNKNOWN")
    confidence = prediction.get("confidence", "UNKNOWN")
    rollout = prediction.get("recommendedRolloutMode", "Review before enforcement")

    st.markdown('<div class="ztvp-section-title">Simulation Result</div>', unsafe_allow_html=True)

    st.markdown(
        f"""
        <div class="ztvp-decision {_impact_class(str(impact))}">
            <div class="ztvp-decision-title">
                Executive Decision:
                <span class="ztvp-badge {_badge_class(str(impact))}">{impact}</span>
            </div>
            <div class="ztvp-decision-text">
                Recommended action: <strong>{rollout}</strong><br>
                {_why_result(report)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="ztvp-section-title">1. Impact Overview</div>', unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Predicted Impact", impact)
    c2.metric("Confidence", confidence)

    if counts.get("legacyAuthSimulation"):
        c3.metric("Recently Affected", counts.get("recentlyAffectedIdentities", 0))
        c4.metric("Legacy Signals", counts.get("recentLegacyAuthenticationSignals", 0))
    else:
        c3.metric("Affected Identities", counts.get("potentiallyAffectedIdentities", 0))
        c4.metric("Recent Signals", counts.get("recentRelevantSignIns", 0))

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("In-scope Identities", counts.get("inScopeIdentities", 0))
    c6.metric("Privileged Users", counts.get("privilegedUsersInScope", 0))
    c7.metric("Service-like Accounts", counts.get("serviceLikeAccountsDetected", 0))
    c8.metric("Overlapping Policies", counts.get("overlappingPolicies", 0))

    st.markdown('<div class="ztvp-section-title">2. Executive Summary</div>', unsafe_allow_html=True)
    st.write(prediction.get("summary", "No executive summary was returned by the simulation engine."))

    st.markdown(
        f'<div class="ztvp-explain"><strong>Confidence meaning:</strong> {prediction.get("confidenceReason", _confidence_reason(str(confidence)))}</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f'<div class="ztvp-explain"><strong>Rollout meaning:</strong> {prediction.get("rolloutExplanation", _rollout_explanation(str(rollout)))}</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="ztvp-section-title">3. Proposed Policy Summary</div>', unsafe_allow_html=True)
    inputs = report.get("inputs", {})
    policy_rows = [
        {"Field": "Proposed control", "Value": _clean_value(inputs.get("proposedControl"))},
        {"Field": "Target scope", "Value": _clean_value(inputs.get("targetScope"))},
        {"Field": "Resource scope", "Value": _clean_value(inputs.get("resourceScope"))},
        {"Field": "Client / condition", "Value": _clean_value(inputs.get("clientCondition"))},
        {"Field": "Lookback period", "Value": f"{_clean_value(inputs.get('lookbackDays'))} days"},
        {"Field": "Selected users", "Value": _clean_value(inputs.get("selectedUsers"))},
        {"Field": "Excluded users", "Value": _clean_value(inputs.get("excludedUsers"))},
        {"Field": "Excluded groups", "Value": _clean_value(inputs.get("excludedGroups"))},
    ]
    st.dataframe(policy_rows, use_container_width=True, hide_index=True)

    st.markdown('<div class="ztvp-section-title">4. Risk Findings</div>', unsafe_allow_html=True)
    risk_findings = _extract_risk_findings(report)
    st.markdown(
        "<div class='ztvp-risk-list'><ul>" + "".join(f"<li>{item}</li>" for item in risk_findings) + "</ul></div>",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="ztvp-section-title">5. Evidence Used</div>', unsafe_allow_html=True)
    evidence_rows = [
        {"Evidence": "Users read", "Value": raw.get("totalUsersRead", "Not available")},
        {"Evidence": "Enabled users read", "Value": raw.get("enabledUsersRead", "Not available")},
        {"Evidence": "Sign-ins read", "Value": raw.get("signInsRead", "Not available")},
        {"Evidence": "Relevant sign-ins", "Value": raw.get("relevantSignIns", counts.get("recentRelevantSignIns", 0))},
        {"Evidence": "Conditional Access policies read", "Value": raw.get("policiesRead", "Not available")},
        {"Evidence": "Privileged principals detected", "Value": raw.get("privilegedPrincipalIdsDetected", "Not available")},
        {"Evidence": "Privileged UPNs detected", "Value": raw.get("privilegedUpnsDetected", "Not available")},
    ]
    st.dataframe(evidence_rows, use_container_width=True, hide_index=True)

    if counts.get("legacyAuthSimulation"):
        _show_table("6. Recently Affected Identities", _prepare_identity_rows(report.get("affectedIdentities", [])))
        _show_table("7. In-scope Identities", _prepare_identity_rows(report.get("scopeIdentities", [])))
        _show_table("8. Recent Legacy Authentication Signals", _prepare_signal_rows(report.get("recentSignalSummary", [])))
    else:
        _show_table("6. Affected Population", _prepare_identity_rows(report.get("affectedIdentities", [])))
        _show_table("7. Recent Signal Summary", _prepare_signal_rows(report.get("recentSignalSummary", [])))

    _show_table("8. Risky Identities", _prepare_risky_rows(report.get("riskyIdentities", [])))

    overlap_rows = _prepare_overlap_rows(report.get("existingPolicyOverlap", []))
    strong_overlap = [row for row in overlap_rows if str(row.get("Overlap", "")).lower() == "strong"]
    potential_overlap = [row for row in overlap_rows if str(row.get("Overlap", "")).lower() != "strong"]

    st.markdown('<div class="ztvp-section-title">9. Existing Policy Overlap</div>', unsafe_allow_html=True)
    st.write("Existing overlap helps identify whether the proposed policy is redundant, conflicting, or intentionally stricter.")
    _show_table("Strong overlap", strong_overlap)
    _show_table("Potential overlap", potential_overlap)

    st.markdown('<div class="ztvp-section-title">10. Recommended Rollout Plan</div>', unsafe_allow_html=True)
    recommendations = _as_list(report.get("recommendations", []))
    if recommendations:
        for index, item in enumerate(recommendations, start=1):
            st.write(f"{index}. {item}")
    else:
        st.caption("No recommendations returned.")

    st.markdown('<div class="ztvp-section-title">11. Limitations</div>', unsafe_allow_html=True)
    limitations = _as_list(report.get("limitations", []))
    default_limitations = [
        "This simulation does not create, modify, or enforce Conditional Access policies.",
        "Results depend on available Microsoft Graph permissions and sign-in log retention.",
        "Device compliance, location-based, and risk-based conditions may require additional context.",
        "Report-only testing is recommended before production enforcement.",
    ]

    shown_limits = limitations if limitations else default_limitations
    for item in shown_limits:
        st.write(f"- {item}")

    json_path = project_root / "powershell" / "Reports" / "Simulation" / "CA-Policy-Change-Sandbox-result.json"
    html_path = project_root / "powershell" / "Reports" / "Simulation" / "Html" / "CA-Policy-Change-Sandbox-result.html"

    st.markdown('<div class="ztvp-section-title">12. Downloads</div>', unsafe_allow_html=True)
    d1, d2 = st.columns(2)

    if json_path.exists():
        d1.download_button(
            "Download JSON Simulation Report",
            data=json_path.read_bytes(),
            file_name="CA-Policy-Change-Sandbox-result.json",
            mime="application/json",
            use_container_width=True,
        )

    if html_path.exists():
        d2.download_button(
            "Download HTML Simulation Report",
            data=html_path.read_bytes(),
            file_name="CA-Policy-Change-Sandbox-result.html",
            mime="text/html",
            use_container_width=True,
        )

    with st.expander("Raw simulation JSON"):
        st.json(report)


def render_simulation_page(PROJECT_ROOT):
    _inject_simulation_css()

    project_root = Path(PROJECT_ROOT)

    st.markdown(
        """
        <div class="ztvp-hero">
            <div class="ztvp-hero-title">Simulation — Conditional Access Policy Change Sandbox</div>
            <p class="ztvp-hero-subtitle">Build a proposed policy change and estimate its impact before production enforcement.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_b, col_c = st.columns(3)

    with col_a:
        st.markdown(
            '<div class="ztvp-mini-card"><div class="ztvp-mini-title">1. Build</div><div class="ztvp-mini-text">Choose the proposed control, target users, resource, and access condition.</div></div>',
            unsafe_allow_html=True,
        )

    with col_b:
        st.markdown(
            '<div class="ztvp-mini-card"><div class="ztvp-mini-title">2. Simulate</div><div class="ztvp-mini-text">ZTVP reads current configuration and recent tenant signals without changing the tenant.</div></div>',
            unsafe_allow_html=True,
        )

    with col_c:
        st.markdown(
            '<div class="ztvp-mini-card"><div class="ztvp-mini-title">3. Decide</div><div class="ztvp-mini-text">Review affected users, risky accounts, policy overlap, confidence, and rollout advice.</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="ztvp-warning">Simulation is a prediction only. It does not create, modify, or enforce Conditional Access policies.</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="ztvp-section-title">Proposed Policy Builder</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="ztvp-section-subtitle">Configure the policy change the organization is considering. Nothing is applied to the tenant.</div>',
        unsafe_allow_html=True,
    )

    with st.form("ztvp_ca_policy_change_simulation_form"):
        _label("Policy type")
        policy_type = st.selectbox(
            "Policy type",
            ["Conditional Access"],
            index=0,
            key="sim_policy_type",
            label_visibility="collapsed",
        )

        col1, col2 = st.columns(2)

        with col1:
            _label("Proposed control")
            proposed_control = st.selectbox(
                "Proposed control",
                ["Block access", "Require MFA", "Require compliant device", "Block legacy authentication"],
                index=1,
                key="sim_proposed_control",
                label_visibility="collapsed",
            )

        with col2:
            _label("Client / condition")
            client_condition = st.selectbox(
                "Client / condition",
                ["Browser", "Mobile and desktop apps", "Legacy clients", "Unknown device", "Untrusted location"],
                index=0,
                key="sim_client_condition",
                label_visibility="collapsed",
            )

        col3, col4 = st.columns(2)

        with col3:
            _label("Target")
            target_scope = st.selectbox(
                "Target",
                ["All users", "Privileged users", "Guests / external users", "Selected group", "Selected users"],
                index=0,
                key="sim_target_scope",
                label_visibility="collapsed",
            )

        with col4:
            _label("Lookback period")
            lookback_days = st.selectbox(
                "Lookback period",
                [7, 14, 30],
                index=2,
                key="sim_lookback_days",
                label_visibility="collapsed",
            )

        _label("Resource")
        resource_scope = st.selectbox(
            "Resource",
            ["All cloud apps", "Azure Management", "Exchange Online", "Microsoft 365", "Custom app"],
            index=0,
            key="sim_resource_scope",
            label_visibility="collapsed",
        )

        selected_group = ""
        selected_users_text = ""
        excluded_users_text = "breakglass@tenant.com, admin-emergency@tenant.com"
        excluded_groups_text = "CA-Exclude-BreakGlass"
        breakglass_keywords_text = "breakglass,break-glass,emergency,admin-emergency"
        service_keywords_text = "svc,service,app,automation,scanner,printer,noreply,smtp,backup"
        treat_breakglass = False
        treat_service = False

        with st.expander("Advanced scope and exclusions", expanded=False):
            st.markdown(
                '<div class="ztvp-section-subtitle">Use these only when testing selected groups, selected users, or intentional exclusions.</div>',
                unsafe_allow_html=True,
            )

            col5, col6 = st.columns(2)

            with col5:
                _label("Selected group ID or name")
                selected_group = st.text_input(
                    "Selected group ID or name",
                    value="",
                    placeholder="Example: CA-Pilot-Users",
                    key="sim_selected_group",
                    label_visibility="collapsed",
                )

            with col6:
                _label("Selected user UPNs")
                selected_users_text = st.text_area(
                    "Selected user UPNs",
                    value="",
                    placeholder="user1@tenant.com, user2@tenant.com",
                    key="sim_selected_users",
                    label_visibility="collapsed",
                    height=80,
                )

            col7, col8 = st.columns(2)

            with col7:
                _label("Excluded user UPNs")
                excluded_users_text = st.text_area(
                    "Excluded user UPNs",
                    value=excluded_users_text,
                    key="sim_excluded_users",
                    label_visibility="collapsed",
                    height=80,
                )

            with col8:
                _label("Excluded group IDs or names")
                excluded_groups_text = st.text_area(
                    "Excluded group IDs or names",
                    value=excluded_groups_text,
                    key="sim_excluded_groups",
                    label_visibility="collapsed",
                    height=80,
                )

            col9, col10 = st.columns(2)

            with col9:
                _label("Break-glass account keyword list")
                breakglass_keywords_text = st.text_input(
                    "Break-glass account keyword list",
                    value=breakglass_keywords_text,
                    key="sim_breakglass_keywords",
                    label_visibility="collapsed",
                )
                treat_breakglass = st.checkbox(
                    "Treat break-glass keyword matches as exclusions",
                    value=False,
                    key="sim_treat_breakglass",
                )

            with col10:
                _label("Service account keyword list")
                service_keywords_text = st.text_input(
                    "Service account keyword list",
                    value=service_keywords_text,
                    key="sim_service_keywords",
                    label_visibility="collapsed",
                )
                treat_service = st.checkbox(
                    "Treat service-like keyword matches as exclusions",
                    value=False,
                    key="sim_treat_service",
                )

        st.markdown(
            '<div class="ztvp-safe">Safe mode: No policy will be created, modified, or enforced. ZTVP only reads configuration and estimates impact.</div>',
            unsafe_allow_html=True,
        )

        submitted = st.form_submit_button("See Predicted Impact", use_container_width=True)

    if not submitted:
        return

    inputs = {
        "policy_type": policy_type,
        "proposed_control": proposed_control,
        "target_scope": target_scope,
        "resource_scope": resource_scope,
        "client_condition": client_condition,
        "lookback_days": int(lookback_days),
        "selected_group": selected_group.strip(),
        "selected_users": _split_csv(selected_users_text),
        "excluded_users": _split_csv(excluded_users_text),
        "excluded_groups": _split_csv(excluded_groups_text),
        "breakglass_keywords": _split_csv(breakglass_keywords_text),
        "service_keywords": _split_csv(service_keywords_text),
        "treat_breakglass_as_exclusion": bool(treat_breakglass),
        "treat_service_as_exclusion": bool(treat_service),
    }

    with st.spinner("Analyzing tenant configuration and recent signals..."):
        result = _run_engine(project_root, inputs)

    if not result.get("ok"):
        st.error("Simulation engine failed.")
        st.code(result.get("stderr") or result.get("stdout") or "No output returned.")
        with st.expander("Debug command"):
            st.write(result.get("cmd"))
        return

    report = _load_json_report(project_root)

    if not report:
        st.warning("Simulation completed, but no JSON report was found.")
        st.code(result.get("stdout", ""))
        return

    if "error" in report:
        st.error(report["error"])
        return

    _render_results(project_root, report)
