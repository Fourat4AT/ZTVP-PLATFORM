from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import re
import re
import html
import streamlit as st
from simulation_page import render_simulation_page
from dynamic_idc001 import render_idc001_runner
from dynamic_validation_page import render_dynamic_validation_page
from active_runs_page import render_active_runs_page
PROJECT_ROOT = Path(__file__).resolve().parents[1]
POWERSHELL_DIR = PROJECT_ROOT / "powershell"
CATALOG_PATH = POWERSHELL_DIR / "ScenarioCatalog.ps1"
RUNNER_PATH = POWERSHELL_DIR / "Run-ZTVP.ps1"
REPORTS_DIR = POWERSHELL_DIR / "Reports"
PREFLIGHT_PATH = REPORTS_DIR / "Preflight-discovery.json"


PILLAR_ORDER = [
    "Identity",
    "Devices",
    "Applications",
    "Data",
    "Network",
    "Operations / Monitoring",
]

CATEGORY_ORDER = [
    "Authentication Security",
    "Access Enforcement",
    "Privileged Access",
    "Identity Protection",
    "Baseline Security",
]

SCOPE_ORDER = [
    "Cloud",
    "On-Premises",
    "Hybrid",
]


DYNAMIC_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "ID-DV-001",
        "pillar": "Identity",
        "use_case": "MFA and Strong Authentication",
        "name": "Privileged MFA Enforcement Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID P1 / Conditional Access"],
        "goal": "Prove that privileged access is actually challenged for MFA during a controlled sign-in attempt.",
        "decoys": "Decoy privileged user or decoy privileged group.",
        "test_action": "Attempt a controlled sign-in with the decoy privileged identity.",
        "evidence": "Entra sign-in logs, authenticationRequirement, Conditional Access status, applied policies.",
        "expected": "The sign-in is challenged for MFA or blocked until MFA is satisfied.",
    },
    {
        "id": "ID-DV-002",
        "pillar": "Identity",
        "use_case": "MFA and Strong Authentication",
        "name": "Phishing-Resistant Admin Authentication Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID P1 / Conditional Access"],
        "goal": "Validate whether privileged access requires phishing-resistant or strong authentication.",
        "decoys": "Decoy admin user with controlled role/group assignment.",
        "test_action": "Attempt privileged access with a weaker authentication method.",
        "evidence": "Sign-in logs, authentication method used, authentication strength result, Conditional Access result.",
        "expected": "Weak MFA or password-only access is not enough for privileged access.",
    },
    {
        "id": "ID-DV-003",
        "pillar": "Identity",
        "use_case": "Legacy Authentication",
        "name": "Legacy Authentication Block Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID P1 / Conditional Access"],
        "goal": "Prove that legacy/basic authentication attempts are actually blocked.",
        "decoys": "Decoy standard user.",
        "test_action": "Attempt a controlled legacy-auth style sign-in/client access.",
        "evidence": "Sign-in logs, clientAppUsed, status, Conditional Access result.",
        "expected": "Legacy authentication attempt is blocked.",
    },
    {
        "id": "ID-DV-004",
        "pillar": "Identity",
        "use_case": "Conditional Access Enforcement",
        "name": "Unmanaged Device Access Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID P1 / Conditional Access", "Intune / Device Compliance"],
        "goal": "Prove that access from an unmanaged or non-compliant device is blocked or challenged.",
        "decoys": "Decoy user and unmanaged test VM/device.",
        "test_action": "Attempt access to a protected cloud app from unmanaged or non-compliant device context.",
        "evidence": "Sign-in logs, deviceDetail, Conditional Access result, Intune compliance state.",
        "expected": "Access is blocked or requires a compliant/managed device.",
    },
    {
        "id": "ID-DV-005",
        "pillar": "Identity",
        "use_case": "Conditional Access Enforcement",
        "name": "Conditional Access Exclusion Bypass Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID P1 / Conditional Access"],
        "goal": "Prove whether a Conditional Access exclusion creates a real bypass.",
        "decoys": "Decoy user and controlled exclusion group.",
        "test_action": "Compare sign-in behavior with and without controlled exclusion membership.",
        "evidence": "Sign-in logs, applied policies, excluded policy behavior.",
        "expected": "Only approved emergency identities bypass controls; normal users do not.",
    },
    {
        "id": "ID-DV-006",
        "pillar": "Identity",
        "use_case": "Application Consent and Registration",
        "name": "User Consent Enforcement Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID / App Consent"],
        "goal": "Prove whether normal users can consent to risky applications directly.",
        "decoys": "Decoy standard user and controlled ZTVP test application.",
        "test_action": "Attempt user consent to controlled app permissions.",
        "evidence": "Consent result, audit logs, service principal state, admin consent workflow result.",
        "expected": "Risky consent is blocked or routed to admin approval.",
    },
    {
        "id": "ID-DV-007",
        "pillar": "Identity",
        "use_case": "Application Consent and Registration",
        "name": "App Registration Permission Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID / App Registration"],
        "goal": "Prove whether normal users can create app registrations.",
        "decoys": "Decoy standard user.",
        "test_action": "Attempt to create an app registration as the decoy user.",
        "evidence": "Graph/API result and Entra audit logs.",
        "expected": "Normal user cannot create app registrations when the client baseline restricts it.",
    },
    {
        "id": "ID-DV-008",
        "pillar": "Identity",
        "use_case": "Identity Protection",
        "name": "Risk-Based Access Enforcement Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID P2 / Identity Protection"],
        "goal": "Prove that risky user or risky sign-in conditions trigger remediation.",
        "decoys": "Decoy risk test identity.",
        "test_action": "Attempt access under controlled risky conditions where possible.",
        "evidence": "Risk detections, sign-in logs, risk state, Conditional Access result.",
        "expected": "Risky access is blocked, challenged, or remediated according to policy.",
    },
    {
        "id": "ID-DV-009",
        "pillar": "Identity",
        "use_case": "Privileged Access",
        "name": "PIM Role Activation Enforcement Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID P2 / PIM"],
        "goal": "Prove privileged actions require controlled role activation.",
        "decoys": "Decoy PIM-eligible admin account.",
        "test_action": "Attempt privileged action before activation, then test activation workflow.",
        "evidence": "Role assignment, activation logs, audit logs, sign-in logs.",
        "expected": "Privileged action fails before activation and works only after controlled activation.",
    },
    {
        "id": "ID-DV-010",
        "pillar": "Identity",
        "use_case": "Privileged Access",
        "name": "Break-Glass Monitoring Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID / Sign-in Logs"],
        "goal": "Prove emergency access works but is logged and visible.",
        "decoys": "Controlled break-glass test account.",
        "test_action": "Attempt a controlled break-glass sign-in.",
        "evidence": "Sign-in logs, audit logs, alerting evidence.",
        "expected": "Break-glass sign-in is possible but produces evidence and alerting.",
    },
    {
        "id": "ID-DV-011",
        "pillar": "Identity",
        "use_case": "Hybrid Identity",
        "name": "Disabled Synced Account Cloud Access Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Hybrid Identity"],
        "goal": "Prove that disabling an on-prem synced account blocks cloud sign-in after sync.",
        "decoys": "Controlled synced AD test user.",
        "test_action": "Disable the test account in AD, sync, then attempt cloud sign-in.",
        "evidence": "AD user state, sync evidence, Entra user state, sign-in logs.",
        "expected": "Cloud sign-in fails after the AD account is disabled and synced.",
    },
    {
        "id": "ID-DV-012",
        "pillar": "Identity",
        "use_case": "On-Prem Identity Detection",
        "name": "MDI Suspicious Identity Activity Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Identity"],
        "goal": "Prove that suspicious identity activity from AD/DC context is visible in Microsoft Defender for Identity.",
        "decoys": "Decoy AD user, monitored domain controller, controlled lab activity.",
        "test_action": "Run a safe identity detection validation action in a lab.",
        "evidence": "MDI alert, Defender XDR incident, domain controller telemetry.",
        "expected": "MDI records and surfaces the controlled suspicious identity activity.",
    },

    {
        "id": "EP-DV-001",
        "pillar": "Endpoint",
        "use_case": "Endpoint Detection",
        "name": "MDE Detection Visibility Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Defender for Endpoint"],
        "goal": "Prove endpoint detection telemetry is generated and visible in Defender.",
        "decoys": "Test workstation or VM onboarded to MDE.",
        "test_action": "Run a safe Microsoft-approved detection test.",
        "evidence": "Defender alert, device timeline, incident/event timestamp.",
        "expected": "MDE records the test action and produces expected evidence.",
    },
    {
        "id": "EP-DV-002",
        "pillar": "Endpoint",
        "use_case": "Device Compliance",
        "name": "Device Compliance Enforcement Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Intune / Device Compliance", "Entra ID P1 / Conditional Access"],
        "goal": "Prove non-compliant devices cannot access protected resources.",
        "decoys": "Test device with controlled compliance state.",
        "test_action": "Attempt access from a non-compliant or unmanaged device.",
        "evidence": "Intune compliance state, Entra sign-in logs, Conditional Access result.",
        "expected": "Access is blocked or remediation is required.",
    },
    {
        "id": "EP-DV-003",
        "pillar": "Endpoint",
        "use_case": "Endpoint Protection",
        "name": "Defender Antivirus Protection Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Endpoint"],
        "goal": "Prove Defender AV detects safe test malware patterns.",
        "decoys": "Test endpoint or VM.",
        "test_action": "Use a safe AV test pattern in a controlled lab.",
        "evidence": "Defender AV detection event, alert, remediation action.",
        "expected": "Defender detects and blocks or quarantines the test file.",
    },
    {
        "id": "EP-DV-004",
        "pillar": "Endpoint",
        "use_case": "Attack Surface Reduction",
        "name": "Attack Surface Reduction Enforcement Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Endpoint", "Intune / Device Compliance"],
        "goal": "Prove ASR rules are actually enforced on endpoints.",
        "decoys": "Test endpoint targeted by ASR policy.",
        "test_action": "Run a safe ASR validation action.",
        "evidence": "MDE timeline, ASR event, policy result.",
        "expected": "ASR rule blocks or audits the controlled action as expected.",
    },
    {
        "id": "EP-DV-005",
        "pillar": "Endpoint",
        "use_case": "Endpoint Response",
        "name": "Device Isolation Response Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Endpoint"],
        "goal": "Prove that endpoint response actions can isolate a test device and generate evidence.",
        "decoys": "Test workstation or VM onboarded to MDE.",
        "test_action": "Execute a controlled device isolation response test.",
        "evidence": "MDE action center, device timeline, isolation status.",
        "expected": "The test device is isolated and the action is recorded.",
    },

    {
        "id": "APP-DV-001",
        "pillar": "Applications",
        "use_case": "Enterprise Application Access",
        "name": "Enterprise App Assignment Enforcement Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Entra ID / Enterprise Apps"],
        "goal": "Prove unassigned users cannot access restricted enterprise applications.",
        "decoys": "Decoy standard user not assigned to the app.",
        "test_action": "Attempt access to an enterprise app requiring assignment.",
        "evidence": "Enterprise app sign-in logs, assignment result, audit logs.",
        "expected": "Unassigned user is denied access.",
    },
    {
        "id": "APP-DV-002",
        "pillar": "Applications",
        "use_case": "OAuth Governance",
        "name": "OAuth Consent Governance Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID / App Consent"],
        "goal": "Prove OAuth permission governance blocks risky user consent.",
        "decoys": "Decoy user and controlled OAuth test app.",
        "test_action": "Attempt user consent for controlled app permissions.",
        "evidence": "Consent result, service principal state, audit logs.",
        "expected": "Admin approval is required for risky consent.",
    },
    {
        "id": "APP-DV-003",
        "pillar": "Applications",
        "use_case": "Session Control",
        "name": "App Session Control Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Cloud Apps"],
        "goal": "Prove session controls are applied to risky app sessions.",
        "decoys": "Decoy user and protected SaaS app.",
        "test_action": "Attempt app access under session-control conditions.",
        "evidence": "MDCA session policy logs, app control evidence, sign-in logs.",
        "expected": "Session is monitored, restricted, or blocked according to policy.",
    },
    {
        "id": "APP-DV-004",
        "pillar": "Applications",
        "use_case": "Sensitive App Access",
        "name": "Sensitive App Access From Unmanaged Device Probe",
        "status": "DESIGNED",
        "priority": "Critical",
        "requires": ["Entra ID P1 / Conditional Access"],
        "goal": "Prove sensitive app access is blocked from unmanaged endpoints.",
        "decoys": "Decoy user and unmanaged test VM/device.",
        "test_action": "Attempt access to a sensitive app from unmanaged context.",
        "evidence": "Sign-in logs, CA result, device state, app access result.",
        "expected": "Access is blocked or constrained.",
    },
    {
        "id": "APP-DV-005",
        "pillar": "Applications",
        "use_case": "Email and Collaboration Protection",
        "name": "MDO Safe Attachment / Safe Link Evidence Probe",
        "status": "DESIGNED",
        "priority": "High",
        "requires": ["Defender for Office 365"],
        "goal": "Prove that mail protection generates evidence for controlled safe test content.",
        "decoys": "Decoy mailbox and controlled mail-flow test.",
        "test_action": "Send a safe Microsoft-approved test message through mail protection path.",
        "evidence": "MDO detection, message trace, Explorer evidence, Defender XDR incident if triggered.",
        "expected": "The controlled test is inspected and evidence is visible.",
    },
]




def dyn(
    id: str,
    pillar: str,
    scope: str,
    use_case: str,
    name: str,
    priority: str,
    requires: List[str],
    goal: str,
    decoys: str,
    action: str,
    evidence: str,
    expected: str,
) -> Dict[str, Any]:
    return {
        "id": id,
        "pillar": pillar,
        "scope": scope,
        "use_case": use_case,
        "name": name,
        "status": "DESIGNED",
        "priority": priority,
        "requires": requires,
        "goal": goal,
        "decoys": decoys,
        "test_action": action,
        "evidence": evidence,
        "expected": expected,
    }
# ============================================================
# Dynamic Validation catalog correction
# Classification rule:
# - Identity = authentication, access enforcement, privileged identity, hybrid identity
# - Applications = OAuth consent, app registration, enterprise app access, app governance
# ============================================================

def apply_dynamic_catalog_corrections() -> List[Dict[str, Any]]:
    corrected: List[Dict[str, Any]] = []

    # Remove application-governance scenarios from Identity.
    # They are Entra-backed, but the behavior tested is application/OAuth governance.
    move_from_identity = {
        "User Consent Enforcement Probe",
        "App Registration Permission Probe",
    }

    for scenario in DYNAMIC_SCENARIOS:
        if scenario.get("pillar") == "Identity" and scenario.get("name") in move_from_identity:
            continue
        corrected.append(scenario)

    # Renumber Identity Cloud scenarios after moving app governance out.
    identity_id_map = {
        "ID-C-007": "ID-C-005",  # Risk-Based Access Enforcement Probe
        "ID-C-008": "ID-C-006",  # PIM Role Activation Enforcement Probe
        "ID-C-009": "ID-C-007",  # Break-Glass Monitoring Probe
        "ID-C-010": "ID-C-008",  # Phishing-Resistant Admin Authentication Probe
    }

    for scenario in corrected:
        old_id = scenario.get("id")
        if old_id in identity_id_map:
            scenario["id"] = identity_id_map[old_id]

    def exists(name: str, pillar: str) -> bool:
        return any(
            item.get("name") == name and item.get("pillar") == pillar
            for item in corrected
        )

    # Add User Consent under Applications.
    if not exists("User Consent Enforcement Probe", "Applications"):
        corrected.append(
            dyn(
                "APP-DV-006",
                "Applications",
                "Cloud",
                "OAuth and App Consent",
                "User Consent Enforcement Probe",
                "Critical",
                ["Entra ID / App Consent"],
                "Prove whether normal users can consent to risky applications directly.",
                "Decoy standard user and controlled ZTVP test application.",
                "Attempt user consent to controlled app permissions.",
                "Consent result, audit logs, service principal state, admin consent workflow result.",
                "Risky consent is blocked or routed to admin approval.",
            )
        )

    # Add App Registration under Applications.
    if not exists("App Registration Permission Probe", "Applications"):
        corrected.append(
            dyn(
                "APP-DV-007",
                "Applications",
                "Cloud",
                "App Governance",
                "App Registration Permission Probe",
                "High",
                ["Entra ID / App Registration"],
                "Prove whether normal users can create app registrations.",
                "Decoy standard user.",
                "Attempt to create an app registration as the decoy user.",
                "Graph/API result and Entra audit logs.",
                "Normal user cannot create app registrations when the client baseline restricts it.",
            )
        )

    # Make Identity Cloud IDs clean and clear.
    identity_cloud_order = [
        ("Privileged MFA Enforcement Probe", "ID-C-001"),
        ("Conditional Access Exclusion Bypass Probe", "ID-C-002"),
        ("Unmanaged Device Access Probe", "ID-C-003"),
        ("Legacy Authentication Block Probe", "ID-C-004"),
        ("Risk-Based Access Enforcement Probe", "ID-C-005"),
        ("PIM Role Activation Enforcement Probe", "ID-C-006"),
        ("Break-Glass Monitoring Probe", "ID-C-007"),
        ("Phishing-Resistant Admin Authentication Probe", "ID-C-008"),
    ]

    for scenario_name, new_id in identity_cloud_order:
        for scenario in corrected:
            if (
                scenario.get("pillar") == "Identity"
                and scenario.get("scope") == "Cloud"
                and scenario.get("name") == scenario_name
            ):
                scenario["id"] = new_id

    # Keep Hybrid Identity IDs clear.
    hybrid_order = [
        ("Disabled Synced Account Cloud Access Probe", "ID-H-001"),
        ("Synced Privileged User MFA Enforcement Probe", "ID-H-002"),
        ("Synced Group Conditional Access Enforcement Probe", "ID-H-003"),
        ("Entra Connect Sync Consistency Probe", "ID-H-004"),
        ("On-Prem Privileged Group Change Detection Probe", "ID-H-005"),
        ("Stale or Disabled Synced Privileged Account Probe", "ID-H-006"),
        ("Hybrid Password and Account State Consistency Probe", "ID-H-007"),
        ("MDI Suspicious Identity Activity Evidence Probe", "ID-H-008"),
    ]

    for scenario_name, new_id in hybrid_order:
        for scenario in corrected:
            if (
                scenario.get("pillar") == "Identity"
                and scenario.get("scope") == "Hybrid"
                and scenario.get("name") == scenario_name
            ):
                scenario["id"] = new_id

    return corrected







DYNAMIC_SCENARIOS = apply_dynamic_catalog_corrections()


st.set_page_config(
    page_title="ZTVP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.stApp {
    background: #f4f7fb;
    color: #0f172a;
}

.block-container {
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #07111f 0%, #0f172a 58%, #111827 100%);
}

section[data-testid="stSidebar"] * {
    color: #e5e7eb !important;
}

section[data-testid="stSidebar"] [role="radiogroup"] label {
    border-radius: 12px;
    padding: 0.35rem 0.55rem;
    margin-bottom: 0.2rem;
}

section[data-testid="stSidebar"] [role="radiogroup"] label:hover {
    background: rgba(59, 130, 246, 0.14);
}

[data-testid="stColumns"] {
    align-items: flex-start !important;
}

[data-testid="stColumn"] {
    align-self: flex-start !important;
}

.ztvp-sidebar-brand {
    padding: 0.55rem 0 0.8rem 0;
}

.ztvp-sidebar-brand-title {
    font-size: 1.08rem;
    font-weight: 950;
    color: #f8fafc;
    letter-spacing: .01em;
}

.ztvp-sidebar-brand-subtitle {
    margin-top: 0.12rem;
    font-size: 0.75rem;
    color: #94a3b8 !important;
    line-height: 1.25;
}

.ztvp-hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 52%, #2563eb 100%);
    color: white;
    padding: 34px 38px;
    border-radius: 28px;
    box-shadow: 0 18px 45px rgba(15, 23, 42, .24);
    margin-bottom: 26px;
}

.ztvp-hero h1 {
    margin: 0;
    font-size: 38px;
    color: white;
}

.ztvp-hero p {
    margin: 12px 0 0 0;
    opacity: .92;
    font-size: 17px;
    color: white;
}

.ztvp-card {
    background: white;
    color: #0f172a;
    border: 1px solid #e5e7eb;
    border-radius: 22px;
    padding: 24px;
    box-shadow: 0 10px 28px rgba(15, 23, 42, .07);
    margin-bottom: 18px;
}

.ztvp-card h2,
.ztvp-card h3,
.ztvp-card p {
    color: #0f172a;
}

.ztvp-dashboard-strip {
    display: grid;
    grid-template-columns: 1.6fr 1fr 1fr;
    gap: 0.9rem;
    margin: 0 0 1.25rem 0;
}

.ztvp-stat-tile {
    background: rgba(255, 255, 255, 0.94);
    border: 1px solid #dbe5f3;
    border-radius: 18px;
    padding: 1rem 1.05rem;
    box-shadow: 0 12px 26px rgba(15, 23, 42, 0.065);
}

.ztvp-stat-tile span {
    display: block;
    color: #64748b;
    font-size: 0.76rem;
    font-weight: 850;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 0.35rem;
}

.ztvp-stat-tile strong {
    display: block;
    color: #0f172a;
    font-size: 1rem;
    font-weight: 950;
    line-height: 1.25;
    word-break: break-word;
}

.ztvp-workbench-shell {
    margin-top: 1.35rem;
    margin-bottom: 0.85rem;
}

.ztvp-workbench-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1rem;
}

.ztvp-eyebrow {
    color: #2563eb;
    font-size: 0.74rem;
    font-weight: 950;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
}

.ztvp-workbench-head h3 {
    margin: 0;
    color: #0f172a;
    font-size: 1.28rem;
    font-weight: 950;
}

.ztvp-workbench-head p {
    margin: 0.35rem 0 0 0;
    color: #64748b;
    font-size: 0.95rem;
}

.ztvp-workbench-status {
    background: #ecfdf5;
    color: #166534;
    border: 1px solid #bbf7d0;
    border-radius: 999px;
    padding: 0.42rem 0.68rem;
    font-size: 0.75rem;
    font-weight: 900;
    white-space: nowrap;
}

.ztvp-workbench {
    margin-top: 0.25rem;
    margin-bottom: 0;
}

.ztvp-feature-card {
    background: #ffffff;
    border: 1px solid #dbe5f3;
    border-radius: 20px;
    padding: 24px;
    box-shadow: 0 16px 35px rgba(15, 23, 42, 0.08);
    transition: all 0.2s ease;
    margin-bottom: 0;
    position: relative;
    overflow: hidden;
}

.ztvp-feature-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 20px 45px rgba(15, 23, 42, 0.12);
}

.ztvp-feature-card-primary {
    min-height: 270px;
    padding-bottom: 82px;
    background:
        radial-gradient(circle at top right, rgba(37, 99, 235, 0.10), transparent 34%),
        linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
}

.ztvp-feature-card-primary:before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    right: 0;
    height: 4px;
    background: linear-gradient(135deg, #2563eb, #22c55e);
}

.ztvp-feature-card-secondary {
    min-height: 230px;
    padding-bottom: 82px;
    background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
}

.ztvp-feature-icon {
    width: 46px;
    height: 46px;
    border-radius: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: #eff6ff;
    color: #1d4ed8;
    font-size: 1.3rem;
    margin-bottom: 0.9rem;
}

.ztvp-feature-card h3 {
    margin: 0 0 0.45rem 0;
    color: #0f172a;
    font-size: 1.18rem;
    font-weight: 950;
}

.ztvp-feature-card p {
    color: #475569;
    line-height: 1.52;
    margin: 0;
    font-size: 0.94rem;
}

.ztvp-feature-badges {
    margin-top: 1rem;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.ztvp-feature-badge {
    display: inline-block;
    border-radius: 999px;
    padding: 0.34rem 0.62rem;
    margin-right: 0.38rem;
    margin-bottom: 0.32rem;
    background: #eef6ff;
    color: #1e40af;
    font-size: 0.75rem;
    font-weight: 850;
}

.ztvp-progress-wrap {
    margin-bottom: 12px;
}

.ztvp-container-card-title {
    margin: 0.8rem 0 0.6rem 0;
    color: #0f172a;
    font-size: 1.45rem;
    font-weight: 800;
}

.ztvp-container-card-text {
    color: #475569;
    line-height: 1.6;
    margin: 0 0 1rem 0;
    font-size: 1rem;
}

.ztvp-module-list {
    margin: 0.8rem 0 1rem 1.05rem;
    padding: 0;
    color: #334155;
    line-height: 1.6;
    font-size: 0.92rem;
}

.ztvp-module-list li {
    margin-bottom: 0.15rem;
}

.ztvp-home-module-card {
    display: block;
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) {
    background: #ffffff !important;
    border: 1px solid #dbe5f3 !important;
    border-radius: 22px !important;
    box-shadow: 0 16px 36px rgba(15, 23, 42, 0.08) !important;
    min-height: 300px !important;
    padding: 0.6rem !important;
    position: relative !important;
    overflow: hidden !important;
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card)::before {
    content: "";
    position: absolute;
    top: 0;
    left: 24px;
    right: 24px;
    height: 4px;
    border-radius: 0 0 999px 999px;
    background: linear-gradient(90deg, #2563eb, #22c55e);
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card):hover {
    box-shadow: 0 22px 48px rgba(15, 23, 42, 0.12) !important;
}

.ztvp-home-badge-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 0.5rem;
    margin-bottom: 1.25rem;
}

.ztvp-home-badge {
    background: #eef4ff;
    border: 1px solid #dbeafe;
    color: #1d4ed8;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 0.84rem;
    font-weight: 700;
}

.ztvp-home-action {
    display: flex;
    justify-content: center;
    margin-top: auto;
    padding-top: 12px;
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) div[data-testid="stButton"] {
    display: flex !important;
    justify-content: center !important;
    margin-top: 0.35rem !important;
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) div[data-testid="stButton"] button,
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) button[data-testid="stBaseButton-primary"] {
    min-width: 220px !important;
    max-width: 220px !important;
    height: 46px !important;
    border-radius: 12px !important;
    font-size: 1rem !important;
    font-weight: 700 !important;
    background: linear-gradient(135deg, #2563eb, #1d4ed8) !important;
    color: #ffffff !important;
    border: none !important;
    box-shadow: 0 10px 20px rgba(37, 99, 235, 0.22) !important;
}

div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) div[data-testid="stButton"] button:hover,
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-home-module-card) button[data-testid="stBaseButton-primary"]:hover {
    transform: translateY(-1px);
    box-shadow: 0 12px 24px rgba(37, 99, 235, 0.28) !important;
    background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
}

.ztvp-signal-list {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.55rem;
    margin-top: 1rem;
}

.ztvp-signal {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 0.62rem;
    color: #334155;
    font-size: 0.78rem;
    font-weight: 800;
}

.ztvp-capabilities-section {
    margin-top: 32px;
}

.ztvp-section {
    margin-top: 1.35rem;
    margin-bottom: 0.8rem;
}

.ztvp-section h3 {
    margin-bottom: 0.35rem;
    font-size: 2.1rem;
    font-weight: 800;
    color: #0f172a;
}

.ztvp-section p {
    margin-top: 0;
    margin-bottom: 1.5rem;
    color: #64748b;
    font-size: 1rem;
}

.ztvp-muted {
    color: #475569 !important;
    font-size: 14px;
}

.ztvp-badge {
    display: inline-block;
    padding: 7px 12px;
    border-radius: 999px;
    font-weight: 800;
    margin-right: 8px;
    margin-top: 8px;
    font-size: 13px;
}

.badge-good { background:#dcfce7; color:#166534; }
.badge-warn { background:#fef3c7; color:#92400e; }
.badge-bad { background:#fee2e2; color:#991b1b; }
.badge-info { background:#dbeafe; color:#1e40af; }

.finding-box {
    background:#fff7ed;
    border-left:6px solid #f97316;
    padding:16px;
    border-radius:14px;
    margin-bottom:12px;
    color:#0f172a;
}

.rec-box {
    background:#eff6ff;
    border-left:6px solid #2563eb;
    padding:16px;
    border-radius:14px;
    margin-bottom:12px;
    color:#0f172a;
}

.good-box {
    background:#f0fdf4;
    border-left:6px solid #22c55e;
    padding:16px;
    border-radius:14px;
    margin-bottom:12px;
    color:#0f172a;
}

.warn-box {
    background:#fffbeb;
    border-left:6px solid #f59e0b;
    padding:16px;
    border-radius:14px;
    margin-bottom:12px;
    color:#0f172a;
}

div[data-testid="stMetric"] {
    background:white;
    border:1px solid #e5e7eb;
    border-radius:18px;
    padding:14px;
    box-shadow:0 8px 24px rgba(15,23,42,.05);
}

div[data-testid="stMetric"] label {
    color:#475569 !important;
    font-weight:700 !important;
}

div[data-testid="stMetricValue"] {
    color:#0f172a !important;
    font-weight:900 !important;
}

.stButton > button {
    border-radius: 12px !important;
    padding: 0.58rem 0.9rem !important;
    font-weight: 850 !important;
    min-height: 42px;
    text-align: center !important;
    white-space: normal !important;
    box-shadow: 0 4px 12px rgba(15, 23, 42, .05);
    transition: box-shadow .15s ease, border-color .15s ease, background .15s ease;
}

.stButton > button:hover {
    background: #eff6ff !important;
    color: #0f172a !important;
    border-color: #2563eb !important;
    box-shadow:0 8px 18px rgba(15,23,42,.09);
}

.stButton > button p {
    color: #0f172a !important;
}

/* Primary action buttons */
div[data-testid="stButton"] button[kind="primary"],
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"],
.stButton button[kind="primary"],
.stButton button[data-testid="stBaseButton-primary"],
button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #2563eb, #1d4ed8) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 0.7rem 1.1rem !important;
    font-weight: 700 !important;
    text-align: center !important;
    width: auto !important;
    min-width: 190px !important;
    max-width: 200px !important;
    box-shadow: 0 8px 20px rgba(37, 99, 235, 0.22) !important;
}

div[data-testid="stButton"] button[kind="primary"]:hover,
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"]:hover,
.stButton button[kind="primary"]:hover,
.stButton button[data-testid="stBaseButton-primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: linear-gradient(135deg, #1d4ed8, #1e40af) !important;
    color: #ffffff !important;
}

div[data-testid="stButton"] button[kind="primary"] p,
div[data-testid="stButton"] button[data-testid="stBaseButton-primary"] p,
.stButton button[kind="primary"] p,
.stButton button[data-testid="stBaseButton-primary"] p,
button[data-testid="stBaseButton-primary"] p {
    color: #ffffff !important;
}

[data-testid="stDataFrame"] {
    background:white !important;
    border-radius:18px !important;
}

@media (max-width: 900px) {
    .ztvp-dashboard-strip { grid-template-columns: 1fr; }
    .ztvp-workbench-head { display: block; }
    .ztvp-workbench-status { display: inline-block; margin-top: 0.75rem; }
    .ztvp-signal-list { grid-template-columns: 1fr; }
}
</style>
""",
    unsafe_allow_html=True,
)


def esc(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def hero(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
<div class="ztvp-hero">
    <h1>{esc(title)}</h1>
    <p>{esc(subtitle)}</p>
</div>
""",
        unsafe_allow_html=True,
    )


def badge(label: str, kind: str = "info") -> str:
    css = {
        "good": "badge-good",
        "warn": "badge-warn",
        "bad": "badge-bad",
        "info": "badge-info",
    }.get(kind, "badge-info")
    return f'<span class="ztvp-badge {css}">{esc(label)}</span>'


def read_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="ignore")


def parse_value(raw: str) -> Any:
    value = raw.strip().rstrip(",")
    if value.lower() == "$true":
        return True
    if value.lower() == "$false":
        return False
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace('`"', '"')
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    return value


def extract_assessment_scenarios(text: str, source: str) -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []
    pattern = re.compile(r"\[PSCustomObject\]@\{(.*?)\}", re.DOTALL | re.IGNORECASE)

    for match in pattern.finditer(text):
        body = match.group(1)
        if "ScenarioId" not in body:
            continue

        item: Dict[str, Any] = {"_source": source, "_position": match.start()}

        for line in body.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", line)
            if not m:
                continue
            item[m.group(1)] = parse_value(m.group(2))

        if item.get("ScenarioId") and item.get("Name"):
            item.setdefault("PillarName", "")
            item.setdefault("CategoryName", "")
            item.setdefault("Scope", "")
            item.setdefault("Priority", "")
            item.setdefault("Phase", "")
            item.setdefault("Objective", "")
            item.setdefault("Implemented", False)
            item.setdefault("EnginePath", "")
            item.setdefault("FunctionName", "")
            scenarios.append(item)

    return scenarios


@st.cache_data(show_spinner=False)
def load_assessment_scenarios() -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    for source, path in [("ScenarioCatalog.ps1", CATALOG_PATH), ("Run-ZTVP.ps1", RUNNER_PATH)]:
        collected.extend(extract_assessment_scenarios(read_file(path), source))

    by_id: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for item in collected:
        sid = str(item.get("ScenarioId", "")).strip()
        if not sid:
            continue
        if sid not in by_id:
            order.append(sid)
        by_id[sid] = item

    items = [by_id[sid] for sid in order]

    def idx(value: str, values: List[str]) -> int:
        return values.index(value) if value in values else 999

    return sorted(
        items,
        key=lambda x: (
            idx(x.get("PillarName", ""), PILLAR_ORDER),
            idx(x.get("CategoryName", ""), CATEGORY_ORDER),
            idx(x.get("Scope", ""), SCOPE_ORDER),
            x.get("_position", 999999),
            x.get("ScenarioId", ""),
        ),
    )


def ordered_unique(items: List[Dict[str, Any]], key: str, order: Optional[List[str]] = None) -> List[str]:
    order = order or []
    found: List[str] = []
    for item in items:
        value = item.get(key)
        if value and value not in found:
            found.append(value)

    result = [x for x in order if x in found]
    result.extend([x for x in found if x not in result])
    return result


def ps_quote(value: Any) -> str:
    text = str(value)
    return "'" + text.replace("'", "''") + "'"


def run_powershell(ps: str, timeout: int = 900) -> Dict[str, Any]:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        cwd=str(PROJECT_ROOT),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "returncode": completed.returncode,
    }


def run_tenant_connection() -> Dict[str, Any]:
    ps_lines = [
        '$ErrorActionPreference = "Stop"',
        f"Set-Location -Path {ps_quote(PROJECT_ROOT)}",
        'New-Item -ItemType Directory -Path ".\\powershell\\Reports" -Force | Out-Null',
        'Import-Module Microsoft.Graph.Authentication -Force',
        '$scopes = @(',
        '    "User.Read.All",',
        '    "Group.Read.All",',
        '    "Directory.Read.All",',
        '    "Organization.Read.All",',
        '    "LicenseAssignment.Read.All",',
        '    "AuditLog.Read.All",',
        '    "Policy.Read.All",',
        '    "UserAuthenticationMethod.Read.All"',
        ')',
        '$ctx = Get-MgContext',
        'if (-not $ctx) { Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null }',
        '$ctx = Get-MgContext',
        '$org = $null',
        '$domains = @()',
        '$skus = @()',
        '$syncedSample = @()',
        '$errors = @()',
        'try { $org = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,tenantType,verifiedDomains").value)[0] } catch { $errors += [ordered]@{ area="organization"; error=$_.Exception.Message } }',
        'try { $domains = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/domains").value) } catch { $errors += [ordered]@{ area="domains"; error=$_.Exception.Message } }',
        'try { $skus = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus").value) } catch { $errors += [ordered]@{ area="subscribedSkus"; error=$_.Exception.Message } }',
        'try { $syncedSample = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$top=5&`$select=id,userPrincipalName,onPremisesSyncEnabled,onPremisesSamAccountName&`$filter=onPremisesSyncEnabled eq true").value) } catch { $errors += [ordered]@{ area="syncedUsers"; error=$_.Exception.Message } }',
        '$result = [ordered]@{',
        '    generated_at = (Get-Date).ToString("s")',
        '    account = $ctx.Account',
        '    tenant_id = $ctx.TenantId',
        '    organization = $org',
        '    domains = $domains',
        '    subscribed_skus = $skus',
        '    synced_user_sample = $syncedSample',
        '    errors = $errors',
        '}',
        '$result | ConvertTo-Json -Depth 100 | Set-Content -Path ".\\powershell\\Reports\\Preflight-discovery.json" -Encoding UTF8',
        'Write-Host "ZTVP_CONNECTED_TENANT=$($ctx.TenantId)"',
    ]
    result = run_powershell("\n".join(ps_lines), timeout=900)
    result["json_path"] = str(PREFLIGHT_PATH)
    return result


def load_preflight() -> Optional[Dict[str, Any]]:
    if not PREFLIGHT_PATH.exists():
        return None
    with PREFLIGHT_PATH.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def flatten_service_plans(preflight: Dict[str, Any]) -> List[str]:
    plans: List[str] = []
    for sku in preflight.get("subscribed_skus") or []:
        for sp in sku.get("servicePlans") or []:
            name = sp.get("servicePlanName")
            if name:
                plans.append(str(name).upper())
    return sorted(set(plans))


def sku_part_numbers(preflight: Dict[str, Any]) -> List[str]:
    values = []
    for sku in preflight.get("subscribed_skus") or []:
        value = sku.get("skuPartNumber")
        if value:
            values.append(str(value).upper())
    return sorted(set(values))


def contains_any(text: str, needles: List[str]) -> bool:
    return any(n.upper() in text for n in needles)


def detect_capabilities(preflight: Dict[str, Any]) -> Dict[str, bool]:
    skus = sku_part_numbers(preflight)
    plans = flatten_service_plans(preflight)
    joined = " ".join(skus + plans).upper()

    has_e5 = contains_any(joined, ["SPE_E5", "M365_E5", "OFFICE365_E5", "DEVELOPERPACK_E5", "ENTERPRISEPREMIUM", "_E5", " E5"])
    has_e3 = contains_any(joined, ["SPE_E3", "M365_E3", "OFFICE365_E3", "ENTERPRISEPACK", "_E3", " E3"])

    return {
        "Entra ID P1 / Conditional Access": (
            has_e3 or has_e5 or contains_any(joined, ["AAD_PREMIUM", "EMS", "ENTERPRISEPREMIUM"])
        ),
        "Entra ID P2 / Identity Protection": (
            has_e5 or contains_any(joined, ["AAD_PREMIUM_P2", "EMSPREMIUM", "IDENTITY_THREAT_PROTECTION"])
        ),
        "Entra ID P2 / PIM": (
            has_e5 or contains_any(joined, ["AAD_PREMIUM_P2", "EMSPREMIUM", "PIM"])
        ),
        "Intune / Device Compliance": (
            has_e3 or has_e5 or contains_any(joined, ["INTUNE", "EMS", "MICROSOFT_INTUNE"])
        ),
        "Defender for Endpoint": (
            has_e5 or contains_any(joined, [
                "DEFENDER_ENDPOINT",
                "MDE",
                "MDATP",
                "WDATP",
                "WINDEFATP",
                "MICROSOFT_DEFENDER_FOR_ENDPOINT",
                "WINDOWS_DEFENDER_ADVANCED_THREAT_PROTECTION",
                "THREAT_PROTECTION",
            ])
        ),
        "Defender for Identity": (
            has_e5 or contains_any(joined, [
                "DEFENDER_IDENTITY",
                "AZURE_ADVANCED_THREAT_PROTECTION",
                "ATA",
                "MDI",
            ])
        ),
        "Defender for Cloud Apps": (
            has_e5 or contains_any(joined, [
                "ADALLOM",
                "MCAS",
                "MDCA",
                "DEFENDER_CLOUD_APPS",
                "CLOUD_APP_SECURITY",
            ])
        ),
        "Defender for Office 365": (
            has_e5 or contains_any(joined, [
                "ATP_ENTERPRISE",
                "MDO",
                "DEFENDER_OFFICE",
                "OFFICE_365_ADVANCED_THREAT_PROTECTION",
                "THREAT_INTELLIGENCE",
            ])
        ),
        "Entra ID / App Consent": True,
        "Entra ID / App Registration": True,
        "Entra ID / Enterprise Apps": True,
        "Entra ID / Sign-in Logs": True,
        "Hybrid Identity": len(preflight.get("synced_user_sample") or []) > 0,
    }


def get_effective_capabilities(detected_caps: Dict[str, bool]) -> Dict[str, bool]:
    effective = dict(detected_caps)

    if "cap_overrides" not in st.session_state:
        st.session_state.cap_overrides = {}

    for cap_name, value in detected_caps.items():
        if cap_name not in st.session_state.cap_overrides:
            st.session_state.cap_overrides[cap_name] = value

    for cap_name, value in st.session_state.cap_overrides.items():
        effective[cap_name] = value

    return effective



def get_dynamic_scope(scenario: dict) -> str:
    for key in ["scope", "Scope", "environment", "environment_scope", "EnvironmentScope"]:
        value = str(scenario.get(key, "")).strip()
        if value:
            return value

    scenario_id = str(scenario.get("id", scenario.get("scenario_id", ""))).upper()
    pillar = str(scenario.get("pillar", "")).strip()

    if scenario_id.startswith("ID-H"):
        return "Hybrid"

    if scenario_id.startswith("ID-C"):
        return "Cloud"

    if scenario_id.startswith("APP"):
        return "Cloud"

    if pillar == "Endpoint":
        return "Device"

    if pillar == "Applications":
        return "Cloud"

    return "Cloud"


def clean_dynamic_value(value: object) -> str:
    text = str(value or "")
    text = text.replace("<h3>", "").replace("</h3>", "")
    text = text.replace("<p>", "").replace("</p>", "")
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()

def clean_dynamic_value(value: object) -> str:
    text = str(value or "")
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(
        r"^(Scenario Objective|Controlled Action|Expected Result|Evidence Required|Decoy / Test Object|Decoy/Test Object)\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text


def sanitize_dynamic_catalog(scenarios: list) -> list:
    for scenario in scenarios:
        for key in [
            "goal",
            "objective",
            "description",
            "decoys",
            "test_action",
            "evidence",
            "expected",
        ]:
            if key in scenario:
                scenario[key] = clean_dynamic_value(scenario.get(key))
    return scenarios
def get_dynamic_id(scenario: dict) -> str:
    return str(
        scenario.get("id")
        or scenario.get("scenario_id")
        or scenario.get("ScenarioId")
        or ""
    ).strip()


def is_privileged_mfa_probe(scenario: dict) -> bool:
    scenario_id = get_dynamic_id(scenario).upper()
    name = str(scenario.get("name", scenario.get("Name", ""))).lower()

    return (
        scenario_id in ["ID-C-001", "ID-DV-001"]
        or "privileged mfa" in name
        or "privileged mfa enforcement" in name
    )
def dynamic_support(scenario: Dict[str, Any], caps: Dict[str, bool]) -> str:
    required = scenario.get("requires") or []
    missing = [r for r in required if not caps.get(r, False)]
    return "LIMITED" if missing else "SUPPORTED"


def run_assessment_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    scenario_id = scenario.get("ScenarioId", "")
    engine_path = scenario.get("EnginePath", "")
    function_name = scenario.get("FunctionName", "")

    if not scenario_id or not engine_path or not function_name:
        return {"ok": False, "stdout": "", "stderr": "Missing engine/function metadata.", "json_path": ""}

    ps_lines = [
        '$ErrorActionPreference = "Stop"',
        f"Set-Location -Path {ps_quote(PROJECT_ROOT)}",
        f"$enginePath = {ps_quote(engine_path)}",
        f"$functionName = {ps_quote(function_name)}",
        f"$scenarioId = {ps_quote(scenario_id)}",
        'if (-not (Test-Path $enginePath)) { throw "Engine file not found: $enginePath" }',
        ". $enginePath",
        'if (-not (Get-Command $functionName -ErrorAction SilentlyContinue)) { throw "Scenario function not found: $functionName" }',
        "$result = & $functionName",
        '$reportsDir = ".\\powershell\\Reports"',
        '$htmlDir = ".\\powershell\\Reports\\Html"',
        "New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null",
        "New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null",
        '$jsonPath = Join-Path $reportsDir "$scenarioId-result.json"',
        "$result | ConvertTo-Json -Depth 80 | Set-Content -Path $jsonPath -Encoding UTF8",
        '$converter = ".\\powershell\\Tools\\Convert-ZTVPReportToHtml.ps1"',
        'if (Test-Path $converter) { try { & $converter -JsonPath $jsonPath | Out-Host } catch { Write-Warning $_.Exception.Message } }',
        'Write-Host "ZTVP_RESULT_JSON=$jsonPath"',
    ]
    result = run_powershell("\n".join(ps_lines), timeout=900)
    result["json_path"] = str(REPORTS_DIR / f"{scenario_id}-result.json")
    return result


def list_reports() -> List[Path]:
    if not REPORTS_DIR.exists():
        return []
    return sorted(REPORTS_DIR.glob("*-result.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def load_report(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def render_report(report: Dict[str, Any]) -> None:
    sid = report.get("scenario_id", "Unknown")
    name = report.get("scenario_name", "Unknown")
    status = report.get("status", "Unknown")
    risk = report.get("risk", "Unknown")
    evidence = report.get("evidence") or {}

    status_kind = "good" if status == "PASS" else "warn" if status == "PARTIAL" else "bad"
    risk_kind = "good" if risk == "LOW" else "warn" if risk == "MEDIUM" else "bad"

    st.markdown(
        f"""
<div class="ztvp-card">
    <h2>{esc(sid)} — {esc(name)}</h2>
    {badge(status, status_kind)}
    {badge(risk, risk_kind)}
</div>
""",
        unsafe_allow_html=True,
    )

    if evidence.get("executive_summary"):
        st.info(evidence["executive_summary"])

    findings = report.get("findings") or []
    recommendations = report.get("recommendations") or []

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Findings")
        if findings:
            for f in findings:
                st.markdown(
                    f'<div class="finding-box"><b>{esc(f.get("title", "Finding"))}</b><br>{esc(f.get("detail", ""))}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown('<div class="good-box"><b>No findings</b></div>', unsafe_allow_html=True)

    with col2:
        st.markdown("### Recommendations")
        if recommendations:
            for r in recommendations:
                st.markdown(
                    f'<div class="rec-box"><b>{esc(r.get("title", "Recommendation"))}</b><br>{esc(r.get("detail", ""))}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown('<div class="good-box"><b>No recommendations</b></div>', unsafe_allow_html=True)


if "connected" not in st.session_state:
    st.session_state.connected = PREFLIGHT_PATH.exists()

if "home_mode" not in st.session_state:
    st.session_state.home_mode = "home"

if "dynamic_pillar" not in st.session_state:
    st.session_state.dynamic_pillar = None

if "dynamic_scenario_id" not in st.session_state:
    st.session_state.dynamic_scenario_id = None

if st.session_state.home_mode == "assessment":
    st.session_state.home_mode = "home"


def go_home() -> None:
    st.session_state.home_mode = "home"
    st.session_state.dynamic_pillar = None
    st.session_state.dynamic_scenario_id = None
    st.session_state.pop("ztvp_dynamic_open_scenario", None)


def handle_sidebar_navigation() -> None:
    if st.session_state.get("main_navigation") == "Home":
        go_home()

assessment_scenarios = load_assessment_scenarios()
reports = list_reports()
preflight = load_preflight()
detected_caps = detect_capabilities(preflight) if preflight else {}
caps = get_effective_capabilities(detected_caps) if detected_caps else {}


st.sidebar.markdown(
    """
<div class="ztvp-sidebar-brand">
  <div class="ztvp-sidebar-brand-title">🛡️ ZTVP</div>
  <div class="ztvp-sidebar-brand-subtitle">Zero Trust Validation Platform</div>
</div>
""",
    unsafe_allow_html=True,
)

if st.session_state.connected:
    page = st.sidebar.radio(
        "Navigation",
        ["Home", "Active Runs", "Reports"],
        key="main_navigation",
        on_change=handle_sidebar_navigation,
    )
else:
    page = "Connect Tenant"
    st.sidebar.info("Connect to a tenant first.")

st.sidebar.markdown("---")
st.sidebar.caption("Dynamic Validation · Simulation · Reports")


if not st.session_state.connected:
    hero(
        "Connect Client Tenant",
        "Sign in first. ZTVP discovers tenant subscriptions and capabilities before showing scenarios.",
    )

    st.markdown(
        """
<div class="ztvp-card">
    <h2>Tenant pre-flight discovery</h2>
    <p>
        ZTVP connects to Microsoft Graph and collects tenant identity, subscriptions/SKUs,
        service plans, domains, and hybrid identity signals. This allows the platform to
        suggest scenarios that make sense for the client environment.
    </p>
</div>
""",
        unsafe_allow_html=True,
    )

    if st.button("Connect Tenant and Run Discovery", type="primary", use_container_width=True):
        with st.spinner("Connecting to Microsoft Graph and running pre-flight discovery..."):
            result = run_tenant_connection()

        if result["ok"]:
            st.session_state.connected = True
            st.success("Tenant connected and discovery completed.")
            st.rerun()
        else:
            st.error("Connection or discovery failed.")
            if result["stderr"].strip():
                st.code(result["stderr"][-6000:], language="text")
            if result["stdout"].strip():
                with st.expander("PowerShell output"):
                    st.code(result["stdout"][-6000:], language="text")

    st.stop()


if page == "Home":
    if st.session_state.home_mode == "home":
        hero(
            "Zero Trust Validation Platform",
            "ZTVP validates whether Microsoft security controls actually work in real tenant conditions.",
        )
        st.caption("Run controlled validation scenarios, collect endpoint and tenant evidence, and export consultant-ready results.")

        st.markdown(
            """
<div class="ztvp-section">
  <h3>Validation Workbench</h3>
  <p>Run controlled validation scenarios and preview tenant security changes.</p>
</div>
""",
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2, gap="large")

        with col1:
            with st.container(border=True):
                st.markdown(
                    """
<div class="ztvp-home-module-card"></div>
<div class="ztvp-feature-icon">🧪</div>
<div class="ztvp-container-card-title">Dynamic Validation</div>
<p class="ztvp-container-card-text">Run controlled scenarios with endpoint actions, tenant logs, Defender evidence, and clean verdicts.</p>
<div class="ztvp-home-badge-row">
  <span class="ztvp-home-badge">Controlled tests</span>
  <span class="ztvp-home-badge">Tenant evidence</span>
  <span class="ztvp-home-badge">Endpoint actions</span>
  <span class="ztvp-home-badge">Clean verdicts</span>
</div>
<div class="ztvp-home-action"></div>
""",
                    unsafe_allow_html=True,
                )

                if st.button("Open Dynamic Validation", type="primary"):
                    st.session_state.home_mode = "dynamic"
                    st.session_state.dynamic_pillar = None
                    st.session_state.dynamic_scenario_id = None
                    st.session_state.pop("ztvp_dynamic_open_scenario", None)
                    st.rerun()

        with col2:
            with st.container(border=True):
                st.markdown(
                    """
<div class="ztvp-home-module-card"></div>
<div class="ztvp-feature-icon">🔮</div>
<div class="ztvp-container-card-title">Simulation</div>
<p class="ztvp-container-card-text">Preview planned changes and understand likely tenant impact before configuration updates.</p>
<div class="ztvp-home-badge-row">
  <span class="ztvp-home-badge">Planned changes</span>
  <span class="ztvp-home-badge">Impact preview</span>
  <span class="ztvp-home-badge">Risk review</span>
  <span class="ztvp-home-badge">Consultant notes</span>
</div>
<div class="ztvp-home-action"></div>
""",
                    unsafe_allow_html=True,
                )

                if st.button("Open Simulation", type="primary"):
                    st.session_state.home_mode = "simulation"
                    st.rerun()

        st.markdown('<div class="ztvp-capabilities-section"><h3>Detected Tenant Capabilities</h3></div>', unsafe_allow_html=True)

        cap_rows = []
        for cap_name, detected_value in detected_caps.items():
            cap_rows.append(
                {
                    "Capability": cap_name,
                    "Auto Detected": "YES" if detected_value else "NO",
                    "Effective": "YES" if caps.get(cap_name, False) else "NO",
                }
            )

        st.dataframe(pd.DataFrame(cap_rows), use_container_width=True, hide_index=True)

        with st.expander("Consultant capability override"):
            st.write(
                "Use this if a product exists in the client environment but the SKU/service-plan name was not detected cleanly."
            )

            for cap_name in sorted(detected_caps.keys()):
                st.session_state.cap_overrides[cap_name] = st.checkbox(
                    cap_name,
                    value=bool(st.session_state.cap_overrides.get(cap_name, detected_caps.get(cap_name, False))),
                    key=f"cap_override_{cap_name}",
                )

            st.info("Overrides affect scenario support/suggestions in this UI only.")

    elif st.session_state.home_mode == "assessment":
        hero(
            "Assessment",
            "Browse and run your existing assessment scenarios using the current ZTVP structure.",
        )

        if st.button("← Back to Home"):
            st.session_state.home_mode = "home"
            st.rerun()

        if not assessment_scenarios:
            st.warning("No assessment scenarios were detected.")
            st.stop()

        col1, col2, col3 = st.columns(3)

        with col1:
            pillar = st.selectbox("Pillar", ordered_unique(assessment_scenarios, "PillarName", PILLAR_ORDER))

        pillar_items = [s for s in assessment_scenarios if s.get("PillarName") == pillar]

        with col2:
            category = st.selectbox("Category", ordered_unique(pillar_items, "CategoryName", CATEGORY_ORDER))

        category_items = [s for s in pillar_items if s.get("CategoryName") == category]

        with col3:
            scope = st.selectbox("Scope", ordered_unique(category_items, "Scope", SCOPE_ORDER))

        filtered = [s for s in category_items if get_dynamic_scope(s) == scope]

        rows = []
        for s in filtered:
            rows.append(
                {
                    "ID": s.get("ScenarioId"),
                    "Scenario": s.get("Name"),
                    "Priority": s.get("Priority"),
                    "Phase": s.get("Phase"),
                    "Status": "READY" if s.get("Implemented") is True else "PLANNED",
                    "Objective": s.get("Objective"),
                }
            )

        st.markdown("### Assessment Scenarios")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=330)

        ready = [s for s in filtered if s.get("Implemented") is True]

        if ready:
            selected = st.selectbox(
                "Select scenario",
                ready,
                format_func=lambda x: f"{x.get('ScenarioId')} — {x.get('Name')}",
            )

            st.markdown(
                f"""
<div class="ztvp-card">
    <h2>{esc(selected.get("ScenarioId"))} — {esc(selected.get("Name"))}</h2>
    <p>{esc(selected.get("Objective"))}</p>
    {badge("ASSESSMENT", "info")}
    {badge("READY", "good")}
    {badge(selected.get("Priority", ""), "bad" if selected.get("Priority") in ["Critical", "High"] else "warn")}
    {badge(selected.get("Scope", ""), "info")}
</div>
""",
                unsafe_allow_html=True,
            )

            if st.button("Run Assessment Scenario", type="primary", use_container_width=True):
                with st.spinner(f"Running {selected.get('ScenarioId')}..."):
                    result = run_assessment_scenario(selected)

                if result["ok"]:
                    st.success("Assessment completed and report saved.")
                    st.code(result["json_path"], language="text")
                    if result["stdout"].strip():
                        with st.expander("Execution output"):
                            st.code(result["stdout"][-6000:], language="text")
                else:
                    st.error("Assessment failed.")
                    if result["stderr"].strip():
                        st.code(result["stderr"][-6000:], language="text")
                    if result["stdout"].strip():
                        with st.expander("PowerShell output"):
                            st.code(result["stdout"][-6000:], language="text")
        else:
            st.warning("No READY assessment scenarios in this selection.")




    elif st.session_state.home_mode == "dynamic":
        render_dynamic_validation_page(
            scenarios=DYNAMIC_SCENARIOS,
            caps=caps,
            project_root=PROJECT_ROOT,
            hero=hero,
            badge=badge,
            dynamic_support=dynamic_support,
            render_idc001_runner=render_idc001_runner,
        )

    elif st.session_state.home_mode == "simulation":
        render_simulation_page(PROJECT_ROOT)

elif page == "Active Runs":
    render_active_runs_page(PROJECT_ROOT, hero=hero)

elif page == "Reports":
    hero(
        "Reports",
        "In production, not ready yet.",
    )

    st.markdown(
        """
<div class="ztvp-card">
    <h2>Reports workspace</h2>
    <p>This page is in production and is not ready yet.</p>
</div>
""",
        unsafe_allow_html=True,
    )

