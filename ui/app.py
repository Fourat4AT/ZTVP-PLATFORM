from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st


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
    background: #0f172a;
}

section[data-testid="stSidebar"] * {
    color: #e5e7eb !important;
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

/* Make normal buttons look like clickable cards */
.stButton > button {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #dbe4f0 !important;
    border-radius: 22px !important;
    padding: 1.1rem 1.2rem !important;
    font-weight: 800 !important;
    min-height: 104px;
    text-align: left !important;
    white-space: normal !important;
    box-shadow: 0 10px 28px rgba(15, 23, 42, .07);
    transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease, background .15s ease;
}

.stButton > button:hover {
    background: #eff6ff !important;
    color: #0f172a !important;
    border-color: #2563eb !important;
    transform: translateY(-2px);
    box-shadow:0 16px 36px rgba(15,23,42,.12);
}

.stButton > button p {
    color: #0f172a !important;
}

/* Primary buttons keep action color */
div[data-testid="stButton"] button[kind="primary"] {
    background: #2563eb !important;
    color: #ffffff !important;
    text-align: center !important;
}

div[data-testid="stButton"] button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    color: #ffffff !important;
}

[data-testid="stDataFrame"] {
    background:white !important;
    border-radius:18px !important;
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

assessment_scenarios = load_assessment_scenarios()
reports = list_reports()
preflight = load_preflight()
detected_caps = detect_capabilities(preflight) if preflight else {}
caps = get_effective_capabilities(detected_caps) if detected_caps else {}


st.sidebar.title("🛡️ ZTVP")

if st.session_state.connected:
    page = st.sidebar.radio("Navigation", ["Home", "Reports"])
else:
    page = "Connect Tenant"
    st.sidebar.info("Connect to a tenant first.")

st.sidebar.markdown("---")
st.sidebar.caption("Assessment · Dynamic Validation · Simulation")


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
            "Choose the workflow: Assessment, Dynamic Validation, or Simulation.",
        )

        org = preflight.get("organization") if preflight else {}
        org_name = org.get("displayName") if isinstance(org, dict) else "Connected tenant"

        st.markdown(
            f"""
<div class="ztvp-card">
    <h2>{esc(org_name or "Connected tenant")}</h2>
    <p class="ztvp-muted">Tenant ID: {esc(preflight.get("tenant_id", "")) if preflight else ""}</p>
    {badge("CONNECTED", "good")}
</div>
""",
            unsafe_allow_html=True,
        )

        m1, m2, m3 = st.columns(3)
        m1.metric("Assessment Scenarios", len(assessment_scenarios))
        m2.metric("Dynamic Validation Use Cases", len(DYNAMIC_SCENARIOS))
        m3.metric("Reports", len(reports))

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button(
                "Assessment\n\nExisting ZTVP checks: pillar, category, scope, scenario. Keep your current baseline and configuration assessment work.",
                type="primary",
                use_container_width=True,
            ):
                st.session_state.home_mode = "assessment"
                st.rerun()

        with col2:
            if st.button(
                "Dynamic Validation\n\nReal-life validation use cases with decoys, controlled actions, Microsoft logs, CA decisions, Defender evidence, and expected outcomes.",
                use_container_width=True,
            ):
                st.session_state.home_mode = "dynamic"
                st.session_state.dynamic_pillar = None
                st.session_state.dynamic_scenario_id = None
                st.rerun()

        with col3:
            if st.button(
                "Simulation\n\nFuture what-if module for previewing planned tenant or AD changes before applying them.",
                use_container_width=True,
            ):
                st.session_state.home_mode = "simulation"
                st.rerun()

        st.markdown("## Detected Tenant Capabilities")

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

        filtered = [s for s in category_items if s.get("Scope") == scope]

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
        hero(
            "Dynamic Validation",
            "Choose a pillar, then review real-life validation scenarios using decoys, controlled actions, and Microsoft evidence.",
        )

        if st.button("← Back to Home"):
            st.session_state.home_mode = "home"
            st.session_state.dynamic_pillar = None
            st.session_state.dynamic_scenario_id = None
            st.rerun()

        if st.session_state.dynamic_pillar is None:
            st.markdown("## Choose a Pillar")

            pillar_names = ["Identity", "Endpoint", "Applications"]
            cols = st.columns(3)

            for index, pillar_name in enumerate(pillar_names):
                pillar_items = [s for s in DYNAMIC_SCENARIOS if s["pillar"] == pillar_name]
                supported_count = len([s for s in pillar_items if dynamic_support(s, caps) == "SUPPORTED"])
                limited_count = len(pillar_items) - supported_count

                with cols[index]:
                    if st.button(
                        f"{pillar_name}\n\n{len(pillar_items)} scenario(s). {supported_count} supported, {limited_count} limited based on discovered capabilities.",
                        key=f"open_dynamic_{pillar_name}",
                        use_container_width=True,
                    ):
                        st.session_state.dynamic_pillar = pillar_name
                        st.session_state.dynamic_scenario_id = None
                        st.rerun()

            st.markdown("## What Dynamic Validation Means")
            st.markdown(
                """
<div class="ztvp-card">
    <h3>Not just configuration checking</h3>
    <p>
        Dynamic Validation is the evidence-based layer. It uses decoy users, test devices,
        controlled sign-ins, app consent attempts, Defender signals, audit logs, Conditional Access decisions,
        and Microsoft telemetry to prove whether controls work in real life.
    </p>
</div>
""",
                unsafe_allow_html=True,
            )

        else:
            selected_pillar = st.session_state.dynamic_pillar
            pillar_items = [s for s in DYNAMIC_SCENARIOS if s["pillar"] == selected_pillar]

            if st.button("← Back to Pillars"):
                st.session_state.dynamic_pillar = None
                st.session_state.dynamic_scenario_id = None
                st.rerun()

            st.markdown(f"## {esc(selected_pillar)} Dynamic Validation Scenarios")

            supported_items = [s for s in pillar_items if dynamic_support(s, caps) == "SUPPORTED"]
            limited_items = [s for s in pillar_items if dynamic_support(s, caps) == "LIMITED"]

            a, b, c = st.columns(3)
            a.metric("Total Scenarios", len(pillar_items))
            b.metric("Supported", len(supported_items))
            c.metric("Limited", len(limited_items))

            st.markdown("### Scenarios")

            for scenario in pillar_items:
                support = dynamic_support(scenario, caps)
                support_kind = "good" if support == "SUPPORTED" else "warn"
                priority_kind = "bad" if scenario["priority"] == "Critical" else "warn"

                st.markdown(
                    f"""
<div class="ztvp-card">
    <h3>{esc(scenario["id"])} — {esc(scenario["name"])}</h3>
    <p class="ztvp-muted">{esc(scenario["use_case"])}</p>
    <p>{esc(scenario["goal"])}</p>
    {badge("DYNAMIC VALIDATION", "info")}
    {badge(scenario["status"], "warn")}
    {badge(scenario["priority"], priority_kind)}
    {badge(support, support_kind)}
</div>
""",
                    unsafe_allow_html=True,
                )

                if st.button(
                    f"Open {scenario['id']}",
                    key=f"open_dynamic_scenario_{scenario['id']}",
                    use_container_width=True,
                ):
                    st.session_state.dynamic_scenario_id = scenario["id"]
                    st.rerun()

            if st.session_state.dynamic_scenario_id:
                selected_list = [s for s in pillar_items if s["id"] == st.session_state.dynamic_scenario_id]

                if selected_list:
                    selected = selected_list[0]
                    support = dynamic_support(selected, caps)

                    st.markdown("---")
                    st.markdown("## Selected Scenario")

                    st.markdown(
                        f"""
<div class="ztvp-card">
    <h2>{esc(selected["id"])} — {esc(selected["name"])}</h2>
    <p>{esc(selected["goal"])}</p>
    {badge("DYNAMIC VALIDATION", "info")}
    {badge(selected["status"], "warn")}
    {badge(selected["priority"], "bad" if selected["priority"] == "Critical" else "warn")}
    {badge(support, "good" if support == "SUPPORTED" else "warn")}
</div>
""",
                        unsafe_allow_html=True,
                    )

                    left, right = st.columns(2)

                    with left:
                        st.markdown(
                            f"""
<div class="ztvp-card">
    <h3>Controlled Test</h3>
    <p><b>Use case</b><br>{esc(selected["use_case"])}</p>
    <p><b>Decoys / test objects</b><br>{esc(selected["decoys"])}</p>
    <p><b>Controlled action</b><br>{esc(selected["test_action"])}</p>
</div>
""",
                            unsafe_allow_html=True,
                        )

                    with right:
                        st.markdown(
                            f"""
<div class="ztvp-card">
    <h3>Evidence Model</h3>
    <p><b>Evidence sources</b><br>{esc(selected["evidence"])}</p>
    <p><b>Expected result</b><br>{esc(selected["expected"])}</p>
</div>
""",
                            unsafe_allow_html=True,
                        )

                    st.markdown("### Required Capabilities")

                    req_rows = []
                    for required in selected.get("requires", []):
                        req_rows.append(
                            {
                                "Capability": required,
                                "Detected": "YES" if caps.get(required, False) else "NO",
                            }
                        )

                    st.dataframe(pd.DataFrame(req_rows), use_container_width=True, hide_index=True)

                    if support == "SUPPORTED":
                        st.info("This scenario is supported by the discovered tenant capabilities. Next step is to implement the probe engine.")
                    else:
                        st.warning("This scenario is limited for this tenant because one or more required capabilities were not detected.")

                    st.markdown(
                        """
<div class="warn-box">
    <b>Implementation next step:</b><br>
    Build the probe engine for this scenario: create/use decoys, run the controlled action,
    collect Microsoft evidence, compare actual result with expected result, then export an evidence report.
</div>
""",
                        unsafe_allow_html=True,
                    )

    elif st.session_state.home_mode == "simulation":
        hero(
            "Simulation",
            "Future what-if module for previewing planned changes before applying them.",
        )

        if st.button("← Back to Home"):
            st.session_state.home_mode = "home"
            st.rerun()

        st.markdown(
            """
<div class="warn-box">
    <b>Simulation is planned for a later phase.</b><br>
    It will help consultants preview what may happen before changing a tenant or AD environment.
    First priority is implementing Dynamic Validation probe engines.
</div>
""",
            unsafe_allow_html=True,
        )

        st.write("Future simulation flow:")
        st.write("1. Select pillar/use case/scenario.")
        st.write("2. Load current evidence.")
        st.write("3. Define planned change.")
        st.write("4. Preview expected impact.")
        st.write("5. Apply manually.")
        st.write("6. Re-run validation.")


elif page == "Reports":
    hero(
        "Reports",
        "Review saved assessment reports and evidence.",
    )

    if not reports:
        st.info("No reports found yet.")
        st.stop()

    selected_report = st.selectbox("Select report", reports, format_func=lambda p: p.name)
    render_report(load_report(selected_report))


