from __future__ import annotations

import html
from pathlib import Path
from typing import Any

import streamlit as st

try:
    from dynamic_idc002 import render_idc002_runner
except Exception:
    render_idc002_runner = None

try:
    from dynamic_idc003 import render_idc003_runner
except Exception:
    render_idc003_runner = None

try:
    from dynamic_idc004 import render_idc004_runner
except Exception:
    render_idc004_runner = None

try:
    from dynamic_idc005 import render_idc005_runner
except Exception:
    render_idc005_runner = None



try:
    from dynamic_cld001 import render_cld001_runner
except Exception:
    render_cld001_runner = None



try:
    from dynamic_appc002 import render_appc002_runner
except Exception:
    render_appc002_runner = None



try:
    from dynamic_appc003 import render_appc003_runner
except Exception:
    render_appc003_runner = None


try:
    from dynamic_appdv004 import render_appdv004_runner
except Exception:
    render_appdv004_runner = None



try:
    from dynamic_appdv007 import render_appdv007_runner
except Exception:
    render_appdv007_runner = None


try:
    from dynamic_appdv001 import render_appdv001_runner
except Exception:
    render_appdv001_runner = None


try:
    from dynamic_idv006 import render_idv006_runner
except Exception:
    render_idv006_runner = None



try:
    from dynamic_devdv001 import render_devdv001_runner
except Exception:
    render_devdv001_runner = None



try:
    from dynamic_devdv004 import render_devdv004_runner
except Exception:
    render_devdv004_runner = None

try:
    from dynamic_devdv006 import render_devdv006_runner
except Exception:
    render_devdv006_runner = None

try:
    from dynamic_devdv008 import render_devdv008_runner
except Exception:
    render_devdv008_runner = None


BUILTINS = {
    "DEV-DV-004": {
        "display_id": "DEV-DV-004",
        "scenario_id": "DEV-DV-004",
        "name": "Hybrid Tamper Protection Validation",
        "pillar": "Devices",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether Microsoft Defender Tamper Protection prevents or ignores attempts to weaken Defender security settings on a controlled endpoint, and whether Microsoft Defender XDR captures tenant-side evidence.",
        "decoy": "Controlled Windows VM or test endpoint with Microsoft Defender Antivirus and Defender for Endpoint where available.",
        "action": "Run a generated VM-side PowerShell script that attempts controlled Set-MpPreference changes, then import endpoint evidence and query Defender XDR Advanced Hunting.",
        "evidence": "Fresh VM evidence, Defender status/preferences before and after, tamper attempt results, Defender XDR Advanced Hunting evidence, JSON and HTML report.",
        "expected": "Tamper Protection is enabled, protected Defender settings remain enabled, and Defender XDR captures tenant-side evidence for the validation window.",
    },
    "DEV-DV-003": {
        "display_id": "DEV-DV-003",
        "scenario_id": "DEV-DV-003",
        "name": "Defender EICAR Detection Validation",
        "pillar": "Devices",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether Defender detects and blocks a harmless EICAR antivirus test file on a controlled VM/test endpoint.",
        "decoy": "Separate VM or test endpoint running Microsoft Defender Antivirus.",
        "action": "Run the generated VM-side PowerShell script to create the standard harmless EICAR file, trigger local Defender, and import local JSON evidence into ZTVP.",
        "evidence": "Local VM evidence, Get-MpComputerStatus, Get-MpThreatDetection, Get-MpThreat where available, JSON and HTML report.",
        "expected": "Defender detects, blocks, quarantines, or removes the EICAR test file during the validation window.",
    },
    "DEV-DV-002": {
        "display_id": "DEV-DV-002",
        "scenario_id": "DEV-DV-002",
        "name": "Sandbox Device Registration Abuse Probe",
        "pillar": "Devices",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a normal decoy user can register a new unmanaged Windows Sandbox device identity from the cloud access path.",
        "decoy": "Temporary normal Entra ID decoy user created by ZTVP.",
        "action": "Launch Windows Sandbox, attempt Access work or school registration using the decoy user, then wait for Entra device/audit/sign-in evidence.",
        "evidence": "Decoy user, validation window, Sandbox launch, registered device evidence, audit/sign-in evidence, cleanup record, JSON and HTML report.",
        "expected": "Normal users should not be able to freely register unmanaged devices unless explicitly allowed and protected by policy.",
    },
    "DEV-DV-001": {
        "display_id": "DEV-DV-001",
        "scenario_id": "DEV-DV-001",
        "name": "Unmanaged Device Cloud Access Probe",
        "pillar": "Devices",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a normal user can access Microsoft 365 from an unmanaged or non-compliant device context.",
        "decoy": "Temporary normal Entra ID decoy user created by ZTVP.",
        "action": "Attempt Microsoft 365 access from a clean unmanaged VM or InPrivate browser, then inspect Entra sign-in logs for device trust and Conditional Access evidence.",
        "evidence": "Decoy user, target cloud app, sign-in status, device compliance/management details, Conditional Access result, blocking policy, JSON and HTML report.",
        "expected": "Unmanaged or non-compliant device access should be blocked or require a compliant/managed device.",
    },
    "APP-C-003": {
        "display_id": "APP-DV-003",
        "scenario_id": "APP-C-003",
        "name": "MDCA Public File Sharing Detection Validation",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether MDCA detects or remediates a controlled SharePoint public/anonymous file sharing exposure.",
        "decoy": "Temporary harmless SharePoint dummy file created by ZTVP in a controlled document library.",
        "action": "Create an anonymous public sharing link, automatically poll MDCA Alerts API for matching detection evidence, then remove the link and dummy file.",
        "evidence": "SharePoint site/drive/file evidence, anonymous createLink result, MDCA alert API evidence, remediation evidence, cleanup record, JSON and HTML report.",
        "expected": "The controlled public file exposure should be detected by MDCA policy and/or remediated by governance action.",
    },
    "APP-DV-004": {
        "display_id": "APP-DV-004",
        "scenario_id": "APP-DV-004",
        "name": "Sensitive App Access From Unmanaged Device Probe",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate that a selected sensitive application cannot be accessed from a non-compliant or unmanaged endpoint.",
        "decoy": "Controlled test user and Windows Sandbox or another unmanaged/non-compliant endpoint.",
        "action": "Manually access the target cloud app from the unmanaged endpoint, then poll Entra sign-in logs for Conditional Access evidence.",
        "evidence": "Microsoft Graph signIns, Conditional Access result, applied policies, device compliance/management context, JSON and HTML report.",
        "expected": "Conditional Access blocks access because the device is not compliant or unmanaged.",
    },
    "APP-C-002": {
        "display_id": "APP-DV-002",
        "scenario_id": "APP-C-002",
        "name": "Exchange External Mail Forwarding Exposure Validation",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a controlled Exchange Online mailbox can configure automatic external forwarding or redirect rules.",
        "decoy": "Temporary licensed Exchange Online decoy mailbox created by ZTVP.",
        "action": "Attempt mailbox-level external forwarding and inbox-rule redirect/forwarding to a consultant-controlled external address, then remove test artifacts.",
        "evidence": "Mailbox readiness, Set-Mailbox forwarding result, New-InboxRule result, final forwarding state, cleanup record, JSON and HTML report.",
        "expected": "External automatic forwarding and redirect configuration should be blocked or rejected.",
    },
    "CLD-C-001": {
        "display_id": "APP-DV-008",
        "scenario_id": "CLD-C-001",
        "name": "SharePoint Anonymous Sharing Link Exposure Validation",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether SharePoint allows anonymous/public sharing links for a controlled dummy file.",
        "decoy": "Temporary dummy SharePoint file created by ZTVP in the selected site document library.",
        "action": "Attempt to create an anonymous sharing link using Microsoft Graph createLink, then clean up the dummy file and permission.",
        "evidence": "Microsoft Graph createLink outcome, site and drive evidence, anonymous permission result, cleanup record, JSON and HTML report.",
        "expected": "Anonymous sharing link creation should be denied. No public anonymous link should remain after the validation.",
    },
    "APP-DV-007": {
        "display_id": "APP-DV-007",
        "scenario_id": "APP-DV-007",
        "name": "App Registration Permission Probe",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a normal non-admin user can create Entra ID app registrations.",
        "decoy": "Temporary harmless Entra ID app registration created by ZTVP.",
        "action": "Attempt to create a basic app registration with no secrets, certificates, redirect URIs, or API permissions, then delete it.",
        "evidence": "Connected account, tenant ID, app registration creation result, authorization error if blocked, cleanup result, JSON and HTML report.",
        "expected": "A normal non-admin user should not be able to create app registrations unless this is explicitly allowed by policy.",
    },
    "APP-DV-001": {
        "display_id": "APP-DV-001",
        "scenario_id": "APP-DV-001",
        "name": "Enterprise App Assignment Enforcement Probe",
        "pillar": "Applications",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether an unassigned user is actually denied access to an enterprise application that requires user assignment.",
        "decoy": "Temporary standard decoy user and a controlled assignment-required enterprise application created by ZTVP. The decoy user is intentionally not assigned.",
        "action": "Sign in as the decoy user to the controlled assignment-required enterprise app, then evaluate whether Entra blocks the unassigned user.",
        "evidence": "Connected account, tenant ID, target app, sign-in result, assignment-required authorization block (AADSTS50105) if denied, cleanup result, JSON and HTML report.",
        "expected": "An unassigned user should be denied access to an enterprise application that requires user assignment.",
    },
    "ID-DV-006": {
        "display_id": "ID-DV-006",
        "scenario_id": "ID-DV-006",
        "name": "Sign-in Risk Conditional Access Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether the tenant has an effective Conditional Access response (block or MFA/strong authentication) for risky sign-ins.",
        "decoy": "Temporary standard decoy user created by ZTVP. The tester triggers risky sign-in behavior (TOR/VPN/unusual location and/or repeated wrong passwords) then signs in correctly.",
        "action": "Start the evidence window, perform the risky sign-in test as the decoy, then poll Entra sign-in logs and Conditional Access policies for the enforcement result.",
        "evidence": "Enabled sign-in risk Conditional Access policies, sign-in risk level/state, Conditional Access result, applied policies, JSON and HTML report.",
        "expected": "A risky sign-in is blocked or challenged with MFA/strong authentication by an enabled Conditional Access policy.",
    },
    "ID-C-001": {
        "display_id": "ID-DV-001",
        "scenario_id": "ID-C-001",
        "name": "Privileged Access MFA Enforcement Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "Critical",
        "support": "SUPPORTED",
        "goal": "Validate whether the tenant prevents password-only access to administrative resources for a fresh privileged decoy identity.",
        "decoy": "Fresh temporary decoy user created for the validation run and assigned a selected privileged role such as Security Reader.",
        "action": "Attempt a real interactive sign-in to Azure Portal or an administrative resource using the privileged decoy account.",
        "evidence": "Microsoft Entra interactive sign-in logs, MFA evidence, app/resource accessed, Conditional Access status, applied policy data, and cleanup record.",
        "expected": "The tenant must not allow privileged administrative access with password-only authentication.",
    },
    "ID-C-002": {
        "display_id": "ID-DV-002",
        "scenario_id": "ID-C-002",
        "name": "Device Code Flow Block Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether the tenant blocks OAuth device-code authentication attempts for a controlled decoy user.",
        "decoy": "Fresh temporary decoy user created for the validation run.",
        "action": "Start a controlled device-code authentication challenge and attempt to complete it with the decoy user.",
        "evidence": "Microsoft Entra sign-in logs, token endpoint outcome, Conditional Access status, applied policies, block result, and cleanup record.",
        "expected": "The tenant blocks the device-code authentication flow before a token is issued.",
    },
    "ID-C-003": {
        "display_id": "ID-DV-003",
        "scenario_id": "ID-C-003",
        "name": "Controlled Legacy Authentication Exposure Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a fresh licensed Exchange decoy mailbox can authenticate through legacy username/password mail protocols.",
        "decoy": "Fresh temporary decoy user created for the validation run and assigned an Exchange-capable license.",
        "action": "Attempt SMTP AUTH, IMAP, and POP username/password authentication using the licensed decoy mailbox without sending email or reading mailbox data.",
        "evidence": "Protocol authentication results, Microsoft Entra sign-in logs, Conditional Access status, applied policies, mailbox readiness, license assignment, and cleanup record.",
        "expected": "Legacy username/password authentication must not succeed through SMTP AUTH, IMAP, or POP.",
    },
    "ID-C-004": {
        "display_id": "ID-DV-004",
        "scenario_id": "ID-C-004",
        "name": "OAuth App Consent Exposure Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether a fresh standard decoy user can grant OAuth delegated permissions to a controlled test application without administrator approval.",
        "decoy": "Fresh temporary standard decoy user and temporary ZTVP OAuth test application.",
        "action": "Open a Microsoft OAuth consent URL, sign in with the decoy user, and attempt to grant User.Read delegated consent to the controlled test app.",
        "evidence": "OAuth permission grants, Microsoft Entra sign-in logs, directory audit logs, test app details, observed browser outcome, and cleanup record.",
        "expected": "The tenant blocks user consent or requires administrator approval. No oauth2PermissionGrant should be created.",
    },
    "ID-C-005": {
        "display_id": "ID-DV-005",
        "scenario_id": "ID-C-005",
        "name": "External Guest Admin Portal Block Validation",
        "pillar": "Identity",
        "scope": "Cloud",
        "severity": "High",
        "support": "SUPPORTED",
        "goal": "Validate whether an external guest identity is blocked from Azure/admin portal access.",
        "decoy": "Fresh temporary B2B guest user created by inviting an external email controlled by the consultant.",
        "action": "Redeem the guest invitation, sign in as the external guest, and attempt to access Azure Portal or an administrative resource.",
        "evidence": "Microsoft Entra guest sign-in logs, Conditional Access status, applied policies, browser outcome, guest invitation state, and cleanup record.",
        "expected": "The external guest should be blocked from admin portal access unless explicitly authorized.",
    },
}

ALIASES = {
    "DEV-DV-008": "DEV-DV-004",
    "DEV-DV-006": "DEV-DV-003",
    "DEV-DV-004": "DEV-DV-004",
    "DEV-DV-003": "DEV-DV-003",
    "DEV-DV-002": "DEV-DV-002",
    "DEV-DV-001": "DEV-DV-001",
    "APP-DV-007": "APP-DV-007",
    "APP-DV-001": "APP-DV-001",
    "ID-DV-006": "ID-DV-006",
    "APP-DV-003": "APP-C-003",
    "APP-C-003": "APP-C-003",
    "APP-DV-004": "APP-DV-004",
    "APP-DV-002": "APP-C-002",
    "APP-C-002": "APP-C-002",
    "APP-DV-008": "CLD-C-001",
    "CLD-DV-001": "CLD-C-001",
    "CLD-C-001": "CLD-C-001",
    "ID-DV-001": "ID-C-001",
    "ID-C-001": "ID-C-001",
    "ID-DV-002": "ID-C-002",
    "ID-C-002": "ID-C-002",
    "ID-DV-003": "ID-C-003",
    "ID-C-003": "ID-C-003",
    "ID-DV-004": "ID-C-004",
    "ID-C-004": "ID-C-004",
    "ID-DV-005": "ID-C-005",
    "ID-C-005": "ID-C-005",
}


NAV_PILLARS = ["Applications", "Devices", "Identity"]
PILLAR_LABELS = {
    "Devices": "Endpoint",
}


def _safe(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _first(scenario: dict, keys: list[str], default: str = "") -> str:
    for key in keys:
        if key in scenario and scenario.get(key) not in [None, ""]:
            return _text(scenario.get(key))
    return default


def _ids(scenario: dict) -> set[str]:
    values = set()

    for key in ["scenario_id", "ScenarioId", "code", "Code", "id", "Id"]:
        value = scenario.get(key)

        if value:
            values.add(str(value).upper())

    return values


def _builtin_key(scenario: dict) -> str | None:
    ids = _ids(scenario)
    name = _first(scenario, ["name", "Name", "title", "Title"], "").lower()

    if "unmanaged device cloud access" in name:
        return "DEV-DV-001"

    if "sandbox" in name and ("device registration" in name or "registration abuse" in name):
        return "DEV-DV-002"

    if "eicar" in name or ("defender" in name and "detection" in name):
        return "DEV-DV-003"

    if "tamper" in name:
        return "DEV-DV-004"

    for candidate in ids:
        if candidate in ALIASES:
            return ALIASES[candidate]

    if "privileged access mfa" in name or "privileged mfa" in name:
        return "ID-C-001"

    if "device code" in name or "device-code" in name:
        return "ID-C-002"

    if "legacy authentication" in name or "legacy auth" in name:
        return "ID-C-003"

    if "oauth" in name and "consent" in name:
        return "ID-C-004"

    if "guest" in name and ("admin portal" in name or "external" in name):
        return "ID-C-005"

    if ("sharepoint" in name and "anonymous" in name) or ("sharing link" in name and "anonymous" in name):
        return "CLD-C-001"

    if "exchange" in name and ("forwarding" in name or "mail forwarding" in name):
        return "APP-C-002"

    if "mdca" in name and ("public" in name or "sharing" in name):
        return "APP-C-003"

    if "app registration" in name or "application registration" in name:
        return "APP-DV-007"

    if ("enterprise app" in name or "enterprise application" in name) and "assignment" in name:
        return "APP-DV-001"

    if ("sign-in risk" in name or "signin risk" in name or "sign in risk" in name) and ("conditional access" in name or "risk" in name):
        return "ID-DV-006"

    if "sensitive app access" in name or ("unmanaged" in name and "sensitive" in name):
        return "APP-DV-004"

    return None


def _meta(scenario: dict) -> dict:
    key = _builtin_key(scenario)

    if key and key in BUILTINS:
        return BUILTINS[key]

    return {}


def _scenario_id(scenario: dict) -> str:
    meta = _meta(scenario)

    if meta:
        return meta["scenario_id"]

    return _first(scenario, ["scenario_id", "ScenarioId", "code", "Code", "id", "Id"], "UNKNOWN")


def _display_id(scenario: dict) -> str:
    meta = _meta(scenario)

    if meta:
        return meta["display_id"]

    return _first(scenario, ["id", "Id", "display_id", "DisplayId", "scenario_id", "ScenarioId", "code", "Code"], "UNKNOWN")


def _scenario_name(scenario: dict) -> str:
    meta = _meta(scenario)

    if meta:
        return meta["name"]

    return _first(scenario, ["name", "Name", "title", "Title"], _scenario_id(scenario))


def _normalize_pillar(pillar: str) -> str:
    pillar = pillar.strip()
    if pillar == "Endpoint":
        return "Devices"
    return pillar


def _raw_pillar(scenario: dict) -> str:
    return _meta(scenario).get("pillar") or _first(scenario, ["pillar", "Pillar"], "Identity")


def _pillar(scenario: dict) -> str:
    return _normalize_pillar(_raw_pillar(scenario))


def _scope(scenario: dict) -> str:
    if _raw_pillar(scenario) == "Endpoint" or any(value.startswith("EP-DV-") for value in _ids(scenario)):
        return "Cloud"
    return _meta(scenario).get("scope") or _first(scenario, ["scope", "Scope"], "Cloud")


def _severity(scenario: dict) -> str:
    return _meta(scenario).get("severity") or _first(scenario, ["severity", "Severity", "criticality", "Criticality", "risk", "Risk"], "Designed")


def _support(scenario: dict) -> str:
    return _meta(scenario).get("support") or _first(scenario, ["support", "Support", "status", "Status"], "DESIGNED")


def _goal(scenario: dict) -> str:
    return _meta(scenario).get("goal") or _first(scenario, ["objective", "Objective", "goal", "Goal", "description", "Description"], "Validate the configured Zero Trust control using controlled Microsoft evidence.")


def _decoy(scenario: dict) -> str:
    return _meta(scenario).get("decoy") or _first(scenario, ["decoy", "Decoy", "test_object", "TestObject"], "Controlled decoy or test object.")


def _action(scenario: dict) -> str:
    return _meta(scenario).get("action") or _first(scenario, ["controlled_action", "ControlledAction", "action", "Action"], "Perform a controlled validation action.")


def _evidence(scenario: dict) -> str:
    return _meta(scenario).get("evidence") or _first(scenario, ["evidence", "Evidence", "evidence_required", "EvidenceRequired"], "Microsoft evidence and generated ZTVP report.")


def _expected(scenario: dict) -> str:
    return _meta(scenario).get("expected") or _first(scenario, ["expected", "Expected", "expected_result", "ExpectedResult"], "The configured control is enforced and evidence is collected.")


def _is_idc001(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-C-001"


def _is_idc002(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-C-002"


def _is_idc003(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-C-003"


def _is_idc004(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-C-004"


def _is_idc005(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-C-005"


def _is_cld001(scenario: dict) -> bool:
    return _builtin_key(scenario) == "CLD-C-001"


def _is_appc002(scenario: dict) -> bool:
    return _builtin_key(scenario) == "APP-C-002"


def _is_appc003(scenario: dict) -> bool:
    return _builtin_key(scenario) == "APP-C-003"


def _is_appdv007(scenario: dict) -> bool:
    return _builtin_key(scenario) == "APP-DV-007"


def _is_appdv001(scenario: dict) -> bool:
    return _builtin_key(scenario) == "APP-DV-001"


def _is_idv006(scenario: dict) -> bool:
    return _builtin_key(scenario) == "ID-DV-006"


def _is_appdv004(scenario: dict) -> bool:
    return _builtin_key(scenario) == "APP-DV-004"


def _ensure_builtin_dynamic_scenarios(scenarios: list[dict]) -> list[dict]:
    items = [item for item in list(scenarios or []) if isinstance(item, dict)]
    existing = {_builtin_key(item) for item in items}

    for key, meta in BUILTINS.items():
        if key not in existing:
            items.append(
                {
                    "id": meta["display_id"],
                    "scenario_id": meta["scenario_id"],
                    "name": meta["name"],
                    "pillar": meta["pillar"],
                    "scope": meta["scope"],
                    "severity": meta["severity"],
                    "support": meta["support"],
                }
            )

    return items


def _scenario_key(scenario: dict) -> str:
    # Public navigation keys use the Dynamic Validation display ID first.
    # Internal runner aliases such as ID-C-001/APP-C-003 stay in the fourth
    # segment so existing scenario runners and state folders keep working.
    return "|".join([_pillar(scenario), _scope(scenario), _display_id(scenario), _scenario_id(scenario), _scenario_name(scenario)])


def _sort_key(scenario: dict) -> tuple[str, str]:
    return (_display_id(scenario), _scenario_name(scenario))


def _css() -> None:
    st.markdown(
        """
<style>
.block-container { max-width: 1180px; padding-top: 1.1rem; }
.ztvp-hero {
    background: linear-gradient(135deg, #0f172a 0%, #2563eb 100%);
    color: #ffffff;
    padding: 1.55rem 1.65rem;
    border-radius: 24px;
    margin-bottom: 1.2rem;
    box-shadow: 0 18px 42px rgba(15, 23, 42, 0.16);
}
.ztvp-hero h1 { color: #ffffff; margin: 0 0 0.45rem 0; font-size: 1.55rem; font-weight: 950; }
.ztvp-hero p { margin: 0; color: #dbeafe; line-height: 1.55; }
.ztvp-section-title { margin-top: 1.25rem; margin-bottom: 0.75rem; color: #0f172a; font-size: 1.1rem; font-weight: 950; }
.ztvp-card {
    background: #ffffff;
    border: 1px solid #dbe3ef;
    border-radius: 18px;
    padding: 1.05rem 1.1rem;
    margin-bottom: 0.85rem;
    min-height: 185px;
    box-shadow: 0 12px 26px rgba(15, 23, 42, 0.07);
}
.ztvp-card h3 { margin: 0 0 0.65rem 0; color: #0f172a; font-size: 1.05rem; font-weight: 950; }
.ztvp-card p { color: #334155; line-height: 1.5; font-size: 0.92rem; }
.ztvp-card-meta {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid #e2e8f0;
    color: #475569;
    font-size: 0.86rem;
    line-height: 1.42;
}
.ztvp-scenario-card-marker { display: none; }
.ztvp-scenario-card {
    min-height: 300px;
    height: 100%;
    display: flex;
    flex-direction: column;
}
.ztvp-scenario-card-body {
    flex: 1;
}
.ztvp-scenario-card-title {
    margin: 0 0 0.7rem 0;
    color: #0f172a;
    font-size: 1.05rem;
    font-weight: 950;
    line-height: 1.3;
}
.ztvp-scenario-card-description {
    color: #334155;
    line-height: 1.5;
    font-size: 0.92rem;
    margin: 0.3rem 0 0 0;
}
.ztvp-scenario-card-actions {
    margin-top: auto;
    padding-top: 18px;
}
.ztvp-scenario-card-actions span {
    display: none;
}
div[data-testid="stHorizontalBlock"]:has(.ztvp-scenario-card-marker) {
    align-items: stretch;
}
div[data-testid="stHorizontalBlock"]:has(.ztvp-scenario-card-marker) > div[data-testid="column"] {
    display: flex;
}
div[data-testid="stHorizontalBlock"]:has(.ztvp-scenario-card-marker) > div[data-testid="column"] > div[data-testid="stVerticalBlock"] {
    width: 100%;
    display: flex;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) {
    width: 100%;
    min-height: 300px;
    height: 100%;
    display: flex;
    flex-direction: column;
    background: #ffffff !important;
    border: 1px solid #dbe5f3 !important;
    border-radius: 18px !important;
    padding: 0 !important;
    box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08) !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) > div {
    height: 100%;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stVerticalBlock"] {
    height: 100%;
    display: flex;
    flex-direction: column;
    gap: 0;
    padding: 22px;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stMarkdownContainer"]:has(.ztvp-scenario-card) {
    flex: 1;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stButton"] {
    margin-top: auto;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stButton"] button {
    width: 210px !important;
    min-width: 210px !important;
    max-width: 210px !important;
    height: 44px !important;
    min-height: 44px !important;
    border-radius: 12px !important;
    background: #2563eb !important;
    border: 1px solid #2563eb !important;
    color: #ffffff !important;
    font-weight: 700 !important;
    box-shadow: 0 8px 20px rgba(37, 99, 235, 0.20) !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stButton"] button:hover {
    background: #1d4ed8 !important;
    border-color: #1d4ed8 !important;
    color: #ffffff !important;
}
div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stButton"] button p {
    color: #ffffff !important;
}
.ztvp-chip {
    display: inline-block;
    border-radius: 999px;
    padding: 0.28rem 0.58rem;
    font-size: 0.72rem;
    font-weight: 900;
    margin-right: 0.35rem;
    margin-bottom: 0.55rem;
}
.ztvp-chip-blue { background: #dbeafe; color: #1e40af; }
.ztvp-chip-green { background: #dcfce7; color: #166534; }
.ztvp-chip-yellow { background: #fef3c7; color: #92400e; }
.ztvp-chip-red { background: #fee2e2; color: #991b1b; }
.ztvp-detail-card {
    background: #ffffff;
    border: 1px solid #dbe3ef;
    border-radius: 22px;
    padding: 1.25rem 1.35rem;
    margin-bottom: 1rem;
    box-shadow: 0 12px 26px rgba(15, 23, 42, 0.07);
}
.ztvp-detail-card h3 { margin-top: 0; color: #0f172a; font-weight: 950; }
.ztvp-breadcrumb { color: #64748b; font-size: 0.9rem; margin-bottom: 1rem; }
div.stButton > button,
button[data-testid="stBaseButton-secondary"],
button[data-testid="stBaseButton-default"] {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #dbe5f3 !important;
    border-radius: 12px !important;
    width: 100% !important;
    min-width: 0 !important;
    max-width: none !important;
    height: 44px !important;
    min-height: 42px !important;
    font-weight: 850 !important;
    box-shadow: 0 6px 16px rgba(15,23,42,.06) !important;
}
div.stButton > button:hover,
button[data-testid="stBaseButton-secondary"]:hover,
button[data-testid="stBaseButton-default"]:hover {
    background: #eff6ff !important;
    color: #1d4ed8 !important;
    border: 1px solid #93c5fd !important;
}
div.stButton > button[kind="primary"],
button[data-testid="stBaseButton-primary"] {
    background: #2563eb !important;
    color: #ffffff !important;
    border: 1px solid #2563eb !important;
    width: 100% !important;
    min-width: 0 !important;
    max-width: none !important;
    height: 44px !important;
    box-shadow: 0 8px 20px rgba(37, 99, 235, 0.20) !important;
}
div.stButton > button[kind="primary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: #1d4ed8 !important;
    color: #ffffff !important;
    border: 1px solid #1d4ed8 !important;
}
div.stButton > button p,
button[data-testid="stBaseButton-secondary"] p,
button[data-testid="stBaseButton-default"] p {
    color: inherit !important;
}
div[data-testid="stWidgetLabel"] label,
div[data-testid="stWidgetLabel"] p,
label,
.stTextInput label,
.stSelectbox label,
.stNumberInput label,
.stTextArea label {
    color: #0f172a !important;
    opacity: 1 !important;
    font-weight: 750 !important;
}
div[data-testid="stCaptionContainer"],
div[data-testid="stCaptionContainer"] p,
.stCaption,
small,
div[data-baseweb="form-control"] div {
    color: #64748b !important;
}
input,
textarea,
div[data-baseweb="select"] span {
    color: #f8fafc !important;
}
input::placeholder,
textarea::placeholder {
    color: #94a3b8 !important;
    opacity: 1 !important;
}
input:disabled,
textarea:disabled,
div[aria-disabled="true"],
div[aria-disabled="true"] * {
    color: #64748b !important;
    -webkit-text-fill-color: #64748b !important;
    opacity: 1 !important;
}
@media (max-width: 700px) {
    div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) {
        min-height: 0;
    }
    div[data-testid="stVerticalBlockBorderWrapper"]:has(.ztvp-scenario-card-marker) div[data-testid="stButton"] button {
        width: 100% !important;
        min-width: 0 !important;
        max-width: none !important;
    }
}
</style>
""",
        unsafe_allow_html=True,
    )


def _chip(text: str, tone: str = "blue") -> str:
    return f'<span class="ztvp-chip ztvp-chip-{tone}">{_safe(text)}</span>'


def _tone_for_severity(value: str) -> str:
    value_lower = value.lower()

    if "critical" in value_lower or "high" in value_lower:
        return "red"

    if "medium" in value_lower:
        return "yellow"

    return "blue"


def _render_choice_buttons(values: list[str], state_key: str, reset_keys: list[str]) -> str:
    current = st.session_state.get(state_key)

    if current not in values:
        current = values[0]
        st.session_state[state_key] = current

    if state_key == "ztvp_dynamic_pillar":
        cols = st.columns([1, 1, 1], gap="medium")
    else:
        cols = st.columns(max(1, min(len(values), 4)))

    for index, value in enumerate(values):
        with cols[index % len(cols)]:
            button_type = "primary" if value == current else "secondary"
            label = PILLAR_LABELS.get(value, value) if state_key == "ztvp_dynamic_pillar" else value

            if st.button(label, key=f"{state_key}_{value}", use_container_width=True, type=button_type):
                st.session_state[state_key] = value

                for key in reset_keys:
                    st.session_state.pop(key, None)

                st.rerun()

    return current


def _render_catalog_card(scenario: dict, index: int = 0) -> None:
    did = _display_id(scenario)
    name = _scenario_name(scenario)
    severity = _severity(scenario)
    support = _support(scenario)
    key = _scenario_key(scenario)

    severity_tone = _tone_for_severity(severity)
    support_tone = "green" if support.upper() == "SUPPORTED" else "yellow"

    with st.container(border=True):
        st.markdown(
            f"""
<div class="ztvp-scenario-card-marker"></div>
<div class="ztvp-scenario-card">
  <div class="ztvp-scenario-card-body">
    <div class="ztvp-scenario-card-title">{_safe(did)} - {_safe(name)}</div>
    <div>
      {_chip(severity, severity_tone)}
      {_chip(support, support_tone)}
    </div>
    <p class="ztvp-scenario-card-description">{_safe(_goal(scenario))}</p>
    <div class="ztvp-card-meta"><strong>Required test object:</strong> {_safe(_decoy(scenario))}</div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
        st.markdown('<div class="ztvp-scenario-card-actions"><span>actions</span></div>', unsafe_allow_html=True)

        if st.button("Open scenario", key=f"open_{index}_{key}", type="primary"):
            st.session_state["ztvp_dynamic_open_scenario"] = key
            st.rerun()


def _render_catalog(scenarios: list[dict], pillar: str, scope: str) -> None:
    st.markdown(
        f"""
<div class="ztvp-breadcrumb">
{_safe(pillar)} → {_safe(scope)} → Scenario Catalog
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("### Scenario Catalog")
    st.caption("Choose one scenario to open its full validation page.")

    if not scenarios:
        st.warning("No scenarios were found for this pillar and scope.")
        return

    unique_scenarios = []
    seen_scenario_keys = set()

    for scenario in scenarios:
        dedupe_key = _scenario_key(scenario)

        if dedupe_key in seen_scenario_keys:
            continue

        seen_scenario_keys.add(dedupe_key)
        unique_scenarios.append(scenario)

    scenarios = unique_scenarios

    for row_start in range(0, len(scenarios), 2):
        cols = st.columns(2, gap="large")
        row_scenarios = scenarios[row_start:row_start + 2]

        for offset, scenario in enumerate(row_scenarios):
            with cols[offset]:
                _render_catalog_card(scenario, row_start + offset)


def _render_scenario_detail_card(scenario: dict) -> None:
    did = _display_id(scenario)
    name = _scenario_name(scenario)
    severity = _severity(scenario)
    support = _support(scenario)

    severity_tone = _tone_for_severity(severity)
    support_tone = "green" if support.upper() == "SUPPORTED" else "yellow"

    st.markdown(
        f"""
<div class="ztvp-breadcrumb">
{_safe(_pillar(scenario))} → {_safe(_scope(scenario))} → {_safe(did)}
</div>

<h1>{_safe(did)} — {_safe(name)}</h1>

<div class="ztvp-detail-card">
    <h3>Scenario Objective</h3>
    <p>{_safe(_goal(scenario))}</p>
    {_chip(severity, severity_tone)}
    {_chip(support, support_tone)}
</div>
""",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f'<div class="ztvp-detail-card"><h3>Decoy / Test Object</h3><p>{_safe(_decoy(scenario))}</p></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="ztvp-detail-card"><h3>Controlled Action</h3><p>{_safe(_action(scenario))}</p></div>', unsafe_allow_html=True)

    with col2:
        st.markdown(f'<div class="ztvp-detail-card"><h3>Evidence Required</h3><p>{_safe(_evidence(scenario))}</p></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="ztvp-detail-card"><h3>Expected Result</h3><p>{_safe(_expected(scenario))}</p></div>', unsafe_allow_html=True)


def _is_devdv004(scenario: dict) -> bool:
    return _builtin_key(scenario) == "DEV-DV-002"


def _is_devdv001(scenario: dict) -> bool:
    return _builtin_key(scenario) == "DEV-DV-001"


def _is_devdv006(scenario: dict) -> bool:
    return _builtin_key(scenario) == "DEV-DV-003"


def _is_devdv008(scenario: dict) -> bool:
    return _builtin_key(scenario) == "DEV-DV-004"


def _go_home() -> None:
    st.session_state.home_mode = "home"
    st.session_state.dynamic_pillar = None
    st.session_state.dynamic_scenario_id = None
    st.session_state.pop("ztvp_dynamic_pillar", None)
    st.session_state.pop("ztvp_dynamic_scope", None)
    st.session_state.pop("ztvp_dynamic_open_scenario", None)
    st.session_state.pop("ztvp_dynamic_open_run_id", None)
    st.session_state.pop("ztvp_dynamic_open_run_status", None)
    st.session_state.pop("ztvp_dynamic_open_report_path", None)
    st.session_state.pop("ztvp_dynamic_pending_scenario_id", None)


def _render_open_scenario_navigation() -> None:
    home_col, catalog_col, spacer_col = st.columns([0.16, 0.22, 0.62])

    with home_col:
        if st.button("Home", key="ztvp_open_scenario_home", use_container_width=True):
            _go_home()
            st.rerun()

    with catalog_col:
        if st.button("Scenario Catalog", key="ztvp_open_scenario_catalog", use_container_width=True):
            st.session_state.pop("ztvp_dynamic_open_scenario", None)
            st.session_state.pop("ztvp_dynamic_open_run_id", None)
            st.session_state.pop("ztvp_dynamic_open_run_status", None)
            st.session_state.pop("ztvp_dynamic_open_report_path", None)
            st.session_state.pop("ztvp_dynamic_pending_scenario_id", None)
            st.rerun()


def _render_dynamic_page_navigation() -> None:
    home_col, spacer_col = st.columns([0.16, 0.84])

    with home_col:
        if st.button("Home", key="ztvp_dynamic_page_home", use_container_width=True):
            _go_home()
            st.rerun()


def render_dynamic_validation_page(
    scenarios: list[dict],
    caps: dict | None = None,
    project_root: Path | str | None = None,
    render_idc001_runner=None,
    **kwargs,
) -> None:
    if st.session_state.get("main_navigation") not in (None, "Dynamic Validation"):
        return
    st.session_state["ztvp_rendering_page"] = "Dynamic Validation"
    _css()

    project_root = Path(project_root or Path.cwd())
    scenarios = _ensure_builtin_dynamic_scenarios(list(scenarios or []))

    st.markdown(
        """
<div class="ztvp-hero">
    <h1>Dynamic Validation</h1>
    <p>Choose a pillar and scope, then open a validation scenario from the catalog.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    scenario_by_key = {_scenario_key(item): item for item in scenarios}
    open_key = st.session_state.get("ztvp_dynamic_open_scenario")
    open_scenario = scenario_by_key.get(open_key)

    if open_key and open_scenario is None:
        pending_sid = st.session_state.get("ztvp_dynamic_pending_scenario_id") or open_key
        st.warning(f"Scenario route not found for {pending_sid}.")
        st.session_state.pop("ztvp_dynamic_open_scenario", None)
        open_key = None

    if open_scenario is not None:
        _render_open_scenario_navigation()

        _render_scenario_detail_card(open_scenario)

        st.markdown("---")
        if _is_idc001(open_scenario):
            if render_idc001_runner is None:
                try:
                    from dynamic_idc001 import render_idc001_runner as fallback_idc001_runner
                    fallback_idc001_runner(project_root)
                except Exception as exc:
                    st.error("ID-DV-001 runner could not be loaded.")
                    st.exception(exc)
            else:
                render_idc001_runner(project_root)

        elif _is_idc002(open_scenario):
            if render_idc002_runner is None:
                st.error("ID-DV-002 runner could not be loaded. Check ui/dynamic_idc002.py.")
            else:
                render_idc002_runner(project_root)

        elif _is_idc003(open_scenario):
            if render_idc003_runner is None:
                st.error("ID-DV-003 runner could not be loaded. Check ui/dynamic_idc003.py.")
            else:
                render_idc003_runner(project_root)

        elif _is_idc004(open_scenario):
            if render_idc004_runner is None:
                st.error("ID-DV-004 runner could not be loaded. Check ui/dynamic_idc004.py.")
            else:
                render_idc004_runner(project_root)

        elif _is_idc005(open_scenario):
            if render_idc005_runner is None:
                st.error("ID-DV-005 runner could not be loaded. Check ui/dynamic_idc005.py.")
            else:
                render_idc005_runner(project_root)

        elif _is_cld001(open_scenario):
            try:
                from dynamic_cld001 import render_cld001_runner as _cld001_runner
                _cld001_runner(project_root)
            except Exception as exc:
                st.error("APP-DV-008 runner could not be loaded.")
                st.exception(exc)
        elif _is_appc002(locals().get("open_scenario", locals().get("selected", {}))):
            if render_appc002_runner is None:
                st.error("APP-C-002 runner could not be loaded. Check ui/dynamic_appc002.py.")
            else:
                render_appc002_runner(project_root)


        elif _is_appc003(locals().get("open_scenario", locals().get("selected", {}))):
            if render_appc003_runner is None:
                st.error("APP-C-003 runner could not be loaded. Check ui/dynamic_appc003.py.")
            else:
                render_appc003_runner(project_root)


        elif _is_appdv007(locals().get("open_scenario", locals().get("selected", {}))):
            if render_appdv007_runner is None:
                st.error("APP-DV-007 runner could not be loaded. Check ui/dynamic_appdv007.py.")
            else:
                render_appdv007_runner(project_root)


        elif _is_appdv001(locals().get("open_scenario", locals().get("selected", {}))):
            if render_appdv001_runner is None:
                st.error("APP-DV-001 runner could not be loaded. Check ui/dynamic_appdv001.py.")
            else:
                render_appdv001_runner(project_root)


        elif _is_idv006(locals().get("open_scenario", locals().get("selected", {}))):
            if render_idv006_runner is None:
                st.error("ID-DV-006 runner could not be loaded. Check ui/dynamic_idv006.py.")
            else:
                render_idv006_runner(project_root)


        elif _is_appdv004(locals().get("open_scenario", locals().get("selected", {}))):
            if render_appdv004_runner is None:
                st.error("APP-DV-004 runner could not be loaded. Check ui/dynamic_appdv004.py.")
            else:
                render_appdv004_runner(project_root)


        elif _is_devdv004(locals().get("open_scenario", locals().get("selected", {}))):
            if render_devdv004_runner is None:
                st.error("DEV-DV-002 runner could not be loaded. Check ui/dynamic_devdv004.py.")
            else:
                render_devdv004_runner(project_root)

        elif _is_devdv001(locals().get("open_scenario", locals().get("selected", {}))):
            if render_devdv001_runner is None:
                st.error("DEV-DV-001 runner could not be loaded. Check ui/dynamic_devdv001.py.")
            else:
                render_devdv001_runner(project_root)

        elif _is_devdv006(locals().get("open_scenario", locals().get("selected", {}))):
            if render_devdv006_runner is None:
                st.error("DEV-DV-003 runner could not be loaded. Check ui/dynamic_devdv006.py.")
            else:
                render_devdv006_runner(project_root)

        elif _is_devdv008(locals().get("open_scenario", locals().get("selected", {}))):
            if render_devdv008_runner is None:
                st.error("DEV-DV-004 runner could not be loaded. Check ui/dynamic_devdv008.py.")
            else:
                render_devdv008_runner(project_root)


        else:
            st.info("This scenario is designed. Its real probe engine will be implemented later.")

        return

    _render_dynamic_page_navigation()

    available_pillars = {_pillar(item) for item in scenarios if _pillar(item)}
    pillars = [pillar for pillar in NAV_PILLARS if pillar in available_pillars]

    if not pillars:
        st.warning("No pillars were found in the Dynamic Validation catalog.")
        return

    st.markdown('<div class="ztvp-section-title">1. Choose Pillar</div>', unsafe_allow_html=True)

    selected_pillar = _render_choice_buttons(
        pillars,
        "ztvp_dynamic_pillar",
        ["ztvp_dynamic_scope", "ztvp_dynamic_open_scenario"],
    )

    pillar_scenarios = [item for item in scenarios if _pillar(item).lower() == selected_pillar.lower()]
    scopes = sorted({_scope(item) for item in pillar_scenarios if _scope(item)})

    st.markdown(f'<div class="ztvp-section-title">2. Choose Scope for {_safe(selected_pillar)}</div>', unsafe_allow_html=True)

    if not scopes:
        st.warning("No scopes were found for this pillar.")
        return

    selected_scope = _render_choice_buttons(
        scopes,
        "ztvp_dynamic_scope",
        ["ztvp_dynamic_open_scenario"],
    )

    scoped_scenarios = [
        item for item in pillar_scenarios
        if _scope(item).lower() == selected_scope.lower()
    ]

    scoped_scenarios = sorted(scoped_scenarios, key=_sort_key)

    st.markdown(f'<div class="ztvp-section-title">3. Choose Scenario for {_safe(selected_pillar)} → {_safe(selected_scope)}</div>', unsafe_allow_html=True)

    _render_catalog(scoped_scenarios, selected_pillar, selected_scope)

