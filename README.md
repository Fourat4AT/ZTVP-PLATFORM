Zero Trust Validation Platform (ZTVP)
Overview

Zero Trust Validation Platform (ZTVP) is a Microsoft security validation platform designed for consulting engagements.

The goal of the platform is to prove whether Microsoft security controls actually work in real conditions, not only whether they are configured. ZTVP is being structured around controlled validation scenarios, tenant discovery, capability detection, simulation, evidence collection, and reporting.

The platform focuses on Microsoft security environments such as:

Microsoft Entra ID
Microsoft Graph
Conditional Access
Privileged Identity Management
Microsoft Intune
Microsoft Defender for Endpoint
Microsoft Defender for Identity
Microsoft Defender for Cloud Apps
Defender for Office 365
Hybrid Active Directory / Entra Connect
Project Objective

Traditional assessment tools usually check if a policy or setting exists.

ZTVP aims to go further by validating whether the control actually works in practice.

Example:

Instead of only checking whether an MFA policy exists, ZTVP should validate whether a controlled privileged user is actually challenged for MFA during a real sign-in attempt, then collect sign-in logs, Conditional Access results, and authentication evidence.

Platform Modules
ZTVP
├─ Dynamic Validation
│  └─ Controlled real-life validation scenarios
│
├─ Simulation Lab
│  └─ What-if and sandbox impact analysis
│
└─ Reports
   └─ Evidence reports and simulation reports
Dynamic Validation

Dynamic Validation is the evidence-based testing layer of the platform.

It answers:

Does this security control actually work in real conditions?

Dynamic Validation uses controlled test objects and real Microsoft evidence, such as:

Decoy users
Decoy privileged users
Synced AD test users
Decoy groups
Test devices or VMs
Controlled test applications
Entra ID sign-in logs
Audit logs
Conditional Access decisions
Defender alerts
Intune device compliance state
Hybrid AD / Entra sync evidence

Expected workflow:

Select scenario
→ Prepare decoy or test object
→ Perform controlled action
→ Collect Microsoft evidence
→ Compare actual result with expected result
→ Clean up temporary test object or change
→ Generate evidence report
Simulation Lab

Simulation Lab is the what-if and sandbox planning layer.

It answers:

What would happen if we changed something in the tenant?

The Simulation Lab does not apply changes directly. It models expected impact before implementation.

Example simulations:

What happens if MFA is enforced for all privileged users?
What happens if Conditional Access exclusions are removed?
What happens if legacy authentication is blocked?
What happens if compliant devices are required?
What happens if normal users are blocked from app registration?
What happens if user consent is restricted?

Expected workflow:

Select simulation type
→ Select pillar
→ Choose scenario
→ Define what-if conditions
→ Review predicted impact
→ Review operational risk
→ Recommend Dynamic Validation probe
→ Generate simulation preview or report

Simulation types:

Access What-If
Policy Change Impact
Attack Scenario Sandbox
Rollout Planner
Current Scenario Metrics
Area	Count
Identity Dynamic Validation - Cloud	8
Identity Dynamic Validation - Hybrid	8
Endpoint Dynamic Validation	5
Applications Dynamic Validation	7
Total Dynamic Validation Scenarios	28
Identity Simulation Scenarios	9
Endpoint Simulation Scenarios	6
Applications Simulation Scenarios	7
Total Simulation Scenarios	22
Dynamic Validation Scenario Summary
Identity / Cloud
Scenario ID	Scenario Name	Purpose
ID-C-001	Privileged MFA Enforcement Probe	Validates whether privileged users are actually required to complete MFA.
ID-C-002	Conditional Access Exclusion Bypass Probe	Checks whether excluded users or groups can bypass Conditional Access controls.
ID-C-003	Unmanaged Device Access Probe	Tests whether unmanaged or non-compliant devices are blocked from protected cloud apps.
ID-C-004	Legacy Authentication Block Probe	Validates whether legacy/basic authentication is actually blocked.
ID-C-005	Risk-Based Access Enforcement Probe	Checks whether risky users or risky sign-ins trigger MFA, block, or remediation.
ID-C-006	PIM Role Activation Enforcement Probe	Validates whether privileged actions require PIM activation.
ID-C-007	Break-Glass Monitoring Probe	Checks whether emergency account usage is logged and monitored.
ID-C-008	Phishing-Resistant Admin Authentication Probe	Validates whether privileged access requires strong or phishing-resistant authentication.
Identity / Hybrid
Scenario ID	Scenario Name	Purpose
ID-H-001	Disabled Synced Account Cloud Access Probe	Validates whether disabling an AD account blocks cloud sign-in after sync.
ID-H-002	Synced Privileged User MFA Enforcement Probe	Checks whether synced privileged identities are protected by MFA and Conditional Access.
ID-H-003	Synced Group Conditional Access Enforcement Probe	Validates whether synced AD groups actually drive Conditional Access behavior.
ID-H-004	Entra Connect Sync Consistency Probe	Checks whether AD changes are correctly reflected in Entra ID.
ID-H-005	On-Prem Privileged Group Change Detection Probe	Validates whether privileged AD group changes are detected.
ID-H-006	Stale or Disabled Synced Privileged Account Probe	Detects stale or disabled synced privileged accounts.
ID-H-007	Hybrid Password and Account State Consistency Probe	Checks whether cloud behavior follows AD password/account state.
ID-H-008	MDI Suspicious Identity Activity Evidence Probe	Validates whether Defender for Identity produces evidence for suspicious AD/DC activity.
Endpoint
Scenario ID	Scenario Name	Purpose
EP-DV-001	MDE Detection Visibility Probe	Validates whether endpoint detection telemetry appears in Defender.
EP-DV-002	Device Compliance Enforcement Probe	Checks whether non-compliant devices are blocked from protected resources.
EP-DV-003	Defender Antivirus Protection Probe	Validates whether Defender AV detects controlled safe test patterns.
EP-DV-004	Attack Surface Reduction Enforcement Probe	Checks whether ASR rules are actually enforced.
EP-DV-005	Device Isolation Response Probe	Validates whether endpoint isolation actions work and generate evidence.
Applications
Scenario ID	Scenario Name	Purpose
APP-DV-001	Enterprise App Assignment Enforcement Probe	Validates whether unassigned users are denied access to restricted enterprise apps.
APP-DV-002	OAuth Consent Governance Probe	Checks whether risky OAuth consent is blocked or routed to admin approval.
APP-DV-003	App Session Control Probe	Validates whether risky SaaS sessions are monitored or restricted.
APP-DV-004	Sensitive App Access From Unmanaged Device Probe	Checks whether sensitive apps are blocked from unmanaged devices.
APP-DV-005	MDO Safe Attachment / Safe Link Evidence Probe	Validates whether Defender for Office 365 generates evidence for controlled mail protection tests.
APP-DV-006	User Consent Enforcement Probe	Checks whether normal users can directly consent to risky applications.
APP-DV-007	App Registration Permission Probe	Validates whether normal users can create app registrations.
Simulation Lab Scenario Summary
Identity Simulation
Scenario ID	Scenario Name	Purpose
SIM-ID-001	Privileged Admin Sign-in What-If	Models which controls would apply to a privileged admin sign-in.
SIM-ID-002	Privileged MFA Rollout Impact	Estimates the impact of enforcing MFA for all privileged users.
SIM-ID-003	Conditional Access Exclusion Removal Impact	Shows who would be affected if CA exclusions are removed.
SIM-ID-004	Require Compliant Device Access Impact	Predicts who would lose access if compliant devices are required.
SIM-ID-005	Legacy Authentication Block Impact	Identifies accounts or apps that may break if legacy authentication is blocked.
SIM-ID-006	PIM Migration Impact	Estimates the impact of moving permanent admin roles to PIM.
SIM-ID-007	Stolen Password Attack Path Simulation	Models what would stop an attacker with a stolen password.
SIM-ID-008	Synced Group Conditional Access Impact	Models the effect of using synced AD groups for CA targeting.
SIM-ID-009	Disabled Synced Account Impact	Models cloud access behavior after disabling a synced AD account.
Endpoint Simulation
Scenario ID	Scenario Name	Purpose
SIM-EP-001	Device Compliance Enforcement Impact	Predicts affected users/devices if compliance becomes required.
SIM-EP-002	ASR Audit-to-Block Impact	Estimates what would be blocked if ASR rules move from audit to block.
SIM-EP-003	MDE Onboarding Coverage Impact	Estimates visibility improvement from onboarding missing devices to MDE.
SIM-EP-004	Defender Antivirus Enforcement Impact	Identifies devices affected by standardized Defender AV enforcement.
SIM-EP-005	Device Isolation Business Impact	Models the business impact of isolating an endpoint during an incident.
SIM-EP-006	Endpoint Attack Path Sandbox	Models expected endpoint defense response against malware execution.
Applications Simulation
Scenario ID	Scenario Name	Purpose
SIM-APP-001	Disable User Consent Impact	Estimates the impact of restricting normal user consent.
SIM-APP-002	Restrict App Registration Impact	Predicts the impact of preventing normal users from creating app registrations.
SIM-APP-003	Enterprise App Assignment Required Impact	Identifies users affected if enterprise apps require assignment.
SIM-APP-004	OAuth Consent Attack Sandbox	Models whether a malicious OAuth consent attack would be blocked.
SIM-APP-005	MDCA Session Control Impact	Estimates the effect of applying Defender for Cloud Apps session controls.
SIM-APP-006	Sensitive App Access From Unmanaged Device Impact	Models whether sensitive apps can be accessed from unmanaged devices.
SIM-APP-007	MDO Phishing Simulation Readiness	Checks readiness for phishing simulations and awareness training.
Planned UI Structure
Home
├─ Dynamic Validation
│  ├─ Identity
│  │  ├─ Cloud
│  │  └─ Hybrid
│  ├─ Endpoint
│  └─ Applications
│
├─ Simulation Lab
│  ├─ Access What-If
│  ├─ Policy Change Impact
│  ├─ Attack Scenario Sandbox
│  └─ Rollout Planner
│
└─ Reports
Repository Structure
ztvp/
├─ powershell/
│  ├─ Run-ZTVP.ps1
│  ├─ ScenarioCatalog.ps1
│  ├─ Engines/
│  ├─ Modules/
│  ├─ Tools/
│  └─ Reports/
│
├─ ui/
│  └─ app.py
│
├─ tests/
│
├─ requirements.txt
└─ README.md
Script and Folder Roles
powershell/Run-ZTVP.ps1

Main PowerShell runner.

Role:

Starts the PowerShell CLI workflow.
Connects to Microsoft Graph.
Loads available scenarios.
Allows scenario selection.
Executes scenario engines.
Generates JSON/HTML reports for implemented scenarios.
powershell/ScenarioCatalog.ps1

Scenario catalog file.

Role:

Stores scenario metadata.
Defines scenario IDs, names, pillars, categories, scopes, status, engine paths, and function names.
Used by the runner and UI to display available scenarios.
powershell/Engines/

Scenario engine folder.

Role:

Contains scenario-specific PowerShell logic.
Each engine should collect evidence, evaluate the result, assign status/risk, and return structured output.
Future Dynamic Validation engines will be added here.

Expected engine naming format:

Invoke-ZTVP-<ScenarioId>

Example:

Invoke-ZTVP-ID-C-001
powershell/Modules/

Reusable PowerShell modules.

Role:

Contains shared helper logic.
Handles reusable functions such as Microsoft Graph connection, evidence collection helpers, formatting, and common scenario logic.
powershell/Tools/

Utility scripts.

Role:

Contains helper scripts for report conversion, formatting, or export logic.

Example:

Convert-ZTVPReportToHtml.ps1
powershell/Reports/

Report output folder.

Role:

Stores generated reports.
Stores JSON and HTML output.
Will later store Dynamic Validation and Simulation reports separately.

Planned report folder structure:

powershell/Reports/
├─ Html/
├─ Dynamic/
└─ Simulation/
ui/app.py

Main Streamlit UI file.

Role:

Provides the graphical user interface.
Allows tenant connection and discovery.
Displays detected tenant capabilities.
Shows Dynamic Validation scenario catalog.
Shows Simulation Lab scenario catalog.
Displays report sections.
Will later trigger real Dynamic Validation probe engines.
requirements.txt

Python dependency file.

Current dependencies:

streamlit
pandas
tests/

Testing folder.

Role:

Stores future tests for scenario logic.
Can be used to validate probe behavior, evidence parsing, and result scoring.
Core Logic

The target core logic of the platform is:

Connect to tenant
→ Discover tenant capabilities
→ Recommend supported scenarios
→ Select Dynamic Validation or Simulation Lab
→ Run controlled validation or what-if simulation
→ Collect evidence
→ Score result
→ Generate report
Capability Detection

The platform should detect or receive information about the client environment.

Examples:

Tenant ID
Connected account
Domains
Subscribed SKUs
Entra ID P1/P2 availability
Conditional Access availability
Intune availability
Defender for Endpoint availability
Defender for Identity availability
Defender for Office 365 availability
Defender for Cloud Apps availability
Hybrid identity presence

This allows the platform to recommend only the scenarios that are supported by the client tenant and licensing.

Report Types
Report Type	Purpose
Dynamic Validation Evidence Report	Shows decoy object, controlled action, collected evidence, result, and cleanup proof.
Simulation Report	Shows what-if input, predicted impact, operational risk, and recommended validation.
Executive Summary Report	Provides client-friendly summary of validation results.
Technical Evidence Report	Provides detailed evidence for consultants and security teams.
Current Implementation Status
Component	Status
Streamlit UI	In progress
Tenant connection / discovery	In progress
Dynamic Validation catalog	Designed
Simulation Lab catalog	Designed
Real Dynamic Validation probe engines	Next phase
Simulation evidence engine	Future phase
Report export	Planned / in progress 


How to Run

Install Python dependencies:

py -m pip install -r .\requirements.txt

Run the Streamlit UI:

py -m streamlit run .\ui\app.py

Run the PowerShell runner:

.\powershell\Run-ZTVP.ps1
Safety Principles

ZTVP should follow safe validation principles:

Use decoy/test accounts instead of real employee accounts.
Avoid destructive actions.
Ask for confirmation before modifying tenant or AD objects.
Always collect before/after evidence.
Always clean up temporary test changes.
Store reports securely because they may contain sensitive tenant information.
Prefer controlled and approved validation actions.
