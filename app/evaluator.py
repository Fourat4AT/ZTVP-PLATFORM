from typing import Dict, Any, List
from app.models import (
    EvaluationResult,
    Finding,
    Recommendation,
    ResultStatus,
    RiskLevel,
)


def evaluate_advanced_mfa(evidence: Dict[str, Any]) -> EvaluationResult:
    findings: List[Finding] = []
    recommendations: List[Recommendation] = []

    admin_users = evidence.get("admin_users", [])
    ca_policies = evidence.get("conditional_access", [])

    any_no_mfa = any(not user.get("mfa_enabled", False) for user in admin_users)
    any_weak_mfa = any("sms" in user.get("mfa_methods", []) for user in admin_users)
    any_excluded = any(user.get("excluded_from_ca", False) for user in admin_users)

    admin_ca_missing = not any(
        policy.get("enabled") and policy.get("covers_admins")
        for policy in ca_policies
    )

    if any_no_mfa:
        findings.append(Finding(
            "MFA missing",
            "At least one privileged account does not have MFA enabled."
        ))
        recommendations.append(Recommendation(
            "Enable MFA",
            "Enforce MFA for all privileged accounts."
        ))

    if any_weak_mfa:
        findings.append(Finding(
            "Weak MFA method",
            "At least one privileged account uses SMS as an MFA method."
        ))
        recommendations.append(Recommendation(
            "Use strong MFA",
            "Require Microsoft Authenticator or FIDO2 for privileged accounts."
        ))

    if any_excluded:
        findings.append(Finding(
            "Policy exclusion",
            "At least one privileged account is excluded from Conditional Access."
        ))
        recommendations.append(Recommendation(
            "Remove exclusions",
            "Apply Conditional Access policies to all privileged accounts."
        ))

    if admin_ca_missing:
        findings.append(Finding(
            "Coverage gap",
            "No enabled Conditional Access policy fully covers privileged accounts."
        ))
        recommendations.append(Recommendation(
            "Create admin CA policy",
            "Add an enabled Conditional Access policy that covers all admin roles."
        ))

    if any_no_mfa or any_excluded or admin_ca_missing:
        status = ResultStatus.FAIL
        risk = RiskLevel.CRITICAL
    elif any_weak_mfa:
        status = ResultStatus.PARTIAL
        risk = RiskLevel.HIGH
    else:
        status = ResultStatus.PASS
        risk = RiskLevel.LOW

    return EvaluationResult(
        scenario_id="A1",
        scenario_name="Advanced MFA Enforcement",
        status=status,
        risk=risk,
        findings=findings,
        recommendations=recommendations,
    )


def evaluate_conditional_access_coverage(evidence: Dict[str, Any]) -> EvaluationResult:
    findings: List[Finding] = []
    recommendations: List[Recommendation] = []

    ca_policies = evidence.get("conditional_access", [])

    enabled_admin_policies = [
        policy for policy in ca_policies
        if policy.get("enabled") and policy.get("covers_admins")
    ]

    if not enabled_admin_policies:
        findings.append(Finding(
            "Missing coverage",
            "No enabled Conditional Access policy covers privileged accounts."
        ))
        recommendations.append(Recommendation(
            "Create coverage policy",
            "Create and enable a Conditional Access policy for all privileged accounts."
        ))
        status = ResultStatus.FAIL
        risk = RiskLevel.CRITICAL
    else:
        policies_with_exclusions = [
            policy for policy in enabled_admin_policies
            if policy.get("allows_exclusions")
        ]

        if policies_with_exclusions:
            findings.append(Finding(
                "Policy exclusions allowed",
                "At least one enabled admin Conditional Access policy allows exclusions."
            ))
            recommendations.append(Recommendation(
                "Tighten policy scope",
                "Remove unnecessary exclusions from admin Conditional Access policies."
            ))
            status = ResultStatus.PARTIAL
            risk = RiskLevel.HIGH
        else:
            findings.append(Finding(
                "Admin coverage enforced",
                "Enabled Conditional Access policies cover privileged accounts without exclusions."
            ))
            recommendations.append(Recommendation(
                "Maintain coverage",
                "Continue reviewing admin Conditional Access scope regularly."
            ))
            status = ResultStatus.PASS
            risk = RiskLevel.LOW

    return EvaluationResult(
        scenario_id="A6",
        scenario_name="Conditional Access Coverage",
        status=status,
        risk=risk,
        findings=findings,
        recommendations=recommendations,
    )