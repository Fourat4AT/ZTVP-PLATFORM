from typing import Dict, Any, List


class DataCollector:
    """Mock data collector for Phase 1.

    This class simulates tenant evidence that will later be collected
    from Microsoft Graph and other sources.
    """

    def collect_admin_users(self) -> List[Dict[str, Any]]:
        """Return mock privileged accounts."""
        return [
            {
                "userPrincipalName": "admin1@tenant.local",
                "role": "Global Administrator",
                "mfa_enabled": True,
                "mfa_methods": ["sms"],
                "excluded_from_ca": True,
            },
            {
                "userPrincipalName": "admin2@tenant.local",
                "role": "Privileged Role Administrator",
                "mfa_enabled": True,
                "mfa_methods": ["microsoft_authenticator"],
                "excluded_from_ca": False,
            },
        ]

    def collect_conditional_access_policies(self) -> List[Dict[str, Any]]:
        """Return mock Conditional Access policies."""
        return [
            {
                "name": "Require MFA for Admins",
                "enabled": True,
                "covers_admins": True,
                "allows_exclusions": True,
            },
            {
                "name": "Block legacy authentication",
                "enabled": True,
                "covers_admins": False,
                "allows_exclusions": False,
            },
        ]

    def build_evidence_for_a1(self) -> Dict[str, Any]:
        """Build evidence required for A1 - Advanced MFA Enforcement."""
        return {
            "admin_users": self.collect_admin_users(),
            "conditional_access": self.collect_conditional_access_policies(),
        }

    def build_evidence_for_a6(self) -> Dict[str, Any]:
        """Build evidence required for A6 - Conditional Access Coverage."""
        return {
            "admin_users": self.collect_admin_users(),
            "conditional_access": self.collect_conditional_access_policies(),
        }

    def collect_for_scenario(self, scenario_id: str) -> Dict[str, Any]:
        """Return evidence for a given scenario."""
        if scenario_id == "A1":
            return self.build_evidence_for_a1()
        if scenario_id == "A6":
            return self.build_evidence_for_a6()

        raise ValueError(f"No mock collector implemented for scenario {scenario_id}")