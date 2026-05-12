from typing import Dict, Optional, List
from app.models import Scenario
from app.evaluator import (
    evaluate_advanced_mfa,
    evaluate_conditional_access_coverage,
)


class ScenarioCatalog:
    """Central registry for all available scenarios."""

    def __init__(self) -> None:
        self._scenarios: Dict[str, Scenario] = {}
        self._register_default_scenarios()

    def _register_default_scenarios(self) -> None:
        """Register all scenarios available in the current prototype."""
        self.register(
            Scenario(
                scenario_id="A1",
                name="Advanced MFA Enforcement",
                category="Authentication Security",
                objective="Validate strong MFA enforcement for privileged accounts.",
                evaluator=evaluate_advanced_mfa,
            )
        )

        self.register(
            Scenario(
                scenario_id="A6",
                name="Conditional Access Coverage",
                category="Access Enforcement",
                objective="Validate whether Conditional Access policies correctly cover privileged accounts.",
                evaluator=evaluate_conditional_access_coverage,
            )
        )

    def register(self, scenario: Scenario) -> None:
        """Add a new scenario to the catalog."""
        self._scenarios[scenario.scenario_id] = scenario

    def list_scenarios(self) -> List[Scenario]:
        """Return all registered scenarios."""
        return list(self._scenarios.values())

    def get(self, scenario_id: str) -> Optional[Scenario]:
        """Return a scenario by its ID."""
        return self._scenarios.get(scenario_id)