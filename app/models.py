from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Any, List


class ResultStatus(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    title: str
    detail: str


@dataclass
class Recommendation:
    title: str
    detail: str


@dataclass
class EvaluationResult:
    scenario_id: str
    scenario_name: str
    status: ResultStatus
    risk: RiskLevel
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)


@dataclass
class Scenario:
    scenario_id: str
    name: str
    category: str
    objective: str
    evaluator: Callable[[Dict[str, Any]], EvaluationResult]