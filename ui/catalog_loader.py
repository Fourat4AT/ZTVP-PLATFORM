from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "powershell" / "ScenarioCatalog.ps1"
RUNNER_PATH = PROJECT_ROOT / "powershell" / "Run-ZTVP.ps1"


PILLAR_ORDER = [
    "Identity",
    "Devices",
    "Applications",
    "Data",
    "Network",
    "Operations / Monitoring",
]

SCOPE_ORDER = [
    "Cloud",
    "On-Premises",
    "Hybrid",
]


def _parse_value(raw: str) -> Any:
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


def _extract_scenario_objects(text: str, source: str) -> List[Dict[str, Any]]:
    objects: List[Dict[str, Any]] = []

    blocks = re.finditer(r"\[PSCustomObject\]@\{(.*?)\}", text, flags=re.DOTALL | re.IGNORECASE)

    for match in blocks:
        body = match.group(1)

        if "ScenarioId" not in body:
            continue

        item: Dict[str, Any] = {
            "_source": source,
            "_position": match.start(),
        }

        for line in body.splitlines():
            line = line.strip()

            if not line or "=" not in line:
                continue

            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", line)

            if not m:
                continue

            key = m.group(1)
            value = _parse_value(m.group(2))
            item[key] = value

        if item.get("ScenarioId") and item.get("Name"):
            item.setdefault("Implemented", False)
            item.setdefault("PillarName", "")
            item.setdefault("CategoryName", "")
            item.setdefault("CategoryId", "")
            item.setdefault("Scope", "")
            item.setdefault("Priority", "")
            item.setdefault("Phase", "")
            item.setdefault("Objective", "")
            item.setdefault("EnginePath", "")
            item.setdefault("FunctionName", "")
            objects.append(item)

    return objects


def _read_file(path: Path) -> str:
    if not path.exists():
        return ""

    return path.read_text(encoding="utf-8-sig", errors="ignore")


def load_scenarios() -> List[Dict[str, Any]]:
    """
    Loads the scenario catalog without executing PowerShell.
    This avoids UI crashes caused by patched PowerShell functions.
    """
    files = [
        ("ScenarioCatalog.ps1", CATALOG_PATH),
        ("Run-ZTVP.ps1", RUNNER_PATH),
    ]

    collected: List[Dict[str, Any]] = []

    for source_name, path in files:
        text = _read_file(path)
        if text:
            collected.extend(_extract_scenario_objects(text, source_name))

    # De-duplicate by ScenarioId.
    # Keep the last definition because later patches usually contain the latest version.
    by_id: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for item in collected:
        sid = str(item.get("ScenarioId", "")).strip()

        if not sid:
            continue

        if sid not in by_id:
            order.append(sid)

        by_id[sid] = item

    scenarios = [by_id[sid] for sid in order]

    # Stable order: pillar order, category as discovered, scope order, then original source position.
    category_order: Dict[str, int] = {}

    for scenario in scenarios:
        category = scenario.get("CategoryName", "")
        if category and category not in category_order:
            category_order[category] = len(category_order)

    def sort_key(item: Dict[str, Any]):
        pillar = item.get("PillarName", "")
        category = item.get("CategoryName", "")
        scope = item.get("Scope", "")

        pillar_index = PILLAR_ORDER.index(pillar) if pillar in PILLAR_ORDER else 999
        category_index = category_order.get(category, 999)
        scope_index = SCOPE_ORDER.index(scope) if scope in SCOPE_ORDER else 999

        return (
            pillar_index,
            category_index,
            scope_index,
            item.get("_position", 999999),
            item.get("ScenarioId", ""),
        )

    return sorted(scenarios, key=sort_key)


def unique_ordered(items: List[Dict[str, Any]], key: str, preferred_order: List[str] | None = None) -> List[str]:
    preferred_order = preferred_order or []
    found: List[str] = []

    for item in items:
        value = item.get(key)

        if value in (None, ""):
            continue

        value = str(value)

        if value not in found:
            found.append(value)

    ordered: List[str] = []

    for preferred in preferred_order:
        if preferred in found:
            ordered.append(preferred)

    for value in found:
        if value not in ordered:
            ordered.append(value)

    return ordered


def scenario_label(item: Dict[str, Any]) -> str:
    scenario_id = item.get("ScenarioId", "Unknown")
    name = item.get("Name", "Unknown")
    state = "READY" if item.get("Implemented") is True else "PLANNED"
    return f"{scenario_id} - {name} [{state}]"
