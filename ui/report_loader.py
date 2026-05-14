from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "powershell" / "Reports"
HTML_REPORTS_DIR = REPORTS_DIR / "Html"


def list_json_reports() -> List[Path]:
    if not REPORTS_DIR.exists():
        return []

    return sorted(
        REPORTS_DIR.glob("*-result.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def load_report(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def find_html_report(scenario_id: str) -> Optional[Path]:
    if not scenario_id:
        return None

    path = HTML_REPORTS_DIR / f"{scenario_id}-result.html"
    return path if path.exists() else None


def report_summary_rows() -> List[Dict[str, Any]]:
    rows = []

    for path in list_json_reports():
        try:
            report = load_report(path)

            rows.append(
                {
                    "Scenario": report.get("scenario_id", ""),
                    "Name": report.get("scenario_name", ""),
                    "Category": report.get("category", ""),
                    "Status": report.get("status", ""),
                    "Risk": report.get("risk", ""),
                    "Generated": report.get("timestamp", ""),
                    "File": path.name,
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "Scenario": "ERROR",
                    "Name": path.name,
                    "Category": "",
                    "Status": "LOAD ERROR",
                    "Risk": "",
                    "Generated": "",
                    "File": str(exc),
                }
            )

    return rows
