from pathlib import Path
from datetime import datetime

from rich.console import Group
from rich.table import Table
from rich.panel import Panel
from rich import box

from app.models import EvaluationResult


class ReportFormatter:
    @staticmethod
    def _status_style(status: str) -> str:
        if status == "PASS":
            return "bold green"
        if status == "PARTIAL":
            return "bold yellow"
        return "bold red"

    @staticmethod
    def _risk_style(risk: str) -> str:
        if risk == "LOW":
            return "green"
        if risk == "MEDIUM":
            return "yellow"
        if risk == "HIGH":
            return "bright_red"
        return "bold red"

    @staticmethod
    def _summary(result: EvaluationResult) -> Table:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold cyan", width=10)
        table.add_column(style="white")

        table.add_row("Scenario", f"{result.scenario_id} - {result.scenario_name}")
        table.add_row(
            "Status",
            f"[{ReportFormatter._status_style(result.status.value)}]{result.status.value}[/{ReportFormatter._status_style(result.status.value)}]",
        )
        table.add_row(
            "Risk",
            f"[{ReportFormatter._risk_style(result.risk.value)}]{result.risk.value}[/{ReportFormatter._risk_style(result.risk.value)}]",
        )
        return table

    @staticmethod
    def to_console_brief(result: EvaluationResult):
        findings = Table(
            box=box.SIMPLE,
            header_style="bold cyan",
            show_header=True,
        )
        findings.add_column("Top Findings", style="white", width=46)

        if result.findings:
            for item in result.findings[:2]:
                findings.add_row(item.title)
        else:
            findings.add_row("No findings")

        recommendation = (
            result.recommendations[0].title if result.recommendations else "No recommendation"
        )

        recommendation_table = Table.grid()
        recommendation_table.add_row(
            f"[bold cyan]Primary Recommendation:[/bold cyan] [white]{recommendation}[/white]"
        )

        content = Group(
            ReportFormatter._summary(result),
            findings,
            recommendation_table,
        )

        return Panel.fit(
            content,
            title="[bold white]Brief Report[/bold white]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )

    @staticmethod
    def to_console_detailed(result: EvaluationResult):
        findings = Table(
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
        )
        findings.add_column("Finding", style="bright_white", width=24)
        findings.add_column("Detail", style="white", width=60)

        if result.findings:
            for item in result.findings:
                findings.add_row(item.title, item.detail)
        else:
            findings.add_row("None", "No findings")

        recommendations = Table(
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
        )
        recommendations.add_column("Recommendation", style="bright_white", width=24)
        recommendations.add_column("Detail", style="white", width=60)

        if result.recommendations:
            for item in result.recommendations:
                recommendations.add_row(item.title, item.detail)
        else:
            recommendations.add_row("None", "No recommendations")

        content = Group(
            ReportFormatter._summary(result),
            findings,
            recommendations,
        )

        return Panel.fit(
            content,
            title="[bold white]Detailed Report[/bold white]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )

    @staticmethod
    def to_text(result: EvaluationResult) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append(f"Scenario : {result.scenario_id} - {result.scenario_name}")
        lines.append(f"Status   : {result.status.value}")
        lines.append(f"Risk     : {result.risk.value}")
        lines.append("-" * 60)
        lines.append("Findings:")

        if result.findings:
            for item in result.findings:
                lines.append(f"- {item.title}: {item.detail}")
        else:
            lines.append("- None")

        lines.append("-" * 60)
        lines.append("Recommendations:")

        if result.recommendations:
            for item in result.recommendations:
                lines.append(f"- {item.title}: {item.detail}")
        else:
            lines.append("- None")

        lines.append("=" * 60)
        return "\n".join(lines)

    @staticmethod
    def save_text_report(result: EvaluationResult, folder: str = "reports") -> str:
        reports_dir = Path(folder)
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{result.scenario_id}_{timestamp}.txt"
        filepath = reports_dir / filename

        filepath.write_text(ReportFormatter.to_text(result), encoding="utf-8")
        return str(filepath)