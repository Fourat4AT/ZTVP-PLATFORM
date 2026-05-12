from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.text import Text
from rich import box

from app.catalog import ScenarioCatalog
from app.collector import DataCollector
from app.reporting import ReportFormatter

console = Console()


def microsoft_mark() -> Table:
    mark = Table.grid(padding=(0, 1))
    mark.add_row(
        "[#F25022]■[/#F25022] [#7FBA00]■[/#7FBA00]",
        "[#00A4EF]■[/#00A4EF] [#FFB900]■[/#FFB900]",
    )
    return mark


def print_banner(catalog: ScenarioCatalog) -> None:
    big_title = Text("ZTVP", style="bold white")
    subtitle = Text("Zero Trust Validation Platform", style="bold #7DD3FC")
    desc = Text("Scenario-Based Security Validation CLI Prototype", style="#94A3B8")

    title_block = Group(big_title, subtitle, desc)

    header_table = Table.grid(expand=False, padding=(0, 3))
    header_table.add_column(justify="center", width=12)
    header_table.add_column()
    header_table.add_row(microsoft_mark(), title_block)

    stats = Table.grid(expand=True)
    stats.add_column(justify="center")
    stats.add_column(justify="center")
    stats.add_column(justify="center")

    total = len(catalog.list_scenarios())
    stats.add_row(
        Panel.fit(f"[bold #F8FAFC]{total}[/bold #F8FAFC]\n[dim]Implemented Scenarios[/dim]", border_style="#334155"),
        Panel.fit("[bold #22C55E]ACTIVE[/bold #22C55E]\n[dim]Prototype Status[/dim]", border_style="#334155"),
        Panel.fit("[bold #38BDF8]CLI[/bold #38BDF8]\n[dim]Execution Mode[/dim]", border_style="#334155"),
    )

    hero = Group(
        Align.center(header_table),
        Text(""),
        stats,
    )

    console.print()
    console.print(
        Panel(
            hero,
            title="[bold #93C5FD]Launch Console[/bold #93C5FD]",
            border_style="#2563EB",
            box=box.DOUBLE,
            padding=(1, 3),
            width=min(console.size.width - 4, 110),
        ),
        justify="center",
    )
    console.print()


def print_menu() -> None:
    cards = [
        Panel.fit(
            "[bold #F8FAFC]1[/bold #F8FAFC]\n[dim]List Scenarios[/dim]",
            border_style="#38BDF8",
            box=box.ROUNDED,
            padding=(1, 4),
        ),
        Panel.fit(
            "[bold #F8FAFC]2[/bold #F8FAFC]\n[dim]Run Scenario[/dim]",
            border_style="#22C55E",
            box=box.ROUNDED,
            padding=(1, 4),
        ),
        Panel.fit(
            "[bold #F8FAFC]3[/bold #F8FAFC]\n[dim]Run All[/dim]",
            border_style="#A78BFA",
            box=box.ROUNDED,
            padding=(1, 4),
        ),
        Panel.fit(
            "[bold #F8FAFC]Q[/bold #F8FAFC]\n[dim]Quit[/dim]",
            border_style="#F59E0B",
            box=box.ROUNDED,
            padding=(1, 4),
        ),
    ]

    console.print(Columns(cards, equal=True, expand=False), justify="center")
    console.print()


def list_scenarios(catalog: ScenarioCatalog) -> None:
    table = Table(
        title="[bold #E2E8F0]Available Scenarios[/bold #E2E8F0]",
        box=box.HEAVY_HEAD,
        border_style="#475569",
        header_style="bold #7DD3FC",
        row_styles=["none", "#0F172A"],
        width=min(console.size.width - 8, 100),
    )
    table.add_column("ID", justify="center", style="bold #38BDF8", width=8)
    table.add_column("Category", style="#E2E8F0", width=28)
    table.add_column("Scenario", style="#F8FAFC", width=40)

    for scenario in catalog.list_scenarios():
        table.add_row(
            scenario.scenario_id,
            scenario.category,
            scenario.name,
        )

    console.print(table, justify="center")
    console.print("[dim]Use option 2 to execute one scenario or option 3 to run all.[/dim]", justify="center")
    console.print()


def choose_report_mode() -> str:
    modes = [
        Panel.fit(
            "[bold #F8FAFC]1[/bold #F8FAFC]\n[dim]Brief Report[/dim]",
            border_style="#38BDF8",
            box=box.ROUNDED,
            padding=(1, 3),
        ),
        Panel.fit(
            "[bold #F8FAFC]2[/bold #F8FAFC]\n[dim]Detailed Report[/dim]",
            border_style="#A78BFA",
            box=box.ROUNDED,
            padding=(1, 3),
        ),
    ]

    console.print(Columns(modes, equal=True, expand=False), justify="center")
    console.print()

    while True:
        choice = Prompt.ask("[bold #7DD3FC]Select mode[/bold #7DD3FC]").strip()
        if choice == "1":
            return "brief"
        if choice == "2":
            return "detailed"
        console.print("[bold red]Invalid choice. Enter 1 or 2.[/bold red]")


def ask_save_report() -> bool:
    while True:
        choice = Prompt.ask("[bold #7DD3FC]Save report to file? (Y/N)[/bold #7DD3FC]").strip().upper()
        if choice in ("Y", "N"):
            return choice == "Y"
        console.print("[bold red]Invalid choice. Enter Y or N.[/bold red]")


def render_result(result, formatter, mode: str) -> None:
    console.print()
    if mode == "brief":
        console.print(formatter.to_console_brief(result), justify="center")
    else:
        console.print(formatter.to_console_detailed(result), justify="center")
    console.print()

    if ask_save_report():
        path = formatter.save_text_report(result)
        console.print(f"[bold green]Report saved:[/bold green] [white]{path}[/white]\n")


def run_scenario(
    catalog: ScenarioCatalog,
    collector: DataCollector,
    formatter: ReportFormatter,
) -> None:
    console.print(Rule(style="#334155"))
    scenario_id = Prompt.ask("[bold #7DD3FC]Enter scenario ID (A1 / A6)[/bold #7DD3FC]").strip().upper()
    scenario = catalog.get(scenario_id)

    if not scenario:
        console.print("[bold red]Invalid scenario ID.[/bold red]\n")
        return

    scenario_info = Panel.fit(
        f"[bold white]{scenario.scenario_id} - {scenario.name}[/bold white]\n[dim]{scenario.category}[/dim]\n\n[white]{scenario.objective}[/white]",
        title="[bold #93C5FD]Selected Scenario[/bold #93C5FD]",
        border_style="#475569",
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(scenario_info, justify="center")
    console.print()

    try:
        evidence = collector.collect_for_scenario(scenario_id)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]\n")
        return

    report_mode = choose_report_mode()
    result = scenario.evaluator(evidence)
    render_result(result, formatter, report_mode)


def run_all_scenarios(
    catalog: ScenarioCatalog,
    collector: DataCollector,
    formatter: ReportFormatter,
) -> None:
    console.print(Rule(style="#334155"))
    report_mode = choose_report_mode()

    for scenario in catalog.list_scenarios():
        try:
            evidence = collector.collect_for_scenario(scenario.scenario_id)
            result = scenario.evaluator(evidence)
            render_result(result, formatter, report_mode)
        except ValueError as exc:
            console.print(f"[bold red]{exc}[/bold red]\n")


def main() -> None:
    catalog = ScenarioCatalog()
    collector = DataCollector()
    formatter = ReportFormatter()

    print_banner(catalog)

    while True:
        print_menu()
        choice = Prompt.ask("[bold #7DD3FC]Select an option[/bold #7DD3FC]").strip().upper()

        if choice == "1":
            list_scenarios(catalog)
        elif choice == "2":
            run_scenario(catalog, collector, formatter)
        elif choice == "3":
            run_all_scenarios(catalog, collector, formatter)
        elif choice == "Q":
            console.print("\n[bold #93C5FD]Goodbye.[/bold #93C5FD]\n", justify="center")
            break
        else:
            console.print("[bold red]Invalid menu option.[/bold red]\n")


if __name__ == "__main__":
    main()