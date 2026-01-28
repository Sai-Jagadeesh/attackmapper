"""AttackMapper CLI - Attack Path Visualizer for Red Team Operations."""

import asyncio
from typing import Optional
from pathlib import Path
from datetime import datetime

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.syntax import Syntax

from attackmapper.core.models import AttackPhase, InfrastructureType
from attackmapper.core.display import DisplayManager
from attackmapper.core.export import ExportManager
from attackmapper.modules.ad import ADModule
from attackmapper.modules.aws import AWSModule
from attackmapper.modules.azure import AzureModule
from attackmapper.modules.gcp import GCPModule
from attackmapper.modules.network import NetworkModule
from attackmapper.intel import ThreatIntelManager

app = typer.Typer(
    name="attackmapper",
    help="CLI Attack Path Visualizer for Red Team Operations",
    no_args_is_help=False,
    invoke_without_command=True,
)

console = Console()
display = DisplayManager()
export_manager = ExportManager()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    AttackMapper - Interactive CLI Attack Path Visualizer.

    Run without arguments for interactive mode, or use subcommands for direct access.
    """
    if ctx.invoked_subcommand is not None:
        return

    # Interactive mode when no subcommand is provided
    run_interactive_mode()


def run_interactive_mode():
    """Run the full interactive mode experience."""
    from rich.table import Table

    # Display welcome banner
    console.print()
    console.print(Panel.fit(
        "[bold cyan]AttackMapper[/bold cyan]\n"
        "[dim]CLI Attack Path Visualizer for Red Team Operations[/dim]",
        border_style="cyan",
    ))
    console.print()

    intel_manager = ThreatIntelManager()

    # Step 1: Threat Intelligence Update
    console.print("[bold yellow]Step 1:[/] Threat Intelligence")
    console.print()

    cache_stats = intel_manager.get_cache_stats()
    last_update = cache_stats.get('last_update')
    custom_feed_count = cache_stats.get('custom_feed_count', 0)

    if last_update:
        console.print(f"  [dim]Last updated: {last_update}[/]")
        console.print(f"  [dim]Cached CVEs: {cache_stats.get('cve_count', 0)} | Threat Actors: {cache_stats.get('threat_actor_count', 0)} | Custom Feeds: {custom_feed_count}[/]")
    else:
        console.print("  [yellow]Threat intelligence has never been updated.[/]")

    console.print()
    console.print("  [bold cyan]1[/]. [bold]Skip[/] - Continue without updating")
    console.print("  [bold cyan]2[/]. [bold]Update Now[/] - Fetch latest threat intel from all sources")
    console.print("  [bold cyan]3[/]. [bold]Manage Custom Feeds[/] - Add/remove custom threat intel feeds")
    console.print()

    intel_choice = Prompt.ask(
        "Select option",
        choices=["1", "2", "3", "skip", "update", "feeds"],
        default="1"
    )

    intel_map = {"1": "skip", "2": "update", "3": "feeds"}
    intel_action = intel_map.get(intel_choice, intel_choice.lower())

    if intel_action == "update":
        console.print()
        _do_update_intel()
        console.print()
    elif intel_action == "feeds":
        console.print()
        _manage_custom_feeds_interactive(intel_manager)
        console.print()
        # After managing feeds, ask if they want to update
        if Confirm.ask("Update threat intelligence now?", default=True):
            console.print()
            _do_update_intel()
            console.print()

    console.print(f"[green]✓[/] Threat intelligence configured")
    console.print()

    # Step 2: Select infrastructure type
    console.print("[bold yellow]Step 2:[/] Select Infrastructure Type")
    console.print()

    infra_options = [
        ("ad", "Active Directory", "On-prem AD attacks: Kerberoasting, DCSync, Golden Ticket, etc."),
        ("aws", "AWS", "Cloud attacks: IAM privesc, EC2 SSRF, S3 misconfigs, Lambda injection"),
        ("azure", "Azure", "Azure attacks: Managed Identity, Key Vault, AKS, Entra ID"),
        ("gcp", "GCP", "GCP attacks: Service accounts, GKE, Cloud Functions, metadata"),
        ("network", "Network", "Network attacks: Pivoting, lateral movement, MitM, exfiltration"),
    ]

    for i, (key, name, desc) in enumerate(infra_options, 1):
        console.print(f"  [bold cyan]{i}[/]. [bold]{name}[/] - {desc}")

    console.print()
    infra_choice = Prompt.ask(
        "Select infrastructure",
        choices=["1", "2", "3", "4", "5", "ad", "aws", "azure", "gcp", "network"],
        default="1"
    )

    # Map choice to infrastructure key
    infra_map = {"1": "ad", "2": "aws", "3": "azure", "4": "gcp", "5": "network"}
    infra = infra_map.get(infra_choice, infra_choice.lower())
    infra_name = INFRA_NAMES.get(infra, infra)

    console.print()
    console.print(f"[green]✓[/] Selected: [bold]{infra_name}[/]")
    console.print()

    # Step 3: Select category/phase filter
    console.print("[bold yellow]Step 3:[/] Select Attack Phase (optional)")
    console.print()

    categories = [
        ("all", "All Phases", "Show all attack techniques"),
        ("reconnaissance", "Reconnaissance", "Information gathering and enumeration"),
        ("initial_access", "Initial Access", "Gaining first foothold"),
        ("execution", "Execution", "Running malicious code"),
        ("persistence", "Persistence", "Maintaining access"),
        ("privilege_escalation", "Privilege Escalation", "Gaining higher privileges"),
        ("defense_evasion", "Defense Evasion", "Avoiding detection"),
        ("credential_access", "Credential Access", "Stealing credentials"),
        ("discovery", "Discovery", "Exploring the environment"),
        ("lateral_movement", "Lateral Movement", "Moving through the network"),
        ("collection", "Collection", "Gathering target data"),
        ("exfiltration", "Exfiltration", "Stealing data out"),
        ("impact", "Impact", "Disruption and destruction"),
    ]

    for i, (key, name, desc) in enumerate(categories):
        console.print(f"  [bold cyan]{i:2}[/]. [bold]{name}[/] - {desc}")

    console.print()
    cat_choice = Prompt.ask(
        "Select phase (number or name)",
        default="0"
    )

    # Map choice to category
    if cat_choice.isdigit() and int(cat_choice) < len(categories):
        category = categories[int(cat_choice)][0]
    else:
        category = cat_choice.lower().replace(" ", "_")
        if category not in [c[0] for c in categories]:
            category = "all"

    cat_name = next((c[1] for c in categories if c[0] == category), category)
    console.print()
    console.print(f"[green]✓[/] Selected: [bold]{cat_name}[/]")
    console.print()

    # Step 4: Select Output Format
    console.print("[bold yellow]Step 4:[/] Select Output Format")
    console.print()
    console.print("  [bold cyan]1[/]. [bold]Terminal[/] - Display attack paths and threat intel in terminal")
    console.print("  [bold cyan]2[/]. [bold]HTML Report[/] - Generate interactive web report")
    console.print("  [bold cyan]3[/]. [bold]Both[/] - Display in terminal AND generate HTML report")
    console.print()

    format_choice = Prompt.ask(
        "Select output format",
        choices=["1", "2", "3", "terminal", "html", "both"],
        default="3"
    )

    format_map = {"1": "terminal", "2": "html", "3": "both"}
    output_format = format_map.get(format_choice, format_choice.lower())

    console.print()
    console.print(f"[green]✓[/] Selected: [bold]{output_format.upper()}[/]")
    console.print()

    # Step 5: Generate output
    console.print("[bold yellow]Step 5:[/] Generating Output")
    console.print()

    # Get threat intel report
    infra_type_map = {
        "ad": InfrastructureType.ACTIVE_DIRECTORY,
        "aws": InfrastructureType.AWS,
        "azure": InfrastructureType.AZURE,
        "gcp": InfrastructureType.GCP,
        "network": InfrastructureType.NETWORK,
    }
    infrastructure_type = infra_type_map.get(infra, InfrastructureType.ACTIVE_DIRECTORY)
    threat_report = intel_manager.get_threat_report(infrastructure_type)

    # Terminal output
    if output_format in ["terminal", "both"]:
        console.print()
        _display_terminal_report(infra, category, threat_report)
        console.print()

    # HTML output
    if output_format in ["html", "both"]:
        # Ensure reports directory exists
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if category != "all":
            filename = f"attackmapper_{infra}_{category}_{timestamp}.html"
        else:
            filename = f"attackmapper_{infra}_{timestamp}.html"

        output_path = f"reports/{filename}"

        console.print(f"[dim]Generating HTML report: {output_path}[/]")
        console.print()

        # Generate the report with threat intel included
        run_infrastructure_command(
            infra,
            category=category if category != "all" else None,
            output=output_path,
            format="html",
            include_threat_intel=True,
        )

        # Final message for HTML
        console.print()
        console.print(Panel.fit(
            f"[bold green]HTML Report generated![/]\n\n"
            f"Open in browser:\n"
            f"[cyan]file://{Path(output_path).absolute()}[/]",
            border_style="green",
        ))


def _display_terminal_report(infra: str, category: str, threat_report):
    """Display a comprehensive terminal report with techniques and threat intel."""
    from rich.table import Table
    from rich.syntax import Syntax

    module = get_module(infra)
    if not module:
        return

    module.load_techniques()

    # Get techniques based on category
    if category and category != "all":
        techniques = module.get_techniques_by_category(category)
    else:
        techniques = module.get_all_techniques()

    infra_name = INFRA_NAMES.get(infra, infra)

    # Header
    console.print(Panel.fit(
        f"[bold cyan]{infra_name.upper()} ATTACK PATHS[/]",
        border_style="cyan",
    ))
    console.print()

    # Display Active Threat Intelligence First
    console.print(Panel.fit("[bold red]ACTIVE THREAT INTELLIGENCE[/]", border_style="red"))
    console.print()

    # Critical CVEs
    if threat_report.critical_cves:
        console.print("[bold red]Critical CVEs (Actively Exploited):[/]")
        cve_table = Table(show_header=True, header_style="bold", box=None)
        cve_table.add_column("CVE", style="bold red")
        cve_table.add_column("CVSS", justify="center")
        cve_table.add_column("Description")
        cve_table.add_column("Status")

        for cve in threat_report.critical_cves[:10]:
            status = "[bold red]EXPLOITED[/]" if cve.exploitation_status == "in-the-wild" else cve.exploitation_status
            cve_table.add_row(
                cve.cve_id,
                f"{cve.cvss_score:.1f}",
                cve.description[:60] + "..." if len(cve.description) > 60 else cve.description,
                status,
            )
        console.print(cve_table)
        console.print()

    # Active Threat Actors
    if threat_report.active_threat_actors:
        console.print("[bold yellow]Active Threat Actors:[/]")
        for actor in threat_report.active_threat_actors[:5]:
            console.print(f"  [bold]{actor.name}[/]", end="")
            if actor.aliases:
                console.print(f" [dim]({', '.join(actor.aliases[:3])})[/]", end="")
            console.print()
            if actor.recent_activity:
                console.print(f"    [dim]Recent TTPs: {actor.recent_activity}[/]")
            if actor.ttps:
                console.print(f"    [dim]MITRE: {', '.join(actor.ttps[:5])}[/]")
        console.print()

    # Trending Techniques
    if threat_report.trending_techniques:
        console.print("[bold cyan]Trending Attack Techniques:[/]")
        for i, technique in enumerate(threat_report.trending_techniques[:8], 1):
            console.print(f"  {i}. {technique}")
        console.print()

    # Attack Techniques Section
    console.print(Panel.fit("[bold green]ATTACK TECHNIQUES & COMMANDS[/]", border_style="green"))
    console.print()

    # Group techniques by phase
    by_phase: dict[AttackPhase, list] = {}
    for tech in techniques:
        if tech.phase not in by_phase:
            by_phase[tech.phase] = []
        by_phase[tech.phase].append(tech)

    # Phase colors
    phase_colors = {
        AttackPhase.RECONNAISSANCE: "cyan",
        AttackPhase.INITIAL_ACCESS: "green",
        AttackPhase.EXECUTION: "yellow",
        AttackPhase.PERSISTENCE: "magenta",
        AttackPhase.PRIVILEGE_ESCALATION: "red",
        AttackPhase.DEFENSE_EVASION: "blue",
        AttackPhase.CREDENTIAL_ACCESS: "bright_red",
        AttackPhase.DISCOVERY: "bright_cyan",
        AttackPhase.LATERAL_MOVEMENT: "bright_yellow",
        AttackPhase.COLLECTION: "bright_magenta",
        AttackPhase.EXFILTRATION: "bright_blue",
        AttackPhase.IMPACT: "bold red",
    }

    # Display each phase
    for phase in AttackPhase.get_order():
        if phase not in by_phase:
            continue

        phase_color = phase_colors.get(phase, "white")
        phase_name = AttackPhase.get_display_name(phase)

        console.print(f"\n[bold {phase_color}]{'='*60}[/]")
        console.print(f"[bold {phase_color}]  {phase_name.upper()}[/]")
        console.print(f"[bold {phase_color}]{'='*60}[/]")

        for tech in by_phase[phase]:
            # Technique header
            console.print()
            console.print(f"[bold][{tech.mitre_id}][/] [bold {phase_color}]{tech.name}[/]")
            console.print(f"[dim]{tech.description}[/]")

            # Tools
            if tech.tools:
                console.print(f"[cyan]Tools:[/] {', '.join(tech.tools)}")

            # Commands (the key part)
            if tech.commands:
                console.print(f"[green]Commands:[/]")
                for cmd in tech.commands[:5]:  # Limit to 5 commands per technique
                    # Display as code block
                    console.print(Panel(
                        Syntax(cmd, "bash", theme="monokai", line_numbers=False, word_wrap=True),
                        border_style="dim",
                        padding=(0, 1),
                    ))

            # Detection
            if tech.detection:
                console.print(f"[yellow]Detection:[/] {tech.detection}")

    # Summary
    console.print()
    console.print(Panel.fit(
        f"[bold]Summary:[/] {len(techniques)} techniques across {len(by_phase)} phases\n"
        f"[dim]Infrastructure: {infra_name}[/]",
        border_style="dim",
    ))


def _manage_custom_feeds_interactive(intel_manager: ThreatIntelManager):
    """Interactive menu for managing custom feeds."""
    from rich.table import Table

    while True:
        console.print("[bold]Custom Threat Intelligence Feeds[/]")
        console.print()

        # Show current feeds
        feeds = intel_manager.get_custom_feeds()
        if feeds:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("#", width=3)
            table.add_column("Name", style="bold")
            table.add_column("URL")
            table.add_column("Type")
            table.add_column("Status")
            table.add_column("Last Fetched")

            for i, feed in enumerate(feeds, 1):
                status = "[green]Enabled[/]" if feed["enabled"] else "[dim]Disabled[/]"
                last_fetched = feed.get("last_fetched", "Never") or "Never"
                table.add_row(
                    str(i),
                    feed["name"],
                    feed["url"][:50] + "..." if len(feed["url"]) > 50 else feed["url"],
                    feed["feed_type"],
                    status,
                    last_fetched[:16] if last_fetched != "Never" else last_fetched,
                )
            console.print(table)
        else:
            console.print("  [dim]No custom feeds configured.[/]")

        console.print()
        console.print("  [bold cyan]1[/]. [bold]Add Feed[/] - Add a new custom feed URL")
        console.print("  [bold cyan]2[/]. [bold]Remove Feed[/] - Remove an existing feed")
        console.print("  [bold cyan]3[/]. [bold]Done[/] - Return to main menu")
        console.print()

        choice = Prompt.ask(
            "Select option",
            choices=["1", "2", "3", "add", "remove", "done"],
            default="3"
        )

        choice_map = {"1": "add", "2": "remove", "3": "done"}
        action = choice_map.get(choice, choice.lower())

        if action == "done":
            break

        elif action == "add":
            console.print()
            console.print("[bold]Add Custom Feed[/]")
            console.print()
            console.print("[dim]Supported formats:[/]")
            console.print("  - JSON: {\"techniques\": [...], \"cves\": [...], \"threat_actors\": [...]}")
            console.print("  - STIX 2.x: Standard STIX bundle format")
            console.print("  - MISP: MISP event export format")
            console.print()

            name = Prompt.ask("Feed name (unique identifier)")
            if not name:
                console.print("[red]Name is required[/]")
                continue

            url = Prompt.ask("Feed URL")
            if not url:
                console.print("[red]URL is required[/]")
                continue

            feed_type = Prompt.ask(
                "Feed type",
                choices=["json", "stix", "misp"],
                default="json"
            )

            console.print()
            console.print("[dim]Optional: Specify which infrastructure this feed relates to[/]")
            infra = Prompt.ask(
                "Infrastructure (or leave empty for all)",
                default=""
            )

            success = intel_manager.add_custom_feed(
                name=name,
                url=url,
                feed_type=feed_type,
                infrastructure=infra if infra else None,
            )

            if success:
                console.print(f"[green]✓ Feed '{name}' added successfully[/]")
            else:
                console.print(f"[red]✗ A feed with name '{name}' already exists[/]")

            console.print()

        elif action == "remove":
            if not feeds:
                console.print("[yellow]No feeds to remove[/]")
                console.print()
                continue

            console.print()
            name = Prompt.ask("Enter feed name to remove")

            if intel_manager.remove_custom_feed(name):
                console.print(f"[green]✓ Feed '{name}' removed[/]")
            else:
                console.print(f"[red]✗ Feed '{name}' not found[/]")

            console.print()


# Module registry
MODULE_REGISTRY = {
    "ad": ADModule,
    "aws": AWSModule,
    "azure": AzureModule,
    "gcp": GCPModule,
    "network": NetworkModule,
}

INFRA_NAMES = {
    "ad": "Active Directory",
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "network": "Network",
}


def get_module(infra: str):
    """Get the appropriate module for the infrastructure type."""
    infra_lower = infra.lower()
    if infra_lower in MODULE_REGISTRY:
        return MODULE_REGISTRY[infra_lower]()
    return None


def get_phase_from_string(phase_str: str) -> Optional[AttackPhase]:
    """Convert string to AttackPhase enum."""
    phase_map = {
        "recon": AttackPhase.RECONNAISSANCE,
        "reconnaissance": AttackPhase.RECONNAISSANCE,
        "initial": AttackPhase.INITIAL_ACCESS,
        "initial_access": AttackPhase.INITIAL_ACCESS,
        "execution": AttackPhase.EXECUTION,
        "persistence": AttackPhase.PERSISTENCE,
        "privesc": AttackPhase.PRIVILEGE_ESCALATION,
        "privilege_escalation": AttackPhase.PRIVILEGE_ESCALATION,
        "defense_evasion": AttackPhase.DEFENSE_EVASION,
        "evasion": AttackPhase.DEFENSE_EVASION,
        "credential_access": AttackPhase.CREDENTIAL_ACCESS,
        "credentials": AttackPhase.CREDENTIAL_ACCESS,
        "creds": AttackPhase.CREDENTIAL_ACCESS,
        "discovery": AttackPhase.DISCOVERY,
        "lateral": AttackPhase.LATERAL_MOVEMENT,
        "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
        "collection": AttackPhase.COLLECTION,
        "exfil": AttackPhase.EXFILTRATION,
        "exfiltration": AttackPhase.EXFILTRATION,
        "impact": AttackPhase.IMPACT,
    }
    return phase_map.get(phase_str.lower())


def interactive_prompts(infra: str) -> dict:
    """Run interactive prompts for user preferences."""
    console.print()
    console.print(Panel(f"[bold cyan]{INFRA_NAMES.get(infra, infra).upper()} Attack Mapper[/]",
                       subtitle="Interactive Mode"))
    console.print()

    options = {}

    # Ask about threat intelligence update
    intel_manager = ThreatIntelManager()
    cache_stats = intel_manager.get_cache_stats()
    last_update = cache_stats.get('last_update')

    if last_update:
        console.print(f"[dim]Threat intel last updated: {last_update}[/]")
    else:
        console.print("[yellow]Threat intelligence has never been updated.[/]")

    if Confirm.ask("Update threat intelligence sources?", default=False):
        options['update_intel'] = True
        console.print("[dim]Will update threat intelligence...[/]")
    else:
        options['update_intel'] = False

    console.print()

    # Ask about category filter
    categories = [
        "all", "reconnaissance", "initial_access", "execution", "persistence",
        "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection", "exfiltration", "impact"
    ]
    console.print("[bold]Available categories:[/]")
    for i, cat in enumerate(categories):
        console.print(f"  {i}. {cat}")

    cat_choice = Prompt.ask(
        "Select category (number or name)",
        default="0"
    )

    if cat_choice.isdigit() and int(cat_choice) < len(categories):
        options['category'] = categories[int(cat_choice)]
    elif cat_choice in categories:
        options['category'] = cat_choice
    else:
        options['category'] = "all"

    console.print()

    # Ask about output format
    output_choice = Prompt.ask(
        "Output format",
        choices=["terminal", "html", "json"],
        default="terminal"
    )
    options['format'] = output_choice

    if output_choice in ["html", "json"]:
        # Ensure reports directory exists
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        default_name = f"reports/attackmapper_{infra}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if output_choice == "html":
            default_name += ".html"
        else:
            default_name += ".json"

        output_path = Prompt.ask("Output file path", default=default_name)
        options['output'] = output_path

    console.print()

    # Ask about including threat intel in report
    if output_choice == "html":
        options['include_threat_intel'] = Confirm.ask(
            "Include threat intelligence in report?",
            default=True
        )

    return options


def run_infrastructure_command(
    infra: str,
    category: Optional[str] = None,
    phase: Optional[str] = None,
    search: Optional[str] = None,
    output: Optional[str] = None,
    format: str = "terminal",
    interactive: bool = False,
    include_threat_intel: bool = False,
):
    """Common function to run infrastructure commands."""
    module = get_module(infra)
    if not module:
        display.display_error(f"Unknown infrastructure: {infra}")
        raise typer.Exit(1)

    module.load_techniques()
    techniques = []

    if category and category != "all":
        techniques = module.get_techniques_by_category(category)
        if not techniques:
            display.display_error(f"No techniques found for category: {category}")
            raise typer.Exit(1)
    elif phase:
        phase_enum = get_phase_from_string(phase)
        if phase_enum:
            techniques = module.get_techniques_by_phase(phase_enum)
        if not techniques:
            display.display_error(f"No techniques found for phase: {phase}")
            raise typer.Exit(1)
    elif search:
        techniques = module.search_techniques(search)
        if not techniques:
            display.display_error(f"No techniques found matching: {search}")
            raise typer.Exit(1)
    else:
        techniques = module.get_all_techniques()

    # Get threat intel if requested
    threat_report = None
    if include_threat_intel or format == "html":
        intel_manager = ThreatIntelManager()
        threat_report = intel_manager.get_threat_report(module.infrastructure_type)

    # Handle output
    if output:
        output_path = Path(output)
        if format == "json":
            path = export_manager.export_techniques_json(techniques, str(output_path))
            display.display_success(f"Exported to: {path}")
        elif format == "html":
            path = export_manager.export_interactive_html(
                techniques,
                module.infrastructure_type,
                str(output_path),
                threat_report=threat_report,
            )
            display.display_success(f"Exported to: {path}")
            console.print(f"[dim]Open in browser: file://{path}[/]")
        else:
            display.display_error("Invalid format. Use: json, html")
            raise typer.Exit(1)
    else:
        if category or phase:
            title = f"{INFRA_NAMES.get(infra, infra)} - {category or phase}".upper()
            display.display_techniques_list(techniques, title)
        else:
            display.display_techniques_by_phase(techniques, module.infrastructure_type)


@app.command()
def ad(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category/phase"
    ),
    phase: Optional[str] = typer.Option(
        None, "--phase", "-p", help="Filter by attack phase"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search techniques"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Run in interactive mode"
    ),
):
    """Display Active Directory attack paths and techniques."""
    if interactive:
        options = interactive_prompts("ad")
        if options.get('update_intel'):
            _do_update_intel()
        run_infrastructure_command(
            "ad",
            category=options.get('category'),
            output=options.get('output'),
            format=options.get('format', 'terminal'),
            include_threat_intel=options.get('include_threat_intel', False),
        )
    else:
        run_infrastructure_command("ad", category, phase, search, output, format)


@app.command()
def aws(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category/phase"
    ),
    phase: Optional[str] = typer.Option(
        None, "--phase", "-p", help="Filter by attack phase"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search techniques"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Run in interactive mode"
    ),
):
    """Display AWS attack paths and techniques."""
    if interactive:
        options = interactive_prompts("aws")
        if options.get('update_intel'):
            _do_update_intel()
        run_infrastructure_command(
            "aws",
            category=options.get('category'),
            output=options.get('output'),
            format=options.get('format', 'terminal'),
            include_threat_intel=options.get('include_threat_intel', False),
        )
    else:
        run_infrastructure_command("aws", category, phase, search, output, format)


@app.command()
def azure(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category/phase"
    ),
    phase: Optional[str] = typer.Option(
        None, "--phase", "-p", help="Filter by attack phase"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search techniques"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Run in interactive mode"
    ),
):
    """Display Azure attack paths and techniques."""
    if interactive:
        options = interactive_prompts("azure")
        if options.get('update_intel'):
            _do_update_intel()
        run_infrastructure_command(
            "azure",
            category=options.get('category'),
            output=options.get('output'),
            format=options.get('format', 'terminal'),
            include_threat_intel=options.get('include_threat_intel', False),
        )
    else:
        run_infrastructure_command("azure", category, phase, search, output, format)


@app.command()
def gcp(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category/phase"
    ),
    phase: Optional[str] = typer.Option(
        None, "--phase", "-p", help="Filter by attack phase"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search techniques"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Run in interactive mode"
    ),
):
    """Display GCP attack paths and techniques."""
    if interactive:
        options = interactive_prompts("gcp")
        if options.get('update_intel'):
            _do_update_intel()
        run_infrastructure_command(
            "gcp",
            category=options.get('category'),
            output=options.get('output'),
            format=options.get('format', 'terminal'),
            include_threat_intel=options.get('include_threat_intel', False),
        )
    else:
        run_infrastructure_command("gcp", category, phase, search, output, format)


@app.command()
def network(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category/phase"
    ),
    phase: Optional[str] = typer.Option(
        None, "--phase", "-p", help="Filter by attack phase"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search techniques"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Run in interactive mode"
    ),
):
    """Display Network attack paths and techniques."""
    if interactive:
        options = interactive_prompts("network")
        if options.get('update_intel'):
            _do_update_intel()
        run_infrastructure_command(
            "network",
            category=options.get('category'),
            output=options.get('output'),
            format=options.get('format', 'terminal'),
            include_threat_intel=options.get('include_threat_intel', False),
        )
    else:
        run_infrastructure_command("network", category, phase, search, output, format)


@app.command("full-chain")
def full_chain(
    infra: str = typer.Option(
        "ad", "--infra", "-i", help="Infrastructure type: ad, aws, azure, gcp, network"
    ),
    from_phase: Optional[str] = typer.Option(
        None, "--from", help="Starting phase"
    ),
    to_phase: Optional[str] = typer.Option(
        None, "--to", help="Ending phase"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, html"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-I", help="Run in interactive mode"
    ),
):
    """Generate a full attack chain for the specified infrastructure."""
    module = get_module(infra)
    if not module:
        display.display_error(f"Unknown infrastructure: {infra}")
        raise typer.Exit(1)

    module.load_techniques()

    start_phase = get_phase_from_string(from_phase) if from_phase else None
    end_phase = get_phase_from_string(to_phase) if to_phase else None

    attack_path = module.generate_full_chain(start_phase, end_phase)

    if output:
        output_path = Path(output)
        if format == "json":
            path = export_manager.export_attack_path_json(attack_path, str(output_path))
            display.display_success(f"Exported to: {path}")
        elif format == "html":
            path = export_manager.export_attack_path_html(attack_path, str(output_path))
            display.display_success(f"Exported to: {path}")
            console.print(f"[dim]Open in browser: file://{path}[/]")
        else:
            display.display_error("Invalid format. Use: json, html")
            raise typer.Exit(1)
    else:
        display.display_full_chain_diagram(attack_path)


@app.command("threat-intel")
def threat_intel(
    infra: str = typer.Option(
        "ad", "--infra", "-i", help="Infrastructure type: ad, aws, azure, gcp, network"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export to file"
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json"
    ),
):
    """Display threat intelligence for the specified infrastructure."""
    infra_map = {
        "ad": InfrastructureType.ACTIVE_DIRECTORY,
        "aws": InfrastructureType.AWS,
        "azure": InfrastructureType.AZURE,
        "gcp": InfrastructureType.GCP,
        "network": InfrastructureType.NETWORK,
    }

    infrastructure = infra_map.get(infra.lower())
    if not infrastructure:
        display.display_error(f"Unknown infrastructure: {infra}")
        raise typer.Exit(1)

    intel_manager = ThreatIntelManager()
    report = intel_manager.get_threat_report(infrastructure)

    if output:
        output_path = Path(output)
        if format == "json":
            path = export_manager.export_threat_intel_json(report, str(output_path))
            display.display_success(f"Exported to: {path}")
        else:
            display.display_error("Invalid format for threat intel. Use: json")
            raise typer.Exit(1)
    else:
        display.display_threat_intel(report)


def _do_update_intel():
    """Helper function to update threat intelligence."""
    intel_manager = ThreatIntelManager()

    def progress_callback(source: str, status: str, count: int = 0):
        display.display_update_progress(source, status, count)

    display.display_info("Updating threat intelligence...")
    console.print()

    stats = asyncio.run(intel_manager.update_intel(progress_callback))

    if stats.get("errors"):
        for error in stats["errors"]:
            display.display_warning(f"Warning: {error}")


@app.command("update-intel")
def update_intel():
    """Update threat intelligence from external sources."""
    _do_update_intel()


@app.command()
def version():
    """Display AttackMapper version."""
    from attackmapper import __version__
    console.print(f"AttackMapper version {__version__}")


@app.command()
def stats():
    """Display statistics about loaded techniques and cached intel."""
    console.print("[bold cyan]AttackMapper Statistics[/]")
    console.print()

    total_techniques = 0
    for infra, module_cls in MODULE_REGISTRY.items():
        module = module_cls()
        try:
            module.load_techniques()
            count = len(module.get_all_techniques())
            total_techniques += count
            console.print(f"[bold]{INFRA_NAMES.get(infra, infra)} Module:[/] {count} techniques")
        except Exception:
            console.print(f"[bold]{INFRA_NAMES.get(infra, infra)} Module:[/] [dim]Not loaded[/]")

    console.print(f"\n[bold]Total techniques:[/] {total_techniques}")
    console.print()

    # Intel cache stats
    intel_manager = ThreatIntelManager()
    cache_stats = intel_manager.get_cache_stats()

    console.print("[bold]Threat Intelligence Cache:[/]")
    console.print(f"  Cached CVEs: {cache_stats.get('cve_count', 0)}")
    console.print(f"  Cached Threat Actors: {cache_stats.get('threat_actor_count', 0)}")
    console.print(f"  Custom Feeds: {cache_stats.get('custom_feed_count', 0)}")
    console.print(f"  Last Updated: {cache_stats.get('last_update') or 'Never'}")


@app.command()
def list_infra():
    """List all available infrastructure types."""
    console.print("[bold cyan]Available Infrastructure Types[/]")
    console.print()

    for infra, name in INFRA_NAMES.items():
        module = MODULE_REGISTRY.get(infra)
        if module:
            m = module()
            try:
                m.load_techniques()
                count = len(m.get_all_techniques())
                console.print(f"  [bold]{infra}[/] - {name} ({count} techniques)")
            except Exception:
                console.print(f"  [bold]{infra}[/] - {name} (not available)")


# Create feeds subcommand group
feeds_app = typer.Typer(help="Manage custom threat intelligence feeds")
app.add_typer(feeds_app, name="feeds")


@feeds_app.command("list")
def feeds_list():
    """List all configured custom feeds."""
    from rich.table import Table

    intel_manager = ThreatIntelManager()
    feeds = intel_manager.get_custom_feeds()

    console.print("[bold cyan]Custom Threat Intelligence Feeds[/]")
    console.print()

    if not feeds:
        console.print("[dim]No custom feeds configured.[/]")
        console.print()
        console.print("Add a feed with: [bold]attackmapper feeds add <name> <url>[/]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("URL")
    table.add_column("Type")
    table.add_column("Infrastructure")
    table.add_column("Status")
    table.add_column("Last Fetched")

    for feed in feeds:
        status = "[green]Enabled[/]" if feed["enabled"] else "[dim]Disabled[/]"
        last_fetched = feed.get("last_fetched", "Never") or "Never"
        infra = feed.get("infrastructure") or "All"
        table.add_row(
            feed["name"],
            feed["url"][:60] + "..." if len(feed["url"]) > 60 else feed["url"],
            feed["feed_type"],
            infra,
            status,
            last_fetched[:16] if last_fetched != "Never" else last_fetched,
        )

    console.print(table)


@feeds_app.command("add")
def feeds_add(
    name: str = typer.Argument(..., help="Unique name for the feed"),
    url: str = typer.Argument(..., help="URL of the threat intel feed"),
    feed_type: str = typer.Option(
        "json", "--type", "-t", help="Feed format: json, stix, misp"
    ),
    infrastructure: Optional[str] = typer.Option(
        None, "--infra", "-i", help="Target infrastructure: ad, aws, azure, gcp, network"
    ),
):
    """Add a new custom threat intelligence feed.

    Supported feed formats:
    - json: {"techniques": [...], "cves": [...], "threat_actors": [...]}
    - stix: STIX 2.x bundle format
    - misp: MISP event export format

    Example:
        attackmapper feeds add my-feed https://example.com/feed.json
        attackmapper feeds add ad-intel https://example.com/ad.json --infra ad
    """
    intel_manager = ThreatIntelManager()

    if feed_type not in ["json", "stix", "misp"]:
        display.display_error(f"Invalid feed type: {feed_type}. Use: json, stix, misp")
        raise typer.Exit(1)

    if infrastructure and infrastructure not in ["ad", "aws", "azure", "gcp", "network"]:
        display.display_error(f"Invalid infrastructure: {infrastructure}")
        raise typer.Exit(1)

    success = intel_manager.add_custom_feed(
        name=name,
        url=url,
        feed_type=feed_type,
        infrastructure=infrastructure,
    )

    if success:
        display.display_success(f"Feed '{name}' added successfully")
        console.print()
        console.print(f"[dim]Run [bold]attackmapper update-intel[/] to fetch data from this feed.[/]")
    else:
        display.display_error(f"A feed with name '{name}' already exists")
        raise typer.Exit(1)


@feeds_app.command("remove")
def feeds_remove(
    name: str = typer.Argument(..., help="Name of the feed to remove"),
):
    """Remove a custom feed."""
    intel_manager = ThreatIntelManager()

    if intel_manager.remove_custom_feed(name):
        display.display_success(f"Feed '{name}' removed")
    else:
        display.display_error(f"Feed '{name}' not found")
        raise typer.Exit(1)


@feeds_app.command("toggle")
def feeds_toggle(
    name: str = typer.Argument(..., help="Name of the feed to toggle"),
    enable: bool = typer.Option(
        True, "--enable/--disable", help="Enable or disable the feed"
    ),
):
    """Enable or disable a custom feed."""
    intel_manager = ThreatIntelManager()

    if intel_manager.toggle_feed(name, enable):
        status = "enabled" if enable else "disabled"
        display.display_success(f"Feed '{name}' {status}")
    else:
        display.display_error(f"Feed '{name}' not found")
        raise typer.Exit(1)


# Create sources subcommand group for built-in sources
sources_app = typer.Typer(help="Manage built-in threat intelligence sources")
app.add_typer(sources_app, name="sources")


@sources_app.command("list")
def sources_list(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category: red_team, exploits, techniques, iocs, threat_intel"
    ),
    infrastructure: Optional[str] = typer.Option(
        None, "--infra", "-i", help="Filter by infrastructure: ad, aws, azure, gcp, network"
    ),
    enabled_only: bool = typer.Option(
        False, "--enabled", "-e", help="Show only enabled sources"
    ),
):
    """List all available built-in threat intelligence sources.

    Categories:
    - red_team: Offensive security tools and techniques (LOLBAS, GTFOBins, etc.)
    - exploits: Vulnerability and exploit databases (CISA KEV, Nuclei, etc.)
    - techniques: Attack technique references (MITRE ATT&CK, Atomic Red Team)
    - iocs: Indicators of compromise (abuse.ch feeds, phishing)
    - threat_intel: Threat actor intelligence (Malpedia, OTX)
    """
    from rich.table import Table

    intel_manager = ThreatIntelManager()
    sources = intel_manager.get_builtin_sources()

    # Apply filters
    if category:
        sources = [s for s in sources if s["category"] == category]
    if infrastructure:
        sources = [s for s in sources if s["infrastructure"] is None or s["infrastructure"] == infrastructure]
    if enabled_only:
        sources = [s for s in sources if s["enabled"]]

    console.print("[bold cyan]Built-in Threat Intelligence Sources[/]")
    console.print()

    if not sources:
        console.print("[dim]No sources match the filter criteria.[/]")
        return

    # Group by category
    categories = {}
    for source in sources:
        cat = source["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(source)

    category_names = {
        "red_team": "Red Team Resources",
        "exploits": "Vulnerability & Exploits",
        "techniques": "Attack Techniques",
        "iocs": "Indicators of Compromise",
        "threat_intel": "Threat Intelligence",
    }

    for cat, cat_sources in categories.items():
        console.print(f"\n[bold yellow]{category_names.get(cat, cat)}[/]")

        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Name", style="cyan", width=25)
        table.add_column("Description", width=50)
        table.add_column("Infra", width=8)
        table.add_column("Status", width=10)

        for source in cat_sources:
            status = "[green]Enabled[/]" if source["enabled"] else "[dim]Disabled[/]"
            if source["requires_api_key"]:
                status += " [yellow](API key)[/]"
            infra = source["infrastructure"] or "All"
            table.add_row(
                source["name"],
                source["description"][:48] + "..." if len(source["description"]) > 48 else source["description"],
                infra,
                status,
            )

        console.print(table)

    console.print()
    console.print(f"[dim]Total: {len(sources)} sources | Use 'attackmapper sources enable <name>' to enable a source[/]")


@sources_app.command("enable")
def sources_enable(
    name: str = typer.Argument(..., help="Name of the source to enable"),
):
    """Enable a built-in source."""
    intel_manager = ThreatIntelManager()

    if intel_manager.enable_builtin_source(name):
        display.display_success(f"Source '{name}' enabled")
        console.print()
        console.print(f"[dim]Run [bold]attackmapper update-intel[/] to fetch data from this source.[/]")
    else:
        display.display_error(f"Source '{name}' not found")
        console.print()
        console.print("[dim]Use 'attackmapper sources list' to see available sources[/]")
        raise typer.Exit(1)


@sources_app.command("disable")
def sources_disable(
    name: str = typer.Argument(..., help="Name of the source to disable"),
):
    """Disable a built-in source."""
    intel_manager = ThreatIntelManager()

    if intel_manager.disable_builtin_source(name):
        display.display_success(f"Source '{name}' disabled")
    else:
        display.display_error(f"Source '{name}' not found")
        raise typer.Exit(1)


@sources_app.command("info")
def sources_info(
    name: str = typer.Argument(..., help="Name of the source to get info about"),
):
    """Show detailed information about a source."""
    from attackmapper.intel.sources import get_source

    source = get_source(name)
    if not source:
        display.display_error(f"Source '{name}' not found")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]{source.name}[/]",
        subtitle=source.category,
    ))
    console.print()
    console.print(f"[bold]Description:[/] {source.description}")
    console.print(f"[bold]URL:[/] {source.url}")
    console.print(f"[bold]Type:[/] {source.feed_type}")
    console.print(f"[bold]Category:[/] {source.category}")
    console.print(f"[bold]Infrastructure:[/] {source.infrastructure or 'All'}")
    console.print(f"[bold]Enabled by default:[/] {'Yes' if source.enabled_by_default else 'No'}")

    if source.requires_api_key:
        console.print()
        console.print(f"[yellow]Requires API key:[/] Set {source.api_key_env} environment variable")


@sources_app.command("enable-all")
def sources_enable_all(
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Enable all sources in a specific category"
    ),
):
    """Enable all built-in sources (or all in a category)."""
    from attackmapper.intel.sources import BUILTIN_SOURCES

    intel_manager = ThreatIntelManager()
    count = 0

    for name, source in BUILTIN_SOURCES.items():
        if category and source.category != category:
            continue
        if intel_manager.enable_builtin_source(name):
            count += 1

    display.display_success(f"Enabled {count} sources")
    console.print()
    console.print(f"[dim]Run [bold]attackmapper update-intel[/] to fetch data from all sources.[/]")


@sources_app.command("disable-all")
def sources_disable_all():
    """Disable all built-in sources."""
    from attackmapper.intel.sources import BUILTIN_SOURCES

    intel_manager = ThreatIntelManager()
    count = 0

    for name in BUILTIN_SOURCES:
        if intel_manager.disable_builtin_source(name):
            count += 1

    display.display_success(f"Disabled {count} sources")


if __name__ == "__main__":
    app()
