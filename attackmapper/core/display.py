"""Rich console display utilities for AttackMapper."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.box import DOUBLE, ROUNDED

from .models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    ThreatActor,
    CVEInfo,
    ThreatIntelReport,
    InfrastructureType,
)


class DisplayManager:
    """Manages Rich console output for AttackMapper."""

    # Phase colors for visual distinction
    PHASE_COLORS = {
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

    RISK_COLORS = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }

    INFRASTRUCTURE_NAMES = {
        InfrastructureType.ACTIVE_DIRECTORY: "Active Directory",
        InfrastructureType.AWS: "AWS",
        InfrastructureType.AZURE: "Azure",
        InfrastructureType.GCP: "GCP",
        InfrastructureType.NETWORK: "Network",
        InfrastructureType.ONPREM: "On-Premises",
    }

    def __init__(self):
        self.console = Console()

    def display_header(self, title: str, infrastructure: InfrastructureType | None = None):
        """Display a styled header panel."""
        if infrastructure:
            infra_name = self.INFRASTRUCTURE_NAMES.get(infrastructure, infrastructure.value.upper())
            full_title = f"{infra_name.upper()} ATTACK PATHS"
        else:
            full_title = title.upper()

        self.console.print(
            Panel(
                Text(full_title, style="bold white", justify="center"),
                box=DOUBLE,
                style="bright_blue",
                padding=(0, 2),
            )
        )
        self.console.print()

    def display_techniques_by_phase(
        self, techniques: list[AttackTechnique], infrastructure: InfrastructureType
    ):
        """Display techniques organized by attack phase."""
        self.display_header("Attack Paths", infrastructure)

        # Group techniques by phase
        by_phase: dict[AttackPhase, list[AttackTechnique]] = {}
        for tech in techniques:
            if tech.phase not in by_phase:
                by_phase[tech.phase] = []
            by_phase[tech.phase].append(tech)

        # Display each phase in order
        for phase in AttackPhase.get_order():
            if phase not in by_phase:
                continue

            phase_color = self.PHASE_COLORS.get(phase, "white")
            phase_name = AttackPhase.get_display_name(phase)

            self.console.print(f"[bold {phase_color}]Phase: {phase_name.upper()}[/]")

            tree = Tree("")
            for tech in by_phase[phase]:
                tech_node = tree.add(f"[{phase_color}][{tech.mitre_id}][/] {tech.name}")
                tech_node.add(f"[dim]{tech.description}[/]")

            self.console.print(tree)
            self.console.print()

    def display_technique_detail(self, technique: AttackTechnique):
        """Display detailed information about a single technique."""
        phase_color = self.PHASE_COLORS.get(technique.phase, "white")
        risk_color = self.RISK_COLORS.get(technique.risk_level, "white")

        self.console.print(
            Panel(
                f"[bold]{technique.name}[/]",
                subtitle=f"[{phase_color}]{technique.id}[/]",
                box=ROUNDED,
            )
        )

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")

        table.add_row("MITRE ID", technique.mitre_id)
        table.add_row("Phase", f"[{phase_color}]{AttackPhase.get_display_name(technique.phase)}[/]")
        table.add_row("Risk Level", f"[{risk_color}]{technique.risk_level.upper()}[/]")
        table.add_row("Description", technique.description)

        if technique.prerequisites:
            table.add_row("Prerequisites", "\n".join(f"- {p}" for p in technique.prerequisites))

        if technique.tools:
            table.add_row("Tools", ", ".join(technique.tools))

        if technique.detection:
            table.add_row("Detection", technique.detection)

        if technique.next_techniques:
            table.add_row("Enables", ", ".join(technique.next_techniques))

        self.console.print(table)
        self.console.print()

    def display_techniques_list(self, techniques: list[AttackTechnique], title: str = "Techniques"):
        """Display a numbered list of techniques with details."""
        self.console.print(Panel(f"[bold]{title}[/]", box=DOUBLE, style="bright_blue"))
        self.console.print()

        for i, tech in enumerate(techniques, 1):
            phase_color = self.PHASE_COLORS.get(tech.phase, "white")
            risk_color = self.RISK_COLORS.get(tech.risk_level, "white")

            self.console.print(f"[bold][{i}][/] {tech.name}")

            tree = Tree("")
            tree.add(f"[dim]MITRE:[/] {tech.mitre_id}")
            tree.add(f"[dim]Phase:[/] [{phase_color}]{AttackPhase.get_display_name(tech.phase)}[/]")
            tree.add(f"[dim]Risk:[/] [{risk_color}]{tech.risk_level.upper()}[/]")

            if tech.prerequisites:
                prereq_node = tree.add("[dim]Prereq:[/]")
                for prereq in tech.prerequisites:
                    prereq_node.add(f"[dim]{prereq}[/]")

            tree.add(f"[dim]Attack:[/] {tech.description}")

            if tech.tools:
                tree.add(f"[dim]Tools:[/] {', '.join(tech.tools)}")

            if tech.detection:
                tree.add(f"[dim]Detection:[/] {tech.detection}")

            if tech.next_techniques:
                tree.add(f"[dim]Next:[/] {', '.join(tech.next_techniques)}")

            self.console.print(tree)
            self.console.print()

    def display_attack_path(self, path: AttackPath):
        """Display a complete attack path with ASCII visualization."""
        self.display_header(f"Full Attack Chain - {self.INFRASTRUCTURE_NAMES.get(path.infrastructure, path.infrastructure.value)}")

        # ASCII chain visualization
        phases_in_path = []
        for step in path.steps:
            if step.technique.phase not in phases_in_path:
                phases_in_path.append(step.technique.phase)

        # Build the chain visualization
        chain_parts = []
        for phase in phases_in_path:
            color = self.PHASE_COLORS.get(phase, "white")
            short_name = phase.value.upper()[:6]
            chain_parts.append(f"[{color}][{short_name}][/]")

        chain_visual = " --> ".join(chain_parts)
        self.console.print(chain_visual)
        self.console.print()

        # Detailed path breakdown
        self.console.print("[bold]Detailed Path:[/]")
        for step in path.steps:
            phase_color = self.PHASE_COLORS.get(step.technique.phase, "white")
            phase_name = AttackPhase.get_display_name(step.technique.phase).upper()

            self.console.print(
                f"[bold]{step.step_number}.[/] [{phase_color}][{phase_name}][/] "
                f"{step.technique.name}"
            )
            if step.description:
                self.console.print(f"   [dim]{step.description}[/]")

        self.console.print()

    def display_full_chain_diagram(self, path: AttackPath):
        """Display a more detailed attack chain with arrows and descriptions."""
        self.display_header(f"Full Attack Chain - {self.INFRASTRUCTURE_NAMES.get(path.infrastructure, path.infrastructure.value)}")

        # Compact phase header
        phases_used = list(dict.fromkeys(step.technique.phase for step in path.steps))
        header_parts = []
        for phase in phases_used:
            color = self.PHASE_COLORS.get(phase, "white")
            short = phase.value.replace("_", " ").title()[:8]
            header_parts.append(f"[{color}]{short}[/]")

        self.console.print(" --> ".join(header_parts))
        self.console.print()

        # Detailed steps
        self.console.print("[bold]Detailed Path:[/]")
        for step in path.steps:
            phase_color = self.PHASE_COLORS.get(step.technique.phase, "white")
            phase_display = AttackPhase.get_display_name(step.technique.phase).upper()

            self.console.print(
                f"{step.step_number}. [{phase_color}][{phase_display}][/] "
                f"{step.description or step.technique.name}"
            )

        self.console.print()
        self.console.print(f"[dim]Export: attackmapper full-chain --infra {path.infrastructure.value} --output report.html[/]")

    def display_threat_intel(self, report: ThreatIntelReport):
        """Display threat intelligence report."""
        infra_name = self.INFRASTRUCTURE_NAMES.get(report.infrastructure, report.infrastructure.value)
        self.display_header(f"Active Threat Intelligence - {infra_name}")

        # Critical CVEs
        if report.critical_cves:
            self.console.print("[bold red]CRITICAL CVEs:[/]")
            tree = Tree("")
            for cve in report.critical_cves:
                severity_color = self.RISK_COLORS.get(cve.severity, "yellow")
                cve_node = tree.add(
                    f"[{severity_color}]{cve.cve_id}[/]: {cve.description[:60]}... "
                    f"(CVSS: {cve.cvss_score})"
                )
                if cve.exploitation_status == "in-the-wild":
                    cve_node.add("[bold red]ACTIVELY EXPLOITED[/]")
            self.console.print(tree)
            self.console.print()

        # Active threat actors
        if report.active_threat_actors:
            self.console.print("[bold yellow]ACTIVE THREAT ACTORS targeting {infra_name}:[/]")
            tree = Tree("")
            for actor in report.active_threat_actors:
                actor_node = tree.add(f"[bold]{actor.name}[/]")
                if actor.aliases:
                    actor_node.add(f"[dim]Aliases: {', '.join(actor.aliases)}[/]")
                if actor.recent_activity:
                    actor_node.add(f"[dim]Recent TTPs: {actor.recent_activity}[/]")
            self.console.print(tree)
            self.console.print()

        # Trending techniques
        if report.trending_techniques:
            self.console.print("[bold cyan]TRENDING TECHNIQUES:[/]")
            tree = Tree("")
            for technique in report.trending_techniques:
                tree.add(technique)
            self.console.print(tree)
            self.console.print()

        if report.last_updated:
            self.console.print(f"[dim]Last updated: {report.last_updated}[/]")

    def display_cves(self, cves: list[CVEInfo], title: str = "CVE Information"):
        """Display a list of CVEs."""
        self.console.print(Panel(f"[bold]{title}[/]", box=ROUNDED))

        table = Table(box=ROUNDED)
        table.add_column("CVE ID", style="bold")
        table.add_column("CVSS", justify="center")
        table.add_column("Severity", justify="center")
        table.add_column("Status")
        table.add_column("Description")

        for cve in cves:
            severity_color = self.RISK_COLORS.get(cve.severity, "white")
            status_display = "[bold red]EXPLOITED[/]" if cve.exploitation_status == "in-the-wild" else cve.exploitation_status

            table.add_row(
                cve.cve_id,
                f"{cve.cvss_score:.1f}",
                f"[{severity_color}]{cve.severity.upper()}[/]",
                status_display,
                cve.description[:50] + "..." if len(cve.description) > 50 else cve.description,
            )

        self.console.print(table)

    def display_threat_actors(self, actors: list[ThreatActor]):
        """Display threat actor information."""
        for actor in actors:
            self.console.print(Panel(f"[bold]{actor.name}[/]", box=ROUNDED))

            tree = Tree("")
            if actor.aliases:
                tree.add(f"[dim]Aliases:[/] {', '.join(actor.aliases)}")
            if actor.description:
                tree.add(f"[dim]Description:[/] {actor.description}")
            if actor.recent_activity:
                tree.add(f"[dim]Recent Activity:[/] {actor.recent_activity}")
            if actor.ttps:
                ttps_node = tree.add("[dim]Known TTPs:[/]")
                for ttp in actor.ttps[:5]:  # Limit displayed TTPs
                    ttps_node.add(ttp)

            self.console.print(tree)
            self.console.print()

    def display_update_progress(self, source: str, status: str, count: int = 0):
        """Display progress during threat intel updates."""
        if status == "fetching":
            self.console.print(f"[*] Fetching {source}...")
        elif status == "success":
            self.console.print(f"[green][+][/] {source}: {count} items cached")
        elif status == "error":
            self.console.print(f"[red][-][/] {source}: Failed to fetch")
        elif status == "complete":
            self.console.print(f"[green][+][/] Threat intel updated. {count} total items cached.")

    def display_error(self, message: str):
        """Display an error message."""
        self.console.print(f"[bold red]Error:[/] {message}")

    def display_warning(self, message: str):
        """Display a warning message."""
        self.console.print(f"[bold yellow]Warning:[/] {message}")

    def display_info(self, message: str):
        """Display an info message."""
        self.console.print(f"[bold blue]Info:[/] {message}")

    def display_success(self, message: str):
        """Display a success message."""
        self.console.print(f"[bold green]Success:[/] {message}")
