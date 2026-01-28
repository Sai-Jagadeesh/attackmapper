"""Export utilities for AttackMapper."""

import json
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    ThreatIntelReport,
    InfrastructureType,
)


class ExportManager:
    """Manages export to various formats."""

    def __init__(self):
        # Set up Jinja2 environment for HTML templates
        template_dir = Path(__file__).parent.parent / "templates"
        if template_dir.exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self.jinja_env = None

    def export_techniques_json(
        self, techniques: list[AttackTechnique], output_path: str
    ) -> str:
        """Export techniques to JSON file."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_techniques": len(techniques),
            "techniques": [tech.to_dict() for tech in techniques],
        }

        path = Path(output_path)
        path.write_text(json.dumps(data, indent=2))
        return str(path.absolute())

    def export_attack_path_json(self, path: AttackPath, output_path: str) -> str:
        """Export attack path to JSON file."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "attack_path": path.to_dict(),
        }

        file_path = Path(output_path)
        file_path.write_text(json.dumps(data, indent=2))
        return str(file_path.absolute())

    def export_threat_intel_json(
        self, report: ThreatIntelReport, output_path: str
    ) -> str:
        """Export threat intelligence report to JSON file."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "threat_intel": report.to_dict(),
        }

        path = Path(output_path)
        path.write_text(json.dumps(data, indent=2))
        return str(path.absolute())

    def export_techniques_html(
        self,
        techniques: list[AttackTechnique],
        infrastructure: InfrastructureType,
        output_path: str,
    ) -> str:
        """Export techniques to HTML report."""
        # Group techniques by phase
        by_phase: dict[str, list[dict]] = {}
        for tech in techniques:
            phase_key = tech.phase.value
            if phase_key not in by_phase:
                by_phase[phase_key] = []
            by_phase[phase_key].append(tech.to_dict())

        # Get phase order
        phase_order = [p.value for p in AttackPhase.get_order()]

        context = {
            "title": f"{infrastructure.value.upper()} Attack Paths",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "infrastructure": infrastructure.value,
            "total_techniques": len(techniques),
            "techniques_by_phase": by_phase,
            "phase_order": phase_order,
            "phase_display_names": {
                p.value: AttackPhase.get_display_name(p) for p in AttackPhase
            },
        }

        html_content = self._render_techniques_html(context)
        path = Path(output_path)
        path.write_text(html_content)
        return str(path.absolute())

    def export_attack_path_html(self, attack_path: AttackPath, output_path: str) -> str:
        """Export attack path to HTML report with visualization."""
        # Prepare step data
        steps_data = []
        for step in attack_path.steps:
            steps_data.append({
                "step_number": step.step_number,
                "phase": step.technique.phase.value,
                "phase_display": AttackPhase.get_display_name(step.technique.phase),
                "technique_name": step.technique.name,
                "mitre_id": step.technique.mitre_id,
                "description": step.description or step.technique.description,
                "tools": step.technique.tools,
                "detection": step.technique.detection,
            })

        # Get unique phases in order
        phases_in_path = []
        for step in attack_path.steps:
            if step.technique.phase.value not in phases_in_path:
                phases_in_path.append(step.technique.phase.value)

        context = {
            "title": f"Attack Chain - {attack_path.name}",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "path_name": attack_path.name,
            "infrastructure": attack_path.infrastructure.value,
            "start_phase": attack_path.start_phase.value,
            "end_phase": attack_path.end_phase.value,
            "total_steps": len(attack_path.steps),
            "steps": steps_data,
            "phases_in_path": phases_in_path,
            "phase_display_names": {
                p.value: AttackPhase.get_display_name(p) for p in AttackPhase
            },
        }

        html_content = self._render_attack_path_html(context)
        path = Path(output_path)
        path.write_text(html_content)
        return str(path.absolute())

    def _render_techniques_html(self, context: dict) -> str:
        """Render techniques HTML using template or fallback."""
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("report.html.j2")
                return template.render(**context)
            except Exception:
                pass

        # Fallback inline template
        return self._generate_techniques_html_inline(context)

    def _render_attack_path_html(self, context: dict) -> str:
        """Render attack path HTML using template or fallback."""
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("attack_path.html.j2")
                return template.render(**context)
            except Exception:
                pass

        # Fallback inline template
        return self._generate_attack_path_html_inline(context)

    def _generate_techniques_html_inline(self, context: dict) -> str:
        """Generate techniques HTML without external template."""
        phases_html = ""
        for phase in context["phase_order"]:
            if phase not in context["techniques_by_phase"]:
                continue
            techniques = context["techniques_by_phase"][phase]
            phase_display = context["phase_display_names"].get(phase, phase)

            techniques_items = ""
            for tech in techniques:
                tools_str = ", ".join(tech["tools"]) if tech["tools"] else "N/A"
                techniques_items += f"""
                <div class="technique">
                    <h4>[{tech['mitre_id']}] {tech['name']}</h4>
                    <p><strong>Description:</strong> {tech['description']}</p>
                    <p><strong>Tools:</strong> {tools_str}</p>
                    <p><strong>Detection:</strong> {tech['detection'] or 'N/A'}</p>
                    <p><strong>Risk:</strong> <span class="risk-{tech['risk_level']}">{tech['risk_level'].upper()}</span></p>
                </div>
                """

            phases_html += f"""
            <div class="phase">
                <h3 class="phase-header phase-{phase}">{phase_display}</h3>
                {techniques_items}
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{context['title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #ff6b6b; }}
        .meta {{ color: #888; margin-bottom: 20px; }}
        .phase {{ background: #16213e; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
        .phase-header {{ margin: 0 0 15px 0; padding: 10px; border-radius: 4px; }}
        .phase-reconnaissance {{ background: #0891b2; }}
        .phase-initial_access {{ background: #059669; }}
        .phase-execution {{ background: #d97706; }}
        .phase-persistence {{ background: #7c3aed; }}
        .phase-privilege_escalation {{ background: #dc2626; }}
        .phase-defense_evasion {{ background: #2563eb; }}
        .phase-credential_access {{ background: #be123c; }}
        .phase-discovery {{ background: #0e7490; }}
        .phase-lateral_movement {{ background: #ca8a04; }}
        .phase-collection {{ background: #9333ea; }}
        .phase-exfiltration {{ background: #1d4ed8; }}
        .phase-impact {{ background: #991b1b; }}
        .technique {{ background: #0f3460; border-left: 3px solid #00d4ff; padding: 10px 15px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }}
        .technique h4 {{ margin: 0 0 10px 0; color: #00d4ff; }}
        .technique p {{ margin: 5px 0; font-size: 14px; }}
        .risk-low {{ color: #22c55e; }}
        .risk-medium {{ color: #eab308; }}
        .risk-high {{ color: #ef4444; }}
        .risk-critical {{ color: #dc2626; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{context['title']}</h1>
        <p class="meta">Generated: {context['generated_at']} | Total Techniques: {context['total_techniques']}</p>
        {phases_html}
    </div>
</body>
</html>"""

    def export_interactive_html(
        self,
        techniques: list[AttackTechnique],
        infrastructure: InfrastructureType,
        output_path: str,
        threat_report: ThreatIntelReport | None = None,
    ) -> str:
        """Export techniques to interactive HTML report with filtering and search."""
        # Group techniques by phase
        by_phase: dict[str, list[dict]] = {}
        for tech in techniques:
            phase_key = tech.phase.value
            if phase_key not in by_phase:
                by_phase[phase_key] = []
            by_phase[phase_key].append(tech.to_dict())

        # Get phase order
        phase_order = [p.value for p in AttackPhase.get_order()]

        context = {
            "title": f"{infrastructure.value.upper()} Attack Techniques",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "infrastructure": infrastructure.value,
            "total_techniques": len(techniques),
            "techniques_by_phase": by_phase,
            "phase_order": phase_order,
            "phase_display_names": {
                p.value: AttackPhase.get_display_name(p) for p in AttackPhase
            },
            "threat_intel": threat_report.to_dict() if threat_report else None,
        }

        html_content = self._render_interactive_html(context)
        path = Path(output_path)
        path.write_text(html_content)
        return str(path.absolute())

    def _render_interactive_html(self, context: dict) -> str:
        """Render interactive HTML using template or fallback."""
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("interactive_report.html.j2")
                return template.render(**context)
            except Exception:
                pass

        # Fallback to basic techniques HTML if template fails
        return self._generate_techniques_html_inline(context)

    def _generate_attack_path_html_inline(self, context: dict) -> str:
        """Generate attack path HTML without external template."""
        # Build chain visualization
        chain_items = " &rarr; ".join(
            f'<span class="chain-phase phase-{p}">{context["phase_display_names"].get(p, p)}</span>'
            for p in context["phases_in_path"]
        )

        # Build steps HTML
        steps_html = ""
        for step in context["steps"]:
            tools_str = ", ".join(step["tools"]) if step["tools"] else "N/A"
            steps_html += f"""
            <div class="step">
                <div class="step-number">{step['step_number']}</div>
                <div class="step-content">
                    <span class="step-phase phase-{step['phase']}">{step['phase_display']}</span>
                    <h4>{step['technique_name']}</h4>
                    <p class="mitre-id">{step['mitre_id']}</p>
                    <p>{step['description']}</p>
                    <p><strong>Tools:</strong> {tools_str}</p>
                    <p><strong>Detection:</strong> {step['detection'] or 'N/A'}</p>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{context['title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        .meta {{ color: #888; margin-bottom: 20px; }}
        .chain-visualization {{ background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; font-size: 18px; }}
        .chain-phase {{ display: inline-block; padding: 8px 16px; border-radius: 4px; margin: 0 5px; }}
        .steps {{ margin-top: 30px; }}
        .step {{ display: flex; margin-bottom: 20px; background: #16213e; border-radius: 8px; overflow: hidden; }}
        .step-number {{ background: #00d4ff; color: #1a1a2e; font-size: 24px; font-weight: bold; padding: 20px; display: flex; align-items: center; justify-content: center; min-width: 60px; }}
        .step-content {{ padding: 15px 20px; flex: 1; }}
        .step-phase {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; text-transform: uppercase; margin-bottom: 10px; }}
        .step-content h4 {{ margin: 5px 0; color: #00d4ff; }}
        .step-content p {{ margin: 5px 0; font-size: 14px; }}
        .mitre-id {{ color: #888; font-family: monospace; }}
        .phase-reconnaissance {{ background: #0891b2; }}
        .phase-initial_access {{ background: #059669; }}
        .phase-execution {{ background: #d97706; }}
        .phase-persistence {{ background: #7c3aed; }}
        .phase-privilege_escalation {{ background: #dc2626; }}
        .phase-defense_evasion {{ background: #2563eb; }}
        .phase-credential_access {{ background: #be123c; }}
        .phase-discovery {{ background: #0e7490; }}
        .phase-lateral_movement {{ background: #ca8a04; }}
        .phase-collection {{ background: #9333ea; }}
        .phase-exfiltration {{ background: #1d4ed8; }}
        .phase-impact {{ background: #991b1b; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{context['title']}</h1>
        <p class="meta">Generated: {context['generated_at']} | Infrastructure: {context['infrastructure'].upper()} | Steps: {context['total_steps']}</p>

        <h2>Attack Chain</h2>
        <div class="chain-visualization">
            {chain_items}
        </div>

        <h2>Detailed Steps</h2>
        <div class="steps">
            {steps_html}
        </div>
    </div>
</body>
</html>"""
