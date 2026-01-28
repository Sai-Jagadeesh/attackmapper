"""Attack path generation engine for AttackMapper."""

from typing import Optional
from collections import defaultdict

from .models import (
    AttackTechnique,
    AttackPath,
    AttackStep,
    AttackPhase,
    InfrastructureType,
)


class AttackPathEngine:
    """Engine for generating and analyzing attack paths."""

    # Risk level scores for calculating path risk
    RISK_SCORES = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self):
        self.techniques: dict[str, AttackTechnique] = {}
        self.techniques_by_phase: dict[AttackPhase, list[AttackTechnique]] = defaultdict(list)
        self.techniques_by_infra: dict[InfrastructureType, list[AttackTechnique]] = defaultdict(list)

    def load_techniques(self, techniques: list[AttackTechnique]):
        """Load techniques into the engine."""
        for tech in techniques:
            self.techniques[tech.id] = tech
            self.techniques_by_phase[tech.phase].append(tech)
            self.techniques_by_infra[tech.infrastructure].append(tech)

    def get_techniques_by_phase(
        self,
        phase: AttackPhase,
        infrastructure: Optional[InfrastructureType] = None,
    ) -> list[AttackTechnique]:
        """Get all techniques for a specific phase, optionally filtered by infrastructure."""
        techniques = self.techniques_by_phase.get(phase, [])
        if infrastructure:
            techniques = [t for t in techniques if t.infrastructure == infrastructure]
        return techniques

    def get_techniques_by_infrastructure(
        self, infrastructure: InfrastructureType
    ) -> list[AttackTechnique]:
        """Get all techniques for a specific infrastructure type."""
        return self.techniques_by_infra.get(infrastructure, [])

    def get_technique_by_id(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get a specific technique by its ID."""
        return self.techniques.get(technique_id)

    def get_techniques_by_mitre_id(self, mitre_id: str) -> list[AttackTechnique]:
        """Get techniques matching a MITRE ATT&CK ID."""
        return [t for t in self.techniques.values() if t.mitre_id == mitre_id]

    def search_techniques(
        self,
        query: str,
        infrastructure: Optional[InfrastructureType] = None,
    ) -> list[AttackTechnique]:
        """Search techniques by name or description."""
        query_lower = query.lower()
        results = []

        for tech in self.techniques.values():
            if infrastructure and tech.infrastructure != infrastructure:
                continue

            if (
                query_lower in tech.name.lower()
                or query_lower in tech.description.lower()
                or query_lower in tech.mitre_id.lower()
            ):
                results.append(tech)

        return results

    def generate_full_chain(
        self,
        infrastructure: InfrastructureType,
        start_phase: Optional[AttackPhase] = None,
        end_phase: Optional[AttackPhase] = None,
    ) -> AttackPath:
        """Generate a full attack chain from start to end phase."""
        # Default to full chain if not specified
        if start_phase is None:
            start_phase = AttackPhase.RECONNAISSANCE
        if end_phase is None:
            end_phase = AttackPhase.IMPACT

        # Get phases in order
        all_phases = AttackPhase.get_order()
        start_idx = all_phases.index(start_phase)
        end_idx = all_phases.index(end_phase)
        phases_to_include = all_phases[start_idx : end_idx + 1]

        # Build the attack path
        steps: list[AttackStep] = []
        step_number = 1

        for phase in phases_to_include:
            techniques = self.get_techniques_by_phase(phase, infrastructure)
            if not techniques:
                continue

            # Select representative technique(s) for this phase
            # For a full chain, we typically pick one technique per phase
            # Prioritize by risk level and connectivity
            selected = self._select_chain_technique(techniques, steps)
            if selected:
                step = AttackStep(
                    step_number=step_number,
                    technique=selected,
                    description=self._generate_step_description(selected, step_number),
                )
                steps.append(step)
                step_number += 1

        # Calculate total risk score
        total_risk = sum(
            self.RISK_SCORES.get(step.technique.risk_level, 2) for step in steps
        )

        return AttackPath(
            id=f"{infrastructure.value}-chain-{start_phase.value}-{end_phase.value}",
            name=f"Full Attack Chain - {infrastructure.value.upper()}",
            infrastructure=infrastructure,
            start_phase=start_phase,
            end_phase=end_phase,
            steps=steps,
            total_risk_score=total_risk,
        )

    def _select_chain_technique(
        self,
        techniques: list[AttackTechnique],
        existing_steps: list[AttackStep],
    ) -> Optional[AttackTechnique]:
        """Select the best technique to add to a chain."""
        if not techniques:
            return None

        # Score techniques based on:
        # 1. Connection to previous steps (if they enable this technique)
        # 2. Risk level (prefer higher risk for realistic paths)
        # 3. Number of next techniques (more connected = better)

        scored_techniques: list[tuple[AttackTechnique, int]] = []

        for tech in techniques:
            score = 0

            # Check if previous step enables this technique
            if existing_steps:
                last_tech = existing_steps[-1].technique
                if tech.id in last_tech.next_techniques:
                    score += 10

            # Risk level bonus
            score += self.RISK_SCORES.get(tech.risk_level, 2) * 2

            # Connectivity bonus
            score += len(tech.next_techniques)

            scored_techniques.append((tech, score))

        # Sort by score descending
        scored_techniques.sort(key=lambda x: x[1], reverse=True)

        return scored_techniques[0][0] if scored_techniques else None

    def _generate_step_description(
        self, technique: AttackTechnique, step_number: int
    ) -> str:
        """Generate a contextual description for an attack step."""
        # Use the technique's description but can be customized
        return technique.description

    def find_paths_to_goal(
        self,
        infrastructure: InfrastructureType,
        goal_technique_id: str,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        """Find attack paths that lead to a specific goal technique."""
        goal = self.get_technique_by_id(goal_technique_id)
        if not goal:
            return []

        paths: list[AttackPath] = []

        # BFS to find paths leading to the goal
        # This is a simplified version - could be enhanced with proper graph algorithms
        techniques = self.get_techniques_by_infrastructure(infrastructure)

        # Build reverse adjacency (what techniques lead to this one)
        reverse_graph: dict[str, list[str]] = defaultdict(list)
        for tech in techniques:
            for next_id in tech.next_techniques:
                reverse_graph[next_id].append(tech.id)

        # Find all techniques that lead to the goal
        def build_path(
            current_id: str, path: list[str], depth: int
        ) -> list[list[str]]:
            if depth > max_depth:
                return []

            predecessors = reverse_graph.get(current_id, [])
            if not predecessors:
                # This is a starting point
                return [path]

            all_paths = []
            for pred_id in predecessors:
                if pred_id not in path:  # Avoid cycles
                    new_paths = build_path(pred_id, [pred_id] + path, depth + 1)
                    all_paths.extend(new_paths)

            return all_paths

        # Find paths ending at the goal
        raw_paths = build_path(goal_technique_id, [goal_technique_id], 0)

        # Convert to AttackPath objects
        for i, raw_path in enumerate(raw_paths[:5]):  # Limit to 5 paths
            steps = []
            for j, tech_id in enumerate(raw_path):
                tech = self.get_technique_by_id(tech_id)
                if tech:
                    steps.append(
                        AttackStep(
                            step_number=j + 1,
                            technique=tech,
                            description=tech.description,
                        )
                    )

            if steps:
                total_risk = sum(
                    self.RISK_SCORES.get(s.technique.risk_level, 2) for s in steps
                )
                paths.append(
                    AttackPath(
                        id=f"path-to-{goal_technique_id}-{i}",
                        name=f"Path to {goal.name}",
                        infrastructure=infrastructure,
                        start_phase=steps[0].technique.phase,
                        end_phase=steps[-1].technique.phase,
                        steps=steps,
                        total_risk_score=total_risk,
                    )
                )

        return paths

    def get_prerequisites_chain(
        self, technique_id: str
    ) -> list[AttackTechnique]:
        """Get the chain of techniques needed as prerequisites."""
        technique = self.get_technique_by_id(technique_id)
        if not technique:
            return []

        # Find techniques that list this one in their next_techniques
        prerequisites = []
        for tech in self.techniques.values():
            if technique_id in tech.next_techniques:
                prerequisites.append(tech)

        # Sort by phase order
        phase_order = {p: i for i, p in enumerate(AttackPhase.get_order())}
        prerequisites.sort(key=lambda t: phase_order.get(t.phase, 99))

        return prerequisites

    def calculate_path_risk(self, path: AttackPath) -> dict:
        """Calculate detailed risk metrics for an attack path."""
        if not path.steps:
            return {"total_score": 0, "average_risk": 0, "max_risk": "none"}

        scores = [
            self.RISK_SCORES.get(step.technique.risk_level, 2)
            for step in path.steps
        ]

        max_risk_level = max(
            path.steps, key=lambda s: self.RISK_SCORES.get(s.technique.risk_level, 0)
        ).technique.risk_level

        return {
            "total_score": sum(scores),
            "average_risk": sum(scores) / len(scores),
            "max_risk": max_risk_level,
            "step_count": len(path.steps),
            "phases_covered": len(set(s.technique.phase for s in path.steps)),
        }
