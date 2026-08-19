"""Simulation Scenario Registry and Discovery."""

import threading
from typing import Dict, List, Optional
from src.core.logging import get_logger
from src.detection.models import MitreTactic
from src.simulation.models import BaseScenario
from src.simulation.scenarios import get_all_scenarios

logger = get_logger("simulation.registry")


class ScenarioRegistry:
    """Thread-safe registry for attack simulation and benign control scenarios."""

    def __init__(self, scenarios: Optional[List[BaseScenario]] = None):
        self._scenarios: Dict[str, BaseScenario] = {}
        self._lock = threading.Lock()

        initial_scenarios = scenarios if scenarios is not None else get_all_scenarios()
        for scenario in initial_scenarios:
            self.register_scenario(scenario)

    def register_scenario(self, scenario: BaseScenario) -> None:
        """Register or update a scenario."""
        with self._lock:
            self._scenarios[scenario.id] = scenario
            logger.debug(f"Registered scenario: [{scenario.id}] {scenario.name}")

    def get_scenario(self, scenario_id: str) -> Optional[BaseScenario]:
        """Retrieve a scenario by ID."""
        with self._lock:
            return self._scenarios.get(scenario_id)

    def list_scenarios(
        self,
        tactic: Optional[MitreTactic] = None,
        is_benign: Optional[bool] = None,
        target: Optional[str] = None,
    ) -> List[BaseScenario]:
        """List scenarios matching optional filters."""
        with self._lock:
            results = list(self._scenarios.values())

        if tactic is not None:
            results = [s for s in results if s.mitre_attack.tactic == tactic]

        if is_benign is not None:
            results = [s for s in results if s.is_benign == is_benign]

        if target is not None:
            results = [s for s in results if target.lower() in s.lab_target.lower()]

        return results

    def count(self) -> int:
        """Return total number of registered scenarios."""
        with self._lock:
            return len(self._scenarios)

    def count_by_tactic(self) -> Dict[str, int]:
        """Summarize scenario counts grouped by MITRE ATT&CK tactic."""
        with self._lock:
            counts: Dict[str, int] = {}
            for s in self._scenarios.values():
                if not s.is_benign:
                    t = s.mitre_attack.tactic.value
                    counts[t] = counts.get(t, 0) + 1
            return counts
