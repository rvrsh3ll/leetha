"""Base class for finding rules."""
from __future__ import annotations
from abc import ABC, abstractmethod
from leetha.store.models import Host, Finding, AlertSeverity
from leetha.evidence.models import Verdict

class FindingRule(ABC):
    """Abstract base for rules that evaluate hosts and produce findings."""
    severity: str = "info"

    @abstractmethod
    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        """Evaluate a host and return a Finding if the rule triggers."""
        ...
