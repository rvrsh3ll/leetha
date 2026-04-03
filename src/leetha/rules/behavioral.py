"""Behavioral drift detection rule.

Fires when a host's DNS vendor affinity shifts dramatically.
"""
from __future__ import annotations

from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict
from leetha.processors.behavioral import DnsBehaviorTracker

_shared_tracker = DnsBehaviorTracker()


@register_rule("behavioral_drift")
class BehavioralDriftRule(RuleBase):
    """Detect DNS vendor affinity drift per host."""
    severity = "high"

    def __init__(self):
        self._tracker = _shared_tracker

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        drift = self._tracker.check_drift(host.hw_addr)
        if drift is None:
            return None

        return Finding(
            hw_addr=host.hw_addr,
            rule=FindingRule.BEHAVIORAL_DRIFT,
            severity=AlertSeverity.HIGH,
            message=(
                f"DNS behavioral drift on {host.hw_addr}: "
                f"profile shifted from {drift['from_vendor']} ({drift['from_pct']}%) "
                f"to {drift['to_vendor']} ({drift['to_pct']}%) "
                f"over {drift['observation_minutes']} minutes"
            ),
        )
