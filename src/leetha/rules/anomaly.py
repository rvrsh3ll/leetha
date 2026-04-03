"""Anomaly detection rules."""
from __future__ import annotations
import time
from pathlib import Path
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

@register_rule("dhcp_anomaly")
class DhcpAnomalyRule(RuleBase):
    severity = "warning"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # DHCP anomalies are detected by the analysis module and fed in directly
        # This rule is a placeholder for the bridge
        return None

@register_rule("stale_source")
class StaleSourceRule(RuleBase):
    severity = "warning"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # Stale source detection runs on a timer, not per-host
        # This is handled by the periodic check in the app layer
        return None
