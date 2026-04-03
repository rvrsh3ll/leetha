"""MAC randomization detection rules."""
from __future__ import annotations
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

@register_rule("randomized_addr")
class RandomizedAddrRule(RuleBase):
    severity = "info"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if host.mac_randomized:
            msg = f"Randomized MAC detected: {host.hw_addr}"
            if host.real_hw_addr:
                msg += f" (real: {host.real_hw_addr})"
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.RANDOMIZED_ADDR,
                severity=AlertSeverity.INFO,
                message=msg,
            )
        return None
