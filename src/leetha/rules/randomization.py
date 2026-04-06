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
            hw_addr = host.hw_addr
            # Deduplicate: skip if an unresolved finding already exists for this MAC+rule
            cursor = await store.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (hw_addr, "randomized_addr"),
            )
            existing = (await cursor.fetchone())[0]
            if existing > 0:
                return None
            msg = f"Randomized MAC detected: {hw_addr}"
            if host.real_hw_addr:
                msg += f" (real: {host.real_hw_addr})"
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.RANDOMIZED_ADDR,
                severity=AlertSeverity.INFO,
                message=msg,
            )
        return None
