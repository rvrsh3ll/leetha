"""Discovery-related finding rules."""
from __future__ import annotations
from datetime import datetime, timedelta
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_LOW_CERT_LAST_FIRED: dict[str, datetime] = {}
_LOW_CERT_COOLDOWN = timedelta(hours=1)

@register_rule("new_host")
class NewHostRule(RuleBase):
    severity = "info"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # Only fire on truly new hosts (disposition still "new").
        # The pipeline transitions disposition to "known" after rules run,
        # so this will only fire once per host.
        if host.disposition == "new":
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO,
                message=f"New host discovered: {host.hw_addr}"
                        + (f" ({verdict.vendor})" if verdict.vendor else ""),
            )
        return None

@register_rule("low_certainty")
class LowCertaintyRule(RuleBase):
    severity = "low"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if verdict.certainty < 50 and host.disposition == "known":
            hw_addr = host.hw_addr
            last = _LOW_CERT_LAST_FIRED.get(hw_addr)
            if last and (datetime.now() - last) < _LOW_CERT_COOLDOWN:
                return None
            _LOW_CERT_LAST_FIRED[hw_addr] = datetime.now()
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.LOW_CERTAINTY,
                severity=AlertSeverity.LOW,
                message=f"Host {hw_addr} has low identification certainty ({verdict.certainty}%)",
            )
        return None
