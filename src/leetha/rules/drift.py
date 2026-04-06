"""Drift detection rules — unexpected identity and address changes."""
from __future__ import annotations

import time
from datetime import datetime
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_MIN_CERTAINTY = 50
_MIN_EVIDENCE_COUNT = 3
_GRACE_PERIOD_SECONDS = 60
_COOLDOWN_SECONDS = 300

_last_fired: dict[str, float] = {}


@register_rule("identity_shift")
class IdentityShiftRule(RuleBase):
    """Detect when a host's fingerprint class changes unexpectedly."""
    severity = "critical"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        existing = await store.verdicts.find_by_addr(host.hw_addr)
        if existing is None:
            return None

        if existing.certainty < _MIN_CERTAINTY or verdict.certainty < _MIN_CERTAINTY:
            return None

        if len(existing.evidence_chain) < _MIN_EVIDENCE_COUNT:
            return None

        age = (datetime.now() - host.discovered_at).total_seconds()
        if age < _GRACE_PERIOD_SECONDS:
            return None

        now = time.monotonic()
        last = _last_fired.get(host.hw_addr, 0)
        if now - last < _COOLDOWN_SECONDS:
            return None

        cat_changed = (existing.category and verdict.category
                       and existing.category != verdict.category)
        vendor_changed = (existing.vendor and verdict.vendor
                          and existing.vendor != verdict.vendor)
        platform_changed = (existing.platform and verdict.platform
                            and existing.platform != verdict.platform)
        version_changed = (existing.platform_version and verdict.platform_version
                           and existing.platform_version != verdict.platform_version)

        if not (cat_changed or vendor_changed or platform_changed or version_changed):
            return None

        if cat_changed or vendor_changed:
            severity = AlertSeverity.CRITICAL
            parts = []
            if cat_changed:
                parts.append(f"category: {existing.category} \u2192 {verdict.category}")
            if vendor_changed:
                parts.append(f"vendor: {existing.vendor} \u2192 {verdict.vendor}")
            if platform_changed:
                parts.append(f"platform: {existing.platform} \u2192 {verdict.platform}")
            detail = ", ".join(parts)
            message = f"Identity shift on {host.hw_addr}: {detail}"
        elif platform_changed:
            severity = AlertSeverity.HIGH
            message = (f"Platform changed on {host.hw_addr}: "
                       f"{existing.platform} \u2192 {verdict.platform}")
        else:
            severity = AlertSeverity.INFO
            message = (f"Platform version changed on {host.hw_addr}: "
                       f"{existing.platform_version} \u2192 {verdict.platform_version}")

        _last_fired[host.hw_addr] = now

        return Finding(
            hw_addr=host.hw_addr,
            rule=FindingRule.IDENTITY_SHIFT,
            severity=severity,
            message=message,
        )


@register_rule("addr_conflict")
class AddrConflictRule(RuleBase):
    """Detect multiple MACs claiming the same IP address."""
    severity = "high"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if not host.ip_addr:
            return None
        # Targeted query instead of full table scan
        cursor = await store.connection.execute(
            "SELECT hw_addr FROM hosts WHERE ip_addr = ? AND hw_addr != ?",
            (host.ip_addr, host.hw_addr),
        )
        conflicts = await cursor.fetchall()
        if conflicts:
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.ADDR_CONFLICT,
                severity=AlertSeverity.HIGH,
                message=f"Address conflict: {host.ip_addr} claimed by "
                        f"{host.hw_addr} and {conflicts[0][0]}",
            )
        return None
