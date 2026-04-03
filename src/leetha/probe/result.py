"""Legacy probe result container.

Retained for backward compatibility. New code should use
:class:`leetha.probe.identity.ServiceIdentity` instead.

.. deprecated::
    Use :class:`leetha.probe.identity.ServiceIdentity` instead.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    """Result from a legacy probe plugin.

    Maps to :class:`~leetha.probe.identity.ServiceIdentity` via
    :meth:`~leetha.probe.scheduler.ProbeScheduler.result_to_match`.
    """

    service: str = ""
    version: str | None = None
    banner: str | None = None
    confidence: int = 0
    metadata: dict = field(default_factory=dict)
    tls: bool = False

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary."""
        return {
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "tls": self.tls,
        }
