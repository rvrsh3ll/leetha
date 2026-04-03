"""Service identity result from active probing.

ServiceIdentity represents what we learned about a service from an
active probe. It replaces the old ProbeResult with renamed fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServiceIdentity:
    """What we learned about a service from active probing."""

    service: str                           # e.g. "ssh", "http", "mysql"
    version: str | None = None             # e.g. "8.9p1", "1.24.0"
    banner: str | None = None              # raw banner text
    certainty: int = 0                     # 0-100
    metadata: dict = field(default_factory=dict)
    tls_detected: bool = False
