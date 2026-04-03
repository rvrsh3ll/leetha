"""Active probe processor -- converts probe results into pipeline evidence."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


@register_processor("probe")
class ActiveProbeProcessor(Processor):
    """Handles active probe results.

    Probe results arrive as CapturedPackets with pre-extracted fields.
    This processor normalizes them into Evidence for the fusion pipeline.
    """

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        evidence = []
        probe_type = packet.get("probe_type", "unknown")
        result = packet.get("result", {})
        certainty = packet.get("certainty", 0.70)

        # Extract common fields from probe results
        vendor = result.get("vendor") if isinstance(result, dict) else None
        platform = result.get("platform") if isinstance(result, dict) else None
        platform_version = result.get("platform_version") if isinstance(result, dict) else None
        model = result.get("model") if isinstance(result, dict) else None
        hostname = result.get("hostname") if isinstance(result, dict) else None
        category = result.get("category") if isinstance(result, dict) else None

        evidence.append(Evidence(
            source=f"probe_{probe_type}", method="exact", certainty=certainty,
            vendor=vendor,
            platform=platform,
            platform_version=platform_version,
            model=model,
            hostname=hostname,
            category=category,
            raw={"probe_type": probe_type, "result": result},
        ))

        return evidence
