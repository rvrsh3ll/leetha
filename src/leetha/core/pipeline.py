"""Packet processing pipeline.

Receives CapturedPackets from the capture engine, routes them through
registered processors, computes verdicts, stores results, and evaluates
finding rules. Designed for concurrent execution.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime

from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence, Verdict
from leetha.evidence.engine import VerdictEngine
from leetha.processors.registry import get_processor, get_all_processors
from leetha.rules.registry import get_all_rules
from leetha.store.models import Host, Sighting

logger = logging.getLogger(__name__)


class Pipeline:
    """Main packet processing pipeline.

    Flow: CapturedPacket -> Processors -> Evidence -> VerdictEngine ->
          Store (batch) -> FindingRules -> Findings
    """

    def __init__(self, store, verdict_engine: VerdictEngine | None = None,
                 on_verdict=None, on_arp=None, on_dhcp=None, on_gateway_hint=None):
        self.store = store
        self.verdict_engine = verdict_engine or VerdictEngine()
        self._on_verdict = on_verdict          # async(hw_addr, verdict, packet)
        self._on_arp = on_arp                  # async(packet)
        self._on_dhcp = on_dhcp                # callable(packet) -- sync fire-and-forget
        self._on_gateway_hint = on_gateway_hint  # async(mac, ip, source, interface)
        self._evidence_buffer: dict[str, list[Evidence]] = defaultdict(list)
        self._batch_queue: list = []
        self._processor_instances: dict[str, object] = {}
        self._rule_instances: list = []
        self._running = False

        # Instantiate all registered processors
        for proto, cls in get_all_processors().items():
            if cls not in [type(p) for p in self._processor_instances.values()]:
                instance = cls()
                self._processor_instances[proto] = instance
            else:
                # Reuse existing instance for same class (multi-protocol processors)
                for existing in self._processor_instances.values():
                    if isinstance(existing, cls):
                        self._processor_instances[proto] = existing
                        break

        # Instantiate all registered rules
        for name, cls in get_all_rules().items():
            self._rule_instances.append(cls())

    async def process(self, packet: CapturedPacket) -> None:
        """Process a single captured packet through the full pipeline."""
        protocol = packet.protocol

        # Side effects: fire before main processing
        if packet.protocol == "arp" and self._on_arp:
            try:
                await self._on_arp(packet)
            except Exception:
                logger.debug("ARP side effect failed", exc_info=True)

        if packet.protocol == "dhcpv4" and self._on_dhcp:
            try:
                self._on_dhcp(packet)
            except Exception:
                logger.debug("DHCP side effect failed", exc_info=True)

        # Gateway learning from DHCP OFFER/ACK or ICMPv6 RA
        if self._on_gateway_hint:
            if packet.protocol == "dhcpv4":
                raw_opts = packet.fields.get("raw_options", {})
                msg_type = raw_opts.get("message-type")
                if msg_type in (2, 5) and packet.ip_addr:
                    try:
                        await self._on_gateway_hint(
                            packet.hw_addr, packet.ip_addr, "dhcp_server",
                            packet.interface or "")
                    except Exception:
                        pass
            elif packet.protocol == "icmpv6":
                if packet.fields.get("icmpv6_type") == "router_advertisement" and packet.ip_addr:
                    try:
                        await self._on_gateway_hint(
                            packet.hw_addr, packet.ip_addr, "auto_gateway",
                            packet.interface or "")
                    except Exception:
                        pass

        # 1. Find and run the registered processor
        processor = self._processor_instances.get(protocol)
        if processor is None:
            logger.debug("No processor for protocol: %s", protocol)
            return

        try:
            evidence_list = processor.analyze(packet)
        except Exception:
            logger.debug("Processor failed for %s", protocol, exc_info=True)
            return

        if not evidence_list:
            return

        hw_addr = packet.hw_addr

        # 2. Record sighting
        sighting = Sighting(
            hw_addr=hw_addr,
            source=protocol,
            payload=packet.fields,
            analysis={"evidence_count": len(evidence_list)},
            certainty=max((e.certainty for e in evidence_list), default=0.0),
            interface=packet.interface,
            network=packet.network,
        )
        await self.store.sightings.record(sighting)

        # 3. Accumulate evidence and compute verdict
        self._evidence_buffer[hw_addr].extend(evidence_list)
        verdict = self.verdict_engine.compute(hw_addr, self._evidence_buffer[hw_addr])

        # 4. Upsert host
        host = Host(
            hw_addr=hw_addr,
            ip_addr=packet.ip_addr if packet.ip_addr and packet.ip_addr != "0.0.0.0" else None,
            last_active=datetime.now(),
        )
        await self.store.hosts.upsert(host)

        # 5. Store verdict
        await self.store.verdicts.upsert(verdict)

        if self._on_verdict:
            try:
                await self._on_verdict(hw_addr, verdict, packet)
            except Exception:
                logger.debug("Verdict callback failed", exc_info=True)

        # 6. Evaluate finding rules
        for rule in self._rule_instances:
            try:
                finding = await rule.evaluate(host, verdict, self.store)
                if finding:
                    await self.store.findings.add(finding)
            except Exception:
                logger.debug("Rule %s failed", type(rule).__name__, exc_info=True)

    async def process_batch(self, packets: list[CapturedPacket]) -> None:
        """Process multiple packets. Can be parallelized in future."""
        for packet in packets:
            await self.process(packet)
