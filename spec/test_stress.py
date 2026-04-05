"""Stress tests for reliability under load.

Exercises the pipeline, store, verdict engine, capture engine, and pattern
loader under high-volume and concurrent scenarios to verify correctness,
absence of crashes, and reasonable performance.
"""
import pytest
import asyncio
import time
import random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from unittest.mock import MagicMock

from leetha.core.pipeline import Pipeline
from leetha.capture.packets import CapturedPacket
from leetha.capture.engine import PacketCapture
from leetha.capture.interfaces import InterfaceConfig
from leetha.evidence.engine import VerdictEngine
from leetha.evidence.models import Evidence, Verdict
from leetha.store.store import Store
from leetha.store.models import (
    Host, Finding, Sighting, FindingRule, AlertSeverity,
)
from leetha.patterns import loader as pattern_loader


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def pipeline():
    store = Store(":memory:")
    await store.initialize()
    # Import processors and rules to register them
    import leetha.processors.network
    import leetha.processors.services
    import leetha.processors.names
    import leetha.processors.infrastructure
    import leetha.processors.iot_scada
    import leetha.processors.passive
    import leetha.processors.active
    import importlib
    import leetha.rules.discovery
    import leetha.rules.drift
    import leetha.rules.anomaly
    import leetha.rules.randomization
    importlib.reload(leetha.rules.discovery)
    importlib.reload(leetha.rules.drift)
    importlib.reload(leetha.rules.anomaly)
    importlib.reload(leetha.rules.randomization)
    p = Pipeline(store=store)
    yield p
    await store.close()


@pytest.fixture
async def store():
    s = Store(":memory:")
    await s.initialize()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mac(index: int) -> str:
    """Generate a deterministic MAC address from an integer index."""
    b = index.to_bytes(3, "big")
    return f"aa:bb:cc:{b[0]:02x}:{b[1]:02x}:{b[2]:02x}"


def _ip(index: int) -> str:
    """Generate a deterministic IPv4 address from an integer index."""
    return f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"


# All registered protocol names that processors handle.
ALL_PROTOCOLS = [
    "arp", "dhcpv4", "dhcpv6", "icmpv6",
    "tcp_syn", "tls", "http_useragent",
    "dns", "dns_answer", "mdns", "netbios", "ssdp",
    "lldp", "cdp", "stp", "snmp",
    "modbus", "bacnet", "coap", "mqtt", "enip",
    "ip_observed", "probe",
]

# Minimal fields that let each processor produce at least one Evidence item.
PROTOCOL_FIELDS = {
    "arp":            {"op": 1},
    "dhcpv4":         {"hostname": "host", "opt55": "1,3,6,15"},
    "dhcpv6":         {"vendor_class": "Linux"},
    "icmpv6":         {"type": 134, "prefix": "2001:db8::/64"},
    "tcp_syn":        {"dport": 443, "sport": 12345, "ttl": 64,
                       "window_size": 65535, "mss": 1460,
                       "tcp_options": "mss1460,nop,wscale8"},
    "tls":            {"sni": "example.com", "ja3_hash": "abc123",
                       "cipher_suites": "0x1301,0x1302"},
    "http_useragent": {"user_agent": "Mozilla/5.0 (Windows NT 10.0)"},
    "dns":            {"qname": "example.com", "qtype": "A"},
    "dns_answer":     {"qname": "example.com", "answers": ["93.184.216.34"]},
    "mdns":           {"name": "_http._tcp.local.", "ptr": "myhost._http._tcp.local."},
    "netbios":        {"name": "WORKSTATION"},
    "ssdp":           {"server": "Linux/3.0 UPnP/1.0", "usn": "uuid:abc",
                       "st": "upnp:rootdevice"},
    "lldp":           {"system_name": "switch01",
                       "system_description": "Cisco IOS",
                       "port_description": "GigE0/1"},
    "cdp":            {"device_id": "router01", "platform": "cisco WS-C3560",
                       "port_id": "Fa0/1"},
    "stp":            {"bridge_id": "8000.aabbccddeeff", "root_id": "0001.aabbccddeeff"},
    "snmp":           {"community": "public", "sys_descr": "Linux router"},
    "modbus":         {"unit_id": 1, "function_code": 3},
    "bacnet":         {"object_name": "AHU-1", "vendor_name": "Honeywell"},
    "coap":           {"uri_path": "/.well-known/core", "content_format": "text/plain"},
    "mqtt":           {"client_id": "sensor-01", "topic": "home/temp"},
    "enip":           {"product_name": "1769-L33ER", "vendor": "Rockwell"},
    "ip_observed":    {"ttl": 128, "port": 443},
    "probe":          {"service": "http", "banner": "Apache/2.4",
                       "port": 80, "state": "open"},
}


# =========================================================================
# 1. Large Dataset Tests
# =========================================================================

class TestLargeDatasets:
    """Pipeline and store behaviour under high packet volumes."""

    @pytest.mark.asyncio
    async def test_1000_packets_100_hosts(self, pipeline):
        """Process 1000 ARP packets spread across 100 distinct hosts.

        Verify the pipeline does not crash, every host is stored, and the
        host count matches exactly.
        """
        for i in range(1000):
            host_idx = i % 100
            pkt = CapturedPacket(
                protocol="arp",
                hw_addr=_mac(host_idx),
                ip_addr=_ip(host_idx),
                fields={"op": 1},
            )
            await pipeline.process(pkt)

        count = await pipeline.store.hosts.count()
        assert count == 100, f"Expected 100 hosts, got {count}"

        # Spot-check a few hosts exist
        for idx in [0, 49, 99]:
            host = await pipeline.store.hosts.find_by_addr(_mac(idx))
            assert host is not None, f"Host {_mac(idx)} not found"

    @pytest.mark.asyncio
    async def test_many_packets_same_host(self, pipeline):
        """Feed 2000 packets from the same MAC address.

        Evidence must accumulate correctly, the verdict must remain valid,
        and the evidence buffer must not grow unboundedly (sanity check).
        The count is capped at 2000 because each iteration serialises the
        full evidence chain into SQLite, so very large counts hit I/O limits.
        """
        mac = "de:ad:be:ef:00:01"
        for i in range(2_000):
            pkt = CapturedPacket(
                protocol="arp",
                hw_addr=mac,
                ip_addr="192.168.1.1",
                fields={"op": 1},
            )
            await pipeline.process(pkt)

        # Still only one host
        assert await pipeline.store.hosts.count() == 1

        # Verdict exists and has a valid certainty score
        verdict = await pipeline.store.verdicts.find_by_addr(mac)
        assert verdict is not None
        assert 0 <= verdict.certainty <= 100

        # Evidence buffer is capped (not unbounded) and did not crash
        assert len(pipeline._evidence_buffer[mac]) <= 100  # capped by cap_evidence

    @pytest.mark.asyncio
    async def test_burst_500_packets_timing(self, pipeline):
        """Burst 500 packets and verify processing completes in < 5 seconds."""
        packets = [
            CapturedPacket(
                protocol="arp",
                hw_addr=_mac(i % 50),
                ip_addr=_ip(i % 50),
                fields={"op": 1},
            )
            for i in range(500)
        ]

        start = time.monotonic()
        await pipeline.process_batch(packets)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"Burst of 500 packets took {elapsed:.2f}s (limit: 5s)"
        assert await pipeline.store.hosts.count() == 50

    @pytest.mark.asyncio
    async def test_all_protocols_mixed(self, pipeline):
        """Generate packets for every registered protocol and verify each is handled.

        Uses protocol-specific field templates so each processor can
        produce at least one Evidence object.
        """
        processed_protocols = set()

        for i, proto in enumerate(ALL_PROTOCOLS):
            pkt = CapturedPacket(
                protocol=proto,
                hw_addr=_mac(i),
                ip_addr=_ip(i),
                fields=dict(PROTOCOL_FIELDS.get(proto, {})),
            )
            await pipeline.process(pkt)

            # If a host was stored, the processor ran successfully
            host = await pipeline.store.hosts.find_by_addr(_mac(i))
            if host is not None:
                processed_protocols.add(proto)

        # At minimum the core protocols must process without error
        core_expected = {"arp", "dhcpv4", "tcp_syn", "lldp", "ip_observed"}
        missing = core_expected - processed_protocols
        assert not missing, f"Core protocols not processed: {missing}"

        # Overall: the majority of protocols should produce a host entry
        assert len(processed_protocols) >= len(ALL_PROTOCOLS) * 0.5, (
            f"Only {len(processed_protocols)}/{len(ALL_PROTOCOLS)} protocols "
            f"produced host entries"
        )


# =========================================================================
# 2. Store Reliability Tests
# =========================================================================

class TestStoreReliability:
    """SQLite store under concurrent and high-volume operations."""

    @pytest.mark.asyncio
    async def test_concurrent_upserts_same_host(self, store):
        """Run 100 upserts to the same hw_addr concurrently.

        Verify no SQLite locking errors and exactly one host remains.
        """
        mac = "cc:cc:cc:cc:cc:01"

        async def do_upsert(idx: int):
            host = Host(
                hw_addr=mac,
                ip_addr=f"10.0.0.{idx % 256}",
                last_active=datetime.now(),
            )
            await store.hosts.upsert(host)

        # Run all 100 upserts as concurrent tasks
        tasks = [asyncio.create_task(do_upsert(i)) for i in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check that no exceptions were raised
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Upsert errors: {errors}"

        # Exactly one host should exist
        count = await store.hosts.count()
        assert count == 1

        host = await store.hosts.find_by_addr(mac)
        assert host is not None

    @pytest.mark.asyncio
    async def test_large_finding_volume(self, store):
        """Generate 1000 findings, verify list_active and resolve work."""
        for i in range(1000):
            finding = Finding(
                hw_addr=_mac(i % 100),
                rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO,
                message=f"Test finding {i}",
            )
            await store.findings.add(finding)

        active_count = await store.findings.count_active()
        assert active_count == 1000

        # list_active with default limit returns up to 100
        active = await store.findings.list_active(limit=100)
        assert len(active) == 100

        # list_active with large limit returns all
        all_active = await store.findings.list_active(limit=2000)
        assert len(all_active) == 1000

        # Resolve the first finding and verify count decreases
        await store.findings.resolve(all_active[0].id)
        assert await store.findings.count_active() == 999

    @pytest.mark.asyncio
    async def test_store_10000_hosts(self, store):
        """Insert 10 000 hosts, verify count and find_by_addr performance."""
        for i in range(10_000):
            host = Host(
                hw_addr=_mac(i),
                ip_addr=_ip(i),
                last_active=datetime.now(),
            )
            await store.hosts.upsert(host)

        count = await store.hosts.count()
        assert count == 10_000

        # Lookup by address should still be fast (index on primary key)
        start = time.monotonic()
        for probe_idx in random.sample(range(10_000), 100):
            found = await store.hosts.find_by_addr(_mac(probe_idx))
            assert found is not None
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"100 random lookups in 10k-host store took {elapsed:.2f}s"
        )

    @pytest.mark.asyncio
    async def test_sighting_storage_volume(self, store):
        """Record 5000 sightings, verify for_host returns correct subset."""
        target_mac = "ff:ff:ff:00:00:01"
        other_mac = "ff:ff:ff:00:00:02"

        for i in range(5000):
            mac = target_mac if i % 5 == 0 else other_mac
            sighting = Sighting(
                hw_addr=mac,
                source="arp",
                payload={"op": 1},
                certainty=0.5,
            )
            await store.sightings.record(sighting)

        # target_mac should have 1000 sightings (every 5th)
        target_sightings = await store.sightings.for_host(target_mac, limit=2000)
        assert len(target_sightings) == 1000

        # other_mac should have 4000 sightings
        other_sightings = await store.sightings.for_host(other_mac, limit=5000)
        assert len(other_sightings) == 4000


# =========================================================================
# 3. VerdictEngine Stress Tests
# =========================================================================

class TestVerdictEngineStress:
    """VerdictEngine correctness under adversarial and high-volume inputs."""

    def test_verdict_from_100_evidence_items(self):
        """Compute a verdict from 100 diverse evidence items without crashing."""
        engine = VerdictEngine()
        evidence = []
        sources = ["lldp", "dhcpv4", "tcp_syn", "arp", "ssdp", "mdns"]
        for i in range(100):
            src = sources[i % len(sources)]
            evidence.append(Evidence(
                source=src,
                method="pattern",
                certainty=0.5 + (i % 5) * 0.1,
                vendor=f"Vendor-{i % 10}",
                category="network" if i % 2 == 0 else "endpoint",
                platform=f"OS-{i % 5}",
            ))

        verdict = engine.compute("aa:bb:cc:00:00:01", evidence)

        assert verdict is not None
        assert verdict.hw_addr == "aa:bb:cc:00:00:01"
        assert 0 <= verdict.certainty <= 100
        assert verdict.vendor is not None
        assert verdict.category is not None

    def test_conflicting_evidence_deterministic(self):
        """50 items say 'Cisco' and 50 say 'Juniper' -- verify deterministic winner."""
        engine = VerdictEngine()
        evidence = []

        # 50 high-certainty evidence items for Cisco from reliable sources
        for i in range(50):
            evidence.append(Evidence(
                source="lldp",
                method="exact",
                certainty=0.9,
                vendor="Cisco",
                category="network",
            ))

        # 50 lower-certainty evidence items for Juniper from less reliable sources
        for i in range(50):
            evidence.append(Evidence(
                source="ssdp",
                method="heuristic",
                certainty=0.6,
                vendor="Juniper",
                category="network",
            ))

        verdict = engine.compute("aa:bb:cc:00:00:02", evidence)
        assert verdict.vendor is not None

        # Cisco should win: higher certainty * higher source weight
        assert verdict.vendor == "Cisco"

        # Run again to verify determinism
        verdict2 = engine.compute("aa:bb:cc:00:00:02", evidence)
        assert verdict2.vendor == verdict.vendor
        assert verdict2.certainty == verdict.certainty

    def test_conflicting_evidence_equal_weight(self):
        """Equal evidence for two vendors -- result must still be deterministic."""
        engine = VerdictEngine()
        evidence = []

        for i in range(50):
            evidence.append(Evidence(
                source="lldp",
                method="exact",
                certainty=0.8,
                vendor="Cisco",
                category="network",
            ))

        for i in range(50):
            evidence.append(Evidence(
                source="lldp",
                method="exact",
                certainty=0.8,
                vendor="Juniper",
                category="network",
            ))

        # Must not crash and must produce a valid verdict
        verdict = engine.compute("aa:bb:cc:00:00:03", evidence)
        assert verdict.vendor in ("Cisco", "Juniper")

        # Determinism: re-running gives same result
        verdict2 = engine.compute("aa:bb:cc:00:00:03", evidence)
        assert verdict2.vendor == verdict.vendor

    def test_evidence_with_all_none_fields(self):
        """100 evidence items with only source/method/certainty, no device info.

        Verify the engine does not crash and returns a valid (empty) verdict.
        """
        engine = VerdictEngine()
        evidence = [
            Evidence(source="arp", method="heuristic", certainty=0.3)
            for _ in range(100)
        ]

        verdict = engine.compute("aa:bb:cc:00:00:04", evidence)

        assert verdict is not None
        assert verdict.hw_addr == "aa:bb:cc:00:00:04"
        assert 0 <= verdict.certainty <= 100
        # No device information was provided, so fields should be None
        assert verdict.vendor is None
        assert verdict.platform is None
        assert verdict.model is None

    def test_verdict_update_incremental(self):
        """Incrementally update a verdict many times and verify stability."""
        engine = VerdictEngine()

        initial_evidence = [
            Evidence(source="arp", method="heuristic", certainty=0.3,
                     vendor="Unknown"),
        ]
        verdict = engine.compute("aa:bb:cc:00:00:05", initial_evidence)

        # Incrementally add 200 evidence items
        for i in range(200):
            new_ev = [Evidence(
                source="dhcpv4",
                method="pattern",
                certainty=0.7,
                vendor="Dell",
                category="endpoint",
            )]
            verdict = engine.update(verdict, new_ev)

        assert verdict is not None
        assert verdict.vendor == "Dell"
        # Evidence is capped at max_per_source=20 by cap_evidence(), so
        # only the 20 most recent dhcpv4 items + 1 arp item are retained.
        assert len(verdict.evidence_chain) <= 200


# =========================================================================
# 4. Multi-Interface Simulation
# =========================================================================

class TestMultiInterface:
    """PacketCapture interface management without live capture."""

    def test_multiple_interface_configs(self):
        """Create a PacketCapture with 5 interface configs and verify tracking."""
        configs = [
            InterfaceConfig(name=f"eth{i}") for i in range(5)
        ]
        capture = PacketCapture(interfaces=configs)

        assert len(capture.interfaces) == 5
        for i in range(5):
            assert f"eth{i}" in capture.interfaces

    def test_attach_detach_rapid(self):
        """Attach 10 interfaces, detach 5, verify final state."""
        capture = PacketCapture()

        # Attach 10 interfaces (without activating -- no queue/loop)
        for i in range(10):
            cfg = InterfaceConfig(name=f"iface{i}")
            capture.interfaces[cfg.name] = cfg

        assert len(capture.interfaces) == 10

        # Detach 5 (even-numbered)
        for i in range(0, 10, 2):
            name = f"iface{i}"
            capture.interfaces.pop(name, None)

        assert len(capture.interfaces) == 5
        # Only odd-numbered should remain
        for i in range(1, 10, 2):
            assert f"iface{i}" in capture.interfaces
        for i in range(0, 10, 2):
            assert f"iface{i}" not in capture.interfaces

    def test_attach_detach_with_halt_flags(self):
        """Exercise attach/detach via public API without a running event loop.

        Attach registers the config; detach removes it. Workers are not
        started because activate() was never called, so this purely tests
        the bookkeeping.
        """
        capture = PacketCapture()

        for i in range(10):
            capture.attach(InterfaceConfig(name=f"veth{i}"))

        assert len(capture.interfaces) == 10

        for i in range(5):
            capture.detach(f"veth{i}")

        assert len(capture.interfaces) == 5
        for i in range(5, 10):
            assert f"veth{i}" in capture.interfaces

    def test_single_interface_shorthand(self):
        """Verify the single-interface constructor shorthand works."""
        capture = PacketCapture(interface="wlan0")
        assert "wlan0" in capture.interfaces
        assert len(capture.interfaces) == 1

    def test_no_interfaces(self):
        """PacketCapture with no interfaces should not crash."""
        capture = PacketCapture()
        assert len(capture.interfaces) == 0
        assert not capture.is_running


# =========================================================================
# 5. Pattern Loader Reliability
# =========================================================================

class TestPatternLoaderReliability:
    """Pattern loader thread-safety and reload correctness."""

    def test_concurrent_pattern_loads(self):
        """Load all pattern files simultaneously from multiple threads.

        Verify no corruption: every load returns the same data.
        """
        pattern_loader.clear_cache()

        available = pattern_loader.available_patterns()
        if not available:
            pytest.skip("No pattern files found in data directory")

        results: dict[str, list] = {name: [] for name in available}

        def load_one(name: str):
            return (name, pattern_loader.load(name))

        with ThreadPoolExecutor(max_workers=8) as pool:
            # Each pattern loaded 4 times concurrently
            futures = []
            for name in available:
                for _ in range(4):
                    futures.append(pool.submit(load_one, name))

            for future in futures:
                name, data = future.result()
                results[name].append(data)

        # All loads of the same pattern must return identical data
        for name, copies in results.items():
            assert len(copies) == 4, f"Missing results for {name}"
            for i in range(1, len(copies)):
                assert copies[i] == copies[0], (
                    f"Pattern '{name}' load #{i} differs from load #0"
                )

    def test_reload_after_clear_cache(self):
        """Clear cache, reload, verify data is identical to pre-clear state."""
        available = pattern_loader.available_patterns()
        if not available:
            pytest.skip("No pattern files found in data directory")

        # Load all and capture reference copies
        reference = {}
        for name in available:
            reference[name] = pattern_loader.load(name)

        # Clear and reload
        pattern_loader.clear_cache()

        for name in available:
            reloaded = pattern_loader.load(name)
            assert reloaded == reference[name], (
                f"Pattern '{name}' changed after cache clear and reload"
            )

    def test_compiled_patterns_thread_safety(self):
        """Load compiled patterns concurrently and verify consistency."""
        pattern_loader.clear_cache()

        available = pattern_loader.available_patterns()
        if not available:
            pytest.skip("No pattern files found in data directory")

        # Pick patterns that are likely list-based (have 'match' fields)
        results: dict[str, list] = {}

        def load_compiled(name: str):
            return (name, pattern_loader.load_compiled(name))

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = []
            for name in available:
                for _ in range(3):
                    futures.append(pool.submit(load_compiled, name))

            for future in futures:
                name, data = future.result()
                results.setdefault(name, []).append(data)

        # All concurrent loads must return the same number of compiled entries
        for name, copies in results.items():
            lengths = [len(c) for c in copies]
            assert len(set(lengths)) == 1, (
                f"Pattern '{name}' compiled to different lengths: {lengths}"
            )

    def test_clear_cache_idempotent(self):
        """Clearing the cache multiple times in a row must not crash."""
        for _ in range(10):
            pattern_loader.clear_cache()

        # Loading after repeated clears still works
        available = pattern_loader.available_patterns()
        for name in available:
            data = pattern_loader.load(name)
            assert data is not None
