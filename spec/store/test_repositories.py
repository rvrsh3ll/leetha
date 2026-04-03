"""Tests for repository pattern store layer."""
import pytest
from datetime import datetime
from leetha.store.store import Store
from leetha.store.models import Host, Finding, Sighting, FindingRule, AlertSeverity
from leetha.evidence.models import Evidence, Verdict


@pytest.fixture
async def store():
    s = Store(":memory:")
    await s.initialize()
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_store_initializes(store):
    assert store.hosts is not None
    assert store.findings is not None
    assert store.sightings is not None
    assert store.verdicts is not None


@pytest.mark.asyncio
async def test_host_upsert_and_find(store):
    host = Host(hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.100", disposition="new")
    await store.hosts.upsert(host)
    found = await store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found is not None
    assert found.hw_addr == "aa:bb:cc:dd:ee:ff"
    assert found.ip_addr == "192.168.1.100"


@pytest.mark.asyncio
async def test_host_upsert_updates(store):
    h1 = Host(hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.100")
    await store.hosts.upsert(h1)
    h2 = Host(hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.200")
    await store.hosts.upsert(h2)
    found = await store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found.ip_addr == "192.168.1.200"


@pytest.mark.asyncio
async def test_host_count(store):
    await store.hosts.upsert(Host(hw_addr="aa:bb:cc:dd:ee:ff"))
    await store.hosts.upsert(Host(hw_addr="11:22:33:44:55:66"))
    assert await store.hosts.count() == 2


@pytest.mark.asyncio
async def test_host_find_all(store):
    await store.hosts.upsert(Host(hw_addr="aa:bb:cc:dd:ee:ff"))
    await store.hosts.upsert(Host(hw_addr="11:22:33:44:55:66"))
    hosts = await store.hosts.find_all()
    assert len(hosts) == 2


@pytest.mark.asyncio
async def test_host_not_found(store):
    found = await store.hosts.find_by_addr("ff:ff:ff:ff:ff:ff")
    assert found is None


@pytest.mark.asyncio
async def test_finding_add_and_list(store):
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="New host discovered")
    fid = await store.findings.add(f)
    assert fid is not None
    active = await store.findings.list_active()
    assert len(active) == 1
    assert active[0].rule == FindingRule.NEW_HOST


@pytest.mark.asyncio
async def test_finding_resolve(store):
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="Test")
    fid = await store.findings.add(f)
    await store.findings.resolve(fid)
    active = await store.findings.list_active()
    assert len(active) == 0


@pytest.mark.asyncio
async def test_finding_count_active(store):
    for i in range(3):
        await store.findings.add(Finding(
            hw_addr=f"aa:bb:cc:dd:ee:{i:02x}", rule=FindingRule.NEW_HOST,
            severity=AlertSeverity.INFO, message=f"Host {i}"))
    assert await store.findings.count_active() == 3


@pytest.mark.asyncio
async def test_sighting_record_and_query(store):
    s = Sighting(hw_addr="aa:bb:cc:dd:ee:ff", source="arp",
                 payload={"op": 1}, certainty=0.8, interface="eth0")
    await store.sightings.record(s)
    sightings = await store.sightings.for_host("aa:bb:cc:dd:ee:ff")
    assert len(sightings) == 1
    assert sightings[0].source == "arp"
    assert sightings[0].payload == {"op": 1}


@pytest.mark.asyncio
async def test_verdict_upsert_and_find(store):
    evidence = [Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco")]
    v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", category="switch",
                vendor="Cisco", platform="IOS", certainty=90,
                evidence_chain=evidence)
    await store.verdicts.upsert(v)
    found = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found is not None
    assert found.category == "switch"
    assert found.vendor == "Cisco"
    assert found.certainty == 90
    assert len(found.evidence_chain) == 1
    assert found.evidence_chain[0].source == "lldp"


@pytest.mark.asyncio
async def test_verdict_upsert_updates(store):
    v1 = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", vendor="Unknown", certainty=30)
    await store.verdicts.upsert(v1)
    v2 = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", vendor="Cisco", certainty=90)
    await store.verdicts.upsert(v2)
    found = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert found.vendor == "Cisco"
    assert found.certainty == 90


@pytest.mark.asyncio
async def test_verdict_find_all(store):
    await store.verdicts.upsert(Verdict(hw_addr="aa:bb:cc:dd:ee:ff", certainty=90))
    await store.verdicts.upsert(Verdict(hw_addr="11:22:33:44:55:66", certainty=50))
    verdicts = await store.verdicts.find_all()
    assert len(verdicts) == 2
    assert verdicts[0].certainty >= verdicts[1].certainty  # ordered by certainty desc
