"""Test the list_devices SQL JOIN query in VerdictRepository."""
import pytest
from pathlib import Path
from datetime import datetime

from leetha.store.store import Store
from leetha.evidence.models import Evidence, Verdict
from leetha.store.models import Host


@pytest.fixture
async def store(tmp_path):
    s = Store(tmp_path / "test.db")
    await s.initialize()
    yield s
    await s.close()


async def _seed(store, mac="aa:bb:cc:dd:ee:ff", vendor="Apple", category="phone",
                platform="iOS", certainty=95, ip="192.168.1.10", disposition="new"):
    """Insert a verdict + host pair for testing."""
    verdict = Verdict(
        hw_addr=mac, category=category, vendor=vendor,
        platform=platform, platform_version=None, model=None,
        hostname=None, certainty=certainty, evidence_chain=[],
        computed_at=datetime.now(),
    )
    await store.verdicts.upsert(verdict)
    host = Host(
        hw_addr=mac, ip_addr=ip, disposition=disposition,
    )
    await store.hosts.upsert(host)


async def test_list_devices_returns_joined_data(store):
    """list_devices should return verdict + host data in one query."""
    await _seed(store)
    devices, total = await store.verdicts.list_devices()
    assert total == 1
    assert len(devices) == 1
    d = devices[0]
    assert d["mac"] == "aa:bb:cc:dd:ee:ff"
    assert d["manufacturer"] == "Apple"
    assert d["device_type"] == "phone"
    assert d["ip_v4"] == "192.168.1.10"


async def test_list_devices_filter_by_manufacturer(store):
    await _seed(store, mac="aa:bb:cc:dd:ee:01", vendor="Apple")
    await _seed(store, mac="aa:bb:cc:dd:ee:02", vendor="Samsung")
    devices, total = await store.verdicts.list_devices(manufacturer="Apple")
    assert total == 1
    assert devices[0]["manufacturer"] == "Apple"


async def test_list_devices_filter_by_device_type(store):
    await _seed(store, mac="aa:bb:cc:dd:ee:01", category="phone")
    await _seed(store, mac="aa:bb:cc:dd:ee:02", category="router")
    devices, total = await store.verdicts.list_devices(device_type="phone")
    assert total == 1


async def test_list_devices_filter_by_confidence(store):
    await _seed(store, mac="aa:bb:cc:dd:ee:01", certainty=90)
    await _seed(store, mac="aa:bb:cc:dd:ee:02", certainty=30)
    devices, total = await store.verdicts.list_devices(confidence_min=50)
    assert total == 1
    assert devices[0]["confidence"] == 90


async def test_list_devices_search_query(store):
    await _seed(store, mac="aa:bb:cc:dd:ee:01", vendor="Apple", ip="10.0.0.1")
    await _seed(store, mac="aa:bb:cc:dd:ee:02", vendor="Samsung", ip="10.0.0.2")
    devices, total = await store.verdicts.list_devices(q="Apple")
    assert total == 1


async def test_list_devices_pagination(store):
    for i in range(5):
        await _seed(store, mac=f"aa:bb:cc:dd:ee:{i:02x}", certainty=50+i)
    devices, total = await store.verdicts.list_devices(page=1, per_page=2)
    assert total == 5
    assert len(devices) == 2
    devices2, _ = await store.verdicts.list_devices(page=2, per_page=2)
    assert len(devices2) == 2
    devices3, _ = await store.verdicts.list_devices(page=3, per_page=2)
    assert len(devices3) == 1


async def test_list_devices_filter_by_alert_status(store):
    await _seed(store, mac="aa:bb:cc:dd:ee:01", disposition="new")
    await _seed(store, mac="aa:bb:cc:dd:ee:02", disposition="known")
    devices, total = await store.verdicts.list_devices(alert_status="known")
    assert total == 1
    assert devices[0]["alert_status"] == "known"


async def test_list_devices_empty(store):
    devices, total = await store.verdicts.list_devices()
    assert total == 0
    assert devices == []
