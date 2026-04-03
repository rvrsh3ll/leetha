"""Tests for behavioral drift finding rule."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from leetha.store.models import Host, Finding, FindingRule as FR, AlertSeverity
from leetha.evidence.models import Verdict


@pytest.fixture
def store():
    s = MagicMock()
    s.verdicts = AsyncMock()
    s.hosts = AsyncMock()
    return s


class TestBehavioralDriftRule:
    @pytest.mark.asyncio
    async def test_fires_when_drift_detected(self, store):
        from leetha.rules.behavioral import BehavioralDriftRule
        rule = BehavioralDriftRule()
        with patch.object(rule, '_tracker') as mock_tracker:
            mock_tracker.check_drift.return_value = {
                "from_vendor": "Apple", "from_pct": 15.0,
                "to_vendor": "Microsoft", "to_pct": 72.0,
                "observation_minutes": 45.0,
            }
            host = Host(hw_addr="aa:bb:cc:dd:ee:ff")
            verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
            result = await rule.evaluate(host, verdict, store)
            assert result is not None
            assert result.rule == FR.BEHAVIORAL_DRIFT
            assert result.severity == AlertSeverity.HIGH
            assert "Apple" in result.message
            assert "Microsoft" in result.message

    @pytest.mark.asyncio
    async def test_no_fire_when_no_drift(self, store):
        from leetha.rules.behavioral import BehavioralDriftRule
        rule = BehavioralDriftRule()
        with patch.object(rule, '_tracker') as mock_tracker:
            mock_tracker.check_drift.return_value = None
            host = Host(hw_addr="aa:bb:cc:dd:ee:ff")
            verdict = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
            result = await rule.evaluate(host, verdict, store)
            assert result is None
