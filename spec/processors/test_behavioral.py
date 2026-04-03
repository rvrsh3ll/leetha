"""Tests for DNS behavioral profiler."""
import pytest
from leetha.processors.behavioral import DnsBehaviorTracker


class TestDnsBehaviorTracker:
    def setup_method(self):
        self.tracker = DnsBehaviorTracker()

    def test_record_query_tracks_vendor(self):
        self.tracker.record("aa:bb:cc:dd:ee:ff", "icloud.com", 1)
        profile = self.tracker.get_profile("aa:bb:cc:dd:ee:ff")
        assert profile is not None
        assert profile["query_count"] >= 1

    def test_vendor_affinity_apple(self):
        for domain in ["icloud.com", "gs.apple.com", "apple.com",
                        "push.apple.com", "mesu.apple.com"]:
            self.tracker.record("aa:bb:cc:dd:ee:ff", domain, 1)
        profile = self.tracker.get_profile("aa:bb:cc:dd:ee:ff")
        assert profile["top_vendor"] == "Apple"

    def test_no_profile_for_unknown_host(self):
        assert self.tracker.get_profile("ff:ff:ff:ff:ff:ff") is None

    def test_needs_minimum_queries(self):
        for i in range(10):
            self.tracker.record("aa:bb:cc:dd:ee:ff", "icloud.com", 1)
        assert not self.tracker.is_profiled("aa:bb:cc:dd:ee:ff")

    def test_profiled_after_enough_queries(self):
        for i in range(25):
            self.tracker.record("aa:bb:cc:dd:ee:ff", "icloud.com", 1)
        assert self.tracker.is_profiled("aa:bb:cc:dd:ee:ff")

    def test_detect_drift_when_vendor_flips(self):
        tracker = DnsBehaviorTracker()
        # Build Apple profile and force baseline lock
        for i in range(25):
            tracker.record("aa:bb:cc:dd:ee:ff", "icloud.com", 1)
        # Force baseline lock by manipulating the profile
        profile = tracker._profiles["aa:bb:cc:dd:ee:ff"]
        profile.baseline_vendor = "Apple"
        profile.baseline_locked = True
        # Shift to Microsoft (need enough to exceed early drift threshold)
        for i in range(50):
            tracker.record("aa:bb:cc:dd:ee:ff", "update.microsoft.com", 1)
        drift = tracker.check_drift("aa:bb:cc:dd:ee:ff")
        assert drift is not None
        assert "Apple" in drift["from_vendor"]
        assert "Microsoft" in drift["to_vendor"]

    def test_no_drift_when_consistent(self):
        tracker = DnsBehaviorTracker()
        for i in range(50):
            tracker.record("aa:bb:cc:dd:ee:ff", "icloud.com", 1)
        profile = tracker._profiles["aa:bb:cc:dd:ee:ff"]
        profile.baseline_vendor = "Apple"
        profile.baseline_locked = True
        drift = tracker.check_drift("aa:bb:cc:dd:ee:ff")
        assert drift is None

    def test_ignores_unclassified_domains(self):
        for i in range(30):
            self.tracker.record("aa:bb:cc:dd:ee:ff", "example.com", 1)
        assert not self.tracker.is_profiled("aa:bb:cc:dd:ee:ff")
