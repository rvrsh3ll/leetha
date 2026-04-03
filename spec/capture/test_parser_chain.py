"""Tests for the split parser chain."""
from leetha.capture.protocols import PARSER_CHAIN


class TestParserChain:
    def test_chain_has_expected_count(self):
        assert len(PARSER_CHAIN) >= 15  # 15+ parsers

    def test_all_parsers_callable(self):
        for parser in PARSER_CHAIN:
            assert callable(parser), f"{parser} is not callable"

    def test_chain_order_starts_with_specific(self):
        """Most specific parsers (L2) should come first."""
        names = [p.__name__ for p in PARSER_CHAIN]
        assert names[0] == "parse_lldp"
        assert names[-1] == "parse_ip_observed"

    def test_parsers_return_none_for_empty_bytes(self):
        """Each parser should handle non-matching input gracefully."""
        from unittest.mock import MagicMock
        dummy = MagicMock()
        dummy.haslayer = MagicMock(return_value=False)
        for parser in PARSER_CHAIN:
            result = parser(dummy)
            # Should return None (or empty list for multi-result parsers)
            assert result is None or result == [], (
                f"{parser.__name__} should return None/[] for non-matching packet"
            )
