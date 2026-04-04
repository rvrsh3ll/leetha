import re
from leetha.patterns.matching import _match_extended


class TestCompiledMatching:
    def test_compiled_tuple_matches(self):
        compiled = [(re.compile(r"OpenSSH", re.IGNORECASE), {
            "product": "OpenSSH", "vendor": "OpenBSD",
            "platform": "Linux", "device_type": "server",
        })]
        result = _match_extended("SSH-2.0-OpenSSH_9.2", compiled)
        assert result is not None
        assert result["product"] == "OpenSSH"

    def test_compiled_no_match_returns_none(self):
        compiled = [(re.compile(r"Apache", re.IGNORECASE), {
            "product": "Apache",
        })]
        result = _match_extended("SSH-2.0-OpenSSH", compiled)
        assert result is None

    def test_raw_dict_still_works(self):
        raw = [{"match": "nginx", "product": "nginx", "vendor": "F5", "platform": "Linux"}]
        result = _match_extended("Server: nginx/1.25", raw)
        assert result is not None

    def test_version_extraction_with_compiled(self):
        compiled = [(re.compile(r"Apache", re.IGNORECASE), {
            "product": "Apache", "vendor": "Apache Foundation",
            "version_match": r"Apache/([\d.]+)",
        })]
        result = _match_extended("Server: Apache/2.4.58", compiled)
        assert result is not None
        assert result["version"] == "2.4.58"
