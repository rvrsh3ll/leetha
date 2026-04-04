import json
import tempfile
from pathlib import Path
from leetha.sync.streaming import stream_json_array, stream_json_lines


class TestStreamJsonArray:
    def test_streams_items(self):
        data = [{"mac": "aa:bb", "vendor": "Foo"}, {"mac": "cc:dd", "vendor": "Bar"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        items = list(stream_json_array(path))
        assert len(items) == 2
        assert items[0]["mac"] == "aa:bb"

    def test_empty_array(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([], f)
            path = Path(f.name)
        assert list(stream_json_array(path)) == []

    def test_dict_yields_single(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"key": "value"}, f)
            path = Path(f.name)
        items = list(stream_json_array(path))
        assert len(items) == 1


class TestStreamJsonLines:
    def test_streams_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"a": 1}\n{"a": 2}\n')
            path = Path(f.name)
        items = list(stream_json_lines(path))
        assert len(items) == 2

    def test_skips_blank_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"a": 1}\n\n{"a": 2}\n')
            path = Path(f.name)
        items = list(stream_json_lines(path))
        assert len(items) == 2

    def test_skips_malformed_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"a": 1}\nnot json\n{"a": 2}\n')
            path = Path(f.name)
        items = list(stream_json_lines(path))
        assert len(items) == 2
