import json
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)


def stream_json_array(path: Path) -> Generator[dict, None, None]:
    try:
        import ijson
        with open(path, "rb") as f:
            for item in ijson.items(f, "item"):
                yield item
        return
    except ImportError:
        pass
    # Fallback
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        yield from data
    elif isinstance(data, dict):
        yield data


def stream_json_lines(path: Path) -> Generator[dict, None, None]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping malformed JSONL line in %s", path.name)
