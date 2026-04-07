"""Root conftest — validates async test dependencies are available."""

import pytest


def pytest_configure(config):
    try:
        import pytest_asyncio  # noqa: F401
    except ImportError:
        raise pytest.UsageError(
            "pytest-asyncio is required to run the test suite.\n"
            "Install dev dependencies:  uv sync --group dev"
        )
