"""Auto-discovery of probe plugins.

Scans the plugins/ directory for ServiceProbe subclasses and registers them.
No more hardcoded PLUGINS list in __init__.py.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Type

from leetha.probe.base import ServiceProbe

logger = logging.getLogger(__name__)


def discover_probes(package_path: str = "leetha.probe.plugins") -> dict[str, ServiceProbe]:
    """Auto-discover all ServiceProbe subclasses in the plugins package.

    Returns a dict mapping plugin name to plugin instance.
    """
    import leetha.probe.plugins as plugins_pkg

    probes: dict[str, ServiceProbe] = {}

    for importer, modname, ispkg in pkgutil.walk_packages(
        plugins_pkg.__path__, prefix=plugins_pkg.__name__ + "."
    ):
        if ispkg:
            continue
        try:
            mod = importlib.import_module(modname)
        except Exception:
            logger.debug("Failed to import plugin %s", modname, exc_info=True)
            continue

        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (isinstance(attr, type)
                and issubclass(attr, ServiceProbe)
                and attr is not ServiceProbe
                and hasattr(attr, "name") and attr.name):
                try:
                    instance = attr()
                    probes[instance.name] = instance
                except Exception:
                    logger.debug("Failed to instantiate %s", attr_name, exc_info=True)

    return probes
