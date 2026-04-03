"""Finding rule registry with auto-discovery decorator."""
from __future__ import annotations
import logging
from typing import Type

logger = logging.getLogger(__name__)

_RULE_REGISTRY: dict[str, Type] = {}

def register_rule(name: str):
    """Decorator to register a finding rule class."""
    def decorator(cls):
        _RULE_REGISTRY[name] = cls
        cls._rule_name = name
        return cls
    return decorator

def get_rule(name: str):
    return _RULE_REGISTRY.get(name)

def get_all_rules() -> dict[str, Type]:
    return dict(_RULE_REGISTRY)

def clear_rule_registry():
    _RULE_REGISTRY.clear()
