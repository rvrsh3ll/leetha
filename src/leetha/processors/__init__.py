"""Registry-based packet processors.

Processors analyze CapturedPackets and produce Evidence. They register
themselves for specific protocols using the @register_processor decorator.
"""
import leetha.processors.discovery_enhanced  # noqa: F401
