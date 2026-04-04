"""Registry-based packet processors.

Processors analyze CapturedPackets and produce Evidence. They register
themselves for specific protocols using the @register_processor decorator.
"""
import leetha.processors.network  # noqa: F401
import leetha.processors.services  # noqa: F401
import leetha.processors.names  # noqa: F401
import leetha.processors.infrastructure  # noqa: F401
import leetha.processors.iot_scada  # noqa: F401
import leetha.processors.passive  # noqa: F401
import leetha.processors.banner  # noqa: F401
import leetha.processors.behavioral  # noqa: F401
import leetha.processors.active  # noqa: F401
import leetha.processors.discovery_enhanced  # noqa: F401
