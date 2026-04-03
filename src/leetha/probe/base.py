"""New probe plugin base class for leetha architecture.

Plugins inherit from ServiceProbe and implement identify() instead of probe().
Uses ServiceConnection instead of raw sockets.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity


class ServiceProbe(ABC):
    """Base class for service identification plugins.

    Subclasses implement identify() to detect and characterize a service.
    The ServiceConnection wrapper handles socket operations.
    """

    name: str = ""
    protocol: str = "tcp"
    default_ports: list[int] = []

    @abstractmethod
    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        """Identify the service on this connection.

        Args:
            conn: ServiceConnection wrapping the socket with read/write/exchange helpers

        Returns:
            ServiceIdentity if the service was identified, None otherwise
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} ports={self.default_ports}>"
