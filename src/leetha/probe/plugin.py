"""Legacy probe plugin base class.

Retained for backward compatibility with code that imports ProbePlugin.
New plugins should inherit from ``leetha.probe.base.ServiceProbe`` and
implement ``identify(conn)`` instead of ``probe(sock, host, port)``.

.. deprecated::
    Use :class:`leetha.probe.base.ServiceProbe` instead.
"""
from __future__ import annotations

import socket
from abc import ABC, abstractmethod


class ProbePlugin(ABC):
    """Abstract base for service detection probes (legacy interface).

    Subclasses implement :meth:`probe` to detect a service on a socket.
    Prefer :class:`~leetha.probe.base.ServiceProbe` for new plugins.
    """

    name: str = ""
    protocol: str = "tcp"
    default_ports: list[int] = []

    @abstractmethod
    def probe(self, sock: socket.socket, host: str, port: int):
        """Probe the service and return a result or None."""
        ...

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"
