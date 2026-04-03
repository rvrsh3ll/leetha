"""ServiceScanner -- active service fingerprinting engine.

Self-contained module that drives probe plugins against a target
host:port over real sockets.  Usable independently of the rest of
the leetha package.
"""

from __future__ import annotations

import logging
import socket

from leetha.probe.plugin import ProbePlugin
from leetha.probe.result import ProbeResult

_log = logging.getLogger(__name__)


class ServiceScanner:
    """Identify services on a host:port by cycling through probe plugins.

    Workflow
    --------
    1. Establish a TCP or UDP socket to the target.
    2. Try port-affinity plugins first (those whose *default_ports*
       includes the target port).
    3. Fall through to the remaining plugins in registration order.
    4. The first plugin that returns a ``ProbeResult`` wins.
    5. If every plugin declines, attempt a raw banner read as a last
       resort.
    """

    def __init__(self, conn_timeout: float = 5.0) -> None:
        self._registry: list[ProbePlugin] = []
        self.conn_timeout = conn_timeout

    # -- kept for backward compat via property alias --
    @property
    def timeout(self) -> float:
        return self.conn_timeout

    @timeout.setter
    def timeout(self, value: float) -> None:
        self.conn_timeout = value

    @property
    def plugins(self) -> list[ProbePlugin]:
        return self._registry

    @plugins.setter
    def plugins(self, value: list[ProbePlugin]) -> None:
        self._registry = value

    def register(self, handler: ProbePlugin) -> None:
        """Append a probe plugin to the internal registry."""
        self._registry.append(handler)

    def initialize(self) -> None:
        """Discover and register every bundled probe plugin."""
        from leetha.probe.plugins import PLUGINS

        for cls in PLUGINS:
            self.register(cls())

    # Backward-compatible alias
    load_plugins = initialize

    def _rank_plugins_by_port(self, target_port: int) -> list[ProbePlugin]:
        """Sort registered plugins so port-affinity matches come first.

        Plugins whose *default_ports* contains ``target_port`` are
        placed at the head of the list; all others follow in their
        original registration order.
        """
        affinity: list[ProbePlugin] = []
        remainder: list[ProbePlugin] = []
        for handler in self._registry:
            if target_port in handler.default_ports:
                affinity.append(handler)
            else:
                remainder.append(handler)
        return affinity + remainder

    def scan_service(
        self,
        target_host: str,
        target_port: int,
        port_hint: int | None = None,
        protocol: str = "tcp",
    ) -> ProbeResult | None:
        """Run all matching plugins against *target_host*:*target_port*.

        Returns the first successful ``ProbeResult``, or ``None`` if
        nothing matched (including the raw-banner fallback).
        """
        effective_port = port_hint if port_hint is not None else target_port
        candidates = self._rank_plugins_by_port(effective_port)
        candidates = [h for h in candidates if h.protocol == protocol]

        for handler in candidates:
            try:
                hit = self._execute_plugin(handler, target_host, target_port, protocol)
                if hit is not None:
                    _log.debug(
                        "Plugin %s matched %s:%d -> %s",
                        handler.name, target_host, target_port, hit.service,
                    )
                    return hit
            except Exception as err:
                _log.debug(
                    "Plugin %s error on %s:%d: %s",
                    handler.name, target_host, target_port, err,
                )

        return self._grab_raw_banner(target_host, target_port, protocol)

    # Backward-compatible alias
    probe = scan_service

    def _execute_plugin(self, handler, host, port, protocol):
        """Open a socket, delegate to the plugin, then clean up."""
        conn = self._open_socket(host, port, protocol)
        if conn is None:
            return None
        try:
            return handler.probe(conn, host, port)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _open_socket(self, host, port, protocol):
        """Return a connected socket to *host*:*port*, or None on failure."""
        try:
            kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
            conn = socket.socket(socket.AF_INET, kind)
            conn.settimeout(self.conn_timeout)
            conn.connect((host, port))
            return conn
        except (socket.error, OSError) as err:
            _log.debug("Connection failed to %s:%d: %s", host, port, err)
            return None

    def _grab_raw_banner(self, host, port, protocol):
        """Last-resort fallback: read whatever bytes the remote side sends."""
        conn = self._open_socket(host, port, protocol)
        if conn is None:
            return None
        try:
            raw = conn.recv(1024)
            if raw:
                text = raw.decode("utf-8", errors="replace").strip()
                if text:
                    return ProbeResult(
                        service="unknown",
                        banner=text,
                        confidence=20,
                        metadata={"method": "raw_banner"},
                    )
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return None


# Backward-compatible alias so existing imports keep working
ProbeEngine = ServiceScanner
