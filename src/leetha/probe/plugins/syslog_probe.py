"""Syslog probe plugin — TCP RFC 5424 syslog message detection."""
from __future__ import annotations
import socket
import time
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SyslogProbePlugin(ServiceProbe):
    name = "syslog"
    protocol = "tcp"
    default_ports = [514, 601]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # RFC 5424 syslog message format with octet counting (RFC 6587)
            # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
            syslog_msg = (
                f"<14>1 {timestamp}Z leetha-probe probe - - "
                f"[meta sequenceId=\"1\"] probe message"
            )
            # Octet-counted framing for TCP syslog
            framed = f"{len(syslog_msg)} {syslog_msg}"
            conn.write(framed.encode("utf-8"))

            # Syslog servers typically don't respond, but connection acceptance
            # with no RST after sending a valid message indicates syslog service.
            conn.set_timeout(2)
            try:
                data = conn.read(4096)
            except socket.timeout:
                data = b""

            metadata: dict = {"protocol": "rfc5424", "transport": "tcp"}

            if data:
                response = data.decode("utf-8", errors="replace")
                metadata["response_received"] = True
                metadata["response_length"] = len(data)
            else:
                metadata["response_received"] = False

            # TCP syslog detected by successful connection + message send
            return ServiceIdentity(
                service="syslog",
                certainty=55,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
