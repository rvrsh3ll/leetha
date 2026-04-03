"""Graylog GELF probe plugin — TCP GELF message (JSON + null byte) detection."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GraylogGELFProbePlugin(ServiceProbe):
    name = "graylog_gelf"
    protocol = "tcp"
    default_ports = [12201]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # GELF TCP: send a JSON message terminated by a null byte
            gelf_message = json.dumps({
                "version": "1.1",
                "host": "leetha-probe",
                "short_message": "probe",
                "level": 6,
            })
            # GELF TCP uses null-byte delimited messages
            conn.write(gelf_message.encode("utf-8") + b"\x00")

            # Graylog typically doesn't send a response for valid GELF messages,
            # but the connection acceptance itself indicates the service.
            # Try to read — some setups send back an ack or error.
            conn.set_timeout(2)
            try:
                data = conn.read(4096)
            except socket.timeout:
                # No response is normal for GELF TCP — connection accepted = service detected
                data = b""

            metadata: dict = {"protocol": "gelf_tcp"}

            if data:
                response = data.decode("utf-8", errors="replace")
                metadata["response_received"] = True
                metadata["response_length"] = len(data)
            else:
                metadata["response_received"] = False

            # Service detected by successful connection + message acceptance
            return ServiceIdentity(
                service="graylog_gelf",
                certainty=65,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
