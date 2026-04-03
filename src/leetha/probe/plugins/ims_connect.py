"""IMS Connect probe plugin — IBM IMS Connect detection via IRM header."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IMSConnectProbePlugin(ServiceProbe):
    name = "ims_connect"
    protocol = "tcp"
    default_ports = [9999]

    # IRM (IMS Request Message) header identifiers
    _IRM_ID = b"IRM "
    _IRM_HEADER_LEN = 28

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal IRM header probe
            # IRM header: length(4) + id(4="IRM ") + reserved fields
            irm_data = bytearray(self._IRM_HEADER_LEN)
            struct.pack_into(">I", irm_data, 0, self._IRM_HEADER_LEN)  # total length
            irm_data[4:8] = self._IRM_ID  # identifier
            # Remaining fields zeroed (timer, socket, clientid, mod, etc.)

            conn.write(bytes(irm_data))

            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse IMS Connect response
            metadata: dict = {}

            # Check for IRM response header
            if len(data) >= 8:
                resp_id = data[4:8]
                if resp_id == self._IRM_ID:
                    metadata["irm_response"] = True
                    if len(data) >= 4:
                        resp_len = struct.unpack(">I", data[0:4])[0]
                        metadata["response_length"] = resp_len
                    return ServiceIdentity(
                        service="ims_connect",
                        certainty=85,
                        version=None,
                        metadata=metadata,
                    )

            # Check for IMS Connect error/rejection which also identifies the service
            # IMS Connect may respond with a CSM (Complete Status Message) or RSM
            if len(data) >= 4:
                resp_len = struct.unpack(">I", data[0:4])[0]
                # Valid response length should be reasonable
                if 8 <= resp_len <= 65536 and resp_len <= len(data) + 4:
                    # Look for known IMS Connect markers in data
                    text = data.decode("ebcdic-cp-us", errors="replace")
                    if "IMS" in text or "DFS" in text:
                        metadata["ims_marker"] = True
                        return ServiceIdentity(
                            service="ims_connect",
                            certainty=70,
                            version=None,
                            metadata=metadata,
                        )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
