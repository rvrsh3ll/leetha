"""BGP probe plugin — Border Gateway Protocol OPEN message."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class BGPProbePlugin(ServiceProbe):
    name = "bgp"
    protocol = "tcp"
    default_ports = [179]

    MARKER = b"\xff" * 16

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build BGP OPEN message
            # Version: 4, AS: 65000, Hold Time: 180, BGP ID: 1.1.1.1
            bgp_version = 4
            my_as = 65000
            hold_time = 180
            bgp_id = socket.inet_aton("1.1.1.1")
            opt_params_len = 0

            open_msg = struct.pack(
                ">BHH",
                bgp_version,     # Version
                my_as,           # My AS
                hold_time,       # Hold Time
            ) + bgp_id + struct.pack("B", opt_params_len)

            # Total length = 16 (marker) + 2 (length) + 1 (type) + open_msg
            total_length = 19 + len(open_msg)

            packet = self.MARKER + struct.pack(">HB", total_length, 1) + open_msg

            conn.write(packet)
            data = conn.read(4096)

            if not data or len(data) < 19:
                return None

            # Check BGP marker (16 x 0xFF)
            if data[0:16] != self.MARKER:
                return None

            # Parse length and type
            msg_length, msg_type = struct.unpack(">HB", data[16:19])

            metadata: dict = {"message_type": msg_type}
            version = None

            if msg_type == 1:  # OPEN
                if len(data) >= 29:
                    bgp_ver = data[19]
                    peer_as = struct.unpack(">H", data[20:22])[0]
                    peer_hold = struct.unpack(">H", data[22:24])[0]
                    peer_id = socket.inet_ntoa(data[24:28])
                    metadata["bgp_version"] = bgp_ver
                    metadata["peer_as"] = peer_as
                    metadata["hold_time"] = peer_hold
                    metadata["bgp_id"] = peer_id
                    version = f"BGPv{bgp_ver}"
            elif msg_type == 3:  # NOTIFICATION
                if len(data) >= 21:
                    error_code = data[19]
                    error_subcode = data[20]
                    metadata["error_code"] = error_code
                    metadata["error_subcode"] = error_subcode
            # Type 4 = KEEPALIVE is also valid

            return ServiceIdentity(
                service="bgp",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
