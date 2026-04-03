"""X11 probe plugin — X Window System connection setup to detect X servers."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class X11ProbePlugin(ServiceProbe):
    name = "x11"
    protocol = "tcp"
    default_ports = [6000, 6001, 6002, 6003]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build X11 connection setup request
            # byte-order: 0x6C = little-endian ('l')
            # unused: 0x00
            # protocol-major-version: 11
            # protocol-minor-version: 0
            # authorization-protocol-name-length: 0
            # authorization-protocol-data-length: 0
            # unused padding: 2 bytes
            conn_request = struct.pack(
                "<BxHHHH2x",
                0x6C,   # byte order (little-endian)
                11,     # protocol major version
                0,      # protocol minor version
                0,      # auth name length
                0,      # auth data length
            )

            conn.write(conn_request)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse connection reply
            # First byte indicates result:
            # 0 = Failed, 1 = Success, 2 = Authenticate
            result_code = data[0]
            if result_code not in (0, 1, 2):
                return None

            metadata: dict = {}
            version = None

            if result_code == 1:
                # Success reply
                metadata["status"] = "success"
                # Parse success response:
                # byte 1: unused
                # bytes 2-3: protocol-major-version
                # bytes 4-5: protocol-minor-version
                # bytes 6-7: additional data length (in 4-byte units)
                if len(data) >= 8:
                    major = struct.unpack_from("<H", data, 2)[0]
                    minor = struct.unpack_from("<H", data, 4)[0]
                    metadata["protocol_version"] = f"{major}.{minor}"
                    version = f"{major}.{minor}"

                # Parse vendor string
                # After 8-byte header: release_number(4) + resource_id_base(4) +
                # resource_id_mask(4) + motion_buffer_size(4) +
                # vendor_length(2) + ...
                if len(data) >= 24:
                    release_number = struct.unpack_from("<I", data, 8)[0]
                    metadata["release_number"] = release_number
                    vendor_len = struct.unpack_from("<H", data, 24)[0]
                    # Vendor string starts at offset 40
                    if len(data) >= 40 + vendor_len:
                        vendor = data[40:40 + vendor_len].decode(
                            "utf-8", errors="replace"
                        )
                        metadata["vendor"] = vendor

            elif result_code == 0:
                # Failed reply
                metadata["status"] = "failed"
                # byte 1: reason length
                reason_len = data[1]
                if len(data) >= 8:
                    major = struct.unpack_from("<H", data, 2)[0]
                    minor = struct.unpack_from("<H", data, 4)[0]
                    metadata["protocol_version"] = f"{major}.{minor}"
                    version = f"{major}.{minor}"
                # Reason string starts at offset 8
                if len(data) >= 8 + reason_len:
                    reason = data[8:8 + reason_len].decode(
                        "utf-8", errors="replace"
                    )
                    metadata["reason"] = reason

            elif result_code == 2:
                # Authenticate required
                metadata["status"] = "authenticate"

            return ServiceIdentity(
                service="x11",
                certainty=85,
                version=version,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
