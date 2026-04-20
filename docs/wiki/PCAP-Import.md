# PCAP Import

Leetha can import captured traffic from Wireshark, tcpdump, or any tool that produces `.pcap`, `.pcapng`, or `.cap` files. Imported packets flow through the full fingerprinting pipeline -- devices are identified, verdicts computed, and findings generated.

## CLI Import

```bash
leetha import capture.pcap
leetha import scan1.pcap scan2.pcapng
leetha import --max-size 1000 large-capture.pcap
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--max-size` | 500 | Maximum file size in MB |

### Output

```
Importing: capture.pcap
 capture.pcap ━━━━━━━━━━━━ 12847/12847 packets  0:00:03
+---------------------------+-------+
| Metric                    | Value |
+---------------------------+-------+
| Packets parsed            | 12847 |
| Devices processed         | 12847 |
| Total packets             | 12847 |
| Parse errors              | 0     |
+---------------------------+-------+

42 devices now in inventory
```

## Web UI Import

1. Navigate to the Console page
2. Click **Import PCAP** or drag-and-drop a file
3. Progress is shown in real time via WebSocket
4. Devices appear in the inventory as they are processed

## What Gets Processed

Imported packets go through the same pipeline as live capture:
- Protocol parsers (ARP, DHCP, mDNS, TLS, HTTP, LLDP, etc.)
- Fingerprint database lookups (OUI, Huginn, p0f, JA3/JA4)
- Evidence fusion and verdict computation
- Finding rule evaluation
- Identity correlation

## Supported Formats

- `.pcap` -- libpcap format
- `.pcapng` -- next-generation capture format
- `.cap` -- alternative pcap extension
