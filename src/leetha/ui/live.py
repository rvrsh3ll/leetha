"""
CLI Live Mode -- real-time packet stream with fingerprint reasoning.

Renders each captured packet with evidence tree showing which fingerprint
sources matched and why, plus the final device verdict.
"""

from __future__ import annotations

import asyncio
import collections
import sys
import time

try:
    import select
    import termios
    import tty
    _HAS_TERMINAL = True
except ImportError:
    _HAS_TERMINAL = False

from rich.console import Console
from leetha.app import LeethaApp
from leetha.capture.protocols import ParsedPacket


class _RateLimiter:
    """Token-bucket rate limiter for display throttling."""

    def __init__(self, max_per_sec: int | None = None):
        self._max = max_per_sec
        self._window_start = time.monotonic()
        self._count = 0
        self.skipped = 0

    def allow(self) -> bool:
        if self._max is None:
            return True
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._count = 0
        if self._count < self._max:
            self._count += 1
            return True
        self.skipped += 1
        return False


class _StatusBar:
    """Persistent status line for live capture mode."""

    def __init__(self, max_rate: int | None = None):
        self.max_rate = max_rate
        self.total_events = 0
        self.skipped = 0
        self.paused = False
        self.buffered = 0
        self.interface_name = ""
        self.seen_macs: set[str] = set()
        self.alert_count = 0
        self._timestamps: collections.deque[float] = collections.deque(maxlen=100)

    def record_event(self) -> None:
        self.total_events += 1
        self._timestamps.append(time.monotonic())

    def events_per_sec(self) -> int:
        if not self._timestamps:
            return 0
        now = time.monotonic()
        cutoff = now - 1.0
        count = sum(1 for t in self._timestamps if t >= cutoff)
        return count

    def render(self) -> str:
        iface = f"  {self.interface_name}" if self.interface_name else ""
        device_count = len(self.seen_macs)
        if self.paused:
            return (
                f"[PAUSED]{iface}"
                f" | {self.total_events} events"
                f" | {device_count} devices"
                f" | {self.alert_count} alerts"
                f" | {self.buffered} buffered"
                f" | Space: resume"
            )
        rate_str = f"{self.max_rate}/s" if self.max_rate else "unlimited"
        eps = self.events_per_sec()
        return (
            f"[LIVE]{iface}"
            f" | {self.total_events} events"
            f" | {device_count} devices"
            f" | {self.alert_count} alerts"
            f" | {eps}/s"
            f" | Space: pause"
            f" | Ctrl+C: stop"
        )

    def print(self, console: 'Console') -> None:
        """Print status bar pinned to bottom of terminal."""
        text = self.render()
        console.print(
            f"\033[s\033[{console.height};0H\033[2K"
            f"[dim]{text}[/dim]"
            f"\033[u",
            highlight=False,
            end="",
        )


class _KeyReader:
    """Non-blocking keyboard reader using raw terminal mode."""

    def __init__(self):
        self._old_settings = None
        self._fd = None

    def enable(self) -> None:
        self._fd = sys.stdin.fileno()
        self._old_settings = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)

    def disable(self) -> None:
        if self._old_settings is not None and self._fd is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)

    def poll(self) -> str | None:
        """Return keypress character if available, else None."""
        if self._fd is None:
            return None
        rlist, _, _ = select.select([sys.stdin], [], [], 0)
        if rlist:
            return sys.stdin.read(1)
        return None


async def run_live(
    interfaces: list | None = None,
    decode: bool = False,
    packet_filter: str | None = None,
    rate: int | None = None,
    app: LeethaApp | None = None,
):
    """Entry point for --live mode.

    If *app* is provided, subscribe to it without managing its lifecycle.
    If *app* is None, create and manage a new LeethaApp.
    """
    if not _HAS_TERMINAL:
        from rich.console import Console
        Console().print(
            "[bold red]Live packet viewer requires a Unix terminal "
            "(not available on Windows).[/bold red]\n"
            "Use [bold]--web[/bold] for the web dashboard instead."
        )
        return

    console = Console(emoji=False)
    owns_app = app is None
    if owns_app:
        app = LeethaApp(interfaces=interfaces)
        await app.start()

    events = app.subscribe()
    limiter = _RateLimiter(max_per_sec=rate)
    status = _StatusBar(max_rate=rate)
    keys = _KeyReader()
    paused = False
    buffer: list[dict] = []
    repeat_tracker = _RepeatTracker()

    interface_name = ", ".join(app.capture_engine.interfaces.keys()) or "auto"
    status.interface_name = interface_name

    console.print(
        "[bold green]LEETHA Live Capture[/bold green]"
        f"  [dim]{interface_name}[/dim]\n"
    )

    keys.enable()
    try:
        last_status_update = time.monotonic()
        while True:
            # Check for keypress
            key = keys.poll()
            if key == " ":
                paused = not paused
                status.paused = paused
                if not paused:
                    # Drain buffer on resume
                    for buffered_event in buffer:
                        if limiter.allow():
                            status.record_event()
                            status.seen_macs.add(buffered_event["packet"].src_mac)
                            status.alert_count += len(buffered_event.get("alerts", []))
                            _render_event(console, buffered_event, decode=decode, repeat_tracker=repeat_tracker)
                        else:
                            status.skipped = limiter.skipped
                    buffer.clear()
                    status.buffered = 0

            # Non-blocking get with timeout for responsive key handling
            try:
                event = await asyncio.wait_for(events.get(), timeout=0.05)
            except asyncio.TimeoutError:
                # Refresh status bar periodically
                now = time.monotonic()
                if now - last_status_update >= 1.0:
                    status.print(console)
                    last_status_update = now
                continue

            if packet_filter and not _matches_filter(event, packet_filter):
                continue

            if paused:
                buffer.append(event)
                status.buffered = len(buffer)
            elif limiter.allow():
                status.record_event()
                status.seen_macs.add(event["packet"].src_mac)
                status.alert_count += len(event.get("alerts", []))
                _render_event(console, event, decode=decode, repeat_tracker=repeat_tracker)
            else:
                status.skipped = limiter.skipped

            # Refresh status bar every second
            now = time.monotonic()
            if now - last_status_update >= 1.0:
                status.print(console)
                last_status_update = now

    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        keys.disable()
        app.unsubscribe(events)
        # Clear the status bar line on exit
        console.print(f"\033[{console.height};0H\033[2K", end="")
        if owns_app:
            await app.stop()


# Protocol tag colors
_PROTO_COLORS: dict[str, str] = {
    "arp": "bright_cyan",
    "tcp_syn": "bright_blue",
    "dhcpv4": "bright_green",
    "dhcpv6": "green",
    "mdns": "bright_yellow",
    "dns": "yellow",
    "dns_answer": "yellow",
    "ssdp": "bright_magenta",
    "netbios": "orange1",
    "tls": "magenta",
    "banner": "white",
    "icmpv6": "cyan",
    "http_useragent": "bright_white",
    "ip_observed": "dim white",
}

# Indentation for tree lines
_INDENT = "             "


def _conf_style(conf: int) -> str:
    """Return Rich style string for a confidence percentage."""
    if conf >= 80:
        return "bold bright_green"
    if conf >= 50:
        return "yellow"
    return "red"


class _RepeatTracker:
    """Detect consecutive identical evidence from the same MAC."""

    def __init__(self):
        self._last_mac: str | None = None
        self._last_hash: int | None = None
        self.repeat_count: int = 0

    def check(self, mac: str, evidence_keys: list[str],
              confidence: int, alert_count: int) -> bool:
        """Return True if this event is a repeat of the previous one.

        Resets when MAC, evidence, confidence, or alert count changes.
        """
        h = hash((mac, tuple(sorted(evidence_keys)), confidence, alert_count))
        if mac == self._last_mac and h == self._last_hash:
            self.repeat_count += 1
            return True
        self._last_mac = mac
        self._last_hash = h
        self.repeat_count = 0
        return False


def _proto_tag(protocol: str) -> str:
    """Return a colored, fixed-width protocol tag."""
    color = _PROTO_COLORS.get(protocol, "white")
    _PROTO_NAMES = {
        "tcp_syn": "TCP SYN",
        "dhcpv4": "DHCPv4",
        "dhcpv6": "DHCPv6",
        "dns_answer": "DNS ANSWER",
        "http_useragent": "HTTP",
        "ip_observed": "IP",
        "icmpv6": "ICMPv6",
    }
    label = _PROTO_NAMES.get(protocol, protocol.upper())
    return f"[bold {color}]{label:<12s}[/bold {color}]"


def _render_event(console: Console, event: dict, decode: bool = False,
                  repeat_tracker: _RepeatTracker | None = None):
    """Render a single packet event with fingerprint reasoning."""
    packet: ParsedPacket = event["packet"]
    device = event.get("device")
    alerts = event.get("alerts", [])
    matches = event.get("matches", [])
    data = packet.data

    # ── Header: timestamp + protocol + src MAC/IP + dst MAC/IP + verdict ──
    timestamp = packet.timestamp.strftime("%H:%M:%S")
    tag = _proto_tag(packet.protocol)

    src_mac = f"[bright_blue]{packet.src_mac}[/bright_blue]"
    src_ip = f"[white]{packet.src_ip}[/white]" if packet.src_ip else ""

    dst_mac = f"[bright_blue]{packet.dst_mac}[/bright_blue]" if packet.dst_mac else ""
    dst_ip = f"[white]{packet.dst_ip}[/white]" if packet.dst_ip else ""
    if not dst_mac and not dst_ip:
        dst_mac = "[dim]—[/dim]"

    # Build verdict from device identity
    verdict = ""
    if device:
        dtype = device.device_type or "—"
        mfr = device.hostname or device.manufacturer or "Unknown"
        os_str = device.os_family or "—"
        if device.os_version:
            os_str = f"{os_str} {device.os_version}"
        conf = device.confidence
        style = _conf_style(conf)
        verdict = (
            f"  [bold bright_white]{dtype}[/bold bright_white]"
            f" [dim]|[/dim] [white]{mfr}[/white]"
            f" [dim]|[/dim] [white]{os_str}[/white]"
            f" [dim]|[/dim] [{style}]{conf}%[/{style}]"
        )

    console.print(
        f"[dim white]{timestamp}[/dim white]  {tag}"
        f"{src_mac}  {src_ip}  {dst_mac}  {dst_ip}"
        f"{verdict}"
    )

    # MAC randomization indicator
    if device and device.is_randomized_mac:
        corr = f" -> [bright_blue]{device.correlated_mac}[/bright_blue]" if device.correlated_mac else ""
        console.print(
            f"{_INDENT}[bright_magenta][R] Randomized MAC{corr}[/bright_magenta]"
        )

    # Build evidence key for repeat detection
    evidence_keys = [f"{m.source}:{int(m.confidence * 100)}" for m in matches]
    device_conf = device.confidence if device else 0
    alert_count = len(alerts)

    if repeat_tracker and repeat_tracker.check(
        packet.src_mac, evidence_keys, device_conf, alert_count
    ):
        console.print(
            f"{_INDENT}[dim]↻ same evidence (×{repeat_tracker.repeat_count})[/dim]"
        )
        console.print()
        return

    # ── Protocol-specific details ──
    if packet.protocol == "arp":
        op = data.get("op", "")
        op_label = "Request" if op == 1 else "Reply" if op == 2 else str(op)
        console.print(
            f"{_INDENT}[yellow]Op:[/yellow] {op_label}"
            f"  [yellow]Target:[/yellow] {packet.dst_ip or '?'}"
        )

    elif packet.protocol == "tcp_syn":
        ttl = data.get("ttl", "?")
        win = data.get("window_size", "?")
        mss = data.get("mss", "?")
        wscale = data.get("window_scale", "")
        opts = data.get("tcp_options", "")
        dst_port = data.get("dst_port", "")
        parts = [f"TTL: {ttl}", f"Win: {win}", f"MSS: {mss}"]
        if wscale:
            parts.append(f"WScale: {wscale}")
        if opts:
            parts.append(f"Opts: {opts}")
        if dst_port:
            parts.append(f"Port: {dst_port}")
        console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")

    elif packet.protocol == "dhcpv4":
        parts = []
        msg_type = data.get("message_type", "")
        if msg_type:
            parts.append(f"Type: {msg_type}")
        if data.get("hostname"):
            parts.append(f"Hostname: {data['hostname']}")
        if data.get("opt55"):
            parts.append(f"Opt55: {data['opt55']}")
        if data.get("opt60"):
            parts.append(f"Vendor: {data['opt60']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        client_id = data.get("client_id")
        if client_id and client_id != packet.src_mac:
            console.print(
                f"{_INDENT}[yellow]Client-ID:[/yellow] "
                f"[bright_magenta]{client_id}[/bright_magenta] [dim](real MAC)[/dim]"
            )

    elif packet.protocol == "dhcpv6":
        parts = []
        if data.get("message_type"):
            parts.append(f"Type: {data['message_type']}")
        if data.get("oro"):
            parts.append(f"ORO: {data['oro']}")
        if data.get("duid"):
            parts.append(f"DUID: {data['duid']}")
        if data.get("fqdn"):
            parts.append(f"FQDN: {data['fqdn']}")
        if data.get("vendor_class"):
            parts.append(f"Vendor: {data['vendor_class']}")
        if data.get("enterprise_id"):
            parts.append(f"Enterprise: {data['enterprise_id']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")

    elif packet.protocol == "dns":
        qname = data.get("query_name", "")
        qtype_name = data.get("query_type_name", str(data.get("query_type", "")))
        console.print(
            f"{_INDENT}[yellow]Query:[/yellow] {qname}  "
            f"[yellow]Type:[/yellow] {qtype_name}"
        )

    elif packet.protocol == "mdns":
        parts = []
        if data.get("service_type"):
            parts.append(f"Service: {data['service_type']}")
        if data.get("name"):
            parts.append(f'Name: "{data["name"]}"')
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        txt_parts = []
        if data.get("model"):
            txt_parts.append(f"Model: {data['model']}")
        if data.get("apple_model"):
            txt_parts.append(f"Apple: {data['apple_model']}")
        if data.get("friendly_name"):
            txt_parts.append(f'Friendly: "{data["friendly_name"]}"')
        if data.get("txt_manufacturer"):
            txt_parts.append(f"Mfr: {data['txt_manufacturer']}")
        if txt_parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(txt_parts)}[/yellow]")

    elif packet.protocol == "ssdp":
        parts = []
        if data.get("server"):
            parts.append(f"Server: {data['server']}")
        if data.get("st"):
            parts.append(f"ST: {data['st']}")
        if data.get("ssdp_type"):
            parts.append(f"Type: {data['ssdp_type']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        if data.get("usn"):
            console.print(f"{_INDENT}[yellow]USN: {data['usn']}[/yellow]")
        if data.get("location"):
            console.print(f"{_INDENT}[yellow]Location: {data['location']}[/yellow]")

    elif packet.protocol == "netbios":
        qtype = data.get("query_type", "").upper()
        console.print(f"{_INDENT}[yellow]{qtype}:[/yellow] {data.get('query_name')}")
        if data.get("netbios_suffix") is not None:
            console.print(f"{_INDENT}[yellow]Suffix:[/yellow] 0x{data['netbios_suffix']:02X}")

    elif packet.protocol == "tls":
        ja3 = data.get("ja3_hash", "")
        ja4 = data.get("ja4", "")
        tls_ver = data.get("tls_version", "")
        sni = data.get("sni", "")
        console.print(
            f"{_INDENT}[yellow]JA3:[/yellow] {ja3}  "
            f"[yellow]JA4:[/yellow] {ja4}"
        )
        line_parts = []
        if tls_ver:
            line_parts.append(f"[yellow]TLS:[/yellow] {tls_ver}")
        if sni:
            line_parts.append(f"[yellow]SNI:[/yellow] {sni}")
        if line_parts:
            console.print(f"{_INDENT}{'  '.join(line_parts)}")

    elif packet.protocol == "icmpv6":
        icmp_type = data.get("icmpv6_type", "")
        type_display = icmp_type.replace("_", " ").title()
        line = f"{_INDENT}[yellow]Type:[/yellow] {type_display}"
        if data.get("hop_limit"):
            line += f"  [yellow]Hop Limit:[/yellow] {data['hop_limit']}"
        if data.get("target"):
            line += f"  [yellow]Target:[/yellow] {data['target']}"
        console.print(line)
        # Show flags for RA and NA
        flag_parts = []
        if data.get("managed"):
            flag_parts.append("Managed")
        if data.get("other"):
            flag_parts.append("Other")
        if data.get("router"):
            flag_parts.append("Router")
        if data.get("solicited"):
            flag_parts.append("Solicited")
        if data.get("override"):
            flag_parts.append("Override")
        if flag_parts:
            console.print(f"{_INDENT}[yellow]Flags:[/yellow] {', '.join(flag_parts)}")

    elif packet.protocol == "banner":
        banner_text = data.get("banner", "")
        if banner_text:
            # Truncate long banners
            display = banner_text[:120] + ("..." if len(banner_text) > 120 else "")
            console.print(f"{_INDENT}[yellow]Banner:[/yellow] {display}")

    elif packet.protocol == "ip_observed":
        ttl = data.get("ttl", "?")
        os_hint = data.get("ttl_os_hint", "")
        hops = data.get("ttl_hops", "")
        src_port = data.get("src_port")
        dst_port = data.get("dst_port")
        hint_str = f" ({os_hint}, {hops} hops)" if os_hint else ""
        port_str = ""
        if src_port and dst_port:
            port_str = f"  Port: {src_port} -> {dst_port}"
        console.print(f"{_INDENT}[yellow]TTL: {ttl}{hint_str}{port_str}[/yellow]")

    elif packet.protocol == "http_useragent":
        method = data.get("method", "")
        path = data.get("path", "")
        host = data.get("host", "")
        ua = data.get("user_agent", "")
        parts = []
        if method:
            parts.append(method)
        if path:
            parts.append(path)
        if host:
            parts.append(f"Host: {host}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        if ua:
            display_ua = ua[:120] + ("..." if len(ua) > 120 else "")
            console.print(f"{_INDENT}[yellow]UA: {display_ua}[/yellow]")

    elif packet.protocol == "dns_answer":
        qname = data.get("query_name", "?")
        rtype = data.get("record_type", "?")
        answer_ip = data.get("answer_ip", "")
        hostname = data.get("hostname", "")
        ttl = data.get("ttl", "")
        target = answer_ip or hostname or "?"
        ttl_str = f"  TTL: {ttl}" if ttl else ""
        console.print(
            f"{_INDENT}[yellow]{qname}  {rtype} -> {target}{ttl_str}[/yellow]"
        )

    # ── Evidence from fingerprint matches ──
    for i, match in enumerate(matches):
        is_last = i == len(matches) - 1
        prefix = "└─" if is_last else "├─"
        conf_pct = int(match.confidence * 100)
        style = _conf_style(conf_pct)

        parts = []
        if match.manufacturer:
            parts.append(f"[white]manufacturer=[/white]{match.manufacturer}")
        if match.os_family:
            parts.append(f"[white]os=[/white]{match.os_family}")
        if match.device_type:
            parts.append(f"[white]type=[/white]{match.device_type}")
        if match.model:
            parts.append(f"[white]model=[/white]{match.model}")
        detail = ", ".join(parts) if parts else match.match_type
        console.print(
            f"{_INDENT}  {prefix} [cyan]{match.source}[/cyan]: "
            f"{detail} [{style}]({conf_pct}%)[/{style}]"
        )

    # Alerts
    for alert in alerts:
        severity_colors = {
            "info": "blue",
            "low": "bright_yellow",
            "warning": "yellow",
            "medium": "yellow",
            "high": "bright_red",
            "critical": "bold bright_red",
        }
        color = severity_colors.get(alert.severity, "white")
        sev_label = str(alert.severity).upper()
        console.print(
            f"{_INDENT}[{color}]▲ {sev_label} {alert.alert_type}: "
            f"{alert.message}[/{color}]"
        )

    # Full protocol decode
    if decode and packet.raw_bytes:
        hex_str = packet.raw_bytes[:64].hex()
        suffix = "..." if len(packet.raw_bytes) > 64 else ""
        console.print(f"{_INDENT}[dim white]RAW: {hex_str}{suffix}[/dim white]")

    console.print()  # blank line


def _matches_filter(event: dict, packet_filter: str) -> bool:
    """Check if event matches the user's --filter."""
    packet = event["packet"]
    if packet_filter.startswith("mac="):
        return packet.src_mac.upper().startswith(packet_filter[4:].upper())
    return packet.protocol == packet_filter
