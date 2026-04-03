"""Manage trusted MAC-to-IP bindings via the CLI.

Exposes the async handler for the 'trust' subcommand, which lets
operators pin known-good address pairs into the backing store.
"""

from __future__ import annotations

import argparse

from leetha.store.database import Database


async def handle_trust_binding(
    parsed_args: argparse.Namespace,
    storage: Database,
) -> None:
    """Route the trust subcommand to the correct store operation.

    Supports adding, removing, and listing trusted MAC/IP bindings.
    """
    cmd = getattr(parsed_args, "trust_action", None)

    if cmd == "add":
        normalized_mac = parsed_args.mac.lower()
        await storage.add_trusted_binding(
            mac=normalized_mac,
            ip=parsed_args.ip,
            source="manual",
            interface=None,
        )
        print(f"Trusted binding added: {normalized_mac} -> {parsed_args.ip}")

    elif cmd == "remove":
        normalized_mac = parsed_args.mac.lower()
        await storage.remove_trusted_binding(normalized_mac)
        print(f"Trusted binding removed: {normalized_mac}")

    elif cmd == "list" or cmd is None:
        rows = await storage.list_trusted_bindings()
        if not rows:
            print("No trusted bindings configured.")
            return
        print(f"{'MAC':<20s} {'IP':<18s} {'Source':<15s} {'Since':<20s}")
        print("-" * 73)
        for row in rows:
            ts = row["created_at"][:19] if row["created_at"] else "\u2014"
            print(
                f"{row['mac']:<20s} {row['ip']:<18s} "
                f"{row['source']:<15s} {ts:<20s}"
            )


# Backward-compatible alias
run_trust = handle_trust_binding
