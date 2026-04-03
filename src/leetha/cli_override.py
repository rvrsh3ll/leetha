"""Manage manual attribute overrides for discovered devices.

Provides the async entry point for the 'override' CLI subcommand,
allowing users to inspect, apply, and remove per-device field overrides.
"""

from __future__ import annotations

import json

from leetha.config import get_config
from leetha.store.database import Database


async def handle_device_override(parsed_args):
    """Process the device-override subcommand dispatched from the CLI.

    Connects to the backing store, routes to the requested action
    (display_all / inspect / apply / reset), then tears down the
    database connection.
    """
    cfg = get_config()
    storage = Database(cfg.db_path)
    await storage.initialize()

    try:
        cmd = parsed_args.override_action

        if cmd == "list":
            all_devices = await storage.list_devices()
            with_overrides = [
                rec for rec in all_devices if rec.manual_override
            ]
            if not with_overrides:
                print("No device overrides configured.")
                return
            print(f"{'MAC':<20s} {'Override'}")
            print("-" * 60)
            for rec in with_overrides:
                print(f"{rec.mac:<20s} {json.dumps(rec.manual_override)}")

        elif cmd == "show":
            node = await storage.get_device(parsed_args.mac)
            if node is None:
                print(f"Device {parsed_args.mac} not found.")
                return
            if node.manual_override:
                print(json.dumps(node.manual_override, indent=2))
            else:
                print(f"No override set for {parsed_args.mac}.")

        elif cmd == "set":
            node = await storage.get_device(parsed_args.mac)
            if node is None:
                print(f"Device {parsed_args.mac} not found.")
                return

            overrides = {}
            if parsed_args.device_type:
                overrides["device_type"] = parsed_args.device_type
            if parsed_args.manufacturer:
                overrides["manufacturer"] = parsed_args.manufacturer
            if parsed_args.os_family:
                overrides["os_family"] = parsed_args.os_family
            if parsed_args.os_version:
                overrides["os_version"] = parsed_args.os_version

            if not overrides:
                print(
                    "No override fields provided. Use --device-type, "
                    "--manufacturer, --os-family, or --os-version."
                )
                return

            node.manual_override = overrides
            for attr_name in ("device_type", "manufacturer", "os_family", "os_version"):
                attr_val = overrides.get(attr_name)
                if attr_val is not None:
                    setattr(node, attr_name, attr_val)

            await storage.upsert_device(node)
            print(f"Override set for {parsed_args.mac}: {json.dumps(overrides)}")

        elif cmd == "clear":
            node = await storage.get_device(parsed_args.mac)
            if node is None:
                print(f"Device {parsed_args.mac} not found.")
                return
            node.manual_override = None
            await storage.upsert_device(node)
            print(f"Override cleared for {parsed_args.mac}.")

        else:
            print("Usage: leetha override {list|show|set|clear} [mac]")
    finally:
        await storage.close()


# Backward-compatible alias
run_override = handle_device_override
