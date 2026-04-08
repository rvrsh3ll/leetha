"""Manage manual attribute overrides for discovered devices.

Provides the async entry point for the 'override' CLI subcommand,
allowing users to inspect, apply, and remove per-device field overrides.
"""

from __future__ import annotations

import json

from leetha.config import get_config
from leetha.store.store import Store


async def handle_device_override(parsed_args):
    """Process the device-override subcommand."""
    cfg = get_config()
    store = Store(cfg.db_path)
    await store.initialize()

    try:
        cmd = parsed_args.override_action

        if cmd == "list":
            overrides = await store.overrides.find_all()
            if not overrides:
                print("No device overrides configured.")
                return
            print(f"{'MAC':<20s} {'Override'}")
            print("-" * 60)
            for o in overrides:
                mac = o.pop("hw_addr")
                o.pop("updated_at", None)
                fields = {k: v for k, v in o.items() if v is not None}
                print(f"{mac:<20s} {json.dumps(fields)}")

        elif cmd == "show":
            override = await store.overrides.find_by_addr(parsed_args.mac)
            if override:
                print(json.dumps(override, indent=2))
            else:
                print(f"No override set for {parsed_args.mac}.")

        elif cmd == "set":
            verdict = await store.verdicts.find_by_addr(parsed_args.mac)
            host = await store.hosts.find_by_addr(parsed_args.mac)
            if not verdict and not host:
                print(f"Device {parsed_args.mac} not found.")
                return

            overrides = {}
            for field in ("device_type", "manufacturer", "os_family",
                          "os_version", "model", "hostname",
                          "connection_type", "disposition", "notes"):
                val = getattr(parsed_args, field, None)
                if val is not None:
                    overrides[field] = val

            if not overrides:
                print(
                    "No override fields provided. Use --device-type, "
                    "--manufacturer, --os-family, --os-version, --model, "
                    "--hostname, --connection-type, --disposition, or --notes."
                )
                return

            await store.overrides.upsert(parsed_args.mac, overrides)

            if "disposition" in overrides and host:
                host.disposition = overrides["disposition"]
                await store.hosts.upsert(host)

            print(f"Override set for {parsed_args.mac}: {json.dumps(overrides)}")

        elif cmd == "clear":
            override = await store.overrides.find_by_addr(parsed_args.mac)
            if not override:
                print(f"No override set for {parsed_args.mac}.")
                return

            if override.get("disposition"):
                host = await store.hosts.find_by_addr(parsed_args.mac)
                if host and host.disposition != "self":
                    host.disposition = "new"
                    await store.hosts.upsert(host)

            await store.overrides.delete(parsed_args.mac)
            print(f"Override cleared for {parsed_args.mac}.")

        else:
            print("Usage: leetha override {list|show|set|clear} [mac]")
    finally:
        await store.close()


# Backward-compatible alias
run_override = handle_device_override
