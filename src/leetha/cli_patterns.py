"""Manage user-defined fingerprint patterns via the CLI.

Provides the async entry point for the 'patterns' subcommand, supporting
listing, creation, deletion, export, and import of custom pattern rules.
"""

from __future__ import annotations

import json
import sys

from leetha.config import get_config
from leetha.fingerprint.lookup import load_custom_patterns, save_custom_patterns


async def handle_patterns(parsed_args):
    """Dispatch the patterns subcommand to the appropriate action handler.

    Reads or mutates the custom-patterns store based on the requested
    action (display / create / delete / dump / ingest).
    """
    cfg = get_config()
    storage_dir = cfg.data_dir

    action = parsed_args.patterns_action

    if action == "list":
        rules = load_custom_patterns(storage_dir)
        if not rules:
            print("No custom patterns defined.")
            return
        print(json.dumps(rules, indent=2))

    elif action == "add":
        rules = load_custom_patterns(storage_dir)

        new_rule = {
            "device_type": parsed_args.device_type,
            "confidence": parsed_args.confidence,
        }
        if parsed_args.manufacturer:
            new_rule["manufacturer"] = parsed_args.manufacturer
        if parsed_args.os_family:
            new_rule["os_family"] = parsed_args.os_family

        kind = parsed_args.pattern_type

        if kind in ("hostname", "dhcp_opt60"):
            if not parsed_args.pattern:
                print(
                    f"Error: --pattern is required for {kind} patterns."
                )
                return
            new_rule["pattern"] = parsed_args.pattern
            rules.setdefault(kind, []).append(new_rule)

        elif kind == "dhcp_opt55":
            if not parsed_args.key:
                print("Error: --key is required for dhcp_opt55 patterns.")
                return
            rules.setdefault("dhcp_opt55", {})[parsed_args.key] = new_rule

        elif kind == "mac_prefix":
            if not parsed_args.key:
                print("Error: --key is required for mac_prefix patterns (MAC prefix).")
                return
            rules.setdefault("mac_prefix", {})[parsed_args.key] = new_rule

        save_custom_patterns(storage_dir, rules)
        print(f"Pattern added to {kind}.")

    elif action == "remove":
        rules = load_custom_patterns(storage_dir)
        kind = parsed_args.pattern_type
        if kind not in rules:
            print(f"No patterns of type '{kind}'.")
            return

        position = int(parsed_args.index)
        collection = rules[kind]

        if isinstance(collection, list):
            if position < 0 or position >= len(collection):
                print(f"Index {position} out of range (0-{len(collection)-1}).")
                return
            deleted = collection.pop(position)
            print(f"Removed: {json.dumps(deleted)}")

        elif isinstance(collection, dict):
            ordered_keys = list(collection.keys())
            if position < 0 or position >= len(ordered_keys):
                print(f"Index {position} out of range (0-{len(ordered_keys)-1}).")
                return
            target_key = ordered_keys[position]
            deleted = collection.pop(target_key)
            print(f"Removed key '{target_key}': {json.dumps(deleted)}")

        save_custom_patterns(storage_dir, rules)

    elif action == "export":
        rules = load_custom_patterns(storage_dir)
        print(json.dumps(rules, indent=2))

    elif action == "import":
        if parsed_args.file:
            with open(parsed_args.file) as fh:
                incoming = json.load(fh)
        else:
            incoming = json.load(sys.stdin)

        save_custom_patterns(storage_dir, incoming)
        print("Patterns imported.")

    else:
        print("Usage: leetha patterns {list|add|remove|export|import}")


# Backward-compatible alias
run_patterns = handle_patterns
