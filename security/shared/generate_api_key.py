#!/usr/bin/env python3
"""
API Key generation utility for the Kimi ecosystem.
"""

import argparse
import hashlib
import secrets
import sys
from pathlib import Path

import yaml


def generate_api_key(key_id: str, role: str = "viewer") -> str:
    """Generate a new API key."""
    # Generate a secure random key
    raw_key = f"kimi_{secrets.token_urlsafe(32)}"
    
    # Hash the key for storage
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    
    return raw_key, hashed_key


def add_key_to_config(config_path: Path, key_id: str, hashed_key: str, role: str) -> None:
    """Add a key to the security configuration file."""
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    
    if "api_keys" not in config:
        config["api_keys"] = {}
    
    config["api_keys"][key_id] = {
        "hash": hashed_key,
        "role": role,
    }
    
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def main():
    parser = argparse.ArgumentParser(description="Generate API keys for Kimi services")
    parser.add_argument("key_id", help="Unique identifier for this key")
    parser.add_argument(
        "--role",
        choices=["admin", "operator", "viewer"],
        default="viewer",
        help="Role for this key (default: viewer)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("security.yaml"),
        help="Path to security configuration file",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save the key to config file, just print it",
    )
    
    args = parser.parse_args()
    
    raw_key, hashed_key = generate_api_key(args.key_id, args.role)
    
    print(f"Generated API Key for '{args.key_id}' (role: {args.role})")
    print()
    print("=" * 60)
    print("API KEY (save this - it won't be shown again):")
    print("=" * 60)
    print(raw_key)
    print("=" * 60)
    print()
    print(f"Hashed key: {hashed_key}")
    
    if not args.no_save:
        if args.config.exists():
            add_key_to_config(args.config, args.key_id, hashed_key, args.role)
            print(f"\nKey saved to {args.config}")
        else:
            print(f"\nWarning: Config file {args.config} not found. Key not saved.")
            print("Use --no-save to suppress this warning.")
    
    print()
    print("Usage:")
    print(f'  curl -H "X-API-Key: {raw_key}" https://localhost:8000/health')


if __name__ == "__main__":
    main()