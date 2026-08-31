#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Sign official package manifests for downloads.bitcoinpurity.org.

The client verifies a detached ECDSA signature over SHA-256 of the manifest JSON
with the top-level "signature" field removed (keys sorted lexicographically when
re-serialized, matching UniValue::write()).

Usage:
  ./sign-manifest.py --generate-keypair
  ./sign-manifest.py --show-pubkey --key manifest-sign.pem
  ./sign-manifest.py --sign official-packages-mainnet.json --key manifest-sign.pem
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def canonicalize(value):
    if isinstance(value, dict):
        return {key: canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    return value


def canonical_payload(manifest: dict) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(canonicalize(unsigned), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(manifest: dict) -> bytes:
    return hashlib.sha256(canonical_payload(manifest)).digest()


def run_openssl(args: list[str], input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(["openssl", *args], input=input_bytes)


def generate_keypair(path: Path) -> None:
    run_openssl(["ecparam", "-name", "secp256k1", "-genkey", "-noout", "-out", str(path)])
    print(f"Wrote private key to {path}")
    print("Update OFFICIAL_PACKAGES_SIGNING_PUBKEY_HEX in src/kernel/official_packages.cpp:")
    print(show_pubkey(path))


def show_pubkey(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(
            f"error: private key not found: {path}\n"
            f"Generate one first with: {sys.argv[0]} --generate-keypair"
        )
    text = run_openssl(["ec", "-in", str(path), "-text", "-noout"]).decode("utf-8")
    pub_lines = []
    in_pub = False
    for line in text.splitlines():
        if line.strip().startswith("pub:"):
            in_pub = True
            continue
        if in_pub:
            if not line.strip() or ":" in line and "ASN1" in line:
                break
            pub_lines.extend(part for part in line.strip().split(":") if part)
    pub_bytes = bytes(int(part, 16) for part in pub_lines)
    if pub_bytes[0] != 0x04:
        raise SystemExit("expected uncompressed secp256k1 pubkey from openssl")
    x = int.from_bytes(pub_bytes[1:33], "big")
    y = int.from_bytes(pub_bytes[33:65], "big")
    prefix = 0x02 if y % 2 == 0 else 0x03
    compressed = bytes([prefix]) + x.to_bytes(32, "big")
    hex_pubkey = compressed.hex()
    print(hex_pubkey)
    return hex_pubkey


def sign_manifest(path: Path, key_path: Path) -> None:
    if not path.is_file():
        raise SystemExit(
            f"error: manifest file not found: {path}\n"
            "Pass the path to the manifest JSON you want to sign, e.g.\n"
            f"  {sys.argv[0]} --sign /path/to/official-packages-mainnet.json --key {key_path}"
        )
    if not key_path.is_file():
        raise SystemExit(
            f"error: private key not found: {key_path}\n"
            f"Generate one first with: {sys.argv[0]} --generate-keypair"
        )
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"error: {path} is not valid JSON: {e}")
    if not isinstance(manifest, dict):
        raise SystemExit(f"error: {path} must contain a top-level JSON object")
    if "signature" in manifest:
        manifest = {key: value for key, value in manifest.items() if key != "signature"}
    # pkeyutl signs the provided digest directly; `dgst -sign` would hash the
    # input again, which does not match CPubKey::Verify() on the client.
    signature = run_openssl(
        ["pkeyutl", "-sign", "-inkey", str(key_path)], input_bytes=digest(manifest))
    manifest["signature"] = base64.b64encode(signature).decode("ascii")
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Signed {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-keypair", metavar="PATH", nargs="?", const="manifest-sign.pem")
    parser.add_argument("--show-pubkey", action="store_true")
    parser.add_argument("--sign", metavar="MANIFEST")
    parser.add_argument("--key", metavar="PATH", default="manifest-sign.pem")
    args = parser.parse_args()

    if args.generate_keypair:
        generate_keypair(Path(args.generate_keypair))
        return 0
    if args.show_pubkey:
        show_pubkey(Path(args.key))
        return 0
    if args.sign:
        sign_manifest(Path(args.sign), Path(args.key))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
