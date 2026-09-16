#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bridge a durable miner gate to evidence relayed by its own Bitcoin node.

Remote transport stays inside the node's existing P2P connections. This module
uses only the caller's bounded, authenticated local node RPC. The native relay
cache is ephemeral; every downloaded object still passes the miner gate before
the miner acknowledges it or uses it to authorize work.
"""
import hashlib
import re

from native_enforcement import RULES_HASH
from native_mining_gate import REGTEST_GENESIS, parse_block, parse_share, template_id

MAX_OBJECTS = 32
MAX_BYTES = 16_000_000
HEX = re.compile(r"[0-9a-f]{64}\Z")


class NodeRelayError(ValueError):
    pass


def require(test, message):
    if not test:
        raise NodeRelayError(message)


def _hex(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


class NativeNodeRelay:
    def __init__(self, gate):
        self.gate, self.rpc, self.pool = gate, gate.rpc, gate.pool
        # Explicit construction opts this local node into one pool's relay.
        self.profile = gate.base_template()["sharepool"]
        require(self.rpc("setsharepoolrelay", f"{self.pool:064x}") is True,
                "native node did not enable evidence relay")

    def _inventory(self):
        result = self.rpc("getsharepoolinventory")
        require(type(result) is dict and set(result) == {
            "enabled", "pool", "genesis", "rules", "activation_height", "tip",
            "height", "revision", "items"}, "invalid native relay inventory")
        require(result["enabled"] is True and result["pool"] == f"{self.pool:064x}" and
                result["genesis"] == REGTEST_GENESIS and result["rules"] == f"{RULES_HASH:064x}" and
                type(result["activation_height"]) is int and
                result["activation_height"] == self.profile["activation_height"] and
                _hex(result["tip"]) and _integer(result["height"], 0, 0x7ffffffe) and
                _integer(result["revision"], 0, (1 << 64) - 1) and
                type(result["items"]) is list and len(result["items"]) <= 256,
                "wrong native relay profile or bounds")
        seen, counts = set(), {"template": 0, "receipt": 0}
        for item in result["items"]:
            require(type(item) is dict and set(item) == {"kind", "id", "sha256", "bytes",
                "origin_height", "origin_parent", "template_id"}, "invalid native object descriptor")
            kind = item["kind"]
            require(type(kind) is str and kind in counts and
                    all(_hex(item[key]) for key in ("id", "sha256", "origin_parent", "template_id")) and
                    _integer(item["bytes"], 1, 4_000_000 if kind == "template" else 1024) and
                    _integer(item["origin_height"], max(1, result["height"] - 2), result["height"] + 1),
                    "invalid native evidence context")
            require(kind != "template" or item["template_id"] == item["id"], "native template identity mismatch")
            identity = (kind, item["id"])
            require(identity not in seen, "duplicate native inventory identity")
            seen.add(identity)
            counts[kind] += 1
            require(counts[kind] <= 128, "native relay kind count exceeds bound")
        return result

    def _body(self, item):
        result = self.rpc("getsharepoolobject", item["kind"], item["id"])
        require(type(result) is dict and set(result) == set(item) | {"data"} and
                all(result[key] == value for key, value in item.items()), "native object descriptor changed")
        encoded = result["data"]
        require(type(encoded) is str and len(encoded) == item["bytes"] * 2 and
                re.fullmatch(r"[0-9a-f]+", encoded), "invalid native object encoding")
        raw = bytes.fromhex(encoded)
        require(hashlib.sha256(raw).hexdigest() == item["sha256"], "native object digest mismatch")
        if item["kind"] == "template":
            block = parse_block(raw)
            identity, origin_id = template_id(block), template_id(block)
            height, parent = block.m_height, block.hashPrevBlock
        else:
            share = parse_share(raw)
            identity, origin_id = f"{share.proof_id:064x}", template_id(share.header)
            height, parent = share.envelope.height, share.header.hashPrevBlock
        require((identity, origin_id, height, f"{parent:064x}") ==
                (item["id"], item["template_id"], item["origin_height"], item["origin_parent"]),
                "native object identity mismatch")
        return raw

    def poll(self):
        """One bounded bidirectional pass; never claims complete disclosure.

        Exceptions, including RecoveryRequired, propagate to the local operator.
        Partial admitted work remains durable. Exact retries are idempotent.
        """
        local = self.gate.active_inventory()
        remote = self._inventory()
        require((local["tip"], local["height"]) == (remote["tip"], remote["height"]),
                "native tip changed before evidence exchange")
        result = {"status": "progress", "published_templates": 0, "published_receipts": 0,
                  "templates": 0, "receipts": 0, "duplicate_receipts": 0,
                  "transferred_bytes": 0, "deferred_objects": 0, "native_tip": local["tip"]}
        used = 0
        known_node = {(item["kind"], item["id"]) for item in remote["items"]}
        templates_deferred = False
        for item in sorted(local["items"], key=lambda x: (x["kind"] != "template", x["id"])):
            if (item["kind"], item["id"]) in known_node:
                continue
            if (used >= MAX_OBJECTS or result["transferred_bytes"] + item["bytes"] > MAX_BYTES or
                    (item["kind"] == "receipt" and templates_deferred)):
                result["deferred_objects"] += 1
                templates_deferred |= item["kind"] == "template"
                continue
            raw = (self.gate.template_bytes if item["kind"] == "template" else self.gate.receipt_bytes)(item["id"])
            require(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"],
                    "local evidence changed during publication")
            reply = self.rpc("submitsharepoolevidence", item["kind"], raw.hex())
            require(reply == {"kind": item["kind"], "id": item["id"]}, "native publication identity mismatch")
            result["published_templates" if item["kind"] == "template" else "published_receipts"] += 1
            result["transferred_bytes"] += len(raw)
            used += 1
        remote = self._inventory()
        require((local["tip"], local["height"]) == (remote["tip"], remote["height"]),
                "native tip changed during evidence exchange")
        known_gate = {(item["kind"], item["id"]) for item in local["items"]}
        templates_deferred = False
        for item in sorted(remote["items"], key=lambda x: (x["kind"] != "template", x["id"])):
            if (item["kind"], item["id"]) in known_gate:
                continue
            if (used >= MAX_OBJECTS or result["transferred_bytes"] + item["bytes"] > MAX_BYTES or
                    (item["kind"] == "receipt" and templates_deferred)):
                result["deferred_objects"] += 1
                templates_deferred |= item["kind"] == "template"
                continue
            raw = self._body(item)
            if item["kind"] == "template":
                self.gate.register_template(raw)
                result["templates"] += 1
            else:
                admitted = self.gate.receive(raw)
                result["receipts" if admitted else "duplicate_receipts"] += 1
            result["transferred_bytes"] += len(raw)
            used += 1
        require(self.gate.maintenance()["tip"] == local["tip"], "native tip changed before exchange finished")
        return result
