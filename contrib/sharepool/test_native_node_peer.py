#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Local RPC/gate boundary; native P2P and consensus have functional tests."""
import unittest
from unittest.mock import patch

import native_node_peer as relay
from native_enforcement import RULES_HASH, solve_share
from native_mining_gate import REGTEST_GENESIS, RecoveryRequired, parse_block, parse_share, template_id
from test_native_peer import FakeGate as MemoryGate, fixture


class Gate(MemoryGate):
    def base_template(self):
        self.check()
        return {"sharepool": {"activation_height": 1}}

    def maintenance(self):
        return {key: value for key, value in self.active_inventory().items() if key != "items"}

    def receive(self, raw):
        if ("template", template_id(parse_share(raw).header)) not in self.saved:
            raise ValueError("full origin required")
        return super().receive(raw)


class Node:
    def __init__(self):
        self.store, self.calls = Gate({}), []

    def inventory(self):
        source = self.store.active_inventory()
        items = []
        for item in source["items"]:
            raw = self.store.saved[(item["kind"], item["id"])]
            header = parse_block(raw) if item["kind"] == "template" else parse_share(raw).header
            items.append(dict(item, template_id=template_id(header)))
        return {"enabled": True, "pool": f"{3:064x}", "genesis": REGTEST_GENESIS,
                "rules": f"{RULES_HASH:064x}", "activation_height": 1,
                "tip": source["tip"], "height": 0, "revision": self.store.revision, "items": items}

    def __call__(self, method, *args):
        self.calls.append((method, args))
        if method == "setsharepoolrelay":
            return args == (f"{3:064x}",)
        if method == "getsharepoolinventory":
            return self.inventory()
        if method == "getsharepoolobject":
            item = next(item for item in self.inventory()["items"] if (item["kind"], item["id"]) == args)
            return dict(item, data=self.store.saved[args].hex())
        if method == "submitsharepoolevidence":
            kind, encoded = args
            raw = bytes.fromhex(encoded)
            if kind == "template":
                identity = self.store.register_template(raw)
            else:
                self.store.receive(raw)
                identity = f"{parse_share(raw).proof_id:064x}"
            return {"kind": kind, "id": identity}
        raise AssertionError("unexpected node RPC")


class NativeNodeRelayTests(unittest.TestCase):
    def setUp(self):
        self.node, self.gate = Node(), Gate({})
        self.gate.rpc = self.node
        self.bridge = relay.NativeNodeRelay(self.gate)

    def populate(self, gate, time=1800000000):
        block, manifest = fixture(time)
        gate.register_template(block.serialize())
        proof = solve_share(block, manifest)
        gate.receive(proof.serialize())
        return block, proof

    def test_bidirectional_ordering_and_idempotent_receipts(self):
        self.populate(self.gate)
        self.populate(self.node.store, 1800000001)
        result = self.bridge.poll()
        self.assertEqual([result[k] for k in ("published_templates", "published_receipts", "templates", "receipts")], [1, 1, 1, 1])
        self.assertEqual(self.gate.saved, self.node.store.saved)
        before = self.gate.revision
        self.assertEqual(self.bridge.poll()["transferred_bytes"], 0)
        self.assertEqual(self.gate.revision, before)

    def test_object_budget_defers_receipts_until_origins_are_admitted(self):
        self.populate(self.node.store)
        with patch.object(relay, "MAX_OBJECTS", 1):
            result = self.bridge.poll()
        self.assertEqual((result["templates"], result["receipts"], result["deferred_objects"]), (1, 0, 1))
        self.assertEqual(self.bridge.poll()["receipts"], 1)

    def test_bad_receipt_digest_keeps_valid_origin_progress(self):
        self.populate(self.node.store)
        original = self.node.inventory
        def wrong():
            result = original()
            for item in result["items"]:
                if item["kind"] == "receipt":
                    item["sha256"] = "00" * 32
            return result
        with patch.object(self.node, "inventory", side_effect=wrong):
            with self.assertRaisesRegex(relay.NodeRelayError, "digest"):
                self.bridge.poll()
        self.assertEqual({kind for kind, unused in self.gate.saved}, {"template"})
        self.assertEqual(self.bridge.poll()["receipts"], 1)

    def test_profile_duplicates_and_boolean_integer_fields_are_refused(self):
        self.populate(self.node.store)
        original = self.node.inventory
        changes = [lambda r: r.update(pool="ab" * 32),
                   lambda r: r.update(height=False),
                   lambda r: r.update(activation_height=True),
                   lambda r: r["items"].append(r["items"][0]),
                   lambda r: r["items"][0].update(bytes=True),
                   lambda r: next(item for item in r["items"] if item["kind"] == "template").update(template_id="ff" * 32)]
        for change in changes:
            def wrong(change=change):
                result = original()
                change(result)
                return result
            with self.subTest(change=change), patch.object(self.node, "inventory", side_effect=wrong):
                with self.assertRaises(relay.NodeRelayError):
                    self.bridge.poll()
        self.assertEqual(self.gate.saved, {})

    def test_missing_full_origin_cannot_receive_durable_credit(self):
        unused, proof = self.populate(self.node.store)
        self.node.store.saved = {key: raw for key, raw in self.node.store.saved.items() if key[0] == "receipt"}
        with self.assertRaisesRegex(ValueError, "full origin"):
            self.bridge.poll()
        self.assertEqual(self.gate.revision, 0)

    def test_native_tip_change_and_local_recovery_stop_polling(self):
        original = self.node.inventory
        def moved():
            result = original()
            result["tip"] = "aa" * 32
            return result
        with patch.object(self.node, "inventory", side_effect=moved):
            with self.assertRaisesRegex(relay.NodeRelayError, "tip changed"):
                self.bridge.poll()
        count = len(self.node.calls)
        with patch.object(self.gate, "active_inventory", side_effect=RecoveryRequired("fixture recovery")):
            with self.assertRaises(RecoveryRequired):
                self.bridge.poll()
        self.assertEqual(len(self.node.calls), count)

    def test_local_publication_budget_never_forgets_acknowledged_work(self):
        self.populate(self.gate)
        before = dict(self.gate.saved)
        with patch.object(relay, "MAX_BYTES", 1):
            result = self.bridge.poll()
        self.assertEqual(result["deferred_objects"], 2)
        self.assertEqual(self.gate.saved, before)
        self.assertEqual(self.node.store.saved, {})
        self.assertEqual(self.bridge.poll()["published_receipts"], 1)


if __name__ == "__main__":
    unittest.main()
