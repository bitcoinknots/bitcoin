#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Transport faults/limits; real native admission is a separate functional test."""
import hashlib
import socket
import threading
import time
import unittest
from unittest.mock import patch

import native_peer as peer
from native_enforcement import candidate, solve_share
from native_mining_gate import REGTEST_GENESIS, RecoveryRequired, parse_block, parse_share, template_id
from test_framework.authproxy import JSONRPCException


SECRET = (1).to_bytes(32, "big")
SCRIPT = b"\x00\x14" + b"T" * 20


def fixture(ntime=1800000000):
    return candidate(genesis=int(REGTEST_GENESIS, 16), native_parent=int(REGTEST_GENESIS, 16),
                     height=1, ntime=ntime, pool=3, secret=SECRET, payout_script=SCRIPT)


class FakeGate:
    """No consensus claim: this checks transport ordering and owning threads."""
    def __init__(self, saved):
        self.owner = threading.get_ident()
        self.pool, self.saved, self.revision = 3, saved, 0
        self.closed = False

    def check(self):
        assert threading.get_ident() == self.owner and not self.closed

    def base_template(self):
        self.check()

    def register_template(self, raw):
        self.check()
        identity = template_id(parse_block(raw))
        self.saved[("template", identity)] = raw
        return identity

    def receive(self, raw):
        self.check()
        share = parse_share(raw)
        assert ("template", template_id(share.header)) in self.saved
        identity = ("receipt", f"{share.proof_id:064x}")
        fresh = identity not in self.saved
        self.saved[identity] = raw
        self.revision += int(fresh)
        return fresh

    def active_inventory(self):
        self.check()
        items = []
        for (kind, identity), raw in self.saved.items():
            header = parse_block(raw) if kind == "template" else parse_share(raw).header
            items.append({"kind": kind, "id": identity, "sha256": hashlib.sha256(raw).hexdigest(),
                          "bytes": len(raw), "origin_height": header.m_height,
                          "origin_parent": f"{header.hashPrevBlock:064x}"})
        return {"tip": REGTEST_GENESIS, "height": 0, "anchor_height": 0,
                "anchor_hash": REGTEST_GENESIS, "revision": self.revision, "pruned_through": 0,
                "items": sorted(items, key=lambda x: (x["kind"], x["id"]))}

    def template_bytes(self, identity):
        self.check()
        return self.saved[("template", identity)]

    def receipt_bytes(self, identity):
        self.check()
        return self.saved[("receipt", identity)]

    def close(self):
        self.check()
        self.closed = True


class NativePeerTests(unittest.TestCase):
    def service(self, saved=None):
        saved = {} if saved is None else saved
        result = peer.NativePeerService(lambda: FakeGate(saved))
        self.addCleanup(result.close)
        return result

    def populate(self, service, ntime=1800000000):
        block, manifest = fixture(ntime)
        service.local("register_template", block.serialize())
        proof = solve_share(block, manifest)
        service.local("receive", proof.serialize())
        return block, proof

    def test_loopback_pull_orders_full_origins_before_proofs_and_is_idempotent(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        result = peer.sync_peer(destination, source.url, 3)
        self.assertEqual((result["templates"], result["receipts"]), (1, 1))
        self.assertEqual(peer.sync_peer(destination, source.url, 3)["downloaded_bytes"], 0)
        self.assertEqual(source.local("active_inventory")["items"],
                         destination.local("active_inventory")["items"])

    def test_inventory_change_between_status_and_page_requires_retry(self):
        source = self.service()
        self.populate(source)
        client = peer.PeerClient(source.url)
        status = peer._json(client.get("/spn1/status", peer.MAX_JSON))
        self.populate(source, 1800000001)
        with self.assertRaises(peer.PeerUnavailable):
            client.get("/spn1/inventory?root={}&offset=0&limit=32".format(status["root"]), peer.MAX_JSON)

    def test_changed_digest_or_native_identity_is_never_admitted(self):
        source = self.service()
        self.populate(source)
        client = peer.PeerClient(source.url)
        unused, items = client.inventory(3)
        item = next(x for x in items if x["kind"] == "receipt")
        raw = client.object(item)
        with patch.object(client, "get", return_value=raw + b"x"):
            with self.assertRaisesRegex(peer.PeerError, "digest"):
                client.object(item)
        wrong = dict(item, id="01" * 32)
        with patch.object(client, "get", return_value=raw):
            with self.assertRaisesRegex(peer.PeerError, "identity"):
                client.object(wrong)

    def test_incomplete_withheld_object_preserves_previous_durable_progress(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        original = peer.PeerClient.object
        def withheld(client, item):
            if item["kind"] == "receipt":
                raise peer.PeerUnavailable("fixture withhold")
            return original(client, item)
        with patch.object(peer.PeerClient, "object", withheld):
            with self.assertRaises(peer.PeerUnavailable):
                peer.sync_peer(destination, source.url, 3)
        self.assertEqual([i["kind"] for i in destination.local("active_inventory")["items"]], ["template"])
        self.assertEqual(peer.sync_peer(destination, source.url, 3)["receipts"], 1)

    def test_native_chain_disagreement_prevents_all_import(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        real = destination.local
        def different(operation, *args):
            result = real(operation, *args)
            if operation == "active_inventory":
                result["tip"] = "11" * 32
            return result
        with patch.object(destination, "local", different):
            with self.assertRaisesRegex(peer.PeerUnavailable, "chains differ"):
                peer.sync_peer(destination, source.url, 3)
        self.assertEqual(destination.local("active_inventory")["items"], [])

    def test_transfer_budget_defers_proofs_until_origins_can_be_admitted(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        with patch.object(peer, "MAX_SYNC_BYTES", 100):
            result = peer.sync_peer(destination, source.url, 3)
        self.assertEqual(result["deferred_objects"], 2)
        self.assertEqual(destination.local("active_inventory")["items"], [])
        self.assertEqual(peer.sync_peer(destination, source.url, 3)["receipts"], 1)

    def test_no_network_mutation_route_or_historical_object_or_arbitrary_local_call(self):
        source = self.service()
        client = peer.PeerClient(source.url)
        with self.assertRaises(peer.PeerUnavailable):
            client.get("/spn1/object/receipt/" + "00" * 32, 1024)
        with self.assertRaises(peer.PeerError):
            source.local("close")
        host, port = peer._endpoint(source.url)
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(b"POST /spn1/submit HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            self.assertIn(b"400", sock.recv(1024).split(b"\r\n")[0])
        self.assertEqual(source.local("active_inventory")["items"], [])

    def test_peer_destination_cannot_redirect_credentials_or_use_dns_or_public_hosts(self):
        for url in ("https://127.0.0.1:1", "http://localhost:1", "http://8.8.8.8:1",
                    "http://user:secret@127.0.0.1:1", "http://127.0.0.1:1/path",
                    "http://127.0.0.1:1?next=x", "http://127.0.0.1:1#fragment"):
            with self.subTest(url=url), self.assertRaises(peer.PeerError):
                peer.PeerClient(url)

    def test_http_duplicate_lengths_and_chunking_are_rejected(self):
        for header in (b"Content-Length: 1\r\nContent-Length: 2", b"Transfer-Encoding: chunked",
                       b"Content-Encoding: gzip", b" Content-Length: 0"):
            left, right = socket.socketpair()
            try:
                left.sendall(b"HTTP/1.1 200 OK\r\n" + header + b"\r\n\r\n")
                with self.assertRaises(peer.PeerError):
                    peer._headers(right, time.monotonic() + 1)
            finally:
                left.close()
                right.close()

    def test_json_duplicate_keys_and_nonfinite_values_reject(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[[', b'"\xff"',
                     b'{"x":1.25}', b'{"x":' + b'9' * 1000 + b'}'):
            with self.subTest(data=data), self.assertRaises(peer.PeerError):
                peer._json(data)

    def test_failed_peer_backoff_preserves_fair_polling(self):
        source = self.service()
        replicator = peer.PeerReplicator(source, 3, ["http://127.0.0.1:1", "http://127.0.0.1:2"])
        with patch.object(peer, "sync_peer", side_effect=peer.PeerUnavailable("offline")):
            first, second, third = replicator.poll(), replicator.poll(), replicator.poll()
        self.assertEqual(first["status"], "retry")
        self.assertEqual(second["status"], "retry")
        self.assertNotEqual(first["peer"], second["peer"])
        self.assertEqual(third["status"], "backoff")

    def test_service_shutdown_rejects_further_work(self):
        source = self.service()
        source.close()
        with self.assertRaises(peer.PeerUnavailable):
            source.local("active_inventory")

    def test_native_rejection_is_backoff_but_local_recovery_stops_replication(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        original = destination.local
        def invalid(operation, *args):
            if operation == "register_template":
                raise JSONRPCException({"code": -26, "message": "fixture invalid template"})
            return original(operation, *args)
        replicator = peer.PeerReplicator(destination, 3, [source.url])
        with patch.object(destination, "local", invalid):
            assert replicator.poll()["status"] == "retry"
        self.assertEqual(destination.local("active_inventory")["items"], [])
        replicator = peer.PeerReplicator(destination, 3, [source.url])
        with patch.object(destination, "local", side_effect=RecoveryRequired("fixture anchor lost")):
            self.assertEqual(replicator.poll(), {"status": "recovery_required"})
        with patch.object(peer, "sync_peer", side_effect=AssertionError("must remain stopped")):
            self.assertEqual(replicator.poll(), {"status": "recovery_required"})
        self.assertEqual(replicator.schedule[source.url]["failures"], 0)

    def test_local_inventory_failure_is_not_attributed_to_remote_peer(self):
        source, destination = self.service(), self.service()
        replicator = peer.PeerReplicator(destination, 3, [source.url])
        with patch.object(destination, "local", side_effect=ValueError("fixture disk corruption")):
            self.assertEqual(replicator.poll(), {"status": "local_error"})
        self.assertEqual(replicator.schedule[source.url]["failures"], 0)

    def test_progress_and_duplicate_receipts_do_not_claim_new_credit_or_completeness(self):
        source, destination = self.service(), self.service()
        self.populate(source)
        original = destination.local
        def race(operation, *args):
            if operation == "receive":
                original(operation, *args)
            return original(operation, *args)
        replicator = peer.PeerReplicator(destination, 3, [source.url])
        with patch.object(destination, "local", race):
            result = replicator.poll()
        self.assertEqual(result["status"], "progress")
        self.assertEqual(result["receipts"], 0)
        self.assertEqual(result["duplicate_receipts"], 1)

    def test_rpc_operation_deadline_prevents_acknowledgment_after_slow_validation(self):
        saved = {}
        class SlowGate(FakeGate):
            def __init__(self):
                super().__init__(saved)
                self.rpc = lambda unused: time.sleep(0.03)
            def register_template(self, raw):
                self.rpc("validate")
                return super().register_template(raw)
        with patch.object(peer, "OPERATION_SECONDS", 0.01):
            source = peer.NativePeerService(SlowGate)
            self.addCleanup(source.close)
            block, unused = fixture()
            with self.assertRaisesRegex(peer.PeerUnavailable, "deadline"):
                source.local("register_template", block.serialize())
        self.assertEqual(saved, {})


if __name__ == "__main__":
    unittest.main()
