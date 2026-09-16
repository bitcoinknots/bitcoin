#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded SPN1 negotiation and adversarial framing on ordinary Bitcoin P2P.

The separate feature_sharepool_node test exercises valid full native objects,
miner acknowledgments, historical recovery and direct coinbase settlement.
"""
import hashlib
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from native_enforcement import candidate, solve_share
from native_mining_gate import template_id

from test_framework.messages import ser_compact_size, ser_uint256
from test_framework.p2p import MESSAGEMAP, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class EvidenceMessage:
    msgtype = b""

    def __init__(self, payload=b""):
        self.payload = payload

    def serialize(self):
        return self.payload

    def deserialize(self, stream):
        self.payload = stream.read()

    def __repr__(self):
        return f"{self.msgtype!r}({len(self.payload)} bytes)"


class Hello(EvidenceMessage):
    msgtype = b"spnhello"


class Inventory(EvidenceMessage):
    msgtype = b"spninv"


class Get(EvidenceMessage):
    msgtype = b"spnget"


class Data(EvidenceMessage):
    msgtype = b"spndata"


for message_class in (Hello, Inventory, Get, Data):
    MESSAGEMAP[message_class.msgtype] = message_class


def item(kind=1, identity=1):
    return bytes([kind]) + ser_uint256(identity)


def inventory(*items):
    return Inventory(ser_compact_size(len(items)) + b"".join(items))


def data(descriptor, offset, total, body_hash, chunk):
    return Data(descriptor + struct.pack("<II", offset, total) + ser_uint256(body_hash) +
                ser_compact_size(len(chunk)) + chunk)


class EvidencePeer(P2PInterface):
    def on_spnhello(self, message): pass
    def on_spninv(self, message): pass
    def on_spnget(self, message): pass
    def on_spndata(self, message): pass

    def count(self, command):
        with p2p_lock:
            return self.message_count[command]

    def wait_payload(self, command, payload):
        self.wait_until(lambda: command in self.last_message and
                        self.last_message[command].payload == payload)


class SharePoolRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"],
                           ["-testactivationheight=blake2b@1", "-disablewallet"]]

    def setup_network(self):
        self.setup_nodes()

    def hello(self, *, version=1, genesis=None, rules=None, pool=None, activation=1):
        return Hello(bytes([version]) + ser_uint256(self.genesis if genesis is None else genesis) +
                     ser_uint256(self.rules if rules is None else rules) +
                     ser_uint256(self.pool if pool is None else pool) + struct.pack("<I", activation))

    def peer(self, *, negotiate=True):
        peer = self.nodes[0].add_p2p_connection(EvidencePeer())
        peer.wait_payload("spnhello", self.hello().payload)
        if negotiate:
            peer.send_and_ping(self.hello())
            peer.wait_until(lambda: peer.message_count["spninv"] > 0)
        return peer

    def malformed(self, message, *, request=None):
        peer = self.peer()
        if request is not None:
            peer.send_message(inventory(request))
            peer.wait_payload("spnget", request + struct.pack("<I", 0))
        with self.nodes[0].assert_debug_log(["Disconnecting malformed SPN1 evidence"]):
            peer.send_message(message)
            peer.wait_for_disconnect()
        self.nodes[0].disconnect_p2ps()
        assert_equal(self.nodes[0].getsharepoolinventory()["items"], [])

    def run_test(self):
        node = self.nodes[0]
        profile = node.getsharepoolinventory()
        self.pool, self.genesis, self.rules = 0xdeadbeef, int(profile["genesis"], 16), int(profile["rules"], 16)
        tip = node.getbestblockhash()
        self.log.info("Relay is opt-in and can negotiate over an already established connection")
        assert_equal(profile["enabled"], False)
        early = node.add_p2p_connection(EvidencePeer())
        early.send_and_ping(self.hello())
        assert_equal(early.count("spnhello"), 0)
        assert_equal(early.count("spninv"), 0)
        assert_raises_rpc_error(-8, "nonzero pool", node.setsharepoolrelay, "0" * 64)
        node.setsharepoolrelay(f"{self.pool:064x}")
        early.wait_payload("spnhello", self.hello().payload)
        early.wait_until(lambda: early.message_count["spninv"] > 0)
        assert_raises_rpc_error(-8, "cannot change", node.setsharepoolrelay, f"{self.pool + 1:064x}")
        node.disconnect_p2ps()

        disabled = self.nodes[1].add_p2p_connection(EvidencePeer())
        disabled.send_and_ping(Hello(b"malformed but profile disabled"))
        disabled.send_and_ping(inventory(item()))
        assert_equal(disabled.count("spnhello"), 0)
        assert_equal(disabled.count("spnget"), 0)
        assert_raises_rpc_error(-8, "active regtest", self.nodes[1].setsharepoolrelay, f"{self.pool:064x}")
        self.nodes[1].disconnect_p2ps()

        self.log.info("Legacy peers and mismatching pool, genesis, rules or activation never exchange evidence")
        for override in (None, {"version": 2}, {"genesis": self.genesis + 1}, {"rules": self.rules + 1},
                         {"pool": self.pool + 1}, {"pool": 0}, {"activation": 2}):
            peer = self.peer(negotiate=False)
            if override is not None:
                peer.send_and_ping(self.hello(**override))
            peer.send_and_ping(inventory(item()))
            assert_equal(peer.count("spnget"), 0)
            assert_equal(peer.count("spninv"), 0)
            node.disconnect_p2ps()

        self.log.info("Unknown requests return bounded notfound and unsolicited bodies never enter the store")
        peer = self.peer()
        peer.send_message(Get(item() + struct.pack("<I", 0)))
        peer.wait_payload("spndata", data(item(), 0, 0, 0, b"").payload)
        peer.send_and_ping(data(item(), 0, 1, 0, b"x"))
        assert_equal(node.getsharepoolinventory()["items"], [])
        # uint256 compares serialized bytes: 256 sorts before 1, despite its
        # larger numeric/RPC-hex representation.
        peer.send_message(inventory(item(1, 256), item(1, 1)))
        peer.wait_payload("spnget", item(1, 256) + struct.pack("<I", 0))
        peer.send_message(data(item(1, 256), 0, 0, 0, b""))
        peer.wait_payload("spnget", item(1, 1) + struct.pack("<I", 0))
        peer.send_and_ping(data(item(1, 1), 0, 0, 0, b""))
        node.disconnect_p2ps()

        self.log.info("Reject malformed bounded framing before allocation or native admission")
        messages = [Hello(b""), Hello(self.hello().payload + b"x"),
                    Inventory(b"\xfd\x00\x00"), Inventory(b"\xff" + b"\xff" * 8),
                    Inventory(ser_compact_size(257)), inventory(item(), item()),
                    inventory(item(1, 1), item(1, 256)),
                    inventory(item(2), item(1)), inventory(item(0)), inventory(item(1, 0)),
                    Inventory(b"\x00x"), Get(item()), Get(item(3) + b"\x00" * 4),
                    Get(item() + struct.pack("<I", 4_000_001)), Data(b""),
                    Data(item() + b"\x00" * 40 + ser_compact_size(65537) + b"x" * 65537),
                    Data(item() + b"\x00" * 40 + b"\xfd\x00\x00")]
        for message in messages:
            self.malformed(message)
        self.malformed(data(item(), 1, 1, 0, b"x"), request=item())
        self.malformed(data(item(), 0, 4_000_001, 0, b"x" * 65536), request=item())
        self.malformed(data(item(2), 0, 1025, 0, b"x" * 1025), request=item(2))
        self.malformed(data(item(), 0, 1, 0, b"x"), request=item())
        self.malformed(data(item(), 0, 0, 1, b""), request=item())

        self.log.info("Rapid repeated negotiation consumes the control-message budget")
        peer = self.peer()
        with node.assert_debug_log(["Disconnecting malformed SPN1 evidence"]):
            for unused in range(9):
                peer.send_message(self.hello())
            peer.wait_for_disconnect()
        node.disconnect_p2ps()

        self.log.info("A complete multi-chunk invalid template reaches native validation and is refused")
        peer = self.peer()
        body = b"\x00" * 131073
        digest = int(hashlib.sha256(body).hexdigest(), 16)
        descriptor = item(1, 987)
        peer.send_message(inventory(descriptor))
        with node.assert_debug_log(["SPN1 evidence not admitted"], timeout=20):
            for offset in range(0, len(body), 65536):
                peer.wait_payload("spnget", descriptor + struct.pack("<I", offset))
                peer.send_message(data(descriptor, offset, len(body), digest, body[offset:offset + 65536]))
            peer.sync_with_ping()
        assert_equal(node.getsharepoolinventory()["items"], [])
        assert peer.is_connected
        node.disconnect_p2ps()

        self.log.info("Only eight download buffers are active globally; disconnect releases a slot")
        peers = [self.peer() for unused in range(9)]
        for index, peer in enumerate(peers):
            peer.send_and_ping(inventory(item(1, 1000 + index)))
            if index < 8:
                peer.wait_payload("spnget", item(1, 1000 + index) + struct.pack("<I", 0))
        assert_equal(peers[8].count("spnget"), 0)
        peers[0].peer_disconnect()
        peers[0].wait_for_disconnect()
        peers[8].wait_payload("spnget", item(1, 1008) + struct.pack("<I", 0))
        node.disconnect_p2ps()
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getsharepoolinventory()["items"], [])
        assert_equal(node.listbanned(), [])

        self.log.info("An incomplete transfer expires after 30 seconds and the next queued object can proceed")
        peer = self.peer()
        # Serialized uint256 lexical ordering: these small IDs retain order.
        first, second = item(1, 200), item(1, 201)
        peer.send_message(inventory(first, second))
        peer.wait_payload("spnget", first + struct.pack("<I", 0))
        started = time.monotonic()
        peer.send_message(data(first, 0, 131072, 42, b"x" * 65536))
        peer.wait_payload("spnget", first + struct.pack("<I", 65536))
        peer.wait_payload("spnget", second + struct.pack("<I", 0))
        assert time.monotonic() - started >= 29
        peer.send_and_ping(data(second, 0, 0, 0, b""))
        peer.send_and_ping(inventory(first))
        assert_equal(peer.count("spnget"), 3)
        assert_equal(node.getsharepoolinventory()["items"], [])
        node.disconnect_p2ps()

        self.log.info("A valid native body under a wrong announced identity is refused before cache mutation")
        # Public fixture key is confined to this disposable protocol test. The
        # service integration separately exercises ephemeral native signers.
        block, manifest = candidate(genesis=self.genesis, native_parent=int(tip, 16), height=1,
            ntime=node.getblockheader(tip)["time"] + 1, pool=self.pool,
            secret=(1).to_bytes(32, "big"), payout_script=b"\x00\x14" + b"Q" * 20)
        proof = solve_share(block, manifest)
        peer = self.peer()

        def transfer(descriptor, body):
            digest = int(hashlib.sha256(body).hexdigest(), 16)
            peer.send_message(inventory(descriptor))
            for offset in range(0, len(body), 65536):
                peer.wait_payload("spnget", descriptor + struct.pack("<I", offset))
                peer.send_message(data(descriptor, offset, len(body), digest, body[offset:offset + 65536]))
            peer.sync_with_ping()

        template_identity = int(template_id(block), 16)
        with node.assert_debug_log(["SPN1 evidence not admitted"], timeout=20):
            transfer(item(1, template_identity ^ 1), block.serialize())
        assert_equal(node.getsharepoolinventory()["items"], [])
        transfer(item(1, template_identity), block.serialize())
        self.wait_until(lambda: len(node.getsharepoolinventory()["items"]) == 1)
        with node.assert_debug_log(["SPN1 evidence not admitted"], timeout=20):
            transfer(item(2, proof.proof_id ^ 1), proof.serialize())
        assert_equal(len(node.getsharepoolinventory()["items"]), 1)
        transfer(item(2, proof.proof_id), proof.serialize())
        self.wait_until(lambda: len(node.getsharepoolinventory()["items"]) == 2)
        assert_equal({entry["id"] for entry in node.getsharepoolinventory()["items"]},
                     {f"{template_identity:064x}", f"{proof.proof_id:064x}"})
        node.disconnect_p2ps()
        assert_equal(node.getbestblockhash(), tip)
        self.log.info("Optional relay framing failures did not change native chain validity or ban peers")


if __name__ == "__main__":
    SharePoolRelayTest(__file__).main()
