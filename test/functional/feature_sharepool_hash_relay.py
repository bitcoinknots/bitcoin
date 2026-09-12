#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native hash relay: changed inventory, bounded slots and waiting-peer turns.

The lifecycle test separately verifies full snapshot validation and automatic
pending-block recovery. These disposable loopback peers exercise relay policy.
"""
import struct
import time

from test_framework.messages import ser_compact_size, ser_uint256
from test_framework.p2p import MESSAGEMAP, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RelayMessage:
    msgtype = b""

    def __init__(self, payload=b""):
        self.payload = payload

    def serialize(self):
        return self.payload

    def deserialize(self, stream):
        self.payload = stream.read()

    def __repr__(self):
        return f"{self.msgtype!r}({len(self.payload)} bytes)"


class Hello(RelayMessage):
    msgtype = b"sphhello"


class Inventory(RelayMessage):
    msgtype = b"sphinv"


class Get(RelayMessage):
    msgtype = b"sphget"


class Data(RelayMessage):
    msgtype = b"sphdata"


for message_class in (Hello, Inventory, Get, Data):
    MESSAGEMAP[message_class.msgtype] = message_class


def inventory(*hashes):
    return Inventory(ser_compact_size(len(hashes)) + b"".join(ser_uint256(value) for value in hashes))


def no_data(identity):
    return Data(ser_uint256(identity) + struct.pack("<II", 0, 0) + b"\x00")


class RelayPeer(P2PInterface):
    def on_sphhello(self, message): pass
    def on_sphinv(self, message): pass
    def on_sphget(self, message): pass
    def on_sphdata(self, message): pass

    def count(self, command):
        with p2p_lock:
            return self.message_count[command]

    def wait_payload(self, command, payload):
        self.wait_until(lambda: command in self.last_message and
                        self.last_message[command].payload == payload)


class SharePoolHashRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]]

    def peer(self):
        peer = self.nodes[0].add_p2p_connection(RelayPeer())
        peer.wait_payload("sphhello", self.hello.payload)
        peer.send_and_ping(self.hello)
        return peer

    def run_test(self):
        node = self.nodes[0]
        status = node.getsharepoolhashstatus()
        self.hello = Hello(b"\x01" + ser_uint256(int(node.getblockhash(0), 16)) +
                           ser_uint256(int(status["rules"], 16)) + struct.pack("<I", 1))
        tip = node.getbestblockhash()

        self.log.info("Empty inventory stays quiet; changes and new connections discover existing objects")
        peer = self.peer()
        assert_equal(peer.count("sphinv"), 0)
        # Authenticated but malformed preimages are retained so they can prove
        # invalid encoding. Storage/relay itself never claims consensus validity.
        first = int(node.submitsharepoolhashsnapshot("0301")["hash"], 16)
        peer.wait_payload("sphinv", inventory(first).payload)
        count = peer.count("sphinv")
        time.sleep(2.2)
        peer.sync_with_ping()
        assert_equal(peer.count("sphinv"), count)
        second = int(node.submitsharepoolhashsnapshot("0302")["hash"], 16)
        hashes = sorted((first, second), key=ser_uint256)
        peer.wait_payload("sphinv", inventory(*hashes).payload)
        newcomer = self.peer()
        newcomer.wait_payload("sphinv", inventory(*hashes).payload)
        node.disconnect_p2ps()

        self.log.info("Four active downloads cannot repeatedly overtake an already waiting fifth peer")
        peers = [self.peer() for _ in range(5)]
        identities = [100 + index for index in range(5)]
        for index, connected in enumerate(peers):
            connected.send_and_ping(inventory(identities[index]))
            if index < 4:
                connected.wait_payload("sphget", ser_uint256(identities[index]) + struct.pack("<I", 0))
        assert_equal(peers[4].count("sphget"), 0)
        # Connection zero queues more work while holding a slot. On completion
        # it must go behind connection four, regardless of shuffled visit order.
        peers[0].send_and_ping(inventory(200))
        peers[0].send_message(no_data(identities[0]))
        peers[4].wait_payload("sphget", ser_uint256(identities[4]) + struct.pack("<I", 0))
        peers[0].sync_with_ping()
        assert_equal(peers[0].count("sphget"), 1)
        peers[1].peer_disconnect()
        peers[1].wait_for_disconnect()
        peers[0].wait_payload("sphget", ser_uint256(200) + struct.pack("<I", 0))
        assert_equal(peers[0].count("sphget"), 2)
        node.disconnect_p2ps()

        self.log.info("Malformed inventory is refused before any download is scheduled")
        for message in (Inventory(b"\xfd\x00\x00"), inventory(1, 1), inventory(1, 256)):
            connected = self.peer()
            connected.send_message(message)
            connected.wait_for_disconnect()
            assert_equal(connected.count("sphget"), 0)
            node.disconnect_p2ps()

        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getsharepoolhashstatus()["stored_snapshots"], 2)
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)


if __name__ == "__main__":
    SharePoolHashRelayTest(__file__).main()
