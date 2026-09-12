#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Hash-only v2 snapshots: pending data, existing P2P, restart and reorganization.

Deterministic disposable regtest lifecycle fixtures. No wallet, hardware miner,
existing credentials, public network, or trusted peer membership is involved.
"""
import json
from pathlib import Path
import sys
import time
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from hash_snapshot import HashSigner, candidate, solve_share
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolHashLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]
                           for unused in range(self.num_nodes)]

    def add_options(self, parser):
        parser.add_argument("--results", type=Path, help="Write a machine-readable lifecycle result")

    def setup_network(self):
        # First create a real data-availability gap, then connect ordinary native
        # peers. Connections use the framework's disposable loopback P2P ports.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built on this platform")

    def make(self, index, *, templates=(), shares=()):
        node, signer = self.nodes[index], self.signers[index]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16),
            height=info["height"] + 1, ntime=max(int(time.time()), info["time"] + 1),
            pool=self.pool, public_key=signer.public_key, sign_owner=signer.sign_owner,
            payout_script=self.scripts[index], templates=templates, shares=shares,
            parent_snapshot=self.snapshots.get(parent))

    def store(self, index, snapshot):
        result = self.nodes[index].submitsharepoolhashsnapshot(snapshot.serialize().hex())
        assert_equal(result["hash"], snapshot.hash_hex)
        assert result["status"] in ("stored", "present")

    def settle(self, index, *, templates=(), shares=()):
        block, snapshot = self.make(index, templates=templates, shares=shares)
        self.store(index, snapshot)
        assert_equal(self.nodes[index].validatesharepoolhashtemplate(block.serialize().hex())["valid"], True)
        block.solve()
        assert_equal(self.nodes[index].submitblock(block.serialize().hex()), None)
        assert_equal(self.nodes[index].getbestblockhash(), block.hash)
        self.snapshots[block.hash] = snapshot
        return block, snapshot

    def wait_tip(self, nodes, block):
        self.wait_until(lambda: all(node.getbestblockhash() == block.hash for node in nodes), timeout=120)
        for node in nodes:
            assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

    def available(self, node, snapshot):
        result = node.getsharepoolhashsnapshot(snapshot.hash_hex)
        assert_equal(result, {"hash": snapshot.hash_hex, "data": snapshot.serialize().hex()})

    def run_test(self):
        directory = Path(self.options.tmpdir) / "hash-lifecycle-identities"
        directory.mkdir(mode=0o700)
        self.pool = 0x48415348324C4946
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.scripts = [b"\x00\x14" + bytes([0x71 + index]) * 20 for index in range(3)]
        self.snapshots = {}
        keys = [directory / f"owner-{index}.key" for index in range(3)]
        expected_transport = "v2" if self.options.v2transport else "v1"
        report = {"profile": "hash-only-v3-regtest", "nodes": 3,
                  "transport": expected_transport, "cases": []}
        try:
            self.signers = [HashSigner.create(self.signer_binary, key,
                pool=self.pool, payout_script=self.scripts[index]) for index, key in enumerate(keys)]
            assert_equal(len({signer.public_key for signer in self.signers}), 3)
            for node in self.nodes:
                status = node.getsharepoolhashstatus()
                assert_equal(status["mode"], "hash-only-v3")
                assert_equal(status["pending_blocks"], 0)
                assert_equal(node.getconnectioncount(), 0)

            self.log.info("A solved block waits for its full snapshot; pending data survives restart")
            origin, origin_snapshot = self.make(0)
            self.store(0, origin_snapshot)
            assert_equal(self.nodes[0].validatesharepoolhashtemplate(origin.serialize().hex())["valid"], True)
            proof = solve_share(origin, origin_snapshot, start_nonce=1)
            assert_equal(self.nodes[0].validatesharepoolhashshare(proof.serialize().hex())["valid"], True)
            block, snapshot = self.make(0, templates=(origin,), shares=(proof,))
            block.solve()
            for index in (1, 2):
                assert_equal(self.nodes[index].submitblock(block.serialize().hex()), "sharepool-hash-data-missing")
                assert_equal(self.nodes[index].getblockcount(), 0)
                assert_equal(self.nodes[index].getsharepoolhashstatus()["pending_blocks"], 1)
            self.restart_node(1)
            assert_equal(self.nodes[1].getblockcount(), 0)
            assert_equal(self.nodes[1].getsharepoolhashstatus()["pending_blocks"], 1)
            report["cases"].append({"case": "missing_snapshot_and_pending_restart", "block": block.hash,
                "snapshot": snapshot.hash_hex, "result": "pending_without_consensus_rejection"})

            self.log.info("Existing native peer connections deliver dependencies and automatically retry the block")
            self.store(0, snapshot)
            assert_equal(self.nodes[0].submitblock(block.serialize().hex()), None)
            self.snapshots[block.hash] = snapshot
            self.connect_nodes(0, 1)
            self.connect_nodes(1, 2)
            self.wait_tip(self.nodes, block)
            for node in self.nodes:
                self.available(node, snapshot)
                self.available(node, origin_snapshot)
            assert_equal([node.getconnectioncount() for node in self.nodes], [1, 2, 1])
            peer_transports = [[peer["transport_protocol_type"] for peer in node.getpeerinfo()]
                               for node in self.nodes]
            assert_equal(peer_transports, [[expected_transport], [expected_transport] * 2, [expected_transport]])
            for index in (1, 2):
                assert sum(peer.get("bytesrecv_per_msg", {}).get("sphdata", 0)
                           for peer in self.nodes[index].getpeerinfo()) > 0
            report["cases"].append({"case": "native_p2p_dependency_retry", "result": "accepted",
                "connections": [1, 2, 1], "peer_transports": peer_transports,
                "proof": f"{proof.proof_id:064x}"})

            self.log.info("Late work uses a new immutable snapshot and direct coinbase payout")
            late = solve_share(origin, origin_snapshot, start_nonce=proof.header.nNonce + 1)
            second, second_snapshot = self.settle(0, templates=(origin,), shares=(late,))
            self.wait_tip(self.nodes, second)
            assert_equal(snapshot.hash_hex, f"{block.m_mm_rhs:064x}")
            assert snapshot.hash != second_snapshot.hash
            assert_equal(len(second_snapshot.post_state), 2)
            assert_equal(bytes(second.vtx[0].vout[0].scriptPubKey), self.scripts[0])
            assert_equal(second.vtx[0].vout[0].nValue, 5_000_000_000)
            report["cases"].append({"case": "late_share_refresh", "result": "accepted",
                "original_snapshot": snapshot.hash_hex, "new_snapshot": second_snapshot.hash_hex,
                "late_proof": f"{late.proof_id:064x}"})

            self.log.info("An offline restart replays chainstate from the locally retained snapshot history")
            self.disconnect_nodes(1, 2)
            self.restart_node(2, extra_args=self.extra_args[2] + ["-reindex-chainstate"])
            assert_equal(self.nodes[2].getconnectioncount(), 0)
            assert_equal(self.nodes[2].getbestblockhash(), second.hash)
            for item in (origin_snapshot, snapshot, second_snapshot):
                self.available(self.nodes[2], item)
            report["cases"].append({"case": "offline_reindex_chainstate", "result": "restored",
                "tip": second.hash, "height": 2})

            self.log.info("Valid competing branches reorganize by native chainwork after snapshots arrive")
            a3, unused = self.settle(0)
            self.wait_tip(self.nodes[:2], a3)
            a4, unused = self.settle(0)
            self.wait_tip(self.nodes[:2], a4)
            b3, unused = self.settle(2)
            b4, unused = self.settle(2)
            b5, branch_snapshot = self.settle(2)
            assert a3.hash != b3.hash
            assert_equal(self.nodes[0].getblockcount(), 4)
            assert_equal(self.nodes[2].getblockcount(), 5)
            self.connect_nodes(1, 2)
            self.wait_tip(self.nodes, b5)
            for node in self.nodes:
                self.available(node, branch_snapshot)
            for node in self.nodes[:2]:
                assert_equal(node.getblockheader(a4.hash)["confirmations"], -1)
            # Both proofs originated at height1, so the carried nullifiers expire
            # when the next payable origin window starts at height2 (height5).
            assert_equal(len(branch_snapshot.post_state), 0)
            report["cases"].append({"case": "native_chainwork_reorganization", "result": "accepted",
                "orphan_tip": a4.hash, "selected_tip": b5.hash, "height": 5})

            self.disconnect_nodes(0, 1)
            self.disconnect_nodes(1, 2)
            self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex-chainstate"])
            assert_equal(self.nodes[1].getconnectioncount(), 0)
            assert_equal(self.nodes[1].getbestblockhash(), b5.hash)
            self.available(self.nodes[1], branch_snapshot)
            report["cases"].append({"case": "reorganized_history_reindex", "result": "restored",
                "tip": b5.hash, "height": 5})
            self.log.info("Level-four native verification disconnects and reconnects the complete selected chain")
            for node in self.nodes:
                assert_equal(node.verifychain(4, 0), True)
                assert_equal(node.getbestblockhash(), b5.hash)
            report["cases"].append({"case": "verifychain_level_four", "result": "passed",
                "nodes": 3, "selected_tip": b5.hash, "complete_chain": True})
            report["result"] = "passed"
            report["identities"] = [{"owner": signer.public_key.hex(), "payout_script": script.hex()}
                                    for signer, script in zip(self.signers, self.scripts)]
            if self.options.results:
                self.options.results.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            self.log.info("Hash-only native snapshot lifecycle passed")
        finally:
            for key in keys:
                if key.exists():
                    key.unlink()


if __name__ == "__main__":
    SharePoolHashLifecycleTest(__file__).main()
