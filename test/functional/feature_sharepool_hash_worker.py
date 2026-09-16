#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native asynchronous origin validation, responsiveness, and durable shutdown.

All work is valid, generated locally on a disposable regtest chain. The same
ordinary P2WSH transaction appears in independent, exactly signed templates.
The workload is a reproducible functional measurement, not a throughput claim.
"""
import hashlib
import json
import platform
from copy import deepcopy
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import candidate, solve_share
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex, msg_block
from feature_sharepool_hash_relay import RelayPeer
from test_framework.script import CScript, OP_DROP, OP_SHA256, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolHashWorkerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=202", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]] * 2

    @staticmethod
    def worker(node):
        return node.getsharepoolhashstatus()["validation_worker"]

    def run_test(self):
        source, node = self.nodes
        redeem = CScript([OP_SHA256] * 199 + [OP_DROP, OP_TRUE])
        funding_blocks = self.generatetoaddress(source, 201, script_to_p2wsh(redeem))
        self.sync_all()
        self.disconnect_nodes(0, 1)
        tip = node.getbestblockhash()
        genesis = int(node.getblockhash(0), 16)
        transaction = CTransaction()
        value = 0
        for blockhash in funding_blocks[:100]:
            funding = from_hex(CBlock(), source.getblock(blockhash, 0)).vtx[0]
            funding.rehash()
            transaction.vin.append(CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff))
            witness = CTxInWitness()
            witness.scriptWitness.stack = [b"w" * 500, bytes(redeem)]
            transaction.wit.vtxinwit.append(witness)
            value += funding.vout[0].nValue
        script = b"\x00\x14" + b"z" * 20
        transaction.vout = [CTxOut(value - 1000, CScript(script))]
        transaction.rehash()
        ntime = max(int(time.time()), node.getblockheader(tip)["time"] + 1)
        common = dict(genesis=genesis, native_parent=int(tip, 16), height=202,
                      ntime=ntime, pool=987, secret=(1).to_bytes(32, "big"))
        origins, proofs = [], []
        for number in range(64):
            origin, snapshot = candidate(**common,
                payout_script=b"\x00\x14" + number.to_bytes(20, "big"),
                transactions=(transaction,), fees=1000, witness=True)
            node.submitsharepoolhashsnapshot(snapshot.serialize().hex())
            origins.append(origin)
            proofs.append(solve_share(origin, snapshot))
        settlement, snapshot = candidate(**common, payout_script=script, templates=origins, shares=proofs)
        node.submitsharepoolhashsnapshot(snapshot.serialize().hex())
        settlement.solve()
        self.wait_until(lambda: not self.worker(node)["active"] and not self.worker(node)["pending"])
        before = self.worker(node)
        assert_equal(before["started"], True)
        peer = node.add_p2p_connection(RelayPeer())
        began = time.monotonic()
        peer.send_message(msg_block(settlement))
        ping_started = time.monotonic()
        peer.sync_with_ping()
        ping_seconds = time.monotonic() - ping_started
        samples = []
        saw_active = False
        # Ordinary command responsiveness is measured while the validation
        # worker runs. No timing claim relies solely on a completed idle pass.
        deadline = began + 120
        while node.getbestblockhash() != settlement.hash:
            assert time.monotonic() < deadline
            active = self.worker(node)["active"]
            started = time.monotonic()
            node.getblockcount()
            elapsed = time.monotonic() - started
            if active:
                saw_active = True
                samples.append(elapsed)
            time.sleep(0.01)
        self.wait_until(lambda: not self.worker(node)["active"])
        after = self.worker(node)
        assert saw_active, "Workload completed without measuring an active validation pass"
        assert samples and max(samples) < 5, samples
        assert ping_seconds < 5, ping_seconds
        assert after["passes"] > before["passes"]
        assert_equal(after["failures"], 0)
        assert after["outside_script_checks"] - before["outside_script_checks"] >= 6400
        assert_equal(after["locked_fallbacks"], before["locked_fallbacks"])
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)
        assert_equal(len(settlement.vtx[0].vout), 64)
        assert_equal(sum(output.nValue for output in settlement.vtx[0].vout), 2_500_000_000)
        report = {"origins": 64, "inputs_per_origin": 100, "sha256_ops_per_input": 199,
                  "snapshot_bytes": len(snapshot.serialize()), "block_bytes": len(settlement.serialize()),
                  "pipeline_seconds": time.monotonic() - began, "p2p_ping_seconds": ping_seconds,
                  "active_rpc_samples": len(samples), "maximum_active_rpc_seconds": max(samples),
                  "worker": after}
        self.log.info("A pending data notification survives shutdown and is accepted after restart")
        child, child_snapshot = candidate(genesis=genesis, native_parent=int(settlement.hash, 16),
            height=203, ntime=ntime + 1, pool=987, secret=(1).to_bytes(32, "big"),
            payout_script=script, parent_snapshot=snapshot)
        child.solve()
        assert_equal(node.submitblock(child.serialize().hex()), "sharepool-hash-data-missing")
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 1)
        self.restart_node(1)
        node = self.nodes[1]
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 1)
        assert_equal(node.getbestblockhash(), settlement.hash)
        node.submitsharepoolhashsnapshot(child_snapshot.serialize().hex())
        self.wait_until(lambda: node.getbestblockhash() == child.hash)
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)
        assert_equal(self.worker(node)["started"], True)
        self.log.info("A local disconnect/reconnect revalidates the settled branch with retained evidence")
        node.invalidateblock(child.hash)
        assert_equal(node.getbestblockhash(), settlement.hash)
        node.reconsiderblock(child.hash)
        self.wait_until(lambda: node.getbestblockhash() == child.hash)
        assert_equal(node.verifychain(4, 0), True)
        report["pending_restart"] = "accepted"
        report["reorganization_verifydb"] = "valid"
        self.log.info("A tip change during script execution discards the capture and retries the competing block")
        race_common = dict(genesis=genesis, native_parent=int(child.hash, 16), height=204,
            ntime=ntime + 2, pool=987, secret=(1).to_bytes(32, "big"), parent_snapshot=child_snapshot)
        # VerifyDB legitimately populated the full script-execution cache for
        # the earlier transaction. A distinct valid spend gives this race fresh
        # script work without weakening or disabling the native cache.
        race_transaction = deepcopy(transaction)
        race_transaction.vout[0].scriptPubKey = CScript(b"\x00\x14" + b"y" * 20)
        race_transaction.rehash()
        origins, proofs = [], []
        for number in range(64):
            origin, opening = candidate(**race_common,
                payout_script=b"\x00\x14" + number.to_bytes(20, "big"),
                transactions=(race_transaction,), fees=1000, witness=True)
            node.submitsharepoolhashsnapshot(opening.serialize().hex())
            origins.append(origin)
            proofs.append(solve_share(origin, opening))
        competing, competing_snapshot = candidate(**race_common,
            payout_script=script, templates=origins, shares=proofs)
        alternate, alternate_snapshot = candidate(**{**race_common, "ntime": ntime + 3}, payout_script=script)
        competing.solve()
        alternate.solve()
        node.submitsharepoolhashsnapshot(competing_snapshot.serialize().hex())
        self.wait_until(lambda: not self.worker(node)["active"] and not self.worker(node)["pending"])
        race_before = self.worker(node)
        race_peer = node.add_p2p_connection(RelayPeer())
        race_peer.send_message(msg_block(competing))
        self.wait_until(lambda: self.worker(node)["outside_script_checks"] > race_before["outside_script_checks"])
        assert_equal(self.worker(node)["active"], True)
        node.submitsharepoolhashsnapshot(alternate_snapshot.serialize().hex())
        assert_equal(node.submitblock(alternate.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), alternate.hash)
        self.wait_until(lambda: self.worker(node)["context_retries"] > race_before["context_retries"])
        self.wait_until(lambda: node.getsharepoolhashstatus()["pending_blocks"] == 0)
        assert_equal(node.getblockheader(competing.hash)["confirmations"], -1)
        extension, extension_snapshot = candidate(genesis=genesis, native_parent=int(competing.hash, 16),
            height=205, ntime=ntime + 4, pool=987, secret=(1).to_bytes(32, "big"),
            payout_script=script, parent_snapshot=competing_snapshot)
        extension.solve()
        node.submitsharepoolhashsnapshot(extension_snapshot.serialize().hex())
        assert_equal(node.submitblock(extension.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), extension.hash)
        assert_equal(node.verifychain(4, 0), True)
        report["context_change"] = {"retry_count": self.worker(node)["context_retries"] - race_before["context_retries"],
                                  "competing_branch": "accepted_and_extended"}
        report["protocol_version"] = 4
        report["platform"] = platform.platform()
        report["binary_sha256"] = hashlib.sha256(Path(node.binary).read_bytes()).hexdigest()
        report["test_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        (Path(self.options.tmpdir) / "sharepool-worker-report.json").write_text(json.dumps(report, indent=2) + "\n")
        self.log.info("Worker measurement: %s", json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    SharePoolHashWorkerTest(__file__).main()
