#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recover acknowledged origin graphs into an empty native snapshot store.

Two disconnected regtest nodes share only genesis initially. Public disposable
fixture keys produce real native-validated jobs and low-difficulty share proofs.
"""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import candidate, solve_share
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises


class SharePoolHashGateProvenanceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]] * 2

    def setup_network(self):
        self.setup_nodes()

    @staticmethod
    def rpc(node):
        return lambda method, *args: getattr(node, method)(*args)

    def run_test(self):
        source, recovered = self.nodes
        genesis = int(source.getblockhash(0), 16)
        secret = (1).to_bytes(32, "big")
        script = b"\x00\x14" + b"a" * 20
        options = dict(genesis=genesis, native_parent=genesis, height=1,
                       pool=3, secret=secret, payout_script=script)
        pairs, proof = [], None
        now = int(time.time())
        for index in range(3):
            block, snapshot = candidate(**options, ntime=now + index,
                templates=[pairs[-1][0]] if pairs else (), shares=[proof] if pairs else ())
            pairs.append((block, snapshot))
            proof = solve_share(block, snapshot)
        for unused, snapshot in pairs[:-1]:
            source.submitsharepoolhashsnapshot(snapshot.serialize().hex())
        block, snapshot = pairs[-1]
        policy = dict(pool=3, public_key=snapshot.envelope.public_key, payout_script=script)
        path = Path(self.options.tmpdir) / "origin-gate.sqlite"
        archive = Path(self.options.tmpdir) / "origin-gate.spharc"
        self.log.info("Native overlay validation admits a three-opening graph in one local receipt")
        with HashMiningGate(path, rpc=self.rpc(source), **policy) as gate:
            authorization = gate.authorize(block.serialize(), snapshot.serialize())
            assert_equal(authorization.receipt_sequence, 1)
            for unused, opening in pairs:
                assert_equal(gate.snapshot_bytes(opening.hash_hex), opening.serialize())
            head = gate.export_archive(archive)

            foreign, foreign_snapshot = candidate(**dict(options, pool=4), ntime=now + 10)
            source.submitsharepoolhashsnapshot(foreign_snapshot.serialize().hex())
            assert_raises(ValueError, gate.register_template, foreign.serialize())
            assert_equal(gate.archive_head(), head)
            assert_raises(KeyError, gate.snapshot_bytes, foreign_snapshot.hash_hex)

        assert_equal(recovered.getsharepoolhashstatus()["stored_snapshots"], 0)
        assert_equal(recovered.getblockcount(), 0)
        self.log.info("An archive alone rehydrates a disconnected native node and revalidates the acknowledged work")
        recovered_path = Path(self.options.tmpdir) / "restored-gate.sqlite"
        with HashMiningGate.restore_archive(archive, recovered_path, trusted_head=head,
                rpc=self.rpc(recovered), **policy) as gate:
            assert_equal(gate.archive_head(), head)
            assert_equal(recovered.getsharepoolhashstatus()["stored_snapshots"], 3)
            for unused, opening in pairs:
                assert_equal(recovered.getsharepoolhashsnapshot(opening.hash_hex)["data"], opening.serialize().hex())
            acknowledged = snapshot.shares[0]
            assert_equal(gate.receive(acknowledged), False)
            assert_equal(gate.archive_head(), head)
            assert_equal(gate.revalidate_active()["unsettled_proofs"], (f"{acknowledged.proof_id:064x}",))

        self.log.info("The recovered evidence admits the actual solved settlement and native coinbase payment")
        block.solve()
        assert_equal(recovered.submitblock(block.serialize().hex()), None)
        self.wait_until(lambda: recovered.getblockcount() == 1)
        assert_equal(recovered.getbestblockhash(), block.hash)
        assert_equal(recovered.getblock(block.hash, 2)["tx"][0]["vout"][0]["value"], 50)
        assert recovered.verifychain(4, 0)
        with HashMiningGate(recovered_path, rpc=self.rpc(recovered), **policy) as gate:
            assert_equal(gate.archive_head(), head)
            assert_equal(gate.receipt_status()["receipts"][0]["status"], "paid")


if __name__ == "__main__":
    SharePoolHashGateProvenanceTest(__file__).main()
