#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native v2 settlement outcomes for unavailable data and inconsistent payouts."""
from dataclasses import replace
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import candidate, solve_share, attest
from native_enforcement import h256
from test_framework.messages import CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashRulesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]]

    def make(self, **kwargs):
        return candidate(genesis=self.genesis, native_parent=self.genesis, height=1,
            ntime=int(time.time()), pool=123, secret=(1).to_bytes(32, "big"),
            payout_script=self.script, **kwargs)

    def commit(self, block, snapshot):
        block.vtx[0].vout = list(snapshot.payouts)
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        snapshot = attest(block, snapshot, secret=(1).to_bytes(32, "big"))
        self.nodes[0].submitsharepoolhashsnapshot(snapshot.serialize().hex())

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        self.script = b"\x00\x14" + b"a" * 20
        origin, opening = self.make()
        node.submitsharepoolhashsnapshot(opening.serialize().hex())
        assert_equal(node.validatesharepoolhashtemplate(origin.serialize().hex())["valid"], True)
        proof = solve_share(origin, opening)
        assert_equal(node.validatesharepoolhashshare(proof.serialize().hex())["proof_id"], f"{proof.proof_id:064x}")

        self.log.info("Complete proof attribution fixes the actual payout script")
        block, snapshot = self.make(templates=(origin,), shares=(proof,))
        wrong_script = b"\x00\x14" + b"b" * 20
        changed = replace(snapshot, payouts=(CTxOut(5_000_000_000, CScript(wrong_script)),))
        self.commit(block, changed)
        assert_raises_rpc_error(-26, "bad-sharepool-hash-payouts", node.validatesharepoolhashtemplate, block.serialize().hex())
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "bad-sharepool-hash-payouts")

        self.log.info("The snapshot and coinbase must allocate the exact native subsidy plus fees")
        block, snapshot = self.make(templates=(origin,), shares=(proof,))
        changed = replace(snapshot, payouts=(CTxOut(4_999_999_999, CScript(self.script)),))
        self.commit(block, changed)
        assert_raises_rpc_error(-26, "bad-sharepool-hash-reward", node.validatesharepoolhashtemplate, block.serialize().hex())
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "bad-sharepool-hash-reward")

        self.log.info("Unavailable preimages are pending; available invalid encodings establish rejection")
        block, unused = self.make()
        raw = b"\x02"
        block.m_mm_rhs = h256(b"SharePool/snapshot/v3\0", raw)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "sharepool-hash-data-missing")
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 1)
        result = node.submitsharepoolhashsnapshot(raw.hex())
        assert_equal(result["hash"], f"{block.m_mm_rhs:064x}")
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.submitblock(block.serialize().hex()), "duplicate-invalid")
        assert_equal(node.getsharepoolhashsnapshot(result["hash"])["data"], raw.hex())

        # The empty preimage has a known commitment, so no network lookup is
        # needed to establish that it cannot encode a settlement snapshot.
        empty, unused = self.make()
        empty.m_mm_rhs = h256(b"SharePool/snapshot/v3\0", b"")
        empty.solve()
        assert_equal(node.submitblock(empty.serialize().hex()), "bad-sharepool-hash-snapshot-encoding")
        assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

        self.log.info("A complete consistent settlement is accepted after the refused examples")
        block, snapshot = self.make(templates=(origin,), shares=(proof,))
        self.commit(block, snapshot)
        assert_equal(node.validatesharepoolhashtemplate(block.serialize().hex())["valid"], True)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), block.hash)
        assert_equal(len(block.vtx[0].vout), 1)


if __name__ == "__main__":
    SharePoolHashRulesTest(__file__).main()
