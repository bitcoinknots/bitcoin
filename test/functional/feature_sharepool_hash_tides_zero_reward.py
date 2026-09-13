#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native TIDES jobs remain valid when every per-address payout floors to zero.

At regtest height4800 the subsidy is one satoshi; at4950 it is zero. Ordinary
preactivation blocks reach that height without changing consensus parameters.
The builder must retain a valid coinbase containing only its normal BIP141
witness commitment when there are no positive monetary payouts.
"""
from dataclasses import replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, TIDES_VERSION, solve_share
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashTidesZeroRewardTest(SharePoolHashTidesTest):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[f"-sharepoolheight={self.options.activation_height}", "-sharepoolhashonly=1",
                            "-sharepooltides=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for _ in range(2)]

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=4800, choices=(4800, 4950))

    @staticmethod
    def assert_witness_only(block, snapshot):
        assert_equal(snapshot.payouts, ())
        assert_equal(len(block.vtx[0].vout), 1)
        output = block.vtx[0].vout[0]
        assert_equal(output.nValue, 0)
        assert_equal(len(output.scriptPubKey), 38)
        assert bytes(output.scriptPubKey).startswith(bytes.fromhex("6a24aa21a9ed"))
        assert_equal(block.m_mm_rhs, snapshot.hash)

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        self.connect_nodes(0, 1)
        self.log.info("Generate ordinary preactivation blocks to a %d-satoshi subsidy",
                      5_000_000_000 >> (self.options.activation_height // 150))
        # Keep each ordinary generation RPC below the framework's timeout and
        # let the follower catch up between bounded batches.
        remaining = self.options.activation_height - 1
        while remaining:
            count = min(500, remaining)
            self.generatetoaddress(node, count, script_to_p2wsh(CScript([OP_TRUE])))
            remaining -= count
        self.sync_blocks(timeout=180)
        reward = 5_000_000_000 >> (self.options.activation_height // 150)
        assert reward in (0, 1)
        keys = [Path(self.options.tmpdir) / f"zero-reward-{index}.key" for index in range(2)]
        gate = None
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=601,
                       payout_script=b"\x00\x14" + bytes([index + 1]) * 20)
                       for index, path in enumerate(keys)]
            gate = HashMiningGate(Path(self.options.tmpdir) / "zero-reward-gate.sqlite",
                rpc=lambda method, *args: getattr(node, method)(*args), pool=601,
                public_key=signers[0].public_key, payout_script=signers[0].payout_script,
                profile_version=TIDES_VERSION, activation_height=self.options.activation_height)
            for signer in signers:
                origin, snapshot, _ = self.construct(0, signer, reward=reward)
                assert_equal(len(snapshot.payouts), 1) # Explicit empty-pool bootstrap.
                assert_equal(snapshot.payouts[0].nValue, reward)
                gate.register_snapshot(snapshot.serialize())
                gate.register_template(origin.serialize())
                gate.receive(solve_share(origin, snapshot))

            self.log.info("Native builder and gate approve a witness-only coinbase with empty monetary payouts")
            block, snapshot = gate.make_native(sign_owner=signers[0].sign_owner)
            self.assert_witness_only(block, snapshot)
            assert_equal(len(snapshot.shares), 2)
            authorization = gate.authorize(block.serialize(), snapshot.serialize())
            assert gate.ready_for_dispatch(authorization)
            invalid = replace(snapshot, payouts=(CTxOut(1, CScript(signers[0].payout_script)),))
            invalid = replace(invalid, owner_signature=signers[0].sign_owner(invalid))
            assert_raises_rpc_error(-26, "payout", node.finalizesharepoolhashjob,
                                    block.serialize().hex(), invalid.serialize().hex())
            gate.register_snapshot(snapshot.serialize())
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), None)
            self.wait_tip(block)
            assert_equal(follower.getblock(block.hash, 0), block.serialize().hex())

            self.log.info("Repeating the rolling window preserves the empty payout vector through restart/reindex")
            repeated, repeated_state = gate.make_native(sign_owner=signers[0].sign_owner)
            self.assert_witness_only(repeated, repeated_state)
            assert_equal(repeated_state.shares, ())
            repeat_auth = gate.authorize(repeated.serialize(), repeated_state.serialize())
            assert gate.ready_for_dispatch(repeat_auth)
            gate.register_snapshot(repeated_state.serialize())
            repeated.solve()
            assert_equal(node.submitblock(repeated.serialize().hex()), None)
            self.wait_tip(repeated)
            self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex-chainstate"])
            assert_equal(follower.getbestblockhash(), repeated.hash)
            assert_equal(follower.verifychain(4, 0), True)
        finally:
            if gate is not None:
                gate.close()
            for path in keys:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashTidesZeroRewardTest(__file__).main()
