#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Opt-in v5 admitted credits: native payouts, late work, carry and reorgs.

Small disposable regtest fixtures use native job construction, the external
owner signer, real header proof of work and ordinary node-to-node relay.
"""
from dataclasses import replace
from pathlib import Path
import sys
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import EnvelopeV2, HashSigner, LEDGER_RULES_HASH, LEDGER_VERSION, Snapshot, TemplateRecord, share_work, solve_share
from test_framework.messages import CBlock, CTxOut, from_hex, ser_uint256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashLedgerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooladmittedledger=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(self.num_nodes)]

    def setup_network(self):
        # Start disconnected to observe pending-data behavior before relay.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    def proposal(self, index, signer, *, templates=(), shares=()):
        node = self.nodes[index]
        binding = EnvelopeV2(self.genesis, LEDGER_RULES_HASH, node.getblockcount() + 1,
                             int(node.getbestblockhash(), 16), signer.pool, signer.public_key,
                             signer.payout_script, version=LEDGER_VERSION)
        records = tuple(sorted((TemplateRecord.from_block(block) for block in templates),
                               key=lambda record: ser_uint256(record.template_id)))
        return Snapshot(binding, bytes(64), records, tuple(sorted(shares, key=lambda proof: proof.proof_id)),
                        (), (CTxOut(0, signer.payout_script),))

    def construct(self, index, signer, **kwargs):
        node = self.nodes[index]
        prepared = node.preparesharepoolhashjob(self.proposal(index, signer, **kwargs).serialize().hex())
        unsigned = Snapshot.deserialize(bytes.fromhex(prepared["snapshot"]))
        assert_equal(unsigned.envelope.version, LEDGER_VERSION)
        assert_equal(unsigned.owner_signature, bytes(64))
        assert_equal(prepared["signing_payload"], unsigned.signing_payload.hex())
        signed = replace(unsigned, owner_signature=signer.sign_owner(unsigned))
        finalized = node.finalizesharepoolhashjob(prepared["template"], signed.serialize().hex())
        block = from_hex(CBlock(), finalized["template"])
        assert_equal(finalized["commitment"], signed.hash_hex)
        assert_equal(block.m_mm_rhs, signed.hash)
        assert_equal(finalized["reward"], 5_000_000_000)
        return block, signed, prepared

    def store(self, index, snapshot):
        assert_equal(self.nodes[index].submitsharepoolhashsnapshot(snapshot.serialize().hex())["hash"], snapshot.hash_hex)

    def publish(self, index, block, snapshot):
        self.store(index, snapshot)
        block.solve()
        assert_equal(self.nodes[index].submitblock(block.serialize().hex()), None)
        assert_equal(self.nodes[index].getbestblockhash(), block.hash)

    def mine(self, index, signer, **kwargs):
        block, snapshot, _ = self.construct(index, signer, **kwargs)
        self.publish(index, block, snapshot)
        return block, snapshot

    def wait_tip(self, block):
        self.wait_until(lambda: all(node.getbestblockhash() == block.hash for node in self.nodes), timeout=120)
        for node in self.nodes:
            assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

    @staticmethod
    def payouts(block):
        # The builder can append a zero-value witness commitment. Only direct
        # monetary outputs belong to settlement allocation.
        return {bytes(output.scriptPubKey): output.nValue for output in block.vtx[0].vout if output.nValue}

    def reject_changed_snapshot(self, index, signer, prepared, snapshot, reason):
        node = self.nodes[index]
        before = node.getsharepoolhashstatus()["stored_snapshots"]
        signed = replace(snapshot, owner_signature=signer.sign_owner(snapshot))
        assert_raises_rpc_error(-26, reason, node.finalizesharepoolhashjob,
                                prepared["template"], signed.serialize().hex())
        assert_equal(node.getsharepoolhashstatus()["stored_snapshots"], before)
        return signed

    def assert_local_snapshot(self, node, snapshot):
        local = node.getsharepoolhashsnapshot(snapshot.hash_hex)
        assert_equal(local["data"], snapshot.serialize().hex())
        decoded = Snapshot.deserialize(bytes.fromhex(local["data"]))
        assert_equal(decoded.pending, snapshot.pending)
        assert_equal(decoded.settled, snapshot.settled)

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        pool_a, pool_b, pool_c = 0x4c454447455241, 0x4c454447455242, 0x4c454447455243
        paths = [Path(self.options.tmpdir) / f"ledger-owner-{index}.key" for index in range(4)]
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=pool,
                       payout_script=b"\x00\x14" + bytes([index + 1]) * 20)
                       for index, (path, pool) in enumerate(zip(paths, (pool_a, pool_a, pool_b, pool_c)))]
            a1, a2, b, c = signers
            for current in self.nodes:
                assert_equal(current.getsharepoolhashstatus()["mode"], "hash-only-v5-confirmed-ledger")
                assert_equal(current.getconnectioncount(), 0)

            self.log.info("Pool C anchors fresh valid A/B receipts without paying those receipts in its own block")
            origins, origin_snapshots, proofs = [], [], []
            for signer in (a1, a2, b):
                origin, snapshot, _ = self.construct(0, signer)
                self.store(0, snapshot)
                assert_equal(node.validatesharepoolhashtemplate(origin.serialize().hex())["valid"], True)
                proof = solve_share(origin, snapshot)
                assert_equal(node.validatesharepoolhashshare(proof.serialize().hex())["valid"], True)
                origins.append(origin)
                origin_snapshots.append(snapshot)
                proofs.append(proof)
            assert_equal(len({origin.hashMerkleRoot for origin in origins}), 3)
            first, first_state, _ = self.construct(0, c, templates=origins, shares=proofs)
            assert_equal(first_state.settled, ())
            assert_equal({credit.pool for credit in first_state.pending}, {pool_a, pool_b})
            assert_equal({credit.proof_id for credit in first_state.pending}, {proof.proof_id for proof in proofs})
            assert_equal(self.payouts(first), {c.payout_script: 5_000_000_000})

            self.log.info("Missing committed data stays pending through restart, then ordinary P2P supplies the complete state")
            first.solve()
            assert_equal(follower.submitblock(first.serialize().hex()), "sharepool-hash-data-missing")
            assert_equal(follower.getblockcount(), 0)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.restart_node(1)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.publish(0, first, first_state)
            self.connect_nodes(0, 1)
            self.wait_tip(first)
            for snapshot in (*origin_snapshots, first_state):
                self.assert_local_snapshot(follower, snapshot)

            self.log.info("A pays its parent's two A credits; newly received work on the previous job is admitted for a later block")
            late = solve_share(origins[0], origin_snapshots[0], start_nonce=proofs[0].header.nNonce + 1)
            second, second_state, prepared = self.construct(0, a1, templates=(origins[0],), shares=(late,))
            assert_equal({credit.proof_id for credit in second_state.settled}, {proof.proof_id for proof in proofs[:2]})
            assert_equal({credit.proof_id for credit in second_state.pending}, {proofs[2].proof_id, late.proof_id})
            assert_equal(self.payouts(second), {a1.payout_script: 2_500_000_000, a2.payout_script: 2_500_000_000})
            late_credit = next(credit for credit in second_state.pending if credit.proof_id == late.proof_id)
            assert_equal((late_credit.origin_height, late_credit.admitted_height), (1, 2))

            self.log.info("Even fresh valid owner signatures cannot omit credits, change their recipient/work, or choose a shorter payout prefix")
            omitted = replace(second_state, pending=second_state.pending[1:])
            self.reject_changed_snapshot(0, a1, prepared, omitted, "bad-sharepool-hash-ledger-pending")
            changed_recipient = replace(second_state.pending[0], payout_script=c.payout_script)
            forged = self.reject_changed_snapshot(0, a1, prepared,
                replace(second_state, pending=(changed_recipient,) + second_state.pending[1:]), "bad-sharepool-hash-ledger-pending")
            changed_work = replace(second_state.pending[0], native_bits=0x1e7fffff)
            assert share_work(changed_work.native_bits) > share_work(second_state.pending[0].native_bits)
            self.reject_changed_snapshot(0, a1, prepared,
                replace(second_state, pending=(changed_work,) + second_state.pending[1:]), "bad-sharepool-hash-ledger-pending")
            shorter = replace(second_state, settled=second_state.settled[:-1])
            self.reject_changed_snapshot(0, a1, prepared, shorter, "bad-sharepool-hash-ledger-settled")
            self.reject_changed_snapshot(0, a1, prepared,
                replace(second_state, certificates=()), "bad-sharepool-hash-ledger-certificates")
            # A replay with a valid origin signature is not new work. Keep the
            # previously correct derived state, so only the extra proof changes.
            replay = replace(second_state, shares=tuple(sorted((late, proofs[0]), key=lambda proof: proof.proof_id)))
            self.reject_changed_snapshot(0, a1, prepared, replay, "bad-sharepool-hash-repeat-payment")

            # Exercise block consensus too: a coordinator can sign and solve a
            # block without using finalize, but cannot change an admitted payee.
            invalid = from_hex(CBlock(), prepared["template"])
            invalid.m_mm_rhs = forged.hash
            invalid.solve()
            self.store(0, forged)
            assert_equal(node.submitblock(invalid.serialize().hex()), "bad-sharepool-hash-ledger-pending")
            assert_equal(node.getbestblockhash(), first.hash)
            self.publish(0, second, second_state)
            self.wait_tip(second)

            self.log.info("Confirmed A/B credits survive unrelated-pool blocks beyond the fresh-proof age limit")
            carried = second_state.pending
            for height in range(3, 7):
                common, common_state = self.mine(0, c)
                assert_equal(common.m_height, height)
                assert_equal(common_state.pending, carried)
                assert_equal(common_state.settled, ())
                assert_equal(self.payouts(common), {c.payout_script: 5_000_000_000})
                self.wait_tip(common)
            assert_equal(common_state.post_state, ())
            assert_equal(common_state.certificates, ())
            assert all(common.m_height - credit.origin_height > 3 for credit in common_state.pending)

            self.log.info("A longer nonpaying branch restores credits removed by orphaned B/A payouts")
            self.disconnect_nodes(0, 1)
            paid_b, paid_b_state = self.mine(0, b)
            assert_equal({credit.proof_id for credit in paid_b_state.settled}, {proofs[2].proof_id})
            assert_equal(self.payouts(paid_b), {b.payout_script: 5_000_000_000})
            paid_a, paid_a_state = self.mine(0, a2)
            assert_equal({credit.proof_id for credit in paid_a_state.settled}, {late.proof_id})
            assert_equal(paid_a_state.pending, ())
            assert_equal(self.payouts(paid_a), {a1.payout_script: 5_000_000_000})
            for _ in range(3):
                alternate, alternate_state = self.mine(1, c)
                assert_equal(alternate_state.pending, carried)
                assert_equal(alternate_state.settled, ())
            assert_equal((node.getblockcount(), follower.getblockcount()), (8, 9))
            self.connect_nodes(0, 1)
            self.wait_tip(alternate)
            assert_equal(node.getblockheader(paid_a.hash)["confirmations"], -1)
            for current in self.nodes:
                self.assert_local_snapshot(current, alternate_state)

            self.log.info("Selected-branch credits pay their original recipients once after the reorganization")
            final_b, final_b_state = self.mine(0, b)
            assert_equal({credit.proof_id for credit in final_b_state.settled}, {proofs[2].proof_id})
            assert_equal(self.payouts(final_b), {b.payout_script: 5_000_000_000})
            self.wait_tip(final_b)
            final_a, final_a_state = self.mine(0, a2)
            assert_equal({credit.proof_id for credit in final_a_state.settled}, {late.proof_id})
            assert_equal(final_a_state.pending, ())
            assert_equal(self.payouts(final_a), {a1.payout_script: 5_000_000_000})
            self.wait_tip(final_a)

            self.log.info("Offline chainstate reindex and level-four verification reconstruct the selected ledger history")
            self.disconnect_nodes(0, 1)
            self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex-chainstate"])
            assert_equal(follower.getconnectioncount(), 0)
            assert_equal(follower.getbestblockhash(), final_a.hash)
            for current in self.nodes:
                self.assert_local_snapshot(current, final_a_state)
                assert_equal(current.verifychain(4, 0), True)
                assert_equal(current.getbestblockhash(), final_a.hash)
        finally:
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashLedgerTest(__file__).main()
