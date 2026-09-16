#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""100 simulated v5 owners, full native jobs/proofs, and two real P2P nodes.

This tests the native builder, owner signer, confirmed ledger and exact direct
coinbase payouts. It uses 100 simulated owners, not 100 nodes or physical ASICs.
"""
from dataclasses import replace
from pathlib import Path

from feature_sharepool_hash_ledger import SharePoolHashLedgerTest
from hash_snapshot import HashSigner, LEDGER_VERSION, Snapshot, solve_share
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal


class SharePoolHashLedger100MinersTest(SharePoolHashLedgerTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [["-sharepoolheight=102", "-sharepoolhashonly=1", "-sharepooladmittedledger=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(self.num_nodes)]

    def construct(self, index, signer, *, expected_reward=5_000_000_000, **kwargs):
        node = self.nodes[index]
        before = node.getsharepoolhashstatus()["stored_snapshots"]
        prepared = node.preparesharepoolhashjob(self.proposal(index, signer, **kwargs).serialize().hex())
        unsigned = Snapshot.deserialize(bytes.fromhex(prepared["snapshot"]))
        assert_equal(unsigned.envelope.version, LEDGER_VERSION)
        assert_equal(unsigned.owner_signature, bytes(64))
        assert_equal(prepared["signing_payload"], unsigned.signing_payload.hex())
        assert_equal(prepared["signing_hash"], unsigned.owner_message[::-1].hex())
        signed = replace(unsigned, owner_signature=signer.sign_owner(unsigned))
        finalized = node.finalizesharepoolhashjob(prepared["template"], signed.serialize().hex())
        block = from_hex(CBlock(), finalized["template"])
        assert_equal(finalized["commitment"], signed.hash_hex)
        assert_equal(block.m_mm_rhs, signed.hash)
        assert_equal(finalized["reward"], expected_reward)
        assert_equal(node.getsharepoolhashstatus()["stored_snapshots"], before)
        return block, signed, prepared

    @staticmethod
    def spend_coinbase(node, block_hash, redeem, payout_script, fee):
        funding = from_hex(CBlock(), node.getblock(block_hash, 0)).vtx[0]
        funding.rehash()
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(funding.vout[0].nValue - fee, CScript(payout_script))]
        witness = CTxInWitness()
        witness.scriptWitness.stack = [bytes(redeem)]
        transaction.wit.vtxinwit = [witness]
        transaction.rehash()
        assert_equal(node.sendrawtransaction(transaction.serialize().hex()), transaction.hash)
        return transaction

    @staticmethod
    def assert_hash_only_block(block, snapshot, transaction=None):
        assert_equal(block.m_mm_rhs, snapshot.hash)
        assert_equal(len(block.vtx), 1 if transaction is None else 2)
        if transaction is not None:
            assert_equal(block.vtx[1].serialize_with_witness(), transaction.serialize_with_witness())
        direct = [(bytes(output.scriptPubKey), output.nValue) for output in block.vtx[0].vout
                  if not bytes(output.scriptPubKey).startswith(b"\x6a")]
        assert_equal(direct, [(bytes(output.scriptPubKey), output.nValue) for output in snapshot.payouts])
        carriers = [output for output in block.vtx[0].vout if bytes(output.scriptPubKey).startswith(b"\x6a")]
        assert len(carriers) <= 1
        for output in carriers:
            # Only the ordinary BIP141 witness commitment may accompany the
            # direct payouts. Full settlement evidence travels outside blocks.
            assert_equal(output.nValue, 0)
            assert_equal(len(output.scriptPubKey), 38)
            assert_equal(bytes(output.scriptPubKey)[:6], bytes.fromhex("6a24aa21a9ed"))
        assert snapshot.serialize() not in block.serialize()

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        pool_a, pool_c = 0x4c454447455231303041, 0x4c454447455231303043
        redeem = CScript([OP_TRUE])
        self.log.info("Mature two native coinbases before ledger activation for real fee-paying witness transactions")
        funding_blocks = self.generatetoaddress(node, 101, script_to_p2wsh(redeem), sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        template_info = node.getblocktemplate({"rules": ["segwit", "blake2b", "sharepool"],
                                                "capabilities": ["skip_validity_test"]})["sharepool"]
        assert_equal(template_info["version"], LEDGER_VERSION)
        assert_equal(template_info["mode"], "hash-only-v5-confirmed-ledger")
        assert_equal(template_info["payout_cutoff"], "native-parent-block")
        assert_equal(template_info["local_receipts"], "provisional-until-anchored")
        paths = [Path(self.options.tmpdir) / f"ledger-100-owner-{index}.key" for index in range(101)]
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=pool_a if index < 100 else pool_c,
                       payout_script=b"\x00\x14" + (index + 1).to_bytes(20, "big"))
                       for index, path in enumerate(paths)]
            miners, coordinator = signers[:100], signers[100]
            assert_equal(len({signer.public_key for signer in miners}), 100)
            assert_equal(len({signer.payout_script for signer in miners}), 100)
            transaction = self.spend_coinbase(node, funding_blocks[0], redeem, miners[0].payout_script, 10_000)
            self.log.info("Construct and validate 100 distinct native jobs and real shares with external owner signatures")
            origins, openings, proofs = [], [], []
            for index, signer in enumerate(miners):
                origin, opening, _ = self.construct(0, signer, expected_reward=5_000_010_000)
                self.assert_hash_only_block(origin, opening, transaction)
                self.store(0, opening)
                assert_equal(node.validatesharepoolhashtemplate(origin.serialize().hex())["valid"], True)
                proof = solve_share(origin, opening)
                verified = node.validatesharepoolhashshare(proof.serialize().hex())
                assert_equal(verified["valid"], True)
                assert_equal(verified["proof_id"], f"{proof.proof_id:064x}")
                assert_equal(verified["payout_script"], signer.payout_script.hex())
                assert_equal(verified["pool"], f"{pool_a:064x}")
                origins.append(origin)
                openings.append(opening)
                proofs.append(proof)
                if (index + 1) % 25 == 0:
                    self.log.info("Validated %d/100 miners", index + 1)
            assert_equal(len({origin.hashMerkleRoot for origin in origins}), 100)
            assert_equal(len({opening.hash for opening in openings}), 100)
            assert_equal(len({proof.proof_id for proof in proofs}), 100)

            self.log.info("A pool C block anchors all 100 A receipts; both native nodes obtain and validate the committed snapshot")
            anchor, anchored, _ = self.construct(0, coordinator, templates=origins, shares=proofs,
                                                  expected_reward=5_000_010_000)
            assert_equal(len(anchored.templates), 100)
            assert_equal(len(anchored.shares), 100)
            assert_equal(len(anchored.pending), 100)
            assert_equal(len(anchored.certificates), 100)
            assert_equal(anchored.settled, ())
            assert_equal({credit.proof_id for credit in anchored.pending}, {proof.proof_id for proof in proofs})
            assert_equal({credit.pool for credit in anchored.pending}, {pool_a})
            assert_equal(self.payouts(anchor), {coordinator.payout_script: 5_000_010_000})
            self.assert_hash_only_block(anchor, anchored, transaction)
            self.publish(0, anchor, anchored)
            self.wait_tip(anchor)
            self.assert_local_snapshot(follower, anchored)
            for opening in openings:
                self.assert_local_snapshot(follower, opening)

            self.log.info("A's next block derives 100 exact direct payouts; an extra late proof cannot change their fixed parent cutoff")
            next_transaction = self.spend_coinbase(node, funding_blocks[1], redeem, miners[1].payout_script, 20_000)
            late = solve_share(origins[0], openings[0], start_nonce=proofs[0].header.nNonce + 1)
            assert_equal(node.validatesharepoolhashshare(late.serialize().hex())["valid"], True)
            payment, paid, prepared = self.construct(0, miners[1], templates=(origins[0],), shares=(late,),
                                                     expected_reward=5_000_020_000)
            assert_equal(len(paid.settled), 100)
            assert_equal(paid.settled, anchored.pending)
            assert_equal(len(paid.pending), 1)
            assert_equal(paid.pending[0].proof_id, late.proof_id)
            assert_equal((paid.pending[0].origin_height, paid.pending[0].admitted_height), (102, 103))
            expected_payouts = {signer.payout_script: 50_000_200 for signer in miners}
            assert_equal(self.payouts(payment), expected_payouts)
            self.assert_hash_only_block(payment, paid, next_transaction)
            self.reject_changed_snapshot(0, miners[1], prepared, replace(paid, pending=()),
                                         "bad-sharepool-hash-ledger-pending")
            self.reject_changed_snapshot(0, miners[1], prepared, replace(paid, settled=paid.settled[:-1]),
                                         "bad-sharepool-hash-ledger-settled")
            self.publish(0, payment, paid)
            self.wait_tip(payment)
            for current in self.nodes:
                self.assert_local_snapshot(current, paid)
                actual = from_hex(CBlock(), current.getblock(payment.hash, 0))
                assert_equal(self.payouts(actual), expected_payouts)

            self.log.info("The separately confirmed late receipt pays its original miner in the following A block")
            final, settled, _ = self.construct(0, miners[1])
            assert_equal(settled.pending, ())
            assert_equal(settled.settled, paid.pending)
            assert_equal(self.payouts(final), {miners[0].payout_script: 5_000_000_000})
            self.assert_hash_only_block(final, settled)
            self.publish(0, final, settled)
            self.wait_tip(final)
            for current in self.nodes:
                self.assert_local_snapshot(current, settled)
                assert_equal(current.verifychain(4, 0), True)
                assert_equal(current.getblockcount(), 104)
        finally:
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashLedger100MinersTest(__file__).main()
