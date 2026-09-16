#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native mempool job construction, external exact signatures and real payouts."""
from dataclasses import replace
from pathlib import Path
import sys
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import EnvelopeV2, HashSigner, RULES_HASH, Snapshot, TemplateRecord, solve_share
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex, ser_uint256
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashBuilderTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=102", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]] * 2

    def skip_test_if_missing_module(self):
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    def proposal(self, signer, *, templates=(), shares=()):
        node = self.nodes[0]
        parent = node.getbestblockhash()
        envelope = EnvelopeV2(self.genesis, RULES_HASH, node.getblockcount() + 1, int(parent, 16),
                              self.pool, signer.public_key, signer.payout_script)
        records = tuple(sorted((TemplateRecord.from_block(block) for block in templates),
                               key=lambda record: ser_uint256(record.template_id)))
        return Snapshot(envelope, bytes(64), records, tuple(sorted(shares, key=lambda proof: proof.proof_id)),
                        (), (CTxOut(0, signer.payout_script),))

    def construct(self, signer, **kwargs):
        node = self.nodes[0]
        before = self.evidence(node)
        prepared = node.preparesharepoolhashjob(self.proposal(signer, **kwargs).serialize().hex())
        unsigned = Snapshot.deserialize(bytes.fromhex(prepared["snapshot"]))
        assert_equal(unsigned.owner_signature, bytes(64))
        assert_equal(prepared["signing_payload"], unsigned.signing_payload.hex())
        assert_equal(prepared["signing_hash"], unsigned.owner_message[::-1].hex())
        assert_raises_rpc_error(-26, "bad-sharepool-hash-owner", node.finalizesharepoolhashjob,
                                prepared["template"], prepared["snapshot"])
        signed = replace(unsigned, owner_signature=signer.sign_owner(unsigned))
        finalized = node.finalizesharepoolhashjob(prepared["template"], signed.serialize().hex())
        block = from_hex(CBlock(), finalized["template"])
        assert_equal(finalized["commitment"], signed.hash_hex)
        assert_equal(block.m_mm_rhs, signed.hash)
        assert_equal(self.evidence(node), before)
        return block, signed, prepared, finalized

    @staticmethod
    def evidence(node):
        return {name: value for name, value in node.getsharepoolhashstatus().items() if name != "validation_worker"}

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        self.pool = 0x4255494c444552
        redeem = CScript([OP_TRUE])
        funded = self.generatetoaddress(node, 101, script_to_p2wsh(redeem))
        self.sync_all()
        paths = [Path(self.options.tmpdir) / f"builder-owner-{index}.key" for index in range(2)]
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=self.pool,
                       payout_script=b"\x00\x14" + bytes([index + 1]) * 20) for index, path in enumerate(paths)]
            self.log.info("Native construction creates distinct fully validated externally signed origins")
            origins, proofs = [], []
            for signer in signers:
                origin, snapshot, prepared, finalized = self.construct(signer)
                assert_equal(finalized["reward"], 5_000_000_000)
                node.submitsharepoolhashsnapshot(snapshot.serialize().hex())
                node.validatesharepoolhashtemplate(origin.serialize().hex())
                origins.append(origin)
                proofs.append(solve_share(origin, snapshot))
            assert origins[0].hashMerkleRoot != origins[1].hashMerkleRoot

            self.log.info("The native mempool supplies a valid witness transaction and exact fee")
            funding = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
            funding.rehash()
            transaction = CTransaction()
            transaction.vin = [CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff)]
            transaction.vout = [CTxOut(funding.vout[0].nValue - 10000, CScript(signers[0].payout_script))]
            witness = CTxInWitness()
            witness.scriptWitness.stack = [bytes(redeem)]
            transaction.wit.vtxinwit = [witness]
            transaction.rehash()
            node.sendrawtransaction(transaction.serialize().hex())
            block, snapshot, prepared, finalized = self.construct(signers[0], templates=origins, shares=proofs)
            assert_equal(len(block.vtx), 2)
            assert_equal(block.vtx[1].serialize_with_witness(), transaction.serialize_with_witness())
            assert_equal(finalized["reward"], 5_000_010_000)
            assert_equal([output.nValue for output in snapshot.payouts], [2_500_005_000] * 2)
            assert_equal(len(block.vtx[0].vout), 3) # Two direct payouts and the ordinary BIP141 commitment.
            assert_equal(len(snapshot.post_state), 2) # Derived from actual selected work, not proposal values.

            self.log.info("A changed job or forged payout cannot reuse the exact owner authorization")
            modified = from_hex(CBlock(), prepared["template"])
            modified.nTime += 1
            assert_raises_rpc_error(-26, "bad-sharepool-hash-job-commitment", node.finalizesharepoolhashjob,
                                    modified.serialize().hex(), snapshot.serialize().hex())
            altered = replace(snapshot, payouts=(CTxOut(1, signers[0].payout_script),))
            altered = replace(altered, owner_signature=signers[0].sign_owner(altered))
            before = self.evidence(node)
            assert_raises_rpc_error(-26, "bad-sharepool-hash-payouts", node.finalizesharepoolhashjob,
                                    prepared["template"], altered.serialize().hex())
            assert_equal(self.evidence(node), before)

            self.log.info("Full snapshot relay permits the follower to verify and accept the winning block")
            node.submitsharepoolhashsnapshot(snapshot.serialize().hex())
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), None)
            self.sync_blocks(timeout=120)
            assert_equal(follower.getbestblockhash(), block.hash)
            assert_equal(node.verifychain(4, 0), True)
            assert_equal(follower.verifychain(4, 0), True)
            assert_raises_rpc_error(-25, "Native tip changed", node.finalizesharepoolhashjob,
                                    prepared["template"], snapshot.serialize().hex())
        finally:
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashBuilderTest(__file__).main()
