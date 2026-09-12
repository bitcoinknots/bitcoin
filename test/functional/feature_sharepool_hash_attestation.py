#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact v3 template signatures and native validation of signed origin bodies.

All keys and spends are public disposable regtest fixtures. The bad-origin cases
are deliberately signed by their fixture owner so signature rejection cannot
conceal missing native transaction validation.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import TemplateRecord, attest, candidate, share_target, solve_share
from native_enforcement import compute_xonly_pubkey
from test_framework.address import script_to_p2wsh
from test_framework.blocktools import add_witness_commitment
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashAttestationTest(BitcoinTestFramework):
    SECRET = (1).to_bytes(32, "big")
    FEE = 1_000

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Mature native funding first, then start the hash-only profile. This is
        # a fresh chain with an explicit activation, never an existing v2 DB.
        self.extra_args = [["-sharepoolheight=102", "-sharepoolhashonly=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"]]

    def make(self, **kwargs):
        return candidate(genesis=self.genesis, native_parent=int(self.tip, 16), height=102,
            ntime=self.ntime, pool=123, secret=self.SECRET, payout_script=self.script, **kwargs)

    def store(self, snapshot):
        result = self.nodes[0].submitsharepoolhashsnapshot(snapshot.serialize().hex())
        assert_equal(result["hash"], snapshot.hash_hex)

    def reject(self, block, snapshot, reason):
        self.store(snapshot)
        assert_raises_rpc_error(-26, reason, self.nodes[0].validatesharepoolhashtemplate,
                                block.serialize().hex())
        block.solve()
        result = self.nodes[0].submitblock(block.serialize().hex())
        assert reason in result, (reason, result)
        assert_equal(self.nodes[0].getbestblockhash(), self.tip)
        assert_equal(self.nodes[0].getsharepoolhashstatus()["pending_blocks"], 0)

    def reject_origin(self, origin, snapshot, reason, *, proof=True):
        self.store(snapshot)
        shares = (solve_share(origin, snapshot),) if proof else ()
        block, settlement = self.make(templates=(origin,), shares=shares)
        self.reject(block, settlement, reason)

    @staticmethod
    def refresh_body(block):
        # Remove the old BIP141 output before adding its replacement. The native
        # monetary outputs and exact reward remain unchanged.
        block.vtx[0].vout = block.vtx[0].vout[:1]
        for transaction in block.vtx:
            transaction.rehash()
        add_witness_commitment(block)

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        self.script = b"\x00\x14" + b"a" * 20
        redeem = CScript([OP_DROP, OP_TRUE])
        funding_blocks = self.generatetoaddress(node, 101, script_to_p2wsh(redeem))
        self.tip = node.getbestblockhash()
        self.ntime = max(int(time.time()), node.getblockheader(self.tip)["time"] + 1)
        self.log.info("GBT identifies the exact v3 share target and explicitly requires job completion")
        base = node.getblocktemplate({"rules": ["segwit", "blake2b", "sharepool"],
                                      "capabilities": ["skip_validity_test"]})
        metadata = base["sharepool"]
        assert_equal(metadata["version"], 3)
        assert_equal(metadata["mode"], "hash-only-v3")
        assert_equal(metadata["activation_height"], 102)
        assert_equal(metadata["share_target"], f"{share_target(int(base['bits'], 16)):064x}")
        assert_equal(metadata["requires_completion"], True)
        assert "share_bits" not in metadata
        assert "!sharepool" in base["rules"]
        funding = from_hex(CBlock(), node.getblock(funding_blocks[0], 0)).vtx[0]
        funding.rehash()
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(funding.vout[0].nValue - self.FEE, CScript(self.script))]
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [b"original", bytes(redeem)]
        transaction.rehash()
        origin, opening = self.make(transactions=(transaction,), fees=self.FEE, witness=True)
        self.log.info("Valid and invalid snapshot overlays leave native evidence storage unchanged")
        before = node.getsharepoolhashstatus()
        assert_equal(before["stored_snapshots"], 0)
        assert_equal(before["inventory"], [])
        assert_equal(node.validatesharepoolhashtemplate(origin.serialize().hex(), opening.serialize().hex())["valid"], True)
        assert_equal(node.getsharepoolhashstatus(), before)
        assert_raises_rpc_error(-25, "sharepool-hash-data-missing", node.getsharepoolhashsnapshot, opening.hash_hex)
        bad_overlay = replace(opening, envelope=replace(opening.envelope, pool=124))
        bad_offer = deepcopy(origin)
        bad_offer.m_mm_rhs = bad_overlay.hash
        bad_offer.rehash()
        assert_raises_rpc_error(-26, "bad-sharepool-hash-owner", node.validatesharepoolhashtemplate,
                                bad_offer.serialize().hex(), bad_overlay.serialize().hex())
        assert_equal(node.getsharepoolhashstatus(), before)
        assert_raises_rpc_error(-25, "sharepool-hash-data-missing", node.getsharepoolhashsnapshot, bad_overlay.hash_hex)
        self.store(opening)
        assert_equal(node.getsharepoolhashstatus()["stored_snapshots"], 1)
        assert_equal(node.getsharepoolhashstatus()["inventory"], [opening.hash_hex])
        assert_equal(node.validatesharepoolhashtemplate(origin.serialize().hex())["valid"], True)
        proof = solve_share(origin, opening)
        assert_equal(node.validatesharepoolhashshare(proof.serialize().hex())["valid"], True)

        self.log.info("Changing a valid transaction body requires a new exact-job signature")
        changed = deepcopy(origin)
        changed.vtx[1].vout[0].scriptPubKey = CScript(b"\x00\x14" + b"b" * 20)
        self.refresh_body(changed)
        self.reject_origin(changed, opening, "bad-sharepool-hash-job-commitment", proof=False)

        self.log.info("Witness bytes are signed even when the ordinary transaction ID is unchanged")
        changed = deepcopy(origin)
        changed.vtx[1].wit.vtxinwit[0].scriptWitness.stack[0] = b"changed"
        # Deliberately leave the old header and BIP141 commitment. Exact origin
        # attestation rejects this before the native witness check, including
        # after the correct body has already populated the native cache.
        assert_equal(changed.vtx[1].serialize_without_witness(), origin.vtx[1].serialize_without_witness())
        self.reject_origin(changed, opening, "bad-sharepool-hash-job-commitment", proof=False)

        self.log.info("The signature authenticates policy/context and the complete evidence snapshot")
        plain, snapshot = self.make()
        bindings = (
            ("pool", snapshot.envelope.pool + 1, "owner"),
            ("payout_script", b"\x00\x14" + b"c" * 20, "owner"),
            ("public_key", compute_xonly_pubkey((2).to_bytes(32, "big"))[0], "owner"),
            ("genesis", self.genesis ^ 1, "binding"),
            ("native_parent", int(self.tip, 16) ^ 1, "binding"),
            ("height", 103, "binding"),
        )
        for field, value, reason in bindings:
            changed_snapshot = replace(snapshot, envelope=replace(snapshot.envelope, **{field: value}))
            changed = deepcopy(plain)
            changed.m_mm_rhs = changed_snapshot.hash
            changed.rehash()
            self.reject(changed, changed_snapshot, "bad-sharepool-hash-" + reason)
        changed_snapshot = replace(snapshot, templates=(TemplateRecord.from_block(origin),))
        changed = deepcopy(plain)
        changed.m_mm_rhs = changed_snapshot.hash
        changed.rehash()
        self.reject(changed, changed_snapshot, "bad-sharepool-hash-owner")

        self.log.info("Search nonces can change; a newly authorized valid transaction can be mined")
        search = deepcopy(origin)
        search.nNonce, search.m_nonce2, search.m_nonce3, search.m_extranonce = 7, 8, 9, 10
        search.rehash()
        assert_equal(node.validatesharepoolhashtemplate(search.serialize().hex())["valid"], True)
        authorized = deepcopy(origin)
        authorized.vtx[1].wit.vtxinwit[0].scriptWitness.stack[0] = b"authorized"
        self.refresh_body(authorized)
        authorization = attest(authorized, opening, secret=self.SECRET)
        self.store(authorization)
        assert_equal(node.validatesharepoolhashtemplate(authorized.serialize().hex())["valid"], True)
        authorized_proof = solve_share(authorized, authorization)
        assert_equal(node.validatesharepoolhashshare(authorized_proof.serialize().hex())["valid"], True)

        self.log.info("A legitimate owner cannot authorize a nonexistent UTXO into a valid origin")
        missing = deepcopy(transaction)
        missing.vin[0].prevout.hash ^= 1
        missing.rehash()
        invalid, attestation = self.make(transactions=(missing,), fees=self.FEE, witness=True)
        self.reject_origin(invalid, attestation, "bad-sharepool-hash-origin-body: bad-txns-inputs-missingorspent")

        self.log.info("Native origin validation rejects two transactions spending the same input")
        duplicate = deepcopy(transaction)
        duplicate.vout[0].scriptPubKey = CScript(b"\x00\x14" + b"d" * 20)
        duplicate.rehash()
        invalid, attestation = self.make(transactions=(transaction, duplicate), fees=2 * self.FEE, witness=True)
        self.reject_origin(invalid, attestation, "bad-sharepool-hash-origin-body: bad-txns-inputs-missingorspent")

        self.log.info("A signed origin with correct witness commitment still must execute its scripts")
        bad_script = deepcopy(transaction)
        bad_script.wit.vtxinwit[0].scriptWitness.stack = [bytes(redeem)] # OP_DROP sees an empty stack.
        bad_script.rehash()
        invalid, attestation = self.make(transactions=(bad_script,), fees=self.FEE, witness=True)
        self.reject_origin(invalid, attestation, "bad-sharepool-hash-origin-body: mandatory-script-verify-flag-failed")

        self.log.info("The accepted settlement validates its real spend and pays the verified origin owner")
        settlement, snapshot = self.make(templates=(authorized,), shares=(authorized_proof,),
            transactions=(transaction,), fees=self.FEE, witness=True)
        self.store(snapshot)
        assert_equal(node.validatesharepoolhashtemplate(settlement.serialize().hex())["valid"], True)
        settlement.solve()
        assert_equal(node.submitblock(settlement.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), settlement.hash)
        assert_equal(node.gettxout(funding.hash, 0), None)
        assert_equal(settlement.vtx[0].vout[0].nValue, 5_000_000_000 + self.FEE)
        assert_equal(bytes(settlement.vtx[0].vout[0].scriptPubKey), self.script)
        assert_equal(node.verifychain(4, 0), True)


if __name__ == "__main__":
    SharePoolHashAttestationTest(__file__).main()
