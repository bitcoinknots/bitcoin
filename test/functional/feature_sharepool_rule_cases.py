#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Identifiable SPN1 rule cases using fresh native signers and disposable nodes.

Optional --results writes public fixture identities, exact native/gate outcomes,
and evidence IDs. This is deterministic correctness coverage, not a benchmark
or a claim that an invalid authorization identifies its real-world submitter.
"""
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import (apply_to_coinbase, candidate, monetary_outputs,
    parse_coinbase, payouts_root, solve_share, winner_share)
from native_mining_gate import JobOmission, NativeMiningGate, template_id
from native_signer import NativeSigner
from test_framework.authproxy import JSONRPCException
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, uint256_from_compact
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def money(outputs):
    return [{"payout_script": bytes(output.scriptPubKey).hex(), "satoshis": output.nValue}
            for output in outputs]


class SharePoolRuleCasesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for unused in range(self.num_nodes)]

    def add_options(self, parser):
        parser.add_argument("--results", help="Write a machine-readable public fixture report to this path")

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        build = Path(self.config["environment"]["BUILDDIR"]) / "bin"
        extension = self.config["environment"]["EXEEXT"]
        self.signer_binary = build / ("bitcoin-sharepool-signer" + extension)
        self.node_binary = build / ("bitcoind" + extension)
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built on this platform")

    def make(self, owner=0, shares=(), transactions=()):
        node, signer = self.nodes[0], self.signers[owner]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16), height=info["height"] + 1,
            ntime=max(int(time.time()), info["time"] + 1), pool=self.pool,
            public_key=signer.public_key, sign_owner=signer.sign_owner,
            payout_script=self.scripts[owner], shares=shares, transactions=transactions,
            parent_manifest=self.manifests.get(parent))

    def solve(self, block):
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        assert int(block.hash, 16) <= uint256_from_compact(block.nBits)
        return block

    def accept(self, block, manifest):
        self.solve(block)
        result = self.nodes[0].submitblock(block.serialize().hex())
        assert_equal(result, None)
        self.sync_blocks()
        assert_equal([node.getbestblockhash() for node in self.nodes], [block.hash] * self.num_nodes)
        self.manifests[block.hash] = manifest
        return {"layer": "block", "interface": "RPC", "method": "submitblock",
                "result": result, "outcome": "accepted", "block_id": block.hash,
                "accepting_enforcing_nodes": self.num_nodes}

    def begin(self, name, owner, *, templates=(), shares=(), **extra):
        self.log.info("Rule case: %s", name)
        row = {"case": name, "fixture_owner": self.owners[owner],
               "template_ids": [template_id(block) for block in templates],
               "proofs": [{"proof_id": f"{share.proof_id:064x}",
                           "origin_template_id": template_id(share.header),
                           "claimed_owner_public_key": share.envelope.public_key.hex(),
                           "claimed_payout_script": share.envelope.payout_script.hex()}
                          for share in shares],
               "native_tip_before": self.nodes[0].getbestblockhash(), "checks": [], **extra}
        self.report["cases"].append(row)
        return row

    def finish(self, row):
        row["native_tip_after"] = self.nodes[0].getbestblockhash()
        row["result"] = "passed"

    def rpc_refusal(self, row, layer, method, raw, expected, *, node_index=0):
        try:
            getattr(self.nodes[node_index], method)(raw.hex())
        except JSONRPCException as error:
            assert_equal(error.error["code"], -26)
            assert expected in error.error["message"], error.error
            row["checks"].append({"layer": layer, "interface": "RPC", "method": method,
                "node": node_index, "outcome": "rejected", "error": error.error})
        else:
            raise AssertionError(f"{method} accepted {row['case']}")

    def gate_refusal(self, row, gate, block, expected, *, omission=False):
        try:
            gate.authorize(block.serialize())
        except (JobOmission if omission else ValueError) as error:
            assert expected in str(error), str(error)
            check = {"layer": "gate", "interface": "local miner gate", "method": "authorize",
                     "outcome": "refused", "error_type": type(error).__name__, "reason": str(error)}
            if omission:
                check["missing_proof_ids"] = list(error.proof_ids)
            else:
                check["underlying_rpc"] = "getblocktemplate(mode=proposal)"
            row["checks"].append(check)
            return error
        raise AssertionError(f"Gate accepted {row['case']}")

    def block_refusal(self, row, block, expected):
        self.solve(block)
        tips = [node.getbestblockhash() for node in self.nodes]
        for index, node in enumerate(self.nodes):
            result = node.submitblock(block.serialize().hex())
            assert_equal(result, expected)
            row["checks"].append({"layer": "block", "interface": "RPC", "method": "submitblock",
                "node": index, "outcome": "rejected", "reason": result,
                "block_id": block.hash, "block_pow_valid": True})
        assert_equal([node.getbestblockhash() for node in self.nodes], tips)

    def proposal(self, block, node_index=0):
        return self.nodes[node_index].getblocktemplate({"mode": "proposal",
            "rules": ["segwit", "blake2b", "sharepool"], "data": block.serialize().hex()})

    def run_test(self):
        self.directory = Path(self.options.tmpdir) / "rule-case-identities"
        self.directory.mkdir(mode=0o700)
        self.pool = 0x52554c4543415345
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.scripts = [b"\x00\x14" + bytes([0x11 + index]) * 20 for index in range(3)]
        self.key_files = [self.directory / f"owner-{index}.key" for index in range(3)]
        self.signers, self.gates, self.manifests = [], [], {}
        self.report = {"schema": 1, "profile": "SPN1 opt-in regtest", "started_utc": utc_now(),
            "result": "running", "cases": [], "genesis": f"{self.genesis:064x}", "pool": f"{self.pool:064x}",
            "native_binary_sha256": hashlib.sha256(self.node_binary.read_bytes()).hexdigest(),
            "native_signer_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
            "identity_scope": "Fresh native owner keys; fixture attribution does not identify the submitter of an invalid authorization.",
            "private_keys_exported": False, "physical_hardware_used": False, "public_network_used": False}
        try:
            self.signers = [NativeSigner.create(self.signer_binary, path, pool=self.pool,
                            payout_script=self.scripts[index]) for index, path in enumerate(self.key_files)]
            assert_equal(len({signer.public_key for signer in self.signers}), 3)
            self.owners = [{"name": name, "public_key": signer.public_key.hex(),
                            "payout_script": self.scripts[index].hex()}
                           for index, (name, signer) in enumerate(zip(("Alice", "Bob", "Carol"), self.signers))]
            self.report["owners"] = self.owners
            first, first_manifest = self.make()
            self.accept(first, first_manifest)

            for owner, node_index in ((0, 0), (2, 1)):
                def call(method, *args, index=node_index):
                    return getattr(self.nodes[index], method)(*args)
                gate = NativeMiningGate(self.directory / f"gate-{owner}.sqlite", rpc=call, pool=self.pool,
                    public_key=self.signers[owner].public_key, payout_script=self.scripts[owner])
                self.gates.append(gate)
            alice_gate, carol_gate = self.gates
            origins = [self.make(index) for index in range(3)]
            for block, unused in origins:
                for gate in self.gates:
                    gate.register_template(block.serialize())
            groups = []
            for (block, manifest), count in zip(origins, (6, 3, 1)):
                group, nonce = [], 0
                for unused in range(count):
                    proof = solve_share(block, manifest, start_nonce=nonce)
                    group.append(proof)
                    nonce = proof.header.nNonce + 1
                groups.append(group)
            a, b, c = groups
            nine, ten = tuple(a + b), tuple(a + b + c)
            late = solve_share(*origins[0], start_nonce=a[-1].header.nNonce + 1)

            row = self.begin("distinct_templates_and_nonce_only_identity", 0,
                templates=[entry[0] for entry in origins], shares=(a[0], a[1]))
            assert_equal(len(set(row["template_ids"])), 3)
            assert a[0].proof_id != a[1].proof_id
            assert_equal(template_id(a[0].header), template_id(a[1].header))
            assert_equal(template_id(a[0].header), template_id(origins[0][0]))
            for proof in (a[0], a[1]):
                checked = self.nodes[0].validatesharepoolshare(proof.serialize().hex())
                assert_equal(checked["valid"], True)
                row["checks"].append({"layer": "share", "interface": "RPC", "method": "validatesharepoolshare",
                    "outcome": "accepted", "result": checked})
            row["nonce_only_same_normalized_template"] = True
            self.finish(row)

            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(0xdeadbeef, 0), CScript(), 0xffffffff)]
            tx.vout = [CTxOut(1, CScript(self.scripts[0]))]
            tx.rehash()
            bad_origin, unused = self.make(transactions=(tx,))
            row = self.begin("origin_missing_input", 0, templates=(bad_origin,),
                transaction_id=tx.hash, missing_outpoint={"txid": f"{0xdeadbeef:064x}", "vout": 0})
            for index in range(2):
                self.rpc_refusal(row, "origin", "validatesharepooltemplate", bad_origin.serialize(),
                    "bad-txns-inputs-missingorspent", node_index=index)
            self.finish(row)

            block, manifest = origins[0]
            invalid_owner = copy.deepcopy(block)
            apply_to_coinbase(invalid_owner, replace(manifest, owner_signature=bytes(64)), parse_coinbase(block.vtx[0])[1])
            row = self.begin("origin_invalid_owner_signature", 0, templates=(invalid_owner,))
            self.rpc_refusal(row, "origin", "validatesharepooltemplate", invalid_owner.serialize(), "bad-sharepool-owner")
            self.finish(row)

            invalid_share = replace(a[0], owner_signature=bytes(64))
            row = self.begin("share_invalid_owner_signature", 0, templates=(block,), shares=(invalid_share,),
                             attribution_verified=False)
            self.rpc_refusal(row, "share", "validatesharepoolshare", invalid_share.serialize(), "bad-sharepool-proof")
            self.finish(row)

            insufficient = solve_share(block, manifest, valid=False)
            row = self.begin("share_insufficient_pow", 0, templates=(block,), shares=(insufficient,))
            self.rpc_refusal(row, "share", "validatesharepoolshare", insufficient.serialize(), "bad-sharepool-shares")
            self.finish(row)

            row = self.begin("duplicate_proof_idempotent_admission", 0, templates=(block,), shares=(a[0],))
            assert_equal(alice_gate.receive(a[0].serialize()), True)
            revision = alice_gate.maintenance()["revision"]
            assert_equal(alice_gate.receive(a[0].serialize()), False)
            assert_equal(alice_gate.maintenance()["revision"], revision)
            row["checks"].append({"layer": "gate", "interface": "local miner gate", "method": "receive",
                "outcome": "idempotent", "first_result": True, "duplicate_result": False,
                "receipt_revision_after_first": revision, "receipt_revision_after_duplicate": revision})
            self.finish(row)

            duplicate, unused = self.make(shares=(a[0], a[0]))
            row = self.begin("duplicate_proof_in_snapshot", 0, templates=(duplicate,), shares=(a[0], a[0]))
            self.block_refusal(row, duplicate, "bad-sharepool-shares")
            self.finish(row)
            for proof in nine:
                alice_gate.receive(proof.serialize())
            for proof in ten:
                carol_gate.receive(proof.serialize())

            settlement, manifest = self.make(shares=ten)
            correct = monetary_outputs(ten, reward=5_000_000_000, fallback_script=self.scripts[0])
            assert_equal([output.nValue for output in correct], [3_000_000_000, 1_500_000_000, 500_000_000])
            for alteration in ("payout_script", "payout_amount"):
                outputs = copy.deepcopy(correct)
                if alteration == "payout_script":
                    outputs[0].scriptPubKey = CScript(b"\x00\x14" + b"D" * 20)
                    outputs.sort(key=lambda output: bytes(output.scriptPubKey))
                else:
                    outputs[0].nValue += 500_000_000
                    outputs[1].nValue -= 500_000_000
                changed_manifest = replace(manifest, envelope=replace(manifest.envelope, payouts_root=payouts_root(outputs)))
                changed = copy.deepcopy(settlement)
                apply_to_coinbase(changed, changed_manifest, outputs)
                assert changed.m_mm_rhs != settlement.m_mm_rhs
                row = self.begin(alteration + "_tampering_recommitted", 0, templates=(settlement, changed),
                    shares=ten, expected_outputs=money(correct), proposed_outputs=money(outputs),
                    original_commitment=f"{settlement.m_mm_rhs:064x}", recomputed_commitment=f"{changed.m_mm_rhs:064x}")
                self.rpc_refusal(row, "origin", "validatesharepooltemplate", changed.serialize(), "bad-sharepool-payout")
                self.gate_refusal(row, alice_gate, changed, "bad-sharepool-payout")
                self.block_refusal(row, changed, "bad-sharepool-payout")
                self.finish(row)

            omitted, omitted_manifest = self.make(owner=2, shares=nine)
            omission_row = self.begin("known_omission_is_local_not_consensus", 2, templates=(omitted,), shares=ten,
                                      omitted_proof_ids=[f"{c[0].proof_id:064x}"])
            for index in range(2):
                assert_equal(self.proposal(omitted, index), None)
                omission_row["checks"].append({"layer": "block", "interface": "RPC",
                    "method": "getblocktemplate(mode=proposal)", "node": index, "result": None, "outcome": "valid"})
            error = self.gate_refusal(omission_row, carol_gate, omitted, "job omits known eligible unpaid work", omission=True)
            assert_equal(error.proof_ids, (f"{c[0].proof_id:064x}",))

            old_job, old_manifest = self.make(owner=0, shares=nine)
            authorization = alice_gate.authorize(old_job.serialize())
            self.solve(old_job)
            solved_bytes = authorization.block_for_header(old_job.serialize()[:164])
            assert_equal(solved_bytes, old_job.serialize())
            frozen_bytes, frozen_commitment = authorization.block_bytes, authorization.commitment
            assert_equal(alice_gate.ready_for_dispatch(authorization), True)
            row = self.begin("frozen_commitment_and_late_share_refresh", 0, templates=(old_job,), shares=(late,),
                authorized_job_id=authorization.job_id, frozen_commitment=frozen_commitment,
                solved_candidate_id=old_job.hash)
            assert_equal(alice_gate.receive(late.serialize()), True)
            assert_equal(alice_gate.needs_refresh(authorization), True)
            assert_equal(alice_gate.ready_for_dispatch(authorization), False)
            assert_equal(authorization.block_bytes, frozen_bytes)
            assert_equal(authorization.commitment, frozen_commitment)
            assert_equal(self.proposal(old_job), None)
            refreshed, unused = self.make(owner=0, shares=nine + (late,))
            refreshed_auth = alice_gate.authorize(refreshed.serialize())
            assert_equal(alice_gate.ready_for_dispatch(refreshed_auth), True)
            assert refreshed_auth.commitment != frozen_commitment
            assert template_id(refreshed) != template_id(old_job)
            try:
                authorization.block_for_header(refreshed.serialize()[:164])
            except ValueError as error:
                assert_equal(str(error), "work changes the authorized template or settlement")
                row["checks"].append({"layer": "gate", "interface": "local mining authorization",
                    "method": "block_for_header", "outcome": "refused", "error_type": type(error).__name__, "reason": str(error)})
            else:
                raise AssertionError("Old authorization permitted a changed commitment")
            row["checks"].extend([
                {"layer": "gate", "method": "needs_refresh / ready_for_dispatch", "outcome": "refresh required",
                 "old_needs_refresh": True, "old_ready": False, "old_bytes_unchanged": True, "new_ready": True},
                {"layer": "block", "interface": "RPC", "method": "getblocktemplate(mode=proposal)",
                 "outcome": "valid", "result": None, "candidate": "old solved immutable job"}])
            row["refreshed_template_id"] = template_id(refreshed)
            row["refreshed_commitment"] = refreshed_auth.commitment
            self.finish(row)

            # Submit the exact candidate Carol refused, bypassing only her local
            # dispatch gate. Both enforcing full nodes must still accept it.
            omission_row["checks"].append(self.accept(omitted, omitted_manifest))
            expected_nine = monetary_outputs(nine, reward=5_000_000_000, fallback_script=self.scripts[2])
            assert_equal(money(parse_coinbase(omitted.vtx[0])[1]), money(expected_nine))
            assert_equal([output.nValue for output in expected_nine], [3_333_333_333, 1_666_666_667])
            assert c[0].proof_id not in {entry.proof_id for entry in omitted_manifest.post_state}
            omission_row["paid_outputs"] = money(expected_nine)
            omission_row["omitted_proof_remains_unpaid"] = True
            self.finish(omission_row)

            replay, unused = self.make(shares=(a[0],))
            row = self.begin("repeated_payment_rejected", 0, templates=(replay,), shares=(a[0],),
                             first_payment_block=omitted.hash)
            checked = self.nodes[0].validatesharepoolshare(a[0].serialize().hex())
            assert_equal(checked["valid"], True)
            row["checks"].append({"layer": "share", "interface": "RPC", "method": "validatesharepoolshare",
                "outcome": "proof still valid", "result": checked,
                "note": "This RPC checks proof validity, not payment eligibility against paid state."})
            self.block_refusal(row, replay, "bad-sharepool-shares")
            self.finish(row)

            winning = winner_share(omitted, omitted_manifest)
            carol_gate.register_template(omitted.serialize())
            assert_equal(carol_gate.receive(winning.serialize()), True)
            assert_equal(carol_gate.receive(late.serialize()), True)
            carried = (c[0], late, winning)
            followup, followup_manifest = self.make(owner=2, shares=carried)
            row = self.begin("late_omitted_and_winning_work_settle_next_block", 2,
                             templates=(followup, omitted), shares=carried)
            assert_equal(carol_gate.ready_for_dispatch(carol_gate.authorize(followup.serialize())), True)
            row["checks"].append(self.accept(followup, followup_manifest))
            assert {share.proof_id for share in carried} <= {entry.proof_id for entry in followup_manifest.post_state}
            assert_equal(len(followup_manifest.post_state), 12)
            expected_followup = monetary_outputs(carried, reward=5_000_000_000, fallback_script=self.scripts[2])
            assert_equal(money(parse_coinbase(followup.vtx[0])[1]), money(expected_followup))
            row["paid_outputs"] = money(expected_followup)
            row["paid_state_entries"] = len(followup_manifest.post_state)
            self.finish(row)
            self.report["result"] = "passed"
            self.report["native_blocks"] = self.nodes[0].getblockcount()
            self.report["final_tip"] = self.nodes[0].getbestblockhash()
            self.log.info("All %d identifiable rule cases passed", len(self.report["cases"]))
        except Exception as error:
            self.report["result"] = "failed"
            self.report["failure"] = {"type": type(error).__name__, "message": str(error)[:2048]}
            raise
        finally:
            for gate in self.gates:
                gate.close()
            for path in self.key_files:
                if path.exists():
                    path.unlink()
            self.report["finished_utc"] = utc_now()
            if self.options.results:
                Path(self.options.results).write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    SharePoolRuleCasesTest(__file__).main()
