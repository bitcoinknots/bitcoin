#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native proof-first recovery with bounded Python state reuse on isolated regtest.

Correctness and RPC call counts only; this small fixture is not a capacity or
latency benchmark. Native snapshots and templates may survive daemon restart.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate, SNAPSHOT, TEMPLATE
from hash_snapshot import COMPACT_TIDES_RULES_HASH, HashSigner, solve_share
from native_mining_gate import parse_block, template_id
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CTxInWitness
from test_framework.util import assert_equal, assert_raises_rpc_error


class RecordingRPC:
    def __init__(self, node):
        self.node, self.calls = node, []

    def __call__(self, method, *args):
        event = {"method": method}
        self.calls.append(event)
        if method == "validatesharepoolhashtemplate":
            event["overlay"] = len(args) > 1 and args[1] is not None
            event["mining"] = args[2] if len(args) > 2 else True
        try:
            result = getattr(self.node, method)(*args)
        except JSONRPCException as error:
            event["error"] = dict(error.error)
            raise
        event["success"] = True
        return result

    def summary(self):
        return {"counts": dict(Counter(event["method"] for event in self.calls)),
                "validation": [event for event in self.calls if event["method"].startswith("validatesharepoolhash")]}


class SharePoolHashStateReuseTest(SharePoolHashTidesTest):
    PROFILE_VERSION = 7

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=1, choices=(1,))

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
                            "-sharepoolcompacttides=1", "-testactivationheight=blake2b@1",
                            "-disablewallet", "-networkactive=0"] for _ in range(self.num_nodes)]

    @staticmethod
    def validation_calls(rpc):
        return [event for event in rpc.calls if event["method"].startswith("validatesharepoolhash")]

    def assert_warm(self, rpc):
        calls = self.validation_calls(rpc)
        assert_equal([event["method"] for event in calls], ["validatesharepoolhashshare"])
        assert_equal(calls[0]["success"], True)
        assert any(event["method"] == "getblockheader" for event in rpc.calls)

    def run_test(self):
        node, recovery_node = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        directory = Path(self.options.tmpdir)
        keys = [directory / f"state-owner-{index}.key" for index in range(2)]
        report = {"network": "isolated native regtest", "profile": "hash-only-v7-compact-tides",
                  "scope": "Correctness and RPC call counts; no capacity or latency claim",
                  "rules": f"{COMPACT_TIDES_RULES_HASH:064x}",
                  "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
                  "signer_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
                  "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                      for name in ("contrib/sharepool/hash_snapshot.py", "contrib/sharepool/hash_state_cache.py",
                                   "contrib/sharepool/hash_gate_batch.py", "contrib/sharepool/hash_mining_gate.py",
                                   "contrib/sharepool/hash_gate_rpc.py", "test/functional/feature_sharepool_hash_state_reuse.py")}}
        gate = None
        try:
            signers = [HashSigner.create(self.signer_binary, key, pool=101,
                payout_script=b"\x00\x14" + bytes([index + 1]) * 20) for index, key in enumerate(keys)]
            rpc = RecordingRPC(node)
            gate = HashMiningGate(directory / "state-gate.sqlite", rpc=rpc, profile_version=7,
                pool=101, public_key=signers[0].public_key, payout_script=signers[0].payout_script)
            self.log.info("Create an actual native parent with two admitted recipients")
            initial = [self.origin(0, signer) for signer in signers]
            for block, opening, proof in initial:
                gate.register_snapshot(opening.serialize())
                gate.register_template(block.serialize())
                assert gate.receive(proof)
            parent, parent_state = gate.make_native(sign_owner=signers[0].sign_owner)
            gate.authorize(parent.serialize(), parent_state.serialize())
            assert_equal(self.payouts(parent), {signer.payout_script: 2_500_000_000 for signer in signers})
            self.publish(0, parent, parent_state)
            # Copy only chain dependencies, without any later standalone jobs.
            for _, opening, _ in initial:
                self.store(1, opening)
            self.store(1, parent_state)
            assert_equal(recovery_node.submitblock(parent.serialize().hex()), None)
            assert_equal(recovery_node.getbestblockhash(), parent.hash)

            origins = [self.origin(0, signer) for signer in signers]
            for block, opening, _ in origins:
                gate.register_snapshot(opening.serialize())
                gate.register_template(block.serialize())
            a_block, a_opening, a_first = origins[0]
            a_second = solve_share(a_block, a_opening, start_nonce=a_first.header.nNonce + 1)
            b_block, b_opening, b_proof = origins[1]

            self.log.info("Warm state calculations retain fresh native proof checks and header reads")
            warmed = gate._parent_snapshot(1, parent.hash, {})
            assert_equal(len(warmed.post_state), 2)
            before_hits = gate._compact_state_cache.stats()["hits"]
            report["warm"] = []
            for proof in (a_first, a_second):
                rpc.calls.clear()
                assert gate.receive(proof)
                self.assert_warm(rpc)
                report["warm"].append(rpc.summary())
            assert gate._compact_state_cache.stats()["hits"] > before_hits

            self.log.info("Reject an exact-header witness-body substitution before the proof endpoint")
            changed = parse_block(a_block.serialize())
            changed.vtx[0].wit.vtxinwit = [CTxInWitness()]
            changed.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [b"x" * 32]
            assert_equal(template_id(changed), template_id(a_block))
            assert changed.serialize() != a_block.serialize()
            staged = {(TEMPLATE, template_id(a_block)): changed.serialize(),
                      (SNAPSHOT, a_opening.hash_hex): a_opening.serialize()}
            gate._require_origin(a_first, staged)  # The header alone cannot identify witness bytes.
            before_head = gate.archive_head()
            rpc.calls.clear()
            try:
                gate._native_share(a_first, parent.hash, staged)
            except ValueError as error:
                assert "exact committed job" in str(error)
            else:
                raise AssertionError("staged witness substitution was accepted")
            assert_equal(self.validation_calls(rpc), [])
            assert_equal(gate.archive_head(), before_head)
            report["witness_substitution"] = {"rejected_before_native_proof": True, "journal_unchanged": True}

            self.log.info("A same-tip node without the full job body triggers exactly one bounded recovery")
            self.store(1, b_opening)
            assert_raises_rpc_error(-25, "sharepool-hash-data-missing", recovery_node.validatesharepoolhashshare,
                                    b_proof.serialize().hex())
            rpc.node = recovery_node
            before_hits = gate._compact_state_cache.stats()["hits"]
            rpc.calls.clear()
            assert gate.receive(b_proof)
            calls = self.validation_calls(rpc)
            assert_equal([event["method"] for event in calls],
                         ["validatesharepoolhashshare", "validatesharepoolhashtemplate", "validatesharepoolhashshare"])
            assert_equal(calls[0]["error"]["code"], -25)
            assert_equal(calls[0]["error"]["message"], "sharepool-hash-data-missing")
            assert_equal((calls[1]["overlay"], calls[1]["mining"], calls[1]["success"]), (False, False, True))
            assert_equal(calls[2]["success"], True)
            assert any(event["method"] == "getblockheader" for event in rpc.calls)
            assert gate._compact_state_cache.stats()["hits"] > before_hits
            report["missing_body_recovery"] = rpc.summary()

            self.log.info("Same-tip daemon restart cannot substitute cached Python state for a native verdict")
            self.restart_node(1)
            assert_equal(recovery_node.getbestblockhash(), parent.hash)
            before_head = gate.archive_head()
            before_hits = gate._compact_state_cache.stats()["hits"]
            rpc.calls.clear()
            assert_equal(gate.receive(b_proof), False)  # Duplicate retained receipt, freshly checked.
            methods = [event["method"] for event in self.validation_calls(rpc)]
            assert methods in (["validatesharepoolhashshare"],
                ["validatesharepoolhashshare", "validatesharepoolhashtemplate", "validatesharepoolhashshare"])
            assert any(event["method"] == "getblockheader" for event in rpc.calls)
            assert gate._compact_state_cache.stats()["hits"] > before_hits
            assert_equal(gate.archive_head(), before_head)
            report["same_tip_restart"] = rpc.summary()

            # This second backend has not seen A's standalone height-2 job.
            # Recovering B cannot silently certify or publish unrelated work.
            before_head = gate.archive_head()
            assert_raises_rpc_error(-25, "sharepool-hash-data-missing", gate.make_native,
                                    sign_owner=signers[0].sign_owner)
            assert_equal(gate.archive_head(), before_head)
            rpc.calls.clear()
            assert_equal(gate.receive(a_first), False)
            calls = self.validation_calls(rpc)
            assert_equal([event["method"] for event in calls],
                         ["validatesharepoolhashshare", "validatesharepoolhashtemplate", "validatesharepoolhashshare"])
            assert_equal(calls[0]["error"]["message"], "sharepool-hash-data-missing")
            assert_equal(calls[-1]["success"], True)
            assert_equal(gate.archive_head(), before_head)
            report["remaining_origin_recovery"] = rpc.summary()
            report["incomplete_settlement"] = {"rejected_missing_data": True, "journal_unchanged": True}

            self.log.info("Recovered work settles to the exact 3:2 native coinbase payouts")
            block, snapshot = gate.make_native(sign_owner=signers[0].sign_owner)
            authorization = gate.authorize(block.serialize(), snapshot.serialize())
            assert gate.ready_for_dispatch(authorization)
            assert_equal({share.proof_id for share in snapshot.shares}, {a_first.proof_id, a_second.proof_id, b_proof.proof_id})
            expected = {signers[0].payout_script: 3_000_000_000, signers[1].payout_script: 2_000_000_000}
            assert_equal(self.payouts(block), expected)
            self.publish(1, block, snapshot)
            assert recovery_node.verifychain(4, 0)
            assert_equal({item["status"] for item in gate.receipt_status(limit=16)["receipts"]}, {"confirmed_admitted"})
            assert_equal(gate.archive_head()["receipt_revision"], 5)
            report.update(result="passed", final_height=recovery_node.getblockcount(), retained_receipts=5,
                          payouts={script.hex(): amount for script, amount in expected.items()},
                          state_cache=gate._compact_state_cache.stats())
            (directory / "state-reuse-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            if gate is not None:
                gate.close()
            for key in keys:
                key.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashStateReuseTest(__file__).main()
