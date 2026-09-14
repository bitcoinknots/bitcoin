#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""An actual v8 local credit refusal must not suppress an issued native winner.

Two disconnected regtest nodes and an intentionally small local snapshot budget.
The service's owner-side submit path receives real Sia proofs and calls native
RPCs; socket framing is covered by feature_sharepool_hash_vardiff_stratum.py.
This is a bounded correctness test, not a production capacity measurement.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_admission_budget import AdmissionRefused
from hash_mining_gate import HashMiningGate, PROOF
from hash_snapshot import HashSigner
from hash_stratum import VardiffStratumService
from hash_vardiff import VardiffController
from testnet_template import proof_from_sia, sia_notify
from feature_sharepool_hash_datum_cadence import Clock
from feature_sharepool_hash_vardiff_stratum import SharePoolHashVardiffStratumTest
from test_framework.util import assert_equal, assert_raises


class SharePoolHashStratumPressureTest(SharePoolHashVardiffStratumTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 2
        self.extra_args = [list(self.extra_args[0]) for _ in range(self.num_nodes)]

    def run_test(self):
        node = self.nodes[0]
        directory = Path(self.options.tmpdir)
        path = directory / "pressure-owner.key"
        service = None
        native_calls = []

        def rpc(method, *args):
            native_calls.append((method, args))
            return getattr(node, method)(*args)

        try:
            signer = HashSigner.create(self.signer_binary, path, pool=101,
                payout_script=b"\x00\x14" + b"p" * 20)
            with HashMiningGate(directory / "pressure-gate.sqlite", rpc=rpc,
                    pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
                    profile_version=8, share_work_bits=0, snapshot_budget=2048) as gate:
                clock = Clock()
                controller = VardiffController(initial_work_bits=0, clock=clock)
                service = VardiffStratumService(gate, controller=controller,
                    sign_owner=signer.sign_owner, observer_rpc=rpc, clock=clock)
                # No observer thread or socket handler shares this RPC client.
                service._observe()
                service.service_once()
                work = service.current
                assert work is not None
                assert_equal(work.snapshot.envelope.share_work_bits, 0)
                prefix = bytes(4)
                notify = sia_notify(work.template, prefix, clean=True)
                native_target = service._native_target(work.template.header.nBits)
                next_nonce = 0

                def search(winning):
                    nonlocal next_nonce
                    for _ in range(10000):
                        encoded = next_nonce.to_bytes(8, "little").hex()
                        next_nonce += 1
                        proof = proof_from_sia(work.template, prefix, bytes(8), notify[7], encoded)
                        if (proof.hash_int <= native_target) == winning:
                            return proof, ["sharepool.regtest", work.template.job_id,
                                bytes(8).hex(), notify[7], encoded]
                    raise AssertionError("bounded synthetic nonce search failed")

                self.log.info("Real native-verified nonwinning shares fill the local next-batch credit budget")
                accepted_params, refusal = [], None
                first_receive = len(native_calls)
                for _ in range(32):
                    proof, params = search(False)
                    before = gate.archive_head()
                    try:
                        assert service._submit(prefix, params)
                    except AdmissionRefused as error:
                        refusal = error
                        assert_equal(gate.archive_head(), before)
                        assert_raises(KeyError, gate._read, PROOF, proof.display_hash)
                        break
                    accepted_params.append(params)
                assert refusal is not None and accepted_params
                assert_equal(refusal.decision.mode, "DRAIN")
                assert "offered-proof-not-selected" in refusal.decision.reasons or "resource-budget" in refusal.decision.reasons
                assert_equal(service.stats["acknowledged"], len(accepted_params))
                assert_equal(service.stats["capacity_refused"], 1)
                assert_equal(service.stats["rejected"], 0)
                assert_equal(service.stats["submitted_candidates"], 0)
                assert controller.status()["admission_paused"]
                assert_equal(controller.status()["window_accepted_work"], 0)
                calls = [name for name, _ in native_calls[first_receive:]]
                assert_equal(calls.count("validatesharepoolhashshare"), len(accepted_params) + 1)
                assert "validatesharepoolhashtemplate" not in calls
                assert "submitsharepoolhashsnapshot" not in calls

                self.log.info("A duplicate is still exact, while a refused winning proof submits its original block")
                before = gate.archive_head()
                assert service._submit(prefix, accepted_params[0])
                assert_equal(gate.archive_head(), before)
                assert_equal(service.stats["duplicate"], 1)
                assert controller.status()["admission_paused"]

                self.log.info("Only native missing data permits retained recovery; a later credit refusal still writes no receipt")
                source = node
                node = self.nodes[1]
                assert_equal(node.getbestblockhash(), source.getbestblockhash())
                assert_equal(node.getsharepoolhashstatus()["stored_snapshots"], 0)
                recovered_proof, recovered_params = search(False)
                recovery_start = len(native_calls)
                assert_raises(AdmissionRefused, service._submit, prefix, recovered_params)
                assert_equal(gate.archive_head(), before)
                assert_raises(KeyError, gate._read, PROOF, recovered_proof.display_hash)
                recovery_calls = [name for name, _ in native_calls[recovery_start:]]
                assert_equal(recovery_calls.count("validatesharepoolhashshare"), 2)
                assert_equal(recovery_calls.count("validatesharepoolhashtemplate"), 1)
                assert recovery_calls.count("submitsharepoolhashsnapshot") > 0
                assert_equal(service.stats["capacity_refused"], 2)

                winner, params = search(True)
                calls_before = len(native_calls)
                assert_raises(AdmissionRefused, service._submit, prefix, params)
                assert_equal(gate.archive_head(), before)
                assert_raises(KeyError, gate._read, PROOF, winner.display_hash)
                assert_equal([args for method, args in native_calls[calls_before:] if method == "submitblock"],
                    [(winner.block.hex(),)])
                assert_equal(node.getbestblockhash(), winner.display_hash)
                assert_equal(bytes.fromhex(node.getblock(winner.display_hash, 0)), winner.block)
                warm_calls = [name for name, _ in native_calls[calls_before:]]
                assert_equal(warm_calls.count("validatesharepoolhashshare"), 1)
                assert "validatesharepoolhashtemplate" not in warm_calls
                assert "submitsharepoolhashsnapshot" not in warm_calls
                assert_equal(service.stats["capacity_refused"], 3)
                assert_equal(service.stats["acknowledged"], len(accepted_params))
                assert_equal(service.stats["accepted_candidates"], 1)
                assert_equal(service.stats["rejected"], 0)
                assert_equal(controller.status()["window_accepted_work"], 0)
                assert controller.status()["admission_paused"]
                assert node.verifychain(4, 0)
                report = {"network": "two disconnected native regtest nodes", "profile": 8,
                    "local_snapshot_budget": 2048, "hardware_used": False,
                    "transport": "real Sia proofs through owner-side Stratum submit path; no socket framing",
                    "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
                    "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                        for name in ("contrib/sharepool/hash_mining_gate.py", "contrib/sharepool/hash_gate_admission.py",
                            "contrib/sharepool/hash_admission_accounting.py", "contrib/sharepool/hash_stratum.py",
                            "contrib/sharepool/hash_vardiff.py", "test/functional/feature_sharepool_hash_stratum_pressure.py")},
                    "accepted_before_pressure": len(accepted_params), "refusal_reasons": refusal.decision.reasons,
                    "missing_only_recovery": {"proof_rpcs": 2, "template_rpcs": 1,
                        "snapshot_replay_rpcs": recovery_calls.count("submitsharepoolhashsnapshot"),
                        "journal_unchanged_after_recovery_and_refusal": True},
                    "block": winner.display_hash, "stats": dict(service.stats),
                    "checks": ["actual_gate_budget_refuses_native_valid_share", "refused_proofs_not_journaled",
                        "warm_proofs_no_template_or_snapshot_replay", "exact_duplicate_not_recredited",
                        "missing_only_recovery_into_empty_native_peer", "recovered_refusal_not_journaled",
                        "native_winner_submitted_with_exact_old_bytes", "native_block_accepted",
                        "pressure_pauses_estimator_without_credit", "native_verifychain"]}
                (directory / "stratum-pressure-results.json").write_text(json.dumps(report, indent=2) + "\n")
                service.close()
                service = None
        finally:
            if service is not None:
                service.close()
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashStratumPressureTest(__file__).main()
