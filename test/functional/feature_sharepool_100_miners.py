#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""100 logical miners, real native P2P/UTXOs/PoW, and the 32-share liveness limit.

A regression PASS includes reproducing the current admission failure; it is NOT
an assertion that the honest 100-miner pipeline completed. After recording that
failure, explicit consensus-control submissions settle the disclosed work over
four blocks so payout, replay, historical origin and delivery checks still run.
No gate is weakened, no public network is used and no hardware is rerouted.
"""
from concurrent.futures import ThreadPoolExecutor
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
from native_enforcement import (MAX_SHARES, apply_to_coinbase, candidate, parse_coinbase,
    payouts_root, solve_share, winner_share)
from native_mining_gate import JobOmission, NativeMiningGate, template_id
from native_node_peer import NativeNodeRelay
from native_signer import NativeSigner
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePool100MinersTest(BitcoinTestFramework):
    MINERS = 100

    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1",
                            "-disablewallet", "-debug=net"] for _ in range(self.num_nodes)]

    def add_options(self, parser):
        parser.add_argument("--results", type=Path, help="Write public test evidence JSON outside node directories")

    def setup_network(self):
        self.setup_nodes()
        for index in range(self.num_nodes):
            self.connect_nodes(index, (index + 1) % self.num_nodes)

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    def make(self, owner, *, shares=(), transactions=(), fees=0, parent=None):
        node = self.nodes[owner % self.num_nodes]
        parent = node.getbestblockhash() if parent is None else parent
        info = node.getblockheader(parent)
        signer = self.signers[owner]
        return candidate(genesis=self.genesis, native_parent=int(parent, 16), height=info["height"] + 1,
            ntime=max(self.start_time, info["time"] + 1), pool=self.pool, public_key=signer.public_key,
            sign_owner=signer.sign_owner, payout_script=self.scripts[owner], shares=shares,
            parent_manifest=self.manifests.get(parent), transactions=transactions, fees=fees,
            witness=bool(transactions))

    def publish(self, block, manifest, *, node=0, sync=True):
        block.rehash()
        block.solve()
        assert_equal(self.nodes[node].submitblock(block.serialize().hex()), None)
        self.manifests[block.hash] = manifest
        if sync:
            self.sync_blocks(timeout=90)
            for peer in self.nodes:
                assert_equal(peer.getbestblockhash(), block.hash)
                assert_equal(peer.getblock(block.hash, 0), block.serialize().hex())
        return winner_share(block, manifest)

    def open_gate(self, owner):
        node = self.nodes[owner % self.num_nodes]
        return NativeMiningGate(self.directory / f"miner-{owner:03d}.sqlite",
            rpc=lambda method, *args: getattr(node, method)(*args), pool=self.pool,
            public_key=self.signers[owner].public_key, payout_script=self.scripts[owner])

    def node_objects(self, node):
        return {(item["kind"], item["id"]) for item in node.getsharepoolinventory()["items"]}

    def converge(self, expected, *, label, timeout=300):
        began, deadline, next_log = time.monotonic(), time.monotonic() + timeout, 0
        while True:
            inventories = [self.node_objects(node) for node in self.nodes]
            missing = [len(expected - items) for items in inventories]
            if not any(missing):
                elapsed = time.monotonic() - began
                self.report["relay_stages"].append({"label": label, "expected_objects": len(expected),
                    "seconds": round(elapsed, 3), "missing_by_node": missing})
                return
            now = time.monotonic()
            if now > deadline:
                raise AssertionError(f"{label}: native evidence did not converge; missing per node {missing}")
            if now >= next_log:
                self.log.info("%s: missing objects per native node %s", label, missing)
                next_log = now + 20
            time.sleep(0.2)

    def import_all(self, expected):
        began = time.monotonic()
        for owner, (gate, bridge) in enumerate(zip(self.gates, self.bridges)):
            for _ in range(12):
                known = {(item["kind"], item["id"]) for item in gate.active_inventory()["items"]}
                if expected <= known:
                    break
                bridge.poll()
            else:
                raise AssertionError(f"miner {owner} did not import all native evidence")
            known = {(item["kind"], item["id"]) for item in gate.active_inventory()["items"]}
            assert expected <= known
            if owner % 20 == 19:
                self.log.info("Full-origin validation and durable evidence: %d/100 miner gates", owner + 1)
        self.report["gate_import_seconds"].append(round(time.monotonic() - began, 3))

    @staticmethod
    def spend(previous, index, value, redeem, script, fee):
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(previous, index), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(value - fee, CScript(script))]
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(redeem)]
        transaction.rehash()
        return transaction

    def save_report(self):
        if self.options.results:
            self.options.results.parent.mkdir(parents=True, exist_ok=True)
            self.options.results.write_text(json.dumps(self.report, indent=2) + "\n")

    def run_test(self):
        self.start_time = int(time.time())
        self.directory = Path(self.options.tmpdir) / "logical-miners"
        self.directory.mkdir(mode=0o700)
        self.pool = 0x100decaf
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.signers, self.gates, self.bridges, self.manifests = [], [], [], {}
        self.keys = [self.directory / f"owner-{owner:03d}.key" for owner in range(self.MINERS)]
        self.redeems = [CScript([owner, OP_DROP, OP_TRUE]) for owner in range(self.MINERS)]
        self.scripts = [b"\x00\x20" + hashlib.sha256(bytes(script)).digest() for script in self.redeems]
        self.report = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(),
            "result": "running", "network": "isolated native regtest", "public_testnet": False,
            "logical_miners": 100, "native_nodes": self.num_nodes, "hashing_threads": 8,
            "physical_miners_used": 0, "consensus_max_shares": MAX_SHARES,
            "transport": "v2" if self.options.v2transport else "v1", "relay_stages": [],
            "gate_import_seconds": [], "miners": [], "settlements": [], "rule_cases": [],
            "honest_dispatch_pipeline_completed": False,
            "limitations": ["100 logical miner gates share five native nodes and eight CPU hashing threads",
                "Loopback regtest timing is not WAN or measured hashrate performance",
                "Share target and block target are both extremely easy in this test profile",
                "Controlled block submissions after job refusal are explicit bypass tests, not honest mining success"]}
        binary = Path(self.options.bitcoind)
        self.report["native_binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        started = time.monotonic()
        try:
            self.log.info("Create100 fresh native owner keys and distinct payout scripts")
            self.signers = [NativeSigner.create(self.signer_binary, key_file, pool=self.pool,
                payout_script=self.scripts[owner]) for owner, key_file in enumerate(self.keys)]
            assert_equal(len({s.public_key for s in self.signers}), 100)
            assert_equal(len(set(self.scripts)), 100)

            self.log.info("Mature native funding and create100 independent spendable transaction inputs")
            first, manifest = self.make(0)
            self.publish(first, manifest, sync=False)
            funding_coinbase = first.vtx[0].rehash()
            while self.nodes[0].getblockcount() < 101:
                block, manifest = self.make(0)
                self.publish(block, manifest, sync=False)
            self.sync_blocks(timeout=90)
            shared_redeem = CScript([OP_TRUE])
            funding_script = b"\x00\x20" + hashlib.sha256(bytes(shared_redeem)).digest()
            funding_value = 49_999_990
            funding = self.spend(int(funding_coinbase, 16), 0, 5_000_000_000,
                self.redeems[0], funding_script, 1000)
            funding.vout = [CTxOut(funding_value, CScript(funding_script)) for _ in range(100)]
            funding.rehash()
            funding_block, manifest = self.make(0, transactions=(funding,), fees=1000)
            self.publish(funding_block, manifest)
            assert_equal(self.nodes[0].getblockcount(), 102)
            funding_id = int(funding.rehash(), 16)
            self.transactions = [self.spend(funding_id, owner, funding_value, shared_redeem,
                self.scripts[owner], 100 + owner) for owner in range(100)]
            assert_equal(len({tx.rehash() for tx in self.transactions}), 100)
            self.gates = [self.open_gate(owner) for owner in range(100)]
            self.bridges = [NativeNodeRelay(gate) for gate in self.gates]
            connections = [[(p["id"], p["addr"]) for p in node.getpeerinfo()] for node in self.nodes]

            self.log.info("Authorize100 distinct full transaction templates before any share is submitted")
            origins, origin_manifests, authorizations, ids = [], [], [], []
            for owner in range(100):
                origin, manifest = self.make(owner, transactions=(self.transactions[owner],), fees=100 + owner)
                authorization = self.gates[owner].authorize(origin.serialize())
                assert self.gates[owner].ready_for_dispatch(authorization)
                origins.append(origin)
                origin_manifests.append(manifest)
                authorizations.append(authorization)
                ids.append(template_id(origin))
            assert_equal(len(set(ids)), 100)
            assert_equal(len({origin.hashMerkleRoot for origin in origins}), 100)
            with ThreadPoolExecutor(max_workers=8) as workers:
                proofs = list(workers.map(lambda pair: solve_share(*pair), zip(origins, origin_manifests)))
            assert_equal(len({proof.proof_id for proof in proofs}), 100)
            for owner, proof in enumerate(proofs):
                assert_equal(self.gates[owner].receive(proof.serialize()), True)
                self.bridges[owner].poll()
                self.report["miners"].append({"miner_id": f"miner-{owner:03d}", "native_node": owner % 5,
                    "owner_public_key": self.signers[owner].public_key.hex(),
                    "payout_script": self.scripts[owner].hex(), "template_id": ids[owner],
                    "transaction_id": self.transactions[owner].rehash(), "proof_id": f"{proof.proof_id:064x}",
                    "initial_job_authorized": True, "share_native_validated": True, "paid_satoshis": 0})
            expected = {("template", identity) for identity in ids} | {
                ("receipt", f"{proof.proof_id:064x}") for proof in proofs}
            self.converge(expected, label="100 origins +100 proofs")
            self.import_all(expected)
            assert_equal([[(p["id"], p["addr"]) for p in node.getpeerinfo()] for node in self.nodes], connections)
            self.report["existing_connections_preserved"] = True
            self.report["received_spndata_bytes"] = [sum(p.get("bytesrecv_per_msg", {}).get("spndata", 0)
                for p in node.getpeerinfo()) for node in self.nodes]
            assert all(self.report["received_spndata_bytes"])
            for gate, authorization in zip(self.gates, authorizations):
                assert gate.needs_refresh(authorization)
                assert not gate.ready_for_dispatch(authorization)
            self.report["all100_initial_jobs_require_refresh"] = True
            self.save_report()

            self.log.info("Every informed gate must refuse a32-proof job that omits68 acknowledged proofs")
            ordered = sorted(proofs, key=lambda p: p.proof_id)
            remaining = list(ordered)
            known_winners = []
            all_paid = set()
            for round_number in range(4):
                carry = known_winners[-1:]  # prior winning proof was not in its own solved commitment
                chosen = remaining[:MAX_SHARES - len(carry)]
                remaining = remaining[len(chosen):]
                included = tuple(chosen + carry)
                transactions = self.transactions if round_number == 0 else ()
                fees = sum(100 + owner for owner in range(100)) if round_number == 0 else 0
                refusals, candidate_jobs = [], []
                for owner in range(100):
                    block, manifest = self.make(owner, shares=included, transactions=transactions, fees=fees)
                    try:
                        authorized = self.gates[owner].authorize(block.serialize())
                        assert self.gates[owner].ready_for_dispatch(authorized)
                        assert not remaining
                    except JobOmission as error:
                        assert_equal(set(error.proof_ids), {f"{p.proof_id:064x}" for p in remaining})
                        assert remaining
                        refusals.append({"miner_id": f"miner-{owner:03d}", "reason": str(error),
                            "missing_count": len(error.proof_ids)})
                    candidate_jobs.append((block, manifest))
                assert_equal(len(refusals), 100 if remaining else 0)
                block, manifest = candidate_jobs[round_number]
                parent = self.nodes[0].getbestblockhash()
                if round_number == 0:
                    self.gates[0].close()
                    self.gates[0] = self.open_gate(0)
                    self.bridges[0] = NativeNodeRelay(self.gates[0])
                    try:
                        self.gates[0].authorize(candidate_jobs[0][0].serialize())
                    except JobOmission as error:
                        assert_equal(len(error.proof_ids), 68)
                    else:
                        raise AssertionError("restart improperly cleared known-work obligations")
                    self.report["restart_preserves_100_proof_obligation"] = True
                    bad = copy.deepcopy(block)
                    outputs = list(copy.deepcopy(parse_coinbase(block.vtx[0])[1]))
                    outputs[0].nValue += 1
                    outputs[1].nValue -= 1
                    bad_manifest = replace(manifest, envelope=replace(manifest.envelope,
                        payouts_root=payouts_root(outputs)))
                    apply_to_coinbase(bad, bad_manifest, outputs, witness=True)
                    bad.solve()
                    reasons = []
                    for node in self.nodes:
                        reason = node.submitblock(bad.serialize().hex())
                        assert isinstance(reason, str) and reason.startswith("bad-sharepool-payout"), reason
                        assert_equal(node.getbestblockhash(), parent)
                        reasons.append(reason)
                    self.report["rule_cases"].append({"case": "one-satoshi diversion with recomputed root",
                        "layer": "native consensus", "reasons_by_node": reasons,
                        "coordinator_owner": self.signers[0].public_key.hex(), "active_tip_unchanged": True})
                self.log.info("Settlement control%d: %d original proofs +%d prior winner; %d gates refuse; missing%d",
                    round_number + 1, len(chosen), len(carry), len(refusals), len(remaining))
                # Intentional bypass for the first three jobs. The test records
                # that no fully informed honest gate authorized those blocks.
                winning = self.publish(block, manifest, node=round_number % 5)
                money = parse_coinbase(block.vtx[0])[1]
                reward = 5_000_000_000 + fees
                counts = {script: sum(p.envelope.payout_script == script for p in included)
                    for script in {p.envelope.payout_script for p in included}}
                ordered_scripts = sorted(counts)
                expected_amounts = {script: reward * counts[script] // len(included) for script in ordered_scripts}
                left = reward - sum(expected_amounts.values())
                priority = sorted(ordered_scripts, key=lambda script: (-(reward * counts[script] % len(included)), script))
                for script in priority[:left]:
                    expected_amounts[script] += 1
                observed = {bytes(out.scriptPubKey): out.nValue for out in money}
                assert_equal(observed, expected_amounts)
                assert_equal(sum(observed.values()), reward)
                assert not all_paid.intersection(p.proof_id for p in included)
                all_paid.update(p.proof_id for p in included)
                for miner, script in zip(self.report["miners"], self.scripts):
                    miner["paid_satoshis"] += observed.get(script, 0)
                self.report["settlements"].append({"height": block.m_height, "block_hash": block.hash,
                    "original_proofs": len(chosen), "carried_winners": len(carry),
                    "omitted_original_proofs": len(remaining), "gate_refusals": refusals,
                    "bypassed_gate": bool(refusals), "all_native_nodes_accepted": True,
                    "payout_total_satoshis": reward, "fees_satoshis": fees,
                    "exact_allocation_verified": True, "commitment": f"{block.m_mm_rhs:064x}"})
                owner = round_number
                for gate in self.gates:
                    gate.register_template(block.serialize())
                self.gates[owner].receive(winning.serialize())
                self.bridges[owner].poll()
                winner_objects = {("template", template_id(block)), ("receipt", f"{winning.proof_id:064x}")}
                self.converge(winner_objects, label=f"winning origin and proof {round_number + 1}")
                self.import_all(winner_objects)
                known_winners.append(winning)
                self.save_report()
            assert not remaining
            assert {p.proof_id for p in proofs} <= all_paid
            assert_equal(len(all_paid), 103)
            assert all(miner["paid_satoshis"] > 0 for miner in self.report["miners"])
            assert known_winners[-1].proof_id not in all_paid
            self.report.update({"result": "passed_expected_regressions", "all100_original_proofs_paid": True,
                "total_credited_proofs": 103, "winning_proofs_carried": 3, "last_winner_pending": True,
                "honest_dispatch_pipeline_completed": False,
                "blocking_issue": "100 informed gates reject32-share snapshots; unbounded local inclusion obligation conflicts with consensus capacity",
                "control_blocks_bypassing_refused_jobs": 3,
                "final_seven_proof_job_authorized_by_all100_miners": True,
                "public_testnet_activation_changed": False})
            self.log.info("100-miner regression completed: honest admission blocked; explicit consensus controls paid100 owners")
        except BaseException as error:
            self.report["result"] = "failed"
            self.report["failure"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            for gate in self.gates:
                gate.close()
            for key_file in self.keys:
                if key_file.exists():
                    key_file.unlink()
            self.report["native_owner_keys_removed"] = not any(path.exists() for path in self.keys)
            self.report["seconds"] = round(time.monotonic() - started, 3)
            self.report["finished_utc"] = datetime.now(timezone.utc).isoformat()
            self.save_report()


if __name__ == "__main__":
    SharePool100MinersTest(__file__).main()
