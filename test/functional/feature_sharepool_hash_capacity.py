#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Finite native capacity calibration, not a mainnet or WAN benchmark.

Distinct, fee-paying native transaction sets are built, signed, authorized and
worked by logical miners repeatedly. A pinned byte budget defers a bounded
burst, then offers stop while native blocks drain it. No opaque wire fixtures,
physical miners, concurrency extrapolation, or simulated GPU hashrate are used.
"""
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
import platform
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from capacity_metrics import (Measurements, ResourceSampler, distribution,
                              pipeline_progress, resource_utilization, template_geometry)
from hash_mining_gate import HashMiningGate
from hash_snapshot import (CompactTemplateRecord, HashSigner, MAX_DEPENDENCY_BYTES, MAX_EXPANDED_TEMPLATE_BYTES,
                           MAX_ORIGIN_CHECKS, MAX_SNAPSHOT_BYTES, MAX_TEMPLATE_BYTES,
                           MAX_TEMPLATE_TX_REFERENCES, Snapshot, TemplateRecord, TIDES_RULES_HASH,
                           TIDES_VERSION, job_hash, solve_share)
from native_mining_gate import parse_block
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, CBlockHeader, CTxOut, MAX_BLOCK_WEIGHT, from_hex
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.util import assert_equal


class SharePoolHashCapacityTest(SharePoolHashTides100MinersTest):
    def set_test_params(self):
        super().set_test_params()
        if self.options.witness_heavy:
            # The 256-byte stack elements are consensus-valid but exceed the
            # standard relay-policy limit. This changes disposable regtest
            # mempool policy only, never native consensus resource limits.
            for arguments in self.extra_args:
                arguments.append("-acceptnonstdtxn=1")

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=102, choices=(102,))
        parser.add_argument("--results", type=Path, help="Default: capacity-results.json inside the disposable test directory")
        parser.add_argument("--miners", type=int, default=100)
        parser.add_argument("--epochs", type=int, default=3)
        parser.add_argument("--shares-per-origin", type=int, default=3)
        parser.add_argument("--padding-outputs", type=int, default=0)
        parser.add_argument("--template-layout", choices=("cumulative", "shared", "disjoint"), default="cumulative")
        parser.add_argument("--witness-heavy", action="store_true",
                            help="Use 128 x 256-byte witness stack elements; explicitly allows nonstandard regtest transactions")
        parser.add_argument("--resource-diagnostics", action="store_true",
                            help="Measure unique transaction bytes, template reuse and separate native resource utilization")
        parser.add_argument("--snapshot-budget-bytes", type=int, default=0,
                            help="Explicit pinned gate byte policy; zero selects the recorded deterministic fixture policy")
        parser.add_argument("--batch-fraction", type=float, default=.75)
        parser.add_argument("--offer-interval-ms", type=float, default=0)
        parser.add_argument("--settle-every", type=int, default=0,
                            help="Interleave settlement after this many ACKs; requires exactly three publications per epoch")
        parser.add_argument("--max-runtime-seconds", type=int, default=1800)
        parser.add_argument("--host-load", choices=("unknown", "concurrent", "quiescent"), default="unknown",
                            help="Operator-declared competing test load; the harness cannot certify host isolation")

    def bounded(self):
        if time.monotonic() - self.started > self.options.max_runtime_seconds:
            raise AssertionError("finite workload runtime budget exceeded")

    def save_report(self):
        self.report.update(pipeline_progress(self.report.get("epochs", ())))
        super().save_report()

    def rpc(self, index, method, *args):
        return self.metrics.call(f"rpc.node{index}.{method}", getattr(self.nodes[index], method), *args)

    @staticmethod
    def tag_unsigned_job(result, tag):
        """Externally add a bounded coinbase tag before exact native authorization."""
        assert type(tag) is bytes and 1 <= len(tag) <= 32
        block = parse_block(bytes.fromhex(result["template"]))
        snapshot = Snapshot.deserialize(bytes.fromhex(result["snapshot"]))
        assert_equal(snapshot.owner_signature, bytes(64))
        coinbase = block.vtx[0]
        original_outputs = tuple(output.serialize() for output in coinbase.vout)
        coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + bytes(CScript([tag])))
        assert len(coinbase.vin[0].scriptSig) <= 100
        coinbase.rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        snapshot = replace(snapshot, job_commitment=job_hash(block))
        block.m_mm_rhs = snapshot.hash
        # Changing coinbase scriptSig preserves its outputs and the witness
        # commitment: BIP141 uses a zero leaf for the coinbase witness hash.
        assert_equal(tuple(output.serialize() for output in coinbase.vout), original_outputs)
        return dict(result, template=block.serialize().hex(), snapshot=snapshot.serialize().hex(),
                    commitment=snapshot.hash_hex, job_commitment=f"{snapshot.job_commitment:064x}",
                    signing_payload=snapshot.signing_payload.hex(), signing_hash=snapshot.owner_message[::-1].hex())

    def open(self, name, signer, *, index=0, budget=MAX_SNAPSHOT_BYTES, origin_tag=None):
        def call(method, *args):
            result = self.rpc(index, method, *args)
            if origin_tag is not None and method == "preparesharepoolhashjob":
                result = self.tag_unsigned_job(result, origin_tag)
            return result
        gate = HashMiningGate(self.directory / (name + ".sqlite"),
            rpc=call,
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=TIDES_VERSION, activation_height=102, snapshot_budget=budget)
        self.gates.append(gate)
        return gate

    def job(self, gate, signer, name):
        with self.metrics.measure(name):
            block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
            authorization = gate.authorize(block.serialize(), snapshot.serialize())
            assert gate.ready_for_dispatch(authorization)
            gate.register_snapshot(snapshot.serialize())
            return block, snapshot, authorization

    def receipt_counts(self, gate):
        counts, cursor = Counter(), 0
        for _ in range(100):
            page = self.metrics.call("gate.receipt_status", gate.receipt_status, after_revision=cursor, limit=256)
            assert not page["history_limited"]
            counts.update(receipt["status"] for receipt in page["receipts"])
            if page["next_revision"] is None:
                return dict(counts)
            cursor = page["next_revision"]
        raise AssertionError("bounded receipt page limit exceeded")

    def fixture_spend(self, previous, index, value, redeem, script, fee):
        transaction = self.spend(previous, index, value, redeem, script, fee)
        if self.options.witness_heavy:
            transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(256)] * 128 + [bytes(redeem)]
        transaction.rehash()
        return transaction

    def snapshot_diagnostics(self, snapshot):
        """Measure once after scheduled ingress, never authorize from counters."""
        raw = snapshot.serialize()
        records = tuple(CompactTemplateRecord.from_record(record) for record in snapshot.templates)
        transactions = {transaction.wtxid: len(transaction.raw) for record in records for transaction in record.transactions}
        result = self.metrics.call("diagnostic.snapshot_resources", self.nodes[0].getsharepoolhashresources, raw.hex())
        assert_equal(result["hash"], snapshot.hash_hex)
        assert_equal(result["version"], TIDES_VERSION)
        assert_equal(result["consensus_validated"], False)
        assert_equal(result["dependency_graph_checked"], False)
        expected = {"encoded_bytes": len(raw), "templates": len(records),
                    "expanded_template_bytes": sum(record.expanded_bytes for record in records),
                    "transaction_references": sum(len(record.transactions) for record in records),
                    "unique_transactions": len(transactions), "unique_transaction_bytes": sum(transactions.values())}
        for name, value in expected.items():
            assert_equal(result["usage"][name], value)
        components = ("binding_bytes", "transaction_table_bytes", "template_table_bytes", "share_bytes",
                      "state_bytes", "payout_bytes", "pending_bytes", "settled_bytes", "certificate_bytes", "history_bytes")
        assert_equal(sum(result["usage"][name] for name in components), len(raw))
        return result

    def run_test(self):
        opts = self.options
        if opts.results is None:
            opts.results = Path(opts.tmpdir) / "capacity-results.json"
        assert 2 <= opts.miners <= 100 and 1 <= opts.epochs <= 10
        assert 1 <= opts.shares_per_origin <= 16 and 0 <= opts.padding_outputs <= 200
        assert not opts.witness_heavy or opts.padding_outputs <= 24
        assert opts.snapshot_budget_bytes == 0 or 1024 <= opts.snapshot_budget_bytes <= MAX_SNAPSHOT_BYTES
        assert .5 <= opts.batch_fraction < .95 and 0 <= opts.offer_interval_ms <= 10_000
        assert opts.settle_every == 0 or opts.settle_every * 3 == opts.miners * opts.shares_per_origin
        assert 60 <= opts.max_runtime_seconds <= 7200
        node, follower = self.nodes
        self.MINERS, self.pool = opts.miners, 0xCA9AC17
        self.FEE = 1_000 + 50 * opts.padding_outputs + (10_000 if opts.witness_heavy else 0)
        self.genesis = int(node.getblockhash(0), 16)
        self.directory = Path(opts.tmpdir) / "capacity-gates"
        self.directory.mkdir(mode=0o700)
        self.metrics, self.gates, keys = Measurements(), [], []
        self.started = time.monotonic()
        self.report = {"schema": 1, "result": "running", "network": "isolated native regtest",
            "started_utc": datetime.now(timezone.utc).isoformat(), "rules_hash": f"{TIDES_RULES_HASH:064x}",
            "native_binary_sha256": hashlib.sha256(Path(opts.bitcoind).read_bytes()).hexdigest(),
            "signer_binary_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                for name in ("contrib/sharepool/hash_mining_gate.py", "contrib/sharepool/hash_snapshot.py",
                             "contrib/sharepool/hash_gate_batch.py", "contrib/sharepool/hash_gate_inventory.py",
                             "contrib/sharepool/capacity_metrics.py",
                             "test/functional/feature_sharepool_hash_tides_100_miners.py")},
            "command": [sys.executable, *sys.argv],
            "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count()},
            "operator_declared_host_load": opts.host_load,
            "configuration": {key: getattr(opts, key) for key in ("miners", "epochs", "shares_per_origin", "padding_outputs",
                "template_layout", "witness_heavy", "resource_diagnostics", "snapshot_budget_bytes",
                "batch_fraction", "offer_interval_ms", "settle_every", "max_runtime_seconds")},
            "native_nodes": 2, "physical_miners_used": 0, "opaque_proof_fixtures": 0,
            "transaction_fee_satoshis": self.FEE,
            "transaction_policy": {"acceptnonstdtxn_explicit": opts.witness_heavy,
                "witness_items_per_input": 128 if opts.witness_heavy else 0,
                "witness_item_bytes": 256 if opts.witness_heavy else 0,
                "consensus_limits_changed": False,
                "shared_coinbase_tags": "external unsigned native-job transformation before exact signing/finalization/authorization" if opts.template_layout == "shared" else None,
                "disjoint_selection": "temporary negative mempool fee deltas, restored before settlement" if opts.template_layout == "disjoint" else None},
            "epochs": [], "rewards": [], "limitations": [
                "Sequential local RPC driver; observed service rate is not a concurrent saturation maximum",
                "Offered bursts are finite precomputed native proofs; client queue and settlement backlog are measured separately",
                "Two loopback native nodes, not 100 native nodes, WAN propagation, or a public testnet",
                "Easy regtest proof target does not establish production sampling variance or mining hashrate",
                "The driver deliberately schedules settlement blocks; qualifying headers may also satisfy native difficulty without immediate publication",
                "Snapshot budget overload tests deterministic carry and expiry; it does not exhaust host RAM or disk",
                "RSS is sampled, CPU is cumulative ps time, disk sizes are logical lengths rather than physical allocation",
                "Local durable ACKs become recurring reward eligible only after native canonical admission"]}
        sampler = None
        try:
            self.connect_nodes(0, 1)
            redeem = CScript(([OP_DROP] * 128 if opts.witness_heavy else []) + [OP_TRUE])
            funding_script = b"\x00\x20" + hashlib.sha256(bytes(redeem)).digest()
            funded = self.generatetoaddress(node, 100, script_to_p2wsh(redeem))
            coinbase = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
            coinbase.rehash()
            funding_fee = 20_000 if opts.witness_heavy else 10_000
            value = (coinbase.vout[0].nValue - funding_fee) // self.MINERS
            funding = self.fixture_spend(coinbase.sha256, 0, coinbase.vout[0].nValue, redeem, funding_script, funding_fee)
            funding.vout = [CTxOut(value, CScript(funding_script)) for _ in range(self.MINERS)]
            funding.rehash()
            node.sendrawtransaction(funding.serialize().hex())
            self.generatetoaddress(node, 1, script_to_p2wsh(redeem))
            self.sync_blocks()
            unspent = [(funding.sha256, index, value) for index in range(self.MINERS)]
            signers, builders = [], []
            for index in range(self.MINERS):
                path = self.directory / f"owner-{index:03d}.key"
                keys.append(path)
                signer = HashSigner.create(self.signer_binary, path, pool=self.pool,
                    payout_script=b"\x00\x14" + (index + 1).to_bytes(20, "big"))
                signers.append(signer)
                builders.append(self.open(f"miner-{index:03d}", signer,
                    origin_tag=f"capacity-origin-{index:03d}".encode() if opts.template_layout == "shared" else None))
            sampler = ResourceSampler({"node0": node.process.pid, "node1": follower.process.pid, "driver": os.getpid()},
                {"node0": node.datadir_path, "node1": follower.datadir_path, "gates": self.directory,
                 "node0_snapshot_store": node.datadir_path / "regtest" / "sharepool-snapshots-v6",
                 "node1_snapshot_store": follower.datadir_path / "regtest" / "sharepool-snapshots-v6"})
            sampler.start()
            network_start = [self.rpc(index, "getnettotals") for index in range(2)]
            collector, history, admitted, offered = None, [], set(), set()
            for epoch in range(opts.epochs):
                self.bounded()
                self.log.info("Capacity epoch %d/%d: %d distinct native origins, layout=%s, padding outputs=%d, witness-heavy=%s",
                              epoch + 1, opts.epochs, self.MINERS, opts.template_layout, opts.padding_outputs, opts.witness_heavy)
                if epoch == 0:
                    self.disconnect_nodes(0, 1)
                native_context = None
                if opts.resource_diagnostics:
                    template_info = self.metrics.call("diagnostic.native_limits", node.getblocktemplate,
                        {"rules": ["segwit", "blake2b", "sharepool"], "capabilities": ["skip_validity_test"]})
                    native_context = {name: template_info[name] for name in
                        ("previousblockhash", "height", "bits", "curtime", "weightlimit", "sizelimit")}
                epoch_started = time.monotonic()
                self.report["active_stage"] = "origin_preparation"
                origins, proofs, transaction_ids, transaction_sets = [], [], set(), set()
                transactions = []

                def publish_transaction(index):
                    previous, output_index, previous_value = unspent[index]
                    transaction = self.fixture_spend(previous, output_index, previous_value, redeem, funding_script, self.FEE)
                    padding_value = 1_000
                    transaction.vout[0].nValue -= padding_value * opts.padding_outputs
                    transaction.vout.extend(CTxOut(padding_value, CScript(funding_script)) for _ in range(opts.padding_outputs))
                    transaction.rehash()
                    self.rpc(0, "sendrawtransaction", transaction.serialize().hex())
                    transaction_ids.add(transaction.hash)
                    unspent[index] = transaction.sha256, 0, transaction.vout[0].nValue
                    transactions.append(transaction)
                    return transaction

                if opts.template_layout == "shared":
                    for index in range(self.MINERS):
                        self.bounded()
                        publish_transaction(index)
                suppressed = []
                try:
                    for index, (signer, gate) in enumerate(zip(signers, builders)):
                        self.bounded()
                        transaction = transactions[index] if opts.template_layout == "shared" else publish_transaction(index)
                        expected = {transaction.hash} if opts.template_layout == "disjoint" else transaction_ids
                        block, snapshot, authorization = self.job(gate, signer, "gate.origin_job")
                        actual = {tx.rehash() for tx in block.vtx[1:]}
                        assert_equal(actual, expected)
                        assert block.get_weight() <= MAX_BLOCK_WEIGHT
                        transaction_sets.add(tuple(sorted(actual)))
                        nonce = 0
                        for _ in range(opts.shares_per_origin):
                            proof = solve_share(parse_block(authorization.block_bytes), snapshot, start_nonce=nonce)
                            nonce = proof.header.nNonce + 1
                            assert_equal(CBlockHeader(parse_block(authorization.block_for_header(proof.header_bytes))).serialize(), proof.header_bytes)
                            proofs.append(proof)
                        origins.append((block, snapshot))
                        if opts.template_layout == "disjoint":
                            # Each transaction spends a different confirmed output.
                            # Exclusion changes native job selection, never validity.
                            self.rpc(0, "prioritisetransaction", transaction.hash, 0, -2 * self.FEE)
                            suppressed.append(transaction.hash)
                        if index % 25 == 24:
                            self.log.info("Epoch %d: %d/%d native origins ready", epoch + 1, index + 1, self.MINERS)
                finally:
                    for identity in suppressed:
                        self.rpc(0, "prioritisetransaction", identity, 0, 2 * self.FEE)
                # All epoch transactions must fit together in the winning job;
                # the mode changes source origins, not the settlement's fees.
                assert sum(transaction.get_weight() for transaction in transactions) + 20_000 <= MAX_BLOCK_WEIGHT
                assert_equal(len(transaction_sets), 1 if opts.template_layout == "shared" else self.MINERS)
                assert_equal(len({TemplateRecord.from_block(block).template_id for block, _ in origins}), self.MINERS)
                assert_equal(len({block.hashMerkleRoot for block, _ in origins}), self.MINERS)
                assert_equal(len({proof.proof_id for proof in proofs}), len(proofs))
                assert not offered.intersection(proof.proof_id for proof in proofs)
                offered.update(proof.proof_id for proof in proofs)
                full_size = len(self.proposal(0, signers[0], templates=[block for block, _ in origins], shares=proofs).serialize())
                if collector is None:
                    minimum_origin_floor = 0
                    if opts.template_layout == "shared" or opts.witness_heavy:
                        largest = max(range(len(origins)), key=lambda index: len(origins[index][0].serialize()))
                        minimum = self.proposal(0, signers[0], templates=[origins[largest][0]],
                            shares=[proofs[largest * opts.shares_per_origin]])
                        prepared = self.rpc(0, "preparesharepoolhashjob", minimum.serialize().hex())
                        minimum_origin_floor = len(bytes.fromhex(prepared["snapshot"]))
                        assert minimum_origin_floor < full_size
                    budget = (opts.snapshot_budget_bytes or
                        max(4096, minimum_origin_floor + int((full_size - minimum_origin_floor) * opts.batch_fraction)))
                    collector = self.open("collector", signers[0], budget=budget)
                    self.report["pinned_snapshot_budget_bytes"] = budget
                    self.report["snapshot_policy_selection"] = {"explicit_override": bool(opts.snapshot_budget_bytes),
                        "native_prepared_one_origin_snapshot_floor_bytes": minimum_origin_floor,
                        "full_proposal_bytes": full_size, "fraction_of_remaining_bytes": opts.batch_fraction,
                        "policy_frozen_after_first_epoch": True}
                for block, snapshot in origins:
                    self.report["active_stage"] = "collector_origin_registration"
                    self.metrics.call("gate.register_snapshot", collector.register_snapshot, snapshot.serialize())
                    self.metrics.call("gate.register_origin", collector.register_template, block.serialize())
                origin_seconds = time.monotonic() - epoch_started
                acceptance_started = time.monotonic()
                interval = opts.offer_interval_ms / 1000
                queue, lateness, acknowledged = [], [], 0
                previous_offers = len(offered) - len(proofs)
                row = {"epoch": epoch + 1, "native_origin_height": origins[0][0].m_height,
                    "real_distinct_origins": len(origins), "real_distinct_transaction_sets": len(transaction_sets),
                    "template_bytes": distribution([len(block.serialize()) for block, _ in origins], "bytes"),
                    "template_weight": distribution([block.get_weight() for block, _ in origins], "weight_units"),
                    "template_transaction_references": distribution([len(block.vtx) for block, _ in origins], "references"),
                    "full_unbounded_proposal_bytes": full_size, "offered": len(proofs), "acknowledged": 0,
                    "origin_preparation_seconds": origin_seconds, "client_queue_trace": queue, "blocks": []}
                diagnostic_snapshots = []
                if opts.resource_diagnostics:
                    diagnostics_started = time.monotonic()
                    assert_equal(native_context["height"], origins[0][0].m_height)
                    assert_equal(int(native_context["previousblockhash"], 16), origins[0][0].hashPrevBlock)
                    row["native_template_context"] = native_context
                    geometry = template_geometry(((len(block.serialize()), block.get_weight(),
                        (transaction.serialize() for transaction in block.vtx)) for block, _ in origins),
                        max_expanded_bytes=384 * 1024 * 1024 if opts.witness_heavy else 128 * 1024 * 1024)
                    row["template_geometry"] = geometry
                    row["proposal_resource_utilization"] = resource_utilization({
                        "snapshot_bytes": full_size, "expanded_template_bytes": geometry["expanded_template_bytes"],
                        "template_transaction_references": geometry["transaction_references"],
                        "largest_template_bytes": geometry["template_bytes"]["max_bytes"],
                        "largest_native_weight": geometry["template_weight"]["max_weight_units"],
                        "source_origins": len(origins)}, {
                        "snapshot_bytes": MAX_SNAPSHOT_BYTES, "expanded_template_bytes": MAX_EXPANDED_TEMPLATE_BYTES,
                        "template_transaction_references": MAX_TEMPLATE_TX_REFERENCES,
                        "largest_template_bytes": MAX_TEMPLATE_BYTES, "largest_native_weight": native_context["weightlimit"],
                        "source_origins": MAX_ORIGIN_CHECKS})
                    row["pre_ingress_diagnostics_seconds"] = time.monotonic() - diagnostics_started
                    acceptance_started = time.monotonic()
                self.report["epochs"].append(row)

                def queue_sample(event):
                    elapsed = time.monotonic() - acceptance_started
                    due_count = len(proofs) if interval == 0 else min(len(proofs), int(elapsed / interval) + 1)
                    sample = {"event": event, "elapsed_seconds": elapsed, "offered_due": due_count,
                        "acknowledged": acknowledged, "client_queue": max(0, due_count - acknowledged),
                        "scheduled_not_yet_due": len(proofs) - due_count,
                        "offers_not_yet_acknowledged": len(proofs) - acknowledged}
                    queue.append(sample)
                    return sample

                def settle(batch):
                    self.bounded()
                    assert len(row["blocks"]) < 4, "bounded admission-age drain exhausted"
                    started = time.monotonic()
                    before = queue_sample("before_settlement")
                    planned_resources = batch["resources"]
                    first_block = not row["blocks"]
                    self.report["active_stage"] = "settlement_job_construction"
                    block, snapshot, authorization = self.job(collector, signers[0], "gate.settlement_job")
                    new_ids = {proof.proof_id for proof in snapshot.shares}
                    assert new_ids and not admitted.intersection(new_ids)
                    assert_equal(new_ids, {int(identity, 16) for identity in batch["selected_proofs"]})
                    next_history = [(block.m_height, proof) for proof in snapshot.shares]
                    self.check_payouts(block, snapshot, history + next_history,
                        reward=5_000_000_000 + (self.MINERS * self.FEE if first_block else 0))
                    block.solve()
                    assert_equal(authorization.block_for_header(CBlockHeader(block).serialize()), block.serialize())
                    self.report["active_stage"] = "native_block_submission"
                    assert_equal(self.rpc(0, "submitblock", block.serialize().hex()), None)
                    assert_equal(self.rpc(0, "getbestblockhash"), block.hash)
                    # Record local admission before waiting for remote progress.
                    # A failed peer transfer must not erase this checkpoint or
                    # report local acceptance as completed peer verification.
                    history.extend(next_history)
                    admitted.update(new_ids)
                    entry = {"height": block.m_height, "hash": block.hash,
                        "admitted": len(new_ids), "snapshot_bytes": len(snapshot.serialize()),
                        "native_accepted": True, "peer_ready": False,
                        "planned_resources": planned_resources,
                        "eligible_backlog": None, "deferred_backlog": None,
                        "client_queue_before": before["client_queue"],
                        "offers_still_unacknowledged": before["offers_not_yet_acknowledged"],
                        "local_admission_step_seconds": time.monotonic() - started}
                    row["blocks"].append(entry)
                    self.report["active_stage"] = "follower_block_and_snapshot_recovery"
                    self.save_report()
                    recovering = epoch == 0 and first_block
                    if recovering:
                        recovery = time.monotonic()
                        self.connect_nodes(0, 1)
                    with self.metrics.measure("p2p.block_and_snapshot_ready"):
                        self.wait_tip(block)
                    entry["peer_ready"] = True
                    if recovering:
                        self.report["peer_recovery_seconds"] = time.monotonic() - recovery
                    self.report["active_stage"] = "following_batch_selection"
                    following = self.metrics.call("gate.batch_status", collector.batch_status)
                    entry.update(eligible_backlog=following["eligible_count"], deferred_backlog=following["deferred_count"],
                                 drain_step_seconds=time.monotonic() - started)
                    if opts.resource_diagnostics:
                        diagnostic_snapshots.append(snapshot)
                        row["blocks"][-1]["planned_resource_utilization"] = resource_utilization({
                            "snapshot_bytes": planned_resources["reserved_snapshot_bytes"],
                            "dependency_bytes": planned_resources["reserved_dependency_bytes"],
                            "origins": planned_resources["origins"]}, {
                            "snapshot_bytes": collector.snapshot_budget, "dependency_bytes": MAX_DEPENDENCY_BYTES,
                            "origins": MAX_ORIGIN_CHECKS})
                    queue_sample("after_settlement")
                    self.report.update(offered=len(offered), acknowledged=previous_offers + acknowledged,
                        admitted=len(admitted), current_acknowledged_backlog=previous_offers + acknowledged - len(admitted))
                    self.save_report()
                    return following

                queue_sample("ingress_start")
                for index, proof in enumerate(proofs):
                    self.report["active_stage"] = "source_proof_acknowledgement"
                    self.bounded()
                    due = acceptance_started + index * interval
                    delay = due - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    lateness.append(max(0, time.monotonic() - due))
                    self.metrics.call("gate.receive", collector.receive, proof)
                    acknowledged += 1
                    row["acknowledged"] = acknowledged
                    if index % 25 == 0 or index + 1 == len(proofs):
                        queue_sample("acknowledgement")
                    if opts.settle_every and acknowledged % opts.settle_every == 0:
                        batch = self.metrics.call("gate.batch_status", collector.batch_status)
                        if "initial_deferred" not in row:
                            row.update(initial_deferred=batch["deferred_count"], initial_batch_resources=batch["resources"])
                        settle(batch)
                acceptance_seconds = time.monotonic() - acceptance_started
                row.update(admission_seconds=acceptance_seconds,
                    observed_serial_acknowledgements_per_second=len(proofs) / acceptance_seconds,
                    scheduler_lateness=distribution(lateness),
                    ingress_includes_interleaved_settlement=bool(opts.settle_every))
                self.report["active_stage"] = "initial_batch_selection"
                batch = self.metrics.call("gate.batch_status", collector.batch_status)
                if not opts.settle_every:
                    assert_equal(batch["eligible_count"], len(proofs))
                    if not opts.snapshot_budget_bytes:
                        assert batch["deferred_count"] > 0, "chosen fixed budget must create a measured settlement backlog"
                    row.update(initial_deferred=batch["deferred_count"], initial_batch_resources=batch["resources"])
                else:
                    assert_equal(len(row["blocks"]), 3)
                    assert_equal(batch["eligible_count"], 0)
                    assert all(entry["offers_still_unacknowledged"] > 0 for entry in row["blocks"][:2])
                # Burst mode stops all further offers before draining. Interleaved
                # mode must already have admitted its three scheduled batches.
                while batch["eligible_count"] and len(row["blocks"]) < 4:
                    batch = settle(batch)
                self.report["active_stage"] = "receipt_status"
                counts = self.receipt_counts(collector)
                row.update(receipt_states=counts, admitted=sum(proof.proof_id in admitted for proof in proofs),
                           total_admitted=len(admitted), seconds=time.monotonic() - epoch_started)
                self.report.update(expired=counts.get("expired_unanchored", 0),
                                   unresolved_receipts=counts.get("unknown", 0))
                self.save_report()
                assert_equal(counts.get("confirmed_admitted", 0), len(offered))
                assert_equal(counts.get("expired_unanchored", 0), 0)
                assert_equal(batch["eligible_count"], 0)
                assert_equal(node.getrawmempool(), [])
                if epoch == 0:
                    self.report["active_stage"] = "follower_gate_receipt_import"
                    relay = self.open("follower-recovery", signers[0], index=1)
                    cursor, imported, pages, deferred = None, 0, 0, 0
                    with self.metrics.measure("gate.p2p_recovery_import"):
                        for _ in range(128):
                            self.bounded()
                            result = relay.sync_native_receipts(cursor=cursor, limit=32, max_receipts=128)
                            cursor, imported = result["cursor"], imported + len(result["accepted"])
                            pages, deferred = pages + result["pages"], deferred + len(result["deferred"])
                            if relay.archive_head()["receipt_revision"] == len(proofs):
                                break
                    assert_equal(relay.archive_head()["receipt_revision"], len(proofs))
                    self.report["follower_gate_recovery"] = {"native_verified_acknowledgements": imported,
                        "inventory_pages": pages, "deferred_attempts": deferred,
                        "receipt_states": self.receipt_counts(relay)}
                if opts.resource_diagnostics:
                    self.report["active_stage"] = "post_ingress_resource_diagnostics"
                    diagnostics_started = time.monotonic()
                    for entry, snapshot in zip(row["blocks"], diagnostic_snapshots):
                        entry["native_snapshot_resources"] = self.snapshot_diagnostics(snapshot)
                    row["post_ingress_diagnostics_seconds"] = time.monotonic() - diagnostics_started
                self.log.info("Epoch %d: %d offers admitted in %d blocks; zero expired", epoch + 1, len(proofs), len(row["blocks"]))
            assert_equal(offered, admitted)
            assert node.getpeerinfo() and follower.getpeerinfo()
            self.report["active_stage"] = "final_chain_verification"
            assert node.verifychain(4, 0) and follower.verifychain(4, 0)
            self.report.update(result="passed", offered=len(offered), admitted=len(admitted), expired=0,
                               final_backlog=0, payout_oracle_verified=True, peer_recovery_verified=True, active_stage="complete")
            self.report["native_p2p_bytes"] = [{key: self.rpc(index, "getnettotals")[key] - initial[key]
                for key in ("totalbytessent", "totalbytesrecv")} for index, initial in enumerate(network_start)]
        except BaseException as error:
            self.report.update(result="failed", error_type=type(error).__name__, error=str(error)[:300],
                               failure_stage=self.report.get("active_stage", "setup"))
            raise
        finally:
            self.report.update(seconds=time.monotonic() - self.started, measurements=self.metrics.report())
            if sampler is not None:
                self.report["resources"] = sampler.finish()
            for gate in self.gates:
                gate.close()
            for path in keys:
                path.unlink(missing_ok=True)
            self.save_report()


if __name__ == "__main__":
    SharePoolHashCapacityTest(__file__).main()
