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
from datetime import datetime, timezone
import hashlib
import os
import platform
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from capacity_metrics import Measurements, ResourceSampler, distribution
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, MAX_SNAPSHOT_BYTES, TemplateRecord, TIDES_RULES_HASH, TIDES_VERSION, solve_share
from native_mining_gate import parse_block
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, CBlockHeader, CTxOut, from_hex
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal


class SharePoolHashCapacityTest(SharePoolHashTides100MinersTest):
    def set_test_params(self):
        super().set_test_params()

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=102, choices=(102,))
        parser.add_argument("--results", type=Path, help="Default: capacity-results.json inside the disposable test directory")
        parser.add_argument("--miners", type=int, default=100)
        parser.add_argument("--epochs", type=int, default=3)
        parser.add_argument("--shares-per-origin", type=int, default=3)
        parser.add_argument("--padding-outputs", type=int, default=0)
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

    def rpc(self, index, method, *args):
        return self.metrics.call(f"rpc.node{index}.{method}", getattr(self.nodes[index], method), *args)

    def open(self, name, signer, *, index=0, budget=MAX_SNAPSHOT_BYTES):
        gate = HashMiningGate(self.directory / (name + ".sqlite"),
            rpc=lambda method, *args: self.rpc(index, method, *args),
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

    def run_test(self):
        opts = self.options
        if opts.results is None:
            opts.results = Path(opts.tmpdir) / "capacity-results.json"
        assert 2 <= opts.miners <= 100 and 1 <= opts.epochs <= 10
        assert 1 <= opts.shares_per_origin <= 16 and 0 <= opts.padding_outputs <= 128
        assert .5 <= opts.batch_fraction < .95 and 0 <= opts.offer_interval_ms <= 10_000
        assert opts.settle_every == 0 or opts.settle_every * 3 == opts.miners * opts.shares_per_origin
        assert 60 <= opts.max_runtime_seconds <= 7200
        node, follower = self.nodes
        self.MINERS, self.pool = opts.miners, 0xCA9AC17
        self.FEE = 1_000 + 50 * opts.padding_outputs
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
                "batch_fraction", "offer_interval_ms", "settle_every", "max_runtime_seconds")},
            "native_nodes": 2, "physical_miners_used": 0, "opaque_proof_fixtures": 0,
            "transaction_fee_satoshis": self.FEE,
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
            redeem = CScript([OP_TRUE])
            funding_script = b"\x00\x20" + hashlib.sha256(bytes(redeem)).digest()
            funded = self.generatetoaddress(node, 100, script_to_p2wsh(redeem))
            coinbase = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
            coinbase.rehash()
            value = (coinbase.vout[0].nValue - 10_000) // self.MINERS
            funding = self.spend(coinbase.sha256, 0, coinbase.vout[0].nValue, redeem, funding_script, 10_000)
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
                builders.append(self.open(f"miner-{index:03d}", signer))
            sampler = ResourceSampler({"node0": node.process.pid, "node1": follower.process.pid, "driver": os.getpid()},
                {"node0": node.datadir_path, "node1": follower.datadir_path, "gates": self.directory,
                 "node0_snapshot_store": node.datadir_path / "regtest" / "sharepool-snapshots-v6",
                 "node1_snapshot_store": follower.datadir_path / "regtest" / "sharepool-snapshots-v6"})
            sampler.start()
            network_start = [self.rpc(index, "getnettotals") for index in range(2)]
            collector, history, admitted, offered = None, [], set(), set()
            for epoch in range(opts.epochs):
                self.bounded()
                self.log.info("Capacity epoch %d/%d: %d distinct native origins, padding outputs=%d",
                              epoch + 1, opts.epochs, self.MINERS, opts.padding_outputs)
                if epoch == 0:
                    self.disconnect_nodes(0, 1)
                epoch_started = time.monotonic()
                origins, proofs, transaction_ids = [], [], set()
                for index, (signer, gate) in enumerate(zip(signers, builders)):
                    self.bounded()
                    previous, output_index, previous_value = unspent[index]
                    transaction = self.spend(previous, output_index, previous_value, redeem, funding_script, self.FEE)
                    padding_value = 1_000
                    transaction.vout[0].nValue -= padding_value * opts.padding_outputs
                    transaction.vout.extend(CTxOut(padding_value, CScript(funding_script)) for _ in range(opts.padding_outputs))
                    transaction.rehash()
                    self.rpc(0, "sendrawtransaction", transaction.serialize().hex())
                    transaction_ids.add(transaction.hash)
                    unspent[index] = transaction.sha256, 0, transaction.vout[0].nValue
                    block, snapshot, authorization = self.job(gate, signer, "gate.origin_job")
                    assert_equal({tx.rehash() for tx in block.vtx[1:]}, transaction_ids)
                    nonce = 0
                    for _ in range(opts.shares_per_origin):
                        proof = solve_share(parse_block(authorization.block_bytes), snapshot, start_nonce=nonce)
                        nonce = proof.header.nNonce + 1
                        assert_equal(CBlockHeader(parse_block(authorization.block_for_header(proof.header_bytes))).serialize(), proof.header_bytes)
                        proofs.append(proof)
                    origins.append((block, snapshot))
                    if index % 25 == 24:
                        self.log.info("Epoch %d: %d/%d native origins ready", epoch + 1, index + 1, self.MINERS)
                assert_equal(len({TemplateRecord.from_block(block).template_id for block, _ in origins}), self.MINERS)
                assert_equal(len({block.hashMerkleRoot for block, _ in origins}), self.MINERS)
                assert_equal(len({proof.proof_id for proof in proofs}), len(proofs))
                assert not offered.intersection(proof.proof_id for proof in proofs)
                offered.update(proof.proof_id for proof in proofs)
                full_size = len(self.proposal(0, signers[0], templates=[block for block, _ in origins], shares=proofs).serialize())
                if collector is None:
                    budget = max(4096, int(full_size * opts.batch_fraction))
                    collector = self.open("collector", signers[0], budget=budget)
                    self.report["pinned_snapshot_budget_bytes"] = budget
                for block, snapshot in origins:
                    self.metrics.call("gate.register_snapshot", collector.register_snapshot, snapshot.serialize())
                    self.metrics.call("gate.register_origin", collector.register_template, block.serialize())
                origin_seconds = time.monotonic() - epoch_started
                acceptance_started = time.monotonic()
                interval = opts.offer_interval_ms / 1000
                queue, lateness, acknowledged = [], [], 0
                previous_offers = len(offered) - len(proofs)
                row = {"epoch": epoch + 1, "native_origin_height": origins[0][0].m_height,
                    "real_distinct_origins": len(origins), "real_distinct_transaction_sets": self.MINERS,
                    "template_bytes": distribution([len(block.serialize()) for block, _ in origins], "bytes"),
                    "template_weight": distribution([block.get_weight() for block, _ in origins], "weight_units"),
                    "template_transaction_references": distribution([len(block.vtx) for block, _ in origins], "references"),
                    "full_unbounded_proposal_bytes": full_size, "offered": len(proofs), "acknowledged": 0,
                    "origin_preparation_seconds": origin_seconds, "client_queue_trace": queue, "blocks": []}
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
                    block, snapshot, authorization = self.job(collector, signers[0], "gate.settlement_job")
                    new_ids = {proof.proof_id for proof in snapshot.shares}
                    assert new_ids and not admitted.intersection(new_ids)
                    assert_equal(new_ids, {int(identity, 16) for identity in batch["selected_proofs"]})
                    history.extend((block.m_height, proof) for proof in snapshot.shares)
                    admitted.update(new_ids)
                    self.check_payouts(block, snapshot, history,
                        reward=5_000_000_000 + (self.MINERS * self.FEE if not row["blocks"] else 0))
                    block.solve()
                    assert_equal(authorization.block_for_header(CBlockHeader(block).serialize()), block.serialize())
                    assert_equal(self.rpc(0, "submitblock", block.serialize().hex()), None)
                    recovering = epoch == 0 and not row["blocks"]
                    if recovering:
                        recovery = time.monotonic()
                        self.connect_nodes(0, 1)
                    with self.metrics.measure("p2p.block_and_snapshot_ready"):
                        self.wait_tip(block)
                    if recovering:
                        self.report["peer_recovery_seconds"] = time.monotonic() - recovery
                    following = self.metrics.call("gate.batch_status", collector.batch_status)
                    row["blocks"].append({"height": block.m_height, "hash": block.hash,
                        "admitted": len(new_ids), "snapshot_bytes": len(snapshot.serialize()),
                        "planned_resources": planned_resources,
                        "eligible_backlog": following["eligible_count"], "deferred_backlog": following["deferred_count"],
                        "client_queue_before": before["client_queue"],
                        "offers_still_unacknowledged": before["offers_not_yet_acknowledged"],
                        "drain_step_seconds": time.monotonic() - started})
                    queue_sample("after_settlement")
                    self.report.update(offered=len(offered), acknowledged=previous_offers + acknowledged,
                        admitted=len(admitted), current_acknowledged_backlog=previous_offers + acknowledged - len(admitted))
                    self.save_report()
                    return following

                queue_sample("ingress_start")
                for index, proof in enumerate(proofs):
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
                batch = self.metrics.call("gate.batch_status", collector.batch_status)
                if not opts.settle_every:
                    assert_equal(batch["eligible_count"], len(proofs))
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
                self.log.info("Epoch %d: %d offers admitted in %d blocks; zero expired", epoch + 1, len(proofs), len(row["blocks"]))
            assert_equal(offered, admitted)
            assert node.getpeerinfo() and follower.getpeerinfo()
            assert node.verifychain(4, 0) and follower.verifychain(4, 0)
            self.report.update(result="passed", offered=len(offered), admitted=len(admitted), expired=0,
                               final_backlog=0, payout_oracle_verified=True, peer_recovery_verified=True)
            self.report["native_p2p_bytes"] = [{key: self.rpc(index, "getnettotals")[key] - initial[key]
                for key in ("totalbytessent", "totalbytesrecv")} for index, initial in enumerate(network_start)]
        except BaseException as error:
            self.report.update(result="failed", error_type=type(error).__name__, error=str(error)[:300])
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
