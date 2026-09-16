#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Opt-in native A/B of per-receipt rebuilding and DATUM-style job cadence.

Both arms consume identical real proofs at identical real monotonic due offsets.
The fixture uses isolated regtest, two native backends, fresh collector journals,
and real signing, validation and payouts. It is a finite local service benchmark,
not production difficulty, Stratum transport, WAN propagation or saturation.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from capacity_metrics import Measurements, cpu_seconds, distribution, logical_bytes
from hash_job_scheduler import HashJobScheduler
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, Snapshot, TemplateRecord, job_hash, solve_share
from native_mining_gate import parse_block
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.address import script_to_p2wsh
from test_framework.authproxy import serialization_fallback
from test_framework.messages import CBlock, CTxOut, from_hex
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal


class SharePoolHashCadenceBenchmark(SharePoolHashTides100MinersTest):
    PROFILE_VERSION = 7

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_argument("--miners", type=int, default=100)
        parser.add_argument("--offer-interval-ms", type=float, default=1000)
        parser.add_argument("--max-runtime-seconds", type=int, default=900)
        parser.add_argument("--work-update-seconds", type=int, default=40, choices=range(5, 121))
        parser.add_argument("--arm-order", choices=("per-ack-first", "datum-first"), default="per-ack-first")
        parser.add_argument("--host-load", choices=("unknown", "concurrent", "quiescent"), default="unknown")

    def set_test_params(self):
        super().set_test_params()
        for arguments in self.extra_args:
            arguments.extend(("-sharepoolcompacttides=1", "-persistmempool=1"))

    def bounded(self):
        if time.monotonic() - self.started > self.options.max_runtime_seconds:
            raise AssertionError("finite cadence benchmark runtime budget exceeded")

    def wait_until_clock(self, due):
        """Real pacing, with short bounded sleeps; no injected scheduler clock."""
        waited = 0.0
        while time.monotonic() < due:
            self.bounded()
            before = time.monotonic()
            time.sleep(max(0, min(.1, due - before)))
            waited += time.monotonic() - before
        return waited

    @staticmethod
    def process_sample(pid):
        result = subprocess.run(["ps", "-p", str(pid), "-o", "rss=", "-o", "time="],
                                check=True, capture_output=True, text=True, timeout=5)
        rss, cpu = result.stdout.split()
        return {"rss_bytes": int(rss) * 1024, "cpu_seconds": cpu_seconds(cpu)}

    @staticmethod
    def child_cpu():
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime

    @staticmethod
    def encoded_size(value):
        return len(json.dumps(value, default=serialization_fallback, ensure_ascii=True,
                              separators=(",", ":")).encode())

    def call(self, index, method, *args):
        name = f"{self.phase}.rpc.node{index}.{method}"
        encoded_started = time.process_time()
        self.rpc_payload[name]["request_bytes"] += self.encoded_size({"method": method, "params": args})
        self.rpc_encoding_cpu[self.phase] += time.process_time() - encoded_started
        self.rpc_payload[name]["calls"] += 1
        result = self.metrics.call(name, getattr(self.nodes[index], method), *args)
        encoded_started = time.process_time()
        self.rpc_payload[name]["response_bytes"] += self.encoded_size(result)
        self.rpc_encoding_cpu[self.phase] += time.process_time() - encoded_started
        return result

    def open_collector(self, name, signer, index):
        return HashMiningGate(self.directory / (name + ".sqlite"),
            rpc=lambda method, *args: self.call(index, method, *args),
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=self.PROFILE_VERSION, activation_height=102)

    def prepare_fixture(self):
        node, follower = self.nodes
        self.connect_nodes(0, 1)
        redeem = CScript([OP_TRUE])
        funding_script = b"\x00\x20" + hashlib.sha256(bytes(redeem)).digest()
        funded = self.generatetoaddress(node, 100, script_to_p2wsh(redeem))
        coinbase = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
        coinbase.rehash()
        value = (coinbase.vout[0].nValue - 10_000) // self.MINERS
        funding = self.spend(coinbase.sha256, 0, coinbase.vout[0].nValue,
                             redeem, funding_script, 10_000)
        funding.vout = [CTxOut(value, CScript(funding_script)) for _ in range(self.MINERS)]
        funding.rehash()
        node.sendrawtransaction(funding.serialize().hex())
        self.generatetoaddress(node, 1, script_to_p2wsh(redeem))
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        for peer in self.nodes:
            peer.setnetworkactive(False)
        parent = node.getbestblockhash()
        assert_equal(follower.getbestblockhash(), parent)
        self.fixed_mocktime = node.getblockheader(parent)["time"] + 1
        for peer in self.nodes:
            peer.setmocktime(self.fixed_mocktime)

        signers, origins, proofs, transactions, txsets = [], [], [], [], set()
        for index in range(self.MINERS):
            self.bounded()
            key = self.directory / f"owner-{index:03d}.key"
            self.keys.append(key)
            signer = HashSigner.create(self.signer_binary, key, pool=0xCAD40,
                payout_script=b"\x00\x14" + (index + 1).to_bytes(20, "big"))
            signers.append(signer)
            transaction = self.spend(funding.sha256, index, value, redeem, funding_script, self.FEE)
            node.sendrawtransaction(transaction.serialize().hex())
            transactions.append(transaction)
            builder = self.open_collector(f"origin-{index:03d}", signer, 0)
            try:
                with self.metrics.measure("fixture.origin_job"):
                    block, snapshot = builder.make_native(sign_owner=signer.sign_owner)
                    authorization = builder.authorize(block.serialize(), snapshot.serialize())
                    assert builder.ready_for_dispatch(authorization)
                    builder.register_snapshot(snapshot.serialize())
                actual = {tx.rehash() for tx in block.vtx[1:]}
                assert_equal(actual, {tx.hash for tx in transactions})
                txsets.add(tuple(sorted(actual)))
                origins.append((authorization.block_bytes, authorization.snapshot_bytes))
                proofs.append(solve_share(parse_block(authorization.block_bytes), snapshot))
            finally:
                builder.close()
            if index % 25 == 24:
                self.log.info("Prepared %d/%d distinct native origins", index + 1, self.MINERS)
        assert_equal(len({signer.public_key for signer in signers}), self.MINERS)
        assert_equal(len({signer.payout_script for signer in signers}), self.MINERS)
        assert_equal(len({TemplateRecord.from_block(parse_block(raw)).template_id for raw, _ in origins}), self.MINERS)
        assert_equal(len({parse_block(raw).hashMerkleRoot for raw, _ in origins}), self.MINERS)
        assert_equal(len(txsets), self.MINERS)
        assert_equal(len({proof.proof_id for proof in proofs}), self.MINERS)
        for transaction in transactions:
            follower.sendrawtransaction(transaction.serialize().hex())
        for index, name in enumerate(("per_ack", "datum")):
            gate = self.open_collector(name, signers[0], index)
            try:
                for block_raw, snapshot_raw in origins:
                    gate.register_snapshot(snapshot_raw)
                    gate.register_template(block_raw)
                assert_equal(gate.archive_head()["receipt_revision"], 0)
            finally:
                gate.close()
        expected_mempool = {transaction.hash for transaction in transactions}
        # Restart at the same paths: native profile markers bind their block path.
        # Both nodes keep identical public evidence and mempools; restart discards
        # validation caches without copying or modifying an activation marker.
        self.stop_nodes()
        self.start_nodes(extra_args=[arguments + ["-networkactive=0"] for arguments in self.extra_args])
        for peer in self.nodes:
            peer.setnetworkactive(False)
            peer.setmocktime(self.fixed_mocktime)
            assert_equal(peer.getbestblockhash(), parent)
            assert_equal(set(peer.getrawmempool()), expected_mempool)
        self.report["fixture"] = {"native_parent": parent, "height": 101,
            "distinct_valid_origins": self.MINERS, "distinct_transaction_sets": len(txsets),
            "payout_identities": self.MINERS, "real_proofs": len(proofs),
            "template_bytes": distribution([len(raw) for raw, _ in origins], "bytes"),
            "proof_sequence_sha256": hashlib.sha256(b"".join(proof.serialize() for proof in proofs)).hexdigest(),
            "mempool_txids": sorted(expected_mempool), "mock_native_time": self.fixed_mocktime,
            "scheduler_clock": "real time.monotonic; native block time fixed equally in both arms",
            "both_backends_restarted_after_identical_collector_preload": True}
        return signers[0], proofs

    def phase_metrics(self, prefix):
        return {name: value for name, value in self.metrics.report().items() if name.startswith(prefix + ".")}

    def phase_payload(self, prefix):
        rows = {name: dict(value) for name, value in self.rpc_payload.items() if name.startswith(prefix + ".")}
        return {"methods": rows, "totals": {field: sum(row.get(field, 0) for row in rows.values())
                for field in ("calls", "request_bytes", "response_bytes")}}

    def run_arm(self, name, index, signer, proofs):
        self.phase = name + "_initial_open"
        self.report["active_stage"] = name
        self.log.info("Starting %s: %d proofs at %.3f second offered intervals", name, len(proofs),
                      self.options.offer_interval_ms / 1000)
        node = self.nodes[index]
        initial_open_started = time.monotonic()
        gate = self.open_collector(name, signer, index)
        initial_open_seconds = time.monotonic() - initial_open_started
        self.phase = name
        scheduler = None
        published, withdrawn, preparation, due_lateness, receipt_latency, receipt_service, queue_wait = [], [], [], [], [], [], []
        acknowledged_at, first_publication_delay = {}, {}
        last_authorization = None
        signer_cpu = 0.0
        published_bytes = Counter()
        expected_proofs = {proof.proof_id for proof in proofs}
        snapshot_directory = node.datadir_path / "regtest" / "sharepool-snapshots-v7"
        gate_directory_files = lambda: sum(path.stat().st_size for path in self.directory.glob(name + ".sqlite*") if path.is_file())
        initial_disk = {"gate_logical_bytes": gate_directory_files(),
                        "native_snapshot_logical_bytes": logical_bytes(snapshot_directory)}
        before_native = self.process_sample(node.process.pid)
        before_driver = self.process_sample(os.getpid())
        started, cpu_started, children_started = time.monotonic(), time.process_time(), self.child_cpu()
        idle_seconds, busy_seconds = 0.0, 0.0

        def sign(snapshot):
            nonlocal signer_cpu
            before = self.child_cpu()
            try:
                return signer.sign_owner(snapshot)
            finally:
                # No other child is reaped in this interval; native nodes stay alive.
                signer_cpu += self.child_cpu() - before

        def publish(authorization):
            nonlocal last_authorization
            gate.register_snapshot(authorization.snapshot_bytes)
            snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
            block = parse_block(authorization.block_bytes)
            assert_equal(block.m_mm_rhs, snapshot.hash)
            assert_equal(job_hash(block), snapshot.job_commitment)
            assert {share.proof_id for share in snapshot.shares} <= expected_proofs
            moment = time.monotonic()
            identities = {share.proof_id for share in snapshot.shares}
            for identity in identities:
                if identity not in first_publication_delay:
                    first_publication_delay[identity] = moment - acknowledged_at[identity]
            # Retain just the active authorization and small publication records.
            # Keeping every large body in the driver would inflate the old arm's
            # memory independently of actual gate and native archive retention.
            last_authorization = authorization
            published.append({"elapsed_seconds": moment - started, "proofs": len(identities),
                              "snapshot_hash": snapshot.hash_hex})
            published_bytes.update(template_bytes=len(authorization.block_bytes), snapshot_bytes=len(authorization.snapshot_bytes))
            return True

        def withdraw():
            withdrawn.append(time.monotonic())

        def operate(function, metric):
            nonlocal busy_seconds
            before = time.monotonic()
            before_publications = len(published)
            try:
                return self.metrics.call(name + "." + metric, function)
            finally:
                duration = time.monotonic() - before
                busy_seconds += duration
                if len(published) > before_publications:
                    # Same measurement boundary in both arms, including exact
                    # construction, signing, authorization, publication and the
                    # final context fence (plus the scheduler's own checks).
                    preparation.append(duration)

        def eager_job():
            block, snapshot = gate.make_native(sign_owner=sign)
            authorization = gate.authorize(block.serialize(), snapshot.serialize())
            assert gate.ready_for_dispatch(authorization)
            publish(authorization)
            assert gate.ready_for_continued_work(authorization)
            return authorization

        def poll():
            result = scheduler.poll()
            if result is not None:
                due_lateness.append(scheduler.last_due_lateness_seconds)
            return result

        try:
            if name == "datum":
                scheduler = HashJobScheduler(gate, sign_owner=sign, publish=publish, withdraw=withdraw,
                                             work_update_seconds=self.options.work_update_seconds)
                first = operate(poll, "scheduler_poll")
            else:
                first = operate(eager_job, "job_prepare_dispatch")
            assert_equal(Snapshot.deserialize(first.snapshot_bytes).shares, ())
            frozen = first.block_bytes, first.snapshot_bytes
            offers_start = time.monotonic()
            interval = self.options.offer_interval_ms / 1000
            for offset, proof in enumerate(proofs):
                self.bounded()
                due = offers_start + offset * interval
                while time.monotonic() < due:
                    wake = min(due, scheduler.next_refresh_at) if scheduler is not None else due
                    idle_seconds += self.wait_until_clock(wake)
                    if scheduler is not None and time.monotonic() >= scheduler.next_refresh_at:
                        operate(poll, "scheduler_poll")
                receipt_started = time.monotonic()
                queue_wait.append(max(0, receipt_started - due))
                assert operate(lambda: gate.receive(proof), "receive")
                acknowledged_at[proof.proof_id] = time.monotonic()
                receipt_service.append(time.monotonic() - receipt_started)
                receipt_latency.append(time.monotonic() - due)
                if scheduler is None:
                    operate(eager_job, "job_prepare_dispatch")
                else:
                    operate(poll, "scheduler_poll")
                assert_equal((first.block_bytes, first.snapshot_bytes), frozen)
                if offset % 25 == 24:
                    self.log.info("%s acknowledged %d/%d; published %d jobs", name, offset + 1, len(proofs), len(published))
            offers_complete = time.monotonic()
            # A fixed old cutoff remains unchanged; wait for the next ordinary
            # real deadline rather than forcing an unrepresentative final job.
            def published_ids():
                return {share.proof_id for share in Snapshot.deserialize(last_authorization.snapshot_bytes).shares}
            while published_ids() != expected_proofs:
                self.bounded()
                assert scheduler is not None
                idle_seconds += self.wait_until_clock(scheduler.next_refresh_at)
                operate(poll, "scheduler_poll")
            finished, driver_cpu, children_cpu = time.monotonic(), time.process_time() - cpu_started, self.child_cpu() - children_started
            after_native = self.process_sample(node.process.pid)
            after_driver = self.process_sample(os.getpid())
            final_disk = {"gate_logical_bytes": gate_directory_files(),
                          "native_snapshot_logical_bytes": logical_bytes(snapshot_directory)}
            row = {"node": index, "result": "timing_complete", "offered": len(proofs), "acknowledged": len(proofs),
                "published_jobs": len(published), "replacement_jobs": len(published) - 1,
                "initial_preloaded_gate_open_seconds_excluded": initial_open_seconds,
                "published_body_bytes": dict(published_bytes), "paced_wall_seconds": finished - started,
                "busy_operation_wall_seconds": busy_seconds, "explicit_pacing_sleep_seconds": idle_seconds,
                "other_driver_wall_seconds": max(0, finished - started - busy_seconds - idle_seconds),
                "offers_to_last_ack_and_refresh_seconds": offers_complete - offers_start,
                "final_refresh_wait_and_work_seconds": finished - offers_complete,
                "driver_cpu_seconds": driver_cpu, "driver_children_cpu_seconds": children_cpu,
                "rpc_json_reencoding_cpu_seconds": self.rpc_encoding_cpu[name],
                "driver_cpu_excluding_json_reencoding_seconds": max(0, driver_cpu - self.rpc_encoding_cpu[name]),
                "signer_children_cpu_seconds": signer_cpu,
                "native_cpu_seconds": after_native["cpu_seconds"] - before_native["cpu_seconds"],
                "rss_at_boundaries_bytes": {"driver_start": before_driver["rss_bytes"], "driver_end": after_driver["rss_bytes"],
                                            "native_start": before_native["rss_bytes"], "native_end": after_native["rss_bytes"]},
                "logical_disk_growth_bytes": {key: final_disk[key] - initial_disk[key] for key in initial_disk},
                "receipt_due_to_ack": distribution(receipt_latency), "receipt_service": distribution(receipt_service),
                "receipt_queue_wait": distribution(queue_wait), "job_preparation": distribution(preparation),
                "job_preparation_boundary": "entire fresh-job operation: build, sign, authorize, publish, final context checks",
                "ack_to_first_publication": distribution(first_publication_delay.values()),
                "publication_trace": published,
                "refresh_due_lateness": distribution(due_lateness), "rpc": self.phase_payload(name),
                "measurements": self.phase_metrics(name), "initial_job_cutoff_bytes_preserved": True}
            row["total_measured_cpu_seconds"] = driver_cpu + signer_cpu + row["native_cpu_seconds"]
            self.report["arms"][name] = row
            self.save_report()

            self.phase = name + "_idle_probe"
            idle_cpu, idle_wall = time.process_time(), time.monotonic()
            initial_publications = len(published)
            for _ in range(50):
                self.bounded()
                if scheduler is not None:
                    self.metrics.call(self.phase + ".poll", scheduler.poll)
                else:
                    assert self.metrics.call(self.phase + ".context_check", gate.ready_for_continued_work, last_authorization)
            row["idle_context_probe"] = {"operations": 50, "wall_seconds": time.monotonic() - idle_wall,
                "driver_cpu_seconds": time.process_time() - idle_cpu,
                "extra_publications": len(published) - initial_publications,
                "rpc": self.phase_payload(self.phase), "measurements": self.phase_metrics(self.phase)}
            self.phase = name + "_settlement"
            final = last_authorization
            block, snapshot = parse_block(final.block_bytes), Snapshot.deserialize(final.snapshot_bytes)
            assert_equal({proof.proof_id for proof in snapshot.shares}, expected_proofs)
            self.check_payouts(block, snapshot, [(block.m_height, proof) for proof in proofs],
                               reward=5_000_000_000 + self.MINERS * self.FEE)
            block.solve()
            assert_equal(self.call(index, "submitblock", block.serialize().hex()), None)
            assert_equal(self.call(index, "getbestblockhash"), block.hash)
            assert_equal(self.call(index, "getblock", block.hash, 0), block.serialize().hex())
            assert self.call(index, "verifychain", 4, 0)
            status = gate.receipt_status(limit=256)
            assert_equal(status["next_revision"], None)
            assert not status["history_limited"]
            counts = dict(Counter(receipt["status"] for receipt in status["receipts"]))
            assert_equal(counts, {"confirmed_admitted": self.MINERS})
            assert_equal(gate.batch_status()["eligible_count"], 0)
            assert_equal(node.getrawmempool(), [])
            row.update(result="passed", settlement={"block": block.hash, "parent": final.native_parent,
                "snapshot_hash": snapshot.hash_hex, "all_proof_ids_preserved": True,
                "exact_rational_payouts_verified": True, "receipt_states": counts,
                "remaining_eligible_backlog": 0, "expired_or_unknown": 0,
                "stored_block_bytes_match": True, "verifychain_level4": True})
            self.phase = name + "_reopen"
            head = gate.archive_head()
            if scheduler is not None:
                scheduler.close()
                scheduler = None
            close_started = time.monotonic()
            gate.close()
            close_seconds = time.monotonic() - close_started
            reopen_started, reopen_cpu = time.monotonic(), time.process_time()
            gate = self.open_collector(name, signer, index)
            open_seconds, open_cpu = time.monotonic() - reopen_started, time.process_time() - reopen_cpu
            assert_equal(gate.archive_head(), head)
            restored = gate.receipt_status(limit=256)
            assert not restored["history_limited"]
            assert_equal(restored["next_revision"], None)
            assert_equal(dict(Counter(receipt["status"] for receipt in restored["receipts"])), counts)
            row["populated_collector_reopen"] = {"close_wall_seconds": close_seconds,
                "open_wall_seconds": open_seconds, "open_driver_cpu_seconds": open_cpu,
                "journal_events": head["events"], "journal_bytes": head["bytes"],
                "exact_head_preserved": True, "confirmed_receipts_preserved": self.MINERS,
                "archive_rotation_exercised": False, "rpc": self.phase_payload(self.phase)}
            self.save_report()
        finally:
            if scheduler is not None:
                scheduler.close()
            gate.close()

    def run_test(self):
        opts = self.options
        assert 2 <= opts.miners <= 100
        assert 0 <= opts.offer_interval_ms <= 10_000
        assert 60 <= opts.max_runtime_seconds <= 7200
        if opts.results is None:
            opts.results = Path(opts.tmpdir) / "cadence-benchmark-results.json"
        self.MINERS = opts.miners
        self.directory = Path(opts.tmpdir) / "cadence-benchmark-gates"
        self.directory.mkdir(mode=0o700)
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.started, self.phase = time.monotonic(), "fixture"
        self.metrics, self.rpc_payload, self.keys = Measurements(), defaultdict(Counter), []
        self.rpc_encoding_cpu = Counter()
        order = ["per_ack", "datum"] if opts.arm_order == "per-ack-first" else ["datum", "per_ack"]
        source_names = ("test/functional/feature_sharepool_hash_cadence_benchmark.py",
                        "contrib/sharepool/hash_job_scheduler.py", "contrib/sharepool/hash_mining_gate.py",
                        "contrib/sharepool/hash_snapshot.py", "contrib/sharepool/hash_gate_batch.py",
                        "contrib/sharepool/capacity_metrics.py", "test/functional/feature_sharepool_hash_tides_100_miners.py")
        root = Path(__file__).resolve().parents[2]
        self.report = {"schema": 1, "result": "running", "network": "isolated native regtest",
            "profile": "hash-only-v7-compact-tides", "started_utc": datetime.now(timezone.utc).isoformat(),
            "command": [sys.executable, *sys.argv], "arm_order": order,
            "configuration": {"miners": opts.miners, "offer_interval_ms": opts.offer_interval_ms,
                              "refresh_seconds": opts.work_update_seconds, "max_runtime_seconds": opts.max_runtime_seconds},
            "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count(), "declared_load": opts.host_load},
            "native_binary_sha256": hashlib.sha256(Path(opts.bitcoind).read_bytes()).hexdigest(),
            "signer_binary_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest(),
            "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in source_names},
            "arms": {}, "rewards": [], "limitations": [
                "One finite sequential local workload and fixed arm order; no statistical confidence interval or saturation claim",
                "Real monotonic pacing; slow service creates a measured client queue instead of slowing offered due offsets",
                "Two disconnected native backends share the same parent, origin bytes and mempool; separate fresh collector journals",
                "Native validation caches are restarted, but OS file cache and thermals are not reset or controlled",
                "All source jobs and proofs are prepared before timing; fixture cost is reported separately",
                "This begins at activation with empty reward history; later-round accumulated history and archive rotation are unmeasured",
                "Per-ACK rebuilding is an explicit comparator caller, not a claim that the old gate automatically rebuilt jobs",
                "Logical publish callback stores native snapshot and retains bytes; no Stratum hardware or WAN transmission",
                "RPC byte totals re-encode method/params and result JSON without HTTP, authentication, envelope IDs or framing",
                "Driver CPU includes measurement overhead; separately timed JSON re-encoding cost is an approximate removable diagnostic cost",
                "RSS is measured at boundaries only, not peak; logical disk growth is not physical allocation or fsync latency",
                "Native CPU uses cumulative ps time; signer CPU uses reaped child rusage around individual signing calls",
                "Regtest share difficulty does not establish mainnet sampling variance or physical mining hashrate",
                "The final scheduled refresh can add deliberate waiting; busy work and paced wall time are reported separately",
                "One hundred logical miner origins feed one coordinator per arm, not one hundred full validating nodes"]}
        try:
            fixture_started = time.monotonic()
            signer, proofs = self.prepare_fixture()
            self.report["fixture"]["wall_seconds"] = time.monotonic() - fixture_started
            self.report["fixture"]["measurements"] = self.phase_metrics("fixture")
            self.save_report()
            for name in order:
                self.bounded()
                self.run_arm(name, 0 if name == "per_ack" else 1, signer, proofs)
            old, new = self.report["arms"]["per_ack"], self.report["arms"]["datum"]
            assert_equal(old["settlement"]["parent"], new["settlement"]["parent"])
            fields = ("replacement_jobs", "busy_operation_wall_seconds", "paced_wall_seconds",
                      "driver_cpu_seconds", "signer_children_cpu_seconds", "native_cpu_seconds", "total_measured_cpu_seconds")
            self.report["comparison"] = {field: {"per_ack": old[field], "datum": new[field],
                "reduction_fraction": 1 - new[field] / old[field] if old[field] else None} for field in fields}
            self.report.update(result="passed", active_stage="complete")
        except BaseException as error:
            self.report.update(result="failed", error_type=type(error).__name__, error=str(error)[:500],
                               failure_stage=self.report.get("active_stage", "fixture"))
            raise
        finally:
            self.report["wall_seconds"] = time.monotonic() - self.started
            for key in self.keys:
                key.unlink(missing_ok=True)
            self.save_report()


if __name__ == "__main__":
    SharePoolHashCadenceBenchmark(__file__).main()
