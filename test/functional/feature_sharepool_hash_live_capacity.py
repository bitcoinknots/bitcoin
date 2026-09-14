#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Finite continuously offered native work with live mempool/jobs and settlement.

A bounded number of source threads own disjoint miner gates and RPC connections.
The collector owns its gate on the test thread. Offers follow one fixed schedule,
including during settlement; fixed-phase results exclude all later catch-up and
drain. This is two loopback native nodes, not a WAN or ASIC saturation claim.
"""
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import math
import os
from pathlib import Path
import queue
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'contrib' / 'sharepool'))
from capacity_metrics import Measurements, ResourceSampler, distribution
from hash_admission_budget import AdmissionDecision, AdmissionRefused
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, MAX_SHARE_AGE, Snapshot, TemplateRecord, solve_share
from live_capacity_metrics import merge_measurements, owner_slots, phase_counts
from native_mining_gate import parse_block
from feature_sharepool_hash_capacity import SharePoolHashCapacityTest
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, CBlockHeader, CTxOut, from_hex, uint256_from_compact
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal, get_rpc_proxy, rpc_url


class SharePoolHashLiveCapacityTest(SharePoolHashTides100MinersTest):
    PROFILE_VERSION = 7
    ITEM_WIRE_LIMIT = 2 * 1024 * 1024
    QUEUE_ITEMS = 8
    MAX_PLANNED = 10000

    @staticmethod
    def parse_assignments(value):
        values = tuple(int(item) for item in value.split(','))
        if not 1 <= len(values) <= 100 or any(not 0 <= item <= 12 for item in values):
            raise ValueError('finite synthetic assignments require 1..100 exponents in 0..12')
        return values

    @staticmethod
    def schedule(miners, seconds, *, offer_interval_ms=None, target_share_seconds=None, profile=7):
        if type(miners) is not int or not 2 <= miners <= 100 or type(seconds) is not int or not 10 <= seconds <= 600:
            raise ValueError('finite workload requires 2..100 miners over 10..600 seconds')
        if offer_interval_ms is not None and target_share_seconds is not None:
            raise ValueError('select aggregate offer interval or per-miner cadence, not both')
        if offer_interval_ms is None and target_share_seconds is None:
            if profile == 8:
                target_share_seconds = 6
            else:
                offer_interval_ms = 500
        if target_share_seconds is not None:
            if not math.isfinite(target_share_seconds) or not 1 <= target_share_seconds <= 600:
                raise ValueError('finite target cadence must be 1..600 seconds')
            offer_interval_ms = 1000 * target_share_seconds / miners
        if not math.isfinite(offer_interval_ms) or not 10 <= offer_interval_ms <= 10000:
            raise ValueError('finite aggregate offer interval must be 10..10000 milliseconds')
        planned = math.ceil(Fraction(seconds * 1000) / Fraction(str(offer_interval_ms)))
        return offer_interval_ms, target_share_seconds, planned

    @staticmethod
    def queue_accounting(transfers, *, seconds):
        selected = []
        for row in transfers:
            assert math.isfinite(row['seconds']) and row['seconds'] >= 0
            for name in ('origin_bytes', 'origin_bytes_without_deduplication', 'proof_bytes', 'logical_payload_bytes'):
                assert type(row[name]) is int and row[name] >= 0
            assert type(row['full_origin']) is bool
            assert row['proof_bytes'] > 0 and row['origin_bytes_without_deduplication'] > 0
            assert_equal(row['origin_bytes'], row['origin_bytes_without_deduplication'] if row['full_origin'] else 0)
            assert_equal(row['logical_payload_bytes'], row['origin_bytes'] + row['proof_bytes'] + 68)
            if row['seconds'] <= seconds:
                selected.append(row)
        result = {name: sum(row[name] for row in selected) for name in
            ('origin_bytes', 'origin_bytes_without_deduplication', 'proof_bytes', 'logical_payload_bytes')}
        return dict(result, transferred_items=len(selected),
            full_origin_items=sum(row['full_origin'] for row in selected),
            reference_items=sum(not row['full_origin'] for row in selected),
            origin_bytes_avoided=result['origin_bytes_without_deduplication'] - result['origin_bytes'])

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_argument('--miners', type=int, default=100)
        parser.add_argument('--source-workers', type=int, default=1,
            help='1..miners fixed owner threads; default1 preserves the serial baseline')
        parser.add_argument('--profile-version', type=int, choices=(7, 8), default=7)
        parser.add_argument('--share-work-bits', type=self.parse_assignments,
            help='v8 only: explicit cycling per-miner assigned exponents, e.g. 2,4,6; bounded to 0..12')
        parser.add_argument('--duration-seconds', type=int, default=120)
        parser.add_argument('--offer-interval-ms', type=float,
            help='aggregate schedule; defaults to 500ms for v7, or six seconds per miner for v8')
        parser.add_argument('--target-share-seconds', type=float,
            help='derive aggregate schedule from this per-miner cadence; v8 default 6 seconds')
        parser.add_argument('--deduplicate-job-evidence', action='store_true',
            help='fixture FIFO queue sends each exact miner/job origin once, then references it')
        parser.add_argument('--settlement-seconds', type=int, default=20)
        parser.add_argument('--work-update-seconds', type=int, default=40)
        parser.add_argument('--snapshot-budget-bytes', type=int, default=65536)
        parser.add_argument('--padding-outputs', type=int, default=0)
        parser.add_argument('--max-runtime-seconds', type=int, default=1800)

    def set_test_params(self):
        super().set_test_params()
        self.PROFILE_VERSION = self.options.profile_version
        for args in self.extra_args:
            args.append('-sharepoolcompacttides=1')
            if self.PROFILE_VERSION == 8:
                args.append('-sharepoolvardiff=1')

    def open(self, name, signer, rpc):
        return HashMiningGate(self.directory / (name + '.sqlite'), rpc=rpc,
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=self.PROFILE_VERSION, activation_height=102,
            share_work_bits=self.assignments[signer.public_key] if self.PROFILE_VERSION == 8 else None,
            snapshot_budget=self.options.snapshot_budget_bytes)

    def check_payouts(self, block, snapshot, history, *, reward):
        if self.PROFILE_VERSION == 7:
            return super().check_payouts(block, snapshot, history, reward=reward)
        # Independent arithmetic: exact signed exponents, never current gateway
        # policy or equal-share counts. The native-height boundary cohort is
        # proportionally clipped using rational arithmetic, as in the v7 oracle.
        remaining = Fraction(8 << 256, uint256_from_compact(block.nBits) + 1)
        cohorts, weights, selected = {}, {}, []
        for height, proof in history:
            if proof.envelope.pool == snapshot.envelope.pool:
                assert_equal(proof.envelope.version, 8)
                assert 0 <= proof.envelope.share_work_bits <= 255
                cohorts.setdefault(height, []).append(proof)
        for height in sorted(cohorts, reverse=True):
            if remaining == 0:
                break
            cohort = cohorts[height]
            total_work = sum(1 << proof.envelope.share_work_bits for proof in cohort)
            included = min(remaining, Fraction(total_work))
            for proof in cohort:
                script = proof.envelope.payout_script
                contribution = Fraction(1 << proof.envelope.share_work_bits) * included / total_work
                weights[script] = weights.get(script, Fraction(0)) + contribution
                selected.append(proof.proof_id)
            remaining -= included
        assert weights
        total = sum(weights.values())
        expected = {script: int(reward * work / total) for script, work in weights.items()
                    if int(reward * work / total)}
        assert_equal(self.payouts(block), expected)
        assert_equal({bytes(output.scriptPubKey): output.nValue for output in snapshot.payouts}, expected)
        assert_equal([output.serialize() for output in block.vtx[0].vout[:len(snapshot.payouts)]],
            [output.serialize() for output in snapshot.payouts])
        assert len(block.vtx[0].vout) - len(snapshot.payouts) in (0, 1)
        for output in block.vtx[0].vout[len(snapshot.payouts):]:
            assert_equal(output.nValue, 0)
            assert bytes(output.scriptPubKey).startswith(bytes.fromhex('6a24aa21a9ed'))
        assert_equal(block.m_mm_rhs, snapshot.hash)
        assert_equal((snapshot.pending, snapshot.settled), ((), ()))
        self.report['rewards'].append({'height': block.m_height, 'commitment': snapshot.hash_hex,
            'new_admissions': len(snapshot.shares), 'eligible_proofs': len(selected),
            'payout_scripts': len(expected), 'reward_satoshis': reward,
            'unclaimed_rounding_satoshis': reward - sum(expected.values()),
            'whole_admission_height_cohorts_verified': True,
            'exact_rational_window_and_coinbase_verified': True, 'assigned_work_weighting_verified': True})
        return selected

    def bounded(self):
        if time.monotonic() - self.started > self.options.max_runtime_seconds:
            raise AssertionError('finite live workload runtime exceeded')

    def event(self, stage, proofs, *, slot=None):
        with self.lock:
            row = {'stage': stage, 'seconds': time.monotonic() - self.phase_start,
                   'proof_ids': [f'{proof.proof_id:064x}' for proof in proofs]}
            if slot is not None:
                row['slot'] = slot
            self.events.append(row)

    def capacity_refused(self, slot, index, signer, reason):
        """A terminal pre-dispatch refusal consumes no offered proof or ACK."""
        with self.lock:
            self.events.append({'stage': 'capacity_refused',
                'seconds': time.monotonic() - self.phase_start, 'slot': slot,
                'miner': index, 'identity': signer.public_key.hex(), 'reason': str(reason)[:160]})

    def pressure_decision(self, decision, *, stage, worker=None, miner=None, slot=None):
        if type(decision) is not AdmissionDecision or decision.mode not in ('OPEN','DRAIN'):
            raise ValueError('fixture requires an exact admission decision')
        with self.lock:
            self.pressure_decisions.append({'seconds': time.monotonic()-self.phase_start,
                'stage': stage, 'worker': worker, 'miner': miner, 'slot': slot,
                'mode': decision.mode, 'dispatch_allowed': decision.dispatch_allowed,
                'ack_allowed': decision.ack_allowed, 'reasons': decision.reasons,
                'resource_failures': decision.resource_failures,
                'eligible_count': decision.eligible_count, 'selected_count': decision.selected_count,
                'native_height': decision.native_height, 'receipt_revision': decision.receipt_revision})

    def prepare(self, gate, signer, *, stage, worker=None, miner=None, slot=None):
        if self.PROFILE_VERSION == 8:
            try:
                decision = gate.admission_status()
            except AdmissionRefused as error:
                self.pressure_decision(error.decision,stage=stage,worker=worker,miner=miner,slot=slot)
                raise
            self.pressure_decision(decision,stage=stage,worker=worker,miner=miner,slot=slot)
            # DRAIN can still dispatch the retained prefix. Refusing fresh ACKs
            # must never suppress a valid settlement of already promised work.
            if not decision.dispatch_allowed:
                raise AdmissionRefused(decision)
        return gate.prepare_native_authorization(sign_owner=signer.sign_owner)

    def produce(self, worker, signers, unspent, redeem, script):
        gates = {}
        node = self.nodes[0]
        metrics = self.source_metrics[worker]
        stats = self.worker_stats[worker]
        stats['thread_ident'] = threading.get_ident()
        tag = [b'initial']
        def rpc(method, *args):
            assert_equal(threading.get_ident(), stats['thread_ident'])
            result = metrics.call('rpc.' + method, getattr(proxy, method), *args)
            return (SharePoolHashCapacityTest.tag_unsigned_job(result, tag[0])
                    if method == 'preparesharepoolhashjob' else result)
        try:
            proxy = get_rpc_proxy(rpc_url(node.datadir_path, node.index, node.chain, node.rpchost), worker, timeout=60)
            for index, signer in enumerate(signers):
                if index % self.options.source_workers == worker:
                    gates[index] = self.open(f'live-miner-{index:03}', signer, rpc)
            stats['miner_indices'] = sorted(gates)
            self.source_ready[worker].set()
            self.begin.wait()
            active, nonces, refreshed, origin_keys, sent = {}, {}, {}, {}, {}
            for slot in owner_slots(miners=len(signers), planned=self.planned,
                    workers=self.options.source_workers, owner=worker):
                due = self.phase_start + slot * self.options.offer_interval_ms / 1000
                if self.stop.wait(max(0, due - time.monotonic())):
                    return
                self.bounded()
                index = slot % len(signers)
                gate, signer = gates[index], signers[index]
                started = time.monotonic()
                need_job = (index not in active or started - refreshed[index] >= self.options.work_update_seconds or
                            not gate.ready_for_continued_work(active[index]))
                if need_job:
                    previous, output, value = unspent[index]
                    tx = self.spend(previous, output, value, redeem, script, self.FEE)
                    tx.vout[0].nValue -= 1000 * self.options.padding_outputs
                    tx.vout.extend(CTxOut(1000, CScript(script)) for _ in range(self.options.padding_outputs))
                    tx.rehash()
                    rpc('sendrawtransaction', tx.serialize().hex())
                    unspent[index] = tx.sha256, 0, tx.vout[0].nValue
                    tag[0] = f'live-{index:03}-{slot:05}'.encode()
                    refused = False
                    for attempt in range(20):
                        if self.stop.is_set():
                            return
                        parent = rpc('getbestblockhash')
                        try:
                            authorization = self.prepare(gate,signer,stage='source_due_build',
                                worker=worker,miner=index,slot=slot)
                            block = parse_block(authorization.block_bytes)
                            snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
                            if not gate.ready_for_dispatch(authorization):
                                raise ValueError('native context changed before dispatch')
                            gate.register_snapshot(snapshot.serialize())
                            active[index], nonces[index] = authorization, 0
                            origin_keys[index] = (hashlib.sha256(authorization.block_bytes).digest(),
                                                  hashlib.sha256(authorization.snapshot_bytes).digest())
                            refreshed[index] = time.monotonic()
                            with self.lock:
                                self.jobs.append({'slot': slot, 'miner': index, 'worker': worker,
                                    'seconds': refreshed[index] - self.phase_start,
                                    'native_height': block.m_height,
                                    'template_id': f'{TemplateRecord.from_block(block).template_id:064x}',
                                    'transaction_merkle_root': f'{block.hashMerkleRoot:064x}',
                                    'transaction_ids': [tx.rehash() for tx in block.vtx[1:]],
                                    'template_bytes': len(authorization.block_bytes),
                                    'snapshot_bytes': len(authorization.snapshot_bytes),
                                    'assigned_work_bits': snapshot.envelope.share_work_bits if self.PROFILE_VERSION == 8 else None,
                                    'native_weight': block.get_weight()})
                            break
                        except AdmissionRefused as error:
                            self.capacity_refused(slot,index,signer,error)
                            with self.lock:
                                stats['capacity_refused'] = stats.get('capacity_refused',0)+1
                            refused = True
                            break
                        except Exception:
                            if rpc('getbestblockhash') == parent:
                                raise
                            with self.lock:
                                self.tip_retries += 1
                    else:
                        raise AssertionError('native-tip retry budget exhausted')
                    if refused:
                        continue
                authorization = active[index]
                snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
                proof = solve_share(parse_block(authorization.block_bytes), snapshot, start_nonce=nonces[index])
                nonces[index] = proof.header.nNonce + 1
                assert_equal(CBlockHeader(parse_block(authorization.block_for_header(proof.header_bytes))).serialize(), proof.header_bytes)
                key = origin_keys[index]
                full_origin = not self.options.deduplicate_job_evidence or sent.get(index) != key
                origin_bytes = len(authorization.block_bytes) + len(authorization.snapshot_bytes)
                proof_bytes = len(proof.serialize())
                wire = (origin_bytes if full_origin else 0) + proof_bytes + 68
                assert wire <= self.ITEM_WIRE_LIMIT, 'fixture queue item exceeds explicit wire budget'
                self.event('offered', [proof], slot=slot)
                with self.lock:
                    lateness, service = max(0, started - due), time.monotonic() - started
                    self.source_lateness.append(lateness)
                    self.source_service.append(service)
                    stats['lateness'].append(lateness)
                    stats['service'].append(service)
                    stats['offered'] += 1
                queue_started = time.monotonic()
                while not self.stop.is_set():
                    try:
                        self.inbox.put((index, key,
                            authorization.block_bytes if full_origin else None,
                            authorization.snapshot_bytes if full_origin else None, proof), timeout=.1)
                        sent[index] = key
                        with self.lock:
                            self.queue_high_water = max(self.queue_high_water, self.inbox.qsize())
                            self.source_queue_wait.append(time.monotonic() - queue_started)
                            stats['queue_wait'].append(time.monotonic() - queue_started)
                            self.queue_transfers.append({'seconds': time.monotonic() - self.phase_start,
                                'slot': slot, 'miner': index, 'worker': worker,
                                'full_origin': full_origin, 'origin_bytes': origin_bytes if full_origin else 0,
                                'origin_bytes_without_deduplication': origin_bytes,
                                'proof_bytes': proof_bytes, 'logical_payload_bytes': wire})
                        break
                    except queue.Full:
                        self.bounded()
        except BaseException as error:
            with self.lock:
                if self.source_error is None:
                    self.source_error = error
                stats['error_type'] = type(error).__name__
            self.source_ready[worker].set()
        finally:
            for gate in gates.values():
                try:
                    gate.close()
                except BaseException as error:
                    with self.lock:
                        if self.source_error is None:
                            self.source_error = error
                        stats['error_type'] = type(error).__name__
            with self.lock:
                self.source_finished += 1
                if self.source_finished == self.options.source_workers:
                    self.finished.set()

    def settle(self, gate, signer, history, admitted):
        self.bounded()
        started = time.monotonic()
        authorization = self.prepare(gate,signer,stage='collector_settlement')
        block = parse_block(authorization.block_bytes)
        snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
        assert gate.ready_for_dispatch(authorization)
        gate.register_snapshot(snapshot.serialize())
        ids = {proof.proof_id for proof in snapshot.shares}
        assert ids and not ids & admitted
        history.extend((block.m_height, proof) for proof in snapshot.shares)
        self.check_payouts(block, snapshot, history, reward=5_000_000_000 + self.FEE * (len(block.vtx) - 1))
        block.solve()
        assert_equal(authorization.block_for_header(CBlockHeader(block).serialize()), block.serialize())
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), None)
        admitted.update(ids)
        self.event('admitted', snapshot.shares)
        row = {'height': block.m_height, 'hash': block.hash, 'admitted': len(ids),
               'native_accepted': True, 'peer_ready': False,
               'local_seconds': time.monotonic() - self.phase_start,
               'snapshot_bytes': len(snapshot.serialize()), 'payout_recipients': len(snapshot.payouts),
               'coinbase_weight': block.vtx[0].get_weight(), 'native_weight': block.get_weight()}
        if self.PROFILE_VERSION == 8:
            row['admitted_assigned_work'] = sum(1 << proof.envelope.share_work_bits for proof in snapshot.shares)
            row['assigned_work_bits_counts'] = dict(Counter(proof.envelope.share_work_bits for proof in snapshot.shares))
        self.report['blocks'].append(row)
        self.wait_tip(block)
        self.event('peer_verified', snapshot.shares)
        row.update(peer_ready=True, peer_seconds=time.monotonic() - self.phase_start,
                   service_seconds=time.monotonic() - started)
        self.log.info('Live block %d admitted %d proofs; source continues independently', block.m_height, len(ids))

    def run_test(self):
        opts = self.options
        if opts.results is None:
            opts.results = Path(opts.tmpdir) / 'live-capacity-results.json'
        self.MINERS = opts.miners
        self.FEE = 1000 + 50 * opts.padding_outputs
        assert 2 <= opts.miners <= 100 and 10 <= opts.duration_seconds <= 600
        assert 1 <= opts.source_workers <= opts.miners
        opts.offer_interval_ms, opts.target_share_seconds, self.planned = self.schedule(opts.miners,
            opts.duration_seconds, offer_interval_ms=opts.offer_interval_ms,
            target_share_seconds=opts.target_share_seconds, profile=self.PROFILE_VERSION)
        assert opts.miners <= self.planned <= self.MAX_PLANNED
        assert (self.PROFILE_VERSION == 8) == (opts.share_work_bits is not None), 'only v8 requires explicit assignments'
        assert 5 <= opts.work_update_seconds <= 120 and 5 <= opts.settlement_seconds <= 120
        assert 4096 <= opts.snapshot_budget_bytes <= 16 * 1024 * 1024
        assert 0 <= opts.padding_outputs <= 100 and 60 <= opts.max_runtime_seconds <= 7200
        self.started = time.monotonic()
        self.directory = Path(opts.tmpdir) / 'live-capacity-gates'
        self.directory.mkdir(mode=0o700)
        self.lock, self.inbox = threading.Lock(), queue.Queue(maxsize=self.QUEUE_ITEMS)
        self.begin, self.stop, self.finished = (threading.Event() for _ in range(3))
        self.source_ready = [threading.Event() for _ in range(opts.source_workers)]
        self.source_finished = 0
        self.events, self.jobs, self.source_lateness, self.source_service = [], [], [], []
        self.pressure_decisions = []
        self.source_queue_wait, self.queue_transfers = [], []
        self.source_error, self.tip_retries, self.queue_high_water = None, 0, 0
        self.metrics = Measurements()
        self.source_metrics = [Measurements() for _ in range(opts.source_workers)]
        self.worker_stats = [{'worker': index, 'offered': 0, 'service': [], 'lateness': [], 'queue_wait': []}
                             for index in range(opts.source_workers)]
        self.phase_start = time.monotonic()
        self.report = {'schema': 3, 'result': 'running',
            'profile': 'hash-only-v8-vardiff-tides' if self.PROFILE_VERSION == 8 else 'hash-only-v7-compact-tides',
            'network': 'isolated native regtest', 'started_utc': datetime.now(timezone.utc).isoformat(),
            'configuration': {name: getattr(opts, name) for name in ('miners','duration_seconds','offer_interval_ms',
                'settlement_seconds','work_update_seconds','snapshot_budget_bytes','padding_outputs','max_runtime_seconds',
                'profile_version','share_work_bits','target_share_seconds','deduplicate_job_evidence','source_workers')},
            'scheduled_share_interval_per_miner_seconds': opts.offer_interval_ms * opts.miners / 1000,
            'scheduled_aggregate_shares_per_second': 1000 / opts.offer_interval_ms,
            'scheduled_requests': self.planned, 'native_nodes': 2, 'physical_miners_used': 0,
            'blocks': [], 'rewards': [], 'command': [sys.executable, *sys.argv],
            'source_ownership': {'workers': opts.source_workers,
                'identity_assignment': 'miner_index modulo source_workers; fixed for the whole run',
                'one_owner_per_miner': True, 'rpc_connections': opts.source_workers,
                'max_concurrent_signer_subprocesses': opts.source_workers + 1,
                'independent_identity_owners': opts.source_workers == opts.miners,
                'queue_items': self.QUEUE_ITEMS, 'max_pending_producer_items': opts.source_workers,
                'max_consumer_items': 1, 'max_logical_item_bytes': self.ITEM_WIRE_LIMIT,
                'max_transit_logical_bytes': (self.QUEUE_ITEMS + opts.source_workers + 1) * self.ITEM_WIRE_LIMIT},
            'limitations': ['Bounded source owner threads service fixed identity shards; one worker preserves the serial baseline.',
                'One worker per miner separates gateway scheduling; fewer workers still couple miners within each shard.',
                'All threads share the Python GIL, one native node and host resources; this is not distributed production capacity.',
                'Aggregate source/RPC service durations sum overlapping owner intervals, not elapsed time or CPU; driver CPU excludes signer subprocesses.',
                'Source offers continue during settlement on separate owner gates and RPC connections.',
                'Finite scheduled phase followed by explicit catch-up/drain; only timestamped phase completions count toward phase rates.',
                'Two loopback Debug native nodes, easy proofs and controlled block opportunities; no WAN, ASIC or production variance claim.',
                'Queue has eight items of at most two MiB logical payload, plus one item per source owner and one consumer; Python object and persistent gate overhead are additional.',
                'Optional origin deduplication uses per-identity ordered messages in this bounded FIFO fixture; logical payload accounting is not measured network traffic.',
                'Each source gate retains its current job; collector deduplication retains at most one origin key/envelope/signature per logical miner, with full evidence in the durable gate.',
                'V8 assignments are explicit fixed synthetic work exponents; cadence is an offered workload schedule, not an adaptive-controller or physical-hashrate measurement.']}
        self.report['limitations'].append('Admission pressure refuses only new local promises; existing ACKs remain retained. Native-winning synthetic shares are not auto-submitted in this controlled-block fixture; settlement block submission is independent of ACK pressure.')
        self.report['limitations'].append('An additional admission_status query precedes due source and settlement preparation for diagnostic pressure reporting; its preflight cost is included. Collector register_and_ack service includes capacity-refused attempts, whose outcomes are counted separately.')
        keys, producers, collector, sampler = [], [], None, None
        try:
            node, follower = self.nodes
            self.connect_nodes(0,1)
            self.genesis = int(node.getblockhash(0),16)
            redeem = CScript([OP_TRUE]); script = b'\x00\x20' + hashlib.sha256(bytes(redeem)).digest()
            funded = self.generatetoaddress(node,100,script_to_p2wsh(redeem))
            coinbase = from_hex(CBlock(),node.getblock(funded[0],0)).vtx[0]; coinbase.rehash()
            value = (coinbase.vout[0].nValue - 10000) // self.MINERS
            funding = self.spend(coinbase.sha256,0,coinbase.vout[0].nValue,redeem,script,10000)
            funding.vout = [CTxOut(value,CScript(script)) for _ in range(self.MINERS)]; funding.rehash()
            node.sendrawtransaction(funding.serialize().hex())
            self.generatetoaddress(node,1,script_to_p2wsh(redeem)); self.sync_blocks()
            signers = []
            self.assignments = {}
            for index in range(self.MINERS):
                path = self.directory / f'owner-{index:03}.key'; keys.append(path)
                signers.append(HashSigner.create(self.signer_binary,path,pool=0x11C0,
                    payout_script=b'\x00\x14'+(index+1).to_bytes(20,'big')))
                if self.PROFILE_VERSION == 8:
                    self.assignments[signers[-1].public_key] = opts.share_work_bits[index % len(opts.share_work_bits)]
            collector = self.open('live-collector',signers[0],lambda method,*args:
                self.metrics.call('collector.rpc.' + method,getattr(node,method),*args))
            unspent = [(funding.sha256,index,value) for index in range(self.MINERS)]
            for worker in range(opts.source_workers):
                producer = threading.Thread(target=self.produce,
                    args=(worker,signers,unspent,redeem,script), name=f'live-native-source-{worker}')
                producers.append(producer)
                producer.start()
            setup_deadline = time.monotonic() + 30
            for ready in self.source_ready:
                assert ready.wait(max(0, setup_deadline - time.monotonic())), 'source setup timeout'
            if self.source_error: raise self.source_error
            sampler = ResourceSampler({'node0':node.process.pid,'node1':follower.process.pid,'driver':os.getpid()},
                                      {'gates':self.directory,'node0':node.datadir_path,'node1':follower.datadir_path})
            sampler.start()
            network_start = [peer.getnettotals() for peer in self.nodes]
            self.phase_start = time.monotonic(); self.begin.set()
            next_block = self.phase_start + opts.settlement_seconds
            acknowledged, admitted, history, rejected, admission_refused = set(), set(), [], 0, 0
            seen_origins = {}
            phase_end = self.phase_start + opts.duration_seconds
            while (time.monotonic() < phase_end or not self.finished.is_set() or
                   not self.inbox.empty() or acknowledged != admitted):
                self.bounded()
                if self.source_error: raise self.source_error
                try:
                    index, key, raw, opening, proof = self.inbox.get(timeout=.02)
                    assert 0 <= index < self.MINERS
                    if raw is not None:
                        assert opening is not None
                        assert_equal(key, (hashlib.sha256(raw).digest(), hashlib.sha256(opening).digest()))
                        origin = Snapshot.deserialize(opening)
                        seen_origins[index] = (key, origin.envelope, origin.owner_signature)
                    else:
                        assert opening is None and opts.deduplicate_job_evidence
                    assert index in seen_origins
                    assert_equal(seen_origins[index], (key, proof.envelope, proof.owner_signature))
                    assert_equal(proof.envelope.public_key, signers[index].public_key)
                    if self.PROFILE_VERSION == 8:
                        assert_equal(proof.envelope.share_work_bits, self.assignments[signers[index].public_key])
                    if proof.envelope.height < node.getblockcount() + 1 - MAX_SHARE_AGE:
                        self.event('rejected',[proof]); rejected += 1
                    else:
                        with self.metrics.measure('collector.register_and_ack'):
                            if raw is not None:
                                collector.register_snapshot(opening)
                                collector.register_template(raw)
                            try:
                                assert collector.receive(proof)
                            except AdmissionRefused as error:
                                self.pressure_decision(error.decision,stage='collector_pre_ack',miner=index)
                                self.event('admission_refused',[proof]); admission_refused += 1
                            else:
                                assert proof.proof_id not in acknowledged
                                acknowledged.add(proof.proof_id); self.event('acknowledged',[proof])
                except queue.Empty:
                    pass
                now = time.monotonic()
                drain_ready = now >= phase_end and self.finished.is_set() and self.inbox.empty()
                if acknowledged != admitted and (now >= next_block or drain_ready):
                    assert len(self.report['blocks']) < 64, 'finite settlement opportunity limit'
                    with self.metrics.measure('collector.settlement'):
                        self.settle(collector,signers[0],history,admitted)
                    # Do not compress missed block opportunities into artificial
                    # immediate blocks while work is being offered.
                    next_block = time.monotonic() + opts.settlement_seconds
            for producer in producers:
                producer.join(timeout=5)
                assert not producer.is_alive()
            assert_equal(len(self.jobs),len({row['template_id'] for row in self.jobs}))
            assert_equal(len(self.jobs),len({row['transaction_merkle_root'] for row in self.jobs}))
            if not any(event['stage']=='capacity_refused' for event in self.events):
                assert_equal(len({row['miner'] for row in self.jobs}),self.MINERS)
            assert node.verifychain(4,0) and follower.verifychain(4,0)
            counts, cursor = Counter(),0
            for _ in range(math.ceil(self.MAX_PLANNED / 256)):
                page = collector.receipt_status(after_revision=cursor,limit=256)
                assert not page['history_limited']
                counts.update(row['status'] for row in page['receipts'])
                if page['next_revision'] is None:break
                cursor = page['next_revision']
            else:
                raise AssertionError('bounded receipt pagination did not reach the end')
            assert_equal(counts.get('confirmed_admitted',0),len(acknowledged))
            assert_equal(counts.get('expired_unanchored',0),0)
            assert_equal(sum(counts.values()),len(acknowledged))
            with self.lock:
                complete = phase_counts(self.events, seconds=time.monotonic() - self.phase_start)
                transfers = self.queue_accounting(self.queue_transfers, seconds=time.monotonic() - self.phase_start)
            assert_equal(complete['offered'] + complete['capacity_refused'], self.planned)
            assert_equal({event['slot'] for event in self.events if event['stage'] in ('offered','capacity_refused')},set(range(self.planned)))
            assert_equal(complete['acknowledged'] + complete['rejected'] + complete['admission_refused'], complete['offered'])
            assert_equal(complete['admission_refused'],admission_refused)
            assert_equal(complete['admitted'], len(acknowledged))
            assert_equal(complete['peer_verified'], len(acknowledged))
            assert_equal(transfers['transferred_items'], complete['offered'])
            assert_equal(transfers['full_origin_items'], len(self.jobs) if opts.deduplicate_job_evidence else complete['offered'])
            assert len(seen_origins) <= self.MINERS
            self.report.update(result='passed',receipt_states=dict(counts),expired_acknowledged=0,
                               rejected_before_ack=rejected,admission_refused=admission_refused,
                               payout_oracle_verified=bool(self.report['blocks']),peer_verified=bool(self.report['blocks']))
            self.report['native_p2p_bytes'] = [{key:peer.getnettotals()[key]-start[key]
                for key in ('totalbytessent','totalbytesrecv')} for peer,start in zip(self.nodes,network_start)]
        except BaseException as error:
            self.report.update(result='failed',error_type=type(error).__name__,error=str(error)[:300])
            raise
        finally:
            self.stop.set(); self.begin.set()
            cleanup_deadline = time.monotonic() + 60
            for producer in producers:
                producer.join(timeout=max(0,cleanup_deadline-time.monotonic()))
            sources_stopped = all(not producer.is_alive() for producer in producers)
            if not sources_stopped:
                self.report['cleanup_error'] = 'source RPC exceeded cleanup deadline'
            if sampler is not None:self.report['resources'] = sampler.finish()
            if collector is not None:collector.close()
            if sources_stopped:
                for path in keys:path.unlink(missing_ok=True)
            elapsed = max(.000001,time.monotonic()-self.phase_start)
            with self.lock:
                self.report.update(events=list(self.events),jobs=list(self.jobs),pressure_decisions=list(self.pressure_decisions),
                    measured_phase=phase_counts(self.events,seconds=opts.duration_seconds),
                    completed_run=phase_counts(self.events,seconds=max(elapsed,opts.duration_seconds)),
                    source_scheduling_lateness=distribution(self.source_lateness),
                    source_service=distribution(self.source_service),native_tip_retries=self.tip_retries,
                    source_queue_put_wait=distribution(self.source_queue_wait),
                    queue_transfers=list(self.queue_transfers),
                    measured_phase_queue_payload=self.queue_accounting(self.queue_transfers, seconds=opts.duration_seconds),
                    completed_queue_payload=self.queue_accounting(self.queue_transfers, seconds=elapsed),
                    queue_high_water_items=self.queue_high_water)
            self.report['measured_phase']['scheduled_requests_due'] = self.planned
            self.report['measured_phase']['source_unfulfilled_requests'] = (self.planned -
                self.report['measured_phase']['offered'] - self.report['measured_phase']['capacity_refused'])
            self.report['source_workers'] = [dict(worker=row['worker'],
                miner_indices=list(row.get('miner_indices', ())), owner_thread=row.get('thread_ident'),
                offered=row['offered'], source_service=distribution(row['service']),
                capacity_refused=row.get('capacity_refused',0),
                source_scheduling_lateness=distribution(row['lateness']),
                queue_put_wait=distribution(row['queue_wait']), error_type=row.get('error_type'),
                rpc_measurements=metrics.report()) for row,metrics in zip(self.worker_stats,self.source_metrics)] if sources_stopped else None
            self.report.update(seconds=time.monotonic()-self.started,live_and_drain_seconds=elapsed,
                catchup_and_drain_seconds=max(0,elapsed-opts.duration_seconds),measurements=self.metrics.report(),
                source_rpc_measurements=merge_measurements(self.source_metrics) if sources_stopped else None,
                source_sha256={str(path.relative_to(Path(__file__).resolve().parents[2])):hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in [Path(__file__).resolve(),*sorted((Path(__file__).resolve().parents[2]/'contrib/sharepool').glob('hash_*.py')),
                                 Path(__file__).resolve().parents[2]/'contrib/sharepool/live_capacity_metrics.py']},
                native_binary_sha256=hashlib.sha256(Path(opts.bitcoind).read_bytes()).hexdigest(),
                signer_binary_sha256=hashlib.sha256(self.signer_binary.read_bytes()).hexdigest())
            self.save_report()


if __name__ == '__main__':
    SharePoolHashLiveCapacityTest(__file__).main()
