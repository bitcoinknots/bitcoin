#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Finite continuously offered native work with live mempool/jobs and settlement.

A source thread owns its miner gates and a separate RPC connection. The collector
owns its gate on the test thread. Offers follow one fixed monotonic schedule,
including during settlement; fixed-phase results exclude all later catch-up and
drain. This is two loopback native nodes, not a WAN or ASIC saturation claim.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import queue
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'contrib' / 'sharepool'))
from capacity_metrics import Measurements, ResourceSampler, distribution
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, MAX_SHARE_AGE, Snapshot, TemplateRecord, solve_share
from live_capacity_metrics import phase_counts
from native_mining_gate import parse_block
from feature_sharepool_hash_capacity import SharePoolHashCapacityTest
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, CBlockHeader, CTxOut, from_hex
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal, get_rpc_proxy, rpc_url


class SharePoolHashLiveCapacityTest(SharePoolHashTides100MinersTest):
    PROFILE_VERSION = 7
    ITEM_WIRE_LIMIT = 2 * 1024 * 1024
    QUEUE_ITEMS = 8

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_argument('--miners', type=int, default=100)
        parser.add_argument('--duration-seconds', type=int, default=120)
        parser.add_argument('--offer-interval-ms', type=int, default=500)
        parser.add_argument('--settlement-seconds', type=int, default=20)
        parser.add_argument('--work-update-seconds', type=int, default=40)
        parser.add_argument('--snapshot-budget-bytes', type=int, default=65536)
        parser.add_argument('--padding-outputs', type=int, default=0)
        parser.add_argument('--max-runtime-seconds', type=int, default=1800)

    def set_test_params(self):
        super().set_test_params()
        for args in self.extra_args:
            args.append('-sharepoolcompacttides=1')

    def open(self, name, signer, rpc):
        return HashMiningGate(self.directory / (name + '.sqlite'), rpc=rpc,
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=7, activation_height=102,
            snapshot_budget=self.options.snapshot_budget_bytes)

    def bounded(self):
        if time.monotonic() - self.started > self.options.max_runtime_seconds:
            raise AssertionError('finite live workload runtime exceeded')

    def event(self, stage, proofs):
        with self.lock:
            self.events.append({'stage': stage, 'seconds': time.monotonic() - self.phase_start,
                                'proof_ids': [f'{proof.proof_id:064x}' for proof in proofs]})

    def produce(self, signers, unspent, redeem, script):
        gates = []
        node = self.nodes[0]
        proxy = get_rpc_proxy(rpc_url(node.datadir_path, node.index, node.chain, node.rpchost), 0, timeout=60)
        tag = [b'initial']
        def rpc(method, *args):
            result = getattr(proxy, method)(*args)
            return (SharePoolHashCapacityTest.tag_unsigned_job(result, tag[0])
                    if method == 'preparesharepoolhashjob' else result)
        try:
            for index, signer in enumerate(signers):
                gates.append(self.open(f'live-miner-{index:03}', signer, rpc))
            self.ready.set()
            self.begin.wait()
            active, nonces, refreshed = {}, {}, {}
            for slot in range(self.planned):
                due = self.phase_start + slot * self.options.offer_interval_ms / 1000
                if self.stop.wait(max(0, due - time.monotonic())):
                    return
                self.bounded()
                index = slot % len(gates)
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
                    for attempt in range(20):
                        if self.stop.is_set():
                            return
                        parent = rpc('getbestblockhash')
                        try:
                            block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
                            authorization = gate.authorize(block.serialize(), snapshot.serialize())
                            if not gate.ready_for_dispatch(authorization):
                                raise ValueError('native context changed before dispatch')
                            gate.register_snapshot(snapshot.serialize())
                            active[index], nonces[index] = authorization, 0
                            refreshed[index] = time.monotonic()
                            with self.lock:
                                self.jobs.append({'slot': slot, 'miner': index,
                                    'seconds': refreshed[index] - self.phase_start,
                                    'native_height': block.m_height,
                                    'template_id': f'{TemplateRecord.from_block(block).template_id:064x}',
                                    'transaction_merkle_root': f'{block.hashMerkleRoot:064x}',
                                    'transaction_ids': [tx.rehash() for tx in block.vtx[1:]],
                                    'template_bytes': len(authorization.block_bytes),
                                    'snapshot_bytes': len(authorization.snapshot_bytes),
                                    'native_weight': block.get_weight()})
                            break
                        except Exception:
                            if rpc('getbestblockhash') == parent:
                                raise
                            with self.lock:
                                self.tip_retries += 1
                    else:
                        raise AssertionError('native-tip retry budget exhausted')
                authorization = active[index]
                snapshot = Snapshot.deserialize(authorization.snapshot_bytes)
                proof = solve_share(parse_block(authorization.block_bytes), snapshot, start_nonce=nonces[index])
                nonces[index] = proof.header.nNonce + 1
                assert_equal(CBlockHeader(parse_block(authorization.block_for_header(proof.header_bytes))).serialize(), proof.header_bytes)
                wire = len(authorization.block_bytes) + len(authorization.snapshot_bytes) + len(proof.serialize())
                assert wire <= self.ITEM_WIRE_LIMIT, 'fixture queue item exceeds explicit wire budget'
                self.event('offered', [proof])
                with self.lock:
                    self.source_lateness.append(max(0, started - due))
                    self.source_service.append(time.monotonic() - started)
                while not self.stop.is_set():
                    try:
                        self.inbox.put((authorization.block_bytes, authorization.snapshot_bytes, proof), timeout=.1)
                        with self.lock:
                            self.queue_high_water = max(self.queue_high_water, self.inbox.qsize())
                        break
                    except queue.Full:
                        self.bounded()
        except BaseException as error:
            self.source_error = error
            self.ready.set()
        finally:
            for gate in gates:
                gate.close()
            self.finished.set()

    def settle(self, gate, signer, history, admitted):
        self.bounded()
        started = time.monotonic()
        block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
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
        self.planned = math.ceil(opts.duration_seconds * 1000 / opts.offer_interval_ms)
        assert 2 <= opts.miners <= 100 and opts.miners <= self.planned <= 1000
        assert 10 <= opts.duration_seconds <= 600 and 50 <= opts.offer_interval_ms <= 10000
        assert 5 <= opts.work_update_seconds <= 120 and 5 <= opts.settlement_seconds <= 120
        assert 4096 <= opts.snapshot_budget_bytes <= 16 * 1024 * 1024
        assert 0 <= opts.padding_outputs <= 100 and 60 <= opts.max_runtime_seconds <= 7200
        self.started = time.monotonic()
        self.directory = Path(opts.tmpdir) / 'live-capacity-gates'
        self.directory.mkdir(mode=0o700)
        self.lock, self.inbox = threading.Lock(), queue.Queue(maxsize=self.QUEUE_ITEMS)
        self.ready, self.begin, self.stop, self.finished = (threading.Event() for _ in range(4))
        self.events, self.jobs, self.source_lateness, self.source_service = [], [], [], []
        self.source_error, self.tip_retries, self.queue_high_water = None, 0, 0
        self.metrics, self.phase_start = Measurements(), time.monotonic()
        self.report = {'schema': 1, 'result': 'running', 'profile': 'hash-only-v7-compact-tides',
            'network': 'isolated native regtest', 'started_utc': datetime.now(timezone.utc).isoformat(),
            'configuration': {name: getattr(opts, name) for name in ('miners','duration_seconds','offer_interval_ms',
                'settlement_seconds','work_update_seconds','snapshot_budget_bytes','padding_outputs','max_runtime_seconds')},
            'scheduled_requests': self.planned, 'native_nodes': 2, 'physical_miners_used': 0,
            'blocks': [], 'rewards': [], 'command': [sys.executable, *sys.argv],
            'limitations': ['One source thread serially services logical miners; source scheduling backlog is reported.',
                'Source offers continue during settlement on separate owner gates and an independent RPC connection.',
                'Finite scheduled phase followed by explicit catch-up/drain; only timestamped phase completions count toward phase rates.',
                'Two loopback Debug native nodes, easy proofs and controlled block opportunities; no WAN, ASIC or production variance claim.',
                'Serialized queue has eight items of at most two MiB, plus one producer and one consumer item; Python object overhead is not bounded by this wire charge.']}
        keys, producer, collector, sampler = [], None, None, None
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
            for index in range(self.MINERS):
                path = self.directory / f'owner-{index:03}.key'; keys.append(path)
                signers.append(HashSigner.create(self.signer_binary,path,pool=0x11C0,
                    payout_script=b'\x00\x14'+(index+1).to_bytes(20,'big')))
            collector = self.open('live-collector',signers[0],lambda method,*args:getattr(node,method)(*args))
            producer = threading.Thread(target=self.produce, args=(signers,[(funding.sha256,index,value)
                for index in range(self.MINERS)],redeem,script), name='live-native-source')
            producer.start()
            assert self.ready.wait(30), 'source setup timeout'
            if self.source_error: raise self.source_error
            sampler = ResourceSampler({'node0':node.process.pid,'node1':follower.process.pid},
                                      {'gates':self.directory,'node0':node.datadir_path,'node1':follower.datadir_path})
            sampler.start()
            network_start = [peer.getnettotals() for peer in self.nodes]
            self.phase_start = time.monotonic(); self.begin.set()
            next_block = self.phase_start + opts.settlement_seconds
            acknowledged, admitted, history, rejected = set(), set(), [], 0
            phase_end = self.phase_start + opts.duration_seconds
            while (time.monotonic() < phase_end or not self.finished.is_set() or
                   not self.inbox.empty() or acknowledged != admitted):
                self.bounded()
                if self.source_error: raise self.source_error
                try:
                    raw, opening, proof = self.inbox.get(timeout=.02)
                    if proof.envelope.height < node.getblockcount() + 1 - MAX_SHARE_AGE:
                        self.event('rejected',[proof]); rejected += 1
                    else:
                        with self.metrics.measure('collector.register_and_ack'):
                            collector.register_snapshot(opening)
                            collector.register_template(raw)
                            collector.receive(proof)
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
            producer.join(timeout=5)
            assert not producer.is_alive()
            assert_equal(len(self.jobs),len({row['template_id'] for row in self.jobs}))
            assert_equal(len(self.jobs),len({row['transaction_merkle_root'] for row in self.jobs}))
            assert_equal(len({row['miner'] for row in self.jobs}),self.MINERS)
            assert node.verifychain(4,0) and follower.verifychain(4,0)
            counts, cursor = Counter(),0
            for _ in range(16):
                page = collector.receipt_status(after_revision=cursor,limit=256)
                assert not page['history_limited']
                counts.update(row['status'] for row in page['receipts'])
                if page['next_revision'] is None:break
                cursor = page['next_revision']
            assert_equal(counts.get('confirmed_admitted',0),len(acknowledged))
            assert_equal(counts.get('expired_unanchored',0),0)
            self.report.update(result='passed',receipt_states=dict(counts),expired_acknowledged=0,
                               rejected_before_ack=rejected,payout_oracle_verified=True,peer_verified=True)
            self.report['native_p2p_bytes'] = [{key:peer.getnettotals()[key]-start[key]
                for key in ('totalbytessent','totalbytesrecv')} for peer,start in zip(self.nodes,network_start)]
        except BaseException as error:
            self.report.update(result='failed',error_type=type(error).__name__,error=str(error)[:300])
            raise
        finally:
            self.stop.set(); self.begin.set()
            if producer is not None:producer.join(timeout=65)
            if producer is not None and producer.is_alive():
                self.report['cleanup_error'] = 'source RPC exceeded cleanup deadline'
            if sampler is not None:self.report['resources'] = sampler.finish()
            if collector is not None:collector.close()
            if producer is None or not producer.is_alive():
                for path in keys:path.unlink(missing_ok=True)
            elapsed = max(.000001,time.monotonic()-self.phase_start)
            with self.lock:
                self.report.update(events=list(self.events),jobs=list(self.jobs),
                    measured_phase=phase_counts(self.events,seconds=opts.duration_seconds),
                    completed_run=phase_counts(self.events,seconds=max(elapsed,opts.duration_seconds)),
                    source_scheduling_lateness=distribution(self.source_lateness),
                    source_service=distribution(self.source_service),native_tip_retries=self.tip_retries,
                    queue_high_water_items=self.queue_high_water)
            self.report['measured_phase']['scheduled_requests_due'] = self.planned
            self.report['measured_phase']['source_unfulfilled_requests'] = self.planned - self.report['measured_phase']['offered']
            self.report.update(seconds=time.monotonic()-self.started,live_and_drain_seconds=elapsed,
                catchup_and_drain_seconds=max(0,elapsed-opts.duration_seconds),measurements=self.metrics.report(),
                source_sha256={str(path.relative_to(Path(__file__).resolve().parents[2])):hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in [Path(__file__).resolve(),*sorted((Path(__file__).resolve().parents[2]/'contrib/sharepool').glob('hash_*.py')),
                                 Path(__file__).resolve().parents[2]/'contrib/sharepool/live_capacity_metrics.py']},
                native_binary_sha256=hashlib.sha256(Path(opts.bitcoind).read_bytes()).hexdigest(),
                signer_binary_sha256=hashlib.sha256(self.signer_binary.read_bytes()).hexdigest())
            self.save_report()


if __name__ == '__main__':
    SharePoolHashLiveCapacityTest(__file__).main()
