#!/usr/bin/env python3
"""Actual fixture owner lifecycle with fake native RPC, not native validity."""
from io import BytesIO
from pathlib import Path
import queue
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from capacity_metrics import Measurements
from hash_admission_budget import AdmissionDecision, AdmissionRefused
from feature_sharepool_hash_live_capacity import SharePoolHashLiveCapacityTest
from native_mining_gate import parse_block
from test_framework.messages import CBlock, CBlockHeader
from test_hash_compact import compact_fixture


class LiveOwnerTests(unittest.TestCase):
    def test_drain_status_keeps_retained_prefix_buildable_without_ack_permission(self):
        harness=object.__new__(SharePoolHashLiveCapacityTest)
        harness.PROFILE_VERSION=8
        harness.lock=threading.Lock();harness.pressure_decisions=[];harness.phase_start=time.monotonic()
        decision=AdmissionDecision('DRAIN',False,True,('admission-deadline-margin',),(),0,'aa'*32,105,6,6,6)
        calls=[]
        gate=SimpleNamespace(admission_status=lambda:decision,
            prepare_native_authorization=lambda **unused:calls.append('build') or 'authorization')
        signer=SimpleNamespace(sign_owner=None)
        self.assertEqual(harness.prepare(gate,signer,stage='collector_settlement'),'authorization')
        self.assertEqual(calls,['build'])
        self.assertEqual(harness.pressure_decisions[0]['mode'],'DRAIN')
        self.assertFalse(harness.pressure_decisions[0]['ack_allowed'])
        denied=AdmissionDecision('DRAIN',False,False,('resource-budget',),('snapshot_bytes',),0,'aa'*32,105,6,6,0)
        def refuse():raise AdmissionRefused(denied)
        gate.admission_status=refuse
        with self.assertRaises(AdmissionRefused):harness.prepare(gate,signer,stage='source_due_build',worker=0,miner=0,slot=0)
        self.assertEqual(calls,['build'])
        self.assertEqual(len(harness.pressure_decisions),2)

    def test_slow_owner_does_not_block_another_identity_or_cross_gate_threads(self):
        harness = object.__new__(SharePoolHashLiveCapacityTest)
        harness.options = SimpleNamespace(source_workers=2, offer_interval_ms=10,
            work_update_seconds=40, padding_outputs=0, max_runtime_seconds=30,
            deduplicate_job_evidence=True)
        harness.PROFILE_VERSION, harness.planned, harness.FEE = 7, 4, 1000
        harness.nodes = [SimpleNamespace(datadir_path=Path('/unused'),index=0,chain='regtest',rpchost=None)]
        harness.lock, harness.inbox = threading.Lock(), queue.Queue(maxsize=8)
        harness.begin, harness.stop, harness.finished = (threading.Event() for _ in range(3))
        harness.source_ready = [threading.Event(),threading.Event()]
        harness.source_metrics = [Measurements(),Measurements()]
        harness.worker_stats = [dict(worker=i,offered=0,service=[],lateness=[],queue_wait=[]) for i in range(2)]
        harness.source_finished, harness.source_error = 0, None
        harness.events,harness.jobs,harness.source_lateness,harness.source_service = [],[],[],[]
        harness.source_queue_wait,harness.queue_transfers = [],[]
        harness.tip_retries,harness.queue_high_water = 0,0
        harness.started = time.monotonic()
        harness.phase_start = harness.started - 1  # Due slots, no timing/throughput claim.
        blocked,release,other_done = threading.Event(),threading.Event(),threading.Event()
        bodies = [compact_fixture(ntime=1700000010+i,secret=(i+1).to_bytes(32,'big')) for i in range(2)]
        signers = [SimpleNamespace(public_key=s.envelope.public_key,sign_owner=None) for _,s in bodies]
        owners,closed = {},[]

        class Gate:
            def __init__(self,index):
                self.index=index
                self.owner=threading.get_ident()
                owners[index]=self.owner
            def check(self):
                self_test.assertEqual(threading.get_ident(),self.owner)
            def make_native(self,**unused):
                self.check()
                if self.index==0:
                    blocked.set()
                    if not release.wait(3):raise AssertionError('test did not release blocked owner')
                return bodies[self.index]
            def authorize(self,raw,opening):
                self.check()
                def rebuilt(header_bytes):
                    header=CBlockHeader();header.deserialize(BytesIO(header_bytes))
                    block=CBlock(header);block.vtx=parse_block(raw).vtx
                    return block.serialize()
                return SimpleNamespace(block_bytes=raw,snapshot_bytes=opening,block_for_header=rebuilt)
            def prepare_native_authorization(self,**options):
                block,snapshot=self.make_native(**options)
                return self.authorize(block.serialize(),snapshot.serialize())
            def ready_for_dispatch(self,unused):self.check();return True
            def ready_for_continued_work(self,unused):self.check();return True
            def register_snapshot(self,unused):self.check()
            def close(self):
                self.check();closed.append(self.index)
                if self.index==1:other_done.set()

        self_test=self
        harness.open=lambda name,signer,rpc:Gate(int(name.rsplit('-',1)[1]))
        proxy=SimpleNamespace(sendrawtransaction=lambda unused:None,getbestblockhash=lambda:'aa'*32)
        unspent=[(1,0,100000),(1,1,100000)]
        threads=[threading.Thread(target=harness.produce,args=(i,signers,unspent,b'\x51',b'\x51')) for i in range(2)]
        with patch('feature_sharepool_hash_live_capacity.rpc_url',return_value='unused'), \
                patch('feature_sharepool_hash_live_capacity.get_rpc_proxy',return_value=proxy):
            try:
                for thread in threads:thread.start()
                self.assertTrue(all(ready.wait(2) for ready in harness.source_ready))
                harness.begin.set()
                self.assertTrue(blocked.wait(2))
                self.assertTrue(other_done.wait(2))
                self.assertEqual(harness.worker_stats[1]['offered'],2)
                self.assertEqual(harness.worker_stats[0]['offered'],0)
                self.assertFalse(harness.finished.is_set())
            finally:
                release.set();harness.begin.set()
                for thread in threads:thread.join(3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertIsNone(harness.source_error)
        self.assertTrue(harness.finished.is_set())
        self.assertEqual(sorted(closed),[0,1])
        self.assertEqual(len(set(owners.values())),2)
        self.assertNotIn(threading.get_ident(),owners.values())
        self.assertEqual(len(harness.jobs),2)
        self.assertEqual(sorted(row['slot'] for row in harness.queue_transfers),[0,1,2,3])
        self.assertEqual(sum(row['full_origin'] for row in harness.queue_transfers),2)
        self.assertEqual([row['miner_indices'] for row in harness.worker_stats],[[0],[1]])


if __name__=='__main__':
    unittest.main()
