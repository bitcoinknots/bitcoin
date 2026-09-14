#!/usr/bin/env python3
import unittest
import threading
from capacity_metrics import Measurements
from live_capacity_metrics import merge_measurements, owner_slots, phase_counts


def event(stage, seconds, *ids):
    return dict(stage=stage, seconds=seconds, proof_ids=[f'{i:064x}' for i in ids])


class LiveCapacityMetricsTest(unittest.TestCase):
    def test_fixed_cutoff_excludes_drain_and_keeps_each_queue_separate(self):
        events = [event('offered', 1, 1, 2, 3, 4), event('acknowledged', 2, 1, 2, 3),
                  event('admitted', 3, 1, 2), event('peer_verified', 4, 1),
                  event('acknowledged', 11, 4), event('admitted', 12, 3, 4),
                  event('peer_verified', 13, 2, 3, 4)]
        phase = phase_counts(events, seconds=10)
        self.assertEqual([phase[k] for k in ['offered','acknowledged','admitted','peer_verified']], [4,3,2,1])
        self.assertEqual([phase[k] for k in ['unacknowledged_queue','acknowledged_backlog','peer_backlog']], [1,1,1])
        self.assertEqual(phase['observed_admitted_per_second'], .2)
        final = phase_counts(events, seconds=14)
        self.assertEqual(final['peer_verified'], 4)
        self.assertEqual(final['acknowledged_backlog'], 0)

    def test_rejection_is_not_durable_work_and_boundary_completion_counts(self):
        phase = phase_counts([event('offered',1,1),event('rejected',2,1)],seconds=2)
        self.assertEqual((phase['rejected'],phase['acknowledged'],phase['unacknowledged_queue']),(1,0,0))

    def test_invalid_accounting_is_rejected(self):
        for events in [[event('acknowledged',1,1)], [event('offered',1,1),event('offered',2,1)],
                       [event('offered',1,1),event('rejected',2,1),event('acknowledged',3,1)],
                       [event('offered',float('nan'),1)], [event('offered',1,1,1)]]:
            with self.subTest(events=events), self.assertRaises(ValueError): phase_counts(events,seconds=10)
        for seconds in [0,-1,float('inf'),float('nan'),True]:
            with self.assertRaises(ValueError):phase_counts([],seconds=seconds)

    def test_owner_partition_preserves_absolute_schedule_and_identity_affinity(self):
        for miners, planned, workers in [(100,1000,1),(100,1000,8),(100,2000,100),(7,19,3)]:
            with self.subTest(miners=miners,planned=planned,workers=workers):
                shards=[list(owner_slots(miners=miners,planned=planned,workers=workers,owner=i)) for i in range(workers)]
                self.assertEqual(sorted(slot for shard in shards for slot in shard),list(range(planned)))
                owners={}
                for owner,shard in enumerate(shards):
                    self.assertEqual(shard,sorted(shard))
                    for slot in shard:
                        miner=slot%miners
                        self.assertEqual(owners.setdefault(miner,owner),owner)
                self.assertEqual(len(owners),miners)
        for options in ({'workers':0},{'workers':101},{'owner':1},{'miners':True},{'planned':10001}):
            args=dict(miners=100,planned=1000,workers=1,owner=0);args.update(options)
            with self.assertRaises(ValueError):owner_slots(**args)

    def test_independent_owner_schedule_progresses_while_another_owner_is_blocked(self):
        blocked,release,progress=threading.Event(),threading.Event(),threading.Event()
        delivered=[]
        def run(owner):
            for slot in owner_slots(miners=2,planned=4,workers=2,owner=owner):
                if owner==0:
                    blocked.set()
                    release.wait()
                delivered.append((owner,slot))
                if owner==1:progress.set()
        first=threading.Thread(target=run,args=(0,));second=threading.Thread(target=run,args=(1,))
        first.start()
        try:
            self.assertTrue(blocked.wait(2))
            second.start()
            self.assertTrue(progress.wait(2))
            self.assertFalse(any(owner==0 for owner,slot in delivered))
        finally:
            release.set();first.join(2)
            if second.ident is not None:second.join(2)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(sorted(delivered),[(0,0),(0,2),(1,1),(1,3)])

    def test_merged_rpc_percentile_uses_actual_samples(self):
        first,second=Measurements(),Measurements()
        first.values['rpc.job']=[1.0]*99
        second.values['rpc.job']=[100.0]
        second.failures['rpc.job']=1
        result=merge_measurements([first,second])['rpc.job']
        self.assertEqual((result['count'],result['total_seconds'],result['p95_seconds'],result['failures']),(100,199.0,1.0,1))
        self.assertEqual(len(first.values['rpc.job']),99)

    def test_pre_dispatch_capacity_refusal_is_not_an_offer_or_ack(self):
        refused=dict(stage='capacity_refused',seconds=2,slot=1,miner=1,identity='ab'*32,reason='receipt pressure')
        offered=dict(event('offered',1,1),slot=0)
        counts=phase_counts([offered,refused],seconds=2)
        self.assertEqual((counts['offered'],counts['capacity_refused'],counts['acknowledged'],counts['rejected']),(1,1,0,0))
        self.assertEqual(phase_counts([refused],seconds=1)['capacity_refused'],0)
        for invalid in (dict(refused,proof_ids=[]),dict(refused,slot=True),dict(refused,identity='xx'*32)):
            with self.assertRaises(ValueError):phase_counts([invalid],seconds=3)
        for rows in ([refused,refused],[offered,dict(refused,slot=0)],
                [refused,dict(event('offered',3,2),slot=1)]):
            with self.assertRaises(ValueError):phase_counts(rows,seconds=3)

    def test_valid_offered_work_refused_for_capacity_never_becomes_ack_or_invalid(self):
        rows=[event('offered',1,1,2),event('acknowledged',2,1),event('admission_refused',3,2),
              event('admitted',4,1),event('peer_verified',5,1)]
        counts=phase_counts(rows,seconds=5)
        self.assertEqual([counts[k] for k in ['offered','acknowledged','admission_refused','rejected','admitted']],[2,1,1,0,1])
        self.assertEqual(counts['unacknowledged_queue'],0)
        self.assertEqual(phase_counts(rows,seconds=2)['unacknowledged_queue'],1)
        for later in (event('acknowledged',6,2),event('rejected',6,2),event('admission_refused',6,1)):
            with self.assertRaises(ValueError):phase_counts(rows+[later],seconds=6)


if __name__ == '__main__':
    unittest.main()
