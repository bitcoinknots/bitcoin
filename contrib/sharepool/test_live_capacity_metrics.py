#!/usr/bin/env python3
import unittest
from live_capacity_metrics import phase_counts


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


if __name__ == '__main__':
    unittest.main()
