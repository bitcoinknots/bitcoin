#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native CPU profile of construction, authorization and publication for one full job."""
from collections import Counter, defaultdict
from pathlib import Path
import cProfile
import hashlib
import io
import json
import pstats
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'test/functional'), str(REPO / 'contrib/sharepool')]
from feature_sharepool_hash_cadence_benchmark import SharePoolHashCadenceBenchmark
from capacity_metrics import Measurements


class ProfileJob(SharePoolHashCadenceBenchmark):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        assert 2 <= self.options.miners <= 100
        if self.options.results is None:
            self.options.results = Path(self.options.tmpdir) / 'job-profile.json'
        self.MINERS = self.options.miners
        self.directory = Path(self.options.tmpdir) / 'gates'
        self.directory.mkdir(mode=0o700)
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.started, self.phase = time.monotonic(), 'fixture'
        self.metrics, self.rpc_payload, self.keys = Measurements(), defaultdict(Counter), []
        self.rpc_encoding_cpu = Counter()
        names = ('hash_mining_gate.py', 'hash_snapshot.py', 'hash_gate_batch.py', 'hash_state_cache.py',
                 'hash_signature_cache.py', 'hash_gate_startup.py')
        self.report = {'result': 'running', 'rewards': [], 'source_sha256': {
            name: hashlib.sha256((REPO / 'contrib/sharepool' / name).read_bytes()).hexdigest() for name in names if (REPO / 'contrib/sharepool' / name).exists()},
            'native_binary_sha256': hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
            'command': [sys.executable, *sys.argv],
            'scope': 'Profiled final job with precomputed native origins; profiler overhead included; no sustained-capacity claim'}
        gate = None
        try:
            signer, proofs = self.prepare_fixture()
            gate = self.open_collector('per_ack', signer, 0)
            self.phase = 'receive'
            for proof in proofs:
                gate.receive(proof)
            self.phase = 'profile'
            profile = cProfile.Profile()
            self.log.info('Profiling final job with %d acknowledged proofs', len(proofs))
            timings = {}
            profile.enable()
            try:
                started = time.monotonic()
                block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
                timings['construct_wall_seconds'] = time.monotonic() - started
                started = time.monotonic()
                authorization = gate.authorize(block.serialize(), snapshot.serialize())
                timings['authorize_wall_seconds'] = time.monotonic() - started
                started = time.monotonic()
                assert gate.ready_for_dispatch(authorization)
                gate.register_snapshot(authorization.snapshot_bytes)
                assert gate.ready_for_continued_work(authorization)
                timings['publish_wall_seconds'] = time.monotonic() - started
            finally:
                profile.disable()
            assert {proof.proof_id for proof in snapshot.shares} == {proof.proof_id for proof in proofs}
            prefix = self.options.results
            profile.dump_stats(str(prefix) + '.pstats')
            output = io.StringIO()
            stats = pstats.Stats(profile, stream=output).strip_dirs().sort_stats('cumulative')
            stats.print_stats(60)
            Path(str(prefix) + '.txt').write_text(output.getvalue())
            self.report.update(result='passed', timings=timings, profile_seconds=stats.total_tt,
                state_cache=gate._compact_state_cache.stats(),
                signature_cache=gate._signature_cache.stats(), rpc=self.phase_payload('profile'))
        finally:
            if gate is not None:
                gate.close()
            for key in self.keys:
                key.unlink(missing_ok=True)
            self.report['wall_seconds'] = time.monotonic() - self.started
            self.save_report()


if __name__ == '__main__':
    ProfileJob(__file__).main()
