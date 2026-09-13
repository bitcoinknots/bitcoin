#!/usr/bin/env python3
"""Profile 20 gate arrivals over 100 prior proofs using an RPC test double.

Run from a checkout with --output-prefix /tmp/gate-profile. Fixture creation is
excluded. This measures Python work, not native consensus or P2P throughput.
"""
from collections import Counter
from pathlib import Path
import argparse
import cProfile
import hashlib
import io
import json
import pstats
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "contrib/sharepool"), str(REPO / "test/functional")]
from hash_mining_gate import HashMiningGate
from hash_snapshot import solve_share
from test_hash_compact import CompactRPC, compact_fixture
from test_hash_snapshot import SCRIPT


def proofs(block, snapshot, count):
    result, nonce = [], 0
    for _ in range(count):
        proof = solve_share(block, snapshot, start_nonce=nonce)
        nonce = proof.header.nNonce + 1
        result.append(proof)
    return result


def benchmark(prefix):
    rpc = CompactRPC()
    old, old_open = compact_fixture()
    prior = proofs(old, old_open, 100)
    settlement, history = compact_fixture(templates=(old,), shares=prior, ntime=1700000020)
    rpc.snapshots[old_open.hash_hex] = old_open.serialize().hex()
    rpc.publish(settlement, history)
    origin, opening = compact_fixture(native_parent=int(rpc.tip, 16), height=2,
        parent_snapshot=history, ntime=1700000030)
    incoming = proofs(origin, opening, 20)
    with tempfile.TemporaryDirectory(prefix="sharepool-gate-profile-") as directory:
        gate = HashMiningGate(Path(directory) / "gate.sqlite", rpc=rpc, pool=3,
            public_key=opening.envelope.public_key, payout_script=SCRIPT, profile_version=7)
        rpc.gate = gate
        try:
            gate.register_snapshot(opening.serialize())
            gate.register_template(origin.serialize())
            rpc.calls.clear()
            profile = cProfile.Profile()
            profile.enable()
            try:
                for proof in incoming:
                    assert gate.receive(proof)
            finally:
                profile.disable()
        finally:
            gate.close()
    profile.dump_stats(str(prefix) + ".pstats")
    stream = io.StringIO()
    stats = pstats.Stats(profile, stream=stream).strip_dirs().sort_stats("cumulative")
    stats.print_stats(45)
    Path(str(prefix) + ".txt").write_text(stream.getvalue())
    sources = ("hash_mining_gate.py", "hash_gate_inventory.py", "hash_gate_batch.py",
               "hash_snapshot.py", "hash_gate_cache.py", "hash_state_cache.py", "hash_gate_rpc.py")
    report = {"scope": "Python gate synthetic fixtures with RPC double; no native performance claim",
        "history_proofs": 100, "new_proofs": 20, "unique_incoming_origins": 1,
        "source_sha256": {name: hashlib.sha256((REPO / "contrib/sharepool" / name).read_bytes()).hexdigest()
                          for name in sources if (REPO / "contrib/sharepool" / name).exists()},
        "rpc_calls": dict(Counter(name for name, args in rpc.calls)),
        "profile_total_seconds": stats.total_tt}
    Path(str(prefix) + ".json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-prefix", type=Path, required=True)
    print(json.dumps(benchmark(parser.parse_args().output_prefix), indent=2))
