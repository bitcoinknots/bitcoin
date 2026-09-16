#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Opt-in recovery replay of a stopped native capacity capture.

This test requires --source-dir and intentionally is not a routine test-runner
fixture. It copies existing public evidence, checks P2P recovery, and replays
already acknowledged real proofs through normal native validation. It does not
generate another100 mining jobs or measure fresh throughput.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import hashlib
from io import BytesIO
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate, PROOF, SNAPSHOT, TEMPLATE
from hash_snapshot import HashSigner, Snapshot, TIDES_RULES_HASH, TIDES_VERSION, parse_share
from native_mining_gate import template_id
from feature_sharepool_hash_tides_100_miners import SharePoolHashTides100MinersTest
from test_framework.messages import CBlock, CBlockHeader, from_hex
from test_framework.util import assert_equal, util_xor


class SharePoolHashCapacityReplayTest(SharePoolHashTides100MinersTest):
    def set_test_params(self):
        super().set_test_params()
        for args in self.extra_args:
            args.append("-acceptnonstdtxn=1")  # Same captured witness relay policy.

    def add_options(self, parser):
        parser.add_argument("--source-dir", type=Path, required=True,
                            help="Stopped heavy shared100 capacity capture; never modified")
        parser.add_argument("--results", type=Path)
        parser.add_argument("--max-runtime-seconds", type=int, default=900)

    @staticmethod
    def file_digest(path):
        value = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(chunk)
        return value.hexdigest()

    def setup_chain(self):
        super().setup_chain()
        source = self.options.source_dir.resolve(strict=True)
        destination = Path(self.options.tmpdir).resolve()
        assert source != destination and source not in destination.parents
        self.capture = source
        self.source_manifest = {}
        self.source_paths = []
        with ExitStack() as locks:
            # Read locks conflict with the original daemon's exclusive fcntl
            # locks. Hold them while copying so the captured nodes cannot start.
            for index in range(2):
                chain = source / f"node{index}" / "regtest"
                handle = locks.enter_context((chain / ".lock").open("rb"))
                fcntl.lockf(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
            original = source / "capacity-gates" / "collector.sqlite"
            handle = locks.enter_context(Path(str(original) + ".owner.lock").open("rb"))
            fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
            wal = Path(str(original) + "-wal")
            assert not wal.exists() or wal.stat().st_size == 0, "capture must be stopped/checkpointed"
            with sqlite3.connect(original.as_uri() + "?mode=ro&immutable=1", uri=True) as database:
                self.source_config = json.loads(database.execute("SELECT value FROM config").fetchone()[0])
                assert_equal(database.execute("SELECT count(*) FROM segments").fetchone()[0], 0)
                assert_equal(database.execute("SELECT count(*) FROM journal WHERE kind=2").fetchone()[0], 300)
            # The profile marker intentionally binds the absolute blocks path.
            # Rebuild fresh native state from public records instead of changing
            # that marker or pointing a daemon at the original block directory.
            block_directory = source / "node0" / "regtest" / "blocks"
            files = sorted(block_directory.glob("blk*.dat"))
            assert 1 <= len(files) <= 4
            assert sum(path.stat().st_size for path in files) <= 128 * 1024 * 1024
            public_blocks = destination / "capture-blocks"
            public_blocks.mkdir(mode=0o700)
            for path in [*files, block_directory / "xor.dat"]:
                assert path.is_file() and not path.is_symlink()
                shutil.copy2(path, public_blocks / path.name)
                self.source_paths.append(path)
            self.copied_gate = destination / "capture-gate"
            self.copied_gate.mkdir(mode=0o700)
            for suffix in ("", ".archive-head.json"):
                path = Path(str(original) + suffix)
                shutil.copy2(path, self.copied_gate / ("collector.sqlite" + suffix))
                self.source_paths.append(path)
            self.source_manifest = {str(path.relative_to(source)): self.file_digest(path)
                                    for path in self.source_paths}
        key = (public_blocks / "xor.dat").read_bytes()
        assert_equal(len(key), 8)
        self.captured_blocks = []
        for path in sorted(public_blocks.glob("blk*.dat")):
            with path.open("rb") as stream:
                while True:
                    position = stream.tell()
                    encoded = stream.read(8)
                    if encoded in (b"", bytes(8)):
                        break  # Unwritten/preallocated block-file tail.
                    frame = util_xor(encoded, key, offset=position)
                    assert_equal(frame[:4], bytes.fromhex("fabfb5da"))
                    size = struct.unpack("<I", frame[4:])[0]
                    assert 80 <= size <= 4_000_000
                    raw = util_xor(stream.read(size), key, offset=position + 8)
                    assert_equal(len(raw), size)
                    block = CBlock()
                    block.deserialize(BytesIO(raw))
                    assert_equal(block.serialize(), raw)
                    block.rehash()
                    assert len(self.captured_blocks) < 103
                    if self.captured_blocks:
                        assert_equal(block.hashPrevBlock, self.captured_blocks[-1][0].sha256)
                        assert_equal(block.m_height, len(self.captured_blocks))
                    self.captured_blocks.append((block, raw))
        assert_equal(len(self.captured_blocks), 103)
        assert_equal(self.captured_blocks[0][0].hash, self.source_config["genesis"])
        assert_equal(self.captured_blocks[-1][0].hash, "170a0bc93b3d1bd269bd2fee8ac46062ec1025458514ea04e680e58eab9df303")
        self.log.info("Copied and checked exact genesis-through102 native records and300 sealed public receipts")

    def bounded(self):
        assert time.monotonic() - self.started <= self.options.max_runtime_seconds, "replay runtime bound exceeded"

    def canonical_snapshot(self, node, height):
        block = from_hex(CBlock(), node.getblock(node.getblockhash(height), 0))
        block.rehash()
        item = node.getsharepoolhashsnapshot(f"{block.m_mm_rhs:064x}")
        snapshot = Snapshot.deserialize(bytes.fromhex(item["data"]))
        assert_equal(snapshot.hash, block.m_mm_rhs)
        assert_equal(snapshot.hash_hex, item["hash"])
        return block, snapshot

    def run_test(self):
        assert 120 <= self.options.max_runtime_seconds <= 1800
        if self.options.results is None:
            self.options.results = Path(self.options.tmpdir) / "capacity-replay-results.json"
        self.started = time.monotonic()
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        config = self.source_config
        assert_equal(config["profile"], "hash-only-v6-tides")
        assert_equal(config["rules"], f"{TIDES_RULES_HASH:064x}")
        assert_equal(config["pool"], f"{0xCA9AC17:064x}")
        assert_equal(config["snapshot_budget"], 3593859)
        assert_equal([peer.getblockcount() for peer in self.nodes], [0, 0])
        self.report = {"schema": 1, "kind": "Captured native heavy-pipeline recovery/replay; not a fresh capacity benchmark",
            "result": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
            "source_dir": str(self.capture), "source_files_sha256": self.source_manifest,
            "command": [sys.executable, *sys.argv], "rewards": [],
            "native_binary_sha256": self.file_digest(Path(self.options.bitcoind)),
            "signer_binary_sha256": self.file_digest(self.signer_binary),
            "harness_sha256": self.file_digest(Path(__file__)),
            "source_initial_heights": [102, 101], "fresh_replay_initial_heights": [0, 0], "captured_acknowledgements": 300,
            "snapshot_budget_bytes": config["snapshot_budget"], "rules_hash": config["rules"],
            "original_signing_keys_used": False, "physical_miners_used": 0,
            "limitations": ["Fresh nodes revalidate captured public blocks and existing acknowledged proof bytes; no profile marker is rewritten",
                "Two loopback native nodes; no new100-job run, WAN throughput, production difficulty or mainnet claim",
                "Replay timings include native cache warming and historical revalidation and are not throughput estimates",
                "All newly dispatched work requires a fresh external signature and gate authorization",
                "Original source capture and its acknowledged proof/recipient identities remain unchanged"]}
        original_gate = replay_gate = signer = None
        key_path = Path(self.options.tmpdir) / "replay-owner.key"
        try:
            self.save_report()
            self.log.info("Fresh native nodes revalidate the captured101-block ancestry")
            for block, raw in self.captured_blocks[1:102]:
                self.bounded()
                for peer in self.nodes:
                    assert_equal(peer.submitblock(raw.hex()), None)
                    assert_equal(peer.getbestblockhash(), block.hash)
            call = lambda method, *args: getattr(node, method)(*args)
            original_gate = HashMiningGate(self.copied_gate / "collector.sqlite", rpc=call,
                pool=int(config["pool"], 16), public_key=bytes.fromhex(config["public_key"]),
                payout_script=bytes.fromhex(config["script"]), profile_version=TIDES_VERSION,
                activation_height=102, snapshot_budget=config["snapshot_budget"])
            for identity, in original_gate.db.execute("SELECT identity FROM journal WHERE kind=? ORDER BY sequence", (SNAPSHOT,)):
                self.bounded()
                raw = original_gate._read(SNAPSHOT, identity)
                assert_equal(node.submitsharepoolhashsnapshot(raw.hex())["hash"], identity)
            block, raw = self.captured_blocks[102]
            assert_equal(node.submitblock(raw.hex()), None)
            assert_equal(node.getbestblockhash(), block.hash)
            assert_equal(follower.getblockcount(), 101)
            self.report["captured_blocks_freshly_revalidated_on_producer"] = 102
            initial_block, initial_snapshot = self.canonical_snapshot(node, 102)
            assert_equal(len(initial_snapshot.shares), 201)
            self.report.update(initial_block=initial_block.hash,
                               initial_snapshot=initial_snapshot.hash_hex, original_admitted=201)
            started = time.monotonic()
            self.connect_nodes(0, 1)
            self.wait_tip(initial_block)  # Existing helper has a120-second bound.
            self.report["initial_p2p_convergence_seconds"] = time.monotonic() - started
            assert self.report["initial_p2p_convergence_seconds"] <= 120
            _, imported = self.canonical_snapshot(follower, 102)
            assert_equal(imported.serialize(), initial_snapshot.serialize())
            self.report["initial_p2p_exact_snapshot_converged"] = True
            self.save_report()
            self.log.info("Follower recovered the captured201-proof block; authenticating original300 receipt order")

            assert_equal(original_gate.archive_head()["receipt_revision"], 300)
            rows = original_gate.db.execute("SELECT identity,revision FROM journal WHERE kind=? ORDER BY revision", (PROOF,)).fetchall()
            assert_equal([revision for _identity, revision in rows], list(range(1, 301)))
            proofs = [parse_share(original_gate._read(PROOF, identity)) for identity, _revision in rows]
            all_ids = {proof.proof_id for proof in proofs}
            assert_equal(len(all_ids), 300)
            assert_equal({proof.envelope.pool for proof in proofs}, {int(config["pool"], 16)})
            assert_equal(len({proof.envelope.payout_script for proof in proofs}), 100)
            admitted = {proof.proof_id for proof in initial_snapshot.shares}
            assert_equal(admitted, {proof.proof_id for proof in proofs[:201]})
            remaining = [proof for proof in proofs if proof.proof_id not in admitted]
            assert_equal(len(remaining), 99)
            history = [(102, proof) for proof in initial_snapshot.shares]
            self.check_payouts(initial_block, initial_snapshot, history, reward=5_001_220_000)
            self.report["original_proof_id_set_sha256"] = hashlib.sha256(
                b"".join(identity.to_bytes(32, "big") for identity in sorted(all_ids))).hexdigest()
            self.report["original_unadmitted_receipts"] = len(remaining)

            signer = HashSigner.create(self.signer_binary, key_path, pool=int(config["pool"], 16),
                                       payout_script=bytes.fromhex(config["script"]))
            replay_gate = HashMiningGate(Path(self.options.tmpdir) / "replay.sqlite", rpc=call,
                pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
                profile_version=TIDES_VERSION, activation_height=102, snapshot_budget=config["snapshot_budget"])
            self.report["fresh_job_public_key"] = signer.public_key.hex()
            assert signer.public_key.hex() != config["public_key"]
            registered = set()
            for number, proof in enumerate(remaining, 1):
                self.bounded()
                identity = template_id(proof.header)
                if identity not in registered:
                    replay_gate.register_snapshot(original_gate._read(SNAPSHOT, f"{proof.header.m_mm_rhs:064x}"))
                    replay_gate.register_template(original_gate._read(TEMPLATE, identity))
                    registered.add(identity)
                replay_gate.receive(proof)
                self.report["replayed_receipts"] = number
                if number % 25 == 0 or number == len(remaining):
                    self.log.info("Native replay verified%d/%d original receipts", number, len(remaining))
                    self.save_report()
            assert_equal(replay_gate.archive_head()["receipt_revision"], 99)
            self.report["registered_remaining_origins"] = len(registered)
            batch = replay_gate.batch_status()
            assert_equal(batch["eligible_count"], 99)
            assert_equal(set(batch["selected_proofs"]), {f"{proof.proof_id:064x}" for proof in remaining})
            assert_equal(batch["deferred_count"], 0)
            self.bounded()
            block, snapshot, authorization = self.admitted_job(replay_gate, signer)
            assert_equal(block.m_height, 103)
            assert_equal({proof.proof_id for proof in snapshot.shares}, all_ids - admitted)
            history.extend((103, proof) for proof in snapshot.shares)
            self.check_payouts(block, snapshot, history, reward=5_000_000_000)
            block.solve()
            assert_equal(authorization.block_for_header(CBlockHeader(block).serialize()), block.serialize())
            assert_equal(node.submitblock(block.serialize().hex()), None)
            self.wait_tip(block)
            final_ids = []
            for peer in self.nodes:
                identities = set()
                for height in (102, 103):
                    _, committed = self.canonical_snapshot(peer, height)
                    new_ids = {proof.proof_id for proof in committed.shares}
                    assert not identities.intersection(new_ids)
                    identities.update(new_ids)
                assert_equal(identities, all_ids)
                final_ids.append(len(identities))
            assert_equal(replay_gate.batch_status()["eligible_count"], 0)
            assert_equal(original_gate.batch_status()["eligible_count"], 0)
            states = replay_gate.receipt_status(limit=128)
            assert not states["history_limited"]
            assert_equal(len(states["receipts"]), 99)
            assert all(receipt["status"] == "confirmed_admitted" for receipt in states["receipts"])
            self.report.update(result="passed", final_tip=block.hash, final_height=103,
                final_snapshot=snapshot.hash_hex, admitted_original_ids_per_node=final_ids,
                eligible_backlog=0, replay_receipts_confirmed_admitted=99,
                original_receipt_order_preserved=True, original_pool_and_recipient_bytes_preserved=True)
        except BaseException as error:
            self.report.update(result="failed", error=str(error))
            raise
        finally:
            for gate in (replay_gate, original_gate):
                if gate is not None:
                    gate.close()
            key_path.unlink(missing_ok=True)
            if self.report["result"] == "failed":
                self.stop_nodes()  # Only these disposable copies, never capture processes.
            current = {str(path.relative_to(self.capture)): self.file_digest(path) for path in self.source_paths}
            self.report["original_capture_unchanged"] = current == self.source_manifest
            self.report["seconds"] = time.monotonic() - self.started
            self.save_report()
            assert_equal(current, self.source_manifest)


if __name__ == "__main__":
    SharePoolHashCapacityReplayTest(__file__).main()
