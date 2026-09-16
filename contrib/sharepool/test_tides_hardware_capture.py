#!/usr/bin/env python3
"""v6 harness tests and an optional real-node CPU/Sia preflight entry point."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from goldshell_test_guard import guarded_test
from hash_snapshot import HashSigner, Snapshot, job_hash
from native_enforcement import compute_xonly_pubkey, sign_schnorr
from native_hardware_capture import Request
from native_mining_gate import parse_block
from test_framework.messages import CBlockHeader, CTxOut, uint256_from_compact
from test_goldshell_test_guard import FakeBridge, ORIGINAL, TEST_POOL, identities
from test_hash_snapshot import SECRET, SCRIPT
from test_hash_tides import TidesRPC
from testnet_template import proof_from_sia, sia_notify
from tides_hardware_capture import TidesCaptureStore, TidesHardwareCapture
from verify_tides_hardware_capture import verify_capture


class CaptureRPC(TidesRPC):
    """Flow-control double, never evidence of native consensus validation."""
    def __init__(self):
        super().__init__()
        self.thread_ids = []

    def __call__(self, method, *args):
        self.thread_ids.append(threading.get_ident())
        if method == "getnetworkinfo":
            return {"networkactive": False, "connections": 0}
        if method == "preparesharepoolhashjob":
            base = super().__call__(method, *args)
            block, opening = parse_block(bytes.fromhex(base["template"])), Snapshot.deserialize(bytes.fromhex(base["snapshot"]))
            outputs = (CTxOut(5_000_000_000, opening.envelope.payout_script),)
            block.vtx[0].vout = list(outputs)
            block.vtx[0].rehash()
            block.hashMerkleRoot = block.calc_merkle_root()
            opening = replace(opening, payouts=outputs, job_commitment=job_hash(block))
            block.m_mm_rhs = opening.hash
            block.rehash()
            return self.response(block, opening, 5_000_000_000)
        if method == "finalizesharepoolhashjob":
            result = super().__call__(method, *args)
            result["reward"] = 5_000_000_000
            return result
        if method == "submitblock":
            block = parse_block(bytes.fromhex(args[0]))
            block.rehash()
            if f"{block.hashPrevBlock:064x}" != self.tip:
                raise ValueError("test block has wrong parent")
            self.headers[block.hash] = CBlockHeader(block).serialize().hex()
            self.tip, self.height = block.hash, block.m_height
            self.hashes[self.height] = self.tip
            return None
        if method == "verifychain":
            return True
        result = super().__call__(method, *args)
        if method == "getsharepoolhashstatus":
            result["activation_height"] = 1
        return result


def submission(active, *, prefix=b"\x01\x00\x00\x00", start=0):
    ntime, extra = sia_notify(active.template, prefix)[7], bytes(8)
    for nonce in range(start, start + 10_000):
        text = nonce.to_bytes(8, "little").hex()
        proof = proof_from_sia(active.template, prefix, extra, ntime, text)
        if proof.hash_int <= uint256_from_compact(active.template.header.nBits):
            return prefix, ["sharepool.hardware", active.template.job_id, extra.hex(), ntime, text], proof
    raise AssertionError("bounded CPU proof search exhausted")


def run_cpu_stratum(capture):
    """One loopback client exercises dispatch, two blocks and late old work."""
    failures, accepted = [], []
    capture.start()

    def miner():
        try:
            with socket.create_connection(capture.server.server_address, timeout=10) as connection:
                connection.settimeout(15)
                stream = connection.makefile("rwb")
                def send(identity, method, params):
                    stream.write(json.dumps({"id": identity, "method": method, "params": params}).encode() + b"\n")
                    stream.flush()
                send(1, "mining.subscribe", [])
                send(2, "mining.authorize", ["sharepool.hardware", "x"])
                prefix, first, first_nonce, pending_id = None, None, None, None
                for _ in range(40):
                    raw = stream.readline(8193)
                    if not raw or len(raw) > 8192:
                        raise AssertionError("bounded Sia response missing")
                    message = json.loads(raw)
                    if message.get("id") == 1:
                        prefix = bytes.fromhex(message["result"][1])
                    if message.get("id") == pending_id and pending_id is not None:
                        if message.get("result") is not True:
                            raise AssertionError("CPU Sia proof was rejected")
                        accepted.append(pending_id)
                        pending_id = None
                        if len(accepted) == 3:
                            capture.stop.set()
                            return
                        if len(accepted) == 1:
                            _, params, _ = submission(first, prefix=prefix, start=first_nonce + 1)
                            pending_id = 11
                            send(pending_id, "mining.submit", params)
                    if message.get("method") == "mining.notify" and pending_id is None:
                        with capture.lock:
                            active = capture.jobs[message["params"][0]]
                        if len(accepted) == 1:
                            continue
                        _, params, _ = submission(active, prefix=prefix)
                        if first is None:
                            first, first_nonce = active, int.from_bytes(bytes.fromhex(params[4]), "little")
                        pending_id = 10 if not accepted else 12
                        send(pending_id, "mining.submit", params)
                raise AssertionError("CPU Sia exchange exceeded its message bound")
        except BaseException as error:
            failures.append(type(error).__name__ + ": " + str(error))
            capture.stop.set()

    thread = threading.Thread(target=miner)
    thread.start()
    try:
        capture.run(30)
    finally:
        capture.stop.set()
        thread.join(16)
        if thread.is_alive():
            raise AssertionError("CPU Sia client failed to stop")
    if failures:
        raise AssertionError(failures[0])
    if len(accepted) != 3:
        raise AssertionError("CPU Sia capture did not finish three submissions")
    return capture.report()


def native_preflight(rpc, replay_rpc, signer_binary, directory):
    """Caller owns two fresh isolated v6 native nodes; no physical miner access.

    Actual native builder, signer, validation, payouts and independent replay
    run through the same adapter after a fake configuration-guard backup.
    """
    directory = Path(directory)
    signer_path = directory / "cpu-owner.key"
    signer = HashSigner.create(signer_binary, signer_path, pool=3, payout_script=SCRIPT)
    store = TidesCaptureStore(directory / "cpu-capture.sqlite")
    capture = None
    try:
        capture = TidesHardwareCapture(rpc, store, gate_path=directory / "cpu-gate.sqlite",
                                      bind=("127.0.0.1", 0), miner_ip="127.0.0.1", signer=signer)
        bridge = FakeBridge()
        result = guarded_test(bridge, test_pool=TEST_POOL, backup_path=directory / "fake-device-backup.json",
                              run_test=lambda: run_cpu_stratum(capture), before_restore=capture.stop.set)
        if not result.ok or identities(bridge.pools) != identities(ORIGINAL):
            raise AssertionError("CPU preflight or fake restoration guard failed")
        report = result.test_result
        verified = verify_capture(report, native_rpc=replay_rpc)
        if verified["blocks"] != 2 or report["stats"]["old_parent_shares"] != 1:
            raise AssertionError("native CPU preflight did not exercise late work and two payouts")
        (directory / "cpu-capture.json").write_text(json.dumps(report, indent=2) + "\n")
        return {"capture": verified, "fake_guard_restored": True, "physical_device_used": False}
    finally:
        if capture is not None:
            capture.close()
        store.close()
        signer_path.unlink(missing_ok=True)


class TidesHardwareTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.store = TidesCaptureStore(self.path / "capture.sqlite")
        self.addCleanup(self.store.close)
        self.rpc = CaptureRPC()
        self.signer = SimpleNamespace(pool=3, payout_script=SCRIPT, public_key=compute_xonly_pubkey(SECRET)[0],
                                      sign_owner=lambda opening: sign_schnorr(SECRET, opening.owner_message))
        self.capture = TidesHardwareCapture(self.rpc, self.store, gate_path=self.path / "gate.sqlite",
                                          bind=("127.0.0.1", 0), miner_ip="127.0.0.1", signer=self.signer)
        self.rpc.gate = self.capture.gate
        self.addCleanup(self.capture.close)

    def test_signed_native_job_full_snapshot_and_late_work_replay(self):
        first = self.capture.current
        prefix, params, proof = submission(first)
        self.capture._process_proof(prefix, params)
        start = int.from_bytes(bytes.fromhex(params[4]), "little") + 1
        prefix, params, late = submission(first, start=start)
        self.capture._process_proof(prefix, params)
        self.assertEqual(self.capture.stats["old_parent_shares"], 1)
        self.assertEqual(self.capture.last_tip, proof.display_hash)
        self.assertEqual({value.proof_id for value in self.capture.current.manifest.shares}, {proof.hash_int, late.hash_int})
        prefix, params, _ = submission(self.capture.current)
        self.capture._process_proof(prefix, params)
        report = self.capture.report()
        checked = verify_capture(report)
        self.assertEqual((checked["jobs"], checked["proofs"], checked["blocks"]), (4, 3, 2))
        self.assertFalse(checked["physical_provenance_verified"])
        self.assertEqual(set(self.rpc.thread_ids), {threading.get_ident()})
        damaged = json.loads(json.dumps(report))
        damaged["shares"][0]["native_expected_work"] += 1
        with self.assertRaisesRegex(ValueError, "work accounting"):
            verify_capture(damaged)

    def test_owner_thread_dispatch_and_bound_shutdown(self):
        result = []
        thread = threading.Thread(target=lambda: result.append(self.capture.prepare_dispatch(self.capture.current)))
        thread.start()
        request = self.capture.requests.get(timeout=2)
        self.assertFalse(request.done.is_set())
        self.capture._handle(request)
        thread.join(2)
        self.assertEqual(result, [True])
        with self.assertRaisesRegex(ValueError, "at most 90"):
            self.capture.run(91)
        requests = [Request("dispatch", self.capture.current) for _ in range(4)]
        for request in requests:
            self.capture.requests.put_nowait(request)
        self.capture.close()
        self.assertTrue(all(request.done.is_set() and request.error for request in requests))

    def test_archive_failure_after_receipt_never_acknowledges(self):
        prefix, params, _ = submission(self.capture.current)
        request = Request("submit", (prefix, params))
        with patch.object(self.store, "persist_native_proof", side_effect=OSError("test disk failure")):
            self.capture._handle(request)
        self.assertIsNotNone(request.error)
        self.assertTrue(self.capture.stop.is_set())
        self.assertEqual(self.capture.stats["durable_acknowledgments_ready"], 0)
        self.assertEqual(self.store.snapshot(), [])

    def test_native_refusal_after_archive_stops_without_ack(self):
        original = self.capture.rpc
        self.capture.rpc = lambda method, *args: "bad-test-block" if method == "submitblock" else original(method, *args)
        prefix, params, _ = submission(self.capture.current)
        request = Request("submit", (prefix, params))
        self.capture._handle(request)
        self.assertIsNotNone(request.error)
        self.assertTrue(self.capture.stop.is_set())
        self.assertEqual(self.capture.stats["durable_acknowledgments_ready"], 0)
        with self.assertRaises(ValueError):
            verify_capture(self.capture.report())


if __name__ == "__main__":
    unittest.main()
