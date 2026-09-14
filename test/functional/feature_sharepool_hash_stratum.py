#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real loopback Sia transport, v7 native payouts and independent tip withdrawal.

Synthetic work only; this does not connect to or configure a physical miner.
"""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, solve_share
from hash_stratum import HashStratumService
from native_mining_gate import parse_block
from testnet_template import proof_from_sia, sia_notify
from feature_sharepool_hash_datum_cadence import Clock, SharePoolHashDatumCadenceTest
from test_framework.address import script_to_p2wsh
from test_framework.messages import uint256_from_compact
from test_framework.script import CScript, OP_TRUE
from test_framework.util import assert_equal, get_rpc_proxy


class Client:
    def __init__(self, address):
        self.socket = socket.create_connection(address, timeout=5)
        self.socket.settimeout(5)
        self.pending = b""
        self.send(1, "mining.subscribe", [])
        self.send(2, "mining.authorize", ["sharepool.regtest", ""])
        self.prefix = None

    def send(self, identity, method, params):
        self.socket.sendall(json.dumps({"id": identity, "method": method, "params": params}).encode() + b"\n")

    def read(self):
        while b"\n" not in self.pending:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise EOFError("transport withdrawn")
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        result = json.loads(line)
        if result.get("id") == 1:
            self.prefix = bytes.fromhex(result["result"][1])
        return result

    def notify(self):
        while True:
            message = self.read()
            if message.get("method") == "mining.notify":
                assert self.prefix is not None
                return message["params"]

    def close(self):
        self.socket.close()


class SharePoolHashStratumTest(SharePoolHashDatumCadenceTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        directory = Path(self.options.tmpdir)
        keys = [directory / f"stratum-owner-{i}.key" for i in range(2)]
        service = gate = client = None
        report = {"network": "isolated regtest", "profile": "hash-only-v7-compact-tides",
                  "transport": "loopback Sia Stratum with synthetic nonce search",
                  "hardware_used": False}
        try:
            self.generatetoaddress(node, 101, script_to_p2wsh(CScript([OP_TRUE])))
            signers = [HashSigner.create(self.signer_binary, key, pool=101,
                payout_script=b"\x00\x14" + bytes([i + 1]) * 20) for i, key in enumerate(keys)]
            owner_calls = []
            owner = threading.get_ident()

            def rpc(method, *args):
                assert_equal(threading.get_ident(), owner)
                owner_calls.append(method)
                return getattr(node, method)(*args)

            gate = HashMiningGate(directory / "stratum-gate.sqlite", rpc=rpc,
                pool=101, public_key=signers[0].public_key, payout_script=signers[0].payout_script,
                profile_version=7, activation_height=102)
            for signer in signers:
                block, snapshot, proof = self.origin(0, signer)
                gate.register_snapshot(snapshot.serialize())
                gate.register_template(block.serialize())
                assert gate.receive(proof)
            observer = get_rpc_proxy(node.url, 40, timeout=1)
            clock = Clock()
            signing = {"hold": False}
            entered, released = threading.Event(), threading.Event()

            def sign(snapshot):
                if signing["hold"]:
                    entered.set()
                    assert released.wait(5), "test did not release held owner construction"
                return signers[0].sign_owner(snapshot)

            observer_pause = threading.Event()
            observer_entered, observer_released = threading.Event(), threading.Event()

            def observe(method, *args):
                if observer_pause.is_set():
                    observer_entered.set()
                    assert observer_released.wait(5)
                return getattr(observer, method)(*args)

            service = HashStratumService(gate, sign_owner=sign, observer_rpc=observe,
                observe_seconds=0.05, observation_timeout=1, clock=clock)
            service.start()
            service.service_once()
            assert_equal(service.stats["published"], 1)
            assert_equal(self.payouts(parse_block(service.current.authorization.block_bytes)),
                         {signer.payout_script: 2_500_000_000 for signer in signers})
            original = service.current
            results, failures = {}, []
            acknowledged = threading.Event()

            def mine():
                nonlocal client
                try:
                    client = Client(service.address)
                    notify = client.notify()
                    assert_equal(notify[0], original.template.job_id)
                    for invalid in (["sharepool.regtest"],
                                    ["sharepool.regtest", "f" * 64, bytes(8).hex(), notify[7], bytes(8).hex()]):
                        attacker = Client(service.address)
                        try:
                            assert_equal(attacker.notify()[0], original.template.job_id)
                            attacker.send(90, "mining.submit", invalid)
                            try:
                                attacker.read()
                                raise AssertionError("invalid submission unexpectedly accepted")
                            except EOFError:
                                pass
                        finally:
                            attacker.close()
                        assert service.current is original
                        assert_equal(service.stats["published"], 1)
                    results["invalid_client_isolated"] = True
                    # Find an actual native share that is not a native block.
                    target = uint256_from_compact(original.template.header.nBits)
                    for nonce in range(10000):
                        encoded = nonce.to_bytes(8, "little").hex()
                        proof = proof_from_sia(original.template, client.prefix, bytes(8), notify[7], encoded)
                        if target < proof.hash_int <= original.target:
                            break
                    else:
                        raise AssertionError("failed bounded non-block share search")
                    client.send(3, "mining.submit", ["sharepool.regtest", notify[0], bytes(8).hex(), notify[7], encoded])
                    while True:
                        response = client.read()
                        if response.get("id") == 3:
                            assert_equal(response["result"], True)
                            break
                    results["proof"] = proof.display_hash
                    newcomer = Client(service.address)
                    newcomer.socket.settimeout(0.3)
                    try:
                        newcomer.notify()
                        raise AssertionError("new client received a stale ACK-prefix job")
                    except socket.timeout:
                        results["new_client_stale_dispatch_refused"] = True
                    finally:
                        newcomer.close()
                    acknowledged.set()
                    next_job = client.notify()
                    current = service.current
                    assert_equal(next_job[0], current.template.job_id)
                    for nonce in range(10000):
                        encoded = nonce.to_bytes(8, "little").hex()
                        proof = proof_from_sia(current.template, client.prefix, bytes(8), next_job[7], encoded)
                        if proof.hash_int <= uint256_from_compact(current.template.header.nBits):
                            break
                    else:
                        raise AssertionError("failed bounded native block search")
                    results["block"] = proof.display_hash
                    results["block_bytes"] = proof.block
                    results["payouts"] = self.payouts(parse_block(proof.block))
                    client.send(4, "mining.submit", ["sharepool.regtest", next_job[0], bytes(8).hex(), next_job[7], encoded])
                    # The new native tip can close the socket before a response;
                    # loss of the response cannot revoke the journaled proof.
                    try:
                        while client.read().get("id") != 4:
                            pass
                    except EOFError:
                        pass
                except BaseException as error:
                    failures.append(error)

            miner = threading.Thread(target=mine)
            miner.start()

            def pump(condition, seconds=10):
                deadline = time.monotonic() + seconds
                while not condition():
                    if failures:
                        raise failures[0]
                    if time.monotonic() >= deadline:
                        raise AssertionError("owner/transport test deadline exceeded")
                    service.service_once()
                    time.sleep(0.01)

            pump(acknowledged.is_set)
            assert_equal(service.stats["published"], 1)
            assert_equal(service.stats["acknowledged"], 1)
            assert_equal(gate.ready_for_dispatch(original.authorization), False)
            assert_equal(gate.ready_for_continued_work(original.authorization), True)
            clock.now = 40
            pump(lambda: not miner.is_alive())
            miner.join(timeout=1)
            if failures:
                raise failures[0]
            assert_equal(node.getbestblockhash(), results["block"])
            assert_equal(bytes.fromhex(node.getblock(results["block"], 0)), results["block_bytes"])
            assert_equal(results["payouts"], {signers[0].payout_script: 3_333_333_333,
                                             signers[1].payout_script: 1_666_666_666})
            assert node.verifychain(4, 0)
            assert_equal(service.stats["acknowledged"], 2)
            report["pipeline"] = {"proof_acknowledged": results["proof"], "accepted_block": results["block"],
                "exact_native_block_bytes": True, "direct_payouts_verified": True,
                "share_did_not_force_refresh": True, "full_snapshot_published": True,
                "new_client_stale_dispatch_refused": results["new_client_stale_dispatch_refused"],
                "invalid_client_did_not_retire_healthy_work": results["invalid_client_isolated"],
                "all_gate_rpc_calls_on_owner_thread": True}

            # Recover a new native job, then hold the owner inside signing while
            # another independent RPC connection invalidates the current tip.
            pump(lambda: service.current is not None and service.current.authorization.native_parent == results["block"])
            client.close()
            client = socket.create_connection(service.address, timeout=2)
            client.settimeout(3)
            observer_change = get_rpc_proxy(node.url, 41, timeout=1)
            signing["hold"] = True
            clock.now = service.scheduler.next_refresh_at
            measured = {}

            def change_tip():
                try:
                    assert entered.wait(3)
                    started = time.monotonic()
                    observer_change.invalidateblock(results["block"])
                    assert_equal(client.recv(1), b"")
                    measured["disconnect_seconds"] = time.monotonic() - started
                    assert measured["disconnect_seconds"] < 2
                    assert not released.is_set()
                except BaseException as error:
                    failures.append(error)
                finally:
                    released.set()

            changer = threading.Thread(target=change_tip)
            changer.start()
            try:
                service.service_once()
                raise AssertionError("changed native parent unexpectedly published")
            except ValueError:
                pass
            changer.join(timeout=5)
            if failures:
                raise failures[0]
            assert measured and entered.is_set()
            assert service.current is None
            report["blocked_owner_tip_change"] = {**measured,
                "withdrawal_before_owner_release": True, "stale_job_not_published": True,
                "construction_cancelled": False}
            signing["hold"] = False
            pump(lambda: service.current is not None)
            assert_equal(service.current.authorization.native_parent, node.getbestblockhash())
            report["fresh_context_recovered"] = True
            client.close()
            # Deterministically pause the socket after successful owner handoff.
            # A later ACK cannot rewrite that issued cutoff; a later approval of
            # the same old job must fail even though the first notify may follow.
            held, handoff_release = threading.Event(), threading.Event()
            original_enqueue = service._enqueue
            issued = service.current
            frozen = issued.authorization.block_bytes, issued.authorization.snapshot_bytes

            def pause_approved_handoff(kind, payload):
                result = original_enqueue(kind, payload)
                if kind == "dispatch" and result and not held.is_set():
                    held.set()
                    assert handoff_release.wait(5)
                return result

            service._enqueue = pause_approved_handoff
            race = {}

            def race_client():
                first = later = None
                try:
                    first = Client(service.address)
                    notification = first.notify()
                    assert_equal(notification, sia_notify(issued.template, first.prefix, clean=True))
                    race["issued_notify_received"] = True
                    later = Client(service.address)
                    later.socket.settimeout(0.3)
                    try:
                        later.notify()
                        raise AssertionError("a subsequent approval ignored the later ACK")
                    except socket.timeout:
                        race["subsequent_approval_refused"] = True
                except BaseException as error:
                    failures.append(error)
                finally:
                    if first is not None:
                        first.close()
                    if later is not None:
                        later.close()

            racing_client = threading.Thread(target=race_client)
            racing_client.start()
            pump(held.is_set)
            assert gate.receive(solve_share(parse_block(issued.authorization.block_bytes), issued.snapshot, start_nonce=100000))
            assert_equal(gate.ready_for_dispatch(issued.authorization), False)
            assert_equal(gate.ready_for_continued_work(issued.authorization), True)
            assert_equal((issued.authorization.block_bytes, issued.authorization.snapshot_bytes), frozen)
            handoff_release.set()
            pump(lambda: not racing_client.is_alive())
            racing_client.join(timeout=1)
            if failures:
                raise failures[0]
            assert_equal(race, {"issued_notify_received": True, "subsequent_approval_refused": True})
            service._enqueue = original_enqueue
            report["post_handoff_ack_before_socket_write"] = {**race,
                "exact_issued_bytes_unchanged": True, "continued_native_context_valid": True,
                "linearization_point": "successful owner approval before the later ACK"}
            client = socket.create_connection(service.address, timeout=2)
            client.settimeout(3)
            until = time.monotonic() + 2
            while not service.latch.sockets:
                assert time.monotonic() < until
                time.sleep(0.01)
            observer_pause.set()
            assert observer_entered.wait(2)
            started = time.monotonic()
            assert_equal(client.recv(1), b"")
            watchdog_elapsed = time.monotonic() - started
            assert watchdog_elapsed < 2
            assert not observer_released.is_set()
            report["blocked_observer_watchdog"] = {"disconnect_seconds": watchdog_elapsed,
                "observation_timeout_seconds": 1, "owner_service_not_required": True,
                "observer_still_blocked_at_withdrawal": True}
            observer_pause.clear()
            observer_released.set()
            report["stats"] = dict(service.stats)
            service.close()
            service = None
            command = [sys.executable, "-B", str(Path(__file__).resolve().parents[2] / "contrib/sharepool/hash_stratum_runner.py"),
                "--bitcoin-cli", str(Path(self.options.bitcoind).with_name("bitcoin-cli")),
                "--datadir", str(node.datadir_path), "--signer-binary", str(self.signer_binary),
                "--signer-key", str(keys[0]), "--gate", str(directory / "standalone-stratum.sqlite"),
                "--pool", "65", "--payout-script", signers[0].payout_script.hex(), "--seconds", "1"]
            standalone = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
            assert standalone.returncode == 0, standalone.stderr
            output = [json.loads(line) for line in standalone.stdout.splitlines()]
            assert_equal(output[0]["address"][0], "127.0.0.1")
            assert_equal(output[0]["hardware_configured"], False)
            assert_equal(output[1]["stats"]["published"], 1)
            report["standalone_runner"] = {"exit_code": 0, "v7_job_published": True,
                "loopback_listener": True, "duration_limit_seconds": 1}
            report["source_sha256"] = {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                for name in ("contrib/sharepool/hash_stratum.py", "contrib/sharepool/hash_job_scheduler.py",
                             "contrib/sharepool/hash_stratum_runner.py",
                             "test/functional/feature_sharepool_hash_stratum.py")}
            (directory / "stratum-v7-results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        finally:
            if client is not None:
                client.close()
            if service is not None:
                service.close()
            if gate is not None:
                gate.close()
            for key in keys:
                key.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashStratumTest(__file__).main()
