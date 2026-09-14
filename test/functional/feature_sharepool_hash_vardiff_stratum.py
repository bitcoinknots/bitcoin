#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Two independent v8 gateway listeners, real Sia work and native-only winners.

Synthetic isolated regtest correctness fixture. The controller clock is injected;
these nonce searches do not measure physical hashrate or production throughput.
"""
import hashlib
import json
import math
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, share_target, solve_share
from hash_stratum import VardiffStratumService
from hash_vardiff import VardiffController
from native_mining_gate import parse_block
from testnet_template import proof_from_sia
from feature_sharepool_hash_datum_cadence import Clock
from feature_sharepool_hash_stratum import Client
from feature_sharepool_hash_vardiff import SharePoolHashVardiffTest
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


class VardiffClient(Client):
    def __init__(self, address):
        self.difficulties = []
        super().__init__(address)

    def read(self):
        message = super().read()
        if message.get("method") == "mining.set_difficulty":
            self.difficulties.append(message["params"][0])
        return message


class SharePoolHashVardiffStratumTest(SharePoolHashVardiffTest):
    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=1, choices=(1,))

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
            "-sharepoolcompacttides=1", "-sharepoolvardiff=1", "-testactivationheight=blake2b@1",
            "-disablewallet", "-networkactive=0"]]
        self.assignments = {}

    def run_test(self):
        node = self.nodes[0]
        self.genesis = int(node.getblockhash(0), 16)
        directory = Path(self.options.tmpdir)
        paths = [directory / f"vardiff-stratum-owner-{index}.key" for index in range(2)]
        gates, services, clients = [], [], []
        failures, results = [], {}
        stop = threading.Event()
        shares_done, late_done, allow_native = threading.Event(), threading.Event(), threading.Event()
        miner = None
        report = {"network": "isolated native regtest", "profile": "hash-only-v8-vardiff-tides",
            "transport": "two independent loopback Sia listeners; one active client per identity",
            "hardware_used": False, "injected_controller_clock": True,
            "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
            "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                for name in ("contrib/sharepool/hash_mining_gate.py", "contrib/sharepool/hash_job_scheduler.py",
                    "contrib/sharepool/hash_stratum.py", "contrib/sharepool/hash_vardiff.py",
                    "contrib/sharepool/hash_stratum_runner.py",
                    "test/functional/feature_sharepool_hash_vardiff_stratum.py")},
            "checks": []}
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=101,
                payout_script=b"\x00\x14" + bytes([index + 1]) * 20) for index, path in enumerate(paths)]
            for signer, bits in zip(signers, (0, 6)):
                self.assignments[signer.public_key] = bits
            # Construct and store only the openings. The usual origin() helper
            # also registers native bodies and would mask first-proof recovery.
            origins = []
            for signer in signers:
                block, snapshot, _ = self.construct(0, signer)
                self.store(0, snapshot)
                proof = solve_share(block, snapshot)
                assert_raises_rpc_error(-25, "sharepool-hash-data-missing",
                    node.validatesharepoolhashshare, proof.serialize().hex())
                origins.append((block, snapshot, proof))
            clocks = [Clock(), Clock()]
            controllers = [VardiffController(initial_work_bits=bits, target_share_seconds=10,
                retarget_seconds=40, clock=clock) for bits, clock in zip((0, 6), clocks)]
            owner = threading.get_ident()
            native_calls, native_failures, registration_receives = [], [], []

            def rpc(method, *args):
                assert_equal(threading.get_ident(), owner)
                native_calls.append(method)
                try:
                    return getattr(node, method)(*args)
                except Exception:
                    native_failures.append(method)
                    raise

            for index, signer in enumerate(signers):
                gate = HashMiningGate(directory / f"vardiff-stratum-{index}.sqlite", rpc=rpc,
                    pool=101, public_key=signer.public_key, payout_script=signer.payout_script,
                    profile_version=8, share_work_bits=(0, 6)[index])
                gates.append(gate)
                for block, snapshot, proof in origins:
                    gate.register_snapshot(snapshot.serialize())
                    gate.register_template(block.serialize())
                    before = len(native_calls)
                    assert gate.receive(proof)
                    received = native_calls[before:]
                    assert_equal(received.count("validatesharepoolhashshare"), 1)
                    assert "validatesharepoolhashtemplate" not in received
                    assert "submitsharepoolhashsnapshot" not in received
                    registration_receives.append({"owner": index,
                        "proof_id": f"{proof.proof_id:064x}", "proof_rpcs": 1,
                        "template_recovery_rpcs": 0, "snapshot_replay_rpcs": 0})
                observer = get_rpc_proxy(node.url, 60 + index, timeout=1)
                service = VardiffStratumService(gate, controller=controllers[index],
                    sign_owner=signer.sign_owner,
                    observer_rpc=lambda method, *args, connection=observer: getattr(connection, method)(*args),
                    observe_seconds=0.05, observation_timeout=2, clock=clocks[index])
                services.append(service)
                service.start()
                service.service_once()
            original = [service.current for service in services]
            assert all(original)
            assert_equal([work.snapshot.envelope.share_work_bits for work in original], [0, 6])
            assert original[0].template.job_id != original[1].template.job_id
            assert original[0].snapshot.envelope.payout_script != original[1].snapshot.envelope.payout_script
            assert_equal([self.payouts(parse_block(work.authorization.block_bytes)) for work in original],
                [self.expected_payouts([origin[2] for origin in origins])] * 2)
            initial_receipts = [gate.receipt_status()["retained_receipts"] for gate in gates]
            assert_equal(native_failures, [])
            report["explicit_registration"] = {"initial_native_missing_origins": len(origins),
                "first_receives": registration_receives}
            report["checks"].append("explicit_registration_first_proof_without_missing_recovery")
            transport_start = len(native_calls)

            def search(work, client, notify, predicate, start=0):
                for nonce in range(start, start + 10000):
                    encoded = nonce.to_bytes(8, "little").hex()
                    proof = proof_from_sia(work.template, client.prefix, bytes(8), notify[7], encoded)
                    if predicate(proof.hash_int):
                        return proof, encoded, nonce + 1
                raise AssertionError("bounded synthetic nonce search failed")

            def submit(client, identity, notify, encoded):
                client.send(identity, "mining.submit", ["sharepool.regtest", notify[0],
                    bytes(8).hex(), notify[7], encoded])
                while True:
                    response = client.read()
                    if response.get("id") == identity:
                        assert_equal(response["result"], True)
                        return

            def mine():
                try:
                    notify = []
                    for index, service in enumerate(services):
                        client = VardiffClient(service.address)
                        clients.append(client)
                        notify.append(client.notify())
                        assert_equal(notify[-1][0], original[index].template.job_id)
                        assert_equal(client.difficulties, [math.nextafter(
                            ((1 << 224) - 1) / (original[index].target + 1), 0.0)])
                        with socket.create_connection(service.address, timeout=2) as excess:
                            excess.settimeout(2)
                            assert_equal(excess.recv(1), b"")
                    results["notify_job_ids"] = [item[0] for item in notify]
                    results["initial_wire_difficulties"] = [client.difficulties[0] for client in clients]
                    assert results["initial_wire_difficulties"][0] != results["initial_wire_difficulties"][1]
                    native = services[0]._native_target(original[0].template.header.nBits)
                    proofs, encoded_proofs, next_nonce = [], [], 0
                    for sequence in range(8):
                        proof, encoded, next_nonce = search(original[0], clients[0], notify[0],
                            lambda value: value > native, next_nonce)
                        proofs.append(proof)
                        encoded_proofs.append(encoded)
                        submit(clients[0], 10 + sequence, notify[0], encoded)
                    submit(clients[0], 20, notify[0], encoded_proofs[0])
                    results["initial_shares"] = proofs
                    shares_done.set()
                    updated_notify = clients[0].notify()
                    updated = services[0].current
                    assert_equal(updated_notify[0], updated.template.job_id)
                    assert updated.template.job_id != original[0].template.job_id
                    assert_equal(updated.snapshot.envelope.share_work_bits, 1)
                    # This share is valid only under the older exact assignment;
                    # neither the new target nor native block target admits it.
                    fresh_target = share_target(updated.template.header.nBits, 8, 1)
                    proof, encoded, _ = search(original[0], clients[0], notify[0],
                        lambda value: value > max(native, fresh_target), next_nonce)
                    submit(clients[0], 21, notify[0], encoded)
                    results["late_share"] = proof
                    results["late_assigned_work"] = 1
                    late_done.set()
                    assert allow_native.wait(10), "owner did not release native-only test"
                    assert not stop.is_set()
                    assigned = share_target(original[1].template.header.nBits, 8, 6)
                    winner, encoded, _ = search(original[1], clients[1], notify[1],
                        lambda value: assigned < value <= native)
                    results["native_only"] = winner
                    clients[1].send(30, "mining.submit", ["sharepool.regtest", notify[1][0],
                        bytes(8).hex(), notify[1][7], encoded])
                    # Native tip observation may close the socket before the
                    # reply; exact native block acceptance is checked below.
                    try:
                        while clients[1].read().get("id") != 30:
                            pass
                    except EOFError:
                        pass
                except BaseException as error:
                    failures.append(error)

            miner = threading.Thread(target=mine, daemon=True)
            miner.start()

            def pump(condition, timeout=30):
                deadline = time.monotonic() + timeout
                while not condition():
                    if failures:
                        raise failures[0]
                    assert time.monotonic() < deadline, "owner/transport deadline exceeded"
                    for service in services:
                        service.service_once()
                    time.sleep(0.01)

            pump(shares_done.is_set)
            assert_equal([service.stats["published"] for service in services], [1, 1])
            assert_equal([service.stats["acknowledged"] for service in services], [8, 0])
            assert_equal(services[0].stats["duplicate"], 1)
            assert_equal(controllers[0].status()["window_accepted_work"], 8)
            assert_equal(controllers[1].status()["window_accepted_work"], 0)
            assert gates[0].ready_for_continued_work(original[0].authorization)
            clocks[0].now = 40
            pump(late_done.is_set)
            assert_equal([service.stats["published"] for service in services], [2, 1])
            assert_equal([gate.share_work_bits for gate in gates], [1, 6])
            state = controllers[0].status()
            assert_equal(state["last_estimate"]["accepted_work"], 8)
            assert_equal(state["last_estimate"]["elapsed_seconds"], 40)
            assert_equal(state["window_accepted_work"], 1)
            assert_equal(state["window_accepted_shares"], 1)
            assert_equal(controllers[1].status()["observations"], 0)
            assert gates[0].ready_for_continued_work(original[0].authorization)
            # The eight new submissions, duplicate and late old-target proof
            # all require fresh native verdicts, without missing-data retries.
            transport_proof_rpcs = native_calls[transport_start:].count("validatesharepoolhashshare")
            assert_equal(transport_proof_rpcs, 10)
            assert_equal(native_failures, [])
            report["transport_proof_rpcs"] = transport_proof_rpcs
            report["checks"].append("wire_submissions_no_missing_origin_recovery")
            report["retarget"] = state
            report["checks"] += ["independent_signed_assignments_and_real_notifications",
                "wire_difficulty_matches_union_of_assigned_and_native_targets", "one_active_client_per_identity",
                "eight_native_validated_shares_without_refresh", "duplicate_does_not_affect_estimator",
                "retarget_only_on_due_refresh", "other_identity_assignment_unchanged",
                "late_old_target_share_keeps_original_work", "all_gate_rpc_calls_on_owner_thread"]
            allow_native.set()
            pump(lambda: not miner.is_alive())
            miner.join(timeout=1)
            if failures:
                raise failures[0]
            winner = results["native_only"]
            assert_equal(node.getbestblockhash(), winner.display_hash)
            assert_equal(bytes.fromhex(node.getblock(winner.display_hash, 0)), winner.block)
            assert_equal(self.payouts(parse_block(winner.block)), self.expected_payouts([origin[2] for origin in origins]))
            assert_equal(gates[1].receipt_status()["retained_receipts"], initial_receipts[1])
            assert_equal(services[1].stats["acknowledged"], 0)
            assert_equal(services[1].stats["native_only_candidates"], 1)
            assert_equal(services[1].stats["accepted_candidates"], 1)
            assert_equal(controllers[1].status()["window_accepted_work"], 0)
            assert_equal(services[0].stats["acknowledged"], 9)
            assert node.verifychain(4, 0)
            report["checks"] += ["native_only_winner_exact_bytes_accepted", "native_only_winner_not_credited",
                "exact_work_weighted_coinbase_payouts", "native_verifychain"]
            report["native_only_block"] = winner.display_hash
            report["notify_job_ids"] = results["notify_job_ids"]
            report["initial_wire_difficulties"] = results["initial_wire_difficulties"]
            report["initial_assignments"] = [0, 6]
            report["service_stats"] = [dict(service.stats) for service in services]
            report["payouts"] = {script.hex(): value for script, value in self.payouts(parse_block(winner.block)).items()}
            report["native_only_receipt_revision_unchanged"] = True
            self.log.info("Standalone v8 CLI runner publishes work and closes its listener without changing the chain")
            before_tip, before_height = node.getbestblockhash(), node.getblockcount()
            cli = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
                "bitcoin-cli" + self.config["environment"]["EXEEXT"])
            runner = Path(__file__).resolve().parents[2] / "contrib/sharepool/hash_stratum_runner.py"
            command = [sys.executable, "-B", str(runner), "--bitcoin-cli", str(cli),
                "--datadir", str(node.datadir_path), "--signer-binary", str(self.signer_binary),
                "--signer-key", str(paths[1]), "--gate", str(directory / "standalone-v8-stratum.sqlite"),
                "--pool", f"{signers[1].pool:x}", "--payout-script", signers[1].payout_script.hex(),
                "--seconds", "1", "--profile-version", "8", "--share-work-bits", "6",
                "--activation-height", "1"]
            standalone = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
            assert standalone.returncode == 0, standalone.stderr
            output = [json.loads(line) for line in standalone.stdout.splitlines()]
            assert_equal(len(output), 2)
            ready, outcome = output
            assert_equal(ready["profile"], 8)
            assert_equal(ready["network"], "regtest")
            assert_equal(ready["hardware_configured"], False)
            assert_equal(ready["share_work_bits"], 6)
            assert_equal(ready["active_client_limit"], 1)
            assert_equal(ready["target_share_seconds"], 6)
            assert_equal(outcome["duration_limit_seconds"], 1)
            assert_equal(outcome["stats"]["published"], 1)
            assert_equal(outcome["stats"]["acknowledged"], 0)
            assert_equal(outcome["stats"]["submitted_candidates"], 0)
            assert_equal(outcome["vardiff"]["target_share_seconds"], 6)
            assert_equal(outcome["vardiff"]["retarget_seconds"], 24)
            assert_equal(outcome["vardiff"]["share_work_bits"], 6)
            assert_equal(outcome["vardiff"]["adjustments"], 0)
            assert_equal(node.getbestblockhash(), before_tip)
            assert_equal(node.getblockcount(), before_height)
            network = node.getnetworkinfo()
            assert_equal(network["networkactive"], False)
            assert_equal(network["connections"], 0)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_listener:
                closed_listener.settimeout(1)
                assert closed_listener.connect_ex(tuple(ready["address"])) != 0
            report["standalone_runner"] = {"exit_code": 0, "v8_job_published": True,
                "listener_closed": True, "chain_and_network_unchanged": True,
                "target_share_seconds": 6, "retarget_seconds": 24, "assigned_work_bits": 6,
                "bitcoin_cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest()}
            report["checks"].append("standalone_cli_startup_default_cadence_and_shutdown")
            (directory / "vardiff-stratum-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            stop.set()
            allow_native.set()
            for client in clients:
                client.close()
            for service in reversed(services):
                service.close()
            if miner is not None:
                miner.join(timeout=2)
            for gate in gates:
                gate.close()
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashVardiffStratumTest(__file__).main()
