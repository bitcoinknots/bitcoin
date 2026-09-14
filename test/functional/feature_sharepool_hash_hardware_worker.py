#!/usr/bin/env python3
"""Mining-only v7 ASIC capture worker; no control bridge or miner settings API.

Hardware mode requires explicit private LAN endpoints. Only --software-test
uses a synthetic loopback client and easy transport work. Two disposable native
nodes independently validate the recorded pipeline; P2P remains disabled.
"""
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, Share
from hash_stratum import HashStratumService
from hash_stratum_forwarder import TestMinerForwarder
from testnet_template import proof_from_sia
from v7_hardware_capture import CaptureStore, RPC_METHODS, replay_capture, write_terminal_report
from feature_sharepool_hash_stratum import Client
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.messages import uint256_from_compact
from test_framework.util import get_rpc_proxy


class CapturingService(HashStratumService):
    def __init__(self, *args, capture, **kwargs):
        self.capture, self.captured_jobs, self.captured_proofs, self.capture_failure = capture, set(), set(), None
        super().__init__(*args, **kwargs)

    def _publish(self, authorization):
        result = super()._publish(authorization)
        work = self.current
        if work.template.job_id not in self.captured_jobs:
            if len(self.captured_jobs) >= 32:
                raise ValueError("bounded hardware job capture exhausted")
            # Owner approval cannot finish while this synchronous durable write
            # is outstanding, so notification cannot precede its job capture.
            self.capture.append("job", {"job_id": work.template.job_id,
                "block": authorization.block_bytes.hex(), "snapshot": authorization.snapshot_bytes.hex()})
            self.captured_jobs.add(work.template.job_id)
        return result

    def _submit(self, prefix, params):
        result = super()._submit(prefix, params)
        work = self.jobs[params[1]]
        proof = proof_from_sia(work.template, prefix, bytes.fromhex(params[2]), params[3], params[4])
        if proof.display_hash in self.captured_proofs:
            return result
        share = Share(proof.header, work.snapshot.envelope, work.snapshot.owner_signature)
        try:
            self.capture.append("proof", {"job_id": params[1], "params": params, "prefix": prefix.hex(),
                "share": share.serialize().hex(), "hash": proof.display_hash,
                "work": proof.work.hex(), "block": proof.block.hex()})
            self.captured_proofs.add(proof.display_hash)
        except Exception:
            self.capture_failure = "durable proof capture failed"
            self.withdraw()
            raise
        return result


class SharePoolHashHardwareWorker(SharePoolHashTidesTest):
    PROFILE_VERSION = 7

    def add_options(self, parser):
        parser.add_argument("--software-test", action="store_true")
        parser.add_argument("--bind", default="127.0.0.1")
        parser.add_argument("--miner-ip", default="127.0.0.1")
        parser.add_argument("--forward-port", type=int, default=0)
        parser.add_argument("--ready-file", type=Path)
        parser.add_argument("--seconds", type=int, default=90)
        parser.add_argument("--capture-file", type=Path)
        parser.add_argument("--results", type=Path)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
            "-sharepoolcompacttides=1", "-testactivationheight=blake2b@1", "-disablewallet",
            "-networkactive=0"] for unused in range(2)]

    def run_test(self):
        options, node, replay = self.options, self.nodes[0], self.nodes[1]
        software = options.software_test
        if not 1 <= options.seconds <= 90:
            raise ValueError("hardware capture interval must be 1..90 seconds")
        if software:
            if not all(ipaddress.ip_address(value).is_loopback for value in (options.bind, options.miner_ip)):
                raise ValueError("software client must remain on loopback")
        elif (options.ready_file is None or options.capture_file is None or options.results is None or not options.forward_port or
                any(ipaddress.ip_address(value).is_loopback for value in (options.bind, options.miner_ip))):
            raise ValueError("hardware mode requires explicit LAN endpoints and readiness path")
        directory = Path(options.tmpdir)
        options.capture_file = options.capture_file or directory / "v7-software-capture.jsonl"
        options.results = options.results or directory / "v7-software-capture-result.json"
        if options.capture_file.exists() or options.results.exists():
            raise ValueError("fresh capture and result paths required")
        os.chmod(directory, 0o700)
        for path in (options.capture_file.parent, options.results.parent):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = directory / "hardware-owner.key"
        capture = CaptureStore(directory / "hardware-capture.sqlite")
        gate = service = forwarder = miner = None
        successful = False
        miner_stop, failures = threading.Event(), []
        report = {"result": "failed", "mode": "software" if software else "hardware",
            "hardware_input_requested": not software, "network": "isolated regtest", "profile": 7,
            "physical_provenance": "not established by worker/replay alone",
            "capture_limit_seconds": options.seconds, "transport_difficulty": None if software else 4096,
            "daemon_sha256": hashlib.sha256(Path(options.bitcoind).read_bytes()).hexdigest(),
            "signer_sha256": hashlib.sha256(self.signer_binary.read_bytes()).hexdigest()}
        root = Path(__file__).resolve().parents[2]
        report["source_sha256"] = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [Path(__file__), *sorted((root / "contrib/sharepool").glob("*.py"))]}
        try:
            signer = HashSigner.create(self.signer_binary, key, pool=0xABC123,
                                       payout_script=b"\x00\x14" + bytes.fromhex("42" * 20))
            capture.append("policy", {"profile": 7, "genesis": node.getblockhash(0), "mode": report["mode"],
                "transport_difficulty": report["transport_difficulty"], "pool": signer.pool,
                "payout_script": signer.payout_script.hex(), "public_key": signer.public_key.hex()})
            owner = threading.get_ident()

            def rpc(method, *args):
                assert threading.get_ident() == owner
                result = getattr(node, method)(*args)
                if method in RPC_METHODS:
                    capture.append("rpc", {"method": method, "params": list(args), "result": result})
                return result

            gate = HashMiningGate(directory / "hardware-gate.sqlite", rpc=rpc, pool=signer.pool,
                public_key=signer.public_key, payout_script=signer.payout_script, profile_version=7, activation_height=1)
            observer = get_rpc_proxy(node.url, 77, timeout=1)
            service = CapturingService(gate, sign_owner=signer.sign_owner,
                observer_rpc=lambda method, *args: getattr(observer, method)(*args), capture=capture,
                transport_difficulty=report["transport_difficulty"])
            service.start()
            service.service_once()
            forwarder = TestMinerForwarder(bind=(options.bind, options.forward_port), miner_ip=options.miner_ip,
                                          upstream=service.address, seconds=options.seconds + 10)
            forwarder.start()
            report["forward_address"] = list(forwarder.address)
            if options.ready_file is not None:
                # Publish only a fully written, fsynced marker; the supervisor
                # never observes a partially written readiness file.
                staging = options.ready_file.with_name(options.ready_file.name + ".staging")
                descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(descriptor, b"sharepool-v7-hardware-ready\n")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.link(staging, options.ready_file)
                staging.unlink()
                descriptor = os.open(options.ready_file.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

            def synthetic_client():
                try:
                    while not miner_stop.is_set():
                        client = Client(forwarder.address)
                        try:
                            notify = client.notify()
                            with service.latch.lock:
                                work = service.jobs[notify[0]]
                            for nonce in range(10000):
                                encoded = nonce.to_bytes(8, "little").hex()
                                proof = proof_from_sia(work.template, client.prefix, bytes(8), notify[7], encoded)
                                if proof.hash_int <= uint256_from_compact(work.template.header.nBits):
                                    break
                            else:
                                raise AssertionError("bounded synthetic native nonce search failed")
                            client.send(3, "mining.submit", ["sharepool.regtest", notify[0], bytes(8).hex(), notify[7], encoded])
                            try:
                                while client.read().get("id") != 3:
                                    pass
                            except EOFError:
                                pass
                            parent = work.authorization.native_parent
                            while not miner_stop.wait(0.02):
                                with service.latch.lock:
                                    current = service.current
                                if current is not None and current.authorization.native_parent != parent:
                                    break
                        finally:
                            client.close()
                except (EOFError, OSError) as error:
                    if not miner_stop.is_set():
                        failures.append(error)
                except BaseException as error:
                    failures.append(error)

            if software:
                miner = threading.Thread(target=synthetic_client, daemon=True)
                miner.start()
            started, deadline = time.monotonic(), time.monotonic() + options.seconds
            report["withdrawn_publication_retries"] = 0
            while time.monotonic() < deadline and service.stats["acknowledged"] < (4 if software else 16):
                try:
                    service.service_once(max_requests=1)
                except ValueError as error:
                    # A just-submitted block can beat the independent observer
                    # to the new tip. That attempted publication has already
                    # withdrawn its sockets; wait for observation and build
                    # afresh. Do not retry arbitrary validation/capture failures.
                    if (str(error) not in ("native observer refuses stale or unobserved work",
                                           "native context changed during scheduled dispatch") or
                            capture.failed or report["withdrawn_publication_retries"] >= 32):
                        raise
                    report["withdrawn_publication_retries"] += 1
                if failures:
                    raise failures[0]
                if capture.failed or service.capture_failure:
                    raise ValueError(service.capture_failure or "durable capture failed")
                time.sleep(0.01)
            report["capture_seconds"] = time.monotonic() - started
            miner_stop.set()
            forwarder.close()
            service.close()
            if miner is not None:
                miner.join(timeout=2)
                if miner.is_alive():
                    raise ValueError("synthetic client did not stop")
            if failures or capture.failed or service.capture_failure:
                raise ValueError("mining transport/capture failed")
            report["stats"] = dict(service.stats)
            report["height"], report["tip"] = node.getblockcount(), node.getbestblockhash()
            if report["height"] < 2 or service.stats["acknowledged"] < 2 or not node.verifychain(4, 0):
                raise ValueError("capture did not establish two native settlements")
            capture.append("complete", {"height": report["height"], "tip": report["tip"], "stats": report["stats"]})
            report["capture_sha256"] = capture.export(options.capture_file)
            report["replay"] = replay_capture(options.capture_file, lambda method, *args: getattr(replay, method)(*args))
            if (report["replay"]["height"], report["replay"]["tip"]) != (report["height"], report["tip"]):
                raise ValueError("independent replay diverged from captured native chain")
            successful = True
        finally:
            try:
                miner_stop.set()
                if forwarder is not None:
                    forwarder.close()
                if service is not None and not service._closed:
                    service.close()
                if gate is not None:
                    gate.close()
                capture.close()
                key.unlink(missing_ok=True)
            except BaseException:
                successful = False
                raise
            finally:
                write_terminal_report(options.results, report, successful=successful)


if __name__ == "__main__":
    SharePoolHashHardwareWorker(__file__).main()
