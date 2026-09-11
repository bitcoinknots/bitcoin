#!/usr/bin/env python3
"""Loopback HTTP replication smoke for the experimental signed pool protocol.

Three separate Engine objects share one Python process. Real loopback HTTP
transports public signed objects, with fixture ECDSA keys and synthetic BLAKE2b
work. This is not Knots integration, production P2P, or independent processes.
Missing objects are not retained: senders explicitly resend complete bundles.
"""

import argparse
import copy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

from live_protocol import (Engine, MissingData, Rules, append_receipt, canonical,
                           decode_coinbase, issue_job, mine)
from signed_registry import private_key, public_key, register

MAX_BODY = 2 * 1024 * 1024
OBJECT_FIELDS = ("changes", "jobs", "receipts", "blocks")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def public_state(engine):
    """Return verified public state; never return signing keys or secrets."""
    state = engine.state(engine.tip)
    compatible = []
    for root, ledger in engine.ledgers.items():
        try:
            pending = engine.pending(root)
        except (MissingData, ValueError):
            continue
        compatible.append((len(ledger.roots), root, pending))
    _, root, pending = max(compatible)
    ledger = engine.ledger(root)
    return {
        "rules_root": engine.rules.root.hex(), "tip": format(engine.tip, "064x"),
        "height": state.height, "anchored_ledger_root": state.ledger_root.hex(),
        "verified_ledger_root": root.hex(), "verified_receipts": len(ledger.roots) - 1,
        "registry_root": state.registry_root.hex(),
        "paid": sorted(identity.hex() for identity in state.paid),
        "pending": sorted(identity.hex() for identity in pending),
        "claims": sorted(claim.proof_id.hex() for claim in ledger.claims),
        "winners": sorted(claim.proof_id.hex() for claim in state.winners),
        "balances": [[script.hex(), amount] for script, amount in state.balances],
        "object_counts": {field: len(getattr(engine, field)) for field in OBJECT_FIELDS},
    }


def validate_bundle(bundle, rules):
    if type(bundle) is not dict:
        raise ValueError("bundle must be an object")
    if set(bundle) - {"format", "rules", "tip", *OBJECT_FIELDS}:
        raise ValueError("unknown bundle fields")
    count = 0
    for field in OBJECT_FIELDS:
        values = bundle.get(field, [])
        if type(values) is not list or not all(type(value) is dict for value in values):
            raise ValueError("object collections must be lists of objects")
        count += len(values)
    if count > rules.max_events * 8:
        raise ValueError("too many objects")


class ReplicaHTTPServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


class ReplicaHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, payload):
        raw = canonical(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path != "/state":
            self.respond(404, {"errors": ["unknown endpoint"]})
            return
        self.respond(200, public_state(self.server.engine))

    def do_POST(self):
        if self.path != "/objects":
            self.respond(404, {"errors": ["unknown endpoint"]})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("chunked requests are not supported")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("application/json is required")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                self.respond(413, {"missing": None, "errors": ["body size outside bounds"]})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("truncated request")
            bundle = json.loads(raw)
            validate_bundle(bundle, self.server.engine.rules)
            missing = self.server.engine.import_objects(bundle)
            self.respond(200, {"missing": missing, "errors": [],
                               "retry_complete_bundle": bool(missing)})
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
            # Import is incremental: earlier valid objects may already be stored.
            # Invalid signatures/objects never receive credit from this wrapper.
            self.respond(422, {"missing": None,
                               "errors": [type(error).__name__ + ": " + str(error)]})


class Peer:
    def __init__(self, engine):
        self.server = ReplicaHTTPServer(("127.0.0.1", 0), ReplicaHandler)
        self.server.engine = engine
        self.address = "http://127.0.0.1:{}".format(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.1}, daemon=False)
        try:
            self.thread.start()
        except BaseException:
            self.server.server_close()
            raise

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=6)
        require(not self.thread.is_alive(), "Replica listener thread did not stop")


def request(peer, path, bundle=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    message = urllib.request.Request(peer.address + path,
        data=None if bundle is None else canonical(bundle),
        headers={"Content-Type": "application/json"})
    try:
        response = opener.open(message, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def subset(bundle, **fields):
    result = {key: copy.deepcopy(bundle[key]) for key in ("format", "rules", "tip")}
    result.update({key: [] for key in OBJECT_FIELDS})
    result.update(fields)
    return result


def reversed_bundle(bundle):
    result = copy.deepcopy(bundle)
    for field in OBJECT_FIELDS:
        result[field].reverse()
    return result


def relay(peers, bundle):
    for index, peer in enumerate(peers):
        status, result = request(peer, "/objects", reversed_bundle(bundle) if index % 2 == 0 else bundle)
        require(status == 200 and result["missing"] == 0 and not result["errors"],
                "Complete public object relay failed: " + str(result))


def converged(peers, producer):
    expected = public_state(producer)
    for peer in peers:
        status, state = request(peer, "/state")
        require(status == 200 and state == expected, "Public replica state differs")
    return expected


def run_smoke():
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "success": False,
              "scope": "Three Engine objects in one process; real loopback HTTP; signed fixtures and synthetic work",
              "knots_integration": False, "separate_processes": False,
              "external_network": False, "private_keys_transmitted": False,
              "missing_dependency_policy": "Unresolved objects are uncredited and not retained; sender resends a complete bundle",
              "cases": []}
    peers = []

    def record(name, **details):
        report["cases"].append({"name": name, "passed": True, **details})

    try:
        coordinator = private_key(1801)
        miners = (private_key(1802), private_key(1803))
        producer = Engine(Rules(public_key(coordinator)))
        report["rules"] = producer.rules.to_object()
        engines = (producer, Engine(producer.rules), Engine(producer.rules))
        for engine in engines:
            peers.append(Peer(engine))
        producer_peer, replica_a, replica_b = peers
        replicas = (replica_a, replica_b)
        registry_root = producer.genesis_registry
        scripts = (b"\x00\x20" + b"\x41" * 32, b"\x00\x20" + b"\x42" * 32)
        for index, key in enumerate(miners):
            change = register(producer.registry(registry_root), key,
                              ("http-miner-" + str(index)).encode(), scripts[index])
            registry_root = producer.add_change(change)
        old_job = issue_job(producer, miners[0], coordinator, registry_root, producer.empty_ledger)
        tail = mine(old_job, extranonce=10)
        receipt = append_receipt(producer, coordinator, producer.empty_ledger, proof=tail)
        refreshed = issue_job(producer, miners[1], coordinator, registry_root, receipt.root, serial=1)
        require(old_job.manifest.root != refreshed.manifest.root, "Refresh must change commitment")
        require(old_job.manifest.share_snapshot_root != refreshed.manifest.share_snapshot_root,
                "Verified receipt must change the actual share snapshot Merkle root")
        first_winner = mine(old_job, extranonce=20, full_block=True)
        first_block = producer.add_block(first_winner)
        require(producer.state(first_block).ledger_root == producer.empty_ledger,
                "Old job winner must settle its immutable old prefix")
        complete = producer.export()

        bad_receipt = copy.deepcopy(receipt.to_object())
        bad_receipt["signature"] = "00" * 8
        status, response = request(replica_a, "/objects", subset(complete, receipts=[bad_receipt]))
        require(status == 422 and "authorization" in str(response["errors"]),
                "Modified receipt signature must be rejected")
        require(request(replica_a, "/state")[1]["object_counts"]["receipts"] == 0,
                "Invalid receipt must not enter cache")
        record("modified_receipt_signature_rejected", http_status=status, errors=response["errors"])

        incomplete_a = subset(complete, jobs=list(reversed(complete["jobs"])),
                              receipts=complete["receipts"], blocks=complete["blocks"])
        incomplete_b = subset(complete, changes=list(reversed(complete["changes"])),
                              receipts=complete["receipts"], blocks=complete["blocks"])
        missing_counts = []
        for peer, bundle in ((replica_a, incomplete_a), (replica_b, incomplete_b)):
            status, response = request(peer, "/objects", bundle)
            require(status == 200 and response["missing"] > 0, "Missing dependencies must be reported")
            missing_counts.append(response["missing"])
            state = request(peer, "/state")[1]
            require(state["height"] == 0 and state["pending"] == [] and
                    state["object_counts"]["receipts"] == 0, "Incomplete proof must remain uncredited")
        record("reordered_missing_dependencies_remain_uncredited", missing_counts=missing_counts)

        relay(replicas, complete)
        state = converged(peers, producer)
        expected_pending = sorted((tail.proof_id.hex(), first_winner.proof_id.hex()))
        require(state["pending"] == expected_pending and state["verified_receipts"] == 1,
                "Verified tail and implicit winner must survive old-job win")
        require(state["paid"] == [], "Old empty-prefix winner cannot prepay later claims")
        record("complete_retry_converges_and_accepts_correct_receipt", state=state,
               old_snapshot_merkle_root=old_job.manifest.share_snapshot_root.hex(),
               refreshed_snapshot_merkle_root=refreshed.manifest.share_snapshot_root.hex(),
               old_sidechain_commitment=old_job.manifest.root.hex(),
               refreshed_sidechain_commitment=refreshed.manifest.root.hex())

        seal = append_receipt(producer, coordinator, receipt.root, winner=first_block)
        child = issue_job(producer, miners[1], coordinator, registry_root, seal.root)
        child_outputs = [(bytes(output.scriptPubKey), output.nValue)
                         for output in decode_coinbase(child.coinbase).vout]
        require(child_outputs == [(scripts[0], producer.rules.reward)],
                "New job must allocate reward to old tail and implicit winner")
        second_winner = mine(child, extranonce=30, full_block=True)
        second_block = producer.add_block(second_winner)
        require(producer.state(second_block).paid == frozenset((tail.proof_id, first_winner.proof_id)),
                "Exactly old tail and old winner must be marked paid")
        second_bundle = producer.export()
        status, response = request(replica_a, "/objects", subset(second_bundle, jobs=[child.to_object()]))
        require(status == 200 and response["missing"] == 1, "Child job must wait for parent seal")
        status, response = request(replica_b, "/objects", subset(second_bundle, blocks=[second_winner.to_object()]))
        require(status == 200 and response["missing"] == 1, "Child proof must wait for authenticated job")
        relay(replicas, second_bundle)
        state = converged(peers, producer)
        require(state["paid"] == expected_pending and state["pending"] == [second_winner.proof_id.hex()],
                "Paid work must disappear from pending while new winner remains")
        record("signed_seal_and_next_job_settle_tail_once", state=state)

        for _ in range(2):
            relay(replicas, second_bundle)
            require(converged(peers, producer) == state, "Duplicate bundle changed settled state")
        record("duplicate_bundle_is_idempotent", replays_per_replica=2)

        seal2 = append_receipt(producer, coordinator, seal.root, winner=second_block)
        third_job = issue_job(producer, miners[0], coordinator, registry_root, seal2.root)
        require([(bytes(output.scriptPubKey), output.nValue)
                 for output in decode_coinbase(third_job.coinbase).vout] == [(scripts[1], producer.rules.reward)],
                "Following job must pay second finder, not already paid first-finder work")
        third_winner = mine(third_job, extranonce=40, full_block=True)
        producer.add_block(third_winner)
        relay(replicas, producer.export())
        state = converged(peers, producer)
        require(state["balances"] == [[scripts[0].hex(), 2 * producer.rules.reward],
                                     [scripts[1].hex(), producer.rules.reward]],
                "Unexpected cumulative payouts")
        require(state["pending"] == [third_winner.proof_id.hex()], "Only newest winner may remain unpaid")
        record("later_payout_does_not_repay_old_claims", state=state)
        report["success"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        cleanup_errors = []
        for peer in reversed(peers):
            try:
                peer.close()
            except Exception as error:
                cleanup_errors.append(str(error))
        report["listeners_closed"] = all(peer.server.socket.fileno() == -1 for peer in peers)
        report["threads_joined"] = all(not peer.thread.is_alive() for peer in peers)
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["success"] = False
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-smoke", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / "live-peer.json")
    args = parser.parse_args()
    report = run_smoke()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"success": report["success"], "cases_passed": len(report["cases"]),
                      "error": report.get("error"), "report": str(args.output)}, indent=2))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
