#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run two isolated stock Knots regtest nodes and probe commitment/fork behavior.

No settlement consensus rules are implemented by this script. Its roots
commit to opaque fixtures; stock nodes never receive or validate those fixtures.
The local-disagreement case uses invalidateblock/reconsiderblock explicitly.
All block relay is manual RPC over loopback; P2P and wallets are disabled.
"""

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "test" / "functional"))

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE  # noqa: E402
from test_framework.blocktools import create_block, create_coinbase  # noqa: E402
from test_framework.messages import uint256_from_compact  # noqa: E402
from test_framework.script import CScript  # noqa: E402
from precommit_demo import Snapshot  # noqa: E402


class RPCError(RuntimeError):
    pass


class IsolatedNode:
    def __init__(self, binary, datadir):
        self.datadir = Path(datadir)
        self.cookie = self.datadir / "regtest" / ".cookie"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.output = (self.datadir / "process.log").open("wb")
        args = [
            str(binary), "-regtest", "-nosettings", "-conf=/dev/null",
            "-datadir=" + str(self.datadir), "-networkactive=0", "-listen=0",
            "-connect=0", "-dnsseed=0", "-discover=0", "-listenonion=0",
            "-disablewallet=1", "-server=1", "-rest=0", "-persistmempool=0",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            "-rpcport=" + str(self.port), "-testactivationheight=blake2b@1",
            "-blake2b_headline=Isolated sharepool commitment test",
            "-printtoconsole=1", "-daemon=0", "-logips=0",
        ]
        try:
            self.process = subprocess.Popen(args, stdout=self.output, stderr=subprocess.STDOUT)
        except BaseException:
            self.output.close()
            raise

    def rpc(self, method, *params):
        cookie = self.cookie.read_text().strip().encode()
        request = urllib.request.Request(
            "http://127.0.0.1:{}/".format(self.port),
            data=json.dumps({"jsonrpc": "1.0", "id": "smoke", "method": method,
                             "params": list(params)}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + base64.b64encode(cookie).decode()},
        )
        try:
            response = self.opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result.get("error"):
            raise RPCError(str(result["error"]))
        return result["result"]

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Isolated regtest daemon exited during startup")
            try:
                return self.rpc("getblockchaininfo")
            except (OSError, RPCError):
                time.sleep(0.1)
        raise TimeoutError("Isolated regtest startup exceeded 30 seconds")

    def close(self):
        if self.process.poll() is None:
            try:
                self.rpc("stop")
            except Exception:
                self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.output.close()


def require(value, message):
    if not value:
        raise AssertionError(message)


def solve(block):
    """Bounded proof-of-work search at regtest difficulty."""
    target = uint256_from_compact(block.nBits)
    for nonce in range(100_000):
        block.nNonce = nonce
        if block.rehash() <= target:
            return block
    raise RuntimeError("Regtest nonce budget exhausted")


def make_block(node, parent, tag, root):
    previous = node.rpc("getblockheader", parent)
    height = previous["height"] + 1
    coinbase = create_coinbase(height)
    coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + bytes(CScript([tag])))
    coinbase.rehash()
    block = create_block(int(parent, 16), coinbase, previous["time"] + 1,
                         height=height, header_v2=True)
    block.m_mm_rhs = int.from_bytes(root, "little")
    return solve(block)


def accept(node, block, *, side_branch=False):
    result = node.rpc("submitblock", block.serialize().hex())
    require(result is None or (side_branch and result == "inconclusive"),
            "Expected block acceptance at height {} for tag {}, got {}".format(
                block.m_height, bytes(block.vtx[0].vin[0].scriptSig).hex(), result))
    # submitblock can return inconclusive for a stored equal-work side branch
    # because it was not connected, so BlockChecked was never emitted.
    require(node.rpc("getblock", block.hash, 0) == block.serialize().hex(),
            "Submitted block data must be retrievable")
    return result


def run(binary):
    report = {
        "scope": "Two installed stock Knots nodes; regtest; loopback RPC only; no wallets or P2P",
        "settlement_rules_implemented": False,
        "snapshot_contents": "Opaque Merkle fixture records, not actual verified miner shares",
        "binary": str(binary),
        "binary_provenance": "Version self-report only; not a reproducible-build verification",
        "cases": [],
        "success": False,
    }
    nodes = []
    directories = []

    def record(name, **details):
        report["cases"].append({"name": name, "passed": True, **details})

    try:
        for _ in range(2):
            directory = tempfile.TemporaryDirectory(prefix="knots-sharepool-regtest-", dir="/private/tmp")
            directories.append(directory)
            node = IsolatedNode(binary, directory.name)
            nodes.append(node)
            chain = node.ready()
            require(chain["chain"] == "regtest" and chain["blocks"] == 0,
                    "Fresh regtest chain required")
            network = node.rpc("getnetworkinfo")
            require(network["networkactive"] is False and network["connections"] == 0,
                    "Network must remain disabled")
            require("29.4.1" in network["subversion"] and "20260508" in network["subversion"],
                    "Installed daemon must identify the requested Knots version")
        left, right = nodes
        report["versions"] = [node.rpc("getnetworkinfo")["subversion"] for node in nodes]

        activation = left.rpc("generatetoaddress", 1, ADDRESS_BCRT1_UNSPENDABLE)[0]
        require(right.rpc("submitblock", left.rpc("getblock", activation, 0)) is None,
                "Second node must accept activation block")
        normal = make_block(left, activation, b"DATUM/test-00", bytes(32))
        for node in nodes:
            accept(node, normal)
            require(node.rpc("getblockheader", normal.hash)["header_version"] == 2,
                    "Post-activation block must have a v2 header")
        record("activation_and_normal_v2", activation_height=1, normal_height=2,
               normal_block=normal.hash)

        snapshot = Snapshot(hashlib.sha256(b"regtest opaque snapshot fixture").digest(),
                            [b"opaque tag/share record A", b"opaque tag/share record B"])
        tagged = make_block(left, normal.hash, b"DATUM/test-01", snapshot.root)
        changed = copy.deepcopy(tagged)
        for counter in range(100_000):
            changed.m_mm_rhs = int.from_bytes(hashlib.sha256(
                b"post-solve mutation" + counter.to_bytes(4, "big")).digest(), "little")
            if changed.rehash() > uint256_from_compact(changed.nBits):
                break
        else:
            raise RuntimeError("Could not construct deterministic high-hash root mutation")
        for node in nodes:
            require(node.rpc("submitblock", changed.serialize().hex()) == "high-hash",
                    "Post-solve root mutation selected above target must fail")
        record("post_solve_commitment_mutation_rejected", reason="high-hash",
               original_nonce=tagged.nNonce, mutated_nonce=changed.nNonce,
               note="Mutation chosen to fail the easy target; not every root mutation must fail")
        for node in nodes:
            accept(node, tagged)
            actual = node.rpc("getblock", tagged.hash, 2)
            require(actual["mm_rhs"] == snapshot.root.hex(), "Root serialization mismatch")
            script = bytes.fromhex(actual["tx"][0]["vin"][0]["coinbase"])
            require(bytes(CScript([b"DATUM/test-01"])) in script, "Coinbase tag missing")
        record("tagged_coinbase_and_merkle_root_accepted", block=tagged.hash,
               root=snapshot.root.hex(), tag="DATUM/test-01", supplied_snapshot_to_nodes=False)

        arbitrary = make_block(left, tagged.hash, b"DATUM/test-02",
                               hashlib.sha256(b"no corresponding snapshot provided").digest())
        for node in nodes:
            accept(node, arbitrary)
        record("arbitrary_root_without_snapshot_accepted", block=arbitrary.hash,
               proves="Stock nodes do not enforce pool snapshot validity or availability")

        sibling_a = make_block(left, arbitrary.hash, b"DATUM/fork-A", snapshot.root)
        sibling_b = make_block(right, arbitrary.hash, b"DATUM/fork-B", snapshot.root)
        accept(left, sibling_a)
        accept(right, sibling_b)
        cross_relay = [accept(left, sibling_b, side_branch=True),
                       accept(right, sibling_a, side_branch=True)]
        require(left.rpc("getbestblockhash") == sibling_a.hash, "Left first-seen tip changed")
        require(right.rpc("getbestblockhash") == sibling_b.hash, "Right first-seen tip changed")
        tips_before = [node.rpc("getbestblockhash") for node in nodes]
        extension = make_block(left, sibling_a.hash, b"DATUM/fork-A2", snapshot.root)
        for node in nodes:
            accept(node, extension)
            require(node.rpc("getbestblockhash") == extension.hash, "Nodes must converge on more work")
        record("equal_work_siblings_converge_after_extension", first_seen_tips=tips_before,
               cross_relay_results=cross_relay, converged_tip=extension.hash,
               note="Both siblings validated as active tips on their initial nodes; equal-work side-branch storage may return inconclusive")

        right.rpc("invalidateblock", sibling_a.hash)
        require(right.rpc("getbestblockhash") == sibling_b.hash, "Invalidation must select alternative")
        longer = make_block(left, extension.hash, b"DATUM/fork-A3", snapshot.root)
        accept(left, longer)
        rejection = right.rpc("submitblock", longer.serialize().hex())
        require(rejection is not None, "Descendant of locally invalidated ancestor must not be accepted")
        require(left.rpc("getbestblockhash") == longer.hash and
                right.rpc("getbestblockhash") == sibling_b.hash,
                "Administrative rejection must keep tips split")
        split_tips = [node.rpc("getbestblockhash") for node in nodes]
        right.rpc("reconsiderblock", sibling_a.hash)
        # A previously rejected descendant may lack stored block data.
        resubmission = right.rpc("submitblock", longer.serialize().hex())
        require(resubmission in (None, "duplicate"), "Reconsidered descendant must be accepted")
        require(right.rpc("getbestblockhash") == longer.hash, "Reconsideration must heal split")
        record("administrative_disagreement_and_reconsideration", split_tips=split_tips,
               descendant_rejection=rejection, healed_tip=longer.hash,
               mechanism="Explicit invalidateblock/reconsiderblock; not automatic settlement consensus")
        for node in nodes:
            network = node.rpc("getnetworkinfo")
            require(network["networkactive"] is False and network["connections"] == 0,
                    "Network isolation must remain intact")
        report["success"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        cleanup_errors = []
        for node in reversed(nodes):
            try:
                node.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
        report["processes_stopped"] = all(node.process.poll() is not None for node in nodes)
        for directory in reversed(directories):
            try:
                directory.cleanup()
            except Exception as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
        report["temporary_datadirs_removed"] = all(not Path(directory.name).exists()
                                                   for directory in directories)
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["success"] = False
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).parent / "results" / "regtest.json")
    args = parser.parse_args()
    report = run(args.bitcoind.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"success": report["success"], "cases_passed": len(report["cases"]),
                      "report": str(args.output), "error": report.get("error")}, indent=2))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
