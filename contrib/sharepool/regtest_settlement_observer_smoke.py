#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Observe real stock-Knots regtest settlements, maturity, and forced reorgs.

Creates one disposable datadir with P2P and wallets disabled. Reorganizations
use explicit invalidateblock/reconsiderblock RPCs, not a claimed natural attack.
The native node validates actual blocks; the separate SQLite observer validates
the supplied settlement envelope and exact ordered coinbase outputs. Snapshot
digests and allocations are fixtures, not a proof of share-ledger settlement.
No existing datadir, miner, public network, or wallet is accessed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time

from base_chain_settlement import BaseChainSettlement, SettlementCommitment
from regtest_commitment_smoke import IsolatedNode, accept, make_block, require, solve
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CTxInWitness, CTxOut, hash256
from test_framework.script import CScript


def _digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _settlement_block(node, parent, payouts, root, tag):
    previous = node.rpc("getblockheader", parent)
    height = previous["height"] + 1
    coinbase = create_coinbase(height)
    require(sum(amount for _, amount in payouts) == coinbase.vout[0].nValue,
            "fixture must exactly allocate the regtest subsidy")
    coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + bytes(CScript([tag])))
    coinbase.vout = [CTxOut(amount, CScript(bytes.fromhex(script))) for script, amount in payouts]
    # The fixture includes the ordinary witness commitment and zero reserved
    # value, even though there are no additional transactions in these blocks.
    coinbase.wit.vtxinwit = [CTxInWitness()]
    coinbase.wit.vtxinwit[0].scriptWitness.stack = [bytes(32)]
    coinbase.rehash()
    candidate = create_block(int(parent, 16), coinbase, previous["time"] + 1,
                             height=height, header_v2=True)
    candidate.m_mm_rhs = int.from_bytes(root, "little")
    return solve(candidate)


def run(binary):
    started = time.monotonic()
    report = {
        "scope": "One disposable stock Knots regtest node; P2P and wallets disabled; actual native block validation and passive SQLite observation",
        "binary": Path(binary).name,
        "binary_provenance": "Version self-report; not a reproducible-build verification",
        "public_testnet_block_found": False,
        "settlement_rules_enforced_by_native_node": False,
        "snapshot_provenance": "Deterministic digest and payout fixtures; snapshot/share contents are not validated by this observer",
        "reorganization_method": "Administrative invalidateblock/reconsiderblock on the disposable regtest chain",
        "cases": [],
        "success": False,
    }

    def record(name, **details):
        report["cases"].append({"name": name, "passed": True, **details})

    with tempfile.TemporaryDirectory(prefix="sharepool-native-observer-") as directory:
        node, observer = None, None
        try:
            node = IsolatedNode(binary, directory)
            initial = node.ready()
            network = node.rpc("getnetworkinfo")
            require(initial["chain"] == "regtest" and initial["blocks"] == 0,
                    "disposable regtest genesis required")
            require(network["networkactive"] is False and network["connections"] == 0,
                    "native networking must be disabled")
            require("29.4.1" in network["subversion"] and "20260508" in network["subversion"],
                    "stock daemon must identify the requested Knots version")
            report["version"] = network["subversion"]
            genesis = node.rpc("getblockhash", 0)
            report["network_genesis"] = genesis
            record("fresh_isolated_regtest", initial_height=0, peer_connections=0, wallets_enabled=False)

            activation = node.rpc("generatetoaddress", 1, ADDRESS_BCRT1_UNSPENDABLE)[0]
            witness = (bytes.fromhex("6a24aa21a9ed") + hash256(bytes(64))).hex()
            left_script, right_script = "0014" + "11" * 20, "0014" + "22" * 20
            payouts = ((left_script, 2_500_000_000), (right_script, 2_500_000_000), (witness, 0))
            commitment = SettlementCommitment.create(
                network_genesis=genesis, pool_id=b"sharepool/native-observer-test",
                rules_root=_digest("native observer fixture rules"),
                snapshot_root=_digest("native observer fixture snapshot"),
                base_parent=activation, payouts=payouts)
            candidate = _settlement_block(node, activation, payouts, commitment.root, b"sharepool/settlement")
            store = Path(directory) / "settlements.sqlite3"
            observer = BaseChainSettlement(store, network_genesis=genesis, rpc=node.rpc)
            pending = observer.observe(candidate.hash, commitment, payouts)
            require(pending["status"] == "pending" and not pending["payload_verified"],
                    "an observed envelope must not imply native acceptance")
            accept(node, candidate)
            native_header = node.rpc("getblockheader", candidate.hash, True)
            require(native_header["mm_rhs"] == commitment.root.hex(),
                    "native m_mm_rhs must match envelope digest bytes")
            require(native_header["header_version"] == 2, "header-v2 required")
            observer.refresh()
            current = observer.record(candidate.hash)
            require(current["status"] == "immature" and current["confirmations"] == 1
                    and current["payload_verified"] and current["payouts"] == payouts,
                    "native accepted commitment and exact payouts must become verified and immature")
            record("native_envelope_and_exact_coinbase", height=candidate.m_height,
                   block_hash=candidate.hash, commitment=commitment.root.hex(),
                   outputs_including_witness=len(payouts), confirmations=1,
                   status=current["status"], native_body_verified=True)

            # Stock consensus does not understand the envelope's payout rules.
            # Demonstrate that native acceptance alone cannot prove settlement.
            wrong_commitment = SettlementCommitment.create(
                network_genesis=genesis, pool_id=commitment.pool_id,
                rules_root=commitment.rules_root, snapshot_root=commitment.snapshot_root,
                base_parent=candidate.hash, payouts=payouts)
            wrong_payouts = ((left_script, 5_000_000_000), (witness, 0))
            wrong = _settlement_block(node, candidate.hash, wrong_payouts, wrong_commitment.root,
                                      b"sharepool/wrong-payout")
            accept(node, wrong)
            with BaseChainSettlement(Path(directory) / "wrong-payout.sqlite3",
                                     network_genesis=genesis, rpc=node.rpc) as negative:
                negative.observe(wrong.hash, wrong_commitment, payouts)
                try:
                    negative.refresh()
                except ValueError as error:
                    require("native coinbase" in str(error), "wrong payout must fail for the expected reason")
                else:
                    raise AssertionError("observer accepted an incorrect native payout split")
                require(negative.record(wrong.hash)["status"] == "pending"
                        and not negative.record(wrong.hash)["payload_verified"],
                        "failed validation must not partially update persisted status")
            record("native_acceptance_does_not_enforce_pool_payouts", native_block_accepted=True,
                   observer_rejected=True, failure="native coinbase differs from observed payouts",
                   atomic_status="pending")
            node.rpc("invalidateblock", wrong.hash)
            require(node.rpc("getbestblockhash") == candidate.hash, "wrong-payout fixture removal failed")

            main_descendants = node.rpc("generatetoaddress", 2, ADDRESS_BCRT1_UNSPENDABLE)
            main_tip = main_descendants[-1]
            observer.refresh()
            require(observer.record(candidate.hash)["descendants"] == 2, "two descendants expected")
            node.rpc("invalidateblock", candidate.hash)
            require(node.rpc("getbestblockhash") == activation, "administrative disconnect failed")
            alternate = make_block(node, activation, b"sharepool/alternate", bytes(32))
            accept(node, alternate)
            require(node.rpc("getbestblockhash") == alternate.hash, "alternate native branch must be active")
            observer.refresh()
            disconnected = observer.record(candidate.hash)
            require(disconnected["status"] == "orphaned" and disconnected["confirmations"] == 0
                    and not disconnected["spendable_next_block"],
                    "observer must roll back canonicality after actual native chain disconnection")
            record("administrative_native_reorg_rolls_back_observer", status="orphaned",
                   observed_tip=alternate.hash, payout_credit_available=False,
                   method="invalidateblock plus a submitted alternate branch")
            node.rpc("reconsiderblock", candidate.hash)
            require(node.rpc("getbestblockhash") == main_tip, "reconsider must select the longer original branch")
            observer.refresh()
            reconnected = observer.record(candidate.hash)
            require(reconnected["status"] == "immature" and reconnected["descendants"] == 2,
                    "reconnected block must recover its actual native depth")
            record("administrative_reconsider_restores_observer", status="immature",
                   descendants=2, observed_tip=main_tip)

            node.rpc("generatetoaddress", 97, ADDRESS_BCRT1_UNSPENDABLE)
            observer.refresh()
            boundary = observer.record(candidate.hash)
            require(boundary["descendants"] == 99 and boundary["confirmations"] == 100
                    and boundary["spendable_next_block"] and boundary["status"] == "immature",
                    "99 descendants must expose next-block spendability without conservative maturity")
            record("coinbase_next_block_boundary", descendants=99, confirmations=100,
                   spendable_next_block=True, status="immature", coins_spent=False)
            node.rpc("generatetoaddress", 1, ADDRESS_BCRT1_UNSPENDABLE)
            observer.refresh()
            mature = observer.record(candidate.hash)
            require(mature["descendants"] == 100 and mature["confirmations"] == 101
                    and mature["spendable_next_block"] and mature["status"] == "mature",
                    "100 descendants must reach conservative observer maturity")
            record("conservative_maturity_after_100_descendants", descendants=100,
                   confirmations=101, status="mature", coins_spent=False)

            observer.close()
            observer = BaseChainSettlement(store, network_genesis=genesis, rpc=node.rpc)
            require(observer.record(candidate.hash) == mature, "durable reopen must preserve exact observation")
            observer.refresh()
            require(observer.record(candidate.hash)["status"] == "mature", "reopened observer must refresh")
            record("durable_store_reopen_and_refresh", status="mature", payload_verified=True)
            final_network = node.rpc("getnetworkinfo")
            require(final_network["networkactive"] is False and final_network["connections"] == 0,
                    "native networking must remain disabled through completion")
            report["final_height"] = node.rpc("getblockcount")
            report["success"] = True
        finally:
            if observer is not None:
                observer.close()
            if node is not None:
                node.close()
    report["temporary_datadir_removed"] = True
    report["wall_seconds"] = round(time.monotonic() - started, 3)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", required=True, help="Explicit stock Knots 29.4.1 daemon path")
    parser.add_argument("--output", type=Path, help="Write JSON report after all checks pass")
    args = parser.parse_args()
    report = run(args.bitcoind)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
