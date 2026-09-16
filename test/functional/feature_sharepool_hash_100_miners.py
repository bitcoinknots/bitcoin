#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""100 honest v4 gates settle100 proofs, then carry late work and the winner.

Five isolated native nodes exchange complete flat-hash snapshots over their
existing Bitcoin P2P connections. Fresh local signer keys and CPU proof search
are disposable fixtures. No refused job is dispatched or used as a bypass.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import (HashSigner, Snapshot, MAX_SNAPSHOT_BYTES, MAX_DEPENDENCY_BYTES,
    candidate, solve_share, winner_share)
from hash_mining_gate import HashMiningGate
from native_mining_gate import JobOmission, template_id
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolHash100MinersTest(BitcoinTestFramework):
    MINERS = 100

    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-testactivationheight=blake2b@1",
                            "-disablewallet", "-debug=net"] for _ in range(self.num_nodes)]

    def add_options(self, parser):
        parser.add_argument("--results", type=Path, help="Public test evidence JSON")

    def setup_network(self):
        self.setup_nodes()
        for index in range(self.num_nodes):
            self.connect_nodes(index, (index + 1) % self.num_nodes)

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    def make(self, owner, *, templates=(), shares=(), transactions=(), fees=0):
        node = self.nodes[owner % self.num_nodes]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        signer = self.signers[owner]
        return candidate(genesis=self.genesis, native_parent=int(parent, 16), height=info["height"] + 1,
            ntime=max(self.start_time, info["time"] + 1), pool=self.pool, public_key=signer.public_key,
            sign_owner=signer.sign_owner, payout_script=self.scripts[owner], templates=templates, shares=shares,
            parent_snapshot=self.snapshots.get(parent), transactions=transactions, fees=fees,
            witness=bool(transactions))

    def publish_snapshot(self, snapshot, *, node=0):
        result = self.nodes[node].submitsharepoolhashsnapshot(snapshot.serialize().hex())
        assert_equal(result["hash"], snapshot.hash_hex)
        assert result["status"] in ("stored", "present")

    def converge(self, expected, *, label, timeout=300):
        began, deadline, next_log = time.monotonic(), time.monotonic() + timeout, 0
        while True:
            inventories = [set(node.getsharepoolhashstatus()["inventory"]) for node in self.nodes]
            missing = [len(expected - values) for values in inventories]
            if not any(missing):
                self.report["relay_stages"].append({"label": label, "expected_snapshots": len(expected),
                    "seconds": round(time.monotonic() - began, 3), "missing_by_node": missing})
                return
            now = time.monotonic()
            if now >= deadline:
                raise AssertionError(f"{label}: native snapshots did not converge: {missing}")
            if now >= next_log:
                self.log.info("%s: missing snapshots per native node %s", label, missing)
                next_log = now + 20
            time.sleep(0.2)

    def publish(self, block, snapshot, *, node=0, sync=True, solved=False):
        self.publish_snapshot(snapshot, node=node)
        if not solved:
            block.rehash()
            block.solve()
        assert_equal(self.nodes[node].submitblock(block.serialize().hex()), None)
        self.snapshots[block.hash] = snapshot
        if sync:
            self.sync_blocks(timeout=120)
            for peer in self.nodes:
                assert_equal(peer.getbestblockhash(), block.hash)
                assert_equal(peer.getblock(block.hash, 0), block.serialize().hex())
                stored = peer.getsharepoolhashsnapshot(snapshot.hash_hex)
                assert_equal(stored["data"], snapshot.serialize().hex())
        return winner_share(block, snapshot)

    def open_gate(self, owner):
        node = self.nodes[owner % self.num_nodes]
        return HashMiningGate(self.directory / f"miner-{owner:03d}.sqlite",
            rpc=lambda method, *args: getattr(node, method)(*args), pool=self.pool,
            public_key=self.signers[owner].public_key, payout_script=self.scripts[owner])

    def import_announcements(self, hashes, *, expected_receipts, label):
        began = time.monotonic()
        for owner, gate in enumerate(self.gates):
            node = self.nodes[owner % self.num_nodes]
            for identity in hashes:
                result = node.getsharepoolhashsnapshot(identity)
                raw = bytes.fromhex(result["data"])
                snapshot = Snapshot.deserialize(raw)
                assert_equal(snapshot.hash_hex, identity)
                gate.register_snapshot(raw)
                for record in snapshot.templates:
                    gate.register_template(record.data)
                for proof in snapshot.shares:
                    gate.receive(proof.serialize())
            assert_equal(gate.archive_head()["receipt_revision"], expected_receipts)
            if owner % 20 == 19:
                self.log.info("%s: full native admission and durable evidence at%d/100 gates", label, owner + 1)
        self.report["gate_stages"].append({"label": label, "seconds": round(time.monotonic() - began, 3),
            "acknowledged_receipts_each": expected_receipts})

    @staticmethod
    def spend(previous, index, value, redeem, script, fee):
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(previous, index), CScript(), 0xffffffff)]
        transaction.vout = [CTxOut(value - fee, CScript(script))]
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [bytes(redeem)]
        transaction.rehash()
        return transaction

    def check_payouts(self, block, snapshot, *, reward):
        counts = {}
        for proof in snapshot.shares:
            script = proof.envelope.payout_script
            counts[script] = counts.get(script, 0) + 1
        total = sum(counts.values())
        expected = {script: reward * count // total for script, count in counts.items()}
        priority = sorted(counts, key=lambda script: (-(reward * counts[script] % total), script))
        for script in priority[:reward - sum(expected.values())]:
            expected[script] += 1
        observed = {bytes(out.scriptPubKey): out.nValue for out in block.vtx[0].vout[:len(snapshot.payouts)]}
        assert_equal(observed, expected)
        assert_equal([output.serialize() for output in block.vtx[0].vout[:len(snapshot.payouts)]],
                     [output.serialize() for output in snapshot.payouts])
        assert_equal(sum(observed.values()), reward)
        assert all(b"SPN1" not in bytes(output.scriptPubKey) for output in block.vtx[0].vout)
        for miner, script in zip(self.report["miners"], self.scripts):
            miner["paid_satoshis"] += observed.get(script, 0)
        self.report["settlements"].append({"height": block.m_height, "block_hash": block.hash,
            "commitment": snapshot.hash_hex, "proofs": len(snapshot.shares), "payouts": len(observed),
            "reward_satoshis": reward, "exact_allocation_verified": True,
            "all100_jobs_authorized": True, "bypassed_gate": False})

    def save_report(self):
        if self.options.results:
            self.options.results.parent.mkdir(parents=True, exist_ok=True)
            self.options.results.write_text(json.dumps(self.report, indent=2) + "\n")

    def run_test(self):
        self.start_time = int(time.time())
        self.directory = Path(self.options.tmpdir) / "hash-logical-miners"
        self.directory.mkdir(mode=0o700)
        self.pool = 0x200decaf
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        self.signers, self.gates, self.snapshots = [], [], {}
        self.keys = [self.directory / f"owner-{owner:03d}.key" for owner in range(self.MINERS)]
        self.redeems = [CScript([owner, OP_DROP, OP_TRUE]) for owner in range(self.MINERS)]
        self.scripts = [b"\x00\x20" + hashlib.sha256(bytes(script)).digest() for script in self.redeems]
        self.report = {"schema": 4, "profile": "hash-only-v4", "started_utc": datetime.now(timezone.utc).isoformat(),
            "result": "running", "network": "isolated native regtest", "public_testnet": False,
            "logical_miners": 100, "native_nodes": 5, "hashing_threads": 8, "physical_miners_used": 0,
            "independent_share_count_ceiling": None, "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
            "max_dependency_bytes": MAX_DEPENDENCY_BYTES, "transport": "v2" if self.options.v2transport else "v1",
            "relay_stages": [], "gate_stages": [], "miners": [], "settlements": [],
            "honest_dispatch_pipeline_completed": False,
            "limitations": ["100 logical gates share five native nodes and eight CPU proof-search threads",
                "Loopback regtest timing does not measure WAN performance or physical hashrate",
                "The native block target and approved share target are both extremely easy",
                "Snapshot and dependency byte/depth limits remain; this test is not a capacity guarantee"]}
        self.report["native_binary_sha256"] = hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest()
        started = time.monotonic()
        try:
            self.log.info("Create100 fresh v4 native signer keys and distinct payout scripts")
            self.signers = [HashSigner.create(self.signer_binary, path, pool=self.pool, payout_script=self.scripts[owner])
                            for owner, path in enumerate(self.keys)]
            assert_equal(len({signer.public_key for signer in self.signers}), 100)
            assert_equal(len(set(self.scripts)), 100)

            self.log.info("Mature native funding and create100 independent UTXO spends")
            first, snapshot = self.make(0)
            self.publish(first, snapshot, sync=False)
            funding_coinbase = int(first.vtx[0].rehash(), 16)
            while self.nodes[0].getblockcount() < 101:
                block, snapshot = self.make(0)
                self.publish(block, snapshot, sync=False)
                # Funding setup is not a pending-block-queue pressure test.
                if block.m_height % 8 == 0:
                    self.sync_blocks(timeout=120)
            self.sync_blocks(timeout=120)
            shared_redeem = CScript([OP_TRUE])
            funding_script = b"\x00\x20" + hashlib.sha256(bytes(shared_redeem)).digest()
            funding_value = 49_999_990
            funding = self.spend(funding_coinbase, 0, 5_000_000_000, self.redeems[0], funding_script, 1000)
            funding.vout = [CTxOut(funding_value, CScript(funding_script)) for _ in range(100)]
            funding.rehash()
            block, snapshot = self.make(0, transactions=(funding,), fees=1000)
            self.publish(block, snapshot)
            assert_equal(self.nodes[0].getblockcount(), 102)
            funding_id = int(funding.rehash(), 16)
            self.transactions = [self.spend(funding_id, owner, funding_value, shared_redeem,
                self.scripts[owner], 100 + owner) for owner in range(100)]
            self.gates = [self.open_gate(owner) for owner in range(100)]
            connections = [[(peer["id"], peer["addr"]) for peer in node.getpeerinfo()] for node in self.nodes]

            self.log.info("Authorize and dispatch100 distinct full transaction templates before disclosure")
            origins, openings, initial_authorizations = [], [], []
            for owner in range(100):
                origin, opening = self.make(owner, transactions=(self.transactions[owner],), fees=100 + owner)
                authorization = self.gates[owner].authorize(origin.serialize(), opening.serialize())
                # Authorization validates through an ephemeral native overlay.
                # Announce only the snapshot whose job this miner accepted.
                self.gates[owner].register_snapshot(authorization.snapshot_bytes)
                assert self.gates[owner].ready_for_dispatch(authorization)
                origins.append(origin)
                openings.append(opening)
                initial_authorizations.append(authorization)
            assert_equal(len({template_id(origin) for origin in origins}), 100)
            assert_equal(len({origin.hashMerkleRoot for origin in origins}), 100)
            self.converge({opening.hash_hex for opening in openings}, label="100 origin snapshot dependencies")
            with ThreadPoolExecutor(max_workers=8) as workers:
                proofs = list(workers.map(lambda pair: solve_share(*pair), zip(origins, openings)))
            assert_equal(len({proof.proof_id for proof in proofs}), 100)
            announcements = []
            for owner, proof in enumerate(proofs):
                assert self.gates[owner].receive(proof)
                unused, announcement = self.make(owner, templates=(origins[owner],), shares=(proof,))
                self.publish_snapshot(announcement, node=owner % self.num_nodes)
                announcements.append(announcement.hash_hex)
                self.report["miners"].append({"miner_id": f"miner-{owner:03d}", "native_node": owner % 5,
                    "owner_public_key": self.signers[owner].public_key.hex(), "payout_script": self.scripts[owner].hex(),
                    "template_id": template_id(origins[owner]), "transaction_id": self.transactions[owner].rehash(),
                    "proof_id": f"{proof.proof_id:064x}", "initial_job_authorized": True,
                    "share_native_validated": True, "paid_satoshis": 0})
            self.converge(set(announcements), label="100 full origins and100 proofs in P2P snapshots")
            self.import_announcements(announcements, expected_receipts=100, label="100-proof baseline")
            for gate, authorization in zip(self.gates, initial_authorizations):
                assert_equal(len(gate.active_templates()), 100)
                assert_equal(len(gate.eligible_shares()), 100)
                assert gate.needs_refresh(authorization)
            self.gates[0].close()
            self.gates[0] = self.open_gate(0)
            assert_equal(self.gates[0].archive_head()["receipt_revision"], 100)
            self.report["restart_preserves100_acknowledgements"] = True
            assert_equal([[(peer["id"], peer["addr"]) for peer in node.getpeerinfo()] for node in self.nodes], connections)
            self.report["existing_connections_preserved"] = True
            self.report["peer_received_bytes_by_message"] = [{name: sum(peer.get("bytesrecv_per_msg", {}).get(name, 0)
                for peer in node.getpeerinfo()) for name in set().union(*(peer.get("bytesrecv_per_msg", {}).keys()
                for peer in node.getpeerinfo()))} for node in self.nodes]
            self.save_report()

            self.log.info("Every informed miner authorizes one complete100-proof settlement")
            jobs, authorizations = [], []
            fees = sum(100 + owner for owner in range(100))
            for transaction in self.transactions:
                self.nodes[0].sendrawtransaction(transaction.serialize().hex())
            self.sync_mempools(timeout=120)
            for owner in range(100):
                block, snapshot = self.gates[owner].make_native(sign_owner=self.signers[owner].sign_owner)
                assert_equal(len(block.vtx), 101)
                assert_equal(len(snapshot.shares), 100)
                authorization = self.gates[owner].authorize(block.serialize(), snapshot.serialize())
                self.gates[owner].register_snapshot(authorization.snapshot_bytes)
                assert self.gates[owner].ready_for_dispatch(authorization)
                jobs.append((block, snapshot))
                authorizations.append(authorization)
            block, snapshot = jobs[1]
            block.solve()
            frozen = block.serialize()
            assert_equal(authorizations[1].block_for_header(winner_share(block, snapshot).header_bytes), frozen)

            self.log.info("Late work refreshes future dispatch while the solved100-proof block stays immutable")
            late = solve_share(origins[0], openings[0], start_nonce=proofs[0].header.nNonce + 1)
            unused, announcement = self.make(0, templates=(origins[0],), shares=(late,))
            self.publish_snapshot(announcement)
            self.converge({announcement.hash_hex}, label="late proof after winning header was frozen")
            self.import_announcements([announcement.hash_hex], expected_receipts=101, label="late-proof refresh")
            for gate, authorization in zip(self.gates, authorizations):
                assert gate.needs_refresh(authorization)
                assert not gate.ready_for_dispatch(authorization)
            try:
                self.gates[1].authorize(block.serialize())
            except JobOmission as error:
                assert_equal(set(error.proof_ids), {f"{late.proof_id:064x}"})
            else:
                raise AssertionError("new authorization omitted late acknowledged work")
            assert_equal(block.serialize(), frozen)
            winning = self.publish(block, snapshot, node=1, solved=True)
            self.check_payouts(block, snapshot, reward=5_000_000_000 + fees)
            assert all(miner["paid_satoshis"] > 0 for miner in self.report["miners"])
            assert all([proof.proof_id for proof in gate.eligible_shares()] == [late.proof_id] for gate in self.gates)
            self.report["late_proof_preserved_after100_proof_settlement"] = True
            self.save_report()

            self.log.info("Carry late work and the winning proof into a second honestly authorized settlement")
            unused, announcement = self.make(1, templates=(block,), shares=(winning,))
            self.publish_snapshot(announcement, node=1)
            self.converge({announcement.hash_hex}, label="winning full origin and proof")
            self.import_announcements([announcement.hash_hex], expected_receipts=102, label="winner carry")
            for gate in self.gates:
                assert_equal({proof.proof_id for proof in gate.eligible_shares()}, {late.proof_id, winning.proof_id})
            carry_jobs = []
            for owner, gate in enumerate(self.gates):
                next_block, next_snapshot = gate.make_native(sign_owner=self.signers[owner].sign_owner)
                authorization = gate.authorize(next_block.serialize(), next_snapshot.serialize())
                gate.register_snapshot(authorization.snapshot_bytes)
                assert gate.ready_for_dispatch(authorization)
                assert_equal({proof.proof_id for proof in next_snapshot.shares}, {late.proof_id, winning.proof_id})
                carry_jobs.append((next_block, next_snapshot, authorization))
            next_block, next_snapshot, authorization = carry_jobs[0]
            next_block.solve()
            assert_equal(authorization.block_for_header(winner_share(next_block, next_snapshot).header_bytes), next_block.serialize())
            final_winner = self.publish(next_block, next_snapshot, solved=True)
            self.check_payouts(next_block, next_snapshot, reward=5_000_000_000)
            assert_equal({bytes(out.scriptPubKey): out.nValue for out in next_snapshot.payouts},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            assert all(not gate.eligible_shares() for gate in self.gates)
            assert self.gates[0].receive(final_winner)
            assert_equal([proof.proof_id for proof in self.gates[0].eligible_shares()], [final_winner.proof_id])
            self.report.update({"result": "passed", "honest_dispatch_pipeline_completed": True,
                "all100_original_proofs_paid_in_one_snapshot": True, "late_proof_and_winner_paid_next_block": True,
                "credited_proofs": 102, "gate_bypasses": 0, "solved_commitments_modified": False,
                "settlements_constructed_by_native_builder": True,
                "last_winner_durably_pending": True, "mainnet_activation_changed": False})
            self.log.info("100-miner hash-only pipeline passed:100 exact payouts, then late proof and winner paid")
        except BaseException as error:
            self.report["result"], self.report["failure"] = "failed", f"{type(error).__name__}: {error}"
            raise
        finally:
            for gate in self.gates:
                gate.close()
            for path in self.keys:
                if path.exists():
                    path.unlink()
            self.report["native_owner_keys_removed"] = not any(path.exists() for path in self.keys)
            self.report["seconds"] = round(time.monotonic() - started, 3)
            self.report["finished_utc"] = datetime.now(timezone.utc).isoformat()
            self.save_report()


if __name__ == "__main__":
    SharePoolHash100MinersTest(__file__).main()
