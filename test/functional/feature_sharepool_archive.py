#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native deep rollback restores acknowledged work from complete sealed history.

One disposable enforcing regtest node, two fresh native owner keys, and local
archives are used. The rollback is administrative, not a competing P2P chain.
No hardware, public service or mainnet activation participates.
"""

import hashlib
from pathlib import Path
import sqlite3
import sys
import time
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import candidate, parse_coinbase, solve_share
from native_mining_gate import JobOmission, NativeMiningGate, RecoveryRequired
from native_signer import NativeSigner
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolArchiveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built on this platform")

    def rpc(self, method, *params):
        return getattr(self.nodes[0], method)(*params)

    def gate_arguments(self, rpc=None):
        return {"rpc": self.rpc if rpc is None else rpc, "pool": self.pool,
                "public_key": self.signers[0].public_key, "payout_script": self.scripts[0]}

    def make(self, owner=0, *, shares=()):
        node = self.nodes[0]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        self.clock += 1
        signer = self.signers[owner]
        return candidate(genesis=self.genesis, native_parent=int(parent, 16),
            height=info["height"] + 1, ntime=max(self.clock, info["time"] + 1), pool=self.pool,
            public_key=signer.public_key, sign_owner=signer.sign_owner,
            payout_script=self.scripts[owner], shares=shares,
            parent_manifest=self.manifests.get(parent))

    def publish(self, block, manifest):
        block.rehash()
        block.solve()
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), None)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)
        self.manifests[block.hash] = manifest
        return block.hash

    @staticmethod
    def database_state(path):
        """Logical rows, not SQLite page/WAL representation, detect partial edits."""
        with sqlite3.connect(str(path)) as db:
            tables = sorted(row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
            result = {}
            for table in tables:
                assert all(c.isalnum() or c == "_" for c in table)
                rows = db.execute('SELECT * FROM "' + table + '"').fetchall()
                def canonical(row):
                    return tuple(("blob", len(value), hashlib.sha256(value).hexdigest())
                                 if isinstance(value, bytes) else (type(value).__name__, value)
                                 for value in row)
                result[table] = sorted((canonical(row) for row in rows), key=repr)
            return result

    @staticmethod
    def fail(action, description):
        try:
            opened = action()
        except (ValueError, OSError, RuntimeError):
            return
        if isinstance(opened, NativeMiningGate):
            opened.close()
        raise AssertionError(description)

    def run_test(self):
        node = self.nodes[0]
        self.directory = Path(self.options.tmpdir) / "private-archive-fixtures"
        self.directory.mkdir(mode=0o700)
        self.pool, self.genesis = 0xabc123, int(node.getblockhash(0), 16)
        self.clock = int(time.time())
        self.manifests = {}
        self.scripts = (b"\x00\x14" + b"A" * 20, b"\x00\x14" + b"B" * 20)
        self.signers = tuple(NativeSigner.create(self.signer_binary, self.directory / f"owner-{index}.key",
            pool=self.pool, payout_script=script) for index, script in enumerate(self.scripts))
        assert self.signers[0].public_key != self.signers[1].public_key
        gate_path = self.directory / "gate.sqlite"
        stale_export, complete_export = self.directory / "stale.archive", self.directory / "complete.archive"
        gate = NativeMiningGate(gate_path, **self.gate_arguments())
        restored = None
        try:
            self.log.info("Seal two distinct height-one origins and acknowledged native proofs")
            first_origin, first_manifest = self.make(0)
            gate.register_template(first_origin.serialize())
            proof_a = solve_share(first_origin, first_manifest)
            assert_equal(gate.receive(proof_a.serialize()), True)
            stale_head = gate.export_archive(stale_export)
            assert_equal(stale_head["receipt_revision"], 1)
            second_origin, second_manifest = self.make(1)
            gate.register_template(second_origin.serialize())
            proof_b = solve_share(second_origin, second_manifest)
            assert_equal(gate.receive(proof_b.serialize()), True)
            expected_proofs = {f"{proof.proof_id:064x}" for proof in (proof_a, proof_b)}

            settlement, settlement_manifest = self.make(shares=(proof_a, proof_b))
            gate.authorize(settlement.serialize())
            first_settlement = self.publish(settlement, settlement_manifest)
            self.log.info("Advance to height 162 and prune both original receipts from the hot cache")
            while node.getblockcount() < 162:
                block, manifest = self.make()
                gate.authorize(block.serialize())
                self.publish(block, manifest)
                if block.m_height % 40 == 0:
                    self.log.info("Native archive chain reached height %d", block.m_height)
            state = gate.maintenance()
            assert_equal(state["anchor_height"], 18)
            assert_equal(state["revision"], 2)
            assert_equal(gate.db.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)
            assert_equal(gate.db.execute("SELECT count(*) FROM templates WHERE origin_height=1").fetchone()[0], 0)
            trusted_head = gate.export_archive(complete_export)
            assert_equal(trusted_head, gate.archive_head())
            assert_equal(trusted_head["receipt_revision"], 2)
            assert trusted_head["events"] > stale_head["events"]

            self.log.info("A 162-block administrative rollback makes those pruned proofs eligible again")
            node.invalidateblock(first_settlement)
            assert_equal(node.getblockcount(), 0)
            try:
                gate.maintenance()
                raise AssertionError("deep rollback silently cleared the known-work basis")
            except RecoveryRequired:
                pass
            gate.close()
            gate = None
            before_recovery = self.database_state(gate_path)
            self.fail(lambda: NativeMiningGate(gate_path, **self.gate_arguments()),
                      "normal restart cleared the recovery requirement")

            self.log.info("Missing, stale, wrong-head and truncated exports cannot publish a restored gate")
            truncated = self.directory / "truncated.archive"
            complete = complete_export.read_bytes()
            truncated.write_bytes(complete[:-1])
            wrong_head = dict(trusted_head)
            wrong_head["root"] = "00" * 32 if trusted_head["root"] != "00" * 32 else "11" * 32
            for name, archive, head in (
                    ("missing", self.directory / "absent.archive", trusted_head),
                    ("stale", stale_export, trusted_head),
                    ("wrong-head", complete_export, wrong_head),
                    ("truncated", truncated, trusted_head)):
                destination = self.directory / (name + ".sqlite")
                self.fail(lambda: NativeMiningGate.restore_archive(archive, destination,
                    trusted_head=head, **self.gate_arguments()), f"{name} archive was accepted")
                assert not destination.exists(), f"{name} restore published a partial database"
                assert_equal(self.database_state(gate_path), before_recovery)

            self.log.info("A native validation failure midway through recovery preserves the old latched cache")
            validated = []
            def partial_failure(method, *params):
                if method == "validatesharepooltemplate":
                    validated.append(params[0])
                    if len(validated) == 2:
                        raise RuntimeError("deliberate native validation interruption")
                return self.rpc(method, *params)
            self.fail(lambda: NativeMiningGate.recover_archive(gate_path,
                **self.gate_arguments(rpc=partial_failure)), "interrupted native recovery was accepted")
            assert_equal(len(validated), 2)
            assert_equal(self.database_state(gate_path), before_recovery)
            self.fail(lambda: NativeMiningGate(gate_path, **self.gate_arguments()),
                      "failed recovery permitted ordinary admission")

            self.log.info("A complete export plus separately trusted head restores all eligible acknowledged proofs")
            # Retry the same destination after the truncated restore failed;
            # a staging artifact must not prevent a correct subsequent import.
            offsite_path = self.directory / "truncated.sqlite"
            restored = NativeMiningGate.restore_archive(complete_export, offsite_path,
                trusted_head=trusted_head, **self.gate_arguments())
            recovered = {item["id"] for item in restored.active_inventory()["items"] if item["kind"] == "receipt"}
            assert_equal(recovered, expected_proofs)
            assert_equal(restored.archive_head(), trusted_head)
            restored.close()
            restored = None

            gate = NativeMiningGate.recover_archive(gate_path, **self.gate_arguments())
            assert_equal({item["id"] for item in gate.active_inventory()["items"] if item["kind"] == "receipt"}, expected_proofs)
            recovered_state = gate.maintenance()
            assert_equal(recovered_state["height"], 0)
            assert_equal(recovered_state["revision"], 2)
            gate.close()
            gate = NativeMiningGate(gate_path, **self.gate_arguments())
            assert_equal(gate.maintenance(), recovered_state)

            self.log.info("Recovered work remains mandatory locally and settles to the original exact payout scripts")
            omitted, _ = self.make(shares=(proof_a,))
            try:
                gate.authorize(omitted.serialize())
                raise AssertionError("recovered proof could be silently omitted")
            except JobOmission as error:
                assert_equal(set(error.proof_ids), {f"{proof_b.proof_id:064x}"})
            final, final_manifest = self.make(shares=(proof_a, proof_b))
            authorization = gate.authorize(final.serialize())
            assert_equal(authorization.block_bytes, final.serialize())
            final_hash = self.publish(final, final_manifest)
            assert final_hash != first_settlement
            outputs = parse_coinbase(final.vtx[0])[1]
            assert_equal({bytes(output.scriptPubKey): output.nValue for output in outputs},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            gate.close()
            gate = NativeMiningGate(gate_path, **self.gate_arguments())
            assert_equal(gate.maintenance()["revision"], 2)
            assert_equal(gate.receive(proof_b.serialize()), False)
            replay, _ = self.make(shares=(proof_a, proof_b))
            replay.solve()
            assert_equal(node.submitblock(replay.serialize().hex()), "bad-sharepool-shares")
            assert_equal(node.getbestblockhash(), final_hash)
            self.log.info("Native archive recovery passed: two pruned proofs restored and paid once on the replacement chain")
        finally:
            if restored is not None:
                restored.close()
            if gate is not None:
                gate.close()
            for index in range(2):
                key_file = self.directory / f"owner-{index}.key"
                if key_file.exists():
                    key_file.unlink()


if __name__ == "__main__":
    SharePoolArchiveTest(__file__).main()
