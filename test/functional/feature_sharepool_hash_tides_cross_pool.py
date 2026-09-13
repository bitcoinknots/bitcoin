#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A v6 gate relays another pool's proof; only its original pool pays it later."""

from dataclasses import replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, MAX_SHARE_AGE, TIDES_VERSION
from feature_sharepool_hash_tides import SharePoolHashTidesTest
from test_framework.util import assert_equal, assert_raises


class SharePoolHashTidesCrossPoolTest(SharePoolHashTidesTest):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-sharepoolhashonly=1", "-sharepooltides=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(2)]

    def add_options(self, parser):
        pass

    def open_gate(self, path, index, signer):
        return HashMiningGate(path, rpc=lambda method, *args: getattr(self.nodes[index], method)(*args),
            pool=signer.pool, public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=TIDES_VERSION)

    def gate_job(self, index, gate, signer):
        block, snapshot = gate.make_native(sign_owner=signer.sign_owner)
        authorization = gate.authorize(block.serialize(), snapshot.serialize())
        assert gate.ready_for_dispatch(authorization)
        assert_equal(authorization.block_bytes, block.serialize())
        assert_equal(authorization.snapshot_bytes, snapshot.serialize())
        gate.register_snapshot(snapshot.serialize())
        return block, snapshot, authorization

    def run_test(self):
        node, follower = self.nodes
        self.genesis = int(node.getblockhash(0), 16)
        directory = Path(self.options.tmpdir) / "cross-pool-gates"
        directory.mkdir(mode=0o700)
        keys, gates = [], []
        recipient_a = b"\x00\x14" + b"a" * 20
        recipient_b = b"\x00\x14" + b"b" * 20
        recipient_new_a = b"\x00\x14" + b"c" * 20
        try:
            signers = []
            for number, (pool, script) in enumerate(((101, recipient_a), (202, recipient_b), (101, recipient_new_a))):
                path = directory / f"owner-{number}.key"
                signers.append(HashSigner.create(self.signer_binary, path, pool=pool, payout_script=script))
                keys.append(path)
            a, b, later_a = signers
            origin, opening, proof = self.origin(0, a)
            # An unsigned inventory listing is not authority. Publish the full
            # signed proposal opening, then let B validate the enclosed proof's
            # original job locally after normal P2P delivery. No block is mined.
            _, offered, _ = self.construct(0, a, templates=(origin,), shares=(proof,))
            self.store(0, offered)
            self.connect_nodes(0, 1)
            self.wait_until(lambda: {offered.hash_hex, opening.hash_hex}.issubset(
                follower.getsharepoolhashstatus()["inventory"]))
            gate_b = self.open_gate(directory / "pool-b.sqlite", 1, b)
            gates.append(gate_b)
            before = gate_b.archive_head()
            altered = replace(proof, envelope=replace(proof.envelope, pool=b.pool))
            assert_raises(ValueError, gate_b.receive, altered)
            assert_equal(gate_b.archive_head(), before)
            self.log.info("Pool B ingests A's unmined proposal through bounded native P2P inventory")
            imported = gate_b.sync_native_receipts(limit=16)
            self.log.info("Bounded inventory ingestion: %s", imported)
            assert_equal(imported["accepted"], [f"{proof.proof_id:064x}"])
            assert_equal(imported["deferred"], [])
            assert_equal(gate_b.eligible_shares(), (proof,))

            self.log.info("Restore a foreign-pool ACK from its protected archive and revalidate its native origin")
            export = directory / "pool-b.archive"
            trusted = gate_b.export_archive(export)
            gate_b.close()
            gate_b = HashMiningGate.restore_archive([export], directory / "pool-b-restored.sqlite",
                trusted_head=trusted, rpc=lambda method, *args: getattr(follower, method)(*args),
                pool=b.pool, public_key=b.public_key, payout_script=b.payout_script, profile_version=TIDES_VERSION)
            gates.append(gate_b)
            assert_equal(gate_b.archive_head(), trusted)
            assert_equal(gate_b.eligible_shares(), (proof,))
            status = gate_b.receipt_status()["receipts"][0]
            assert_equal(status["pool"], f"{a.pool:064x}")
            assert_equal(status["payout_script"], recipient_a.hex())

            self.log.info("Pool B's native block admits A's proof without paying A from B's reward")
            anchored, state, authorization = self.gate_job(0, gate_b, b)
            assert_equal(state.envelope.pool, b.pool)
            assert_equal(state.shares, (proof,))
            assert_equal(self.payouts(anchored), {recipient_b: 5_000_000_000})
            self.publish(0, anchored, state)
            self.wait_tip(anchored)
            assert not gate_b.ready_for_dispatch(authorization)
            assert_equal(follower.getsharepoolhashsnapshot(state.hash_hex)["data"], state.serialize().hex())
            assert_equal(follower.getsharepoolhashsnapshot(opening.hash_hex)["data"], opening.serialize().hex())

            for _ in range(MAX_SHARE_AGE + 1):
                block, state, _ = self.gate_job(0, gate_b, b)
                assert_equal(state.shares, ())
                assert_equal(self.payouts(block), {recipient_b: 5_000_000_000})
                self.publish(0, block, state)
                self.wait_tip(block)
            assert node.getblockcount() + 1 - proof.envelope.height > MAX_SHARE_AGE
            assert_equal(state.post_state, ())
            status = gate_b.receipt_status()["receipts"][0]
            assert_equal(status["status"], "confirmed_admitted")
            assert_equal(status["admitted_in"], anchored.hash)
            assert_equal(status["pool"], f"{a.pool:064x}")

            self.log.info("After origin admission expiry and peer restart, A's later block pays its old recipient")
            self.restart_node(1)
            self.connect_nodes(0, 1)
            self.wait_tip(block)
            gate_a = self.open_gate(directory / "pool-a-later.sqlite", 1, later_a)
            gates.append(gate_a)
            paying, paying_state, _ = self.gate_job(1, gate_a, later_a)
            assert_equal(paying_state.shares, ())
            assert_equal(paying_state.envelope.payout_script, recipient_new_a)
            assert_equal(self.payouts(paying), {recipient_a: 5_000_000_000})
            self.publish(1, paying, paying_state)
            self.wait_tip(paying)
            assert node.verifychain(4, 0)
            assert follower.verifychain(4, 0)
        finally:
            for gate in gates:
                gate.close()
            for path in keys:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashTidesCrossPoolTest(__file__).main()
