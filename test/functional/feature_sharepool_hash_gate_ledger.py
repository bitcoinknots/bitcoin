#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native v5 gate: provisional ACK, archive recovery, anchor, late pay, reorg."""
from contextlib import ExitStack
from pathlib import Path
import sys
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner, solve_share
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolHashGateLedgerTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, choices=(1, 102), default=1)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[f"-sharepoolheight={self.options.activation_height}", "-sharepoolhashonly=1", "-sharepooladmittedledger=1",
                            "-testactivationheight=blake2b@1", "-disablewallet"] for _ in range(2)]

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    @staticmethod
    def rpc(node):
        return lambda method, *args: getattr(node, method)(*args)

    @staticmethod
    def status(gate):
        return gate.receipt_status()["receipts"][0]

    def publish(self, node, gate, signer):
        block, opening = gate.make_native(sign_owner=signer.sign_owner)
        gate.authorize(block.serialize(), opening.serialize())
        gate.register_snapshot(opening.serialize())
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), block.hash)
        return block, opening

    def run_test(self):
        source, follower = self.nodes
        directory = Path(self.options.tmpdir)
        if self.options.activation_height > 1:
            self.connect_nodes(0, 1)
            self.generatetoaddress(source, self.options.activation_height - 1, ADDRESS_BCRT1_UNSPENDABLE)
            self.sync_blocks()
            self.disconnect_nodes(0, 1)
        for node in self.nodes:
            assert_equal(node.getblockcount(), self.options.activation_height - 1)
            assert_equal(node.getsharepoolhashstatus()["activation_height"], self.options.activation_height)
        with ExitStack() as cleanup:
            signers = []
            for index, pool in enumerate((3, 3, 9)):
                path = directory / f"gate-ledger-key-{index}"
                signer = HashSigner.create(self.signer_binary, path, pool=pool,
                    payout_script=b"\x00\x14" + bytes([index + 1]) * 20)
                signers.append(signer)
            miner, coordinator, other = signers
            def options(signer):
                return dict(pool=signer.pool, public_key=signer.public_key,
                            payout_script=signer.payout_script, profile_version=5, activation_height=self.options.activation_height)
            def gate(name, signer, node=source):
                return cleanup.enter_context(HashMiningGate(directory / f"{name}.sqlite", rpc=self.rpc(node), **options(signer)))
            miner_gate = gate("miner", miner)
            main_gate = gate("coordinator", coordinator)
            other_gate = gate("other-pool", other)
            self.log.info("Real native job and share become a durable provisional ACK, with no promise of payment")
            origin, opening = miner_gate.make_native(sign_owner=miner.sign_owner)
            miner_gate.authorize(origin.serialize(), opening.serialize())
            miner_gate.register_snapshot(opening.serialize())
            main_gate.register_template(origin.serialize())
            proof = solve_share(origin, opening)
            assert_equal(main_gate.receive(proof), True)
            assert_equal(self.status(main_gate)["status"], "provisional")
            archive = directory / "provisional.spharc"
            head = main_gate.export_archive(archive)
            assert_equal(follower.getsharepoolhashstatus()["stored_snapshots"], 0)
            restored = cleanup.enter_context(HashMiningGate.restore_archive([archive], directory / "recovered.sqlite",
                trusted_head=head, rpc=self.rpc(follower), **options(coordinator)))
            assert_equal(restored.receive(proof), False)
            assert_equal(self.status(restored)["status"], "provisional")

            self.log.info("The actual anchor confirms pending credit; its coinbase still pays its own fallback")
            anchor, snapshot = self.publish(source, main_gate, coordinator)
            assert_equal(snapshot.settled, ())
            assert_equal([credit.proof_id for credit in snapshot.pending], [proof.proof_id])
            assert_equal(bytes(anchor.vtx[0].vout[0].scriptPubKey), coordinator.payout_script)
            assert_equal(self.status(main_gate)["status"], "confirmed_pending")
            self.connect_nodes(0, 1)
            self.sync_blocks()
            assert_equal(self.status(restored)["status"], "confirmed_pending")

            self.log.info("Other pools carry confirmed credit beyond the original proof age without paying or dropping it")
            for unused in range(5):
                block, snapshot = self.publish(source, other_gate, other)
                self.sync_blocks()
                assert_equal([credit.proof_id for credit in snapshot.pending], [proof.proof_id])
                assert_equal(self.status(restored)["status"], "confirmed_pending")
            paid, snapshot = self.publish(source, main_gate, coordinator)
            self.sync_blocks()
            assert_equal(snapshot.pending, ())
            assert_equal([credit.proof_id for credit in snapshot.settled], [proof.proof_id])
            assert_equal(bytes(paid.vtx[0].vout[0].scriptPubKey), miner.payout_script)
            assert_equal(paid.vtx[0].vout[0].nValue, 5_000_000_000)
            assert_equal(self.status(restored)["status"], "settled")
            assert_equal(self.status(restored)["settled_in"], paid.hash)
            self.publish(source, other_gate, other)
            self.sync_blocks()
            assert_equal(self.status(restored)["settled_in"], paid.hash)

            self.log.info("Canonical reorg status restores pending credit; reconsideration restores the actual payment")
            self.disconnect_nodes(0, 1)
            follower.invalidateblock(paid.hash)
            assert_equal(self.status(restored)["status"], "confirmed_pending")
            assert_equal(self.status(restored)["settled_in"], None)
            follower.reconsiderblock(paid.hash)
            assert_equal(self.status(restored)["status"], "settled")
            assert_equal(self.status(restored)["settled_in"], paid.hash)
            for node in self.nodes:
                assert_equal(node.verifychain(4, 0), True)


if __name__ == "__main__":
    SharePoolHashGateLedgerTest(__file__).main()
