#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native pool evidence, durable gates and payouts over existing Bitcoin P2P."""
from pathlib import Path
import sys
import time
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import candidate, parse_coinbase, solve_share, winner_share
from native_mining_gate import JobOmission, NativeMiningGate
from native_node_peer import NativeNodeRelay
from native_signer import NativeSigner
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SharePoolNodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for unused in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built on this platform")

    def open_gate(self, index, name):
        signer = self.signers[index]
        def call(method, *args):
            return getattr(self.nodes[index], method)(*args)
        gate = NativeMiningGate(self.directory / name, rpc=call, pool=self.pool,
            public_key=signer.public_key, payout_script=self.scripts[index])
        self.gates.append(gate)
        return gate

    def make(self, index, shares=()):
        node, signer = self.nodes[index], self.signers[index]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16), height=info["height"] + 1,
            ntime=max(int(time.time()), info["time"] + 1), pool=self.pool,
            public_key=signer.public_key, sign_owner=signer.sign_owner,
            payout_script=self.scripts[index], shares=shares, parent_manifest=self.manifests.get(parent))

    def settle(self, index, block, manifest):
        block.rehash()
        block.solve()
        assert_equal(self.nodes[index].submitblock(block.serialize().hex()), None)
        self.sync_blocks()
        self.manifests[block.hash] = manifest
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), block.hash)
            assert_equal(node.getblock(block.hash, 0), block.serialize().hex())
        return winner_share(block, manifest)

    def wait_inventory(self, node, identities):
        self.wait_until(lambda: identities <= {
            item["id"] for item in node.getsharepoolinventory()["items"]}, timeout=90)

    def run_test(self):
        self.directory = Path(self.options.tmpdir) / "native-evidence-fixtures"
        self.directory.mkdir(mode=0o700)
        self.pool, self.genesis = 0xdecaf123, int(self.nodes[0].getblockhash(0), 16)
        self.scripts = [b"\x00\x14" + bytes([81 + index]) * 20 for index in range(3)]
        self.key_files = [self.directory / f"owner-{index}.key" for index in range(3)]
        self.signers, self.gates, self.manifests = [], [], {}
        try:
            self.signers = [NativeSigner.create(self.signer_binary, key_file, pool=self.pool,
                payout_script=self.scripts[index]) for index, key_file in enumerate(self.key_files)]
            assert_equal(len({signer.public_key for signer in self.signers}), 3)
            connections = [[(p["id"], p["addr"]) for p in node.getpeerinfo()] for node in self.nodes]
            assert all(connections)
            a, b, c = [self.open_gate(index, f"gate-{index}.sqlite") for index in range(3)]
            bridges = [NativeNodeRelay(gate) for gate in (a, b, c)]
            self.log.info("Publish distinct signed origins and proofs through each existing native node")
            origin_a, manifest_a = self.make(0)
            origin_b, manifest_b = self.make(1)
            a.register_template(origin_a.serialize())
            b.register_template(origin_b.serialize())
            proof_a, proof_b = solve_share(origin_a, manifest_a), solve_share(origin_b, manifest_b)
            a.receive(proof_a.serialize())
            b.receive(proof_b.serialize())
            bridges[0].poll()
            bridges[1].poll()
            proofs = {f"{proof.proof_id:064x}" for proof in (proof_a, proof_b)}
            for node in self.nodes:
                self.wait_inventory(node, proofs)
            for bridge in bridges:
                bridge.poll()
            for gate in (a, b, c):
                assert_equal({item["id"] for item in gate.active_inventory()["items"]
                              if item["kind"] == "receipt"}, proofs)
            assert_equal([[ (p["id"], p["addr"]) for p in node.getpeerinfo()]
                          for node in self.nodes], connections)
            for node in self.nodes:
                assert sum(p.get("bytesrecv_per_msg", {}).get("spndata", 0)
                           for p in node.getpeerinfo()) > 0

            self.log.info("Known omissions remain miner policy; exact direct payouts enter native blocks")
            try:
                a.authorize(origin_a.serialize())
                raise AssertionError("known eligible work was omitted")
            except JobOmission as error:
                assert_equal(set(error.proof_ids), proofs)
            block, manifest = self.make(0, (proof_a, proof_b))
            authorization = a.authorize(block.serialize())
            assert a.ready_for_dispatch(authorization)
            bridges[0].poll()
            winning_proof = self.settle(0, block, manifest)
            assert_equal({bytes(output.scriptPubKey): output.nValue for output in parse_coinbase(block.vtx[0])[1]},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            a.receive(winning_proof.serialize())
            bridges[0].poll()

            self.log.info("A restarted native peer and fresh gate recover recent full origins over the same P2P protocol")
            c.close()
            self.restart_node(2)
            self.connect_nodes(2, 1)
            self.sync_blocks()
            c = self.open_gate(2, "cold-gate.sqlite")
            bridges[2] = NativeNodeRelay(c)
            late = solve_share(origin_b, manifest_b, start_nonce=proof_b.header.nNonce + 1)
            assert late.proof_id != proof_b.proof_id
            b.receive(late.serialize())
            bridges[1].poll()
            all_proofs = proofs | {f"{proof.proof_id:064x}" for proof in (winning_proof, late)}
            self.wait_inventory(self.nodes[2], all_proofs)
            imported = bridges[2].poll()
            assert imported["templates"] >= 3
            assert_equal(imported["receipts"], 4)
            revision = c.maintenance()["revision"]
            assert_equal(bridges[2].poll()["receipts"], 0)
            assert_equal(c.maintenance()["revision"], revision)

            self.log.info("Recovered winner and late work pay the original scripts exactly once")
            replacement, next_manifest = self.make(2, (winning_proof, late))
            c.authorize(replacement.serialize())
            final_winner = self.settle(2, replacement, next_manifest)
            assert final_winner.proof_id not in {share.proof_id for share in next_manifest.shares}
            assert_equal({bytes(output.scriptPubKey): output.nValue for output in parse_coinbase(replacement.vtx[0])[1]},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            c.close()
            c = self.open_gate(2, "cold-gate.sqlite")
            assert_equal(c.maintenance()["revision"], revision)
            assert_equal({item["id"] for item in c.active_inventory()["items"]
                          if item["kind"] == "receipt"}, all_proofs)
            self.log.info("Three-node evidence/settlement integration passed; no separate transport service was used")
        finally:
            for gate in self.gates:
                gate.close()
            for key_file in self.key_files:
                if key_file.exists():
                    key_file.unlink()


if __name__ == "__main__":
    SharePoolNodeTest(__file__).main()
