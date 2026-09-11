#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native signer, durable miner gates, HTTP evidence and native P2P integration.

Uses fresh native signing keys, three local gate services and two enforcing
regtest nodes. No public network, existing credentials or physical miner.
"""
from pathlib import Path
import sys
import time
from unittest import SkipTest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))

from native_enforcement import candidate, parse_coinbase, solve_share, winner_share
from native_mining_gate import JobOmission, NativeMiningGate, RecoveryRequired
from native_peer import NativePeerService, PeerClient, PeerReplicator, PeerUnavailable, sync_peer
from native_signer import NativeSigner
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy


class SharePoolPeerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-sharepoolheight=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built on this platform")

    def open_service(self, index):
        node = self.nodes[min(index, 1)]
        signer, script = self.signers[index], self.scripts[index]
        def factory():
            rpc = get_rpc_proxy(node.url, 50 + index, timeout=5)
            def call(method, *params):
                self.rpc_methods[index].append(method)
                return getattr(rpc, method)(*params)
            return NativeMiningGate(self.directory / f"gate-{index}.sqlite", rpc=call,
                pool=self.pool, public_key=signer.public_key, payout_script=script)
        service = NativePeerService(factory)
        self.services[index] = service
        return service

    def make(self, index, *, shares=()):
        node, signer = self.nodes[0], self.signers[index]
        parent = node.getbestblockhash()
        info = node.getblockheader(parent)
        return candidate(genesis=self.genesis, native_parent=int(parent, 16), height=info["height"] + 1,
            ntime=max(int(time.time()), info["time"] + 1), pool=self.pool,
            public_key=signer.public_key, sign_owner=signer.sign_owner,
            payout_script=self.scripts[index], shares=shares, parent_manifest=self.manifests.get(parent))

    def publish(self, block, manifest):
        block.rehash()
        block.solve()
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), None)
        self.sync_blocks()
        self.manifests[block.hash] = manifest
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), block.hash)
        return winner_share(block, manifest)

    def run_test(self):
        self.directory = Path(self.options.tmpdir) / "private-peer-fixtures"
        self.directory.mkdir(mode=0o700)
        self.pool, self.genesis = 0xabc123, int(self.nodes[0].getblockhash(0), 16)
        self.scripts = [b"\x00\x14" + bytes([65 + i]) * 20 for i in range(3)]
        self.signers = [NativeSigner.create(self.signer_binary, self.directory / f"owner-{i}.key",
            pool=self.pool, payout_script=self.scripts[i]) for i in range(3)]
        assert_equal(len({s.public_key for s in self.signers}), 3)
        self.services, self.manifests, self.rpc_methods = {}, {}, [[], [], []]
        try:
            self.log.info("Exchange distinct full templates and native-signed work through HTTP peers")
            a, b = self.open_service(0), self.open_service(1)
            origin_a, manifest_a = self.make(0)
            origin_b, manifest_b = self.make(1)
            assert origin_a.m_mm_rhs != origin_b.m_mm_rhs
            a.local("register_template", origin_a.serialize())
            b.local("register_template", origin_b.serialize())
            assert_equal(sync_peer(a, b.url, self.pool)["templates"], 1)
            assert_equal(sync_peer(b, a.url, self.pool)["templates"], 1)
            proof_a, proof_b = solve_share(origin_a, manifest_a), solve_share(origin_b, manifest_b)
            a.local("receive", proof_a.serialize())
            b.local("receive", proof_b.serialize())
            assert_equal(sync_peer(a, b.url, self.pool)["receipts"], 1)
            assert_equal(sync_peer(b, a.url, self.pool)["receipts"], 1)
            try:
                a.local("authorize", origin_a.serialize())
                raise AssertionError("omitting both known proofs was accepted")
            except JobOmission as error:
                assert_equal(len(error.proof_ids), 2)

            self.log.info("Settle the two owners directly and relay the actual block through native P2P")
            block, manifest = self.make(0, shares=(proof_a, proof_b))
            authorization = a.local("authorize", block.serialize())
            assert_equal(authorization.block_bytes, block.serialize())
            sync_peer(b, a.url, self.pool)
            winner = self.publish(block, manifest)
            outputs = parse_coinbase(block.vtx[0])[1]
            assert_equal({bytes(o.scriptPubKey): o.nValue for o in outputs},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            a.local("receive", winner.serialize())

            self.log.info("Late old-template work survives service restart and is shared with the next miner")
            late = solve_share(origin_b, manifest_b, start_nonce=proof_b.header.nNonce + 1)
            assert late.proof_id != proof_b.proof_id
            b.local("receive", late.serialize())
            before = b.local("active_inventory")
            b.close()
            b = self.open_service(1)
            after = b.local("active_inventory")
            assert_equal(after["revision"], before["revision"])
            assert_equal(after["items"], before["items"])

            self.log.info("A fresh gate recovers historical full origin bodies without rewinding the chain")
            c = self.open_service(2)
            assert_equal(c.local("active_inventory")["items"], [])
            tip = self.nodes[1].getbestblockhash()
            original_object = PeerClient.object
            def withhold_receipts(client, item):
                if item["kind"] == "receipt":
                    raise PeerUnavailable("deliberate test withholding")
                return original_object(client, item)
            with patch.object(PeerClient, "object", withhold_receipts):
                try:
                    sync_peer(c, a.url, self.pool)
                    raise AssertionError("withheld evidence reported complete")
                except PeerUnavailable:
                    pass
            partial = c.local("active_inventory")
            assert partial["items"] and all(i["kind"] == "template" for i in partial["items"])
            assert_equal(self.nodes[1].getbestblockhash(), tip)
            sync_peer(c, a.url, self.pool)
            sync_peer(c, b.url, self.pool)
            assert self.rpc_methods[2].count("validatesharepooltemplate") >= 3
            assert_equal({i["id"] for i in c.local("active_inventory")["items"] if i["kind"] == "receipt"},
                         {f"{p.proof_id:064x}" for p in (proof_a, proof_b, winner, late)})

            self.log.info("Recovered work and the prior winner settle once under a third native signer")
            next_block, next_manifest = self.make(2, shares=(winner, late))
            c.local("authorize", next_block.serialize())
            final_winner = self.publish(next_block, next_manifest)
            assert_equal({s.proof_id for s in next_manifest.shares}, {winner.proof_id, late.proof_id})
            assert final_winner.proof_id not in {s.proof_id for s in next_manifest.shares}
            next_outputs = parse_coinbase(next_block.vtx[0])[1]
            assert_equal({bytes(o.scriptPubKey): o.nValue for o in next_outputs},
                         {self.scripts[0]: 2_500_000_000, self.scripts[1]: 2_500_000_000})
            assert_equal(self.nodes[0].getblockcount(), 2)
            assert_equal(self.nodes[1].getblockcount(), 2)

            self.log.info("Run 160 more native blocks through one gate, beyond its former lifetime cap")
            a.local("register_template", next_block.serialize())
            a.local("receive", final_winner.serialize())
            last_winner = final_winner
            for iteration in range(160):
                continued, continued_manifest = self.make(0, shares=(last_winner,))
                a.local("authorize", continued.serialize())
                last_winner = self.publish(continued, continued_manifest)
                a.local("receive", last_winner.serialize())
                reward = (50 * 100_000_000) >> (continued.m_height // 150)
                assert_equal(sum(o.nValue for o in parse_coinbase(continued.vtx[0])[1]), reward)
                if iteration % 40 == 39:
                    self.log.info("Completed %d endurance blocks with exact subsidy payouts", iteration + 1)
            state = a.local("maintenance")
            assert_equal(state["height"], 162)
            assert state["revision"] > 128 and state["pruned_through"] > 0 and state["anchor_height"] > 0
            before_restart = a.local("active_inventory")
            a.close()
            a = self.open_service(0)
            assert_equal(a.local("active_inventory"), before_restart)

            self.log.info("An administrative deep rollback latches local recovery without penalizing peers")
            # Actual competing-chain P2P recovery is tested separately. This
            # explicit rollback targets the gate's retained-anchor guard.
            anchor = state["anchor_hash"]
            final_tip = self.nodes[0].getbestblockhash()
            self.nodes[0].invalidateblock(anchor)
            assert self.nodes[0].getblockcount() < state["anchor_height"]
            try:
                a.local("maintenance")
                raise AssertionError("deep rollback did not require recovery")
            except RecoveryRequired:
                pass
            replicator = PeerReplicator(a, self.pool, [b.url])
            assert_equal(replicator.poll(), {"status": "recovery_required"})
            assert_equal(replicator.schedule[b.url]["failures"], 0)
            self.nodes[0].reconsiderblock(anchor)
            self.sync_blocks()
            assert_equal(self.nodes[0].getbestblockhash(), final_tip)
            a.close()
            try:
                self.open_service(0)
                raise AssertionError("restart silently cleared the recovery latch")
            except PeerUnavailable:
                pass
            self.log.info("Native peer integration passed at height162; recovery remains explicit and the final winner is pending")
        finally:
            for service in self.services.values():
                service.close()


if __name__ == "__main__":
    SharePoolPeerTest(__file__).main()
