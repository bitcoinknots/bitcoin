#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native v6 TIDES jobs, recurring payouts, history availability and profile isolation.

All nodes, work and externally generated signer keys are disposable regtest
fixtures. Recipient scripts are arbitrary destinations, not identity keys.
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import sys
from unittest import SkipTest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib" / "sharepool"))
from hash_snapshot import EnvelopeV2, HashSigner, Snapshot, TemplateRecord, TIDES_RULES_HASH, TIDES_VERSION, apply_tides_state, solve_share
from test_framework.address import script_to_p2wsh
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex, ser_uint256
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class SharePoolHashTidesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        if self.options.cpu_capture:
            self.options.activation_height = 1
        self.extra_args = [[f"-sharepoolheight={self.options.activation_height}", "-sharepoolhashonly=1",
                            "-sharepooltides=1", "-testactivationheight=blake2b@1", "-disablewallet"]
                           for _ in range(self.num_nodes)]
        if self.options.cpu_capture:
            for arguments in self.extra_args:
                arguments.append("-networkactive=0")

    def add_options(self, parser):
        parser.add_argument("--activation-height", type=int, default=102, choices=(1, 102))
        parser.add_argument("--cpu-capture", action="store_true", help="Run isolated native Sia transport preflight without hardware")

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.signer_binary = Path(self.config["environment"]["BUILDDIR"]) / "bin" / (
            "bitcoin-sharepool-signer" + self.config["environment"]["EXEEXT"])
        if not self.signer_binary.is_file():
            raise SkipTest("native sharepool signer is not built")

    def proposal(self, index, signer, *, templates=(), shares=()):
        node = self.nodes[index]
        binding = EnvelopeV2(self.genesis, TIDES_RULES_HASH, node.getblockcount() + 1,
                             int(node.getbestblockhash(), 16), signer.pool, signer.public_key,
                             signer.payout_script, version=TIDES_VERSION)
        records = tuple(sorted((TemplateRecord.from_block(block) for block in templates),
                               key=lambda record: ser_uint256(record.template_id)))
        return Snapshot(binding, bytes(64), records, tuple(sorted(shares, key=lambda proof: proof.proof_id)),
                        (), (CTxOut(0, signer.payout_script),))

    def construct(self, index, signer, *, reward=5_000_000_000, **kwargs):
        node = self.nodes[index]
        prepared = node.preparesharepoolhashjob(self.proposal(index, signer, **kwargs).serialize().hex())
        unsigned = Snapshot.deserialize(bytes.fromhex(prepared["snapshot"]))
        assert_equal(unsigned.envelope.version, TIDES_VERSION)
        assert_equal(unsigned.owner_signature, bytes(64))
        assert_equal(unsigned.pending, ())
        assert_equal(unsigned.settled, ())
        assert_equal(prepared["signing_payload"], unsigned.signing_payload.hex())
        signed = replace(unsigned, owner_signature=signer.sign_owner(unsigned))
        finalized = node.finalizesharepoolhashjob(prepared["template"], signed.serialize().hex())
        block = from_hex(CBlock(), finalized["template"])
        assert_equal(finalized["commitment"], signed.hash_hex)
        assert_equal(block.m_mm_rhs, signed.hash)
        assert_equal(finalized["reward"], reward)
        return block, signed, prepared

    def store(self, index, snapshot):
        assert_equal(self.nodes[index].submitsharepoolhashsnapshot(snapshot.serialize().hex())["hash"], snapshot.hash_hex)

    def publish(self, index, block, snapshot):
        self.store(index, snapshot)
        block.solve()
        assert_equal(self.nodes[index].submitblock(block.serialize().hex()), None)
        assert_equal(self.nodes[index].getbestblockhash(), block.hash)

    def mine(self, index, signer, **kwargs):
        block, snapshot, _ = self.construct(index, signer, **kwargs)
        self.publish(index, block, snapshot)
        return block, snapshot

    def wait_tip(self, block):
        self.wait_until(lambda: all(node.getbestblockhash() == block.hash for node in self.nodes), timeout=120)
        for node in self.nodes:
            assert_equal(node.getsharepoolhashstatus()["pending_blocks"], 0)

    @staticmethod
    def payouts(block):
        return {bytes(output.scriptPubKey): output.nValue for output in block.vtx[0].vout if output.nValue}

    def origin(self, index, signer):
        block, snapshot, _ = self.construct(index, signer)
        self.store(index, snapshot)
        assert_equal(self.nodes[index].validatesharepoolhashtemplate(block.serialize().hex())["valid"], True)
        proof = solve_share(block, snapshot)
        assert_equal(self.nodes[index].validatesharepoolhashshare(proof.serialize().hex())["valid"], True)
        return block, snapshot, proof

    def reject_snapshot(self, signer, prepared, snapshot, reason):
        signed = replace(snapshot, owner_signature=signer.sign_owner(snapshot))
        assert_raises_rpc_error(-26, reason, self.nodes[0].finalizesharepoolhashjob,
                                prepared["template"], signed.serialize().hex())
        return signed

    @staticmethod
    def disk_manifest(directory):
        return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in directory.rglob("*") if path.is_file()}

    def check_profile_guard(self, final):
        node = self.nodes[1]
        self.stop_node(1)
        directory = Path(node.chain_path)
        marker = directory / "sharepool-profile-v6"
        marker_bytes = marker.read_bytes()
        index_before = self.disk_manifest(directory / "blocks" / "index")
        body_before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in (directory / "blocks").glob("*.dat")}
        common = [arg for arg in self.extra_args[1] if not arg.startswith("-sharepooltides")]
        wrong_height = [arg for arg in self.extra_args[1] if not arg.startswith("-sharepoolheight")]
        variants = [common, ["-testactivationheight=blake2b@1", "-disablewallet", "-reindex"],
                    common + ["-sharepooladmittedledger=1", "-reindex"],
                    wrong_height + [f"-sharepoolheight={self.options.activation_height + 1}", "-reindex-chainstate"],
                    self.extra_args[1] + ["-blake2b_headline=TIDES profile headline mismatch", "-checkblocks=1", "-reindex"]]
        for arguments in variants:
            node.assert_start_raises_init_error(arguments, "TIDES datadir profile", match=ErrorMatch.PARTIAL_REGEX)
            assert_equal(marker.read_bytes(), marker_bytes)
            assert_equal(self.disk_manifest(directory / "blocks" / "index"), index_before)
            assert_equal({path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (directory / "blocks").glob("*.dat")}, body_before)
        self.log.info("Local history budgets reject invalid settings and can change without changing the chain profile")
        for option in ("-sharepooltideshistorycachemib", "-sharepooltideshistoryquerymib"):
            for value in ("0", "1.5", "18446744073709551616"):
                node.assert_start_raises_init_error(self.extra_args[1] + [f"{option}={value}"],
                    f"{option} requires a positive whole MiB", match=ErrorMatch.PARTIAL_REGEX)
            node.assert_start_raises_init_error(self.extra_args[1] + [f"{option}=1", f"{option}=2"],
                f"{option} may be specified only once", match=ErrorMatch.PARTIAL_REGEX)
            node.assert_start_raises_init_error(common + [f"{option}=1"],
                f"{option} requires the opt-in regtest TIDES profile", match=ErrorMatch.PARTIAL_REGEX)
        assert_equal(marker.read_bytes(), marker_bytes)
        assert_equal(self.disk_manifest(directory / "blocks" / "index"), index_before)
        # A missing marker cannot silently import an existing pre-v6 or v6 DB.
        marker.unlink()
        try:
            node.assert_start_raises_init_error(self.extra_args[1] + ["-reindex"],
                                               "TIDES requires a fresh datadir", match=ErrorMatch.PARTIAL_REGEX)
            assert_equal(self.disk_manifest(directory / "blocks" / "index"), index_before)
            assert not marker.exists()
        finally:
            marker.write_bytes(marker_bytes)
            marker.chmod(0o600)
        self.start_node(1, self.extra_args[1] + ["-sharepooltideshistorycachemib=1", "-sharepooltideshistoryquerymib=2"])
        assert_equal(node.getbestblockhash(), final.hash)
        assert_equal(marker.read_bytes(), marker_bytes)
        assert node.verifychain(4, 0)

    def run_test(self):
        node, follower = self.nodes
        if self.options.cpu_capture:
            import json
            from test_tides_hardware_capture import native_preflight
            result = native_preflight(lambda method, *args: getattr(node, method)(*args),
                                     lambda method, *args: getattr(follower, method)(*args),
                                     self.signer_binary, self.options.tmpdir)
            Path(self.options.tmpdir, "cpu-preflight-result.json").write_text(json.dumps(result, indent=2) + "\n")
            self.log.info("Native Sia CPU preflight and independent replay: %s", result)
            return
        self.genesis = int(node.getblockhash(0), 16)
        funded = []
        redeem = CScript([OP_TRUE])
        if self.options.activation_height == 102:
            self.connect_nodes(0, 1)
            funded = self.generatetoaddress(node, 101, script_to_p2wsh(redeem))
            self.sync_blocks()
            self.disconnect_nodes(0, 1)
        paths = [Path(self.options.tmpdir) / f"tides-owner-{index}.key" for index in range(3)]
        common_script, other_script = b"\x00\x14" + b"a" * 20, b"\x00\x14" + b"b" * 20
        try:
            signers = [HashSigner.create(self.signer_binary, path, pool=pool, payout_script=script)
                       for path, pool, script in zip(paths, (101, 101, 202), (common_script, other_script, common_script))]
            a1, a2, b = signers
            bootstrap_budget = node.getsharepoolhashtidesbudget(f"{a1.pool:064x}", common_script.hex())
            assert_equal(bootstrap_budget["native_tip"], node.getbestblockhash())
            assert_equal(bootstrap_budget["output_count"], 1)
            assert_equal(bootstrap_budget["output_bytes"], 31)
            for pool, script in (("00" * 32, common_script.hex()), (f"{a1.pool:064x}", "51"),
                                 (f"{a1.pool:064x}", "ab" * 35)):
                assert_raises_rpc_error(-8, "Invalid", node.getsharepoolhashtidesbudget, pool, script)
            for current in self.nodes:
                assert_equal(current.getsharepoolhashstatus()["rules"], f"{TIDES_RULES_HASH:064x}")
                assert_equal(current.getsharepoolhashstatus()["activation_height"], self.options.activation_height)
                assert (Path(current.chain_path) / "sharepool-profile-v6").is_file()

            self.log.info("Empty-pool bootstrap jobs need only a recipient script and a separate owner signer")
            origins = [self.origin(0, signer) for signer in signers]
            assert_equal(len({TemplateRecord.from_block(item[0]).template_id for item in origins}), 3)
            assert_equal(a1.payout_script, b.payout_script)
            assert a1.public_key != b.public_key
            for (origin, _, _), signer in zip(origins, signers):
                assert_equal(self.payouts(origin), {signer.payout_script: 5_000_000_000})
            fee = 0
            if funded:
                funding = from_hex(CBlock(), node.getblock(funded[0], 0)).vtx[0]
                funding.rehash()
                transaction = CTransaction()
                transaction.vin = [CTxIn(COutPoint(funding.sha256, 0), CScript(), 0xffffffff)]
                transaction.vout = [CTxOut(funding.vout[0].nValue - 10_000, CScript(common_script))]
                witness = CTxInWitness()
                witness.scriptWitness.stack = [bytes(redeem)]
                transaction.wit.vtxinwit = [witness]
                transaction.rehash()
                node.sendrawtransaction(transaction.serialize().hex())
                fee = 10_000
            first, first_state, _ = self.construct(0, a1, templates=[item[0] for item in origins],
                shares=[item[2] for item in origins], reward=5_000_000_000 + fee)
            assert_equal(first_state.history_head, apply_tides_state(first_state, None).history_head)
            assert first_state.history_head != 0
            assert_equal(self.payouts(first), {common_script: (5_000_000_000 + fee) // 2,
                                               other_script: (5_000_000_000 + fee) // 2})
            if fee:
                assert_equal(first.vtx[1].serialize_with_witness(), transaction.serialize_with_witness())
            self.publish(0, first, first_state)
            self.connect_nodes(0, 1)
            self.wait_tip(first)
            history_budget = node.getsharepoolhashtidesbudget(f"{a1.pool:064x}", common_script.hex())
            assert_equal(history_budget["native_tip"], first.hash)
            assert_equal(history_budget["native_bits"], first.nBits)
            assert_equal(history_budget["output_count"], 2)
            assert_equal(history_budget["output_bytes"], 62)
            separate_budget = node.getsharepoolhashtidesbudget(f"{b.pool:064x}", common_script.hex())
            assert_equal(separate_budget["output_count"], 1)
            assert_equal(separate_budget["output_bytes"], 31)

            self.log.info("Paid shares remain in the rolling history; late submissions cannot change an issued job")
            second, second_state, prepared = self.construct(0, a2)
            assert_equal(second_state.history_head, apply_tides_state(second_state, first_state).history_head)
            assert_equal(self.payouts(second), {common_script: 2_500_000_000, other_script: 2_500_000_000})
            frozen = (second.serialize(), second_state.serialize())
            late = solve_share(origins[0][0], origins[0][1], start_nonce=origins[0][2].header.nNonce + 1)
            assert_equal(node.validatesharepoolhashshare(late.serialize().hex())["valid"], True)
            self.reject_snapshot(a2, prepared, replace(second_state, history_head=0), "history")
            self.reject_snapshot(a2, prepared, replace(second_state, payouts=(CTxOut(1, common_script),)), "payout")
            assert_equal((second.serialize(), second_state.serialize()), frozen)
            self.publish(0, second, second_state)
            self.wait_tip(second)
            third, third_state, _ = self.construct(0, a1, templates=(origins[0][0],), shares=(late,))
            assert_equal(self.payouts(third), {common_script: 3_333_333_333, other_script: 1_666_666_666})
            assert_equal(sum(self.payouts(third).values()), 4_999_999_999) # One satoshi remains unclaimed.

            self.log.info("Missing older history leaves a known native tip pending until its exact opening is restored")
            self.disconnect_nodes(0, 1)
            self.stop_node(1)
            shutil.rmtree(Path(follower.chain_path) / "sharepool-snapshots-v6")
            self.start_node(1)
            assert_equal(follower.getbestblockhash(), second.hash)
            self.store(1, second_state)
            self.store(1, third_state)
            third.solve()
            assert_equal(follower.submitblock(third.serialize().hex()), "sharepool-hash-data-missing")
            assert_equal(follower.getbestblockhash(), second.hash)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.restart_node(1)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.publish(0, third, third_state)
            self.connect_nodes(0, 1)
            self.wait_tip(third)
            fourth, fourth_state = self.mine(0, b)
            assert_equal(self.payouts(fourth), {common_script: 5_000_000_000})
            self.wait_tip(fourth)

            self.log.info("Competing native forks select their own admitted history and recurring payout ratios")
            self.disconnect_nodes(0, 1)
            left_origin = self.origin(0, a1)
            left, left_state = self.mine(0, a1, templates=(left_origin[0],), shares=(left_origin[2],))
            assert_equal(self.payouts(left), {common_script: 3_750_000_000, other_script: 1_250_000_000})
            right_origin = self.origin(1, a2)
            right, right_state = self.mine(1, a2, templates=(right_origin[0],), shares=(right_origin[2],))
            for _ in range(2):
                right, right_state = self.mine(1, a2)
                assert_equal(self.payouts(right), {common_script: 2_500_000_000, other_script: 2_500_000_000})
            self.connect_nodes(0, 1)
            self.wait_tip(right)
            assert_equal(node.getblockheader(left.hash)["confirmations"], -1)
            assert_equal(node.getsharepoolhashsnapshot(right_state.hash_hex)["data"], right_state.serialize().hex())

            self.log.info("New work fills the finite TIDES work window without deleting older historical snapshots")
            fresh = self.origin(0, a1)
            work = [fresh[2]]
            for _ in range(19):
                work.append(solve_share(fresh[0], fresh[1], start_nonce=work[-1].header.nNonce + 1))
            final, final_state = self.mine(0, a1, templates=(fresh[0],), shares=work)
            assert_equal(self.payouts(final), {common_script: 5_000_000_000})
            self.wait_tip(final)
            repeated, repeated_state = self.mine(0, a2)
            assert_equal(self.payouts(repeated), self.payouts(final))
            self.wait_tip(repeated)
            assert_equal(node.getsharepoolhashsnapshot(first_state.hash_hex)["data"], first_state.serialize().hex())

            self.log.info("Offline reindex reconstructs the selected history; profile changes cannot overwrite its block database")
            self.disconnect_nodes(0, 1)
            self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex-chainstate"])
            assert_equal(follower.getbestblockhash(), repeated.hash)
            for current in self.nodes:
                assert_equal(current.verifychain(4, 0), True)
            # Full reindex also runs ContextualCheckBlock before ConnectBlock
            # supplies its reward, including our one-satoshi rounding residue.
            self.restart_node(1, extra_args=self.extra_args[1] + ["-reindex"])
            assert_equal(follower.getbestblockhash(), repeated.hash)
            assert_equal(follower.verifychain(4, 0), True)
            self.check_profile_guard(repeated)
        finally:
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashTidesTest(__file__).main()
