#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the height-activated proof-of-work change on regtest."""

import json
from pathlib import Path

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    blake2b_header_hash_components,
    from_hex,
    hash256,
    powhash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

CHANGE_HEIGHT = 20


class PowChangeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-testactivationheight=blake2b@{CHANGE_HEIGHT}"]]

    def get_header(self, blockhash):
        return from_hex(CBlockHeader(), self.nodes[0].getblockheader(blockhash, False))

    def test_header_vectors(self):
        vectors_path = Path(self.config["environment"]["SRCDIR"]) / "src/test/data/block_header_v2.json"
        with vectors_path.open(encoding="utf8") as vectors_file:
            vectors = json.load(vectors_file)["headers"]

        for vector in vectors:
            fields = vector["fields"]
            header = CBlockHeader()
            header.m_header_v2 = True
            header.nVersion = fields["nVersion"]
            header.hashPrevBlock = int(fields["hashPrevBlock"], 16)
            header.hashMerkleRoot = int(fields["hashMerkleRoot"], 16)
            header.nTime = fields["nTime"]
            header.nBits = fields["nBits"]
            header.nNonce = fields["nNonce"]
            header.m_nonce2 = fields["m_nonce2"]
            header.m_nonce3 = fields["m_nonce3"]
            header.m_extranonce = int(fields["m_extranonce"], 16)
            header.m_time_offset = fields["m_time_offset"]
            header.m_txcount = fields["m_txcount"]
            header.m_flags = fields["m_flags"]
            header.m_xor_key_mask_clear_bits = fields["m_xor_key_mask_clear_bits"]
            header.m_xor_key = int(fields["m_xor_key"], 16)
            header.m_height = fields["m_height"]
            header.m_mm_rhs = int(fields["m_mm_rhs"], 16)

            assert_equal(len(header.serialize()), 164)
            assert_equal(header.serialize().hex(), vector["serialized"])
            components = blake2b_header_hash_components(header)
            assert_equal(components["asic_profile"], vector["asic_profile"])
            assert_equal(components["asic_input"].hex(), vector["asic_input"])
            for component in ("xor_key_hash", "h1", "h2", "mask"):
                assert_equal(components[component].hex(), vector[component])
            assert_equal(components["hash1"].hex(), vector["blake2b_1"])
            assert_equal(components["hash2"].hex(), vector["blake2b_2"])
            assert_equal(components["result"].hex(), vector["block_hash"])
            assert_equal(powhash(header)[::-1].hex(), vector["block_hash"])

    def run_test(self):
        node = self.nodes[0]
        addr = node.get_deterministic_priv_key().address

        self.log.info("A BLAKE2b headline is required")
        self.stop_node(0)
        headline_arg_index = next(i for i, arg in enumerate(node.args) if arg.startswith("-blake2b_headline="))
        headline_arg = node.args.pop(headline_arg_index)
        node.assert_start_raises_init_error(
            expected_msg="Error: This version requires blake2b_headline set manually",
        )
        node.args.insert(headline_arg_index, headline_arg)
        self.start_node(0)

        self.test_header_vectors()

        self.log.info("Blocks before the activation height use SHA256d")
        self.generatetoaddress(node, CHANGE_HEIGHT - 2, addr)
        pre_parent_hash = node.getbestblockhash()
        pre_parent = node.getblockheader(pre_parent_hash)
        pre_template = node.getblocktemplate({"rules": ["segwit"]})
        assert "!blake2b" not in pre_template["rules"]
        assert not pre_template["version"] & 0x80000000

        invalid_pre_header = create_block(
            int(pre_parent_hash, 16),
            create_coinbase(CHANGE_HEIGHT - 1),
            pre_parent["time"] + 1,
            height=CHANGE_HEIGHT - 1,
            header_v2=True,
        )
        invalid_pre_header.solve()
        assert_raises_rpc_error(
            -25, "bad-version-sha256d",
            lambda: node.submitheader(hexdata=CBlockHeader(invalid_pre_header).serialize().hex()),
        )

        pre_hash = self.generatetoaddress(node, 1, addr)[0]
        pre_header = self.get_header(pre_hash)
        assert_equal(node.getblockcount(), CHANGE_HEIGHT - 1)
        assert not pre_header.m_header_v2
        assert_equal(len(pre_header.serialize()), 80)
        assert_equal(pre_hash, hash256(pre_header.serialize())[::-1].hex())
        assert_equal(pre_hash, powhash(pre_header)[::-1].hex())

        self.log.info("The activation block and its successors use BLAKE2b")
        assert_raises_rpc_error(
            -8, "Support for 'blake2b' rule requires explicit client support",
            lambda: node.getblocktemplate({"rules": ["segwit"]}),
        )
        template = node.getblocktemplate({"rules": ["segwit", "blake2b"]})
        assert_equal(template["height"], CHANGE_HEIGHT)
        assert template["version"] & 0x80000000
        assert "!blake2b" in template["rules"]

        template = node.getblocktemplate({"rules": ["segwit", "blake2b"]})
        assert_equal(template["height"], CHANGE_HEIGHT)
        assert_equal(template["coinbaseaux"]["blake2b_headline"], b"BLAKE2b functional test headline".hex())

        invalid_activation_block = create_block(
            int(pre_hash, 16),
            create_coinbase(CHANGE_HEIGHT),
            pre_header.nTime + 1,
            height=CHANGE_HEIGHT,
            header_v2=True,
        )
        invalid_activation_block.solve()
        assert_equal(node.submitblock(invalid_activation_block.serialize().hex()), "bad-headline")

        post_hash = self.generatetoaddress(node, 1, addr)[0]
        post_header = self.get_header(post_hash)
        assert_equal(node.getblockcount(), CHANGE_HEIGHT)
        assert post_header.m_header_v2
        assert_equal(post_header.m_height, CHANGE_HEIGHT)
        assert_equal(post_header.m_txcount, 1)
        assert_equal(len(post_header.serialize()), 164)
        assert_equal(post_hash, powhash(post_header)[::-1].hex())
        verbose_post_header = node.getblockheader(post_hash)
        assert_equal(verbose_post_header["version"], post_header.nVersion)
        assert_equal(verbose_post_header["versionHex"], f"{post_header.nVersion:08x}")
        assert "blake2b_headline" not in node.getblocktemplate({"rules": ["segwit", "blake2b"]})["coinbaseaux"]

        self.log.info("The high two flag bits are reserved")
        for high_flag in (0x40, 0x80):
            invalid_flags = create_block(
                int(post_hash, 16),
                create_coinbase(CHANGE_HEIGHT + 1),
                post_header.nTime + 1,
                height=CHANGE_HEIGHT + 1,
                header_v2=True,
            )
            invalid_flags.m_flags |= high_flag
            invalid_flags.solve()
            assert_raises_rpc_error(
                -25, "bad-flags-highbits",
                lambda: node.submitheader(hexdata=CBlockHeader(invalid_flags).serialize().hex()),
            )

        # A null XOR key disables anti-withholding regardless of how many mask
        # bits the pool requests to clear.
        assert_equal(post_header.m_xor_key, 0)
        post_header.m_xor_key_mask_clear_bits = 255
        disabled_xor = blake2b_header_hash_components(post_header)
        assert_equal(disabled_xor["mask"], bytes(32))
        assert_equal(disabled_xor["result"], disabled_xor["hash2"])

        merge_mined_block = create_block(
            int(post_hash, 16),
            create_coinbase(CHANGE_HEIGHT + 1),
            post_header.nTime + 1,
            height=CHANGE_HEIGHT + 1,
            header_v2=True,
        )
        merge_mined_block.m_xor_key = 0x0123456789abcdef0123456789abcdef
        merge_mined_block.m_xor_key_mask_clear_bits = 255
        merge_mined_block.m_mm_rhs = 0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
        merge_mined_block.solve()
        assert_equal(node.submitblock(merge_mined_block.serialize().hex()), None)

        invalid_txcount = create_block(
            merge_mined_block.sha256,
            create_coinbase(CHANGE_HEIGHT + 2),
            merge_mined_block.nTime + 1,
            height=CHANGE_HEIGHT + 2,
            header_v2=True,
        )
        invalid_txcount.m_txcount += 1
        invalid_txcount.solve()
        assert_equal(node.submitblock(invalid_txcount.serialize().hex()), "bad-txnlist-size")

        invalid_height = create_block(
            merge_mined_block.sha256,
            create_coinbase(CHANGE_HEIGHT + 2),
            merge_mined_block.nTime + 1,
            height=CHANGE_HEIGHT + 2,
            header_v2=True,
        )
        invalid_height.m_height += 1
        invalid_height.solve()
        assert_raises_rpc_error(
            -25, "bad-header-height",
            lambda: node.submitheader(hexdata=CBlockHeader(invalid_height).serialize().hex()),
        )

        invalid_post_header = create_block(
            merge_mined_block.sha256,
            create_coinbase(CHANGE_HEIGHT + 2),
            merge_mined_block.nTime + 1,
            height=CHANGE_HEIGHT + 2,
            header_v2=False,
        )
        invalid_post_header.solve()
        assert_raises_rpc_error(
            -25, "bad-version-blake2b",
            lambda: node.submitheader(hexdata=CBlockHeader(invalid_post_header).serialize().hex()),
        )

        self.log.info("Regenerating commitments refreshes the transaction count")
        wallet = MiniWallet(node)
        self.generate(wallet, 100)
        transaction = wallet.create_self_transfer()
        generated = self.generateblock(node, wallet.get_address(), [transaction["hex"]])
        generated_block = node.getblock(generated["hash"])
        generated_header = self.get_header(generated["hash"])
        assert_equal(len(generated_block["tx"]), 2)
        assert_equal(generated_header.m_txcount, 2)


if __name__ == "__main__":
    PowChangeTest(__file__).main()
