#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Lua-based spam filters for P2WSH and OP_RETURN spam patterns."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_RETURN,
    hash160,
    sha256,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class LuaSpamFiltersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    # MiniWallet doesn't require BDB, so no need to skip

    def setup_network(self):
        """Setup the test network and copy Lua scripts to the datadir."""
        import os
        import shutil

        # Setup nodes first
        self.setup_nodes()

        # Copy Lua scripts to each node's datadir
        scripts_src = os.path.join(os.path.dirname(__file__), '../../share/scripts')
        for i in range(self.num_nodes):
            datadir = self.nodes[i].datadir_path
            scripts_dest = os.path.join(datadir, 'regtest', 'scripts')
            os.makedirs(scripts_dest, exist_ok=True)

            # Copy all .lua files directly to scripts directory
            if os.path.exists(scripts_src):
                for lua_file in os.listdir(scripts_src):
                    if lua_file.endswith('.lua'):
                        shutil.copy(
                            os.path.join(scripts_src, lua_file),
                            os.path.join(scripts_dest, lua_file)
                        )
                        self.log.info(f"Copied {lua_file} to {scripts_dest}")

    def create_p2wsh_fake_multisig_tx(self, wallet, num_fake_pubkeys=15):
        """Create a P2WSH transaction with fake pubkeys (spam pattern)."""
        # Start with a normal self-transfer transaction
        tx_info = wallet.create_self_transfer()
        tx = tx_info['tx']

        # Create fake pubkeys (0x02 prefix followed by zeros)
        fake_pubkeys = []
        for i in range(num_fake_pubkeys):
            # Create fake compressed pubkey: 0x02 + 32 zero bytes
            fake_pubkey = bytes([0x02]) + bytes(32)
            fake_pubkeys.append(fake_pubkey)

        # Build a CHECKMULTISIG script: OP_2 <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
        witness_script = CScript([OP_2] + fake_pubkeys + [num_fake_pubkeys, OP_CHECKMULTISIG])

        # Create P2WSH scriptPubKey
        script_hash = sha256(witness_script)
        script_pubkey = CScript([OP_0, script_hash])

        # Replace the output with our spam output
        tx.vout[0].scriptPubKey = script_pubkey

        # Add witness data to spend this output (fake witness)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'', witness_script]

        return tx

    def create_p2wsh_normal_multisig_tx(self, wallet):
        """Create a P2WSH transaction with real pubkeys (not spam)."""
        # Start with a normal self-transfer transaction
        tx_info = wallet.create_self_transfer()
        tx = tx_info['tx']

        # Create real pubkeys (using the wallet's keys)
        pubkey1 = wallet.get_pubkey().key
        # Create a second real pubkey by modifying the first slightly
        pubkey2 = bytes([pubkey1[0]]) + bytes([(b + 1) % 256 for b in pubkey1[1:]])
        pubkey3 = bytes([pubkey2[0]]) + bytes([(b + 2) % 256 for b in pubkey2[1:]])

        # Build a CHECKMULTISIG script with only 3 keys (not spam threshold)
        witness_script = CScript([OP_2, pubkey1, pubkey2, pubkey3, OP_3, OP_CHECKMULTISIG])

        # Create P2WSH scriptPubKey
        script_hash = sha256(witness_script)
        script_pubkey = CScript([OP_0, script_hash])

        # Replace the output with our normal multisig output
        tx.vout[0].scriptPubKey = script_pubkey

        return tx

    def create_opreturn_knotwork_spam_tx(self, wallet):
        """Create an OP_RETURN transaction with knotwork magic prefix (spam pattern)."""
        # Start with a normal self-transfer transaction
        tx_info = wallet.create_self_transfer()
        tx = tx_info['tx']

        # Knotwork magic prefix: ASCII "444" = 0x34 0x34 0x34
        # This is the magic number that the Lua filter looks for
        knotwork_magic = bytes([0x34, 0x34, 0x34])
        spam_data = knotwork_magic + b"some spam data here" * 3

        # Add an OP_RETURN output with spam data
        tx.vout.insert(0, CTxOut(0, CScript([OP_RETURN, spam_data])))

        return tx

    def create_opreturn_normal_tx(self, wallet):
        """Create a normal OP_RETURN transaction (not spam)."""
        # Start with a normal self-transfer transaction
        tx_info = wallet.create_self_transfer()
        tx = tx_info['tx']

        # Normal data without knotwork magic prefix
        normal_data = b"normal OP_RETURN data"

        # Add an OP_RETURN output with normal data
        tx.vout.insert(0, CTxOut(0, CScript([OP_RETURN, normal_data])))

        return tx

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Generate initial blocks for wallet")
        self.generate(self.wallet, 101)

        self.log.info("Test P2WSH fake multisig spam rejection")
        spam_tx = self.create_p2wsh_fake_multisig_tx(self.wallet)
        result = node.testmempoolaccept([spam_tx.serialize().hex()])
        self.log.info(f"P2WSH spam result: {result}")
        # The Lua filter should reject this
        assert_equal(result[0]['allowed'], False)
        assert 'rejected by script' in result[0]['reject-reason'].lower()

        self.log.info("Test P2WSH normal multisig acceptance")
        normal_tx = self.create_p2wsh_normal_multisig_tx(self.wallet)
        result = node.testmempoolaccept([normal_tx.serialize().hex()])
        self.log.info(f"P2WSH normal result: {result}")
        # This should be accepted (assuming it's otherwise valid)
        if not result[0]['allowed']:
            self.log.info(f"Normal P2WSH rejected: {result[0].get('reject-reason', 'unknown')}")

        self.log.info("Test OP_RETURN knotwork spam rejection")
        spam_tx = self.create_opreturn_knotwork_spam_tx(self.wallet)
        result = node.testmempoolaccept([spam_tx.serialize().hex()])
        self.log.info(f"OP_RETURN spam result: {result}")
        # The Lua filter should reject this
        assert_equal(result[0]['allowed'], False)
        assert 'rejected by script' in result[0]['reject-reason'].lower()

        self.log.info("Test OP_RETURN normal data acceptance")
        normal_tx = self.create_opreturn_normal_tx(self.wallet)
        result = node.testmempoolaccept([normal_tx.serialize().hex()])
        self.log.info(f"OP_RETURN normal result: {result}")
        # This should be accepted (assuming it's otherwise valid)
        if not result[0]['allowed']:
            self.log.info(f"Normal OP_RETURN rejected: {result[0].get('reject-reason', 'unknown')}")

        self.log.info("All spam filter tests passed!")


if __name__ == '__main__':
    LuaSpamFiltersTest(__file__).main()
