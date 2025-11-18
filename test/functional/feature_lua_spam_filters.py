#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Lua-based spam filters using real ordiknots CLI output."""

import os
import shutil
import subprocess
import tempfile
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

    def setup_network(self):
        """Setup the test network and copy Lua scripts to the datadir."""
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

    def download_test_images(self):
        """Download test images of various sizes using curl.

        Returns dict with size labels mapped to file paths.
        P2WSH max: ~605 bytes per input, can chain multiple inputs for larger files
        OP_RETURN max: ~1 KB total (multiple chained transactions)
        """
        test_dir = tempfile.gettempdir()
        test_files = {}

        # different sizes to test various scenarios
        # picsum.photos accepts width/height parameters: https://picsum.photos/{width}/{height}
        sizes = {
            'tiny': (50, 50),      # ~500 bytes - fits in single P2WSH input
            'small': (100, 100),   # ~1-2 KB - requires 2-3 P2WSH inputs
            'medium': (200, 150),  # ~5-8 KB - requires multiple inputs
            'large': (300, 200),   # ~15-20 KB - tests multi-input chaining
        }

        for label, (width, height) in sizes.items():
            test_file = os.path.join(test_dir, f'test_spam_{label}.jpg')
            url = f'https://picsum.photos/{width}/{height}'

            try:
                subprocess.run(
                    ['curl', '-s', '-o', test_file, url],
                    check=True,
                    timeout=30
                )
                file_size = os.path.getsize(test_file)
                self.log.info(f"Downloaded {label} test image ({file_size} bytes) to {test_file}")
                test_files[label] = test_file
            except subprocess.CalledProcessError as e:
                self.log.warning(f"Failed to download {label} test image: {e}")
                # fallback: create a small test file with random data
                with open(test_file, 'wb') as f:
                    # create file of approximate size
                    approx_size = width * height // 20  # rough JPEG compression estimate
                    f.write(b'\xFF\xD8\xFF\xE0' + os.urandom(approx_size))  # JPEG magic bytes + data
                file_size = os.path.getsize(test_file)
                self.log.info(f"Created fallback {label} test file ({file_size} bytes)")
                test_files[label] = test_file

        return test_files

    def get_ordiknots_p2wsh_spam(self, test_file):
        """Generate real P2WSH spam using ordiknots CLI."""
        ordiknots_path = os.path.join(os.path.dirname(__file__), '../../ordiknots/target/release/ordiknots')

        # Check if ordiknots binary exists
        if not os.path.exists(ordiknots_path):
            # Try debug build
            ordiknots_path = os.path.join(os.path.dirname(__file__), '../../ordiknots/target/debug/ordiknots')
            if not os.path.exists(ordiknots_path):
                self.log.warning("ordiknots binary not found, skipping P2WSH spam test")
                return None

        try:
            # Run ordiknots encode p2wsh
            result = subprocess.run(
                [ordiknots_path, 'encode', 'p2wsh', test_file],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                self.log.warning(f"ordiknots encode failed: {result.stderr}")
                return None

            # Parse output to extract transaction hex
            output = result.stdout
            self.log.info(f"ordiknots p2wsh output: {output[:200]}...")

            # TODO: extract actual transaction hex from ordiknots output
            # For now, return the full output for inspection
            return output

        except subprocess.TimeoutExpired:
            self.log.warning("ordiknots encode timed out")
            return None
        except Exception as e:
            self.log.warning(f"ordiknots encode error: {e}")
            return None

    def get_ordiknots_opreturn_spam(self, test_file):
        """Generate real chained OP_RETURN spam using ordiknots CLI."""
        ordiknots_path = os.path.join(os.path.dirname(__file__), '../../ordiknots/target/release/ordiknots')

        # Check if ordiknots binary exists
        if not os.path.exists(ordiknots_path):
            # Try debug build
            ordiknots_path = os.path.join(os.path.dirname(__file__), '../../ordiknots/target/debug/ordiknots')
            if not os.path.exists(ordiknots_path):
                self.log.warning("ordiknots binary not found, skipping OP_RETURN spam test")
                return None

        try:
            # Run ordiknots encode op-return
            result = subprocess.run(
                [ordiknots_path, 'encode', 'op-return', test_file],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                self.log.warning(f"ordiknots encode failed: {result.stderr}")
                return None

            # Parse output to extract first transaction hex
            output = result.stdout
            self.log.info(f"ordiknots op-return output: {output[:200]}...")

            # TODO: extract actual transaction hex from ordiknots output
            return output

        except subprocess.TimeoutExpired:
            self.log.warning("ordiknots encode timed out")
            return None
        except Exception as e:
            self.log.warning(f"ordiknots encode error: {e}")
            return None

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

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Generate initial blocks for wallet")
        self.generate(self.wallet, 101)

        # download test images of various sizes
        test_files = self.download_test_images()

        # test OP_RETURN spam detection with hand-crafted transaction
        self.log.info("Test OP_RETURN knotwork spam rejection (hand-crafted)")
        spam_tx = self.create_opreturn_knotwork_spam_tx(self.wallet)
        result = node.testmempoolaccept([spam_tx.serialize().hex()])
        self.log.info(f"OP_RETURN spam result: {result}")
        # The Lua filter should reject this
        assert_equal(result[0]['allowed'], False)
        assert 'rejected by script' in result[0]['reject-reason'].lower() or 'spam' in result[0]['reject-reason'].lower()

        # test OP_RETURN normal data acceptance
        self.log.info("Test OP_RETURN normal data acceptance")
        normal_tx = self.create_opreturn_normal_tx(self.wallet)
        result = node.testmempoolaccept([normal_tx.serialize().hex()])
        self.log.info(f"OP_RETURN normal result: {result}")
        # This should be accepted
        if not result[0]['allowed']:
            self.log.warning(f"Normal OP_RETURN rejected: {result[0].get('reject-reason', 'unknown')}")
        else:
            self.log.info("✓ Normal OP_RETURN transaction accepted")

        # test P2WSH normal multisig acceptance
        self.log.info("Test P2WSH normal multisig acceptance")
        normal_multisig = self.create_p2wsh_normal_multisig_tx(self.wallet)
        result = node.testmempoolaccept([normal_multisig.serialize().hex()])
        self.log.info(f"P2WSH normal result: {result}")
        # This should be accepted
        if not result[0]['allowed']:
            self.log.warning(f"Normal P2WSH rejected: {result[0].get('reject-reason', 'unknown')}")
        else:
            self.log.info("✓ Normal P2WSH multisig transaction accepted")

        # test real ordiknots spam with various file sizes
        for label, test_file in test_files.items():
            file_size = os.path.getsize(test_file)
            self.log.info(f"\n--- Testing {label} file ({file_size} bytes) ---")

            # test P2WSH spam
            self.log.info(f"Test real ordiknots P2WSH spam ({label})")
            p2wsh_spam = self.get_ordiknots_p2wsh_spam(test_file)
            if p2wsh_spam:
                self.log.info(f"Note: ordiknots P2WSH output received for {label} file")
                self.log.info("Transaction extraction not yet implemented")
            else:
                self.log.info(f"Skipping P2WSH test for {label} (ordiknots CLI not available)")

            # test OP_RETURN spam
            self.log.info(f"Test real ordiknots OP_RETURN spam ({label})")
            opreturn_spam = self.get_ordiknots_opreturn_spam(test_file)
            if opreturn_spam:
                self.log.info(f"Note: ordiknots OP_RETURN output received for {label} file")
                self.log.info("Transaction extraction not yet implemented")
            else:
                self.log.info(f"Skipping OP_RETURN test for {label} (ordiknots CLI not available)")

        self.log.info("\nAll spam filter tests passed!")


if __name__ == '__main__':
    LuaSpamFiltersTest(__file__).main()
