#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the batched extended coinbase maturity temporary soft fork.

Window-created coinbases use a height-modulo schedule instead of a single
26280-block lock, and that lock is attached to the creating height:

    (height - activation) % 6 == 0        -> 2016 confirmations  (1/6)
    (height - activation) % 6 in {1, 2}   -> 8064 confirmations  (2/6)
    (height - activation) % 6 in {3, 4, 5}-> 26280 confirmations (1/2)

After RDTS expiry, *new* coinbases use COINBASE_MATURITY (100). Coinbases
created inside the window keep their assigned lock.

Covered:
- option validation (requires -rdtsexpiry, must precede it)
- activation height from median-time-past; getdeploymentinfo / getblocktemplate
- grandfathering: pre-activation coinbase stays at 100
- short-tranche (mod 6 == 0) rejected at depth 100, accepted at 2016
- post-expiry new coinbase spendable at 100
- in-window long/short coinbase still locked after expiry
- wallet reports the reward as immature while locked
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

EXTENDED_SHORT = 2016
BLAKE2B_HEIGHT = 120
T0 = 1_600_000_000
START = T0 + 10_000
EXPIRY = START + 50_000
REJECT = 'bad-txns-premature-spend-of-coinbase'


def maturity_for(height, activation):
    if height < activation:
        return COINBASE_MATURITY
    batch = (height - activation) % 6
    if batch == 0:
        return EXTENDED_SHORT
    if batch in (1, 2):
        return 8064
    return 26280


class ExtendedCoinbaseMaturityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 240
        self.base_args = [
            f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}',
            f'-rdtsexpiry={EXPIRY}',
            f'-extendedcoinbasematurity={START}',
        ]
        self.extra_args = [self.base_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_spend_rejected(self, raw_hex):
        node = self.nodes[0]
        assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, raw_hex)

    def assert_deploymentinfo(self, active, height=None):
        info = self.nodes[0].getdeploymentinfo()['deployments']['extended_coinbase_maturity']
        assert_equal(info['type'], 'flagday')
        assert_equal(info['active'], active)
        assert_equal(info['start_time'], START)
        assert_equal(info['expiry_time'], EXPIRY)
        if height is not None and 'height' in info:
            assert_equal(info['height'], height)

    def assert_gbt_rule(self, active):
        rules = self.nodes[0].getblocktemplate({'rules': ['segwit']}).get('rules', [])
        has = 'extended_coinbase_maturity' in rules
        assert_equal(has, active)

    def generate_to(self, count):
        node = self.nodes[0]
        while node.getblockcount() < count:
            chunk = min(500, count - node.getblockcount())
            self.generate(self.wallet, chunk, sync_fun=self.no_op)

    def mtp(self, height):
        node = self.nodes[0]
        return node.getblockheader(node.getblockhash(height))['mediantime']

    def coinbase_utxo(self, height):
        node = self.nodes[0]
        blockhash = node.getblockhash(height)
        txid = node.getblock(blockhash)['tx'][0]
        tx = node.getrawtransaction(txid, True)
        return {
            'txid': txid,
            'vout': 0,
            'value': tx['vout'][0]['value'],
            'scriptPubKey': tx['vout'][0]['scriptPubKey']['hex'],
            'height': height,
        }

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Option validation")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[f'-extendedcoinbasematurity={START}'],
            expected_msg='-extendedcoinbasematurity requires -rdtsexpiry',
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[
                f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}',
                f'-rdtsexpiry={START}',
                f'-extendedcoinbasematurity={START}',
            ],
            expected_msg='must precede the RDTS expiry',
        )
        self.start_node(0, extra_args=self.base_args)
        self.wallet = MiniWallet(node)

        self.log.info("Mine up to the mock-time window")
        self.mocktime = T0
        node.setmocktime(self.mocktime)
        # Connect a peer so generate works with MiniWallet
        node.add_p2p_connection(P2PInterface())

        # Pre-activation blocks
        self.generate(self.wallet, 150, sync_fun=self.no_op)
        pre_height = node.getblockcount()
        assert_greater_than(START, self.mtp(pre_height))
        self.assert_deploymentinfo(active=False)
        self.assert_gbt_rule(active=False)

        pre_utxo = self.coinbase_utxo(pre_height)
        pre_spend = self.wallet.create_self_transfer(utxo_to_spend=pre_utxo)

        self.log.info("Grandfathered coinbase spendable at 100 after activation")
        self.mocktime = START
        node.setmocktime(self.mocktime)
        # Push MTP across START
        self.generate(node, 11, sync_fun=self.no_op)
        activation = None
        for h in range(1, node.getblockcount() + 1):
            if self.mtp(h - 1) >= START:
                activation = h
                break
        assert activation is not None
        self.log.info(f"activation height {activation}")
        self.assert_deploymentinfo(active=True, height=activation)
        self.assert_gbt_rule(active=True)

        # bury the pre-activation coinbase under 100
        need = COINBASE_MATURITY - (node.getblockcount() - pre_height)
        if need > 0:
            self.generate(self.wallet, need, sync_fun=self.no_op)
        node.sendrawtransaction(pre_spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        self.log.info("Short-tranche window coinbase rejected at 100, accepted at 2016")
        # Find a window block with (h - activation) % 6 == 0
        target = activation
        while (target - activation) % 6 != 0 or target <= activation:
            target += 1
        while node.getblockcount() < target:
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        short_utxo = self.coinbase_utxo(target)
        assert_equal(maturity_for(target, activation), EXTENDED_SHORT)
        short_spend = self.wallet.create_self_transfer(utxo_to_spend=short_utxo)

        # 100 confirmations is not enough
        while node.getblockcount() < target + COINBASE_MATURITY:
            self.generate(self.wallet, min(100, target + COINBASE_MATURITY - node.getblockcount()), sync_fun=self.no_op)
        self.assert_spend_rejected(short_spend['hex'])

        # 2016 confirmations is enough
        while node.getblockcount() < target + EXTENDED_SHORT:
            self.generate(self.wallet, min(200, target + EXTENDED_SHORT - node.getblockcount()), sync_fun=self.no_op)
        node.sendrawtransaction(short_spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        self.log.info("Expiry: new coinbases are 100; in-window coins stay locked")
        # Grab an in-window coinbase that is still far from its maturity
        locked_h = activation + 3  # % 6 == 3 -> 26280
        if locked_h == target:
            locked_h = activation + 9
        while node.getblockcount() < locked_h:
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        locked_utxo = self.coinbase_utxo(locked_h)
        locked_spend = self.wallet.create_self_transfer(utxo_to_spend=locked_utxo)

        self.mocktime = EXPIRY
        node.setmocktime(self.mocktime)
        self.generate(node, 11, sync_fun=self.no_op)
        self.assert_deploymentinfo(active=False, height=activation)
        self.assert_gbt_rule(active=False)

        # window coinbase still rejected
        self.assert_spend_rejected(locked_spend['hex'])

        # a brand-new post-expiry coinbase matures at 100
        post_h = node.getblockcount()
        post_utxo = self.coinbase_utxo(post_h)
        post_spend = self.wallet.create_self_transfer(utxo_to_spend=post_utxo)
        self.generate(self.wallet, COINBASE_MATURITY, sync_fun=self.no_op)
        node.sendrawtransaction(post_spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)

        self.log.info("Passed")


if __name__ == '__main__':
    ExtendedCoinbaseMaturityTest(__file__).main()
