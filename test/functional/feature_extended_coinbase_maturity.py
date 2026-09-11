#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the batched extended coinbase maturity temporary soft fork.

Layout follows knots#402's feature_extended_coinbase_maturity.py so a
human diff against that PR is mostly the two intended deltas:

  1. Window coinbases use (height - activation) % 6
       0        -> 2016 confirmations   (1/6 of blocks)
       1 or 2   -> 8064 confirmations   (2/6)
       3, 4, 5  -> 26280 confirmations  (1/2)
     instead of a single 26280-block lock. Coinbase size is unchanged.
  2. The lock is attached to the creating height. After RDTS expiry,
     *new* coinbases use COINBASE_MATURITY (100). Window-created
     coinbases keep their assigned lock. (#402 unlocked them at expiry.)

Covered (same checklist as #402, with (2) replacing "hard expiry unlocks"):
- option validation (requires -rdtsexpiry, must precede it)
- activation height derived from median-time-past; getdeploymentinfo/getblocktemplate
- grandfathering: a coinbase from the block before activation keeps the 100-block rule
- an in-window coinbase is rejected at depth >= 100 by the mempool
- short-tranche spendable at exactly 2016; the reorg filter evicts it one block earlier
- after expiry a still-locked window coinbase stays rejected; a post-expiry
  coinbase is spendable at 100
- the wallet reports the reward as immature while locked
- -reindex reproduces the chain and derives the same activation height
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
EXTENDED_MID = 8064
EXTENDED_LONG = 26280
BLAKE2B_HEIGHT = 120
# Mock clock: pre-activation blocks are stamped from T0, the window opens once
# the median-time-past reaches START, and RDTS (with it, this rule's *creation*
# window) expires at EXPIRY. Block times creep by one second per block, so
# START and EXPIRY leave room for the blocks mined before each.
T0 = 1_600_000_000
START = T0 + 10_000
EXPIRY = START + 50_000
REJECT = 'bad-txns-premature-spend-of-coinbase'


def maturity_for(height, activation):
    """Consensus schedule: pre-activation is 100; in-window is batched."""
    if height < activation:
        return COINBASE_MATURITY
    batch = (height - activation) % 6
    if batch == 0:
        return EXTENDED_SHORT
    if batch in (1, 2):
        return EXTENDED_MID
    return EXTENDED_LONG


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

    def mine(self, count):
        """Mine count blocks to the MiniWallet, keeping the mock clock within
        the two-hour future window of the creeping block times."""
        node = self.nodes[0]
        while count > 0:
            chunk = min(count, 1000)
            self.mocktime = max(self.mocktime, node.getblockheader(node.getbestblockhash())['time']) + chunk
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, chunk, sync_fun=self.no_op)
            count -= chunk

    def mtp(self, height):
        node = self.nodes[0]
        return node.getblockheader(node.getblockhash(height))['mediantime']

    def coinbase_utxo(self, height):
        node = self.nodes[0]
        txid = node.getblock(node.getblockhash(height))['tx'][0]
        return self.wallet.get_utxo(txid=txid)

    def assert_spend_rejected(self, tx_hex):
        node = self.nodes[0]
        assert_equal(node.testmempoolaccept([tx_hex])[0]['reject-reason'], REJECT)
        assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, tx_hex)

    def submit_block_with(self, tx_hex):
        """Mine a block carrying tx_hex ourselves and return submitblock's verdict."""
        node = self.nodes[0]
        tmpl = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        block = create_block(tmpl=tmpl, txlist=[tx_hex])
        add_witness_commitment(block)
        block.solve()
        return node.submitblock(block.serialize().hex())

    def assert_deploymentinfo(self, *, active, height=None):
        info = self.nodes[0].getdeploymentinfo()['deployments']['extended_coinbase_maturity']
        assert_equal(info['type'], 'flagday')
        assert_equal(info['start_time'], START)
        assert_equal(info['expiry_time'], EXPIRY)
        assert_equal(info['active'], active)
        assert_equal(info.get('height'), height)

    def assert_gbt_rule(self, *, active):
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert_equal('extended_coinbase_maturity' in tmpl['rules'], active)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Option validation")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=[f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}', f'-extendedcoinbasematurity={START}'],
            expected_msg='Error: -extendedcoinbasematurity requires -rdtsexpiry=<time> (window ends at RDTS expiry).')
        node.assert_start_raises_init_error(
            extra_args=[f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}', f'-rdtsexpiry={EXPIRY}', f'-extendedcoinbasematurity={EXPIRY}'],
            expected_msg=f'Error: Invalid start ({EXPIRY}) for -extendedcoinbasematurity=<time>: must precede the RDTS expiry ({EXPIRY}).')
        self.start_node(0)
        node.add_p2p_connection(P2PInterface())  # getblocktemplate needs a peer

        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        self.log.info("Before activation: the 100-block rule applies")
        self.generate(self.wallet, 200, sync_fun=self.no_op)  # crosses the BLAKE2b fork
        assert_greater_than(START, self.mtp(200))
        self.assert_deploymentinfo(active=False)
        self.assert_gbt_rule(active=False)
        spend = self.wallet.create_self_transfer(utxo_to_spend=self.coinbase_utxo(201 - COINBASE_MATURITY))
        node.sendrawtransaction(spend['hex'])
        self.generate(self.wallet, 1, sync_fun=self.no_op)

        self.log.info("Activation: the first block whose parent's median-time-past reaches the start time")
        self.mocktime = START
        node.setmocktime(self.mocktime)
        while self.mtp(node.getblockcount()) < START:
            self.assert_deploymentinfo(active=False)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        activation = node.getblockcount() + 1
        self.log.info(f"  activation height {activation}")
        self.assert_deploymentinfo(active=True, height=activation)
        self.assert_gbt_rule(active=True)
        self.generate(self.wallet, 1, sync_fun=self.no_op)  # block `activation`, the first in the window
        self.assert_deploymentinfo(active=True, height=activation)
        grandfathered = self.coinbase_utxo(activation - 1)
        # First window block: (activation - activation) % 6 == 0 -> short tranche
        locked = self.coinbase_utxo(activation)
        assert_equal(maturity_for(activation, activation), EXTENDED_SHORT)

        self.log.info("Inside the window: pre-activation coinbases keep the 100-block rule")
        self.mine(COINBASE_MATURITY)  # tip = activation + 100
        spend = self.wallet.create_self_transfer(utxo_to_spend=grandfathered)
        node.sendrawtransaction(spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)  # tip = activation + 101
        assert_equal(node.getrawmempool(), [])

        self.log.info("Inside the window: an in-window coinbase is locked past 100 confirmations")
        locked_spend = self.wallet.create_self_transfer(utxo_to_spend=locked)
        self.assert_spend_rejected(locked_spend['hex'])
        assert_equal(self.submit_block_with(locked_spend['hex']), REJECT)
        assert_equal(node.getblockcount(), activation + 101)

        if self.is_wallet_compiled():
            self.log.info("Wallet: an in-window reward stays immature past 100 confirmations")
            node.createwallet('miner')
            wallet_rpc = node.get_wallet_rpc('miner')
            self.mocktime += 1
            node.setmocktime(self.mocktime)
            self.generatetoaddress(node, 1, wallet_rpc.getnewaddress(), sync_fun=self.no_op)
            reward_height = node.getblockcount()
            self.mine(COINBASE_MATURITY + 10)
            balances = wallet_rpc.getbalances()['mine']
            assert_greater_than(balances['immature'], 0)
            assert_equal(balances['trusted'], 0)
            assert_equal(wallet_rpc.listunspent(), [])
            reward = wallet_rpc.listtransactions()[0]
            assert_equal(reward['category'], 'immature')
            assert_equal(reward['blockheight'], reward_height)

        self.log.info("-reindex reproduces the chain and the activation height")
        tip = node.getbestblockhash()
        self.restart_node(0, extra_args=self.base_args + ['-reindex'])
        node.setmocktime(self.mocktime)
        node.add_p2p_connection(P2PInterface())
        self.wait_until(lambda: node.getbestblockhash() == tip)
        self.assert_deploymentinfo(active=True, height=activation)
        self.assert_gbt_rule(active=True)
        self.assert_spend_rejected(locked_spend['hex'])

        self.log.info(f"Short tranche spendable at exactly {EXTENDED_SHORT} confirmations")
        self.mine(activation + EXTENDED_SHORT - 2 - node.getblockcount())
        assert_equal(node.getblockcount(), activation + EXTENDED_SHORT - 2)
        self.assert_spend_rejected(locked_spend['hex'])
        self.mine(1)
        self.assert_deploymentinfo(active=True, height=activation)
        node.sendrawtransaction(locked_spend['hex'])
        assert_equal(node.getrawmempool(), [locked_spend['txid']])
        self.generate(node, 1, sync_fun=self.no_op)
        mature_block = node.getbestblockhash()
        assert_equal(node.getblockcount(), activation + EXTENDED_SHORT)
        assert locked_spend['txid'] in node.getblock(mature_block)['tx']

        self.log.info("A reorg below the maturity boundary evicts the spend from the mempool")
        node.invalidateblock(mature_block)
        assert_equal(node.getrawmempool(), [locked_spend['txid']])
        boundary_block = node.getbestblockhash()
        node.invalidateblock(boundary_block)
        assert_equal(node.getrawmempool(), [])
        node.reconsiderblock(boundary_block)
        assert_equal(node.getbestblockhash(), mature_block)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Expiry: window coins stay locked; new coinbases use 100")
        still_locked_height = activation + 3
        if node.getblockcount() < still_locked_height:
            self.mine(still_locked_height - node.getblockcount())
        still_locked = self.coinbase_utxo(still_locked_height)
        assert_equal(maturity_for(still_locked_height, activation), EXTENDED_LONG)
        still_locked_spend = self.wallet.create_self_transfer(utxo_to_spend=still_locked)
        self.assert_spend_rejected(still_locked_spend['hex'])

        self.mocktime = EXPIRY
        node.setmocktime(self.mocktime)
        self.generate(node, 5, sync_fun=self.no_op)
        assert_greater_than(EXPIRY, self.mtp(node.getblockcount()))
        self.assert_deploymentinfo(active=True, height=activation)
        self.assert_gbt_rule(active=True)
        self.assert_spend_rejected(still_locked_spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(self.mtp(node.getblockcount()), EXPIRY)
        self.assert_deploymentinfo(active=False, height=activation)
        self.assert_gbt_rule(active=False)
        # #402 would accept still_locked_spend here. The lock sticks:
        self.assert_spend_rejected(still_locked_spend['hex'])
        self.generate(self.wallet, 1, sync_fun=self.no_op)
        post_h = node.getblockcount()
        post_utxo = self.coinbase_utxo(post_h)
        post_spend = self.wallet.create_self_transfer(utxo_to_spend=post_utxo)
        self.mine(COINBASE_MATURITY)
        node.sendrawtransaction(post_spend['hex'])
        self.generate(node, 1, sync_fun=self.no_op)
        assert post_spend['txid'] in node.getblock(node.getbestblockhash())['tx']


if __name__ == '__main__':
    ExtendedCoinbaseMaturityTest(__file__).main()
