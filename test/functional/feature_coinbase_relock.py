#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the experimental, one-generation coinbase payout maturity rule.

Coinbase inputs retain their 100-block maturity. Spending one at an age below
1,000 blocks freezes every output of the spending transaction for 1,000 blocks
from its confirmation. Once those outputs mature, the restriction does not
propagate. This test opts in on regtest; no public network activation is set.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


ACTIVATION_HEIGHT = 103
RELOCK_REASON = "bad-txns-premature-spend-of-coinbase-payout"
COINBASE_REASON = "bad-txns-premature-spend-of-coinbase"


class CoinbaseRelockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-testactivationheight=coinbaserelock@{ACTIVATION_HEIGHT}",
            '-coinstatsindex',
        ]]

    def mine_to(self, height):
        count = height - self.node.getblockcount()
        assert count >= 0
        if count:
            self.generate(self.wallet, count)
        assert_equal(self.node.getblockcount(), height)

    def empty_block(self):
        return self.generateblock(self.node, self.wallet.get_address(), [])['hash']

    def make_block(self, txs):
        """Construct independently of block assembly, including witness commitment."""
        tip = self.node.getbestblockhash()
        height = self.node.getblockcount() + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(height, script_pubkey=self.wallet.get_output_script()),
            self.node.getblockheader(tip)['time'] + 1,
            height=height,
            txlist=[tx['tx'] for tx in txs],
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_block(self, txs, *, reject_reason=None):
        block = self.make_block(txs)
        old_tip = self.node.getbestblockhash()
        assert_equal(self.node.submitblock(block.serialize().hex()), reject_reason)
        assert_equal(self.node.getbestblockhash(), old_tip if reject_reason else block.hash)
        return block.hash

    def assert_rejected(self, tx, reason=RELOCK_REASON):
        result = self.node.testmempoolaccept([tx['hex']])[0]
        assert_equal(result['allowed'], False)
        assert_equal(result['reject-reason'], reason)
        assert_raises_rpc_error(-26, reason, self.node.sendrawtransaction, tx['hex'])

    def assert_allowed(self, tx):
        assert_equal(self.node.testmempoolaccept([tx['hex']])[0]['allowed'], True)

    def assert_coin_metadata(self, utxo, *, relocked, unlock_height=None):
        coin = self.node.gettxout(utxo['txid'], utxo['vout'])
        assert_equal(coin['coinbase'], False)
        assert_equal(coin['coinbase_relocked'], relocked)
        if unlock_height is None:
            assert 'coinbase_relock_height' not in coin
        else:
            assert_equal(coin['coinbase_relock_height'], unlock_height)

    def send(self, tx):
        assert_equal(self.node.sendrawtransaction(tx['hex']), tx['txid'])

    def assert_coinstats(self):
        self.wait_until(lambda: self.node.getindexinfo()['coinstatsindex']['synced'])
        scanned = self.node.gettxoutsetinfo('muhash', None, False)
        indexed = self.node.gettxoutsetinfo('muhash')
        for field in ('bestblock', 'txouts', 'total_amount', 'muhash'):
            assert_equal(scanned[field], indexed[field])

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, 4)
        coinbases = [
            self.wallet.get_utxo(txid=self.node.getblock(self.node.getblockhash(height))['tx'][0])
            for height in range(1, 5)
        ]

        self.log.info("Original coinbase maturity remains 100 blocks")
        self.mine_to(99)
        before_activation = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[coinbases[0]], num_outputs=3,
        )
        self.assert_rejected(before_activation, COINBASE_REASON)
        self.submit_block([before_activation], reject_reason=COINBASE_REASON)
        self.empty_block()
        self.assert_allowed(before_activation)  # Height 101 - coinbase height 1 = 100.
        before_activation_child = self.wallet.create_self_transfer(
            utxo_to_spend=before_activation['new_utxos'][0],
        )
        self.submit_block([before_activation, before_activation_child])
        assert_equal(self.node.getblockcount(), 101)

        self.log.info("Activation revalidates an existing mempool parent and child")
        payout = self.wallet.create_self_transfer(utxo_to_spend=coinbases[1])
        payout_child = self.wallet.create_self_transfer(utxo_to_spend=payout['new_utxo'])
        self.send(payout)
        self.send(payout_child)
        assert_equal(set(self.node.getrawmempool()), {payout['txid'], payout_child['txid']})
        self.empty_block()  # Transactions for the next block now use the new rule.
        assert_equal(self.node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(self.node.getrawmempool(), [payout['txid']])
        self.assert_rejected(payout_child)
        self.assert_coin_metadata(payout['new_utxo'], relocked=True)
        self.assert_coin_metadata(before_activation['new_utxos'][2], relocked=False)

        self.log.info("A coinbase in any input position freezes all outputs, including change")
        mixed_payout = self.wallet.create_self_transfer_multi(
            # Put the ordinary input first to check that every input is inspected.
            utxos_to_spend=[before_activation['new_utxos'][1], coinbases[2]],
            num_outputs=2,
        )
        mixed_children = [
            self.wallet.create_self_transfer(utxo_to_spend=utxo)
            for utxo in mixed_payout['new_utxos']
        ]

        self.log.info("Packages and externally constructed blocks cannot spend a fresh payout")
        # Neither transaction in this package is already in the mempool, so
        # validation must also attach the restriction to temporary package coins.
        package_hex = [mixed_payout['hex'], mixed_children[0]['hex']]
        package = self.node.testmempoolaccept(package_hex)
        assert_equal(package[1]['allowed'], False)
        assert_equal(package[1]['reject-reason'], RELOCK_REASON)
        result = self.node.submitpackage(package_hex)
        assert_equal(result['package_msg'], "transaction failed")
        assert RELOCK_REASON in result['tx-results'][mixed_children[0]['wtxid']]['error']
        assert_equal(set(self.node.getrawmempool()), {payout['txid'], mixed_payout['txid']})
        self.submit_block([payout, payout_child], reject_reason=RELOCK_REASON)
        for child in mixed_children:
            self.assert_rejected(child)
        self.submit_block([payout, mixed_payout])
        payout_height = self.node.getblockcount()
        assert_equal(payout_height, ACTIVATION_HEIGHT)
        frozen_children = [payout_child, *mixed_children]
        frozen_utxos = [payout['new_utxo'], *mixed_payout['new_utxos']]
        for child in frozen_children:
            self.assert_rejected(child)
        for utxo in frozen_utxos:
            self.assert_coin_metadata(utxo, relocked=True, unlock_height=payout_height + 1000)
        self.assert_coinstats()

        self.log.info("Coin flags survive restart and reconstruction from block files")
        for restart_args in ([], ['-reindex-chainstate'], ['-reindex']):
            self.restart_node(0, extra_args=self.extra_args[0] + restart_args)
            self.wait_until(lambda: self.node.getblockcount() == payout_height)
            for child in frozen_children:
                self.assert_rejected(child)
            for utxo in frozen_utxos:
                self.assert_coin_metadata(utxo, relocked=True, unlock_height=payout_height + 1000)
            self.assert_coinstats()

        self.log.info("Pre-activation payouts and unrelated ordinary UTXOs remain spendable")
        ordinary = self.wallet.create_self_transfer(utxo_to_spend=before_activation['new_utxos'][2])
        ordinary_child = self.wallet.create_self_transfer(utxo_to_spend=ordinary['new_utxo'])
        self.send(ordinary)
        self.send(ordinary_child)
        self.submit_block([ordinary, ordinary_child])

        self.log.info("A pending coinbase spend stops triggering the lock at age 1,000")
        self.mine_to(1002)
        boundary_payout = self.wallet.create_self_transfer(utxo_to_spend=coinbases[3])
        boundary_child = self.wallet.create_self_transfer(utxo_to_spend=boundary_payout['new_utxo'])
        self.send(boundary_payout)  # Next height 1003 - coinbase height 4 = 999.
        self.assert_rejected(boundary_child)
        self.assert_coin_metadata(boundary_payout['new_utxo'], relocked=True)
        self.submit_block([boundary_payout, boundary_child], reject_reason=RELOCK_REASON)
        transition_block = self.empty_block()
        self.assert_coin_metadata(boundary_payout['new_utxo'], relocked=False)
        self.send(boundary_child)  # Next height 1004 - coinbase height 4 = 1000.

        self.log.info("Reorg back across age 1,000 evicts a newly frozen mempool child")
        self.node.invalidateblock(transition_block)
        assert_equal(self.node.getblockcount(), 1002)
        assert_equal(self.node.getrawmempool(), [boundary_payout['txid']])
        self.assert_rejected(boundary_child)
        self.node.reconsiderblock(transition_block)
        assert_equal(self.node.getblockcount(), 1003)
        self.send(boundary_child)
        self.submit_block([boundary_payout, boundary_child])

        self.log.info("Payout outputs are locked for a fresh 1,000 blocks after confirmation")
        self.mine_to(payout_height + 998)
        # The next spending block has age 999, although the original coinbase
        # is already more than 1,000 blocks old.
        for child in frozen_children:
            self.assert_rejected(child)
        self.submit_block([payout_child], reject_reason=RELOCK_REASON)
        maturity_tip = self.empty_block()
        for child in frozen_children:
            self.assert_allowed(child)
        for utxo in frozen_utxos:
            self.assert_coin_metadata(utxo, relocked=True, unlock_height=payout_height + 1000)

        self.log.info("The restriction ends after one generation, including within one block")
        grandchild = self.wallet.create_self_transfer(utxo_to_spend=payout_child['new_utxo'])
        for tx in [*frozen_children, grandchild]:
            self.send(tx)
        spend_block = self.submit_block([*frozen_children, grandchild])
        assert_equal(self.node.getblockcount(), payout_height + 1000)
        self.assert_coinstats()

        self.log.info("Undo restores the payout flag, and reorg removes premature descendants")
        self.restart_node(0)
        self.node.invalidateblock(maturity_tip)
        assert_equal(self.node.getblockcount(), payout_height + 998)
        assert_equal(self.node.getrawmempool(), [])
        for child in frozen_children:
            self.assert_rejected(child)
        for utxo in frozen_utxos:
            self.assert_coin_metadata(utxo, relocked=True, unlock_height=payout_height + 1000)
        self.assert_coinstats()
        self.node.reconsiderblock(maturity_tip)
        assert_equal(self.node.getbestblockhash(), spend_block)
        self.assert_coinstats()

        self.log.info("A competing chain crossing activation cleans up disconnected inputs first")
        self.wallet.rescan_utxos()
        old_coinbase = self.wallet.get_utxo(
            txid=self.node.getblock(self.node.getblockhash(ACTIVATION_HEIGHT + 1))['tx'][0],
        )
        old_branch_spend = self.wallet.create_self_transfer(utxo_to_spend=old_coinbase)
        old_branch_child = self.wallet.create_self_transfer(utxo_to_spend=old_branch_spend['new_utxo'])
        self.send(old_branch_spend)
        self.send(old_branch_child)

        # Keep a spend of a mature, old-branch coinbase in the mempool while
        # replacing the chain from just before activation. At the intermediate
        # activation boundary that coinbase input is absent. The reorg must
        # remove its spenders before attempting activation mempool validation.
        fork_height = ACTIVATION_HEIGHT - 3
        fork_hash = self.node.getblockhash(fork_height)
        block_time = self.node.getblockheader(fork_hash)['time']
        previous = int(fork_hash, 16)
        alternative = []
        for height in range(fork_height + 1, self.node.getblockcount() + 2):
            block_time += 1
            block = create_block(previous, create_coinbase(height), block_time, height=height)
            block.solve()
            alternative.append(block)
            previous = block.sha256
        peer = self.node.add_p2p_connection(P2PDataStore())
        peer.send_blocks_and_test(alternative, self.node)
        assert old_branch_spend['txid'] not in self.node.getrawmempool()
        assert old_branch_child['txid'] not in self.node.getrawmempool()
        self.assert_coinstats()


if __name__ == '__main__':
    CoinbaseRelockTest(__file__).main()
