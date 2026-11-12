#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Experimental sibling-only next-block exception (synthetic transactions)."""
from decimal import Decimal
from copy import deepcopy
from time import perf_counter, time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.script_util import PAY_TO_ANCHOR


class TrucNextBlockTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument('--rdts', action='store_true')
        parser.add_argument('--stress', action='store_true')
        parser.add_argument('--mixed', action='store_true')

    def set_test_params(self):
        self.num_nodes = 2 if self.options.mixed else 1
        self.setup_clean_chain = True
        self.activation_args = ['-testactivationheight=blake2b@100', '-rdtsexpiry=2000000000'] if self.options.rdts else []
        self.fee_args = ['-blockmintxfee=0.00001000', '-minrelaytxfee=0.00001000']
        self.extra_args = [['-persistmempool=1', '-mempooltruc=enforce', '-trucsiblingnextblock=1'] + self.activation_args + self.fee_args]
        if self.options.mixed:
            self.extra_args.append(['-mempooltruc=enforce', '-trucsiblingnextblock=0'] + self.activation_args + self.fee_args)

    def run_test(self):
        if self.options.mixed:
            return self.run_mixed()
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 2800 if self.options.stress else 800)

        def restart(enabled=True, mode='enforce', core=1, fee_mining=False, shared=False, overrides=None):
            mining = ['-blockprioritysize=0', '-blockmaxsize=4000000', '-blockmaxweight=4000000'] if fee_mining else []
            self.restart_node(0, extra_args=['-persistmempool=1', f'-corepolicy={core}', f'-mempooltruc={mode}', f'-trucsiblingnextblock={int(enabled)}', f'-trucsharedanchornextblock={int(shared)}'] + self.activation_args + self.fee_args + mining + (overrides or []))
            wallet.rescan_utxos()

        def child(utxo, fee, outputs=1, version=3):
            if outputs > 1:
                return wallet.create_self_transfer_multi(utxos_to_spend=[utxo], num_outputs=outputs,
                    fee_per_output=fee // outputs, version=version)
            return wallet.create_self_transfer(utxo_to_spend=utxo, version=version, fee=Decimal(fee)/100000000)

        def pair(parent_fee=2000):
            parent = wallet.create_self_transfer_multi(confirmed_only=True, num_outputs=2, version=3, fee_per_output=parent_fee//2)
            old = child(parent['new_utxos'][0], 10000, outputs=20)
            assert_equal(node.submitpackage([parent['hex'], old['hex']])['package_msg'], 'success')
            return parent, old

        def reject(tx):
            assert_raises_rpc_error(-26, 'insufficient fee', node.sendrawtransaction, tx['hex'])

        self.log.info('Empty mempool: old package is already next-block eligible; no exception')
        parent, old = pair()
        reject(child(parent['new_utxos'][1], 3000))
        self.generate(node, 1)
        wallet.rescan_utxos()

        self.log.info('Fill fee-based projection at 15 sat/vB, leaving less than a parent of space')
        # Real outputs avoid synthetic data-padding exceptions under native policy.
        # Fill 999,000 vB (4,000,000 weight minus 4,000 coinbase/header reserve).
        remaining = 199000 if self.options.rdts else 999000
        while remaining >= 104:
            outputs = min(230, (remaining - 61) // 43)
            tx = wallet.create_self_transfer_multi(confirmed_only=True, num_outputs=outputs, fee_per_output=700)
            size = tx['tx'].get_vsize()
            # Select an exact fee; rounding among outputs may add < outputs sats.
            tx = wallet.create_self_transfer_multi(utxos_to_spend=[wallet.get_utxo(confirmed_only=True)],
                num_outputs=outputs, fee_per_output=(size*15 + outputs-1)//outputs)
            node.sendrawtransaction(tx['hex'], 0)
            remaining -= tx['tx'].get_vsize()
        assert remaining < 104
        # Small competing transactions fill gaps after larger packages move in.
        for _ in range(100):
            wallet.send_self_transfer(from_node=node, confirmed_only=True, fee=Decimal(1560)/100000000)
        wallet.rescan_utxos()

        parent, old = pair()
        honest = child(parent['new_utxos'][1], 5000)
        self.log.info('Disabled feature preserves absolute fee requirement')
        restart(enabled=False)
        reject(honest)
        restart()
        self.log.info('Higher feerate but still outside projected block: rejected')
        reject(child(parent['new_utxos'][1], 1600))
        self.log.info('Direct conflict is never exempted')
        reject(child(parent['new_utxos'][0], 3000))
        self.log.info('Local fee delta cannot manufacture eligibility')
        node.prioritisetransaction(parent['txid'], 0, 1)
        reject(honest)
        node.prioritisetransaction(parent['txid'], 0, -1)
        competitor = next(txid for txid in node.getrawmempool() if txid not in [parent['txid'], old['txid']])
        node.prioritisetransaction(competitor, 0, 1)
        reject(honest)
        node.prioritisetransaction(competitor, 0, -1)
        self.log.info('Native default miner: incompatible projection must fail closed')
        restart(core=0)
        default_template = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        self.log.info('Default miner selects old child: %s (projection does not model priority space)', old['txid'] in {t['txid'] for t in default_template['transactions']})
        reject(honest)
        assert old['txid'] in node.getrawmempool()
        for setting in ['-blockmaxweight=700000', '-blockmaxsize=100000', '-blockreservedweight=12000', '-blockmintxfee=0.00002000']:
            restart(overrides=[setting])
            reject(honest)
        restart(core=0, fee_mining=True)
        before_template = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert old['txid'] not in {t['txid'] for t in before_template['transactions']}
        before_pool = set(node.getrawmempool())
        started = perf_counter()
        for nonce in range(10):
            invalid = deepcopy(honest['tx'])
            invalid.vout[0].nValue -= nonce  # Distinct txids, not one cached rejection.
            invalid.wit.vtxinwit[0].scriptWitness.stack[-1] = bytes(33)
            assert_raises_rpc_error(-26, None, node.sendrawtransaction, invalid.serialize().hex())
        self.log.info('Ten invalid-witness submissions: %.4fs', perf_counter() - started)
        assert_equal(set(node.getrawmempool()), before_pool)
        assert_equal(node.sendrawtransaction(honest['hex']), honest['txid'])
        assert old['txid'] not in node.getrawmempool()
        assert parent['txid'] in node.getrawmempool()
        node.setmocktime(int(time()) + 10)  # Expire the five-second template cache.
        after_template = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert honest['txid'] in {t['txid'] for t in after_template['transactions']}
        self.log.info('Actual block-template fee delta: %d sats', sum(t['fee'] for t in after_template['transactions']) - sum(t['fee'] for t in before_template['transactions']))
        assert sum(t['fee'] for t in after_template['transactions']) >= sum(t['fee'] for t in before_template['transactions'])
        node.setmocktime(0)
        self.log.info('No second cheap replacement once the parent is next-block eligible')
        # The existing 104-vB child cannot shrink further; this is also prevented
        # by the already-selected-package gate, independently tested below.
        reject(child(parent['new_utxos'][0], 2500))

        self.log.info('An already-selected high-fee parent cannot hide behind a low-fee child')
        parent2, old2 = pair(parent_fee=10000)
        reject(child(parent2['new_utxos'][1], 3000))

        self.log.info('Core policy: second independent eligible pair uses same exception')
        restart(core=1)
        parent3, old3 = pair()
        honest3 = child(parent3['new_utxos'][1], 5000)
        assert_equal(node.sendrawtransaction(honest3['hex']), honest3['txid'])
        assert old3['txid'] not in node.getrawmempool()

        self.log.info('Further shrinking with sufficient ratio still fails once package is selected')
        parent4, old4 = pair()
        first = child(parent4['new_utxos'][1], 8000, outputs=4)
        assert_equal(node.sendrawtransaction(first['hex']), first['txid'])
        second = child(parent4['new_utxos'][0], 7000)
        assert second['tx'].get_vsize() < first['tx'].get_vsize()
        reject(second)

        self.log.info('Ordinary sufficiently funded sibling eviction remains available')
        funded = child(parent4['new_utxos'][0], 12000)
        assert_equal(node.sendrawtransaction(funded['hex']), funded['txid'])

        self.log.info('Zero-fee parent: distinct-output sibling can recover without covering old absolute fee')
        zero_parent, zero_old = pair(parent_fee=0)
        zero_new = child(zero_parent['new_utxos'][1], 5000)
        assert_equal(node.sendrawtransaction(zero_new['hex']), zero_new['txid'])
        assert zero_old['txid'] not in node.getrawmempool()

        self.log.info('Shared P2A anchor: direct conflicts remain subject to Rule 3')
        anchor_parent = wallet.create_self_transfer_multi(confirmed_only=True, num_outputs=2, version=3, fee_per_output=0)
        anchor_parent['tx'].vout[1].nValue += anchor_parent['tx'].vout[0].nValue - 330
        anchor_parent['tx'].vout[0].nValue = 330
        anchor_parent['tx'].vout[0].scriptPubKey = PAY_TO_ANCHOR
        anchor_id = anchor_parent['tx'].rehash()
        anchor = dict(anchor_parent['new_utxos'][0], txid=anchor_id, value=Decimal(330)/100000000)

        def anchor_child(fee, outputs):
            tx = wallet.create_self_transfer_multi(utxos_to_spend=[anchor, wallet.get_utxo(confirmed_only=True)],
                version=3, num_outputs=outputs, fee_per_output=fee//outputs)['tx']
            tx.wit.vtxinwit[0] = deepcopy(tx.wit.vtxinwit[0])
            tx.wit.vtxinwit[0].scriptWitness.stack = []
            return tx

        anchor_old = anchor_child(10000, 20)
        assert anchor_old.get_vsize() <= 1000
        assert_equal(node.submitpackage([anchor_parent['tx'].serialize().hex(), anchor_old.serialize().hex()])['package_msg'], 'success')
        anchor_new = anchor_child(5000, 1)
        assert anchor_new.get_vsize() < anchor_old.get_vsize()
        assert 5000 * anchor_old.get_vsize() > 10000 * anchor_new.get_vsize()
        assert 10000 < 15 * (anchor_parent['tx'].get_vsize() + anchor_old.get_vsize())
        assert 5000 > 15 * (anchor_parent['tx'].get_vsize() + anchor_new.get_vsize())
        self.log.info('Shared anchor: old 10000 sats/%d vB; replacement 5000 sats/%d vB remains rejected', anchor_old.get_vsize(), anchor_new.get_vsize())
        assert_raises_rpc_error(-26, 'insufficient fee', node.sendrawtransaction, anchor_new.serialize().hex())
        assert anchor_old.rehash() in node.getrawmempool()
        restart(shared=True)
        # Mempool reload admits transactions individually, not as packages.
        # Restore zero-fee parent packages explicitly after changing the opt-in.
        if anchor_old.rehash() not in node.getrawmempool():
            assert_equal(node.submitpackage([anchor_parent['tx'].serialize().hex(), anchor_old.serialize().hex()])['package_msg'], 'success')
        if zero_new['txid'] not in node.getrawmempool():
            assert_equal(node.submitpackage([zero_parent['hex'], zero_new['hex']])['package_msg'], 'success')
        assert anchor_old.rehash() in node.getrawmempool()
        assert zero_new['txid'] in node.getrawmempool()
        before_anchor_template = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert anchor_old.rehash() not in {t['txid'] for t in before_anchor_template['transactions']}
        before_anchor = set(node.getrawmempool())
        invalid_anchor = deepcopy(anchor_new)
        invalid_anchor.wit.vtxinwit[1].scriptWitness.stack[-1] = bytes(33)
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, invalid_anchor.serialize().hex())
        assert_equal(set(node.getrawmempool()), before_anchor)
        assert_equal(node.sendrawtransaction(anchor_new.serialize().hex()), anchor_new.rehash())
        assert anchor_old.rehash() not in node.getrawmempool()
        node.setmocktime(int(time()) + 10)
        anchor_template = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert anchor_new.rehash() in {t['txid'] for t in anchor_template['transactions']}
        assert sum(t['fee'] for t in anchor_template['transactions']) >= sum(t['fee'] for t in before_anchor_template['transactions'])
        node.setmocktime(0)
        self.log.info('Opt-in shared P2A anchor recovery accepted and selected by fee-only miner')
        wallet.rescan_utxos()  # Account for packages restored after restart and raw anchor sends.
        non_anchor_parent, non_anchor_old = pair()
        reject(child(non_anchor_parent['new_utxos'][0], 5000))
        assert non_anchor_old['txid'] in node.getrawmempool()

        self.log.info('Unconfirmed Ark-shaped tree: grandchild stays forbidden until parent confirms')
        grandchild = child(zero_new['new_utxo'], 1000)
        assert_raises_rpc_error(-26, 'truc-ancestors-toomany', node.sendrawtransaction, grandchild['hex'])
        self.generateblock(node, wallet.get_address(), [zero_parent['hex']])
        delayed = wallet.create_self_transfer(utxo_to_spend=zero_new['new_utxo'], version=3,
            sequence=1, fee=Decimal(1000)/100000000)
        assert_raises_rpc_error(-26, 'non-BIP68-final', node.sendrawtransaction, delayed['hex'])
        self.generateblock(node, wallet.get_address(), [zero_new['hex']])
        assert_equal(node.sendrawtransaction(delayed['hex']), delayed['txid'])
        self.log.info('One-block relative delay respected; serialized recovery accepted after confirmation')

        self.log.info('Moving congestion can permit a second shrinking exception on the same parent')
        drift_parent, drift_old = pair()
        drift_first = child(drift_parent['new_utxos'][1], 8000, outputs=4)
        node.sendrawtransaction(drift_first['hex'])
        drift_second = child(drift_parent['new_utxos'][0], 7000)
        reject(drift_second)
        remaining = 199000 if self.options.rdts else 999000
        while remaining >= 104:
            outputs = min(230, (remaining - 61)//43)
            size = 61 + 43*outputs
            tx = wallet.create_self_transfer_multi(confirmed_only=True, num_outputs=outputs,
                fee_per_output=(size*30 + outputs-1)//outputs)
            node.sendrawtransaction(tx['hex'], 0)
            remaining -= tx['tx'].get_vsize()
        for _ in range(100):
            wallet.send_self_transfer(from_node=node, confirmed_only=True, fee=Decimal(3120)/100000000)
        assert_equal(node.sendrawtransaction(drift_second['hex']), drift_second['txid'])
        assert drift_first['txid'] not in node.getrawmempool()

        if self.options.stress:
            self.log.info('Indexed projection: add 1,500 high-feerate independent competitors')
            for _ in range(1500):
                wallet.send_self_transfer(from_node=node, confirmed_only=True, fee=Decimal(4160)/100000000)
            budget_parent, budget_old = pair()
            candidate = child(budget_parent['new_utxos'][1], 9000)
            started = perf_counter()
            assert_equal(node.sendrawtransaction(candidate['hex']), candidate['txid'])
            self.log.info('Indexed projection acceptance: %.4fs with %d entries', perf_counter() - started, len(node.getrawmempool()))
            assert budget_old['txid'] not in node.getrawmempool()

        self.log.info('Accept mode never gains TRUC sibling eviction from the experimental flag')
        restart(mode='accept')
        parent5 = wallet.send_self_transfer_multi(from_node=node, version=3, confirmed_only=True, num_outputs=2)
        a = child(parent5['new_utxos'][0], 10000, outputs=20)
        b = child(parent5['new_utxos'][1], 5000)
        node.sendrawtransaction(a['hex'])
        node.sendrawtransaction(b['hex'])
        assert a['txid'] in node.getrawmempool()
        assert b['txid'] in node.getrawmempool()

        self.log.info('Legacy v2 Lightning-shaped anchors: no sibling eviction; direct Rule 3 unchanged')
        restart()
        legacy_parent = wallet.send_self_transfer_multi(from_node=node, confirmed_only=True, version=2, num_outputs=2)
        legacy_old = child(legacy_parent['new_utxos'][0], 10000, outputs=20, version=2)
        node.sendrawtransaction(legacy_old['hex'])
        reject(child(legacy_parent['new_utxos'][0], 5000, version=2))
        legacy_other = child(legacy_parent['new_utxos'][1], 5000, version=2)
        node.sendrawtransaction(legacy_other['hex'])
        assert legacy_old['txid'] in node.getrawmempool()
        assert legacy_other['txid'] in node.getrawmempool()

    def run_mixed(self):
        enabled, stock = self.nodes
        wallet = MiniWallet(enabled)
        self.generate(wallet, 500)
        remaining = 199000 if self.options.rdts else 999000
        while remaining >= 104:
            outputs = min(230, (remaining - 61)//43)
            size = 61 + 43*outputs
            tx = wallet.create_self_transfer_multi(confirmed_only=True, num_outputs=outputs,
                fee_per_output=(size*15 + outputs-1)//outputs)
            wallet.sendrawtransaction(from_node=enabled, tx_hex=tx['hex'])
            remaining -= tx['tx'].get_vsize()
        for _ in range(100):
            wallet.send_self_transfer(from_node=enabled, confirmed_only=True, fee=Decimal(1560)/100000000)
        parent = wallet.create_self_transfer_multi(confirmed_only=True, version=3, num_outputs=2)
        old = wallet.create_self_transfer_multi(utxos_to_spend=[parent['new_utxos'][0]], version=3,
            num_outputs=20, fee_per_output=500)
        enabled.submitpackage([parent['hex'], old['hex']])
        self.sync_mempools()
        honest = wallet.create_self_transfer(utxo_to_spend=parent['new_utxos'][1], version=3,
            fee=Decimal(5000)/100000000)
        self.log.info('Mixed-policy P2P: enabled node relays candidate, stock-policy peer rejects it')
        # Inventory relay is asynchronous and randomized; the default two-second
        # log timeout can expire before announcement under concurrent test load.
        with stock.assert_debug_log(['insufficient fee (including sibling eviction)'], timeout=60):
            enabled.sendrawtransaction(honest['hex'])
        assert honest['txid'] in enabled.getrawmempool()
        assert old['txid'] not in enabled.getrawmempool()
        assert old['txid'] in stock.getrawmempool()
        assert honest['txid'] not in stock.getrawmempool()
        self.log.info('Both policies validate a block containing the replacement; no consensus change')
        result = self.generateblock(enabled, wallet.get_address(), [parent['hex'], honest['hex']], sync_fun=self.sync_blocks)
        assert_equal(stock.getbestblockhash(), result['hash'])
        # Different-output siblings are not consensus double spends. The old
        # child may still be mined after the parent confirms.
        assert old['txid'] in stock.getrawmempool()
        self.log.info('Disconnect and reconsider the block on both nodes')
        for node in self.nodes:
            node.invalidateblock(result['hash'])
        self.sync_blocks()
        for node in self.nodes:
            node.reconsiderblock(result['hash'])
        self.sync_blocks()
        assert_equal(enabled.getbestblockhash(), stock.getbestblockhash())


if __name__ == '__main__':
    TrucNextBlockTest(__file__).main()

