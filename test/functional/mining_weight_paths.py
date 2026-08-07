#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Block assembly must never select more consensus weight than -blockmaxweight,
even when policy vsize is discounted below real weight.

-scriptsigcost=0.25 discounts scriptSig bytes for policy purposes, so an
input-heavy legacy transaction reports a vsize well below weight/4. Every path
that fills a block is covered:

  A. addPackageTxs, independent transactions
  B. addPackageTxs, ancestor packages (CPFP)
  C. addPriorityTxs -> TestForBlock
  D. fNeedSizeAccounting=true (-blockmaxsize below MAX_BLOCK_SERIALIZED_SIZE)

Each scenario derives its weight limit from the assembler's actual selection
order: build a template with a huge limit, walk the chosen transactions, and
find a prefix where the next one's discounted estimate would fit but its real
weight would not. A round-number limit proves nothing, because the assembler
just runs out of transactions before reaching the boundary.
"""

from decimal import Decimal

from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, OP_DUP, sign_input_legacy
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than
from test_framework.wallet import MiniWallet, MiniWalletMode

RESERVED = 8000
BIG_LIMIT = 4000000


class MiningWeightPathsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-scriptsigcost=0.25', '-blockmaxsize=4000000',
                            f'-blockreservedweight={RESERVED}']]

    def node_args(self, limit, prioritysize, maxsize):
        # -persistmempool=0 so each scenario starts from an empty mempool;
        # leftovers from a previous scenario would break the calibration.
        return ['-scriptsigcost=0.25', '-persistmempool=0',
                f'-blockmaxsize={maxsize}', f'-blockreservedweight={RESERVED}',
                f'-blockprioritysize={prioritysize}', f'-blockmaxweight={limit}']

    def build_tx(self, wallet, utxos, num_outputs, fee=100_000):
        spk = wallet._scriptPubKey
        priv = wallet._priv_key
        value_in = sum(int(COIN * u['value']) for u in utxos)
        amount = (value_in - fee) // num_outputs
        assert amount > 0
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(u['txid'], 16), u['vout'])) for u in utxos]
        tx.vout = [CTxOut(amount, bytearray(spk)) for _ in range(num_outputs)]
        p2pkh = bytes(spk)[:1] == bytes([OP_DUP])
        pub = priv.get_pubkey().get_bytes()
        for i in range(len(tx.vin)):
            tx.vin[i].scriptSig = CScript([pub]) if p2pkh else b''
            sign_input_legacy(tx, i, spk, priv)
        return tx

    def submit(self, raws):
        failed = []
        for raw in raws:
            try:
                self.nodes[0].sendrawtransaction(raw)
            except Exception as e:
                if 'already in' not in str(e) and 'txn-already' not in str(e):
                    failed.append(str(e)[:110])
        assert not failed, f"transactions failed to enter the mempool: {failed[:3]}"

    def calibrate(self, raws, prioritysize, maxsize, skip_first=0):
        node = self.nodes[0]
        self.restart_node(0, extra_args=self.node_args(BIG_LIMIT, prioritysize, maxsize))
        self.submit(raws)
        txs = node.getblocktemplate({'rules': ['segwit']})['transactions']
        assert_greater_than(len(txs), 1)
        w = [t['weight'] for t in txs]
        v = [node.getmempoolentry(t['txid'])['vsize'] for t in txs]
        cum, seen = RESERVED, 0
        for k in range(len(txs) - 1):
            cum += w[k]
            nw, nv = w[k + 1], 4 * v[k + 1]
            if nw > nv + 1:
                seen += 1
                if seen <= skip_first:
                    continue
                return cum + nv + (nw - nv) // 2, nw, nv
        raise AssertionError("no discounted transaction found to calibrate against")

    def check(self, name, raws, prioritysize, maxsize, skip_first=0):
        limit, nw, nv = self.calibrate(raws, prioritysize, maxsize, skip_first)
        self.restart_node(0, extra_args=self.node_args(limit, prioritysize, maxsize))
        self.submit(raws)
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit']})
        assembled = RESERVED + sum(t['weight'] for t in tmpl['transactions'])
        over = assembled - limit
        self.log.info(f"   {name}: limit={limit} (next tx real W={nw} vs est 4V={nv}) "
                      f"-> {len(tmpl['transactions'])} txs, assembled={assembled}"
                      + (f"  OVERSHOOT by {over}" if over > 0 else "  (within limit)"))
        self.results.append((name, over))

    def run_test(self):
        self.results = []
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        self.generate(wallet, 400)
        utxos = wallet.get_utxos(mark_as_spent=True, confirmed_only=True)
        idx = 0
        assert_greater_than(len(utxos), 210)

        # Input-heavy transactions: most of their weight is scriptSig, so the
        # policy vsize lands far below weight/4.
        self.log.info("A. addPackageTxs, independent transactions")
        raws = []
        for _ in range(8):
            raws.append(self.build_tx(wallet, utxos[idx:idx + 15], 4).serialize().hex())
            idx += 15
        self.check("independent", raws, prioritysize=0, maxsize=4000000)

        self.log.info("B. addPackageTxs, ancestor packages (CPFP)")
        raws_b = []
        for _ in range(5):
            parent = self.build_tx(wallet, utxos[idx:idx + 10], 4, fee=1000)
            idx += 10
            raws_b.append(parent.serialize().hex())
            child_in = [{'txid': parent.rehash(), 'vout': k,
                         'value': Decimal(parent.vout[k].nValue) / COIN} for k in range(2)]
            child = self.build_tx(wallet, child_in + utxos[idx:idx + 8], 4, fee=800_000)
            idx += 8
            raws_b.append(child.serialize().hex())
        self.check("packages", raws_b, prioritysize=0, maxsize=4000000)

        self.log.info("C. addPriorityTxs -> TestForBlock")
        self.check("priority", raws, prioritysize=100000, maxsize=4000000)

        self.log.info("D. fNeedSizeAccounting=true")
        self.check("sizeacct", raws, prioritysize=100000, maxsize=300000)

        for n, o in self.results:
            self.log.info(f"RESULT {n}: " + (f"OVERSHOOT +{o}" if o > 0 else "within limit"))
        bad = [(n, o) for n, o in self.results if o > 0]
        assert not bad, f"paths exceeded -blockmaxweight: {bad}"
        self.log.info("all paths respected -blockmaxweight")


if __name__ == '__main__':
    MiningWeightPathsTest(__file__).main()
