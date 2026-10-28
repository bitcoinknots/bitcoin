#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test outputs whose hash or key is data, and -rejectfakeoutputs"""
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_2, OP_3, OP_TRUE
from test_framework.script_util import program_to_witness_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet

from random import randbytes


class DataOutputsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        # The framework passes -corepolicy to every node, which turns -rejectfakeoutputs off
        self.extra_args = [
            ["-acceptnonstddatacarrier=1", "-datacarrierfullcount", "-rejectfakeoutputs=1"],
            ["-datacarrier=1", "-datacarriersize=2", "-acceptnonstddatacarrier=1", "-datacarrierfullcount", "-rejectfakeoutputs=1"],
            ["-corepolicy=0"],  # Knots defaults: non-OP_RETURN data carriers are rejected outright
            ["-corepolicy=0", "-rejectfakeoutputs=0"],
            ["-datacarrierfullcount"],  # -corepolicy alone turns -rejectfakeoutputs off
        ]

    def test_data_output_transaction(self, node: TestNode, outputs, reject_reason) -> None:
        """Send a self-transfer with extra (value, scriptPubKey) outputs; reject_reason None means it must be accepted."""
        tx = self.wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
        for value, script in outputs:
            tx.vout.append(CTxOut(nValue=value, scriptPubKey=script))
        tx.vout[0].nValue -= sum(value for value, _ in outputs) + tx.get_vsize()  # 1 sat/vbyte
        tx_hex = tx.serialize().hex()

        if reject_reason is None:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
            assert tx.rehash() in node.getrawmempool(True), f'{tx_hex} not in mempool'
        else:
            assert_raises_rpc_error(-26, reject_reason, self.wallet.sendrawtransaction, from_node=node, tx_hex=tx_hex)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        counted, tight, default, disabled, corepolicy = self.nodes

        def p2wsh(program):
            return program_to_witness_script(0, program)

        self.log.info("Testing three P2WSH outputs at the dust threshold (an OLGA-style payload, whatever its magic).")
        dust_run = [(330, p2wsh(randbytes(32))) for _ in range(3)]
        self.test_data_output_transaction(node=default, outputs=dust_run, reject_reason="txn-datacarrier-nonstandard")
        # Counted as 3 * 41 bytes where non-standard carriers are accepted
        self.test_data_output_transaction(node=counted, outputs=dust_run, reject_reason="txn-datacarrier-exceeded")
        # Not counted at all with -rejectfakeoutputs=0, or under -corepolicy
        self.test_data_output_transaction(node=disabled, outputs=dust_run, reject_reason=None)
        self.test_data_output_transaction(node=corepolicy, outputs=dust_run, reject_reason=None)

        self.log.info("Testing a run at 546 sat, what the fake-key encoder pays per chunk.")
        self.test_data_output_transaction(node=default, outputs=[(546, p2wsh(randbytes(32))) for _ in range(3)], reject_reason="txn-datacarrier-nonstandard")

        self.log.info("Testing that small P2WSH outputs of different values, or 330-sat taproot outputs, are still standard.")
        self.test_data_output_transaction(node=default, outputs=[(330, p2wsh(randbytes(32))), (330, p2wsh(randbytes(32))), (400, p2wsh(randbytes(32))), (450, p2wsh(randbytes(32)))], reject_reason=None)
        on_curve = [bytes.fromhex(k) for k in ("9f537de0a7f7403067880d3d62d3f8d20889c4f77b74b612406d7d5ce0a9b206", "4d6abe64a78cd5dcb98a719490753a84a061274cc6f7ecefea0aedad967676ba", "44d8f2d6c1d5f3d2b53fda185d92462adf0ec0f4a66a6e31680b731ddbca111d")]
        self.test_data_output_transaction(node=default, outputs=[(330, program_to_witness_script(1, k)) for k in on_curve], reject_reason=None)

        self.log.info("Testing that three outputs at the dust threshold to one script are still standard.")
        same_script = p2wsh(randbytes(32))
        self.test_data_output_transaction(node=default, outputs=[(330, same_script)] * 3, reject_reason=None)

        self.log.info("Testing that a pair of anchor-sized P2WSH outputs is still standard.")
        anchors = [(330, p2wsh(randbytes(32))) for _ in range(2)] + [(10000, p2wsh(randbytes(32)))]
        self.test_data_output_transaction(node=default, outputs=anchors, reject_reason=None)

        self.log.info("Testing a taproot output whose key is not on the curve.")
        off_curve = bytes.fromhex("4420f4cd273fe68ccc6df6aaf1bd40d6f879884882386754e2c2e55cfad0b0bb")
        self.test_data_output_transaction(node=default, outputs=[(10000, program_to_witness_script(1, off_curve))], reject_reason="txn-datacarrier-nonstandard")
        self.test_data_output_transaction(node=disabled, outputs=[(10000, program_to_witness_script(1, off_curve))], reject_reason=None)

        self.log.info("Testing P2WSH outputs whose hash is padded data.")
        padded = [(10000, p2wsh(randbytes(24) + bytes(8))) for _ in range(2)]
        self.test_data_output_transaction(node=default, outputs=padded[:1], reject_reason="txn-datacarrier-nonstandard")
        # Two of them are 82 bytes, inside the default -datacarriersize where non-standard carriers are accepted
        self.test_data_output_transaction(node=counted, outputs=padded, reject_reason=None)
        self.test_data_output_transaction(node=tight, outputs=padded, reject_reason="txn-datacarrier-exceeded")

        self.log.info("Testing that an output to the all-zero burn hash is not data.")
        self.test_data_output_transaction(node=default, outputs=[(20000, program_to_witness_script(0, bytes(20)))], reject_reason=None)

        self.log.info("Testing that outputs paying back the scripts of the coins spent are not data.")
        # A run of three 330-sat P2WSH outputs is data unless each pays a script the
        # transaction spends: then the spender holds those scripts and chose nothing in them.
        scripts = [CScript([OP_TRUE]), CScript([OP_2]), CScript([OP_3])]
        fund = self.wallet.create_self_transfer(fee_rate=0, confirmed_only=True)["tx"]
        for script in scripts:
            fund.vout.append(CTxOut(nValue=330, scriptPubKey=script_to_p2wsh_script(script)))
        fund.vout[0].nValue -= 3 * 330 + fund.get_vsize()
        self.wallet.sendrawtransaction(from_node=disabled, tx_hex=fund.serialize().hex())
        # The other nodes refuse the funding run, so only the block can sync
        self.generate(disabled, 1, sync_fun=self.no_op)
        self.sync_blocks()
        fund_txid = int(fund.rehash(), 16)
        fee_utxo = self.wallet.get_utxo(confirmed_only=True)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(fee_utxo["txid"], 16), fee_utxo["vout"]))] + [CTxIn(COutPoint(fund_txid, i + 1)) for i in range(len(scripts))]
        spend.vout = [CTxOut(nValue=330, scriptPubKey=script_to_p2wsh_script(script)) for script in scripts]
        spend.vout.append(CTxOut(nValue=int(fee_utxo["value"] * 100_000_000) - 1000, scriptPubKey=self.wallet.get_output_script()))
        self.wallet.sign_tx(spend)
        wallet_stack = list(spend.wit.vtxinwit[0].scriptWitness.stack)
        spend.wit.vtxinwit = [CTxInWitness() for _ in spend.vin]
        spend.wit.vtxinwit[0].scriptWitness.stack = wallet_stack
        for i, script in enumerate(scripts):
            spend.wit.vtxinwit[i + 1].scriptWitness.stack = [script]
        self.wallet.sendrawtransaction(from_node=default, tx_hex=spend.serialize().hex())
        assert spend.rehash() in default.getrawmempool()


if __name__ == '__main__':
    DataOutputsTest(__file__).main()
