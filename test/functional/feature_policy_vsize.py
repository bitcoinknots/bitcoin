#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that reported vsize accounts for the -datacarriercost policy.

The policy-adjusted vsize must be reported for both unconfirmed transactions
(from the mempool entry) and confirmed ones (from block undo data).
"""

from test_framework.key import ECKey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKMULTISIG,
    OP_ENDIF,
    OP_NOTIF,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair

# A BPUB v5 stream, as its encoder writes it (same vector as the bpub_bytes unit test)
BPUB_V5 = bytes.fromhex(
    "000000ca05030000000000000180b25870e5538d2124919e1345dcb4674cab44d42456ad164038eb93f5e4f996"
    "9d006976a654abd02a15e1b2c15177f6e73f72ca9c2b339a651509ebf29bf1299d3bcf8c6df6aa2695cd184ad6"
    "1eb1dd462f000a40ec28b0c273677fa0ef8b8a49540319ab20d0912a5ee05e445f98f078087d5532c24bb4c1e2"
    "704c913bcc6801ad6464d35d4fae82e95a5020a035e89da5d512011a4da91b2734737ea3cea48260b798faa33c"
    "e4aa13806859a490644a60d834964fb01829605702b9c3b3bf53")


class PolicyVSizeTest(BitcoinTestFramework):
    BYTES_PER_SIGOP = 200

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 3
        policy = ['-corepolicy=0', '-datacarriercost=2', '-acceptnonstddatacarrier=1', '-datacarrierfullcount=0', '-txindex']
        self.extra_args = [
            policy,
            policy + ['-rejectdeadbranches=0', '-rejectbpub=0'],
            policy + [f'-bytespersigop={self.BYTES_PER_SIGOP}'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def base_vsize(self, weight):
        return (weight + 3) // 4

    def spend_p2wsh(self, witness_script, make_stack):
        """Fund a P2WSH output to witness_script and return a spend of it"""
        node = self.nodes[0]
        funding_value = 100_000
        funding = self.mini.send_to(from_node=node, scriptPubKey=script_to_p2wsh_script(witness_script), amount=funding_value)
        self.generate(node, 1)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["sent_vout"]))]
        tx.vout = [CTxOut(funding_value - 20_000, self.mini.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = make_stack(tx, funding_value) + [bytes(witness_script)]
        return tx.serialize().hex()

    def check_mined_vsize(self, tx_hex, compare_uncounted=False):
        """Mine tx_hex and assert each node reports the same vsize for it before and after confirmation"""
        node, uncounted, _ = self.nodes
        if compare_uncounted:
            lower_vsize = uncounted.testmempoolaccept([tx_hex])[0]['vsize']
        else:
            lower_vsize = self.base_vsize(node.decoderawtransaction(tx_hex)['weight'])
        txid = node.sendrawtransaction(tx_hex)
        self.sync_mempools()
        vsizes = [n.getrawmempool(True)[txid]['vsize'] for n in self.nodes]
        for n, vsize in zip(self.nodes, vsizes):
            assert_equal(n.getmempoolentry(txid)['vsize'], vsize)
            assert_equal(n.getrawtransaction(txid, True)['vsize'], vsize)
        assert_greater_than(vsizes[0], lower_vsize)

        block_hash = self.generate(node, 1)[0]
        for n, vsize in zip(self.nodes, vsizes):
            assert_equal(n.getrawtransaction(txid, True)['vsize'], vsize)
            assert_equal(n.getrawtransaction(txid, 2)['vsize'], vsize)
            for verbosity in (2, 3):
                block_tx = next(t for t in n.getblock(block_hash, verbosity)['tx'] if t['txid'] == txid)
                assert_equal(block_tx['vsize'], vsize)
        self.log.info(f"  vsizes {vsizes} (lower bound {lower_vsize})")
        return vsizes

    def test_dead_branch(self):
        self.log.info("Dead-branch data (-rejectdeadbranches): mempool and confirmed vsize agree")
        script = CScript([OP_1, OP_NOTIF, b'\xab' * 10, OP_ENDIF, OP_1])
        self.check_mined_vsize(self.spend_p2wsh(script, lambda tx, value: []), compare_uncounted=True)

    def test_unproven_pubkeys(self):
        self.log.info("1-of-15 multisig with 14 unproven keys: mempool and confirmed vsize agree")
        keys = []
        for _ in range(15):
            key = ECKey()
            key.generate(compressed=True)
            keys.append(key)
        script = CScript([1] + [k.get_pubkey().get_bytes() for k in keys] + [15, OP_CHECKMULTISIG])

        def make_stack(tx, value):
            sighash = SegwitV0SignatureHash(script, tx, 0, SIGHASH_ALL, value)
            return [b'', keys[0].sign_ecdsa(sighash) + bytes([SIGHASH_ALL])]
        vsizes = self.check_mined_vsize(self.spend_p2wsh(script, make_stack))

        self.log.info("-bytespersigop: the sigop term sets the vsize and is the same once confirmed")
        assert_equal(vsizes[2], (15 * self.BYTES_PER_SIGOP + 3) // 4)
        assert_greater_than(vsizes[2], vsizes[0])

    def test_unspendable_prevout(self):
        self.log.info("signrawtransactionwithkey with an unspendable prevout does not abort the node")
        node = self.nodes[0]
        privkey, _ = generate_keypair(wif=True)
        prevout = {'txid': 'aa' * 32, 'vout': 0, 'scriptPubKey': '6a'}
        tx_hex = node.createrawtransaction([prevout], [{'data': '00'}])
        result = node.signrawtransactionwithkey(tx_hex, [privkey], [prevout])
        assert_equal(result['complete'], False)

    def test_bpub(self):
        self.log.info("BPUB stream in 1-of-N keys (-rejectbpub): mempool and confirmed vsize agree")
        control = ECKey()
        control.generate(compressed=True)
        keys = [b'\x02' + BPUB_V5[i:i + 31].ljust(32, b'\x00') for i in range(0, len(BPUB_V5), 31)]
        assert len(keys) < 16
        script = CScript([OP_1] + keys + [control.get_pubkey().get_bytes(), len(keys) + 1, OP_CHECKMULTISIG])

        def make_stack(tx, value):
            sighash = SegwitV0SignatureHash(script, tx, 0, SIGHASH_ALL, value)
            return [b'', control.sign_ecdsa(sighash) + bytes([SIGHASH_ALL])]
        self.check_mined_vsize(self.spend_p2wsh(script, make_stack), compare_uncounted=True)

    def run_test(self):
        node = self.nodes[0]
        self.mini = MiniWallet(node)
        self.generate(self.mini, 3)
        self.generate(node, 101)

        self.test_dead_branch()
        self.test_unproven_pubkeys()
        self.test_bpub()
        self.test_unspendable_prevout()

        data = 'ff' * 80
        funded = node.fundrawtransaction(node.createrawtransaction([], [{'data': data}]))
        signed = node.signrawtransactionwithwallet(funded['hex'])
        txid = node.sendrawtransaction(signed['hex'])

        raw = node.getrawtransaction(txid, True)
        policy_vsize = node.getmempoolentry(txid)['vsize']
        assert_greater_than(policy_vsize, self.base_vsize(raw['weight']))

        self.log.info("Unconfirmed: policy vsize is reported everywhere")
        assert_equal(raw['vsize'], policy_vsize)
        assert_equal(node.getrawmempool(True)[txid]['vsize'], policy_vsize)
        assert_equal(node.gettransaction(txid, True, True)['decoded']['vsize'], policy_vsize)

        self.log.info("Confirmed: policy vsize comes from block undo data")
        self.generate(node, 1)
        assert_equal(node.getrawtransaction(txid, True)['vsize'], policy_vsize)
        assert_equal(node.getrawtransaction(txid, 2)['vsize'], policy_vsize)
        assert_equal(node.gettransaction(txid, True, True)['decoded']['vsize'], policy_vsize)

        self.log.info("signrawtransactionwithwallet feerate uses policy vsize")
        funded2 = node.fundrawtransaction(node.createrawtransaction([], [{'data': data}]))
        signed2 = node.signrawtransactionwithwallet(funded2['hex'])
        base_feerate = funded2['fee'] * 1000 / self.base_vsize(node.decoderawtransaction(signed2['hex'])['weight'])
        assert_greater_than(base_feerate, signed2['feerate'])

        self.log.info("getrawtransaction reports unreadable undo data")

        def move_block_file(old, new):
            (node.blocks_path / old).rename(node.blocks_path / new)

        move_block_file('rev00000.dat', 'rev_wrong')
        assert_raises_rpc_error(-32603, "Undo data expected but can't be read.", node.getrawtransaction, txid, 2)

        self.log.info("vsize is omitted rather than reported without policy weight")
        assert 'vsize' not in node.getrawtransaction(txid, True)
        assert 'vsize' not in node.gettransaction(txid, True, True)['decoded']
        move_block_file('rev_wrong', 'rev00000.dat')

        assert_equal(node.getrawtransaction(txid, True)['vsize'], policy_vsize)


if __name__ == '__main__':
    PolicyVSizeTest(__file__).main()
