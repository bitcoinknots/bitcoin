#!/usr/bin/env python3
# Copyright (c) 2025 Luke Dashjr
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getextrapoolinfo RPC command."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.messages import msg_tx, tx_from_hex
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.messages import CTxOut


class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()


class RPCExtraPoolInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        self.wallet0 = MiniWallet(self.nodes[0])
        
        self.connect_nodes(0, 1)
        
        self.p2p_conn = self.nodes[1].add_p2p_connection(TestP2PConn())
        
        info = self.nodes[1].getextrapoolinfo()
        assert_equal(info['count'], 0)
        assert_equal(info['bytes'], 0)
        assert_equal(info['memory_usage'], 0)
        
        dust_tx = self.wallet0.create_self_transfer()
        dust_amount = 100  # Below dust threshold
        dust_script = CScript([OP_TRUE])
        dust_tx['tx'].vout.append(CTxOut(dust_amount, dust_script))
        dust_tx['tx'].vout[0].nValue -= dust_amount
        dust_tx['tx'].rehash()
        
        tx_obj = tx_from_hex(dust_tx['tx'].serialize().hex())
        self.p2p_conn.send_message(msg_tx(tx_obj))
        self.p2p_conn.sync_with_ping()
        
        info = self.nodes[1].getextrapoolinfo()
        print(info)
        assert_equal(info['count'] > 0, True)
        assert_equal(info['bytes'] > 0, True)
        assert_equal(info['memory_usage'] > 0, True)


if __name__ == '__main__':
    RPCExtraPoolInfoTest(__file__).main()