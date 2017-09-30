#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    start_node,
    assert_equal,
    assert_raises_jsonrpc,
    connect_nodes_bi,
)


class WalletAccountsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.node_args = [[]]

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-maxorphantx=1000",
                                                              "-whitelist=127.0.0.1"]))
        self.is_network_split = False

    def test_sort_multisig(self, node):
        node.importprivkey("cSJUMwramrFYHKPfY77FH94bv4Q5rwUCyfD6zX3kLro4ZcWsXFEM")
        node.importprivkey("cSpQbSsdKRmxaSWJ3TckCFTrksXNPbh8tfeZESGNQekkVxMbQ77H")
        node.importprivkey("cRNbfcJgnvk2QJEVbMsxzoprotm1cy3kVA2HoyjSs3ss5NY5mQqr")

        addresses = [
            "muRmfCwue81ZT9oc3NaepefPscUHtP5kyC",
            "n12RzKwqWPPA4cWGzkiebiM7Gu6NXUnDW8",
            "n2yWMtx8jVbo8wv9BK2eN1LdbaakgKL3Mt",
        ]

        sorted_default = node.addmultisigaddress(2, addresses)
        sorted_false = node.addmultisigaddress(2, addresses, {"sort": False})
        sorted_true = node.addmultisigaddress(2, addresses, {"sort": True})

        assert_equal(sorted_default, sorted_false)
        assert_equal("2N6dne8yzh13wsRJxCcMgCYNeN9fxKWNHt8", sorted_default)
        assert_equal("2MsJ2YhGewgDPGEQk4vahGs4wRikJXpRRtU", sorted_true)

    def test_sort_multisig_with_uncompressed_hash160(self, node):
        node.importpubkey("02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0")
        node.importpubkey("04dd4fe618a8ad14732f8172fe7c9c5e76dd18c2cc501ef7f86e0f4e285ca8b8b32d93df2f4323ebb02640fa6b975b2e63ab3c9d6979bc291193841332442cc6ad")
        address = "2MxvEpFdXeEDbnz8MbRwS23kDZC8tzQ9NjK"

        addresses = [
            "msDoRfEfZQFaQNfAEWyqf69H99yntZoBbG",
            "myrfasv56W7579LpepuRy7KFhVhaWsJYS8",
        ]
        default = self.nodes[0].addmultisigaddress(2, addresses)
        assert_equal(address, default)

        unsorted = self.nodes[0].addmultisigaddress(2, addresses, {"sort": False})
        assert_equal(address, unsorted)

        assert_raises_jsonrpc(-1, "Compressed key required for BIP67: myrfasv56W7579LpepuRy7KFhVhaWsJYS8", node.addmultisigaddress, 2, addresses, {"sort": True})

    def run_test (self):
        node = self.nodes[0]
        # Check that there's no UTXO on any of the nodes
        assert_equal(len(node.listunspent()), 0)
        
        node.generate(101)
        
        assert_equal(node.getbalance(), 50)
        
        accounts = ["a","b","c","d","e"]
        amount_to_send = 1.0
        account_addresses = dict()
        for account in accounts:
            address = node.getaccountaddress(account)
            account_addresses[account] = address
            
            node.getnewaddress(account)
            assert_equal(node.getaccount(address), account)
            assert(address in node.getaddressesbyaccount(account))
            
            node.sendfrom("", address, amount_to_send)
        
        node.generate(1)
        
        for i in range(len(accounts)):
            from_account = accounts[i]
            to_account = accounts[(i+1)%len(accounts)]
            to_address = account_addresses[to_account]
            node.sendfrom(from_account, to_address, amount_to_send)
        
        node.generate(1)
        
        for account in accounts:
            address = node.getaccountaddress(account)
            assert(address != account_addresses[account])
            assert_equal(node.getreceivedbyaccount(account), 2)
            node.move(account, "", node.getbalance(account))
        
        node.generate(101)
        
        expected_account_balances = {"": 5200}
        for account in accounts:
            expected_account_balances[account] = 0
        
        assert_equal(node.listaccounts(), expected_account_balances)
        
        assert_equal(node.getbalance(""), 5200)
        
        for account in accounts:
            address = node.getaccountaddress("")
            node.setaccount(address, account)
            assert(address in node.getaddressesbyaccount(account))
            assert(address not in node.getaddressesbyaccount(""))
        
        for account in accounts:
            addresses = []
            for x in range(10):
                addresses.append(node.getnewaddress())
            multisig_address = node.addmultisigaddress(5, addresses, account)
            node.sendfrom("", multisig_address, 50)
        
        node.generate(101)
        
        for account in accounts:
            assert_equal(node.getbalance(account), 50)
        self.test_sort_multisig(node)
        self.test_sort_multisig_with_uncompressed_hash160(node)

if __name__ == '__main__':
    WalletAccountsTest().main ()
