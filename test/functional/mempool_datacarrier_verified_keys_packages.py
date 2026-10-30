#!/usr/bin/env python3
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the recount of datacarrier bytes after the script checks also runs on the package paths.

mempool_datacarrier_verified_keys.py covers single transactions. This test sends the same decoy spend
(a 1-of-15 whose fourteen fake keys sit beside signature checks in code that never runs) inside packages:

- as the child of an honest parent, as the parent of an honest child, and as an honest package;
- through submitpackage and, for one parent and one child, through p2p (child first, then parent).

Both nodes run Knots policy defaults, on the same mainnet-shaped chain as mempool_datacarrier_verified_keys.py
(-corepolicy=0 undoes the -corepolicy the test framework adds, which would turn the full count off and set
-mempooltruc=enforce), and enforce standardness (-acceptnonstdtxn=0). The full count is on by default.

Node 0 runs nothing else. There a package of version 2 transactions is validated one transaction at a time
first (AcceptPackage), and only a transaction that fails on feerate is retried as part of a package. An
honest parent that pays its way is therefore accepted on its own, and the decoy is refused by the
single-transaction path (PolicyScriptChecks through AcceptSingleTransaction).

Node 1 adds -mempooltruc=enforce, and its rows are the ones that reach AcceptMultipleTransactions, where
PolicyScriptChecks runs once for every transaction of the package. The reason it needs the flag: a
transaction below the min relay feerate is refused on its own (PreChecks, "min relay fee not met", which
package validation cannot bypass), unless it is version 3 and the TRUC policy is "enforce". Knots defaults
to "accept". So at Knots defaults a 0-fee parent cannot be CPFP'd by its child and no package ever has to
be validated together; the flag is what makes the multi-transaction path reachable. The flag changes
nothing for version 2 transactions. Each row there first checks that the
0-fee parent really is refused on its own, so that a pass cannot come from the single-transaction path.
"""
from mempool_datacarrier_verified_keys import (
    FUNDING,
    NODE_ARGS,
    REJECT,
    WARMUP_BLOCKS,
    VerifiedKeyCreditTest,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    msg_tx,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_TRUE,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

TRUC = 3
PARENT_FEE = 10_000
CHILD_FEE = 50_000


class VerifiedKeyPackageTest(VerifiedKeyCreditTest):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        defaults = NODE_ARGS + ["-acceptnonstdtxn=0"]
        self.extra_args = [defaults, defaults + ["-mempooltruc=enforce"]]
        # value of every output this test created, by (txid, n), for the signature hash. The base class
        # signs for a fixed amount, which does not hold once a parent pays a fee.
        self.values = {}

    def p2wsh_sig(self, key, script, tx, i):
        prev = tx.vin[i].prevout
        amount = self.values.get((prev.hash, prev.n), FUNDING)
        return key.sign_ecdsa(SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, amount)) + bytes([SIGHASH_ALL])

    # ---- building packages ----

    def spend_ex(self, spec, out_spk, version, fee):
        """One input (funded and confirmed first, unless the spec names an outpoint), one output."""
        if 'outpoint' in spec:
            op = spec['outpoint']
        else:
            op = self.fund(spec['spk'])
            self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        total = self.values.get((op.hash, op.n), FUNDING)
        tx = CTransaction()
        tx.version = version
        tx.vin = [CTxIn(op)]
        tx.vout = [CTxOut(total - fee, out_spk)]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = spec['stack'](tx, 0)
        tx.rehash()
        self.values[(int(tx.rehash(), 16), 0)] = total - fee
        return tx

    def make_pair(self, parent_spec, child_spec, version, parent_fee):
        """The parent spends a confirmed output and pays child_spec's script; the child spends it."""
        parent = self.spend_ex(parent_spec, child_spec['spk'], version, parent_fee)
        child_spec = dict(child_spec, outpoint=COutPoint(int(parent.rehash(), 16), 0))
        child = self.spend_ex(child_spec, script_to_p2wsh_script(CScript([OP_TRUE])), version, CHILD_FEE)
        return parent, child

    def decoy(self):
        return self.decoy_spec(15, 1, 'depth')

    def honest(self):
        return self.honest_multisig_spec(2, 3)

    @staticmethod
    def hexes(txs):
        return [t.serialize().hex() for t in txs]

    def in_pool(self, node, tx):
        return tx.rehash() in node.getrawmempool()

    def next_block(self):
        """A new tip, so that each row starts from an empty mempool."""
        self.generate(self.nodes[0], 1, sync_fun=self.sync_blocks)

    # ---- the rows ----

    def alone_is_refused_on_fee(self, node, parent):
        res = node.testmempoolaccept([parent.serialize().hex()])[0]
        assert not res['allowed'] and "fee not met" in res['reject-reason'], \
            f"the 0-fee parent should be refused on its own for its fee, so that it needs the package path: {res}"

    def decoy_child(self, node, version, parent_fee, name, multi):
        parent, child = self.make_pair(self.honest(), self.decoy(), version, parent_fee)
        if multi:
            self.alone_is_refused_on_fee(node, parent)
        res = node.submitpackage(self.hexes([parent, child]))
        child_res = res['tx-results'].get(child.getwtxid(), {})
        assert_equal(res['package_msg'], "transaction failed")
        assert REJECT in child_res.get('error', ''), f"{name}: decoy child should be refused by the recount: {res}"
        assert not self.in_pool(node, child), name
        # Alone, the honest parent paid its way and is in. In a package that needs the child's fee, the
        # package fails as a whole and the parent is not.
        assert_equal(self.in_pool(node, parent), not multi)
        self.log.info(f"  ok  {name}: the decoy child is refused with {REJECT}, parent in mempool: {not multi}")
        self.next_block()

    def decoy_parent(self, node, version, parent_fee, name, multi):
        parent, child = self.make_pair(self.decoy(), self.honest(), version, parent_fee)
        if multi:
            # The decoy parent is a v3 0-fee transaction: it needs the package for its fee as well.
            self.alone_is_refused_on_fee(node, parent)
        res = node.submitpackage(self.hexes([parent, child]))
        parent_res = res['tx-results'].get(parent.getwtxid(), {})
        assert_equal(res['package_msg'], "transaction failed")
        assert REJECT in parent_res.get('error', ''), f"{name}: decoy parent should be refused by the recount: {res}"
        assert not self.in_pool(node, parent), name
        assert not self.in_pool(node, child), name
        self.log.info(f"  ok  {name}: the decoy parent is refused with {REJECT} and its honest child is not accepted")
        self.next_block()

    def honest_package(self, node, version, parent_fee, name, multi, parent_spec=None, child_spec=None):
        parent, child = self.make_pair(parent_spec or self.honest(), child_spec or self.honest(), version, parent_fee)
        if multi:
            self.alone_is_refused_on_fee(node, parent)
        res = node.submitpackage(self.hexes([parent, child]))
        assert_equal(res['package_msg'], "success")
        assert self.in_pool(node, parent) and self.in_pool(node, child), f"{name}: {res}"
        self.log.info(f"  ok  {name}: accepted")
        self.next_block()

    def p2p_1p1c(self, node, decoy_in_child, name):
        """The child arrives first and is kept as an orphan; the parent then arrives, and the pair is validated as a 1p1c package."""
        parent_spec, child_spec = (self.honest(), self.decoy()) if decoy_in_child else (self.honest(), self.honest())
        parent, child = self.make_pair(parent_spec, child_spec, TRUC, 0)
        self.alone_is_refused_on_fee(node, parent)
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_tx(child))
        assert child.rehash() in node.getorphantxs(), 'the child should wait as an orphan'
        if decoy_in_child:
            # The package, not either transaction alone, is what the node validates here, and the log names the recount.
            with node.assert_debug_log([REJECT]):
                peer.send_and_ping(msg_tx(parent))
            peer.sync_with_ping()
            assert not self.in_pool(node, parent) and not self.in_pool(node, child), name
            self.log.info(f"  ok  {name}: neither is accepted")
        else:
            peer.send_and_ping(msg_tx(parent))
            self.wait_until(lambda: self.in_pool(node, parent) and self.in_pool(node, child))
            self.log.info(f"  ok  {name}: both accepted")
        node.disconnect_p2ps()
        self.next_block()

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, WARMUP_BLOCKS)
        node0, node1 = self.nodes

        self.log.info("Node 0, Knots defaults: version 2 packages are tried transaction by transaction first")
        self.decoy_child(node0, 2, PARENT_FEE, "decoy child of an honest parent", multi=False)
        self.decoy_parent(node0, 2, PARENT_FEE, "decoy parent with an honest child", multi=False)
        self.honest_package(node0, 2, PARENT_FEE, "honest package", multi=False)
        # More than ten keys, all of which verify, must stay free in a package as they do alone.
        self.honest_package(node0, 2, PARENT_FEE, "honest package, 12-of-12 child", multi=False,
                            child_spec=self.honest_multisig_spec(12, 12))

        self.log.info("Node 1, -mempooltruc=enforce: a 0-fee version 3 parent makes this AcceptMultipleTransactions")
        self.decoy_child(node1, TRUC, 0, "decoy child of an honest 0-fee parent", multi=True)
        self.decoy_parent(node1, TRUC, 0, "decoy 0-fee parent with an honest child", multi=True)
        self.honest_package(node1, TRUC, 0, "honest 0-fee package", multi=True)
        self.honest_package(node1, TRUC, 0, "honest 0-fee package, 12-of-12 child", multi=True,
                            child_spec=self.honest_multisig_spec(12, 12))

        self.log.info("Node 1, p2p 1p1c: child first, then its 0-fee parent")
        self.p2p_1p1c(node1, True, "p2p 1p1c, decoy child")
        self.p2p_1p1c(node1, False, "p2p 1p1c, honest control")


if __name__ == '__main__':
    VerifiedKeyPackageTest(__file__).main()
