#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Proof of Datum: local, advisory tracking of how a connection uses this
node's mining RPCs, plus a persistent manual/heuristic flag list.

This is not a consensus rule -- two simulated "miners" are told apart only by
which loopback address they call the RPC server from, exactly as two real
mining backends behind the same node would be told apart by their source IP.
"""

import http.client
import json
import base64
from urllib.parse import urlparse

from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_TRUE
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_auth_cookie

# Must stay in sync with DatumTracker::DATUM_MIN_SUBMISSIONS in src/datum.h.
DATUM_MIN_SUBMISSIONS = 50


class RawRpcClient:
    """A minimal JSON-RPC client bound to a specific loopback source address,
    so this test can simulate two different mining backends talking to the
    same node -- Proof of Datum tracks callers by address, and Python's
    AuthServiceProxy has no way to pin an outgoing source address itself."""

    def __init__(self, node, source_address):
        user, password = get_auth_cookie(node.datadir_path, node.chain)
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.host = "127.0.0.1"
        self.port = urlparse(node.url).port
        self.source_address = source_address
        self._id = 0

    def call(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)})
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30,
                                          source_address=(self.source_address, 0))
        try:
            conn.request("POST", "/", body, headers={
                "Authorization": f"Basic {self.auth}",
                "Content-Type": "application/json",
            })
            resp = conn.getresponse()
            parsed = json.loads(resp.read())
        finally:
            conn.close()
        if parsed.get("error") is not None:
            raise JSONRPCException(parsed["error"])
        return parsed["result"]


class ProofOfDatumTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-rpcallowip=127.0.0.0/8", "-rpcbind=127.0.0.1"]]

    def setup_network(self):
        self.setup_nodes()

    def submit_block(self, node, height, script_pubkey):
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(height, script_pubkey=script_pubkey),
                             node.getblock(tip)["time"] + 1)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]

        # Two simulated mining backends, told apart purely by source address,
        # exactly as this node would tell apart two real ones.
        good_client = RawRpcClient(node, "127.0.0.2")
        bad_client = RawRpcClient(node, "127.0.0.3")
        good_addr, bad_addr = "127.0.0.2", "127.0.0.3"
        fixed_script = CScript([OP_TRUE, OP_TRUE])

        self.log.info("an address with no recorded activity reports as unflagged")
        info = node.getdatuminfo(good_addr)
        assert_equal(info, [{
            "address": good_addr, "gbt_calls": 0, "blocks_submitted": 0,
            "coinbase_reuse_pct": 0, "gbt_starved": False, "coinbase_stale": False,
            "heuristic_match": False, "flagged": False, "manually_flagged": False,
        }])

        self.log.info("a client that pulls templates and varies its payout looks fine")
        for i in range(5):
            good_client.call("getblocktemplate", {"rules": ["segwit"]})
            height = node.getblockcount() + 1
            script = CScript([OP_TRUE, i])  # a distinct "payout" each time
            block = self.submit_block(node, height, script)
            result = good_client.call("submitblock", block.serialize().hex())
            assert result is None

        info = node.getdatuminfo(good_addr)[0]
        assert_equal(info["gbt_calls"], 5)
        assert_equal(info["blocks_submitted"], 5)
        assert_equal(info["heuristic_match"], False)
        assert_equal(info["flagged"], False)
        self.log.info("getblocktemplate still serves this address")
        good_client.call("getblocktemplate", {"rules": ["segwit"]})

        self.log.info("by default (-datumautoban off), a handful of one-off submissions never gets flagged")
        # This is the exact scenario a debug script, a one-off manual relay,
        # or a low-volume solo miner produces perfectly innocently: a few
        # blocks, no getblocktemplate calls, most likely one reused address.
        # It must never trip anything on its own with the default settings.
        for _ in range(3):
            height = node.getblockcount() + 1
            block = self.submit_block(node, height, fixed_script)
            assert bad_client.call("submitblock", block.serialize().hex()) is None
        info = node.getdatuminfo(bad_addr)[0]
        assert_equal(info["blocks_submitted"], 3)
        assert_equal(info["heuristic_match"], False)  # below DATUM_MIN_SUBMISSIONS
        assert_equal(info["flagged"], False)
        bad_client.call("getblocktemplate", {"rules": ["segwit"]})  # still served

        self.log.info(f"a sustained pattern over {DATUM_MIN_SUBMISSIONS} blocks matches the heuristic, "
                      "but still isn't enforced with -datumautoban off")
        for _ in range(DATUM_MIN_SUBMISSIONS - 3):
            height = node.getblockcount() + 1
            block = self.submit_block(node, height, fixed_script)
            assert bad_client.call("submitblock", block.serialize().hex()) is None

        info = node.getdatuminfo(bad_addr)[0]
        assert info["gbt_calls"] <= 1  # the one getblocktemplate probe just above, if any
        assert_equal(info["blocks_submitted"], DATUM_MIN_SUBMISSIONS)
        assert_equal(info["coinbase_reuse_pct"], 100)
        assert_equal(info["gbt_starved"], True)
        assert_equal(info["coinbase_stale"], True)
        assert_equal(info["heuristic_match"], True)
        self.log.info("the pattern matches, but nothing is withheld: no -datumautoban, no ban entry")
        assert_equal(info["flagged"], False)
        assert_equal(node.listdatumbans(), [])
        bad_client.call("getblocktemplate", {"rules": ["segwit"]})  # still served

        self.log.info("its blocks were all still accepted regardless -- Datum never touches block validity")
        assert_equal(node.getblockcount(), 5 + DATUM_MIN_SUBMISSIONS)

        self.log.info("with -datumautoban on, the same pattern is promoted to an actual, enforced ban")
        # Restarting resets the in-memory RPC-usage counters (only the ban list
        # itself is persisted), but not the chain -- so height is tracked
        # relative to wherever this restart's tip already is, not from zero.
        self.restart_node(0, extra_args=self.extra_args[0] + ["-datumautoban=1"])
        node = self.nodes[0]
        good_client = RawRpcClient(node, "127.0.0.2")
        bad_client = RawRpcClient(node, "127.0.0.3")
        height_before = node.getblockcount()
        for _ in range(DATUM_MIN_SUBMISSIONS):
            height = node.getblockcount() + 1
            block = self.submit_block(node, height, fixed_script)
            assert bad_client.call("submitblock", block.serialize().hex()) is None

        info = node.getdatuminfo(bad_addr)[0]
        assert_equal(info["heuristic_match"], True)
        assert_equal(info["flagged"], True)
        assert_equal(info["manually_flagged"], False)

        self.log.info("its blocks are still all accepted, even once auto-banned")
        assert_equal(node.getblockcount(), height_before + DATUM_MIN_SUBMISSIONS)

        self.log.info("but it is now refused a template")
        assert_raises_rpc_error(-1, "Proof of Datum", bad_client.call, "getblocktemplate", {"rules": ["segwit"]})
        self.log.info("an unrelated address is unaffected")
        good_client.call("getblocktemplate", {"rules": ["segwit"]})

        self.log.info("and a further block from the banned address still goes through")
        height = node.getblockcount() + 1
        block = self.submit_block(node, height, fixed_script)
        assert bad_client.call("submitblock", block.serialize().hex()) is None
        assert_equal(node.getblockcount(), height)

        self.log.info("listdatumbans shows the auto-promoted entry")
        bans = node.listdatumbans()
        assert_equal(len(bans), 1)
        assert_equal(bans[0]["address"], bad_addr)
        assert_equal(bans[0]["source"], "heuristic")

        self.log.info("a manual ban works the same way, on an address the heuristic never touched")
        third_addr = "127.0.0.4"
        node.adddatumban(third_addr, "reported by a community member")
        info = node.getdatuminfo(third_addr)[0]
        assert_equal(info["heuristic_match"], False)
        assert_equal(info["flagged"], True)
        assert_equal(info["manually_flagged"], True)
        bans = {b["address"]: b for b in node.listdatumbans()}
        assert_equal(bans[third_addr]["reason"], "reported by a community member")
        assert_equal(bans[third_addr]["source"], "manual")

        self.log.info("removedatumban lifts a flag")
        assert_equal(node.removedatumban(third_addr), True)
        assert_equal(node.removedatumban(third_addr), False)  # already gone
        info = node.getdatuminfo(third_addr)[0]
        assert_equal(info["flagged"], False)

        self.log.info("the ban list survives a restart")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-datumautoban=1"])
        node = self.nodes[0]
        bans = {b["address"]: b for b in node.listdatumbans()}
        assert bad_addr in bans
        assert third_addr not in bans


if __name__ == '__main__':
    ProofOfDatumTest(__file__).main()
