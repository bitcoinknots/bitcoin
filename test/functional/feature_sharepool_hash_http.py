#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The explicit regtest profile transports bounded hex jobs without raising defaults.

These requests are deliberately invalid fixtures. Reaching the RPC error proves
transport capacity, not validation or authorization of a large mining job.
"""
import http.client
import json
from urllib.parse import urlparse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, str_to_b64str


class SharePoolHashHTTPTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-disablewallet"],
            ["-sharepoolheight=1", "-sharepoolhashonly=1", "-testactivationheight=blake2b@1", "-disablewallet"]]

    def setup_network(self):
        self.setup_nodes()

    @staticmethod
    def connection(node):
        url = urlparse(node.url)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=30)
        headers = {"Authorization": "Basic " + str_to_b64str(f"{url.username}:{url.password}"),
                   "Content-Type": "application/json", "Connection": "close"}
        return conn, headers

    def refuses_length(self, node, size):
        conn, headers = self.connection(node)
        conn.putrequest("POST", "/")
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.putheader("Content-Length", str(size))
        conn.endheaders()
        # libevent rejects the declared size without receiving that body.
        reply = conn.getresponse()
        assert_equal(reply.status, http.client.REQUEST_ENTITY_TOO_LARGE)
        reply.read()
        conn.close()

    def run_test(self):
        ordinary, profile = self.nodes
        self.log.info("Default HTTP rejects bodies above 32 MiB; the explicit profile has a 48 MiB cap")
        self.refuses_length(ordinary, 32 * 1024 * 1024 + 1)
        self.refuses_length(profile, 48 * 1024 * 1024 + 1)
        # Both fields fit their own maximum raw-byte lengths. The zero-filled
        # template is not a valid block and must be rejected by the native RPC.
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "finalizesharepoolhashjob",
                           "params": ["00" * 4_000_000, "00" * (16 * 1024 * 1024)]},
                          separators=(",", ":")).encode("ascii")
        assert 32 * 1024 * 1024 < len(body) < 48 * 1024 * 1024
        self.refuses_length(ordinary, len(body))
        self.log.info("Maximum template-plus-snapshot JSON reaches field validation and is rejected there")
        conn, headers = self.connection(profile)
        conn.request("POST", "/", body, headers)
        reply = conn.getresponse()
        assert reply.status != http.client.REQUEST_ENTITY_TOO_LARGE
        result = json.loads(reply.read())
        conn.close()
        assert_equal(result["error"]["code"], -22)
        assert "Noncanonical or malformed template" in result["error"]["message"]
        status = profile.getsharepoolhashstatus()
        assert_equal(status["stored_snapshots"], 0)
        assert_equal(status["stored_bytes"], 0)
        assert_equal(status["pending_blocks"], 0)
        assert_equal(ordinary.getblockcount(), 0)
        assert_equal(profile.getblockcount(), 0)


if __name__ == "__main__":
    SharePoolHashHTTPTest(__file__).main()
