#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""Embedded Stratum solo end-to-end regtest submit test."""

import json
import socket
import time

from test_framework.util import assert_equal
from test_framework.test_framework import BitcoinTestFramework


class StratumSoloTest(BitcoinTestFramework):
    def add_options(self, parser):
        # This test only needs a standard wallet/address and works with descriptor wallets.
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def send_json(sock, payload):
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))

    def recv_json(self, sock, timeout=5):
        sock.settimeout(timeout)
        while b"\n" not in self._stratum_buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("stratum socket closed")
            self._stratum_buf += chunk
        line, _, self._stratum_buf = self._stratum_buf.partition(b"\n")
        return json.loads(line.decode("utf-8"))

    def recv_until(self, sock, predicate, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.recv_json(sock, timeout=max(1, int(deadline - time.time())))
            if predicate(msg):
                return msg
        raise AssertionError("timed out waiting for expected Stratum message")

    def restart_with_bind(self, addr, bind):
        self.restart_node(0, extra_args=[
            '-regtest=1',
            '-server=1',
            '-stratum=1',
            f'-stratumbind={bind}',
            '-stratumport=3333',
            '-stratumdifficulty=0.0001',
            f'-stratumpayoutaddress={addr}',
        ])

    def wait_for_stratum_connection(self, host):
        def stratum_port_reachable():
            try:
                with socket.create_connection((host, 3333), timeout=1):
                    return True
            except OSError:
                return False
        self.wait_until(stratum_port_reachable, timeout=10)

    def run_test(self):
        addr = self.nodes[0].getnewaddress()
        self.restart_with_bind(addr, '0.0.0.0')
        self.wait_for_stratum_connection('127.0.0.1')
        info_ipv4_any = self.nodes[0].getstratuminfo()
        assert_equal(info_ipv4_any["bind"], "0.0.0.0")
        assert_equal(info_ipv4_any["listening"], True)

        if socket.has_ipv6:
            self.restart_with_bind(addr, '::')
            self.wait_for_stratum_connection('::1')
            info_ipv6_any = self.nodes[0].getstratuminfo()
            assert_equal(info_ipv6_any["bind"], "::")
            assert_equal(info_ipv6_any["listening"], True)

        self.restart_with_bind(addr, '127.0.0.1')
        self.wait_for_stratum_connection('127.0.0.1')

        with socket.create_connection(("127.0.0.1", 3333), timeout=5) as sock:
            self._stratum_buf = b""
            self.send_json(sock, {"id": 1, "method": "mining.subscribe", "params": []})
            subscribe = self.recv_until(sock, lambda m: m.get("id") == 1)
            assert subscribe["result"] is not None
            assert subscribe["error"] is None

            self.send_json(sock, {"id": 2, "method": "mining.authorize", "params": ["miner", "x"]})
            authorize = self.recv_until(sock, lambda m: m.get("id") == 2)
            assert_equal(authorize["result"], True)
            assert authorize["error"] is None

            set_diff = self.recv_until(sock, lambda m: m.get("method") == "mining.set_difficulty")
            assert_equal(len(set_diff["params"]), 1)
            assert_equal(set_diff["params"][0], 0.0001)

            notify = self.recv_until(sock, lambda m: m.get("method") == "mining.notify")
            params = notify["params"]
            job = {
                "job_id": params[0],
                "prevhash": params[1],
                "coinb1": params[2],
                "coinb2": params[3],
                "merkle_branches": params[4],
                "version": params[5],
                "nbits": params[6],
                "ntime": params[7],
            }

            info_connected = self.nodes[0].getstratuminfo()
            assert info_connected["clients"] >= 1
            assert_equal(info_connected["current_job_id"], job["job_id"])
            assert_equal(info_connected["current_height"] > 0, True)
            assert_equal(info_connected["current_prevhash"], job["prevhash"])
            assert_equal(info_connected["stratum_difficulty"], 0.0001)
            shares_before = info_connected["accepted_shares"]
            blocks_before = info_connected["blocks_found"]
            blockcount_before = self.nodes[0].getblockcount()

            accepted = False
            for nonce in range(0, 2000):
                submit_id = 100000 + nonce
                self.send_json(sock, {
                    "id": submit_id,
                    "method": "mining.submit",
                    "params": ["miner", job["job_id"], "00000000", job["ntime"], f"{nonce:08x}"],
                })
                submit_resp = self.recv_until(sock, lambda m: m.get("id") == submit_id, timeout=3)
                if submit_resp.get("result") is True and submit_resp.get("error") is None:
                    accepted = True
                    break
            assert accepted

            self.wait_until(lambda: self.nodes[0].getstratuminfo()["accepted_shares"] > shares_before, timeout=10)
            self.wait_until(
                lambda: (
                    self.nodes[0].getstratuminfo()["blocks_found"] > blocks_before or
                    self.nodes[0].getblockcount() > blockcount_before
                ),
                timeout=10,
            )


if __name__ == '__main__':
    StratumSoloTest(__file__).main()
