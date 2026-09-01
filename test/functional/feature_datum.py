#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Purity developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the embedded DATUM Stratum V1 subsystem."""

import json
import socket

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error, p2p_port


class StratumClient:
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.socket.settimeout(3)
        self.stream = self.socket.makefile("rb")

    def close(self):
        self.stream.close()
        self.socket.close()

    def send(self, request_id, method, params):
        message = json.dumps({"id": request_id, "method": method, "params": params})
        self.socket.sendall((message + "\n").encode())

    def receive(self):
        line = self.stream.readline()
        if not line:
            raise ConnectionError("Stratum connection closed")
        return json.loads(line)

    def receive_id(self, request_id):
        messages = []
        while True:
            message = self.receive()
            messages.append(message)
            if message.get("id") == request_id:
                return message, messages


class DatumTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.datum_port = p2p_port(11)

    def skip_test_if_missing_module(self):
        if not self.is_datum_compiled():
            raise SkipTest("embedded DATUM support not compiled")

    def setup_network(self):
        self.setup_nodes()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)

    def assert_bad_config(self, extra_args, message):
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-server=1", "-datum=1", *extra_args],
            expected_msg=message,
            match=ErrorMatch.PARTIAL_REGEX,
        )

    def connect(self):
        return StratumClient(self.datum_port)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Runtime default is disabled and opens no Stratum listener")
        self.start_node(0, extra_args=["-server=1"])
        assert_equal(node.getdatuminfo()["enabled"], False)
        assert_raises_rpc_error(-1, "DATUM is not running", node.setdatumdiff, 1024)
        try:
            self.connect()
            raise AssertionError("DATUM port listened while datum=0")
        except ConnectionRefusedError:
            pass
        self.stop_node(0)

        base = [
            f"-datumport={self.datum_port}",
            "-datumuser=miner",
            "-datumpassword=secret",
            f"-datumaddress={ADDRESS_BCRT1_UNSPENDABLE}",
        ]
        self.log.info("Reject invalid DATUM configuration")
        self.assert_bad_config(base + ["-datumport=0"], "-datumport must be between 1 and 65535")
        self.assert_bad_config(base + ["-datumdiff=0"], "-datumdiff must be between 1 and 2147483647")
        self.assert_bad_config(base + ["-datummaxclients=0"], "-datummaxclients must be between 1 and 4096")
        self.assert_bad_config(base + ["-datummaxclients=2", "-datummaxperip=3"], "-datummaxperip must be positive")
        self.assert_bad_config(base + ["-datumlisten=localhost"], "-datumlisten must be a numeric IPv4 or IPv6 address")
        self.assert_bad_config(base + ["-datumrpcurl=http://127.0.0.1:notaport"], "-datumrpcurl must be a loopback HTTP URL")
        self.assert_bad_config(base + ["-datumrpcurl=http://192.0.2.1:18443"], "-datumrpcurl must be a loopback HTTP URL")
        self.assert_bad_config(base + ["-datumrpcuser=only-user"], "-datumrpcuser and -datumrpcpassword must be configured together")
        self.assert_bad_config(base + [f"-datumuser={'u' * 192}"], "-datumuser must be at most 191 bytes")
        self.assert_bad_config(base + [f"-datumcoinbasetag={'t' * 64}"], "-datumcoinbasetag must be at most 63 bytes")
        self.assert_bad_config(base + ["-datumupnp=1"], "-datumupnp=1 requires")
        self.assert_bad_config([arg for arg in base if not arg.startswith("-datumaddress=")], "-datumaddress is missing or invalid")
        self.assert_bad_config([arg for arg in base if not arg.startswith("-datumpassword=")] + ["-datumauth=1"], "authentication requires -datumuser and -datumpassword")

        self.log.info("Authentication is disabled by default")
        default_base = [arg for arg in base if not arg.startswith("-datumuser=") and not arg.startswith("-datumpassword=")]
        self.start_node(0, extra_args=["-server=1", "-datum=1", "-datumdiff=1", *default_base])
        self.wait_until(lambda: self._can_connect(), timeout=10)
        anonymous_client = self.connect()
        self.wait_until(lambda: node.getdatuminfo()["authorized_clients"] == 1, timeout=5)
        anonymous_client.close()
        self.stop_node(0)

        self.log.info("Start DATUM using the node RPC cookie fallback with authentication enabled")
        enabled = ["-server=1", "-datum=1", "-datumdiff=1", "-datumauth=1", *base]
        self.start_node(0, extra_args=enabled)
        self.wait_until(lambda: self._can_connect(), timeout=10)
        info = node.getdatuminfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["running"], True)
        assert_equal(info["status"], "Running")
        assert_equal(info["upnp"], False)
        assert_equal(info["auth_required"], True)
        assert_equal(info["share_difficulty"], 1)
        assert_equal(info["port_mapping"]["requested"], False)
        assert_equal(info["port_mapping"]["active"], False)
        assert_equal(info["current_job"]["height"], info["current_height"])
        assert "block_submission" in info
        assert "session_accepted_difficulty" not in info
        assert "session_best_share_difficulty" not in info
        serialized_info = json.dumps(info, default=str)
        for private_field in ["worker", "remote_host", "user_agent", "datumpassword", "datumrpcpassword"]:
            assert private_field not in serialized_info

        self.log.info("Enforce per-IP connection bounds and authentication timeout")
        clients = [self.connect() for _ in range(4)]
        rejected = self.connect()
        self.wait_until(lambda: self._is_closed(rejected.socket), timeout=3)
        rejected.close()
        for bounded_client in clients:
            bounded_client.close()
        timed_out = self.connect()
        self.wait_until(lambda: self._is_closed(timed_out.socket), timeout=12)
        timed_out.close()

        self.log.info("Subscribe exposes no usable work before authorization")
        client = self.connect()
        client.send(1, "mining.subscribe", ["bitaxe/test"])
        subscribe = client.receive()
        assert_equal(subscribe["id"], 1)
        client.socket.settimeout(0.2)
        try:
            extra = client.socket.recv(1)
            assert_equal(extra, b"")
        except TimeoutError:
            pass
        client.socket.settimeout(3)
        client.send(2, "mining.submit", ["miner.worker", "badjob", "0000000000000000", "00000000", "00000000"])
        assert_equal(client.receive()["error"][1], "unauthorized")
        client.send(3, "mining.authorize", ["miner.worker", "secret"])
        authorize = client.receive()
        assert_equal(authorize["result"], True)
        messages = [client.receive(), client.receive()]
        assert_equal({message.get("method") for message in messages}, {"mining.set_difficulty", "mining.notify"})
        notify = next(message for message in messages if message.get("method") == "mining.notify")
        coinbase1 = bytes.fromhex(notify["params"][2])
        assert_equal(coinbase1[42], 0x51)  # Canonical BIP34 OP_1 for regtest height 1.

        self.log.info("Hot-reload the fixed share difficulty for the connected miner")
        assert_equal(node.setdatumdiff(1024), {"difficulty": 1024})
        reloaded_messages = [client.receive(), client.receive()]
        assert_equal({message.get("method") for message in reloaded_messages}, {"mining.set_difficulty", "mining.notify"})
        set_difficulty = next(message for message in reloaded_messages if message.get("method") == "mining.set_difficulty")
        assert_equal(set_difficulty["params"], [1024])
        assert_equal(node.getdatuminfo()["share_difficulty"], 1024)
        assert_raises_rpc_error(-1, "between 1 and 2147483647", node.setdatumdiff, 0)

        previous_height = node.getdatuminfo()["current_height"]
        self.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE)
        self.wait_until(lambda: node.getdatuminfo()["current_height"] == previous_height + 1, timeout=5)
        client.close()

        self.log.info("Reject wrong credentials and accept the base username")
        for request_id, username, password in [(4, "wrong", "secret"), (5, "miner", "wrong"), (8, "miner.", "secret"), (9, "miner.bad\nworker", "secret")]:
            client = self.connect()
            client.send(request_id, "mining.authorize", [username, password])
            assert_equal(client.receive()["result"], False)
            client.close()
        client = self.connect()
        client.send(6, "mining.authorize", ["miner", "secret"])
        assert_equal(client.receive()["result"], True)

        self.log.info("Configure version rolling and enforce submit rate limits")
        client.send(7, "mining.configure", [["version-rolling"], {"version-rolling.mask": "1fffe000"}])
        configure, seen = client.receive_id(7)
        assert_equal(configure["result"]["version-rolling"], True)
        if not any(message.get("method") == "mining.set_version_mask" for message in seen):
            assert_equal(client.receive()["method"], "mining.set_version_mask")
        with node.assert_debug_log(expected_msgs=["Stratum share rejected: worker=miner reason=unknown-work"]):
            for request_id in range(1000, 1300):
                client.send(request_id, "mining.submit", ["miner", "badjob", "0000000000000000", "00000000", "00000000"])
            responses = [client.receive() for _ in range(300)]
            assert any(response.get("error") and response["error"][1] == "rate-limit" for response in responses)
        session_rejected = node.getdatuminfo()["session_rejected_shares"]
        assert session_rejected > 0
        client.close()
        self.wait_until(lambda: node.getdatuminfo()["clients"] == 0, timeout=5)
        disconnected_info = node.getdatuminfo()
        assert_equal(disconnected_info["rejected_shares"], 0)
        assert disconnected_info["session_rejected_shares"] >= session_rejected

        self.log.info("Disconnect malformed JSON and oversized messages")
        for payload in [b"not-json\n", b"{" + b"a" * (16 * 1024) + b"\n"]:
            client = self.connect()
            client.socket.sendall(payload)
            self.wait_until(lambda: self._is_closed(client.socket), timeout=3)
            client.close()

        partial = self.connect()
        partial.socket.sendall(b'{"id":99,"method":"mining.authorize"')
        partial.close()
        client = self.connect()
        client.send(19, "mining.authorize", ["miner", "secret"])
        assert_equal(client.receive()["result"], True)
        client.close()

        self.log.info("Throttle rapid failed authentication attempts")
        client = self.connect()
        for request_id in range(20, 25):
            client.send(request_id, "mining.authorize", ["wrong", "wrong"])
            assert_equal(client.receive()["result"], False)
        client.close()
        cooled_down = self.connect()
        self.wait_until(lambda: self._is_closed(cooled_down.socket), timeout=3)
        cooled_down.close()

        with node.assert_debug_log(expected_msgs=["[datum] subsystem stopped"]):
            self.stop_node(0)

    def _can_connect(self):
        try:
            client = self.connect()
            client.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _is_closed(sock):
        try:
            return sock.recv(1) == b""
        except TimeoutError:
            return False
        except ConnectionResetError:
            return True


if __name__ == "__main__":
    DatumTest(__file__).main()
