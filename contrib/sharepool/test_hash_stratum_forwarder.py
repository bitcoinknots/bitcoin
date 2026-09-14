#!/usr/bin/env python3
"""Loopback-only proxy tests; no ASIC, bridge or LAN interface is accessed."""
import socket
import socketserver
import threading
import unittest

from hash_stratum_forwarder import TestMinerForwarder


class ForwarderTests(unittest.TestCase):
    def setUp(self):
        outer = self
        self.accepted = 0

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                outer.accepted += 1
                self.request.settimeout(2)
                try:
                    while True:
                        data = self.request.recv(1024)
                        if not data or data == b"close":
                            return
                        self.request.sendall(data)
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Echo)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02))
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def forwarder(self, **options):
        settings = dict(bind=("127.0.0.1", 0), miner_ip="127.0.0.1", upstream=self.server.server_address)
        settings.update(options)
        forwarder = TestMinerForwarder(**settings)
        forwarder.start()
        self.addCleanup(forwarder.close)
        return forwarder

    def connect(self, forwarder):
        client = socket.create_connection(forwarder.address, timeout=2)
        self.addCleanup(client.close)
        return client

    def test_bidirectional_bytes_and_upstream_withdrawal_reach_client(self):
        client = self.connect(self.forwarder())
        client.sendall(b"work")
        self.assertEqual(client.recv(4), b"work")
        client.sendall(b"close")
        self.assertEqual(client.recv(1), b"")

    def test_nonmatching_source_is_refused_before_upstream_connection(self):
        client = self.connect(self.forwarder(miner_ip="127.0.0.2"))
        self.assertEqual(client.recv(1), b"")
        self.assertEqual(self.accepted, 0)

    def test_aggregate_byte_budget_closes_connection(self):
        client = self.connect(self.forwarder(max_connection_bytes=4))
        client.sendall(b"ok")
        self.assertEqual(client.recv(2), b"ok")
        client.sendall(b"x")
        self.assertEqual(client.recv(1), b"")

    def test_client_limit_and_independent_deadline_withdrawal(self):
        forwarder = self.forwarder(seconds=1, max_clients=1)
        first = self.connect(forwarder)
        first.sendall(b"a")
        self.assertEqual(first.recv(1), b"a")
        second = self.connect(forwarder)
        self.assertEqual(second.recv(1), b"")
        self.assertTrue(forwarder.stop.wait(2))
        self.assertEqual(first.recv(1), b"")

    def test_public_wildcard_upstream_and_unbounded_options_are_refused(self):
        settings = dict(bind=("127.0.0.1", 0), miner_ip="127.0.0.1", upstream=self.server.server_address)
        for changed in ({"bind": ("0.0.0.0", 0)}, {"bind": ("8.8.8.8", 0)},
                        {"miner_ip": "192.168.1.0/24"}, {"upstream": ("192.168.1.1", 3333)},
                        {"seconds": 0}, {"max_clients": 5}, {"max_connection_bytes": 0}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                TestMinerForwarder(**dict(settings, **changed))


if __name__ == "__main__":
    unittest.main()
