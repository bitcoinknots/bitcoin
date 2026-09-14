#!/usr/bin/env python3
"""Finite, exact-IP test forwarder to an unchanged loopback Stratum service.

This module never changes a miner or firewall. It is a laboratory adapter, not
remote authentication: the caller must control the private test network.
"""
import ipaddress
import select
import socket
import socketserver
import threading


def _test_address(value):
    address = ipaddress.ip_address(value)
    allowed = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
    if not any(address in ipaddress.ip_network(network) for network in allowed):
        raise ValueError("numeric private IPv4 test address required")
    return str(address)


class TestMinerForwarder:
    CHUNK_BYTES = 16 * 1024

    def __init__(self, *, bind, miner_ip, upstream, seconds=90, max_clients=1,
                 max_connection_bytes=16 * 1024 * 1024):
        self.bind = (_test_address(bind[0]), bind[1])
        self.miner_ip = _test_address(miner_ip)
        if (not ipaddress.ip_address(upstream[0]).is_loopback or
                any(type(port) is not int or not 0 <= port <= 65535 for port in (bind[1], upstream[1])) or
                not upstream[1] or type(seconds) is not int or not 1 <= seconds <= 600 or
                type(max_clients) is not int or not 1 <= max_clients <= 4 or
                type(max_connection_bytes) is not int or not 1 <= max_connection_bytes <= 16 * 1024 * 1024):
            raise ValueError("bounded loopback upstream and test budgets required")
        self.upstream, self.seconds = upstream, seconds
        self.maximum_bytes, self.maximum_clients = max_connection_bytes, max_clients
        self.stop = threading.Event()
        self.lock, self.close_lock = threading.Lock(), threading.Lock()
        self.sockets = set()
        self.server = self.thread = self.timer = None

    @property
    def address(self):
        return None if self.server is None else self.server.server_address

    def start(self):
        if self.server is not None or self.stop.is_set():
            raise RuntimeError("test forwarder already started or closed")
        forwarder = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client, upstream = self.request, None
                try:
                    client.settimeout(0.2)
                    upstream = socket.create_connection(forwarder.upstream, timeout=0.2)
                    with forwarder.lock:
                        if forwarder.stop.is_set():
                            return
                        forwarder.sockets.update((client, upstream))
                    used = 0
                    while not forwarder.stop.is_set():
                        ready, unused_write, unused_error = select.select((client, upstream), (), (), 0.05)
                        for source in ready:
                            data = source.recv(min(forwarder.CHUNK_BYTES, forwarder.maximum_bytes - used + 1))
                            if not data or len(data) > forwarder.maximum_bytes - used:
                                return
                            destination = upstream if source is client else client
                            destination.sendall(data)
                            used += len(data)
                except OSError:
                    pass
                finally:
                    with forwarder.lock:
                        for connection in (client, upstream):
                            if connection is not None:
                                forwarder.sockets.discard(connection)
                                try:
                                    connection.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass
                                connection.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            request_queue_size = 4

            def __init__(self):
                self.slots = threading.BoundedSemaphore(forwarder.maximum_clients)
                super().__init__(forwarder.bind, Handler)

            def verify_request(self, request, address):
                return address[0] == forwarder.miner_ip and not forwarder.stop.is_set()

            def process_request(self, request, address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except BaseException:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self.slots.release()

        self.server = Server()
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True)
        self.timer = threading.Timer(self.seconds, self.close)
        self.timer.daemon = True
        self.thread.start()
        self.timer.start()

    def close(self):
        with self.close_lock:
            if self.stop.is_set():
                return
            self.stop.set()
            if self.timer is not None:
                self.timer.cancel()
            with self.lock:
                for connection in tuple(self.sockets):
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()
                self.thread.join(timeout=1)
