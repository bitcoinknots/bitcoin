#!/usr/bin/env python3
"""ThreadOpenConnections prefers NODE_BLAKE2B peers for the first outbound
full-relay slots (SEED_OUTBOUND_CONNECTION_THRESHOLD), so a node quickly gains
peers that can serve the header chain past the BLAKE2b hard fork. It falls back
to any desirable peer after enough tries so a node with none yet still bootstraps.

The addresses are unreachable (connections go through an unreachable proxy and
never complete), so we observe the addresses the node attempts in debug.log. A
fresh node with no anchors always opens OUTBOUND_FULL_RELAY first, so every
attempt exercises the preference.

Case A: mix of NODE_BLAKE2B (250.x) and non-HF (251.x) -> the first slots are HF.
Case B: only non-HF (251.x)                            -> attempted anyway (fallback).
"""
import re

from test_framework.messages import NODE_NETWORK, NODE_WITNESS, NODE_BLAKE2B
from test_framework.netutil import UNREACHABLE_PROXY_ARG
from test_framework.test_framework import BitcoinTestFramework

HF = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B
NON_HF = NODE_NETWORK | NODE_WITNESS

# Enough distinct netgroups that the first several attempts are HF before any of
# them fall into the recently-tried window, so an unbiased draw would almost
# never yield an all-HF prefix.
NUM_ADDRS = 12
FIRST_SLOTS = 6

ATTEMPT_RE = re.compile(r"trying v[12] connection (25[01])\.\d+\.0\.1:8333")


class Blake2bOutboundPreference(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # Let the nodes run ThreadOpenConnections (autonomous outbound selection).
        self.disable_autoconnect = False
        self.extra_args = [["-dnsseed=0", "-debug=net", UNREACHABLE_PROXY_ARG]] * 2

    def setup_network(self):
        # Leave the nodes unconnected so their only addresses are the ones we add.
        self.setup_nodes()

    def add_addrs(self, node, second_octet, services):
        for n in range(1, NUM_ADDRS + 1):
            node.addpeeraddress(f"{second_octet}.{n}.0.1", 8333, False, services)

    def attempts(self, node):
        with open(node.debug_log_path, encoding="utf8") as f:
            return ATTEMPT_RE.findall(f.read())

    def run_test(self):
        self.log.info("Case A: NODE_BLAKE2B (250.x) preferred over non-HF (251.x)")
        node = self.nodes[0]
        self.add_addrs(node, 250, HF)
        self.add_addrs(node, 251, NON_HF)
        self.wait_until(lambda: len(self.attempts(node)) >= FIRST_SLOTS, timeout=90)
        first = self.attempts(node)[:FIRST_SLOTS]
        assert all(a == "250" for a in first), f"non-HF peer attempted among the first outbound slots: {first}"
        self.log.info(f"PASS A: first outbound attempts {first} are all NODE_BLAKE2B")

        self.log.info("Case B: with only non-HF peers, fall back and still connect")
        node2 = self.nodes[1]
        self.add_addrs(node2, 251, NON_HF)
        self.wait_until(lambda: "251" in self.attempts(node2), timeout=90)
        self.log.info("PASS B: fallback attempts non-HF peer, node does not stall")


if __name__ == '__main__':
    Blake2bOutboundPreference(__file__).main()
