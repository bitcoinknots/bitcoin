#!/usr/bin/env python3
"""ThreadDNSAddressSeed drives its DNS-seed cadence off the NODE_BLAKE2B peer
count, not total addrman size: only such a peer can serve the header chain past
the BLAKE2b hard fork. Query the seeds immediately when there are none, and use
the NODE_BLAKE2B count for the FEW/MANY delay threshold.

Case A: >1000 non-HF, 0 NODE_BLAKE2B   -> "Loading addresses from DNS seed", no wait.
Case B: same + 1 NODE_BLAKE2B (few HF) -> FEW-peers delay ("Waiting 11 seconds"),
                                          not MANY, though total addrman > 1000.
"""
from test_framework.messages import NODE_NETWORK, NODE_WITNESS, NODE_BLAKE2B
from test_framework.netutil import UNREACHABLE_PROXY_ARG
from test_framework.test_framework import BitcoinTestFramework

NON_HF = NODE_NETWORK | NODE_WITNESS
HF = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B


class Blake2bDnsImmediate(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-dnsseed=1", "-debug=net", UNREACHABLE_PROXY_ARG]]

    def _counts(self):
        raw = self.nodes[0].getrawaddrman()
        entries = [e for table in raw.values() for e in table.values()]
        hf = sum(1 for e in entries if int(e["services"]) & NODE_BLAKE2B)
        return len(entries), hf

    def run_test(self):
        node = self.nodes[0]

        # >1000 total (past DNSSEEDS_DELAY_PEER_THRESHOLD) so Case B proves the
        # delay uses the NODE_BLAKE2B count, not size. Aim past 1100 since new-table
        # bucketing drops a non-deterministic fraction.
        self.log.info("Populate well over 1000 non-HF addresses")
        for i in range(20000):
            first, second, third = i % 2 + 1, i % 256, i % 100
            node.addpeeraddress(f"{first}.{second}.{third}.1", 8333, False, NON_HF)
            if i > 1000 and i % 100 == 0 and self._counts()[0] > 1100:
                break
        else:
            assert False, f"could not populate >1100 addrman entries; got {self._counts()[0]}"
        total, hf = self._counts()
        self.log.info(f"addrman: {total} entries, {hf} NODE_BLAKE2B")
        assert total > 1000 and hf == 0

        self.log.info("Case A: zero-HF, >1000 total -> DNS immediately (no wait)")
        with node.assert_debug_log(
                expected_msgs=["Loading addresses from DNS seed"],
                unexpected_msgs=["seconds before querying DNS seeds."], timeout=30):
            self.restart_node(0)
        self.log.info("PASS A: queries DNS right away")

        self.log.info("Add one NODE_BLAKE2B address")
        node.addpeeraddress("8.8.8.8", 8333, False, HF)
        total, hf = self._counts()
        self.log.info(f"addrman: {total} entries, {hf} NODE_BLAKE2B")
        assert total > 1000 and hf >= 1

        self.log.info("Case B: 1 NODE_BLAKE2B among >1000 total -> FEW delay (HF-count, not size)")
        with node.assert_debug_log(
                expected_msgs=["Waiting 11 seconds before querying DNS seeds."], timeout=30):
            self.restart_node(0)
        self.log.info("PASS B: delay keys on NODE_BLAKE2B count, not total addrman size")

        self.log.info("RESULT: cadence tracks NODE_BLAKE2B count -- 0 -> instant, few -> FEW delay")


if __name__ == '__main__':
    Blake2bDnsImmediate(__file__).main()
