#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The TIDES budget RPC reports the same contextual payout cap as construction.

Native unit tests exercise the exact zero/max/max+1/size_t-max reservation
boundaries. This small two-node fixture checks ordinary and RDTS RPC contexts
and constructs independently signed native jobs under both caps.
"""
import hashlib
import json
from pathlib import Path

from feature_sharepool_hash_vardiff import SharePoolHashVardiffTest
from hash_snapshot import HashSigner
from test_framework.util import assert_equal


class SharePoolHashMiningBudgetTest(SharePoolHashVardiffTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 2
        self.extra_args = [args + ["-networkactive=0"] for args in self.extra_args[:2]]
        self.extra_args[1].append("-rdtsexpiry=2000000000")

    def run_test(self):
        self.genesis = int(self.nodes[0].getblockhash(0), 16)
        directory = Path(self.options.tmpdir)
        key = directory / "mining-budget-owner.key"
        contexts = []
        try:
            signer = HashSigner.create(self.signer_binary, key, pool=101,
                payout_script=b"\x00\x14" + b"b" * 20)
            for index, maximum in enumerate((999612, 199612)):
                node = self.nodes[index]
                self.log.info("Check contextual payout-byte reservation, RDTS=%s", bool(index))
                budget = node.getsharepoolhashtidesbudget(f"{signer.pool:064x}", signer.payout_script.hex())
                assert_equal(budget["native_tip"], node.getbestblockhash())
                assert_equal(budget["pool"], f"{signer.pool:064x}")
                assert_equal(budget["payout_script"], signer.payout_script.hex())
                assert_equal(budget["output_count"], 1)
                assert_equal(budget["output_bytes"], 31)
                assert_equal(budget["max_output_bytes"], maximum)
                block, snapshot, unused = self.construct(index, signer)
                assert_equal(budget["native_bits"], block.nBits)
                assert_equal(snapshot.envelope.native_parent, int(budget["native_tip"], 16))
                assert_equal(sum(len(output.serialize()) for output in snapshot.payouts), budget["output_bytes"])
                assert_equal(self.payouts(block), {signer.payout_script: 5_000_000_000})
                assert_equal(node.getsharepoolhashtidesbudget(f"{signer.pool:064x}", signer.payout_script.hex()), budget)
                assert_equal(node.getblockcount(), 0)
                assert_equal(node.getnetworkinfo()["connections"], 0)
                contexts.append({"rdts": bool(index), "budget": budget,
                    "signed_native_job_constructed": True, "template_bytes": len(block.serialize())})
            report = {"network": "two disconnected native regtest nodes", "profile": 8,
                "hardware_used": False, "contexts": contexts,
                "daemon_sha256": hashlib.sha256(Path(self.options.bitcoind).read_bytes()).hexdigest(),
                "source_sha256": {name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                    for name in ("src/sharepool/mining_budget.h", "src/rpc/mining.cpp",
                        "src/test/sharepool_retry_worker_tests.cpp", "test/functional/feature_sharepool_hash_mining_budget.py")},
                "checks": ["ordinary_context_max_output_bytes", "rdts_context_max_output_bytes",
                    "payout_budget_tip_and_target_binding", "native_job_construction_in_both_contexts"]}
            (directory / "mining-budget-results.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            key.unlink(missing_ok=True)


if __name__ == "__main__":
    SharePoolHashMiningBudgetTest(__file__).main()
