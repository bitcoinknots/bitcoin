#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -blockmintxfeerampstart, which raises the required feerate as the block fills up."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# Block resource limits pinned by the node's arguments, in weight units.
MAX_WEIGHT = 90000
RESERVED_WEIGHT = 8000
# Used only by the size-limited phase. DEFAULT_BLOCK_RESERVED_SIZE is not configurable.
MAX_SIZE = 20000
RESERVED_SIZE = 1000
# Every test transaction is padded to this vsize, so each costs ~4000 weight.
TX_VSIZE = 1000
# Byte budget for the coin-age priority pass, which runs before the fee pass.
PRIORITY_SIZE = 20000
# -blockmintxfee, in BTC/kvB. At TX_VSIZE this is exactly 1000 satoshis.
MIN_TX_FEE = Decimal("0.00001")


class BlockMinTxFeeRampTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            f"-blockmaxweight={MAX_WEIGHT}",
            f"-blockreservedweight={RESERVED_WEIGHT}",
            f"-blockmintxfee={MIN_TX_FEE}",
            "-blockprioritysize=0",
            "-blockmintxfeerampstart=100",
            # MiniWallet pads transactions to a target vsize with OP_RETURN outputs.
            "-datacarriersize=100000",
            "-acceptnonstdtxn=1",
        ]]

    def template_tx_count(self):
        return len(self.nodes[0].getblocktemplate({"rules": ["segwit"]})["transactions"])

    def template_size(self):
        """Serialized size the assembler accounts for, including its reserved allowance."""
        template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        return RESERVED_SIZE + sum(len(tx["data"]) // 2 for tx in template["transactions"])

    def base_args(self):
        return [a for a in self.extra_args[0] if not a.startswith("-blockmintxfeerampstart")]

    def restart_with_ramp(self, ramp):
        expected_mempool = self.nodes[0].getmempoolinfo()["size"]
        self.restart_node(0, extra_args=self.base_args() + [f"-blockmintxfeerampstart={ramp}"])
        assert_equal(self.nodes[0].getmempoolinfo()["size"], expected_mempool)

    def fill_mempool(self, fee_rate, count):
        # Each transaction spends its own confirmed UTXO, so every package is a single
        # transaction and its feerate is its own.
        for _ in range(count):
            self.wallet.send_self_transfer(from_node=self.nodes[0], fee_rate=fee_rate,
                                           target_vsize=TX_VSIZE, utxo_to_spend=self.utxos.pop())

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 200)
        self.utxos = self.wallet.get_utxos(confirmed_only=True)
        assert len(self.utxos) >= 70

        # The assembler tracks nBlockWeight starting from RESERVED_WEIGHT and each transaction
        # adds ~4000 weight, so after n transactions it stands at 8000 + ~4000n. The expected
        # counts below all clear their boundary by far more than the few weight units a padded
        # transaction can fall short of 4 * TX_VSIZE.
        self.log.info("Fill the mempool with transactions paying exactly -blockmintxfee")
        self.fill_mempool(MIN_TX_FEE, 25)

        self.log.info("With the ramp disabled the block fills to the weight limit")
        # Added while nBlockWeight + 4000 < 90000, i.e. while 8000 + 4000n < 86000, so n runs
        # to 19 and the 20th transaction is the last one in.
        assert_equal(self.template_tx_count(), 20)

        self.log.info("A getblocktemplate request can override the configured ramp")
        # The node is running with the ramp disabled, so a per-request ramp of 50 has to
        # reproduce the cutoff that -blockmintxfeerampstart=50 produces below.
        template = node.getblocktemplate({"rules": ["segwit"], "minfeeraterampstart": 50})
        assert_equal(len(template["transactions"]), 10)
        # Out of range is an error, not a silent clamp to "disabled", which would fill the block
        # at the base feerate and look like success.
        for bad in (-1, 101):
            assert_raises_rpc_error(-8, "minfeeraterampstart must be between 0 and 100",
                                    node.getblocktemplate,
                                    {"rules": ["segwit"], "minfeeraterampstart": bad})
        # The configured value still applies when the request omits it.
        assert_equal(self.template_tx_count(), 20)

        self.log.info("The ramp start defaults to 50")
        self.restart_node(0, extra_args=self.base_args())
        assert_equal(self.template_tx_count(), 10)

        self.log.info("A ramp of 50 cuts off transactions paying exactly -blockmintxfee")
        # The ramp starts at 45000 weight. Above it the required fee is scaled by
        # (90000 - 45000) / (90000 - used), which exceeds 1 as soon as used passes 45000, so a
        # transaction paying exactly the base feerate needs 8000 + 4000n <= 45000: n runs to 9
        # and the 10th transaction is the last one in.
        self.restart_with_ramp(50)
        assert_equal(self.template_tx_count(), 10)

        self.log.info("Transactions paying twice -blockmintxfee ride the ramp further")
        # These sort ahead of the 1x transactions, so they are selected first. The multiplier
        # stays at or below 2 while 45000 <= 2 * (90000 - used), i.e. used <= 67500, so it needs
        # 8000 + 4000n <= 67500: n runs to 14 and the 15th transaction is the last one in. The
        # 1x transactions are then rejected too, since the multiplier is already past 2.
        self.fill_mempool(MIN_TX_FEE * 2, 25)
        assert_equal(node.getmempoolinfo()["size"], 50)
        # Restart so getblocktemplate rebuilds instead of serving its cached template.
        self.restart_with_ramp(50)
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(len(template["transactions"]), 15)
        # Every selected transaction is one of the 2x payers.
        assert_equal({tx["fee"] for tx in template["transactions"]}, {2000})

        self.log.info("A ramp of 0 scales the required fee from an empty block")
        # ramp_start is 0, so the multiplier is 90000 / (90000 - used). The 2x transactions are
        # admitted while that stays at or below 2, i.e. used <= 45000: the 10th is the last in.
        self.restart_with_ramp(0)
        assert_equal(self.template_tx_count(), 10)

        self.log.info("The ramp follows the size limit when that is the tighter one")
        # -blockmaxsize below MAX_BLOCK_SERIALIZED_SIZE turns on byte accounting, which is the
        # default configuration on mainnet. Here the weight limit is left wide open, so fullness
        # has to be measured against the size limit for the ramp to engage at all.
        size_args = [a for a in self.base_args() if not a.startswith("-blockmaxweight")]
        size_args.append(f"-blockmaxsize={MAX_SIZE}")

        self.restart_node(0, extra_args=size_args + ["-blockmintxfeerampstart=100"])
        assert_greater_than(self.template_size(), MAX_SIZE * 0.9)

        self.restart_node(0, extra_args=size_args + ["-blockmintxfeerampstart=50"])
        # The 2x payers are admitted while (MAX_SIZE - MAX_SIZE/2) / (MAX_SIZE - used) <= 2,
        # i.e. while used <= 0.75 * MAX_SIZE, and the 1x payers are already priced out by then.
        ramped_size = self.template_size()
        assert_greater_than(ramped_size, MAX_SIZE * 0.6)
        assert_greater_than(MAX_SIZE * 0.85, ramped_size)

        self.log.info("Priority transactions push the fee-selected portion up the ramp")
        # -blockprioritysize is nonzero by default on mainnet. Its pass runs before the fee pass
        # and is exempt from -blockmintxfee, so it fills PRIORITY_SIZE bytes (19 transactions of
        # 1029 bytes on top of the 1000 reserved) and leaves the block at ~84000 weight, already
        # past the 45000 ramp start. Without a ramp one more transaction still fits by weight;
        # with a ramp of 50 the required fee at that fullness prices it out.
        priority_args = [a for a in self.base_args()
                         if not a.startswith("-blockprioritysize")] + \
                        [f"-blockprioritysize={PRIORITY_SIZE}"]

        self.restart_node(0, extra_args=priority_args + ["-blockmintxfeerampstart=100"])
        assert_equal(self.template_tx_count(), 20)

        self.restart_node(0, extra_args=priority_args + ["-blockmintxfeerampstart=50"])
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(len(template["transactions"]), 19)
        # The priority pass ignores fees, so it takes both payer classes; the fee pass, which
        # would only have taken 2x payers, added nothing on top.
        assert_equal({tx["fee"] for tx in template["transactions"]}, {1000, 2000})
        assert_greater_than(RESERVED_SIZE + sum(len(tx["data"]) // 2
                                                for tx in template["transactions"]), PRIORITY_SIZE)

        self.log.info("Degenerate and extreme configurations are handled without crashing")
        # A block with no room at all leaves used == limit, the divide-by-zero guard.
        self.restart_node(0, extra_args=[a for a in self.base_args()
                                         if not a.startswith("-blockmaxweight")]
                          + ["-blockmaxweight=8000", "-blockmintxfeerampstart=50"])
        assert_equal(self.template_tx_count(), 0)
        # A -blockmintxfee far beyond any payable fee exercises the saturation guard, with the
        # ramp starting from an empty block so that the scaling is applied at all.
        self.restart_node(0, extra_args=[a for a in self.base_args()
                                         if not a.startswith("-blockmintxfee")]
                          + ["-blockmintxfee=1000", "-blockmintxfeerampstart=0"])
        assert_equal(self.template_tx_count(), 0)
        assert_equal(node.getmempoolinfo()["size"], 50)

        self.log.info("The ramp applies to blocks that are actually mined, not just templates")
        self.restart_with_ramp(50)
        blockhash = self.generate(self.wallet, 1)[0]
        block = node.getblock(blockhash, 2)
        # The coinbase plus the same 15 transactions the template selected.
        assert_equal(len(block["tx"]) - 1, 15)
        assert_equal({tx["fee"] for tx in block["tx"][1:]}, {Decimal("0.00002000")})
        assert_equal(node.getmempoolinfo()["size"], 35)
        # The block stopped well short of the limit it was allowed to fill.
        assert block["weight"] < MAX_WEIGHT * 0.8, block["weight"]

        self.log.info("The ramp prices whole ancestor packages, not individual transactions")
        # Everything above used single-transaction packages. Here each package is a CPFP pair:
        # a parent paying 1x that could never get in alone, and a child paying 3x. The assembler
        # sees one package of 2000 vbytes paying 4000 satoshis, so it must scale the 2000
        # satoshi base fee for the pair, not for either transaction. At an ancestor feerate of
        # 2x the pair is admitted while used <= 67500, and each pair costs 8000 weight:
        # 8000 + 8000n <= 67500 admits 8 pairs, so 16 transactions.
        # Drain the leftover singles by mining them, so the packages are the only candidates.
        # Clearing via -persistmempool=0 would leave a stale mempool.dat for later restarts.
        self.restart_with_ramp(100)
        while node.getmempoolinfo()["size"] > 0:
            self.generate(self.wallet, 1)
        for _ in range(11):
            parent = self.wallet.send_self_transfer(from_node=node, fee_rate=MIN_TX_FEE,
                                                    target_vsize=TX_VSIZE,
                                                    utxo_to_spend=self.utxos.pop())
            self.wallet.send_self_transfer(from_node=node, fee_rate=MIN_TX_FEE * 3,
                                           target_vsize=TX_VSIZE,
                                           utxo_to_spend=parent["new_utxo"])
        assert_equal(node.getmempoolinfo()["size"], 22)

        # Without a ramp the pairs fill the block: 8000 + 8000n < 90000 admits 10 pairs.
        self.restart_with_ramp(100)
        assert_equal(self.template_tx_count(), 20)
        self.restart_with_ramp(50)
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(len(template["transactions"]), 16)
        # Both halves of every selected pair are present, parents included.
        assert_equal(sorted({tx["fee"] for tx in template["transactions"]}), [1000, 3000])

        self.log.info("Out-of-range values are rejected at startup")
        self.stop_node(0)
        # "abc" and "" would both reach 0, the most aggressive ramp, under a lenient parse.
        for bad in (-1, 101, "abc", ""):
            node.assert_start_raises_init_error(
                extra_args=self.base_args() + [f"-blockmintxfeerampstart={bad}"],
                expected_msg="must be a number between 0 and 100",
                match=ErrorMatch.PARTIAL_REGEX,
            )

        # Both spellings would otherwise parse as 0, the most aggressive ramp, when a user
        # writing them plainly means "off" (which is 100).
        self.log.info("Negated and valueless forms are rejected rather than meaning 0")
        node.assert_start_raises_init_error(
            extra_args=self.base_args() + ["-noblockmintxfeerampstart"],
            expected_msg="Negating of -blockmintxfeerampstart is meaningless and therefore forbidden",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=self.base_args() + ["-blockmintxfeerampstart"],
            expected_msg="Can not set -blockmintxfeerampstart with no value",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == '__main__':
    BlockMinTxFeeRampTest(__file__).main()
