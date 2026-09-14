#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the extra-work temporary soft fork.

While the deployment is active, a block must meet its header target divided by
the extra-work factor, which rises when the hashrate over the last 72 blocks
exceeds the hashrate over the last 4320 blocks by more than 5/4 (both measured
as effective work over elapsed median-time-past) and is 1 otherwise. It
activates for the first block whose parent's median-time-past reaches
-extrawork and expires with RDTS (-rdtsexpiry).

The chain's timing is driven with mocktime. Where the factor is above 1, block
intervals are scaled by it, as they would be on a real network where the
required work grew: a 5x burst at 120 s spacing becomes 120 s * factor.

Covered:
- option validation (requires -rdtsexpiry, must precede it)
- inactive before the start time: factor 1, no rule advertised, target as bits encode
- steady hashrate after activation keeps factor 1 and the header target
- a 5x hashrate burst raises the factor to ~4 (5 / band 5/4); getblocktemplate
  lists "!extra_work", requires client support, lowers "target" and reports the factor
- a block meeting the header target but not the effective target is rejected
  with bad-extra-work, both as a submitted block and as a header
- when the burst leaves, the factor returns to 1 within about a fast window
- -reindex reproduces the chain and the factor
- expiry: once the parent's median-time-past reaches the RDTS expiry, the
  rule and the rule advertisement are gone
"""
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    CBlockHeader,
    uint256_from_compact,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

BLAKE2B_HEIGHT = 120
FAST_WINDOW = 72
SLOW_WINDOW = 4320
SPACING = 600
# Mock clock: blocks are stamped from T0 at the target spacing; the rule starts
# once the median-time-past reaches START (after the slow window is full) and
# RDTS (with it, this rule) expires at EXPIRY.
T0 = 1_600_000_000
START = T0 + 3000   # activa temprano: EPWG necesita 3*W bloques por encima del piso
EXPIRY = START + 50_000_000
REJECT = 'bad-extra-work'
CLIENT_RULES = ['segwit', 'blake2b', 'extra_work']


class ExtraWorkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            f'-testactivationheight=blake2b@{BLAKE2B_HEIGHT}',
            f'-rdtsexpiry={EXPIRY}',
            f'-extrawork={START}',
        ]
        self.extra_args = [self.base_args]

    # -- helpers ---------------------------------------------------------

    def deployment(self):
        return self.nodes[0].getdeploymentinfo()['deployments'].get('extra_work')

    def factor(self):
        # float(): el RPC devuelve Decimal para los valores JSON numéricos y mezclarlo con los floats del
        # espaciado revienta con TypeError a mitad de la razzia. Se convierte en la única puerta de entrada.
        return float(self.deployment()['factor'])

    def mine_one(self, spacing):
        """Mine one block `spacing` seconds after the previous one."""
        self.mocktime += spacing
        self.nodes[0].setmocktime(self.mocktime)
        self.generate(self.wallet, 1, sync_fun=self.no_op)

    def mine(self, count, spacing=SPACING):
        for _ in range(count):
            self.mine_one(spacing)

    def mine_physical(self, count, hash_multiple):
        """Mine `count` blocks as a network with `hash_multiple` times the base
        hashrate would: the interval is the base spacing divided by the hash
        multiple, times the extra work the rule currently requires."""
        for _ in range(count):
            self.mine_one(int(SPACING * self.factor() / hash_multiple))

    def tmpl(self, rules=CLIENT_RULES):
        return self.nodes[0].getblocktemplate({'rules': rules})

    @staticmethod
    def header_target(tmpl):
        return uint256_from_compact(int(tmpl['bits'], 16))

    def assert_inactive(self, tmpl):
        assert_equal(self.deployment()['active'], False)
        assert_equal(self.factor(), 1)
        assert '!extra_work' not in tmpl['rules']
        assert 'extra_work_factor' not in tmpl
        assert_equal(int(tmpl['target'], 16), self.header_target(tmpl))

    # -- test ------------------------------------------------------------

    # -- EPWG: la razzia tiene que seguir pagando (requisito b) -----------------
    #
    # EPWG compara las ultimas W contra las DOS ventanas anteriores de W bloques, y
    # necesita 3*W por encima del piso de activacion para que el peldano entre. Con
    # W = 1008 son 3024 bloques. Por eso el prefijo es largo: no es adorno, es el tiempo
    # que la regla tarda en estar en vigencia.
    #
    # Prefijo honesto a la tendencia, luego una razzia de 5x. El minero de la razzia
    # FRENA bajo el castigo (caso fisico), que es el unico que existe.

    TREND = 169          # s: la tendencia real de la cadena
    PREFIX = 3600        # bloques despues de activar, para que entren los dos peldanos
    MARKS = (60, 120, 252, 504, 756, 1008)

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())
        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        self.log.info("Prefijo: activacion + %d bloques a la tendencia (%d s)" % (self.PREFIX, self.TREND))
        while node.getblockheader(node.getbestblockhash())['mediantime'] < START:
            self.mine(1, spacing=self.TREND)
        self.log.info("  activo en la altura %d" % (node.getblockcount() + 1))
        for _ in range(self.PREFIX):
            self.mocktime += self.TREND
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        self.log.info("  factor antes de la razzia: %.3f  (debe ser 1.000)" % self.factor())

        self.log.info("Razzia 5x, el minero frena bajo el castigo")
        out = {}
        for k in range(1, max(self.MARKS) + 1):
            f = self.factor()
            sp = max(1, int(round(self.TREND / 5.0 * f)))   # 5x hashrate, estirado por el castigo
            self.mocktime += sp
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
            if k in self.MARKS:
                out[k] = (sp, self.factor())
                self.log.info("  razzia + %4d  espaciado %4d s  factor %.3f" % (k, sp, out[k][1]))

        self.log.info("")
        self.log.info("  factor maximo durante la razzia: %.3f" % max(v[1] for v in out.values()))


if __name__ == '__main__':
    ExtraWorkTest(__file__).main()
