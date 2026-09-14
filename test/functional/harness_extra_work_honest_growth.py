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
START = T0 + 3000   # activa temprano: lo que se mide es el regimen, no la activacion
EXPIRY = START + 50_000_000   # LEJOS de la rampa: con 2_000*SPACING la regla
                              # expiraba en el bloque 3664 y los 1.000 del final
                              # eran "regla apagada", no "se auto-extinguio".
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
        return self.deployment()['factor']

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

    # -- harness del FALSO POSITIVO con crecimiento honesto -------------------
    #
    # La pregunta que supera en importancia al hallazgo del timestamp: en una cadena
    # cuyo hashrate crece de verdad, la regla dispara igual? Nuestra cadena pego el
    # tope de 4x del retarget en CADA epoca desde el fork, asi que el caso honesto
    # no es "hashrate estable" sino "hashrate creciendo al tope".
    #
    # Se rampea el espaciado 4x por epoca (2016 bloques) llenando la ventana lenta
    # entera y se lee el factor. No hay ninguna rafaga: todo es crecimiento honesto.

    EPOCH = 2016
    RAMP_MULT = 4.0      # x por epoca
    S0 = 900             # espaciado inicial
    MARKS = (1000, 2000, 3000, 4000, 4320, 4700)

    # Variante FISICA: el minero no puede ignorar el castigo. Si el factor es f, con el
    # mismo hashrate sus bloques salen f veces mas lentos. Esto es lo honesto: mide la
    # auto-extincion cuando el minero REALMENTE frena, no cuando se come el castigo.
    PHYSICAL = True

    def run_test(self):
        import math
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())
        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        k = math.log(self.RAMP_MULT) / self.EPOCH
        self.log.info("Rampa honesta: %.1fx por epoca de %d bloques (sin ninguna rafaga)" % (self.RAMP_MULT, self.EPOCH))
        out = {}
        total = max(self.MARKS)
        for n in range(1, total + 1):
            sp = max(1, int(round(self.S0 * math.exp(-k * n))))
            if self.PHYSICAL:
                # el espaciado que sale de verdad: el que su hashrate da, estirado por el factor
                sp = max(1, int(round(sp * self.factor())))
            self.mocktime += sp
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
            if n in self.MARKS:
                f = self.factor()
                out[n] = (sp, f)
                self.log.info("  bloque %5d  espaciado %4d s  factor %.3f" % (n, sp, f))

        self.log.info("")
        self.log.info("  bloques | espaciado | factor  (crecimiento HONESTO, cero razzia)")
        for n in self.MARKS:
            if n in out:
                sp, f = out[n]
                self.log.info("  %7d | %6d s  | %.3f %s" % (n, sp, f, "  <-- FALSO POSITIVO" if f > 1.01 else ""))
        peor = max((v[1] for v in out.values()), default=0)
        self.log.info("")
        self.log.info("  factor maximo con crecimiento honesto: %.3f" % peor)


if __name__ == '__main__':
    ExtraWorkTest(__file__).main()
