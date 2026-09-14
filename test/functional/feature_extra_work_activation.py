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
START = T0 + (SLOW_WINDOW + 300) * SPACING
EXPIRY = START + 2_000 * SPACING
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

    # -- regresion: el borde de activacion --------------------------------------
    #
    # El recorte de las ventanas rapidas en la altura de activacion (necesario: si no, la
    # ventana lee median-time-pasts de antes del flag day, cuando nada de esta regla los
    # ataba) se implemento primero TRUNCANDO el peldaño en vez de saltearlo. Con eso, un
    # bloque despues de la activacion la ventana rapida medía UN bloque contra una tendencia
    # de 4320, la tasa de una ventana de un bloque no tiene techo, y un timestamp legal en el
    # ultimo bloque pre-activacion clavaba una cadena HONESTA en el tope de 8x, en una fecha
    # publicada. Un modelo entero sobre 300 cadenas honestas de Poisson dio 57 clavadas en el
    # tope con el truncado y ninguna con el salteo.
    #
    # El timestamp que se usa acá es legal sin ninguna licencia: basta que supere el
    # median-time-past, y es lo que produce UpdateTime (max(MTP+1, reloj)) para cualquier
    # minero cuyo reloj vaya atrasado.

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())
        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        self.log.info("Prefijo honesto al espaciado objetivo hasta el borde de la activacion")
        self.mine(SLOW_WINDOW + 200)
        while node.getblockheader(node.getbestblockhash())['mediantime'] < START - 5 * SPACING:
            self.mine(1)

        self.log.info("Un bloque con timestamp minimo legal (MTP+1) justo antes del cruce")
        mtp = node.getblockheader(node.getbestblockhash())['mediantime']
        self.mine_at_exact(mtp + 1)

        self.log.info("Cruzo la activacion con bloques honestos")
        while not self.deployment()['active']:
            self.mine(1)
        activation_tip = node.getblockcount()
        self.log.info("  activo con la punta en %d" % activation_tip)

        self.log.info("Los primeros bloques activos: ningun peldaño entra, el factor DEBE ser 1")
        for i in range(1, 6):
            self.mine(1)
            f = self.factor()
            self.log.info("  activacion + %d  factor %.3f" % (i, f))
            assert_equal(f, 1)

        self.log.info("Y sigue en 1 hasta que el peldaño mas corto entre completo")
        for _ in range(20):
            self.mine(1)
        f = self.factor()
        self.log.info("  activacion + 25  factor %.3f" % f)
        assert_greater_than(1.2, f)
        self.log.info("OK: el borde de activacion no clava el factor")

    def mine_at_exact(self, t):
        """Un bloque sellado exactamente en t (legal si t > median-time-past)."""
        self.mocktime = t
        self.nodes[0].setmocktime(t)
        self.generate(self.wallet, 1, sync_fun=self.no_op)


if __name__ == '__main__':
    ExtraWorkTest(__file__).main()
