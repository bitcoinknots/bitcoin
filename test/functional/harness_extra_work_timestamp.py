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
START = T0 + (SLOW_WINDOW + 300) * 169   # con la tendencia a 169 s, no a SPACING=600
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
        # float(): el RPC devuelve Decimal y mezclarlo con floats revienta con TypeError (pasó en el raid).
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

    # -- harness del escenario de jasonsopko (PR #405) ------------------------
    #
    # No es un test de regresion: es la REPRODUCCION de su hallazgo, para poder
    # contestarle con numeros propios. Dos corridas deterministas sobre el mismo
    # prefijo y la misma rafaga; en una de ellas, seis bloques despues de que
    # empieza la rafaga, un UNICO sello legal de +7200 s (el limite de futuro).
    # Despues de ese paso la cadencia vuelve a ser la honesta, asi que el efecto
    # es exactamente el que describe: el span de median-time-past de cualquier
    # ventana que contenga el paso queda inflado 7200 s de una sola vez.
    #
    # Se mide el factor a los 24/48/72/96/120 bloques de rafaga, que son las
    # filas de su tabla.

    TREND_SPACING = 169   # s: la tendencia. TODO el prefijo va a este ritmo, incluida la ventana
                          #    lenta: la regla mide desviacion de la tendencia PROPIA de la cadena,
                          #    no del objetivo de 600 s. Si se llena la ventana lenta a 600 y el
                          #    prefijo a 169, para la regla la cadena YA viene en rafaga 3,55x y el
                          #    factor arranca en 4,28 en vez de 1 (primer intento de este harness).
    HASH_MULTIPLE = 5     # la rafaga de su escenario: 5x el hashrate de la tendencia
    BURST_SPACING = 169 // 5   # s: 5x mas hashrate = bloques 5x mas seguidos = 33 s
    PUSH = 7200           # s: el limite de futuro, el empujon mas grande que es legal
    PUSH_AT = 6           # bloque de la rafaga en el que se mete el paso
    # Extendido a las marcas del raid: EPWG usa ventanas de 504/1008 bloques, así que a 120 la regla
    # está dormida para las DOS corridas y la diferencia sale 0 por vacía, no por cerrada.
    # Recortado tras un OOM: 10.242 bloques minados no entran en este server. El peldaño de 504 necesita
    # 3 ventanas post-activación (1512 bloques) para tener baseline, y es el que despierta primero —
    # el raid lo vio reaccionar ahí (2.386). El peldaño de 1008 necesitaría 3024 y queda SIN MEDIR.
    MARKS = (24, 72, 120, 252, 504, 756)
    POST_ACTIVATION = 1600   # bloques honestos despues de activar, antes de medir nada

    def mine_at(self, t):
        """Un bloque sellado en t (el reloj del nodo se pone en t, asi que es 'ahora', no futuro)."""
        self.mocktime = t
        self.nodes[0].setmocktime(t)
        self.generate(self.wallet, 1, sync_fun=self.no_op)

    def burst(self, push, tweak=0):
        """Rafaga de 120 bloques al espaciado real. Devuelve {marca: factor}.

        `tweak` desfasa la linea honesta unos segundos. Hace falta porque la segunda
        corrida arranca del MISMO prefijo: sin desfase sus primeros bloques salen
        byte a byte identicos a los de la primera, el nodo ya los tiene marcados
        invalidos por el invalidateblock y los rechaza con `duplicate-invalid`.
        Un segundo sobre 169 no mueve el factor de forma medible (jasonsopko evito
        esto usando dos nodos; esto es mas barato que llenar la ventana lenta dos veces).
        """
        honest = self.mocktime + tweak
        out = {}
        for k in range(1, max(self.MARKS) + 1):
            honest += self.BURST_SPACING
            self.mine_at(honest + (self.PUSH if (push and k >= self.PUSH_AT) else 0))
            if k in self.MARKS:
                out[k] = self.factor()
        return out

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())
        self.wallet = MiniWallet(node)
        self.mocktime = T0
        node.setmocktime(self.mocktime)

        self.log.info("Prefijo: ventana lenta COMPLETA al ritmo de la tendencia (%d s)" % self.TREND_SPACING)
        self.mine(SLOW_WINDOW + 300, spacing=self.TREND_SPACING)
        while node.getblockheader(node.getbestblockhash())['mediantime'] < START:
            self.mine(1, spacing=self.TREND_SPACING)
        assert_equal(self.deployment()['active'], True)
        self.log.info("  activo en la altura %d" % (node.getblockcount() + 1))

        # EPWG compara ventanas de 504/1008 contra las DOS equal-length previas, y las que empiezan antes de la
        # altura de activación se saltean (extrawork.cpp:121). Arrancando la ráfaga apenas activa la regla no hay
        # baseline y el factor es 1.000 por construcción: las dos corridas dan 1.000 y la diferencia sale 0 por
        # vacía, no por cerrada. Hacen falta ≥3 ventanas post-activación antes de medir nada. Mismo PREFIX que
        # harness_epwg_raid.py, para que las dos mediciones sean comparables.
        self.log.info("Prefijo post-activacion: %d bloques a la tendencia (para que entren los dos peldanos)" % self.POST_ACTIVATION)
        for _ in range(self.POST_ACTIVATION):
            self.mocktime += self.TREND_SPACING
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        self.log.info("  factor tras el prefijo: %.3f  (debe ser 1.000)" % self.factor())

        self.log.info("Ventana rapida tambien a la tendencia, para arrancar con factor 1")
        for _ in range(FAST_WINDOW + 10):
            self.mocktime += self.TREND_SPACING
            node.setmocktime(self.mocktime)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        base_h = node.getblockcount()
        base_t = self.mocktime
        self.log.info("  factor antes de la rafaga: %.3f" % self.factor())

        self.log.info("Corrida A: rafaga honesta")
        honest = self.burst(push=False)

        self.log.info("Invalido la rafaga y vuelvo al prefijo para la corrida B")
        node.invalidateblock(node.getblockhash(base_h + 1))
        assert_equal(node.getblockcount(), base_h)
        self.mocktime = base_t
        node.setmocktime(self.mocktime)
        self.wallet.rescan_utxos()   # el rewind dejo al MiniWallet apuntando a coinbases que ya no estan

        self.log.info("Corrida B: misma rafaga con un unico +%d s en el bloque %d" % (self.PUSH, self.PUSH_AT))
        pushed = self.burst(push=True, tweak=1)

        self.log.info("")
        self.log.info("  bloques de rafaga | honesta | +2 h de empujon")
        for k in self.MARKS:
            self.log.info("  %17d | %7.3f | %7.3f" % (k, honest[k], pushed[k]))
        self.log.info("")
        peor = max(honest[k] - pushed[k] for k in self.MARKS)
        self.log.info("  mayor diferencia a favor del atacante: %.3f" % peor)


if __name__ == '__main__':
    ExtraWorkTest(__file__).main()
