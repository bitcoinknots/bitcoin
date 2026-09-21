#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dumpsettings / setsettings RPCs (corepolicy settings over RPC)."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class RpcSettingsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def dump(self):
        return self.nodes[0].dumpsettings()["settings"]

    def set_one(self, name, value):
        res = self.nodes[0].setsettings({name: value})["results"]
        assert name in res, f"{name} missing from setsettings result"
        assert_equal(res[name]["applied"], True)
        return res[name]

    def test_roundtrip(self):
        node = self.nodes[0]
        self.log.info("Round-trip each setting kind through setsettings -> dumpsettings")

        # (name, value, expected-readback)
        cases = [
            # booleans
            ("rejectparasites", True, True),
            ("rejecttokens", True, True),
            ("permitbaremultisig", True, True),
            ("permitbarepubkey", True, True),
            ("permitbaredatacarrier", True, True),
            ("permitbareanchor", True, True),
            ("acceptnonstddatacarrier", True, True),
            ("acceptnonstdtxn", True, True),
            ("subdustfeepenalty", False, False),
            ("acceptunknownwitness", False, False),
            # integers
            ("maxmempool", 500, 500),
            ("mempoolexpiry", 240, 240),
            ("minrelaycoinblocks", 3, 3),
            ("minrelaymaturity", 2, 2),
            ("limitancestorcount", 30, 30),
            ("limitancestorsize", 202, 202),
            ("limitdescendantcount", 30, 30),
            ("limitdescendantsize", 202, 202),
            ("maxtxlegacysigops", 1000, 1000),
            ("bytespersigop", 50, 50),
            ("bytespersigopstrict", 50, 50),
            ("maxscriptsize", 2000, 2000),
            ("datacarriersize", 100, 100),
            # amounts (BTC/kvB, numeric readback)
            ("minrelaytxfee", "0.00002000", Decimal("0.00002000")),
            ("incrementalrelayfee", "0.00001500", Decimal("0.00001500")),
            ("dustrelayfee", "0.00003000", Decimal("0.00003000")),
            # fixed-point number
            ("datacarriercost", "2.50", Decimal("2.5")),
            # strings
            ("mempooltruc", "reject", "reject"),
            ("mempoolreplacement", "never", "never"),
            ("mempoolreplacement", "fee,optin", "fee,optin"),
            ("mempoolreplacement", "fee", "fee,-optin"),
            ("permitephemeral", "reject", "reject"),
            ("permitephemeral", "-anchor,-send,dust", "-anchor,-send,dust"),
            ("dustdynamic", "off", "off"),
        ]
        for name, value, expected in cases:
            self.set_one(name, value)
            got = self.dump()[name]
            assert_equal(got, expected)

        self.log.info("datacarriersize=0 disables datacarrier")
        self.set_one("datacarriersize", 0)
        assert_equal(self.dump()["datacarriersize"], 0)

    def test_live_effect_via_getmempoolinfo(self):
        node = self.nodes[0]
        self.log.info("Changes take live effect (cross-checked via getmempoolinfo)")
        self.set_one("minrelaytxfee", "0.00005000")
        assert_equal(node.getmempoolinfo()["minrelaytxfee"], Decimal("0.00005000"))
        self.set_one("maxmempool", 123)
        assert_equal(node.getmempoolinfo()["maxmempool"], 123 * 1_000_000)
        self.set_one("mempoolreplacement", "never")
        assert_equal(node.getmempoolinfo()["fullrbf"], False)

    def test_atomicity(self):
        node = self.nodes[0]
        self.log.info("A batch with any invalid value applies nothing")
        before = self.dump()["rejectparasites"]
        assert_raises_rpc_error(
            -8, "Invalid settings",
            node.setsettings, {"rejectparasites": (not before), "maxmempool": "not-a-number"})
        assert_equal(self.dump()["rejectparasites"], before)

        self.log.info("Unknown setting names are rejected")
        assert_raises_rpc_error(-8, "unknown setting", node.setsettings, {"nosuchsetting": 1})

        self.log.info("Type errors are rejected")
        assert_raises_rpc_error(-8, "Invalid settings", node.setsettings, {"rejectparasites": "banana"})

        self.log.info("Out-of-range integers are rejected")
        assert_raises_rpc_error(-8, "Invalid settings", node.setsettings, {"maxmempool": 2**40})
        assert_raises_rpc_error(-8, "Invalid settings", node.setsettings, {"maxmempool": -1})

    def test_detailed(self):
        node = self.nodes[0]
        self.log.info("dumpsettings detailed returns real type/help metadata")
        detailed = node.dumpsettings(True)["settings"]
        entry = detailed["rejectparasites"]
        assert_equal(entry["type"], "bool")
        assert "value" in entry
        assert "help" in entry and len(entry["help"]) > 0
        assert_equal(detailed["spkreuse"]["restart_required"], True)

    def test_persistence_and_restart(self):
        node = self.nodes[0]
        self.log.info("settings.json + rwconf persistence survives restart")
        self.set_one("rejectparasites", True)      # settings.json
        self.set_one("maxmempool", 456)            # rwconf
        spk = self.set_one("spkreuse", "conflict")  # restart-required
        assert_equal(spk["restart_required"], True)

        settings_json = node.chain_path / "settings.json"
        assert settings_json.exists()
        assert "rejectparasites" in settings_json.read_text()

        self.restart_node(0)
        dumped = self.dump()
        assert_equal(dumped["rejectparasites"], True)
        assert_equal(dumped["maxmempool"], 456)
        assert_equal(dumped["spkreuse"], "conflict")

    def run_test(self):
        self.test_roundtrip()
        self.test_live_effect_via_getmempoolinfo()
        self.test_atomicity()
        self.test_detailed()
        self.test_persistence_and_restart()


if __name__ == "__main__":
    RpcSettingsTest(__file__).main()
