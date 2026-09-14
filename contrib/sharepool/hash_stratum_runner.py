#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the bounded v7 loopback Stratum/Sia integration on existing regtest.

Requires an already running, isolated v7 regtest node and an existing native
owner signer. Reads RPC credentials through bitcoin-cli's datadir handling;
never configures a miner, starts public networking or creates a signer key.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

from hash_mining_gate import HashMiningGate
from hash_snapshot import HashSigner
from hash_stratum import HashStratumService


class RegtestCLI:
    METHODS = frozenset(("getbestblockhash", "getblockchaininfo", "getblockhash", "getblockheader",
        "getblock", "getnetworkinfo", "getsharepoolhashsnapshot", "getsharepoolhashstatus",
        "getsharepoolhashtidesbudget", "preparesharepoolhashjob", "finalizesharepoolhashjob",
        "submitsharepoolhashsnapshot", "validatesharepoolhashshare", "validatesharepoolhashtemplate",
        "submitblock"))

    def __init__(self, binary, datadir, *, timeout):
        self.args = [str(Path(binary).absolute()), "-regtest", "-datadir=" + str(Path(datadir).absolute()), "-stdin"]
        self.timeout = timeout

    def __call__(self, method, *params):
        if method not in self.METHODS:
            raise ValueError("RPC outside v7 regtest transport scope")
        command = [method]
        # bitcoin-cli intentionally treats the optional hash cursor as a string;
        # the literal text "null" is not a nullable JSON cursor. Omit it with a
        # named count argument to preserve the gate's exact no-cursor query.
        if method == "getsharepoolhashstatus" and len(params) == 2 and params[0] is None:
            command = ["-named", method]
            params = ("count=" + str(params[1]),)
        data = "\n".join(value if isinstance(value, str) else json.dumps(value, separators=(",", ":")) for value in params)
        result = subprocess.run(self.args + command, input=data + "\n" if params else "",
            text=True, capture_output=True, timeout=self.timeout, check=False)
        if result.returncode:
            # A remote/RPC diagnostic may echo inputs. Keep its data out of logs.
            raise RuntimeError("bounded regtest RPC failed: " + method)
        try:
            return json.loads(result.stdout)
        except ValueError:
            return result.stdout.strip() or None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-cli", required=True)
    parser.add_argument("--datadir", required=True)
    parser.add_argument("--signer-binary", required=True)
    parser.add_argument("--signer-key", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--pool", required=True, type=lambda value: int(value, 16), help="nonzero pool ID in hex")
    parser.add_argument("--payout-script", required=True, help="exact native signer policy script in hex")
    parser.add_argument("--activation-height", type=int, default=102)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--work-update-seconds", type=int, default=40)
    options = parser.parse_args()
    if not 1 <= options.seconds <= 600 or not 0 <= options.port <= 65535:
        parser.error("test duration must be 1..600 seconds and port 0..65535")
    gate = service = None
    try:
        signer = HashSigner(options.signer_binary, options.signer_key, pool=options.pool,
                            payout_script=bytes.fromhex(options.payout_script))
        # Separate subprocess-backed adapters have no shared HTTP connection.
        rpc = RegtestCLI(options.bitcoin_cli, options.datadir, timeout=30)
        observer = RegtestCLI(options.bitcoin_cli, options.datadir, timeout=1)
        gate = HashMiningGate(options.gate, rpc=rpc, pool=options.pool,
            public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=7, activation_height=options.activation_height)
        service = HashStratumService(gate, sign_owner=signer.sign_owner, observer_rpc=observer,
            bind=("127.0.0.1", options.port), work_update_seconds=options.work_update_seconds)
        service.start()
        print(json.dumps({"address": list(service.address), "network": "regtest", "profile": 7,
                          "user": "sharepool.regtest", "hardware_configured": False}), flush=True)
        deadline = time.monotonic() + options.seconds
        while time.monotonic() < deadline:
            service.service_once()
            time.sleep(0.01)
        print(json.dumps({"stats": service.stats, "duration_limit_seconds": options.seconds}), flush=True)
    finally:
        if service is not None:
            service.close()
        if gate is not None:
            gate.close()


if __name__ == "__main__":
    main()
