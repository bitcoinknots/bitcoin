#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run bounded v7/v8 loopback Stratum/Sia integration on existing regtest.

Requires an already running, isolated v7 or v8 regtest node and an existing native
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
from hash_stratum import HashStratumService, VardiffStratumService
from hash_vardiff import VardiffController


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
            raise ValueError("RPC outside regtest transport scope")
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
    parser.add_argument("--profile-version", type=int, choices=(7, 8), default=7)
    parser.add_argument("--share-work-bits", type=int,
        help="required initial v8 expected work exponent, 0..255; one payout identity per listener")
    parser.add_argument("--target-share-seconds", type=float, default=60,
        help="v8 accepted-share cadence target; not a physical hashrate cap")
    parser.add_argument("--vardiff-retarget-seconds", type=float,
        help="v8 minimum observation window; default four target intervals")
    parser.add_argument("--transport-difficulty", type=int,
        help="optional harder ASIC traffic target, power of two in 1..2^24; native work credit is unchanged")
    options = parser.parse_args()
    if not 1 <= options.seconds <= 600 or not 0 <= options.port <= 65535:
        parser.error("test duration must be 1..600 seconds and port 0..65535")
    if options.profile_version == 8:
        if options.share_work_bits is None or options.transport_difficulty is not None:
            parser.error("v8 requires --share-work-bits and does not use --transport-difficulty")
    elif options.share_work_bits is not None or options.vardiff_retarget_seconds is not None or options.target_share_seconds != 60:
        parser.error("adaptive share-work options require --profile-version=8")
    gate = service = None
    try:
        signer = HashSigner(options.signer_binary, options.signer_key, pool=options.pool,
                            payout_script=bytes.fromhex(options.payout_script))
        # Separate subprocess-backed adapters have no shared HTTP connection.
        rpc = RegtestCLI(options.bitcoin_cli, options.datadir, timeout=30)
        observer = RegtestCLI(options.bitcoin_cli, options.datadir, timeout=1)
        gate = HashMiningGate(options.gate, rpc=rpc, pool=options.pool,
            public_key=signer.public_key, payout_script=signer.payout_script,
            profile_version=options.profile_version, activation_height=options.activation_height,
            share_work_bits=options.share_work_bits)
        common = dict(sign_owner=signer.sign_owner, observer_rpc=observer,
            bind=("127.0.0.1", options.port), work_update_seconds=options.work_update_seconds)
        if options.profile_version == 8:
            controller = VardiffController(initial_work_bits=options.share_work_bits,
                target_share_seconds=options.target_share_seconds, retarget_seconds=options.vardiff_retarget_seconds)
            service = VardiffStratumService(gate, controller=controller, **common)
        else:
            service = HashStratumService(gate, transport_difficulty=options.transport_difficulty, **common)
        service.start()
        announcement = {"address": list(service.address), "network": "regtest", "profile": options.profile_version,
                          "user": "sharepool.regtest", "hardware_configured": False,
                          "transport_difficulty": options.transport_difficulty}
        if options.profile_version == 8:
            announcement.update(share_work_bits=options.share_work_bits,
                target_share_seconds=options.target_share_seconds, active_client_limit=1,
                assignment_scope="one independently configured payout identity")
        print(json.dumps(announcement), flush=True)
        deadline = time.monotonic() + options.seconds
        while time.monotonic() < deadline:
            service.service_once()
            time.sleep(0.01)
        outcome = {"stats": service.stats, "duration_limit_seconds": options.seconds}
        if options.profile_version == 8:
            outcome["vardiff"] = controller.status()
        print(json.dumps(outcome), flush=True)
    finally:
        if service is not None:
            service.close()
        if gate is not None:
            gate.close()


if __name__ == "__main__":
    main()
