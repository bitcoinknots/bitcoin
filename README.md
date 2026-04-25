Bitcoin Knots — Node-Native Solo Stratum Fork
============================================

This repository is an experimental fork of [Bitcoin Knots](https://bitcoinknots.org) with an embedded solo Stratum mining server built directly into the node.

The goal is simple:

> Let a miner such as a Bitaxe connect directly to a Bitcoin node and receive mining jobs without requiring Miningcore, ckpool, or any external pool server.

This project is currently experimental and intended for research, testing, and development.

Current status
--------------

This fork currently includes an embedded Stratum-v1 solo mining server that can be enabled with node startup flags.

Confirmed working so far:

- Built from source on Raspberry Pi
- Regtest node startup with embedded Stratum enabled
- Stratum listener binding on `127.0.0.1`
- Stratum listener binding on `0.0.0.0`
- Remote LAN connection from another machine
- `mining.subscribe`
- `mining.authorize`
- `mining.set_difficulty`
- `mining.notify`
- `mining.submit`
- `getstratuminfo` RPC
- Bitaxe connected directly to the node over LAN
- Accepted shares on regtest
- Regtest blocks found through the embedded Stratum path
- Functional test coverage for the embedded Stratum solo flow

This has been successfully tested on regtest with a real Bitaxe pointed at:

stratum+tcp://<node-lan-ip>:3333

Why this exists

Bitcoin nodes already validate blocks, track the chain tip, maintain mempool policy, and can construct block templates.

However, most ASIC miners do not speak directly to Bitcoin Core or Bitcoin Knots. They usually expect a Stratum server. In practice, this means a solo miner often needs extra software between the miner and their own node, such as:

Miningcore
ckpool
public solo pools
custom proxy software

This fork explores a different model:

ASIC / Bitaxe → Bitcoin node → block template → submitted block

No external mining pool server. No third-party block template provider. No RPC-to-self bridge. The node itself serves the mining job.

Important warning

This is experimental software.

Do not use this on mainnet with meaningful funds or serious hashpower unless you fully understand the risks and have reviewed the code yourself.

Potential risks include:

invalid block template handling
stale jobs
incorrect share validation
Stratum compatibility issues
miner-specific behavior differences
denial-of-service surface from exposing a Stratum port
bugs in block submission logic
incomplete production hardening

Regtest has been successful. Signet testing is the next intended step. Mainnet should only be considered after extended live-network testing.

Embedded Stratum server

The embedded Stratum server is controlled with startup flags.

Example regtest startup:

./bin/bitcoind -regtest \
  -server=1 \
  -fallbackfee=0.0001 \
  -stratum=1 \
  -stratumbind=0.0.0.0 \
  -stratumport=3333 \
  -stratumdifficulty=1 \
  -rpcuser=bitcoin \
  -rpcpassword=bitcoinpass \
  -stratumpayoutaddress="<REGTEST_ADDRESS>" \
  -printtoconsole

Example miner settings:

Pool URL: stratum+tcp://<node-lan-ip>:3333
Worker:   miner1
Password: x
Useful RPC

This fork adds:

bitcoin-cli getstratuminfo

Example output:

{
  "enabled": true,
  "listening": true,
  "accept_loop_running": true,
  "bind": "0.0.0.0",
  "port": 3333,
  "clients": 1,
  "connected_clients": 1,
  "authorized_clients": 1,
  "current_job_id": "00000037",
  "current_height": 2,
  "current_prevhash": "...",
  "accepted_shares": 19,
  "rejected_shares": 16,
  "blocks_found": 19,
  "last_client_ip": "192.168.1.7",
  "last_authorized_worker": "miner1",
  "last_accepted_share_hash": "...",
  "last_rejected_share_reason": "...",
  "last_block_submission_result": "accepted",
  "uptime": 123,
  "last_notify_time": 1760000000,
  "version_rolling_enabled": false,
  "version_rolling_mask": "1fffe000"
}
Development notes

The embedded Stratum implementation currently includes:

TCP listener
per-client session handling
line-delimited JSON-RPC Stratum messages
mining.subscribe
mining.authorize
mining.submit
mining.suggest_difficulty
mining.extranonce.subscribe
job creation from internal mining/template interfaces
share reconstruction and validation
block candidate submission path
observability through getstratuminfo
functional test coverage

This is currently solo-only. It is not a pooled accounting system.

No Miningcore, ckpool, or external Stratum proxy is required.

Testing

Run the functional Stratum test with descriptor wallets enabled:

./test/functional/test_runner.py --descriptors feature_stratum_solo.py

The regtest flow has also been manually tested with a real Bitaxe connected over LAN.

Suggested testing progression:

regtest → signet → mainnet

Mainnet testing should only happen after signet behavior is stable and boring.

Upstream Bitcoin Knots

This repository is based on Bitcoin Knots.

For an immediately usable, binary version of the upstream Bitcoin Knots software, see:

https://bitcoinknots.org

What is Bitcoin Knots?

Bitcoin Knots connects to the Bitcoin peer-to-peer network to download and fully validate blocks and transactions. It also includes a wallet and graphical user interface, which can be optionally built.

Further information about Bitcoin Knots is available in the doc folder
.

License

Bitcoin Knots is released under the terms of the MIT license. See COPYING
 for more information or see:

https://opensource.org/licenses/MIT

Development Process

Development generally takes place as part of Bitcoin Core
, and is merged into Knots for each release.

Even if your pull request to Core is closed, or if your feature is not suitable for Core, it may still be eligible for inclusion in Bitcoin Knots. In this case, a pull request may be opened on the Knots GitHub
 for review and consideration.

Testing and code review are critical because this is security-sensitive software.

Translations

Changes to translations as well as new translations can be submitted to Bitcoin Core's Transifex page
.

Translations are periodically pulled from Transifex and merged into the git repository. See the translation process
 for details.

Important: translation changes should not be submitted as GitHub pull requests because the next pull from Transifex would overwrite them.
