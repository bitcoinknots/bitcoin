# Hardware integration and production readiness

This report records the hardware milestone before the later
[SPN1 native regtest enforcement](sharepool-native-enforcement.md) was added.
Its physical results apply to the capture/observer envelope, not SPN1 mining.

At that milestone on 2026-09-11, the reference had a real Testnet4/Sia adapter, physical
Goldshell evidence, and a durable passive observer tested against native Knots.
**It is not a mainnet-ready settlement protocol.** The public hardware test does
not connect the earlier PoW checkpoint ledger to native block validity.

The later SPN1 run produced [28 enforcing regtest blocks](../contrib/sharepool/results/native-hardware-regtest.json)
from the Goldshell, with [independent native replay](../contrib/sharepool/results/native-hardware-replay.json)
and verified restoration to Lazarus. The latest software-only
[hardening pass](../contrib/sharepool/results/native-hardening.json) then added
native owner signing, historical-template validation, bounded peer exchange and
retained evidence recovery. It passed 333 Python tests and a 162-block native
integration run. Those changes did not reroute the miner again. The physical
measurements below remain the earlier Testnet4 results, not measurements of the
later software pass.

## Physical test and restoration

The local Goldshell SCLITE, firmware 2.2.0, was temporarily assigned to a
dedicated test listener for 90 seconds. Its original pools remained configured
as fallbacks. The native node reported `/Satoshi:29.4.1/Knots:20260508/`,
`chain=testnet4`, no initial block download, and the expected Testnet4 genesis.
These results concern this Knots release's BLAKE2b Testnet4 branch.

| Check | Measured result |
| --- | --- |
| Physical accepted/rejected shares | 13 / 0 |
| Successful Stratum subscription/authorization | 1 / 1; the other connections were probes |
| Jobs constructed / notifications sent | 7 / 6 |
| Distinct settlement commitments | 4 |
| Snapshot share counts as jobs were constructed | 0, 0, 5, 7, 13, 13, 13 |
| ASIC hash equals reconstructed Knots header hash | All 13 shares |
| Full native template proposal acceptance | All 7 constructed jobs |
| Public testnet base-target solutions | 0; no testnet block was submitted |
| Restoration | Original pool order and operating settings restored; test entry removed |
| Lazarus after restoration | Active gateway and fresh upstream accepted shares observed |

The last job was constructed at shutdown and was not necessarily delivered to
the ASIC. Its inclusion of all 13 shares is not evidence that a winning block
settled them. Native proposal validation checks transactions and other candidate
rules while skipping PoW; the separate recorded share replay verifies the ASIC
hash and approved share target. A share target is not the native block target.

The saved pool configuration identified the original local gateway's upstream
as `stratum.awokenlazarus.xyz:28915`. At 20:34:53 UTC the original first pool was
active again. A fresh upstream accepted-share log entry was observed at
20:34:51 UTC, after restoration completed. Fan, power, firmware, and network
settings were not changed. No factory reset or miner reboot was performed.

The [hardware report](../contrib/sharepool/results/hardware-testnet4.json)
contains results and the full capture's SHA256. Raw captures and private device
configuration backups remain local. Credentials are not repository artifacts.
The published unit fixtures can be reproduced without access to that miner.

## Exact ASIC-to-block binding

[`testnet_template.py`](../contrib/sharepool/testnet_template.py) retains the
GBT transaction bytes and verifies their advertised txids, witness hashes,
weights, dependency shape, fee sum, and derived witness commitment. It allocates
the complete subsidy plus advertised fees to explicit outputs and enforces
candidate size/weight limits before native proposal validation. Native Knots
remains authoritative for scripts, UTXOs, and actual transaction fees.

For BLAKE2b the Bitcoin coinbase is immutable within a job. Connection and miner
extranonce live in the header's `m_extranonce`; inserting them into the coinbase
after dispatch would change H1 and destroy the link to the ASIC's work. The Sia
adapter maps all 64 nonce bits and all 64 search-time bits into their permitted
header fields while preserving the committed consensus time. Every submission
is hashed as both an 80-byte ASIC work preimage and a complete reconstructed
164-byte Knots header; acceptance requires identical hashes.

The implemented profile is unmasked Sia work with zero header flags and zero
XOR key. Unsupported required GBT rules, masking, preexisting merge-mining roots,
and other networks reject. Namespace composition with other sidechains is still
needed; this laboratory profile occupies the entire `m_mm_rhs` root.

## Durable admission and native settlement observation

[`testnet_hardware_capture.py`](../contrib/sharepool/testnet_hardware_capture.py)
is a bounded integration-test listener, restricted to a configured private
interface and miner IP. RPC forces `-chain=testnet4` and checks chain/genesis and
sync status. The listener supports at most four handlers; workers finish before
the capture database closes. Its unique extranonce leases, immutable job bytes,
and accepted proofs are persisted in SQLite with WAL and FULL synchronous mode.
When a proof qualifies as both a share and a block candidate, its credit and
candidate artifact enter one transaction before acknowledgment. Fault-injection
tests verify rollback if the candidate write fails after the share insert. A native submission outage cannot revoke a durable
share acknowledgment; full failed candidates remain available for explicit replay.

When a testnet block target is easier than the assigned share target, a valid
block candidate can be retained/submitted without falsely crediting harder
share work. Invalid ordinary proofs, wrong sessions, duplicate proofs, unknown
jobs, expired jobs, and ordinary work older than the latest refreshed native
parent reject. Native templates refresh every 15 seconds. This test admission
policy is separate from the earlier checkpoint ledger's age/epoch policy.

The versioned `SettlementCommitment` envelope in
[`base_chain_settlement.py`](../contrib/sharepool/base_chain_settlement.py)
binds network genesis, pool, rules root, snapshot root, actual base parent, and
a digest of every ordered coinbase output, including a witness output. It
removes ambiguity between display-order block hashes and raw commitment bytes.

The passive observer accepts supplied commitment metadata, verifies the native
header and exact coinbase, and tracks `pending`, `immature`, `mature`, or
`orphaned` from the validating node's actual chain. It has no checkpoint-tip
input. It caches verified bodies for pruned nodes, binds persistent state to one
network, and detects tip changes/concurrent observation updates before committing
a refresh. Unknown data stays pending. It does not validate the meaning or
completeness of the supplied snapshot and does not spend funds.

The observer's conservative `mature` status means 100 descendants, or 101
confirmations. It separately exposes `spendable_next_block` at 100 confirmations,
matching the earlier next-block coinbase spending boundary. Neither status
asserts irreversible finality: an actual native reorganization can reverse it.

Eight [native observer cases](../contrib/sharepool/results/native-observer.json)
ran against one disposable stock Knots process with networking and wallets
disabled. Tests covered exact commitments and payouts, an incorrect allocation,
administrative disconnection/reconsideration, both maturity boundaries, and
SQLite restart. Snapshot roots and allocations in this regtest are fixtures.
The node reached height 102, stopped, and its temporary datadir was removed.

The negative payout test is essential: **the native node accepted the deliberately
incorrect pool allocation, while the passive observer rejected it.** No native
settlement consensus has been added by these adapters.

## Reproduction

The combined suite recorded at this earlier hardware milestone passed 243 tests.
The latest combined suite passed 333 with the built native signer enabled; see
[current native reproduction](sharepool-native-enforcement.md#reproduction).
The legacy capture/observer components can still be exercised with:

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/regtest_settlement_observer_smoke.py \
  --bitcoind /absolute/path/to/bitcoin-knotsd \
  --output /absolute/path/to/native-observer.json
python3 contrib/sharepool/verify_hardware_capture.py /private/path/to/capture.json
```

To prepare a new physical test, create a fresh capture database, verify an
authenticated Testnet4 node, choose the private listen address and exact miner
IP, and supply an explicit payout script. `HardwareCapture` performs native
proposal validation before `start()` opens the listener. Its `run()` duration
is bounded; it never changes a device's pool settings by itself.

For temporary routing, the optional
[`goldshell_test_guard.py`](../contrib/sharepool/goldshell_test_guard.py) uses the
existing loopback control bridge. `guarded_test()` writes an exclusive mode-0600
backup and fsyncs it before mutation; it adds only its own temporary pool, keeps
original fallbacks, and verifies read-back priority. Its `finally` path restores
the original ordering, removes only the owned test pool, and checks settings
equality. An unrelated concurrent pool change is preserved and reported. The
caller supplies the bounded test callback and must separately verify restored
active mining. Power loss, SIGKILL, or an unreachable device can defeat in-process
restoration; the saved backup supports recovery. The recorded run completed
restoration and separately verified Lazarus activity.

## Remaining mainnet release gates

The native SPN1 profile now implements self-contained block rejection, direct
coinbase allocation and native-parent replay state. Its local signer, peer and
recovery path has integrated tests. The table below distinguishes that progress
from work still required; test coverage or another configuration switch does
not make mainnet activation safe.

| Gate | Current evidence and remaining requirement |
| --- | --- |
| Settlement canonicality and deployment | SPN1 derives paid state from the actual native parent and rechecks exact payouts in `ConnectBlock`. Activation remains regtest-only. Specify and review public deployment, nonparticipating blocks and composition with other `m_mm_rhs` users; unchanged peers otherwise disagree on validity. |
| Data availability and omitted work | Loopback peers exchange bounded full origins and proofs; miners enforce their locally known work. External transport, censorship behavior and availability incentives remain. A commitment cannot prove disclosure of unseen shares. |
| Difficulty and quota meaning | SPN1 uses an easy fixed target and no percentage or physical TH/s cap. Production difficulty, sampling, incentives and attack budgets need specification; the earlier synthetic checkpoint quotas are separate. |
| Production authorization | The new local signer uses native libsecp256k1 and an exclusive mode-0600 key file with regtest/pool/payout policy. Secure provisioning/recovery, further platform support, independent review and a deployed DATUM/gateway authorization protocol remain. Legacy Sia username authorization is not cryptographic miner authentication. |
| Origin and payout validation | Native consensus verifies contained header work, signatures and exact script/amount allocation; miner gates additionally validate full current or recent historical origins through a temporary UTXO view. Review that consensus/policy boundary and exercise many independently operated miners and pools. |
| Resource and recovery behavior | Gates retain a bounded archive behind a 144-block anchor and latch deep-reorg recovery across restart. Queues, downloads and parser allocations are bounded. Sustained load, capacity planning, complete archive restoration and operational failure recovery still need validation. |
| Complete mining pipeline | Earlier hardware tests cover ASIC/native hash binding and 28 regtest settlements; the later native-signer/peer test covers 162 blocks including delayed proofs, halving, pruning and restart. A sustained deployed DATUM pipeline, the new service path on hardware and public-test-network activation remain untested. |
| Independent security and deployment evidence | Native P2P partition/rejoin and historical UTXO cases pass, as does a 2,685-input deterministic address/undefined-behavior sanitizer corpus. Coverage-guided fuzzing, external review, additional platforms, reproducible builds and sustained adversarial campaigns remain. |

No mainnet node, wallet, consensus, or activation configuration was changed.
Miner routing changed temporarily for the test and was restored. The existing
draft PR remains an experiment for review, with the physical integration
milestone now measured explicitly.
