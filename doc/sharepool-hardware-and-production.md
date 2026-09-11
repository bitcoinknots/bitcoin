# Hardware integration and production readiness

Status on 2026-09-11: the reference now has a real Testnet4/Sia adapter, physical
Goldshell evidence, and a durable passive observer tested against native Knots.
**It is not a mainnet-ready settlement protocol.** The public hardware test does
not connect the earlier PoW checkpoint ledger to native block validity.

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

The final combined regression suite passes 243 tests. Reproduce it and the
disposable native observer test with:

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

These are unresolved engineering/protocol requirements, not an assertion that
test coverage or one more configuration switch enables mainnet safely.

| Gate | Required before mainnet use |
| --- | --- |
| Single definition of settlement canonicality | Specify how native accepted blocks anchor checkpoint history without allowing a checkpoint reorganization to erase a still-canonical payout. The passive observer supplies a boundary, not integrated share-ledger consensus. |
| Mandatory block validity and deployment | Define exact self-contained validation data, rule activation and behavior for nonparticipating blocks; implement and review native validation. New mandatory rejection rules split unchanged peers. A locally selected checkpoint tip is unsuitable as a Bitcoin validity predicate. |
| Data availability and omitted work | Define bounded publication/download, missing-data recovery, censorship behavior and data retention. A Merkle root cannot establish disclosure of unseen shares. |
| Checkpoint security and quota meaning | Specify difficulty adjustment, work incentives, attack budget and anchored renewal/expiry policy. Easy fixed targets and accelerated checkpoint epochs cannot enforce physical TH/s. |
| Production authorization | Replace functional-test key handling with reviewed production cryptography, secure keys, replay/network separation and a defined miner/gateway authorization protocol. Sia Stratum username authorization in this harness is not cryptographic miner authentication. |
| Integrated registry/payout rules | Validate registry and snapshot contents against native jobs, then prove delayed work is settled once across base-chain and checkpoint forks. The hardware capture and passive observer are currently separate from `PowLedger`. |
| Long-running resource and recovery behavior | Replace the reference's 4096-checkpoint stop with specified pruning/fork eviction, bounded download queues, incremental validated storage and operational recovery. SQLite durability for capture/observer does not fix the old checkpoint archive. |
| Complete mining pipeline | Integrate transactions, actual rewards/fees, miner refresh/expiry, candidate replay and native block results into one end-to-end protocol. Exercise actual testnet wins, peer loss, partitions, restart and many independent miners/pools. |
| Independent security and deployment evidence | Obtain protocol/implementation review, sustained adversarial multi-node testing and reproducible builds. These short local tests and version self-report do not establish production security. |

No mainnet node, wallet, consensus, or activation configuration was changed.
Miner routing changed temporarily for the test and was restored. The existing
draft PR remains an experiment for review, with the physical integration
milestone now measured explicitly.
