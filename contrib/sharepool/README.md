# Share-pool settlement experiments

The [template-body and dependency reuse follow-up](../../doc/sharepool-v8-body-reuse.md)
retains bounded immutable template decodes and passes successful graph captures
directly into admission accounting. Fresh evidence, native proof validation and
durable acknowledgements remain required.

The latest [v8 admission-pressure follow-up](../../doc/sharepool-v8-admission-pressure.md)
checks local next-batch capacity before new acknowledgements, preserves mining
of retained work during congestion, and reuses local selection and native
history calculations during job preparation. The default is ten shares per
minute per miner. Mainnet remains disabled; finite regtest success does not
establish sustained production capacity.

The [v6 native experiment](../../doc/sharepool-tides-accounting.md) adds
separate-pool rolling payouts, exact job signatures and full-snapshot hashes on
fresh regtest chains. **Rules revision 2** shares the oldest native-height batch
proportionally, carries local ACKs in durable order, relays foreign-pool work
without relabeling it, and adds paged native archives with authenticated restore.
See the [v6 verification report](../../doc/sharepool-v6-r2-report.md) and
[coupled variance calibration](../../doc/sharepool-tides-calibration.md). The
[revision 1 report](../../doc/sharepool-v6-tides-report.md) retains the earlier
Goldshell capture and restoration to Lazarus; that capture is not revision 2
hardware evidence. Mainnet and public-testnet activation remain disabled.

The [resource-budget follow-up](../../doc/sharepool-resource-budget-report.md)
adds exact snapshot counters, avoids repeated codec/cache work and tests shared
and disjoint native transaction sets. Its corrected model includes exact job
dependencies, repeated state and recipient coinbases; production capacity
remains an explicit open constraint.

The separate [v7 compact profile](../../doc/sharepool-v7-compact.md) stores job
authentication once per snapshot, encodes only changing fields per share and
derives recent state from bounded native ancestry. A persistent local pool-history
index accelerates repeated queries. Direct payout policy and SHIFT10 are unchanged;
v7 requires a fresh regtest chain and does not migrate v6 history. Its
[verification report](../../doc/sharepool-v7-verification.md) records the compact
encoding, decoded-memory bounds and remaining pipeline latency.

The profiles and results below are earlier experiments and retain their original
scope and revision-specific limitations.

This directory contains executable tests of commitments, tagged share proofs,
snapshot settlement, and disagreement between nodes. It also includes a smoke
test that ran two actual stock Knots nodes in isolated regtest.

The new [native enforcement profile](../../doc/sharepool-native-enforcement.md)
implements mandatory snapshot, authenticated share-work, replay and exact direct
coinbase payout validation on explicitly enabled regtest nodes. Its miner gate
also validates full origin templates and rejects omissions of locally known
eligible work. Mainnet and public testnet activation are disabled. This native
profile has its own [wire contract](../../doc/sharepool-native-format.md); it does
not transplant the synthetic checkpoint ledger or its absolute work-budget policy.

The current [native P2P relay](../../doc/sharepool-native-p2p.md) exchanges full
templates and shares over existing Bitcoin connections, with explicit SPN1
negotiation and bounded downloads. [`NativeNodeRelay`](native_node_peer.py)
connects that ephemeral cache to the durable miner gate. The
[complete archive](../../doc/sharepool-archive-recovery.md) preserves acknowledged
history through hot-cache pruning and supports verified deep-fork recovery
against a separately protected checkpoint. Peer inventories and untrusted
backups cannot clear local recovery requirements. See the
[current results](results/native-p2p-recovery.json).

The preceding [hardening pass](results/native-hardening.json) added native owner
signing without Python private keys, full historical-origin validation through a
temporary native UTXO view, 144-block retained gate evidence with a persistent
recovery latch, and bounded read-only loopback peer exchange. The final combined
suite passed 333 Python tests with no skips. Its integrated native test reached
162 accelerated blocks, covering multiple owner/payout bindings, delayed work, the regtest
halving, archive pruning, restart and deep rollback. Separate
[adversarial checks](results/native-adversarial.json) cover native P2P partitions
and 2,685 deterministic sanitizer corpus inputs. See the
[signer](../../doc/sharepool-native-signer.md) and
[recovery](../../doc/sharepool-native-recovery.md) interfaces and limitations.

The earlier [physical SPN1 test](results/native-hardware-regtest.json) captured 28 accepted
Goldshell proofs and 28 enforcing regtest blocks, settling 27 prior proofs with
the last winner pending. A [second enforcing node](results/native-hardware-replay.json)
replayed all 29 full origin proposals and the same chain. These isolated test
results predate the new signer and peer/recovery pass, which did not use the
hardware again. They do not establish public-network or production readiness.

The [hardware and production report](../../doc/sharepool-hardware-and-production.md)
records 13 actual Goldshell shares verified on this Knots release's Testnet4
branch, followed by confirmed restoration to Lazarus. That earlier native-template
adapter, capture/replay tools, and durable passive base-chain observer are
separate integration components. Eight disposable native-node cases test the
observer. Neither these results nor the earlier checkpoint model establish
mainnet readiness; the report lists the remaining integration and release gates.

The earlier [permissionless checkpoint reference](../../doc/sharepool-pow-ledger.md)
orders registry changes, shares, and candidate settlements using verified PoW.
Anyone can mine checkpoints, including empty checkpoints that renew work epochs
without a coordinator seal or reward block. Jobs bind an ancestral snapshot with
a bounded checkpoint age. Delayed included shares carry forward, and provisional
payout history reorganizes with the selected checkpoint branch. Epochs count
checkpoint work, not elapsed seconds; this does not measure a hard TH/s limit.

```sh
SHAREPOOL_SIGNER_BINARY=/absolute/build/bin/bitcoin-sharepool-signer \
  python3 -B -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/run_pow_ledger_scenarios.py
```

Build the native signer with `BUILD_UTIL=ON` on POSIX to include its executable
tests; without that environment variable those native signer tests are skipped.
The [native reproduction instructions](../../doc/sharepool-native-enforcement.md#reproduction)
also run the separate enforcing-node functional tests.

The eight [checkpoint scenarios](results/pow-ledger.json) use three independent
replicas per case with direct object delivery in one process. The bounded store,
easy fixed targets, synthetic reward history, and test cryptography are laboratory
tools. Bitcoin anchoring, production difficulty/incentives, pruning, and actual
DATUM/ASIC integration remain open. No network or GPU benchmark is claimed.

The earlier [continuous protocol](../../doc/sharepool-live-protocol.md) implements
authenticated registry versions, signed reward jobs, live Merkle updates,
race-safe gateway refreshes, old-job winners, and carried pending work. Its
loopback smoke transfers signed objects between three validating replicas.
That gateway and HTTP path remain a separate coordinator-signed baseline; they
are not connected to the new permissionless checkpoint reference.

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/live_protocol_peer.py --run-smoke
```

| Reference component | Purpose |
| --- | --- |
| `../../src/consensus/sharepool.cpp` | Native regtest snapshot, share, parent-state and exact coinbase enforcement. |
| `native_enforcement.py` | Independent SPN1 wire builder, deterministic public-key fixtures and an external owner-signing callback. |
| `native_signer.py`, `../../src/bitcoin-sharepool-signer.cpp` | Bounded local adapter and native walletless regtest owner signer with immutable pool/payout policy. |
| `native_mining_gate.py` | Full current/historical origin validation, durable proof admission, known-work inclusion policy, immutable jobs and bounded retained evidence with recovery latching. |
| `native_archive.py` | Complete append-only evidence, protected checkpoint, streaming export/import and verified recovery. |
| `native_node_peer.py`, `../../src/sharepool/relay.cpp` | Miner bridge and native evidence cache relayed over existing Bitcoin P2P connections. |
| `native_peer.py` | Earlier standalone loopback test transport, retained for isolated fixtures. |
| `native_fuzz_corpus.py`, `../../src/test/fuzz/sharepool.cpp` | Deterministic malformed/valid native corpus and sanitizer target for settlement and signer parsers. |
| `native_hardware_capture.py`, `verify_native_hardware_capture.py` | Bounded isolated-regtest Sia transport through the native gate, durable proof/block capture and independent archive replay. |
| `testnet_template.py` | Full GBT transaction/witness preservation and exact Sia ASIC-to-Knots header reconstruction. |
| `testnet_hardware_capture.py`, `verify_hardware_capture.py` | Bounded testnet-only Stratum capture, durable admission, native proposals, and recorded-proof replay. |
| `base_chain_settlement.py` | Versioned native commitment envelope and durable passive observation of base-chain payouts/reorgs/maturity. |
| `goldshell_test_guard.py` | Private configuration backup, temporary test routing, and verified pool/settings restoration through an existing local bridge. |
| `regtest_settlement_observer_smoke.py` | Eight real-node observer tests in a disposable regtest chain. |
| `pow_share_ledger.py` | Permissionless checkpoint PoW, deterministic fork selection, bounded job age, quota heartbeats, exact snapshot settlement, and replay. |
| `run_pow_ledger_scenarios.py` | Eight three-replica checkpoint scenarios, including competing reward histories. |
| `signed_registry.py` | Authenticated miner registration, key rotation, and immutable payout versions. |
| `live_protocol.py` | Signed ledger prefixes, snapshot inclusions, eligible reward shares, parent seals, and branch-specific pending/paid claims. |
| `job_gateway.py` | Verify new work and automatically replace the active commitment; discard stale proposal responses. |
| `live_protocol_peer.py` | Bounded loopback HTTP replication and replay tests. |

The earlier Python ledger reference uses test-only cryptography, synthetic coinbase-only jobs, fixed
rewards, and public XOR keys. Rules commit `budget_basis = "payout-script"`:
all tags and miner IDs assigned to the same registered payout script share one
allowance per pool and origin epoch. Tags identify templates and bind their miner
and registry payout history; they do not grant extra allowance. Claims keep their
original payout script when a registry update changes future jobs' destination.

The explicit `credit-and-stop` policy keeps acknowledged in-flight work payable,
reports excess, and rejects new jobs whose own committed prefix has exhausted
their payout script's budget. The honest gateway uses its current verified
prefix. Eligible older-prefix jobs remain possible; this is not globally enforced
latest-prefix freshness or a hard cap on accepted submissions. The gateway
exposes assignments; it does not send ASIC/DATUM messages.

Read the [test report](../../doc/sharepool-test-report.md) for measured behavior,
design gaps, and the distinction between real nodes and model nodes. The
[protocol draft](../../doc/sharepool-design.md) describes the proposed system.
The [additional rule proposal](../../doc/sharepool-rule-proposal.md) specifies
the payout-script budget, registered miner tags, and registry-bound coinbase payouts.

## Earlier fixed-snapshot model

From the repository root, with Python 3 and no third-party dependencies:

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/run_settlement_scenarios.py
python3 contrib/sharepool/precommit_demo.py
```

The scenario runner writes [results/simulation.json](results/simulation.json).
The recorded unit-test run is in [results/unit-tests.txt](results/unit-tests.txt).
These checks use this checkout's upstream Python implementation of the header-v2
BLAKE2b hash. Supporting shares have actual synthetic PoW at easy targets;
they are not submissions from live miners.

| File | Scope |
| --- | --- |
| `precommit_demo.py` | Pre-mining root commitment and header hash binding, using opaque records. |
| `work_accounting.py` | Exact target-derived work aggregation and duplicate record checks. |
| `work_rate_budget.py` | Configurable absolute work budget over supplied groups; protocol callers group by payout-script bytes. |
| `proof_fixtures.py` | Coinbase tag and payout-script extraction, coinbase/header binding, context, approved share target, and synthetic PoW. |
| `settlement_sim.py` | Canonical snapshots, counted Merkle inclusion proofs, payout calculation, pending/invalid/valid states, chain selection, reorg accounting, and restart replay. |
| `run_settlement_scenarios.py` | Reproducible multi-node model scenarios, including disagreement and known design limitations. |
| `regtest_commitment_smoke.py` | Actual stock-node commitment acceptance, competing blocks, and explicit administrative rejection/reconsideration. |

The `settlement_sim.py` model checks one pool and a current-parent share window.
Its payout-script aggregation uses the script actually bound into each supporting
share's zero-value coinbase output. It has no signed registry; that authentication
belongs to the continuous reference. Tags remain available for attribution across
refreshed jobs and extranonce changes. Non-coinbase transaction selections
may be identical. Work credit uses the approved share target, separately from
the base-chain target in header `nBits`; unexpectedly good hashes earn no extra
credit. The default model uses a common approved share target; separate tests
exercise different targets and unequal work weights.

The fixed-snapshot check is `payout_script_work <= cap_hashes_per_second * window_seconds`.
The simulator uses a tiny illustrative rate of 1 and nominal duration of 2,
giving a budget of 2 work units per payout script. These values suit the easy synthetic
proofs and are not production hashrate parameters. Budget tests also exercise
the example 5 TH/s over 600 seconds, including the exact boundary and one unit
above. Different tags sharing one script aggregate under that same budget. There
is no percentage-of-pool rule or minimum number of recipients or templates; one
recipient may contain all disclosed work if it fits the budget. Empty snapshots
still cannot produce the model's work-based payouts.

## Run the actual-node smoke test

Supply a compatible Knots binary explicitly:

```sh
python3 contrib/sharepool/regtest_commitment_smoke.py --bitcoind /absolute/path/to/bitcoin-knotsd
```

The script creates two temporary datadirs, enables BLAKE2b at regtest height 1,
disables P2P and wallets, and relays test blocks through loopback RPC. It stops
the child processes and removes their datadirs on exit. It does not use the
normal wallet or chain directory. Results go to
[results/regtest.json](results/regtest.json).

The recorded run used a binary reporting `/Satoshi:29.4.1/Knots:20260508/`.
This is version self-report, not reproducible-build verification. The nodes
accepted arbitrary `m_mm_rhs` roots without receiving snapshots. The test's
local rejection uses `invalidateblock` and `reconsiderblock`; it does not
demonstrate automatic settlement validation.

## Earlier model limits and current reference scope

The points below describe the earlier fixed-snapshot fixtures. The continuous
reference adds signed registries, actual reward-job shares, live receipt updates,
and carryover within its test model. Complete disclosure, production consensus,
full transaction validation, and trustworthy physical hashrate remain unresolved;
see [its implementation report](../../doc/sharepool-live-protocol.md).

- A Merkle proof proves inclusion. It does not prove the committed set contains
  all eligible work: a coordinator can disclose an under-budget subset of an
  over-budget inventory under the model's current rule.
- Supporting shares use zero-payout evidence templates. The model does not yet
  require them to be eligible settlement-bearing reward-mining jobs. Thus it
  does not prove diversity of a pool's actual reward mining.
- Share difficulty and a common window support a disclosed-work rate estimate,
  not an upper bound on physical hashing. Timing, window membership, withholding,
  sampling variation, and cross-pool scope require explicit protocol rules.
- A tag binds template attribution; it does not prove independent ownership or
  execution of DATUM. The budget separately aggregates all tags paying the same
  script, so changing tags does not provide more allowance for that destination.
- Snapshot transfer, coordinator signatures, authenticated jobs, multiple pools,
  a complete eligible-share ledger, hidden XOR keys, full transaction validation,
  spendable payouts, maturity, durable crash recovery, and resource-exhaustion
  protection are not implemented by the model.

The winning job uses the root issued before hashing. Later local shares do not
rewrite that snapshot. Nodes with matching rules settle the committed data,
retain missing-data blocks as pending, and reconstruct provisional settlement
when their active chain changes. More work only wins among branches the node
considers valid. See the test report for recovery and split cases.
