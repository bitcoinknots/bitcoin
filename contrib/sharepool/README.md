# Share-pool settlement experiments

This directory contains executable tests of commitments, tagged share proofs,
snapshot settlement, and disagreement between nodes. It also includes a smoke
test that ran two actual stock Knots nodes in isolated regtest.
**The proposed settlement and absolute work-budget rules are not integrated into Knots consensus.**

The new [continuous protocol](../../doc/sharepool-live-protocol.md) implements
authenticated registry versions, signed reward jobs, live Merkle updates,
race-safe gateway refreshes, old-job winners, and carried pending work. Its
loopback smoke transfers signed objects between three validating replicas.

```sh
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
python3 contrib/sharepool/live_protocol_peer.py --run-smoke
```

| New reference component | Purpose |
| --- | --- |
| `signed_registry.py` | Authenticated miner registration, key rotation, and immutable payout versions. |
| `live_protocol.py` | Signed ledger prefixes, snapshot inclusions, eligible reward shares, parent seals, and branch-specific pending/paid claims. |
| `job_gateway.py` | Verify new work and automatically replace the active commitment; discard stale proposal responses. |
| `live_protocol_peer.py` | Bounded loopback HTTP replication and replay tests. |

The reference uses test-only cryptography, synthetic coinbase-only jobs, fixed
rewards, and public XOR keys. Its explicit `credit-and-stop` in-flight policy
keeps acknowledged work payable, reports budget excess, and stops future jobs
for the affected group. A hard cap on credited submissions is a different policy.
The gateway exposes assignments; it does not send ASIC/DATUM messages.

Read the [test report](../../doc/sharepool-test-report.md) for measured behavior,
design gaps, and the distinction between real nodes and model nodes. The
[protocol draft](../../doc/sharepool-design.md) describes the proposed system.
The [additional rule proposal](../../doc/sharepool-rule-proposal.md) specifies
the absolute budget, registered miner tags, and registry-bound coinbase payouts.

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
| `work_rate_budget.py` | Configurable absolute work budget per stable group over a supplied common window. |
| `proof_fixtures.py` | Coinbase tag extraction, coinbase/header binding, context, approved share target, and synthetic PoW. |
| `settlement_sim.py` | Canonical snapshots, counted Merkle inclusion proofs, payout calculation, pending/invalid/valid states, chain selection, reorg accounting, and restart replay. |
| `run_settlement_scenarios.py` | Reproducible multi-node model scenarios, including disagreement and known design limitations. |
| `regtest_commitment_smoke.py` | Actual stock-node commitment acceptance, competing blocks, and explicit administrative rejection/reconsideration. |

The earlier `settlement_sim.py` model checks one pool and a current-parent share window. Tags remain stable
across refreshed jobs and extranonce changes. Non-coinbase transaction selections
may be identical. Work credit uses the approved share target, separately from
the base-chain target in header `nBits`; unexpectedly good hashes earn no extra
credit. The default model uses a common approved share target; separate tests
exercise different targets and unequal work weights.

The only work cap is `group_work <= cap_hashes_per_second * window_seconds`.
The simulator uses a tiny illustrative rate of 1 and nominal duration of 2,
giving a budget of 2 work units per group. These values suit the easy synthetic
proofs and are not production hashrate parameters. Budget tests also exercise
the example 5 TH/s over 600 seconds, including the exact boundary and one unit
above. There is no percentage-of-pool rule or minimum number of groups; a single
group may contain all disclosed work if it fits its budget. Empty snapshots
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
  all eligible work: a coordinator can disclose a balanced sample of a
  concentrated inventory under the model's current rule.
- Supporting shares use zero-payout evidence templates. The model does not yet
  require them to be eligible settlement-bearing reward-mining jobs. Thus it
  does not prove diversity of a pool's actual reward mining.
- Share difficulty and a common window support a disclosed-work rate estimate,
  not an upper bound on physical hashing. Timing, window membership, withholding,
  sampling variation, and cross-pool scope require explicit protocol rules.
- A tag proves a label was bound into the work, not independent ownership or
  execution of DATUM. One operator can create multiple tags and mine real work
  for each of them.
- Snapshot transfer, coordinator signatures, authenticated jobs, multiple pools,
  a complete eligible-share ledger, hidden XOR keys, full transaction validation,
  spendable payouts, maturity, durable crash recovery, and resource-exhaustion
  protection are not implemented by the model.

The winning job uses the root issued before hashing. Later local shares do not
rewrite that snapshot. Nodes with matching rules settle the committed data,
retain missing-data blocks as pending, and reconstruct provisional settlement
when their active chain changes. More work only wins among branches the node
considers valid. See the test report for recovery and split cases.
