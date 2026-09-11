# Share-pool settlement experiments

This directory contains executable tests of commitments, tagged share proofs,
snapshot settlement, and disagreement between nodes. It also includes a smoke
test that ran two actual stock Knots nodes in isolated regtest.
**The proposed settlement and 10% rules are not integrated into Knots consensus.**

Read the [test report](../../doc/sharepool-test-report.md) for measured behavior,
design gaps, and the distinction between real nodes and model nodes. The
[protocol draft](../../doc/sharepool-design.md) describes the proposed system.

## Run the model tests

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
| `work_concentration.py` | Exact difficulty-weighted 10% predicate and duplicate record checks. |
| `proof_fixtures.py` | Coinbase tag extraction, coinbase/header binding, context, approved share target, and synthetic PoW. |
| `settlement_sim.py` | Canonical snapshots, counted Merkle inclusion proofs, payout calculation, pending/invalid/valid states, chain selection, reorg accounting, and restart replay. |
| `run_settlement_scenarios.py` | Reproducible multi-node model scenarios, including disagreement and known design limitations. |
| `regtest_commitment_smoke.py` | Actual stock-node commitment acceptance, competing blocks, and explicit administrative rejection/reconsideration. |

The model checks one pool and a current-parent share window. Tags remain stable
across refreshed jobs and extranonce changes. Non-coinbase transaction selections
may be identical. Work credit uses the approved share target, separately from
the base-chain target in header `nBits`; unexpectedly good hashes earn no extra
credit. The default model uses a common approved share target; separate tests
exercise different targets and unequal work weights.

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

## Limits demonstrated by the tests

- A Merkle proof proves inclusion. It does not prove the committed set contains
  all eligible work: a coordinator can disclose a balanced sample of a
  concentrated inventory under the model's current rule.
- Supporting shares use zero-payout evidence templates. The model does not yet
  require them to be eligible settlement-bearing reward-mining jobs. Thus it
  does not prove diversity of a pool's actual reward mining.
- A nonempty work set needs at least ten groups to meet a 10% cap. With exactly
  ten groups, all must have equal credited work. Bootstrap and the measurement
  window need explicit protocol rules.
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
