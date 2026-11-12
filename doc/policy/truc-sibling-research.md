# TRUC next-block experiment: current scope and testing

This report covers the indexed projection, shared-anchor extension and miner
guard included in the updated draft. The experiment remains opt-in and is not
a production recommendation. Earlier test results are identified below.

## Improvement

The original selector reconstructed every remaining ancestor package after each
selection. This made even independent transactions expensive: the test with 1,755
mempool entries exhausted its two-million-step budget and rejected the replacement.

The research version constructs ancestor packages once, keeps them ordered by
actual feerate and txid, and maintains reverse membership so selecting an ancestor
only updates affected packages. Comparator keys are removed before mutation;
packages affected by ancestor selection are reconsidered. Both projections still
share a work budget and operate on an immutable snapshot under the mempool lock.

The indexed-selector optimization itself preserved eligibility. Subsequent
shared-anchor and miner-guard work is described separately below. Arithmetic and
invalid-index checks reject malformed projection inputs rather than overflowing.

## Indexed-selector evidence (before the shared-anchor extension)

- A deliberately independent, slow oracle reconstructs all remaining ancestor
  packages. The optimized selection matches it on 500 deterministic randomized
  DAGs, varying ancestry, fees, capacity, sigops, exclusions and minimum feerates.
- A 5,000-independent-transaction unit fixture completes below 100,000 charged
  work steps, within the existing two-million-step budget.
- Explicit work-exhaustion and invalid-parent-index unit cases fail closed.
- The previous 1,755-entry congestion fixture now accepts the eligible replacement
  and removes the old sibling. Its assertion changed from expected exhaustion to
  expected successful recovery.
  One isolated run accepted it in 0.0189 seconds, versus an earlier 0.1293-second
  budget-exhaustion rejection. These are illustrative timings, not a controlled
  benchmark or a guaranteed speedup.
- Normal/RDTS cases and existing TRUC, package-RBF, package-limit and ordinary RBF
  regression coverage exercise the same unchanged policy boundaries.

The P2P fixture's default two-second log timeout proved too short under concurrent
load. It now waits up to 60 seconds for the peer's actual rejection diagnostic;
the assertion was not removed or replaced by an arbitrary sleep.
The failed seed and a fresh-seed rerun both passed with that timeout correction.
All eight functional variants/regressions are covered by successful runs, and all
six RBF unit cases pass, including the 500-graph differential test.

Work steps do not count every comparison, allocation, byte or CPU instruction.
These results do not establish a worst-case DoS bound. Dense ancestor graphs,
large configured limits, repeated invalid requests and lock contention remain
important profiling targets. Randomized differential testing is evidence of
equivalence, not a formal proof.

## Shared-anchor extension and miner guard

`-trucsharedanchornextblock=1` additionally allows the exception for a direct
conflict on a common parent's P2A output. It requires `-trucsiblingnextblock=1`
and enforced TRUC. Each child must spend exactly one common-parent output, and
the anchor must be their only shared input. Reusing a confirmed fee input as an
additional conflict is excluded. The existing one-conflict/no-descendants,
shrinking, fee-ratio, projection and non-package requirements remain in force.
Neither option is enabled by default. This does not enable legacy v2 recovery.

The miner guard uses BlockAssembler's argument parser and declines the exception
unless priority space is zero, weight/size limits are the full consensus maxima,
the reserved weight is the default, and mining's minimum feerate matches relay's.
Any mempool entry with a nonzero fee delta also disables the exception for that
attempt. Ordinary adequately funded RBF remains available.

The projection now reserves the actual default 8,000 weight units, rather than
4,000, and uses strict weight/sigop boundaries. A compatible test configuration
is `-blockprioritysize=0 -blockmaxsize=4000000 -blockmaxweight=4000000
-blockmintxfee=0.00001000 -minrelaytxfee=0.00001000`, with default reserve.
`-corepolicy=1` alone does not match those fee floors. The consensus RDTS weight reduction
still applies. The guard does not change operator mining settings automatically.

**This closes known configuration-driven false admissions by refusing them; it
does not implement support for default priority mining.** Exact BlockAssembler
equivalence remains unproven even with compatible settings: ancestor-score
ordering, policy-vsize fit checks, finality and near-full stopping heuristics
must be covered by a shared selection implementation or differential tests.
RPC template overrides and other miners' preferences are not predicted.

New tests cover anchor scope, invalid witnesses without eviction, opt-in/off
behavior, actual template inclusion and fee totals, competitor fee deltas, and
rejection under mismatched priority, size, weight, reserve and fee-floor settings.
These are synthetic recovery fixtures, not real CLN/LND/Ark end-to-end tests.

The test changes settings by restarting. Reloading the mempool does not perform
package admission, so zero-fee parents and their children may be absent after
restart. The fixture explicitly resubmits those packages and checks their
presence before exercising invalid-witness and recovery assertions. This is not
evidence that zero-fee packages persist across restart; L2 rebroadcast behavior
must be covered by the later end-to-end tests.

### Validation results

- Linux build completed; all seven `rbf_tests` cases passed, including the new
  anchor-scope case and the 500 randomized projection comparisons.
- All four next-block variants passed: normal blocks, RDTS, RDTS stress and
  mixed-policy P2P. The final run took 75 seconds wall time with two jobs.
- Existing `mempool_truc`, `mempool_package_rbf`, `mempool_package_limits` and
  `feature_rbf` regressions passed against the changed binary.
- The shared-anchor fixture replaces a 10,000-sat / 962-vB child with a
  5,000-sat / 145-vB child. It verifies the old child is absent, the new child
  is selected by the actual fee-only template, and template fees do not fall.
- Invalid witness submission leaves the old mempool intact. Shared-anchor
  opt-out and non-P2A direct-conflict rejection remain covered.
- Default priority mining and incompatible size, weight, reserve and fee-floor
  settings reject the exception; ordinary fee-paying replacement remains tested.

Initial failures are retained in the operational logs. The first run exposed
the test's implicit corepolicy mining/relay-floor mismatch. Later runs exposed
zero-fee package reload and stale MiniWallet input tracking after raw package
resubmission. Tests now set matching fee floors, restore/check the packages and
rescan the test wallet. No rejection assertion was weakened to make them pass.
Logs are archived outside this repository under
`operations/truc-policy-tests/sibling-nextblock/research/anchor-*.log` in the
operations workspace.

## Remaining work before considering production use

1. Default priority mining is guarded out, not modeled. Exact fee-only miner
   equivalence and dynamic template settings still require further work.
2. Shared P2A anchor support passes synthetic validation; legacy v2 Lightning
   paths remain excluded. Real protocol compatibility must not be inferred from
   these tests.
3. A rising congestion boundary can permit repeated shrinking; this is not a
   persistent one-use allowance or a lifetime relay-cost budget.
4. Real signed CLN/LND HTLC and Ark exit recovery still needs end-to-end testing.
   No fee-reserve reduction or production rollout follows from these tests.
