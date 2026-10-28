# TRUC sibling next-block experiment: deeper testing

This report records the original draft at `f1fa0d3605`. The separate research
branch changes projection performance; see [research results](truc-sibling-research.md).
The original work-budget failure below is retained as historical evidence.

## Assessment

The exception removes the absolute-fee barrier in the tested **different-output
v3 sibling** case. It is not a general solution to BIP125 Rule 3 pinning, and the
current draft is not ready for production. Shared-anchor conflicts are excluded,
the projection can disagree with the default miner, and its work limit can make
the exception unavailable in a moderately populated mempool.

These are regtest policy and transaction-topology fixtures. They do not establish
successful recovery of a real CLN/LND channel, HTLC, or signed production VTXO.
No production services or funds were used.

## Reproduction

Build this branch, then run the functional runner with:

```
mempool_truc_nextblock.py
mempool_truc_nextblock.py --rdts
mempool_truc_nextblock.py --rdts --stress
mempool_truc_nextblock.py --rdts --mixed
```

Regression coverage: `mempool_truc.py`, `mempool_package_rbf.py`,
`mempool_package_limits.py`, `feature_rbf.py`, and the four `rbf_tests` unit cases.
The isolated Linux container used four CPUs and a 6-GiB memory limit. Logged
timings are observations, not performance guarantees or a denial-of-service proof.

All four listed variants passed (41, 11, 53, and 4 seconds respectively in the
final two-job run). All four regression scripts and all four RBF unit cases also
passed. A passing negative test means the documented limitation was reproduced,
not that the limitation was fixed.

## Results and implications

| Scenario | Observed behavior | Implication |
| --- | --- | --- |
| 10,000-sat old child; smaller 5,000-sat sibling; congested fee-only block | Disabled: rejected. Enabled: accepted and old child evicted | Demonstrates relief from the absolute-fee barrier in scope |
| Same case with zero-fee parent | Accepted | Parent need not prepay its fee for this topology |
| Empty mempool or already-selected parent/package | Exception rejected | The next-block condition is material |
| Higher child rate but package still below boundary | Rejected | Standalone child rate is insufficient |
| Direct conflict on an actual shared P2A output, with separate confirmed fee inputs | Lower-fee, higher-feerate replacement rejected | Shared anchors remain exposed to the absolute-fee barrier |
| v2 parent and children | Different-output children coexist; lower-absolute-fee direct replacement rejected | Existing v2 Lightning-style behavior is unchanged |
| Ten distinct invalid-witness transactions | Rejected; mempool unchanged | Passing the fee gate does not bypass script validation |
| Three-level unconfirmed v3 recovery tree | Grandchild rejected | TRUC's ancestor restriction remains |
| Serialized recovery with one-block relative lock | Rejected before required confirmation; accepted afterward | Fee exception does not bypass relative locktime |
| Additional shrinking at fixed congestion | Rejected once parent/package is selected | No immediate repeat in this fixture |
| Congestion rises from about 15 to 30 sat/vB | Second shrinking exception on the same parent accepted | Not a lifetime one-use mechanism |
| 1,500 additional high-rate independent competitors | Work budget exhausted at 1,755 total entries; candidate rejected | Fail-closed resource protection also limits useful availability |
| Enabled and disabled nodes connected over P2P | Enabled node accepts/relays; disabled peer rejects and retains old child | Deployment requires compatible relay/mining paths |
| Block containing the replacement, then disconnect/reconsider | Both policies accept the block and recover the same tip | Tested policy disagreement does not create a consensus split |

After the common parent confirms, the disabled peer can retain the old child:
different-output siblings are not consensus double spends. Policy eviction does
not invalidate the old transaction or guarantee it can never subsequently mine.

The work-budget case checks the explicit debug diagnostic, not merely a generic
fee rejection. An observed rejection took about 0.13 seconds; repeated requests,
large ancestor graphs, script verification, concurrent RPCs, and slower machines
still require adversarial profiling. The 10,000-entry ceiling is not a guarantee
that the selector can process every smaller mempool.

### Miner comparison

Under default mining settings, the old child was present in the actual block
template despite being excluded by the experiment's fee-only projection.
Knots has priority selection and different mining limits; the projection is not
an exact model of those choices.

With priority space disabled and the mining weight/size configured to match the
fee-only capacity, the old child was excluded, the replacement was included, and
template transaction fees increased by **2,320 sats** in the fixture, for both
normal and RDTS runs. That single favorable example is not a general proof of
miner revenue improvement.

### Repetition and the child cap

In the moving-congestion test an 8,000-sat, four-output child first replaces a
10,000-sat child. A smaller 7,000-sat child is initially refused; after competing
fees rise, it becomes eligible and replaces the 8,000-sat child. Both exceptions
apply to the same parent. The 1,000-vB cap and strict shrinking bound this particular
sequence, but do not bound total traffic across ordinary replacements, changing
congestion, and multiple parents. No cumulative anti-churn claim is established.

## What this means for L2 implementations

- **Two distinct v3 anchors:** a candidate may benefit if all the narrow eligibility
  conditions hold. The test uses actual transactions but simplified spending
  scripts, not channel commitments with negotiated keys and HTLCs.
- **Shared P2A anchor:** two fee bumpers spend the same outpoint. They are direct
  conflicts, not the policy-only siblings this draft permits. The negative fixture
  spends an actual P2A output and demonstrates that exclusion.
- **Legacy v2 Lightning:** the exception does not apply. Merely enabling the node
  option does not upgrade a channel's negotiated transaction format.
- **Ark v3 exit trees:** a shared fee anchor remains outside this exception, and
  deeper recovery must still obey the unconfirmed ancestor limit. Sequential
  confirmation and relative delays were tested; full signed exit recovery was not.
- **Funded v2 Ark recovery:** unchanged by this v3-only exception. This PR alone
  does not justify removing recovery funding or reducing reserves.

Format references: [BIP431](https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki)
and [BOLT3](https://github.com/lightning/bolts/blob/master/03-transactions.md).
The inspected CLN checkout (`57366b39d5482a35c806327ba6a965c103d66fca`) asserts
version 2 in `channeld/commit_tx.c`. The inspected Ark implementation
(`6d301e8bfd4b5c6d7be273a4e58e32527f0fe5a1`) distinguishes v3/P2A and funded
v2/P2WSH formats in `bitcoin-ext/src/fee.rs`. These are source observations,
not assertions about every deployed channel or wallet.

## Recommended follow-up before broadening the exception

1. Agree on the precise next-block/miner-incentive condition; the default-miner
   mismatch must be addressed or explicitly accepted as part of the policy model.
2. Replace or optimize the reference selector and measure worst-case lock/CPU
   costs without silently changing its decisions. Test availability under realistic
   congestion, not only the 10,000-entry hard ceiling.
3. Ask whether single-parent, single-child **direct shared-anchor conflicts** are
   acceptable scope for a separate extension. Do not silently enable general RBF.
4. Exercise signed CLN/LND and Ark recovery fixtures, fee-budget exhaustion,
   deadlines, competing HTLC paths, low/high-fee oscillation, and miner diversity.
5. Keep the experiment off by default. Passing these tests is evidence of its
   boundaries, not approval to deploy it or a proof that pinning has been solved.
