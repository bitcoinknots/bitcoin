# TIDES difficulty, payout variance and capacity calibration

The v6-r2 experiment now has a reproducible coupled variance harness. It does
**not** establish that the current difficulty has the same variance as every
ordinary pool. A comparison needs a pool fraction, miner fraction, share target,
payout window, job cutoff and observation duration. Making shares easier reduces
sampling noise while increasing the evidence that every enforcing node must
obtain, validate and retain. Native block-finding luck remains.

The harness is [tides_calibration.py](../contrib/sharepool/tides_calibration.py).
Its [tests](../contrib/sharepool/test_tides_calibration.py) include independent
compact-target vectors, comparison with the native wire codec, an exhaustive
fractional-window variance oracle, matched arrival accounting, bootstrap,
rounding, correlated native finds, expiry and bounded-queue backpressure.

## Exact work and what the current setting buys

For canonical native target `T`, expected native work is exactly
`N = 2^256 / (T+1)`. The assigned share work is the largest power of two at most
`max(1, floor(N) >> shift)`. A share has target `2^256/W - 1`, giving a
threshold success probability exactly `1/W`. The negligible protocol exclusion
of a null proof ID is not modeled (one hash value out of `2^256`). Let `K=N/W`.
An eight-network-work window contains
`8*K` shares, including a fractional oldest contribution if necessary. The
integer conversion and rational boundary are kept exact in the harness.

The following is an **illustrative constant target**, `nBits=0x17034219`, not a
claim about today's network difficulty. The RSD columns are stationary
per-block **allocation sampling** RSD for three miner fractions of their own
pool. They exclude block luck and are not daily payout RSD. The exact IID-label
formula includes the fractional oldest share. Proportional clipping at a height
boundary can change its effective sample size; the formula is the
arrival-ordered, equal-work benchmark.

| Global shift | Shares per expected native block | Proof-only GiB/day | 1% miner RSD | 0.1% miner RSD | 0.01% miner RSD |
| --- | ---: | ---: | ---: | ---: | ---: |
| 10 (unchanged experimental rule) | 1,257.14 | 0.086 | 9.92% | 31.52% | 99.71% |
| 12 | 5,028.55 | 0.345 | 4.96% | 15.76% | 49.86% |
| 14 | 20,114.21 | 1.381 | 2.48% | 7.88% | 24.93% |
| 16 | 80,456.84 | 5.525 | 1.24% | 3.94% | 12.46% |
| 18 | 321,827.37 | 22.098 | 0.62% | 1.97% | 6.23% |
| 19 | 643,654.74 | 44.196 | 0.44% | 1.39% | 4.41% |

A shortest native v6 proof is exactly 512 bytes with a P2WPKH recipient, or
524 bytes with P2TR. The table includes one copy of those 512-byte proofs only.
Templates, transaction tables, certificates, snapshot framing, database indexes,
transport, replication and retries add cost. This is an archival lower bound,
not a measured sustainable rate. Native validation operations are reported as
counts, not invented milliseconds: when every proof has a different origin job,
each needs corresponding native job validation. At shift 14 the mean 20,114
proofs per block already exceeds the 2,048-new-origin budget for that workload.
Sharing transaction bytes does not remove that CPU check.

For an explicitly illustrative 5% per-block allocation sampling target, the
minimum shifts at these bits are 12, 16 and 19 for the three miner sizes above.
These are calculations, not activated profiles or recommended production
settings. No finite global share rate provides the same sampling precision for
arbitrarily small miners. A real pool can assign easier per-miner share targets;
introducing that here would need consensus-verifiable assigned work and bounded
admission costs, rather than silently changing one constant.

Pool size instead determines wall time: the expected eight-work window spans
`8*600/pool_fraction` seconds. Even an ideal pool that splits every block in
perfect hashrate proportions has one-day block-luck RSD
`1/sqrt(144*pool_fraction)`. This is 83.3% for a pool with 1% of network hashrate.
An easier share target does not create additional native blocks.

## Coupled comparison rather than independent block coins

The CPU/standard-library experiment generates the easiest reference's PoW
successes as a marked Poisson process. Each success receives an integer hash
uniformly distributed below that target. The same integer determines whether
it meets the harder v6 target and whether it is also a native pool block.
Every native find is thus a share from the same work stream. The winning proof
is added only after computing the already issued job's payout. Outside-pool
valid native blocks come from an independent process of other miners.

The primary `proportional` result models v6 rules revision 2: an oldest partially
consumed native-height batch contributes proportionally across its recipients.
The `numeric` control models historical revision 1's proof-ID boundary. Two
arrival-ordered TIDES references receive the same events and job cutoffs: one
uses the same share difficulty, and the other uses shift 14, sixteen times as
many proofs. The latter is an explicit denser regular-pool benchmark, not a
measurement of a commercial service's vardiff configuration. All use the same
eight-work window, recipient labels, block reward and exact downward rounding.

Every scenario starts with empty history, including the explicit empty-pool
bootstrap. Six scenarios cover 10%, 1% and 0.1% network pools, cooperative
cross-pool admission, a pool-only-admission negative control, slower refresh and
latency, and a deliberately saturated queue. Stable local receipt order selects
the bounded carry prefix; it is not presented as a provable global receipt
order. Admitted, expired and still-pending work must reconcile exactly.

The origin-age limit makes cross-pool relay important. A small pool that can
admit work only in its own blocks loses many proofs before its next win.
Cooperative native producers can admit other pools' verified work while leaving
the old pool and recipient intact. The harness's all-native scenario assumes
this cooperation. It cannot make a censoring producer acknowledge or include
data it refuses to receive. The bounded-queue scenario separately exposes work
that still expires after admission capacity is exhausted.

The reported totals cover **fixed wall time**, expressed as 24 expected pool
blocks, following a 16-expected-block warmup. Runs do not stop at a fixed number
of observed wins. With seed 20260913 and 32 independent runs per scenario, the
JSON records event and payout counts, standard errors, approximate mean
intervals and paired variance ratios. Variance-ratio intervals resample whole
independent runs, preserving overlapping-window covariance within each run.
The decomposition explicitly retains
`Var(total)=Var(fixed split)+Var(allocation residual)+2*Cov`; block luck is not
subtracted as though independent of the share stream.

The checked run processed 154,438,332 simulated marked-event evaluations across
the six paired scenarios. These are CPU simulations, not real proof hashes or
independent physical trials. For the 1%-network pool with cooperative admission,
1-second refresh and 0.2-second propagation/submission delays, the 32 runs found
756 blocks during their measured intervals. The v6-r2 total-reward variance
relative to the sixteen-times-denser arrival pool was:

| Miner fraction of pool | Sample variance ratio | 95% whole-run bootstrap interval |
| --- | ---: | ---: |
| 1% | 1.24 | 1.06–1.46 |
| 0.1% | 1.47 | 0.89–2.18 |
| 0.01% | 5.55 | 3.08–10.40 |

The smallest miner's higher observed variance is substantial in this model;
replacing proof-ID ordering with proportional clipping does not create more
work samples. The middle interval is too broad to establish a precise increase
for that case. The native block-luck split and paired mean differences are in
the JSON so a variance ratio is not mistaken for a payout-mean guarantee.

No otherwise eligible proof expired in the cooperative, uncongested run. With
only the pool's own producers admitting its work, 95.93% expired. With cooperative
admission limited to four proofs per native block, 68.01% expired despite FIFO
carry. This is deliberately insufficient capacity, not a proposed production
limit. Raising refresh to 30 seconds and both delays to 2 seconds reduced the
measured accepted pool wins from 756 to 734 on the same marked-event stream.
These controls show why cross-pool relay, adequate capacity and prompt template
refresh are separate requirements.

## Reproduction and limits

```sh
python3 -B -m unittest discover -s contrib/sharepool -p test_tides_calibration.py -v
python3 -B contrib/sharepool/tides_calibration.py --replicates 32 --workers 4 \
  --seed 20260913 --warmup-pool-blocks 16 --measured-pool-blocks 24 \
  --output contrib/sharepool/results/tides-v6-calibration.json
```

Worker count changes CPU concurrency, not the deterministic JSON. This is not
GPU execution, live mining or a native validation benchmark. The machine-readable
[results](../contrib/sharepool/results/tides-v6-calibration.json) keep analytical
lower bounds separate from simulated observations and confidence intervals.
All 17 focused tests passed. A short complete six-scenario run with one worker
and with two workers produced byte-identical JSON; the main run used four CPU
processes.

The model has constant target and hashrates. It does not simulate retargets,
partitions, changing miners, malicious proof withholding, real transaction
validation, archive recovery or full external-network propagation. The tracked
pool's stale dispatches are measured; outside-pool blocks are explicitly valid
tip extensions. The queue includes this pool's proof count, not competing pools'
full template and transaction usage, so the cooperative scenario is an
uncontended-load comparison. Network-wide traffic bounds identify capacity that
this simulation cannot establish. Statistical intervals do not guarantee an
economic tolerance for every workload or adversary.

The calibration gap is now measurable rather than an unsupported equivalence
claim. Production target selection still needs an explicit supported miner size
and variance tolerance, native full-template throughput measurements at that
load, and an admission/availability design that can sustain it. The experimental
shift stays at 10; this report does not authorize or activate a different native
difficulty or mainnet deployment.
