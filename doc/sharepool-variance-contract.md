# Variance and capacity service contract candidates

This is an engineering decision aid for the separate-pool, eight-work TIDES
profile. It does not activate a difficulty, promise payment from a pool that
stops finding blocks, or establish mainnet readiness. The older
[SHIFT10 calibration](sharepool-tides-calibration.md) remains a historical result.

A concrete proposed statistical target is at most **10% additional variance in
cumulative miner rewards**, with paired mean reward differences within **2% of
expected rewards**, over a fixed duration of 24 expected pool blocks after a
16-expected-block warmup. Tests consider pools with 10%, 1% and 0.1% of network
hashrate, and miners with 1%, 0.1% and 0.01% of their pool. Those are service
claims to test; smaller participants remain free to mine. They are not identity,
registration or permission requirements.

A 24-expected-block observation lasts about 1.67, 16.67 and 166.67 days for those
three pools. Equal block-luck variance in normalized rewards does not imply
equal earnings per day. Direct coinbase payouts necessarily retain the pool's
block-finding luck.

## Reference and model

The new [harness](../contrib/sharepool/tides_service_contract.py) reuses the
marked Poisson event generator and exact target-to-work conversion from the
historical harness. An integer hash mark determines whether the same success
is a share and a native block. A winning proof enters subsequent work; it
cannot change its own already issued payout snapshot. The primary payout is
v6-r2 proportional clipping of the oldest native-height cohort. The historical
numeric ordering remains a negative control. Three tracked recipient fractions
and one aggregate remainder are statistical labels; they do not measure the
coinbase size or native cost of a thousand distinct payout recipients.

Two comparisons answer different questions:

* An arrival-ordered TIDES reference at SHIFT14 has an explicit finite share
  density. SHIFT10/12/14 use the same events, hash marks, miner labels and issued
  job cutoffs for each pool fraction and seed. Matching this reference does not
  mean matching every commercial pool's difficulty.
* A fixed hashrate split on the same actual pool blocks is the infinitely dense
  TIDES limit for stationary hashrate fractions and complete work reception.
  This is the stronger comparison for sampling variance. It is not FPPS and
  does not remove block luck or model a changing population.

The main sweep deliberately gives each modeled pool an uncongested proof-count
budget. It isolates payout policy and share difficulty. All native producers
cooperate in admitting verified work; refresh is one second and propagation
and submission delays are 0.2 seconds each. Competing pools' transaction loads
are assessed separately by explicit resource predicates. Two additional
single-pool cases represent all network hashrate and apply a global budget of
134 new 4,000,000-byte origins per block, based only on the expanded-body
limit. This is optimistic: completely disjoint transaction bodies hit the wire
limit sooner. These controls expose overload and age expiry; they are not sustainable production recommendations.

Each run has its own event trace. Confidence intervals resample complete runs,
including all overlapping rolling windows within a run. The report keeps the
block-luck, allocation residual and covariance terms, and tests upper confidence
bounds rather than accepting a favorable point estimate. Source-level oracle
tests compare every payout of short traces with the original straightforward
implementation, including fractional clipping, floor-after-aggregation and
replacement of a cached history prefix.

## Recorded labeled sweep

The [recorded results](../contrib/sharepool/results/tides-v6-service-contract.json)
contain 128 runs for each of eleven cases, seed 20260919. The run evaluated
1,132,720,900 marked events on four CPU workers in 1,247.94 seconds wall time.
Those are simulated event evaluations, including paired traces reused across
cases; they are not mined hashes or independent physical trials.

For the 1%-network pool, 3,066 blocks fell in the measured intervals. The
proportional payout variance ratios to the ideal dense split were:

| Miner fraction of pool | SHIFT10 ratio (95% CI) | SHIFT12 ratio (95% CI) | SHIFT14 ratio (95% CI) |
| --- | ---: | ---: | ---: |
| 1% | 1.130 (0.974–1.283) | 1.008 (0.951–1.062) | 0.999 (0.960–1.035) |
| 0.1% | 1.813 (1.368–2.430) | 1.239 (1.095–1.422) | 1.127 (1.013–1.256) |
| 0.01% | 10.184 (7.352–14.369) | 3.281 (2.524–4.424) | 1.714 (1.401–2.129) |

SHIFT14 tracks the finite SHIFT14 arrival reference closely: its variance ratios
are between 0.999 and 1.001 across the three miner sizes in this pool. The ideal
reference exposes the remaining finite-sampling cost. The 0.1% miner's raw
interval is too broad to certify the proposed 1.10 variance target, while the
0.01% miner clearly fails it. A point ratio below one is finite-sample variation,
not evidence that sampling eliminates native block luck. All cases and paired
mean intervals remain available in the JSON.

No otherwise eligible proof expired in the nine uncongested cases. In the global
134-origin full-body controls, only 2.67% of eligible SHIFT12 proofs and 0.67%
of SHIFT14 proofs were admitted. Respectively 85.20% and 87.16% expired by the
end of the run, while another 12.12% and 12.17% remained pending. Pending work is
not counted as expired, admitted or guaranteed eventual payment. These counts
include warmup and reconcile exactly; they expose a resource failure even
though the uncongested statistical comparison looks promising.

## Conditional check of the sampling variance

The [conditional estimator](../contrib/sharepool/tides_conditional_variance.py)
provides a second calculation with less noise from accidentally lucky recipient
labels. For one fixed PoW/admission trace, let `c_j` be proof `j`'s total payout
coefficient summed across all observed pool wins. Its appearances in overlapping
windows remain part of that sum. Let `B` be the observed pool block count and
`a` the miner's constant pool fraction. Before integer rounding:

```
E[payout / reward | trace] = a * B
Var(payout / reward | trace) = a * (1-a) * sum_j(c_j^2)
Var(payout / reward) = a^2 * Var(B) + a * (1-a) * E[sum_j(c_j^2)]
```

The formula is exact when recipient labels are independent draws conditional on
the pool's work and block trajectory, and difficulty, cutoff, latency, refresh
and admission do not depend on the recipient; the modeled block reward and
native difficulty are constant. The implementation numerically
accumulates cohort coefficients; exhaustive rational label enumeration checks
the result, including proofs reused in several payouts. This estimator does
not apply to recipient-dependent job construction or variable difficulty.

Conditional allocation error has zero mean, so its covariance with block luck
is zero under these assumptions. The labeled Monte Carlo still reports its
finite-sample covariance; a chance negative or positive covariance is not a
protocol improvement or failure. Whole-trace bootstrap intervals account for
uncertainty in both block counts and the conditional allocation term.

The conditional calculation refuses measured empty-history bootstrap instead
of treating it as an ordinary proportional window. Satoshi rounding is separate:
a recipient loses less than one satoshi per paid block from flooring, relative
to the unrounded amount. Seeds pair with a subset of the labeled sweep, so these
are two analyses of shared traces, not independent replications to add together.

## Statistical decision at the tested target

The [conditional results](../contrib/sharepool/results/tides-v6-conditional-variance.json)
use 64 independent traces per case, paired with the first half of the labeled
sweep. They required 308,957,452 additional CPU event evaluations and 328.31
seconds wall time on four workers. For a miner with **0.1% of its pool**, the
unrounded cumulative reward variance ratios to the ideal dense split are:

| Pool fraction of network | SHIFT12 ratio (95% CI) | SHIFT14 ratio (95% CI) |
| --- | ---: | ---: |
| 10% | 1.205 (1.138–1.347) | 1.051 (1.035–1.087) |
| 1% | 1.235 (1.170–1.354) | 1.059 (1.042–1.088) |
| 0.1% | 1.216 (1.171–1.301) | 1.054 (1.043–1.075) |

All three SHIFT14 upper intervals are below the proposed 1.10 criterion; every
SHIFT12 lower interval exceeds it. SHIFT12 does support the tested **1%-of-pool**
miner, with upper intervals below 1.036. Neither shift supports the tested
**0.01%-of-pool** miner: SHIFT14 ratios are approximately 1.51–1.59, with every
lower interval above 1.34. This excludes the smallest tested recipient from the
candidate statistical envelope; it does not exclude that recipient from mining.

The proposed mean criterion is checked separately. For the 0.1%-of-pool miner,
SHIFT14's raw 128-run paired mean intervals, **including integer payouts**, are
[-0.38%, +1.30%], [-0.18%, +1.50%] and [-0.31%, +1.21%] of expected rewards.
All lie within the proposed ±2% range; the 1%-of-pool miner passes too. The
conditional model also has zero expected allocation error before rounding.
Since expected accepted wins cannot exceed the 24 expected PoW finds, the
expected normalized rounding loss is at most `1/(reward*a)`, or 0.0000032 for
`a=0.001` with the configured reward. The maximum per-observed-trace bound is
0.00000574. These mean-loss bounds are separate from an exact post-rounding
conditional variance calculation; the reported variance intervals are unrounded.

**Recommendation:** retain SHIFT14 as the statistical candidate for the tested
0.1% and larger pool recipients, and keep the current native target unchanged
until resource capacity supports it. This is a proposed engineering envelope at
constant `0x17034219`, fixed rewards and the three tested pool fractions. It is
not a proof across every target-rounding position, retarget, changing miner
population or recipient-dependent job policy. Each interval is reported at its
individual 95% level, without a simultaneous confidence claim across all cases.
The complete production contract does **not** pass: the native capacity
conditions below still fail. No difficulty is activated by these results.

## Capacity is a separate acceptance condition

At the illustrative constant native target `0x17034219`, SHIFT10/12/14 generate
about 1,257 / 5,029 / 20,114 shares per expected native block, or 2.10 / 8.38 /
33.52 shares per second across the network. One P2WPKH proof occupies 512 bytes
before its template, transactions, certificates, transport or indexes. The
proof-only archival lower bounds are 0.086 / 0.345 / 1.381 GiB per day, per
unique network stream; replication multiplies transfer/storage.

Power-of-two assignment makes density vary as native difficulty changes. Away
from the easy-target clamp, SHIFT14 means `16,384 <= K < 32,768`, not a fixed
20,114 proofs per native block. The JSON also evaluates the conservative upper
mean-load bound for each shift; the illustrative target cannot define a
permanent capacity promise.

The current native limits are independently binding: 2,048 origins, 512 MiB of
expanded template bodies, two million transaction references and a 16 MiB
snapshot. The JSON tests each limit for declared transaction-set reuse and
proofs-per-origin assumptions. Both rounded mean load and the geometric 99th
percentile of proofs through the next native find are reported. Random block
intervals make that percentile roughly 4.6 times mean demand. It is not a
fixed-ten-minute Poisson quantile.

Shared transaction-table encoding reduces wire bytes. It does not remove each
origin's expanded-body or transaction-reference charge. At 4,000,000 bytes per
origin the expanded limit allows only **134 origins**, even if all non-coinbase
transactions are shared. At SHIFT14, sixteen proofs per origin still require
roughly five gigabytes of expanded bodies at mean load. Raising only the origin
count or making only the share target easier cannot support that workload.

Wire predicates are deliberately lower bounds: they include proofs, origin
headers, transaction bodies and at least one byte for each CompactSize table
index and transaction length. They omit certificates, payout/state metadata and
some framing. A failed predicate rules out the declared workload; a passed
predicate is **not** evidence that it will fit or validate quickly. The JSON
always marks these bounds insufficient for native admission. Fully different
transaction sets are reported separately from shared non-coinbase sets.

Native transaction validation rates, startup scan time and disk/fsync latency
must be measured independently. CPU model runtime is never a native capacity
measurement. Safe activation needs statistical support **and** a sustainable
resource envelope with headroom and bounded backlog/expiry under the same job
churn. An uncongested variance result alone cannot authorize a target change.

## Global targets and signed per-job difficulty

A global target is simple to authenticate and makes every accepted proof carry
the same expected work at a given native target. Easier targets improve small
miners' sampling while imposing the resulting traffic on every enforcing node.
The sweep compares SHIFT12 and SHIFT14 rather than assuming the easiest target
is affordable.

Per-job variable difficulty can make an individual miner's sampling cadence
more uniform. The official [Stratum V2 mining protocol](https://stratumprotocol.org/specification/05-mining-protocol/)
allows a server to control share submission rate by channel target and preserves
the target of already active jobs. It does not specify a universal commercial
share cadence. [DATUM's upstream gateway](https://github.com/OCEAN-xyz/datum_gateway)
also requires pooled work to carry and meet the target. Neither behavior by
itself defines a consensus-verifiable global resource contract.

A defensible extension would require the assigned target to be committed in the
actual hashed job **before** mining, and covered by the exact-job signature.
For each proof, credit must equal the inverse success probability for that
assigned target. The current power-of-two converter makes this integer exact.
A proof cannot choose a more profitable target after its hash is known, and a
signature alone is insufficient if its target can be changed without changing
the hashed job. Pool, recipient and assigned work remain fixed after admission.
A miner who changes targets prospectively still needs the correct weighted
TIDES boundary and a maximum individual proof weight relative to the window.

Variable difficulty also needs a consensus minimum work per proof and a global
resource service policy. Per-address limits do not bound permissionless global
load. An arbitrarily large population can request arbitrarily small proof
weights; local identity labels cannot fund that validation. Consequently
per-job difficulty is a protocol design alternative, not a completed fix or a
reason to claim universal variance parity.

## Reproduction

```sh
python3 -B -m unittest discover -s contrib/sharepool -p test_tides_service_contract.py -v
python3 -B contrib/sharepool/tides_service_contract.py --replicas 128 --workers 4 \
  --seed 20260919 --warmup-pool-blocks 16 --measured-pool-blocks 24 \
  --output contrib/sharepool/results/tides-v6-service-contract.json
python3 -B -m unittest discover -s contrib/sharepool -p test_tides_conditional_variance.py -v
python3 -B contrib/sharepool/tides_conditional_variance.py --replicas 64 --workers 4 \
  --seed 20260919 --output contrib/sharepool/results/tides-v6-conditional-variance.json
```

The report retains every run's payouts and event counters, configured seed,
horizon, pool fraction, assigned work, bootstrap intervals and resource
assumptions. The calculations use standard-library CPU processes, not GPU
mining. They do not model changing hashrates, retargets, variable transaction fees, malicious withholding,
real transaction validation, slow disks or WAN partitions. Cooperative relay
cannot compel a producer to receive or include work it censors.
