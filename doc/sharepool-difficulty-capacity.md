# Share difficulty: sampling and capacity bounds

The experimental v4 shift of 10 has **not been calibrated for production**. This
analysis quantifies its sampling limits and the cost of two easier share targets.
It changes neither consensus parameters nor public-network activation.

For pool fraction `f`, target shift `s`, and a fixed observation duration of
`600 × b` seconds, the model is:

```
expected proofs λ = f × 2^s × b
P(no proofs)       = exp(-λ)
relative std. dev. = 1 / sqrt(λ)
proofs per second = f × 2^s / 600
```

These are exact statistics of the stated Poisson model. The model assumes
independent uniform hash trials, constant hashrates and target, complete proof
delivery, and an unclamped share target. The exact target-probability ratio is
`(share_target + 1) / (native_target + 1)`; `2^s` neglects integer rounding.
Easy regtest targets can hit the target ceiling, so low-difficulty regtest share
counts do not establish production capacity. A “block interval” below means
600 fixed seconds, not the random time taken to observe an actual block. Stopping
on a winning block and conditioning on its discovery changes the distribution.

## Minimum resource cost

The current proof encoding is at least **512 bytes**: a 164-byte native header,
a 284-byte envelope with the shortest accepted payout script, and a 64-byte
signature. A 34-byte payout script makes it 524 bytes. The envelope still carries
the three reserved 32-byte fields; they are included in this count.

| Target shift | Whole-network proofs / 600 s | Proofs / s | Minimum proof bytes / interval | Minimum unique-proof archive / day |
|---|---:|---:|---:|---:|
| 10, current experimental | 1,024 | 1.707 | 0.5 MiB | 72 MiB |
| 14, comparison only | 16,384 | 27.307 | 8 MiB | 1.125 GiB |
| 18, comparison only | 262,144 | 436.907 | 128 MiB | 18 GiB |

These are expected lower bounds for a node collecting the entire network's
proofs once. Multiply by `f` for an isolated pool's proofs. They exclude full
templates, transaction references, payout and spent-proof state, signatures
outside individual proofs, snapshot framing, relay fanout, retransmission,
repeated publication, indexes, backups and archive records. They measure neither
CPU validation cost nor latency. Transaction deduplication does not reduce these
individual proof bytes.

A 16 MiB snapshot could fit at most 32,768 such proofs **before any other fields**;
the actual bound is lower. At shift 18, even one expected network interval's
proofs alone is eight times that byte budget. Increasing the target shift must
therefore be evaluated together with settlement batching, arrival and service
rates, and state retention. Deterministic carry-forward preserves acknowledged
work but cannot drain a queue whose sustained arrival rate exceeds service.

## Small-pool sampling

For a pool contributing **0.01%** of network hashrate:

| Shift | Observation time | Expected proofs | Probability of no proofs | Relative standard deviation |
|---|---|---:|---:|---:|
| 10 | 10 minutes | 0.1024 | 90.27% | 312.50% |
| 10 | 1 hour | 0.6144 | 54.10% | 127.58% |
| 10 | 1 day | 14.7456 | 0.0000395% | 26.04% |
| 14 | 10 minutes | 1.6384 | 19.43% | 78.13% |
| 14 | 1 hour | 9.8304 | 0.00538% | 31.89% |
| 14 | 1 day | 235.9296 | < 10^-100% | 6.51% |
| 18 | 10 minutes | 26.2144 | 4.12 × 10^-10% | 19.53% |
| 18 | 1 hour | 157.2864 | < 10^-60% | 7.97% |
| 18 | 1 day | 3,774.8736 | < 10^-1000% | 1.63% |

Relative standard deviation concerns proof-count sampling around its expected
value; it is not a confidence bound, a guaranteed payout error, or a direct
measurement of physical hashrate. A zero-proof interval does not prove idleness,
and an unusually high count does not prove that a miner exceeded a physical
hashrate limit. Nothing here detects undisclosed work.

The complete JSON includes pool fractions 100%, 10%, 1%, 0.1%, and 0.01% for
1, 6, and 144 nominal intervals at all three shifts. Log probabilities are kept
when floating-point `exp(-λ)` underflows to zero; numeric zero is not an assertion
that the event is impossible.

## The remaining production decision

Choose a supported pool-size floor, observation/settlement horizon, sampling
error objective, and resource/latency budget before selecting a production
target. Permissionless membership does not require a guaranteed sampling error
for an arbitrarily small participant: with finite proof throughput and time,
`f → 0` implies `λ → 0`, so the probability of observing no proof approaches one.

For illustration only, requiring at most 5% relative standard deviation and at
most 1% zero-proof probability needs `λ ≥ max(400, -ln(0.01)) = 400`.
For a 0.01% pool this would require an idealized shift of at least 22 over
10 minutes, or 15 over a day. The corresponding whole-network proof-only
archive lower bounds are **288 GiB/day** and **2.25 GiB/day**. These are examples
of the tradeoff, not adopted requirements or a recommended target.

## Reproduce

From the repository root, using only the Python standard library:

```sh
python3 -B contrib/sharepool/share_difficulty_capacity.py --output contrib/sharepool/results/share-difficulty-capacity-v4.json
python3 -B -m unittest discover -s contrib/sharepool -p test_share_difficulty_capacity.py -v
```

Source: [analytical script](../contrib/sharepool/share_difficulty_capacity.py),
[45-case JSON](../contrib/sharepool/results/share-difficulty-capacity-v4.json),
[seven regression checks](../contrib/sharepool/test_share_difficulty_capacity.py).
No native node, ASIC, GPU, or public network is exercised by this analysis.

## Matching an ordinary pool's payout variance

“Same variance” needs a payout contract. A relevant direct-coinbase baseline is
OCEAN's TIDES: it weights an ordered rolling history covering eight network
difficulty units of pool work. A proof can participate in multiple block rewards;
the history is not cleared after a win. Its cutoff follows the work issued to
the winning miner. [OCEAN's TIDES specification](https://ocean.xyz/docs/tides).

PPS/FPPS instead credits accepted work independently of the pool's actual block
finds, with the operator absorbing block luck. FPPS also accounts for transaction
fees. That funding obligation differs from paying only rewards actually found
through coinbase. [Luxor's FPPS documentation](https://docs.luxor.tech/platform/mining/revenue-payments).

Three quantities must remain separate: observed proof-count noise, allocation
noise **for an individual miner**, and the pool's block luck. Let `a` be the
miner's fraction of the settlement domain's hashrate, and `q` that domain's
fraction of network hashrate. For `N` equal-work proofs selected without bias
toward a miner, independent owner labels give:

```
X ~ Binomial(N, a)
payout fraction F = X/N
E[F] = a
Var(F) = a(1-a)/N
relative allocation standard deviation = sqrt((1-a)/(aN))
```

This is an exact **conditional single-payout** comparison. Different valid
templates do not themselves change it: the same owner/work distribution and
window produce the same allocation law. The present v4 does not yet implement
the same payout window as the baseline.

| Miner's share of pool | N = 64 | N = 1,024 | N = 8,192 |
|---|---:|---:|---:|
| 10% | 37.50% | 9.38% | 3.31% |
| 1% | 124.37% | 31.09% | 10.99% |
| 0.01% | 1,249.94% | 312.48% | 110.48% |

Entries are relative allocation standard deviations, not measured payout
volatility. All counts are illustrative. At the same unclamped shift 10, an
eight-work-unit window contains 8,192 equal-work proofs. Its expected fill time
is `8 × 600/q` seconds: about 5.56 days at `q = 1%`. Easier per-miner share targets
can supply more samples; similar total pool hashrate alone does not match
individual allocation noise. Unequal proof weights require their weighted
distribution, not just a submission count.

Successive rolling payouts also share evidence. For equal-size windows with
`O` common proofs, `Cov(F_i,F_j) = a(1-a)O/N²`. The new calculator includes that
covariance instead of treating payouts as independent. With a 1% miner, eight
8,192-proof windows advancing by 1,024 proofs have 9.01% conditional standard
deviation for their total; eight disjoint windows of that same size give 3.89%.
These examples hold the number of rewards and window positions fixed. Actual
block-discovery timing and job cutoffs must also be modeled before reporting
wall-time payout variance.

As a separate benchmark, with `B ~ Poisson(qT/600)` and a perfect constant split,
the miner receives `aRB`; its relative block-luck standard deviation is
`1/sqrt(qT/600)`. Under an ideal fixed PPS rate `R/2^s`, credit-count sampling has
relative standard deviation `1/sqrt(aq2^sT/600)`. For a 1% miner in a 1% domain
over one day at shift 10, these are 83.33% and 26.04%, respectively. They are
separate model benchmarks, **not terms to add into a payout forecast**. Real
block successes are a subset of proof successes; their dependence, overlapping
windows, reward changes, startup, and job freezes cannot be discarded.

### Why the current age/payment rules differ

Current v4 requires a selected proof's pool ID to match the block's settlement
domain, credits each proof once, and limits origin age to three native heights.
Already admitted work from height `j` can optimistically enter heights `j`
through `j+3`: four opportunities. A winning proof cannot enter its own frozen
block, leaving at most three subsequent heights. If only fraction `q` of network
hashrate mines blocks settling that domain, the optimistic probability of a
matching block is `1-(1-q)^4`, or `1-(1-q)^3` for that winning proof. At `q = 1%`,
these are **3.94% and 2.97%**. Another organization's miners can increase `q` if
they actually mine that same settlement domain. These bounds assume immediate
availability and inclusion; queue limits and job cutoffs can reduce eligibility.
Durable carry-forward retains the receipt but does not extend these consensus
rules or guarantee eventual payment. The user's requested carry-forward policy
therefore still needs compatible settlement eligibility.

Empty batches matter too: current `CalculatePayouts` sends an empty selected
proof set's reward to the snapshot owner. The binomial comparisons condition on
`N > 0` and cannot establish an unbiased unconditional payout. For an independent
fixed 2,400-second proxy window, `P(N=0)=exp(-4q2^10)`; at `q=0.01%` that is about
66.39%. If the fallback owner's indicator is `o`, the proxy's mean fraction is
`a(1-P0)+oP0`, rather than necessarily `a`. This proxy is **not the actual stopped
v4 batch distribution**: previous settlements, age boundaries, winning-proof
exclusion, and commitment cutoffs change it. The JSON preserves zero cases
instead of dropping them when comparing means.

To match a direct-coinbase rolling pool, define an authenticated ordered work
window, allow its proofs to participate in distinct block rewards, and protect
against duplicate submissions separately from legitimate window reuse. Replace
the short payment expiry with window eligibility that preserves acknowledged
deferred work. Specify difficulty changes, cutoff ordering, reorg behavior,
and zero/minimum-payout handling. Then compare actual miner payout distributions
on the same coupled share/block traces, matching aggregate hashrate, proof
difficulty, weights, payout horizon, and membership history. No production target
or runtime change is selected by this analysis.

Reproduce the comparison and its nine tests, including exhaustive small-window
checks of the covariance formula:

```sh
python3 -B contrib/sharepool/payout_variance_comparison.py --output contrib/sharepool/results/payout-variance-comparison-v4.json
python3 -B -m unittest discover -s contrib/sharepool -p test_payout_variance_comparison.py -v
```

Artifacts: [calculator](../contrib/sharepool/payout_variance_comparison.py),
[conditional cases and bounds](../contrib/sharepool/results/payout-variance-comparison-v4.json),
[regression checks](../contrib/sharepool/test_payout_variance_comparison.py).
