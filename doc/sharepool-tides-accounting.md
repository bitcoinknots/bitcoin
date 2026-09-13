# Separate pools and the v6 TIDES-style native experiment

Version 6 is a fresh, opt-in **regtest-only** profile. It connects rolling payout
accounting to native block validation, job construction, external signing and the
mining gate. It does not activate these rules on mainnet or public testnets and
does not convert v5 pending credits. The current v6 rules revision is **2**;
revision 1 chains require their original binary and cannot reopen under these rules.

## Recipients and separate pools

A payout script is a destination, not an exclusive identity. A miner can choose
a recipient without proving possession of its spending key. The job signer
attests the exact job and payout destination; its key need not be the recipient's
key. There is no global ownership registration or pool-membership lock.

Pool A's blocks reward recorded work for A. The same recipient can earn in B,
but an old proof keeps its original pool and payout script. Leaving a pool does
not erase or transfer its old work. That work can earn again while eligible if
its original pool finds more blocks. This does not promise payment from an
abandoned pool, identify operators, or enforce exclusive affiliation.

## Window and native amounts

The reference is [OCEAN's TIDES specification](https://ocean.xyz/docs/tides),
checked on 2026-09-13. V6 adopts its rolling work window, job-issuance cutoff,
per-recipient aggregation and downward satoshi rounding. Its consensus admission
ordering and bootstrap are explicit extensions; it is not a claim of identical
pool behavior or measured payout variance.

For a canonical native target T, the window contains exactly
`8 * 2^256 / (T + 1)` expected hashes. V6 assigns each share a positive
power-of-two work weight W and verifies a share target of `2^256 / W - 1`.
The threshold probability is exactly `1/W` (the protocol additionally excludes
the single null proof ID); an unusually low submitted hash
never increases credit. W is the largest power of two at most
`max(1, floor(2^256 / (T + 1)) >> 10)`. This experimental setting implies roughly
1,024–2,048 shares per native block at unclamped difficulty. The
[coupled calibration](sharepool-tides-calibration.md) now measures its payout
variance against explicit arrival-ordered references. It finds a substantial
gap for small miners against denser sampling; shift 10 remains experimental.

The native calculation keeps the network-work boundary rational, clips only the
oldest eligible **native-height batch proportionally by verified work**,
aggregates full and fractional contributions for each script, then floors each amount
using the full native subsidy plus actual transaction fees. Rounding residue is
unclaimed. It is neither reassigned nor carried as a satoshi balance. Repeated
blocks can reward the same proof. A later difficulty increase can bring older
work back into the window, so old admissions must remain retrievable.

Only when the complete relevant history and current job contain no work for
the winning pool does
the bootstrap pay the job's recipient. Missing history never triggers bootstrap.
An all-zero payout calculation is allowed; the native coinbase still has its
required transaction shape and witness commitment. There is no operator fee,
custodial balance or minimum-payout carry in this profile.

## Frozen jobs and canonical admission

The actual native parent fixes the historical branch. A job extends that branch
with its own valid admission batch before calculating payouts. Its exact signed
body commits the resulting recipients and amounts. Later receipts require a new
job and a new snapshot hash; they cannot modify the job already being hashed.
A winning proof cannot insert itself into the job it solved.

Native admission height gives an objective batch boundary. In revision 2, all
work admitted in the same native block shares the oldest window boundary in
proportion to its verified work. Numeric proof IDs remain canonical encoding
order; changing those IDs or their order cannot change payouts for a fixed
admitted set. The history index retrieves the complete boundary batch before
calculating amounts. Wide intermediates preserve exact arithmetic even across
difficulty changes.

This differs from OCEAN's reception-ordered TIDES: nodes cannot prove a single
global arrival order. The gate carries older origins first, then previously
acknowledged receipts in durable local order. V6 gates can import and admit
verified foreign-pool work without relabeling it or paying it from the wrong
pool. Bounded recent and archival inventory feeds support this exchange.
Producer omission, withholding across admission heights and insufficient service
capacity remain possible. See the [admission audit](sharepool-admission-fairness.md).

A locally durable ACK is provisional. Once a block admits a proof, its original
pool/script position persists in branch history and can earn repeatedly. A proof
not admitted before the existing origin-age limit can still expire unpaid.
Deterministic queue carry preserves evidence; it cannot compel a producer to
include an undisclosed receipt or guarantee service under unlimited arrivals.

## Flat commitment, historical retrieval and forks

The block's `m_mm_rhs` contains only a domain-separated hash of its complete
canonical snapshot. Full template bodies and shares are exchanged outside the
block using the existing peer connections. The settlement is not a Merkle root.
The snapshot also contains a cumulative history hash binding the parent history
and this block's admissions; it does not replace or duplicate the complete log.

The history index walks the candidate's actual native ancestry and authenticates
each required snapshot. Cached cursors retain hashes/heights, not block-index
pointers across calls. Missing bytes and exhausted local resource budgets remain
pending, never consensus-invalid or an invented empty window. Bounded scans can
resume across retries. Derived caches are disposable; durable native snapshot
evidence remains the source for restart, reindex and competing forks.

Locally valid signatures or cached inactive-branch deltas do not activate a
branch. Native validation must accept every ancestor before that branch becomes
active. Nodes given the same valid history derive the same payouts; nodes with
missing evidence wait. Nodes enforcing different consensus rules can fork.

## Profile isolation and operation

Use a fresh datadir and blocks directory, for example:

```sh
bitcoind -regtest -sharepoolheight=1 -testactivationheight=blake2b@1 \
  -sharepoolhashonly=1 -sharepooltides=1
```

An fsynced profile marker pins the genesis, rules, SharePool/Blake2b activation
heights, Blake2b headline and blocks path before block-index initialization. A
v6 datadir cannot silently reopen as
v4/v5/plain regtest or with a changed schedule, including through reindex. The
v4/v5 hash mapping remains unchanged even for malformed preimages. V6 uses an
explicitly selected domain in the store, RPCs and validator.

The native archive has a disk index, bounded inventory pages and verified
streaming export/import. `-sharepoolarchivemib` sets a finite charged quota; there
is no fixed snapshot-count ceiling. See [archive operation](sharepool-archive.md).
Normal archive startup uses its local atomic index checkpoint; explicit index
repair authenticates retained payloads in resumable batches. This does not skip
cold native-history validation. Configurable history-cache budgets and archive quotas do not
provide archival funding, unlimited admission or an initial-sync solution.
RPC callers may need to retry a yielded history scan.
Mining gateways must dispatch the exact bytes returned by their final
`ready_for_dispatch()` authorization and react to tip/receipt changes.

## Verification and remaining work

The pure [C++ calculator](../src/sharepool/tides.cpp),
[Python reference](../contrib/sharepool/tides_accounting.py) and their
[historical accounting results](../contrib/sharepool/results/tides-accounting.json)
remain useful independent arithmetic checks. Their integer-input API does not
itself perform native rational-target conversion or validate chain history.
The native profile is implemented in
[consensus/sharepool_hash.cpp](../src/consensus/sharepool_hash.cpp) and
[sharepool/tides_history.cpp](../src/sharepool/tides_history.cpp).

The [revision 2 report](sharepool-v6-r2-report.md) records the boundary, archive
and live-relay changes. The [revision 1 report](sharepool-v6-tides-report.md)
retains its original native and Goldshell evidence; that hardware run does not
validate revision 2. Production release still needs a measured difficulty and
capacity contract, scalable archival startup/initial sync, realistic latency and
backlog measurements, independent review,
and a reviewed activation plan. These test results cannot establish mainnet
readiness or prove that miners run a particular software implementation.
