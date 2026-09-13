# V6 revision 2: proportional boundaries, live relay and native archives

This revision implements proportional boundary sharing for the separate-pool,
eight-network-work payout window. It also adds bounded live receipt ingestion
and native archive export/recovery. It requires a **fresh opt-in regtest chain**.
The v6 wire version remains 6, but the rules hash changes; the existing datadir
marker rejects revision 1 state. V4/v5 consensus rules and hash mappings are
preserved. No public-network activation is included.

## What changes

All work for a pool admitted in the same native block receives the same
proportional weighting when that block crosses the oldest window boundary.
The history reader retrieves the complete boundary batch. Proof IDs determine
canonical encoding, not payout rank. Full and fractional contributions are
combined before one satoshi floor per recipient. Wide intermediate arithmetic
handles large rewards and changes between origin and winning-block targets.
The 100-miner fixture now expects all 100 recipients in its initial boundary
batch, with exact native subsidy and fees shared between them.

A gate carries older origins first, then durable ACK order. New low-ID work
cannot overtake acknowledged work with the same origin height. V6 gates can
receive and admit another pool's verified shares, retaining the original pool
and recipient; that pool's later blocks fund its rewards. Exact dispatch checks
still bind the gate's own signed job. Missing dependencies produce no ACK.

A bounded recent-insertion feed keeps fresh proposals from waiting behind a
large historical scan. Both P2P feeds use sorted, unique hash lists and share
one message-per-second send allowance. The 4,096-event recent ring reports gaps;
an epoch detects restarts even when sequence counts overlap. The archival feed
continues independently. Gate ingestion alternates the two feeds, meters bytes
and proof validation, and resumes inside a partly processed snapshot.

The native archive keeps snapshot metadata and template sources on disk instead
of a RAM entry for every snapshot. There is no fixed snapshot-count ceiling.
`-sharepoolarchivemib` sets a positive finite quota, charged for payload plus
128 bytes per snapshot and 192 bytes per decoded template. Live object caches
remain bounded. In v6, archived template bodies can release duplicate unfinished
job storage without removing their shared transactions prematurely.

Administrative RPCs page inventory and export/import authenticated chunks.
File reads/writes and archive transcript hashing occur outside the main chain
mutex; individual durable admissions still take it. Export uses exclusive
creation, private POSIX file permissions, and checked file/directory sync.
Import rejects non-regular files and embedded-NUL paths. Individually verified
records survive later chunk failure; importing missing history wakes pending
block validation. A chunk footer describes local inventory traversal, not proof
that every required historical object is available.

## Verification

The [verification manifest](../contrib/sharepool/results/tides-v6-r2-verification.json)
records exact commands, source and binary hashes, logs and separate run scopes.
The final build passed **139 selected C++ cases with 141,234 assertions**,
**204 Python cases with no skips**, and **24 native scenarios**. The native
results comprise the 19-case v4/v5/v6 regression matrix plus the v6 100-miner,
two tiny-reward, cross-pool and archive cases. All use the final daemon
`ebf5acc7…`; source and full binary hashes are pinned in the manifests.
These runs used macOS and disposable loopback nodes, not Windows or WAN tests.

Native checks cover actual payout amounts, 100 distinct fee-paying transaction
jobs and recipient scripts, altered-payout rejection, issued-job cutoff, late
and winning work, cross-pool admission, missing-evidence recovery, competing
forks, restart, reindex-chainstate and full reindex. Archive checks include
65,540 stored records across restart, charged quotas, damaged-record repair,
bounded chunk resume and native recovery after the follower loses its snapshot
database. A separate transport fixture uses 1,030 tiny untrusted preimages to
exercise historical P2P pagination beyond the first page; those preimages are
not presented as valid jobs or work.

The integration runs reproduced two relay defects during development: recent
hash lists initially used insertion order, and independently paced feeds could
exceed the receiver's combined rate allowance. Both have explicit regression
checks. The successful final runs use the corrected binary; earlier failing
attempts are retained separately rather than counted as passes.

No physical miner was rerouted for this pass. The earlier Goldshell capture
belongs to [revision 1](sharepool-v6-tides-report.md). It still verifies with the
complete `590cfe6` tool tree; revision 2's verifier explicitly rejects it as old
rules. The new CPU/Sia capture and fresh-node replay are software transport
checks, not new ASIC evidence.

## What remains before production

The [coupled calibration](sharepool-tides-calibration.md) uses one PoW event
stream for shares and pool block finds, with frozen jobs, rolling-window
covariance, bootstrap, latency and bounded-queue expiry. It does not confirm
ordinary-pool variance at the current experimental share target. Against its
explicit sixteen-times-denser arrival-ordered reference, a miner with 0.01% of
a 1%-network pool has an observed total-payout variance ratio of 5.55, with a
95% whole-run bootstrap interval of 3.08–10.40. This is an illustrative CPU model,
not a commercial-pool measurement. Denser sampling increases template-validation
and archive requirements; no difficulty change is activated here.

Proportional sharing removes proof-rank dependence for a fixed admitted set.
It cannot force a producer to include withheld work, establish global reception
order, or prevent expiry when admission capacity is insufficient. A hash binds
supplied data; it does not prove universal disclosure or use of a particular
DATUM executable.

The archive still authenticates retained payloads at startup, so restart cost
grows with history. Production requires a supported miner-size and variance
contract, measured full-template throughput, sustained relay/disk capacity,
scalable startup and initial sync, independent consensus review, and an explicit
activation plan. These tests do not establish mainnet readiness.

See [protocol](sharepool-tides-accounting.md), [admission guarantees](sharepool-admission-fairness.md),
[archive operation](sharepool-archive.md) and the [production gap register](sharepool-production-gaps.md).
