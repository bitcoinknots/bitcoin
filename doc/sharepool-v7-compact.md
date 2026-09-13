# V7 compact TIDES snapshots

V7 is a separate, opt-in regtest profile. It preserves separate pools, direct
coinbase payouts, the eight-network-work window, proportional native-height
boundary sharing and the issued-job cutoff. It changes the canonical encoding
and derives recent state from committed native ancestry. V6 bytes and rules
remain unchanged; existing chains and gate databases are not migrated.

This format addresses repeated per-proof job information and inherited recent
state. It does not establish sustained production capacity, solve arbitrary
recipient growth, or activate easier share difficulty.

## Canonical data and the commitment

The native `m_mm_rhs` remains one domain-separated flat hash of the complete
canonical snapshot. Full evidence travels over existing Bitcoin peer
connections. V7 contains, in order:

1. The snapshot binding, owner authorization and exact job commitment.
2. The existing canonical witness-transaction dictionary and full template
   records, with ordered transaction references.
3. A job dictionary ordered by template index. Each used job contains its
   template index, exact origin binding and owner authorization.
4. Ordered share records: a job-dictionary index plus three 32-bit nonces, the
   16-byte extranonce and the 32-bit time offset.
5. The exact payout output vector and cumulative admission-history hash.

A compact share's changing fields occupy 32 bytes plus the canonical index.
Nodes reconstruct its full header from the referenced template and its binding
and signature from the job record. They independently check the actual proof,
exact signed job, native transactions and payout scripts and amounts. Different
valid templates remain distinct. Every declared template still undergoes native
validation, including templates not used by a share.

Conflicting descriptors, unused descriptors, noncanonical ordering, invalid
indices and attempts to change immutable header fields are rejected. A job
reference cannot transfer a proof to another pool, recipient or template.
Exact origin snapshot openings remain necessary: a valid signature does not
attest native validity or data availability.

## Derived recent state

V7 omits the copied `post_state` and validation-certificate vectors from the
wire. They are deterministic derived data, not omitted current shares. The
current admission delta and actual native parent remain committed. Materializing
height H examines current admissions and at most the preceding three native
snapshots, since a surviving origin must be at least H minus the existing
three-height maximum share age. Checking older origin jobs can require their
own earlier suffixes; all distinct openings count against the dependency budget.
An exact certificate derived from the actual native parent can bypass an old
origin's already-validated recursive state checks. Its exact signed opening and
template binding remain required. A cold current-and-parent reconstruction can
open four preceding native snapshots; deeper uncertified origins add their own
bounded suffixes.

Materialization authenticates each exact snapshot, binding and owner signature.
It ignores caller-supplied derived arrays and checks the current cumulative
history hash. An ancestor's accounting remains conditional until native
validation accepts that ancestor. Missing data is pending, not empty state or
proof of invalidity. Repeated-proof checks and certificate shortcuts use the
reconstructed state from the candidate's actual branch.

This bounded recent-state reconstruction is distinct from the eight-work payout
window. Payout history can extend much farther, especially for a small pool or
after difficulty changes; its older admissions remain necessary and retrievable.

## Independent resource budgets

The 16 MiB snapshot, 64 MiB unique dependency closure, 64-edge depth, 2,048-origin,
512 MiB expanded-template, two-million-reference and contextual native block
limits remain. V7 adds explicit proof-count ceilings equivalent to the previous
full-share encoding's coarse bounds: 32,768 per snapshot and 131,072 across unique
snapshot dependencies. These prevent smaller records from implicitly admitting
unbounded proof-verification work. Reconstructed recent state and certificates
retain their own bounds even though their wire-byte counters are zero.

`getsharepoolhashresources` reports the job dictionary separately from compact
proof bytes. Its validation flags remain false: encoding measurement does not
validate a dependency graph, native body, signature or payout. Wire budgets do
not bound whole-process memory or elapsed validation time. The native session
cache separately charges decoded objects and allocations, and oversized values
are checked without being retained there. The Python graph preflight also avoids
retaining a derived-state copy for every alternative job. Local cache eviction
does not change evidence availability or consensus dependency limits.

## Persistent pool-history access

The optional local history accelerator indexes validated admissions by native
branch and pool. A per-branch persistent pool map points to linked admission
batches, so a warm lookup need not decode unrelated pools' snapshots. Changed
map paths are stored incrementally. These internal index hashes are local data
structures; they do not replace the block's flat snapshot commitment.
The saving depends on admission placement: if every snapshot contains work for
the requested pool, all those selected snapshots still need reauthentication.
The sparse-history unit fixture does not establish that all production histories
will be sparse.

Coverage is created only for native ancestors with full script-validation
status. Exact selected snapshot admissions are fetched and checked before use.
Conditional competing branches use the authenticated scan until eligible for
indexing. Scope includes genesis, rules, profile and activation height.

A separate local sealing key detects damaged or altered index coverage. It has
no spending or mining authority and does not protect against host compromise.
Missing keys, corrupt records and local quotas do not authorize empty history.
The node falls back to bounded, resumable authenticated snapshot scans. A cold
index still processes the full validated prefix from activation to the queried
native parent, not only the requested payout window. This is not a shortcut
around initial validation or an archival data-availability guarantee.

The local index has a charged quota controlled by `-sharepooltidesindexmib`
(default 1024 MiB), excluding database compaction. Explicit
`-sharepooltidesindexrebuild=1` discards only derived index data and rebuilds
through bounded queries. Native blocks and snapshot evidence remain intact.
`getsharepoolhashstatus` exposes index availability and charges.
Index rebuilds commit one native block at a time. Query budgets bound their work,
but cold disk latency, including callers holding `cs_main`, still needs sustained
measurement.

## Profile selection and remaining constraints

Use a fresh datadir and blocks directory with:

```sh
bitcoind -regtest -sharepoolheight=1 -testactivationheight=blake2b@1 \
  -sharepoolhashonly=1 -sharepooltides=1 -sharepoolcompacttides=1
```

Both v6 and v7 datadir markers prevent silent profile changes or changes to the
activation schedule and blocks directory. Public networks reject the compact
profile option, including an explicitly disabled value.

Share difficulty remains SHIFT10. Template transaction dictionaries already
share identical witness transactions; distinct coinbases and genuinely different
transaction sets still consume bytes and native validation work. Origin jobs
that each include a large current admission delta can still duplicate that
delta across exact openings. Removing inherited arrays does not provide unlimited
cross-job or cross-snapshot compression.

Every positive direct payout still needs an actual output in the winning
coinbase. This change introduces neither deferred balances nor a new recipient
admission policy. A production recipient envelope, realistic sustained-load and
recovery measurements, admission-aware variance analysis and independent review
remain required before considering public activation.

## Serialization model

The [v7 resource model](../contrib/sharepool/results/v7-compact-resource-model.json)
compares the existing illustrative SHIFT14 workload without changing the active
SHIFT10 rules. At its mean load of 20,115 proofs, 100 distinct jobs, 100 payout
recipients and shared 100 kB transaction bodies, the modeled snapshot upper
bound falls from 13.11 MiB to 1.16 MiB. The declared dependency graph falls from
236.60 MiB to 6.12 MiB. The v7 graph includes four previous native snapshots and
one exact empty-current-delta opening for each job. These are serialization
bounds under stated assumptions, not measured native throughput or proof of
admissibility.

The same model exposes remaining failures. Repeating the same still-unadmitted
acknowledged 20,115-proof delta across 100 exact job openings needs at least
117.37 MiB and 2,112,075 raw proof instances. Those copies are validation costs,
not additional credited work. Even with empty-delta jobs, an uncertified age-three suffix can
require 160,920 proof instances, above the 131,072 dependency limit. A workload
with 1,000 jobs and 1,000 recipients still exceeds the snapshot and dependency
byte budgets. Compact bytes therefore do not justify easier share difficulty or
a general production capacity claim.

[Native verification and measured limits](sharepool-v7-verification.md) records
the exact tested scope, encoding savings and remaining adapter latency.
