# TIDES v6 local history budgets

The opt-in regtest TIDES profile uses exact native-parent history. Its local
history cache is derived from immutable snapshot deltas, not a second ledger.
Running out of cache or validation budget leaves a block pending; it does not
make the block invalid or shorten its payout window.

Two startup options allow an operator to raise the retained history capacity
without changing the profile, snapshot bytes, or payout rules:

| Option | Default | Scope |
| --- | --- | --- |
| `-sharepooltideshistoryquerymib` | 64 MiB | Total retained admission suffixes across up to 16 queries, per validation/RPC thread |
| `-sharepooltideshistorycachemib` | 64 MiB | Derived historical deltas across up to 4,096 blocks, per validation/RPC thread |

Both require the explicit regtest `-sharepooltides` profile. Values must be
positive whole MiB; zero, unlimited sentinels, negation, omitted values,
duplicates, malformed numbers, and conversion overflow are rejected. The
maximum representable value is `floor(SIZE_MAX / 1048576)` MiB for the platform.
Accepting an explicit value does not reserve that much RAM or establish that
the machine can safely provide it.

For a node pending at `tides-history-query-budget`, increase the query option
and restart with the same datadir and unchanged consensus options, for example
`-sharepooltideshistoryquerymib=256`. Restart reconstructs derived state from
the retained snapshots. The internal configuration API also preserves pending
query progress when a budget is increased; there is no live configuration RPC.
Reducing a budget may evict derived state, which can be reconstructed later.

Per-call scanning remains limited to 4,096 blocks, 65,536 admission summaries,
and 64 MiB of charged delta data. These are work-scheduling limits: interrupted
queries retain progress and retry. They are not total-history consensus caps.
Missing snapshot data still needs to be retrieved; a larger memory budget
cannot replace it.

These budgets are accounting limits on cached payloads, not hard process RSS
limits. Each participating thread has its own caches. Allocator overhead,
temporary decoded snapshots, copied return values, and payout aggregation need
additional memory. Raising a configured limit can therefore exhaust physical
RAM. A large valid window may still require more local resources, a different
storage/aggregation implementation, or operational intervention. This change
removes the fixed 64 MiB query ceiling; it is not a production capacity claim.

History on an unconnected competing branch remains conditional on native
validation of every ancestor during activation. Cache budgets do not add a
connected-parent requirement that would prevent a competing branch growing.
