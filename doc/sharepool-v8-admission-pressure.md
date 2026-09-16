# V8 admission pressure and preparation reuse

The v8 gateway now checks local settlement capacity **before acknowledging new
work**. This addresses the earlier 64 KiB workload that acknowledged 1,000
proofs but let 96 expire before admission. It does not change consensus,
extend proof eligibility, or guarantee confirmation under arbitrary future
block timing. The default target remains ten shares per minute per miner, and the
profile remains opt-in regtest.

## Credit and settlement behavior

A new receipt requires fresh native proof validation and a resource quote bound
to the current native tip, durable receipt revision and local policy. All
eligible pending work, including the offered proof, must fit the next local
settlement prefix. The oldest proof must have at least one additional eligible
inclusion height beyond the next block. The check reserves snapshot bytes,
dependency bytes and proofs, template bodies and references, origins, depth,
derived certificates and historical payout recipients.

The native budget RPC also supplies `max_output_bytes`, using the same
contextual coinbase reservation as the block builder. The current limits are
999,612 output bytes for ordinary blocks and 199,612 under reduced-data rules,
excluding the output-count prefix. Snapshot capacity cannot override this
smaller native bound. Missing or malformed metadata fails closed, and a changed
tip requires a new quote. Consensus size and weight limits are unchanged.

When a new proof cannot fit, `AdmissionRefused` reports
`local-admission-capacity`. No proof receipt is appended and no acknowledgement
or hashrate-estimator credit is issued. This local refusal does not declare the
proof or its block invalid. Exact duplicate receipts still receive fresh native
checks and return the existing duplicate result.

Already acknowledged work stays in the journal. An `OPEN` gateway can admit new
work subject to each new quote. `DRAIN` refuses new credit while permitting a
nonempty fitting retained prefix to be mined, including at its final eligible
height. A proposed empty job cannot claim to drain a nonempty queue whose first
proof does not fit. External job construction goes through the same checks;
it cannot bypass pressure by introducing a batch of unacknowledged proofs.

If even an empty settlement cannot fit its historical payouts, the gateway
reports non-dispatchable capacity pressure. The Stratum runner stays alive,
serves already issued submissions and retries construction after one second.
A new native generation triggers an immediate reassessment. This handling is
specific to local resource refusal; native invalidity and missing-data errors
retain their existing failure paths.

Native inventory import applies the same pre-ACK guard. A capacity refusal
returns `limit_reason=admission-capacity` and preserves the exact snapshot/share
retry position in both recent and archive traversal. Importing already retained
receipts does not issue new credit. Restoring a trusted archive preserves its
existing acknowledgements; it does not treat them as new offers.

A native-winning submission remains a block candidate even if its separate
share receipt is refused. The Stratum adapter submits the exact issued block
bytes and reports the capacity refusal separately. Its `capacity_refused`
counter is distinct from invalid-share rejection and block acceptance.

During congestion the v8 difficulty estimator discards its partial observation
window and pauses measurements. Otherwise, refused shares would look like low
hashrate and could lower difficulty precisely when the gateway is overloaded.
Recovery starts a fresh observation window; issued jobs keep their original
assigned target and weight.

The safety margin is measured in block heights, not ten-minute promises. Fast
blocks, reorgs, unavailable evidence or a changed local budget can still prevent
an acknowledged proof from being admitted. Receipt status continues to report
expired or orphaned work separately. Independent gateways do not reserve a
globally guaranteed place in the next block by issuing a local acknowledgement.

## Bounded accounting and preparation

One gate retains an optional accountant for one tip, receipt revision and
policy. It stores only scalar resource totals and hash identities, with
16 MiB of charged metadata and 65,536 entries as local ceilings. These are not
process RSS limits. Every incoming proof still supplies freshly checked
canonical provenance and a native verdict. Evidence-only journal registrations
cannot alter immutable retained bodies and therefore do not invalidate the
resource totals; new receipts, changed tips and changed policy do.

The accountant reserves nine bytes for each variable-length count or index.
This permits incremental additions without resizing the charge for every older
entry. If that conservative estimate exceeds a limit, the gateway tries the
existing exact deterministic prefix selection. Optional metadata exhaustion
also falls back to that exact path. An allocation failure while updating the
accountant after a durable receipt cannot revoke a successful acknowledgement.

Local job construction now selects its batch once across prepare and authorize,
with immutable proposal bytes and complete journal/context fences. External
offers still select independently. Native finalization validates the signed job;
authorization retains its separate fresh native validation. Explicit template
checks replay durable evidence only after an exact missing-data response, with
one bounded retry.

Within one native preparation invocation, decoded history and exact rational
TIDES payout weights are reused for recipient reservation and final allocation.
The fee-dependent amounts are still calculated from the actual reward. The
optional decoded data stays under the existing shared retention budget; payout
plans own their weights and do not persist native validity across RPCs.

## Measurement method

The live fixture can use bounded independent owner threads, each with its own
gateway instances and RPC connection. One owner preserves the previous serial
baseline. Eight owners divide 100 miners into fixed groups; this is still one
host and one shared native service, not 100 distributed gateways. The queue
holds eight items of at most two MiB logical payload, plus at most one pending
item per producer and one consumer item.

Reports distinguish scheduled requests, unproduced requests, pre-dispatch
refusals, offered proofs, pre-ACK capacity refusals, acknowledged proofs,
settled proofs and peer verification. Catch-up and draining never count as
first-minute throughput. A passing correctness run requires every ACK to
settle with the independently calculated coinbase payout; it does not imply
that every scheduled request was accepted on time.

The fixture also performs an explicit admission-status preflight before due
job builds, including its cost in the timings. Some of that selection work is
repeated in preparation. Concurrent service durations overlap and must not be
summed into elapsed time or described as CPU time. The proofs use fixed easy
assignments and controlled block opportunities; there is no ASIC, WAN,
adaptive-controller or production-variance measurement in this workload.

Measurements and verification for this change are recorded in the
[throughput report](sharepool-v8-throughput-report.md). The earlier
[failed overload and serial measurements](sharepool-v8-scalability.md)
remain unchanged for comparison.
