# DATUM-style local job refresh

The hash-only gate now has a cooperative job scheduler with a default normal
refresh interval of 40 seconds, configurable from 5 through 120 seconds. This
matches upstream DATUM's normal work-update setting. A changed native parent,
including a same-height reorganization, bypasses that interval. No consensus,
share difficulty, settlement encoding or public-network activation changes.

The original gate did not itself request a job on every share. Its
`needs_refresh()` predicate rejected initial dispatch after any newly
acknowledged receipt. Treating that predicate as a continuous mining stop
signal forced callers to rebuild on every share. The strict initial-dispatch
check remains: a newly handed-off job must include the deterministic eligible
receipt prefix known when it is authorized.

`ready_for_continued_work()` separately rechecks an authentic authorization's
native parent, profile, local policy, journal integrity and retained evidence
sequence. It permits newer receipt revisions without modifying the original
job. This predicate does not prove the job was dispatched. The scheduler only
continues the exact authorization whose mining-transport handoff succeeded.
Callers must not use the continuation predicate to approve fresh dispatch.

## Issued cutoff and new receipts

Suppose job A was authorized and dispatched at receipt revision 100. New shares
advance the durable journal to 110 while A is being hashed. A retains its exact
snapshot hash, transactions and payout vector. The next scheduled job uses the
current deterministic batch, including those newly acknowledged receipts when
they fit its existing resource and age rules. Incoming shares and mempool events
never reset the refresh deadline. They therefore cannot indefinitely postpone
the next job by repeatedly restarting the timer.

The winning header is still bound to its original template and snapshot. A
previously solved candidate remains submit-capable under native rules; replacing
or withdrawing active work does not rewrite the candidate or delete evidence.
This is a fixed issued-job cutoff, not a claim that a winning block includes
work that arrived after it was issued. Block admission, carry-forward, payout
history and expiry rules remain unchanged.

## Integration

Use the same owner thread and process as `HashMiningGate`:

```python
from hash_job_scheduler import HashJobScheduler

scheduler = HashJobScheduler(
    gate,
    sign_owner=signer.sign_owner,
    publish=send_authorized_work,
    withdraw=withdraw_current_work,
    work_update_seconds=40,
)

# The external event loop calls this regularly, and promptly on native block
# notifications. New mempool transactions need no immediate job construction.
scheduler.poll()

# When shutting down:
scheduler.close()
gate.close()
```

`publish(authorization)` must arrange full snapshot availability, hand the exact
authorized bytes to the mining transport and return `True` on successful handoff.
For a local backend this includes `gate.register_snapshot()`; authorization alone
uses a validation overlay and does not announce the snapshot. Any other return
value or exception is failure; the scheduler attempts to withdraw potentially
partial work. `withdraw()` must stop advertising current mining work and return
normally only when that succeeds. Neither callback may reenter the scheduler or
use its gate concurrently.

A callback failure propagates to the caller; clearing the local active record
does not guarantee a broken transport successfully stopped its miners. Failed
withdrawal sets `withdrawal_pending` and blocks construction and publication
until a later `poll()` or `close()` successfully retries it. A failed `close()`
can be retried, but the closed scheduler cannot resume issuing jobs.

An initial or replacement job is always built with `make_native()`, signed by
the external signer, authorized by the gate and checked with the strict
`ready_for_dispatch()` fence. Native context is checked again after handoff.
Later receipts preserve the cutoff; a new parent or native/profile/journal
failure withdraws work. Restarting the gate cannot revive old dispatch seals.
The scheduler accepts no caller-supplied candidate as its active job.

Normal replacement keeps the current exact job while construction runs. A
changed native context withdraws it before construction. Construction, signer,
authorization, clock or transport failure clears the active job and propagates
the error. A caller may explicitly retry by servicing the scheduler again.
Missed intervals produce one replacement, not a catch-up burst of old jobs.

## Timing and scope

The interval starts after successful handoff, using a finite monotonic clock.
`next_refresh_at`, `last_update_reason`, `last_prepare_seconds` and
`last_due_lateness_seconds` expose the schedule and delays. Clock rollback,
cross-process/thread use and callback reentrancy are rejected.

The scheduler is a local library adapter, not a background service or Stratum
implementation. Call `poll()` on block notifications as well as regular event
loop ticks; a notification itself is only a hint, since the gate rereads actual
native context. Even a repeated notification cannot force an unchanged-parent
refresh before its normal deadline.

This scheduling change does not reproduce DATUM's per-client staggered Stratum
notifications or empty-to-full priority-job sequence. It also does not add
v7 live-template/delta gossip, change share difficulty to DATUM's vardiff, prune
settled evidence, or modify physical miner settings.

Native construction and signing are synchronous. A slow job can take longer
than the interval and delay servicing a block event. The existing 138-second
later-round preparation observation for 100 jobs is not made into a 40-second
guarantee by adding a timer. A transport must handle prompt stale-work cancellation, and
production operation still needs construction and event-loop latency tests.

[Traffic at the DATUM cadence](sharepool-datum-traffic.md) distinguishes gateway
template producers from ASIC clients and models block-triggered refreshes.
The measured transaction encoding is reused; the traffic projection does not
establish a live transport or hardware capacity.

## Verification

The current change passes 342 Python tests and three isolated native regtest
scenarios: cadence, state reuse and compact settlement. The new native fixture
uses an injected clock, real mempool transactions, native signatures and proofs,
exact coinbase payout assertions, old-job settlement and actual chain rollback
and restoration. Python failure tests cover withdrawal retry, invalid clocks,
ownership, forged authorizations and damaged journal/profile state.

[Commands, source and artifact hashes](../contrib/sharepool/results/datum-cadence-verification.json)
record the runs, including the initial fixture's omitted snapshot announcement
and its correction. The earlier 900-proof capacity measurement remains historical
evidence; this cadence change does not rerun or establish sustained capacity.

Upstream references: [normal interval and bounds](https://github.com/OCEAN-xyz/datum_gateway/blob/master/src/datum_conf.c#L71-L75),
[notification-aware template loop](https://github.com/OCEAN-xyz/datum_gateway/blob/master/src/datum_blocktemplates.c#L557-L568).
