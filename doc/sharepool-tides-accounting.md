# Separate pools with a TIDES reward window

**Selected on 2026-09-12:** each pool funds its own rewards, using a TIDES
window. These two choices are settled. This document records the implementation
boundary and the remaining native integration; it does not activate new rules.

## Selected reward contract

Pool A's blocks reward work recorded for A; B's blocks reward B's work. Relaying
and checking another pool's data does not make its miners beneficiaries of the
relaying pool's blocks. A miner leaving A retains its original position in A's
history. New work for B cannot relabel that old work. Rewards depend on the
original pool continuing to find blocks; there is no fixed satoshi debt or
promise that every share is rewarded.

The reference is [OCEAN's TIDES specification](https://ocean.xyz/docs/tides),
read on 2026-09-12. Its relevant rules are:

- Keep distinct proofs in order, weighted by their assigned difficulty.
- Use a window containing eight times the winning block's network difficulty.
- Freeze its top when issuing the winning job.
- Aggregate work by payout address, include subsidy and transaction fees, and
  round each address's reward down to satoshis.
- Keep shares after a reward; retain older history for difficulty increases.
- When history is shorter than the window, divide by the available work.

This is eight blocks **worth of work**, not the last eight blocks, eight shares,
or an eighty-minute timer. The [previous experiment](sharepool-production-protocol-plan.md)
used different rounding and a confirmed-parent cutoff. Its published numbers
remain historical; they are not TIDES variance measurements.

## Accounting implemented in this change

The independent [C++ calculator](../src/sharepool/tides.cpp) and
[Python reference](../contrib/sharepool/tides_accounting.py) implement the chosen
window arithmetic. Shared [known-answer vectors](../src/test/data/sharepool_tides.json)
check exact agreement for the zero-operator-fee contract. These modules are not
called by `CheckSnapshot`, the native builder or the mining gate yet.

Both use positive integer work in one common exact difficulty scale. The caller
must establish that scale and verify the assigned share target; an observed
low hash or a claimed hashrate is not a work weight. Converting native targets
to this scale is still part of the new protocol design. In particular, the
existing rounded expected-hash integers must not be advertised as identical to
all TIDES difficulty conventions.

The oldest contribution is clipped to the amount that fills the window; its
original proof and full work remain in history. This is an explicit boundary
convention, since the reference does not spell out that algorithm. The libraries
aggregate equal scripts before rounding and return any leftover satoshis as
unclaimed residue. They neither redistribute that residue nor carry it as a
balance. No implicit recipient, minimum-payment account or operator fee is added
by the C++ calculator. Python additionally models tagged fee buckets as an
explicit extension; it is not native fee enforcement.

For example, with network work 10, the window holds 80 units. If Alice's older
proof represents 60 and Bob's newer proof represents 30, Alice contributes 50
and Bob 30 to this window. At a reward of 101 satoshis, their floored amounts are
63 and 37, leaving one satoshi unclaimed. Another block can reward this same
history. If network work rises to 20, both full proofs return to eligibility;
the available-history denominator is then 90.

Empty history raises a distinct error: the calculator does not invent a full
coordinator payout. Output budget exhaustion rejects the calculation without
omitting a miner. A C++ history evaluation budget also fails explicitly; it is a
caller resource limit, not a new consensus share-count cap. This full-prefix
reference is intentionally not a scalable historical index.

## Cutoff and native integration

The chosen target is an **issued-job window**. Its inputs must be bound to the
exact signed template before hashing: native parent, pool, complete history
prefix, new admitted work, current difficulty, reward and resulting coinbase.
Receiving more shares creates a new job with a new snapshot hash. It does not
alter an existing job or insert a winning proof into the job that it solved.

Native implementation should extend the actual parent's confirmed per-pool log
with the valid admissions committed by that particular job. The resulting
cutoff can therefore include work verified since the parent block. The current
v5 rule, which only pays from the parent's confirmed credits, has extra delay
and is not silently renamed TIDES. The canonical order of new admissions must
be explicit: different nodes' arrival times cannot define one objective order.
A frozen prefix authenticates supplied work; it still cannot prove inclusion
of undisclosed acknowledgments.

The Python job freezes its accounting inputs. The C++ API verifies a contiguous
per-pool prefix ending at the supplied sequence/proof ID. **Neither is proof
that the history was authorized.** A last proof ID does not authenticate earlier
records. The native integration must verify the entire committed history,
membership and evidence on the candidate's actual branch before calling either
calculator.

The remaining implementation work is concrete:

1. A separate regtest profile with an explicitly scoped codec, signature and
   snapshot hash. Preserve v4/v5 handling of even malformed hash preimages;
   merely assigning a new version byte in their shared hash function can change
   existing invalidity evidence. Start with a fresh chain, without converting
   v5's confirmed pending credits into rolling positions.
2. Native pool membership with actual proof of payout-script control. A first
   arbitrary owner signature cannot register somebody else's address. Explicit
   branch-confirmed switches govern new jobs; earlier work keeps its original
   pool and payout. No permanent membership lock is introduced by this choice.
3. An append-only historical work store with bounded admission deltas, exact
   parent references and undo/reorg support. Repeating all history inside every
   snapshot is not sustainable. Older data must remain retrievable when a
   window expands. The full snapshot still has one flat hash in `m_mm_rhs`;
   evidence remains outside the block on the existing P2P connections.
4. Exact admission order, target units, empty-log bootstrap and coinbase output
   limits, followed by native builder, gate, restart, reindex and competing-fork
   tests. Keep provisional ACKs distinct from canonical admission and preserve
   deterministic carry without claiming unlimited inclusion capacity.

These are integration requirements, not requests to reconsider the selected
funding and reward window. Production difficulty, archive capacity and payout
variance still need measurements using the completed pipeline.

## Verification

Run the accounting tests from the repository root:

```sh
python3 -B -m unittest discover -s contrib/sharepool -p 'test_tides*.py' -v
```

Build `test_bitcoin` and run its `sharepool_tides_tests` suite for the native
reference and embedded cross-language vectors. This revision passed:

- 92 C++ sharepool cases / 9,846 assertions, including 12 new TIDES cases and
  all 80 existing sharepool cases.
- 24 Python TIDES cases, including an independent interval calculation across
  2,720 inputs and the 11 shared C++/Python known-answer vectors.
- All 18 historical accounting-model regression cases.

Commands, source/binary hashes and test logs are recorded in the
[accounting verification manifest](../contrib/sharepool/results/tides-accounting.json).
These are library/unit checks, not new native block or network scenarios.
Existing v4/v5 functional regression results
remain in the [hardening report](sharepool-production-hardening-report.md).
This change contains no hardware or public-network test and does not establish
mainnet readiness.
