# Recovery, dispatch and pending-block hardening

This pass follows `b1d69343bd07218f01918e2aa96d3600c182a467`. It changes local
recovery, dispatch authorization and pending-block retention. It does not change
the v4/v5 consensus wire format, payout contract or public-network activation.

## What changed

**F7: recover bounded damaged records.** Startup authenticates the complete
snapshot/pending record wrapper. Corrupted values or identities quarantine while
retaining their local byte and object quota. A pending body must also have sound
transaction count, Merkle and witness commitments before it suppresses network
downloads. Exact reoffers can repair records durably. Hash-correct malformed
snapshot preimages remain available to establish consensus invalidity. Template
lookup tries up to four independently verified snapshot sources.

This is bounded-record recovery, not repair of underlying LevelDB structure,
malformed keys, missing files or storage exhaustion. Four sources are bounded
redundancy, not a guarantee when every available copy is lost.

**F8: bind final dispatch authorization.** The open gate issues a per-instance
HMAC capability binding exact immutable block and snapshot bytes, current
policy/profile, parent height/hash and receipt/evidence counters. Fabricated,
altered, cross-gate, inherited-process, closed and post-restart objects cannot
authorize dispatch. Reopening the same journal requires fresh native
authorization; persisted evidence and already-solved blocks remain intact.

This is an integration check, not an in-process sandbox or a complete Stratum
authentication protocol. The caller must send the exact authorized bytes and
continue processing refresh notifications. A tip can change after a check.

**Two reproduced pending-body eviction paths.**

1. `ProcessNewBlock()` removed a retained good body after rejecting a different
   malformed body with the same header. The RPC regression reproduced the
   pending count falling from one to zero. Rejection now removes only the exact
   retained witness-inclusive body. This RPC reproduction does not establish a
   P2P malformed-body exploit; P2P also has earlier mutation checks.
2. `AcceptBlock()` can return success when it ignores an unsolicited lower-work
   block. The success handler then deleted its existing pending copy, although
   the snapshot was still missing. A P2P regression reproduced this loss on a
   competing branch. Successful removal now requires `BLOCK_HAVE_DATA` under
   the same lock, rather than a successful no-op.

The final native regression also checks witness-only alternates, no duplicate
downloads, restart, acceptance after evidence arrives, removal of an exact
invalid pending body, and retrieval of the competing branch after its missing
opening is supplied.

## Verification and evidence boundaries

Commands, per-run binary hashes, source hashes and retained evidence are in the
[machine-readable report](../contrib/sharepool/results/production-hardening.json).
The normal build completed with the existing duplicate-library linker warning
and no source warnings.

- 80 native C++ sharepool cases and 9,635 assertions passed.
- 93 hash/ledger/gate Python cases passed, including seven new dispatch cases.
- 22 native signer Python cases passed with the built signer configured.
- The protocol proposal has 18 separate model tests; these are not native
  consensus or network tests.

All **16 final-binary functional scenarios passed**. The matrix covers worker
scheduling, HTTP limits, both native
transports, relay, exact-template attestation, native construction, invalid
settlements, legacy compatibility, v5 ledger/reorg/reindex, the two eviction
regressions, cold archive restore, gate activation at heights 1 and 102, and the
v4/v5 100-miner pipelines. Native tests use disposable regtest nodes and software
miners. Hardware configuration and Lazarus routing were not touched in this pass.

The requested additional delegated fuzz-testing task was blocked by automated
safety screening. No new coverage-guided campaign or sanitizer result is claimed.
Scoped automated code reviews were performed; they are not independent external
security approval or evidence of production readiness.

## Protocol work prepared for decision

The [accounting proposal](sharepool-production-protocol-plan.md) and its finite
executable model preserve separate pool funding as the proposed default. They
describe script-bound pool/member identities, the need for real proof of script
control, explicit membership exit, sustainable capacity and admission promises.
The model's conservative membership lock is an illustrative rule, not a proposed
permanent lock on production miners.

Four coupled share/block experiments cover 15,457 simulated block payouts.
An independent comparator agrees on the same admitted history/cutoff, while
14,693 payouts differ from a live-cutoff comparator. This does not establish
regular-pool variance equivalence. The model also exhibits abandoned-pool state
saturation, admission overload, and confirmed rolling work leaving the window
without ever earning a reward.

Those examples expose actual contract choices. Rolling entitlements differ from
v5 credits that remain pending until one settlement. Global reward sharing
differs from each pool funding only its own miners. Neither choice is silently
applied to native consensus. Funding scope, window semantics, membership exit,
minimum payouts, admission service and capacity need an agreed specification
before implementing the next profile. Historical availability, sustained WAN and
disk performance, real miner integration and deployment compatibility also
remain release requirements in the [gap register](sharepool-production-gaps.md).
