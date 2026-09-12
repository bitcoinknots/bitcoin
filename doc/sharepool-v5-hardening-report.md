# v5 admitted-work ledger and v4 review fixes

This revision adds an explicitly enabled regtest v5 profile and fixes the first
three high-priority implementation findings from the v4 review. Default v4 wire
encoding remains unchanged. There is no public-network activation or production
readiness claim.

## Settlement behavior

The block still carries only a flat hash in `m_mm_rhs`. Full canonical snapshot
bytes, including templates, shares and ledger state, travel over existing native
P2P connections. Nodes validate native transactions, exact job signatures, share
work and direct coinbase scripts and amounts.

In v5, a block anchors fresh admissions. A later block derives its required
payout from the actual parent's confirmed credits for its declared pool. The
oldest byte-bounded prefix settles and every other confirmed credit carries
forward intact, including beyond the original proof admission window. Fresh work
cannot alter an already-fixed payout or solved commitment. Native reorganization
rolls back the associated admissions and settlements together.

This proves completeness against a confirmed record. A local ACK remains
provisional until anchored; it cannot prove that every submitted or undisclosed
share was included. See the [protocol](sharepool-confirmed-ledger.md).

## Review findings addressed

| Finding | Change | Relevant checks |
|---|---|---|
| F1: admitted work may have no remaining settlement depth | Mining-job and proof admission reserve the next embedding edge and origin slot. Historical block validity keeps its existing boundary. Confirmed v5 certificates can terminate previously validated origin recursion. | Boundary-depth job/proof tests; longer worked history across a confirmed checkpoint; witness and actual-parent certificate checks. |
| F2: durable ACK lacks required evidence | Stage the complete transitive snapshot and native-parent opening closure before committing an ACK. Missing data, invalid jobs or quota failures leave the admission unchanged. | Cold archive restore into an empty disconnected native store; multi-level provenance, old origin parents, duplicate repair, quota rollback and actual payout. |
| F3: speculative dependencies obstruct block data | Reserve required roots and dependencies per retained pending block. Bound speculative hints separately, rotate issued requirements, and give ordinary data service amid required requests. | Capacity, shared provenance, progressive refill and weighted-turn unit tests; native relay/lifecycle runs. |

Related fixes memoize Python dependency DAG traversal, discard rejected
registration evidence, and keep local resource failures separate from consensus
invalidity. The template-validation RPC normalizes only the five physical
search fields, preserving exact signed template contents and v4 compatibility.

A further native scheduling bug appeared during the v5 100-miner run: while
waiting for snapshot data, the node repeatedly downloaded a block body already
retained in its durable pending queue. Both normal and direct-header fetching
now skip that retained body. This neither marks it valid nor advances the common
ancestor. Removing the pending body restores ordinary fetching.

## Verification

The [machine-readable results](../contrib/sharepool/results/hash-only-v5-hardening.json)
record commands, per-run binary hashes, source hashes and evidence files. Tests
use native regtest nodes and simulated miners on one macOS host. No ASIC, GPU,
public testnet or mainnet test was performed.

- **73 C++ sharepool cases, 9,308 assertions passed.** This is the sharepool
  subset, not every Bitcoin unit test.
- **108 Python cases passed:** 86 hash/ledger/gate cases and 22 native signer
  cases, with the signer binary configured and no signer skips.
- **16 native functional scenarios passed** across the recorded builds. They
  cover v4 compatibility, both transports, full transaction
  validation, exact payout attestation, missing-data restart, cold gate restore,
  v5 activation at heights 1 and 102, confirmed carry, signed invalid state,
  actual competing branches, reindex and level-four chain verification.

The v5 100-miner test used 100 distinct externally signed native jobs and real
share proofs. A pool-C block admitted all 100 A credits; the next A block paid
100 outputs of 50,000,200 satoshis each, including its verified 20,000-satoshi
transaction fee. A late credit paid its original recipient in a subsequent
A block. Both nodes checked the full selected chain.

After the pending-body fix, observed initial admission-to-convergence time fell
from **83.338 seconds to 20.659 seconds**. Both runs reconstructed the block once
through compact relay; redundant full-body requests fell from **2,645 to zero**.
These are two loopback observations, with other bounded tests running
concurrently, not a controlled throughput benchmark. The remaining 20.659-second
delay itself demonstrates that this is not a production latency result. The
separate withheld-data test observed one body request, none after restart, then
normal validation after the opening arrived.

The v4 100-miner pipeline also passed on the earlier build recorded in the
results, before the final RPC normalization, activation metadata and pending-body
fetch fixes. Those changes received focused regression runs; the report does not
attribute that earlier run to the final binary. An initial attestation regression
failed on physical search fields and passed after the RPC normalization fix.

## Remaining limits

Confirmed credits are mandatory only for blocks declaring their pool. The
protocol cannot force pool continuation or identify relabeled pools; abandoned
pools can occupy the bounded ledger indefinitely. Provisional ACK inclusion,
admission incentives and sustainable service capacity remain unresolved.

One-time settlement still does not establish the requested regular-pool payout
variance or a rolling PPLNS/TIDES policy. Finite historical evidence storage,
data availability, WAN/slow-disk behavior and worst-case validation latency still
need production design and measurements. Review findings F7 (startup and
alternative-source recovery) and F8 (issuer/policy/bytes binding at final
dispatch) remain open. See the [production gap register](sharepool-production-gaps.md).

Final static review also identified an older availability edge: an invalid
alternate body sharing a pending block's header hash can remove that pending
entry in `ProcessNewBlock()`. The ordinary duplicate-download test does not
exercise this adversarial eviction path. It remains a follow-up finding, not a
tested remote exploit or a claimed fix in this revision.
