# V6 native TIDES-style accounting verification

This change wires separate-pool rolling rewards into the native validator,
builder, external signer and miner gate. It is an opt-in fresh-regtest profile,
not a mainnet activation or production readiness claim.

## Resulting behavior

A miner selects a payout script without proving possession of its spending key.
The signer authorizes the exact job, and each admitted proof keeps its original
pool and recipient. Different pools may use the same recipient. There is no
exclusive ownership registration or global membership lock.

The native validator derives the actual branch's historical pool window plus
the current issued job's admissions. It checks exact rational work, native fees
and subsidy, per-script satoshi floors and the resulting coinbase outputs.
History survives rewards: a proof can earn more than once, and older work remains
available when difficulty rises. Late work requires a new signed job; it cannot
change a solved header or insert its own winning proof into that header.

`m_mm_rhs` contains one flat hash of the complete canonical snapshot. Full
snapshots and templates travel on the existing P2P connections. A cumulative
history hash binds admission deltas; it is not a settlement Merkle root. Missing
evidence or local resource exhaustion remains pending rather than becoming an
invalid block or a fabricated empty reward window.

Profile-specific hashes preserve v4/v5 behavior, including malformed preimages.
A durable marker rejects incompatible v6 reuse before opening the block index,
including reindex with a changed activation height, Blake2b headline, blocks path
or a downgrade to an older/plain profile. Historical scan cursors can resume;
retained-history memory budgets are explicit operator settings.

## Native and Python checks

The [verification manifest](../contrib/sharepool/results/tides-v6-verification.json)
records commands, source hashes, binaries and results. The selected C++ suite
passed **119 cases and 10,360 assertions**. Unrelated C++ suites were not selected.
The Python runs passed 107 hash/codec/gate cases, 22 native signer cases,
28 TIDES/reference/adapter cases and 18 historical-model regressions: **175
executed cases**, with no skips in those Python runs.

Coverage includes exact assigned-work probability, malformed hash compatibility,
fractional oldest-share clipping with large rewards, actual historical payouts,
separate pools sharing one recipient, query-budget recovery, stale cursors and
startup/profile isolation. Hardware-adapter fault tests verify that archive or
native-submission failures never produce successful ACKs.

The final native regression matrix passed **19 of 19 scenarios** and records
its individual commands and full logs separately. It includes v4/v5 lifecycle, builder, rules, ledger, worker,
pending-body, HTTP and gate regressions, both existing 100-miner pipelines, v6
activation at heights 1 and 102, and the CPU/Sia capture with fresh-node replay.
V6 cases exercise actual fees and payouts, late work, missing older history,
P2P repair, competing forks, restart, reindex-chainstate and full reindex.

The [new v6 pipeline](../contrib/sharepool/results/tides-v6-native-pipeline-verification.json)
passed with **100 logical miner gates, 100 distinct valid fee-paying transaction
templates, 100 admitted proofs and two native nodes**. It verified exact payouts,
rejected altered bindings/payouts, carried late and winning work into later jobs,
repeated rolling rewards and recovered native/gate state after restart.
The easy target's roughly 16-unit window gives 17 boundary-inclusive eligible
proofs from the 100-proof batch; admission is not a promise that all 100 earn
from that block. This is not 100 independently running native nodes or a full
100-by-100 relay simulation.

Two additional native cases passed at activation heights 4800 and 4950. A
one-satoshi reward split between two recipients floors both payouts to zero;
a zero-subsidy job also has no monetary payouts. The ordinary witness commitment
keeps the coinbase valid. Both cases verify dispatch, rejection of changed
payouts, P2P following and reindex-chainstate. No zero-output runtime patch was
needed.

The 100-miner and tiny-reward cases ran on daemon `08411d5c…`. The later
`86ab0ebd…` build adds only the reviewed headline field to the datadir marker;
the final regression matrix, hardware run and final C++ suite use that build.
The manifests retain full hashes rather than relabeling earlier test binaries.

## Physical Goldshell and independent replay

The [hardware report](../contrib/sharepool/results/tides-v6-hardware.json) records
a bounded approximately 90-second run of the local Goldshell through the new
Sia/BLAKE2b adapter. A fresh isolated v6 node accepted **21 proofs and 19 native
blocks**, using 22 signed jobs. Two proofs arrived on an old parent. All 21
successful submissions reached the durable acknowledgment point; no submission
was rejected. Two proofs remain durable but unanchored at the cutoff.

A [public protocol capture](../contrib/sharepool/results/tides-v6-hardware-capture.json)
contains exact jobs, signatures, snapshot openings and proofs. An independent
exact-rational verifier checked its amounts and bindings, then a separate fresh
native node validated all jobs/proofs, replayed the 19-block chain and passed
`verifychain`. Device credentials, private keys and operational backups are not
part of that public artifact. Nonce bytes alone cannot prove physical provenance;
the temporary device routing and observed submissions provide that operational
evidence.

The configuration guard restored the original pool order, credentials and
settings. Independent read-back confirmed the original first pool active, the
temporary pool absent and the local gateway still configured for Lazarus.
Thirteen fresh upstream accepted-share messages were observed after restoration
at the independent check. This is gateway acceptance evidence, not individual
socket attribution for every accepted message. Both test and replay nodes shut
down cleanly.

The transport difficulty of 4096 throttles hardware submissions. It is not the
v6 credited work weight and does not measure production sampling variance.

## Limits that remain

- **Fairness and variance:** admission order is height plus numeric proof ID,
  rather than a pool's observed arrival order. Selective publication, batch
  composition and proof-ID selection need adversarial analysis and realistic
  payout comparisons before claiming ordinary-pool variance.
- **Availability and capacity:** the native snapshot store still has local
  1 GiB/65,536-object limits and a separate 256 MiB template-data budget. Query
  RAM knobs do not fund archives, solve initial sync or guarantee bounded RSS.
  Deep-history retrieval, slow disks, WAN loss and sustained backlogs need
  production measurements and an archival design.
- **Inclusion:** a hash authenticates supplied data, not undisclosed receipts.
  Provisional work can expire before canonical admission. Permissionless entry
  does not guarantee unlimited admission or payment from an abandoned pool.
- **Deployment:** only isolated regtest is enabled. Independent consensus review,
  production difficulty calibration, deployed gateway integration and a reviewed
  public activation/rollback plan remain. Distinct signed jobs do not prove
  independent transaction selection or use of a specific DATUM executable.
