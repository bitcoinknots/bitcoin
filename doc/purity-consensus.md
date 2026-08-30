# Bitcoin Purity consensus (short-term hard fork)

This document is the source of truth for the short-term hard fork. Code must
match it. Long-term ideas belong in [roadmap.md](roadmap.md) and are **not**
specified here as active rules.

Activation height `nPurityActivationHeight` is hardcoded on mainnet to
**961637** (block hash
`0000000000000000003ea74f4dafdda7ed4e02c4c1ccb9768e0ca4f9e1a35159`, the first
Purity consensus block). It must be **greater than** the ASERT anchor height
**961632** so the first ASERT-adjusted block has the anchor as an ancestor.
Historical Bitcoin / Knots validation is unchanged before that height so IBD
still works.

The activation block hash is **consensus-pinned**
(`hashPurityActivationBlock`): any header at height 961637 with a different
hash is invalid. This is enforced unconditionally in header validation and is
independent of the checkpoint at the same height (which `-checkpoints=0` can
disable). On startup, a block index that already contains a conflicting block
at 961637 (stored by other software before upgrading) is rejected and must be
rebuilt with `-reindex`.

Peers whose header chain announces a competing block at 961637 (typical
Core/Knots tips) are **not** disconnected for that announcement. Their shared
pre-activation headers are retained so IBD can download historical blocks from
them in parallel with Purity peers; only post-activation history must come from
the Purity chain.
Automatic outbound peers proven to follow such a competing block are demoted to
additional stale-consensus connections, subject to `-maxstaleoutbound`, so they
cannot occupy or receive eviction protection for a Purity-compatible outbound
slot. Once the active tip is at `nPurityActivationHeight-1` or higher, those
peers are no longer useful: the node stops opening automatic outbound
connections to them (requiring `NODE_REDUCED_DATA`) and disconnects any already
tolerated stale outbound peers.

**Fork baseline:** the Knots/BIP110 *enforcement* chain that rejected
non-signaling blocks at height 961632 — not the Core majority chain at the
same height.

## Unchanged

- SHA256d proof-of-work.
- P2P magic `f9beb4d9`, default port 8333.
- Address formats, transaction serialization, sighash (no replay protection).
- Block size / weight limits inherited from Bitcoin.

## 1. Permanent RDTS (BIP110 rules)

BIP110 Reduced Data rules become **always active** at
`nPurityActivationHeight` and never expire. They cannot be turned off with
`-consensusrules`, `rdts_consent_flag`, or similar.

After activation, version-bit 4 mandatory signaling is not required. The
rules are consensus, not a miner poll.

### Output size

Defined in `src/consensus/consensus.h`:

- Non-empty non-`OP_RETURN` `scriptPubKey`: at most **34** bytes
  (`MAX_OUTPUT_SCRIPT_SIZE`).
- `OP_RETURN` outputs: at most **83** bytes (`MAX_OUTPUT_DATA_SIZE`).

### Script (`SCRIPT_VERIFY_REDUCED_DATA`)

Defined in `src/script/interpreter.h` / `interpreter.cpp`:

- Script elements at most **256** bytes (`MAX_SCRIPT_ELEMENT_SIZE_REDUCED`),
  with the documented P2SH redeemScript-push exemption.
- Taproot control blocks limited to depth **7**
  (`TAPROOT_CONTROL_MAX_SIZE_REDUCED`).
- Taproot annex is invalid.
- `OP_IF` / `OP_NOTIF` forbidden in Tapscript.

Knots deployed this as a temporary BIP9 deployment
(`max_activation_height = 965664`, `active_duration = 52416`). Purity does
not wait for 965664: the enforcement chain stalled during mandatory
signaling, so transaction-level RDTS must turn on at the hard fork.

## 2. Difficulty: aserti3-1d

Port of Bitcoin Cash **aserti3** (integer cubic approximation; no floating
point). Specification:
https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/

Parameter change vs BCH `aserti3-2d`:

- Half-life `nDAAHalfLife` = **86400** seconds (24 hours), i.e. `aserti3-1d`.
- Ideal block time remains 600 seconds.

**Anchor** is enforcement-chain block **961632**:

- `anchor_height` = 961632
- `anchor_bits` = that block’s `nBits` (filled from the real block when known)
- `anchor_parent_time` = timestamp of **parent** of 961632 (BCH convention)

From `nPurityActivationHeight` onward, `GetNextWorkRequired` uses ASERT.
**Only at the activation-height block** is ASERT a minimum difficulty
(maximum allowed target): that header is valid if its decoded `nBits`
target is **less than or equal to** the ASERT target. Harder `nBits` are
accepted so a block mined with the legacy 2016-block DAA (current mainnet
high difficulty) can be the first Purity block when that target does not
exceed the ASERT maximum.

Compare the decoded `arith_uint256` targets, not the compact `nBits`
integers. Illegal compact encodings and targets above `powLimit` are still
rejected. `CheckProofOfWork` continues to check the block hash against the
block’s own `nBits`, so a harder header must actually meet the harder
target.

Every other height still requires an exact `nBits` match: the 2016-block
DAA before activation (Bitcoin Core behaviour), and the ASERT compact
value from height `nPurityActivationHeight + 1` onward.

Using an anchor in the past (while the enforcement chain has been behind
schedule) drops the ASERT floor at the first Purity block so production can
resume.

## 3. Deep-reorg parking (local policy, not consensus)

Port of Bitcoin Cash Node parking. **Not** a consensus rule. Different nodes
may use different thresholds. A block or chain is not consensus-invalid merely
because a node parks it; parking only affects that node's chain selection.

Default local policy:

- Parking is enabled on mainnet (`-parkdeepreorg=1`) and disabled by default
  on test chains.
- The default threshold is **6** (`-parkreorgdepth=6`).
- If connecting a competing chain would rewind the active chain by **more
  than 6** blocks (`rewind > 6`), mark the competing chain **parked** and do
  not reorg automatically.
- Reorgs of 6 blocks or fewer proceed under normal most-work chain selection.

Operators may override the threshold with `-parkreorgdepth=<n>` (minimum 1).
For example, `parkreorgdepth=4` means reorg depths 1–4 may activate
automatically, while depth 5 or greater is parked for manual review. Disable
the mechanism with `-parkdeepreorg=0`.

Parked chains can be reviewed with `parkblock` / `unparkblock`.
`invalidateblock` / `reconsiderblock` remain available to reject or restore.

- Do **not** port BCH Avalanche or automatic unparking.
- Do **not** port BCH `-maxreorgdepth` auto-finalization.

## 4. Double-spend freeze (specified, not implemented)

**Status: draft only. No code in this release.**

Bitcoin Cash DSProofs are mempool notifications only and are **not** a freeze
implementation.

Intended future consensus (to be finalized before coding):

- **When:** a reorg actually connects; an outpoint spent by txid A on the
  disconnected chain is spent by a different txid B on the new chain.
- **What:** freeze coinbase outputs of new-chain blocks that contain the
  conflicting spend; freeze the original input outpoint so it cannot be
  spent again.
- **Not while parked:** detection may log; freeze applies only if the reorg
  is accepted (unparked and connected), so the set is determined by chain
  history rather than local park state.

All nodes must compute the same freeze set. That requires a later spec
revision covering IBD, assumevalid, and pruned nodes.

## Testnets

Regtest may activate Purity rules at low height for tests. Public testnet /
signet parameters are chosen when those networks are actually used; they are
not required to match mainnet dates.
