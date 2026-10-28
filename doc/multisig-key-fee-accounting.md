# Draft: executed multisig key-fee accounting

This is an experimental relay-policy fee floor, not a new consensus rule.
The default is 1,000 satoshis per charged key operand, with one free unproven
operand per executed script. The fee floor is not added to the ordinary fee
requirement; the larger requirement applies. Zero disables the setting;
`-corepolicy` disables it unless explicitly overridden.

## Authoritative admission counter

The normal policy script-validation pass collects optional observations:

- Legacy/SegWit v0 CHECKMULTISIG and CHECKMULTISIGVERIFY contribute their
  actual number of key operands minus successful signature matches. Dynamic
  m/n values and stack transformations are handled by the interpreter itself.
  A false result subsequently consumed by NOT does not earn structural m
  credit for empty signatures.
- In tapscript, a script is in scope only if CHECKSIGADD actually executes.
  Its executed CHECKSIG, CHECKSIGVERIFY and CHECKSIGADD operands contribute
  one unproven operand when no valid Schnorr signature authenticates them.
  This includes the initial CHECKSIG of multi_a. It is a script-level scope
  rule: it does not trace whether every CHECKSIG feeds the same accumulator.
  Upgradable key types do not receive signature credit merely for succeeding
  without verification when nonstandard flags permit them.
- Each script contributes `max(0, unproven_operands - 1)`. Operations within
  that script share the allowance. Counts accumulate across input scripts.
  These are operand occurrences, not distinct public-key byte strings.

For a successful canonical m-of-n spend, this is `max(0, n - m - 1)`:
2-of-2 and 2-of-3 have no additional floor; 1-of-15 has thirteen charged
operands and therefore a 13,000-sat floor at the default.

Unrelated hashes, dropped data, signature-shaped witness padding and keys in
unexecuted branches do not become operands merely because of their size.
Standalone CHECKSIG, pure data scripts, Taproot key-path spends and outputs
whose scripts are still hidden are outside this rule. P2SH, P2WSH, nested
P2SH-P2WSH and tapscript observations use the actual validated execution path.
There is no separate speculative EvalScript pass with relaxed flags.

No observations from a failed input validation are used for admission. The
existing interpreter success/failure rules and signature checks remain in
place. Block verification does not request observations or enforce this fee.
Nevertheless, the optional instrumentation touches consensus-critical code
and requires compilation, regression tests and independent review.

## Cache and verification cost

Observed transaction counts are cached in a bounded 4,096-entry FIFO using
the salted full-script cache key (wtxid and flags). A hit is used only alongside
a full-script validity-cache hit. A cached valid bit with missing count
metadata triggers normal execution to recover the count; it is never treated
as zero. Existing signature caching remains usable. Cached values are counts,
not fees, so the current configured price is applied after retrieval.

Ordinary cheap admission/fee checks still precede script verification. This
new floor is checked after successful policy script verification. It is not
an early CPU-exhaustion defense, and no relay-CPU improvement is claimed.

## Package admission

A transaction below its key-fee floor returns a reconsiderable fee failure.
The existing child-with-unconfirmed-parents submission path can retry it with
a child. Newly evaluated package members must collectively pay the sum of
their key-fee floors in actual base fees. A charged child contributes its own
floor. Already admitted/mempool transactions and local prioritisation deltas
do not provide reusable fee credit. Ordinary fee, topology, signature,
replacement, and mempool-limit checks still apply.

This does not make arbitrary packages relayable. `testmempoolaccept` retains
individual-fee test semantics; use the supported `submitpackage` path for
CPFP. The ordinary per-transaction minimum relay-fee restriction is unchanged.
This is an admission check, not an ongoing parent/child binding or mining
rule: it does not guarantee that the child is mined with its parent or that
they remain together after eviction/replacement. No P2P interoperability
validation has been performed for this revision.

## Lightning

Admission no longer needs the previous whole-template Lightning exception.
Ordinary 2-of-2 funding spends prove both operands. A to_local spend has no
multisig opcode. Standard offered/received HTLC 2-of-2 branches prove their
two operands; their revocation/preimage paths do not execute CHECKMULTISIG.
These paths therefore have no key-fee floor under the executed-operand rule.
This is not a guarantee for every future channel script or presigned protocol.

## Wallet funding

Signed transaction creation obtains observations from the existing signing
verification, adjusts change or retries coin selection with bounded retries
and maximum-fee checks, and signs the final transaction. Final observations
are checked again against its actual fee. If a different final signing path
requires more, creation fails rather than silently returning an underfunded
transaction. No extra verification pass is added merely to count operands.

Unsigned funding cannot know the final execution path. Its old static helper
remains an estimate, including its bounded stack-identity normalization and
exact BOLT #3 template allowance. It is not used for mempool admission and
can overestimate or underestimate complex scripts. For unsigned Taproot
funding, the largest estimate among known leaves is reserved unless
`options.multisig_fee` specifies a nonnegative integer total key-fee floor in
satoshis. Zero can express a planned key-path spend. This replaces only the
unsigned estimate, not relay enforcement. External signers must check the
eventual fee and may need to re-fund or use an eligible package.

## Relationship to #422 and limits

The design takes inspiration from #422's unproven-key concept, but applies a
fee floor rather than classifying the excess as datacarrier usage. The new
admission counter follows actual execution instead of static push/threshold
recognition. Its treatment of dead branches and non-key data is deliberately
narrower. This is a different tradeoff, not proof of overall superiority.

The intentional free operand can carry a small payload. Dead-branch data,
other encodings and non-multisig data are not comprehensively charged; other
datacarrier rules remain independent. This is not an unbypassable general
spam detector, and it does not identify legitimate intent. No historical
transaction sample has been replayed under this revision. Presigned charged
transactions and unsupported package shapes remain compatibility concerns.

## Validation status

This revision has not been compiled or run against a node. Windows CMake /
vcpkg configuration was attempted but blocked before C++ compilation by
dependency-tool process/handle access and SDK registry access errors.
Python syntax checks are not functional test results.

Added regression cases cover real ECDSA and Schnorr spends, dynamic counts,
unrelated data in mixed scripts, witness-supplied operands, false multisig
results, per-script allowances, cache metadata misses/eviction, flags and
witness mutation, Lightning paths, and package fee boundaries/deduplication.
The existing wallet and script-estimator cases are retained. These C++ and
node-based cases still need to execute successfully before merge readiness
can be assessed; the PR must remain a draft.
