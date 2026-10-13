# Draft: multisig key-fee accounting

This is an experimental relay-policy change, not a consensus change. The
default remains 1,000 satoshis per charged key, with one free unproven key per
inspected script. The fee floor is not added to the ordinary fee requirement;
the larger of the two applies.

## Lightning compatibility allowance

The generic counter miscounts the standard BOLT #3 `to_local`, offered HTLC,
and received HTLC scripts: their branches and stack operations prevent
adjacent-key/threshold recognition. It previously charged one key (1,000 sats)
per such input, including ordinary delayed sweeps and penalty transactions.

The complete standard templates now have an explicit zero-key-fee allowance,
including HTLC variants with and without anchors. This does not grant generic
CHECKSIG credit. It does not assert that the witness proves the embedded keys:
on the HTLC revocation path, both embedded HTLC keys really are unused and the
signature authenticates a different, witness-supplied revocation key. Avoiding
the fee on that path necessarily requires a compatibility policy choice, not
just more accurate counting under the original formula.

Matching is whole-script and bounded to 160 bytes. It requires the exact
opcodes, two minimally pushed compressed-key encodings, 20-byte hash fields,
the fixed preimage length, and minimal nonnegative u16/u32 delay/expiry fields.
No leading/trailing instructions, additional keys, larger data fields, or
nonminimal encodings receive the allowance. Tapscript is excluded. Existing
script validation still validates signatures, hashes, timelocks and execution;
this matcher does not execute the script or declare a spend valid.

This is a bounded compatibility exception, not reliable identification of
Lightning or spam. An encoder can imitate these templates and put data in
their fixed key/hash fields; the template does not establish that an actual
channel exists. In particular, a revocation spend can leave two embedded keys
uncharged. The general one-free-key allowance remains unchanged, but this is
an explicit exception to it. A canonical bpub 1-of-15 still has thirteen
charged keys. Adding a Lightning fragment to it does not exempt the script.

PR #422 at 177e5cad72982d875f2f4f4e2ed97599045b9f25 avoids this particular
Lightning charge through its ten-key allowance and unconditional CHECKSIG
credits. Even with zero credit, these two-key templates fit inside its free
allowance. This does not mean #422 added a special CPFP repair. Here the
supported Lightning templates no longer encounter this fee floor at all;
other charged scripts still cannot use a child's fee to meet their own floor.

Added regressions cover the exact templates, delay/expiry boundaries,
nonminimal fields, larger hash fields, prepended/appended payloads, and signed
P2WSH spends of all normal/revocation branches with and without anchors. These
checks have not been executed. They do not establish compatibility with every
Lightning implementation, future script variant, or package-relay scenario.

## Identity-preserving stack blocks

The static counter now symbolically checks bounded, straight-line blocks of
stack-only instructions. It skips a block only if the order and identity of
every main-stack and altstack input is restored exactly. Actual script
validation still checks stack availability and all other execution rules.

The supported instructions are NOP, DUP, 2DUP, 3DUP, DROP, 2DROP, OVER, NIP,
TUCK, SWAP, ROT, 2SWAP, 2ROT, TOALTSTACK and FROMALTSTACK. At most 32 instructions
are considered per candidate block. Values, signatures, conditions, dynamic
indices, locktimes, and arbitrary script execution are not evaluated by this
normalizer. Unsupported or non-identity blocks keep the previous counting
behavior; they are not silently treated as identity.

Three families are covered:

- Permutations which restore order, such as SWAP/SWAP or ROT/ROT/ROT.
- Duplication followed by removal, such as DUP/DROP or OVER/DROP.
- Round trips through the altstack, such as TOALTSTACK/FROMALTSTACK.

Compositions of these operations are supported when the entire examined block
provably restores both stacks. Thus a key, m/n count, or multi_a threshold is
not hidden merely by inserting such a block. Ordinary 32-byte hashes do not
become public keys just because they have the same length as x-only keys.

## Comparison target

PR #422 at commit 177e5cad72982d875f2f4f4e2ed97599045b9f25 recognizes an x-only
key using its association with a following signature opcode. The neutral stack
blocks above can break that association in its static counter. Preserving the
count across those equivalent forms is the specific improvement targeted here.
This does not establish that the entire proposal is better than #422.

There is no defined or measured "3x" improvement. Three operation families are
not a benchmark, and no performance or complete evasion-resistance claim is
made.

## Validation and limitations

Added unit cases compare canonical and transformed key counts, check hash
non-classification, and, when run, compare the supported identities with the
real interpreter. Added functional cases sign canonical and transformed
Taproot 1-of-15 and 2-of-3 spends and check the fee boundaries for all three
families. These tests have not been run and this revision has not been built.

This remains a partial static estimator. In particular, non-identity or
unsupported stack manipulation, conditions, and false-branch payload require
further design; there is no independent arbitrary-data accounting rule here.
Encoding checks are not proof of which signatures authenticated which keys.
The intentional one-key allowance permits a small amount of uncharged payload.
The fee floor is per transaction and remains non-package-aware: a CPFP child
cannot rescue a parent rejected by this floor.
