# Unified opt-in signature hash

One signature hash for every input type, supplementing the three in use today
for spenders who opt in. It removes CVE-2013-2292 and CVE-2020-14199 from the
legacy and segwit v0 algorithms for the inputs that opt in, which have carried
both defects since 2013 and 2017. Opting in is the spender's choice, so it
lowers the cost an honest transaction imposes rather than bounding what an
attacker can still construct: a quadratic-hashing transaction simply does not
opt in, and worst-case block validation cost is unchanged.
Because the message it produces is distinct from every existing one, an opted-in
transaction is also protected against replay onto any chain that does not
implement it.

Status: draft.

Bitcoin specifies consensus rules in BIPs rather than in this directory. None has
been written for this change, and anything implementing it needs the rules from
somewhere, so they are recorded here until that changes.

## Motivation

Bitcoin has three signature hash algorithms in use: the original one for bare,
P2PKH and P2SH inputs, BIP143 for segwit v0, and BIP341 for taproot. The first
two have known defects that BIP341 does not have but that were never fixed for
the inputs that predate it.

**Quadratic hashing (CVE-2013-2292).** The legacy algorithm reserializes the whole
transaction once per input, so validating an n-input transaction costs O(n^2).
The Bitcoin wiki's CVE list still records its fix deployment as 0%. Measured on
the reference implementation at 1500 inputs, computing every input's message
costs 111ms under the legacy rules and 0.5ms under the rules below. BIP143,
BIP341 and the algorithm below are all free of it.

Bitcoin Knots carries a midstate cache that reduces the cost of several
signatures within one input. The serialization differs per input, so it cannot
help across inputs and does not affect the quadratic term.

**Double-signing for unintended fees (CVE-2020-14199).** BIP143 commits to the
amount of the input being signed, but not to the amounts of the other inputs. A
signing device can therefore be lied to about what a transaction is really
spending, shown a small fee, and its signatures combined across two sessions into
a valid transaction paying an enormous one. BIP341 commits to every spent amount
and does not have this defect, but it is a separate algorithm rather than a
change to BIP143: segwit v0 was never given the same treatment.

**Replay.** Where two chains share history, a transaction valid on both can be
rebroadcast from one to the other. Preventing that requires the transaction to
be invalid on any chain that does not implement this algorithm.

One algorithm addresses all three. Taproot needs neither fix, since BIP341
already has both properties, but it does need the replay protection, and
carrying it in the same algorithm leaves one message format rather than two.

## Design

The algorithm is **opt-in per signature**, selected by a bit in the hash type
byte. A spender who opts in gets the fixes and the replay protection; a spender
who does not is unaffected, with one exception set out under Compatibility below.

Replay protection follows from opting in. A node that does not know the bit
computes the legacy message for the same byte, so the signature does not verify
there. Protection runs one way: transactions made on this chain cannot be
replayed onto a chain that does not implement this algorithm.

The reverse does not hold. A signature made without the opt-in stays valid
wherever the history is shared, so anyone can rebroadcast it and the same coins
move in both places. Refusing such a transaction would mean rejecting signatures
this chain has always accepted, which is the mandatory scheme declined below.

**Protection attaches to the signature, not to the coins.** Every output that
exists today can be spent with an opted-in signature once the fork is active.
The algorithm never examines when an output was created, so there is no
distinction between coins that predate the fork and coins created after it. What
decides whether a spend is protected is whether the signer opted in.

## Activation

The rules apply to a block when its height is greater than or equal to
`Blake2bHeight`, the buried deployment the proof of work change activates at.
One trigger covers every rule the fork carries, so there is no window where one
is live and another is not. That deployment belongs to the proof of work change
and is specified there, not here.

Consensus asks whether the deployment is active *at* a block. Everything that
has to decide in advance, the mempool, the block builder and the wallet, asks
whether it is active *after* the current tip, which is the same question about
the block being built. Both are the standard buried-deployment comparisons, and
an implementation should call those helpers rather than open-code the
arithmetic: a copy that drifts is a consensus split.

Crossing the activation height invalidates something in either direction, so
neither can be ignored. A byte that opts in reads as its low bits under the
legacy algorithm today, so a signature carrying one is valid before activation
and not after; a signature made under the fork's rules is not valid before it.
A mempool entry accepted under one answer can therefore be invalid under the
other, whether the chain reached the height by a reorg or by ordinary forward
progress, and the block assembler cannot skip an entry that has become invalid.
An entry is dropped when its recorded state disagrees with the block being built
*and* it carries a signature that opted in, since no other entry reads
differently on the two sides; see *Implementation notes* below.

## Specification

### Hash type byte

```
SIGHASH_ALL           0x01
SIGHASH_NONE          0x02
SIGHASH_SINGLE        0x03
SIGHASH_UNIFIED       0x20
SIGHASH_ANYONECANPAY  0x80
```

A signature uses the algorithm below if and only if `SIGHASH_UNIFIED` is set. The byte
is committed to by the signature, so the bit cannot be added or removed by a
third party without invalidating it.

Each script type keeps the reading it has today. For bare, P2SH and segwit v0
that is the legacy one: `SIGHASH_SINGLE` signs the output at the input's index,
`SIGHASH_NONE` signs none, any other value signs them all, and
`SIGHASH_ANYONECANPAY` has its usual meaning. Remaining bits carry no meaning and
are committed to with the rest of the byte, so every distinct byte is a distinct
message. Bytes outside the three named output types stay non-standard and stay
valid for those script types, exactly as today, since the defined-hashtype check
is policy rather than consensus there.

For taproot and tapscript it is BIP341's: a hash type it does not define is
refused, at consensus rather than by policy, so the bytes it reserved stay
reserved. Only `SIGHASH_ALL`, `SIGHASH_NONE` and `SIGHASH_SINGLE`, with or
without `SIGHASH_ANYONECANPAY`, carry the opt-in bit there.

Opting in changes which message is signed and nothing else.

Before activation, `SIGHASH_UNIFIED` is not a defined hash type. Under
`SCRIPT_VERIFY_STRICTENC` such a signature is rejected outright, and without it
the legacy message is computed and the signature does not verify. Opting in early
is therefore neither relayable nor minable.

### Message

Let `spent_outputs` be the outputs being spent, one per input, in input order.

Define these, each a single SHA256 over the concatenation of the listed
serializations, using Bitcoin's usual encodings:

```
sha_prevouts   = SHA256( for each input:  outpoint (32-byte hash, 4-byte index LE) )
sha_amounts    = SHA256( for each spent output:  value (8-byte signed LE) )
sha_scripts    = SHA256( for each spent output:  scriptPubKey (compact-size length, then bytes) )
sha_sequences  = SHA256( for each input:  nSequence (4-byte LE) )
sha_outputs    = SHA256( for each output:  value (8 bytes LE), scriptPubKey (compact size, bytes) )
```

The message is the concatenation below, and the signature hash is
`TaggedHash("UnifiedSighash", message)` as defined by BIP340, that is
`SHA256( SHA256(tag) || SHA256(tag) || message )`.

```
  1 byte    script type: 0 bare or P2SH, 1 segwit v0, 2 taproot key path,
             3 tapscript
  4 bytes   hash type, little endian
  4 bytes   transaction version, little endian
  5 bytes   transaction locktime, little endian, zero-extended

  if ANYONECANPAY is not set:
 32 bytes   sha_prevouts
 32 bytes   sha_amounts
 32 bytes   sha_scripts
 32 bytes   sha_sequences

  if hash_type & 0x1f == SIGHASH_SINGLE:
 32 bytes   SHA256( output at the same index as this input )
             invalid if no output exists at that index
  else if hash_type & 0x1f == SIGHASH_NONE:
             nothing
  otherwise:
 32 bytes   sha_outputs
             every value that is not SINGLE or NONE signs all outputs,
             as the legacy algorithm does. Script types 2 and 3 accept
             only SIGHASH_ALL, SIGHASH_NONE and SIGHASH_SINGLE, so the
             fallthrough is reachable for script types 0 and 1 only.

  if ANYONECANPAY is set:
 36 bytes   this input's outpoint
  variable  this input's spent output (value, then scriptPubKey)
  4 bytes   this input's nSequence
  otherwise:
  4 bytes   this input's index, little endian

  then the tail for this script type.

  for script types 0 and 1:
  variable  scriptCode (compact-size length, then bytes)

  for script types 2 and 3:
  1 byte    1 if an annex is present, else 0
 32 bytes   SHA256 of the annex (compact-size length, then bytes), if present

  for script type 3 only:
 32 bytes   tapleaf hash, as BIP341 defines it
  1 byte    key version, 0
  4 bytes   codeseparator position, little endian, 0xffffffff if none
```

The locktime occupies four bytes in a transaction but five here. Four run out
on 2106-02-07, and a later hardfork that widened the field would otherwise have
to change this message and invalidate every signature already made under it. The
fifth byte is zero until something sets it, so it costs nothing now and cannot
be added later. Height and time are not distinguished here: the message commits
to the value, and `LOCKTIME_THRESHOLD` decides which it means during validation,
which leaves that split untouched by the wider field.

`scriptCode` is what the legacy rules already use: the scriptPubKey for a bare
input, the redeemScript for P2SH, the witnessScript for P2WSH, and for P2WPKH the
implied P2PKH script as in BIP143. Where `OP_CODESEPARATOR` has executed, it is
the portion of the script following it, exactly as today.

For script type 0 this includes the legacy removal of the signature from the
script before hashing, the operation the original algorithm performs and BIP143
dropped. It applies here because the script interpreter performs it before any
signature hash is computed, and opting in must not change how an existing script
is evaluated. It is a no-op for every script that does not contain the signature
being checked. Script type 1 does not perform it, matching BIP143.

Three differences from the legacy algorithm, all reachable only by signatures
that opted in:

* `SIGHASH_SINGLE` with no output at the input's index is invalid, as in BIP341.
  The two algorithms this replaces both allow it: the legacy one returns the
  constant 1 as the message, and BIP143 substitutes a zero hash for the outputs.
  Both are signable, and neither is carried over.
* The script type byte separates the four script types, so a signature made for
  one can never be valid for another.
* `SIGHASH_NONE` and `SIGHASH_SINGLE` still commit to every input's `nSequence`,
  as BIP341 does. The legacy algorithm zeroes the others and BIP143 omits the
  aggregate, so a protocol that relies on a counterparty being able to raise
  `nSequence` under those types does not carry over.

Under `ANYONECANPAY` the input's position is not committed to, so the input may
still be moved into another transaction. Its own outpoint, spent output and
sequence are committed to directly, since the aggregates are absent.

### What an implementation needs

The message is shaped like BIP341's, but implementing it does not require
implementing BIP341. There is no Schnorr signature, no x-only public key, no key
tweaking and no control block: signatures over this message are made and verified
exactly as they are today for the script type in question.

A signer that does not support taproot implements script types 0 and 1 and never
encounters the rest. Against BIP143 it needs the same aggregate hashes with a
single SHA256 rather than a double one, two further aggregates over every input's
amount and scriptPubKey, and the BIP340 tagged hash.

The one new requirement is data rather than code. BIP143 commits to the amount of
the input being signed; this commits to the amount and scriptPubKey of every
input, so a signer needs all of the outputs being spent. PSBT already carries
them per input. That requirement is inherited from BIP341, and is what closes
CVE-2020-14199.

### Taproot and tapscript

Taproot spends use the same algorithm as every other script type. BIP341's own
digest is not involved once a signature opts in, and BIP341 itself is unchanged:
a node without the fork computes BIP341 for the same byte, does not recognise the
hash type, and rejects the spend.

The message is the one above, with the script type byte set to 2 for a key path
spend and 3 for a tapscript spend, and with the taproot tail in place of
`scriptCode`.

The tail is required. An uncommitted annex is malleable, and without the tapleaf
hash a signature made for one script leaf would be valid for any other leaf under
the same key. The codeseparator position serves the same purpose it serves
elsewhere. These live outside the transaction, so the script interpreter supplies
them rather than reading them from it.

The hash type is read under BIP341's rule rather than the legacy one: a byte it
does not define is refused. See *Hash type byte* above.

`SIGHASH_DEFAULT` cannot be used with `SIGHASH_UNIFIED`: it means "append no hash
type byte at all", so there would be nothing to carry the bit. An opted-in taproot
signature is therefore always 65 bytes, which is the size wallets already budget
for. A byte holding only `SIGHASH_UNIFIED` is a distinct byte and so a distinct
message, not a second spelling of `SIGHASH_DEFAULT`.

### What this fixes

Every spent amount and scriptPubKey is committed to, so a signer cannot be lied
to about any input's value. That closes CVE-2020-14199.

The per-input work is one hash over a fixed-size preimage plus the scriptCode.
The aggregates are computed once per transaction. Validation is therefore linear
in the number of inputs, closing CVE-2013-2292 for inputs that opt in.

## Test vectors

`src/test/data/unified_sighash.json` contains 166 vectors covering all four script
types: scriptCode, raw transaction, input index, hash type, script type, the
spent outputs, and the expected signature hash. Hashes are raw bytes, not the
reversed display order. For tapscript vectors the scriptCode column holds the
leaf script, and the vectors assume no annex and no executed
`OP_CODESEPARATOR`.

Three implementations agree on them: the reference one, a second written
separately in `test/functional/test_framework/script.py`, and a third written
from this document alone, which reproduces all 166. The third is what checks this
text for completeness: an ambiguity in any script type would show up as a
mismatch.

Agreement establishes that the three are consistent and that this document
describes them. It does not establish that the design is correct, since all three
share an author.

The functional test signs taproot and tapscript from the second implementation
and a real node accepts the result, which exercises the tapleaf hash and
codeseparator commitments end to end.

## Prior art

The mechanism is not new. A bit in the hash type byte selecting a different
digest, signatures without the bit unaffected, and the bit rejected until
activation through a script flag: that shape has been in production on other
chains for years, which is the argument for not inventing a new one.

Those digests are derived from BIP143 rather than BIP341, so they commit to the
value of the input being signed and no other, and they identify their chain with
a numeric field in the hash type where this uses the tag.

## Decisions

**`SIGHASH_UNIFIED = 0x20`.** The low five bits carry the output type and `0x80`
carries `ANYONECANPAY`, which leaves `0x20` and `0x40` as the only bits free to
define. Neither is untouched on mainnet, so the exception under *Compatibility*
below is unavoidable either way.

`0x40` carries the same role on other chains, where it selects their digest. A
signer that recognises that byte would compute their message rather than this
one, producing a signature that fails for a reason it cannot report. An undefined
byte fails immediately, and fails legibly.

**The tag string is `"UnifiedSighash"`.** The signature hash is a tagged hash,
the way BIP341 uses `"TapSighash"`, and the string cannot change after
deployment without invalidating every signature made under it and every vector
here.

It names the algorithm, following that convention. Its job is to keep this
message distinct from every other BIP340 tagged hash, not to separate one chain
from another: anything implementing this specification copies the tag with it.

**Opt-in rather than mandatory.** Nothing a wallet, signer or service produces
today stops being valid at activation. Protection still reaches ordinary users,
because a wallet that knows about the fork opts in on their behalf without being
asked.

**Compatibility.** The claim above holds for everything reachable in practice,
but not for every conceivable script. The check that a hash type is one of the
defined values is policy, not consensus: `SCRIPT_VERIFY_STRICTENC` is absent from
the mandatory flags, and the legacy message commits to the byte whatever it is.
So a bare, P2SH or segwit v0 signature whose hash type already has this bit set
is consensus-valid today, and after activation it is read under the new algorithm
and stops verifying.

What that costs depends on who still holds the key. A signature can be replaced,
so for a live wallet this is an inconvenience: sign again after activation. Where
the signature was made in advance and the key deliberately destroyed, as a
pre-signed refund or an inheritance path does, there is nothing left to sign
with and the output cannot be spent. That is a loss of funds, and it is worth
naming as one.

Reaching that state takes deliberate effort. Such a transaction is non-standard,
so no node relays it and it can only enter a block direct from a miner, and it
has to have been signed before activation and held. No choice of bit avoids it:
consensus accepts every hash type byte for these input types, so there is no
unused value to claim. Taproot is unaffected, since BIP341 already makes
undefined hash types invalid at consensus.

The choice has a cost. Protection reaches a spender only if their signer knows
about the fork. A signature produced by one that does not, an external signer, a
hardware device on old firmware, a co-signer running older software, remains
valid, so the transaction confirms and nothing reports a problem, but it carries
no replay protection.

Mandatory opting in would remove that case and break every such signer at
activation instead. Surfacing it to the user is a wallet behavior rather than a
consensus rule, and is not specified here.

**One algorithm for every script type.** Taproot uses the same signature hash as
bare, P2SH and segwit v0 inputs rather than keeping BIP341's, so there is a
single message format rather than one per script type.

The cost is that a signer implementing BIP341 cannot sign here by setting a bit;
it has to implement this algorithm. The benefit is a single message format to
specify, implement, test and review, and a single place for a future defect to be
fixed.

Taproot keeps the parts of its message that carry meaning the others do not: the
annex hash, the tapleaf hash and the codeseparator position. Dropping them would
make a signature for one script leaf valid for another.

Opted-in taproot spends give up `SIGHASH_DEFAULT` and its one-byte saving, since
a bit needs a byte to live in.

**Activation offset.** None. Both this rule and the proof of work change activate
at the same height, so there is no window in which blocks are mined under the new
proof of work while opting in is unavailable. An offset between two triggers
would have needed a constant sized against how slow blocks run immediately after
the fork, which cannot be given confidently and cannot be changed once deployed.

## Tooling

`bitcoin-tx` has no chain access, so it cannot work out whether the hardfork is
active. It takes `-unifiedsighash` to sign this way, and the same flag is needed to
recognise an existing signature of this kind when combining. Without it the tool
produces legacy signatures, which stay valid but carry no replay protection.

`libbitcoinconsensus` is in the same position and takes
`bitcoinconsensus_SCRIPT_FLAGS_VERIFY_UNIFIED_SIGHASH`. It also needs the spent
outputs whenever that flag is set, for the reason taproot already needs them
there: the message commits to every spent amount and scriptPubKey, on inputs
carrying no witness as well.

Everything with chain access decides on its own, from the rules of the block
being built rather than the tip's: the wallet, `signrawtransactionwithkey`, the
PSBT RPCs, `combinerawtransaction`, and the GUI.

## Implementation notes

Verification is selected entirely by the script flags plus the hash type byte.
Nothing else carries a copy of that decision, because a verifier holding its own
copy can disagree with the signer and split consensus.

`SCRIPT_VERIFY_UNIFIED_SIGHASH` is unlike every other script flag. The others only
ever make scripts fail that would otherwise pass. This one is a switch: it makes
opted-in signatures valid that were not, and it makes others invalid that were,
because a byte the legacy algorithm reads as an output type means "opted in"
once the flag applies, and the message changes with it. The usual argument that
anything accepted by policy is valid under consensus therefore does not hold,
and the mempool must derive the flag from the rules of the block being built
rather than from the tip.

It follows that the mempool has to be reconciled whenever the chain crosses the
height, in either direction. Handling only the reorg leaves an entry accepted
before activation sitting in the pool afterwards, and block production stops on
that node from the first block that enforces the fork.

An entry has to be dropped when the answer recorded on it disagrees with the
block about to be built, in either direction, *and* the transaction carries a
signature that opted in. Whether it was accepted under the fork's rules is
recorded on the entry rather than recomputed later: recomputing means trusting
that the chain still says the same thing about a height it may have replaced.

The second condition matters as much as the first. Only an opted-in signature
reads differently on the two sides, so dropping on the recorded state alone
empties every mempool on the network at the crossing block and discards
payments already in flight for a rule that does not apply to them. Detecting it
is a read of the input bytes, not a verification: a 65-byte Schnorr signature,
or a DER signature followed by one hash type byte, with that bit set. Err
towards dropping when a push cannot be ruled out as a signature.

Both directions matter because the flag is a switch. Gaining the fork invalidates
an entry whose legacy signature carries the opt-in bit, and losing it invalidates
one that opted in. The chain reaches the height by ordinary forward progress as
well as by reorg, and the forward path disconnects nothing, so an implementation
that reconciles only on reorg leaves the first case in the pool and stops making
blocks.

### Relationship to the proof-of-work change

This is built on that change rather than beside it, so `DEPLOYMENT_BLAKE2B` and
`Blake2bHeight` are declared there and used here. Both sets of rules activate at
that one deployment, so the fork takes effect at a single block and there is no
window where one applies without the other.

Two things follow for anyone reading the tests. A block at or after the
activation height must carry the v2 header, which states its own height and
transaction count, and a node refuses one that does not: first
`bad-version-blake2b`, then `bad-txnlist-size` once the version is right. Blocks
the framework solves for itself therefore go through the two helpers at the top
of `feature_unified_sighash.py` rather than calling `create_block` directly.
Asking the node for a block template also requires naming the `blake2b` rule.

The wallet still asks whether the fork applies to the next block before it
signs, because the deployment is scheduled on no network yet. Once it has a
height everywhere the wallet runs, that question and the plumbing that carries
its answer from the GUI can go.

## Interaction with PSBT

A PSBT input may declare a sighash type. When it is present it is compared
against the type the signer was asked for, and the opt-in bit is reconciled
rather than compared literally: the bit comes from chain state, not from the
request, so a field carrying it and a request without it mean the same
signature. A request that demands the bit when the signer is not opting in is a
real disagreement and is refused.

A signer that adds a signature also records the effective type in the field, so
the field and the hash type byte on the signature agree. Only the call that
produced the signature does this: a finalizer or an update pass holds no key,
and rewriting a type it did not sign for would lock out a co-signer that
declared something else.

The cost is that a PSBT carrying an opted-in type is unreadable to a signer that
rejects hash types it does not know. That is unavoidable for any encoding of
this: the alternative leaves the field disagreeing with the signature, which an
implementation requiring the two to match rejects instead.

## References

* BIP68, relative lock-time using consensus-enforced sequence numbers: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
* BIP113, median time-past as endpoint for lock-time calculations: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
* BIP143, transaction signature verification for version 0 witness program: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
* BIP340, Schnorr signatures for secp256k1, defining the tagged hash: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
* BIP341, taproot: SegWit version 1 spending rules: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
* BIP342, validation of taproot scripts: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
* CVE-2013-2292, quadratic hashing: https://www.cve.org/CVERecord?id=CVE-2013-2292
* CVE-2020-14199, signing without committing to every input amount: https://www.cve.org/CVERecord?id=CVE-2020-14199
* Bitcoin wiki, Common Vulnerabilities and Exposures, which records CVE-2013-2292 at 0% fix deployment: https://en.bitcoin.it/wiki/Common_Vulnerabilities_and_Exposures
