# Input Script Shapes

The scripts a transaction reveals when it spends P2SH, P2WSH and tapscript outputs are relayed and
mined only when they are a *known shape*, and the public keys and hashes in them that no witness
item proves are counted as data carrier bytes past a small allowance. Both rules live in
`src/policy/scriptshape.cpp`; the shape check is controlled by `-rejectunknownscripts` (default on,
turned off by `-corepolicy`).

## Why

Data is stored in input scripts by dressing it as fields a script would have anyway: public keys
in a 1-of-N multisig that nobody ever signs for, hashes no preimage is ever revealed for, pushes in
a branch that never runs. Counting rules written against one such shape are evaded by the next.
Accepting only shapes that real contracts use, and pricing the fields those shapes leave free, is
one rule for all of them.

## Known shapes

A revealed script is known when it is one of:

- **Sane miniscript**: `miniscript::FromScript` parses it and `IsSane()` holds (valid top level,
  satisfiable within the resource limits, non-malleable, no timelock mix, no duplicate keys, needs
  a signature). Keys are treated as opaque bytes; the P2WSH rules are applied to P2SH redeem
  scripts as well.
- **Sane miniscript behind checks**: leading `<n> OP_CHECKSEQUENCEVERIFY OP_DROP` or
  `<n> OP_CHECKLOCKTIMEVERIFY OP_DROP` runs and one leading hash check (`OP_SHA256|OP_HASH160|
  OP_HASH256|OP_RIPEMD160 <hash> OP_EQUALVERIFY`, with or without the `OP_SIZE 32 OP_EQUALVERIFY`
  guard), and the same checks trailing a sane miniscript (`OP_EQUAL` for a trailing hash). This
  covers the timelock-first and hash-first scripts of Ark, Core DAO, JoinMarket, Boltz claims and
  batch consolidations without naming them.
- **Legacy multisig**: `m <key>... n OP_CHECKMULTISIG` with 33- or 65-byte keys, in P2SH only.
  Everywhere else a key push is 33 bytes (32 in tapscript): segwit policy never lets an
  uncompressed key sign, so a 65-byte push in a P2WSH multisig slot is no key and the shape is
  unknown.
- **Tapscript thresholds** written with `OP_GREATERTHANOREQUAL` instead of `OP_NUMEQUAL`.
- **Contract templates** seen on the network: the BOLT-3 scripts (to_local, anchor, offered and
  received HTLCs with and without anchors), Phoenix swap-in, Boltz submarine swaps and their
  variants, two further swap scripts, a four-path VHTLC, a selector-prefixed federation, a
  custodial index-switch script, the Rootstock PowPeg script with its optional Flyover prefix,
  the Liquid federation layout, a two-key leaf ending in a short tag, the LND taproot revocation
  leaf (`<local_key> OP_DROP <revocation_key> OP_CHECKSIG`), and the `OP_TRUE` anchor or a bare
  timelock leaf (`<n> OP_CHECKSEQUENCEVERIFY` alone, the LND taproot anchor) spent with an empty
  witness. Templates are patterns over opcodes with typed placeholders for
  keys, hashes and numbers; keys and hashes in them are bound by signatures, preimages or keys
  the spender supplies.

Anything else is an unknown shape and the transaction is refused with
`bad-witness-script-unknown` (P2WSH, tapscript) or `bad-txns-input-script-unknown` (P2SH). With
`-rejectunknownscripts=0` the shape is logged under the `mempool` debug category instead.

Witness items a known script consumes must be a signature, a key, a preimage (up to 65 bytes,
since a hash check without a size guard takes any), a small number or empty; any other item
refuses the transaction with `...witness-item-type`. Which items count as signatures is the
script kind's call: a DER signature with its sighash byte under P2SH and P2WSH, a 64- or 65-byte
BIP340 signature in tapscript. A 64-byte preimage is no signature where ECDSA checks it.

## The field budget

Every public key and hash push in a known script is a field. Each signature in the witness
proves one field, as far as the script can check signatures (one per `OP_CHECKSIG`-family
opcode, m per m-of-n `OP_CHECKMULTISIG`); signature-shaped items past that are ordinary witness
bytes. Fields past the proven ones are free up to an allowance of 5 per input
(`-unprovenfieldallowance`, a debug option) plus one for every signature beyond the first; the
rest are counted as data carrier bytes at the average field size. Witness items other than
signatures (preimages, keys, selectors) are free up to 66 bytes per input, two keys' worth; past
that they are counted too, so a chain of hash checks satisfied with chosen preimages pays like
any other payload. Template data pushes (the tag of a tagged leaf, the PowPeg Flyover prefix)
are counted whole. These bytes join the existing data carrier count, so `-datacarriersize`
bounds them per transaction and `-datacarriercost` prices them; where the script-level count
also prices unproven keys, an input is charged the stricter of the two, never the sum. A 1-of-15 multisig spent with one
signature therefore counts 9 keys, 297 bytes, and does not relay at the default limit of 83; a
2-of-3, an 8-of-15 or a Liquid federation spend on its signed path count nothing. The same
layouts spent with few signatures pay for the keys they leave unsigned: there are no exemptions
a copy of a script could inherit.

## What is not covered

Key spends (P2PK, P2PKH, P2WPKH, taproot key path) and bare output scripts reveal no script and
are untouched. Scripts in blocks are never checked; this is relay and mining policy only.
