# Running a node and mining across the BLAKE2b proof-of-work change

Status: draft, written against pull request #359 at `fee27ccfe9` and
`v29.4.1.knots20260508rc2` on 2026-08-26; updated on 2026-08-31 for
the mainnet activation and, later the same day, for
`v29.4.1.knots20260508rc5`. "Measured" means
observed on testnet4, mainnet, or a regtest node built from those
sources, on the date given. Re-check anything you rely on against the
release you actually run.

This is for people who operate a node or a miner. It does not argue for
or against the change; the specification is the code and the discussion
on #359.

## What changes, and what does not

At the activation height the block header grows from 80 bytes to a
164-byte "version 2" header, and the proof of work changes from double
SHA-256 over the header to a BLAKE2b construction. The block hash is the
proof-of-work hash, so from that height block hashes are computed
differently as well.

A version 2 header is marked by bit 31 of the version field. The first
80 bytes keep the legacy layout (version, previous block, merkle root,
time, bits, nonce); after them come two more nonces, a 16-byte
extranonce, a time offset, a transaction count, a flags byte, and the
fields for the pool-side XOR key, the block height and a merge-mining
hook. The height and transaction count in the header are consensus:
they must match the block. The time field on the wire is not always the
timestamp; when flag bit 2 is set the node adds the time offset back on
read. Software that reads headers as raw bytes needs to know both.

Everything below the header is unchanged. Transactions, txids, witness
data, the merkle root, signature hashes, PSBT, addresses, descriptors
and wallet files are the same before and after. A wallet that talks to
the node over RPC does not notice the fork. The P2P and RPC ports, the
protocol version (70016) and the network magic are unchanged.

Anything that parses or hashes block headers itself stops working at
the height unless it is updated: Electrum servers and clients,
Lightning implementations, SPV and Neutrino libraries, block explorers,
ZMQ consumers, mining software, and every SHA-256 ASIC. See "Software
that needs updating".

## Activation

The change activates at a fixed block height, `Blake2bHeight`, per
network in `src/kernel/chainparams.cpp`. There is no signaling and no
grace period: the block at that height must carry a version 2 header,
and so must every block after it. A version 2 header below the height
is rejected (`bad-version-sha256d`); a version 1 header at or above it
is rejected (`bad-version-blake2b`).

| Network | `Blake2bHeight` | State on 2026-08-31 |
|---|---|---|
| mainnet | 961640 in rc4; hardcoded in rc5 | live since 2026-08-30 06:14 UTC |
| testnet4 | 150308 in rc4 (149537 in rc2, 150027 in rc3; each cut re-forked it) | live since 2026-08-30 |
| regtest | `-testactivationheight=blake2b@N` | for testing |

Both networks are past their heights. Mainnet's fork block is 961640
(`0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb`),
and rc4 ships checkpoints at 961632 and 961639 against the transition
being replayed differently; rc5 adds one for 961640, the fork block
itself. From the activation height, SHA-256
hardware is useless on this chain; blocks it mines there are invalid.

### The first BLAKE2b difficulty

The first BLAKE2b block's target is the last SHA-256 target made
easier by a factor of 2^`Blake2bTargetShift` (22 for mainnet since rc4,
20 by default), capped at the minimum difficulty. On mainnet that put
block 961640 at difficulty 3.0e7, and enough hashrate turned up that
the first day ran a few minutes per block (measured 2026-08-30). The
first retarget, at 963648, moves difficulty toward ten-minute pacing;
until then the pace follows whatever hashrate is pointed at the chain.

## Upgrading a node

### Verify what you download

Release candidates are under
`https://test.bitcoinknots.org/~luke-jr/programs/bitcoin/files/bitcoin-knots/`
with `SHA256SUMS` and a detached `SHA256SUMS.asc` carrying signatures
from several independent Guix builders. Check the sum, then verify the
signatures against fingerprints obtained somewhere other than that
site; the names on the keys are self-asserted.
`contrib/verify-commits/trusted-keys` in the repository is the commit
signing set, not the release signing set, so it does not contain these
keys, and that is expected.

### `blake2b_headline`

The block at exactly `Blake2bHeight`, and only that block, must contain
a news headline in its coinbase scriptSig, checked by every node as a
plain substring search against its own configuration (`bad-headline`).
Mainnet's fork block was mined on 2026-08-30 carrying
`8-30 NYPost Deride And Conquer`, so the requirement is behind the
chain: miners no longer put the headline anywhere.

What remains is node configuration. rc4 refuses to start without a
`blake2b_headline` setting:

    Error: This version requires blake2b_headline set manually

and uses the value to validate the fork block, which still matters for
initial sync and reindex. Set it to the exact string above, unquoted.
A mismatched value makes the node reject the real block 961640 and
treat the peer that sent it as having sent a corrupt block (100
misbehavior points, the disconnect threshold); an empty value matches
anything and silently disables the check.

All of that is rc4 only. rc5 ships #385: the headline is hardcoded in
the mainnet chain parameters, block 961640 has a checkpoint, and the
option is reduced to a regtest-only debug setting. An rc5 node needs
no headline configuration, and a leftover bitcoin.conf line is
recognized and ignored on mainnet (measured). The one place the option
still does something is regtest, where it now requires
`-testactivationheight=blake2b@<height>` and is a startup error
without it — including when the line sits at the top level of a
bitcoin.conf shared with a regtest node (measured).

The current stable release, v29.4.0, does not know the option. On its
command line it is fatal (`Error parsing command line arguments:
Invalid parameter -blake2b_headline=...`). In `bitcoin.conf` it is a
warning (`Ignoring unknown configuration value blake2b_headline`) and
the node runs, so the line can go in before the upgrade (measured).

### Upgrading in place

An rc2 binary started on a v29.4.0 data directory loaded the block
index and chainstate without `-reindex` and went straight on syncing
(measured, testnet4). The on-disk index record for a pre-fork block is
byte-identical between the versions. No reindex, no resync.

Memory: the in-memory block index grows by about 88 bytes per block,
roughly 80 MB on a mainnet-sized chain. `consensusrules=rdts`, which
earlier 29.x releases required, is accepted and ignored by rc2.

### There is no downgrade after the fork

Once the data directory holds version 2 headers, v29.4.0 fails while
loading the block index:

    [error] LoadBlockIndexGuts: CheckProofOfWork failed: CBlockIndex(...)

A reindex under the old version would stop below the fork. If you might
need the old software again, keep a copy of the pre-fork data directory;
it is the only way back.

## Peers

Nodes running the fork advertise a new service bit, `NODE_BLAKE2B`
(bit 28, `0x10000000`), and ask DNS seeds for peers that have it with
the query `x10000009.<seed>` (NODE_NETWORK, NODE_WITNESS and
NODE_BLAKE2B). This is in rc2 and in #368; it is not in #359 itself.

On 2026-08-26 no mainnet seed returned any address for that query. The
two seeds marked in rc2 as supporting it
(`dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us` and
`seed.bitcoin.haf.ovh`) answered plain queries but had no fork-flagged
node to hand out, which is what to expect before a release ships. On
testnet4, `seed.testnet-bitcoin.haf.ovh` (added by #375) returns one
fork node; the two older testnet4 seeds return none.

When the seeds return nothing, the node connects to the seed hosts
themselves and to ordinary peers, and keeps only a limited number of
peers without the bit. A low connection count on a fork node is
expected. If you know a fork node, `addnode` it.

Whether you cross the height at all depends on having a fork peer. With
only pre-fork peers, a fork node syncs to the last SHA-256 header and
stops; the first peer that serves it version 1 headers past the height
is disconnected (measured: `getblockchaininfo` reports `headers:
149536` and stays there). With one fork peer it synced from below the
fork to the tip in under twenty seconds (measured).

To see what your node advertises:

    bitcoin-cli getnetworkinfo | grep -A8 localservicesnames

`BLAKE2B?` in that list is the bit; the question mark is how Knots
labels service bits that are not in a BIP. `getpeerinfo` shows the same
per peer under `servicesnames`.

## At the fork: what you see

Header sync runs across the height without ceremony. The `new best=`
lines in the debug log show the version with bit 31 set from the fork
block on (`version=0xa0000000` and similar). Per block:

    bitcoin-cli getblockheader <hash>

On rc2, `header_version` is 0 below the height and 2 at and above it,
and a version 2 entry carries `txcount`, `nonce2`, `nonce3`,
`extranonce`, `time_offset`, `header_flags`, `xor_key_mask_clear_bits`,
`xor_key` and `mm_rhs`. The `version` field is shown without bit 31;
read `header_version`. #359 alone does not add these fields; there the
only view of a version 2 header is the raw hex
(`getblockheader <hash> false`), 164 bytes. The RPC field set is being
settled in #363. `getblockhash <height>` needs the block itself, not only the
header, so during initial sync use a hash you already have.

`getdeploymentinfo` since rc4 reports the deployment as `blake2b`, with
`height` and `active`. #359 by itself does not report it in any RPC.

Chain work keeps the same scale across the fork, so `chainwork` in
`getblockchaininfo` barely moves after the height and `getnetworkhashps`
is not comparable across it. That is how the code is, not a sign of
trouble.

## A node that does not upgrade

Measured with a v29.4.0 node given only a fork peer on testnet4. Header
sync stopped at 148000, not at 149536. Headers arrive in batches of
2000; the batch that spans the fork holds both formats, the old parser
fails partway through it and drops the whole message, including the
1536 valid pre-fork headers in it. The failure is logged only under
`-debug=net`:

    ProcessMessages(headers, 200979 bytes): Exception 'ReadCompactSize(): size too large: iostream error' caught

The peer was not disconnected, no further headers were requested, and
`getpeerinfo` showed a healthy connection. The node looks fine and is
following nothing. With ordinary SHA-256 peers it follows the SHA-256
continuation instead. Either way it never accepts the BLAKE2b chain.

## Mining

### The stack

The node and the mining gateway both need the fork. The gateway with
BLAKE2b support is `innerhat-dev/datum_gateway` (named
`justinfilip/datum_gateway` until a 2026-08-29 account rename); the
DATUM Gateway release used for SHA-256 mining does not have it. Build
the fork separately and keep it separate from a production gateway.

### What `getblocktemplate` does

At and after the height the template's `rules` array carries
`!blake2b`. A client that does not name `blake2b` in its own `rules`
gets no template:

    error code: -8
    error message: Support for 'blake2b' rule requires explicit client support

So old pool software cannot silently mine an invalid block; it gets
nothing. Two further things a template consumer must handle:

- `version` is now the complete header version, with bit 31 set, and it
  is emitted as an unsigned number above 2147483648 (for example
  `2684354560`). Code that parses it into a signed 32-bit integer
  overflows.
- For the template at exactly the activation height — long past on
  mainnet and testnet4 — `coinbaseaux` carries `blake2b_headline` as
  hex, and the block is invalid without those bytes in its coinbase
  scriptSig. The key is absent from every other template, and rc5
  (#385) removes it entirely.

The template does not supply the header's height, transaction count,
flags, extranonce or nonce fields. The pool or gateway builds those.
The block is rejected if the header's transaction count does not match
the block (`bad-txnlist-size`) or its height does not match the chain
(`bad-header-height`).

### Gateway settings

`mining.pow_algorithm` should stay at `auto`. It follows the template
and switches at the height on its own; forcing `blake2b` on a node that
is still below the height produces blocks the node rejects.
`mining.allow_hasher_time_rolling` is off by default. Before
`justinfilip/datum_gateway#7` the gateway did not bound a rolled time
field, so leave it off unless that fix is in your build.

### Hardware

BLAKE2b and BLAKE2b-sia miners over Sia-style Stratum. On mainnet's
first day the chain ran a few minutes per block at the fork-block
difficulty, roughly 600 TH/s, from dozens of distinct coinbase tags
(measured 2026-08-30).

Sia-firmware ASICs confirmed end to end, with share and block counts,
are tracked in paulscode's compatibility matrix:
https://github.com/paulscode/datum-blake2b-startos#compatibility-matrix
(Goldshell HS-Box, SC5 Pro and SC Box II, Antminer A3, Innosilicon S11
as of 2026-08-29). Try yours on testnet4 first.

## Transactions, wallets and replay

Nothing about transactions changes, which cuts both ways.

Wallets keep working, and a transaction valid on the Knots chain before
the fork is valid after it.

There is no replay protection between this chain and the SHA-256 chain
that shares its history to block 961631. A transaction broadcast on one
can be broadcast on the other. #357 proposes an opt-in signature hash
(`SIGHASH_UNIFIED`, bit `0x20`) that a wallet on this chain would use by
default, making those transactions invalid elsewhere; it is under
review. Even with it, protection runs one way: a transaction signed the
old way, by old software or by a hardware signer that does not know the
fork, still replays in both directions. Until you know your signer opts
in, treat every spend as possibly happening on both chains.

## Software that needs updating

Only the header changed, so the list is short in kind and long in
instances: everything that hashes, measures or parses a block header.

- Electrum servers and clients (header chain, checkpoints, SPV proofs)
- Lightning implementations (block header verification)
- SPV and Neutrino libraries, and the wallets built on them
- Block explorers and chain indexers (`mempool.guide` follows both the
  Knots mainnet chain and the testnet4 fork chain)
- ZMQ `rawblock` consumers that take the first 80 bytes as the header
  (`contrib/zmq/zmq_sub.py` shows the fix), and `blk*.dat` readers
  (`contrib/linearize` was updated in #359)
- Mining software: pools, proxies, gateways, and every SHA-256 ASIC
- Bitcoin libraries with their own header type

Anything that only talks to a node over RPC is fine.

## Rehearsing on testnet4

testnet4 has run the fork since 2026-08-22, currently from block
150308 (each release candidate re-forked it; under rc4 a node from an
older candidate rewinds on its own at startup). A rehearsal node fits
alongside a production node with its own data directory and the
testnet4 ports (P2P 48333, RPC 48332 by default); the gateway needs
its own stratum and API ports too. Give the node a fork peer or the
#375 seed, sync, and watch `getblockheader` flip to `header_version: 2`
at 150308. That exercise found most of what is in this document.

## Open items on 2026-08-31

| Where | What | Matters for |
|---|---|---|
| #359 | the change itself; shipped in rc4 and rc5, not yet merged | everything |
| #385 | hardcoded headline and fork-block checkpoint; shipped in rc5, PR still open | node config |
| #358 | activation tied to RDTS; startup warning if scheduled past RDTS expiry | startup |
| #368 | `NODE_BLAKE2B` service bit and seed filter | peering |
| #375 | testnet4 seed answering the fork filter | testnet4 peering |
| #363 | version 2 header fields in RPC output | monitoring |
| #357 | opt-in signature hash, replay protection | wallets |
| #359 thread | first-retarget behavior at 963648 | mining |
