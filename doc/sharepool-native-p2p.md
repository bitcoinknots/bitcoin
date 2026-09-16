# Experimental SPN1 evidence on existing Bitcoin peer connections

This regtest-only relay transports complete origin templates and submitted share
proofs over the node's existing Bitcoin P2P connections. It opens no additional
listener and exposes no signer, wallet, local RPC credentials or archive methods
to peers. Native consensus enforcement and a miner's durable receipt archive
remain separate from this ephemeral transport cache.

The relay requires the active experimental `-sharepoolheight` profile and an
explicit local `setsharepoolrelay "pool_hex"` RPC. The pool must be nonzero and
cannot change until node restart. The pool filter selects relevant evidence; it
does not authenticate a coordinator, authorize a participant or establish a
quorum. A node accepts correctly validated evidence from any negotiated peer
in that pool. Payout-owner signatures and full native validation supply evidence
accountability. Connections continue to use ordinary Bitcoin peer discovery,
admission and transport configuration.

The opt-in RPC can run after Bitcoin connections are established. `spnhello`
negotiation occurs after their normal version/verack handshake. Both ends must
agree on version, genesis, rules hash, pool and exact activation height before
inventories, requests or objects are exchanged. The relay excludes feeler,
address-fetch and outbound block-only connections. An unchanged peer can ignore
the new hello command and continue ordinary Bitcoin traffic. Nodes with the
experimental profile disabled do not exchange evidence. There is no new service
bit and no change to Bitcoin `inv`, block announcements or proof-of-work rules.

## Wire format

All fixed integers use the existing Bitcoin little-endian serialization. Hashes
use `uint256` serialization; RPC hex strings are their ordinary displayed hex.
`RelayDigest` computes a single SHA256 while arranging the internal bytes so its
RPC display equals `hashlib.sha256(body).hexdigest()`. A template's identifier is
that digest of its normalized native header; a receipt's identifier is its
actual native proof hash. An item is one byte of kind (`1` template, `2` receipt)
followed by its 32-byte identifier. Zero identifiers are invalid in inventories
and requests.

| Command | Payload | Bound |
| --- | --- | --- |
| `spnhello` | version byte, genesis, rules hash, pool, activation height u32 | Exactly 101 bytes |
| `spninv` | Canonical CompactSize count and items | At most 256 items |
| `spnget` | One item and byte offset u32 | Exactly 37 bytes |
| `spndata` | Item, offset u32, total u32, complete body SHA256, canonical byte-vector chunk | At most 65,536 chunk bytes |

Inventories must be strictly sorted by kind and then the native `uint256`
comparator (lexicographic serialized identifier bytes), with no duplicates.
Templates therefore precede receipts. This helps obtain origin dependencies
before shares; an unavailable origin still causes receipt admission to fail and
be retried later. An inventory is a bounded cache listing, not proof of complete
disclosure of a round or of all work seen by the remote peer.

For an unknown or no longer eligible object, the response preserves the requested
item and offset, with total zero, null hash and empty chunk. For a known object,
each chunk contains exactly `min(65536, total - offset)` bytes. Downloaders request
offset zero first, then consecutive offsets. Every reply must preserve total
length and complete-body hash. Whole-body hash verification precedes native
admission. A template is at most 4,000,000 bytes; a receipt is at most 1,024 bytes.
No object is admitted from an unsolicited reply. Chunks let a maximum-size
template travel without exceeding the native P2P message size limit.

## Resource and validation policy

Each peer has at most one outstanding download, one bounded pending serving
request and 256 pending inventory items. Across all peers at most eight download
buffers exist, totaling at most 32,000,000 body bytes. An entire transfer expires
after 30 seconds measured by a steady clock. Expired, unavailable or rejected
items are suppressed for 10 seconds in a per-peer map limited to 256 entries.
Disconnect cleanup releases the download slot. Normal send-queue backpressure
pauses requests and responses; bounded pending state resumes when the queue and
bandwidth allowance permit it. Serving requests expire after 30 seconds too.

Each peer has token buckets for control traffic (eight initial messages,
refilling at one per second), chunk requests (128 initially, 32 per second),
received evidence payload bytes (8,000,000 initially, 1,000,000 per second) and
served chunk bytes (the same byte allowance). Inventories are advertised no
more often than once per second. Framing and token-budget violations disconnect
the connection without adding the peer to the ban list. Counts and canonical
encodings are checked before count-based allocation.

Completed bodies wait for native admission at the end of normal message-send
scheduling. Every admission attempt, including failed ones, consumes a per-peer
250 ms interval and a global 50 ms interval. Full-template admission additionally
requires a global interval of at least one second after the prior attempt, or
four times that attempt's elapsed validation time, whichever is longer. This
limits repeated script-validation work from candidate templates that are not
required to solve the block target. Native validation still takes `cs_main`, and
an individual expensive validation can delay other work while it runs; these
intervals are not a latency guarantee or a complete adversarial CPU defense.

The native store retains at most 128 full templates and 128 receipts, with a
64 MiB aggregate body limit. It prunes origins outside the active eligible
ancestry and refuses new admission when full. Full templates use the existing
native current/historical validation helper for inputs, fees, scripts, manifests
and exact coinbase payouts. Receipts use native share validation and must have
their complete, exact normalized origin already in the store. Chunk hashes are
cached after admission; serving does not repeatedly hash entire templates.

## Miner integration and trust boundary

Local RPCs `getsharepoolinventory`, `getsharepoolobject` and
`submitsharepoolevidence` connect the native relay to a miner's gate. The
`contrib/sharepool/native_node_peer.py` adapter publishes local evidence and
imports received full objects through the gate's ordinary validation methods.
Successful native relay admission is ephemeral and is never a durable miner
acknowledgment or authorization to dispatch a job. Native node restart empties
the transport cache; the durable miner archive and local recovery policy retain
their own acknowledged history.

Miners still check the candidate's exact payout commitment and their local
acknowledged eligible work before dispatch. A remote peer cannot clear a local
omission or recovery latch. Different visible inventories are possible, and
missing data does not itself prove that work was withheld. Neither a peer's
connection nor its hello makes its statement trusted. The protocol supplies no
identity uniqueness and does not solve multiple payout-address identities,
eclipse attacks, selective disclosure or global agreement about completeness.

`feature_sharepool_relay.py` exercises handshake compatibility, malformed
framing, unsolicited-data refusal, multi-chunk invalid-body refusal, global
download-slot cleanup, actual 30-second incomplete-transfer expiry and control
traffic limits using disposable regtest nodes and synthetic Bitcoin P2P peers.
It also rejects valid template/share bodies sent under the wrong announced
identity, then accepts those same bodies under their correct identities.
The suite passed on both ordinary v1 and BIP324 v2 transport; recorded commands,
binary provenance and limits are in
[`native-p2p-wire.json`](../contrib/sharepool/results/native-p2p-wire.json).
`feature_sharepool_node.py` exercises real native signed templates,
shares, miner gates and direct payout blocks across existing native connections.
These are isolated local tests, not measured WAN capacity, congestion fairness,
hostile peer-diversity, sustained CPU-load or mainnet deployment evidence. The
experimental consensus schedule remains disabled on public networks.
