# Native settlement test profile, version 1

Implementation contract for an opt-in, regtest-only native validator. All other
networks and default regtest remain unchanged. This is a new, self-contained
native profile, not native activation of the synthetic checkpoint reward ledger.

## Wire encoding

Use Bitcoin serialization (little-endian integers, canonical CompactSize for
vectors/scripts). All 32-byte hashes use their native serialized byte order.
Hash domains below include the terminating NUL byte. H is double SHA256.
Merkle roots use Bitcoin's duplicate-last algorithm, empty root zero, with leaves
already domain-separated and hashed. Lists are strictly ordered by numeric
uint256 proof ID (Python int.from_bytes(id, 'little')); duplicates reject.

Rules: MAX_SHARES=32, MAX_SHARE_AGE=3, MAX_STATE=128, MAX_MANIFEST=65536.
The approved share bits are 0x207fffff in this regtest-only profile. Its rules hash
is H("SharePool/rules/v1\0" || uint32(share_bits) || uint32(MAX_SHARE_AGE) ||
uint32(MAX_SHARES)). No percentage cap or physical TH/s inference is introduced.

Envelope, in order:

1. uint8 version=1; uint256 genesis; uint256 rules;
2. uint32 height; uint256 native_parent; uint256 pool;
3. fixed32 x-only miner public key; vector<byte> payout_script;
4. uint256 shares_root; uint256 state_root; uint256 payouts_root.

Payout scripts must have an exact standard P2PKH, P2SH, P2WPKH, P2WSH or P2TR
shape. They are compared as script bytes, never address strings. Pool is a
permissionlessly chosen nonzero 32-byte identifier. Public keys and Schnorr
signatures are verified using the native production secp256k1 implementation.

The header m_mm_rhs is H("SharePool/envelope/v1\0" || envelope). A 64-byte
BIP340 owner authorization signs H("SharePool/owner/v1\0" || genesis || rules ||
uint32(height) || native_parent || pool || public_key || vector(payout_script)).
It authorizes that key/script/pool/native round. The owner binding is in the
envelope before PoW; supplying a new signature cannot redirect a public proof.
The signature excludes the snapshot roots, containing coinbase and solved header.
The [local native signer](sharepool-native-signer.md) constrains this exact
authorization to its regtest pool/key/payout policy. It does not independently
attest to the full template or current chain state.

A state entry is uint32(origin_height), uint256(proof_id). Its leaf is
H("SharePool/state/v1\0" || entry). A share is a full native CBlockHeader,
its origin envelope, and a fixed64 owner authorization. Its leaf is
H("SharePool/share/v1\0" || share). Its proof ID is header.GetHash(), i.e. the
actual native BLAKE2b PoW hash. Different authorizations never create new credit
for the same work. Shares and state entries are ordered by that ID.

The manifest is current_envelope, fixed64 current_owner_authorization,
uint8(has_parent), then (when has_parent=1) parent_envelope,
vector(parent_state_entries), followed by vector(shares). The parent-state vector
is present even when has_parent=0 and must then be empty. No trailing data or
noncanonical reserialization is accepted. Current post-state is derived, not
duplicated in the payload. Parent envelopes contain only roots, avoiding recursive
parent-manifest inclusion.

Carrier output layout is exactly: sorted monetary payouts, canonical zero-value
manifest chunks, optional zero-value BIP141 witness commitment last. Each chunk
script is OP_RETURN followed by one minimal data push containing ASCII "SPN1",
uint16(chunk_index), uint16(chunk_count), then up to 72 payload bytes. All
non-final chunks carry 72 bytes; the final chunk is nonempty. Script length is
at most 83 bytes, respecting current RDTS limits. The serialized manifest is the
concatenation of payload bytes. Extra outputs, chunks, tags, nonzero carriers,
or misplaced witness commitments reject. The normal native witness check remains
authoritative. A payout root is H("SharePool/payouts/v1\0" || vector(CTxOut))
over monetary outputs only, so carriers cannot introduce a hash self-reference.

## Native validation and state transition

Current envelope genesis/rules/height/parent must equal native consensus context.
It must match m_mm_rhs, and the current owner authorization must verify. The
winning block keeps all normal native transaction/PoW/header/witness validation.

At the configured activation height, has_parent=0 and state is empty. Otherwise
has_parent=1; hash parent_envelope against the actual parent's m_mm_rhs, check its
genesis/rules/height/parent fields against that index, and match the supplied
parent-state root. State entries must have origin_height in
[max(1,parent_height-MAX_SHARE_AGE), parent_height]. All are sorted and unique.

Every share must have a v2 native header, flags=0, zero XOR/mask, positive
m_txcount, versionbits top bits, and an origin height j in
[max(activation_height,h-MAX_SHARE_AGE),h]. Its actual ancestor at height j-1 must
match hashPrevBlock; m_height=j, origin envelope height/parent/pool/genesis/rules
must match, and its m_mm_rhs must equal the origin envelope commitment. Its
nBits must equal GetNextWorkRequired for that ancestor, nTime must exceed the
ancestor median time and be at most settlement_block.nTime+7200. All physical
nonce/extranonce/search-time fields remain valid PoW inputs. Check native PoW at
or below the approved share target and verify the precommitted owner authorization.
This proves work on the committed header; it does not separately revalidate the
full transaction body of an unmined origin template.

Reject proof IDs already in the parent state or repeated in the current shares.
Prune parent entries with origin_height < h-MAX_SHARE_AGE, append accepted IDs,
sort, and require the resulting state root in the current envelope. The expiry
and eligibility inequalities are identical: a proof from j can be credited
through block j+3, and is ineligible at j+4. State is global across pools;
current shares must belong to the current envelope's pool.

All shares use the same approved target, hence the same expected-work weight.
Aggregate counts by the original authorized payout script. Allocate the entire
actual subsidy plus native-validated transaction fees proportionally by count,
using integer largest remainders and script-byte tie breaks; output order is
script-byte ascending. Empty snapshots pay the current authorized owner. Include
zero-value monetary outputs when rounding produces zero. Compare every amount
and script, output order and payout root exactly. Never use achieved hash as
weight. Never silently cap/discard already accepted work.

Structural/evidence/output checks run in ContextualCheckBlock and again in
ConnectBlock. The latter compares exact subsidy plus actual fees after UTXO fee
calculation, including reindex-chainstate and VerifyDB paths. No local snapshot,
sidecar, best checkpoint or external RPC contributes to consensus validity.

## Miner-side validation and evidence recovery

The native `validatesharepooltemplate` RPC validates a complete origin block at
its active-chain parent, skipping only candidate PoW. At most three recent
blocks are disconnected in a temporary UTXO view to recover the original input,
script and fee context. The live chain is not rewound. An unavailable block or
undo record, orphaned parent or expired origin prevents admission. The separate
`validatesharepoolshare` RPC validates the header proof and its attribution.

The miner gate requires that full origin validation before storing a share or
accepting one introduced through a proposed settlement job. Its local omission
policy uses durably received, eligible unpaid proofs; another node's different
receipt history cannot change native block validity. The new local peer
transport exchanges bounded inventories, full templates and proofs through this
gate. Inventories never select settlement ancestry or authorize signing.

The gate's 144-block hot cache, complete append-only archive and explicit
recovery are operational rules, not additions to the settlement wire format.
Recovery requires a protected checkpoint and full native revalidation of
currently eligible evidence.
The consensus eligibility window remains `j` through `j+3`; retaining older
evidence cannot make it payable again. See [native enforcement](sharepool-native-enforcement.md)
and [retention/recovery](sharepool-native-recovery.md) for implementation limits.

## Scope and unresolved policy

This profile verifies the selected snapshot and prevents repeat native payouts
within the exact eligibility window. It does not prove disclosure of unseen
shares or force a coordinator to include them. A miner must locally check a job
against its received eligible work before authorizing hash power. Later work and
the winning proof can be disclosed in subsequent eligible blocks; a solved
commitment is immutable. This profile replaces synthetic reward fork selection
with native-parent state; it does not transplant checkpoint-based quotas or claim
an absolute physical hash-rate cap. Registrations here are self-authorized
key/script bindings per native round, not a global identity authority.

The native signer, historical-origin RPC and earlier loopback exchange were
exercised together in the recorded 162-block integration test. The current
[P2P extension](sharepool-native-p2p.md) reuses existing Bitcoin connections;
[complete recovery](sharepool-archive-recovery.md) preserves acknowledged work
beyond hot-cache pruning. See the
[current report](../contrib/sharepool/results/native-p2p-recovery.json).
Separate native P2P/reorg/reindex cases and a deterministic sanitizer corpus
provide additional evidence. These bounded tests do not establish large-pool
performance, undisclosed-work detection, independent security review or mainnet
deployment readiness. See the [hardening report](../contrib/sharepool/results/native-hardening.json).
