# Confirmed admitted-work ledger: experimental v5

Version 5 adds a native-chain record of admitted work and a fixed payout cutoff.
It is a separate, explicitly enabled **regtest** profile. Version 4 remains the
default hash-only profile and its wire encoding is unchanged. This work does not
activate rules on mainnet or a public testnet.

```
bitcoind -regtest -datadir=/path/to/fresh/v5-directory \
  -testactivationheight=blake2b@1 -sharepoolheight=1 \
  -sharepoolhashonly=1 -sharepooladmittedledger=1
```

Use a fresh chain and `sharepool-snapshots-v5` evidence database. Changing the
flags on an existing v4 chain is not migration. The existing native prepare,
external signer, finalize, validation and P2P snapshot interfaces support v5.
The gate selects it explicitly with `profile_version=5`. If activation is
scheduled later than height 1, pass the matching `activation_height` to the gate;
it checks the node's advertised activation height before accepting work.

## What a block proves

A valid block at height H fixes a complete snapshot. Every newly admitted proof
in that snapshot has an exact authorized template, contextual native share
target, valid native transactions, and a bound payout script. The commitment in
`m_mm_rhs` is the flat hash of the complete canonical snapshot, including all
its templates, shares and ledger state. Full bytes travel over existing Bitcoin
P2P connections; the block carries no settlement evidence or settlement Merkle
root. Bitcoin's ordinary transaction and witness commitments remain in use.

The payout cutoff for a job at H is **its actual native parent block H−1**. The
node derives the required settlement from that parent's confirmed pending
credits. The coordinator cannot remove a required credit, change its owner or
work, substitute a later credit, or change the corresponding coinbase amounts
and still produce a valid block under these rules.

A local ACK is **provisional until a block anchors the admission**. A hash cannot
prove that an undisclosed share exists or compel anyone to include it. This
profile establishes completeness relative to the confirmed record, not relative
to every hash attempt, local ACK or message that might have been sent.

## State transition and late work

1. Read and authenticate the actual parent's snapshot. At activation there is
   no prior ledger.
2. Select the oldest pending credits for this job's declared pool, ordered by
   `(admitted_height, numeric_proof_id)`. Take the largest prefix whose complete
   serialized credit vector fits 1 MiB. Selection does not depend on local
   arrival order, wall-clock ACK times or the coordinator's preferred list.
3. Compute direct coinbase payouts from those credits' original share targets
   and payout scripts, using exact integer work and the existing deterministic
   remainder allocation. The reward is the native subsidy plus verified fees.
   If that pool has no selected confirmed credits, the existing owner fallback
   receives the reward.
4. Remove only that selected prefix. Carry all other confirmed credits intact.
5. Validate new admissions from any pool and append their derived credits. They
   first become eligible for payment in a later block. Other pools can therefore
   anchor a small pool's admissions without spending its future rewards.

For example, a pool-C block can anchor two A credits and one B credit. That
block's new admissions do not change its already-fixed payout. The next A block
pays the two required A credits; the B credit remains pending until a B block
settles it. A later-arriving A share cannot change either solved block: it needs
its own subsequent admission and settlement.

Unanchored proofs retain the original height j through j+3 eligibility rule.
Confirmed pending credits do **not** expire with that proof window. They are
weights for a later reward, not fixed-denomination debts or a promise of a
payment date. A native reorg rolls admissions, pending credits and settlements
back together; a payment in a disconnected block is not final payment on the
selected chain. Consensus uses the native chain's existing fork choice.

## Canonical extension and bounded state

Version 5 retains the existing envelope, signature, normalized job commitment,
transaction table, templates, shares, recent proof index and payouts. It appends
three CompactSize-prefixed vectors:

| Vector | Record fields in wire order | Limit, including count prefix |
|---|---|---|
| `pending` | uint32 admitted height; uint32 origin height; uint256 proof ID; uint256 pool; uint32 native bits; byte-vector payout script | 4 MiB |
| `settled` | Same credit encoding | 1 MiB |
| `certificates` | uint32 origin height; uint256 native parent; uint256 exact body identity; uint256 snapshot hash | 4 MiB |

Credits sort by admitted height then numeric proof ID. Certificates sort by
serialized identity bytes. The existing `post_state` is a recent **admission**
index in v5, not evidence of payment. It prevents readmission of paid proofs
while their origins remain eligible. Pending IDs also prevent duplicates.

All snapshot bytes, including these vectors, still fit the existing 16 MiB
consensus budget. The v5 rules hash commits the v4 resource constants followed
by the three vector byte limits above. Snapshot, contents, owner and rules use
`SharePool/<name>/v5` domain strings with a terminating NUL. The normalized
`JobHash` primitive remains unchanged; the v5 owner statement binds its version,
rules, exact job and complete snapshot contents.

A certificate is generated only for a full origin of an admission validated in
a native block. Its identity hashes `SharePool/origin-certificate/v5\0`, the
normalized complete header **with `m_mm_rhs` retained**, the transaction count,
and ordered Wtxids. It therefore binds witness bytes, transactions, native
parent, ordinary commitments and the origin's snapshot hash.

Only certificates in the caller's actual confirmed native-parent state may
terminate a recursive origin check. A proposed snapshot cannot certify itself.
The origin's direct opening, binding, exact job and owner authorization are
still required. Certificates remain recent while new proofs on their origins
can be admitted. This lets a confirmed block break a worked-template dependency
chain; it does not remove the depth bound within an unconfirmed sequence.

When a new admission would exceed a state or snapshot budget, it is refused for
that batch. Existing confirmed credits are never truncated to make room. Local
receipts remain provisional and can be proposed again while still eligible.

## Boundaries still requiring production work

- **Admission availability:** miners can relay receipts to other nodes, but no
  rule here forces a native block to confirm every provisional receipt before
  it expires. Missing openings leave enforcing nodes pending.
- **Pool continuation:** payment is compulsory for a block declaring that pool.
  The protocol does not compel an operator to keep mining for that pool, or
  prove that a newly declared pool belongs to the same operator. Changing a pool
  identifier is distinct from changing payout addresses. Confirmed credits for
  abandoned pools can occupy the bounded ledger indefinitely.
- **Capacity and incentives:** preserving old credits and applying backpressure
  is safe state accounting, not a permissionless long-term service guarantee.
  Admission funding, abandoned pools, archival growth and resource pricing need
  an explicit design and sustained measurements.
- **Payout variance:** this remains one-time settlement of admitted weights. It
  is not yet a rolling PPLNS/TIDES window and does not establish the requested
  variance equivalence to a regular pool. The owner fallback also remains part
  of that unresolved payout-policy analysis.
- **Retention and operation:** finite native evidence storage, initial sync,
  reindex, slow disks, WAN partitions, deep forks and stale dispatch still need
  broader testing. Loopback regtest success is not ASIC or mainnet evidence.

See the [production gap register](sharepool-production-gaps.md) and the
[verification report](sharepool-v5-hardening-report.md) for measured results and
the precise source revision.
