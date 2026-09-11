#!/usr/bin/env python3
"""Deterministic settlement/chain simulation, NOT Knots consensus implementation.

Uses actual header-v2 hashes and serialized coinbases with synthetic easy targets.
One pool, current-parent share window, zero XOR key, fixed toy reward, no signatures,
UTXO/script validation, transaction mempool, transport, or coinbase maturity.
An issued snapshot's disclosed set is authoritative in this model: completeness
of the pool's undisclosed share history is deliberately NOT proved.
"""

from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import struct

from precommit_demo import CBlockHeader, solve_header, uint256_from_compact
from proof_fixtures import BASE_BITS, ShareProof, verify_share
from work_concentration import evaluate, expected_work
from test_framework.blocktools import create_coinbase
from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript, OP_0


NETWORK_ID = b"knots-sharepool-simulation-v1"
ANCHOR_HASH = int.from_bytes(hashlib.sha256(NETWORK_ID).digest(), "little")
BLOCK_BITS = BASE_BITS
REWARD = 100003
MAX_SHARES = 1024


def digest(kind, data=b""):
    return hashlib.sha256(NETWORK_ID + b"\x00" + kind + data).digest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _leaf(payload):
    return digest(b"leaf", len(payload).to_bytes(8, "big") + payload)


def _tree_pair(left, right):
    return digest(b"node", left + right)


def _counted_root(count, tree):
    return digest(b"root", count.to_bytes(8, "big") + tree)


def merkle_root(leaves):
    level = [_leaf(leaf) for leaf in leaves]
    if not level:
        return _counted_root(0, digest(b"empty"))
    count = len(level)
    while len(level) > 1:
        level = [_tree_pair(level[i], level[min(i + 1, len(level) - 1)])
                 for i in range(0, len(level), 2)]
    return _counted_root(count, level[0])


def inclusion_proof(leaves, index):
    if not 0 <= index < len(leaves):
        raise ValueError("leaf index outside tree")
    level, siblings = [_leaf(leaf) for leaf in leaves], []
    while len(level) > 1:
        siblings.append(level[min(index ^ 1, len(level) - 1)])
        index //= 2
        level = [_tree_pair(level[i], level[min(i + 1, len(level) - 1)])
                 for i in range(0, len(level), 2)]
    return tuple(siblings)


def verify_inclusion(leaf, index, count, siblings, root):
    if type(index) is not int or type(count) is not int or not 0 <= index < count:
        return False
    if len(siblings) != (count - 1).bit_length():
        return False
    value, width = _leaf(leaf), count
    for sibling in siblings:
        if not isinstance(sibling, bytes) or len(sibling) != 32:
            return False
        if index % 2:
            value = _tree_pair(sibling, value)
        else:
            if index + 1 >= width and sibling != value:
                return False
            value = _tree_pair(value, sibling)
        index, width = index // 2, (width + 1) // 2
    return _counted_root(count, value) == root


def share_object(share):
    return {"header": share.header.hex(), "coinbase": share.coinbase.hex(),
            "declared_tag": share.declared_tag.hex(), "pool_id": share.pool_id.hex()}


@dataclass(frozen=True)
class SnapshotBundle:
    parent_hash: int
    height: int
    shares: tuple
    pool_id: bytes = b"pool-A"
    sequence: int = 0
    previous_settlement: bytes = bytes(32)
    network_id: bytes = NETWORK_ID
    reward: int = REWARD

    def __post_init__(self):
        object.__setattr__(self, "shares", tuple(self.shares))
        if any(type(share) is not ShareProof for share in self.shares):
            raise TypeError("snapshot records must be immutable ShareProof instances")
        for name in ("pool_id", "previous_settlement", "network_id"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError("snapshot byte fields must be bytes or bytearray")
            object.__setattr__(self, name, bytes(value))
        if len(self.previous_settlement) != 32:
            raise ValueError("previous settlement must contain 32 bytes")
        if len(self.shares) > MAX_SHARES:
            raise ValueError("snapshot share count exceeds simulation limit")

    @property
    def metadata(self):
        return {"parent": f"{self.parent_hash:064x}", "height": self.height,
                "pool": self.pool_id.hex(), "sequence": self.sequence,
                "previous_settlement": self.previous_settlement.hex(),
                "network": self.network_id.hex(), "reward": self.reward}

    @property
    def leaves(self):
        return (canonical(self.metadata), *sorted(canonical(share_object(s)) for s in self.shares))

    @property
    def root(self):
        return merkle_root(self.leaves)

    def to_object(self):
        return {"metadata": self.metadata, "shares": [share_object(s) for s in self.shares]}

    @classmethod
    def from_object(cls, obj):
        m = obj["metadata"]
        shares = tuple(ShareProof(**{k: bytes.fromhex(v) for k, v in s.items()}) for s in obj["shares"])
        return cls(int(m["parent"], 16), m["height"], shares, bytes.fromhex(m["pool"]),
                   m["sequence"], bytes.fromhex(m["previous_settlement"]),
                   bytes.fromhex(m["network"]), m["reward"])


def credited_records(snapshot):
    records = tuple(verify_share(s, snapshot.parent_hash, snapshot.height, snapshot.pool_id)
                    for s in snapshot.shares)
    evaluate(records)  # Detect duplicate proof identities, including relabeled records.
    return records


def payout_plan(snapshot):
    concentration = evaluate(credited_records(snapshot))
    if concentration.total_work == 0:
        raise ValueError("empty work set")
    total = concentration.total_work
    amounts = {g.group_id: snapshot.reward * g.credited_work // total for g in concentration.groups}
    remainder_order = sorted(concentration.groups,
                             key=lambda g: (-(snapshot.reward * g.credited_work % total), g.group_id))
    for group in remainder_order[:snapshot.reward - sum(amounts.values())]:
        amounts[group.group_id] += 1
    return tuple(sorted(amounts.items()))


def settlement_coinbase(height, payouts):
    tx = create_coinbase(height)
    # Distinct synthetic recipient scripts; balances are not spendable/matured money.
    tx.vout = [CTxOut(amount, CScript([OP_0, hashlib.sha256(tag).digest()])) for tag, amount in payouts]
    return tx.serialize()


class _ExactReader(BytesIO):
    def read(self, size=-1):
        if size < 0 or size > len(self.getbuffer()) - self.tell():
            raise ValueError("truncated wire fixture")
        return super().read(size)


def _decode_wire(cls, raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise ValueError("wire fixture must contain 1..65536 bytes")
    stream, value = _ExactReader(raw), cls()
    try:
        value.deserialize(stream)
        if stream.tell() != len(raw) or value.serialize() != raw:
            raise ValueError("noncanonical wire fixture")
        value.rehash()
    except (IndexError, OverflowError, TypeError, struct.error, AssertionError) as error:
        raise ValueError("malformed wire fixture") from error
    return value


def decode_header(raw):
    return _decode_wire(CBlockHeader, raw)


def decode_coinbase(raw):
    return _decode_wire(CTransaction, raw)


@dataclass(frozen=True)
class Candidate:
    header: bytes
    coinbase: bytes

    @property
    def block_id(self):
        return decode_header(self.header).sha256

    @property
    def root(self):
        return decode_header(self.header).m_mm_rhs.to_bytes(32, "little")


def make_candidate(snapshot, salt=0, payout_override=None):
    payouts = payout_plan(snapshot) if payout_override is None else payout_override
    coinbase = settlement_coinbase(snapshot.height, payouts)
    header = CBlockHeader()
    header.m_header_v2 = True
    header.nVersion = 4
    header.hashPrevBlock = snapshot.parent_hash
    header.m_height = snapshot.height
    header.hashMerkleRoot = decode_coinbase(coinbase).sha256
    header.m_txcount = 1
    header.nTime = 1700000000 + snapshot.height
    header.nBits = BLOCK_BITS
    header.m_extranonce = salt
    header.m_mm_rhs = int.from_bytes(snapshot.root, "little")
    solve_header(header)
    return Candidate(header.serialize(), coinbase)


class Node:
    """Model node: real hashes, toy consensus and in-memory block delivery.

    cap_percent other than 10 intentionally models incompatible consensus rules.
    Local inventory/latest-proposal are NOT consensus inputs. All balances are
    provisional expected coinbase payouts on the active branch, rebuilt on reorg.
    """

    def __init__(self, name, cap_percent=10):
        if type(cap_percent) is not int or not 0 < cap_percent <= 100:
            raise ValueError("invalid cap")
        self.name, self.cap_percent = name, cap_percent
        self.blocks, self.snapshots, self.states, self.reasons = {}, {}, {}, {}
        self.known_shares, self.conflicts = set(), set()
        self.latest_snapshot = None
        self.tip = ANCHOR_HASH
        self.balances, self.consumed_shares = {}, set()
        self._proposals = {}
        self._work, self._height = {ANCHOR_HASH: 0}, {ANCHOR_HASH: 0}

    def supply_snapshot(self, expected_root, snapshot):
        if snapshot.root != expected_root:
            return False  # Wrong peer reply is not a block-invalidity proof.
        self.snapshots[expected_root] = snapshot
        key = (snapshot.pool_id, snapshot.parent_hash, snapshot.sequence)
        roots = self._proposals.setdefault(key, set())
        roots.add(expected_root)
        if len(roots) > 1:
            self.conflicts.add(key)  # Unsigned proposal conflict, not cryptographic blame.
        self.latest_snapshot = expected_root
        self.revalidate()
        return True

    def submit(self, block):
        try:
            header = decode_header(block.header)
            tx = decode_coinbase(block.coinbase)
        except (ValueError, EOFError, IndexError, AssertionError):
            return "wrong-block-payload"
        # Coinbase witness is not bound by the txid. This model has no witness
        # commitments, so a witness variant must not poison a valid header ID.
        if not tx.wit.is_null() or tx.sha256 != header.hashMerkleRoot:
            return "wrong-block-payload"
        self.blocks.setdefault(header.sha256, block)
        self.revalidate()
        return self.states[header.sha256]

    def _check(self, block_id, block):
        h = decode_header(block.header)
        target = uint256_from_compact(BLOCK_BITS)
        if (not h.m_header_v2 or h.nBits != BLOCK_BITS or h.sha256 > target or
                h.m_txcount != 1 or h.m_flags != 0 or h.m_xor_key != 0):
            return "invalid", "header-rule", None
        parent = h.hashPrevBlock
        if parent != ANCHOR_HASH:
            if parent not in self.blocks:
                return "pending", "missing-parent", None
            if self.states.get(parent) == "invalid":
                return "invalid", "invalid-ancestor", None
            if self.states.get(parent) != "valid":
                return "pending", "unvalidated-parent", None
        if h.m_height != self._height[parent] + 1:
            return "invalid", "height", None
        snapshot = self.snapshots.get(block.root)
        if snapshot is None:
            return "pending", "missing-snapshot", None
        if snapshot.root != block.root:
            return "pending", "cached-snapshot-mismatch", None
        prev_root = bytes(32) if parent == ANCHOR_HASH else self.blocks[parent].root
        if (any(type(value) is not int for value in
                (snapshot.parent_hash, snapshot.height, snapshot.reward, snapshot.sequence)) or
                snapshot.network_id != NETWORK_ID or snapshot.pool_id != b"pool-A" or
                snapshot.parent_hash != parent or snapshot.height != h.m_height or
                snapshot.previous_settlement != prev_root or snapshot.reward != REWARD or
                snapshot.sequence < 0):
            return "invalid", "snapshot-context", None
        try:
            records = credited_records(snapshot)
            concentration = evaluate(records)
            if (concentration.total_work <= 0 or any(100 * g.credited_work >
                    self.cap_percent * concentration.total_work for g in concentration.groups)):
                return "invalid", "concentration", None
            plan = payout_plan(snapshot)
            if block.coinbase != settlement_coinbase(h.m_height, plan):
                return "invalid", "payouts", None
        except (ValueError, EOFError, IndexError, AssertionError) as error:
            return "invalid", "share-or-snapshot: " + str(error), None
        return "valid", "verified", (records, plan)

    def revalidate(self):
        self.states, self.reasons = {}, {}
        self._work, self._height = {ANCHOR_HASH: 0}, {ANCHOR_HASH: 0}
        settlements = {}
        # Retry descendants whose parent arrived later or was waiting for data.
        for _ in range(len(self.blocks) + 1):
            before = dict(self.states)
            for identity, block in self.blocks.items():
                state, reason, settlement = self._check(identity, block)
                self.states[identity], self.reasons[identity] = state, reason
                if state == "valid":
                    h = decode_header(block.header)
                    self._work[identity] = self._work[h.hashPrevBlock] + expected_work(uint256_from_compact(h.nBits))
                    self._height[identity] = h.m_height
                    settlements[identity] = settlement
            if self.states == before:
                break
        highest = max(self._work.values())
        candidates = [identity for identity, work in self._work.items() if work == highest]
        if self.tip not in candidates:
            self.tip = candidates[0]  # Equal-work ties can retain first-seen branches.
        path, current = [], self.tip
        while current != ANCHOR_HASH:
            path.append(current)
            current = decode_header(self.blocks[current].header).hashPrevBlock
        balances, consumed = {}, set()
        for identity in reversed(path):
            records, plan = settlements[identity]
            consumed.update(record.share_id for record in records)
            for tag, amount in plan:
                balances[tag] = balances.get(tag, 0) + amount
        self.balances, self.consumed_shares = balances, consumed

    def save(self, path):
        path = Path(path)
        obj = {"name": self.name, "cap": self.cap_percent, "tip": f"{self.tip:064x}",
               "snapshots": [s.to_object() for s in self.snapshots.values()],
               "blocks": [{"header": b.header.hex(), "coinbase": b.coinbase.hex()} for b in self.blocks.values()]}
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(canonical(obj))
        os.replace(temporary, path)

    @classmethod
    def restore(cls, path):
        obj = json.loads(Path(path).read_text())
        node = cls(obj["name"], obj["cap"])
        for item in obj["snapshots"]:
            snapshot = SnapshotBundle.from_object(item)
            node.supply_snapshot(snapshot.root, snapshot)
        for item in obj["blocks"]:
            node.submit(Candidate(bytes.fromhex(item["header"]), bytes.fromhex(item["coinbase"])))
        saved_tip = int(obj["tip"], 16)
        if node._work.get(saved_tip) == max(node._work.values()):
            node.tip = saved_tip
            node.revalidate()
        return node
