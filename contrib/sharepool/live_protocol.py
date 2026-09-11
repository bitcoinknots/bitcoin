#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Executable authenticated pool protocol reference, not activated Knots consensus.

Real synthetic BLAKE2b reward jobs, signed registry/history, append-only receipts,
immutable job updates, branch-aware pending claims. Test-framework cryptography;
coinbase-only templates, public XOR key, fixed reward, no transport or real clock.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import os

from precommit_demo import CBlockHeader, uint256_from_compact
from settlement_sim import decode_header, decode_coinbase, merkle_root
from proof_fixtures import BASE_BITS, DEFAULT_BITS
from signed_registry import (NETWORK_ID, RegistryChange, RegistrySnapshot, empty_registry,
                             apply_change, public_key, sign, verify)
from work_accounting import expected_work
from test_framework.blocktools import create_coinbase, script_BIP34_coinbase_height
from test_framework.messages import CTxOut
from test_framework.script import CScript


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(kind, value):
    return hashlib.sha256(NETWORK_ID + b"\x00" + kind + canonical(value)).digest()


def byte_field(value, size=None, maximum=65536):
    if type(value) is not bytes or not 0 < len(value) <= maximum or (size and len(value) != size):
        raise ValueError("invalid immutable byte field")


def integer(value, minimum=0, maximum=(1 << 256) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid integer field")


class MissingData(ValueError):
    pass


@dataclass(frozen=True)
class Rules:
    coordinator_key: bytes
    pool_id: bytes = b"pool-A"
    reward: int = 100003
    share_bits: int = DEFAULT_BITS
    block_bits: int = BASE_BITS
    epoch_blocks: int = 8
    window_seconds: int = 600
    cap_hashes_per_second: int = 5_000_000_000_000
    max_events: int = 128
    inflight_policy: str = "credit-and-stop"

    def __post_init__(self):
        byte_field(self.coordinator_key, 33)
        byte_field(self.pool_id, maximum=16)
        for name in ("reward", "epoch_blocks", "window_seconds", "cap_hashes_per_second", "max_events"):
            integer(getattr(self, name), 1)
        integer(self.max_events, 1, 256)
        if self.inflight_policy != "credit-and-stop":
            raise ValueError("unsupported in-flight work policy")
        for bits in (self.share_bits, self.block_bits):
            integer(bits, 1, (1 << 32) - 1)
            if bits & 0x00800000:
                raise ValueError("negative compact target")
            expected_work(uint256_from_compact(bits))
        if uint256_from_compact(self.share_bits) < uint256_from_compact(self.block_bits):
            raise ValueError("share target must include block solutions")

    def to_object(self):
        return {name: (value.hex() if type(value) is bytes else value)
                for name, value in vars(self).items()}

    @property
    def root(self):
        return digest(b"rules", self.to_object())

    @property
    def budget(self):
        return self.cap_hashes_per_second * self.window_seconds

    def epoch(self, height):
        return (height - 1) // self.epoch_blocks


@dataclass(frozen=True)
class Manifest:
    rules_root: bytes
    parent: int
    height: int
    registry_root: bytes
    ledger_root: bytes
    share_snapshot_root: bytes
    miner_id: bytes
    epoch: int
    share_bits: int
    serial: int
    payout_root: bytes

    def __post_init__(self):
        for name in ("rules_root", "registry_root", "ledger_root", "share_snapshot_root", "miner_id", "payout_root"):
            byte_field(getattr(self, name), 32)
        for name in ("parent", "height", "epoch", "share_bits", "serial"):
            integer(getattr(self, name))

    def to_object(self):
        return {name: (value.hex() if type(value) is bytes else value)
                for name, value in vars(self).items()}

    @classmethod
    def from_object(cls, obj):
        return cls(**{name: bytes.fromhex(value) if name.endswith("_root") or name == "miner_id" else value
                      for name, value in obj.items()})

    @property
    def root(self):
        return digest(b"manifest", self.to_object())


@dataclass(frozen=True)
class Job:
    manifest: Manifest
    header: bytes
    coinbase: bytes
    miner_signature: bytes
    coordinator_signature: bytes

    def __post_init__(self):
        if type(self.manifest) is not Manifest:
            raise ValueError("invalid manifest")
        for name in ("header", "coinbase", "miner_signature", "coordinator_signature"):
            byte_field(getattr(self, name))

    @property
    def payload(self):
        return canonical({"manifest": self.manifest.to_object(), "header": self.header.hex(),
                          "coinbase": self.coinbase.hex()})

    @property
    def job_id(self):
        return digest(b"job", self.payload.hex())

    def to_object(self):
        return {"manifest": self.manifest.to_object(), "header": self.header.hex(),
                "coinbase": self.coinbase.hex(), "miner_signature": self.miner_signature.hex(),
                "coordinator_signature": self.coordinator_signature.hex()}

    @classmethod
    def from_object(cls, obj):
        return cls(Manifest.from_object(obj["manifest"]),
                   *(bytes.fromhex(obj[name]) for name in
                     ("header", "coinbase", "miner_signature", "coordinator_signature")))


@dataclass(frozen=True)
class Proof:
    job_id: bytes
    header: bytes

    def __post_init__(self):
        byte_field(self.job_id, 32)
        byte_field(self.header)

    @property
    def proof_id(self):
        return decode_header(self.header).sha256.to_bytes(32, "little")

    def to_object(self):
        return {"job_id": self.job_id.hex(), "header": self.header.hex()}

    @classmethod
    def from_object(cls, obj):
        return cls(bytes.fromhex(obj["job_id"]), bytes.fromhex(obj["header"]))


@dataclass(frozen=True)
class Receipt:
    rules_root: bytes
    sequence: int
    previous_root: bytes
    kind: str
    body: bytes  # Canonical encoded proof or a seal's winning block ID.
    signature: bytes

    def __post_init__(self):
        byte_field(self.rules_root, 32)
        byte_field(self.previous_root, 32)
        byte_field(self.body)
        byte_field(self.signature)
        integer(self.sequence, 1, 256)
        if self.kind not in ("share", "seal"):
            raise ValueError("unknown receipt kind")

    @property
    def payload(self):
        return canonical({"rules_root": self.rules_root.hex(), "sequence": self.sequence,
                          "previous_root": self.previous_root.hex(), "kind": self.kind,
                          "body": self.body.hex()})

    @property
    def root(self):
        return digest(b"receipt", self.payload.hex())

    def to_object(self):
        return {**json.loads(self.payload), "signature": self.signature.hex()}

    @classmethod
    def from_object(cls, obj):
        return cls(bytes.fromhex(obj["rules_root"]), obj["sequence"],
                   bytes.fromhex(obj["previous_root"]), obj["kind"],
                   bytes.fromhex(obj["body"]), bytes.fromhex(obj["signature"]))


@dataclass(frozen=True)
class Claim:
    proof_id: bytes
    miner_id: bytes
    tag: bytes
    payout_script: bytes
    work: int
    epoch: int
    origin_parent: int
    registry_root: bytes


@dataclass(frozen=True)
class LedgerState:
    roots: tuple
    claims: tuple
    seals: tuple  # (closed parent, winning block)


@dataclass(frozen=True)
class BlockState:
    height: int
    ledger_root: bytes
    registry_root: bytes
    paid: frozenset
    winners: tuple
    balances: tuple


def payout_root(outputs):
    return digest(b"payouts", [[script.hex(), amount] for script, amount in outputs])


def coinbase(height, tag, miner_id, pool, outputs):
    tx = create_coinbase(height)
    tx.vin[0].scriptSig = bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([b"SPL1", tag, miner_id, pool]))
    if len(tx.vin[0].scriptSig) > 100:
        raise ValueError("coinbase tags exceed scriptSig bound")
    tx.vout = [CTxOut(amount, CScript(script)) for script, amount in outputs]
    return tx.serialize()


class Engine:
    """A validating replica. New payloads enter caches only after verification."""

    def __init__(self, rules):
        self.rules = rules
        self.anchor = int.from_bytes(digest(b"anchor", rules.root.hex()), "little")
        self.empty_ledger = digest(b"empty-ledger", rules.root.hex())
        registry = empty_registry(network_id=NETWORK_ID, pool_id=rules.pool_id)
        self.registries = {registry.root: registry}
        self.genesis_registry = registry.root
        self.changes, self.jobs, self.receipts, self.blocks = {}, {}, {}, {}
        self.ledgers = {self.empty_ledger: LedgerState((self.empty_ledger,), (), ())}
        self.states = {self.anchor: BlockState(0, self.empty_ledger, registry.root, frozenset(), (), ())}
        self.tip = self.anchor

    def registry(self, root):
        if root not in self.registries:
            raise MissingData("missing registry predecessor")
        return self.registries[root]

    def add_change(self, change):
        byte_field(change.entry.tag, maximum=32)
        snapshot = apply_change(self.registry(change.previous_root), change)
        if snapshot.network_id != NETWORK_ID or snapshot.pool_id != self.rules.pool_id:
            raise ValueError("wrong registry domain")
        if snapshot.root not in self.registries and len(self.registries) >= self.rules.max_events:
            raise ValueError("registry cache limit")
        self.changes[snapshot.root] = change
        self.registries[snapshot.root] = snapshot
        return snapshot.root

    def registry_extends(self, root, ancestor):
        for _ in range(self.rules.max_events + 1):
            if root == ancestor:
                return True
            if root == self.genesis_registry:
                return False
            root = self.registry(root).previous_root
        raise ValueError("registry history limit")

    def ledger(self, root):
        if root not in self.ledgers:
            raise MissingData("missing signed ledger prefix")
        return self.ledgers[root]

    def snapshot_leaves(self, root):
        ledger = self.ledger(root)
        context = canonical({"network": NETWORK_ID.hex(), "rules_root": self.rules.root.hex(),
                             "ledger_root": root.hex(), "receipt_count": len(ledger.roots) - 1})
        return (context, *(self.receipts[r].payload for r in ledger.roots[1:]))

    def snapshot_root(self, root):
        return merkle_root(self.snapshot_leaves(root))

    def state(self, parent):
        if parent not in self.states:
            raise MissingData("missing validated base parent")
        return self.states[parent]

    def ancestor(self, child, parent):
        for _ in range(self.rules.max_events + 1):
            if child == parent:
                return True
            if child == self.anchor:
                return False
            self.state(child)
            child = self.jobs[self.blocks[child].job_id].manifest.parent
        raise ValueError("base history limit")

    def claim(self, proof):
        job = self.jobs.get(proof.job_id)
        if job is None:
            raise MissingData("missing authenticated job")
        h = decode_header(proof.header)
        normalized = decode_header(proof.header)
        normalized.nNonce = 0
        normalized.m_extranonce = 0
        if normalized.serialize() != job.header:
            raise ValueError("proof changed committed job fields")
        if h.sha256 > uint256_from_compact(job.manifest.share_bits):
            raise ValueError("insufficient share proof")
        entry = self.registry(job.manifest.registry_root).entry(job.manifest.miner_id)
        return Claim(proof.proof_id, entry.miner_id, entry.tag, entry.payout_script,
                     expected_work(uint256_from_compact(job.manifest.share_bits)),
                     job.manifest.epoch, job.manifest.parent, job.manifest.registry_root)

    def claims_for(self, parent, ledger_root, registry_root=None):
        base, ledger = self.state(parent), self.ledger(ledger_root)
        if base.ledger_root not in ledger.roots:
            raise ValueError("ledger rewinds anchored prefix")
        for _, winner in ledger.seals:
            if not self.ancestor(parent, winner):
                raise ValueError("seal belongs to another base branch")
        claims = {}
        for claim in (*ledger.claims, *base.winners):
            if not self.ancestor(parent, claim.origin_parent):
                raise ValueError("share origin is on an orphaned branch")
            if claim.proof_id in claims and claims[claim.proof_id] != claim:
                raise ValueError("conflicting proof attribution")
            if registry_root is not None and not self.registry_extends(registry_root, claim.registry_root):
                raise ValueError("claim belongs to conflicting registry history")
            claims[claim.proof_id] = claim
        return claims

    def outputs(self, parent, ledger_root, registry_root, miner_id):
        base = self.state(parent)
        claims = self.claims_for(parent, ledger_root, registry_root)
        unpaid = [c for identity, c in claims.items() if identity not in base.paid]
        if not unpaid:
            # Explicit empty/unpaid-set policy: actual registered finder gets reward.
            return ((self.registry(registry_root).entry(miner_id).payout_script, self.rules.reward),), frozenset()
        weights = {}
        for claim in unpaid:
            weights[claim.payout_script] = weights.get(claim.payout_script, 0) + claim.work
        total = sum(weights.values())
        amounts = {script: self.rules.reward * work // total for script, work in weights.items()}
        order = sorted(weights, key=lambda script: (-(self.rules.reward * weights[script] % total), script))
        for script in order[:self.rules.reward - sum(amounts.values())]:
            amounts[script] += 1
        return tuple(sorted(amounts.items())), frozenset(c.proof_id for c in unpaid)

    def validate_job(self, job, *, require_miner_auth=True):
        m = job.manifest
        if m.rules_root != self.rules.root or m.share_bits != self.rules.share_bits:
            raise ValueError("job uses different rules or unapproved target")
        base = self.state(m.parent)
        if m.height != base.height + 1 or m.epoch != self.rules.epoch(m.height):
            raise ValueError("wrong job height or origin epoch")
        if not self.registry_extends(m.registry_root, base.registry_root):
            raise ValueError("registry rewinds anchored history")
        entry = self.registry(m.registry_root).entry(m.miner_id)
        if require_miner_auth and not verify(entry.signing_key, job.payload, job.miner_signature):
            raise ValueError("invalid miner job authorization")
        if not verify(self.rules.coordinator_key, job.payload, job.coordinator_signature):
            raise ValueError("invalid coordinator job authorization")
        ledger = self.ledger(m.ledger_root)
        if m.share_snapshot_root != self.snapshot_root(m.ledger_root):
            raise ValueError("snapshot Merkle root does not match signed ledger prefix")
        if m.parent != self.anchor:
            old_parent = self.jobs[self.blocks[m.parent].job_id].manifest.parent
            if (old_parent, m.parent) not in ledger.seals:
                raise ValueError("new parent requires signed old-parent seal")
        if any(closed == m.parent for closed, _ in ledger.seals):
            raise ValueError("cannot issue job on sealed parent")
        claims = self.claims_for(m.parent, m.ledger_root, m.registry_root)
        used = sum(c.work for c in claims.values() if c.tag == entry.tag and c.epoch == m.epoch)
        if used + expected_work(uint256_from_compact(m.share_bits)) > self.rules.budget:
            raise ValueError("group has no work budget for another proof")
        outputs, _ = self.outputs(m.parent, m.ledger_root, m.registry_root, m.miner_id)
        if m.payout_root != payout_root(outputs):
            raise ValueError("wrong manifest payout commitment")
        expected_coinbase = coinbase(m.height, entry.tag, entry.miner_id, self.rules.pool_id, outputs)
        if job.coinbase != expected_coinbase:
            raise ValueError("coinbase differs from registered payout allocation")
        h = CBlockHeader()
        h.m_header_v2, h.nVersion = True, 4
        h.hashPrevBlock, h.m_height = m.parent, m.height
        h.hashMerkleRoot, h.m_txcount = decode_coinbase(job.coinbase).sha256, 1
        h.nTime, h.nBits = 1700000000 + m.height, self.rules.block_bits
        h.m_mm_rhs = int.from_bytes(m.root, "little")
        if h.serialize() != job.header:
            raise ValueError("job header is not the exact approved template")
        return True

    def add_job(self, job):
        self.validate_job(job)
        if job.job_id not in self.jobs and len(self.jobs) >= self.rules.max_events * 4:
            raise ValueError("job cache limit")
        self.jobs[job.job_id] = job
        return job.job_id

    def add_receipt(self, receipt):
        if receipt.rules_root != self.rules.root or not verify(self.rules.coordinator_key, receipt.payload, receipt.signature):
            raise ValueError("invalid receipt authorization")
        old = self.ledger(receipt.previous_root)
        if receipt.sequence != len(old.roots) or receipt.sequence > self.rules.max_events:
            raise ValueError("wrong receipt sequence or history limit")
        claims, seals = old.claims, old.seals
        if receipt.kind == "share":
            obj = json.loads(receipt.body)
            if canonical(obj) != receipt.body:
                raise ValueError("noncanonical receipt body")
            proof = Proof.from_object(obj)
            claim = self.claim(proof)
            job = self.jobs[proof.job_id]
            if job.manifest.ledger_root not in old.roots:
                raise ValueError("share must commit an earlier receipt prefix")
            if any(c.proof_id == claim.proof_id for c in claims):
                raise ValueError("duplicate acknowledged proof")
            if any(parent == claim.origin_parent for parent, _ in seals):
                raise ValueError("submission after parent seal")
            for prior in claims:
                if not (self.registry_extends(claim.registry_root, prior.registry_root) or
                        self.registry_extends(prior.registry_root, claim.registry_root)):
                    raise ValueError("receipt mixes conflicting registry histories")
            claims = (*claims, claim)
        else:
            if len(receipt.body) != 32:
                raise ValueError("wrong seal winner ID")
            winner = int.from_bytes(receipt.body, "little")
            base = self.state(winner)
            if winner == self.anchor:
                raise ValueError("cannot seal with anchor")
            parent = self.jobs[self.blocks[winner].job_id].manifest.parent
            if base.ledger_root not in old.roots or any(p == parent for p, _ in seals):
                raise ValueError("seal rewinds winner prefix or repeats parent")
            self.claims_for(winner, receipt.previous_root)
            for claim in claims:
                if not (self.registry_extends(base.registry_root, claim.registry_root) or
                        self.registry_extends(claim.registry_root, base.registry_root)):
                    raise ValueError("seal includes a conflicting registry-branch tail")
            seals = (*seals, (parent, winner))
        result = LedgerState((*old.roots, receipt.root), claims, seals)
        if receipt.root not in self.receipts and len(self.receipts) >= self.rules.max_events * 2:
            raise ValueError("receipt cache limit")
        self.receipts[receipt.root], self.ledgers[receipt.root] = receipt, result
        return receipt.root

    def add_block(self, proof):
        claim = self.claim(proof)
        h = decode_header(proof.header)
        if h.sha256 > uint256_from_compact(self.rules.block_bits):
            raise ValueError("not a base-block solution")
        job = self.jobs[proof.job_id]
        self.validate_job(job)
        base = self.state(job.manifest.parent)
        outputs, paid = self.outputs(job.manifest.parent, job.manifest.ledger_root,
                                     job.manifest.registry_root, job.manifest.miner_id)
        balances = dict(base.balances)
        for script, amount in outputs:
            balances[script] = balances.get(script, 0) + amount
        state = BlockState(h.m_height, job.manifest.ledger_root, job.manifest.registry_root,
                           base.paid | paid, (*base.winners, claim), tuple(sorted(balances.items())))
        if h.sha256 not in self.blocks and len(self.blocks) >= self.rules.max_events:
            raise ValueError("block cache limit")
        self.blocks[h.sha256], self.states[h.sha256] = proof, state
        if state.height > self.states[self.tip].height:
            self.tip = h.sha256
        return h.sha256

    def pending(self, ledger_root, parent=None):
        parent = self.tip if parent is None else parent
        base = self.state(parent)
        return {identity: claim for identity, claim in self.claims_for(parent, ledger_root).items()
                if identity not in base.paid}

    def budget_violations(self, ledger_root, parent=None):
        parent = self.tip if parent is None else parent
        totals = {}
        for claim in self.claims_for(parent, ledger_root).values():
            key = (claim.epoch, claim.tag)
            totals[key] = totals.get(key, 0) + claim.work
        return {key: work for key, work in totals.items() if work > self.rules.budget}

    def export(self):
        return {"format": 1, "rules": self.rules.to_object(), "tip": self.tip,
                "changes": [c.to_object() for c in self.changes.values()],
                "jobs": [j.to_object() for j in self.jobs.values()],
                "receipts": [r.to_object() for r in self.receipts.values()],
                "blocks": [b.to_object() for b in self.blocks.values()]}

    def import_objects(self, bundle):
        if type(bundle) is not dict or bundle.get("format") != 1 or bundle.get("rules") != self.rules.to_object():
            raise ValueError("wrong transport/store rules or format")
        kinds = ("changes", "jobs", "receipts", "blocks")
        if any(type(bundle.get(kind, [])) is not list for kind in kinds):
            raise ValueError("bundle object lists required")
        if sum(len(bundle.get(kind, [])) for kind in kinds) > self.rules.max_events * 8:
            raise ValueError("bundle object limit")
        pending = [(RegistryChange.from_object(o), self.add_change) for o in bundle.get("changes", [])]
        pending += [(Job.from_object(o), self.add_job) for o in bundle.get("jobs", [])]
        pending += [(Receipt.from_object(o), self.add_receipt) for o in bundle.get("receipts", [])]
        pending += [(Proof.from_object(o), self.add_block) for o in bundle.get("blocks", [])]
        while pending:
            deferred = []
            for obj, accept in pending:
                try:
                    accept(obj)
                except MissingData:
                    deferred.append((obj, accept))
            if len(deferred) == len(pending):
                return len(deferred)
            pending = deferred
        return 0

    def save(self, path):
        path = Path(path)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(canonical(self.export()))
        os.replace(temporary, path)

    @classmethod
    def restore(cls, path, rules):
        raw = Path(path).read_bytes()
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("store size limit")
        bundle = json.loads(raw)
        result = cls(rules)
        if result.import_objects(bundle):
            raise MissingData("incomplete persisted dependencies")
        saved_tip = bundle["tip"]
        if saved_tip in result.states and result.states[saved_tip].height == result.states[result.tip].height:
            result.tip = saved_tip
        return result


def propose_job(engine, coordinator_key, miner_id, registry_root, ledger_root, parent=None, serial=0):
    """Coordinator supplies a signed candidate; it never receives a miner key."""
    parent = engine.tip if parent is None else parent
    entry = engine.registry(registry_root).entry(miner_id)
    height = engine.state(parent).height + 1
    outputs, _ = engine.outputs(parent, ledger_root, registry_root, entry.miner_id)
    m = Manifest(engine.rules.root, parent, height, registry_root, ledger_root,
                 engine.snapshot_root(ledger_root), entry.miner_id,
                 engine.rules.epoch(height), engine.rules.share_bits, serial, payout_root(outputs))
    cb = coinbase(height, entry.tag, entry.miner_id, engine.rules.pool_id, outputs)
    h = CBlockHeader()
    h.m_header_v2, h.nVersion = True, 4
    h.hashPrevBlock, h.m_height, h.m_txcount = parent, height, 1
    h.hashMerkleRoot = decode_coinbase(cb).sha256
    h.nTime, h.nBits, h.m_mm_rhs = 1700000000 + height, engine.rules.block_bits, int.from_bytes(m.root, "little")
    placeholder = Job(m, h.serialize(), cb, b"pending", b"pending")
    job = replace(placeholder, coordinator_signature=sign(coordinator_key, placeholder.payload))
    engine.validate_job(job, require_miner_auth=False)
    return job


def authorize_job(engine, proposal, miner_key):
    """Miner independently validates exact data before authorizing hardware work."""
    entry = engine.registry(proposal.manifest.registry_root).entry(proposal.manifest.miner_id)
    if entry.signing_key != public_key(miner_key):
        raise ValueError("proposal is for another miner key")
    engine.validate_job(proposal, require_miner_auth=False)
    job = replace(proposal, miner_signature=sign(miner_key, proposal.payload))
    engine.add_job(job)
    return job


def issue_job(engine, miner_key, coordinator_key, registry_root, ledger_root, parent=None, serial=0):
    """Single-process test convenience; production roles use propose/authorize."""
    matches = [entry for entry in engine.registry(registry_root).entries
               if entry.signing_key == public_key(miner_key)]
    if len(matches) != 1:
        raise ValueError("miner key is not registered")
    proposal = propose_job(engine, coordinator_key, matches[0].miner_id, registry_root,
                           ledger_root, parent, serial)
    return authorize_job(engine, proposal, miner_key)


def mine(job, *, start_nonce=0, extranonce=0, full_block=False, max_attempts=100000):
    integer(start_nonce, 0, (1 << 32) - 1)
    integer(extranonce, 0, (1 << 128) - 1)
    integer(max_attempts, 1, 100000)
    h = decode_header(job.header)
    h.m_extranonce = extranonce
    target = uint256_from_compact(h.nBits if full_block else job.manifest.share_bits)
    for nonce in range(start_nonce, min(start_nonce + max_attempts, 1 << 32)):
        h.nNonce = nonce
        if h.rehash() <= target:
            return Proof(job.job_id, h.serialize())
    raise RuntimeError("bounded synthetic nonce search exhausted")


def append_receipt(engine, coordinator_key, previous_root, *, proof=None, winner=None):
    if (proof is None) == (winner is None):
        raise ValueError("supply one share or one seal")
    old = engine.ledger(previous_root)
    body = canonical(proof.to_object()) if proof is not None else winner.to_bytes(32, "little")
    receipt = Receipt(engine.rules.root, len(old.roots), previous_root,
                      "share" if proof is not None else "seal", body, b"pending")
    receipt = replace(receipt, signature=sign(coordinator_key, receipt.payload))
    engine.add_receipt(receipt)
    return receipt
