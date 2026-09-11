#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Permissionless PoW accounting experiment; NOT Knots consensus or fork choice.

Anyone may mine a parent-linked checkpoint, including an empty heartbeat. The
selected branch has the greatest verified checkpoint work (lowest ID on ties).
Reward history here is provisional, synthetic, and reorganizes with that branch.
Epochs count checkpoints, not seconds. Fixture targets and crypto are for labs.
"""
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path

from live_protocol import (Manifest, Proof, Claim, MissingData, canonical, digest,
                           byte_field, integer, coinbase, decode_header,
                           decode_coinbase, payout_root)
from precommit_demo import CBlockHeader, uint256_from_compact
from proof_fixtures import DEFAULT_BITS, BASE_BITS
from settlement_sim import merkle_root
from signed_registry import (NETWORK_ID, RegistryChange, RegistrySnapshot,
                             empty_registry, apply_change, public_key, sign, verify)
from work_accounting import expected_work


def fields(obj, names):
    if type(obj) is not dict or set(obj) != set(names):
        raise ValueError("noncanonical object fields")


def unhex(value, size=None, maximum=65536):
    if type(value) is not str or len(value) > maximum * 2:
        raise ValueError("invalid hex field")
    raw = bytes.fromhex(value)
    byte_field(raw, size, maximum)
    if raw.hex() != value:
        raise ValueError("noncanonical hex field")
    return raw


@dataclass(frozen=True)
class PowRules:
    pool_id: bytes = b"pool-A"
    reward: int = 100003
    share_bits: int = DEFAULT_BITS
    block_bits: int = BASE_BITS
    checkpoint_bits: int = DEFAULT_BITS
    epoch_checkpoints: int = 8
    max_job_age: int = 3
    cap_hashes_per_second: int = 5_000_000_000_000
    window_seconds: int = 600
    max_checkpoints: int = 4096
    max_actions: int = 128
    max_payload_bytes: int = 262144
    protocol: str = "sharepool-pow-ledger-v1"
    budget_basis: str = "payout-script"
    renewal_basis: str = "checkpoint-height"
    inflight_policy: str = "credit-and-stop"

    def __post_init__(self):
        byte_field(self.pool_id, maximum=16)
        integer(self.reward, 1, 21_000_000 * 100_000_000)
        for name in ("epoch_checkpoints", "cap_hashes_per_second", "window_seconds"):
            integer(getattr(self, name), 1, (1 << 63) - 1)
        integer(self.max_job_age, 0, 4096)
        integer(self.max_checkpoints, 1, 4096)
        integer(self.max_actions, 1, 128)
        integer(self.max_payload_bytes, 2, 1024 * 1024)
        if (self.protocol, self.budget_basis, self.renewal_basis, self.inflight_policy) != (
                "sharepool-pow-ledger-v1", "payout-script", "checkpoint-height", "credit-and-stop"):
            raise ValueError("unsupported accounting rules")
        for bits in (self.share_bits, self.block_bits, self.checkpoint_bits):
            integer(bits, 1, (1 << 32) - 1)
            if bits & 0x00800000:
                raise ValueError("negative compact target")
            expected_work(uint256_from_compact(bits))
        if uint256_from_compact(self.share_bits) < uint256_from_compact(self.block_bits):
            raise ValueError("share target must include block solutions")

    def to_object(self):
        return {k: v.hex() if type(v) is bytes else v for k, v in vars(self).items()}

    @property
    def root(self):
        return digest(b"pow-ledger-rules", self.to_object())

    @property
    def budget(self):
        # A numeric work allowance. These names preserve the illustrative input
        # conversion; checkpoint epochs do NOT last window_seconds of real time.
        return self.cap_hashes_per_second * self.window_seconds

    def epoch(self, height):
        integer(height, 0, (1 << 63) - 1)
        return height // self.epoch_checkpoints


@dataclass(frozen=True)
class WorkJob:
    manifest: Manifest
    header: bytes
    coinbase: bytes
    miner_signature: bytes

    def __post_init__(self):
        if type(self.manifest) is not Manifest:
            raise ValueError("invalid job manifest")
        for name in ("header", "coinbase", "miner_signature"):
            byte_field(getattr(self, name), maximum=4096)

    @property
    def payload(self):
        return canonical({"domain": "sharepool-pow-job-v1", "manifest": self.manifest.to_object(),
                          "header": self.header.hex(), "coinbase": self.coinbase.hex()})

    @property
    def job_id(self):
        return digest(b"pow-ledger-job", self.payload.hex())

    def to_object(self):
        return {"manifest": self.manifest.to_object(), "header": self.header.hex(),
                "coinbase": self.coinbase.hex(), "miner_signature": self.miner_signature.hex()}

    @classmethod
    def from_object(cls, obj):
        fields(obj, ("manifest", "header", "coinbase", "miner_signature"))
        fields(obj["manifest"], Manifest.__dataclass_fields__)
        manifest = Manifest.from_object(obj["manifest"])
        if manifest.to_object() != obj["manifest"]:
            raise ValueError("noncanonical manifest")
        return cls(manifest, *(unhex(obj[k], maximum=4096)
                              for k in ("header", "coinbase", "miner_signature")))


@dataclass(frozen=True)
class LedgerView:
    rules_root: bytes
    registry: RegistrySnapshot
    height: int
    chainwork: int
    reward_tip: int
    reward_height: int
    claims: tuple
    paid: frozenset
    balances: tuple
    reward_history: tuple

    @property
    def root(self):
        context = {"kind": "pow-ledger-state", "rules": self.rules_root.hex(),
                   "registry": self.registry.root.hex(), "height": self.height,
                   "chainwork": self.chainwork, "reward_tip": self.reward_tip,
                   "reward_height": self.reward_height}
        leaves = [canonical(context)]
        for claim in self.claims:
            leaves.append(canonical({"kind": "claim", **{
                k: v.hex() if type(v) is bytes else v for k, v in vars(claim).items()}}))
        leaves.extend(canonical({"kind": "paid", "id": identity.hex()})
                      for identity in sorted(self.paid))
        leaves.extend(canonical({"kind": "balance", "script": script.hex(), "amount": amount})
                      for script, amount in self.balances)
        leaves.extend(canonical({"kind": "reward", "parent": parent, "winner": winner})
                      for parent, winner in self.reward_history)
        return merkle_root(leaves)


@dataclass(frozen=True)
class Checkpoint:
    rules_root: bytes
    parent: bytes
    height: int
    payload: bytes
    state_root: bytes
    nonce: int

    def __post_init__(self):
        for name in ("rules_root", "parent", "state_root"):
            byte_field(getattr(self, name), 32)
        byte_field(self.payload, maximum=1024 * 1024)
        integer(self.height, 1, (1 << 63) - 1)
        integer(self.nonce, 0, (1 << 64) - 1)
        self.actions()

    def actions(self):
        value = json.loads(self.payload)
        if type(value) is not list or len(value) > 128 or canonical(value) != self.payload:
            raise ValueError("noncanonical checkpoint actions or action limit")
        return value

    @property
    def checkpoint_id(self):
        actions = self.actions()
        header = canonical({"domain": "sharepool-pow-checkpoint-v1", "rules": self.rules_root.hex(),
                            "parent": self.parent.hex(), "height": self.height,
                            "action_count": len(actions),
                            "action_root": merkle_root([canonical(a) for a in actions]).hex(),
                            "state_root": self.state_root.hex(), "nonce": self.nonce})
        return hashlib.blake2b(header, digest_size=32).digest()

    def to_object(self):
        return {k: v.hex() if type(v) is bytes else v for k, v in vars(self).items()}

    @classmethod
    def from_object(cls, obj):
        fields(obj, cls.__dataclass_fields__)
        return cls(**{k: unhex(v, maximum=1024 * 1024) if k in
                      ("rules_root", "parent", "payload", "state_root") else v
                      for k, v in obj.items()})


class PowLedger:
    """Fully replayed bounded reference store. Missing data never earns work."""
    def __init__(self, rules):
        if type(rules) is not PowRules:
            raise ValueError("PoW rules required")
        self.rules = rules
        self.genesis = digest(b"pow-ledger-genesis", rules.root.hex())
        anchor = int.from_bytes(digest(b"pow-reward-anchor", rules.root.hex()), "little")
        state = LedgerView(rules.root, empty_registry(network_id=NETWORK_ID, pool_id=rules.pool_id),
                           0, 0, anchor, 0, (), frozenset(), (), ())
        self.tip, self.checkpoints, self.states = self.genesis, {}, {self.genesis: state}

    def state(self, checkpoint=None):
        checkpoint = self.tip if checkpoint is None else checkpoint
        if checkpoint not in self.states:
            raise MissingData("missing validated checkpoint")
        return self.states[checkpoint]

    def ancestor(self, child, parent):
        self.state(parent)
        while True:
            self.state(child)
            if child == parent:
                return True
            if child == self.genesis:
                return False
            child = self.checkpoints[child].parent

    def pending(self, checkpoint=None):
        view = self.state(checkpoint)
        return {c.proof_id: c for c in view.claims if c.proof_id not in view.paid}

    def budget_violations(self, checkpoint=None):
        totals = {}
        for claim in self.state(checkpoint).claims:
            key = (claim.epoch, claim.payout_script)
            totals[key] = totals.get(key, 0) + claim.work
        return {key: work for key, work in totals.items() if work > self.rules.budget}

    def outputs(self, checkpoint, miner_id):
        view = self.state(checkpoint)
        unpaid = self.pending(checkpoint)
        if not unpaid:
            return ((view.registry.entry(miner_id).payout_script, self.rules.reward),), frozenset()
        weights = {}
        for claim in unpaid.values():
            weights[claim.payout_script] = weights.get(claim.payout_script, 0) + claim.work
        total = sum(weights.values())
        amounts = {script: self.rules.reward * work // total for script, work in weights.items()}
        order = sorted(weights, key=lambda script: (-(self.rules.reward * weights[script] % total), script))
        for script in order[:self.rules.reward - sum(amounts.values())]:
            amounts[script] += 1
        return tuple(sorted(amounts.items())), frozenset(unpaid)

    def validate_job(self, job, *, require_miner_auth=True):
        if type(job) is not WorkJob:
            raise ValueError("PoW ledger job required")
        m = job.manifest
        view = self.state(m.ledger_root)
        if (m.rules_root != self.rules.root or m.share_bits != self.rules.share_bits or
                m.registry_root != view.registry.root or m.share_snapshot_root != view.root):
            raise ValueError("job rules, registry or snapshot mismatch")
        if (m.parent != view.reward_tip or m.height != view.reward_height + 1 or
                m.epoch != self.rules.epoch(view.height)):
            raise ValueError("wrong candidate reward parent, height or origin epoch")
        entry = view.registry.entry(m.miner_id)
        if require_miner_auth and not verify(entry.signing_key, job.payload, job.miner_signature):
            raise ValueError("invalid miner job authorization")
        used = sum(c.work for c in view.claims if
                   c.epoch == m.epoch and c.payout_script == entry.payout_script)
        if used + expected_work(uint256_from_compact(m.share_bits)) > self.rules.budget:
            raise ValueError("payout destination has no work budget for another proof")
        outputs, _ = self.outputs(m.ledger_root, m.miner_id)
        if m.payout_root != payout_root(outputs):
            raise ValueError("wrong payout commitment")
        if job.coinbase != coinbase(m.height, entry.tag, entry.miner_id, self.rules.pool_id, outputs):
            raise ValueError("coinbase differs from registered payout allocation")
        if job.header != job_header(m, job.coinbase, self.rules):
            raise ValueError("job header is not the exact approved template")
        return True

    def validate_payout_capacity(self, parent, view):
        """Reserve room before accepting identities or eligible in-flight work.

        Include past registries while their jobs can still submit: rotating an
        unused destination does not immediately free its reserved output space.
        Pending claims keep that space until settled, regardless of job age.
        """
        scripts = {c.payout_script for c in view.claims if c.proof_id not in view.paid}
        entries = list(view.registry.entries)
        cursor = parent
        while view.height - self.state(cursor).height <= self.rules.max_job_age:
            entries.extend(self.state(cursor).registry.entries)
            if cursor == self.genesis:
                break
            cursor = self.checkpoints[cursor].parent
        scripts.update(entry.payout_script for entry in entries)
        if entries:
            entry = max(entries, key=lambda item: len(item.tag))
            # Values always occupy eight bytes. Zero values here measure space
            # only; actual jobs still allocate the complete configured reward.
            cb = coinbase(self.rules.max_checkpoints + 1, entry.tag, entry.miner_id,
                          self.rules.pool_id, tuple((script, 0) for script in sorted(scripts)))
            if len(cb) > 4096:
                raise ValueError("payout capacity exceeds reference coinbase limit")

    def transition(self, parent, actions):
        """Pure validation, shared by miners and importers; never changes caches."""
        old = self.state(parent)
        if type(actions) is not list or len(actions) > self.rules.max_actions:
            raise ValueError("checkpoint action limit")
        if len(canonical(actions)) > self.rules.max_payload_bytes:
            raise ValueError("checkpoint payload limit")
        registry = old.registry
        claims, paid, balances = {c.proof_id: c for c in old.claims}, set(old.paid), dict(old.balances)
        reward_tip, reward_height, history = old.reward_tip, old.reward_height, old.reward_history
        for index, action in enumerate(actions):
            if type(action) is not dict:
                raise ValueError("invalid checkpoint action")
            kind = action.get("kind")
            if kind == "registry":
                fields(action, ("kind", "change"))
                change = RegistryChange.from_object(action["change"])
                byte_field(change.entry.tag, maximum=32)
                registry = apply_change(registry, change)
                if registry.network_id != NETWORK_ID or registry.pool_id != self.rules.pool_id:
                    raise ValueError("wrong registry domain")
                continue
            if kind not in ("share", "winner"):
                raise ValueError("unknown checkpoint action")
            fields(action, ("kind", "job", "proof"))
            if kind == "winner" and index != len(actions) - 1:
                raise ValueError("at most one winner, last in checkpoint")
            job = WorkJob.from_object(action["job"])
            fields(action["proof"], ("job_id", "header"))
            proof = Proof(unhex(action["proof"]["job_id"], 32),
                          unhex(action["proof"]["header"], maximum=4096))
            self.validate_job(job)
            origin, m = self.state(job.manifest.ledger_root), job.manifest
            if not self.ancestor(parent, m.ledger_root):
                raise ValueError("job checkpoint is not an event ancestor")
            if old.height - origin.height > self.rules.max_job_age:
                raise ValueError("job exceeds checkpoint age limit")
            h, normalized = decode_header(proof.header), decode_header(proof.header)
            normalized.nNonce, normalized.m_extranonce = 0, 0
            if proof.job_id != job.job_id or normalized.serialize() != job.header:
                raise ValueError("proof changed committed job fields")
            if h.sha256 > uint256_from_compact(self.rules.share_bits):
                raise ValueError("insufficient share proof")
            entry = origin.registry.entry(m.miner_id)
            claim = Claim(proof.proof_id, entry.miner_id, entry.tag, entry.payout_script,
                          expected_work(uint256_from_compact(m.share_bits)), m.epoch,
                          m.parent, m.registry_root)
            prior = claims.get(claim.proof_id)
            if prior is not None and (kind != "winner" or prior != claim):
                raise ValueError("duplicate or conflicting share proof")
            if kind == "winner":
                if h.sha256 > uint256_from_compact(self.rules.block_bits):
                    raise ValueError("not a candidate reward-block solution")
                if m.parent != reward_tip or m.height != reward_height + 1:
                    raise ValueError("winner does not extend candidate reward tip")
                if any(winner == h.sha256 for _, winner in history):
                    raise ValueError("duplicate reward winner")
                outputs, newly_paid = self.outputs(m.ledger_root, m.miner_id)
                if paid.intersection(newly_paid):
                    raise ValueError("snapshot would pay a claim twice")
                paid.update(newly_paid)
                for script, amount in outputs:
                    balances[script] = balances.get(script, 0) + amount
                history = (*history, (reward_tip, h.sha256))
                reward_tip, reward_height = h.sha256, m.height
            # In-flight work remains credit even if current state is over quota.
            # Admission is based on the immutable origin job and bounded age.
            claims[claim.proof_id] = claim
        result = LedgerView(self.rules.root, registry, old.height + 1,
                            old.chainwork + expected_work(uint256_from_compact(self.rules.checkpoint_bits)),
                            reward_tip, reward_height, tuple(sorted(claims.values(), key=lambda c: c.proof_id)),
                            frozenset(paid), tuple(sorted(balances.items())), history)
        self.validate_payout_capacity(parent, result)
        return result

    def add(self, checkpoint):
        if type(checkpoint) is not Checkpoint or checkpoint.rules_root != self.rules.root:
            raise ValueError("wrong checkpoint rules")
        if len(checkpoint.payload) > self.rules.max_payload_bytes:
            raise ValueError("checkpoint payload limit")
        identity = checkpoint.checkpoint_id
        if int.from_bytes(identity, "big") > uint256_from_compact(self.rules.checkpoint_bits):
            raise ValueError("insufficient checkpoint proof of work")
        if identity in self.checkpoints:
            return identity
        if checkpoint.height != self.state(checkpoint.parent).height + 1:
            raise ValueError("wrong checkpoint height")
        view = self.transition(checkpoint.parent, checkpoint.actions())
        if checkpoint.state_root != view.root:
            raise ValueError("wrong checkpoint post-state root")
        if len(self.checkpoints) >= self.rules.max_checkpoints:
            raise ValueError("reference checkpoint store limit; pruning is not implemented")
        self.checkpoints[identity], self.states[identity] = checkpoint, view
        selected = self.state()
        if view.chainwork > selected.chainwork or (view.chainwork == selected.chainwork and identity < self.tip):
            self.tip = identity
        return identity

    def export(self):
        ordered = sorted(self.checkpoints, key=lambda identity: (self.states[identity].height, identity))
        return {"format": 1, "rules": self.rules.to_object(), "tip": self.tip.hex(),
                "checkpoints": [self.checkpoints[identity].to_object() for identity in ordered]}

    def import_objects(self, bundle):
        fields(bundle, ("format", "rules", "tip", "checkpoints"))
        if (type(bundle["format"]) is not int or bundle["format"] != 1 or
                canonical(bundle["rules"]) != canonical(self.rules.to_object())):
            raise ValueError("wrong transport/store rules or format")
        unhex(bundle["tip"], 32)  # A hint only: never overrides verified fork choice.
        if type(bundle["checkpoints"]) is not list or len(bundle["checkpoints"]) > self.rules.max_checkpoints:
            raise ValueError("bundle checkpoint limit")
        pending = [Checkpoint.from_object(obj) for obj in bundle["checkpoints"]]
        while pending:
            deferred = []
            for checkpoint in pending:
                try:
                    self.add(checkpoint)
                except MissingData:
                    deferred.append(checkpoint)
            if len(deferred) == len(pending):
                return len(deferred)
            pending = deferred
        return 0

    def save(self, path):
        path = Path(path)
        temporary = path.with_name(path.name + ".tmp")
        raw = canonical(self.export())
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("reference store byte limit")
        temporary.write_bytes(raw)
        os.replace(temporary, path)

    @classmethod
    def restore(cls, path, rules):
        with Path(path).open("rb") as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("reference store byte limit")
        result = cls(rules)
        if result.import_objects(json.loads(raw)):
            raise MissingData("incomplete persisted checkpoint dependencies")
        return result


def job_header(manifest, cb, rules):
    h = CBlockHeader()
    h.m_header_v2, h.nVersion = True, 4
    h.hashPrevBlock, h.m_height, h.m_txcount = manifest.parent, manifest.height, 1
    h.hashMerkleRoot = decode_coinbase(cb).sha256
    h.nTime, h.nBits = 1700000000 + manifest.height, rules.block_bits
    h.m_mm_rhs = int.from_bytes(manifest.root, "little")
    return h.serialize()


def make_job(ledger, miner_key, checkpoint=None, serial=0):
    checkpoint = ledger.tip if checkpoint is None else checkpoint
    view = ledger.state(checkpoint)
    matches = [entry for entry in view.registry.entries if entry.signing_key == public_key(miner_key)]
    if len(matches) != 1:
        raise ValueError("miner key is not registered at checkpoint")
    entry = matches[0]
    outputs, _ = ledger.outputs(checkpoint, entry.miner_id)
    m = Manifest(ledger.rules.root, view.reward_tip, view.reward_height + 1, view.registry.root,
                 checkpoint, view.root, entry.miner_id, ledger.rules.epoch(view.height),
                 ledger.rules.share_bits, serial, payout_root(outputs))
    cb = coinbase(m.height, entry.tag, entry.miner_id, ledger.rules.pool_id, outputs)
    proposal = WorkJob(m, job_header(m, cb, ledger.rules), cb, b"pending")
    ledger.validate_job(proposal, require_miner_auth=False)
    return replace(proposal, miner_signature=sign(miner_key, proposal.payload))


def register_action(change):
    return {"kind": "registry", "change": change.to_object()}


def proof_action(job, proof, winner=False):
    if type(winner) is not bool:
        raise ValueError("winner flag must be boolean")
    return {"kind": "winner" if winner else "share", "job": job.to_object(), "proof": proof.to_object()}


def mine_checkpoint(ledger, actions=(), parent=None, start_nonce=0, max_attempts=100000):
    parent = ledger.tip if parent is None else parent
    integer(start_nonce, 0, (1 << 64) - 1)
    integer(max_attempts, 1, 100000)
    actions = list(actions)
    view = ledger.transition(parent, actions)
    checkpoint = Checkpoint(ledger.rules.root, parent, view.height, canonical(actions), view.root, start_nonce)
    target = uint256_from_compact(ledger.rules.checkpoint_bits)
    for nonce in range(start_nonce, min(start_nonce + max_attempts, 1 << 64)):
        candidate = replace(checkpoint, nonce=nonce)
        if int.from_bytes(candidate.checkpoint_id, "big") <= target:
            return candidate
    raise RuntimeError("bounded checkpoint nonce search exhausted")
