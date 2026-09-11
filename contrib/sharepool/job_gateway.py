#!/usr/bin/env python3
"""Local mining-job update state machine; no transport, hardware, or secret store.

The coordinator callback owns its coordinator key. This gateway owns only one
miner's fixture key and its validating replica. Callers must route replica
mutations through the gateway (or hold its lock); Engine is not itself thread
safe. Old authorized jobs remain immutable evidence and can still win.
"""

import json
import os
from pathlib import Path
import threading

from live_protocol import Job, authorize_job, canonical, integer
from signed_registry import public_key


class LedgerConflict(ValueError):
    """Authenticated incompatible receipt histories require an anchored choice."""


class Gateway:
    def __init__(self, engine, miner_key, registry_root, ledger_root=None):
        self.lock = threading.RLock()
        self.engine, self._miner_key = engine, miner_key
        registry = engine.registry(registry_root)
        matches = [entry for entry in registry.entries if entry.signing_key == public_key(miner_key)]
        if len(matches) != 1:
            raise ValueError("gateway key is not uniquely registered")
        self.miner_id = matches[0].miner_id
        if not engine.registry_extends(registry_root, engine.state(engine.tip).registry_root):
            raise ValueError("gateway registry conflicts with active base history")
        ledger_root = engine.state(engine.tip).ledger_root if ledger_root is None else ledger_root
        self._compatible_claims(engine.tip, ledger_root, registry_root)
        self.registry_root, self.ledger_root = registry_root, ledger_root
        self.active_job = None
        self.issued = {}
        self.generation, self._next_serial = 0, 0
        self.conflicts = []
        self.paused_reason = "no authorized job"

    def _pause(self, reason):
        self.active_job = None
        self.generation += 1
        self.paused_reason = reason

    def _compatible_claims(self, parent, ledger_root, registry_root):
        claims = self.engine.claims_for(parent, ledger_root)
        for claim in claims.values():
            if not (self.engine.registry_extends(registry_root, claim.registry_root) or
                    self.engine.registry_extends(claim.registry_root, registry_root)):
                raise ValueError("receipt claims belong to another registry branch")
        # A verified future registry version can arrive before its explicit
        # local selection. Retain those receipts while job authorization waits.
        return claims

    def _unresolved_conflicts(self):
        anchored = set(self.engine.ledger(self.engine.state(self.engine.tip).ledger_root).roots)
        for left, right in self.conflicts:
            left_roots = set(self.engine.ledger(left).roots)
            right_roots = set(self.engine.ledger(right).roots)
            if not anchored.intersection(left_roots ^ right_roots):
                return True
        return False

    def refresh(self, callback):
        """Verify and authorize only a proposal for the exact captured state.

        Returns None if receipt/registry/parent state or another activation
        changed while the coordinator was preparing its response. No miner
        signature is made for such a stale response.
        """
        with self.lock:
            if self._unresolved_conflicts():
                raise LedgerConflict("signed receipt conflict has no anchored resolution")
            captured = (self.generation, self.engine.tip, self.ledger_root, self.registry_root)
            serial = self._next_serial
            integer(serial)
            self._next_serial += 1
        proposal = callback(self.miner_id, captured[3], captured[2], captured[1], serial)
        with self.lock:
            if captured != (self.generation, self.engine.tip, self.ledger_root, self.registry_root):
                return None
            if type(proposal) is not Job:
                raise ValueError("coordinator must return a Job proposal")
            manifest = proposal.manifest
            if ((manifest.parent, manifest.ledger_root, manifest.registry_root,
                 manifest.miner_id, manifest.serial) !=
                    (captured[1], captured[2], captured[3], self.miner_id, serial)):
                raise ValueError("coordinator proposal differs from requested state")
            job = authorize_job(self.engine, proposal, self._miner_key)
            self.issued[job.job_id] = job
            self.active_job = job
            self.paused_reason = None
            self.generation += 1
            return job

    def ingest_receipt(self, receipt):
        with self.lock:
            root = self.engine.add_receipt(receipt)
            current = self.engine.ledger(self.ledger_root)
            if root in current.roots:
                return self.ledger_root  # Replays/ancestors never rewind the active cursor.
            incoming = self.engine.ledger(root)
            conflict = self.ledger_root not in incoming.roots
            if not conflict:
                try:
                    self._compatible_claims(self.engine.tip, root, self.registry_root)
                except ValueError:
                    conflict = True
            if conflict:
                pair = (self.ledger_root, root)
                if pair not in self.conflicts:
                    self.conflicts.append(pair)
                self._pause("signed receipt history conflict")
                raise LedgerConflict(self.paused_reason)
            self.ledger_root = root
            self._pause("verified work changed; fresh job required")
            return root

    def receive_and_refresh(self, receipt, callback):
        """Receipt event handler: validate, pause, then request a fresh commitment."""
        with self.lock:
            previous = self.ledger_root
            self.ingest_receipt(receipt)
            if previous == self.ledger_root:
                return self.active_job
        # Deliberately outside the receipt lock. Another event may supersede
        # this request; refresh checks its captured generation before signing.
        result = self.refresh(callback)
        if result is not None:
            return result
        with self.lock:
            return self.active_job

    def select_registry(self, root):
        with self.lock:
            if root == self.registry_root:
                return root
            registry = self.engine.registry(root)
            if not self.engine.registry_extends(root, self.registry_root):
                raise ValueError("registry cursor may advance only to a verified descendant")
            if not self.engine.registry_extends(root, self.engine.state(self.engine.tip).registry_root):
                raise ValueError("registry conflicts with active base history")
            registry.entry(self.miner_id)
            self.engine.claims_for(self.engine.tip, self.ledger_root, root)
            self.registry_root = root
            self._pause("registry changed; fresh job required")
            return root

    def ingest_change(self, change):
        """Verify registry gossip under the same replica lock; selection is explicit."""
        with self.lock:
            return self.engine.add_change(change)

    def ingest_job(self, job):
        """Verify another miner's job so its incoming shares can be checked."""
        with self.lock:
            return self.engine.add_job(job)

    def ingest_block(self, proof):
        with self.lock:
            previous_tip = self.engine.tip
            identity = self.engine.add_block(proof)
            if previous_tip == self.engine.tip:
                return identity
            self._pause("base parent changed; seal and fresh job required")
            base = self.engine.state(self.engine.tip)
            registry_root = self.registry_root
            if not self.engine.registry_extends(registry_root, base.registry_root):
                registry_root = base.registry_root
            root = self.ledger_root
            for _ in range(self.engine.rules.max_events + 1):
                try:
                    self._compatible_claims(self.engine.tip, root, registry_root)
                    break
                except ValueError:
                    receipt = self.engine.receipts.get(root)
                    if receipt is None:
                        root = base.ledger_root
                        self._compatible_claims(self.engine.tip, root, registry_root)
                        break
                    root = receipt.previous_root
            else:
                raise ValueError("gateway receipt history exceeds limit")
            self.ledger_root = root
            self.registry_root = registry_root
            return identity

    def save_cursor(self, path):
        """Persist public cursor state only; the Engine archive is saved separately."""
        with self.lock:
            data = {"format": 1, "miner_id": self.miner_id.hex(),
                    "registry_root": self.registry_root.hex(), "ledger_root": self.ledger_root.hex(),
                    "generation": self.generation, "next_serial": self._next_serial,
                    "issued": [identity.hex() for identity in self.issued],
                    "conflicts": [[left.hex(), right.hex()] for left, right in self.conflicts]}
            path = Path(path)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_bytes(canonical(data))
            os.replace(temporary, path)

    @classmethod
    def restore_cursor(cls, engine, miner_key, path):
        raw = Path(path).read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError("gateway cursor exceeds size limit")
        data = json.loads(raw)
        expected = {"format", "miner_id", "registry_root", "ledger_root", "generation",
                    "next_serial", "issued", "conflicts"}
        if type(data) is not dict or set(data) != expected or type(data["format"]) is not int or data["format"] != 1:
            raise ValueError("invalid gateway cursor format")
        if canonical(data) != raw:
            raise ValueError("noncanonical gateway cursor")

        def root(value):
            if type(value) is not str or len(value) != 64:
                raise ValueError("invalid gateway cursor identifier")
            decoded = bytes.fromhex(value)
            if decoded.hex() != value:
                raise ValueError("noncanonical gateway cursor identifier")
            return decoded

        result = cls(engine, miner_key, root(data["registry_root"]), root(data["ledger_root"]))
        if root(data["miner_id"]) != result.miner_id:
            raise ValueError("cursor belongs to another miner")
        integer(data["generation"])
        integer(data["next_serial"])
        result.generation, result._next_serial = data["generation"] + 1, data["next_serial"]
        if type(data["issued"]) is not list or len(data["issued"]) > engine.rules.max_events * 8:
            raise ValueError("invalid issued-job cursor list")
        for identity in data["issued"]:
            job = engine.jobs.get(root(identity))
            if job is None or job.manifest.miner_id != result.miner_id:
                raise ValueError("cursor references an unverified or foreign job")
            result.issued[job.job_id] = job
        if type(data["conflicts"]) is not list or len(data["conflicts"]) > engine.rules.max_events:
            raise ValueError("invalid conflict cursor list")
        for pair in data["conflicts"]:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("invalid conflict cursor pair")
            left, right = map(root, pair)
            engine.ledger(left)
            engine.ledger(right)
            result.conflicts.append((left, right))
        result.paused_reason = "restored cursor; fresh local authorization required"
        return result
