#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable miner job admission for the opt-in native regtest profile.

Native RPC verifies signatures, PoW, chain context and complete proposed blocks.
Python only parses wire data and enforces the miner's own payout/inclusion policy.
No signing keys, devices, networking listeners or mainnet activation live here.
The caller must check ready_for_dispatch() immediately before initial dispatch.
Later received work requests a new job; it never rewrites work already running.
"""
from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from native_enforcement import (MAX_MANIFEST, MAX_SHARE_AGE, MAX_SHARES, RULES_HASH,
                                SHARE_BITS, Reader, Share, parse_coinbase)
from test_framework.messages import CBlock, CBlockHeader


REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
MAX_RECEIPTS = 128
MAX_JOBS = 64
MAX_TEMPLATES = 128


def parse_share(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 1024:
        raise ValueError("share encoding exceeds bound")
    reader = Reader(raw)
    share = Share.read(reader)
    if reader.stream.read() or share.serialize() != raw:
        raise ValueError("noncanonical share encoding")
    return share


def parse_block(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 4_000_000:
        raise ValueError("block encoding exceeds bound")
    stream, block = BytesIO(raw), CBlock()
    block.deserialize(stream)
    if stream.read() or block.serialize() != raw or not block.vtx:
        raise ValueError("noncanonical or empty candidate block")
    return block


class JobOmission(ValueError):
    def __init__(self, proof_ids):
        self.proof_ids = tuple(sorted(proof_ids))
        super().__init__("job omits known eligible unpaid work")


def immutable_header(header):
    header = CBlockHeader(header)
    for name in ("nNonce", "m_nonce2", "m_nonce3", "m_extranonce", "m_time_offset"):
        setattr(header, name, 0)
    return header.serialize()


def template_id(header):
    return hashlib.sha256(immutable_header(header)).hexdigest()


@dataclass(frozen=True)
class MiningAuthorization:
    block_bytes: bytes
    native_parent: str
    commitment: str
    receipt_sequence: int

    @property
    def job_id(self):
        return hashlib.sha256(self.block_bytes).hexdigest()

    def block_for_header(self, header_bytes):
        """Apply only the physical nonce/extranonce/search-time fields."""
        if type(header_bytes) is not bytes or len(header_bytes) != 164:
            raise ValueError("native v2 header required")
        header, stream = CBlockHeader(), BytesIO(header_bytes)
        header.deserialize(stream)
        block = parse_block(self.block_bytes)
        if (header.serialize() != header_bytes or
                immutable_header(header) != immutable_header(block)):
            raise ValueError("work changes the authorized template or settlement")
        for name in ("nNonce", "m_nonce2", "m_nonce3", "m_extranonce", "m_time_offset"):
            setattr(block, name, getattr(header, name))
        return block.serialize()


class NativeMiningGate:
    def __init__(self, path, *, rpc, pool, public_key, payout_script):
        if (type(pool) is not int or not 0 < pool < 1 << 256 or
                type(public_key) is not bytes or len(public_key) != 32 or
                type(payout_script) is not bytes or not 1 <= len(payout_script) <= 34):
            raise ValueError("explicit miner pool/key/payout binding required")
        self.rpc, self.pool = rpc, pool
        self.public_key, self.payout_script = public_key, payout_script
        self._check_network()
        self.path = Path(path)
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if self.path.is_symlink() or not self.path.is_file():
                raise ValueError("gate store must be a regular file") from None
        else:
            os.close(descriptor)
        self.db = sqlite3.connect(str(self.path))
        try:
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ValueError("gate store requires WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            config = json.dumps({"version": 1, "genesis": REGTEST_GENESIS, "pool": pool,
                                 "public_key": public_key.hex(), "script": payout_script.hex()}, sort_keys=True)
            tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if not tables:
                with self.db:
                    self.db.execute("CREATE TABLE config (value TEXT NOT NULL)")
                    self.db.execute("INSERT INTO config VALUES (?)", (config,))
                    self.db.execute("CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, proof_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
                    self.db.execute("CREATE TABLE jobs (sequence INTEGER PRIMARY KEY, job_id TEXT UNIQUE NOT NULL, data BLOB NOT NULL)")
                    self.db.execute("CREATE TABLE templates (job_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, data BLOB NOT NULL)")
            saved = self.db.execute("SELECT value FROM config").fetchall()
            if saved != [(config,)]:
                raise ValueError("gate store belongs to another miner, pool or network")
        except Exception:
            self.db.close()
            raise

    def _check_network(self):
        if (self.rpc("getblockchaininfo").get("chain") != "regtest" or
                self.rpc("getblockhash", 0) != REGTEST_GENESIS):
            raise ValueError("native mining gate is restricted to regtest")

    def base_template(self):
        """Get an explicitly incomplete template; this never authorizes mining."""
        self._check_network()
        result = self.rpc("getblocktemplate", {
            "rules": ["segwit", "blake2b", "sharepool"],
            "capabilities": ["skip_validity_test"],
            "blockreservedsize": 90_000, "blockreservedweight": 360_000,
        })
        expected = {"version": 1, "genesis": REGTEST_GENESIS,
                    "rules_root": f"{RULES_HASH:064x}", "share_bits": f"{SHARE_BITS:08x}",
                    "max_share_age": MAX_SHARE_AGE, "max_shares": MAX_SHARES,
                    "max_manifest_bytes": MAX_MANIFEST, "requires_completion": True}
        profile = result.get("sharepool", {})
        if (any(profile.get(key) != value for key, value in expected.items()) or
                "!sharepool" not in result.get("rules", []) or
                type(profile.get("activation_height")) is not int or
                not 1 <= profile["activation_height"] <= result.get("height", 0)):
            raise ValueError("native node does not advertise the required active settlement profile")
        return result

    def receive(self, raw):
        """Validate through native libsecp/PoW, then durably acknowledge once."""
        self._check_network()
        share = parse_share(raw)
        if share.envelope.pool != self.pool:
            raise ValueError("share belongs to another pool")
        self._require_origin(share)
        result = self.rpc("validatesharepoolshare", raw.hex())
        identity = f"{share.proof_id:064x}"
        expected = {"valid": True, "proof_id": identity, "pool": f"{self.pool:064x}",
                    "origin_height": share.envelope.height,
                    "owner": share.envelope.public_key.hex(),
                    "payout_script": share.envelope.payout_script.hex(),
                    "share_bits": f"{SHARE_BITS:08x}"}
        if any(result.get(key) != value for key, value in expected.items()):
            raise ValueError("native share response does not match received work")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            return self._record_receipt(share)

    def _require_origin(self, share):
        saved = self.db.execute("SELECT body_hash,data FROM templates WHERE job_id=?", (template_id(share.header),)).fetchone()
        if saved is None:
            raise ValueError("share origin template has not been validated locally")
        body = bytes(saved[1])
        if (hashlib.sha256(body).hexdigest() != saved[0] or
                immutable_header(parse_block(body)) != immutable_header(share.header)):
            raise ValueError("persisted origin template failed integrity validation")
    def _record_receipt(self, share):
        """Caller has completed native proof validation and owns a transaction."""
        identity = f"{share.proof_id:064x}"
        if self.db.execute("SELECT 1 FROM receipts WHERE proof_id=?", (identity,)).fetchone():
            return False
        if self.db.execute("SELECT count(*) FROM receipts").fetchone()[0] >= MAX_RECEIPTS:
            raise ValueError("receipt archive is full; no work was acknowledged")
        self.db.execute("INSERT INTO receipts(proof_id,data) VALUES (?,?)", (identity, share.serialize()))
        return True

    def _validate_template(self, raw):
        profile = self.base_template()  # An inactive peer's proposal acceptance is insufficient.
        block = parse_block(raw)
        manifest, unused_payouts = parse_coinbase(block.vtx[0])
        if manifest.envelope.pool != self.pool or manifest.envelope.height != profile["height"]:
            raise ValueError("template pool or native height mismatch")
        parent = f"{block.hashPrevBlock:064x}"
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("job no longer extends the native tip")
        proposal = self.rpc("getblocktemplate", {"mode": "proposal",
            "rules": ["segwit", "blake2b", "sharepool"], "data": raw.hex()})
        if proposal is not None:
            raise ValueError("native node rejected completed settlement job: " + str(proposal))
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("native tip changed during job validation")
        return block, manifest

    def _cache_template(self, raw, block):
        identity = template_id(block)
        saved = self.db.execute("SELECT 1 FROM templates WHERE job_id=?", (identity,)).fetchone()
        if not saved:
            if self.db.execute("SELECT count(*) FROM templates").fetchone()[0] >= MAX_TEMPLATES:
                raise ValueError("validated template archive is full")
            self.db.execute("INSERT INTO templates VALUES (?,?,?)",
                            (identity, hashlib.sha256(raw).hexdigest(), raw))
        return identity

    def register_template(self, raw):
        """Verify the full origin block before receiving work on its header.

        Historical jobs must already be cached: proposal mode validates against
        the current UTXO tip and cannot establish an unknown past template.
        This method validates evidence; it does not authorize hash power.
        """
        block, unused_manifest = self._validate_template(raw)
        with self.db:
            return self._cache_template(raw, block)

    def authorize(self, raw):
        block, manifest = self._validate_template(raw)
        origin = manifest.envelope
        if (origin.pool, origin.public_key, origin.payout_script) != (
                self.pool, self.public_key, self.payout_script):
            raise ValueError("job does not bind this miner's registered key and payout")
        parent = f"{block.hashPrevBlock:064x}"
        # A coordinator may introduce proofs directly in a job. Those proofs
        # need the same full-origin verification as gossip-received work.
        for share in manifest.shares:
            self._require_origin(share)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            for share in manifest.shares:
                self._record_receipt(share)
        # Only now is the parent's paid-state opening authenticated by native
        # consensus. Unseen work is not a Bitcoin block-validity condition.
        paid = {entry.proof_id for entry in manifest.parent_state}
        included = {share.proof_id for share in manifest.shares}
        missing, sequence, ancestors = [], 0, {}
        for serial, identity, data in self.db.execute("SELECT sequence,proof_id,data FROM receipts ORDER BY sequence"):
            sequence = serial
            share = parse_share(bytes(data))
            if identity != f"{share.proof_id:064x}" or share.envelope.pool != self.pool:
                raise ValueError("persisted receipt failed identity validation")
            height = share.envelope.height
            if not max(1, origin.height - MAX_SHARE_AGE) <= height <= origin.height:
                continue
            if height not in ancestors:
                ancestors[height] = self.rpc("getblockhash", height - 1)
            if ancestors[height] != f"{share.header.hashPrevBlock:064x}":
                continue
            if share.proof_id not in paid and share.proof_id not in included:
                missing.append(identity)
        if missing:
            raise JobOmission(missing)
        if self.rpc("getbestblockhash") != parent:
            raise ValueError("native tip changed during job validation")
        authorization = MiningAuthorization(raw, parent, f"{origin.root:064x}", sequence)
        with self.db:
            self._cache_template(raw, block)
            self.db.execute("INSERT OR IGNORE INTO jobs(job_id,data) VALUES (?,?)", (authorization.job_id, raw))
            self.db.execute("DELETE FROM jobs WHERE sequence NOT IN (SELECT sequence FROM jobs ORDER BY sequence DESC LIMIT ?)", (MAX_JOBS,))
        return authorization

    def is_current(self, authorization):
        self._check_network()
        return self.rpc("getbestblockhash") == authorization.native_parent

    def needs_refresh(self, authorization):
        newest = self.db.execute("SELECT COALESCE(max(sequence),0) FROM receipts").fetchone()[0]
        return newest > authorization.receipt_sequence or not self.is_current(authorization)

    def ready_for_dispatch(self, authorization):
        """Fence new dispatch on the current profile, native tip and receipts.

        A tip or receipt can still change after this call. The caller must keep
        observing refresh signals while hashing; solved jobs remain immutable.
        """
        self.base_template()
        return not self.needs_refresh(authorization)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
