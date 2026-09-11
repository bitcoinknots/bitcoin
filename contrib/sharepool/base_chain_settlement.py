#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Durable, passive settlement observer; does not enforce Bitcoin consensus.

The supplied rpc(method, *params) must talk to the user's validating native node.
Canonicality follows that node, never a sharepool checkpoint tip. Every coinbase
output, including a zero-value witness commitment, is committed in wire order.
Block hashes use RPC display order. ``root`` is digest bytes; root.hex() matches
Knots' getblockheader ``mm_rhs`` (HexStr of the serialized uint256, not GetHex).

``mature`` conservatively means 100 descendants (101 confirmations). Consensus
allows spending in the next block with 99 descendants (100 confirmations); that
separate boundary is exposed as ``spendable_next_block``. No spending occurs.
"""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import sqlite3


MAX_MONEY = 21_000_000 * 100_000_000
SCHEMA_VERSION = 1


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def hash_hex(value):
    if type(value) is not str or len(value) != 64:
        raise ValueError("expected a canonical 32-byte hexadecimal hash")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("invalid hexadecimal hash") from error
    if raw.hex() != value:
        raise ValueError("noncanonical hexadecimal hash")
    return value


def normalize_payouts(payouts):
    if type(payouts) not in (list, tuple) or not 1 <= len(payouts) <= 10000:
        raise ValueError("payouts must be a bounded nonempty sequence")
    result, total, script_bytes = [], 0, 0
    for output in payouts:
        if type(output) not in (tuple, list) or len(output) != 2:
            raise ValueError("payout must contain script hex and integer satoshis")
        script, amount = output
        if type(script) is not str or not 2 <= len(script) <= 20000:
            raise ValueError("invalid payout script length")
        try:
            raw = bytes.fromhex(script)
        except ValueError as error:
            raise ValueError("invalid payout script") from error
        if raw.hex() != script:
            raise ValueError("noncanonical payout script")
        if type(amount) is not int or not 0 <= amount <= MAX_MONEY:
            raise ValueError("payout amount must be bounded integer satoshis")
        script_bytes += len(raw)
        total += amount
        if total > MAX_MONEY or script_bytes > 1_000_000:
            raise ValueError("payout total or script bytes exceed bound")
        result.append((script, amount))
    if not total:
        raise ValueError("settlement must contain a positive payout")
    return tuple(result)


def payout_digest(payouts):
    return hashlib.sha256(b"SharePool/base-payouts/v1\x00" + canonical(normalize_payouts(payouts))).hexdigest()


@dataclass(frozen=True)
class SettlementCommitment:
    network_genesis: str
    pool_id: bytes
    rules_root: str
    snapshot_root: str
    base_parent: str
    payout_digest: str
    version: int = 1

    def __post_init__(self):
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported settlement commitment version")
        if type(self.pool_id) is not bytes or not 1 <= len(self.pool_id) <= 64:
            raise ValueError("pool ID must contain 1 to 64 bytes")
        for field in ("network_genesis", "rules_root", "snapshot_root", "base_parent", "payout_digest"):
            hash_hex(getattr(self, field))

    @classmethod
    def create(cls, *, network_genesis, pool_id, rules_root, snapshot_root, base_parent, payouts):
        return cls(network_genesis, pool_id, rules_root, snapshot_root, base_parent, payout_digest(payouts))

    def to_object(self):
        return {name: value.hex() if type(value) is bytes else value for name, value in vars(self).items()}

    @classmethod
    def from_object(cls, obj):
        if type(obj) is not dict or set(obj) != set(cls.__dataclass_fields__):
            raise ValueError("invalid commitment fields")
        pool = obj["pool_id"]
        if type(pool) is not str or not 2 <= len(pool) <= 128:
            raise ValueError("invalid pool encoding")
        raw = bytes.fromhex(pool)
        if raw.hex() != pool:
            raise ValueError("noncanonical pool encoding")
        return cls(**{**obj, "pool_id": raw})

    @property
    def root(self):
        return hashlib.sha256(b"SharePool/base-settlement/v1\x00" + canonical(self.to_object())).digest()


class NativeRPCError(Exception):
    """Optional adapter error type; native JSON-RPC errors with .error also work."""
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def unavailable(error):
    code = getattr(error, "code", None)
    detail = getattr(error, "error", None)
    if type(detail) is dict:
        code = detail.get("code", code)
    # Do not mistake an arbitrary RPC_MISC_ERROR (-1) for unavailable data.
    message = detail.get("message", str(error)) if type(detail) is dict else str(error)
    return code == -5 or (code == -1 and message.startswith("Block not available"))


class ChainChanged(RuntimeError):
    """Native tip changed while obtaining a consistent observation; retry later."""


class BaseChainSettlement:
    def __init__(self, path, *, network_genesis, rpc):
        self.network_genesis, self.rpc = hash_hex(network_genesis), rpc
        self._check_network()
        self.path = Path(path)
        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            # WAL plus FULL sync protects committed transactions. Filesystem and
            # hardware durability still depend on the host; no crash-proof claim.
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ValueError("settlement store requires a WAL-capable file")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA busy_timeout=5000")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise ValueError("unsupported settlement database schema")
            self.db.execute("BEGIN IMMEDIATE")
            if version == 0:
                if self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]:
                    raise ValueError("refusing to initialize an unrelated database")
                self.db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.db.execute("INSERT INTO metadata VALUES ('network_genesis', ?)", (self.network_genesis,))
                self.db.execute("""CREATE TABLE settlements (
                    block_hash TEXT PRIMARY KEY, commitment TEXT NOT NULL, payouts TEXT NOT NULL,
                    commitment_root TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                    height INTEGER, confirmations INTEGER NOT NULL DEFAULT 0,
                    descendants INTEGER NOT NULL DEFAULT 0, spendable_next_block INTEGER NOT NULL DEFAULT 0,
                    payload_verified INTEGER NOT NULL DEFAULT 0, observed_tip TEXT,
                    CHECK(status IN ('pending','immature','mature','orphaned')))
                """)
                self.db.execute("PRAGMA user_version=1")
            network = self.db.execute("SELECT value FROM metadata WHERE key='network_genesis'").fetchone()
            if network is None or network[0] != self.network_genesis:
                raise ValueError("settlement database belongs to another network")
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('revision', '0')")
            self._revision()
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            self.db.close()
            raise

    def _check_network(self):
        if hash_hex(self.rpc("getblockhash", 0)) != self.network_genesis:
            raise ValueError("native RPC is connected to another network")

    def _revision(self):
        row = self.db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()
        if row is None or not row[0].isdigit() or len(row[0]) > 20:
            raise ValueError("invalid settlement store revision")
        return int(row[0])

    def _advance_revision(self):
        self.db.execute("UPDATE metadata SET value=? WHERE key='revision'", (str(self._revision() + 1),))

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def observe(self, block_hash, commitment, payouts):
        block_hash = hash_hex(block_hash)
        if type(commitment) is not SettlementCommitment or commitment.network_genesis != self.network_genesis:
            raise ValueError("settlement commitment belongs to another network")
        payouts = normalize_payouts(payouts)
        if payout_digest(payouts) != commitment.payout_digest:
            raise ValueError("payouts do not match commitment")
        encoded, outputs = canonical(commitment.to_object()).decode(), canonical(payouts).decode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute("SELECT commitment,payouts FROM settlements WHERE block_hash=?", (block_hash,)).fetchone()
            if existing is not None:
                if tuple(existing) != (encoded, outputs):
                    raise ValueError("conflicting metadata for an observed block")
            else:
                self.db.execute("INSERT INTO settlements(block_hash,commitment,payouts,commitment_root) VALUES (?,?,?,?)",
                                (block_hash, encoded, outputs, commitment.root.hex()))
                self._advance_revision()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return self.record(block_hash)

    def records(self):
        return [self._record(row) for row in self.db.execute("SELECT * FROM settlements ORDER BY block_hash")]

    def record(self, block_hash):
        row = self.db.execute("SELECT * FROM settlements WHERE block_hash=?", (hash_hex(block_hash),)).fetchone()
        return None if row is None else self._record(row)

    def _record(self, row):
        value = dict(row)
        value["commitment"] = json.loads(value["commitment"])
        value["payouts"] = normalize_payouts(json.loads(value["payouts"]))
        commitment = SettlementCommitment.from_object(value["commitment"])
        if (commitment.network_genesis != self.network_genesis or
                commitment.payout_digest != payout_digest(value["payouts"]) or
                commitment.root.hex() != value["commitment_root"]):
            raise ValueError("persisted settlement metadata failed validation")
        for name in ("spendable_next_block", "payload_verified"):
            value[name] = bool(value[name])
        return value

    @staticmethod
    def _native_payouts(block):
        if type(block) is not dict or type(block.get("tx")) is not list or not block["tx"]:
            raise ValueError("native block does not contain decoded transactions")
        coinbase = block["tx"][0]
        if (type(coinbase) is not dict or type(coinbase.get("vin")) is not list or
                len(coinbase["vin"]) != 1 or "coinbase" not in coinbase["vin"][0] or
                type(coinbase.get("vout")) is not list):
            raise ValueError("native block has no decoded coinbase")
        outputs = []
        for index, output in enumerate(coinbase["vout"]):
            if type(output) is not dict or type(output.get("n")) is not int or output["n"] != index:
                raise ValueError("noncanonical native output order")
            try:
                raw_value = str(output["value"])
                if len(raw_value) > 64:
                    raise ValueError("native output value exceeds encoding bound")
                amount = Decimal(raw_value) * 100_000_000
                script = output["scriptPubKey"]["hex"]
                if (not amount.is_finite() or amount < 0 or amount > MAX_MONEY or
                        amount != amount.to_integral_value()):
                    raise ValueError("native output is not an integer number of satoshis")
                outputs.append((script, int(amount)))
            except (KeyError, InvalidOperation, TypeError, OverflowError) as error:
                raise ValueError("invalid native coinbase output") from error
        return normalize_payouts(outputs)

    def refresh(self):
        """Atomically refresh statuses from a stable native tip; RPC faults abort.

        Unknown headers or unavailable block bodies remain pending. Previously
        verified bodies need not be fetched again, permitting native pruning.
        A disconnected known block is orphaned. No checkpoint argument exists.
        """
        revision = self._revision()
        self._check_network()
        tip = hash_hex(self.rpc("getbestblockhash"))
        tip_header = self.rpc("getblockheader", tip, True)
        tip_height = tip_header.get("height")
        if tip_header.get("hash") != tip or type(tip_height) is not int or tip_height < 0:
            raise ValueError("invalid native tip header")
        updates = []
        for record in self.records():
            identity = record["block_hash"]
            status, height, confirmations, descendants, spendable = "pending", None, 0, 0, False
            verified = record["payload_verified"]
            try:
                header = self.rpc("getblockheader", identity, True)
            except Exception as error:
                if not unavailable(error):
                    raise
                header = None
            if header is not None:
                commitment = SettlementCommitment.from_object(record["commitment"])
                height = header.get("height")
                if (header.get("hash") != identity or type(height) is not int or height < 1 or
                        header.get("previousblockhash") != commitment.base_parent or
                        header.get("header_version") != 2 or header.get("mm_rhs") != commitment.root.hex()):
                    raise ValueError("native header differs from observed settlement commitment")
                if not verified:
                    try:
                        block = self.rpc("getblock", identity, 2)
                    except Exception as error:
                        if not unavailable(error):
                            raise
                        block = None
                    if block is not None:
                        if block.get("hash") != identity or self._native_payouts(block) != record["payouts"]:
                            raise ValueError("native coinbase differs from observed payouts")
                        verified = True
                if verified:
                    canonical_hash = self.rpc("getblockhash", height) if height <= tip_height else None
                    if canonical_hash == identity:
                        descendants = tip_height - height
                        confirmations = descendants + 1
                        spendable = descendants >= 99
                        status = "mature" if descendants >= 100 else "immature"
                    else:
                        status = "orphaned"
            updates.append((status, height, confirmations, descendants, int(spendable), int(verified), tip, identity))
        if hash_hex(self.rpc("getbestblockhash")) != tip:
            raise ChainChanged("native chain changed during settlement observation")
        self._check_network()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self._revision() != revision:
                raise ChainChanged("another observer changed the store during settlement observation")
            self.db.executemany("""UPDATE settlements SET status=?,height=?,confirmations=?,descendants=?,
                spendable_next_block=?,payload_verified=?,observed_tip=? WHERE block_hash=?""", updates)
            self._advance_revision()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return self.records()
