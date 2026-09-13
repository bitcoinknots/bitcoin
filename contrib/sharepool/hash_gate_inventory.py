#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded v6 receipt ingestion from the node's paged snapshot inventory.

Inventory is availability, never validity. Every newly acknowledged proof gets
native origin/proof validation and an atomic durable gate write. Failed inputs
are reported with an exact retry cursor; a completed scan cycles from the start
on the next call so insertions below an old hash cursor are visited too.
"""

from hash_snapshot import TIDES_VERSION
from copy import deepcopy
import native_archive
from native_mining_gate import template_id


def _cursor(value=None):
    value = {"after": None, "snapshot": None, "share": 0} if value is None else value
    if (type(value) is not dict or set(value) != {"after", "snapshot", "share"} or
            any(item is not None and not native_archive.is_hash(item) for item in (value["after"], value["snapshot"])) or
            type(value["share"]) is not int or not 0 <= value["share"] <= 65536 or
            (value["snapshot"] is None and value["share"] != 0)):
        raise ValueError("invalid native inventory cursor")
    return dict(value)


def _fair_cursor(value=None):
    initial = {"archive": _cursor(),
               "recent": {"after": 0, "epoch": None, "snapshot": None, "share": 0, "sequence": 0},
               "next_lane": "recent"}
    if value is None:
        return initial
    if type(value) is dict and set(value) == {"after", "snapshot", "share"}:
        initial["archive"] = _cursor(value)  # Exact per-object deferred retry cursor.
        initial["next_lane"] = "archive"
        return initial
    if type(value) is not dict or set(value) != set(initial) or value["next_lane"] not in ("recent", "archive"):
        raise ValueError("invalid native inventory lane cursor")
    result = deepcopy(value)
    result["archive"] = _cursor(result["archive"])
    recent = result["recent"]
    if (type(recent) is not dict or set(recent) != set(initial["recent"]) or
            any(type(recent[key]) is not int or not 0 <= recent[key] < 1 << 64 for key in ("after", "sequence")) or
            (recent["epoch"] is not None and not native_archive.is_hash(recent["epoch"]))):
        raise ValueError("invalid native recent cursor")
    _cursor({"after": None, "snapshot": recent["snapshot"], "share": recent["share"]})
    return result


class _ByteBudget(ValueError):
    pass


def sync_native_receipts(gate, *, cursor=None, limit=32, max_bytes=64 * 1024 * 1024, max_receipts=128):
    """Scan at most limit one-entry inventory pages and max_receipts proof rows.

    max_bytes charges every snapshot read before decoding, including local,
    repeated and failed dependency reads, plus each expanded origin body and
    proof. A single snapshot/body remains separately bounded by the native
    wire limits before its bytes are available to charge. This is an API for
    the gate's sole owner, not an unbounded background downloader.

    Returned cursor resumes a partly read snapshot without replaying its first
    proofs. Deferred entries are unacknowledged and include retry_cursor; callers
    can retry those directly or let the next complete scan encounter them. No
    recipient payment or global reception order is implied by an import.
    """
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 256 * 1024 * 1024:
        raise ValueError("invalid bounded native inventory budget")
    if gate._snapshot_observer is not None:
        raise ValueError("native inventory ingestion cannot be nested")
    meter = {"bytes": 0}

    def charge(raw):
        if len(raw) > max_bytes - meter["bytes"]:
            raise _ByteBudget("native inventory byte budget")
        meter["bytes"] += len(raw)

    gate._snapshot_observer = charge
    try:
        return _sync_lanes(gate, cursor=cursor, limit=limit, max_bytes=max_bytes,
                           max_receipts=max_receipts, charge=charge, meter=meter)
    finally:
        gate._snapshot_observer = None


def _sync_lanes(gate, *, cursor, limit, max_bytes, max_receipts, charge, meter):
    if gate.profile_version != TIDES_VERSION or type(limit) is not int or not 1 <= limit <= 256 or \
            type(max_receipts) is not int or not 1 <= max_receipts <= 256:
        raise ValueError("invalid v6 native inventory policy or bounded budget")
    position = _fair_cursor(cursor)
    gate._check_seal()
    _, tip = gate._context()
    result = {"native_tip": tip, "cursor": position, "complete": False, "inventory_revision": None,
              "pages": 0, "snapshots": 0, "proofs_examined": 0, "accepted": [], "already_retained": 0,
              "ineligible": 0, "deferred": [], "bytes_charged": 0, "limit_reason": None,
              "recent_gap": False, "recent_epoch_changed": False, "recent_pages": 0, "archive_pages": 0}
    archive_complete, recent_complete = False, False
    while result["pages"] < limit and result["proofs_examined"] < max_receipts:
        lane = position["next_lane"]
        if lane == "archive" and archive_complete:
            lane = "recent"
        if lane == "recent" and recent_complete:
            lane = "archive"
        if archive_complete and recent_complete:
            result["complete"] = True
            break
        position["next_lane"] = "archive" if lane == "recent" else "recent"
        recent = position["recent"]
        if lane == "recent":
            page = gate.rpc("getsharepoolhashrecent", recent["after"], 1)
            if (type(page) is not dict or type(page.get("entries")) is not list or len(page["entries"]) > 1 or
                    any(type(page.get(key)) is not int or not 0 <= page[key] < 1 << 64 for key in ("next", "latest")) or
                    page["next"] > page["latest"] or type(page.get("gap")) is not bool or
                    not native_archive.is_hash(page.get("epoch")) or
                    any(type(entry) is not dict or set(entry) != {"sequence", "hash"} or
                        type(entry["sequence"]) is not int or not 0 < entry["sequence"] <= page["next"] or
                        not native_archive.is_hash(entry["hash"]) for entry in page["entries"])):
                raise ValueError("native recent pagination response failed binding")
            gate._stable(tip)
            result["recent_pages"] += 1
            result["pages"] += 1
            if recent["epoch"] is not None and recent["epoch"] != page["epoch"]:
                result["recent_epoch_changed"] = True
                recent.update(after=0, epoch=page["epoch"], snapshot=None, share=0, sequence=0)
                continue  # Retry from zero even if the new sequence already exceeds the old cursor.
            recent["epoch"] = page["epoch"]
            result["recent_gap"] |= page["gap"]
            if recent["snapshot"] is None:
                if not page["entries"]:
                    recent["after"] = page["next"]
                    recent_complete = recent["after"] == page["latest"]
                    continue
                entry = page["entries"][0]
                if entry["sequence"] <= recent["after"] and not page["gap"]:
                    raise ValueError("native recent cursor made no progress")
                recent.update(snapshot=entry["hash"], share=0, sequence=entry["sequence"])
            work_cursor = {"after": None, "snapshot": recent["snapshot"], "share": recent["share"]}
        else:
            work_cursor = position["archive"]
            result["archive_pages"] += 1
            result["pages"] += 1
        part = _sync_native_receipts(gate, cursor=work_cursor, limit=1, max_bytes=max_bytes,
            max_receipts=max_receipts - result["proofs_examined"], charge=charge, meter=meter)
        for key in ("snapshots", "proofs_examined", "already_retained", "ineligible"):
            result[key] += part[key]
        result["accepted"].extend(part["accepted"])
        result["deferred"].extend(part["deferred"])
        if part["inventory_revision"] is not None:
            result["inventory_revision"] = part["inventory_revision"]
        if lane == "recent":
            if part["cursor"]["snapshot"] is None:
                recent.update(after=recent["sequence"], snapshot=None, share=0, sequence=0)
            else:
                recent["share"] = part["cursor"]["share"]
        else:
            position["archive"] = part["cursor"]
            archive_complete = part["complete"]
        if part["limit_reason"] in ("bytes", "proofs"):
            result["limit_reason"] = part["limit_reason"]
            break
    result["complete"] = archive_complete and recent_complete
    if not result["complete"] and result["limit_reason"] is None:
        result["limit_reason"] = "proofs" if result["proofs_examined"] >= max_receipts else "pages"
    gate._stable(tip)
    gate._check_seal()
    result.update(cursor=deepcopy(position), bytes_charged=meter["bytes"], receipt_revision=gate.archive_head()["receipt_revision"])
    return result


def _sync_native_receipts(gate, *, cursor, limit, max_bytes, max_receipts, charge, meter):
    from hash_mining_gate import TEMPLATE, PROOF

    if gate.profile_version != TIDES_VERSION:
        raise ValueError("cross-pool native inventory ingestion requires v6")
    if (type(limit) is not int or not 1 <= limit <= 256 or type(max_receipts) is not int or
            not 1 <= max_receipts <= 256 or type(max_bytes) is not int or not 1024 <= max_bytes <= 256 * 1024 * 1024):
        raise ValueError("invalid bounded native inventory budget")
    position = _cursor(cursor)
    gate._check_seal()
    height, tip = gate._context()
    result = {"native_tip": tip, "cursor": position, "complete": False, "inventory_revision": None,
              "pages": 0, "snapshots": 0, "proofs_examined": 0, "accepted": [], "already_retained": 0,
              "ineligible": 0, "deferred": [], "bytes_charged": 0, "limit_reason": None}

    def deferred(reason, error):
        result["deferred"].append({"snapshot": position["snapshot"], "share": position["share"],
                                   "reason": reason, "detail": str(error)[:160], "retry_cursor": dict(position)})

    while result["pages"] < limit and result["proofs_examined"] < max_receipts:
        if position["snapshot"] is None:
            page = gate.rpc("getsharepoolhashstatus", position["after"], 1)
            if (type(page) is not dict or type(page.get("inventory")) is not list or len(page["inventory"]) > 1 or
                    any(not native_archive.is_hash(value) for value in page["inventory"]) or
                    type(page.get("inventory_complete")) is not bool or
                    (page.get("inventory_next") is not None and not native_archive.is_hash(page["inventory_next"])) or
                    type(page.get("inventory_revision")) is not int or page["inventory_revision"] < 0):
                raise ValueError("native inventory pagination response failed binding")
            result["inventory_revision"] = page["inventory_revision"]
            result["pages"] += 1
            gate._stable(tip)
            if not page["inventory"]:
                if page["inventory_complete"]:
                    position = _cursor()
                    result["complete"] = True
                    break
                if page["inventory_next"] is None or page["inventory_next"] == position["after"]:
                    raise ValueError("native inventory cursor made no progress")
                position["after"] = page["inventory_next"]
                continue
            identity = page["inventory"][0]
            if identity == position["after"]:
                raise ValueError("native inventory repeated exclusive cursor")
            position.update(snapshot=identity, share=0)
        else:
            result["pages"] += 1
        staged = {}
        try:
            source = gate._snapshot(position["snapshot"], staged)
        except _ByteBudget:
            result["limit_reason"] = "bytes"
            break
        except Exception as error:
            deferred("snapshot-unavailable-or-malformed", error)
            position = {"after": position["snapshot"], "snapshot": None, "share": 0}
            continue
        result["snapshots"] += 1
        if position["share"] > len(source.shares):
            raise ValueError("native inventory cursor exceeds immutable snapshot")
        origins = {f"{record.template_id:064x}": record for record in source.templates}
        while position["share"] < len(source.shares) and result["proofs_examined"] < max_receipts:
            proof = source.shares[position["share"]]
            proof_id = f"{proof.proof_id:064x}"
            result["proofs_examined"] += 1
            try:
                charge(proof.serialize())
            except _ByteBudget:
                result["limit_reason"] = "bytes"
                break
            if gate.db.execute("SELECT 1 FROM journal WHERE kind=? AND identity=?", (PROOF, proof_id)).fetchone():
                if gate._read(PROOF, proof_id) != proof.serialize():
                    raise ValueError("native inventory proof conflicts with acknowledged evidence")
                result["already_retained"] += 1
                position["share"] += 1
                continue
            if not gate._eligible(proof.envelope.height, f"{proof.envelope.native_parent:064x}", height):
                result["ineligible"] += 1
                position["share"] += 1
                continue
            try:
                identity = template_id(proof.header)
                origin = origins.get(identity)
                if origin is None:
                    raise ValueError("missing complete proof origin")
                body = origin.data
                charge(body)
                evidence = {(TEMPLATE, identity): body}
                opening = gate._snapshot(proof.header.m_mm_rhs, evidence)
                parent = gate._parent_snapshot(height, tip, evidence)
                gate._require_origin(proof, evidence)
                gate._provenance(opening, evidence, trusted_parent=parent, root_origin=origin, root_depth=1)
                gate._rehydrate_retained(evidence)
                gate._native_share(proof, tip, evidence)
                gate._stable(tip)
                gate._persist([(kind, raw) for (kind, unused), raw in evidence.items()] + [(PROOF, proof.serialize())])
                result["accepted"].append(proof_id)
            except _ByteBudget:
                result["limit_reason"] = "bytes"
                break
            except Exception as error:
                # Tip/profile failures are not per-object invalidity and must
                # stop this pass. Already committed ACKs remain durable.
                gate._stable(tip)
                gate._check_seal()
                deferred("origin-or-proof-validation-unavailable", error)
            position["share"] += 1
        if result["limit_reason"]:
            break
        if position["share"] == len(source.shares):
            position = {"after": position["snapshot"], "snapshot": None, "share": 0}
        else:
            result["limit_reason"] = "proofs"
            break
    if not result["complete"] and result["limit_reason"] is None:
        result["limit_reason"] = "proofs" if result["proofs_examined"] >= max_receipts else "pages"
    gate._stable(tip)
    gate._check_seal()
    result["cursor"] = dict(position)
    result["bytes_charged"] = meter["bytes"]
    result["receipt_revision"] = gate.archive_head()["receipt_revision"]
    return result
