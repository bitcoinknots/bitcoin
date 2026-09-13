#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native paged snapshot archives recover historical v6-r2 payouts and pending blocks.

Only disposable regtest data is removed, while its follower is stopped. Archive
imports authenticate records individually; a later chunk failure may retain the
already verified prefix, which must never be mistaken for a complete backup.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import time

from feature_sharepool_hash_tides import SharePoolHashTidesTest
from hash_snapshot import HashSigner
from test_framework.messages import CBlock, from_hex
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


class SharePoolHashArchiveTest(SharePoolHashTidesTest):
    def add_options(self, parser):
        parser.set_defaults(activation_height=1, cpu_capture=False)

    def set_test_params(self):
        super().set_test_params()
        for args in self.extra_args:
            args.append("-sharepoolarchivemib=2")

    def inventory(self, node, count=2):
        after, found, seen = None, [], set()
        revision = None
        while True:
            result = node.getsharepoolhashstatus(after, count)
            assert len(result["inventory"]) <= count
            assert not seen.intersection(result["inventory"])
            found.extend(result["inventory"])
            seen.update(result["inventory"])
            if revision is None:
                revision = result["inventory_revision"]
            assert_equal(result["inventory_revision"], revision)
            assert 0 <= result["archive_charged_bytes"] <= result["archive_max_bytes"]
            assert_equal(result["archive_max_bytes"], self.expected_quota)
            if result["inventory_complete"]:
                assert_equal(len(found), result["stored_snapshots"])
                return found
            assert result["inventory_next"] is not None
            assert result["inventory_next"] != after
            after = result["inventory_next"]

    def check_verified_records(self, source, follower):
        for opening in self.inventory(follower):
            assert_equal(follower.getsharepoolhashsnapshot(opening), source.getsharepoolhashsnapshot(opening))

    def archive_chunks(self, source, directory):
        after, chunks, total = None, [], 0
        while True:
            path = directory / f"part-{len(chunks):03d}.spha"
            value = source.exportsharepoolhasharchive(str(path), after, 2, 32768)
            assert 0 < value["records"] <= 2
            assert value["bytes"] <= 32768
            if os.name == "posix":
                assert_equal(stat.S_IMODE(path.stat().st_mode), 0o600)
                assert_equal(value["directory_synced"], True)
            chunks.append((path, value))
            total += value["records"]
            if value["inventory_complete"]:
                break
            assert value["next_after"] is not None
            assert value["next_after"] != after
            after = value["next_after"]
        assert_equal(total, source.getsharepoolhashstatus()["stored_snapshots"])
        assert len(chunks) > 2
        return chunks

    def check_bad_files(self, source, follower, chunks, directory):
        original = chunks[0][0].read_bytes()
        variants = {}
        wrong = bytearray(original)
        wrong[12:16] = struct.pack("<I", 4)
        variants["wrong-profile"] = (bytes(wrong), "profile mismatch")
        corrupt = bytearray(original)
        # 12 magic + uint32 profile + byte cursor-present + cursor32;
        # then uint32 record length + record hash32, followed by payload.
        corrupt[12 + 4 + 1 + 32 + 4 + 32] ^= 1
        variants["corrupt-first-record"] = (bytes(corrupt), "record hash mismatch")
        variants["truncated-footer"] = (original[:-1], None)
        variants["trailing-data"] = (original + b"x", "trailing data")
        for name, (raw, reason) in variants.items():
            path = directory / f"{name}.spha"
            path.write_bytes(raw)
            before = follower.getsharepoolhashstatus()["stored_snapshots"]
            assert_raises_rpc_error(None, reason, follower.importsharepoolhasharchive, str(path), 2, 32768)
            if name in ("wrong-profile", "corrupt-first-record"):
                assert_equal(follower.getsharepoolhashstatus()["stored_snapshots"], before)
            self.check_verified_records(source, follower)
        assert_raises_rpc_error(None, "budget", follower.importsharepoolhasharchive, str(chunks[0][0]), 1, 32768)
        assert_raises_rpc_error(None, "budget", follower.importsharepoolhasharchive, str(chunks[0][0]), 2, 1)
        self.check_verified_records(source, follower)

    def check_options(self, final, directory):
        node = self.nodes[1]
        self.stop_node(1)
        marker = Path(node.chain_path) / "sharepool-profile-v6"
        before = marker.read_bytes()
        base = [arg for arg in self.extra_args[1] if not arg.startswith("-sharepoolarchivemib")]
        for value in ("0", "-1", "1.5", "18446744073709551616", "18446744073709551615"):
            node.assert_start_raises_init_error(base + [f"-sharepoolarchivemib={value}"],
                "-sharepoolarchivemib must be a positive whole MiB", match=ErrorMatch.PARTIAL_REGEX)
        node.assert_start_raises_init_error(base + ["-sharepoolarchivemib=1", "-sharepoolarchivemib=2"],
            "-sharepoolarchivemib requires one value", match=ErrorMatch.PARTIAL_REGEX)
        # A genuinely fresh datadir is used so an existing v6 profile marker
        # cannot hide the archive option's no-hash-only validation branch.
        plain = directory / "plain-regtest"
        plain.mkdir()
        node.assert_start_raises_init_error([f"-datadir={plain}", "-regtest", "-sharepoolarchivemib=1"],
            "-sharepoolarchivemib requires one value and the explicit regtest hash-only profile", match=ErrorMatch.PARTIAL_REGEX)
        assert_equal(marker.read_bytes(), before)
        self.start_node(1, base + ["-sharepoolarchivemib=1"])
        self.expected_quota = 1024 * 1024
        assert_equal(node.getbestblockhash(), final.hash)
        self.inventory(node)
        assert_equal(marker.read_bytes(), before)
        self.restart_node(1, base + ["-sharepoolarchivemib=2", "-reindex-chainstate"])
        self.expected_quota = 2 * 1024 * 1024
        assert_equal(node.getbestblockhash(), final.hash)
        assert node.verifychain(4, 0)
        self.inventory(node)
        assert_equal(marker.read_bytes(), before)

    def check_p2p_pages(self, source, follower, final, directory):
        self.log.info("P2P inventory crosses its first 1,024 records using bounded untrusted preimages")
        # These tiny opaque records intentionally are NOT valid snapshots, jobs,
        # shares or blocks. Their hashes exercise storage/transport pagination;
        # no native block references them or gains validity from their presence.
        fixtures = {}
        for i in range(1030):
            raw = b"\x06" + struct.pack("<I", i)
            result = source.submitsharepoolhashsnapshot(raw.hex())
            fixtures[result["hash"]] = raw.hex()
        first = source.getsharepoolhashstatus()
        assert_equal(len(first["inventory"]), 1024)
        assert_equal(first["inventory_complete"], False)
        assert first["inventory_next"] is not None
        source_inventory = self.inventory(source, 128)
        beyond_first_page = set(source_inventory) - set(first["inventory"])
        assert beyond_first_page.intersection(fixtures)
        # Preload the first 1,024 records so the fixed peer-admission pacing
        # does not turn a pagination regression into a multi-minute load test.
        # Restart the source to clear recent announcements: missing tail data
        # must now be found through the persistent archive's later P2P pages.
        prefix = directory / "p2p-preloaded-prefix.spha"
        exported = source.exportsharepoolhasharchive(str(prefix), None, 1024, 1024 * 1024)
        assert_equal(exported["records"], 1024)
        assert_equal(exported["inventory_complete"], False)
        follower.importsharepoolhasharchive(str(prefix), 1024, 1024 * 1024)
        missing = beyond_first_page - set(self.inventory(follower, 128))
        assert missing
        self.restart_node(0)
        assert_equal(source.getbestblockhash(), final.hash)
        self.connect_nodes(0, 1)
        def complete():
            assert source.getconnectioncount() > 0 and follower.getconnectioncount() > 0, "Paged archive relay disconnected"
            return follower.getsharepoolhashstatus()["stored_snapshots"] == len(source_inventory)
        self.wait_until(complete, timeout=180)
        assert_equal(set(self.inventory(follower, 128)), set(source_inventory))
        for opening in beyond_first_page.intersection(fixtures):
            assert_equal(follower.getsharepoolhashsnapshot(opening)["data"], fixtures[opening])
        assert_equal(source.getbestblockhash(), final.hash)
        assert_equal(follower.getbestblockhash(), final.hash)
        return {"opaque_records": len(fixtures), "total_records": len(source_inventory),
                "records_beyond_first_page": len(beyond_first_page),
                "records_fetched_from_later_archive_pages": len(missing),
                "preloaded_inventory_records": 1024, "source_recent_announcements_cleared_by_restart": True,
                "kind": "Untrusted hash-addressed transport, not validated mining evidence"}

    def run_test(self):
        source, follower = self.nodes
        self.expected_quota = 2 * 1024 * 1024
        self.genesis = int(source.getblockhash(0), 16)
        directory = Path(self.options.tmpdir) / "snapshot-archive-fixtures"
        directory.mkdir()
        key_paths = [directory / f"signer-{i}.key" for i in range(2)]
        started = time.monotonic()
        try:
            signers = [HashSigner.create(self.signer_binary, path,
                pool=303, payout_script=b"\x00\x14" + bytes([i + 1]) * 20) for i, path in enumerate(key_paths)]
            a, b = signers
            origins = [self.origin(0, signer) for signer in signers]
            previous, previous_opening = self.mine(0, a,
                templates=[x[0] for x in origins], shares=[x[2] for x in origins])
            expected = {a.payout_script: 2_500_000_000, b.payout_script: 2_500_000_000}
            assert_equal(self.payouts(previous), expected)
            for _ in range(7):
                previous, previous_opening = self.mine(0, a)
                assert_equal(self.payouts(previous), expected)
            self.connect_nodes(0, 1)
            self.wait_tip(previous)
            self.disconnect_nodes(0, 1)
            self.log.info("Paged inventory crosses several cursors without omissions or duplicates")
            first_inventory = self.inventory(source)
            assert len(first_inventory) >= 10
            for count in (0, -1, 1025):
                assert_raises_rpc_error(-8, "count", source.getsharepoolhashstatus, None, count)

            final, final_opening = self.mine(0, b)
            assert_equal(self.payouts(final), expected)
            final_inventory = self.inventory(source)
            assert set(first_inventory) < set(final_inventory)
            chunks = self.archive_chunks(source, directory)
            original_digest = hashlib.sha256(chunks[0][0].read_bytes()).hexdigest()
            assert_raises_rpc_error(None, None, source.exportsharepoolhasharchive, str(chunks[0][0]))
            assert_equal(hashlib.sha256(chunks[0][0].read_bytes()).hexdigest(), original_digest)
            assert_raises_rpc_error(None, "absolute", source.exportsharepoolhasharchive, "relative.spha")
            assert_raises_rpc_error(None, "absolute", source.importsharepoolhasharchive, "relative.spha")
            nul_path = directory / "must-not-create-nul-prefix.spha"
            assert_raises_rpc_error(-8, "NUL", source.exportsharepoolhasharchive, str(nul_path) + "\x00suffix")
            assert not nul_path.exists()
            assert_raises_rpc_error(-8, "NUL", source.importsharepoolhasharchive, str(chunks[0][0]) + "\x00suffix")
            assert_raises_rpc_error(None, None, source.exportsharepoolhasharchive, str(directory))
            assert_raises_rpc_error(None, "regular", source.importsharepoolhasharchive, str(directory))
            if os.name == "posix":
                pipe = directory / "must-not-block.fifo"
                os.mkfifo(pipe, 0o600)
                # No writer opens this FIFO. A bounded RPC timeout makes a
                # regression fail instead of hanging the entire test process.
                bounded_rpc = get_rpc_proxy(source.url, source.index, timeout=5)
                try:
                    assert_raises_rpc_error(None, "regular", bounded_rpc.importsharepoolhasharchive, str(pipe))
                finally:
                    pipe.unlink()
            for count in (0, 1025):
                invalid_path = directory / f"invalid-count-{count}.spha"
                assert_raises_rpc_error(-8, "max_records", source.exportsharepoolhasharchive,
                                        str(invalid_path), None, count, 32768)
                assert not invalid_path.exists()
                assert_raises_rpc_error(-8, "max_records", follower.importsharepoolhasharchive,
                                        str(chunks[0][0]), count, 32768)
            for size in (0, 268435457):
                invalid_path = directory / f"invalid-bytes-{size}.spha"
                assert_raises_rpc_error(-8, "max_bytes", source.exportsharepoolhasharchive,
                                        str(invalid_path), None, 2, size)
                assert not invalid_path.exists()
                assert_raises_rpc_error(-8, "max_bytes", follower.importsharepoolhasharchive,
                                        str(chunks[0][0]), 2, size)

            self.log.info("A missing historical snapshot archive leaves the next exact-payout block pending")
            self.stop_node(1)
            shutil.rmtree(Path(follower.chain_path) / "sharepool-snapshots-v6")
            self.start_node(1)
            assert_equal(follower.getbestblockhash(), previous.hash)
            self.store(1, previous_opening)
            self.store(1, final_opening)
            assert_equal(follower.submitblock(final.serialize().hex()), "sharepool-hash-data-missing")
            assert_equal(follower.getbestblockhash(), previous.hash)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.restart_node(1)
            assert_equal(follower.getsharepoolhashstatus()["pending_blocks"], 1)
            self.log.info("Damaged imports retain only individually authenticated record prefixes")
            self.check_bad_files(source, follower, chunks, directory)
            for path, exported in chunks:
                imported = follower.importsharepoolhasharchive(str(path), 2, 32768)
                assert_equal(imported["directory_synced"], False)
                for key in ("records", "bytes", "next_after", "inventory_complete"):
                    assert_equal(imported[key], exported[key])
            self.wait_tip(final)
            recovered_worker = follower.getsharepoolhashstatus()["validation_worker"]
            assert_equal(set(self.inventory(follower)), set(final_inventory))
            assert_equal(follower.getblock(final.hash, 0), source.getblock(final.hash, 0))
            self.check_verified_records(source, follower)
            self.restart_node(1)
            assert_equal(follower.getbestblockhash(), final.hash)
            assert_equal(self.payouts(from_hex(CBlock(), follower.getblock(final.hash, 0))), expected)
            self.check_options(final, directory)
            self.restart_node(1, self.extra_args[1] + ["-reindex"])
            assert_equal(follower.getbestblockhash(), final.hash)
            assert follower.verifychain(4, 0)
            self.check_verified_records(source, follower)
            transport = self.check_p2p_pages(source, follower, final, directory)
            result = {"kind": "native v6-r2 paged snapshot archive recovery; disposable regtest",
                "height": final.m_height, "tip": final.hash, "snapshots": len(final_inventory),
                "chunks": len(chunks), "payout_satoshis": sorted(expected.values()),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "pending_recovery_worker_observed": recovered_worker,
                "p2p_inventory": transport,
                "timing_scope": "Small disposable native recovery fixture; not sustained validation throughput",
                "checks": ["paged RPC inventory", "exclusive 0600 export", "hash/profile/truncation rejection",
                           "authenticated partial retention", "pending-block import recovery", "restart",
                           "reindex-chainstate", "full reindex", "finite quota option validation", "P2P inventory beyond 1,024 records"]}
            (Path(self.options.tmpdir) / "archive-result.json").write_text(json.dumps(result, indent=2) + "\n")
            self.log.info("Native archive recovery passed: %s", result)
        finally:
            for path in key_paths:
                path.unlink(missing_ok=True)

if __name__ == "__main__":
    SharePoolHashArchiveTest(__file__).main()
