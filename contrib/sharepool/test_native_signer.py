#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Public-input adapter bounds and optional real native signer integration tests.

Set SHAREPOOL_SIGNER_BINARY to a freshly built bitcoin-sharepool-signer to run
the native key/file tests; those tests generate only disposable random keys.
"""

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from native_enforcement import Envelope, RULES_HASH, candidate, verify_schnorr, compute_xonly_pubkey
from native_signer import NativeSigner, REGTEST_GENESIS, SignerError


SCRIPT = b"\x00\x14" + b"r" * 20
POOL = 0xabc123
NATIVE_BINARY = os.environ.get("SHAREPOOL_SIGNER_BINARY")


class SignerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sharepool-signer-adapter-")
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def binary(self, source):
        path = self.directory / "signer"
        path.write_text("#!" + sys.executable + "\n" + source)
        path.chmod(0o700)
        return path

    def open(self, source, **extra):
        return NativeSigner(self.binary(source), self.directory / "unused-key",
                            pool=POOL, payout_script=SCRIPT, **extra)

    def test_exact_output_and_command_paths(self):
        binary = self.binary("import sys\nassert len(sys.argv) == 3\nassert sys.argv[1] == 'pubkey'\n"
            "assert sys.stdin.buffer.read() == b''\nprint('42' * 32)\n")
        signer = NativeSigner(binary, self.directory / "private key;literal", pool=POOL, payout_script=SCRIPT)
        self.assertEqual(signer.public_key, b"B" * 32)
        self.assertFalse((self.directory / "private key;literal").exists())

    def test_migration_passes_trusted_public_statement_and_literal_paths(self):
        binary = self.binary("import sys\nassert len(sys.argv) == 4\nassert sys.argv[1] == 'migrate'\n"
            "raw = bytes.fromhex(sys.stdin.read().strip())\n"
            "assert raw == bytes.fromhex(%r)\nprint('42' * 32)\n" %
            (b"\x01" + POOL.to_bytes(32, "little") + bytes([len(SCRIPT)]) + SCRIPT + b"B" * 32).hex())
        destination = self.directory / "new key;literal"
        signer = NativeSigner.migrate(binary, self.directory / "old key;literal", destination,
                                      expected_public_key=b"B" * 32, pool=POOL, payout_script=SCRIPT)
        self.assertEqual(signer.public_key, b"B" * 32)
        self.assertEqual(signer.key_file, str(destination))

    def test_rejects_oversized_stdout_and_stderr(self):
        for output in ("stdout", "stderr"):
            with self.subTest(output=output), self.assertRaises(SignerError):
                self.open("import os,sys\nos.write(sys.%s.fileno(), b'x' * 100000)\n" % output)

    def test_rejects_failure_or_ambiguous_output(self):
        for source in ("print('42' * 32); raise SystemExit(2)",
                       "import sys; print('42' * 32); print('warning', file=sys.stderr)",
                       "print('AB' * 32)", "print('42' * 31)", "print('42' * 32); print('')"):
            with self.subTest(source=source), self.assertRaises(SignerError):
                self.open(source + "\n")

    def test_timeout_kills_silent_process(self):
        started = time.monotonic()
        with self.assertRaises(SignerError):
            self.open("import time\ntime.sleep(60)\n", timeout=0.1)
        self.assertLess(time.monotonic() - started, 2)

    def test_sign_timeout_is_bounded_even_when_child_does_not_read(self):
        signer = self.open("import sys,time\nif sys.argv[1] == 'pubkey': print('42' * 32)\n"
                           "else: time.sleep(60)\n")
        signer.timeout = 0.1
        envelope = Envelope(REGTEST_GENESIS, RULES_HASH, 1, REGTEST_GENESIS, POOL, signer.public_key, SCRIPT)
        with self.assertRaises(SignerError):
            signer.sign_owner(envelope)

    def test_bad_policy_and_timeout_rejected_before_launch(self):
        for kwargs in ({"pool": 0}, {"pool": -1}, {"pool": True}, {"payout_script": b"\x51"},
                       {"timeout": 0}, {"timeout": float("nan")}, {"timeout": 31}):
            params = {"pool": POOL, "payout_script": SCRIPT, **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                NativeSigner("/not/a/signer", "/not/a/key", **params)

    def test_external_builder_signature_and_identity_requirements(self):
        # This is an API negative test. All actual native signing tests use
        # freshly generated keys below, with no Python secret passed to builders.
        arguments = dict(genesis=REGTEST_GENESIS, native_parent=REGTEST_GENESIS,
                         height=1, ntime=1700000001, pool=POOL, payout_script=SCRIPT)
        for signing in ({}, {"public_key": b"B" * 32},
                        {"public_key": b"B" * 32, "sign_owner": lambda env: bytes(64)},
                        {"public_key": b"B" * 32, "sign_owner": lambda env: bytes(63)},
                        {"secret": bytes(32), "public_key": b"B" * 32, "sign_owner": lambda env: bytes(64)}):
            with self.subTest(signing=signing), self.assertRaises(ValueError):
                candidate(**arguments, **signing)


@unittest.skipUnless(NATIVE_BINARY, "set SHAREPOOL_SIGNER_BINARY for native signer integration")
class NativeSignerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sharepool-native-signer-")
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.key = self.directory / "owner.key"
        self.signer = NativeSigner.create(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT)

    def envelope(self):
        return Envelope(REGTEST_GENESIS, RULES_HASH, 1, REGTEST_GENESIS, POOL, self.signer.public_key, SCRIPT)

    def raw(self, command, data=b"", path=None):
        return subprocess.run([NATIVE_BINARY, command, str(path or self.key)], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)

    def test_random_key_policy_file_and_valid_signature(self):
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertLessEqual(self.key.stat().st_size, 140)
        with self.key.open("rb") as stream:
            self.assertEqual(stream.read(8), b"SPKEY002")
        opened = NativeSigner(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT)
        self.assertEqual(opened.public_key, self.signer.public_key)
        signature = self.signer.sign_owner(self.envelope())
        self.assertTrue(verify_schnorr(self.signer.public_key, signature, self.envelope().owner_message))
        another = NativeSigner.create(NATIVE_BINARY, self.directory / "other.key", pool=POOL, payout_script=SCRIPT)
        self.assertNotEqual(another.public_key, self.signer.public_key)

    def test_secretless_builder_and_owner_signature(self):
        block, manifest = candidate(genesis=REGTEST_GENESIS, native_parent=REGTEST_GENESIS,
            height=1, ntime=1700000001, pool=POOL, payout_script=SCRIPT,
            public_key=self.signer.public_key, sign_owner=self.signer.sign_owner)
        self.assertEqual(block.m_mm_rhs, manifest.envelope.root)
        self.assertTrue(verify_schnorr(self.signer.public_key, manifest.owner_signature, manifest.envelope.owner_message))

    def test_init_never_overwrites_existing_key(self):
        public = self.signer.public_key
        with self.assertRaises(SignerError):
            NativeSigner.create(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT)
        self.assertEqual(NativeSigner(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT).public_key, public)

    def test_group_readable_and_wrong_modes_rejected(self):
        for mode in (0o644, 0o640, 0o400, 0o700):
            self.key.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT)
        self.key.chmod(0o600)

    def test_symlink_and_hardlink_rejected(self):
        alias = self.directory / "alias"
        alias.symlink_to(self.key)
        with self.assertRaises(SignerError):
            NativeSigner(NATIVE_BINARY, alias, pool=POOL, payout_script=SCRIPT)
        alias.unlink()
        os.link(self.key, alias)
        for path in (alias, self.key):
            with self.subTest(path=path.name), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, path, pool=POOL, payout_script=SCRIPT)

    def test_fifo_and_directory_rejected_without_blocking(self):
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        for path in (fifo, self.directory):
            with self.subTest(path=path.name), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, path, pool=POOL, payout_script=SCRIPT, timeout=1)

    def test_policy_and_network_checks_are_native(self):
        for change in ({"genesis": 1}, {"rules": 1}, {"version": 2}, {"height": 0},
                       {"height": 0x7fffffff}, {"native_parent": 0}, {"pool": POOL + 1},
                       {"payout_script": b"\x00\x14" + b"z" * 20}, {"public_key": b"\x01" * 32}):
            wrong = replace(self.envelope(), **change)
            result = self.raw("sign", wrong.serialize().hex().encode() + b"\n")
            with self.subTest(change=change):
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_native_stdin_strict_bounds_and_canonical_encoding(self):
        valid = self.envelope().serialize()
        for data in (b"x" * 10000, valid.hex().encode() + b"00\n", b" " + valid.hex().encode(),
                     valid.hex().encode() + b"\n\n", valid[:-1].hex().encode(), b"\n"):
            with self.subTest(size=len(data)):
                result = self.raw("sign", data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_native_init_policy_rejections_do_not_create_keys(self):
        policy = b"\x01" + POOL.to_bytes(32, "little") + bytes([len(SCRIPT)]) + SCRIPT
        for index, data in enumerate((b"\x02" + policy[1:], b"\x01" + bytes(32) + policy[33:],
                                     policy + b"\x00", policy[:33] + b"\xfd\x16\x00" + SCRIPT,
                                     b"\x01" + policy[1:33] + b"\x01\x51")):
            path = self.directory / ("rejected-%d.key" % index)
            result = self.raw("init", data.hex().encode() + b"\n", path=path)
            with self.subTest(index=index):
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertFalse(path.exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS extended ACL behavior")
    def test_macos_extended_acl_rejected_and_inheritance_cleared(self):
        import pwd
        owner = pwd.getpwuid(os.getuid()).pw_name
        # Grant only the existing owner, not another principal, for this test.
        subprocess.run(["/bin/chmod", "+a", "user:%s allow read" % owner, str(self.key)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        with self.assertRaises(SignerError):
            NativeSigner(NATIVE_BINARY, self.key, pool=POOL, payout_script=SCRIPT)
        inherited = self.directory / "inherited"
        inherited.mkdir(mode=0o700)
        subprocess.run(["/bin/chmod", "+a", "user:%s allow read,file_inherit" % owner, str(inherited)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        created = NativeSigner.create(NATIVE_BINARY, inherited / "owner.key", pool=POOL, payout_script=SCRIPT)
        opened = NativeSigner(NATIVE_BINARY, inherited / "owner.key", pool=POOL, payout_script=SCRIPT)
        self.assertEqual(opened.public_key, created.public_key)

    def test_key_file_truncated_and_oversized_fail_closed(self):
        # Do not read the original private file, even from Python tests.
        for size in (0, 7, 141, 10000):
            corrupt = self.directory / ("invalid-%d.key" % size)
            corrupt.write_bytes(bytes(size))
            corrupt.chmod(0o600)
            with self.subTest(size=size), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, corrupt, pool=POOL, payout_script=SCRIPT)

    def fixture_record(self, version=2):
        # Explicit disposable known-secret fixtures exercise the file format;
        # the randomly generated owner.key is never read by Python tests.
        secret = (1).to_bytes(32, "big")
        policy = b"\x01" + POOL.to_bytes(32, "little") + bytes([len(SCRIPT)]) + SCRIPT
        raw = (b"SPKEY002" if version == 2 else b"SPKEY001") + policy + secret
        if version == 2:
            raw += hashlib.sha256(b"SharePool/signer-key/v2\0" + raw).digest()
        return raw, compute_xonly_pubkey(secret)[0]

    def test_checksummed_fixture_and_each_record_region_detect_corruption(self):
        raw, public_key = self.fixture_record()
        fixture = self.directory / "checksum-fixture.key"
        fixture.write_bytes(raw)
        fixture.chmod(0o600)
        self.assertEqual(NativeSigner(NATIVE_BINARY, fixture, pool=POOL, payout_script=SCRIPT).public_key, public_key)
        # Magic, syntactically valid pool/script bytes, a still-valid scalar,
        # and the checksum itself must all fail before returning a public key.
        for offset in (0, 9, 43, len(raw) - 34, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] ^= 1
            fixture.write_bytes(changed)
            with self.subTest(offset=offset), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, fixture, pool=POOL, payout_script=SCRIPT)
        for length in (len(raw) - 1, len(raw) - 32):
            fixture.write_bytes(raw[:length])
            with self.subTest(length=length), self.assertRaises(SignerError):
                NativeSigner(NATIVE_BINARY, fixture, pool=POOL, payout_script=SCRIPT)

    def test_legacy_migration_preserves_key_and_source_without_overwrite(self):
        raw, public_key = self.fixture_record(version=1)
        source = self.directory / "legacy.key"
        source.write_bytes(raw)
        source.chmod(0o600)
        with self.assertRaises(SignerError):
            NativeSigner(NATIVE_BINARY, source, pool=POOL, payout_script=SCRIPT)
        destination = self.directory / "migrated.key"
        migrated = NativeSigner.migrate(NATIVE_BINARY, source, destination, expected_public_key=public_key,
                                       pool=POOL, payout_script=SCRIPT)
        self.assertEqual(migrated.public_key, public_key)
        self.assertEqual(source.read_bytes(), raw)
        envelope = replace(self.envelope(), public_key=public_key)
        self.assertTrue(verify_schnorr(public_key, migrated.sign_owner(envelope), envelope.owner_message))
        with self.assertRaises(SignerError):
            NativeSigner.migrate(NATIVE_BINARY, source, destination, expected_public_key=public_key,
                                 pool=POOL, payout_script=SCRIPT)
        self.assertEqual(NativeSigner(NATIVE_BINARY, destination, pool=POOL, payout_script=SCRIPT).public_key, public_key)

    def test_legacy_migration_requires_previously_trusted_identity(self):
        raw, public_key = self.fixture_record(version=1)
        source = self.directory / "legacy.key"
        source.write_bytes(raw)
        source.chmod(0o600)
        destination = self.directory / "must-not-exist.key"
        with self.assertRaises(SignerError):
            NativeSigner.migrate(NATIVE_BINARY, source, destination, expected_public_key=b"x" * 32,
                                 pool=POOL, payout_script=SCRIPT)
        self.assertFalse(destination.exists())
        with self.assertRaises(SignerError):
            NativeSigner.migrate(NATIVE_BINARY, source, destination, expected_public_key=public_key,
                                 pool=POOL + 1, payout_script=SCRIPT)
        self.assertFalse(destination.exists())
        self.assertEqual(source.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
