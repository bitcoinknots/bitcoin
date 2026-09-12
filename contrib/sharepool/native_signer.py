#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded local adapter for bitcoin-sharepool-signer; never reads private keys.

Only public policies/envelopes cross stdin. The offline native signer constrains
network, owner, pool and payout script, but cannot establish current-tip context
or full-template validity. The mining gate remains mandatory before dispatch.
"""

import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

from native_enforcement import Envelope, RULES_HASH, is_payout_script, vector, verify_schnorr


REGTEST_GENESIS = int("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", 16)


class SignerError(RuntimeError):
    pass


class NativeSigner:
    """An explicitly selected executable and private policy/key file on this host.

    Construct to open an existing signer, or use create() to exclusively generate
    a fresh native key. The private file is never read by this Python process.
    """

    def __init__(self, binary, key_file, *, pool, payout_script, timeout=5.0):
        self._configure(binary, key_file, pool=pool, payout_script=payout_script, timeout=timeout)
        self.public_key = self._invoke("pubkey", b"", 32)

    def _configure(self, binary, key_file, *, pool, payout_script, timeout):
        if (type(pool) is not int or not 0 < pool < 1 << 256 or
                type(payout_script) is not bytes or not is_payout_script(payout_script)):
            raise ValueError("invalid local signer policy")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("signer timeout must be in (0,30] seconds")
        # No PATH lookup or shell. Do not resolve symlinks in the private file,
        # because native O_NOFOLLOW must see a final symlink.
        self.binary = str(Path(binary).absolute())
        self.key_file = str(Path(key_file).absolute())
        self.pool = pool
        self.payout_script = payout_script
        self.timeout = float(timeout)

    @classmethod
    def create(cls, binary, key_file, *, pool, payout_script, timeout=5.0):
        result = cls.__new__(cls)
        result._configure(binary, key_file, pool=pool, payout_script=payout_script, timeout=timeout)
        policy = b"\x01" + pool.to_bytes(32, "little") + vector(payout_script)
        result.public_key = result._invoke("init", policy, 32)
        return result

    @classmethod
    def migrate(cls, binary, legacy_file, destination, *, expected_public_key, pool, payout_script, timeout=5.0):
        """Explicitly copy a legacy key to a new checksummed file, retaining it.

        The expected public key must come from the owner's existing trusted
        configuration, not a fresh reading of the unchecksummed source file.
        """
        if type(expected_public_key) is not bytes or len(expected_public_key) != 32:
            raise ValueError("migration requires the previously trusted x-only public key")
        result = cls.__new__(cls)
        result._configure(binary, legacy_file, pool=pool, payout_script=payout_script, timeout=timeout)
        policy = b"\x01" + pool.to_bytes(32, "little") + vector(payout_script)
        result.public_key = result._invoke("migrate", policy + expected_public_key, 32, destination=destination)
        if result.public_key != expected_public_key:
            raise SignerError("migrated signer does not match the trusted public key")
        result.key_file = str(Path(destination).absolute())
        return result

    def _invoke(self, command, payload, size, *, destination=None):
        maximum = 360 if command == "sign-job" else (100 if command == "migrate" else 296)
        if (command not in ("init", "pubkey", "sign", "sign-job", "migrate") or type(payload) is not bytes or
                len(payload) > maximum or (command == "migrate") != (destination is not None)):
            raise SignerError("invalid local signer request")
        wire = payload.hex().encode("ascii") + (b"\n" if payload else b"")
        deadline = time.monotonic() + self.timeout
        process = None
        streams = {}
        try:
            arguments = [self.binary, command, self.key_file]
            if destination is not None:
                arguments.append(str(Path(destination).absolute()))
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                bufsize=0)
            with selectors.DefaultSelector() as ready:
                sent = 0
                if wire:
                    os.set_blocking(process.stdin.fileno(), False)
                    ready.register(process.stdin, selectors.EVENT_WRITE, None)
                else:
                    process.stdin.close()
                for stream, maximum in ((process.stdout, size * 2 + 1), (process.stderr, 256)):
                    streams[stream] = bytearray()
                    ready.register(stream, selectors.EVENT_READ, maximum)
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SignerError("local signer timed out")
                    for key, unused in ready.select(remaining):
                        stream, maximum = key.fileobj, key.data
                        if stream is process.stdin:
                            sent += os.write(stream.fileno(), wire[sent:])
                            if sent == len(wire):
                                ready.unregister(stream)
                                stream.close()
                            continue
                        data = os.read(stream.fileno(), maximum - len(streams[stream]) + 1)
                        if not data:
                            ready.unregister(stream)
                            continue
                        streams[stream].extend(data)
                        if len(streams[stream]) > maximum:
                            raise SignerError("local signer exceeded output bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SignerError("local signer timed out")
            code = process.wait(timeout=remaining)
            output = bytes(streams[process.stdout])
            if code != 0 or streams[process.stderr] or re.fullmatch(rb"[0-9a-f]{%d}\n" % (size * 2), output) is None:
                raise SignerError("local signer rejected request or returned invalid output")
            return bytes.fromhex(output[:-1].decode("ascii"))
        except (OSError, subprocess.TimeoutExpired):
            raise SignerError("local signer failed or timed out") from None
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

    def sign_owner(self, envelope):
        if (not isinstance(envelope, Envelope) or envelope.version != 1 or
                envelope.genesis != REGTEST_GENESIS or envelope.rules != RULES_HASH or
                envelope.pool != self.pool or envelope.payout_script != self.payout_script or
                envelope.public_key != self.public_key or not 0 < envelope.height < 0x7fffffff or
                envelope.native_parent == 0):
            raise SignerError("envelope violates local signer policy")
        signature = self._invoke("sign", envelope.serialize(), 64)
        if not verify_schnorr(self.public_key, signature, envelope.owner_message):
            raise SignerError("local signer signature failed verification")
        return signature
