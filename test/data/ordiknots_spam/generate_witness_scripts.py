#!/usr/bin/env python3
"""
Generate P2WSH witness scripts with ordiknots spam pattern for testing.

This script creates witness scripts that match what ordiknots would generate,
without needing a full Bitcoin node or the ordiknots CLI.
"""

import os
import struct

# ordiknots constants (from ordiknots/src/techniques/p2wsh_fake_multisig/encode.rs)
ORDIKNOT_PREFIX = b"444"
MAX_PUBKEYS_PER_MULTISIG = 20
DATA_BYTES_PER_PUBKEY = 32
MAX_DATA_CAPACITY = (MAX_PUBKEYS_PER_MULTISIG - 1) * DATA_BYTES_PER_PUBKEY - len(ORDIKNOT_PREFIX)

def encode_data_as_fake_pubkeys(data):
    """
    Encode data as fake compressed pubkeys.

    Each pubkey: 1 byte prefix (0x02/0x03) + 32 bytes data
    Prefix chosen based on first bit of data chunk.
    """
    fake_pubkeys = []

    for i in range(0, len(data), DATA_BYTES_PER_PUBKEY):
        chunk = data[i:i + DATA_BYTES_PER_PUBKEY]

        # choose prefix based on first bit
        if chunk and (chunk[0] & 0x80):
            prefix = 0x03
        else:
            prefix = 0x02

        # pad chunk to 32 bytes if needed
        if len(chunk) < DATA_BYTES_PER_PUBKEY:
            chunk = chunk + b'\x00' * (DATA_BYTES_PER_PUBKEY - len(chunk))

        fake_pubkey = bytes([prefix]) + chunk
        fake_pubkeys.append(fake_pubkey)

    return fake_pubkeys

def create_multisig_witness_script(data_with_prefix, real_pubkey=None):
    """
    Create a CHECKMULTISIG witnessScript with embedded data.

    Format: OP_1 <real_pubkey> <fake_pk_1> ... <fake_pk_N> OP_N OP_CHECKMULTISIG
    """
    if real_pubkey is None:
        # use a dummy real pubkey (doesn't matter for filter testing)
        real_pubkey = b'\x02' + b'\x11' * 32  # 33 bytes: 0x02 + 32 bytes

    # encode data as fake pubkeys
    fake_pubkeys = encode_data_as_fake_pubkeys(data_with_prefix)

    # total pubkeys: 1 real + N fake
    total_pubkeys = 1 + len(fake_pubkeys)

    if total_pubkeys > MAX_PUBKEYS_PER_MULTISIG:
        raise ValueError(f"Too many pubkeys: {total_pubkeys} > {MAX_PUBKEYS_PER_MULTISIG}")

    # build witnessScript
    script = bytearray()

    # OP_1 (required signatures)
    script.append(0x51)

    # real pubkey (33 bytes)
    script.append(0x21)  # PUSH 33 bytes
    script.extend(real_pubkey)

    # fake pubkeys (33 bytes each)
    for fake_pk in fake_pubkeys:
        script.append(0x21)  # PUSH 33 bytes
        script.extend(fake_pk)

    # OP_N (total pubkeys)
    script.append(0x50 + total_pubkeys)

    # OP_CHECKMULTISIG
    script.append(0xae)

    return bytes(script)

def generate_spam_witness_scripts():
    """Generate witness scripts for test data files."""
    test_dir = os.path.dirname(__file__)

    for filename in ['tiny.dat', 'small.dat', 'medium.dat']:
        filepath = os.path.join(test_dir, filename)

        with open(filepath, 'rb') as f:
            data = f.read()

        # add ordiknots prefix
        data_with_prefix = ORDIKNOT_PREFIX + data

        # create witness script
        witness_script = create_multisig_witness_script(data_with_prefix)

        # save as hex
        output_file = os.path.join(test_dir, f'witness_{filename.replace(".dat", "")}.hex')
        with open(output_file, 'w') as f:
            f.write(witness_script.hex())

        print(f"✓ Generated {output_file}")
        print(f"  Data: {len(data)} bytes → WitnessScript: {len(witness_script)} bytes")
        print(f"  Pubkeys: {1 + len(encode_data_as_fake_pubkeys(data_with_prefix))}")

        # verify "444" is in the script
        if b'444' in witness_script:
            print(f"  ⚠️  Raw '444' found in script (expected)")

        # verify decoded data starts with "444"
        # (this is what the Lua filter checks)
        fake_pubkeys = encode_data_as_fake_pubkeys(data_with_prefix)
        decoded_data = b''.join(pk[1:] for pk in fake_pubkeys)  # skip 0x02/0x03 prefix
        decoded_data = decoded_data.rstrip(b'\x00')  # strip null padding

        if decoded_data.startswith(ORDIKNOT_PREFIX):
            print(f"  ✓ Decoded data starts with '444' (will be detected as spam)")
        else:
            print(f"  ✗ ERROR: Decoded data doesn't start with '444'!")

        print()

if __name__ == '__main__':
    generate_spam_witness_scripts()
