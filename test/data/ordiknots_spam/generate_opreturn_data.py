#!/usr/bin/env python3
"""
Generate OP_RETURN data with ordiknots spam pattern for testing.

This script creates OP_RETURN data that matches what ordiknots would generate,
without needing a full Bitcoin node or the ordiknots CLI.
"""

import os
import struct

# ordiknots constants (from ordiknots/src/techniques/chained_op_return/encode.rs)
ORDIKNOT_PREFIX = b"444"
MAX_OP_RETURN_SIZE = 83  # Bitcoin Core standard
METADATA_SIZE = 5  # prefix (3) + index (1) + total_chunks (1)
FIRST_CHUNK_METADATA_SIZE = 7  # + file_size (2)

def create_opreturn_chunks(data):
    """
    Create OP_RETURN chunks with ordiknots pattern.

    Format:
    - First chunk: "444" + index (0) + total_chunks + file_size (u16 LE) + data
    - Other chunks: "444" + index + total_chunks + data
    """
    file_size = len(data)

    # calculate data capacity per chunk
    first_chunk_data_capacity = MAX_OP_RETURN_SIZE - FIRST_CHUNK_METADATA_SIZE
    subsequent_chunk_data_capacity = MAX_OP_RETURN_SIZE - METADATA_SIZE

    # split data into chunks
    chunks = []
    offset = 0

    # first chunk
    first_chunk_data = data[offset:offset + first_chunk_data_capacity]
    offset += len(first_chunk_data)

    # calculate total chunks needed
    if offset >= file_size:
        total_chunks = 1
    else:
        remaining = file_size - offset
        total_chunks = 1 + (remaining + subsequent_chunk_data_capacity - 1) // subsequent_chunk_data_capacity

    # build first chunk
    first_chunk = bytearray()
    first_chunk.extend(ORDIKNOT_PREFIX)  # "444"
    first_chunk.append(0)  # chunk index
    first_chunk.append(total_chunks)  # total chunks
    first_chunk.extend(struct.pack('<H', file_size))  # file size (little-endian u16)
    first_chunk.extend(first_chunk_data)
    chunks.append(bytes(first_chunk))

    # subsequent chunks
    chunk_index = 1
    while offset < file_size:
        chunk_data = data[offset:offset + subsequent_chunk_data_capacity]

        chunk = bytearray()
        chunk.extend(ORDIKNOT_PREFIX)  # "444"
        chunk.append(chunk_index)  # chunk index
        chunk.append(total_chunks)  # total chunks
        chunk.extend(chunk_data)
        chunks.append(bytes(chunk))

        offset += len(chunk_data)
        chunk_index += 1

    return chunks

def generate_opreturn_spam():
    """Generate OP_RETURN data for test files."""
    test_dir = os.path.dirname(os.path.abspath(__file__))

    for filename in ['tiny.dat', 'small.dat']:
        filepath = os.path.join(test_dir, filename)

        with open(filepath, 'rb') as f:
            data = f.read()

        # create OP_RETURN chunks
        chunks = create_opreturn_chunks(data)

        # save first chunk (what the filter will see)
        output_file = os.path.join(test_dir, f'opreturn_{filename.replace(".dat", "_chunk0")}.hex')
        with open(output_file, 'w') as f:
            f.write(chunks[0].hex())

        print(f"✓ Generated {output_file}")
        print(f"  Data: {len(data)} bytes → {len(chunks)} chunks")
        print(f"  First chunk: {len(chunks[0])} bytes")

        # verify "444" prefix
        if chunks[0].startswith(ORDIKNOT_PREFIX):
            print(f"  ✓ Starts with '444' prefix (will be detected as spam)")

        # verify chunk 0
        if len(chunks[0]) >= 5 and chunks[0][3] == 0:
            print(f"  ✓ Chunk index = 0 (first chunk)")
        else:
            print(f"  ✗ ERROR: Not a first chunk!")

        print()

    # skip medium.dat for OP_RETURN (would create too many chunks)
    print("Note: Skipped medium.dat for OP_RETURN (would create many chunks)")

if __name__ == '__main__':
    generate_opreturn_spam()
