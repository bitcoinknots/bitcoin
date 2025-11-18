# Ordiknots Spam Test Data

This directory contains ordiknots spam test data (witness scripts and OP_RETURN data) generated to test the Lua spam filters.

## Purpose

These files contain real ordiknots spam patterns (with "444" magic prefix) to verify that the spam filters correctly detect and reject them.

## Test Data Files

### Source Data Files
- `tiny.dat` (100 bytes) - Small test file
- `small.dat` (500 bytes) - Medium test file
- `medium.dat` (600 bytes) - Large test file (near max for single P2WSH input)

### Generated P2WSH Spam (Witness Scripts)
- `witness_tiny.hex` (173 bytes) - 5 pubkeys (1 real + 4 fake)
- `witness_small.hex` (581 bytes) - 17 pubkeys (1 real + 16 fake)
- `witness_medium.hex` (683 bytes) - 20 pubkeys (1 real + 19 fake, maximum)

All witness scripts follow the ordiknots P2WSH fake multisig pattern:
- Format: `OP_1 <real_pubkey> <fake_pk_1> ... <fake_pk_N> OP_N OP_CHECKMULTISIG`
- Each fake pubkey: 33 bytes (0x02/0x03 prefix + 32 data bytes)
- Data embedded in fake pubkeys starts with "444" prefix
- When decoded, data begins with ASCII "444" (0x34 0x34 0x34)

### Generated OP_RETURN Spam (First Chunks)
- `opreturn_tiny_chunk0.hex` (83 bytes) - First chunk of 2-chunk chain
- `opreturn_small_chunk0.hex` (83 bytes) - First chunk of 7-chunk chain

All OP_RETURN data follows the ordiknots chained OP_RETURN pattern:
- Format: `"444" + chunk_index (0) + total_chunks + file_size_u16_le + data`
- First chunk always has index 0
- Starts with ASCII "444" (0x34 0x34 0x34)
- Maximum 83 bytes per OP_RETURN (Bitcoin Core standard)

## Generation Scripts

### `generate_witness_scripts.py`
Generates P2WSH witness scripts with ordiknots spam pattern.

**Usage:**
```bash
python3 generate_witness_scripts.py
```

**What it does:**
1. Reads data from `.dat` files
2. Prepends "444" prefix
3. Encodes data as fake compressed pubkeys (33 bytes each)
4. Builds CHECKMULTISIG witness script
5. Saves as hex files

### `generate_opreturn_data.py`
Generates OP_RETURN data with ordiknots chained pattern.

**Usage:**
```bash
python3 generate_opreturn_data.py
```

**What it does:**
1. Reads data from `.dat` files
2. Splits into chunks (max 83 bytes per chunk)
3. Prepends "444" + metadata to each chunk
4. Saves first chunk (index 0) as hex file

## Why Not Use Ordiknots CLI?

The ordiknots CLI requires a running Bitcoin node to create full transactions. Since we only need the witness scripts and OP_RETURN data for filter testing, these Python scripts generate the exact same patterns without needing:
- A running bitcoind
- Wallet setup
- Network connection
- The ordiknots binary in the repo

This makes testing faster and keeps the repo self-contained.

## How to Use in Tests

### P2WSH Spam Test

```python
# Load witness script
with open('test/data/ordiknots_spam/witness_tiny.hex', 'r') as f:
    witness_hex = f.read().strip()

# Convert to bytes
witness_script = bytes.fromhex(witness_hex)

# Create P2WSH transaction with this witness
# The Lua filter should reject it
```

### OP_RETURN Spam Test

```python
# Load OP_RETURN data
with open('test/data/ordiknots_spam/opreturn_tiny_chunk0.hex', 'r') as f:
    opreturn_hex = f.read().strip()

# Convert to bytes
opreturn_data = bytes.fromhex(opreturn_hex)

# Create OP_RETURN output with this data
# The Lua filter should reject it
```

## Verification

All generated files have been verified to:
1. Contain "444" bytes in raw form (fast path detection)
2. Decode to data starting with "444" prefix (full validation)
3. Match the exact pattern ordiknots would generate

### P2WSH Verification Results:
- ✓ witness_tiny.hex: 5 pubkeys, decodes to "444" + data
- ✓ witness_small.hex: 17 pubkeys, decodes to "444" + data
- ✓ witness_medium.hex: 20 pubkeys, decodes to "444" + data

### OP_RETURN Verification Results:
- ✓ opreturn_tiny_chunk0.hex: Starts with "444", chunk index = 0
- ✓ opreturn_small_chunk0.hex: Starts with "444", chunk index = 0

## Regenerating Test Data

If you need to regenerate the test data (e.g., after changing data sizes):

```bash
# Regenerate P2WSH witness scripts
python3 generate_witness_scripts.py

# Regenerate OP_RETURN data
python3 generate_opreturn_data.py
```

## References

- Ordiknots P2WSH implementation: `../../ordiknots/src/techniques/p2wsh_fake_multisig/encode.rs`
- Ordiknots OP_RETURN implementation: `../../ordiknots/src/techniques/chained_op_return/encode.rs`
- Spam filter: `../../share/scripts/p2wsh_spam.lua` and `../../share/scripts/opreturn_spam.lua`
