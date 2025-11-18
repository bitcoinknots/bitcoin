# Real Multisig Transaction Test Data

This directory contains legitimate Bitcoin multisig transactions downloaded from mainnet to test the P2WSH spam filter for false positives.

## Purpose

These test cases verify that the ordiknots spam filter (using "444" prefix detection) does not falsely reject legitimate multisig transactions of various sizes.

## Test Cases

### 1. Lightning Network 2-of-2 Multisig
- **TxID**: `0191535bfda21f5dfec1c904775c5e2fbee8a985815c88d77258a0b42dba3526`
- **Type**: Lightning Network channel funding transaction
- **WitnessScript**: 77 bytes (154 hex chars)
- **Files**:
  - `lightning_2of2.json` - Full transaction data
  - `witness_lightning_network_2_of_2_0.hex` - WitnessScript from input 0
- **Structure**: 2-of-2 CHECKMULTISIG (most common Lightning pattern)

### 2. Standard 3-of-4 Multisig
- **TxID**: `46ebe264b0115a439732554b2b390b11b332b5b5692958b1754aa0ee57b64265`
- **Type**: Standard P2WSH multisig (educational example from LearnMeABitcoin.com)
- **WitnessScript**: 105 bytes (210 hex chars)
- **Files**:
  - `standard_3of4.json` - Full transaction data
  - `witness_standard_3_of_4_multisig_0.hex` - WitnessScript from input 0
- **Structure**: 3-of-4 CHECKMULTISIG

### 3. Large 3-of-5 Multisig
- **TxID**: `6346e552f62281314dfeace8f977e056f251bc55d15b24ec14f73b34387357cf`
- **Type**: Large institutional multisig setup
- **WitnessScript**: 173 bytes per input (346 hex chars)
- **Files**:
  - `large_3of5.json` - Full transaction data
  - `witness_large_3_of_5_multisig_0.hex` - WitnessScript from input 0
  - `witness_large_3_of_5_multisig_1.hex` - WitnessScript from input 1
- **Structure**: 3-of-5 CHECKMULTISIG (common for institutional custody)

### 4. Extreme 15-of-15 P2SH Multisig
- **TxID**: `552026dade1c9385e4693a4e82f07080d8d1950fc822346f95a0dc1e0a833465`
- **Type**: Maximum size P2SH multisig (P2SH, not P2WSH)
- **ScriptSig**: 1612 bytes (3224 hex chars)
- **Files**:
  - `extreme_15of15.json` - Full transaction data
  - `scriptsig_extreme_15_of_15_p2sh_0.hex` - RedeemScript from input 0 scriptSig
- **Structure**: 15-of-15 CHECKMULTISIG (maximum for P2SH with compressed keys)
- **Note**: This is P2SH (not P2WSH), but included as an edge case test

## Verification Results

All test cases were analyzed for the ordiknots "444" magic prefix (hex: `343434`):

- ✓ **Lightning 2-of-2**: No "444" bytes found
- ✓ **Standard 3-of-4**: No "444" bytes found
- ✓ **Large 3-of-5** (2 inputs): No "444" bytes found in either input
- ✓ **Extreme 15-of-15**: No "444" bytes found

**Conclusion**: Zero false positives across all legitimate multisig sizes (2-of-2 through 15-of-15).

## How to Use

### Manual Testing

Test a witness script against the Lua filter:

```bash
# read witness script hex
WITNESS_HEX=$(cat test/data/multisig_witness_scripts/witness_lightning_network_2_of_2_0.hex)

# convert hex to binary and check for "444" bytes
echo "$WITNESS_HEX" | xxd -r -p | hexdump -C | grep "34 34 34"
# (should return nothing for legitimate multisig)
```

### Automated Testing

The functional test suite at `test/functional/feature_lua_spam_filters.py` can be extended to use these witness scripts:

```python
# load witness script from test data
with open('test/data/multisig_witness_scripts/witness_lightning_network_2_of_2_0.hex', 'r') as f:
    witness_hex = f.read().strip()

# create test transaction with this witness
# verify it's NOT rejected by the spam filter
```

## Data Source

All transactions downloaded from Blockstream.info API on 2025-01-18:

```bash
curl https://blockstream.info/api/tx/{txid} > {name}.json
```

## Why These Tests Matter

The P2WSH spam filter uses decode validation to detect ordiknots spam by:
1. Searching for "444" bytes in witness scripts (fast path)
2. Parsing CHECKMULTISIG structure
3. Extracting fake pubkeys and decoding embedded data
4. Validating that decoded data starts with "444" prefix

Since legitimate ECDSA public keys are cryptographically random, the probability of real pubkeys decoding to "444" is negligible (~1 in 16.7 million). These test cases empirically confirm this theoretical guarantee.

## References

- Lightning Network: https://github.com/lightning/bolts
- LearnMeABitcoin multisig examples: https://learnmeabitcoin.com/
- Bitcoin multisig limits: https://bitcoin.stackexchange.com/questions/23893/
- Blockstream API: https://github.com/Blockstream/esplora/blob/master/API.md
