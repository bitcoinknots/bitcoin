# BIP-0444 Policy Changes (Taproot and Script Limits)

## Summary

This release introduces policy-level enforcement of BIP-0444 to prevent large arbitrary-data inscriptions and reduce UTXO/script bloat. These changes are active immediately as relay/mempool policy defaults; consensus enforcement will follow after BIP8 activation (parameters TBD).

## Policy Changes (Active Now)

### scriptPubKey Limits
- **Non-NULL_DATA scriptPubKey size cap**: Transactions with non-NULL_DATA outputs exceeding 34 bytes are rejected (`scriptpubkey-size-34`).
- **scriptPubKey push length cap**: Any single push operation in a scriptPubKey exceeding 256 bytes is rejected (`scriptpubkey-pushlen`).

### Taproot/Tapscript Limits
- **Control block size cap**: Taproot control blocks exceeding 257 bytes (33-byte base + 7 merkle path nodes) are rejected (`taproot-controlblock-size`).
- **Per-input witness size cap**: Segwit v1 inputs with total witness data exceeding 1024 bytes are rejected (`taproot-perinput-witness`). Configurable via `-v1perinputwitnesslimit` (min 128, max 8192).
- **Tapscript IF ban**: OP_IF and OP_NOTIF opcodes are disallowed in Tapscript leaves (`taproot-if-disallowed`).
- **Tapscript push-only run cap**: Contiguous push-only regions in Tapscript leaves exceeding 256 bytes total payload are rejected (`taproot-pushrun`).
- **Tapscript IF-body cap**: Push-only IF/NOTIF branch bodies exceeding 80 bytes total payload are rejected (`taproot-if-pushonly`).

### Unknown Witness Versions
- **Default reject unknown witness**: The default for `-acceptunknownwitness` is now `false`. Transactions sending to undefined witness program versions are rejected by default unless explicitly allowed via `-acceptunknownwitness=1`.

## Configuration Options

- `-v1perinputwitnesslimit=<n>`: Set maximum total witness bytes per segwit v1 input (default: 1024; min 128, max 8192).
- `-acceptunknownwitness=<bool>`: Allow relay of transactions to unknown/future witness versions (default: 0).

## Rationale

These policy defaults target the common inscription vectors (Taproot witness/script abuse) while preserving legitimate usage:
- Standard P2TR/P2WSH outputs remain valid (≤34 bytes).
- Normal signatures, keys, and small scripts are unaffected.
- Taproot key-path spends are unaffected.
- The limits are conservative and tunable for advanced use cases.

## Deployment

BIP-0444 includes a soft-fork component with BIP8 activation (parameters TBD). Policy enforcement is active immediately; consensus rules will activate after the signaling period and delayed activation height.

For testing on regtest/testnet/signet, use `-vbparams=taproot_script_limits:start:end[:min_activation_height]` to override deployment parameters.

## Compatibility

- **Wallets**: Avoid creating transactions with oversized scriptPubKeys, large push payloads, or Tapscript leaves using OP_IF/NOTIF.
- **Contracts**: Multi-party protocols with large witness data (e.g., complex lightning channels, vaults) may need to tune `-v1perinputwitnesslimit` or split across multiple inputs.
- **Unknown witness versions**: If your application relies on future witness versions, set `-acceptunknownwitness=1`.

## References

- BIP-0444: https://github.com/bitcoin/bips/blob/master/bip-0444.mediawiki (pending merge)
- Discussion: https://gnusha.org/pi/bitcoindev/CALeFGL0PDjtRt2rfbY4gTkoc+5oNQ0mn_obraE7PrtHuNYFpQw@mail.gmail.com/T/#mb71350c5dfb119efeb92c5ee738b6c8225bf15b6

