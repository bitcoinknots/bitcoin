Policy
------

- The to_local revocation leaf of an LND simple taproot channel,
  `<local_delayedpubkey> OP_DROP <revocationkey> OP_CHECKSIG`, spent through
  the script path, now counts its dropped key toward the `-datacarriersize`
  budget as 34 bytes (push opcode, 32 byte key and `OP_DROP`), like an
  OP_RETURN payload, instead of being refused as non-standard data. The
  penalty spend of a revoked commitment relays under the default settings;
  it was rejected with `txn-datacarrier-nonstandard`. Only that exact leaf is
  affected, and a transaction with more such inputs than the budget holds is
  still refused.
