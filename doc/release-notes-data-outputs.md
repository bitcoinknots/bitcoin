Policy
------

- Outputs whose hash or key field is data rather than a hash or key now count
  as data carrier bytes, so under the default settings a transaction carrying
  them is rejected with `txn-datacarrier-nonstandard`. This covers payloads
  spread over P2WSH or taproot outputs at the dust threshold (the OLGA layout,
  whatever magic it uses), taproot outputs whose key is not on the curve, and
  any hash with one byte value repeated eight times or six times in a row.
  Lightning anchor outputs, which come in pairs, are unaffected.
