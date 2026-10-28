Policy
------

- Outputs whose hash or key field is data rather than a hash or key now count
  as data carrier bytes, so under the default settings a transaction carrying
  them is rejected with `txn-datacarrier-nonstandard`. This covers payloads
  spread over three or more distinct P2WSH outputs that share one value of
  546 sat or less (the OLGA layout, whatever magic it uses), taproot outputs
  whose key is not on the curve, and any hash with one byte value repeated
  eight times or six times in a row. Lightning anchor outputs, ordinals
  postage and outputs to the all-zero burn hash are unaffected. The new
  `-rejectfakeoutputs` option (default: 1, reset by `-corepolicy`) turns the
  detection off without accepting other non-standard data carriers.
