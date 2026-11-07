Policy
------

- `-rejecttokens` now also refuses to relay or mine a transaction whose
  `OP_RETURN` output holds a JSON object whose top-level `"p"` member names
  the protocol, the BRC-20 format that ico-20 and crc-20 copy
  (`{"p":"ico-20","op":"mint","tick":"LEAF"}`), refused as `tokens-json`, or
  an Omni Layer message, whose first data push starts with `omni` and whose
  version after the marker has a zero high byte, refused as `tokens-omni`.
  Other `OP_RETURN` payloads are unaffected, including JSON without a
  top-level string `"p"` member and data that happens to start with `{`.
  `-rejecttokens=0` and `-corepolicy` turn these off together with the
  Runes, Counterparty and OLGA checks, as before.
