Policy
------

- Data pushed inside a conditional branch that a constant guard makes
  unreachable now counts as data carrier bytes, so under the default settings
  a transaction carrying it is rejected with `txn-datacarrier-nonstandard`.
  This already applied to the `OP_FALSE OP_IF ... OP_ENDIF` inscription
  envelope; it now also covers `OP_1 OP_NOTIF ... OP_ENDIF` and any branch
  whose guard is a pushed constant that can never take it. This is the layout
  used to carry a contiguous image across the witness scripts of a batch of
  P2WSH inputs. Spendable scripts, which branch on a value computed at
  runtime rather than a constant, are unaffected.
