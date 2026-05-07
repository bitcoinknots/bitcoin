Policy
------

- Data in a conditional part that constants make unreachable now counts as
  data carrier bytes, so under the default settings a transaction carrying it
  is rejected with `txn-datacarrier-nonstandard`. This already applied to the
  `OP_FALSE OP_IF ... OP_ENDIF` inscription envelope; it now also covers
  `OP_1 OP_NOTIF ... OP_ENDIF`, guards computed from constants, and the dead
  part of an `OP_ELSE`. Scripts that branch on witness data or a signature
  check, which is how spendable scripts branch, are unaffected. The new
  `-rejectdeadbranches` option (default: 1, reset by `-corepolicy`) turns the
  wider rule off and leaves only the envelope counted.
