Mempool policy
--------------

- The default for `mempooltruc` changes from `accept` to `enforce`,
  applying the existing version-3 topology, inheritance, and size checks
  by default. Explicit policy settings remain available.
  This also selects the existing version-3 exemption from the individual
  minimum relay fee check; package fee requirements still apply.
  Ephemeral-dust rules, dust-penalty defaults, and mining policy are unchanged.
