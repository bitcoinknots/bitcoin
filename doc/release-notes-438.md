Transaction relay and mining policy
----------------------------------

- Ephemeral-dust transactions may have negative modified fees from the
  calculated sub-dust fee penalty. Actual fees and manual fee deltas must
  remain zero; the child must cover the penalty in package fee evaluation.
  The penalty follows the configured dust relay rate and output values.
  Policy defaults, `corepolicy` overrides, and existing dust and package
  restrictions are unchanged. (#438)

- Mempool persistence saves only explicit fee adjustments, not automatic
  sub-dust penalties. Penalties are recalculated under the current policy on
  admission, preventing repeated deductions and allowing ephemeral packages
  to be resubmitted after restart. This does not add package-aware mempool
  loading. Previously saved deltas are not automatically cleared: old files
  do not distinguish an automatic penalty from an intentional adjustment.
