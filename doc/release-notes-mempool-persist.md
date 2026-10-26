Mempool persistence
-------------------

- Mempool persistence saves only explicit fee adjustments, not automatic
  sub-dust penalties. Penalties are recalculated under the current policy on
  admission, preventing repeated deductions and allowing ephemeral packages
  to be resubmitted after restart. This does not add package-aware mempool
  loading. Previously saved deltas are not automatically cleared: old files
  do not distinguish an automatic penalty from an intentional adjustment.
