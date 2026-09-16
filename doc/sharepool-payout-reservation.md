# Bounded native payout reservation

The 100-miner capacity workload exposed a construction failure after 300 proofs
had been acknowledged. The gate selected 205 proofs within a 154,350-byte local
snapshot budget, but sized the proposed v6 payouts as one zero-valued bootstrap
output. Native preparation expanded the real recipient list and exceeded that
same budget. The failed run is retained with the capacity results.

`getsharepoolhashtidesbudget(pool, payout_script)` now returns the number and
serialized bytes of every recipient slot in that pool's actual native history
window, or its bootstrap output when the history is empty. It calls the native
accounting function with `reserve_scripts=true`: recipients rounded to zero
satoshis remain in the reservation. Queries retain the existing native history
work and memory limits. The response is bound to the requested pool, bootstrap
script, native tip and planned difficulty. It is construction metadata and does
not establish proof validity or authorize mining.

For each candidate prefix the gate reserves those historical bytes plus one
output for each distinct selected **own-pool** script. It replaces the proposal's
placeholder bytes and includes CompactSize count growth, including 252 to 253
outputs. The extra bytes count against both the local snapshot budget and the
native dependency-byte budget. Foreign-pool admissions reserve no local payout
outputs. Native preparation still calculates the exact fees and payouts, and
the gate refuses a changed difficulty before calling the signer.

At the same native tip and difficulty, positive current-pool work can only
shorten the historical suffix of the fixed work window. Proportional native-height
boundary sharing retains a complete boundary cohort. Consequently, the union
of the original historical scripts and the selected scripts contains every
possible final recipient, regardless of transaction fees or satoshi rounding.
The gate conservatively counts a script in both sets twice. This keeps prefix
fit monotonic without exporting a potentially large script list to Python.

This is a local conservative fitting policy. It can refuse an empty batch when
historical payout bytes already exceed the configured budget, even if enough
new work could shorten the history into a smaller valid settlement. Provision
the gate budget for its historical recipient set. The policy does not promise
to find every theoretically feasible subset or guarantee that provisional
receipts enter native history before their existing age limit.

Tests cover historical-only recipients, foreign pools, the CompactSize boundary,
dependency charging, response binding and a difficulty change before signing.
The native capacity workload checks actual finalized snapshots and exact payouts
under the original fixed budget that reproduced the failure.
