# Experimental dynamic coinbase maturity

DCBM is opt-in on regtest. Mainnet and other network activation parameters,
ordinary regtest, and production proof-of-work arithmetic are unchanged.
The existing implementation commits and the quote above
`CalculateDynamicCBMFromTargets` are preserved.

A reward keeps the maturity calculated from its mining block's ancestry.
Activation uses the parent median time past, including equality at RDTS expiry.
The activation block receives the initial maturity; adjustments start at the
next retarget, even if activation itself falls on a retarget boundary.
Subsequent maturity is `floor(previous_maturity * old_target / new_target)`,
clamped to [100, INT_MAX]. Integer rounding can hide small difficulty changes;
clamping and rounding also mean a round trip need not restore the exact initial
maturity. Pre-expiry rewards keep the existing long maturity, and historical
maturity restrictions remain enforced.

## Corrections in this follow-up

- Respect a separately configured rolling-maturity enforcement height in DCBM
  input validation.
- Keep required maturity in 64 bits, avoiding an implicit narrowing warning.
- Saturate the wallet's returned remaining maturity before narrowing to `int`.
- Fix the **test artifact**, not production PoW: `-testdynamiccbmretarget=1`
  selects a separate regtest genesis with target `0x1f3fffff`, a matching PoW
  limit, and a 144-second timespan with one-second spacing. The interval stays
  144 blocks. Even the largest timespan multiplier (576) fits in 256 bits.
  The ordinary target `0x207fffff` does not have that headroom. Ordinary regtest
  snapshot assumptions are cleared for this custom fixture. Use fresh isolated
  datadirs; this fixture is incompatible with the earlier WIP retarget chain.
- Register and expand the real-retarget functional test. It starts at maturity
  100, increases to 400, decreases, and checks the floor. A separate functional
  test uses initial maturity 150.

## Validation

Build: `cmake -S . -B build`, then
`cmake --build build --target bitcoind test_bitcoin -j 2`.

Unit tests (51 cases, all passed):

```sh
build/bin/test_bitcoin --run_test=coinbase_maturity_tests,pow_tests,wallet_tests \
  --log_level=message -- -testdatadir=/tmp/dcbm-unit-validation
```

Functional tests (all passed; 9 seconds wall time, 14 accumulated):

```sh
python3 build/test/functional/test_runner.py \
  feature_dynamic_cbm_retarget.py feature_dynamic_coinbase_maturity.py \
  feature_rolling_coinbase_maturity.py mempool_long_coinbase_maturity.py \
  --jobs=2 --tmpdirprefix=/tmp/dcbm-validation-approved \
  --cachedir=/tmp/dcbm-validation-approved-cache
```

Unit coverage includes target arithmetic limits and invalid encodings,
activation immediately before/at/after expiry, activation on a retarget,
branch-dependent activation and spending, historical restrictions, retained
pre-expiry maturity, and delayed enforcement. Functional coverage includes
actual retargets, exact spending boundaries, mempool and block rejection,
reorg mempool eviction, a competing branch with different difficulty history,
and restoration of the original higher-work branch.

Earlier attempts encountered runner configuration/stale generated test links,
sandbox denial of local socket binding, and two corrected test expectations
(PoW-limit headroom for reaching the maturity floor, and duplicate invalid
block candidates after rollback). The final run has no failing test.
Local socket access required sandbox approval. Tests used temporary datadirs
and disabled automatic peers and DNS seeds.

## Remaining limits

This is experimental, not a production activation proposal. The full unit and
functional suites, sanitizers, sustained adversarial-load benchmarks, and
restart/reindex/snapshot migration scenarios were not run. Maturity lookup
replays retarget ancestry for each reward; validation and wallet performance
on long histories need measurement before production use. INT_MAX saturation
and fractional arithmetic have unit coverage, but no full-chain functional
scenario reaches those extreme maturities. Wallet RPC behavior under dynamic
retargets deserves dedicated coverage beyond the existing wallet unit suite.

The subsequent GUI integration is based on the official 29.4.3 final release.
See [the GUI build and validation report](dynamic-cbm-gui.md) for its build,
Qt tests, isolated preview launcher, and repeat validation results.
