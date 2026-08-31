# TASK-009: DATUM payout and Coinbase hot configuration

## Goal

Allow the Qt DATUM Settings tab to change the payout address and Coinbase tag
while DATUM is running, with the same immediate-application behavior as the
share-difficulty field.

## Contract

- `datumaddress`, `datumcoinbasetag`, and `datumdiff` are written to the
  read/write configuration file.
- While DATUM is running, payout script and Coinbase tag changes are applied to
  the next refreshed template and do not require a node restart.
- Other listener, authentication, client-limit, UPnP, and RPC settings retain
  their existing restart behavior.
- The status window reports active and configured values without a restart
  warning after a successful hot update.

## Implementation

The C ABI keeps a mutex-protected runtime payout script and primary Coinbase
tag. The C++ bridge validates the Purity address, swaps both values atomically
from the configuration dialog, and requests a bounded template refresh. The
coinbase builder copies the runtime values under the C mutex before generating
each job.

## Verification

- Build `BUILD_DATUM=ON` and run the Qt app tests.
- Run `feature_datum.py` to verify the existing difficulty hot-reload and
  Stratum behavior remain intact.
- Confirm the Settings save path writes `datumaddress` and
  `datumcoinbasetag` alongside `datumdiff`.
