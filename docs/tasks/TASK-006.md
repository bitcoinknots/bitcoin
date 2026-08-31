# TASK-006: Runtime DATUM share-difficulty hot reload

- Status: Implemented
- Owner: Codex root
- Depends on: TASK-002, TASK-003, TASK-004, TASK-005

## Objective

Allow an operator to change the fixed Stratum share difficulty through the RPC
or Qt Settings without restarting the node, while keeping socket writes on the
owning Stratum worker thread and leaving the Bitcoin network target unchanged.

## Contract

- `setdatumdiff <difficulty>` accepts only 1 through 2147483647.
- The update takes effect at runtime and the selected value is persisted;
  restart uses the configured `datumdiff` value.
- Existing authorized miners receive `mining.set_difficulty` and a clean
  `mining.notify` for the current job.
- Invalid values and calls while DATUM is stopped fail closed.

## Verification

`test/functional/feature_datum.py` covers a connected Stratum client receiving
the new difficulty and clean job, status-RPC reflection, and invalid-value
rejection. The Qt Settings path uses the same `SetDatumDifficulty` bridge when
DATUM is running, while persisting the selected value for restart. Build and
functional-test evidence is recorded when the DATUM build is rerun after this
change.
