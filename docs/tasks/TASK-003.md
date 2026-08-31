# TASK-003: Stratum authorization and bounded public-port security

- Status: Complete
- Owner: Codex root
- Source: `docs/migration-report.md`
- Depends on: TASK-002

## Objective

Safely expose the preserved Stratum/mining logic to explicitly authorized ASICs.

## Scope

- Shared username/password with exact base user and worker suffix semantics.
- Pre-auth job and submit gating.
- Global/per-IP clients, auth timeout/cooldown, 16 KiB line limit, and submit
  rate limiting.
- Bounded queues/history/buffers and secret-free logging.
- Fixed operator payout and configurable share difficulty.

## Acceptance and validation

- Auth, suffix, pre-auth submit, oversize/invalid JSON, failure flood,
  invalid-submit flood, and disconnect-mid-message tests pass.
- Authorized subscribe/configure/notify/submit behavior matches the baseline.
