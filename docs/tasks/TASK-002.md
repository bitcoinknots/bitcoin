# TASK-002: Purity bridge, configuration, lifecycle, and refresh

- Status: Complete
- Owner: Codex root
- Source: `docs/migration-report.md`
- Depends on: TASK-001

## Objective

Add the stable C ABI and Purity-owned runtime lifecycle without exposing C++
node internals to DATUM C.

## Scope

- Register and validate all required arguments.
- Validate payout through Purity address decoding and build loopback RPC config.
- Start after RPC warmup; interrupt/stop/join before RPC teardown.
- Replace SIGUSR1 with an in-process refresh function and tip listener.
- Prefix logs and expose a bounded, secret-free stats snapshot.

## Acceptance and validation

- Disabled startup has no DATUM listener/threads/config requirement.
- Invalid enabled configuration fails startup clearly.
- Enabled startup, tip refresh, RPC failure, and clean shutdown tests pass.
