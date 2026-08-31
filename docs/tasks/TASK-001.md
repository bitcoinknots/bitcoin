# TASK-001: Baseline provenance, minimal C source, and conditional build

- Status: Complete
- Owner: Codex root
- Source: `docs/migration-report.md`

## Objective

Vendor the smallest auditable non-pooled source set from the fixed DATUM commit
and make it build conditionally as C on all supported platforms.

## Scope

- Record license, source repository, commit, file inventory, and local patches.
- Exclude daemon main, Prime, and Web/API entry points.
- Add `BUILD_DATUM` default ON and complete CMake/depends/vcpkg integration.
- Ensure OFF mode has no DATUM-only dependency.

## Acceptance and validation

- Configure/build with ON and OFF; compile the DATUM target and full daemon for
  Windows x64.
- Link analysis shows no Web/API or Prime-only dependency.
- `git diff --check` and license/provenance review pass.
