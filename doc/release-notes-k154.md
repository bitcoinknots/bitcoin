Settings export over RPC
------------------------

Bitcoin Knots now exposes its corepolicy/mempool settings over RPC, so headless
deployments (Start9, Umbrel, etc.) can read and change the same policy options the
GUI offers, without a graphical interface.

Two RPC commands are added:

- `dumpsettings ( detailed )`: return the current corepolicy/mempool settings as a
  JSON object of `name: value`. With `detailed=true`, each entry instead reports the
  value together with its type and the setting's help text, so a headless UI can be
  built from the node itself instead of hard-coding the option list per release.
- `setsettings {"name": value, ...}`: update one or more settings. The whole batch is
  validated first; if any value is invalid, none are applied. Valid changes take
  effect on the running node where possible and are persisted for restart. A
  per-setting result reports whether a restart is required (for example `spkreuse`).

RPC and the GUI now change these settings through the same internal interface, so the
two stay consistent. Setting names match the corresponding `bitcoin.conf` option names.

See `doc/JSON-RPC-interface.md` for usage details.
