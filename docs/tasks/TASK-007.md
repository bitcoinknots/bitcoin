# TASK-007: DATUM UPnP mapping and authentication default

- Status: Implemented
- Owner: Codex root
- Depends on: TASK-002, TASK-003, TASK-005, TASK-006

## Objective

Expose an explicit `datumupnp=1` option and Qt control that maps only the
configured DATUM Stratum TCP port through a UPnP IGD, with PCP/NAT-PMP fallback
for routers such as the node's existing port-mapping path, while keeping the
node's P2P mapping independent. Make Stratum authentication opt-in with a
default of `datumauth=0`.

## Contract

- `datumupnp` defaults to `0` and requires a build with miniupnpc support.
- UPnP mapping requires a non-loopback IPv4 DATUM listener; `0.0.0.0` is
  accepted and the router-selected LAN address is used for the internal side.
- Mapping is renewed, retried after operational failure, and the UPnP mapping
  is removed during clean shutdown; PCP/NAT-PMP leases expire naturally.
- `datumupnp` does not enable `datumauth`; public deployments should explicitly
  set `datumauth=1`, `datumuser`, and `datumpassword`.
- `datumauth` defaults to `0`; credentials remain required when it is set to
  `1`.

## Verification

Configuration validation covers unsupported UPnP builds, loopback/IPv6
listeners, and the default authentication behavior. The DATUM functional test
continues to exercise the authenticated path explicitly with `datumauth=1`.
