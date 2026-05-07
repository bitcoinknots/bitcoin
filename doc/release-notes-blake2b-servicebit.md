### New NODE_BLAKE2B service bit (hardfork)

Nodes enforcing the BLAKE2b hardfork rules now advertise a new service bit,
`NODE_BLAKE2B` (bit 28, 0x10000000), which replaces `NODE_REDUCED_DATA`
(bit 27) in what this node signals itself: RDTS enforcement is part of the
hardfork rules, so the old bit is no longer advertised separately. Peers
advertising `NODE_REDUCED_DATA` are still shown in the GUI and in
`getnetworkinfo`/`getpeerinfo` as before. The new bit is not advertised if
the node is misconfigured not to enforce the supported protocol rules.

Preferential peering now keys on the new bit instead of `NODE_REDUCED_DATA`:
automatic outbound peers that do not advertise `NODE_BLAKE2B` are tolerated
only as additional connections, up to `-maxstaleoutbound`, while the node
keeps looking for hardfork-enforcing peers to fill its outbound targets. An
unupgraded node advertising only `NODE_REDUCED_DATA` is treated as stale,
since it will not follow the chain past the hardfork.

DNS seed queries and the fixed-seed requirements filter for the new bit
accordingly (service-bit filter `x10000009` replacing `x8000009`), and
addresses added via `addpeeraddress` default to `NODE_NETWORK | NODE_WITNESS
| NODE_BLAKE2B`.
