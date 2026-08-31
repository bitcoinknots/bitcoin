# Embedded DATUM Configuration and RPC Contract

## Configuration

All options are accepted on the command line and in `bitcoin.conf` using the
standard Bitcoin option spelling (`-datum=1` on the command line, `datum=1` in
the file).

| Option | Default | Validation |
| --- | --- | --- |
| `datum` | `0` | Boolean runtime gate. |
| `datumlisten` | `127.0.0.1` | Numeric IPv4 or IPv6 listen address. |
| `datumport` | `23334` | 1 through 65535. |
| `datumupnp` | `0` | Boolean; maps only the DATUM TCP port through UPnP, with PCP/NAT-PMP fallback, and requires UPnP build support plus a non-loopback IPv4 listen address. |
| `datumauth` | `0` | Boolean; credentials are required only when authentication is enabled. |
| `datumuser` | empty | Required when authentication is enabled; at most 191 bytes with no control characters. |
| `datumpassword` | empty | Required and sensitive when authentication is enabled. |
| `datummaxclients` | `32` | Positive bounded implementation limit. |
| `datummaxperip` | `4` | Positive and no greater than global maximum. |
| `datumaddress` | empty | Required and valid for the active Purity network. |
| `datumdiff` | `65536` | Positive integer share difficulty. |
| `datumcoinbasetag` | `Bitcoin Purity` | Must fit the baseline coinbase-tag limit. |
| `datumrpcuser` | empty | Sensitive; may fall back to configured `rpcuser`. |
| `datumrpcpassword` | empty | Sensitive; may fall back to configured `rpcpassword`. |
| `datumrpcurl` | loopback active-network RPC | Exact HTTP loopback literal and valid nonzero port only. |

No configuration value may change the network target returned by GBT. The
payout script is derived only from `datumaddress`.

Bitcoin-Qt exposes the same runtime options in a `DATUM` Settings tab when
compiled with `BUILD_DATUM=ON`. The tab is additive to the upstream Settings
surface; command-line and configuration-file values retain precedence, and
saved credentials remain in the read/write config file rather than
`settings.json`.

The Qt Share difficulty field uses the same runtime update as `setdatumdiff`
when DATUM is running. The payout address and Coinbase tag fields also update
the running coinbase template immediately. All three values are persisted as
`datumdiff`, `datumaddress`, and `datumcoinbasetag`; other DATUM settings still
require a restart.

### Minimal local configuration

```ini
server=1
datum=1
datumaddress=<valid Purity address>
datumauth=1
datumuser=miner
datumpassword=<strong unique password>
datumdiff=1024
```

### Explicit public ASIC configuration

Stratum V1 is plaintext. Expose this listener only on an operator-controlled
network or behind an appropriate encrypted tunnel and firewall policy.

```ini
server=1
datum=1
datumlisten=0.0.0.0
datumport=23334
datumupnp=1
datumaddress=<valid Purity address>
datumauth=1
datumuser=miner
datumpassword=<strong unique password>
datumdiff=1024
datummaxclients=32
datummaxperip=4
```

Configure an external ASIC with:

```text
Pool:     stratum+tcp://NODE_IP:23334
Worker:   miner.worker1
Password: <configured password>
```

## Stratum authorization

When `datumauth=1`, configured user `miner`, `miner` and any non-empty `miner.<worker>` value
are valid username forms. Other prefixes and empty worker suffixes are rejected.
The password must match. Before authorization, a client may perform only the
minimum negotiation needed to authenticate and receives no usable job.

When `datumauth=0` (the default), Stratum clients are authorized without
credentials. Port mapping does not change this setting; public deployments
should explicitly enable authentication.

`datumupnp=1` first tries the miniupnpc SSDP/IGD path. If the router does not
advertise an IGD but supports the same PCP/NAT-PMP port-mapping protocols used
by the node's P2P listener, DATUM falls back to those protocols. Only the
configured DATUM TCP port is requested.

## `getdatuminfo`

The optional read-only RPC returns non-secret aggregate state when compiled.
Existing fields retain their meaning; `accepted_shares` and `rejected_shares`
still describe currently connected clients. Session counters do not decrease
when a miner disconnects and reset on the next DATUM start.

```json
{
  "enabled": true,
  "running": true,
  "status": "Running",
  "listen": "127.0.0.1",
  "port": 23334,
  "upnp": false,
  "auth_required": true,
  "clients": 1,
  "subscribed_clients": 1,
  "authorized_clients": 1,
  "share_difficulty": 1024,
  "accepted_shares": 123,
  "rejected_shares": 1,
  "session_accepted_shares": 123,
  "session_rejected_shares": 1,
  "session_started": 1787620000,
  "last_share_time": 1787620100,
  "estimated_hashrate_ths": 0.42,
  "current_height": 961637,
  "port_mapping": {
    "requested": false,
    "active": false,
    "protocol": "",
    "external": "",
    "lifetime": 0,
    "updated": 0,
    "error": ""
  },
  "current_job": {
    "id": "6a8d24fc0fc0d002",
    "height": 961637,
    "created": 1787620100,
    "previous_block_hash": "...",
    "nbits": "180ffff0",
    "network_difficulty": 1.0,
    "transactions": 1000,
    "size": 500000,
    "weight": 2000000,
    "coinbase_value": 312500000,
    "last_template_update": 1787620100,
    "last_template_success": true,
    "last_template_error": ""
  },
  "block_submission": {
    "candidates": 0,
    "accepted": 0,
    "rejected": 0,
    "last_time": 0,
    "last_hash": "",
    "last_result": "",
    "last_share_rejection_time": 0,
    "last_share_rejection_reason": "",
    "share_rejections": {
      "unknown_work": 0,
      "high_hash": 0,
      "stale": 0,
      "duplicate": 0,
      "other": 0
    }
  }
}
```

Timestamps are Unix seconds; zero means no event. Estimated hashrate is derived
from recently accepted share difficulty and is not an exact device reading.
The RPC never returns worker names, remote IPs, miner user agents, Stratum
credentials, or RPC credentials.

## `setdatumdiff`

`setdatumdiff <difficulty>` hot-reloads the fixed Stratum share difficulty while
DATUM is running. The accepted range is 1 through 2147483647. The response is:

```json
{"difficulty": 1024}
```

The update is runtime-only. Authorized clients receive a clean
`mining.set_difficulty` and `mining.notify` from their owning Stratum worker;
the GBT network target is unaffected. The RPC returns an error when DATUM is
stopped or the value is outside the accepted range. On restart, `datumdiff`
from the normal command-line/configuration precedence chain is used again.
