# Embedded Stratum V1 SOLO mining (MVP)

Run a regtest node with embedded Stratum enabled:

```bash
bitcoind \
  -regtest=1 \
  -server=1 \
  -stratum=1 \
  -stratumbind=127.0.0.1 \
  -stratumport=3333 \
  -stratumpayoutaddress=<regtest-address>
```

Point a Stratum-v1 miner at:

- Host: `127.0.0.1`
- Port: `3333`
- Username: any non-empty worker name (MVP solo mode)
- Password: ignored in MVP

The node serves Stratum jobs from internal block-template construction and accepts `mining.submit` share submissions for local share accounting.

## Future work (post-MVP)

- Full TCP session manager with worker fanout and async notify dispatch
- Vardiff and per-worker target tuning
- Stratum V2 / job-declaration support
- DATUM-like federation and external template distribution hooks
- Pooled payout accounting and durable share storage
