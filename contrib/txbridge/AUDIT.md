# knots-txbridge security review, 2026-09-06

Scope: txbridge.py as first written (v0.1) reviewed as an attacker who controls some or all of the SHA256d peers the bridge connects to, and who can also see the Knots node the bridge feeds. Goal of the attacker: crash or stall the bridge, exhaust its memory, poison the node through it, or use it to fingerprint or burden the node. Everything below was fixed in v0.2/v0.3 and re-tested; the verification section at the end is the harness output.

## Findings

| # | Severity | Finding in v0.1 | Fix |
|---|---|---|---|
| 1 | High | RPC `sendrawtransaction` makes the node adopt every bridged transaction as its own (`AddUnbroadcastTx`), rebroadcasting it until a peer echoes it back. The node looks like the origin wallet of the whole legacy transaction stream, and the RPC path bypasses the node's per-peer P2P accounting and rejection cache. | Submit mode now feeds the node as an ordinary P2P peer with unsolicited `tx` messages, which the node accepts and validates like any peer's. No credentials needed. The RPC submission path was removed outright. |
| 2 | High | `pending` grew without bound: an attacker announcing millions of never-delivered txids leaves entries that only expire when re-announced. Each `inv` also scanned the whole table, so the cost was quadratic. | Global cap (5,000) and per-peer cap (500), pruned on a timer; expired requests cost the peer strikes. Harness: 10 million fake announcements held memory at 32 MB. |
| 3 | High | Witness poisoning: a peer could deliver a transaction with a bogus witness; its txid was marked seen and the honest version was never fetched again. | wtxid relay (BIP339) is negotiated, so announcements and deduplication are by wtxid; a bogus witness is a different wtxid. Per txid, at most 3 witness variants are forwarded, further ones cost strikes. |
| 4 | Medium | A malformed `version` or `inv` (short payload, absurd item count) raised an unhandled exception that killed that peer's task silently. | Every message handler runs under a catch for parse errors; the peer is charged 20 strikes and the loop continues. Inventory counts are checked against the payload length before parsing. |
| 5 | Medium | A single `tx` message could be 4 MB and was buffered whole; nothing capped unsolicited transaction rate, so a peer could push arbitrary garbage as fast as the link allowed, each one validated by the node. | `tx` over 400,000 bytes is drained unbuffered and charged; any message not acted on is drained in 64 KB chunks; per-peer token bucket of 200 tx/s with a 1,000 burst, excess dropped and charged. |
| 6 | Medium | Strikes were per connection: a peer could reconnect and start clean after every offence. | Strikes are carried per address, decay by half every ten minutes of quiet, and a reconnect after a strike-bearing session costs 10 more. |
| 7 | Medium | Slowloris: a header followed by silence held a slot for up to 10 minutes; an idle peer forever. | Idle timeout 180 s on the header read, 60 s on the payload; the bridge pings every 60 s. |
| 8 | Low | User agents were logged raw: ANSI escapes and newlines from a peer landed in the log and terminal, including a forged log line. | Reduced to printable ASCII, 80 characters. |
| 9 | Low | `notfound` was ignored, so a legitimately withdrawn transaction stayed pending for the full timeout. | Handled; clears the request. |
| 10 | Low | All connections could land in one operator's address range. | At most one connection per /16 (IPv4) or /32 (IPv6). |
| 11 | Low | Test mode ran with the node's cookie, which is full RPC access including any wallet. | Documented a dedicated RPC user with `rpcwhitelist` limited to the two read-only calls the bridge makes. |
| 12 | Info | Duplicate `version` messages were answered again. | 50 strikes. |

Things reviewed and left alone: the node cannot be made to accept anything it would reject from a normal peer, since the bridge forwards bytes and the node validates; an attacker who controls all the bridge's peers can withhold transactions but gains nothing else; DNS seed answers are used once at start and no `addr` gossip is accepted, so the peer list cannot be steered after start.

## Verification

`hostile_test.py` runs `fakepeer.py` in each mode below against the bridge on regtest framing and checks exit status, peak RSS, and the reaction. The end-to-end path was checked separately: a fake honest peer announced a real signed transaction, the bridge fetched it and forwarded it over P2P, and it appeared in a regtest Knots 29.4.1 node's mempool. Live runs against six SHA256d Core peers (versions 27 to 31) for 75 to 150 seconds: zero strikes, every request delivered or answered `notfound`, and the transaction rate matched the legacy mempool's growth during the run.

```
hostile_test.py on the final v0.3 code, 2026-09-06 16:20Z, regtest framing, one connection, peak RSS from /proc:
PASS shortversion  rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=120 malformed=4 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS bigmsg        rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=100 malformed=0 oversized=5 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS hugelen       rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS badchecksum   rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS badmagic      rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS invflood      rc=0  75.6s peakRSS=32MB dropped=1 banned=1 strikes=500 malformed=0 oversized=0 rate-dropped=0 announced=10000000 requested=500 received=0 undelivered=500 timeouts=0
PASS invbadcount   rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=110 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS garbagetx     rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=100 malformed=20 oversized=0 rate-dropped=0 announced=0 requested=0 received=20 undelivered=0 timeouts=0
PASS txflood       rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=100 malformed=0 oversized=0 rate-dropped=100 announced=0 requested=0 received=1006 undelivered=0 timeouts=0
PASS malleate      rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=105 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=54 undelivered=0 timeouts=0
PASS slowloris     rc=0 200.6s peakRSS=25MB dropped=0 banned=0 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=3
PASS dupversion    rc=0  30.5s peakRSS=25MB dropped=1 banned=1 strikes=110 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS ansiua        rc=0  20.5s peakRSS=25MB dropped=0 banned=0 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=0
PASS idle          rc=0 200.6s peakRSS=25MB dropped=0 banned=0 strikes=0 malformed=0 oversized=0 rate-dropped=0 announced=0 requested=0 received=0 undelivered=0 timeouts=1
ALL PASS
```

Mode legend: `shortversion` a 3-byte version message; `bigmsg` a 4 MB `tx`; `hugelen` a header claiming 4 GB; `badchecksum`/`badmagic` framing faults; `invflood` 200 inventories of 50,000 fake txids, nothing delivered; `invbadcount` an inventory whose count exceeds its payload; `garbagetx` 5,000 unsolicited random-byte transactions; `txflood` 5,000 well-formed transactions in one burst; `malleate` one txid delivered with six different witnesses; `slowloris` a header then silence; `dupversion` a second version message; `ansiua` a user agent carrying ANSI escapes and a forged log line; `idle` a peer that never speaks. Every misbehaving peer hangs up after its attack so the reconnect path is exercised too.
