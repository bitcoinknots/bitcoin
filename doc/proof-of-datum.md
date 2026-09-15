# Proof of Datum

Proof of Datum is local node policy for a node's own mining RPC surface. It is
**not a consensus rule**, and the reason is structural, not a design choice:
Stratum V1, Stratum V2, and protocols like DATUM all negotiate a block's
template entirely upstream of the block existing. By the time a valid block
reaches the network, its header and coinbase carry no trace of which protocol
built it -- a block a client assembled itself and a block a pool dictated
whole are bit-for-bit indistinguishable. A rule that claimed to tell them
apart from the block alone would have different nodes reach different,
unverifiable conclusions about the same data, which is a fork waiting to
happen, not a consensus mechanism.

What a node genuinely can observe is how a connection *asking it for mining
help* behaves: whether it calls `getblocktemplate` at all, and whether the
blocks it goes on to submit vary or all pay the same fixed script. That
observation lives entirely at the RPC boundary of one node, is never shared
with the rest of the network, and never has any bearing on which blocks are
valid.

## The heuristic, and why it defaults to advisory-only

Each calling address is scored on two things:

- **GBT starvation**: is `blocks_submitted` reasonably large, with very few
  `getblocktemplate` calls behind it? That is the shape of a bridge that only
  ever relays an already-complete block someone else assembled.
- **Coinbase staleness**: does one payout script dominate an address's recent
  submitted blocks? That is the shape of a connection that never chooses its
  own payout, because an upstream pool already fixed it.

Both are real signals and both can be wrong. A legitimate solo miner behind a
caching proxy can look GBT-quiet. A low-volume miner, a debug script, or
anything sharing a NAT'd address with other traffic can produce a handful of
same-payout submissions that look identical to a bare relay for a little
while. Early testing of this feature caught exactly that: three ordinary
manual-relay-style submissions were originally enough to trip an
automatically-persisted ban, which would have meant common, harmless RPC
usage getting nodes locked out of their own mining service.

Two things fixed that, and both matter:

- **The sample the heuristic waits for is large** (`DATUM_MIN_SUBMISSIONS`,
  50 blocks by default) before it forms an opinion at all.
- **Matching the heuristic and being enforced are different things.**
  `getdatuminfo` always reports `heuristic_match` once the pattern is met, but
  that alone withholds nothing. Whether a match becomes an actual, enforced
  block on template service is controlled by `-datumautoban`, off by default.
  With it off, the heuristic is purely informational: an operator sees the
  pattern and decides, via `adddatumban`, whether they agree. With it on, a
  sustained match is promoted to a real, persistent ban automatically.

This asymmetry -- easy to see, hard to trigger automatically -- is deliberate.
An automated system that can lock a node out of its own mining service on a
weak sample is a worse problem than the one it is trying to solve.

## What being flagged actually does

A flagged address (manual, or auto-promoted with `-datumautoban`) is refused a
`getblocktemplate` response. That is the entire enforcement action.

**A submitted block from a flagged address is always still accepted and
relayed if it is valid.** This is deliberate and unconditional: refusing to
propagate an already-valid block would only delay it across the network and
raise its orphan risk, for a purely reputational grievance about how it was
built. A full node's job is to relay valid blocks regardless of what its
operator thinks of who mined them. Proof of Datum withholds a voluntary
service -- this node's help building a future block -- and nothing else.

## Running it

    bitcoind                       # heuristic active and visible, nothing auto-enforced
    bitcoind -datumautoban          # a sustained heuristic match becomes an enforced ban

RPCs:

- `getdatuminfo [address]` -- one address's stats and verdict, or every
  tracked address with none given.
- `adddatumban <address> <reason>` -- flag an address by hand: the mechanism
  for a connection the heuristic missed entirely, caught some other way (a
  disclosure, a report, direct knowledge).
- `removedatumban <address>` -- lift a flag, manual or heuristic.
- `listdatumbans` -- every currently enforced flag, with its reason and
  source.

Addresses are matched without their port (as `getpeerinfo`/RPC logs show
them), so a caller reconnecting on a new ephemeral port is still recognised.
The ban list persists to `datumbans.json` in the data directory and survives a
restart; the request-tracking counters themselves do not, and reset on
restart.

## What this does not do

It does not identify a specific piece of mining software, a Stratum version,
or a person. It observes RPC usage from one address, on one node, and forms an
opinion from that alone. It has no reach beyond the node it runs on: a
connection refused a template here can go ask a different node, and nothing
here coordinates with any other node's view of the same address. Treat it as
what it is -- a local, explainable, deliberately conservative signal, and a
place to record what an operator has separately learned -- not a network-wide
verdict on anyone.
