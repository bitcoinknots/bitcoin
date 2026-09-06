# knots-txbridge

Carries transactions announced on the legacy SHA256d network into a Bitcoin Knots node.

Since the proof-of-work change on 2026-08-30 the two networks share a port and network magic but part at the first block announcement, so a Knots node in steady state has no SHA256d peers and never sees what is broadcast there. Transactions valid under Bitcoin's rules are Bitcoin transactions wherever they were first broadcast. This bridge peers with SHA256d nodes as a light client, asks for every transaction they announce, and hands the raw bytes to the Knots node as an ordinary P2P peer. The node's own consensus and policy rules decide what is accepted. Nothing is sent back to the SHA256d peers, and no Knots code is changed.

Single file, Python 3 standard library only.

Terms used here: SHA256d peers are nodes on the legacy chain; BLAKE2b peers are nodes on this chain, identified by the NODE_BLAKE2B service bit.

## How it sits next to the node

It is not a proxy, and it does not listen. Knots keeps listening on 8333 exactly as before; nothing about the node's configuration changes, and no traffic is routed through the bridge. The bridge is a separate process that only makes outbound connections, in two directions:

    SHA256d nodes  <--(bridge dials them)--  txbridge  --(bridge dials the node)-->  Knots node:8333

- **To SHA256d nodes.** It dials a handful of SHA256d nodes found through the Bitcoin Core DNS seeds and introduces itself as a light client with no services. They announce transactions to it and it asks for the ones it has not seen. It announces nothing to them, serves no blocks or headers, and accepts no inbound connections.
- **To the Knots node.** It dials the node's P2P port like any other peer and hands over each transaction as an ordinary `tx` message. To the node, the bridge is one more inbound peer that sends a lot of transactions. The node validates every one under its own rules, keeps what passes, relays it to the BLAKE2b network, and drops the rest.

Stop the bridge and the node carries on unchanged; it only stops hearing about legacy-side transactions. Because it talks to the node the way any stranger on the network could, it needs no RPC credentials and no special privileges, and it can run on any machine that can reach the node's P2P port.

## Modes

| Mode | What it does | Needs |
|---|---|---|
| `count` | connect, request, count; forwards nothing | nothing |
| `test` | runs each transaction through `testmempoolaccept`; forwards nothing | RPC access |
| `submit` | forwards each transaction to the node over P2P | the node's P2P port |

Submission is over P2P only. The node then treats bridged transactions exactly like any other peer's: its rejection cache, orphan limits, fee filter and per-peer accounting all apply, it does not adopt them as its own for rebroadcast, and the bridge needs no credentials. RPC `sendrawtransaction` does the opposite on every point, so the first version's RPC submission was removed rather than kept as an option.

For `test` mode, give the bridge its own RPC user limited to the two calls it makes rather than the cookie:

    rpcauth=<from share/rpcauth/rpcauth.py>
    rpcwhitelist=txbridge:getmempoolentry,testmempoolaccept

## Run

Measure first, no node involved:

    python3 txbridge.py --mode count --run-seconds 300

Then see what your node would accept:

    python3 txbridge.py --mode test --rpc-user txbridge --rpc-password ... --run-seconds 600

Then for real, against the node's P2P port:

    python3 txbridge.py --mode submit --node 127.0.0.1:8333

Peers come from the Bitcoin Core DNS seeds (`x9` filter) unless you pass `--peer host[:port]` and `--no-dns`. `--connections` (default 8) sets how many SHA256d peers to hold, at most one per /16. A stats line prints every `--stats-interval` seconds.

## Hostile peers

Every SHA256d peer is treated as an attacker. Per connection: framing is checked before anything is parsed; messages the bridge does not act on are drained in chunks, never buffered; a `tx` over 400,000 bytes is drained and charged; inventories are bounded per message, per peer and globally; a peer's undelivered requests, malformed messages, duplicate handshakes, transaction floods and witness-variant floods all cost strikes; at 100 strikes the peer is dropped and its address banned for an hour, and strikes follow the address across reconnects with a penalty for coming back. Parse errors in one message drop that peer and nothing else. User agents are reduced to printable ASCII before they reach the log. Transactions are announced and deduplicated by wtxid (BIP339), so a bogus witness from one peer cannot block the honest transaction from another.

`fakepeer.py` and `hostile_test.py` exercise fourteen attack modes against the bridge and check that it stays up, stays under 300 MB, and reacts as expected. See AUDIT.md.

## What it costs

| | |
|---|---|
| Disk | Nothing. It writes no files and keeps no state; its log goes to stdout, one line per minute by default. |
| Memory | About 30 MB, bounded by design (every table has a cap). The unit caps it at 128 MB. |
| CPU | Under 1% of one core at the legacy network's current rate. |
| Network | 0.3 to 1 GB a day inbound from SHA256d peers, depending on their traffic. Nothing is stored; each transaction is fetched once and handed to the node. The stats line reports the running total. |

The node's own disk use does not change: transactions the node keeps sit in its mempool, which has its own size cap, and block space on this chain is capped by consensus whatever the source of the transactions.

One bridge is enough for the whole network. Everything it feeds to its node is relayed onward by normal transaction propagation, so every other node gets the same transactions without running anything. Run it if you want to be one of the sources; there is no need for every node to.

## What to expect

A ten-minute test-mode run on 2026-09-06 against eight SHA256d peers, judged by a Knots 29.4.1 node with default policy:

| | |
|---|---|
| Transactions received from SHA256d peers | 12,157 |
| Accepted by the node | 193 (1.6%) |
| Already in the node's mempool | 93 |
| Rejected as token or rune traffic | 10,047 (83%) |
| Rejected for missing inputs (spend legacy-only coins) | 1,715 (14%) |
| Other policy rejections | 104 |

So about one legacy transaction in fifty is a Bitcoin transaction the node will keep. That is roughly 30 a minute at the legacy network's current rate, or tens per block on this chain. The rest is filtered by the node itself: four fifths of what the legacy network relays is token spam, and most of the remainder spends coins that only exist over there.

## What it does not do

- Listen. It opens no port; every connection it has, it made.
- Relay in the other direction.
- Filter. Every announced transaction is offered to the node, which rejects what its rules reject.
- Serve anything. It advertises no services and ignores headers, blocks, `getheaders` and `getaddr`.

## systemd

    [Unit]
    Description=knots-txbridge
    After=bitcoind.service
    Requires=bitcoind.service

    [Service]
    DynamicUser=yes
    ExecStart=/usr/bin/python3 /opt/knots-txbridge/txbridge.py --mode submit --node 127.0.0.1:8333 --stats-interval 300
    Restart=on-failure
    RestartSec=30
    MemoryMax=128M

    [Install]
    WantedBy=multi-user.target
