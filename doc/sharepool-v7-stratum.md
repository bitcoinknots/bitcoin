# V7 loopback mining transport and independent withdrawal

The [v7 Sia Stratum adapter](../contrib/sharepool/hash_stratum.py) connects the
existing exact-work mining gate to real TCP subscribe, authorize, job notification
and share-submission messages. It uses the existing Knots header-v2/Sia work
conversion. This is a bounded **isolated regtest integration**, not a mainnet
service, remote authentication protocol or physical ASIC qualification.

The mining gateway validates the complete native template and settlement data.
The synthetic Stratum client supplies nonce/extranonce work; the transport does
not imply that an ASIC itself executes transaction or settlement validation.

## Ownership and withdrawal

The thread constructing the service exclusively calls the mining gate and
`HashJobScheduler`. Socket handlers enqueue at most 16 requests and wait at most
five seconds. A successful share response follows `gate.receive()`'s durable
local receipt; it does not mean the share has been admitted by a native block.
Shares do not force a replacement job. Normal refresh remains 40 seconds.

An independent RPC connection watches the same isolated native profile and tip.
It does not operate the gate. A tip change or observer failure increments a
transport generation and shuts down client sockets. A separate server watchdog
expires an old observation even if its RPC never returns. This works while the
gate's owner is occupied constructing, signing or validating a replacement.
When the owner resumes, scheduler invalidation requires a fresh authorization;
old generations cannot resume merely because the observer recovers.

The default observation interval is 250 ms and the observation lease is two
seconds. The native fixture uses 50 ms and one second. These are local service
settings, not consensus deadlines or hard real-time guarantees. OS scheduling,
native RPC latency and bounded socket writes contribute to withdrawal latency.
Each socket has a 200 ms I/O timeout; notifications hold the generation lock
across their two bounded writes so withdrawal cannot race a stale send. Four
clients are allowed. Closing a connection stops this service advertising work;
it cannot prove that an ASIC immediately stops hashing its last received job.

The owner still constructs synchronously. Independent withdrawal **does not
cancel construction or eliminate CPU cost**. Owner request queues can back up or
time out during a long build. This change addresses the transport response to a
tip event rather than qualifying sustained share-processing capacity.

## Exact handoff and submissions

Before publication, the adapter verifies its Sia wrapper reproduces the exact
authorized native block, publishes the full snapshot to the native store, and
registers the original template. It then performs another strict
`ready_for_dispatch()` fence before assigning the current transport generation.
Each new client/job notification also asks the owner for strict approval. That
successful owner approval is the **per-client handoff boundary**: the job must
reflect the deterministic eligible prefix of receipts acknowledged before it.
Excess work carries forward; later ACKs belong to a subsequent job. A socket
write can happen after a later ACK without changing the already issued cutoff.
A new approval of that old job is refused once its receipt prefix is stale.
The transport generation and current job are checked again under the send lock;
a native-tip change can still prevent an already approved notification.

Every submission reconstructs the original complete native header, checks its
actual native share target and compares its block bytes with the exact issued
authorization. The gate performs native validity checks before a durable ACK.
A qualifying native block is submitted with those exact bytes. An old-parent
candidate is not rewritten or discarded just because it is no longer the
advertised job; native validation decides its validity and branch placement.
Unexpired job records remain available within the explicit transport budgets.
This covers candidates already queued before withdrawal; disconnected sessions
cannot resend their old extranonce allocation through a new session automatically.

A new native tip can disconnect a socket before a block submitter receives its
response. The durable receipt remains. Native RPC failure also does not revoke
that receipt; candidate failure/rejection counters make that outcome visible.
Automatic candidate retry and a persistent transport job/session index are not
implemented. Gate evidence supports explicit recovery, but a new service cannot
silently continue an old Stratum session after restart.

The transport retains at most 32 unexpired jobs and 64 MiB of serialized job and
snapshot bytes. On exhaustion it refuses a new publication and withdraws work;
it does not truncate acknowledged evidence or alter consensus snapshot limits.
Decoded Python memory can exceed this byte counter. This small transport budget,
four-client allowance and strict loopback binding deliberately bound the test.

## Standalone entry point

The [runner](../contrib/sharepool/hash_stratum_runner.py) uses an existing native
signer and an already running node with disabled P2P networking and the v7
regtest profile. It starts no node, changes no miner configuration and creates
no signer key. For example, from the repository root:

```sh
python3 -B contrib/sharepool/hash_stratum_runner.py \
  --bitcoin-cli /absolute/build/bin/bitcoin-cli \
  --datadir /absolute/isolated-regtest-node \
  --signer-binary /absolute/build/bin/bitcoin-sharepool-signer \
  --signer-key /absolute/existing-owner.key \
  --gate /absolute/v7-transport.sqlite \
  --pool 65 \
  --payout-script 00140101010101010101010101010101010101010101 \
  --activation-height 102 --seconds 60
```

Pool IDs are hexadecimal; `65` means decimal 101. Pool and payout script must
match the existing signer's policy. The runner prints its loopback address and
accepts the test username `sharepool.regtest`. Its requested run interval is
1–600 seconds; synchronous owner work can delay exit beyond that interval.
Unexpected owner errors stop the runner and withdraw connections. Separate
`bitcoin-cli` subprocess adapters impose 30-second owner-RPC and one-second
observer-RPC timeouts; an independent watchdog still bounds an observation's age.
RPC credentials are read through the datadir's normal CLI configuration.

## Verification and remaining limits

[Eight unit tests](../contrib/sharepool/test_hash_stratum.py) exercise unknown,
expired, changed and recovered observation generations, malformed tips and
clock rollback, nonfinite values and exceptions. A broken diagnostic clock cannot
prevent socket withdrawal. The scheduler suite checks that explicit retirement forces a
fresh job and retains its original owner and strict authorization rules.

The [native fixture](../test/functional/feature_sharepool_hash_stratum.py) uses
two independent payout recipients, actual external signatures, a synthetic Sia
client, real native proof checks and an actual accepted block. It verifies exact
block bytes, direct coinbase amounts, late-share cadence, stale-prefix refusal
for a new client, withdrawal while the owner is held inside signing, stale
publication rejection, fresh-context recovery and watchdog withdrawal while the
observer itself is held. It also starts the standalone runner on the same
isolated node. It never reads or modifies Goldshell or Lazarus settings.
Malformed submissions and unknown jobs disconnect only the submitting client;
the fixture verifies a healthy miner keeps its issued job and completes its
share submission without an extra rebuild.
A deterministic interleaving pauses a socket after owner approval, admits a new
share, and then releases the original notification. Its issued bytes remain
unchanged and valid; a subsequent approval of the old job is refused.

The [recorded capture](../contrib/sharepool/results/v7-stratum-integration.json)
passed the complete fixture and standalone runner. The [run manifest](../contrib/sharepool/results/v7-stratum-integration-run.json)
records its command, source and daemon/signer/CLI hashes, and failed development
attempts resolved before the final capture. After native tip invalidation,
the client disconnected in **50.2 ms while the owner remained held in signing**.
With the observer deliberately blocked, the separate watchdog disconnected in
**955 ms** under its one-second lease. These are single observed test latencies,
not percentile or production service guarantees. The accepted block paid
3,333,333,333 and 1,666,666,666 satoshis directly to the two expected recipients;
the remaining satoshi was unclaimed under the existing rounding rule.

These checks do not establish production transport fairness, WAN availability,
real miner compatibility, peak-memory bounds or full-size transaction throughput.
Invalid requests are rejected per client. The regular owner-side scheduler fence
still retires work on actual native-context or journal failure. A public service
would additionally need reviewed client authentication, fair admission pricing
and overload handling.
Live cross-node inventory ingestion, automatic archival reconciliation,
persistent candidate retry and hardware reconnect behavior remain separate
integration gates. Full snapshots are published to the local native store;
this loopback fixture does not prove their availability to remote peers.
