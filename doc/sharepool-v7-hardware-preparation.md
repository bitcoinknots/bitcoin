# V7 hardware transport, supervision and testing

This change adds bounded transport, supervision and capture/replay for v7.
Software tests and one 90-second physical Goldshell run passed. The miner's
current DATUM Convoy pools and settings were restored, and a later read-only
check observed its active primary route, positive hashrate and fresh upstream
gateway acceptances. This is finite regtest evidence, not production hardware
qualification; the earlier v6 capture remains separate.
The Goldshell exercises the optional regtest Blake2b/Sia work path. It does not
validate SHA256 Bitcoin mining hardware or qualify a mainnet deployment.

## Optional harder transport work

`HashStratumService(..., transport_difficulty=4096)` and the runner's
`--transport-difficulty 4096` request a harder Sia transport target. The permitted
setting is a power of two from 1 through 2^24. The effective target is the minimum
of the native share target and the transport target, so this option cannot admit
work that fails the native share requirement. The default remains unchanged.

This setting reduces test traffic from an ASIC. It does not alter the template,
header difficulty, exact snapshot commitment, signature or payout work attached
to an admitted proof. In particular, a harder transport sample does not acquire
extra payout weight. Native regtest's v7 share target would otherwise advertise
a difficulty of approximately 2^-32; the successful earlier hardware harness
used transport difficulty 4096. The physical result below tests this setting; it does not measure efficiency.
The capture clock begins around readiness, before the supervisor has finished
temporary routing. Its receipt count and duration are not a calibrated ASIC
hashrate measurement.

## Bounded forwarding

[`TestMinerForwarder`](../contrib/sharepool/hash_stratum_forwarder.py) keeps the
mining service's loopback-only default intact. An explicitly configured test
forwarder binds a numeric private IPv4 address and admits only one exact miner
source IP. Its upstream must be loopback. Loopback endpoints are also allowed
for software tests. Public/wildcard binds and network-prefix allowlists reject.

The forwarder allows one client by default, at most four, and transfers at most
16 KiB per read. Each connection has a configurable aggregate budget of at most
16 MiB across both directions. A separate timer closes the listener and active
sockets after at most 600 seconds. EOF, native service withdrawal, timeout and
budget exhaustion close both directions. Socket writes have 200 ms timeouts;
these settings are operational bounds, not hard real-time guarantees. IP
allowlisting is a lab restriction, not cryptographic miner authentication.

## Independent, sole-restorer supervision

[`goldshell_test_supervisor.py`](../contrib/sharepool/goldshell_test_supervisor.py)
runs separately from the mining worker. Only the supervisor receives the private
bridge configuration and owns pool changes and restoration through the existing
`guarded_test()` routine. The mining worker must not access the bridge.

Before routing changes, the worker must complete native/profile/listener
preflight and atomically publish a fresh, owned mode-0600 readiness file with the
exact `READY` marker exported by the supervisor module. The supervisor refuses
preexisting paths, failed readiness, a dead worker, or unsafe marker files.
Readiness is a process handshake, not a substitute for native validation.

The existing guard writes and fsyncs its exclusive private configuration backup
before changing pools, retains original fallback pools, and verifies priority.
Every restoration path first attempts to terminate the owned mining process
group and reap its leader. An unresponsive worker receives SIGTERM and then
SIGKILL. Detached signer sessions are outside this group; their normal signer
cleanup remains separate. If worker cleanup fails, restoration still proceeds:
the mining-only worker has no bridge access. Cleanup failure is reported
separately without masking the verified restoration result. Only one supervisor
performs pool mutations, avoiding concurrent restoration attempts.
The supervisor remains responsible until original pools/settings are verified.

Child stdout/stderr goes to a new private log. The supervisor's CLI prints only
credential-free outcome fields. Its bridge requests use timeouts of at most five
seconds. Supervisor death, host power loss or an unreachable bridge can still
prevent restoration. This protects against worker failures; it cannot guarantee
recovery after the supervising host disappears. The private backup remains the
recovery source. Restored configuration does not by itself prove that the original production
pool is receiving fresh accepted work; that needs a separate check.

For a restored DATUM route, the existing configured file log can provide that
freshness check when it records `datum_protocol_share_response` acceptance
events. Record the file's identity and byte offset after restoration, then count
only appended share-response accept/reject events over a bounded interval.
Listener messages saying a connection was accepted are not share acknowledgments.
Log rotation, truncation or a byte-budget overrun make the check inconclusive;
restart the observation without changing gateway settings. A positive delta is
gateway-wide upstream acceptance, so pair it with the miner's restored active
pool and fresh device telemetry. It does not by itself attribute the accepted
work to that physical miner. No worker identities or credentials need to appear
in the report.

## Tests and remaining integration

Software tests cover optional target bounds and rejection before native
admission, bidirectional loopback forwarding, wrong-source refusal, connection
and traffic limits, timed withdrawal, and restoration using a fake bridge with
real disposable worker processes. Fault cases include a hung worker, ignored
SIGTERM, death after the pool changes, lost mutation responses, failed readiness,
and cleanup failure that must not veto restoration. These tests do not contact
a device or qualify firmware behavior.

The [mining-only native worker](../test/functional/feature_sharepool_hash_hardware_worker.py)
now combines the service, forwarder and atomic readiness handshake with a bounded
durable capture and [independent native replay](../contrib/sharepool/v7_hardware_capture.py).
It starts two fresh v7 regtest nodes with networking disabled and uses a real
temporary native signer. The capture has a 90-second maximum and stops after
16 unique hardware receipts; issued-job retention and capture records also have
explicit byte/count bounds. SQLite uses FULL synchronous mode; successful native
snapshot/template/share/block calls are recorded in order, and exact job/proof
records are durable before their handoff or response returns. Capture failures
latch and prevent a successful export.
Terminal reports default to `failed`; only completed validation, replay and
cleanup can publish `passed`. Exceptions or unfinished exits cannot leave a
terminal artifact claiming the worker is still running.

Replay reconstructs every Sia proof and native header, checks exact signatures
and full jobs, then replays the native validation/submission calls on the second
isolated node. It checks the resulting native tip, actual coinbase script/amount
and that winning commitments settle captured proofs. Every active-chain winner,
including the final block, must match the exact bytes and hash of a captured,
reconstructed Sia proof. Submission evidence requires the exact five authorized
fields and the matching job ID. This finite fixture uses
one payout owner and coinbase-only jobs; it does not replace multi-owner or
transaction-throughput tests. A replay cannot establish physical provenance.

Hardware mode requires explicit LAN endpoints, fresh capture/result paths and
a readiness file. Only `--software-test` permits the synthetic loopback client
and native easy transport target; it stops after four receipts. For example:

```sh
python3 -B test/functional/feature_sharepool_hash_hardware_worker.py \
  --software-test --seconds=15 \
  --configfile=/absolute/build/test/config.ini \
  --tmpdir=/private/tmp/fresh-v7-worker-test --nocleanup
```

The preparation suite passed **76 tests**. The isolated native software fixture
also passed on the final shared-budget build with **five captured jobs, four
receipts and four accepted blocks**.
A second fresh node replayed 81 captured native calls and reached the identical
tip. All four winning blocks matched their captured reconstructed proofs; three
proofs settled, with the final winner's proof left for a subsequent commitment.
The public capture is 196,531 bytes. The
[verification manifest](../contrib/sharepool/results/production-v7-worker-final-software-verification.json)
records unchanged native source/binary hashes and the captured Python source
hashes; the [result](../contrib/sharepool/results/production-v7-worker-final-software.json)
and [native log](../contrib/sharepool/results/production-v7-worker-final-software-native.txt)
record the observed scope. This is software evidence, not a physical miner test.

The ordinary Stratum runner does not implement the supervisor's readiness/capture
protocol. The new worker has passed independent review and the native software
integration above. Allow the supervisor time beyond the
mining window for replay and clean shutdown. A physical run must also check
restoration and resumed activity separately, as the observation below did.

V7 withdraws TCP connections on native-tip changes. Under easy regtest settings,
an ASIC proof at transport difficulty 4096 is also a block candidate, so frequent
disconnect/reconnect and fallback behavior must be measured. A successful older
v6 run cannot establish those behaviors, current snapshot validity, or current
coinbase settlement correctness.


## Physical Goldshell observation

The [public capture](../contrib/sharepool/results/production-v7-goldshell-capture.jsonl)
and [verification report](../contrib/sharepool/results/production-v7-goldshell-verification.json)
record **six issued jobs, four acknowledged hardware proofs and four accepted
native blocks** during a nominal 90-second window (observed 90.014 seconds).
The synthetic client was disabled. The existing bridge temporarily prioritized
an explicitly configured, exact-IP-restricted forwarder. A separately running
supervisor held the private recovery backup and restored the original routing.

The second isolated node replayed **94 native calls**, matched all four exact
winning proofs and the final tip, and verified actual coinbase payouts. Three
proofs settled; the final winner's acknowledged proof remains for the next
commitment. The 233,055-byte public capture contains public job/proof evidence;
private credentials, pool configuration and bridge logs are excluded.

The immediate post-restore check found the correct configuration but an inactive
primary pool and zero hashrate, so the private wrapper correctly reported an
incomplete overall result. A later read-only check matched the original pool
order and settings, found the original primary active with positive device
hashrate, and observed **two new upstream accepted responses and zero rejected
responses** in 6.02 seconds of the existing DATUM file log. No further pool,
fan, power or restart changes were made. Both observations are preserved in the
public verification report. The original route was Convoy at test time; this
run did not reconfigure it to the Lazarus route used by older tests.

The local wrapper latched stop signals and requested worker shutdown through
normal polling, allowing the sole supervisor to finish restoration. Supervisor
state was persisted before post-test telemetry. This does not survive loss of
the supervising host. The gateway acceptance observation is aggregate, and the
READY-based window is not a calibrated ASIC utilization measurement. Frequent
regtest block-triggered disconnects, reconnect latency, long sessions and SHA256
hardware compatibility still require separate qualification.
