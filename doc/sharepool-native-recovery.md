# Native SPN1 evidence transport and gate recovery

The local regtest integration now combines a native owner signer, durable miner
gates, public template/share exchange and independent native block validation.
[`feature_sharepool_peer.py`](../test/functional/feature_sharepool_peer.py) is the
executable integration example. This is a testing component, not a public-network
service or a mainnet activation mechanism.

## Admission and settlement

Each owner registers a complete origin template with its own accountability key
and exact payout script. A recipient downloads the template before its proofs,
checks its content hash and native template identity, and calls
`validatesharepooltemplate` on its own node. That RPC checks the complete body,
including inputs, scripts, fees and settlement. It accepts the active tip or an
eligible active ancestor at most three blocks behind, using a temporary UTXO
view and actual block/undo data. Missing historical data refuses validation.
See the [native adversarial guide](sharepool-native-adversarial-tests.md).

The gate then validates each share's native proof, owner signature, origin and
eligibility before durable admission. Before releasing a new job, it checks the
current native tip, its configured owner/payout policy, exact native coinbase
payouts and inclusion of its locally known eligible unpaid work. The
[native signer](sharepool-native-signer.md) authorizes the owner/round/payout
binding; it does not replace those full-body and completeness checks.

A mined commitment is immutable. Work received after a snapshot was prepared,
including that job's eventual winning proof, must be included in a refreshed
unsolved job or carried into a later eligible settlement. Editing a solved
commitment would invalidate its PoW. The 162-block integration run checks this
carryover, direct payouts and the regtest subsidy halving.

Native consensus validates the evidence committed in each block. It does not
depend on one node's mutable local registry or the availability of this HTTP
service. If a coordinator withholds a body, the receiving gate cannot admit
that proof; already validated evidence remains durable and can be retried.
Peers may all omit evidence unknown to a miner. A matching inventory root does
not prove complete disclosure, unique human operators or use of a particular
DATUM executable.

## Durable archive and bounded recovery

`NativeMiningGate` owns one SQLite database with a persistent POSIX advisory
lock on its `.owner.lock` sidecar. A second owner is refused. Keep this database
and sidecar in a trusted local directory; do not delete the sidecar while the
service is running. Unsupported locking platforms fail closed. Startup checks
the schema, configured identity, bounded rows/blobs and stored content hashes.
Creation and migration from schema v1 to v2 are explicit atomic transactions.

The permanent receipt revision is a signed 64-bit high-water mark. Pruning
never resets it or reuses a deleted receipt's sequence. Exact duplicate proofs
do not receive another credit. The archive retains paid and orphaned evidence
while a supported reorganization could make it relevant again.

| Bound | Value and behavior |
| --- | --- |
| Native retention anchor | Monotonically advances to at most 144 blocks behind the active tip |
| Pruning cutoff | Delete only origins with `origin_height <= saved_anchor_height - 3` |
| Active inventory | At most 128 templates and 128 receipts |
| Retained archive | At most 18,944 templates and 18,944 receipts |
| Retained full-template bytes | At most 268,435,456 bytes |
| Job audit history | At most 64 jobs, each at most 4,000,000 bytes |
| Native settlement snapshot | At most 32 shares under the unchanged SPN1 regtest rules |

Exceeding capacity refuses new admission; it does not silently discard
acknowledged work. Metadata and content are validated before pruning. Active
inventory contains only origins eligible under the current native ancestry;
retained archive entries need not be advertised. Inventory polling reads scalar
metadata, while object retrieval rechecks the stored body. `pruned_through` is
the greatest removed receipt sequence, **not a native block height**.

If the saved anchor disappears from the active chain, or the tip goes below it,
the gate persistently latches `RecoveryRequired`. Admission stops across restart,
even if the old chain later returns. There is deliberately no clear-latch API:
this version has no verified deep-history recovery protocol. Preserve the
database and restore/reconcile complete acknowledged evidence before resuming;
deleting the database or resetting the latch would lose the completeness basis.
An automated archive recovery procedure remains release work. The peer poller
reports this as a local recovery requirement without penalizing a remote peer.

## Local evidence service

[`native_peer.py`](../contrib/sharepool/native_peer.py) is a library used by the
integration test. `NativePeerService(gate_factory)` runs the gate and its RPC
client on one owning thread. The caller can invoke the explicit local methods
`register_template`, `receive`, `authorize`, `maintenance` and
`active_inventory`. No network route exposes those mutations, private keys,
signing or RPC credentials.

The read-only HTTP surface is:

```text
GET /spn1/status
GET /spn1/inventory?root=<sha256>&offset=<integer>&limit=32
GET /spn1/object/template/<native-template-id>
GET /spn1/object/receipt/<native-proof-id>
```

The canonical inventory root commits to the profile, pool, native tip, anchor,
revision and sorted object descriptors. Each descriptor carries a SHA256 digest,
byte length, native identity, origin height and parent. Paged requests fail if
the inventory changed. The advertisement cache lasts at most one second and
is not an assertion that the native tip stayed unchanged; admission revalidates
native context. Only advertised active objects are network-accessible.

Both listener and client require numeric loopback addresses. There is no DNS,
redirect following, URL credential handling, TLS, discovery, WAN listener,
remote authentication or deployment daemon. Evidence admission is permissionless
within this local test surface: the rules, not a coordinator signature or a
fixed peer quorum, decide whether an object is accepted.

The implementation bounds JSON to 65,536 bytes, inventories to 256 descriptors
and pages to 32. It rejects duplicate JSON keys, floats, nonfinite values and
oversized integers. HTTP headers have an 8,192-byte bound and at most 33 lines;
duplicate headers, chunking, content encoding and GET bodies are refused.
Objects require an exact bounded `Content-Length` and a five-second read
deadline. Template bodies are at most 4,000,000 bytes; receipt descriptors are
at most 1,024 bytes.

The server permits four concurrent handlers and eight queued gate operations.
Its token buckets allow 32 requests and 8,000,000 response bytes initially,
refilling at 16 requests and 1,000,000 bytes per second. The trusted gate factory
must finish within ten seconds and construct an RPC client with a five-second
per-call timeout. Each actor operation checks an eight-second deadline before
and after RPC calls; an in-flight RPC can exceed it by its own timeout. The
local caller waits at most twenty seconds. Arbitrary factory code or CPU work
is not hard-preempted by these checks. Cancelled queued calls are skipped; a
mutation already in flight can finish without an acknowledgement, so exact
retries must remain idempotent.

`sync_peer(service, url, pool)` pulls at most 32 objects and 16,000,000 object
bytes per round, with needed templates before receipts. If template work is
deferred, receipts are deferred too. Native block tips must match first.
`PeerReplicator(service, pool, peers)` accepts one to eight distinct peers;
the caller invokes `poll()` to advance round-robin work with two-to-sixty-second
failure backoff. It reports `progress`, never a proof of global synchronization.
`receipts` counts newly admitted proofs, `duplicate_receipts` identifies races,
and `templates` counts full-template admission/validation operations.

## Untrusted block decoding

The Python test-framework decoder assumes trusted vector counts. Directly
passing a short hostile body to it could loop or allocate based on huge
CompactSize values. The gate now performs a canonical, allocation-free
structural pass before that decoder. Every transaction, input, output, witness
and script vector is bounded by bytes actually remaining in the body. The
second pass uses a stream that rejects truncated reads. Tests verify nine huge
or noncanonical count vectors and eight truncations fail before the framework
decoder runs, plus a valid witness round trip.

This protects the local gate input path. It is separate from native consensus
decoding, which has its own bounded parser and sanitizer corpus.

## Reproduction and observed scope

Build `bitcoind`, `bitcoin-cli`, `test_bitcoin` and `bitcoin-sharepool-signer`
with `BUILD_UTIL=ON`. On a supported POSIX platform:

```sh
SHAREPOOL_SIGNER_BINARY=/absolute/build/bin/bitcoin-sharepool-signer \
  python3 -B -m unittest discover -s contrib/sharepool -p 'test_*.py'
python3 test/functional/feature_sharepool_peer.py \
  --configfile=/absolute/build/test/config.ini
python3 test/functional/feature_sharepool_enforcement.py \
  --configfile=/absolute/build/test/config.ini
```

The recorded final Python run passed 333 cases with no skips. The peer test
used two native nodes, three local services and three disposable native keys.
It recovered historical origins into a fresh gate, retried deliberate missing
data, checked payouts, ran to height 162, pruned old evidence, reopened the gate,
and tested the persistent deep-rollback latch. It is an accelerated local run,
not a sustained real-time or large-pool benchmark. The separate three-node
test exercises actual P2P competing branches and orphaned payout recovery.

See [recorded hardening results](../contrib/sharepool/results/native-hardening.json),
[signer results](../contrib/sharepool/results/native-signer.json) and
[native adversarial results](../contrib/sharepool/results/native-adversarial.json).
No physical miner was switched for this hardening run. Public-network transport,
deep-history recovery, production difficulty/economics, protected key operations,
multi-platform tests, sustained coverage-guided fuzzing and external independent
review remain necessary before any mainnet deployment proposal.
