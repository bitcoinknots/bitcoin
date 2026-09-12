# Native settlement enforcement and miner admission

The new SPN1 profile adds actual native block rejection for incorrect committed
snapshots and direct coinbase payouts. It is explicitly enabled only on a fresh
regtest chain. Mainnet and public test networks reject the activation option.
A separate bounded Goldshell run produced 28 blocks under this new profile on
an isolated regtest chain; another enforcing node independently replayed them.
The earlier public Testnet4 run used a different capture envelope.

The current integration uses existing Bitcoin P2P connections for full origin
templates and shares. Native signing, recent-ancestor validation and a complete
acknowledged-work archive support miner admission and explicit deep-fork
recovery. These software checks did not reroute the physical miner. The prior
accelerated 162-block loopback run remains a separate recorded milestone.

This is a testable native implementation, not a mainnet release. The wire
contract and exact limits are in [the format specification](sharepool-native-format.md).

## What a validating node enforces

A block needs both its ordinary native consensus validity, including PoW at or
below the block target, and a valid settlement. The node verifies:

1. A canonical, bounded manifest transported inside the block's coinbase. The
   `m_mm_rhs` envelope commits the network, rules, pool, native parent, owner,
   share/template evidence, resulting paid state and monetary outputs.
2. Each share's native BLAKE2b PoW, contextual target and native ancestry. The
   origin envelope binds its miner key, payout script and pool before hashing.
   Native libsecp256k1 verifies BIP340 authorizations; a copied proof cannot be
   redirected by attaching somebody else's signature afterward.
3. Exact amounts and script bytes for every monetary coinbase output. Work is
   aggregated by original payout script, including multiple keys paying the
   same destination. Integer allocation and deterministic rounding distribute
   the full subsidy plus actual validated transaction fees directly to those
   scripts. Merely updating the payout hash to match a fraudulent allocation
   does not make the allocation valid.
4. A parent-state opening authenticated against the actual native parent's
   commitment. Previously paid IDs cannot be credited again, including across
   alternate pool snapshots. Each branch derives its state from its own native
   ancestry; off-chain checkpoint preference cannot erase a canonical payout.
5. Exact data-carrier and witness-output placement. Manifest chunks stay within
   the existing 83-byte RDTS script limit. Monetary payout hashing excludes those
   chunks, avoiding a commitment that would contain its own hash preimage.

The implementation is in [consensus/sharepool.cpp](../src/consensus/sharepool.cpp).
Checks run in contextual block validation and again in `ConnectBlock` after
actual UTXO-derived fees are known. The latter covers reindex and chainstate
rebuilding independently of cached block/script validity.

This replaces the earlier synthetic reward-history fork choice for this native
profile. Anyone can participate or define a pool ID; native PoW orders actual
settlements. No fixed coordinator quorum or locally selected checkpoint tip
determines block validity. The older checkpoint and signed-registry experiments
remain separate, including their quota policies.

## What the miner verifies before hashing

[`NativeMiningGate`](../contrib/sharepool/native_mining_gate.py) requires the
miner's configured key, payout script and pool in its own job. Different owner
bindings change the committed template even when transaction selection is the
same. This establishes different committed jobs, not independent hardware or
proof that a particular DATUM executable produced them.

The gate first checks that its local regtest node advertises the exact active
profile. It obtains an explicitly incomplete base GBT using the existing
`skip_validity_test` capability, with space reserved for the manifest. That base
GBT is never an authorization to mine. The coordinator completes the manifest,
coinbase payouts, witness commitment and header root, then each miner submits
the full candidate to its own node's proposal validation.

Before accepting any share, the gate requires the share's complete origin
template to have passed `validatesharepooltemplate`. That native RPC validates
the complete block against its actual active-chain parent, including transactions
and actual fee payouts. For still-eligible historical origins it reverses at most
three recent blocks in a temporary UTXO view; it does not rewind the live chain.
Unknown, orphaned or expired parents and unavailable block/undo data fail closed.
The gate retains the validated body and its normalized immutable header. The
native `validatesharepoolshare` RPC
then verifies the received header proof and owner attribution. Receipts enter
SQLite WAL/FULL storage before acknowledgment. Unknown origin templates cannot
earn local admission merely because their header hash satisfies the share target.

The same full-origin requirement applies to every share introduced directly in
a coordinator's proposed snapshot. Those validated proofs become locally known
work too. The miner rejects a proposed job that omits its known eligible unpaid
proofs, even when the native block would otherwise be valid. This is a mining
policy decision; nodes do not turn their different arrival histories into
different Bitcoin block-validity rules.

An authorized job is immutable. Call `ready_for_dispatch()` immediately before
initial dispatch, and keep observing `needs_refresh()` while mining. Work
received later requests a new template; it does not change a solved block's
coinbase or root. Only the explicitly supported physical nonce, extranonce and
search-time fields can change within an authorization. The later work and a
winning proof can be included in a subsequent snapshot while eligible.

An origin job at height `j` remains eligible through settlement height `j+3`.
Its paid ID survives that complete window. At `j+4`, the proof is ineligible and
its old ID can be pruned. This is a bounded test rule, not a guarantee of later
inclusion or payment if nobody publishes the proof before expiry.

## Signing, peer exchange and recovery

The [native owner signer](sharepool-native-signer.md) generates a private key
locally and uses native libsecp256k1 to sign the existing owner authorization.
Its immutable local policy binds the regtest domain, owner, nonzero pool ID and
payout script. The Python adapter passes only public policy/envelope bytes and
never reads the private key file. The signer is offline: it does not replace
full-template validation or authorize signing requests received from peers.

The [native P2P extension](sharepool-native-p2p.md) negotiates evidence support
over ordinary Bitcoin connections. It bounds inventories, requests, chunks and
admission rates, applies full native validation, and respects existing send-queue
backpressure. [`native_node_peer.py`](../contrib/sharepool/native_node_peer.py)
publishes local evidence and imports origins before proofs through the durable
gate. Relay acceptance is ephemeral; it is not a miner acknowledgment. Inventory
is neither a consensus checkpoint nor proof that all work was disclosed. The
earlier standalone loopback service remains a separate test fixture.

The gate's hot cache retains evidence behind a 144-block native anchor. An
append-only archive in the same SQLite transaction preserves complete
acknowledged history before hot rows are pruned. A protected checkpoint is
synchronized before acknowledgment. Losing the anchor still latches recovery;
explicit recovery verifies complete history against that checkpoint and
revalidates eligible bodies/proofs natively before atomically rebuilding the
cache. Missing, stale or divergent history cannot clear the latch. Quota
exhaustion refuses new work. The three-block eligibility window is unchanged;
see [archive recovery](sharepool-archive-recovery.md).

## Reproduction

Build a separate tree with the normal repository dependencies:

```sh
cmake -S . -B build-sharepool -DBUILD_GUI=OFF -DENABLE_WALLET=OFF -DBUILD_TESTS=ON -DBUILD_UTIL=ON
cmake --build build-sharepool --target bitcoind bitcoin-cli bitcoin-sharepool-signer test_bitcoin -j4
build-sharepool/bin/test_bitcoin --run_test='sharepool*'
python3 -B test/functional/feature_sharepool_enforcement.py \
  --configfile=build-sharepool/test/config.ini
python3 -B test/functional/feature_sharepool_node.py \
  --configfile=build-sharepool/test/config.ini
python3 -B test/functional/feature_sharepool_archive.py \
  --configfile=build-sharepool/test/config.ini
python3 -B test/functional/feature_sharepool_relay.py \
  --configfile=build-sharepool/test/config.ini --v2transport
SHAREPOOL_SIGNER_BINARY="$PWD/build-sharepool/bin/bitcoin-sharepool-signer" \
  python3 -B -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
```

The first functional test creates two disposable wallet-disabled nodes, one enforcing
and one deliberately not enforcing. It builds actual blocks and transactions,
checks deliberate disagreement, exercises native forks, restarts and reindex,
then stops both nodes. The node integration uses three enforcing nodes, three
miner gates and fresh native signer keys to exchange evidence on existing P2P
connections, recover a cold peer and verify direct payouts. The archive test
checks a 162-block rollback and restoration of pruned acknowledged proofs.
The wire test runs with legacy or BIP324 v2 transport, including actual transfer
timeouts and malformed messages. `feature_sharepool_ancestor.py` tests historical UTXO
validation; `feature_sharepool_network.py` tests three enforcing native P2P nodes
through partition, rejoin and offline catch-up. These tests use no public mining
network or physical miner. The signer executable currently requires POSIX.

Manual test activation requires both `-testactivationheight=blake2b@1` and
`-sharepoolheight=1` on regtest. Use a fresh datadir. When changing an existing
test chain's activation schedule, perform a full reindex: activation parameters
are not fingerprinted in the chain database. Never infer retrospective
validation from a previously accepted cached chainstate.

The deterministic fixtures in [`native_enforcement.py`](../contrib/sharepool/native_enforcement.py)
retain explicit public test secrets. Its external signing callback also supports
the native signer without a Python secret, and the new peer functional test uses
that path. The miner gate does not hold signing keys. Production key provisioning,
recovery and DATUM/gateway deployment remain separate integration requirements.

## Evidence and limits

[The native build report](../contrib/sharepool/results/native-build.json) records
compiled targets, their hashes, the native unit/regression cases and activation
guard checks. The [functional report](../contrib/sharepool/results/native-enforcement.json)
records the earlier complete-node scenarios. The preceding
[hardening report](../contrib/sharepool/results/native-hardening.json) records
333 passing Python tests with no skips and the accelerated 162-block native peer
integration. This is not a real-time endurance benchmark.
The [signer report](../contrib/sharepool/results/native-signer.json) records native
key/file-policy tests. The [adversarial report](../contrib/sharepool/results/native-adversarial.json)
records real native P2P disagreement/rejoin, historical UTXO validation and 2,685
deterministic corpus inputs under address and undefined-behavior sanitizers.
That corpus run is not a coverage-guided fuzzing campaign or an external audit.
Python regression results remain in
[unit-tests.txt](../contrib/sharepool/results/unit-tests.txt).
The [current integration report](../contrib/sharepool/results/native-p2p-recovery.json)
and [wire results](../contrib/sharepool/results/native-p2p-wire.json) record
existing-connection propagation, complete archive restoration and both legacy
and BIP324 v2 transport tests. Earlier reports retain their original scope; the
deterministic sanitizer corpus predates this relay/archive implementation.

The earlier [physical SPN1 report](../contrib/sharepool/results/native-hardware-regtest.json)
records the local Goldshell SCLITE run with a 90-second capture limit: 28 accepted
submissions, no rejections, 29 complete authorized jobs and 28 native blocks.
Blocks 2 through 28 each settle the previous hardware winning proof. The final
job includes the last winner, which remains pending because no next block was
found during the test. The solved commitments were never edited. These hardware
measurements predate the new signer, historical-origin RPC and peer/recovery
changes; they are not hardware validation of that later software pass.

The [independent replay](../contrib/sharepool/results/native-hardware-replay.json)
reconstructed every ASIC hash and full native block, then revalidated all 29
origin proposals and the 28-block chain on another fresh enforcing node. All
physical proofs also met transport difficulty 4096; native payout weight stayed
at the profile's fixed expected work of 2 per proof. These targets must not be
conflated. The hardware fixture used one payout destination and coinbase-only
blocks; the separate functional test covers multiple owners and actual fees.

The original miner pool order and settings were restored, the temporary pool
entry was removed, and the isolated native node exited cleanly. Fresh Lazarus
work is verified separately in the physical report. No miner reboot, firmware,
fan, power or network-setting change was performed.

The [native hardware capture](../contrib/sharepool/native_hardware_capture.py)
is a bounded test instrument. It uses an owner-thread queue to keep native gate
SQLite operations on their owning thread, and checks the admission fence before
notifications. Gate receipts and full proof/candidate archives are durable before
acknowledgment readiness. Failures after proof admission stop the run. The
configuration guard disarms the caller's watchdog before every restoration path,
including failures before the mining callback starts. The CPU-only preflight and
fault tests cover these paths; they do not replace long-running recovery work.

The new tests enforce snapshots and direct payouts instead of only observing
incorrect payouts after acceptance. They do not establish production security:

- **Completeness:** a commitment cannot prove disclosure of unseen shares. A
  coordinator can still omit work unknown to a miner. There is no globally
  enforced guarantee to settle every submission, and an empty disclosed
  snapshot pays its authorized owner.
- **Origin bodies:** native settlement consensus verifies the committed origin
  headers and work, not every unmined origin transaction body. Full origin-body
  validation is enforced by the miner gate, now including recent historical
  origins through the temporary-UTXO RPC. Missing local block/undo data prevents
  that validation. The distinction between miner policy and block consensus
  still needs protocol review before broader enforcement claims.
- **Scale and service lifetime:** the profile has 32 shares per block and an easy
  fixed regtest target. The gate permits at most 128 active receipts and 128
  active origin templates, with a separately bounded retained archive and a
  64-job audit cache. Reaching a bound refuses admission; it does not silently
  drop acknowledged work. Complete history has a separate quota and protected
  checkpoint. Native P2P transfer and deep recovery have local tests. Production
  target adjustment, sampling, WAN load/fairness, protected backup operations
  and large-pool capacity testing remain.
- **Quotas and identities:** there is no 10% rule and no claimed physical TH/s
  limit. This native profile does not transplant checkpoint-epoch work caps.
  Self-authorized key/script bindings are permissionless registrations, not a
  proof of independent operators or mandatory use of one software implementation.
- **Deployment:** native peers without this rule accept blocks that enforcing
  peers reject; the functional test demonstrates that divergence. Activation
  coordination, sustained adversarial campaigns, coverage-guided fuzzing,
  independent security review, composition with other uses of `m_mm_rhs`, and
  additional build platforms remain release requirements. The existing P2P,
  deterministic sanitizer and local recovery tests do not authorize mainnet
  activation.
