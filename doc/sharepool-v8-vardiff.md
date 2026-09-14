# Per-miner assigned share difficulty (v8)

V8 gives each miner gateway its own assigned share target. Native block
difficulty remains the Bitcoin difficulty; it no longer determines the credit
or acceptance target of a v8 share. The gateway's starting cadence is one share
per minute, configurable per miner. It is an expected rate, not a timer that
requires a share every minute or every second.

This is a separately selected regtest profile. V4–v7 rules, encodings and signed
evidence remain unchanged. Existing datadirs cannot silently switch profiles.
Mainnet activation is not provided.

## Commitment and work credit

The v8 envelope adds one byte, `share_work_bits`, after `payout_script` and before
the three reserved root fields. The assigned expected work is `2^share_work_bits`
hashes; the acceptance target is `2^(256-share_work_bits)-1`. Assignments range
from 0 through 255. This power-of-two representation makes the proof probability
and integer work credit agree exactly without floating-point consensus math.
V8 includes hash zero in that range; reserving it would bias the hardest
assignments. Its history scanner and index preserve this v8-only eligibility,
including after cache reuse and restart. Legacy profiles retain their rules.

The byte is covered by the owner's exact-job authorization and the complete
snapshot hash in `m_mm_rhs`. A miner must hash a job that already commits to the
assignment. Publishing an easier target afterward, increasing the credit of a
lucky hash, or replacing its payout identity cannot preserve a valid proof.
The full snapshot remains off-block; the sidechain field contains its flat hash.

Every admission uses the assignment in that proof's authenticated origin job.
A proof from an older, easier job keeps its original weight after the gateway
issues a harder job. TIDES aggregates these weights per payout script within
each pool. Its eight-block-work window, proportional boundary sharing and exact
native coinbase output checks remain in force. V8's history commitment appends
the original assignment byte to each admission's existing credit fields. Native
history indexes must derive the same work from the same authenticated origin.

Native `nBits` is still checked against the chain. A native block candidate must
be submitted even if it misses an unusually hard assigned share target. Such a
candidate receives no share credit unless it also satisfies that assignment.
The independent native-target check matters on easy regtest chains in particular.

## Gateway behavior

Each configured miner payout identity has an independent gate, job stream and
variable-difficulty controller. A local gateway supplies work to its ASIC over
Stratum; peer nodes exchange the authenticated templates and proofs. Connecting
another miner gateway does not change every miner's target.

The controller measures only newly acknowledged, valid work, using each job's
original assigned weight and elapsed monotonic time. Duplicate and rejected
submissions do not contribute. Difficulty changes are bounded and wait for a
minimum observation window. A pending change is applied when the normal job
scheduler next builds work, rather than rebuilding a template after every share.
Already issued jobs keep their assignment and their existing validity checks.

The initial transport adapter is bounded to one active ASIC connection per v8
miner gateway/listener. Multiple miner identities use independent instances.
This is a test adapter, not a production multi-user pool endpoint.

At an achieved mean interval of 60 seconds, 100 miners would produce about 1.67
unique shares per second; 30 seconds would produce about 3.33. Templates,
transactions, relay replication and settlement processing add separate costs.
Per-miner targets remove the old need to lower one network-wide target just to
sample a small miner. They do not remove aggregate validation or admission limits.

For steady independent work at a fixed assigned target and complete disclosure,
the work-rate estimate is weighted proof work divided by observation time. At
one share per minute, a day contains 1,440 expected observations and roughly
2.64% relative Poisson count deviation. This describes sampling, not total payout
variance or an exact physical hashrate measurement. Retargeting, stale work,
withheld proofs, TIDES windows and block luck need their own analysis.

## Running the native profile

Use a fresh isolated datadir and explicitly select all required flags:

```sh
bitcoind -regtest -sharepoolheight=1 -testactivationheight=blake2b@1 \
  -sharepoolhashonly=1 -sharepooltides=1 -sharepoolcompacttides=1 \
  -sharepoolvardiff=1
```

`preparesharepoolhashjob` takes the canonical unsigned v8 snapshot containing the
assignment. The owner signs the prepared exact job before finalization. Resource
measurement and native share/template validation remain separate operations.
The native status mode is `hash-only-v8-vardiff-tides`.

The loopback runner selects an independent miner with `--profile-version=8`,
`--share-work-bits=<initial exponent>` and `--target-share-seconds=60`, together
with its existing node, signer, journal and pool settings. Give each miner its
own journal, signer policy and listener. Choose the initial exponent for that
miner's expected work over the desired interval; the controller then adjusts
future assignments from accepted work. It does not infer a safe starting
difficulty from a device name or a claimed hashrate.

The [native regression](../test/functional/feature_sharepool_hash_vardiff.py)
uses independent miners with different assigned weights at the same native
difficulty. It checks exact actual coinbase payouts, target and identity
mutations, late work across retargets, peer validation, persistent history,
competing branches and reindex recovery. These are correctness checks rather
than a sustained-capacity qualification.

The [paired transport regression](../test/functional/feature_sharepool_hash_vardiff_stratum.py)
uses two independent gates and real synthetic Sia proofs. It checks advertised
difficulties, the connection bound, repeated shares without job refresh,
duplicate exclusion, a scheduled retarget, old-job credit and a native-only
winner's exact block bytes and payouts. Its injected clock makes the retarget
test deterministic; it is not a measurement of physical mining performance.

The [verification manifest](../contrib/sharepool/results/v8-verification.json)
records 295 passing Python tests, 105 native C++ cases and four native scenarios,
including the unchanged v7 compact and Stratum regressions. The 100-miner test
settled 100 proofs into 100 direct payout outputs. The paired transport test also
checks the standalone v8 runner's one-minute configuration and clean shutdown.

## Limits of the guarantee

Assigned difficulty proves and accounts for disclosed work on authorized jobs.
It does not prove where the template was constructed or that its transactions
were independently selected. Direct coinbase payouts and different valid job
hashes do not resolve that distinction. No per-address physical hashrate cap is
introduced by this profile.
