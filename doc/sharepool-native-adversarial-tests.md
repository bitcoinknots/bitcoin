# Native SPN1 adversarial validation

The additional tests cover actual native P2P delivery and validation of late
origin-template bodies. They use disposable regtest nodes with
`-sharepoolheight=1 -testactivationheight=blake2b@1`. No public network or physical
miner participates, and this profile remains unavailable on mainnet.

## Recent-ancestor template validation

`validatesharepooltemplate "serialized_block_hex"` checks a complete, canonical
block template of at most 4,000,000 bytes. Its parent must be the native active
tip or an active-chain ancestor at most three blocks behind that tip. Both the
origin height and active chain must have the regtest SPN1 profile enabled.

The node reconstructs the parent's UTXO view by disconnecting at most three
native blocks into a temporary `CCoinsViewCache`. It then uses the same header,
block, contextual and `ConnectBlock(..., fJustCheck=true)` validation as a mining
proposal. Transaction scripts, actual fees, owner authorization and exact
coinbase payouts are checked. Candidate PoW is not required because the input
is an unmined template. The original `getblocktemplate` proposal contract still
requires the current tip.

The temporary view is never flushed. Active tip, block index, mempool, UTXO
contents and on-disk chainstate are not replaced or reorganized. Ordinary
validation caches and timing counters may be updated. Missing block or undo
data fails validation; it does not cause acceptance with reduced checks.

Successful responses include `valid`, `native_tip`, `native_parent`,
`origin_height` and `commitment`, with hashes in normal RPC display order.
This result validates a body; it does not authorize a mining job or credit a
share. The miner gate still verifies the share and its current eligibility,
and checks its own direct-payout and known-work inclusion policy before dispatch.

`feature_sharepool_ancestor.py` checks:

- An unsolved template with a mature P2WSH input and an actual 12,345-satoshi fee.
- Historical validation after the active chain spends that input differently.
- Rejection of wrong scripts, missing inputs, fee underpayment and trailing bytes.
- Rejection of a known, otherwise valid side-branch parent.
- Acceptance three blocks behind the tip, including after restart, and rejection
  four blocks behind it.
- Failure with missing historical undo and recovery when it is restored.
- Unchanged active tip, chain tips, mempool and relevant UTXOs after successful
  and failed validation.

## Actual P2P fork behavior

`feature_sharepool_network.py` connects three enforcing nodes in a line. A valid
block is submitted only to its producing node; peers obtain the complete block
through Bitcoin P2P. Received block-message byte counters and identical raw
coinbase bodies are checked.

The test partitions the third node, pays a share on the two-node branch, then
builds a longer branch on the isolated node. Reconnecting P2P peers selects the
greater-work chain and removes the orphaned payment state. A still-eligible
share whose payment was orphaned can then be paid on the selected branch.

Invalid payout commitments and replayed shares are sent through P2P test
connections and rejected independently by all three nodes. A stopped node
catches up over P2P, and a full reindex preserves the selected chain and payment
state. This tests Bitcoin block propagation; pool snapshot transport has its
own separate tests.

## Bounded native fuzz target

The `sharepool` target in `src/test/fuzz/sharepool.cpp` exercises:

- Canonical manifest decoding, truncation, CompactSize and allocation bounds.
- Native signer policy and envelope decoding, including exact byte limits.
- Exact encode/decode round trips and canonical carrier sizes.
- Payout conservation and permutation invariance, including zero, one satoshi
  and `MAX_MONEY` rewards.
- Active block validation using a signed seed with a real native share proof.
- Mutated parent openings, owner binding, share headers and authorization,
  commitments and coinbase carrier framing.
- Consistent results across repeated calls and with/without the optional exact
  fee-derived reward argument.

Inputs are bounded to `MAX_MANIFEST + 1` bytes, mutations to 32 positions and the
fixture's proof search to 256 attempts. Schnorr verification and the SPN1 share
hash/target comparison use the native implementation.

The initial local campaign compiled this target with AddressSanitizer and
UndefinedBehaviorSanitizer and passed 2,685 deterministic corpus inputs. The
corpus is generated independently by `contrib/sharepool/native_fuzz_corpus.py`.
This was a reproducible corpus run, **not coverage-guided fuzzing**, and is not
an external security audit. Leak detection was disabled on this macOS run;
the prebuilt external dependencies were not rebuilt with sanitizers.

Example reproduction, using a separately configured fuzz build:

```sh
cmake -S . -B build-fuzz -DBUILD_FOR_FUZZING=ON -DENABLE_WALLET=OFF \
  -DCMAKE_BUILD_TYPE=Debug -DSANITIZERS=undefined,address
cmake --build build-fuzz --target fuzz
python3 contrib/sharepool/native_fuzz_corpus.py /tmp/sharepool-corpus
FUZZ=sharepool ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  build-fuzz/bin/fuzz /tmp/sharepool-corpus
```

The final command uses the built-in corpus runner when libFuzzer/AFL is not
linked. An instrumented coverage-guided build should also use these seeds for
longer campaigns, including other platforms and transport integration. The
tests do not establish large-pool capacity, protection against undisclosed
shares, or readiness to activate new mainnet consensus rules.
