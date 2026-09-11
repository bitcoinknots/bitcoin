# Local native owner signer for SPN1 testing

`bitcoin-sharepool-signer` replaces Python fixture-secret signing on the new
local service integration path. It generates and uses a native `CKey`, signs
through the bundled libsecp256k1 implementation, supplies fresh strong auxiliary
randomness for every BIP340 signature, and verifies its output before returning
it. It has no wallet, RPC server, network connection, or private-key import API.

This tool is restricted to the compiled **regtest** genesis and SPN1 rules hash.
It does not activate SPN1 on another network or make the overall experimental
protocol ready for production.

## Local signing policy

Initialization permanently binds one randomly generated owner key to one
nonzero pool ID and one exact supported coinbase payout script. Every signing
request must match that policy, the resulting x-only owner key, version 1,
regtest genesis, and the compiled SPN1 rules hash. Height must be in
`[1, INT_MAX)` and the native parent must be nonzero. A mismatch produces no
signature. There is no general-purpose “sign this digest” command.

The signature authorizes the existing SPN1 `OwnerHash`: genesis, rules, height,
parent, pool, owner, and payout script. **It does not attest to the snapshot
roots, full template body, current chain tip, or complete disclosure of work.**
SPN1 separately binds snapshot roots through the mined header, and native
consensus checks the contained evidence. The caller must use the native mining
gate to validate the complete template and current native context before
dispatching work. A service must not forward peer requests to this signer.

The owner key is an accountability key. It is independent of any wallet key
controlling the configured payout script. Correct local payout configuration
remains the operator's responsibility.

## Executable interface

The target is built when `BUILD_UTIL=ON` on POSIX systems. Windows support is
not implemented. All three commands accept only a file path on the command
line:

```text
bitcoin-sharepool-signer init KEYFILE
bitcoin-sharepool-signer pubkey KEYFILE
bitcoin-sharepool-signer sign KEYFILE
```

`init` reads one canonical hex line from stdin. Its decoded policy is
`version:uint8=1 || pool:uint256-le || payout_script:CompactSize-vector`, at
most 68 bytes. It exclusively creates a new key file and returns the 32-byte
x-only public key as 64 lowercase hex characters and a newline. It refuses
to overwrite an existing file.

`pubkey` reads no stdin and returns the same public key. `sign` reads one
canonical serialized SPN1 Envelope as hex, at most 296 decoded bytes, and
returns a 64-byte signature as 128 lowercase hex characters and a newline.
Input must end at EOF; at most one terminating newline is permitted. Length,
trailing data, CompactSize canonicality and policy are checked before signing.
Errors return a nonzero exit code, no stdout, and a fixed bounded diagnostic.
Neither key bytes nor input contents are printed.

## Private file handling

Use a private directory owned by the operator with mode `0700`, on a trusted
local filesystem. The file contains the literal magic `SPKEY001`, the policy
above, and the 32-byte private scalar. **The file is not encrypted.** It is not
a portable backup, secret sharing, wallet, or hardware signer format.

Creation uses exclusive, no-follow access and mode `0600`, then synchronizes
the file and parent directory before returning success. If creation fails
partway through, a file may remain; initialization never silently overwrites
it. File reads reject symlinks at the final path component, nonregular files,
wrong ownership, any mode other than `0600`, multiple hard links, oversized or
malformed records, and invalid keys. macOS creation clears inherited extended
ACLs before writing the key, and later reads reject any extended ACL.

Private buffers use Bitcoin's cleansing secure allocator and native `CKey`;
the executable disables core dumps before generating or loading a key. These
measures do not protect against a compromised host, another process running as
the same user, an administrator, or malicious filesystem ancestors. Parent
directory symlinks and storage/backup policy are outside this interface. Keep
the executable and private directory under trusted local control.

## Python integration

[`native_signer.py`](../contrib/sharepool/native_signer.py) starts an explicitly
selected local executable without a shell or PATH lookup. It passes only
public policy/envelope bytes on stdin, caps both output streams while reading,
enforces a deadline, and independently verifies returned public signatures.
It never reads the private file. Existing files are opened with `NativeSigner`;
fresh keys use its exclusive `create` method:

```python
signer = NativeSigner.create(binary, key_file, pool=pool_id,
                             payout_script=local_payout_script)
block, manifest = candidate(
    genesis=regtest_genesis, native_parent=validated_parent,
    height=next_height, ntime=block_time, pool=pool_id,
    payout_script=local_payout_script, public_key=signer.public_key,
    sign_owner=signer.sign_owner,
)
# Full origin/template validation and authorization through NativeMiningGate
# remain required before any miner receives this block.
```

`candidate` and `build_manifest` still support the older explicit `secret`
argument for deterministic unit/functional fixtures. The new signer path
rejects mixing that argument with an external signing callback. Hardware test
fixtures and legacy examples that explicitly use public test keys remain test
fixtures; this tool does not silently migrate any existing key.

## Verification

Native unit cases cover successful random-key signing, wrong network and
identity bindings, the exact authorization scope, and bounded canonical input.
The Python suite tests subprocess output floods, deadlines, malformed output,
and callback requirements without accessing private material. To additionally
exercise the actual compiled executable and disposable native keys:

```sh
SHAREPOOL_SIGNER_BINARY=/absolute/build/bin/bitcoin-sharepool-signer \
  python3 -B -m unittest discover -s contrib/sharepool -p test_native_signer.py
```

The executable tests check actual native signatures, the secretless template
builder, exclusive creation, permissions, symlink/hardlink rejection, special
files, corrupted records, native policy enforcement, and strict stdin bounds.
They generate only temporary keys. Multi-platform validation, independent
security review, protected key provisioning/recovery and deployment packaging
remain release work.
