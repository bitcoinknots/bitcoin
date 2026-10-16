#!/usr/bin/env python3
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a pubkey is credited against the datacarrier limit only if a signature verified against it.

A script naming a signature check beside a key used to be enough. Here the checks sit in code that
never runs, or run and fail on an empty signature, and the keys are payload. Unverified pushes are
charged by their length, so a 65 byte push does not pass for a 33 byte key.

Every node runs Knots policy defaults: -corepolicy=0 undoes the -corepolicy the test framework adds,
which would turn the full count off and lift -maxscriptsize. Datacarrier counting is gated on
-datacarrierfullcount (default on). Nodes 0 to 4 count and enforce standardness (-acceptnonstdtxn=0);
nodes 1 to 4 differ from node 0 only in -datacarriersize, which pins a charge between the limits: a
spend is charged c extra bytes if it is accepted by exactly the nodes whose limit is at least c. Exact
numbers above the 83 byte cap are covered by the unit tests. Node 5 turns the full count off
(-datacarrierfullcount=0), so nothing is counted there. Witnesses are kept under 1650 bytes, the
-maxscriptsize default, so each spend stays valid regardless of any script-size policy.

The chain is shaped like mainnet: the BLAKE2b fork is scheduled and active, so the mempool verifies
under SCRIPT_VERIFY_UNIFIED_SIGHASH, and RDTS is in force, so the block script flags include the
reduced-data flags just as the policy flags always do. Honest multisig signed under the unified
signature hash must be credited like any other.
"""
import time
from random import randbytes

from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_string_vector,
)
from test_framework.script import (
    CScript,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_0NOTEQUAL,
    OP_1,
    OP_2DROP,
    OP_2DUP,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CHECKSIGVERIFY,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_IFDUP,
    OP_NOTIF,
    OP_NUMEQUAL,
    OP_SIZE,
    OP_SWAP,
    OP_TRUE,
    SIGHASH_ALL,
    SIGHASH_UNIFIED,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
    UnifiedSignatureHash,
    hash160,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2wpkh_script,
    keyhash_to_p2pkh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet

FUNDING = 100_000
REJECT = "txn-datacarrier-exceeded"
# The -datacarriersize of nodes 0..4 (node 0 runs the default). Knots caps it at 83, so a charge of
# 83 or more can only be told apart from the others by being rejected everywhere.
LIMITS = [83, 0, 32, 33, 66]
UNIT = 33  # an unproven compressed key is charged as 33 bytes, and the allowance is 10 of them
WITNESS_CAP = 1650  # -maxscriptsize at Knots defaults, for the whole witness stack of an input
# The fork and RDTS are active from this height, inside the warmup, with an expiry far ahead.
FORK_HEIGHT = 100
# Knots policy defaults (the framework adds -corepolicy), on a chain past the fork with RDTS in force.
NODE_ARGS = ["-corepolicy=0", f"-testactivationheight=blake2b@{FORK_HEIGHT}", "-rdtsexpiry=2000000000"]
WARMUP_BLOCKS = 310


def charge_for(unproven_keys):
    """Charge for unverified 33 byte keys."""
    return max(0, unproven_keys - 10) * UNIT


class VerifiedKeyCreditTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        # The cached chain predates the fork, so every block here is mined under the fork's rules.
        self.setup_clean_chain = True
        # Counting is gated on -datacarrierfullcount (default on). Nodes 0 to 4 count and enforce
        # standardness; node 5 turns it off, so nothing is counted there.
        defaults = NODE_ARGS + ["-acceptnonstdtxn=0"]
        self.extra_args = [defaults] + [defaults + [f"-datacarriersize={n}"] for n in LIMITS[1:]] + [NODE_ARGS + ["-datacarrierfullcount=0"]]

    # ---- building blocks ----

    def newkey(self, compressed=True):
        k = ECKey()
        k.generate(compressed)
        return k

    @staticmethod
    def pub(k):
        return k.get_pubkey().get_bytes()

    @staticmethod
    def fake_key(size=33):
        if size == 33:
            return b'\x02' + randbytes(32)
        assert size == 65
        return b'\x04' + randbytes(64)

    def p2wsh_sig(self, key, script, tx, i):
        return key.sign_ecdsa(SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL])

    def fund(self, spk):
        f = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=FUNDING)
        return COutPoint(int(f['txid'], 16), f['sent_vout'])

    def spend_many(self, specs, locktime=0, fee=None):
        """Fund every spec that has no outpoint of its own and return an unmined tx spending all of them.

        A spec is a dict with 'spk', 'stack' (a function of the tx and the input index that gives the
        witness) or 'script_sig' (the same, giving the scriptSig of a legacy input), and optionally
        'sequence', 'outpoint' and 'value' for an output that already exists.
        """
        outpoints = [s['outpoint'] if 'outpoint' in s else self.fund(s['spk']) for s in specs]
        if any('outpoint' not in s for s in specs):
            self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        total = sum(s.get('value', FUNDING) for s in specs)
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = locktime
        tx.vin = [CTxIn(op, nSequence=s.get('sequence', 0xffffffff)) for op, s in zip(outpoints, specs)]
        tx.vout = [CTxOut(total - (10_000 * len(specs) if fee is None else fee), script_to_p2wsh_script(CScript([OP_TRUE])))]
        tx.wit.vtxinwit = [CTxInWitness() for _ in specs]
        for i, s in enumerate(specs):
            if 'script_sig' in s:
                tx.vin[i].scriptSig = s['script_sig'](tx, i)
            if 'stack' in s:
                stack = s['stack'](tx, i)
                # Every spend must fit the witness limit of a default node, so that nothing but the
                # datacarrier rules can be what refuses it there.
                size = len(ser_string_vector(stack))
                assert size <= WITNESS_CAP, f"input {i}: witness is {size} bytes, over {WITNESS_CAP}"
                tx.wit.vtxinwit[i].scriptWitness.stack = stack
        return tx

    def p2wsh_spec(self, script, stack, sequence=0xffffffff):
        return {'spk': script_to_p2wsh_script(script), 'stack': lambda tx, i: stack(tx, i) + [bytes(script)], 'sequence': sequence}

    def spend_p2wsh(self, script, stack, sequence=0xffffffff, locktime=0):
        return self.spend_many([self.p2wsh_spec(script, stack, sequence)], locktime=locktime)

    def p2sh_sig(self, key, script, tx, i):
        return key.sign_ecdsa(LegacySignatureHash(script, tx, i, SIGHASH_ALL)[0]) + bytes([SIGHASH_ALL])

    def p2sh_spec(self, redeem, items, sequence=0xffffffff):
        """A legacy P2SH input. items(tx, i) gives the scriptSig pushes that go before the redeem script."""
        assert len(redeem) <= MAX_SCRIPT_ELEMENT_SIZE, f"redeem script is {len(redeem)} bytes"
        return {'spk': script_to_p2sh_script(redeem), 'script_sig': lambda tx, i: CScript(items(tx, i) + [bytes(redeem)]), 'sequence': sequence}

    def p2sh_p2wsh_spec(self, script, stack, sequence=0xffffffff):
        """A P2SH-wrapped P2WSH input. The scriptSig pushes the witness program and the witnessScript is
        spent through the witness, exactly as native P2WSH, so its counted script comes from the witness."""
        program = script_to_p2wsh_script(script)
        return {'spk': script_to_p2sh_script(program),
                'script_sig': lambda tx, i: CScript([bytes(program)]),
                'stack': lambda tx, i: stack(tx, i) + [bytes(script)],
                'sequence': sequence}

    def accept(self, node, tx):
        return node.testmempoolaccept([tx.serialize().hex()])[0]

    def assert_charge(self, tx, charge, what):
        """Accepted by exactly the nodes whose limit is at least charge, rejected for no other reason."""
        for node, limit in zip(self.nodes, LIMITS):
            res = self.accept(node, tx)
            if charge <= limit:
                assert res['allowed'], f"{what}: charge {charge} should fit limit {limit}: {res}"
            else:
                assert not res['allowed'] and res['reject-reason'] == REJECT, \
                    f"{what}: charge {charge} should exceed limit {limit}: {res}"
        self.log.info(f"  ok  {what}: charged {charge}")

    def assert_accepted_without_fullcount(self, tx, what):
        res = self.accept(self.nodes[5], tx)
        assert res['allowed'], f"{what}: the node without -datacarrierfullcount should not count it: {res}"
        self.log.info(f"  ok  {what}: accepted without -datacarrierfullcount")

    # ---- the attack family ----

    def decoy_script_stack(self, n, m, guard, checks=None):
        """m-of-n multisig behind a dead-code signature-check decoy that credits every key.

        Keys 0..m-1 are real and sign. The decoy checks sit in code that never runs, and the witness
        carries as many signature-shaped random items as the decoy asks for, which is what makes the
        script look as though it could prove its keys. checks defaults to n - 1, the posted proof of
        concept. Fewer is enough to look proven for a larger n and keeps the witness under its limit.

        Returns the witnessScript and a function giving the witness stack without the script push, so the
        same decoy can be spent as native P2WSH or wrapped in P2SH-P2WSH.
        """
        real = [self.newkey() for _ in range(m)]
        keys = [self.pub(k) for k in real] + [self.fake_key() for _ in range(n - m)]
        checks = n - 1 if checks is None else checks
        head = {'one': [OP_1, OP_NOTIF], 'depth': [OP_DEPTH, OP_0NOTEQUAL, OP_NOTIF], 'if': [OP_IF]}[guard]
        script = CScript(head + [OP_CHECKSIG] * checks + [OP_ENDIF] + [OP_2DROP] * (checks // 2) + [OP_DROP] * (checks % 2)
                         + [m] + keys + [n, OP_CHECKMULTISIG])

        def stack(tx, i):
            sigs = [self.p2wsh_sig(k, script, tx, i) for k in real]
            cond = [b''] if guard == 'if' else []
            return [b''] + sigs + [randbytes(72) for _ in range(checks)] + cond

        return script, stack

    def decoy_spec(self, n, m, guard, checks=None):
        return self.p2wsh_spec(*self.decoy_script_stack(n, m, guard, checks))

    def decoy_p2sh_p2wsh(self, what):
        """The posted decoy wrapped in P2SH-P2WSH. Its counted script is the witnessScript, taken from
        the witness, so the recount still applies: a change that recounted only native segwit would let
        this back in on the static count, which credits all fifteen keys and charges nothing."""
        script, stack = self.decoy_script_stack(15, 1, 'depth')
        tx = self.spend_many([self.p2sh_p2wsh_spec(script, stack)])
        self.assert_charge(tx, charge_for(14), what)
        return tx

    def tapscript_fake_xonly(self, what):
        """Fourteen fake x-only keys beside one real one in a 1-of-15 tapscript multi_a leaf.

        The leaf is taken from the witness, so the recount applies to it. The witness carries one real
        Schnorr signature, which caps the static count's credit at one key, so this shape is charged and
        refused by the static count as well; the row confirms a witness tapscript leaf is still counted.
        """
        priv = generate_privkey()
        internal = compute_xonly_pubkey(generate_privkey())[0]
        xs = [compute_xonly_pubkey(priv)[0]] + [randbytes(32) for _ in range(14)]
        ops = [xs[0], OP_CHECKSIG]
        for x in xs[1:]:
            ops += [x, OP_CHECKSIGADD]
        leaf = CScript(ops + [1, OP_NUMEQUAL])
        tap = taproot_construct(internal, [("leaf", leaf)])
        info = tap.leaves["leaf"]
        control = bytes([info.version | tap.negflag]) + tap.internal_pubkey + info.merklebranch

        def stack(tx, i):
            utxo = [CTxOut(FUNDING, tap.scriptPubKey)]
            h = TaprootSignatureHash(tx, utxo, 0, i, scriptpath=True, leaf_script=leaf)
            return [sign_schnorr(priv, h) if j == 0 else b'' for j in reversed(range(15))] + [bytes(leaf), control]

        tx = self.spend_many([{'spk': tap.scriptPubKey, 'stack': stack}])
        self.assert_charge(tx, charge_for(14), what)
        return tx

    def guarded(self, n, m, guard, what, charge=None, checks=None):
        tx = self.spend_many([self.decoy_spec(n, m, guard, checks)])
        self.assert_charge(tx, charge_for(n - m) if charge is None else charge, what)
        return tx

    def live_fake_checks(self, n_fake, what):
        """V1: <fakepk> OP_CHECKSIG OP_DROP with empty signatures, which do run.

        Four junk signature-shaped items are enough for the real signature and the junk to make five,
        which is all the static count needs to credit fifteen keys.
        """
        real = self.newkey()
        junk = 4
        ops = []
        for _ in range(n_fake):
            ops += [self.fake_key(), OP_CHECKSIG, OP_DROP]
        script = CScript(ops + [OP_2DROP] * (junk // 2) + [self.pub(real), OP_CHECKSIG])

        def stack(tx, i):
            return [self.p2wsh_sig(real, script, tx, i)] + [randbytes(72) for _ in range(junk)] + [b'' for _ in range(n_fake)]

        tx = self.spend_p2wsh(script, stack)
        self.assert_charge(tx, charge_for(n_fake), what)
        return tx

    def jasonsopko_shape(self, what):
        """Live shape from the #422 review: junk dropped up front, then 14 live OP_CHECKSIG OP_DROP pairs
        whose keys and empty signatures both come from the witness, then a 1-of-15 with one real signature.

        The script holds no key to credit besides the 15 in the multisig, so the static count finds 14
        signature checks and enough signature-shaped witness items, and charges nothing.
        """
        real = self.newkey()
        keys = [self.pub(real)] + [self.fake_key() for _ in range(14)]
        junk = 4
        script = CScript([OP_2DROP] * (junk // 2) + [OP_CHECKSIG, OP_DROP] * 14 + [1] + keys + [15, OP_CHECKMULTISIG])

        def stack(tx, i):
            pairs = []
            for _ in range(14):
                pairs += [b'', self.fake_key()]  # the empty signature, then the key CHECKSIG takes
            return [b'', self.p2wsh_sig(real, script, tx, i)] + pairs + [randbytes(72) for _ in range(junk)]

        tx = self.spend_p2wsh(script, stack)
        self.assert_charge(tx, charge_for(14), what)
        self.log.info("  the 14 fake keys the witness feeds to CHECKSIG, and their empty signatures, are not charged")
        return tx

    def wide_fakes(self, n_fakes, what):
        """1-of-(n_fakes + 1) behind no decoy at all: n_fakes random 65 byte pushes, and the real key last.

        In a witness multisig script a 65 byte push is never a key (segwit policy refuses an uncompressed
        key wherever it checks one), so the odd-push rule counts every fake as data in full, outside the
        allowance: n_fakes * 65 bytes. The 33 byte real key verifies and is free.
        """
        real = self.newkey()
        script = CScript([1] + [self.fake_key(65) for _ in range(n_fakes)] + [self.pub(real), n_fakes + 1, OP_CHECKMULTISIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [b'', self.p2wsh_sig(real, script, tx, i)])
        self.assert_charge(tx, n_fakes * 65, what)
        return tx

    # ---- honest spends, which must stay free ----

    def honest_multisig_spec(self, m, n, signers=None):
        keys = [self.newkey() for _ in range(n)]
        script = CScript([m] + [self.pub(k) for k in keys] + [n, OP_CHECKMULTISIG])
        signers = list(range(m)) if signers is None else signers
        return self.p2wsh_spec(script, lambda tx, i: [b''] + [self.p2wsh_sig(keys[j], script, tx, i) for j in signers])

    def honest_multisig(self, m, n, what):
        tx = self.spend_many([self.honest_multisig_spec(m, n)])
        self.assert_charge(tx, charge_for(n - m), what)
        return tx

    def honest_multisig_unified(self, n, what):
        """n-of-n P2WSH, every key signing under the unified signature hash (SIGHASH_ALL | SIGHASH_UNIFIED).

        With more than ten keys the recount charges whatever was not recorded, so this is accepted at
        charge 0 only if a signature that verifies under the unified rules records its key. The same
        spend with one hash type byte turned back to plain SIGHASH_ALL does not verify, which shows the
        signatures are unified ones and not legacy ones that would verify either way.
        """
        hash_type = SIGHASH_ALL | SIGHASH_UNIFIED
        keys = [self.newkey() for _ in range(n)]
        script = CScript([n] + [self.pub(k) for k in keys] + [n, OP_CHECKMULTISIG])
        spk = script_to_p2wsh_script(script)

        def stack(tx, i):
            h = UnifiedSignatureHash(script, tx, i, hash_type, [CTxOut(FUNDING, spk)], True)
            return [b''] + [k.sign_ecdsa(h) + bytes([hash_type]) for k in keys]

        tx = self.spend_many([self.p2wsh_spec(script, stack)])
        assert all(item[-1] == hash_type for item in tx.wit.vtxinwit[0].scriptWitness.stack[1:-1])
        self.assert_charge(tx, 0, what)
        self.assert_accepted_without_fullcount(tx, what)

        legacy_byte = CTransaction(tx)
        legacy_byte.wit.vtxinwit[0].scriptWitness.stack[1] = tx.wit.vtxinwit[0].scriptWitness.stack[1][:-1] + bytes([SIGHASH_ALL])
        res = self.accept(self.nodes[0], legacy_byte)
        assert not res['allowed'] and 'script-verify-flag' in res['reject-reason'], res
        self.log.info(f"  ok  {what}: one hash type byte set back to SIGHASH_ALL no longer verifies")
        return tx

    def p2wpkh(self):
        k = self.newkey()
        script_code = keyhash_to_p2pkh_script(hash160(self.pub(k)))
        tx = self.spend_many([{'spk': key_to_p2wpkh_script(self.pub(k)), 'stack': lambda tx, i: [
            k.sign_ecdsa(SegwitV0SignatureHash(script_code, tx, i, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL]), self.pub(k)]}])
        self.assert_charge(tx, 0, "P2WPKH")

    def tapscript_multi_a(self, k, n, what, internal):
        """k-of-n tapscript, signed by the first k keys, the others left empty."""
        privs = [generate_privkey() for _ in range(n)]
        xs = [compute_xonly_pubkey(p)[0] for p in privs]
        ops = [xs[0], OP_CHECKSIG]
        for x in xs[1:]:
            ops += [x, OP_CHECKSIGADD]
        leaf = CScript(ops + [k, OP_NUMEQUAL])
        tap = taproot_construct(internal, [("leaf", leaf)])
        info = tap.leaves["leaf"]
        control = bytes([info.version | tap.negflag]) + tap.internal_pubkey + info.merklebranch

        def stack(tx, i):
            utxo = [CTxOut(FUNDING, tap.scriptPubKey)]
            h = TaprootSignatureHash(tx, utxo, 0, i, scriptpath=True, leaf_script=leaf)
            # The first CHECKSIG takes the top of the stack, so the signatures go in reverse key order.
            return [sign_schnorr(privs[j], h) if j < k else b'' for j in reversed(range(n))] + [bytes(leaf), control]

        tx = self.spend_many([{'spk': tap.scriptPubKey, 'stack': stack}])
        self.assert_charge(tx, 0, what)

    def taproot(self):
        priv = generate_privkey()
        internal = compute_xonly_pubkey(priv)[0]
        tap = taproot_construct(internal)
        tweaked = tweak_add_privkey(priv, tap.tweak)

        def keypath(tx, i):
            utxo = [CTxOut(FUNDING, tap.scriptPubKey)]
            return [sign_schnorr(tweaked, TaprootSignatureHash(tx, utxo, 0, i))]
        tx = self.spend_many([{'spk': tap.scriptPubKey, 'stack': keypath}])
        self.assert_charge(tx, 0, "taproot key path")

        self.tapscript_multi_a(2, 3, "tapscript multi_a 2-of-3", internal)
        # More than ten keys, all of which sign or are signed for: a recorder that missed Schnorr
        # verifications would charge these.
        self.tapscript_multi_a(13, 13, "tapscript multi_a 13-of-13", internal)
        self.tapscript_multi_a(14, 14, "tapscript multi_a 14-of-14", internal)
        self.tapscript_multi_a(12, 14, "tapscript multi_a 12-of-14", internal)

    def lightning(self):
        # to_local, and the second-level HTLC output, which has the same shape: revocation or delayed
        rev, delayed = self.newkey(), self.newkey()
        to_local = CScript([OP_IF, self.pub(rev), OP_ELSE, 1, OP_CHECKSEQUENCEVERIFY, OP_DROP, self.pub(delayed), OP_ENDIF, OP_CHECKSIG])
        for name in ("to_local", "second-level HTLC output"):
            tx = self.spend_p2wsh(to_local, lambda tx, i: [self.p2wsh_sig(rev, to_local, tx, i), b'\x01'])
            self.assert_charge(tx, 0, f"{name} revocation")
            tx = self.spend_p2wsh(to_local, lambda tx, i: [self.p2wsh_sig(delayed, to_local, tx, i), b''], sequence=1)
            self.assert_charge(tx, 0, f"{name} delayed")

        # offered HTLC (BOLT 3): revocation, preimage and timeout paths
        rev, remote, local = self.newkey(), self.newkey(), self.newkey()
        preimage = randbytes(32)
        htlc = CScript([OP_DUP, OP_HASH160, hash160(self.pub(rev)), OP_EQUAL, OP_IF, OP_CHECKSIG, OP_ELSE,
                        self.pub(remote), OP_SWAP, OP_SIZE, 32, OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, self.pub(local), 2,
                        OP_CHECKMULTISIG, OP_ELSE, OP_HASH160, hash160(preimage), OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF, OP_ENDIF])
        tx = self.spend_p2wsh(htlc, lambda tx, i: [self.p2wsh_sig(rev, htlc, tx, i), self.pub(rev)])
        self.assert_charge(tx, 0, "offered HTLC revocation")
        tx = self.spend_p2wsh(htlc, lambda tx, i: [self.p2wsh_sig(remote, htlc, tx, i), preimage])
        self.assert_charge(tx, 0, "offered HTLC preimage")
        tx = self.spend_p2wsh(htlc, lambda tx, i: [b'', self.p2wsh_sig(remote, htlc, tx, i), self.p2wsh_sig(local, htlc, tx, i), b''])
        self.assert_charge(tx, 0, "offered HTLC timeout (second-level HTLC-timeout spend)")

        # received HTLC (BOLT 3): revocation, success with the preimage, and the remote's timeout
        rev, remote, local = self.newkey(), self.newkey(), self.newkey()
        preimage = randbytes(32)
        cltv = 1
        received = CScript([OP_DUP, OP_HASH160, hash160(self.pub(rev)), OP_EQUAL, OP_IF, OP_CHECKSIG, OP_ELSE,
                            self.pub(remote), OP_SWAP, OP_SIZE, 32, OP_EQUAL, OP_IF, OP_HASH160, hash160(preimage), OP_EQUALVERIFY,
                            2, OP_SWAP, self.pub(local), 2, OP_CHECKMULTISIG, OP_ELSE, OP_DROP, cltv, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                            OP_CHECKSIG, OP_ENDIF, OP_ENDIF])
        tx = self.spend_p2wsh(received, lambda tx, i: [self.p2wsh_sig(rev, received, tx, i), self.pub(rev)])
        self.assert_charge(tx, 0, "received HTLC revocation")
        tx = self.spend_p2wsh(received, lambda tx, i: [b'', self.p2wsh_sig(remote, received, tx, i), self.p2wsh_sig(local, received, tx, i), preimage])
        self.assert_charge(tx, 0, "received HTLC success (second-level HTLC-success spend)")
        tx = self.spend_p2wsh(received, lambda tx, i: [self.p2wsh_sig(remote, received, tx, i), b''], sequence=0xfffffffe, locktime=cltv)
        self.assert_charge(tx, 0, "received HTLC timeout")

        # anchor: the funding key, or anyone after a delay
        funding = self.newkey()
        anchor = CScript([self.pub(funding), OP_CHECKSIG, OP_IFDUP, OP_NOTIF, 1, OP_CHECKSEQUENCEVERIFY, OP_ENDIF])
        tx = self.spend_p2wsh(anchor, lambda tx, i: [self.p2wsh_sig(funding, anchor, tx, i)])
        self.assert_charge(tx, 0, "anchor by key")
        tx = self.spend_p2wsh(anchor, lambda tx, i: [b''], sequence=1)
        self.assert_charge(tx, 0, "anchor by anyone")

    def recovery(self):
        """11-of-15 with a timelocked 2-of-3 recovery path, spent by recovery. Reports, does not judge."""
        main = [self.newkey() for _ in range(15)]
        rec = [self.newkey() for _ in range(3)]
        script = CScript([OP_IF, 11] + [self.pub(k) for k in main] + [15, OP_CHECKMULTISIG, OP_ELSE, 1, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                                                                        2] + [self.pub(k) for k in rec] + [3, OP_CHECKMULTISIG, OP_ENDIF])
        tx = self.spend_p2wsh(script, lambda tx, i: [b'', self.p2wsh_sig(rec[0], script, tx, i), self.p2wsh_sig(rec[1], script, tx, i), b''], sequence=1)
        # 18 keys, 2 verified: 16 unproven keys, 6 beyond the allowance, the same charge the base count
        # gives this P2WSH recovery-branch spend
        self.assert_charge(tx, charge_for(16), "11-of-15 / recovery 2-of-3, spent via recovery")

    # ---- legacy P2SH, where an honest spend leaves real keys unsigned ----

    def multisig_p2sh_spec(self, m, keys):
        script = CScript([m] + [self.pub(k) for k in keys] + [len(keys), OP_CHECKMULTISIG])
        return self.p2sh_spec(script, lambda tx, i: [b''] + [self.p2sh_sig(k, script, tx, i) for k in keys[:m]])

    def two_branch_p2sh_spec(self, m, n, branch):
        """IF <m-of-n> ELSE 1 CSV DROP <m-of-n> ENDIF, spent through one branch by its first m keys."""
        now, later = [self.newkey() for _ in range(n)], [self.newkey() for _ in range(n)]
        script = CScript([OP_IF, m] + [self.pub(k) for k in now] + [n, OP_CHECKMULTISIG, OP_ELSE, 1, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                                                                    m] + [self.pub(k) for k in later] + [n, OP_CHECKMULTISIG, OP_ENDIF])
        signers, selector, sequence = (now, 1, 0xffffffff) if branch == 'IF' else (later, 0, 1)
        return self.p2sh_spec(script, lambda tx, i: [b''] + [self.p2sh_sig(k, script, tx, i) for k in signers[:m]] + [selector], sequence)

    def legacy_p2sh(self):
        """Honest legacy P2SH multisig that leaves real keys unsigned keeps the static #422 count.

        The recount applies only to an input whose counted script comes from the witness. A legacy P2SH
        spend carries its redeem script and signatures in the scriptSig, not the witness, so it is not
        recounted and keeps the static count unchanged: every threshold the redeem script names is
        credited, in every branch, and an uncompressed key counts as a compressed one. These spends are
        charged exactly what the base #422 count charges, so the verified-key change is no regression for
        legacy P2SH. Each row below asserts that base charge.

        The legacy P2SH rows follow jasonsopko's honest_1of7.py.
        """
        uncompressed = lambda: [self.newkey(compressed=False) for _ in range(7)]
        # 1-of-7 of seven real uncompressed keys (465 byte redeem script), one signing. The static count
        # credits the single threshold and counts each key as compressed, charging nothing; a non-witness
        # input is not recounted, so the six unsigned keys cost nothing either.
        what = "legacy P2SH 1-of-7, uncompressed keys"
        self.assert_charge(self.spend_many([self.multisig_p2sh_spec(1, uncompressed())]), 0, f"{what}, one input")
        tx = self.spend_many([self.multisig_p2sh_spec(1, uncompressed()) for _ in range(2)])
        self.assert_charge(tx, 0, f"{what}, two inputs")
        self.assert_accepted_without_fullcount(tx, f"{what}, two inputs")
        # The same with compressed keys (241 bytes), also free under the static count.
        compressed = lambda: [self.newkey() for _ in range(7)]
        what = "legacy P2SH 1-of-7, compressed keys"
        self.assert_charge(self.spend_many([self.multisig_p2sh_spec(1, compressed())]), 0, f"{what}, one input")
        self.assert_charge(self.spend_many([self.multisig_p2sh_spec(1, compressed()) for _ in range(2)]), 0, f"{what}, two inputs")

        # Two branches of seven compressed keys (488 bytes), spent through one branch. The static count
        # credits both thresholds, which is 66 for 1-of-7 and 0 for 2-of-7, the same the base charges.
        # The branch not taken never signs, but a non-witness input is not recounted, so there is no
        # extra charge for its unsigned keys and nothing above the base.
        for branch in ('IF', 'ELSE'):
            self.assert_charge(self.spend_many([self.two_branch_p2sh_spec(1, 7, branch)]), 66,
                               f"legacy P2SH IF 1-of-7 ELSE CSV 1-of-7, {branch} branch")
        for branch in ('IF', 'ELSE'):
            self.assert_charge(self.spend_many([self.two_branch_p2sh_spec(2, 7, branch)]), 0,
                               f"legacy P2SH IF 2-of-7 ELSE CSV 2-of-7, {branch} branch")
        self.assert_charge(self.spend_many([self.two_branch_p2sh_spec(2, 7, branch) for branch in ('IF', 'ELSE')]), 0,
                           "legacy P2SH IF 2-of-7 ELSE CSV 2-of-7, two inputs")
        # 2-of-3 either way (216 bytes), a small vault, also free.
        for branch in ('IF', 'ELSE'):
            self.assert_charge(self.spend_many([self.two_branch_p2sh_spec(2, 3, branch)]), 0,
                               f"legacy P2SH IF 2-of-3 ELSE CSV 2-of-3, {branch} branch")
        self.assert_charge(self.spend_many([self.two_branch_p2sh_spec(2, 3, branch) for branch in ('IF', 'ELSE')]), 0,
                           "legacy P2SH IF 2-of-3 ELSE CSV 2-of-3, two inputs")

    def same_key(self):
        k = self.newkey()
        pk = self.pub(k)
        # one key named fourteen times in a decoy, verified once: the bytes are identical, so no data
        script = CScript([OP_DEPTH, OP_0NOTEQUAL, OP_NOTIF] + [pk, OP_CHECKSIG] * 14 + [OP_ENDIF] + [OP_2DROP] * 7 + [pk, OP_CHECKSIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [self.p2wsh_sig(k, script, tx, i)] + [randbytes(72) for _ in range(14)])
        self.assert_charge(tx, 0, "same key repeated in a decoy (credited, carries nothing)")
        # the same key and the same signature checked again and again
        script = CScript([pk, OP_CHECKSIGVERIFY] * 13 + [pk, OP_CHECKSIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [self.p2wsh_sig(k, script, tx, i)] * 14)
        self.assert_charge(tx, 0, "same key, same signature, checked 14 times")

    def one_key_checked_repeatedly(self):
        """One key verified 15 times beside 14 fakes: the recount credits keys, not successful checks.

        The real key is checked by 14 OP_CHECKSIGVERIFY and again by a 1-of-15 whose other keys are
        random, so 15 signature checks succeed but only one distinct key is verified. The 14 fakes stay
        unproven and are charged as such.
        """
        k = self.newkey()
        pk = self.pub(k)
        fakes = [self.fake_key() for _ in range(14)]
        what = "one key verified 15 times beside 14 fakes, key named by every check"
        script = CScript([OP_DUP, pk, OP_CHECKSIGVERIFY] * 14 + [1, pk] + fakes + [15, OP_CHECKMULTISIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [b'', self.p2wsh_sig(k, script, tx, i)])
        # The script is valid at standard flags, so only the count can refuse it. The static count
        # already charges this shape, as the witness carries one signature for 29 keys.
        self.assert_accepted_without_fullcount(tx, what)
        self.assert_charge(tx, charge_for(14), what)

        # The 14 checks now take the key from the witness, so the static count sees 15 checks for 15 keys
        # and enough signature-shaped items, and charges nothing. Only the recount can charge it, and
        # only if it credits the one key that verified rather than the 15 checks that succeeded.
        junk = 4
        what = "one key verified 15 times beside 14 fakes, key fed to the checks by the witness"
        script = CScript([OP_2DROP] * (junk // 2) + [OP_2DUP, OP_CHECKSIGVERIFY] * 14 + [OP_DROP, 1, pk] + fakes + [15, OP_CHECKMULTISIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [b'', self.p2wsh_sig(k, script, tx, i), pk] + [randbytes(72) for _ in range(junk)])
        self.assert_accepted_without_fullcount(tx, what)
        self.assert_charge(tx, charge_for(14), what)

    def dup_signature(self):
        k = self.newkey()
        ops = []
        for _ in range(14):
            ops += [OP_DUP, self.fake_key(), OP_CHECKSIG, OP_DROP]
        script = CScript(ops + [self.pub(k), OP_CHECKSIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [self.p2wsh_sig(k, script, tx, i)])
        for node in self.nodes:
            assert not self.accept(node, tx)['allowed']
        # Counting is off on node 5 (no -datacarrierfullcount), so the script itself is what refuses it
        # there. The others stop it earlier, on the static count.
        res = self.accept(self.nodes[5], tx)
        assert 'script-verify-flag' in res['reject-reason'], res
        self.log.info("  ok  one signature DUPed against 14 keys: rejected everywhere, by NULLFAIL where counting is off")

    def multi_input(self):
        """The recount is per input: a decoy in either input is charged, and the charges add up."""
        honest = lambda: self.honest_multisig_spec(2, 3)
        decoy = lambda: self.decoy_spec(15, 1, 'depth')
        self.assert_charge(self.spend_many([honest(), decoy()]), charge_for(14), "honest input 0, decoy input 1")
        self.assert_charge(self.spend_many([decoy(), honest()]), charge_for(14), "decoy input 0, honest input 1")
        self.assert_charge(self.spend_many([decoy(), decoy()]), 2 * charge_for(14), "decoy in both inputs")
        # The allowance of ten is per input, so three inputs of 1-of-11 are all free (pre-existing semantics).
        self.assert_charge(self.spend_many([self.decoy_spec(11, 1, 'depth') for _ in range(3)]), 0, "three inputs of 10 unproven keys each")

    def replace_by_fee(self):
        node = self.nodes[0]
        # An anyone-can-spend output that signals replaceability, confirmed before anything is sent.
        existing = {'outpoint': self.fund(script_to_p2wsh_script(CScript([OP_TRUE]))), 'stack': lambda tx, i: [bytes([OP_TRUE])],
                    'sequence': 0xfffffffd}
        self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        # Everything is funded and mined first, so that nothing in the mempool is confirmed under us.
        original = self.spend_many([existing], fee=2_000)
        decoy_replacement = self.spend_many([existing, self.decoy_spec(15, 1, 'depth')], fee=100_000)
        honest_replacement = self.spend_many([existing, self.honest_multisig_spec(2, 3)], fee=100_000)
        node.sendrawtransaction(original.serialize().hex())
        assert original.rehash() in node.getrawmempool()
        # The decoy pays for the replacement but is refused by the recount, and the original stays.
        assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, decoy_replacement.serialize().hex())
        assert original.rehash() in node.getrawmempool()
        assert decoy_replacement.rehash() not in node.getrawmempool()
        # The same setup with an honest second input replaces it, so the refusal was the decoy's doing.
        node.sendrawtransaction(honest_replacement.serialize().hex())
        assert original.rehash() not in node.getrawmempool()
        assert honest_replacement.rehash() in node.getrawmempool()
        self.log.info("  ok  a decoy replacement is refused by the recount and the original stays; an honest one replaces it")
        self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        assert node.getrawmempool() == []

    def operator_bypass_then_resubmit(self):
        """An operator's bypass must not leave the decoy a way back in through the script execution cache.

        Accepting a tx stores its script checks in the script execution cache under the block flags, and
        ignore_rejects=["non-mandatory-script-verify-flag"] lowers the policy flags to exactly those while
        RDTS is in force (the policy flags always keep the reduced-data flags, and the block flags carry
        them only then, which is why this chain has RDTS active). Were
        the policy check to consult that cache, a resubmission after the tx left the mempool would run
        nothing, record no keys, and fall back to the static count, which is 0. It does not, so the
        recount applies.
        """
        node = self.nodes[0]
        decoy = self.spend_many([self.decoy_spec(15, 1, 'depth')])
        decoy_hex = decoy.serialize().hex()
        # Node 0 alone, so that nothing relays the decoy and the clock jump below touches no peer.
        self.disconnect_nodes(1, 0)
        assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, decoy_hex)
        node.sendrawtransaction(decoy_hex, ignore_rejects=[REJECT])
        assert decoy.rehash() in node.getrawmempool()
        # Past -mempoolexpiry (14 days), the next accept expires the decoy.
        node.setmocktime(int(time.time()) + 15 * 24 * 3600)
        self.wallet.send_self_transfer(from_node=node)
        assert decoy.rehash() not in node.getrawmempool()
        assert_raises_rpc_error(-26, REJECT, node.sendrawtransaction, decoy_hex, ignore_rejects=["non-mandatory-script-verify-flag"])
        assert decoy.rehash() not in node.getrawmempool()
        self.log.info("  ok  bypassed, expired, then resubmitted ignoring non-mandatory script flags: still refused by the recount")
        node.setmocktime(0)
        self.connect_nodes(1, 0)
        self.generate(self.wallet, 1, sync_fun=self.sync_blocks)
        assert node.getrawmempool() == []

    def mined_decoy_and_reorg(self, poc):
        node = self.nodes[0]
        honest = self.spend_many([self.honest_multisig_spec(2, 3)])
        res = self.generateblock(node, output="raw(51)", transactions=[poc.serialize().hex(), honest.serialize().hex()], sync_fun=self.sync_blocks)
        block = node.getblock(res['hash'])
        assert poc.rehash() in block['tx']
        assert honest.rehash() in block['tx']
        assert self.nodes[5].getbestblockhash() == res["hash"]
        self.log.info("  ok  the block carrying the decoy is valid: consensus is untouched")

        node.invalidateblock(res['hash'])
        pool = node.getrawmempool()
        # The re-add runs the policy script check, which runs the scripts and records the keys whatever the
        # script execution cache holds, so the recount applies and the decoy is dropped. The static count,
        # which is 0, would let it in.
        assert honest.rehash() in pool
        assert poc.rehash() not in pool
        self.log.info("  ok  after invalidateblock the honest tx is back in the mempool and the decoy is not")
        node.reconsiderblock(res['hash'])
        self.sync_blocks()
        assert node.getbestblockhash() == res['hash']

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, WARMUP_BLOCKS)
        for node in self.nodes:
            info = node.getdeploymentinfo()
            fork = info.get("blake2b") or info["deployments"]["blake2b"]
            assert fork["active"] and fork["height"] == FORK_HEIGHT, fork

        self.log.info("The posted proof of concept and its variants are charged for the unproven keys")
        poc = self.guarded(15, 1, 'depth', "PoC decoy (OP_DEPTH dead branch)")
        for node in (self.nodes[0], self.nodes[5]):
            t0 = time.perf_counter()
            for _ in range(50):
                self.accept(node, poc)
            self.log.info(f"  PoC testmempoolaccept on node {node.index}: {(time.perf_counter() - t0) / 50 * 1000:.2f} ms per call")
        b1 = self.guarded(15, 1, 'depth', "B1 OP_DEPTH OP_0NOTEQUAL OP_NOTIF decoy")
        b2 = self.guarded(15, 1, 'if', "B2 witness-chosen OP_IF, empty condition")
        v1 = self.live_fake_checks(14, "V1 live fake checks, empty signatures")
        jason = self.jasonsopko_shape("jasonsopko live shape, keys and empty signatures from the witness")
        self.dup_signature()
        self.log.info("The witness bypass is still charged when the witnessScript is wrapped in P2SH, and in a tapscript leaf")
        self.decoy_p2sh_p2wsh("PoC decoy wrapped in P2SH-P2WSH")
        self.tapscript_fake_xonly("14 fake x-only keys in a tapscript leaf")

        self.log.info("Without -datacarrierfullcount nothing is counted, so the recount never runs")
        for tx, name in [(poc, "PoC"), (b1, "B1"), (b2, "B2"), (v1, "V1"), (jason, "jasonsopko shape")]:
            self.assert_accepted_without_fullcount(tx, name)

        self.log.info("Allowance edge, with and without real signatures mixed in")
        self.guarded(11, 1, 'depth', "10 unproven keys", charge=0)
        self.guarded(12, 1, 'depth', "11 unproven keys", charge=UNIT)
        self.guarded(13, 3, 'depth', "10 unproven keys beside 3 real", charge=0)
        self.guarded(14, 3, "depth", "11 unproven keys beside 3 real", charge=UNIT, checks=1)

        self.log.info("65 byte pushes in a witness multisig are odd pushes, charged in full outside the allowance")
        self.wide_fakes(5, "5 fake 65 byte pushes (325 bytes, charged in full)")
        self.wide_fakes(6, "6 fake 65 byte pushes (390 bytes, charged in full)")
        self.wide_fakes(10, "10 fake 65 byte pushes (650 bytes, charged in full)")
        self.wide_fakes(12, "12 fake 65 byte pushes (780 bytes, charged in full)")

        self.log.info("Key count boundaries")
        script = CScript([0, 0, OP_CHECKMULTISIG])
        tx = self.spend_p2wsh(script, lambda tx, i: [b''])
        self.assert_charge(tx, 0, "0-of-0 multisig")
        self.guarded(1, 1, 'depth', "1 key", charge=0)
        for n in (16, 17, 20):
            # Ten fewer signature-shaped items than keys are enough to look proven, and keep the witness in 1650 bytes.
            self.guarded(n, 1, 'depth', f"{n} keys", checks=n - 11)

        self.log.info("Repeated keys")
        self.same_key()
        self.one_key_checked_repeatedly()

        self.log.info("Honest spends stay free, including with more than ten keys that all verify")
        self.honest_multisig(2, 3, "2-of-3")
        self.honest_multisig(3, 5, "3-of-5")
        self.honest_multisig(11, 15, "11-of-15 signed by 11")
        self.honest_multisig(12, 12, "12-of-12")
        self.honest_multisig(15, 15, "15-of-15")
        self.honest_multisig_unified(12, "12-of-12 signed under SIGHASH_UNIFIED")
        self.honest_multisig_unified(15, "15-of-15 signed under SIGHASH_UNIFIED")
        self.p2wpkh()
        self.taproot()
        self.lightning()

        self.log.info("Recovery path")
        self.recovery()

        self.log.info("Legacy P2SH spends that leave keys unsigned")
        self.legacy_p2sh()

        self.log.info("Several inputs")
        self.multi_input()

        self.log.info("Replace by fee")
        self.replace_by_fee()

        self.log.info("An operator's bypass leaves no way back in through the script execution cache")
        self.operator_bypass_then_resubmit()

        self.log.info("A block carrying the PoC is valid, and a reorg re-adds its transactions through the policy checks")
        self.mined_decoy_and_reorg(b1)


if __name__ == '__main__':
    VerifiedKeyCreditTest(__file__).main()
