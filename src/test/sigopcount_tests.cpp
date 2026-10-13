// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <key.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <vector>

#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

    uint160 dummy;
    s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(s1), 0U);
    s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(s1), 0U);

    CScript p2sh = GetScriptForDestination(ScriptHash(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k = GenerateRandomKey();
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(s2), 1U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_CHECKMULTISIG), 0U);

    p2sh = GetScriptForDestination(ScriptHash(s2));
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
    CScript scriptSig2;
    scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
}

BOOST_AUTO_TEST_CASE(CountMultisigExcessKeysBoundary)
{
    std::vector<CPubKey> keys;
    for (int i{0}; i < MAX_PUBKEYS_PER_MULTISIG; ++i) {
        keys.push_back(GenerateRandomKey().GetPubKey());
    }

    const auto multisig = [&](const int required, const int total) {
        const std::vector<CPubKey> selected_keys{keys.begin(), keys.begin() + total};
        return GetScriptForMultisig(required, selected_keys);
    };

    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(1, 1)), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(2, 2)), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(2, 3)), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(3, 3)), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(1, 3)), 1U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(2, 5)), 2U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(1, 15)), 13U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multisig(1, 20)), 18U);

    // Dropping and re-pushing n preserves the spend, but must not erase its
    // public keys. Non-canonical forms conservatively lose their m credit.
    CScript dropped_count{multisig(1, 15)};
    dropped_count.pop_back(); // CHECKMULTISIG
    dropped_count << OP_DROP << OP_15 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(dropped_count), 14U);

    // The allowance applies once per script, not once per CHECKMULTISIG.
    CScript two_multisigs{multisig(2, 3)};
    two_multisigs.back() = OP_CHECKMULTISIGVERIFY;
    const CScript second_multisig{multisig(2, 3)};
    two_multisigs.insert(two_multisigs.end(), second_multisig.begin(), second_multisig.end());
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(two_multisigs), 1U);

    const CScript wide_multisig{multisig(11, 15)};
    CScriptWitness one_sig_witness;
    one_sig_witness.stack.emplace_back(); // CHECKMULTISIG dummy
    one_sig_witness.stack.emplace_back(72, 1); // signature-shaped item
    one_sig_witness.stack.emplace_back(wide_multisig.begin(), wide_multisig.end());
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(wide_multisig), 3U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(wide_multisig, &one_sig_witness), 13U);

    CScript multi_a{CScript() << std::vector<unsigned char>(32, 1) << OP_CHECKSIG};
    multi_a << std::vector<unsigned char>(32, 2) << OP_CHECKSIGADD;
    multi_a << std::vector<unsigned char>(32, 3) << OP_CHECKSIGADD << OP_1 << OP_NUMEQUAL;
    CScriptWitness tapscript_witness;
    tapscript_witness.stack.emplace_back();
    tapscript_witness.stack.emplace_back();
    tapscript_witness.stack.emplace_back(64, 1);
    tapscript_witness.stack.emplace_back(multi_a.begin(), multi_a.end());
    tapscript_witness.stack.emplace_back(65, 0xc0);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2), 1U);

    tapscript_witness.stack[2].clear();
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2), 2U);
    tapscript_witness.stack.emplace_back(65, ANNEX_TAG);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/3), 2U);

    // Invalid, incomplete, and non-canonical shapes are not assigned a punitive fallback.
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_3 << ToByteVector(keys[0]) << ToByteVector(keys[1]) << OP_2 << OP_CHECKMULTISIG), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_1 << ToByteVector(keys[0]) << OP_2 << OP_CHECKMULTISIG), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_1 << OP_CHECKMULTISIG), 0U);
}

/**
 * Verifies script execution of the zeroth scriptPubKey of tx output and
 * zeroth scriptSig and witness of tx input.
 */
static ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, uint32_t flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
static void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& witness)
{
    creationTx.version = 1;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript();
    creationTx.vout.resize(1);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = scriptPubKey;

    spendingTx.version = 1;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = creationTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vin[0].scriptSig = scriptSig;
    spendingTx.vin[0].scriptWitness = witness;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 1;
    spendingTx.vout[0].scriptPubKey = CScript();

    AddCoins(coins, CTransaction(creationTx), 0);
}

BOOST_AUTO_TEST_CASE(GetTxSigOpCost)
{
    // Transaction creates outputs
    CMutableTransaction creationTx;
    // Transaction that spends outputs and whose
    // sig op cost is going to be tested
    CMutableTransaction spendingTx;

    // Create utxo set
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Create key
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};

    // Multisig script (legacy counting)
    {
        CScript scriptPubKey = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << ToByteVector(pubkey) << 3 << OP_CHECKMULTISIGVERIFY;
        // Do not use a valid signature to avoid using wallet operations.
        CScript scriptSig = CScript() << OP_0 << OP_0;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 1);
        // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
        // of a transaction and does not take the actual executed sig operations into account.
        // spendingTx in itself does not contain a signature operation.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        // creationTx contains three signature operations in its scriptPubKey, but legacy counting
        // is not accurate.
        assert(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags) == MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR);
        // Sanity check: script verification fails because of an invalid signature.
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << ToByteVector(pubkey) << 3 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 1);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 3 * WITNESS_SCALE_FACTOR);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // An incomplete multisig shape in a non-push-only legacy scriptSig is not
    // assigned a punitive excess-key fallback.
    {
        CScript scriptPubKey = CScript() << OP_TRUE;
        CScript scriptSig = CScript() << OP_FALSE << OP_IF << OP_3 << OP_CHECKMULTISIG << OP_ENDIF;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_OK);
    }

    // P2WPKH witness program
    {
        CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);


        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        // No signature operations if we don't verify the witness.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);

        // The sig op cost for witness version != 0 is zero.
        assert(scriptPubKey[0] == 0x00);
        scriptPubKey[0] = 0x51;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        scriptPubKey[0] = 0x00;
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);

        // The witness of a coinbase transaction is not taken into account.
        spendingTx.vin[0].prevout.SetNull();
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
    }

    // Tapscript multi_a is counted, while its script and control block are not
    // mistaken for signature-shaped witness items.
    {
        CScript multi_a{CScript() << std::vector<unsigned char>(32, 1) << OP_CHECKSIG};
        multi_a << std::vector<unsigned char>(32, 2) << OP_CHECKSIGADD;
        multi_a << std::vector<unsigned char>(32, 3) << OP_CHECKSIGADD << OP_1 << OP_NUMEQUAL;
        CScript scriptPubKey{CScript() << OP_1 << std::vector<unsigned char>(32, 4)};
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back();
        scriptWitness.stack.emplace_back();
        scriptWitness.stack.emplace_back(64, 1);
        scriptWitness.stack.emplace_back(multi_a.begin(), multi_a.end());
        scriptWitness.stack.emplace_back(65, 0xc0);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, CScript{}, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 1);

        scriptWitness.stack.emplace_back(65, ANNEX_TAG);
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, CScript{}, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 1);

        scriptWitness.stack[4][0] = 0xc2; // a future leaf version is not tapscript
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, CScript{}, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);

        scriptWitness.stack.assign(1, std::vector<unsigned char>(64, 1));
        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, CScript{}, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);
    }

    // P2WPKH nested in P2SH
    {
        CScript scriptSig = GetScriptForDestination(WitnessV0KeyHash(pubkey));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(scriptSig));
        scriptSig = CScript() << ToByteVector(scriptSig);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 0);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);
    }

    // P2WSH witness program
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << ToByteVector(pubkey) << 3 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptSig = CScript();
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        // No signature-shaped witness item is supplied, so none of the three
        // keys is proven and only the one-key allowance is free.
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 2);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 3);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // P2WSH nested in P2SH
    {
        CScript witnessScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << ToByteVector(pubkey) << 3 << OP_CHECKMULTISIGVERIFY;
        CScript redeemScript = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
        CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
        CScript scriptSig = CScript() << ToByteVector(redeemScript);
        CScriptWitness scriptWitness;
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(0);
        scriptWitness.stack.emplace_back(witnessScript.begin(), witnessScript.end());

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
        assert(CountTransactionInputMultisigExcessKeys(CTransaction(spendingTx), coins) == 2);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 3);
        assert(VerifyWithFlag(CTransaction(creationTx), spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }
}

BOOST_AUTO_TEST_SUITE_END()
