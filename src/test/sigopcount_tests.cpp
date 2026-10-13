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

#include <algorithm>
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
    // Strict DER fixtures test encoding recognition only, not cryptographic
    // validity. Both R and S are minimally encoded positive integers.
    const auto der_signature = [](const size_t r_size, const size_t s_size) {
        std::vector<unsigned char> sig(r_size + s_size + 7, 1);
        sig[0] = 0x30;
        sig[1] = static_cast<unsigned char>(r_size + s_size + 4);
        sig[2] = 0x02;
        sig[3] = static_cast<unsigned char>(r_size);
        if (r_size == 33) {
            sig[4] = 0;
            sig[5] = 0x80;
        }
        sig[4 + r_size] = 0x02;
        sig[5 + r_size] = static_cast<unsigned char>(s_size);
        if (s_size == 33) {
            sig[6 + r_size] = 0;
            sig[7 + r_size] = 0x80;
        }
        return sig;
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

    // Signature-shaped witness padding and bare CHECKSIGs in an unreachable
    // ELSE arm cannot cancel the keys of the actual 1-of-15 spend.
    CScript padded_branch;
    for (int i{0}; i < 13; ++i) padded_branch << OP_DROP;
    const CScript one_of_fifteen{multisig(1, 15)};
    padded_branch.insert(padded_branch.end(), one_of_fifteen.begin(), one_of_fifteen.end());
    padded_branch << OP_IF << OP_TRUE << OP_ELSE;
    for (int i{0}; i < 13; ++i) padded_branch << OP_CHECKSIG;
    padded_branch << OP_ENDIF;
    CScriptWitness padded_witness;
    padded_witness.stack.emplace_back();
    padded_witness.stack.push_back(der_signature(32, 32));
    for (int i{0}; i < 13; ++i) padded_witness.stack.push_back(der_signature(29, 29));
    padded_witness.stack.emplace_back(padded_branch.begin(), padded_branch.end());
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(padded_branch, &padded_witness), 13U);

    // A malformed dead branch cannot credit more keys than it contributes.
    CScript invalid_branch{one_of_fifteen};
    invalid_branch << OP_IF << OP_TRUE << OP_ELSE << OP_16;
    invalid_branch << ToByteVector(keys[0]) << ToByteVector(keys[1]) << OP_2 << OP_CHECKMULTISIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(invalid_branch), 13U);

    // The ELSE arm of OP_FALSE OP_IF is reachable and must still be counted.
    CScript false_if_else{CScript() << OP_FALSE << OP_IF << OP_TRUE << OP_ELSE};
    false_if_else.insert(false_if_else.end(), one_of_fifteen.begin(), one_of_fifteen.end());
    false_if_else << OP_ENDIF;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(false_if_else), 13U);

    // The allowance applies once per script, not once per CHECKMULTISIG.
    CScript two_multisigs{multisig(2, 3)};
    two_multisigs.back() = OP_CHECKMULTISIGVERIFY;
    const CScript second_multisig{multisig(2, 3)};
    two_multisigs.insert(two_multisigs.end(), second_multisig.begin(), second_multisig.end());
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(two_multisigs), 1U);

    const CScript wide_multisig{multisig(11, 15)};
    CScriptWitness one_sig_witness;
    one_sig_witness.stack.emplace_back(); // CHECKMULTISIG dummy
    one_sig_witness.stack.push_back(der_signature(32, 32));
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
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2, SigVersion::TAPSCRIPT), 1U);

    tapscript_witness.stack[2].push_back(SIGHASH_ALL);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2, SigVersion::TAPSCRIPT), 1U);
    tapscript_witness.stack[2].push_back(1); // 66 bytes is not a Schnorr encoding
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2, SigVersion::TAPSCRIPT), 2U);

    tapscript_witness.stack[2].clear();
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/2, SigVersion::TAPSCRIPT), 2U);
    tapscript_witness.stack.emplace_back(65, ANNEX_TAG);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(multi_a, &tapscript_witness, /*witness_suffix_items=*/3, SigVersion::TAPSCRIPT), 2U);

    const CScript two_of_three{multisig(2, 3)};
    for (size_t encoded_size{9}; encoded_size <= 73; ++encoded_size) {
        const size_t r_size{std::min(size_t{33}, encoded_size - 8)};
        const auto sig{der_signature(r_size, encoded_size - 7 - r_size)};
        BOOST_CHECK_EQUAL(sig.size(), encoded_size);
        BOOST_REQUIRE(IsValidSignatureEncoding(sig));
        CScriptWitness witness;
        witness.stack = {{}, sig, sig, std::vector<unsigned char>(two_of_three.begin(), two_of_three.end())};
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(two_of_three, &witness), 0U);
    }
    CScriptWitness bad_der;
    bad_der.stack = {{}, std::vector<unsigned char>(72, 1), std::vector<unsigned char>(72, 1),
                     std::vector<unsigned char>(two_of_three.begin(), two_of_three.end())};
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(two_of_three, &bad_der), 2U);

    // 65-byte DER satisfaction items are not public keys in push-only scriptSig.
    CTxIn legacy_input;
    legacy_input.scriptSig = CScript() << OP_0 << der_signature(29, 29) << der_signature(29, 29) << ToByteVector(two_of_three);
    BOOST_CHECK_EQUAL(CountInputMultisigExcessKeys(legacy_input, GetScriptForDestination(ScriptHash{two_of_three})), 0U);

    // Invalid, incomplete, and non-canonical shapes are not assigned a punitive fallback.
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_3 << ToByteVector(keys[0]) << ToByteVector(keys[1]) << OP_2 << OP_CHECKMULTISIG), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_1 << ToByteVector(keys[0]) << OP_2 << OP_CHECKMULTISIG), 0U);
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(CScript() << OP_1 << OP_CHECKMULTISIG), 0U);
}

BOOST_AUTO_TEST_CASE(ExecutedMultisigKeyOperands)
{
    const CKey key{GenerateRandomKey()};
    const auto pubkey{ToByteVector(key.GetPubKey())};
    const auto check = [&](const CScript& script, const CScript& satisfaction, uint64_t expected) {
        ScriptValidationMetrics metrics;
        ScriptError observed_error, plain_error;
        const bool plain{VerifyScript(satisfaction, script, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &plain_error)};
        const bool observed{VerifyScript(satisfaction, script, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &observed_error, &metrics)};
        BOOST_REQUIRE(plain);
        BOOST_REQUIRE(observed);
        BOOST_CHECK_EQUAL(plain_error, observed_error);
        BOOST_CHECK_EQUAL(CountExecutedMultisigExcessKeys(metrics), expected);
    };
    const CScript zero_of_three{CScript() << OP_0 << pubkey << pubkey << pubkey << OP_3 << OP_CHECKMULTISIG};
    check(zero_of_three, CScript() << OP_0, 2);

    // Equal-sized hashes/data are not signature operands, even before/after
    // multisig or after non-identity arithmetic and stack transformations.
    CScript mixed{CScript() << pubkey << OP_HASH160 << OP_DROP << pubkey << OP_SIZE << OP_NIP << OP_DROP};
    mixed.insert(mixed.end(), zero_of_three.begin(), zero_of_three.end());
    mixed << pubkey << OP_TOALTSTACK << OP_FROMALTSTACK << OP_HASH256 << OP_DROP;
    check(mixed, CScript() << OP_0, 2);
    CScript dynamic{CScript() << OP_0 << pubkey << pubkey << pubkey << OP_1 << OP_2 << OP_ADD << OP_CHECKMULTISIG};
    check(dynamic, CScript() << OP_0, 2);
    // Operands supplied by the satisfaction, rather than adjacent literals,
    // receive exactly the same treatment.
    check(CScript() << OP_3 << OP_CHECKMULTISIG, CScript() << OP_0 << OP_0 << pubkey << pubkey << pubkey, 2);
    check(CScript() << OP_0 << OP_0 << pubkey << OP_1 << OP_CHECKMULTISIGVERIFY
                    << OP_0 << OP_0 << pubkey << OP_1 << OP_CHECKMULTISIG,
          CScript{}, 1); // one free key per script, not per opcode
    CScript dead{CScript() << OP_FALSE << OP_IF};
    dead.insert(dead.end(), zero_of_three.begin(), zero_of_three.end());
    dead << OP_ENDIF << OP_TRUE;
    check(dead, CScript{}, 0);

    // A false CHECKMULTISIG result is legal when consumed by NOT. Empty
    // signatures prove no keys; a structural m=1 must not grant credit.
    check(CScript() << OP_1 << pubkey << pubkey << pubkey << OP_3 << OP_CHECKMULTISIG << OP_NOT,
          CScript() << OP_0 << OP_0, 2);
    check(CScript() << pubkey << OP_CHECKSIG << OP_NOT, CScript() << OP_0, 0);

    // Real ECDSA verification: one proven key out of three, plus one free.
    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vout.emplace_back(1, CScript() << OP_TRUE);
    const CScript one_of_three{GetScriptForMultisig(1, std::vector<CPubKey>(3, key.GetPubKey()))};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(SignatureHash(one_of_three, spend, 0, SIGHASH_ALL, 0, SigVersion::BASE), signature));
    signature.push_back(SIGHASH_ALL);
    spend.vin[0].scriptSig = CScript() << OP_0 << signature;
    const CTransaction tx{spend};
    ScriptValidationMetrics metrics;
    BOOST_REQUIRE(VerifyScript(tx.vin[0].scriptSig, one_of_three, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS,
        TransactionSignatureChecker(&tx, 0, 0, MissingDataBehavior::ASSERT_FAIL), nullptr, &metrics));
    BOOST_CHECK_EQUAL(CountExecutedMultisigExcessKeys(metrics), 1U);

    // Tapscript observes the actual CHECKSIG/CHECKSIGADD operands. Padding
    // and both 32- and 33-byte hashed values remain unrelated to these keys.
    const std::vector<unsigned char> xonly(32, 1);
    const CScript tapscript{CScript() << pubkey << OP_HASH160 << OP_DROP << xonly << OP_HASH160 << OP_DROP
        << xonly << OP_CHECKSIG << xonly << OP_CHECKSIGADD << xonly << OP_CHECKSIGADD << OP_0 << OP_NUMEQUAL};
    std::vector<std::vector<unsigned char>> stack(3);
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left_init = true;
    execdata.m_validation_weight_left = 1000;
    ScriptExecutionMetrics execution;
    BOOST_REQUIRE(EvalScript(stack, tapscript, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, SigVersion::TAPSCRIPT, execdata, nullptr, &execution));
    metrics.scripts = {execution};
    BOOST_CHECK_EQUAL(CountExecutedMultisigExcessKeys(metrics), 2U);
}

BOOST_AUTO_TEST_CASE(CountMultisigExcessKeysScope)
{
    for (const size_t length : {size_t{33}, size_t{65}}) {
        // Include opcode bytes inside data to rule out a raw-byte scope scan.
        const std::vector<unsigned char> data(length, OP_CHECKMULTISIG);
        const CScript data_only{CScript() << data << OP_HASH160 << OP_DROP << data << OP_HASH160 << OP_DROP << OP_TRUE};
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(data_only), 0U);
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(data_only, nullptr, 2, SigVersion::TAPSCRIPT), 0U);

        CScript dead_multisig{data_only};
        dead_multisig << OP_FALSE << OP_IF << OP_CHECKMULTISIG << OP_ENDIF;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(dead_multisig), 0U);
        CScript dead_multi_a{data_only};
        dead_multi_a << OP_FALSE << OP_IF << OP_CHECKSIGADD << OP_ENDIF;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(dead_multi_a, nullptr, 2, SigVersion::TAPSCRIPT), 0U);

        // CHECKSIG alone is deliberately not a multisig construct.
        const CScript single_sig{CScript() << data << OP_HASH160 << OP_DROP << data << OP_HASH160 << OP_DROP << data << OP_CHECKSIG};
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(single_sig), 0U);
        CScript wrong_version{data_only};
        wrong_version << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(wrong_version, nullptr, 2, SigVersion::TAPSCRIPT), 0U);
        wrong_version = data_only;
        wrong_version << OP_CHECKSIGADD;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(wrong_version), 0U);
    }
    // Do not require a canonical threshold to activate scope: the existing
    // conservative charge for dropped/re-pushed counts must remain intact.
    const auto key{GenerateRandomKey().GetPubKey()};
    const CScript canonical{GetScriptForMultisig(1, std::vector<CPubKey>(15, key))};
    CScript noncanonical{canonical};
    noncanonical.pop_back();
    noncanonical << OP_DROP << OP_15 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(noncanonical), 14U);

    // Proven dropped data is excluded even in mixed multisig scripts. Neither
    // a whole key run nor a key surviving DUP DROP may be discarded, however.
    CScript mixed{CScript() << ToByteVector(key) << OP_DROP};
    mixed.insert(mixed.end(), canonical.begin(), canonical.end());
    mixed << ToByteVector(key) << OP_DROP;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(mixed), 13U);
    CScript duplicated{canonical};
    duplicated.pop_back();
    duplicated << OP_DUP << OP_DROP << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(duplicated), 13U);
}

BOOST_AUTO_TEST_CASE(CountMultisigExcessKeysLightning)
{
    const auto local{ToByteVector(GenerateRandomKey().GetPubKey())};
    const auto remote{ToByteVector(GenerateRandomKey().GetPubKey())};
    const std::vector<unsigned char> hash(20, 0x42);
    const auto to_local = [&](const int64_t delay) {
        return CScript() << OP_IF << remote << OP_ELSE << delay << OP_CHECKSEQUENCEVERIFY
                         << OP_DROP << local << OP_ENDIF << OP_CHECKSIG;
    };
    const auto htlc = [&](const bool received, const bool anchors, const int64_t expiry) {
        CScript script{CScript() << OP_DUP << OP_HASH160 << hash << OP_EQUAL << OP_IF << OP_CHECKSIG
                                 << OP_ELSE << remote << OP_SWAP << OP_SIZE << 32 << OP_EQUAL};
        if (received) {
            script << OP_IF << OP_HASH160 << hash << OP_EQUALVERIFY << OP_2 << OP_SWAP << local
                   << OP_2 << OP_CHECKMULTISIG << OP_ELSE << OP_DROP << expiry
                   << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_CHECKSIG << OP_ENDIF;
        } else {
            script << OP_NOTIF << OP_DROP << OP_2 << OP_SWAP << local << OP_2 << OP_CHECKMULTISIG
                   << OP_ELSE << OP_HASH160 << hash << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
        }
        if (anchors) script << OP_1 << OP_CHECKSEQUENCEVERIFY << OP_DROP;
        return script << OP_ENDIF;
    };

    std::vector<CScript> scripts;
    for (const int64_t delay : {0LL, 1LL, 16LL, 17LL, 127LL, 128LL, 32768LL, 65535LL}) {
        scripts.push_back(to_local(delay));
    }
    for (const bool anchors : {false, true}) {
        scripts.push_back(htlc(false, anchors, 0));
        for (const int64_t expiry : {0LL, 16LL, 17LL, 128LL, 0x7fffffffLL, 0x80000000LL, 0xffffffffLL}) {
            scripts.push_back(htlc(true, anchors, expiry));
        }
    }
    const CScript payload{GetScriptForMultisig(1, std::vector<CPubKey>(15, CPubKey{local.begin(), local.end()}))};
    for (const auto& script : scripts) {
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(script), 0U);
        // This is explicitly structural compatibility, including revocation
        // paths. It is not a claim that the witness proves the embedded keys.
        CScriptWitness witness;
        witness.stack = {{}, Serialize(script)};
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(script, &witness), 0U);
        // These legacy templates contain no tapscript CHECKSIGADD. Disabled
        // CHECKMULTISIG opcodes must not activate the tapscript policy.
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(script, nullptr, 2, SigVersion::TAPSCRIPT), 0U);

        CTxIn input;
        input.scriptWitness = witness;
        BOOST_CHECK_EQUAL(CountInputMultisigExcessKeys(input, GetScriptForDestination(WitnessV0ScriptHash{script})), 0U);

        // Extra code forfeits the template allowance, but to_local remains
        // outside multisig scope regardless (it only contains CHECKSIG).
        const unsigned int non_template_count{script.front() == OP_IF ? 0U : 1U};
        CScript suffix{script};
        suffix << OP_NOP;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(suffix), non_template_count);
        CScript prefix{CScript() << OP_NOP};
        prefix.insert(prefix.end(), script.begin(), script.end());
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(prefix), non_template_count);

        // Neither a prefix nor suffix Lightning fragment can exempt a data
        // multisig or contribute credits that erase its charged keys.
        CScript combined{script};
        combined << OP_DROP;
        combined.insert(combined.end(), payload.begin(), payload.end());
        BOOST_CHECK_GE(CountMultisigExcessKeys(combined), 13U);
        combined = payload;
        combined << OP_DROP;
        combined.insert(combined.end(), script.begin(), script.end());
        BOOST_CHECK_GE(CountMultisigExcessKeys(combined), 13U);

        // A 33-byte data field substituted for either fixed-size hash is not
        // a Lightning template. Extra payload cannot hide in a hash slot.
        for (auto it{script.begin()}; it != script.end();) {
            const auto start{it};
            opcodetype op;
            std::vector<unsigned char> data;
            BOOST_REQUIRE(script.GetOp(it, op, data));
            if (op != 20) continue;
            CScript enlarged;
            enlarged.insert(enlarged.end(), script.begin(), start);
            enlarged << local;
            enlarged.insert(enlarged.end(), it, script.end());
            BOOST_CHECK_GT(CountMultisigExcessKeys(enlarged), 0U);
        }
    }
    for (const int64_t delay : {-1LL, 65536LL, 0x100000000LL}) {
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(to_local(delay)), 0U);
    }
    for (const int64_t expiry : {-1LL, 0x100000000LL}) {
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(htlc(true, false, expiry)), 1U);
    }
    // Numerically valid but nonminimal fields must not widen the allowance.
    CScript nonminimal{CScript() << OP_IF << remote << OP_ELSE};
    nonminimal << std::vector<unsigned char>{1, 0} << OP_CHECKSEQUENCEVERIFY << OP_DROP
               << local << OP_ENDIF << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(nonminimal), 0U);
    CScript nonminimal_key{CScript() << OP_IF << OP_PUSHDATA1};
    nonminimal_key.push_back(33);
    nonminimal_key.insert(nonminimal_key.end(), remote.begin(), remote.end());
    nonminimal_key << OP_ELSE << OP_1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << local << OP_ENDIF << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(nonminimal_key), 0U);
    auto wrong_key_encoding{remote};
    wrong_key_encoding[0] = 4; // Not a compressed-key encoding, despite its length.
    const CScript bad_key{CScript() << OP_IF << wrong_key_encoding << OP_ELSE << OP_1
                                    << OP_CHECKSEQUENCEVERIFY << OP_DROP << local << OP_ENDIF << OP_CHECKSIG};
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(bad_key), 0U);
    CScript truncated{htlc(true, true, 500)};
    truncated.pop_back(); // Missing the outer ENDIF.
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(truncated), 1U);
    // bpub's original 1-of-15 remains thirteen charged keys.
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(payload), 13U);
}

BOOST_AUTO_TEST_CASE(CountMultisigExcessKeysIdentityBlocks)
{
    // Three families: permutation, duplication/removal, and altstack transport.
    // In #422 at 177e5cad, a SWAP/SWAP between every x-only key and its
    // signature opcode loses all key recognition. These variants must instead
    // retain exactly the canonical count, not merely receive a punitive floor.
    const std::vector<CScript> identities{
        CScript() << OP_SWAP << OP_SWAP,
        CScript() << OP_ROT << OP_ROT << OP_ROT,
        CScript() << OP_2SWAP << OP_2SWAP,
        CScript() << OP_2ROT << OP_2ROT << OP_2ROT,
        CScript() << OP_DUP << OP_DROP,
        CScript() << OP_OVER << OP_DROP,
        CScript() << OP_2DUP << OP_2DROP,
        CScript() << OP_3DUP << OP_DROP << OP_2DROP,
        CScript() << OP_TUCK << OP_DROP << OP_SWAP,
        CScript() << OP_TOALTSTACK << OP_FROMALTSTACK,
        CScript() << OP_FROMALTSTACK << OP_TOALTSTACK,
        CScript() << OP_DUP << OP_TOALTSTACK << OP_SWAP << OP_SWAP << OP_FROMALTSTACK << OP_DROP,
    };
    const std::vector<CPubKey> keys{GenerateRandomKey().GetPubKey(), GenerateRandomKey().GetPubKey(), GenerateRandomKey().GetPubKey()};
    const CScript canonical{GetScriptForMultisig(1, keys)};
    for (const CScript& identity : identities) {
        // Pin the claimed identity against the real interpreter when this test
        // is run. Include enough distinct inputs and a pre-existing altstack
        // item; restore it afterward so both stacks are checked.
        std::vector<std::vector<unsigned char>> initial{{1}, {2}, {3}, {4}, {5}, {6}, {7}};
        auto stack{initial};
        CScript check{CScript() << OP_TOALTSTACK};
        check.insert(check.end(), identity.begin(), identity.end());
        check << OP_FROMALTSTACK;
        BOOST_REQUIRE(EvalScript(stack, check, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE));
        BOOST_CHECK(stack == initial);

        // m, n and every key remain recognized after a proven identity block.
        CScript legacy{CScript() << OP_1};
        legacy.insert(legacy.end(), identity.begin(), identity.end());
        for (const CPubKey& key : keys) {
            legacy << ToByteVector(key);
            legacy.insert(legacy.end(), identity.begin(), identity.end());
        }
        legacy << OP_3;
        legacy.insert(legacy.end(), identity.begin(), identity.end());
        legacy << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(legacy), CountMultisigExcessKeys(canonical));

        CScript tapscript;
        for (size_t i{0}; i < keys.size(); ++i) {
            tapscript << ToByteVector(XOnlyPubKey{keys[i]});
            tapscript.insert(tapscript.end(), identity.begin(), identity.end());
            tapscript << (i == 0 ? OP_CHECKSIG : OP_CHECKSIGADD);
        }
        tapscript << OP_1;
        tapscript.insert(tapscript.end(), identity.begin(), identity.end());
        tapscript << OP_NUMEQUAL;
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(tapscript, nullptr, 2, SigVersion::TAPSCRIPT), 1U);

        // A hash stays a hash: normalizing a neutral block must not count every
        // 32-byte value as an x-only public key.
        CScript hashes;
        for (int i{0}; i < 3; ++i) {
            hashes << std::vector<unsigned char>(32, 1);
            hashes.insert(hashes.end(), identity.begin(), identity.end());
            hashes << OP_EQUALVERIFY;
        }
        BOOST_CHECK_EQUAL(CountMultisigExcessKeys(hashes, nullptr, 2, SigVersion::TAPSCRIPT), 0U);
    }

    // Do not accept equal opcode counts as proof of identity. ROT twice is
    // not neutral; a drop plus a numeric push is not identity for every input.
    CScript not_neutral{canonical};
    not_neutral.pop_back();
    not_neutral << OP_ROT << OP_ROT << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(not_neutral), 2U);
    CScript dropped{canonical};
    dropped.pop_back();
    dropped << OP_DROP << OP_3 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(dropped), 2U);

    // Restoring only the main stack is insufficient: a duplicated item left
    // on the altstack may affect later instructions and must not be hidden.
    CScript altered_altstack{canonical};
    altered_altstack.pop_back();
    altered_altstack << OP_DUP << OP_TOALTSTACK << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(altered_altstack), 2U);

    // Independent bounded identity chunks can be longer than the work limit.
    CScript long_identity{canonical};
    long_identity.pop_back();
    for (int i{0}; i < 128; ++i) long_identity << OP_SWAP;
    long_identity << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(CountMultisigExcessKeys(long_identity), 1U);
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
