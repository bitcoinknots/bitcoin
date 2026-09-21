// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/util/setup_common.h>

#include <checkqueue.h>
#include <clientversion.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <kernel/mempool_options.h>
#include <key.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/transaction_utils.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <functional>
#include <map>
#include <string>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;
using util::SplitString;
using util::ToString;

typedef std::vector<unsigned char> valtype;

static kernel::MemPoolOptions g_mempool_opts;

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("STRICTENC"), (unsigned int)SCRIPT_VERIFY_STRICTENC},
    {std::string("DERSIG"), (unsigned int)SCRIPT_VERIFY_DERSIG},
    {std::string("LOW_S"), (unsigned int)SCRIPT_VERIFY_LOW_S},
    {std::string("SIGPUSHONLY"), (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {std::string("MINIMALDATA"), (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("DISCOURAGE_UPGRADABLE_NOPS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {std::string("CLEANSTACK"), (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {std::string("MINIMALIF"), (unsigned int)SCRIPT_VERIFY_MINIMALIF},
    {std::string("NULLFAIL"), (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {std::string("WITNESS"), (unsigned int)SCRIPT_VERIFY_WITNESS},
    {std::string("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM},
    {std::string("WITNESS_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_WITNESS_PUBKEYTYPE},
    {std::string("CONST_SCRIPTCODE"), (unsigned int)SCRIPT_VERIFY_CONST_SCRIPTCODE},
    {std::string("TAPROOT"), (unsigned int)SCRIPT_VERIFY_TAPROOT},
    {std::string("DISCOURAGE_UPGRADABLE_PUBKEYTYPE"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE},
    {std::string("DISCOURAGE_OP_SUCCESS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS},
    {std::string("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION},
    {std::string("REDUCED_DATA"), (unsigned int)SCRIPT_VERIFY_REDUCED_DATA},
};

unsigned int ParseScriptFlags(std::string strFlags)
{
    unsigned int flags = SCRIPT_VERIFY_NONE;
    if (strFlags.empty() || strFlags == "NONE") return flags;

    std::vector<std::string> words = SplitString(strFlags, ',');
    for (const std::string& word : words)
    {
        if (!mapFlagNames.count(word))
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        flags |= mapFlagNames[word];
    }
    return flags;
}

// Check that all flags in STANDARD_SCRIPT_VERIFY_FLAGS are present in mapFlagNames.
bool CheckMapFlagNames()
{
    unsigned int standard_flags_missing{STANDARD_SCRIPT_VERIFY_FLAGS};
    for (const auto& pair : mapFlagNames) {
        standard_flags_missing &= ~(pair.second);
    }
    return standard_flags_missing == 0;
}

std::string FormatScriptFlags(unsigned int flags)
{
    if (flags == SCRIPT_VERIFY_NONE) {
        return "";
    }
    std::string ret;
    std::map<std::string, unsigned int>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }
    return ret.substr(0, ret.size() - 1);
}

/*
* Check that the input scripts of a transaction are valid/invalid as expected.
*/
bool CheckTxScripts(const CTransaction& tx, const std::map<COutPoint, CScript>& map_prevout_scriptPubKeys,
    const std::map<COutPoint, int64_t>& map_prevout_values, unsigned int flags,
    const PrecomputedTransactionData& txdata, const std::string& strTest, bool expect_valid)
{
    // SCRIPT_VERIFY_UNIFIED_SIGHASH stays in the sweep. Nothing in this corpus
    // opted in, so the flag must make no difference to any of it, and sweeping
    // it here is what holds that: a change that let the new rules reach a
    // signature that did not ask for them would fail these vectors.

    bool tx_valid = true;
    ScriptError err = expect_valid ? SCRIPT_ERR_UNKNOWN_ERROR : SCRIPT_ERR_OK;
    for (unsigned int i = 0; i < tx.vin.size() && tx_valid; ++i) {
        const CTxIn input = tx.vin[i];
        const CAmount amount = map_prevout_values.count(input.prevout) ? map_prevout_values.at(input.prevout) : 0;
        try {
            tx_valid = VerifyScript(input.scriptSig, map_prevout_scriptPubKeys.at(input.prevout),
                &input.scriptWitness, flags, TransactionSignatureChecker(&tx, i, amount, txdata, MissingDataBehavior::ASSERT_FAIL), &err);
        } catch (...) {
            BOOST_ERROR("Bad test: " << strTest);
            return true; // The test format is bad and an error is thrown. Return true to silence further error.
        }
        if (expect_valid) {
            BOOST_CHECK_MESSAGE(tx_valid, strTest);
            BOOST_CHECK_MESSAGE((err == SCRIPT_ERR_OK), ScriptErrorString(err));
            err = SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    if (!expect_valid) {
        BOOST_CHECK_MESSAGE(!tx_valid, strTest);
        BOOST_CHECK_MESSAGE((err != SCRIPT_ERR_OK), ScriptErrorString(err));
    }
    return (tx_valid == expect_valid);
}

/*
 * Trim or fill flags to make the combination valid:
 * WITNESS must be used with P2SH
 * CLEANSTACK must be used WITNESS and P2SH
 */

unsigned int TrimFlags(unsigned int flags)
{
    // WITNESS requires P2SH
    if (!(flags & SCRIPT_VERIFY_P2SH)) flags &= ~(unsigned int)SCRIPT_VERIFY_WITNESS;

    // CLEANSTACK requires WITNESS (and transitively CLEANSTACK requires P2SH)
    if (!(flags & SCRIPT_VERIFY_WITNESS)) flags &= ~(unsigned int)SCRIPT_VERIFY_CLEANSTACK;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

unsigned int FillFlags(unsigned int flags)
{
    // CLEANSTACK implies WITNESS
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_WITNESS;

    // WITNESS implies P2SH (and transitively CLEANSTACK implies P2SH)
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

// Exclude each possible script verify flag from flags. Returns a set of these flag combinations
// that are valid and without duplicates. For example: if flags=1111 and the 4 possible flags are
// 0001, 0010, 0100, and 1000, this should return the set {0111, 1011, 1101, 1110}.
// Assumes that mapFlagNames contains all script verify flags.
std::set<unsigned int> ExcludeIndividualFlags(unsigned int flags)
{
    std::set<unsigned int> flags_combos;
    for (const auto& pair : mapFlagNames) {
        const unsigned int flags_excluding_one = TrimFlags(flags & ~(pair.second));
        if (flags != flags_excluding_one) {
            flags_combos.insert(flags_excluding_one);
        }
    }
    return flags_combos;
}

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    BOOST_CHECK_MESSAGE(CheckMapFlagNames(), "mapFlagNames is missing a script verification flag");
    // Read tests from test/data/tx_valid.json
    UniValue tests = read_json(json_tests::tx_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
            BOOST_CHECK(state.IsValid());

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (~verify_flags != FillFlags(~verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~verify_flags, txdata, strTest, /*expect_valid=*/true),
                                "Tx unexpectedly failed: " << strTest);

            // Backwards compatibility of script verification flags: Removing any flag(s) should not invalidate a valid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                // Removing individual flags
                unsigned int flags = TrimFlags(~(verify_flags | flag));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with flag " << name << " unset: " << strTest);
                }
                // Removing random combinations of flags
                flags = TrimFlags(~(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size())));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Tx unexpectedly failed with random flags " << ToString(flags) << ": " << strTest);
                }
            }

            // Check that flags are maximal: transaction should fail if any unset flags are set.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, ~flags_excluding_one, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Too many flags unset: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    UniValue tests = read_json(json_tests::tx_invalid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test[0].isArray())
        {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, int64_t> mapprevOutValues;
            UniValue inputs = test[0].get_array();
            bool fValid = true;
            for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue& input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4)
                {
                    fValid = false;
                    break;
                }
                COutPoint outpoint{Txid::FromHex(vinput[0].get_str()).value(), uint32_t(vinput[1].getInt<int>())};
                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                if (vinput.size() >= 4)
                {
                    mapprevOutValues[outpoint] = vinput[3].getInt<int64_t>();
                }
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            DataStream stream(ParseHex(transaction));
            CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

            TxValidationState state;
            if (!CheckTransaction(tx, state) || state.IsInvalid()) {
                BOOST_CHECK_MESSAGE(test[2].get_str() == "BADTX", strTest);
                continue;
            }

            PrecomputedTransactionData txdata(tx);
            unsigned int verify_flags = ParseScriptFlags(test[2].get_str());

            // Check that the test gives a valid combination of flags (otherwise VerifyScript will throw). Don't edit the flags.
            if (verify_flags != FillFlags(verify_flags)) {
                BOOST_ERROR("Bad test flags: " << strTest);
            }

            // Not using FillFlags() in the main test, in order to detect invalid verifyFlags combination
            BOOST_CHECK_MESSAGE(CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, verify_flags, txdata, strTest, /*expect_valid=*/false),
                                "Tx unexpectedly passed: " << strTest);

            // Backwards compatibility of script verification flags: Adding any flag(s) should not validate an invalid transaction
            for (const auto& [name, flag] : mapFlagNames) {
                unsigned int flags = FillFlags(verify_flags | flag);
                // Adding individual flags
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with flag " << name << " set: " << strTest);
                }
                // Adding random combinations of flags
                flags = FillFlags(verify_flags | (unsigned int)m_rng.randbits(mapFlagNames.size()));
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags, txdata, strTest, /*expect_valid=*/false)) {
                    BOOST_ERROR("Tx unexpectedly passed with random flags " << name << ": " << strTest);
                }
            }

            // Check that flags are minimal: transaction should succeed if any set flags are unset.
            for (auto flags_excluding_one : ExcludeIndividualFlags(verify_flags)) {
                if (!CheckTxScripts(tx, mapprevOutScriptPubKeys, mapprevOutValues, flags_excluding_one, txdata, strTest, /*expect_valid=*/true)) {
                    BOOST_ERROR("Too many flags set: " << strTest);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_no_inputs)
{
    CMutableTransaction empty;

    TxValidationState state;
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(empty), state), "Transaction with no inputs should be invalid.");
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-vin-empty");
}

BOOST_AUTO_TEST_CASE(tx_oversized)
{
    auto createTransaction =[](size_t payloadSize) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<unsigned char>(payloadSize));
        return CTransaction(tx);
    };
    const auto maxTransactionSize = MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR;
    const auto oversizedTransactionBaseSize = ::GetSerializeSize(TX_NO_WITNESS(createTransaction(maxTransactionSize))) - maxTransactionSize;

    auto maxPayloadSize = maxTransactionSize - oversizedTransactionBaseSize;
    {
        TxValidationState state;
        CheckTransaction(createTransaction(maxPayloadSize), state);
        BOOST_CHECK(state.GetRejectReason() != "bad-txns-oversize");
    }

    maxPayloadSize += 1;
    {
        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(createTransaction(maxPayloadSize), state), "Oversized transaction should be invalid");
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-oversize");
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real transaction (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    DataStream stream(vch);
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction(tx), state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(tx), state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins));
}

static void CreateCreditAndSpend(const FillableSigningProvider& keystore, const CScript& outscript, CTransactionRef& output, CMutableTransaction& input, bool success = true)
{
    CMutableTransaction outputm;
    outputm.version = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = outscript;
    DataStream ssout;
    ssout << TX_WITH_WITNESS(outputm);
    ssout >> TX_WITH_WITNESS(output);
    assert(output->vin.size() == 1);
    assert(output->vin[0] == outputm.vin[0]);
    assert(output->vout.size() == 1);
    assert(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.version = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetHash();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = 1;
    inputm.vout[0].scriptPubKey = CScript();
    SignatureData empty;
    bool ret = SignSignature(keystore, *output, inputm, 0, SIGHASH_ALL, empty);
    assert(ret == success);
    DataStream ssin;
    ssin << TX_WITH_WITNESS(inputm);
    ssin >> TX_WITH_WITNESS(input);
    assert(input.vin.size() == 1);
    assert(input.vin[0] == inputm.vin[0]);
    assert(input.vout.size() == 1);
    assert(input.vout[0] == inputm.vout[0]);
    assert(input.vin[0].scriptWitness.stack == inputm.vin[0].scriptWitness.stack);
}

static void CheckWithFlag(const CTransactionRef& output, const CMutableTransaction& input, uint32_t flags, bool success)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags, TransactionSignatureChecker(&inputi, 0, output->vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &error);
    assert(ret == success);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

static void ReplaceRedeemScript(CScript& script, const CScript& redeemScript)
{
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    assert(stack.size() > 0);
    stack.back() = std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_witness_transaction)
{
    CMutableTransaction mtx;
    mtx.version = 1;

    CKey key = GenerateRandomKey(); // Need to use compressed keys in segwit or the signing will fail
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CKeyID hash = key.GetPubKey().GetID();
    CScript scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(hash.begin(), hash.end());

    std::vector<int> sigHashes;
    sigHashes.push_back(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_NONE);
    sigHashes.push_back(SIGHASH_SINGLE);
    sigHashes.push_back(SIGHASH_ALL);

    // create a big transaction of 4500 inputs signed by the same key
    for(uint32_t ij = 0; ij < 4500; ij++) {
        uint32_t i = mtx.vin.size();
        COutPoint outpoint(Txid::FromHex("0000000000000000000000000000000000000000000000000000000000000100").value(), i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.resize(mtx.vout.size() + 1);
        mtx.vout[i].nValue = 1000;
        mtx.vout[i].scriptPubKey = CScript() << OP_1;
    }

    // sign all inputs
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        SignatureData empty;
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, 1000, sigHashes.at(i % sigHashes.size()), empty);
        assert(hashSigned);
    }

    DataStream ssout;
    ssout << TX_WITH_WITNESS(mtx);
    CTransaction tx(deserialize, TX_WITH_WITNESS, ssout);

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata(tx);
    CCheckQueue<CScriptCheck> scriptcheckqueue(/*batch_size=*/128, /*worker_threads_num=*/20);
    CCheckQueueControl<CScriptCheck> control(&scriptcheckqueue);

    std::vector<Coin> coins;
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        Coin coin;
        coin.nHeight = 1;
        coin.fCoinBase = false;
        coin.out.nValue = 1000;
        coin.out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(coin));
    }

    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(coins[tx.vin[i].prevout.n].out, tx, signature_cache, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false, &txdata);
        control.Add(std::move(vChecks));
    }

    bool controlCheck = !control.Complete().has_value();
    assert(controlCheck);
}

SignatureData CombineSignatures(const CMutableTransaction& input1, const CMutableTransaction& input2, const CTransactionRef tx)
{
    SignatureData sigdata;
    sigdata = DataFromTransaction(input1, 0, tx->vout[0]);
    sigdata.MergeSignatureData(DataFromTransaction(input2, 0, tx->vout[0]));
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(input1, 0, tx->vout[0].nValue, SIGHASH_ALL), tx->vout[0].scriptPubKey, sigdata);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness)
{
    FillableSigningProvider keystore, keystore2;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey();
    CKey key3 = GenerateRandomKey();
    CKey key1L = GenerateRandomKey(/*compressed=*/false);
    CKey key2L = GenerateRandomKey(/*compressed=*/false);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();
    CPubKey pubkey3 = key3.GetPubKey();
    CPubKey pubkey1L = key1L.GetPubKey();
    CPubKey pubkey2L = key2L.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    BOOST_CHECK(keystore.AddKeyPubKey(key1L, pubkey1L));
    BOOST_CHECK(keystore.AddKeyPubKey(key2L, pubkey2L));
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L, scriptMulti;
    scriptPubkey1 << ToByteVector(pubkey1) << OP_CHECKSIG;
    scriptPubkey2 << ToByteVector(pubkey2) << OP_CHECKSIG;
    scriptPubkey1L << ToByteVector(pubkey1L) << OP_CHECKSIG;
    scriptPubkey2L << ToByteVector(pubkey2L) << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1L));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2L));
    BOOST_CHECK(keystore.AddCScript(scriptMulti));
    CScript destination_script_1, destination_script_2, destination_script_1L, destination_script_2L, destination_script_multi;
    destination_script_1 = GetScriptForDestination(WitnessV0KeyHash(pubkey1));
    destination_script_2 = GetScriptForDestination(WitnessV0KeyHash(pubkey2));
    destination_script_1L = GetScriptForDestination(WitnessV0KeyHash(pubkey1L));
    destination_script_2L = GetScriptForDestination(WitnessV0KeyHash(pubkey2L));
    destination_script_multi = GetScriptForDestination(WitnessV0ScriptHash(scriptMulti));
    BOOST_CHECK(keystore.AddCScript(destination_script_1));
    BOOST_CHECK(keystore.AddCScript(destination_script_2));
    BOOST_CHECK(keystore.AddCScript(destination_script_1L));
    BOOST_CHECK(keystore.AddCScript(destination_script_2L));
    BOOST_CHECK(keystore.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti));
    BOOST_CHECK(keystore2.AddCScript(destination_script_multi));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, destination_script_1, output1, input1);
    CreateCreditAndSpend(keystore, destination_script_2, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH witness pay-to-compressed-pubkey (v0).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, destination_script_1);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey1L)), output1, input1);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptPubkey2L)), output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Signing disabled for witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, destination_script_1L, output1, input1, false);
    CreateCreditAndSpend(keystore, destination_script_2L, output2, input2, false);

    // Signing disabled for P2SH witness pay-to-uncompressed-pubkey (v1).
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_1L)), output1, input1, false);
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_2L)), output2, input2, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(scriptMulti)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(scriptMulti)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // Witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, destination_script_multi, output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, destination_script_multi, output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_NONE, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH witness 2-of-2 multisig
    CreateCreditAndSpend(keystore, GetScriptForDestination(ScriptHash(destination_script_multi)), output1, input1, false);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    CreateCreditAndSpend(keystore2, GetScriptForDestination(ScriptHash(destination_script_multi)), output2, input2, false);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    FillableSigningProvider keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins, {11*CENT, 50*CENT, 21*CENT, 22*CENT});

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key = GenerateRandomKey();
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    g_mempool_opts.permit_bare_pubkey = true;

    constexpr auto CheckIsStandard = [](const auto& t) {
        std::string reason;
        BOOST_CHECK(IsStandardTx(CTransaction{t}, g_mempool_opts, reason));
        BOOST_CHECK(reason.empty());
    };
    constexpr auto CheckIsNotStandard = [](const auto& t, const std::string& reason_in) {
        std::string reason;
        BOOST_CHECK(!IsStandardTx(CTransaction{t}, g_mempool_opts, reason));
        BOOST_CHECK_EQUAL(reason_in, reason);
    };

    CheckIsStandard(t);

    g_mempool_opts.permitephemeral_anchor = true;
    g_mempool_opts.permitephemeral_dust = true;
    g_mempool_opts.permitephemeral_send = true;

    // Check dust with default relay fee:
    CAmount nDustThreshold = 182 * g_mempool_opts.dust_relay_feerate.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, 546);

    // Add dust outputs up to allowed maximum, still standard!
    for (size_t i{0}; i < MAX_DUST_OUTPUTS_PER_TX; ++i) {
        t.vout.emplace_back(0, t.vout[0].scriptPubKey);
        CheckIsStandard(t);
    }

    // dust:
    t.vout[0].nValue = nDustThreshold - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    CheckIsStandard(t);

    // Disallowed version
    t.version = std::numeric_limits<uint32_t>::max();
    CheckIsNotStandard(t, "version");

    t.version = 0;
    CheckIsNotStandard(t, "version");

    t.version = TX_MAX_STANDARD_VERSION + 1;
    CheckIsNotStandard(t, "version");

    // Allowed version
    t.version = 1;
    CheckIsStandard(t);

    t.version = 2;
    CheckIsStandard(t);

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 3702 / 1000
    g_mempool_opts.dust_relay_feerate = CFeeRate(3702);
    // dust:
    t.vout[0].nValue = 674 - 1;
    CheckIsNotStandard(t, "dust");
    // not dust:
    t.vout[0].nValue = 674;
    CheckIsStandard(t);
    g_mempool_opts.dust_relay_feerate = CFeeRate{DUST_RELAY_TX_FEE};

    t.vout[0].scriptPubKey = CScript() << OP_1;
    CheckIsNotStandard(t, "scriptpubkey");

    // Test rejectparasites
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout.emplace_back(674, GetScriptForDestination(PKHash(key.GetPubKey())));
    t.nLockTime = 21;
    g_mempool_opts.reject_parasites = false;
    CheckIsStandard(t);
    g_mempool_opts.reject_parasites = true;
    CheckIsNotStandard(t, "parasite-cat21");
    t.nLockTime = 0;
    CheckIsStandard(t);
    g_mempool_opts.reject_parasites = false;

    // Test rejecttokens
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_13 << OP_FALSE;
    g_mempool_opts.reject_tokens = false;
    CheckIsStandard(t);
    g_mempool_opts.reject_tokens = true;
    CheckIsNotStandard(t, "tokens-runes");
    // At least one data push is needed after OP_13 to match
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_13;
    CheckIsStandard(t);

    // Test rejecttokens catching a Counterparty issuance, an asset protocol whose issuance is
    // what anchors the Stamps overlay protocols. Payload and input txid are from mainnet
    // transaction 92df895bbf715316fee36cb536453fcd509dc80569afee6dce9e8203ad51de15.
    const Txid dummy_txid{t.vin[0].prevout.hash};
    const Txid cntrprty_txid{*Txid::FromHex("e915fa8be0a5d25c4327d056a54bbed7051f6ecf850993994741645012bb0e6b")};
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "dfa3af7889188ce8034d69efcf5a63a82d6290bbbc54572b93657db6f7d83d"_hex;
    t.vin[0].prevout.hash = cntrprty_txid;
    CheckIsNotStandard(t, "tokens-counterparty");
    // The payload is obfuscated with the first input's txid, so it only decodes against that input
    t.vin[0].prevout.hash = dummy_txid;
    CheckIsStandard(t);
    // A payload too short to hold the magic is not a Counterparty message
    t.vin[0].prevout.hash = cntrprty_txid;
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "dfa3af7889188c"_hex;
    CheckIsStandard(t);
    // Every datacarrier output is checked, not just the one the keystream is derived on
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "dfa3af7889188ce8034d69efcf5a63a82d6290bbbc54572b93657db6f7d83d"_hex;
    t.vout.emplace_back(0, CScript() << OP_RETURN << "dfa3af7889188c"_hex);
    CheckIsNotStandard(t, "tokens-counterparty");
    t.vout.pop_back();
    g_mempool_opts.reject_tokens = false;
    CheckIsStandard(t);
    g_mempool_opts.reject_tokens = true;
    t.vin[0].prevout.hash = dummy_txid;

    // Test rejecttokens applying to OLGA
    const auto olga_header = CScript() << OP_0 << "003e7374616d703a000000000000000000000000000000000000000000000000"_hex;
    t.vout[0].scriptPubKey = olga_header;
    t.vout.resize(1);
    // Missing a second output, so not OLGA
    CheckIsStandard(t);
    t.vout.emplace_back(1000, olga_header);
    CheckIsNotStandard(t, "tokens-olga");
    t.vout.emplace_back(1000, olga_header);
    CheckIsNotStandard(t, "tokens-olga");
    g_mempool_opts.reject_tokens = false;
    CheckIsStandard(t);
    t.vout.resize(1);

    // MAX_OP_RETURN_RELAY-byte TxoutType::NULL_DATA (standard)
    g_mempool_opts.permitbaredatacarrier = true;
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    while (t.vout[0].scriptPubKey.size() < MAX_OP_RETURN_RELAY) {
        t.vout[0].scriptPubKey << OP_0;
    }
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    CheckIsStandard(t);

    // MAX_OP_RETURN_RELAY+1-byte TxoutType::NULL_DATA (non-standard)
    t.vout[0].scriptPubKey << OP_0;
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    CheckIsNotStandard(t, "scriptpubkey");

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ""_hex;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "00"_hex << "01"_hex;
    CheckIsStandard(t);
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << "01"_hex << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << 0 << "01"_hex << 2 << "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex;
    CheckIsStandard(t);

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    CheckIsNotStandard(t, "scriptpubkey");

    // TxoutType::NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    CheckIsStandard(t);

    // Only one TxoutType::NULL_DATA permitted in all cases
    t.vout.resize(2);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[0].nValue = 0;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].nValue = 0;
    CheckIsNotStandard(t, "multi-op-return");

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"_hex;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsNotStandard(t, "multi-op-return");

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    CheckIsNotStandard(t, "multi-op-return");

    // Test permitbaredatacarrier
    g_mempool_opts.permitbaredatacarrier = false;
    t.vout[1].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    t.vout[1].nValue = COIN;
    CheckIsStandard(t);
    t.vout.resize(1);
    CheckIsNotStandard(t, "bare-datacarrier");
    g_mempool_opts.permitbaredatacarrier = true;
    CheckIsStandard(t);

    // Check large scriptSig (non-standard if size is >1650 bytes)
    t.vout.resize(1);
    t.vout[0].nValue = MAX_MONEY;
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    // OP_PUSHDATA2 with len (3 bytes) + data (1647 bytes) = 1650 bytes
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1647, 0); // 1650
    CheckIsStandard(t);

    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1648, 0); // 1651
    CheckIsNotStandard(t, "scriptsig-size");

    // Check scriptSig format (non-standard if there are any other ops than just PUSHs)
    t.vin[0].scriptSig = CScript()
        << OP_TRUE << OP_0 << OP_1NEGATE << OP_16 // OP_n (single byte pushes: n = 1, 0, -1, 16)
        << std::vector<unsigned char>(75, 0)      // OP_PUSHx [...x bytes...]
        << std::vector<unsigned char>(235, 0)     // OP_PUSHDATA1 x [...x bytes...]
        << std::vector<unsigned char>(1234, 0)    // OP_PUSHDATA2 x [...x bytes...]
        << OP_9;
    CheckIsStandard(t);

    const std::vector<unsigned char> non_push_ops = { // arbitrary set of non-push operations
        OP_NOP, OP_VERIFY, OP_IF, OP_ROT, OP_3DUP, OP_SIZE, OP_EQUAL, OP_ADD, OP_SUB,
        OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY };

    CScript::const_iterator pc = t.vin[0].scriptSig.begin();
    while (pc < t.vin[0].scriptSig.end()) {
        opcodetype opcode;
        CScript::const_iterator prev_pc = pc;
        t.vin[0].scriptSig.GetOp(pc, opcode); // advance to next op
        // for the sake of simplicity, we only replace single-byte push operations
        if (opcode >= 1 && opcode <= OP_PUSHDATA4)
            continue;

        int index = prev_pc - t.vin[0].scriptSig.begin();
        unsigned char orig_op = *prev_pc; // save op
        // replace current push-op with each non-push-op
        for (auto op : non_push_ops) {
            t.vin[0].scriptSig[index] = op;
            CheckIsNotStandard(t, "scriptsig-not-pushonly");
        }
        t.vin[0].scriptSig[index] = orig_op; // restore op
        CheckIsStandard(t);
    }

    // Check tx-size (non-standard if transaction weight is > MAX_STANDARD_TX_WEIGHT)
    t.vin.clear();
    t.vin.resize(2438); // size per input (empty scriptSig): 41 bytes
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(19, 0); // output size: 30 bytes
    // tx header:                12 bytes =>     48 weight units
    // 2438 inputs: 2438*41 = 99958 bytes => 399832 weight units
    //    1 output:              30 bytes =>    120 weight units
    //                      ======================================
    //                                total: 400000 weight units
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400000);
    CheckIsStandard(t);

    // increase output size by one byte, so we end up with 400004 weight units
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(20, 0); // output size: 31 bytes
    BOOST_CHECK_EQUAL(GetTransactionWeight(CTransaction(t)), 400004);
    CheckIsNotStandard(t, "tx-size");

    // Check bare multisig (standard if policy flag g_bare_multi is set)
    g_mempool_opts.permit_bare_multisig = true;
    t.vout[0].scriptPubKey = GetScriptForMultisig(1, {key.GetPubKey()}); // simple 1-of-1
    t.vin.resize(1);
    t.vin[0].scriptSig = CScript() << std::vector<unsigned char>(65, 0);
    CheckIsStandard(t);

    g_mempool_opts.permit_bare_multisig = false;
    CheckIsNotStandard(t, "bare-multisig");
    g_mempool_opts.permit_bare_multisig = true;

    // Add dust outputs up to allowed maximum
    assert(t.vout.size() == 1);
    t.vout.insert(t.vout.end(), MAX_DUST_OUTPUTS_PER_TX, {0, t.vout[0].scriptPubKey});

    // Check compressed P2PK outputs dust threshold (must have leading 02 or 03)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG;
    t.vout[0].nValue = 576;
    CheckIsStandard(t);
    t.vout[0].nValue = 575;
    CheckIsNotStandard(t, "dust");

    // Check uncompressed P2PK outputs dust threshold (must have leading 04/06/07)
    t.vout[0].scriptPubKey = CScript() << std::vector<unsigned char>(65, 0x04) << OP_CHECKSIG;
    t.vout[0].nValue = 672;
    CheckIsStandard(t);
    t.vout[0].nValue = 671;
    CheckIsNotStandard(t, "dust");

    // Check P2PKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    t.vout[0].nValue = 546;
    CheckIsStandard(t);
    t.vout[0].nValue = 545;
    CheckIsNotStandard(t, "dust");

    // Check P2SH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUAL;
    t.vout[0].nValue = 540;
    CheckIsStandard(t);
    t.vout[0].nValue = 539;
    CheckIsNotStandard(t, "dust");

    // Check P2WPKH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0);
    t.vout[0].nValue = 294;
    CheckIsStandard(t);
    t.vout[0].nValue = 293;
    CheckIsNotStandard(t, "dust");

    // Check P2WSH outputs dust threshold
    t.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check P2TR outputs dust threshold (Invalid xonly key ok!)
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    t.vout[0].nValue = 330;
    CheckIsStandard(t);
    t.vout[0].nValue = 329;
    CheckIsNotStandard(t, "dust");

    // Check future Witness Program versions dust threshold (non-32-byte pushes are undefined for version 1)
    for (int op = OP_1; op <= OP_16; op += 1) {
        t.vout[0].scriptPubKey = CScript() << (opcodetype)op << std::vector<unsigned char>(2, 0);
        t.vout[0].nValue = 240;

        g_mempool_opts.acceptunknownwitness = false;
        CheckIsNotStandard(t, "scriptpubkey-unknown-witnessversion");
        g_mempool_opts.acceptunknownwitness = true;

        CheckIsStandard(t);

        t.vout[0].nValue = 239;
        CheckIsNotStandard(t, "dust");
    }

    // Check anchor outputs
    t.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>{0x4e, 0x73};
    BOOST_CHECK(t.vout[0].scriptPubKey.IsPayToAnchor());
    t.vout[0].nValue = 240;
    CheckIsStandard(t);
    t.vout[0].nValue = 239;
    CheckIsNotStandard(t, "dust");

    // Test permitbareanchor
    g_mempool_opts.permitbareanchor = false;
    t.vout[1].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    t.vout[1].nValue = COIN;
    CheckIsStandard(t);
    t.vout.resize(1);
    CheckIsNotStandard(t, "bare-anchor");
    g_mempool_opts.permitbareanchor = true;
    CheckIsStandard(t);

    // Test permitephemeral
    g_mempool_opts.permitephemeral_anchor = false;
    CheckIsNotStandard(t, "anchor");
    t.vout[0].nValue = 0;
    CheckIsNotStandard(t, "anchor");
    g_mempool_opts.permitephemeral_anchor = true;
    g_mempool_opts.permitephemeral_dust = false;
    CheckIsStandard(t);
    t.vout[0].nValue = 1;
    CheckIsNotStandard(t, "dust-nonzero");
    g_mempool_opts.permitephemeral_dust = true;
    g_mempool_opts.permitephemeral_send = false;
    CheckIsStandard(t);
    t.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    CheckIsNotStandard(t, "dust-nonanchor");
    g_mempool_opts.permitephemeral_send = true;
    CheckIsStandard(t);
}

BOOST_AUTO_TEST_CASE(max_standard_legacy_sigops)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    CKey key;
    key.MakeNewKey(true);

    const kernel::MemPoolOptions mempool_opts{
        .maxtxlegacysigops = 2'500,
    };

    // Create a pathological P2SH script padded with as many sigops as is standard.
    CScript max_sigops_redeem_script{CScript() << std::vector<unsigned char>{} << key.GetPubKey()};
    for (unsigned i{0}; i < MAX_P2SH_SIGOPS - 1; ++i) max_sigops_redeem_script << OP_2DUP << OP_CHECKSIG << OP_DROP;
    max_sigops_redeem_script << OP_CHECKSIG << OP_NOT;
    const CScript max_sigops_p2sh{GetScriptForDestination(ScriptHash(max_sigops_redeem_script))};

    // Create a transaction fanning out as many such P2SH outputs as is standard to spend in a
    // single transaction, and a transaction spending them.
    CMutableTransaction tx_create, tx_max_sigops;
    const unsigned p2sh_inputs_count{mempool_opts.maxtxlegacysigops / MAX_P2SH_SIGOPS};
    tx_create.vout.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_create.vout.emplace_back(424242 + i, max_sigops_p2sh);
    }
    auto prev_txid{tx_create.GetHash()};
    tx_max_sigops.vin.reserve(p2sh_inputs_count);
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i, CScript() << ToByteVector(max_sigops_redeem_script));
    }

    // p2sh_inputs_count is truncated to 166 (from 166.6666..)
    BOOST_CHECK_LE(p2sh_inputs_count * MAX_P2SH_SIGOPS, mempool_opts.maxtxlegacysigops);
    AddCoins(coins, CTransaction(tx_create), 0, false);

    // 2490 sigops is below the limit.
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), p2sh_inputs_count * MAX_P2SH_SIGOPS);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins, mempool_opts));

    // Adding one more input will bump this to 2505, hitting the limit.
    tx_create.vout.emplace_back(424242, max_sigops_p2sh);
    prev_txid = tx_create.GetHash();
    for (unsigned i{0}; i < p2sh_inputs_count; ++i) {
        tx_max_sigops.vin[i] = CTxIn(COutPoint(prev_txid, i), CScript() << ToByteVector(max_sigops_redeem_script));
    }
    tx_max_sigops.vin.emplace_back(prev_txid, p2sh_inputs_count, CScript() << ToByteVector(max_sigops_redeem_script));
    AddCoins(coins, CTransaction(tx_create), 0, false);
    BOOST_CHECK_GT((p2sh_inputs_count + 1) * MAX_P2SH_SIGOPS, mempool_opts.maxtxlegacysigops);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(CTransaction(tx_max_sigops), coins), (p2sh_inputs_count + 1) * MAX_P2SH_SIGOPS);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins, mempool_opts));

    // Now, check the limit can be reached with regular P2PK outputs too. Use a separate
    // preparation transaction, to demonstrate spending coins from a single tx is irrelevant.
    CMutableTransaction tx_create_p2pk;
    const auto p2pk_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    unsigned p2pk_inputs_count{10}; // From 2490 to 2500.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_create_p2pk.vout.emplace_back(212121 + i, p2pk_script);
    }
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count); // Drop the extra input.
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);

    // The transaction now contains exactly 2500 sigops, the check should pass.
    BOOST_CHECK_EQUAL(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, mempool_opts.maxtxlegacysigops);
    BOOST_CHECK(::AreInputsStandard(CTransaction(tx_max_sigops), coins, mempool_opts));

    // Now, add some Segwit inputs. We add one for each defined Segwit output type. The limit
    // is exclusively on non-witness sigops and therefore those should not be counted.
    CMutableTransaction tx_create_segwit;
    const auto witness_script{CScript() << key.GetPubKey() << OP_CHECKSIG};
    tx_create_segwit.vout.emplace_back(121212, GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));
    tx_create_segwit.vout.emplace_back(131313, GetScriptForDestination(WitnessV0ScriptHash(witness_script)));
    tx_create_segwit.vout.emplace_back(141414, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())}));
    prev_txid = tx_create_segwit.GetHash();
    for (unsigned i{0}; i < tx_create_segwit.vout.size(); ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }

    // The transaction now still contains exactly 2500 sigops, the check should pass.
    AddCoins(coins, CTransaction(tx_create_segwit), 0, false);
    BOOST_REQUIRE(::AreInputsStandard(CTransaction(tx_max_sigops), coins, mempool_opts));

    // Add one more P2PK input. We'll reach the limit.
    tx_create_p2pk.vout.emplace_back(212121, p2pk_script);
    prev_txid = tx_create_p2pk.GetHash();
    tx_max_sigops.vin.resize(p2sh_inputs_count);
    ++p2pk_inputs_count;
    for (unsigned i{0}; i < p2pk_inputs_count; ++i) {
        tx_max_sigops.vin.emplace_back(prev_txid, i);
    }
    AddCoins(coins, CTransaction(tx_create_p2pk), 0, false);
    BOOST_CHECK_GT(p2sh_inputs_count * MAX_P2SH_SIGOPS + p2pk_inputs_count * 1, mempool_opts.maxtxlegacysigops);
    BOOST_CHECK(!::AreInputsStandard(CTransaction(tx_max_sigops), coins, mempool_opts));
}

/** Sanity check the return value of SpendsNonAnchorWitnessProg for various output types. */
BOOST_AUTO_TEST_CASE(spends_witness_prog)
{
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey{key.GetPubKey()};
    CMutableTransaction tx_create{}, tx_spend{};
    tx_create.vout.emplace_back(0, CScript{});
    tx_spend.vin.emplace_back(Txid{}, 0);
    std::vector<std::vector<uint8_t>> sol_dummy;

    // CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash,
    // WitnessV1Taproot, PayToAnchor, WitnessUnknown.
    static_assert(std::variant_size_v<CTxDestination> == 9);

    // Go through all defined output types and sanity check SpendsNonAnchorWitnessProg.

    // P2PK
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(PubKeyDestination{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::PUBKEY);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2PKH
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(PKHash{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::PUBKEYHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH
    auto redeem_script{CScript{} << OP_1 << OP_CHECKSIG};
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash{redeem_script});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << OP_0 << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();

    // native P2WSH
    const auto witness_script{CScript{} << OP_12 << OP_HASH160 << OP_DUP << OP_EQUAL};
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash{witness_script});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_V0_SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2WSH
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // native P2WPKH
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessV0KeyHash{pubkey});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_V0_KEYHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2WPKH
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2TR
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{pubkey}});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_V1_TAPROOT);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2TR (undefined, non-standard)
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2A
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(PayToAnchor{});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::ANCHOR);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped P2A (undefined, non-standard)
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();

    // Undefined version 1 witness program
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessUnknown{1, {0x42, 0x42}});
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_UNKNOWN);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // P2SH-wrapped undefined version 1 witness program
    redeem_script = tx_create.vout[0].scriptPubKey;
    tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
    BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
    tx_spend.vin[0].prevout.hash = tx_create.GetHash();
    tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
    AddCoins(coins, CTransaction{tx_create}, 0, false);
    BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    tx_spend.vin[0].scriptSig.clear();
    BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

    // Various undefined version >1 32-byte witness programs.
    const auto program{ToByteVector(XOnlyPubKey{pubkey})};
    for (int i{2}; i <= 16; ++i) {
        tx_create.vout[0].scriptPubKey = GetScriptForDestination(WitnessUnknown{i, program});
        BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::WITNESS_UNKNOWN);
        tx_spend.vin[0].prevout.hash = tx_create.GetHash();
        AddCoins(coins, CTransaction{tx_create}, 0, false);
        BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));

        // It's also detected within P2SH.
        redeem_script = tx_create.vout[0].scriptPubKey;
        tx_create.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(redeem_script));
        BOOST_CHECK_EQUAL(Solver(tx_create.vout[0].scriptPubKey, sol_dummy), TxoutType::SCRIPTHASH);
        tx_spend.vin[0].prevout.hash = tx_create.GetHash();
        tx_spend.vin[0].scriptSig = CScript{} << ToByteVector(redeem_script);
        AddCoins(coins, CTransaction{tx_create}, 0, false);
        BOOST_CHECK(::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
        tx_spend.vin[0].scriptSig.clear();
        BOOST_CHECK(!::SpendsNonAnchorWitnessProg(CTransaction{tx_spend}, coins));
    }
}

BOOST_AUTO_TEST_CASE(tx_DataOutputBytes)
{
    // Block 965,224, tx f93ee9d2a8d6fc0dce7889732d8e288ca64dacfe4c94c6cd76eb85037daea09c:
    // an "ACME" payload in four P2WSH outputs at 330 sat (OLGA framing with a
    // different magic), then a taproot and two P2WPKH change outputs.
    CMutableTransaction acme_mtx;
    BOOST_REQUIRE(DecodeHexTx(acme_mtx, "02000000000104478044ee1b430fea5cb8ff1671b670ef9c5b9ae32eea5baef589514ec0a899e60800000000fdffffffbfc7b0134900db70018a0df2fad0f1e5e142213697e8117900f3a8c5937961eb0200000000fdffffffa5296edb74af3c092e4242f47ebb49e6935b84b5ff8b555dc1df205342a17f570200000000fdffffffb37dc44d0fda93e76e10a567b6e30ff16bc0dd84795210b5de9c70ce61026d3a0000000000fdffffff074a01000000000000220020007741434d4501001400789c0160009fff0110000c464f524745544d454b4e4f4a0100000000000022002054020400080000000000000001030800010004100000050800010006080001004a0100000000000022002007100009746578742f68746d6c08110020780f09eb3c8c53dc0a91ed8777c5194a01000000000000220020d06576f8bfe44a149acd6a56bcc81dca9ef91f18abe4cf51a6000000000000001e24000000000000225120f76c46bc64b22b4643971b7b6f93a552bd99b62ed2903fe7903ba74c8a9938df7803000000000000160014b9034eaf3a6cadd9b8687bdc95fa4e2e696ad349d403000000000000160014f05ca0933738059e830756042263a8d8182b9f24024830450221008bc36479a37702f5abc206931f39efcde9d1f98561ebe3733e97478205c4168a022032a6ba41e4609d7be2dd6120a2f24a10160c7caab3a7721b80b13c1e008e453401210273756d05687e8d9a4002940e915bf699c587553859e88a5b5870c5dce6f87f2f0247304402203a2c81569bef2606deccc47c5968b5f07c3a69fa2e6a060098f78be002d96f3702206a10ffda52252ba0c05c3d9ae92181e3d7806e3de5eb390c9bd6c2e508584c8b01210273756d05687e8d9a4002940e915bf699c587553859e88a5b5870c5dce6f87f2f02483045022100edd2b635984b47243124c6aa4bb30b25940f1bfba3d80af0207574a70911a69902206907be25d22a94746bf49d72f61c17a154cce0beb46f13e2e920da028cfeef2601210273756d05687e8d9a4002940e915bf699c587553859e88a5b5870c5dce6f87f2f02473044022018898be34c777e2b8618fde94260a239085a60fe43b82a2e7d46f7f4476f43e50220373634c96189ee47fa639a134599fd31d8872c421f0f75532caec035e07eb6ff01210273756d05687e8d9a4002940e915bf699c587553859e88a5b5870c5dce6f87f2f00000000"));
    const CTransaction acme{acme_mtx};
    const std::vector<size_t> acme_expect{41, 41, 41, 41, 0, 0, 0};
    const auto acme_bytes{DataOutputBytes(acme)};
    BOOST_CHECK_EQUAL_COLLECTIONS(acme_bytes.begin(), acme_bytes.end(), acme_expect.begin(), acme_expect.end());

    // The whole-transaction count sees the same 164 bytes; the P2WPKH inputs add nothing.
    CCoinsView coins_dummy;
    CCoinsViewCache coins(&coins_dummy);
    const CScript acme_prevout_spk{CScript() << OP_0 << "f05ca0933738059e830756042263a8d8182b9f24"_hex};
    for (const CTxIn& txin : acme.vin) {
        coins.AddCoin(txin.prevout, Coin{CTxOut{1000, acme_prevout_spk}, 1, false}, false);
    }
    const auto acme_dcb{DatacarrierBytes(acme, coins, acme_bytes)};
    BOOST_CHECK_EQUAL(acme_dcb.first, 0U);
    BOOST_CHECK_EQUAL(acme_dcb.second, 164U);
    BOOST_CHECK_EQUAL(CalculateExtraTxWeight(acme, coins, 2 * WITNESS_SCALE_FACTOR, acme_bytes), 164 * WITNESS_SCALE_FACTOR);

    // An OLGA header that also trips a byte tell still counts its whole
    // payload (0x64 = 100 bytes, so four outputs), once: the detector covers
    // header and chunks, so DataOutputBytes leaves them all to it
    std::vector<unsigned char> stamp_header{0x00, 0x64, 's', 't', 'a', 'm', 'p', ':'};
    stamp_header.resize(32, 0);
    CMutableTransaction olga_mtx;
    for (const auto& program : {stamp_header, "e9f85819906b6bc0b5f5d902c68cd2298679883ce2b3f8552b029f462c0a0d17"_hex_v_u8, "becb6d3c0662dca214c45cde70e4ce022ade14bac12bfed3aa4811b5b3bde49f"_hex_v_u8, "e2c8d6303cf2cad3a00e0ec1b61aa1355c32dca119c357f5e7ad499781052e3f"_hex_v_u8}) {
        olga_mtx.vout.emplace_back(olga_mtx.vout.empty() ? 330 : 1000, CScript() << OP_0 << program);
    }
    const CTransaction olga{olga_mtx};
    const std::vector<size_t> olga_expect{0, 0, 0, 0};
    const auto olga_bytes{DataOutputBytes(olga)};
    BOOST_CHECK_EQUAL_COLLECTIONS(olga_bytes.begin(), olga_bytes.end(), olga_expect.begin(), olga_expect.end());
    BOOST_CHECK_EQUAL(DatacarrierBytes(olga, coins, olga_bytes).second, 164U);
    BOOST_CHECK_EQUAL(CalculateExtraTxWeight(olga, coins, 2 * WITNESS_SCALE_FACTOR, olga_bytes), 164 * WITNESS_SCALE_FACTOR);
    // The same stamp with its chunks at the threshold, the real layout: still
    // 164, not 164 plus three chunks caught by the dust run
    for (CTxOut& txout : olga_mtx.vout) txout.nValue = 330;
    const CTransaction olga_dust{olga_mtx};
    const auto olga_dust_bytes{DataOutputBytes(olga_dust)};
    BOOST_CHECK_EQUAL_COLLECTIONS(olga_dust_bytes.begin(), olga_dust_bytes.end(), olga_expect.begin(), olga_expect.end());
    BOOST_CHECK_EQUAL(DatacarrierBytes(olga_dust, coins, olga_dust_bytes).second, 164U);

    // Random 32-byte hashes and x-only keys (on and off the curve)
    const std::vector<unsigned char> hash_a{"e9f85819906b6bc0b5f5d902c68cd2298679883ce2b3f8552b029f462c0a0d17"_hex_v_u8};
    const std::vector<unsigned char> hash_b{"becb6d3c0662dca214c45cde70e4ce022ade14bac12bfed3aa4811b5b3bde49f"_hex_v_u8};
    const std::vector<unsigned char> hash_c{"e2c8d6303cf2cad3a00e0ec1b61aa1355c32dca119c357f5e7ad499781052e3f"_hex_v_u8};
    const std::vector<unsigned char> hash_d{"af6adc4480e64dd58e59424f43b6144267d1c4347a58ad0f09013fb9053b307b"_hex_v_u8};
    const std::vector<unsigned char> hash_e{"02c7539d864d18c81557338387d5300f60cb8cc75054c2cfc985ddc401269122"_hex_v_u8};
    const std::vector<unsigned char> key_on_a{"9f537de0a7f7403067880d3d62d3f8d20889c4f77b74b612406d7d5ce0a9b206"_hex_v_u8};
    const std::vector<unsigned char> key_on_b{"4d6abe64a78cd5dcb98a719490753a84a061274cc6f7ecefea0aedad967676ba"_hex_v_u8};
    const std::vector<unsigned char> key_off{"4420f4cd273fe68ccc6df6aaf1bd40d6f879884882386754e2c2e55cfad0b0bb"_hex_v_u8};
    const auto p2wsh = [](const std::vector<unsigned char>& program) { return CScript() << OP_0 << program; };
    const auto p2tr = [](const std::vector<unsigned char>& key) { return CScript() << OP_1 << key; };
    const auto check = [](const CMutableTransaction& mtx, const std::vector<size_t>& expect) {
        const auto got{DataOutputBytes(CTransaction{mtx})};
        BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), expect.begin(), expect.end());
    };
    CMutableTransaction t;

    // A Lightning commitment: two 330-sat anchors, to_local, to_remote, a small HTLC
    t.vout = {CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_b)}, CTxOut{50000, p2wsh(hash_c)}, CTxOut{70000, p2wsh(hash_d)}, CTxOut{400, p2wsh(hash_e)}};
    check(t, {0, 0, 0, 0, 0});

    // A third P2WSH output at the dust threshold makes a data run
    t.vout = {CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_b)}, CTxOut{330, p2wsh(hash_c)}, CTxOut{100000, p2wsh(hash_d)}};
    check(t, {41, 41, 41, 0});
    // One sat above the threshold breaks it
    t.vout[2].nValue = 331;
    check(t, {0, 0, 0, 0});
    // The run counts distinct scripts: padding or consolidation that repeats
    // one script at the threshold is not a spread payload
    t.vout = {CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_b)}};
    check(t, {0, 0, 0, 0});
    t.vout.emplace_back(330, p2wsh(hash_c));
    check(t, {41, 41, 41, 41, 41});
    // Taproot runs count the same way, mixed types do not add up
    t.vout = {CTxOut{330, p2tr(key_on_a)}, CTxOut{330, p2tr(key_on_b)}, CTxOut{330, p2tr(key_off)}};
    check(t, {41, 41, 41});
    t.vout = {CTxOut{330, p2wsh(hash_a)}, CTxOut{330, p2wsh(hash_b)}, CTxOut{330, p2tr(key_on_a)}};
    check(t, {0, 0, 0});

    // A taproot key that is not on the curve can never be spent
    t.vout = {CTxOut{100000, p2tr(key_off)}};
    check(t, {41});
    t.vout = {CTxOut{100000, p2tr(key_on_a)}};
    check(t, {0});
    // Only the first DATA_OUTPUT_CURVE_CHECKS taproot outputs are checked
    t.vout.assign(DATA_OUTPUT_CURVE_CHECKS - 1, CTxOut{1000, p2tr(key_on_a)});
    t.vout.emplace_back(2000, p2tr(key_off));
    std::vector<size_t> capped(DATA_OUTPUT_CURVE_CHECKS, 0);
    capped.back() = 41;
    check(t, capped);
    t.vout.insert(t.vout.begin(), CTxOut{1000, p2tr(key_on_b)});
    capped.assign(DATA_OUTPUT_CURVE_CHECKS + 1, 0);
    check(t, capped);

    // Eight of one byte value trips the multiplicity tell, seven do not
    std::vector<unsigned char> program{hash_a};
    for (size_t k{0}; k < 8; ++k) program[4 * k] = 0x5a;
    t.vout = {CTxOut{100000, p2wsh(program)}};
    check(t, {41});
    program = hash_a;
    for (size_t k{0}; k < 7; ++k) program[4 * k] = 0x5a;
    t.vout = {CTxOut{100000, p2wsh(program)}};
    check(t, {0});

    // Six identical bytes in a row trip the run tell, five do not
    std::vector<unsigned char> run6{hash_b};
    std::fill(run6.begin() + 10, run6.begin() + 16, 0x77);
    t.vout = {CTxOut{100000, p2wsh(run6)}};
    check(t, {41});
    program = hash_b;
    std::fill(program.begin() + 10, program.begin() + 15, 0x77);
    t.vout = {CTxOut{100000, p2wsh(program)}};
    check(t, {0});

    // A caught chunk marks its siblings of the same type and value, nothing else
    t.vout = {CTxOut{1000, p2wsh(hash_c)}, CTxOut{1000, p2wsh(run6)}, CTxOut{1000, p2wsh(hash_d)}, CTxOut{2000, p2wsh(hash_e)}, CTxOut{1000, p2tr(key_on_a)}};
    check(t, {41, 41, 41, 0, 0});

    // 20-byte hashes get the same tells: the all-zero burn address is data, and
    // a random hash at the same value is marked as its sibling, at another value not
    const CScript burn{CScript() << OP_0 << std::vector<unsigned char>(20, 0)};
    const CScript p2wpkh{CScript() << OP_0 << std::vector<unsigned char>(hash_a.begin(), hash_a.begin() + 20)};
    t.vout = {CTxOut{294, burn}, CTxOut{294, p2wpkh}};
    check(t, {29, 29});
    t.vout = {CTxOut{294, burn}, CTxOut{500, p2wpkh}};
    check(t, {29, 0});
}

BOOST_AUTO_TEST_SUITE_END()
