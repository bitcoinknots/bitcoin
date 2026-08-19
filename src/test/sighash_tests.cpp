// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <streams.h>
#include <test/data/unified_sighash.json.h>
#include <test/data/sighash.json.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Old script.cpp SignatureHash function
uint256 static SignatureHashOld(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        return uint256::ONE;
    }
    CMutableTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    FindAndDelete(scriptCode, CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lock-in the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            return uint256::ONE;
        }
        txTmp.vout.resize(nOut+1);
        for (unsigned int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    HashWriter ss{};
    ss << TX_NO_WITNESS(txTmp) << nHashType;
    return ss.GetHash();
}

struct SigHashTest : BasicTestingSetup {
void RandomScript(CScript &script) {
    static const opcodetype oplist[] = {OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR};
    script = CScript();
    int ops = (m_rng.randrange(10));
    for (int i=0; i<ops; i++)
        script << oplist[m_rng.randrange(std::size(oplist))];
}

void RandomTransaction(CMutableTransaction& tx, bool fSingle)
{
    tx.version = m_rng.rand32();
    tx.vin.clear();
    tx.vout.clear();
    tx.nLockTime = (m_rng.randbool()) ? m_rng.rand32() : 0;
    int ins = (m_rng.randbits(2)) + 1;
    int outs = fSingle ? ins : (m_rng.randbits(2)) + 1;
    for (int in = 0; in < ins; in++) {
        tx.vin.emplace_back();
        CTxIn &txin = tx.vin.back();
        txin.prevout.hash = Txid::FromUint256(m_rng.rand256());
        txin.prevout.n = m_rng.randbits(2);
        RandomScript(txin.scriptSig);
        txin.nSequence = (m_rng.randbool()) ? m_rng.rand32() : std::numeric_limits<uint32_t>::max();
    }
    for (int out = 0; out < outs; out++) {
        tx.vout.emplace_back();
        CTxOut &txout = tx.vout.back();
        txout.nValue = RandMoney(m_rng);
        RandomScript(txout.scriptPubKey);
    }
}
}; // struct SigHashTest

BOOST_FIXTURE_TEST_SUITE(sighash_tests, SigHashTest)

BOOST_AUTO_TEST_CASE(sighash_test)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif
    for (int i=0; i<nRandomTests; i++) {
        int nHashType{int(m_rng.rand32())};
        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & 0x1f) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = m_rng.randrange(txTo.vin.size());

        uint256 sh, sho;
        sho = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashType);
        sh = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::BASE);
        #if defined(PRINT_SIGHASH_JSON)
        DataStream ss;
        ss << TX_WITH_WITNESS(txTo);

        std::cout << "\t[\"" ;
        std::cout << HexStr(ss) << "\", \"";
        std::cout << HexStr(scriptCode) << "\", ";
        std::cout << nIn << ", ";
        std::cout << nHashType << ", \"";
        std::cout << sho.GetHex() << "\"]";
        if (i+1 != nRandomTests) {
          std::cout << ",";
        }
        std::cout << "\n";
        #endif
        BOOST_CHECK(sh == sho);
    }
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

// Goal: check that SignatureHash generates correct hash
BOOST_AUTO_TEST_CASE(sighash_from_data)
{
    UniValue tests = read_json(json_tests::sighash);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        if (test.size() == 1) continue; // comment

        std::string raw_tx, raw_script, sigHashHex;
        int nIn, nHashType;
        uint256 sh;
        CTransactionRef tx;
        CScript scriptCode = CScript();

        try {
          // deserialize test data
          raw_tx = test[0].get_str();
          raw_script = test[1].get_str();
          nIn = test[2].getInt<int>();
          nHashType = test[3].getInt<int>();
          sigHashHex = test[4].get_str();

          DataStream stream(ParseHex(raw_tx));
          stream >> TX_WITH_WITNESS(tx);

          TxValidationState state;
          BOOST_CHECK_MESSAGE(CheckTransaction(*tx, state), strTest);
          BOOST_CHECK(state.IsValid());

          std::vector<unsigned char> raw = ParseHex(raw_script);
          scriptCode.insert(scriptCode.end(), raw.begin(), raw.end());
        } catch (...) {
          BOOST_ERROR("Bad test, couldn't deserialize data: " << strTest);
          continue;
        }

        sh = SignatureHash(scriptCode, *tx, nIn, nHashType, 0, SigVersion::BASE);
        BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
    }
}

BOOST_AUTO_TEST_CASE(sighash_caching)
{
    // Get a script, transaction and parameters as inputs to the sighash function.
    CScript scriptcode;
    RandomScript(scriptcode);
    CScript diff_scriptcode{scriptcode};
    diff_scriptcode << OP_1;
    CMutableTransaction tx;
    RandomTransaction(tx, /*fSingle=*/false);
    const auto in_index{static_cast<uint32_t>(m_rng.randrange(tx.vin.size()))};
    const auto amount{m_rng.rand<CAmount>()};

    // Exercise the sighash function under both legacy and segwit v0.
    for (const auto sigversion: {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        // For each, run it against all the 6 standard hash types and a few additional random ones.
        std::vector<int32_t> hash_types{{SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                                          SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                                          SIGHASH_ANYONECANPAY, 0, std::numeric_limits<int32_t>::max()}};
        for (int i{0}; i < 10; ++i) {
            hash_types.push_back(i % 2 == 0 ? m_rng.rand<int8_t>() : m_rng.rand<int32_t>());
        }

        // Reuse the same cache across script types. This must not cause any issue as the cached value for one hash type must never
        // be confused for another (instantiating the cache within the loop instead would prevent testing this).
        SigHashCache cache;
        for (const auto hash_type: hash_types) {
            const bool expect_one{sigversion == SigVersion::BASE && ((hash_type & 0x1f) == SIGHASH_SINGLE) && in_index >= tx.vout.size()};

            // The result of computing the sighash should be the same with or without cache.
            const auto sighash_with_cache{SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache)};
            const auto sighash_no_cache{SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, nullptr)};
            BOOST_CHECK_EQUAL(sighash_with_cache, sighash_no_cache);

            // Calling the cached version again should return the same value again.
            BOOST_CHECK_EQUAL(sighash_with_cache, SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache));

            // While here we might as well also check that the result for legacy is the same as for the old SignatureHash() function.
            if (sigversion == SigVersion::BASE) {
                BOOST_CHECK_EQUAL(sighash_with_cache, SignatureHashOld(scriptcode, CTransaction(tx), in_index, hash_type));
            }

            // Calling with a different scriptcode (for instance in case a CODESEP is encountered) will not return the cache value but
            // overwrite it. The sighash will always be different except in case of legacy SIGHASH_SINGLE bug.
            const auto sighash_with_cache2{SignatureHash(diff_scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache)};
            const auto sighash_no_cache2{SignatureHash(diff_scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, nullptr)};
            BOOST_CHECK_EQUAL(sighash_with_cache2, sighash_no_cache2);
            if (!expect_one) {
                BOOST_CHECK_NE(sighash_with_cache, sighash_with_cache2);
            } else {
                BOOST_CHECK_EQUAL(sighash_with_cache, sighash_with_cache2);
                BOOST_CHECK_EQUAL(sighash_with_cache, uint256::ONE);
            }

            // Calling the cached version again should return the same value again.
            BOOST_CHECK_EQUAL(sighash_with_cache2, SignatureHash(diff_scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache));

            // And if we store a different value for this scriptcode and hash type it will return that instead.
            {
                HashWriter h{};
                h << 42;
                cache.Store(hash_type, scriptcode, h);
                const auto stored_hash{h.GetHash()};
                BOOST_CHECK(cache.Load(hash_type, scriptcode, h));
                const auto loaded_hash{h.GetHash()};
                BOOST_CHECK_EQUAL(stored_hash, loaded_hash);
            }

            // And using this mutated cache with the sighash function will return the new value (except in the legacy SIGHASH_SINGLE bug
            // case in which it'll return 1).
            if (!expect_one) {
                BOOST_CHECK_NE(SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache), sighash_with_cache);
                HashWriter h{};
                BOOST_CHECK(cache.Load(hash_type, scriptcode, h));
                h << hash_type;
                const auto new_hash{h.GetHash()};
                BOOST_CHECK_EQUAL(SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache), new_hash);
            } else {
                BOOST_CHECK_EQUAL(SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache), uint256::ONE);
            }

            // Wipe the cache and restore the correct cached value for this scriptcode and hash_type before starting the next iteration.
            HashWriter dummy{};
            cache.Store(hash_type, diff_scriptcode, dummy);
            (void)SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion, nullptr, &cache);
            BOOST_CHECK(cache.Load(hash_type, scriptcode, dummy) || expect_one);
        }
    }
}

/** Build a two-input, two-output transaction plus the outputs it spends. */
static void BuildUnifiedTestTx(CMutableTransaction& tx, std::vector<CTxOut>& spent, const CScript& script0, const CScript& script1)
{
    tx.version = 2;
    tx.nLockTime = 17;
    tx.vin.resize(2);
    tx.vout.resize(2);
    for (int i = 0; i < 2; ++i) {
        tx.vin[i].prevout = COutPoint(Txid::FromUint256(uint256{uint8_t(i + 1)}), i);
        tx.vin[i].nSequence = 0xfffffffe;
        tx.vout[i].nValue = 1000 * (i + 1);
        tx.vout[i].scriptPubKey = CScript() << OP_TRUE;
    }
    spent.clear();
    spent.emplace_back(5000, script0);
    spent.emplace_back(7000, script1);
}

static PrecomputedTransactionData MakeUnifiedTxdata(const CMutableTransaction& tx, std::vector<CTxOut> spent)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent), /*force=*/true);
    return txdata;
}

BOOST_AUTO_TEST_CASE(unified_sighash_replay_protection)
{
    const CScript script0{CScript() << OP_1 << OP_CHECKSIG};
    const CScript script1{CScript() << OP_2 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script0, script1);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    for (const SigVersion sv : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        uint256 hf;
        BOOST_CHECK(SignatureHashUnified(hf, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, sv, txdata));
        const uint256 legacy{SignatureHash(script0, tx, 0, SIGHASH_ALL, spent[0].nValue, sv, &txdata)};
        // A signature made under one rule set is a signature over a different
        // message under the other, which is what protects against replay.
        BOOST_CHECK_NE(hf, legacy);
    }

    // The two script types are also separated from each other.
    uint256 base_hash, witness_hash;
    BOOST_CHECK(SignatureHashUnified(base_hash, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, txdata));
    BOOST_CHECK(SignatureHashUnified(witness_hash, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, txdata));
    BOOST_CHECK_NE(base_hash, witness_hash);
}

BOOST_AUTO_TEST_CASE(unified_sighash_activation_invalidates_a_legacy_opt_in_byte)
{
    // The one thing activation takes away. A legacy signature whose hash type
    // byte already carries the opt-in bit is valid today: the legacy algorithm
    // reads 0x21 by its low bits and treats it as ALL. Once the rules are in
    // force that same byte means the signature opted in, so it is checked
    // against the unified message and stops verifying. This is what the
    // mempool has to evict when the chain crosses the activation height, in
    // either direction.
    const CScript script0{CScript() << OP_1 << OP_CHECKSIG};
    const CScript script1{CScript() << OP_2 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script0, script1);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    for (const SigVersion sv : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        // What a pre-fork signer committed to. The legacy algorithm serializes
        // the whole byte and then selects outputs by its low bits, so 0x21 has
        // a message of its own and spends as ALL.
        const uint256 before{SignatureHash(script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED,
                                           spent[0].nValue, sv, &txdata)};
        BOOST_CHECK_NE(before,
                       SignatureHash(script0, tx, 0, SIGHASH_ALL, spent[0].nValue, sv, &txdata));

        // What a verifier computes for that same byte once the rules apply.
        uint256 after;
        BOOST_CHECK(SignatureHashUnified(after, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, sv, txdata));

        // Different messages, so the old signature no longer verifies. A
        // checker that wrongly fell back to the legacy hash would make these
        // equal and this test would catch it.
        BOOST_CHECK_NE(before, after);
    }
}

BOOST_AUTO_TEST_CASE(unified_sighash_commits_to_all_spent_outputs)
{
    const CScript script0{CScript() << OP_1 << OP_CHECKSIG};
    const CScript script1{CScript() << OP_2 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script0, script1);

    std::vector<CTxOut> lying{spent};
    lying[1].nValue += 100000; // misreport a different input's value

    const auto honest_data{MakeUnifiedTxdata(tx, spent)};
    const auto lying_data{MakeUnifiedTxdata(tx, lying)};

    // This is CVE-2020-14199: under BIP143 the sighash for input 0 does not
    // depend on input 1's amount, so a signer can be lied to about it and the
    // resulting signature stays valid.
    const uint256 legacy_honest{SignatureHash(script0, tx, 0, SIGHASH_ALL, spent[0].nValue, SigVersion::WITNESS_V0, &honest_data)};
    const uint256 legacy_lying{SignatureHash(script0, tx, 0, SIGHASH_ALL, spent[0].nValue, SigVersion::WITNESS_V0, &lying_data)};
    BOOST_CHECK_EQUAL(legacy_honest, legacy_lying);

    // Under the hardfork sighash the lie changes the message, so the signature
    // does not carry over.
    uint256 hf_honest, hf_lying;
    BOOST_CHECK(SignatureHashUnified(hf_honest, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, honest_data));
    BOOST_CHECK(SignatureHashUnified(hf_lying, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, lying_data));
    BOOST_CHECK_NE(hf_honest, hf_lying);

    // The same holds for a lie about another input's scriptPubKey.
    std::vector<CTxOut> lying_script{spent};
    lying_script[1].scriptPubKey = CScript() << OP_3 << OP_CHECKSIG;
    const auto lying_script_data{MakeUnifiedTxdata(tx, lying_script)};
    uint256 hf_lying_script;
    BOOST_CHECK(SignatureHashUnified(hf_lying_script, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, lying_script_data));
    BOOST_CHECK_NE(hf_honest, hf_lying_script);
}

BOOST_AUTO_TEST_CASE(unified_sighash_single_out_of_range_fails)
{
    const CScript script0{CScript() << OP_1 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script0, script0);
    tx.vout.resize(1); // input 1 now has no corresponding output
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    uint256 hash;
    // Legacy returns the sentinel 1, which a signature can match: the
    // SIGHASH_SINGLE bug. The hardfork sighash reports failure instead.
    BOOST_CHECK_EQUAL(SignatureHash(script0, tx, 1, SIGHASH_SINGLE, spent[1].nValue, SigVersion::BASE, &txdata), uint256::ONE);
    BOOST_CHECK(!SignatureHashUnified(hash, script0, tx, 1, SIGHASH_SINGLE | SIGHASH_UNIFIED, SigVersion::BASE, txdata));
    // In range it still works.
    BOOST_CHECK(SignatureHashUnified(hash, script0, tx, 0, SIGHASH_SINGLE | SIGHASH_UNIFIED, SigVersion::BASE, txdata));
}

BOOST_AUTO_TEST_CASE(unified_sighash_needs_spent_outputs)
{
    const CScript script0{CScript() << OP_1 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script0, script0);

    // Without the spent outputs the sighash cannot be computed, and must fail
    // rather than fall back to a message a legacy signature would match.
    PrecomputedTransactionData bare;
    bare.Init(tx, {});
    uint256 hash;
    BOOST_CHECK(!SignatureHashUnified(hash, script0, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, bare));
}

BOOST_AUTO_TEST_CASE(unified_sighash_sign_and_verify_roundtrip)
{
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_CHECK(keystore.AddKey(key));
    const CScript spk{GetScriptForRawPubKey(key.GetPubKey())};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    auto verify = [&](const CMutableTransaction& t, bool hf) {
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        // The rules travel in the script flags; the checker carries no copy.
        const unsigned int flags{SCRIPT_VERIFY_P2SH | (hf ? uint32_t{SCRIPT_VERIFY_UNIFIED_SIGHASH} : uint32_t{0})};
        return VerifyScript(t.vin[0].scriptSig, spk, nullptr, flags, checker, &err);
    };

    // Sign under the hardfork rules, for every hash type the opt-in bit defines.
    // SIGHASH_SINGLE takes a different path through the message than the others,
    // and after the BIP341 relayout it commits in the tail rather than with the
    // aggregates, so signing it is worth exercising and not only hashing it.
    for (const int32_t base_type : {SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE}) {
        for (const int32_t anyonecanpay : {int32_t{0}, int32_t{SIGHASH_ANYONECANPAY}}) {
            const int32_t hash_type{base_type | anyonecanpay};
            CMutableTransaction unified_tx{tx};
            SignatureData hf_sigdata;
            MutableTransactionSignatureCreator hf_creator{unified_tx, 0, spent[0].nValue, &txdata, hash_type};
            hf_creator.SetSighashRules(SighashRules::UNIFIED);
            BOOST_CHECK_MESSAGE(ProduceSignature(keystore, hf_creator, spk, hf_sigdata),
                                strprintf("hash type %#x should be signable", hash_type));
            UpdateInput(unified_tx.vin[0], hf_sigdata);

            // Signing and validation agree, and the signature is worthless to a
            // node running the old rules.
            BOOST_CHECK_MESSAGE(verify(unified_tx, /*hf=*/true),
                                strprintf("hash type %#x should verify under the fork", hash_type));
            BOOST_CHECK_MESSAGE(!verify(unified_tx, /*hf=*/false),
                                strprintf("hash type %#x must not verify under the legacy rules", hash_type));
        }
    }

    // Sign under the legacy rules.
    CMutableTransaction legacy_tx{tx};
    SignatureData legacy_sigdata;
    MutableTransactionSignatureCreator legacy_creator{legacy_tx, 0, spent[0].nValue, &txdata, SIGHASH_ALL};
    BOOST_CHECK(ProduceSignature(keystore, legacy_creator, spk, legacy_sigdata));
    UpdateInput(legacy_tx.vin[0], legacy_sigdata);

    // ...and it stays valid after activation: the legacy algorithm is
    // unchanged, so a spender who never sets the bit is unaffected.
    BOOST_CHECK(verify(legacy_tx, /*hf=*/false));
    BOOST_CHECK(verify(legacy_tx, /*hf=*/true));
}

BOOST_AUTO_TEST_CASE(unified_sighash_taproot_keypath_roundtrip)
{
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_CHECK(keystore.AddKey(key));
    const XOnlyPubKey xpk{key.GetPubKey()};

    TaprootBuilder builder;
    builder.Finalize(xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};
    const uint256 merkle_root{};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    auto verify = [&](const CMutableTransaction& t, bool hf) {
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
                                 (hf ? uint32_t{SCRIPT_VERIFY_UNIFIED_SIGHASH} : uint32_t{0})};
        return VerifyScript(t.vin[0].scriptSig, spk, &t.vin[0].scriptWitness, flags, checker, &err);
    };

    auto sign = [&](CMutableTransaction& t, bool hf, int hashtype) {
        MutableTransactionSignatureCreator creator{t, 0, spent[0].nValue, &txdata, hashtype};
        creator.SetSighashRules(hf ? SighashRules::UNIFIED : SighashRules::LEGACY);
        std::vector<unsigned char> sig;
        if (!creator.CreateSchnorrSig(keystore, sig, xpk, nullptr, &merkle_root, SigVersion::TAPROOT)) return false;
        t.vin[0].scriptWitness.stack = {sig};
        return true;
    };

    // Opting in. BIP341 already commits the hash type byte, so setting the bit
    // is enough to move the message; no new format is involved.
    CMutableTransaction unified_tx{tx};
    BOOST_CHECK(sign(unified_tx, /*hf=*/true, SIGHASH_DEFAULT));
    BOOST_CHECK_EQUAL(unified_tx.vin[0].scriptWitness.stack[0].size(), 65U);
    BOOST_CHECK_EQUAL(unified_tx.vin[0].scriptWitness.stack[0].back(), SIGHASH_UNIFIED | SIGHASH_ALL);
    BOOST_CHECK(verify(unified_tx, /*hf=*/true));
    // A node that has not activated the fork rejects the byte as an undefined
    // hash type, which is what stops the spend being replayed there.
    BOOST_CHECK(!verify(unified_tx, /*hf=*/false));

    // Existing taproot spends keep working after activation, unchanged.
    CMutableTransaction legacy_tx{tx};
    BOOST_CHECK(sign(legacy_tx, /*hf=*/false, SIGHASH_DEFAULT));
    BOOST_CHECK_EQUAL(legacy_tx.vin[0].scriptWitness.stack[0].size(), 64U);
    BOOST_CHECK(verify(legacy_tx, /*hf=*/false));
    BOOST_CHECK(verify(legacy_tx, /*hf=*/true));

    // Every output type carries the bit, and each is rejected without the fork.
    for (const int base_type : {SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE}) {
        for (const int acp : {0, int{SIGHASH_ANYONECANPAY}}) {
            CMutableTransaction t{tx};
            BOOST_CHECK(sign(t, /*hf=*/true, base_type | acp));
            BOOST_CHECK_EQUAL(t.vin[0].scriptWitness.stack[0].back(), SIGHASH_UNIFIED | base_type | acp);
            BOOST_CHECK(verify(t, /*hf=*/true));
            BOOST_CHECK(!verify(t, /*hf=*/false));
        }
    }
}

BOOST_AUTO_TEST_CASE(unified_sighash_taproot_hashtype_sweep)
{
    // Every one of the 256 hash type bytes, for a taproot input. Two properties
    // matter and neither is safe to take on faith:
    //
    //   1. BIP341 is untouched. It accepts exactly the bytes it always did, so
    //      no spend that exists today changes meaning, and it never accepts an
    //      opted-in byte. That second half is the replay protection: a node
    //      that has not activated the fork computes BIP341 and refuses.
    //   2. For taproot the unified algorithm accepts exactly the six opted-in
    //      bytes, and produces a different message than BIP341 does for each.
    const CKey key{GenerateRandomKey()};
    const XOnlyPubKey xpk{key.GetPubKey()};
    TaprootBuilder builder;
    builder.Finalize(xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    BOOST_REQUIRE(!tx.vout.empty()); // SIGHASH_SINGLE needs a matching output.
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    auto fresh_execdata = [] {
        ScriptExecutionData e;
        e.m_annex_init = true;
        e.m_annex_present = false;
        return e;
    };

    int opted_in_accepted{0};
    for (int i = 0; i < 256; ++i) {
        const uint8_t hash_type(i);
        const bool bip341_defined{hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83)};
        const uint8_t base_type(hash_type & ~SIGHASH_UNIFIED);
        // Taproot keeps BIP341's reading, so the opted-in bytes it accepts are
        // exactly the ones BIP341 defines with the bit added. The legacy
        // fallthrough applies to bare, P2SH and segwit v0, not here.
        const bool opt_in_defined{(hash_type & SIGHASH_UNIFIED) &&
                                  ((base_type >= 0x01 && base_type <= 0x03) ||
                                   (base_type >= 0x81 && base_type <= 0x83))};

        ScriptExecutionData ed_bip341{fresh_execdata()}, ed_hf{fresh_execdata()};
        uint256 bip341_hash, hf_hash;
        const bool got_bip341{SignatureHashSchnorr(bip341_hash, ed_bip341, tx, 0, hash_type,
                                                   SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)};
        const bool got_hf{SignatureHashUnified(hf_hash, CScript{}, tx, 0, hash_type,
                                          SigVersion::TAPROOT, txdata, &ed_hf)};

        // 1. BIP341 unchanged, and blind to the opt-in bit in either direction.
        BOOST_CHECK_EQUAL(got_bip341, bip341_defined);
        // 2. The unified algorithm takes the opted-in bytes and nothing else.
        BOOST_CHECK_EQUAL(got_hf, opt_in_defined);

        // 3. The same acceptance rule for a script path spend. Run separately
        // because a tapscript message needs the leaf and separator, and a check
        // narrowed to the key path would pass on the key-path sweep alone.
        ScriptExecutionData ed_tapscript{fresh_execdata()};
        ed_tapscript.m_tapleaf_hash_init = true;
        ed_tapscript.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, CScript{} << OP_1);
        ed_tapscript.m_codeseparator_pos_init = true;
        ed_tapscript.m_codeseparator_pos = 0xFFFFFFFFUL;
        uint256 tapscript_hash;
        const bool got_tapscript{SignatureHashUnified(tapscript_hash, CScript{}, tx, 0, hash_type,
                                                      SigVersion::TAPSCRIPT, txdata, &ed_tapscript)};
        BOOST_CHECK_EQUAL(got_tapscript, opt_in_defined);
        if (opt_in_defined) {
            // A script path spend commits to the leaf, so it must not collide
            // with the key path message for the same byte.
            BOOST_CHECK(tapscript_hash != hf_hash);
        }

        if (opt_in_defined) {
            ++opted_in_accepted;
            // Where the byte without the opt-in bit is itself a BIP341 type, that
            // spend is still valid there and the two messages differ, which is
            // what makes an opted-in spend unusable on a chain without the fork.
            const bool base_is_bip341{base_type <= 0x03 || (base_type >= 0x81 && base_type <= 0x83)};
            if (base_is_bip341) {
                uint256 legacy_msg;
                ScriptExecutionData ed_legacy{fresh_execdata()};
                BOOST_CHECK(SignatureHashSchnorr(legacy_msg, ed_legacy, tx, 0, base_type,
                                                 SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
                BOOST_CHECK(hf_hash != legacy_msg);
            }
        }
    }
    // 0x21-0x23 and 0xa1-0xa3, and nothing else.
    BOOST_CHECK_EQUAL(opted_in_accepted, 6);
}

BOOST_AUTO_TEST_CASE(unified_sighash_annex_is_wired_to_the_interpreter)
{
    // Elsewhere the annex commitment is shown to move the message when it is
    // set by hand. That is not the same claim as the interpreter deriving the
    // right value from a real witness, which is what consensus depends on, so
    // this spends an output with an annex actually present.
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_CHECK(keystore.AddKey(key));
    const XOnlyPubKey xpk{key.GetPubKey()};
    TaprootBuilder builder;
    builder.Finalize(xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};
    const uint256 merkle_root{};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    // BIP341: a final witness element beginning with 0x50 is the annex.
    const std::vector<unsigned char> annex{0x50, 0x01, 0x02, 0x03};

    auto sign_committing_to = [&](const std::vector<unsigned char>& committed_annex, bool present) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = present;
        if (present) execdata.m_annex_hash = (HashWriter{} << committed_annex).GetSHA256();
        uint256 hash;
        BOOST_REQUIRE(SignatureHashUnified(hash, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED,
                                      SigVersion::TAPROOT, txdata, &execdata));
        std::vector<unsigned char> sig(64);
        BOOST_REQUIRE(key.SignSchnorr(hash, sig, &merkle_root, {}));
        sig.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);
        return sig;
    };
    auto verify = [&](const std::vector<unsigned char>& sig, bool attach_annex,
                      const std::vector<unsigned char>& which) {
        CMutableTransaction t{tx};
        t.vin[0].scriptWitness.stack = attach_annex ? std::vector<std::vector<unsigned char>>{sig, which}
                                                    : std::vector<std::vector<unsigned char>>{sig};
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        return VerifyScript(t.vin[0].scriptSig, spk, &t.vin[0].scriptWitness,
                            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_UNIFIED_SIGHASH,
                            checker, &err);
    };

    // Signed committing to this annex, and spent with it: the interpreter must
    // have derived the same hash the signer did.
    const auto sig_with_annex{sign_committing_to(annex, true)};
    BOOST_CHECK(verify(sig_with_annex, /*attach_annex=*/true, annex));

    // The annex cannot be changed in flight.
    const std::vector<unsigned char> other_annex{0x50, 0x09, 0x09};
    BOOST_CHECK(!verify(sig_with_annex, /*attach_annex=*/true, other_annex));

    // Nor removed.
    BOOST_CHECK(!verify(sig_with_annex, /*attach_annex=*/false, annex));

    // Nor added to a signature that did not commit to one. Control: that same
    // signature spends when no annex is attached, so the rejection above is the
    // annex commitment rather than a broken signature.
    const auto sig_without_annex{sign_committing_to({}, false)};
    BOOST_CHECK(verify(sig_without_annex, /*attach_annex=*/false, annex));
    BOOST_CHECK(!verify(sig_without_annex, /*attach_annex=*/true, annex));
}

BOOST_AUTO_TEST_CASE(unified_sighash_codeseparator_is_wired_to_the_interpreter)
{
    // Same distinction as the annex: setting the position by hand and watching
    // the message move is not the same as the interpreter recording the
    // position of an OP_CODESEPARATOR it actually executed. This spends a leaf
    // containing one, so only a signature made over the recorded position can
    // satisfy it.
    const CKey key{GenerateRandomKey()};
    const XOnlyPubKey xpk{key.GetPubKey()};

    // Position is counted per opcode from zero, so the pubkey push is 0 and the
    // separator is 1.
    const CScript leaf{CScript() << ToByteVector(xpk) << OP_CODESEPARATOR << OP_CHECKSIG};
    constexpr uint32_t EXPECTED_POS{1};

    const CKey internal{GenerateRandomKey()};
    TaprootBuilder builder;
    builder.Add(0, leaf, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(XOnlyPubKey{internal.GetPubKey()});
    const CScript spk{GetScriptForDestination(builder.GetOutput())};
    const TaprootSpendData spenddata{builder.GetSpendData()};
    const auto& blocks{spenddata.scripts.at({std::vector<unsigned char>(leaf.begin(), leaf.end()), TAPROOT_LEAF_TAPSCRIPT})};
    BOOST_REQUIRE(!blocks.empty());
    const std::vector<unsigned char> control{*blocks.begin()};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    auto sign_for_pos = [&](uint32_t pos) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf);
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = pos;
        uint256 hash;
        BOOST_REQUIRE(SignatureHashUnified(hash, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED,
                                      SigVersion::TAPSCRIPT, txdata, &execdata));
        std::vector<unsigned char> sig(64);
        BOOST_REQUIRE(key.SignSchnorr(hash, sig, nullptr, {}));
        sig.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);
        return sig;
    };
    auto spends = [&](const std::vector<unsigned char>& sig) {
        CMutableTransaction t{tx};
        t.vin[0].scriptWitness.stack = {sig, std::vector<unsigned char>(leaf.begin(), leaf.end()), control};
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        return VerifyScript(t.vin[0].scriptSig, spk, &t.vin[0].scriptWitness,
                            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_UNIFIED_SIGHASH,
                            checker, &err);
    };

    // Only the position the interpreter recorded satisfies the leaf.
    BOOST_CHECK(spends(sign_for_pos(EXPECTED_POS)));
    // 0xFFFFFFFF is the value used when no separator executed, so a signature
    // made as though there were none does not spend a script containing one.
    BOOST_CHECK(!spends(sign_for_pos(0xFFFFFFFF)));
    BOOST_CHECK(!spends(sign_for_pos(0)));
    BOOST_CHECK(!spends(sign_for_pos(2)));
}

BOOST_AUTO_TEST_CASE(unified_sighash_bit_does_not_collide_in_the_midstate_cache)
{
    // Knots caches SHA256 midstates for the legacy signature hash, indexed by
    // ANYONECANPAY and output type only. SIGHASH_UNIFIED is not part of that index,
    // so a byte carrying it shares a cache slot with the byte without it.
    //
    // That is safe only because the midstate stops short of the hash type,
    // which is appended per call. Nothing else checks that, and a change to
    // either the cache index or the point the midstate is taken would silently
    // make two different signatures hash alike.
    const CScript script{CScript() << OP_1 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script, script);

    for (const int32_t base : std::initializer_list<int32_t>{SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
                                                            SIGHASH_ALL | SIGHASH_ANYONECANPAY}) {
        const int32_t with_bit{base | SIGHASH_UNIFIED};
        // The two share a cache slot: the index is derived from ANYONECANPAY
        // and the output type, and SIGHASH_UNIFIED changes neither.

        // Warm on one, then compute the other through the same cache.
        SigHashCache shared;
        const uint256 first{SignatureHash(script, tx, 0, base, spent[0].nValue, SigVersion::BASE, nullptr, &shared)};
        const uint256 second{SignatureHash(script, tx, 0, with_bit, spent[0].nValue, SigVersion::BASE, nullptr, &shared)};
        BOOST_CHECK(first != second);

        // And the other way round, so neither order poisons the other.
        SigHashCache reversed;
        const uint256 rev_first{SignatureHash(script, tx, 0, with_bit, spent[0].nValue, SigVersion::BASE, nullptr, &reversed)};
        const uint256 rev_second{SignatureHash(script, tx, 0, base, spent[0].nValue, SigVersion::BASE, nullptr, &reversed)};
        BOOST_CHECK(rev_first == second);
        BOOST_CHECK(rev_second == first);

        // A cold cache agrees with a warm one.
        BOOST_CHECK_EQUAL(SignatureHash(script, tx, 0, base, spent[0].nValue, SigVersion::BASE, nullptr, nullptr).GetHex(), first.GetHex());
        BOOST_CHECK_EQUAL(SignatureHash(script, tx, 0, with_bit, spent[0].nValue, SigVersion::BASE, nullptr, nullptr).GetHex(), second.GetHex());
    }
}

BOOST_AUTO_TEST_CASE(unified_sighash_taproot_tail_is_load_bearing)
{
    // The taproot tail carries the annex, leaf hash and codeseparator position.
    // Elsewhere these are asserted to be necessary; here each one is shown to
    // be, by changing it and requiring the message to move. A commitment that
    // does not move is not a commitment.
    const CKey key{GenerateRandomKey()};
    const XOnlyPubKey xpk{key.GetPubKey()};

    // Two leaves spendable by the same key. This is the case the leaf hash
    // exists for: without it a signature made for one would satisfy the other.
    const CScript leaf_a{CScript() << ToByteVector(xpk) << OP_CHECKSIG};
    const CScript leaf_b{CScript() << ToByteVector(xpk) << OP_CHECKSIGVERIFY << OP_1};
    BOOST_REQUIRE(leaf_a != leaf_b);

    TaprootBuilder builder;
    builder.Add(1, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
    builder.Add(1, leaf_b, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    auto base = [] {
        ScriptExecutionData e;
        e.m_annex_init = true;
        e.m_annex_present = false;
        e.m_tapleaf_hash_init = true;
        e.m_codeseparator_pos_init = true;
        e.m_codeseparator_pos = 0xFFFFFFFF;
        return e;
    };
    auto msg = [&](const ScriptExecutionData& e, SigVersion sv, uint256& out) {
        ScriptExecutionData copy{e};
        return SignatureHashUnified(out, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, sv, txdata, &copy);
    };

    ScriptExecutionData ed_a{base()};
    ed_a.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_a);
    uint256 hash_a;
    BOOST_REQUIRE(msg(ed_a, SigVersion::TAPSCRIPT, hash_a));

    // 1. A different leaf is a different message, so a signature made for one
    //    leaf cannot be replayed into the other.
    ScriptExecutionData ed_b{base()};
    ed_b.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b);
    uint256 hash_b;
    BOOST_REQUIRE(msg(ed_b, SigVersion::TAPSCRIPT, hash_b));
    BOOST_CHECK(hash_a != hash_b);

    // 2. An annex is committed to, so it cannot be added or removed in flight.
    ScriptExecutionData ed_annex{ed_a};
    ed_annex.m_annex_present = true;
    ed_annex.m_annex_hash = uint256::ONE;
    uint256 hash_annex;
    BOOST_REQUIRE(msg(ed_annex, SigVersion::TAPSCRIPT, hash_annex));
    BOOST_CHECK(hash_a != hash_annex);

    // 3. The codeseparator position is committed to.
    ScriptExecutionData ed_cs{ed_a};
    ed_cs.m_codeseparator_pos = 0;
    uint256 hash_cs;
    BOOST_REQUIRE(msg(ed_cs, SigVersion::TAPSCRIPT, hash_cs));
    BOOST_CHECK(hash_a != hash_cs);

    // 4. The script type byte separates key path from script path, so a
    //    tapscript signature is not reusable as a key path spend.
    uint256 hash_keypath;
    ScriptExecutionData ed_key{base()};
    BOOST_REQUIRE(msg(ed_key, SigVersion::TAPROOT, hash_keypath));
    BOOST_CHECK(hash_a != hash_keypath);

    // 5. And the same separation against the other script types, so a segwit v0
    //    or legacy signature is never reusable against a taproot input.
    uint256 hash_base, hash_v0;
    BOOST_REQUIRE(SignatureHashUnified(hash_base, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, txdata));
    BOOST_REQUIRE(SignatureHashUnified(hash_v0, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, txdata));
    BOOST_CHECK(hash_base != hash_v0);
    BOOST_CHECK(hash_base != hash_keypath);
    BOOST_CHECK(hash_v0 != hash_keypath);
    BOOST_CHECK(hash_base != hash_a);
    BOOST_CHECK(hash_v0 != hash_a);
}

BOOST_AUTO_TEST_CASE(unified_sighash_leaf_substitution_is_rejected)
{
    // The attack the leaf hash exists to stop, carried out rather than argued
    // about: two leaves spendable by the same key, sign for one, then present
    // the other with that signature. The script itself would be satisfied,
    // since it is the same key checking the same signature; only the leaf hash
    // in the message stands between the two.
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_CHECK(keystore.AddKey(key));
    const XOnlyPubKey xpk{key.GetPubKey()};

    // Same shape, different bytes, so both are satisfied by one signature.
    const CScript leaf_a{CScript() << ToByteVector(xpk) << OP_CHECKSIG};
    const CScript leaf_b{CScript() << OP_1 << OP_DROP << ToByteVector(xpk) << OP_CHECKSIG};

    const CKey internal{GenerateRandomKey()};
    TaprootBuilder builder;
    builder.Add(1, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
    builder.Add(1, leaf_b, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(XOnlyPubKey{internal.GetPubKey()});
    const CScript spk{GetScriptForDestination(builder.GetOutput())};
    const TaprootSpendData spenddata{builder.GetSpendData()};

    auto control_for = [&](const CScript& leaf) {
        const auto& blocks{spenddata.scripts.at({std::vector<unsigned char>(leaf.begin(), leaf.end()), TAPROOT_LEAF_TAPSCRIPT})};
        BOOST_REQUIRE(!blocks.empty());
        return *blocks.begin();
    };

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    // Sign for leaf A.
    MutableTransactionSignatureCreator creator{tx, 0, spent[0].nValue, &txdata, SIGHASH_ALL};
    creator.SetSighashRules(SighashRules::UNIFIED);
    const uint256 leaf_a_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_a)};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(creator.CreateSchnorrSig(keystore, sig, xpk, &leaf_a_hash, nullptr, SigVersion::TAPSCRIPT));

    auto verify_with = [&](const CScript& leaf) {
        CMutableTransaction t{tx};
        t.vin[0].scriptWitness.stack = {sig, std::vector<unsigned char>(leaf.begin(), leaf.end()), control_for(leaf)};
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        return VerifyScript(t.vin[0].scriptSig, spk, &t.vin[0].scriptWitness,
                            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_UNIFIED_SIGHASH,
                            checker, &err);
    };

    // The leaf it was made for spends.
    BOOST_CHECK(verify_with(leaf_a));
    // The other leaf does not, though the same key satisfies the same opcode.
    BOOST_CHECK(!verify_with(leaf_b));

    // Control, so the rejection above cannot be passing for an unrelated reason
    // such as a malformed control block: leaf B spends perfectly well once the
    // signature is made for leaf B. The only difference is which leaf hash went
    // into the message.
    const uint256 leaf_b_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b)};
    sig.clear();
    BOOST_REQUIRE(creator.CreateSchnorrSig(keystore, sig, xpk, &leaf_b_hash, nullptr, SigVersion::TAPSCRIPT));
    BOOST_CHECK(verify_with(leaf_b));
    BOOST_CHECK(!verify_with(leaf_a));
}

BOOST_AUTO_TEST_CASE(unified_sighash_tapscript_roundtrip)
{
    // The script path reaches the checker by a different route than the key
    // path, so it gets its own coverage rather than being assumed to follow.
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_CHECK(keystore.AddKey(key));
    const XOnlyPubKey xpk{key.GetPubKey()};

    const CScript leaf{CScript() << ToByteVector(xpk) << OP_CHECKSIG};
    const CKey internal{GenerateRandomKey()};
    const XOnlyPubKey internal_xpk{internal.GetPubKey()};

    TaprootBuilder builder;
    builder.Add(0, leaf, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(internal_xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};
    const TaprootSpendData spenddata{builder.GetSpendData()};
    const auto control_blocks{spenddata.scripts.at({std::vector<unsigned char>(leaf.begin(), leaf.end()), TAPROOT_LEAF_TAPSCRIPT})};
    BOOST_REQUIRE(!control_blocks.empty());
    const std::vector<unsigned char> control{*control_blocks.begin()};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};
    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf)};

    auto verify = [&](const CMutableTransaction& t, bool hf) {
        MutableTransactionSignatureChecker checker{&t, 0, spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
                                 (hf ? uint32_t{SCRIPT_VERIFY_UNIFIED_SIGHASH} : uint32_t{0})};
        return VerifyScript(t.vin[0].scriptSig, spk, &t.vin[0].scriptWitness, flags, checker, &err);
    };

    auto sign = [&](CMutableTransaction& t, bool hf) {
        MutableTransactionSignatureCreator creator{t, 0, spent[0].nValue, &txdata, SIGHASH_DEFAULT};
        creator.SetSighashRules(hf ? SighashRules::UNIFIED : SighashRules::LEGACY);
        std::vector<unsigned char> sig;
        if (!creator.CreateSchnorrSig(keystore, sig, xpk, &leaf_hash, nullptr, SigVersion::TAPSCRIPT)) return false;
        t.vin[0].scriptWitness.stack = {sig, std::vector<unsigned char>(leaf.begin(), leaf.end()), control};
        return true;
    };

    CMutableTransaction unified_tx{tx};
    BOOST_CHECK(sign(unified_tx, /*hf=*/true));
    BOOST_CHECK_EQUAL(unified_tx.vin[0].scriptWitness.stack[0].size(), 65U);
    BOOST_CHECK(verify(unified_tx, /*hf=*/true));
    BOOST_CHECK(!verify(unified_tx, /*hf=*/false));

    CMutableTransaction legacy_tx{tx};
    BOOST_CHECK(sign(legacy_tx, /*hf=*/false));
    BOOST_CHECK_EQUAL(legacy_tx.vin[0].scriptWitness.stack[0].size(), 64U);
    BOOST_CHECK(verify(legacy_tx, /*hf=*/false));
    BOOST_CHECK(verify(legacy_tx, /*hf=*/true));
}

BOOST_AUTO_TEST_CASE(unified_sighash_taproot_rejects_bare_opt_in_byte)
{
    // Taproot keeps BIP341's reading, which defines no type for low bits of
    // zero, so a byte carrying only the opt-in bit is refused rather than read
    // as ALL. Bare, P2SH and segwit v0 read it as ALL, as legacy does.
    const CKey key{GenerateRandomKey()};
    const XOnlyPubKey xpk{key.GetPubKey()};
    TaprootBuilder builder;
    builder.Finalize(xpk);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};

    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, spk, spk);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    uint256 hash;
    BOOST_CHECK(!SignatureHashUnified(hash, CScript{}, tx, 0, SIGHASH_UNIFIED, SigVersion::TAPROOT, txdata, &execdata, MissingDataBehavior::FAIL));
    // The same byte is ALL for the script types that follow the legacy reading.
    BOOST_CHECK(SignatureHashUnified(hash, CScript() << OP_1, tx, 0, SIGHASH_UNIFIED, SigVersion::BASE, txdata));

    // A taproot signature also needs the annex state, which lives outside the
    // transaction: without it the annex would not be committed to.
    ScriptExecutionData uninit;
    BOOST_CHECK(!SignatureHashUnified(hash, CScript{}, tx, 0, SIGHASH_UNIFIED | SIGHASH_ALL, SigVersion::TAPROOT, txdata, &uninit, MissingDataBehavior::FAIL));
    BOOST_CHECK(!SignatureHashUnified(hash, CScript{}, tx, 0, SIGHASH_UNIFIED | SIGHASH_ALL, SigVersion::TAPROOT, txdata, nullptr, MissingDataBehavior::FAIL));
}

BOOST_AUTO_TEST_CASE(unified_sighash_anyonecanpay_is_position_independent)
{
    const CScript script{CScript() << OP_1 << OP_CHECKSIG};
    const CTxOut mine{5000, script};
    const CTxOut other{7000, CScript() << OP_2 << OP_CHECKSIG};

    // The same input signed alone, and then again after another input has been
    // prepended. ANYONECANPAY exists so this keeps working, so the position
    // must not be committed to.
    CMutableTransaction solo;
    solo.version = 2;
    solo.nLockTime = 17;
    solo.vin.resize(1);
    solo.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{1}), 0);
    solo.vin[0].nSequence = 0xfffffffe;
    solo.vout.resize(1);
    solo.vout[0].nValue = 4000;
    solo.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CMutableTransaction moved{solo};
    moved.vin.insert(moved.vin.begin(), CTxIn{COutPoint(Txid::FromUint256(uint256{2}), 1), CScript(), 0xfffffffe});

    const auto solo_data{MakeUnifiedTxdata(solo, {mine})};
    const auto moved_data{MakeUnifiedTxdata(moved, {other, mine})};

    uint256 a, b;
    BOOST_CHECK(SignatureHashUnified(a, script, solo, 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED, SigVersion::BASE, solo_data));
    BOOST_CHECK(SignatureHashUnified(b, script, moved, 1, SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED, SigVersion::BASE, moved_data));
    BOOST_CHECK_EQUAL(a, b);

    // Without ANYONECANPAY the position is committed to, as it must be.
    uint256 c, d;
    BOOST_CHECK(SignatureHashUnified(c, script, solo, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, solo_data));
    BOOST_CHECK(SignatureHashUnified(d, script, moved, 1, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, moved_data));
    BOOST_CHECK_NE(c, d);
}

BOOST_AUTO_TEST_CASE(unified_sighash_reads_hashtypes_as_legacy_does)
{
    const CScript script{CScript() << OP_1 << OP_CHECKSIG};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    BuildUnifiedTestTx(tx, spent, script, script);
    const auto txdata{MakeUnifiedTxdata(tx, spent)};

    // Same transaction with one output changed, to tell "commits to outputs"
    // from "does not" rather than trusting the byte to mean what it says.
    CMutableTransaction tx2{tx};
    tx2.vout[1].nValue += 1;
    const auto txdata2{MakeUnifiedTxdata(tx2, spent)};

    auto digest = [&](const CMutableTransaction& t, const PrecomputedTransactionData& d,
                      int32_t ht, uint256& out) {
        return SignatureHashUnified(out, script, t, 0, ht, SigVersion::BASE, d);
    };

    // Anything whose low bits are neither NONE nor SINGLE is ALL, exactly as the
    // legacy algorithm reads it. Unknown bits ride along and are committed to.
    for (const int32_t low : {0x00, 0x01, 0x04, 0x05, 0x06, 0x1f}) {
        for (const int32_t extra : {0, int{SIGHASH_ANYONECANPAY}, 0x40, 0x10, 0x08}) {
            const int32_t ht{SIGHASH_UNIFIED | low | extra};
            uint256 a, b;
            BOOST_CHECK_MESSAGE(digest(tx, txdata, ht, a),
                                strprintf("hashtype %#x should be accepted", ht));
            BOOST_CHECK(digest(tx2, txdata2, ht, b));
            if ((ht & 0x1f) == SIGHASH_NONE || (ht & 0x1f) == SIGHASH_SINGLE) continue;
            BOOST_CHECK_MESSAGE(a != b,
                                strprintf("hashtype %#x must commit to outputs like ALL", ht));
        }
    }

    // NONE commits to no outputs, so changing one leaves the message alone.
    {
        uint256 a, b;
        const int32_t ht{SIGHASH_UNIFIED | SIGHASH_NONE};
        BOOST_CHECK(digest(tx, txdata, ht, a));
        BOOST_CHECK(digest(tx2, txdata2, ht, b));
        BOOST_CHECK_MESSAGE(a == b, "NONE must not commit to outputs");
    }

    // SINGLE commits to the output at the input's index only, so changing the
    // other one leaves the message alone.
    {
        uint256 a, b;
        const int32_t ht{SIGHASH_UNIFIED | SIGHASH_SINGLE};
        BOOST_CHECK(digest(tx, txdata, ht, a));
        BOOST_CHECK(digest(tx2, txdata2, ht, b));
        BOOST_CHECK_MESSAGE(a == b, "SINGLE must commit to its own output only");
    }

    // Every distinct byte is still its own message: the hash type is committed
    // to whole, so two spellings of ALL do not collide.
    {
        uint256 a, b;
        BOOST_CHECK(digest(tx, txdata, SIGHASH_UNIFIED | SIGHASH_ALL, a));
        BOOST_CHECK(digest(tx, txdata, SIGHASH_UNIFIED | 0x05, b));
        BOOST_CHECK_MESSAGE(a != b, "distinct hash type bytes must give distinct messages");
    }

    // Without the opt-in bit the message is not defined at all.
    for (const int32_t ht : {0x00, 0x01, 0x02, 0x03, 0x40, 0x81, 0x83}) {
        uint256 h;
        BOOST_CHECK_MESSAGE(!digest(tx, txdata, ht, h),
                            strprintf("hashtype %#x should be rejected: did not opt in", ht));
    }
}

/** Randomised check of exactly what the hardfork sighash commits to.
 *
 * Mutating anything inside the commitment must change the hash, and mutating
 * anything outside it must not. Getting either direction wrong is a consensus
 * bug: too little means signatures can be replayed onto altered transactions,
 * too much means unrelated changes break valid signatures.
 */
BOOST_AUTO_TEST_CASE(unified_sighash_commitment_set)
{
    for (int iter = 0; iter < 200; ++iter) {
        const size_t n_in{size_t{1} + m_rng.randrange<size_t>(3)};
        const size_t n_out{size_t{1} + m_rng.randrange<size_t>(3)};

        CMutableTransaction tx;
        tx.version = m_rng.rand32();
        tx.nLockTime = m_rng.rand32();
        std::vector<CTxOut> spent;
        for (size_t i = 0; i < n_in; ++i) {
            CTxIn in;
            in.prevout = COutPoint(Txid::FromUint256(m_rng.rand256()), m_rng.rand32());
            in.nSequence = m_rng.rand32();
            in.scriptSig = CScript() << std::vector<unsigned char>(m_rng.randrange(8), 0x51);
            tx.vin.push_back(in);
            spent.emplace_back(CAmount(m_rng.randrange(21000000ULL * COIN)),
                               CScript() << OP_1 << std::vector<unsigned char>(1 + m_rng.randrange(4), 0x52));
        }
        for (size_t i = 0; i < n_out; ++i) {
            tx.vout.emplace_back(CAmount(m_rng.randrange(21000000ULL * COIN)),
                                 CScript() << OP_2 << std::vector<unsigned char>(1 + m_rng.randrange(4), 0x53));
        }

        const unsigned int nIn = m_rng.randrange(n_in);
        const CScript script_code{CScript() << OP_1 << std::vector<unsigned char>(1 + m_rng.randrange(6), 0x54)};
        const SigVersion sv{m_rng.randbool() ? SigVersion::BASE : SigVersion::WITNESS_V0};
        const int32_t base_type{m_rng.randbool() ? SIGHASH_ALL : (m_rng.randbool() ? SIGHASH_NONE : SIGHASH_SINGLE)};
        const bool acp{m_rng.randbool()};
        const int32_t ht{base_type | (acp ? SIGHASH_ANYONECANPAY : 0) | SIGHASH_UNIFIED};

        auto hash_of = [&](const CMutableTransaction& t, const std::vector<CTxOut>& sp,
                           const CScript& sc, uint256& out) {
            PrecomputedTransactionData d;
            d.Init(t, std::vector<CTxOut>{sp}, /*force=*/true);
            return SignatureHashUnified(out, sc, t, nIn, ht, sv, d);
        };

        uint256 base_hash;
        if (!hash_of(tx, spent, script_code, base_hash)) continue; // SINGLE with no output

        // Deterministic.
        uint256 again;
        BOOST_CHECK(hash_of(tx, spent, script_code, again));
        BOOST_CHECK_EQUAL(base_hash, again);

        // Not committed: this input's scriptSig, and the witness. Both are
        // where the signature itself lives, so committing to them would be
        // circular.
        {
            CMutableTransaction m{tx};
            m.vin[nIn].scriptSig = CScript() << OP_16 << OP_16;
            uint256 h;
            BOOST_CHECK(hash_of(m, spent, script_code, h));
            BOOST_CHECK_EQUAL(base_hash, h);
        }

        // Committed: the scriptCode.
        {
            uint256 h;
            BOOST_CHECK(hash_of(tx, spent, CScript() << OP_1 << OP_16, h));
            BOOST_CHECK_NE(base_hash, h);
        }

        // Committed: this input's own value and scriptPubKey, always.
        {
            std::vector<CTxOut> sp{spent};
            sp[nIn].nValue += 1;
            uint256 h;
            BOOST_CHECK(hash_of(tx, sp, script_code, h));
            BOOST_CHECK_NE(base_hash, h);
        }
        {
            std::vector<CTxOut> sp{spent};
            sp[nIn].scriptPubKey = CScript() << OP_16;
            uint256 h;
            BOOST_CHECK(hash_of(tx, sp, script_code, h));
            BOOST_CHECK_NE(base_hash, h);
        }

        // Other inputs' values and scripts: committed unless ANYONECANPAY.
        if (n_in > 1) {
            const size_t other{(nIn + 1) % n_in};
            std::vector<CTxOut> sp{spent};
            sp[other].nValue += 1;
            uint256 h;
            BOOST_CHECK(hash_of(tx, sp, script_code, h));
            if (acp) {
                BOOST_CHECK_EQUAL(base_hash, h);
            } else {
                BOOST_CHECK_NE(base_hash, h);
            }
        }

        // Outputs: committed under ALL; under SINGLE only the matching one.
        if (base_type != SIGHASH_NONE) {
            const size_t target{base_type == SIGHASH_SINGLE ? nIn : 0};
            if (target < n_out) {
                CMutableTransaction m{tx};
                m.vout[target].nValue += 1;
                uint256 h;
                BOOST_CHECK(hash_of(m, spent, script_code, h));
                BOOST_CHECK_NE(base_hash, h);
            }
        } else {
            CMutableTransaction m{tx};
            m.vout[0].nValue += 1;
            uint256 h;
            BOOST_CHECK(hash_of(m, spent, script_code, h));
            BOOST_CHECK_EQUAL(base_hash, h);
        }

        // Locktime and version are always committed.
        {
            CMutableTransaction m{tx};
            m.nLockTime ^= 1;
            uint256 h;
            BOOST_CHECK(hash_of(m, spent, script_code, h));
            BOOST_CHECK_NE(base_hash, h);
        }
        {
            CMutableTransaction m{tx};
            m.version ^= 1;
            uint256 h;
            BOOST_CHECK(hash_of(m, spent, script_code, h));
            BOOST_CHECK_NE(base_hash, h);
        }

        // The two script types never share a message.
        {
            uint256 h;
            PrecomputedTransactionData d;
            d.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
            BOOST_CHECK(SignatureHashUnified(h, script_code, tx, nIn, ht,
                                        sv == SigVersion::BASE ? SigVersion::WITNESS_V0 : SigVersion::BASE, d));
            BOOST_CHECK_NE(base_hash, h);
        }
    }
}

/** Measure the quadratic hashing fix (CVE-2013-2292).
 *
 * Signing every input of an n-input transaction costs O(n^2) under the legacy
 * rules, because each input reserialises the whole transaction, and O(n) under
 * the hardfork sighash, because the per-transaction hashes are computed once.
 * The margin asserted here is far below the ratio the structure implies, so
 * this measures the effect without being sensitive to machine speed.
 */
BOOST_AUTO_TEST_CASE(unified_sighash_is_linear_in_input_count)
{
    constexpr size_t N{1500};

    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    std::vector<CTxOut> spent;
    tx.vin.reserve(N);
    spent.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        CTxIn in;
        in.prevout = COutPoint(Txid::FromUint256(uint256{uint8_t(i & 0xff)}), uint32_t(i));
        in.nSequence = 0xfffffffe;
        tx.vin.push_back(in);
        spent.emplace_back(1000, CScript() << OP_1 << OP_CHECKSIG);
    }
    tx.vout.emplace_back(500, CScript() << OP_TRUE);

    const CScript script_code{CScript() << OP_1 << OP_CHECKSIG};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);

    const auto t0{SteadyClock::now()};
    uint256 acc_legacy;
    for (size_t i = 0; i < N; ++i) {
        acc_legacy = SignatureHash(script_code, tx, i, SIGHASH_ALL, spent[i].nValue, SigVersion::BASE, &txdata);
    }
    const auto t1{SteadyClock::now()};
    uint256 acc_hf;
    for (size_t i = 0; i < N; ++i) {
        BOOST_REQUIRE(SignatureHashUnified(acc_hf, script_code, tx, i, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::BASE, txdata));
    }
    const auto t2{SteadyClock::now()};

    const auto legacy_us{std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()};
    const auto unified_us{std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()};
    BOOST_TEST_MESSAGE("inputs=" << N << " legacy=" << legacy_us << "us hf=" << unified_us
                       << "us ratio=" << (unified_us ? double(legacy_us) / double(unified_us) : 0.0));

    // Sanity: they really are different messages, so nothing was optimised away.
    BOOST_CHECK_NE(acc_legacy, acc_hf);
    BOOST_CHECK_GT(legacy_us, 10 * std::max<int64_t>(unified_us, 1));
}

/** Check the implementation against vectors produced by the separate Python
 *  implementation in the functional test framework.
 *
 * The two were written from the same description but not from each other, so
 * agreement here is the cross-implementation check a consensus change needs.
 * The file is also the artifact a third implementation would validate against.
 */
BOOST_AUTO_TEST_CASE(unified_sighash_vectors)
{
    UniValue tests = read_json(json_tests::unified_sighash);
    size_t checked{0};

    for (unsigned int idx = 1; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        BOOST_REQUIRE_MESSAGE(test.size() == 7, "bad vector at " << idx);

        const std::vector<unsigned char> sc_bytes{ParseHex(test[0].get_str())};
        const CScript script_code(sc_bytes.begin(), sc_bytes.end());
        CMutableTransaction tx;
        {
            DataStream stream{};
            stream << Span{ParseHex(test[1].get_str())};
            stream >> TX_NO_WITNESS(tx);
        }
        const unsigned int in_idx{(unsigned int)test[2].getInt<int>()};
        const int32_t hash_type{test[3].getInt<int>()};
        const int script_type{test[4].getInt<int>()};
        SigVersion sv{SigVersion::BASE};
        switch (script_type) {
        case 0: sv = SigVersion::BASE; break;
        case 1: sv = SigVersion::WITNESS_V0; break;
        case 2: sv = SigVersion::TAPROOT; break;
        case 3: sv = SigVersion::TAPSCRIPT; break;
        default: BOOST_FAIL("bad script type at " << idx);
        }

        std::vector<CTxOut> spent;
        for (const UniValue& utxo : test[5].getValues()) {
            const std::vector<unsigned char> spk{ParseHex(utxo[1].get_str())};
            spent.emplace_back(CAmount{utxo[0].getInt<int64_t>()}, CScript(spk.begin(), spk.end()));
        }
        // The vectors carry the raw hash bytes; uint256::FromHex would reverse them.
        const std::vector<unsigned char> exp_bytes{ParseHex(test[6].get_str())};
        BOOST_REQUIRE_EQUAL(exp_bytes.size(), 32u);
        const uint256 expected{Span{exp_bytes}};

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::move(spent), /*force=*/true);

        // Taproot carries context from outside the transaction; for these
        // vectors there is no annex and no OP_CODESEPARATOR.
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        if (sv == SigVersion::TAPSCRIPT) {
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script_code);
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFF;
        }
        const bool taproot{sv == SigVersion::TAPROOT || sv == SigVersion::TAPSCRIPT};

        uint256 got;
        BOOST_REQUIRE_MESSAGE(SignatureHashUnified(got, script_code, tx, in_idx, hash_type, sv, txdata,
                                              taproot ? &execdata : nullptr),
                              "vector " << idx << " should be computable");
        BOOST_CHECK_MESSAGE(got == expected,
                            "vector " << idx << ": got " << got.GetHex() << " want " << expected.GetHex());
        ++checked;
    }
    BOOST_CHECK_EQUAL(checked, tests.size() - 1);
    BOOST_CHECK_GE(checked, 140u);
}

BOOST_AUTO_TEST_SUITE_END()
