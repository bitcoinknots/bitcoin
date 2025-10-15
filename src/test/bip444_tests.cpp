// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

BOOST_FIXTURE_TEST_SUITE(bip444_tests, BasicTestingSetup)

// Helper to check witness standardness
static bool CheckWitnessStandard(const CTransaction& tx, const CCoinsViewCache& view, const kernel::MemPoolOptions& opts, std::string& reason)
{
    return IsWitnessStandard(tx, view, opts, "bad-witness-", reason);
}

BOOST_AUTO_TEST_CASE(taproot_control_block_cap)
{
    // Policy: Taproot control block size must be <= 257 bytes
    // Control block structure: 1-byte (leaf version + parity) + 32-byte internal key + 0..128 * 32-byte merkle path
    // Max standard: 33 + 7*32 = 257 bytes (7 merkle nodes)
    
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0); // P2TR
    
    // Create a dummy P2TR prevout
    CCoinsView dummy_view;
    CCoinsViewCache view(&dummy_view);
    Coin coin;
    coin.out.nValue = 50 * COIN;
    coin.out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    coin.nHeight = 1;
    view.AddCoin(COutPoint(Txid::FromUint256(uint256::ONE), 0), std::move(coin), false);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    
    // Script-path spend: witness stack = [<inputs>, <script>, <control_block>]
    // Control block: 1 + 32 + N*32 bytes
    std::vector<unsigned char> control_257(257, 0);
    control_257[0] = 0xc0; // leaf version 0xc0
    std::vector<unsigned char> control_258(258, 0);
    control_258[0] = 0xc0;
    
    CScript leaf_script = CScript() << std::vector<unsigned char>(32, 0) << OP_CHECKSIG;
    
    // Valid: control block = 257
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_script.begin(), leaf_script.end()), control_257};
    std::string reason;
    kernel::MemPoolOptions opts;
    BOOST_CHECK(CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    
    // Invalid: control block = 258
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_script.begin(), leaf_script.end()), control_258};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-controlblock-size");
}

BOOST_AUTO_TEST_CASE(taproot_per_input_witness_cap)
{
    // Policy: per-input total witness size for v1 must be <= policy_max_v1_perinput_witness (default 1024)
    
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    
    CCoinsView dummy_view;
    CCoinsViewCache view(&dummy_view);
    Coin coin;
    coin.out.nValue = 50 * COIN;
    coin.out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    coin.nHeight = 1;
    view.AddCoin(COutPoint(Txid::FromUint256(uint256::ONE), 0), std::move(coin), false);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    
    // Key-path spend: single 64-byte signature
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0)};
    std::string reason;
    kernel::MemPoolOptions opts;
    BOOST_CHECK(CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    
    // Script-path spend with total witness ~1024 bytes (within limit)
    CScript leaf_script = CScript() << std::vector<unsigned char>(32, 0) << OP_CHECKSIG;
    std::vector<unsigned char> control(257, 0);
    control[0] = 0xc0;
    std::vector<unsigned char> sig(64, 0);
    std::vector<unsigned char> script_bytes(leaf_script.begin(), leaf_script.end());
    // Total: 64 + script_bytes.size() + 257 = ~355 bytes (well under 1024)
    tx.vin[0].scriptWitness.stack = {sig, script_bytes, control};
    BOOST_CHECK(CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    
    // Exceed limit: add large padding element
    std::vector<unsigned char> padding(800, 0);
    tx.vin[0].scriptWitness.stack = {sig, script_bytes, control, padding};
    // Total: 64 + ~35 + 257 + 800 = ~1156 > 1024
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-perinput-witness");
}

BOOST_AUTO_TEST_CASE(tapscript_if_disallowed)
{
    // Policy: OP_IF/OP_NOTIF are disallowed in Tapscript leaves
    
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    
    CCoinsView dummy_view;
    CCoinsViewCache view(&dummy_view);
    Coin coin;
    coin.out.nValue = 50 * COIN;
    coin.out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    coin.nHeight = 1;
    view.AddCoin(COutPoint(Txid::FromUint256(uint256::ONE), 0), std::move(coin), false);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    
    // Leaf without IF: valid
    CScript leaf_no_if = CScript() << std::vector<unsigned char>(32, 0) << OP_CHECKSIG;
    std::vector<unsigned char> control(33, 0);
    control[0] = 0xc0;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_no_if.begin(), leaf_no_if.end()), control};
    std::string reason;
    kernel::MemPoolOptions opts;
    BOOST_CHECK(CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    
    // Leaf with OP_IF: rejected
    CScript leaf_with_if = CScript() << OP_IF << std::vector<unsigned char>(32, 0) << OP_ENDIF << OP_CHECKSIG;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_with_if.begin(), leaf_with_if.end()), control};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-if-disallowed");
    
    // Leaf with OP_NOTIF: rejected
    CScript leaf_with_notif = CScript() << OP_NOTIF << std::vector<unsigned char>(32, 0) << OP_ENDIF << OP_CHECKSIG;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_with_notif.begin(), leaf_with_notif.end()), control};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-if-disallowed");
}

BOOST_AUTO_TEST_CASE(tapscript_pushrun_cap)
{
    // Policy: max contiguous push-only run in Tapscript leaf must be <= 256 bytes
    
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    
    CCoinsView dummy_view;
    CCoinsViewCache view(&dummy_view);
    Coin coin;
    coin.out.nValue = 50 * COIN;
    coin.out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    coin.nHeight = 1;
    view.AddCoin(COutPoint(Txid::FromUint256(uint256::ONE), 0), std::move(coin), false);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    
    std::vector<unsigned char> control(33, 0);
    control[0] = 0xc0;
    
    // Leaf with push-only run = 256 bytes (valid)
    CScript leaf_256 = CScript() << std::vector<unsigned char>(256, 0) << OP_DROP;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_256.begin(), leaf_256.end()), control};
    std::string reason;
    kernel::MemPoolOptions opts;
    BOOST_CHECK(CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    
    // Leaf with push-only run = 257 bytes (invalid)
    CScript leaf_257 = CScript() << std::vector<unsigned char>(257, 0) << OP_DROP;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_257.begin(), leaf_257.end()), control};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-pushrun");
    
    // Leaf with multiple pushes totaling 300 bytes (invalid)
    CScript leaf_multi = CScript() << std::vector<unsigned char>(200, 0) << std::vector<unsigned char>(100, 0) << OP_DROP;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_multi.begin(), leaf_multi.end()), control};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-pushrun");
}

BOOST_AUTO_TEST_CASE(tapscript_if_body_pushonly_cap)
{
    // Policy: push-only IF/NOTIF branch body must be <= 80 bytes
    // (This test would fail due to IF ban; included for completeness if IF ban is lifted later)
    
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    
    CCoinsView dummy_view;
    CCoinsViewCache view(&dummy_view);
    Coin coin;
    coin.out.nValue = 50 * COIN;
    coin.out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0);
    coin.nHeight = 1;
    view.AddCoin(COutPoint(Txid::FromUint256(uint256::ONE), 0), std::move(coin), false);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    
    std::vector<unsigned char> control(33, 0);
    control[0] = 0xc0;
    
    // Leaf with OP_IF containing 80-byte push-only body (would be rejected by IF ban first)
    CScript leaf_if_80 = CScript() << OP_FALSE << OP_IF << std::vector<unsigned char>(80, 0) << OP_ENDIF << OP_TRUE;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_if_80.begin(), leaf_if_80.end()), control};
    std::string reason;
    kernel::MemPoolOptions opts;
    // Rejected by IF ban
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-if-disallowed");
    
    // Leaf with OP_IF containing 81-byte push-only body (would be rejected by IF ban first, then by IF-body cap)
    CScript leaf_if_81 = CScript() << OP_FALSE << OP_IF << std::vector<unsigned char>(81, 0) << OP_ENDIF << OP_TRUE;
    tx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(64, 0), std::vector<unsigned char>(leaf_if_81.begin(), leaf_if_81.end()), control};
    BOOST_CHECK(!CheckWitnessStandard(CTransaction(tx), view, opts, reason));
    BOOST_CHECK_EQUAL(reason, "bad-witness-taproot-if-disallowed");
}

BOOST_AUTO_TEST_SUITE_END()

