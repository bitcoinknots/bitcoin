// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <kernel/chainparams.h>
#include <node/blockstorage.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/string.h>

#include <cstdlib>

using util::ToString;

/* Equality between doubles is imprecise. Comparison should be done
 * with a small threshold of tolerance, rather than exact equality.
 */
static bool DoubleEquals(double a, double b, double epsilon)
{
    return std::abs(a - b) < epsilon;
}

static CBlockIndex* CreateBlockIndexWithNbits(uint32_t nbits)
{
    CBlockIndex* block_index = new CBlockIndex();
    block_index->nHeight = 46367;
    block_index->nTime = 1269211443;
    block_index->nBits = nbits;
    return block_index;
}

static void RejectDifficultyMismatch(double difficulty, double expected_difficulty) {
     BOOST_CHECK_MESSAGE(
        DoubleEquals(difficulty, expected_difficulty, 0.00001),
        "Difficulty was " + ToString(difficulty)
            + " but was expected to be " + ToString(expected_difficulty));
}

/* Given a BlockIndex with the provided nbits,
 * verify that the expected difficulty results.
 */
static void TestDifficulty(uint32_t nbits, double expected_difficulty)
{
    CBlockIndex* block_index = CreateBlockIndexWithNbits(nbits);
    double difficulty = GetDifficulty(*block_index);
    delete block_index;

    RejectDifficultyMismatch(difficulty, expected_difficulty);
}

BOOST_FIXTURE_TEST_SUITE(blockchain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(coinbase_maturity_deployment_boundaries)
{
    const auto main{CChainParams::Main()};
    const auto& params{main->GetConsensus()};
    for (const int height : {973439, 973440, 979918}) {
        const auto info{GetCoinbaseMaturityDeploymentInfo(params, height)};
        BOOST_CHECK_EQUAL(info["height"].getInt<int>(), 973440);
        BOOST_CHECK_EQUAL(info["height_end"].getInt<int>(), 979919);
        BOOST_CHECK_EQUAL(info["coinbase_start_height"].getInt<int>(), 973440);
        BOOST_CHECK_EQUAL(info["maturity"].getInt<int>(), 6480);
        BOOST_CHECK_EQUAL(info["active"].get_bool(), height >= 973440);
        BOOST_CHECK(info["coinbase_expiry_time"].isNull());
    }
    for (const int height : {979919, 979920, 1005839}) {
        const auto info{GetCoinbaseMaturityDeploymentInfo(params, height)};
        BOOST_CHECK_EQUAL(info["height"].getInt<int>(), 979919);
        BOOST_CHECK_EQUAL(info["coinbase_start_height"].getInt<int>(), 979919);
        BOOST_CHECK_EQUAL(info["maturity"].getInt<int>(), 25920);
        BOOST_CHECK(info["active"].get_bool());
        BOOST_CHECK_EQUAL(info["coinbase_expiry_time"].getInt<int64_t>(), params.RdtsExpiryTime);
        BOOST_CHECK(info["height_end"].isNull());
    }
    const auto testnet4{CChainParams::TestNet4()};
    const auto& test_params{testnet4->GetConsensus()};
    for (const int height : {test_params.CoinbaseMaturityLongEnforceHeight - 1, test_params.CoinbaseMaturityLongEnforceHeight,
                             test_params.CoinbaseMaturityLongReleaseHeight - 1, test_params.CoinbaseMaturityLongReleaseHeight}) {
        const auto info{GetCoinbaseMaturityDeploymentInfo(test_params, height)};
        BOOST_CHECK_EQUAL(info["active"].get_bool(), test_params.CoinbaseMaturityLongActiveAt(height));
        BOOST_CHECK_EQUAL(info["height_end"].getInt<int>(), test_params.CoinbaseMaturityLongReleaseHeight - 1);
        BOOST_CHECK(info["coinbase_expiry_time"].isNull());
    }
    BOOST_CHECK(GetCoinbaseMaturityDeploymentInfo(CChainParams::RegTest({})->GetConsensus(), 0).isNull());
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_very_low_target)
{
    TestDifficulty(0x1f111111, 0.000001);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_low_target)
{
    TestDifficulty(0x1ef88f6f, 0.000016);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_mid_target)
{
    TestDifficulty(0x1df88f6f, 0.004023);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_high_target)
{
    TestDifficulty(0x1cf88f6f, 1.029916);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_very_high_target)
{
    TestDifficulty(0x12345678, 5913134931067755359633408.0);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_blake2b_block)
{
    CBlockIndex* block_index = CreateBlockIndexWithNbits(0x1f111111);
    block_index->m_header_v2 = true;
    double difficulty = GetDifficultyBlake2b(*block_index);
    delete block_index;

    RejectDifficultyMismatch(difficulty, 3840);
}

//! Prune chain from height down to genesis block and check that
//! GetPruneHeight returns the correct value
static void CheckGetPruneHeight(node::BlockManager& blockman, CChain& chain, int height) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);

    // Emulate pruning all blocks from `height` down to the genesis block
    // by unsetting the `BLOCK_HAVE_DATA` flag from `nStatus`
    for (CBlockIndex* it{chain[height]}; it != nullptr && it->nHeight > 0; it = it->pprev) {
        it->nStatus &= ~BLOCK_HAVE_DATA;
    }

    const auto prune_height{GetPruneHeight(blockman, chain)};
    BOOST_REQUIRE(prune_height.has_value());
    BOOST_CHECK_EQUAL(*prune_height, height);
}

BOOST_FIXTURE_TEST_CASE(get_prune_height, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chain = m_node.chainman->ActiveChain();
    auto& blockman = m_node.chainman->m_blockman;

    // Fresh chain of 100 blocks without any pruned blocks, so std::nullopt should be returned
    BOOST_CHECK(!GetPruneHeight(blockman, chain).has_value());

    // Start pruning
    CheckGetPruneHeight(blockman, chain, 1);
    CheckGetPruneHeight(blockman, chain, 99);
    CheckGetPruneHeight(blockman, chain, 100);
}

BOOST_AUTO_TEST_CASE(num_chain_tx_max)
{
    CBlockIndex block_index{};
    block_index.m_chain_tx_count = std::numeric_limits<uint64_t>::max();
    BOOST_CHECK_EQUAL(block_index.m_chain_tx_count, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_SUITE_END()
