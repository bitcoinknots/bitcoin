// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <hash.h>
#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <span.h>
#include <test/util/index.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <txdb.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(coinbase_relock_hash_commitments, TestChain100Setup)
{
    CCoinsViewDB db{{.path = "relock_hash", .cache_bytes = 1_MiB, .memory_only = true}, {}};
    CCoinsViewCache cache{&db};
    const COutPoint outpoint{Txid::FromUint256(uint256{1}), 0};
    const Coin ordinary{CTxOut{123, CScript{} << OP_TRUE}, 100, false};
    const Coin relocked{ordinary.out, 100, false, true};
    cache.AddCoin(outpoint, Coin{ordinary}, false);
    cache.SetBestBlock(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));
    BOOST_REQUIRE(cache.Flush());

    // Independently encode a coin using the historical commitment format.
    DataStream legacy_bytes;
    legacy_bytes << outpoint << uint32_t{200} << ordinary.out;
    HashWriter legacy_hash;
    legacy_hash << outpoint << uint32_t{200} << ordinary.out;
    MuHash3072 legacy_muhash;
    legacy_muhash.Insert(MakeUCharSpan(legacy_bytes));
    uint256 expected_muhash;
    legacy_muhash.Finalize(expected_muhash);

    const auto serialized{kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED, &db, m_node.chainman->m_blockman)};
    const auto muhash{kernel::ComputeUTXOStats(kernel::CoinStatsHashType::MUHASH, &db, m_node.chainman->m_blockman)};
    BOOST_REQUIRE(serialized);
    BOOST_REQUIRE(muhash);
    BOOST_CHECK(serialized->hashSerialized == legacy_hash.GetHash());
    BOOST_CHECK(muhash->hashSerialized == expected_muhash);

    cache.AddCoin(outpoint, Coin{relocked}, true);
    BOOST_REQUIRE(cache.Flush());
    const auto marked_serialized{kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED, &db, m_node.chainman->m_blockman)};
    const auto marked_muhash{kernel::ComputeUTXOStats(kernel::CoinStatsHashType::MUHASH, &db, m_node.chainman->m_blockman)};
    BOOST_REQUIRE(marked_serialized);
    BOOST_REQUIRE(marked_muhash);
    BOOST_CHECK(marked_serialized->hashSerialized != serialized->hashSerialized);
    BOOST_CHECK(marked_muhash->hashSerialized != muhash->hashSerialized);

    MuHash3072 accumulator;
    kernel::ApplyCoinHash(accumulator, outpoint, relocked);
    uint256 marked_hash;
    accumulator.Finalize(marked_hash);
    BOOST_CHECK(marked_hash == marked_muhash->hashSerialized);
    kernel::RemoveCoinHash(accumulator, outpoint, relocked);
    uint256 removed_hash;
    accumulator.Finalize(removed_hash);
    MuHash3072 empty;
    uint256 empty_hash;
    empty.Finalize(empty_hash);
    BOOST_CHECK(removed_hash == empty_hash);
}

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup)
{
    CoinStatsIndex coin_stats_index{interfaces::MakeChain(m_node), 1 << 20, true};
    BOOST_REQUIRE(coin_stats_index.Init());

    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain().Tip();
    }

    // CoinStatsIndex should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookUpStats(*block_index));

    // BlockUntilSyncedToCurrentChain should return false before CoinStatsIndex
    // is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(coin_stats_index.StartBackgroundSync());

    IndexWaitSynced(coin_stats_index, *Assert(m_node.shutdown_signal));

    // Check that CoinStatsIndex works for genesis block.
    const CBlockIndex* genesis_block_index;
    {
        LOCK(cs_main);
        genesis_block_index = m_node.chainman->ActiveChain().Genesis();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*genesis_block_index));

    // Check that CoinStatsIndex updates with new blocks.
    BOOST_CHECK(coin_stats_index.LookUpStats(*block_index));

    const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, script_pub_key);

    // Let the CoinStatsIndex to catch up again.
    BOOST_CHECK(coin_stats_index.BlockUntilSyncedToCurrentChain());

    const CBlockIndex* new_block_index;
    {
        LOCK(cs_main);
        new_block_index = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*new_block_index));

    BOOST_CHECK(block_index != new_block_index);

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The BlockUntilSyncedToCurrentChain()
    // call above is sufficient to ensure this, but the
    // SyncWithValidationInterfaceQueue() call below is also needed to ensure
    // TSAN always sees the test thread waiting for the notification thread, and
    // avoid potential false positive reports.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // Shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();
}

// Test shutdown between BlockConnected and ChainStateFlushed notifications,
// make sure index is not corrupted and is able to reload.
BOOST_FIXTURE_TEST_CASE(coinstatsindex_unclean_shutdown, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const CChainParams& params = Params();
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index, *Assert(m_node.shutdown_signal));
        std::shared_ptr<const CBlock> new_block;
        CBlockIndex* new_block_index = nullptr;
        {
            const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
            const CBlock block = this->CreateBlock({}, script_pub_key, chainstate);

            new_block = std::make_shared<CBlock>(block);

            LOCK(cs_main);
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, params.GetConsensus()));
            BOOST_CHECK(m_node.chainman->AcceptBlock(new_block, state, &new_block_index, true, nullptr, nullptr, true));
            CCoinsViewCache view(&chainstate.CoinsTip());
            BOOST_CHECK(chainstate.ConnectBlock(block, state, new_block_index, view));
        }
        // Send block connected notification, then stop the index without
        // sending a chainstate flushed notification. Prior to #24138, this
        // would cause the index to be corrupted and fail to reload.
        ValidationInterfaceTest::BlockConnected(ChainstateRole::NORMAL, index, new_block, new_block_index);
        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        // Make sure the index can be loaded.
        BOOST_REQUIRE(index.StartBackgroundSync());
        index.Stop();
    }
}

BOOST_AUTO_TEST_SUITE_END()
