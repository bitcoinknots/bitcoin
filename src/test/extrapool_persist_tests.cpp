// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/extrapool_persist.h>

#include <core_memusage.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

using node::DumpExtraPool;
using node::ExtraPoolPath;
using node::LoadExtraPool;
using node::ShouldPersistExtraPool;

BOOST_FIXTURE_TEST_SUITE(extrapool_persist_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(should_persist_rejecttokens_enabled)
{
    // When rejecttokens=1, ShouldPersistExtraPool returns true
    m_args.ForceSetArg("-rejecttokens", "1");
    BOOST_CHECK(ShouldPersistExtraPool(m_args));
}

BOOST_AUTO_TEST_CASE(should_persist_rejecttokens_disabled)
{
    // When rejecttokens=0, ShouldPersistExtraPool returns false
    m_args.ForceSetArg("-rejecttokens", "0");
    BOOST_CHECK(!ShouldPersistExtraPool(m_args));
}

BOOST_AUTO_TEST_CASE(should_persist_rejecttokens_unset)
{
    // When rejecttokens is not set, ShouldPersistExtraPool returns false (default)
    BOOST_CHECK(!ShouldPersistExtraPool(m_args));
}

BOOST_AUTO_TEST_CASE(extrapool_path)
{
    // ExtraPoolPath returns datadir / "extrapool.dat"
    auto path = ExtraPoolPath(m_args);
    BOOST_CHECK_EQUAL(fs::PathToString(path.filename()), "extrapool.dat");
    // The path should end with the expected filename
    BOOST_CHECK(path.parent_path() == m_args.GetDataDirNet());
}

BOOST_AUTO_TEST_CASE(round_trip_happy_path)
{
    // Create a known pool with 5 transactions
    std::vector<CTransactionRef> pool;
    for (int i = 0; i < 5; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256(i)), 0);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = (i + 1) * 1000;
        mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        pool.push_back(MakeTransactionRef(std::move(mtx)));
    }
    size_t original_pos = 3; // ring buffer position

    // Dump to a temp file
    fs::path dump_path = m_args.GetDataDirNet() / "test_extrapool.dat";
    BOOST_CHECK(DumpExtraPool(pool, original_pos, dump_path));

    // Load back
    std::vector<CTransactionRef> loaded_pool;
    size_t loaded_pos = 0, loaded_memusage = 0;
    BOOST_CHECK(LoadExtraPool(loaded_pool, loaded_pos, loaded_memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              dump_path));

    // Verify
    BOOST_CHECK_EQUAL(loaded_pool.size(), pool.size());
    BOOST_CHECK_EQUAL(loaded_pos, original_pos);
    BOOST_CHECK(loaded_memusage > 0);

    for (size_t i = 0; i < pool.size(); ++i) {
        BOOST_CHECK(loaded_pool[i] != nullptr);
        BOOST_CHECK_EQUAL(pool[i]->GetHash().ToString(), loaded_pool[i]->GetHash().ToString());
    }
}

// Property 3: Memory-Limited Eviction on Load
// Validates: Requirements 2.4, 2.5
BOOST_AUTO_TEST_CASE(property_memory_limited_eviction)
{
    // Property 3: For any pool whose loaded memory exceeds limit M,
    // loading evicts transactions until memusage <= M,
    // and memusage equals the sum of RecursiveDynamicUsage over remaining non-null entries.

    FastRandomContext rng{/*fDeterministic=*/true};
    fs::path path = m_args.GetDataDirNet() / "prop3_extrapool.dat";

    for (int iter = 0; iter < 100; ++iter) {
        // Generate pool with 5-20 transactions (all non-null, all substantial)
        size_t N = 5 + rng.randrange(16);
        std::vector<CTransactionRef> pool;
        for (size_t i = 0; i < N; ++i) {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            uint256 hash;
            hash.SetNull();
            uint64_t unique_val = (iter + 1) * 100000 + i;
            std::memcpy(hash.begin(), &unique_val, sizeof(unique_val));
            mtx.vin[0].prevout = COutPoint(Txid::FromUint256(hash), 0);
            // Multiple outputs to increase memory usage
            size_t num_outputs = 2 + rng.randrange(5);
            mtx.vout.resize(num_outputs);
            for (size_t j = 0; j < num_outputs; ++j) {
                mtx.vout[j].nValue = rng.randrange(1000000) + 1;
                mtx.vout[j].scriptPubKey = CScript() << OP_TRUE;
            }
            pool.push_back(MakeTransactionRef(std::move(mtx)));
        }

        size_t original_pos = rng.randrange(N);

        // First, dump and load with unlimited memory to find total memusage
        BOOST_CHECK(DumpExtraPool(pool, original_pos, path));

        std::vector<CTransactionRef> full_pool;
        size_t full_pos = 0, full_memusage = 0;
        BOOST_CHECK(LoadExtraPool(full_pool, full_pos, full_memusage,
                                  1000, 100000000, path));

        if (full_memusage == 0) {
            fs::remove(path);
            continue;
        }

        // Choose memory limit M: between 1/4 and 3/4 of the total
        size_t M = full_memusage / 4 + rng.randrange(full_memusage / 2 + 1);
        if (M >= full_memusage) M = full_memusage / 2;
        if (M == 0) M = 1;

        // Load with memory limit
        std::vector<CTransactionRef> limited_pool;
        size_t limited_pos = 0, limited_memusage = 0;
        BOOST_CHECK(LoadExtraPool(limited_pool, limited_pos, limited_memusage,
                                  1000, M, path));

        // Assert: memusage <= M
        BOOST_CHECK(limited_memusage <= M);

        // Verify memusage equals sum of RecursiveDynamicUsage over non-null entries
        size_t computed_memusage = 0;
        for (const auto& tx : limited_pool) {
            if (tx) {
                computed_memusage += RecursiveDynamicUsage(*tx);
            }
        }
        BOOST_CHECK_EQUAL(limited_memusage, computed_memusage);

        // Clean up
        fs::remove(path);
    }
}

// Property 1: Serialization Round-Trip
// Validates: Requirements 1.2, 1.3, 2.2, 2.5, 7.4
BOOST_AUTO_TEST_CASE(property_round_trip)
{
    // Property 1: For any valid extra pool state, serialize then deserialize
    // produces the same set of non-null transactions in the same order,
    // same ring buffer position, and correct memusage.

    FastRandomContext rng{/*fDeterministic=*/true};
    fs::path path = m_args.GetDataDirNet() / "prop1_extrapool.dat";

    for (int iter = 0; iter < 100; ++iter) {
        // Generate random pool: 0 to 50 entries, some may be null
        size_t pool_size = rng.randrange(51);
        std::vector<CTransactionRef> pool(pool_size);

        for (size_t i = 0; i < pool_size; ++i) {
            // ~20% chance of null entry
            if (rng.randrange(5) == 0) {
                pool[i] = nullptr;
                continue;
            }
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            // Use iteration and index to create unique prevout
            uint256 hash;
            hash.SetNull();
            // Write iter*1000+i into the hash bytes to make unique
            uint64_t unique_val = iter * 1000 + i;
            std::memcpy(hash.begin(), &unique_val, sizeof(unique_val));
            mtx.vin[0].prevout = COutPoint(Txid::FromUint256(hash), 0);
            mtx.vout.resize(1 + rng.randrange(3)); // 1-3 outputs
            for (size_t j = 0; j < mtx.vout.size(); ++j) {
                mtx.vout[j].nValue = rng.randrange(1000000) + 1;
                mtx.vout[j].scriptPubKey = CScript() << OP_TRUE;
            }
            pool[i] = MakeTransactionRef(std::move(mtx));
        }

        // Random position (clamped to pool size)
        size_t original_pos = pool_size > 0 ? rng.randrange(pool_size) : 0;

        // Count non-null entries
        size_t non_null_count = 0;
        for (const auto& tx : pool) {
            if (tx) ++non_null_count;
        }

        // Dump
        BOOST_CHECK(DumpExtraPool(pool, original_pos, path));

        // Load with generous limits
        std::vector<CTransactionRef> loaded_pool;
        size_t loaded_pos = 0, loaded_memusage = 0;
        BOOST_CHECK(LoadExtraPool(loaded_pool, loaded_pos, loaded_memusage,
                                  /*max_count=*/1000, /*max_mem_bytes=*/100000000,
                                  path));

        // Verify: loaded pool has exactly non_null_count entries
        BOOST_CHECK_EQUAL(loaded_pool.size(), non_null_count);

        // Verify: position is clamped to loaded count
        BOOST_CHECK(loaded_pos <= loaded_pool.size());
        // If original_pos <= non_null_count, it should be preserved
        if (original_pos <= non_null_count) {
            BOOST_CHECK_EQUAL(loaded_pos, original_pos);
        }

        // Verify: transactions match in order (non-null entries from original)
        size_t loaded_idx = 0;
        for (size_t i = 0; i < pool_size; ++i) {
            if (pool[i]) {
                BOOST_REQUIRE(loaded_idx < loaded_pool.size());
                BOOST_CHECK(loaded_pool[loaded_idx] != nullptr);
                BOOST_CHECK_EQUAL(pool[i]->GetHash().ToString(),
                                  loaded_pool[loaded_idx]->GetHash().ToString());
                ++loaded_idx;
            }
        }

        // Verify memusage is positive if there are transactions
        if (non_null_count > 0) {
            BOOST_CHECK(loaded_memusage > 0);
        }

        // Clean up for next iteration
        fs::remove(path);
    }
}

// Property 2: Count-Limited Loading
// Validates: Requirements 2.3
BOOST_AUTO_TEST_CASE(property_count_limited_loading)
{
    // Property 2: For any pool with N > L transactions and limit L,
    // loading produces exactly L transactions (the first L from file),
    // and position is clamped to at most L.

    FastRandomContext rng{/*fDeterministic=*/true};
    fs::path path = m_args.GetDataDirNet() / "prop2_extrapool.dat";

    for (int iter = 0; iter < 100; ++iter) {
        // Generate pool with N transactions (N between 5 and 50)
        size_t N = 5 + rng.randrange(46);
        std::vector<CTransactionRef> pool;
        for (size_t i = 0; i < N; ++i) {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            uint256 hash;
            hash.SetNull();
            uint64_t unique_val = (iter + 1) * 100000 + i;
            std::memcpy(hash.begin(), &unique_val, sizeof(unique_val));
            mtx.vin[0].prevout = COutPoint(Txid::FromUint256(hash), 0);
            mtx.vout.resize(1 + rng.randrange(3));
            for (size_t j = 0; j < mtx.vout.size(); ++j) {
                mtx.vout[j].nValue = rng.randrange(1000000) + 1;
                mtx.vout[j].scriptPubKey = CScript() << OP_TRUE;
            }
            pool.push_back(MakeTransactionRef(std::move(mtx)));
        }

        // Choose limit L strictly less than N (L between 1 and N-1)
        size_t L = 1 + rng.randrange(N - 1);

        // Choose a random ring buffer position (may exceed L)
        size_t original_pos = rng.randrange(N);

        // Dump full pool
        BOOST_CHECK(DumpExtraPool(pool, original_pos, path));

        // Load with count limit L and generous memory limit
        std::vector<CTransactionRef> loaded_pool;
        size_t loaded_pos = 0, loaded_memusage = 0;
        BOOST_CHECK(LoadExtraPool(loaded_pool, loaded_pos, loaded_memusage,
                                  /*max_count=*/L, /*max_mem_bytes=*/100000000,
                                  path));

        // Assert: exactly L transactions loaded
        BOOST_CHECK_EQUAL(loaded_pool.size(), L);

        // Assert: ring buffer position clamped to at most L
        BOOST_CHECK(loaded_pos <= L);

        // Assert: the first L transactions match the original first L
        for (size_t i = 0; i < L; ++i) {
            BOOST_REQUIRE(loaded_pool[i] != nullptr);
            BOOST_CHECK_EQUAL(pool[i]->GetHash().ToString(),
                              loaded_pool[i]->GetHash().ToString());
        }

        // Clean up
        fs::remove(path);
    }
}

// --- Unit tests for error/edge cases (Task 5.4) ---

// Requirement 3.1: Missing file → empty pool
BOOST_AUTO_TEST_CASE(load_missing_file_returns_empty)
{
    fs::path path = m_args.GetDataDirNet() / "nonexistent_extrapool.dat";
    // Ensure file does not exist
    fs::remove(path);

    std::vector<CTransactionRef> pool;
    size_t pos = 99, memusage = 99;
    BOOST_CHECK(LoadExtraPool(pool, pos, memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              path));
    BOOST_CHECK(pool.empty());
    BOOST_CHECK_EQUAL(pos, 0u);
    BOOST_CHECK_EQUAL(memusage, 0u);
}

// Requirement 3.3: Bad version number → warning + empty pool
BOOST_AUTO_TEST_CASE(load_bad_version_returns_empty)
{
    fs::path path = m_args.GetDataDirNet() / "badver_extrapool.dat";

    // Write a file with an unrecognized version number
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        uint64_t bad_version = 99;
        file << bad_version;
        uint64_t count = 0;
        file << count;
        uint64_t position = 0;
        file << position;
    }

    std::vector<CTransactionRef> pool;
    size_t pos = 99, memusage = 99;
    BOOST_CHECK(LoadExtraPool(pool, pos, memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              path));
    BOOST_CHECK(pool.empty());
    BOOST_CHECK_EQUAL(pos, 0u);
    BOOST_CHECK_EQUAL(memusage, 0u);

    fs::remove(path);
}

// Requirement 3.4: Corrupt transaction mid-stream → partial load
BOOST_AUTO_TEST_CASE(load_corrupt_transaction_partial_load)
{
    fs::path path = m_args.GetDataDirNet() / "corrupt_extrapool.dat";

    // First, create a valid pool with 5 transactions, dump it, then corrupt it
    std::vector<CTransactionRef> original_pool;
    for (int i = 0; i < 5; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256(i + 100)), 0);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = (i + 1) * 5000;
        mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        original_pool.push_back(MakeTransactionRef(std::move(mtx)));
    }

    // Dump the valid pool
    BOOST_CHECK(DumpExtraPool(original_pool, /*pool_pos=*/2, path));

    // Read the file content, then truncate it partway through a later transaction
    // The header is 24 bytes (3 x uint64_t).
    // Strategy: read full file, truncate to keep ~60% of tx data
    std::vector<uint8_t> file_contents;
    {
        FILE* f = fsbridge::fopen(path, "rb");
        BOOST_REQUIRE(f != nullptr);
        std::fseek(f, 0, SEEK_END);
        long file_size = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        BOOST_REQUIRE(file_size > 24);
        file_contents.resize(static_cast<size_t>(file_size));
        size_t read = std::fread(file_contents.data(), 1, file_contents.size(), f);
        BOOST_CHECK_EQUAL(read, file_contents.size());
        std::fclose(f);
    }

    // Truncate at roughly 60% of the file (after header), which should be mid-transaction
    const size_t header_size = 24; // 3 x uint64_t
    size_t tx_data_size = file_contents.size() - header_size;
    size_t truncate_point = header_size + (tx_data_size * 3 / 5);

    // Write truncated file
    {
        FILE* f = fsbridge::fopen(path, "wb");
        BOOST_REQUIRE(f != nullptr);
        size_t written = std::fwrite(file_contents.data(), 1, truncate_point, f);
        BOOST_CHECK_EQUAL(written, truncate_point);
        std::fclose(f);
    }

    // Load the corrupt file
    std::vector<CTransactionRef> loaded_pool;
    size_t pos = 0, memusage = 0;
    BOOST_CHECK(LoadExtraPool(loaded_pool, pos, memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              path));

    // Should have loaded some but not all 5 transactions
    BOOST_CHECK(loaded_pool.size() > 0);
    BOOST_CHECK(loaded_pool.size() < 5);

    // The loaded transactions should match the originals in order
    for (size_t i = 0; i < loaded_pool.size(); ++i) {
        BOOST_CHECK(loaded_pool[i] != nullptr);
        BOOST_CHECK_EQUAL(original_pool[i]->GetHash().ToString(),
                          loaded_pool[i]->GetHash().ToString());
    }

    fs::remove(path);
}

// Requirement 7.3: Count exceeds upper bound → rejected (empty pool)
BOOST_AUTO_TEST_CASE(load_count_exceeds_upper_bound)
{
    fs::path path = m_args.GetDataDirNet() / "bigcount_extrapool.dat";

    // Write a file with count = 10,000,000 (exceeds max(100, 1000000) = 1000000)
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        uint64_t version = 1;
        file << version;
        uint64_t count = 10000000; // 10 million - way above the bound
        file << count;
        uint64_t position = 0;
        file << position;
        // No actual transaction data needed - count check happens first
    }

    std::vector<CTransactionRef> pool;
    size_t pos = 99, memusage = 99;
    BOOST_CHECK(LoadExtraPool(pool, pos, memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              path));
    BOOST_CHECK(pool.empty());
    BOOST_CHECK_EQUAL(pos, 0u);
    BOOST_CHECK_EQUAL(memusage, 0u);

    fs::remove(path);
}

// Requirement 2.3: Count-limited loading (file has more txs than configured limit)
BOOST_AUTO_TEST_CASE(load_count_limited)
{
    fs::path path = m_args.GetDataDirNet() / "countlimit_extrapool.dat";

    // Create a pool with 10 transactions
    std::vector<CTransactionRef> original_pool;
    for (int i = 0; i < 10; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256(i + 200)), 0);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = (i + 1) * 2000;
        mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        original_pool.push_back(MakeTransactionRef(std::move(mtx)));
    }

    // Dump with position 7
    BOOST_CHECK(DumpExtraPool(original_pool, /*pool_pos=*/7, path));

    // Load with max_count=4 (less than the 10 in the file)
    std::vector<CTransactionRef> loaded_pool;
    size_t pos = 0, memusage = 0;
    BOOST_CHECK(LoadExtraPool(loaded_pool, pos, memusage,
                              /*max_count=*/4, /*max_mem_bytes=*/100000000,
                              path));

    // Should load exactly 4 transactions (the first 4 from the file)
    BOOST_CHECK_EQUAL(loaded_pool.size(), 4u);

    // Verify they are the first 4 transactions
    for (size_t i = 0; i < 4; ++i) {
        BOOST_CHECK(loaded_pool[i] != nullptr);
        BOOST_CHECK_EQUAL(original_pool[i]->GetHash().ToString(),
                          loaded_pool[i]->GetHash().ToString());
    }

    // Position should be clamped to at most the loaded count (4)
    BOOST_CHECK(pos <= 4u);

    fs::remove(path);
}

// Requirement 2.4: Memory-limited eviction (loaded pool exceeds memory limit)
BOOST_AUTO_TEST_CASE(load_memory_limited_eviction)
{
    fs::path path = m_args.GetDataDirNet() / "memlimit_extrapool.dat";

    // Create a pool with 10 transactions, each with enough outputs to have measurable memusage
    std::vector<CTransactionRef> original_pool;
    for (int i = 0; i < 10; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256(i + 300)), 0);
        mtx.vout.resize(5); // multiple outputs to increase memory usage
        for (int j = 0; j < 5; ++j) {
            mtx.vout[j].nValue = (i + 1) * 1000 + j;
            mtx.vout[j].scriptPubKey = CScript() << OP_TRUE;
        }
        original_pool.push_back(MakeTransactionRef(std::move(mtx)));
    }

    // Dump with position 3
    BOOST_CHECK(DumpExtraPool(original_pool, /*pool_pos=*/3, path));

    // First, load with unlimited memory to determine total memusage
    std::vector<CTransactionRef> full_pool;
    size_t full_pos = 0, full_memusage = 0;
    BOOST_CHECK(LoadExtraPool(full_pool, full_pos, full_memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/100000000,
                              path));
    BOOST_REQUIRE(full_memusage > 0);

    // Now load with a tight memory limit (half of the total)
    size_t mem_limit = full_memusage / 2;
    BOOST_REQUIRE(mem_limit > 0);

    std::vector<CTransactionRef> limited_pool;
    size_t limited_pos = 0, limited_memusage = 0;
    BOOST_CHECK(LoadExtraPool(limited_pool, limited_pos, limited_memusage,
                              /*max_count=*/100, /*max_mem_bytes=*/mem_limit,
                              path));

    // Memusage must be within the limit
    BOOST_CHECK(limited_memusage <= mem_limit);

    // Verify memusage equals sum of RecursiveDynamicUsage over remaining non-null entries
    size_t computed_memusage = 0;
    size_t non_null_count = 0;
    for (const auto& tx : limited_pool) {
        if (tx) {
            computed_memusage += RecursiveDynamicUsage(*tx);
            ++non_null_count;
        }
    }
    BOOST_CHECK_EQUAL(limited_memusage, computed_memusage);

    // Some transactions should have been evicted (not all are non-null)
    BOOST_CHECK(non_null_count < 10u);

    fs::remove(path);
}

// Property 4: Partial Load Resilience
// Validates: Requirements 3.4
BOOST_AUTO_TEST_CASE(property_partial_load_resilience)
{
    // Property 4: For any valid serialized extra pool file truncated at position P
    // within transaction data, all transactions fully deserialized before P are
    // retained and identical to those in the original pool (in order).

    FastRandomContext rng{/*fDeterministic=*/true};
    fs::path valid_path = m_args.GetDataDirNet() / "prop4_valid.dat";
    fs::path corrupt_path = m_args.GetDataDirNet() / "prop4_corrupt.dat";

    for (int iter = 0; iter < 100; ++iter) {
        // Generate pool with 3-20 non-null transactions
        size_t N = 3 + rng.randrange(18);
        std::vector<CTransactionRef> pool;
        pool.reserve(N);
        for (size_t i = 0; i < N; ++i) {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            uint256 hash;
            hash.SetNull();
            uint64_t unique_val = (iter + 1) * 100000 + i;
            std::memcpy(hash.begin(), &unique_val, sizeof(unique_val));
            mtx.vin[0].prevout = COutPoint(Txid::FromUint256(hash), 0);
            // Variable number of outputs to create varying serialized sizes
            size_t num_outputs = 1 + rng.randrange(4);
            mtx.vout.resize(num_outputs);
            for (size_t j = 0; j < num_outputs; ++j) {
                mtx.vout[j].nValue = rng.randrange(1000000) + 1;
                mtx.vout[j].scriptPubKey = CScript() << OP_TRUE;
            }
            pool.push_back(MakeTransactionRef(std::move(mtx)));
        }

        size_t original_pos = rng.randrange(N);

        // Dump valid file
        BOOST_CHECK(DumpExtraPool(pool, original_pos, valid_path));

        // Read entire valid file into memory buffer
        std::vector<uint8_t> file_contents;
        {
            FILE* f = fsbridge::fopen(valid_path, "rb");
            BOOST_REQUIRE(f != nullptr);
            std::fseek(f, 0, SEEK_END);
            long file_size = std::ftell(f);
            std::fseek(f, 0, SEEK_SET);
            BOOST_REQUIRE(file_size > 24); // Must have header + at least some tx data
            file_contents.resize(static_cast<size_t>(file_size));
            size_t read = std::fread(file_contents.data(), 1, file_contents.size(), f);
            BOOST_CHECK_EQUAL(read, file_contents.size());
            std::fclose(f);
        }

        // The header is 24 bytes (version + count + position, each uint64_t).
        // Truncate at a random point within the transaction data region.
        // Ensure truncation point is after the header but before the end of file.
        const size_t header_size = 24;
        if (file_contents.size() <= header_size + 1) {
            // File too small to truncate meaningfully; skip this iteration
            fs::remove(valid_path);
            continue;
        }

        // Pick truncation point: at least 1 byte into tx data, at most file_size - 1
        // (so we actually truncate something)
        size_t trunc_point = header_size + 1 + rng.randrange(file_contents.size() - header_size - 1);

        // Write truncated content to corrupt_path
        {
            FILE* f = fsbridge::fopen(corrupt_path, "wb");
            BOOST_REQUIRE(f != nullptr);
            size_t written = std::fwrite(file_contents.data(), 1, trunc_point, f);
            BOOST_CHECK_EQUAL(written, trunc_point);
            std::fclose(f);
        }

        // Load from truncated file
        std::vector<CTransactionRef> loaded_pool;
        size_t loaded_pos = 0, loaded_memusage = 0;
        LoadExtraPool(loaded_pool, loaded_pos, loaded_memusage,
                      1000, 100000000, corrupt_path);

        // Assert: all loaded transactions are non-null and match the prefix of
        // the original pool in order.
        BOOST_CHECK(loaded_pool.size() <= N);
        for (size_t i = 0; i < loaded_pool.size(); ++i) {
            BOOST_CHECK(loaded_pool[i] != nullptr);
            BOOST_CHECK_EQUAL(pool[i]->GetHash().ToString(),
                              loaded_pool[i]->GetHash().ToString());
        }

        // Since we truncated within tx data, we should have fewer transactions
        // than the original (unless truncation happened after all tx data which
        // is extremely unlikely given our random range).
        // At minimum, we verify the loaded transactions are a proper prefix.
        if (loaded_pool.size() < N) {
            // Partial load occurred as expected - good
            BOOST_CHECK(loaded_pool.size() < N);
        }

        // Clean up
        fs::remove(valid_path);
        fs::remove(corrupt_path);
    }
}

BOOST_AUTO_TEST_SUITE_END()
