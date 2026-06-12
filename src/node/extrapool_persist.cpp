// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/extrapool_persist.h>

#include <common/args.h>
#include <core_memusage.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/syserror.h>
#include <util/time.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <vector>

using fsbridge::FopenFn;

namespace node {

bool ShouldPersistExtraPool(const ArgsManager& argsman)
{
    return argsman.GetBoolArg("-rejecttokens", false);
}

fs::path ExtraPoolPath(const ArgsManager& argsman)
{
    return argsman.GetDataDirNet() / "extrapool.dat";
}

bool DumpExtraPool(const std::vector<CTransactionRef>& pool,
                   size_t pool_pos,
                   const fs::path& dump_path,
                   FopenFn mockable_fopen_function)
{
    auto start = SteadyClock::now();

    // Count non-null entries
    uint64_t count = 0;
    for (const auto& tx : pool) {
        if (tx != nullptr) ++count;
    }

    AutoFile file{mockable_fopen_function(dump_path + ".new", "wb")};
    if (file.IsNull()) {
        LogInfo("Failed to open extra pool file for writing: %s. Continuing anyway.\n", fs::PathToString(dump_path));
        return false;
    }

    try {
        // Write header: version, count, ring buffer position
        const uint64_t version{1};
        file << version;
        file << count;
        file << static_cast<uint64_t>(pool_pos);

        // Serialize each non-null transaction
        for (const auto& tx : pool) {
            if (tx != nullptr) {
                file << TX_WITH_WITNESS(*tx);
            }
        }

        if (!file.Commit()) {
            throw std::runtime_error("Commit failed");
        }
        if (file.fclose() != 0) {
            throw std::runtime_error(
                strprintf("Error closing %s: %s", fs::PathToString(dump_path + ".new"), SysErrorString(errno)));
        }
        if (!RenameOver(dump_path + ".new", dump_path)) {
            throw std::runtime_error("Rename failed");
        }

        auto last = SteadyClock::now();
        LogInfo("Dumped extra pool: %d transactions written in %.3fs\n",
                count, Ticks<SecondsDouble>(last - start));
    } catch (const std::exception& e) {
        LogInfo("Failed to dump extra pool: %s. Continuing anyway.\n", e.what());
        (void)file.fclose();
        return false;
    }
    return true;
}

bool LoadExtraPool(std::vector<CTransactionRef>& pool,
                   size_t& pool_pos,
                   size_t& memusage,
                   size_t max_count,
                   size_t max_mem_bytes,
                   const fs::path& load_path,
                   FopenFn mockable_fopen_function)
{
    auto start = SteadyClock::now();

    AutoFile file{mockable_fopen_function(load_path, "rb")};
    if (file.IsNull()) {
        LogInfo("No extra pool file found at %s. Starting with empty pool.\n", fs::PathToString(load_path));
        pool.clear();
        pool_pos = 0;
        memusage = 0;
        return true;
    }

    try {
        uint64_t version;
        file >> version;
        if (version != 1) {
            LogWarning("Extra pool file has unrecognized version %d. Starting with empty pool.\n", version);
            pool.clear();
            pool_pos = 0;
            memusage = 0;
            return true;
        }

        uint64_t count;
        file >> count;
        if (count > std::max(static_cast<uint64_t>(max_count), uint64_t{1000000})) {
            LogWarning("Extra pool file claims %d transactions (likely corrupt). Starting with empty pool.\n", count);
            pool.clear();
            pool_pos = 0;
            memusage = 0;
            return true;
        }

        uint64_t position;
        file >> position;

        size_t to_load = std::min(static_cast<size_t>(count), max_count);
        pool.resize(to_load);
        memusage = 0;

        for (size_t i = 0; i < to_load; ++i) {
            try {
                CTransactionRef tx;
                file >> TX_WITH_WITNESS(tx);
                pool[i] = std::move(tx);
                memusage += RecursiveDynamicUsage(*pool[i]);
            } catch (const std::exception&) {
                LogWarning("Extra pool deserialization failed at transaction %d. Keeping %d already loaded.\n", i, i);
                pool.resize(i);
                break;
            }
        }

        // Clamp position to loaded count
        pool_pos = std::min(static_cast<size_t>(position), pool.size());

        // Memory eviction: if over limit, evict from position forward using ring buffer pattern
        if (memusage > max_mem_bytes && !pool.empty()) {
            size_t safety_counter = 0;
            const size_t pool_size = pool.size();
            while (memusage > max_mem_bytes && safety_counter < pool_size) {
                size_t evict_pos = pool_pos % pool_size;
                if (pool[evict_pos] != nullptr) {
                    memusage -= RecursiveDynamicUsage(*pool[evict_pos]);
                    pool[evict_pos].reset();
                }
                pool_pos = (pool_pos + 1) % pool_size;
                ++safety_counter;
            }
        }

        auto last = SteadyClock::now();
        LogInfo("Imported %d extra pool transactions from file in %.3fs\n",
                pool.size(), Ticks<SecondsDouble>(last - start));
    } catch (const std::exception& e) {
        LogInfo("Failed to deserialize extra pool: %s. Starting with empty pool.\n", e.what());
        pool.clear();
        pool_pos = 0;
        memusage = 0;
        return true;
    }

    return true;
}

} // namespace node
