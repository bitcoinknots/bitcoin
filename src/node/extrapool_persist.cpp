// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/extrapool_persist.h>

#include <common/args.h>
#include <core_memusage.h>
#include <logging.h>
#include <net_processing.h>
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

/**
 * Returns true if extra pool persistence is enabled.
 * Extra pool is persisted when the -persistextrapool option is set.
 *
 * @param argsman The ArgsManager instance containing command line arguments
 * @return true if -persistextrapool=1, false otherwise
 */
bool ShouldPersistExtraPool(const ArgsManager& argsman)
{
    return argsman.GetBoolArg("-persistextrapool", DEFAULT_PERSIST_EXTRA_POOL);
}

/**
 * Returns the path to the extra pool persistence file.
 * The file is stored in the data directory as "extrapool.dat".
 *
 * @param argsman The ArgsManager instance containing command line arguments
 * @return The filesystem path to the extra pool file
 */
fs::path ExtraPoolPath(const ArgsManager& argsman)
{
    return argsman.GetDataDirNet() / "extrapool.dat";
}

/**
 * Serialize extra pool transactions to disk.
 * Writes version, count, and all non-null transactions to the file.
 * Uses atomic write (write to .new file, then rename) for crash safety.
 *
 * @param pool The vector of transaction references to serialize
 * @param dump_path The filesystem path to write the extra pool file to
 * @param mockable_fopen_function Function pointer for opening files (for testing)
 * @return true on success, false on failure (non-fatal, logged)
 */
bool DumpExtraPool(const std::vector<CTransactionRef>& pool,
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
        // Write header: version, count
        // pool_pos is not persisted; on load it will be derived from count
        const uint64_t version{1};
        file << version;
        file << count;

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

/**
 * Deserialize extra pool transactions from disk.
 * Reads version and count from file header, then deserializes each transaction.
 * Enforces per-TX size limit (BLOCK_RECONSTRUCTION_EXTRA_TXN_PER_TXN_SIZE_LIMIT)
 * and cumulative memory limit (max_mem_bytes) during loading.
 * Derives pool_pos from count to maintain ring buffer invariant.
 *
 * @param[out] pool The vector to populate with deserialized transaction references
 * @param[out] pool_pos The ring buffer position (derived from count, clamped to max_count)
 * @param[out] memusage The total memory usage of loaded transactions
 * @param max_count Maximum number of transactions to load
 * @param max_mem_bytes Maximum memory usage allowed for loaded transactions
 * @param load_path The filesystem path to read the extra pool file from
 * @param mockable_fopen_function Function pointer for opening files (for testing)
 * @return true on success (even if file doesn't exist - returns empty pool),
 *         false only on unrecoverable errors (currently always returns true)
 */
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

        size_t to_load = std::min(static_cast<size_t>(count), max_count);
        pool.resize(to_load);
        memusage = 0;

        for (size_t i = 0; i < to_load; ++i) {
            try {
                CTransactionRef tx;
                file >> TX_WITH_WITNESS(tx);
                
                // Check per-TX size limit (match live insert behavior)
                size_t tx_usage = RecursiveDynamicUsage(*tx);
                if (tx_usage > BLOCK_RECONSTRUCTION_EXTRA_TXN_PER_TXN_SIZE_LIMIT) {
                    LogWarning("Skipping oversized extra pool transaction (%d bytes) at index %d\n", tx_usage, i);
                    continue;
                }
                
                // Check cumulative memory before adding
                if (memusage + tx_usage > max_mem_bytes && !pool.empty()) {
                    LogDebug(BCLog::NET, "Extra pool memory limit reached, stopping load at %d transactions\n", i);
                    pool.resize(i);
                    break;
                }
                
                pool[i] = std::move(tx);
                memusage += tx_usage;
            } catch (const std::exception&) {
                LogWarning("Extra pool deserialization failed at transaction %d. Keeping %d already loaded.\n", i, i);
                pool.resize(i);
                break;
            }
        }

        // Derive pool_pos from count (next insertion position is at the end of loaded data)
        // This maintains ring buffer invariant: TXs at [0, pool.size()), next write at pool.size() % max_count
        pool_pos = std::min(static_cast<size_t>(count), max_count);
        if (pool_pos >= max_count) pool_pos = 0;

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
