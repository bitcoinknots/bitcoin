// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_EXTRAPOOL_PERSIST_H
#define BITCOIN_NODE_EXTRAPOOL_PERSIST_H

#include <primitives/transaction.h>
#include <util/fs.h>

#include <cstddef>
#include <vector>

class ArgsManager;

namespace node {

static constexpr bool DEFAULT_PERSIST_EXTRA_POOL{false};

/**
 * Returns true if extra pool persistence is enabled (persistextrapool=1).
 *
 * @param argsman The ArgsManager instance containing command line arguments
 * @return true if -persistextrapool=1, false otherwise
 */
bool ShouldPersistExtraPool(const ArgsManager& argsman);

/**
 * Returns path: GetDataDirNet() / "extrapool.dat".
 *
 * @param argsman The ArgsManager instance containing command line arguments
 * @return The filesystem path to the extra pool file
 */
fs::path ExtraPoolPath(const ArgsManager& argsman);

/**
 * Serialize vExtraTxnForCompact to disk. Called from Shutdown().
 * Uses atomic write (write to .new file, then rename) for crash safety.
 *
 * @param pool The vector of transaction references to serialize
 * @param dump_path The filesystem path to write the extra pool file to
 * @param mockable_fopen_function Function pointer for opening files (for testing)
 * @return true on success, false on failure (logged, non-fatal)
 */
bool DumpExtraPool(const std::vector<CTransactionRef>& pool,
                   const fs::path& dump_path,
                   fsbridge::FopenFn mockable_fopen_function = fsbridge::fopen);

/**
 * Deserialize extrapool.dat into the provided vector and position.
 * Applies count and memory limits. Derives pool_pos from count.
 *
 * @param[out] pool The vector to populate with deserialized transaction references
 * @param[out] pool_pos The ring buffer position (derived from count, clamped to max_count)
 * @param[out] memusage The total memory usage of loaded transactions
 * @param max_count Maximum number of transactions to load
 * @param max_mem_bytes Maximum memory usage allowed for loaded transactions
 * @param load_path The filesystem path to read the extra pool file from
 * @param mockable_fopen_function Function pointer for opening files (for testing)
 * @return true on success (even if file doesn't exist - returns empty pool)
 */
bool LoadExtraPool(std::vector<CTransactionRef>& pool,
                   size_t& pool_pos,
                   size_t& memusage,
                   size_t max_count,
                   size_t max_mem_bytes,
                   const fs::path& load_path,
                   fsbridge::FopenFn mockable_fopen_function = fsbridge::fopen);

} // namespace node

#endif // BITCOIN_NODE_EXTRAPOOL_PERSIST_H
