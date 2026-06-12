// Copyright (c) 2024 The Bitcoin Core developers
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

// Returns true if extra pool persistence is enabled (rejecttokens=1)
bool ShouldPersistExtraPool(const ArgsManager& argsman);

// Returns path: GetDataDirNet() / "extrapool.dat"
fs::path ExtraPoolPath(const ArgsManager& argsman);

// Serialize vExtraTxnForCompact to disk. Called from Shutdown().
// Returns true on success, false on failure (logged, non-fatal).
bool DumpExtraPool(const std::vector<CTransactionRef>& pool,
                   size_t pool_pos,
                   const fs::path& dump_path,
                   fsbridge::FopenFn mockable_fopen_function = fsbridge::fopen);

// Deserialize extrapool.dat into the provided vector and position.
// Applies count and memory limits. Returns true on success.
bool LoadExtraPool(std::vector<CTransactionRef>& pool,
                   size_t& pool_pos,
                   size_t& memusage,
                   size_t max_count,
                   size_t max_mem_bytes,
                   const fs::path& load_path,
                   fsbridge::FopenFn mockable_fopen_function = fsbridge::fopen);

} // namespace node

#endif // BITCOIN_NODE_EXTRAPOOL_PERSIST_H
