// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H
#define BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H

#include <hash.h>
#include <primitives/block.h>

#include <stdexcept>

namespace sharepool {
/** Process-local native-validation identity; never a consensus commitment.
 *
 * The exact, unnormalized header binds its parent and every search field. The
 * ordered witness transaction IDs bind each immutable transaction, including
 * coinbase and witness bytes. A hit still requires the caller's native context
 * checks. Reusing cached transaction hashes avoids hashing full shared payloads
 * again on every cache lookup. No body validity is inferred from these hashes.
 */
inline uint256 NativeBodyCacheKey(const CBlock& block)
{
    static constexpr char domain[]{"SharePool/native-body-cache/v1"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    writer << block.GetBlockHeader();
    WriteCompactSize(writer, block.vtx.size());
    for (const auto& tx : block.vtx) {
        if (!tx) throw std::invalid_argument("null transaction in native body cache key");
        writer << tx->GetWitnessHash();
    }
    return writer.GetHash();
}
} // namespace sharepool

#endif // BITCOIN_SHAREPOOL_HASH_VALIDATION_CACHE_H
