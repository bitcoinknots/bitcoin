// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_MINING_BUDGET_H
#define BITCOIN_SHAREPOOL_MINING_BUDGET_H

#include <consensus/consensus.h>

#include <algorithm>
#include <cstddef>
#include <optional>

namespace sharepool {
struct CoinbaseReservation {
    size_t serialized_bytes;
    size_t weight;
};

/** Conservative v2 header, full coinbase and count-prefix reservation.
 * The caller supplies the contextual RDTS state for the candidate's parent.
 * Reject before arithmetic or block assembly can exceed either native bound.
 */
inline std::optional<CoinbaseReservation> ReserveCoinbasePayouts(size_t output_bytes, bool reduced_data)
{
    constexpr size_t OVERHEAD{164 + 9 + 4 + 1 + 36 + 1 + 100 + 4 + 9 + 47 + 4};
    constexpr size_t WITNESS_BYTES{36};
    const size_t weight_limit = reduced_data ? REDUCED_DATA_MAX_BLOCK_WEIGHT : MAX_BLOCK_WEIGHT;
    const size_t maximum_base = std::min<size_t>(MAX_BLOCK_SERIALIZED_SIZE - WITNESS_BYTES,
                                                (weight_limit - WITNESS_BYTES) / WITNESS_SCALE_FACTOR);
    if (output_bytes > maximum_base - OVERHEAD) return std::nullopt;
    const size_t base = OVERHEAD + output_bytes;
    return CoinbaseReservation{base + WITNESS_BYTES, base * WITNESS_SCALE_FACTOR + WITNESS_BYTES};
}
} // namespace sharepool

#endif // BITCOIN_SHAREPOOL_MINING_BUDGET_H
