// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_TIDES_H
#define BITCOIN_SHAREPOOL_TIDES_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <span.h>
#include <uint256.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <vector>

/** TIDES accounting reference; not called by native block validation.
 * Work inputs must use one exact common difficulty scale. This module does not
 * authenticate PoW, templates, membership, history, or the selected job cutoff.
 * It does not define conversion from native targets to that scale.
 */
namespace sharepool::tides {
inline constexpr uint32_t WINDOW_BLOCKS{8};
// Maximum window < 2^259, multiplied by MAX_MONEY < 2^51. Fixed 512-bit
// intermediates cannot wrap for the bounded inputs accepted below.
using Work = boost::multiprecision::uint512_t;

struct LogEntry {
    uint64_t sequence{0};
    uint256 proof_id;
    uint256 pool;
    std::vector<unsigned char> payout_script;
    uint256 work; // Positive uint256, not observed hash quality or arrival time.
};

struct Cutoff {
    uint256 pool;
    uint64_t sequence{0};
    uint256 proof_id;
};

struct Budget {
    size_t entries;
    size_t outputs;
};

class EmptyWindow : public std::invalid_argument {
public:
    EmptyWindow() : std::invalid_argument("empty TIDES window requires a bootstrap policy") {}
};

struct Rewards {
    Work window_work{0}; // 8 times the supplied current network work.
    Work eligible_work{0}; // Smaller denominator at startup.
    std::map<std::vector<unsigned char>, Work> weights;
    std::vector<CTxOut> payouts; // Positive satoshis, lexical script order.
    CAmount rounding_residue{0}; // Unclaimed; no recipient or balance invented.
    uint64_t oldest_sequence{0};
    Work oldest_work{0}; // Only this contribution may be clipped.
};

/** Evaluate the complete per-pool prefix ending at an already authenticated
 * issued-job cutoff. The caller must bind the WHOLE prefix, difficulty and
 * reward to the job, not merely its last proof ID. Native-parent confirmation
 * and pool receipt ordering are different policies; neither is implemented here.
 *
 * Shares are distinct and sequenced from 1; rewards do not consume them.
 * The oldest boundary contribution is clipped to exactly fill the work window;
 * the original share remains intact. Equal scripts aggregate before flooring.
 * Uses zero operator fee and includes the supplied subsidy + verified tx fees.
 *
 * Invalid inputs throw invalid_argument; empty history throws EmptyWindow.
 * A caller-specified local budget failure throws length_error. It must not be
 * mapped to consensus invalidity or handled by silently dropping work/outputs.
 * This full-prefix reference uses O(n log n) verification, not an archive index.
 */
Rewards CalculateRewards(Span<const LogEntry> prefix, const Cutoff& cutoff,
                         const uint256& network_work, CAmount subsidy,
                         CAmount transaction_fees, Budget budget);
} // namespace sharepool::tides

#endif // BITCOIN_SHAREPOOL_TIDES_H
