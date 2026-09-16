// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides.h>

#include <consensus/sharepool.h>

#include <algorithm>
#include <set>

namespace sharepool::tides {
namespace {
Work Numeric(const uint256& value)
{
    Work result{0};
    for (size_t i{value.size()}; i > 0; --i) {
        result <<= 8;
        result += value.begin()[i - 1];
    }
    return result;
}
} // namespace

Rewards CalculateRewards(Span<const LogEntry> prefix, const Cutoff& cutoff,
                         const uint256& network_work, CAmount subsidy,
                         CAmount transaction_fees, Budget budget)
{
    if (prefix.size() > budget.entries) throw std::length_error("TIDES history evaluation budget");
    if (cutoff.pool.IsNull() || network_work.IsNull() || !MoneyRange(subsidy) ||
        !MoneyRange(transaction_fees) || transaction_fees > MAX_MONEY - subsidy) {
        throw std::invalid_argument("TIDES pool, work or reward");
    }
    if (prefix.size() != cutoff.sequence ||
        (prefix.empty() ? !cutoff.proof_id.IsNull() : prefix.back().proof_id != cutoff.proof_id)) {
        throw std::invalid_argument("TIDES issued-job cutoff");
    }
    if (prefix.empty()) throw EmptyWindow{};

    // Even entries currently below the window must be authentic ordered
    // history: a higher future difficulty may bring those entries back.
    std::set<uint256> seen;
    for (size_t i{0}; i < prefix.size(); ++i) {
        const auto& entry = prefix[i];
        if (entry.sequence != i + 1 || entry.pool != cutoff.pool || entry.proof_id.IsNull() ||
            entry.work.IsNull() || !IsPayoutScript(entry.payout_script) ||
            !seen.insert(entry.proof_id).second) {
            throw std::invalid_argument("TIDES distinct ordered pool history");
        }
    }

    Rewards result;
    result.window_work = Numeric(network_work) * WINDOW_BLOCKS;
    Work remaining = result.window_work;
    for (size_t i{prefix.size()}; i > 0 && remaining != 0; --i) {
        const auto& entry = prefix[i - 1];
        const Work included = std::min(remaining, Numeric(entry.work));
        result.weights[entry.payout_script] += included;
        remaining -= included;
        result.oldest_sequence = entry.sequence;
        result.oldest_work = included;
    }
    result.eligible_work = result.window_work - remaining;
    const CAmount reward = subsidy + transaction_fees;
    result.rounding_residue = reward;
    for (const auto& [script, work] : result.weights) {
        const CAmount amount = (Work{reward} * work / result.eligible_work).convert_to<CAmount>();
        if (amount == 0) continue;
        if (result.payouts.size() == budget.outputs) throw std::length_error("TIDES payout output budget");
        result.payouts.emplace_back(amount, CScript{script.begin(), script.end()});
        result.rounding_residue -= amount;
    }
    return result;
}
} // namespace sharepool::tides
