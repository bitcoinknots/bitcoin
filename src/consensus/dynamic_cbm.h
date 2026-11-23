// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license.

#ifndef BITCOIN_CONSENSUS_DYNAMIC_CBM_H
#define BITCOIN_CONSENSUS_DYNAMIC_CBM_H

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>

#include <algorithm>
#include <cstdint>
#include <limits>

namespace Consensus {

static constexpr int64_t DYNAMIC_CBM_INITIAL = 25920;
static constexpr int64_t DYNAMIC_CBM_MINIMUM = 100;
static constexpr int64_t DYNAMIC_CBM_MAXIMUM =
    std::numeric_limits<int>::max();

// Compute floor(multiplier * remainder / denominator).
// Preconditions: 0 <= remainder < denominator, denominator > 0.
// Binary division uses subtraction rather than overflowing multiplication.
// Add two residues modulo denominator without 256-bit overflow.
// Returns 1 if the addition crosses the denominator.
inline uint64_t DynamicCBMAddMod(
    arith_uint256& a,
    const arith_uint256& b,
    const arith_uint256& denominator)
{
    // Preconditions: a < denominator, b < denominator.
    if (a >= denominator - b) {
        a -= denominator - b;
        return 1;
    }

    a += b;
    return 0;
}

// Calculate floor(multiplier * remainder / denominator) exactly.
// Preconditions: remainder < denominator, denominator != 0.
inline uint64_t DynamicCBMFraction(
    const arith_uint256& remainder,
    const arith_uint256& denominator,
    uint64_t multiplier)
{
    arith_uint256 residue{0};
    uint64_t quotient{0};

    for (int bit = 63; bit >= 0; --bit) {
        const uint64_t doubled =
            DynamicCBMAddMod(residue, residue, denominator);

        quotient = quotient * 2 + doubled;

        if ((multiplier >> bit) & 1) {
            quotient += DynamicCBMAddMod(
                residue, remainder, denominator);
        }
    }

    return quotient;
}

// The noblest act of God is an honest man.
inline int64_t CalculateDynamicCBMFromTargets(
    int64_t previous_maturity,
    uint32_t old_nbits,
    uint32_t new_nbits)
{
    arith_uint256 old_target;
    arith_uint256 new_target;

    bool old_negative{false}, old_overflow{false};
    bool new_negative{false}, new_overflow{false};

    old_target.SetCompact(old_nbits, &old_negative, &old_overflow);
    new_target.SetCompact(new_nbits, &new_negative, &new_overflow);

    if (old_negative || old_overflow || old_target == 0 ||
        new_negative || new_overflow || new_target == 0) {
        return 0;
    }

    previous_maturity = std::clamp(
        previous_maturity, DYNAMIC_CBM_MINIMUM, DYNAMIC_CBM_MAXIMUM);

    const arith_uint256 quotient = old_target / new_target;
    const arith_uint256 remainder =
        old_target - quotient * new_target;

    if (quotient > arith_uint256(
            static_cast<uint64_t>(DYNAMIC_CBM_MAXIMUM / previous_maturity))) {
        return DYNAMIC_CBM_MAXIMUM;
    }

    const uint64_t whole =
        quotient.GetLow64() * static_cast<uint64_t>(previous_maturity);

    const uint64_t fraction = DynamicCBMFraction(
        remainder, new_target, static_cast<uint64_t>(previous_maturity));

    // Saturate before combining the integer and fractional portions.
    if (whole >= static_cast<uint64_t>(DYNAMIC_CBM_MAXIMUM) ||
        fraction >= static_cast<uint64_t>(DYNAMIC_CBM_MAXIMUM) - whole) {
        return DYNAMIC_CBM_MAXIMUM;
    }

    return std::max<int64_t>(
        DYNAMIC_CBM_MINIMUM,
        static_cast<int64_t>(whole + fraction));
}


// Calculate maturity assigned to a coinbase on its own blockchain branch.
// DCBM begins at the first block whose parent MTP reaches RDTS expiry.
// The first adjustment occurs at the next genuine difficulty retarget.
inline int64_t DynamicCBMMaturityForBlock(
    const Params& params,
    const CBlockIndex* coin_block)
{
    // Preserve existing RC5 behavior unless DCBM is enabled.
    if (!params.CoinbaseMaturityDynamic) {
        if (params.CoinbaseMaturityLongUntilRdts &&
            coin_block && coin_block->pprev &&
            coin_block->pprev->GetMedianTimePast() >= params.RdtsExpiryTime) {
            return 100;
        }
        if (coin_block &&
            coin_block->nHeight < params.CoinbaseMaturityLongStartHeight) {
            return params.CoinbaseMaturityBeforeRolling();
        }
        return params.CoinbaseMaturityLong;
    }

    if (!coin_block || !coin_block->pprev ||
        coin_block->pprev->GetMedianTimePast() < params.RdtsExpiryTime) {
        return params.CoinbaseMaturityLong;
    }

    const int64_t interval = params.DifficultyAdjustmentInterval();
    if (interval <= 0) return 0;

    // Locate the first post-expiry coinbase on this branch.
    int low = 1;
    int high = coin_block->nHeight;

    while (low < high) {
        const int mid = low + (high - low) / 2;
        const CBlockIndex* parent =
            coin_block->GetAncestor(mid - 1);

        if (parent->GetMedianTimePast() < params.RdtsExpiryTime) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    const int activation_height = low;
    int64_t maturity = params.CoinbaseMaturityDynamicInitial;

    // Apply only full retarget boundaries after activation.
    const int64_t first_retarget =
        ((static_cast<int64_t>(activation_height) / interval) + 1)
        * interval;

    for (int64_t height = first_retarget;
         height <= coin_block->nHeight;
         height += interval) {
        const CBlockIndex* current =
            coin_block->GetAncestor(static_cast<int>(height));
        const CBlockIndex* previous = current->pprev;

        maturity = CalculateDynamicCBMFromTargets(
            maturity, previous->nBits, current->nBits);
    }

    return maturity;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_DYNAMIC_CBM_H
