// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_COIN_AGE_PRIORITY_H
#define BITCOIN_POLICY_COIN_AGE_PRIORITY_H

#include <consensus/amount.h>

class CCoinsViewCache;
class CTransaction;

struct CoinAgeCache
{
    double inputs_coin_age;        //!< Sum coin-age of all confirmed inputs
    CAmount in_chain_input_value;  //!< Sum value of all confirmed inputs
};

static constexpr CoinAgeCache COIN_AGE_CACHE_ZERO{
    .inputs_coin_age = 0.0,
    .in_chain_input_value = 0,
};

// Compute modified tx vsize for priority calculation
unsigned int CalculateModifiedSize(const CTransaction& tx, unsigned int nTxSize);

// Compute priority, given sum coin-age of inputs and modified tx vsize
// CAUTION: Original ComputePriority accepted UNMODIFIED tx vsize and did the modification internally
double ComputePriority2(double inputs_coin_age, unsigned int mod_vsize);
double ReversePriority2(double coin_age_priority, unsigned int mod_vsize);

/**
 * Return sum coin-age of tx inputs at height nHeight. Also calculate the sum of the values of the inputs
 * that are already in the chain.  These are the inputs that will age and increase priority as
 * new blocks are added to the chain.
 * CAUTION: Original GetPriority also called ComputePriority and returned the final coin-age priority
 */
CoinAgeCache GetCoinAge(const CTransaction &tx, const CCoinsViewCache& view, int nHeight);

/**
 * Calculate a weight discount for transactions spending older coins.
 *
 * The discount reduces a transaction's effective vsize based on the coin age
 * density (coinblocks per vbyte) of its inputs. The formula uses a logarithmic
 * curve that rises quickly for young coins and flattens as they age:
 *
 *   discount_ratio = min(0.5, log2(1 + coinblocks_per_vbyte / MINIMUM_TX_PRIORITY) / 8)
 *
 * where coinblocks_per_vbyte = inputs_coin_age / vsize, and inputs_coin_age is
 * the sum of (value_sat * confirmation_depth) across all confirmed inputs.
 *
 * The divisor of 8 controls saturation speed: the 50% cap is reached when
 * coinblocks_per_vbyte >= 255 * MINIMUM_TX_PRIORITY (i.e. log2(256) / 8 = 1.0,
 * clamped to 0.5). In practice this means a typical 1-input, 1 BTC transaction
 * reaches the maximum discount after roughly 36 days of confirmations.
 *
 * The returned value is always <= 0 (a negative weight offset). The total
 * effective weight (tx_weight + discount) is clamped so it never drops below
 * min_weight, preventing transactions from having an unreasonably small vsize.
 *
 * @param[in] inputs_coin_age  Sum of (value_sat * height_depth) for confirmed inputs.
 * @param[in] tx_weight        Consensus transaction weight.
 * @param[in] min_weight       Floor for effective weight after discount.
 * @return Negative weight discount, or 0 if no discount applies.
 */
int32_t CalculateCoinblocksWeightDiscount(double inputs_coin_age, int32_t tx_weight, int32_t min_weight);

#endif // BITCOIN_POLICY_COIN_AGE_PRIORITY_H
