// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <extrawork.h>

#include <chain.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <pow.h>
#include <util/check.h>

#include <algorithm>
#include <limits>
#include <vector>

arith_uint256 WorkForTarget(const arith_uint256& target)
{
    if (target == 0) return 0;
    return (~target / (target + 1)) + 1;
}

uint64_t ExtraWorkCache::FactorFixed(const Consensus::Params& params, const CBlockIndex* pindexPrev)
{
    LOCK(m_mutex);
    return FactorInternal(params, pindexPrev);
}

arith_uint256 ExtraWorkCache::EffectiveTarget(const Consensus::Params& params, const CBlockIndex* pindexPrev, unsigned int nBits)
{
    LOCK(m_mutex);
    return EffectiveTargetInternal(params, pindexPrev, nBits);
}

void ExtraWorkCache::Clear()
{
    LOCK(m_mutex);
    m_extra.clear();
}

arith_uint256 ExtraWorkCache::CumulativeEffectiveWork(const Consensus::Params& params, const CBlockIndex* index)
{
    return index->nChainWork + CumulativeExtra(params, index);
}

arith_uint256 ExtraWorkCache::CumulativeExtra(const Consensus::Params& params, const CBlockIndex* index)
{
    // Walk back to the nearest cached ancestor, or to a block the rule had not yet
    // applied to (whose cumulative extra is zero), then roll forward in height order.
    // Each block is computed once; a block after the expiry carries its parent's value.
    std::vector<const CBlockIndex*> pending;
    const CBlockIndex* cur{index};
    while (cur != nullptr) {
        if (cur->pprev == nullptr || cur->pprev->GetMedianTimePast() < params.ExtraWorkStartTime) return RollForward(params, pending, 0);
        if (const auto it{m_extra.find(cur)}; it != m_extra.end()) return RollForward(params, pending, it->second);
        pending.push_back(cur);
        cur = cur->pprev;
    }
    return 0; // unreachable: the genesis block has no parent
}

arith_uint256 ExtraWorkCache::RollForward(const Consensus::Params& params, std::vector<const CBlockIndex*>& pending, arith_uint256 extra)
{
    while (!pending.empty()) {
        const CBlockIndex* block{pending.back()};
        pending.pop_back();
        // The parent's cumulative extra is `extra`; every window FactorInternal reads for
        // this block ends at the parent, so all of it is cached or trivially zero by now.
        if (params.ExtraWorkActiveAt(Assert(block->pprev)->GetMedianTimePast())) {
            const arith_uint256 effective_target{EffectiveTargetInternal(params, block->pprev, block->nBits)};
            const arith_uint256 header_work{GetBlockProof(*block)};
            const arith_uint256 effective_work{WorkForTarget(effective_target)};
            if (effective_work > header_work) extra += effective_work - header_work;
        }
        m_extra.emplace(block, extra);
    }
    return extra;
}

uint64_t ExtraWorkCache::FactorInternal(const Consensus::Params& params, const CBlockIndex* pindexPrev)
{
    if (pindexPrev == nullptr || !params.ExtraWorkActiveAt(pindexPrev->GetMedianTimePast())) return EXTRA_WORK_FACTOR_ONE;
    // Windows never reach below the BLAKE2b fork height: the proof-of-work scale
    // changes there, and the rule is only ever scheduled on the BLAKE2b chain.
    const int floor_height{params.Blake2bHeight == std::numeric_limits<int>::max() ? 0 : params.Blake2bHeight};
    const int height{pindexPrev->nHeight};
    if (height - floor_height < 2) return EXTRA_WORK_FACTOR_ONE;
    const CBlockIndex* fast_start{Assert(pindexPrev->GetAncestor(std::max(floor_height, height - EXTRA_WORK_FAST_WINDOW)))};
    const CBlockIndex* slow_start{Assert(pindexPrev->GetAncestor(std::max(floor_height, height - EXTRA_WORK_SLOW_WINDOW)))};
    if (fast_start == pindexPrev || slow_start == fast_start) return EXTRA_WORK_FACTOR_ONE;

    const int64_t fast_seconds{pindexPrev->GetMedianTimePast() - fast_start->GetMedianTimePast()};
    const int64_t slow_seconds{pindexPrev->GetMedianTimePast() - slow_start->GetMedianTimePast()};
    if (fast_seconds <= 0 || slow_seconds <= 0) return EXTRA_WORK_FACTOR_ONE;

    const arith_uint256 tip_work{CumulativeEffectiveWork(params, pindexPrev)};
    const arith_uint256 fast_work{tip_work - CumulativeEffectiveWork(params, fast_start)};
    const arith_uint256 slow_work{tip_work - CumulativeEffectiveWork(params, slow_start)};
    if (slow_work == 0) return EXTRA_WORK_FACTOR_ONE;

    // factor = (fast_work / fast_seconds) / (slow_work / slow_seconds) / band, with 16
    // fractional bits. Work sums are below 2^128 on any chain this can run on and the
    // time spans below 2^40, so the products fit comfortably in 256 bits.
    const arith_uint256 numerator{fast_work * arith_uint256(uint64_t(slow_seconds)) * arith_uint256(uint64_t(EXTRA_WORK_BAND_DEN)) * arith_uint256(EXTRA_WORK_FACTOR_ONE)};
    const arith_uint256 denominator{slow_work * arith_uint256(uint64_t(fast_seconds)) * arith_uint256(uint64_t(EXTRA_WORK_BAND_NUM))};
    const arith_uint256 factor{numerator / denominator};
    const arith_uint256 max_factor{arith_uint256(EXTRA_WORK_FACTOR_ONE * EXTRA_WORK_MAX_FACTOR)};
    if (factor <= arith_uint256(EXTRA_WORK_FACTOR_ONE)) return EXTRA_WORK_FACTOR_ONE;
    if (factor >= max_factor) return EXTRA_WORK_FACTOR_ONE * EXTRA_WORK_MAX_FACTOR;
    return factor.GetLow64();
}

arith_uint256 ExtraWorkCache::EffectiveTargetInternal(const Consensus::Params& params, const CBlockIndex* pindexPrev, unsigned int nBits)
{
    const auto header_target{DeriveTarget(nBits, params.powLimit)};
    if (!header_target) return 0;
    const uint64_t factor{FactorInternal(params, pindexPrev)};
    if (factor == EXTRA_WORK_FACTOR_ONE) return *header_target;
    // header_target / factor with the factor's 16 fractional bits: divide first so the
    // shift back cannot overflow (factor > 1 leaves at least 16 clear high bits).
    return (*header_target / arith_uint256(factor)) << 16;
}
