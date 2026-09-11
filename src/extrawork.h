// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EXTRAWORK_H
#define BITCOIN_EXTRAWORK_H

#include <arith_uint256.h>
#include <sync.h>

#include <cstdint>
#include <map>
#include <vector>

class CBlockIndex;
namespace Consensus { struct Params; }

/** Fixed-point one for the extra-work factor (see ExtraWorkCache). */
static constexpr uint64_t EXTRA_WORK_FACTOR_ONE = uint64_t{1} << 16;

/**
 * Extra-work temporary soft fork (see Consensus::Params::ExtraWorkActiveAt).
 *
 * While the deployment is active, a block must satisfy hash <= header_target / factor,
 * where factor >= 1 rises when the recent hashrate departs upward from its own trend
 * and is 1 otherwise. Requiring more work than the header asks for is a strict
 * tightening, so every block valid under this rule is valid for a node that does not
 * enforce it. The rule can only raise the effective difficulty, never lower it: the
 * header nBits and the difficulty retarget are untouched.
 *
 * Both hashrate estimators divide effective work by elapsed median-time-past over a
 * window of ancestors: EXTRA_WORK_FAST_WINDOW blocks (about half a day at the target
 * spacing) and EXTRA_WORK_SLOW_WINDOW blocks (about a month). The effective work of a
 * block is the work its effective target required, so a burst that is being held to
 * ~target spacing by the rule is still measured at its true hashrate. Windows are
 * clipped at the BLAKE2b fork height, so the two proof-of-work scales never mix.
 *
 *   factor = clamp(H_fast / (H_slow * EXTRA_WORK_BAND_NUM/EXTRA_WORK_BAND_DEN), 1, EXTRA_WORK_MAX_FACTOR)
 *
 * evaluated in integer arithmetic with 16 fractional bits, from the parent block's
 * chain only, so the effective target of the next block is known at the tip.
 *
 * The cumulative extra work (effective minus header work, summed over the blocks the
 * rule applied to) is cached per block index, like the versionbits cache; the cache is
 * rebuilt on demand from ancestors and is safe to clear at any time.
 */
class ExtraWorkCache
{
private:
    Mutex m_mutex;
    std::map<const CBlockIndex*, arith_uint256> m_extra GUARDED_BY(m_mutex);

    arith_uint256 CumulativeExtra(const Consensus::Params& params, const CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    arith_uint256 RollForward(const Consensus::Params& params, std::vector<const CBlockIndex*>& pending, arith_uint256 extra) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    arith_uint256 CumulativeEffectiveWork(const Consensus::Params& params, const CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    uint64_t FactorInternal(const Consensus::Params& params, const CBlockIndex* pindexPrev) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    arith_uint256 EffectiveTargetInternal(const Consensus::Params& params, const CBlockIndex* pindexPrev, unsigned int nBits) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    /** The factor the rule applies to the block built on pindexPrev, as a fixed-point
     *  number with 16 fractional bits (EXTRA_WORK_FACTOR_ONE means no extra work). */
    uint64_t FactorFixed(const Consensus::Params& params, const CBlockIndex* pindexPrev) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The target the block built on pindexPrev must meet: the target encoded by nBits
     *  divided by the factor. Equal to the header target whenever the rule is inactive
     *  or the factor is 1. Zero if nBits does not encode a valid target. */
    arith_uint256 EffectiveTarget(const Consensus::Params& params, const CBlockIndex* pindexPrev, unsigned int nBits) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

/** Work required to meet a target: 2^256 / (target + 1), as GetBlockProof computes it. */
arith_uint256 WorkForTarget(const arith_uint256& target);

#endif // BITCOIN_EXTRAWORK_H
