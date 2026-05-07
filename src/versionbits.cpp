// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <util/check.h>
#include <versionbits.h>

// NOLINTBEGIN(misc-no-recursion)
ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    int nPeriod = Period(params);
    int nThreshold = Threshold(params);
    int min_activation_height = MinActivationHeight(params);
    int max_activation_height = MaxActivationHeight(params);
    int active_duration = ActiveDuration(params);
    int64_t nTimeStart = BeginTime(params);
    int64_t nTimeTimeout = EndTime(params);

    // Check if this deployment is always active.
    if (nTimeStart == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
        return ThresholdState::ACTIVE;
    }

    // Check if this deployment is never active.
    if (nTimeStart == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return ThresholdState::FAILED;
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == nullptr) {
            // The genesis block is by definition defined.
            cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
            cache[pindexPrev] = ThresholdState::DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));
    ThresholdState state = cache[pindexPrev];

    // Everything is already cached. Return immediately.
    if (vToCompute.empty()) {
        return state;
    }

    // For temporary deployments, we need to know when ACTIVE started to determine the
    // ACTIVE -> EXPIRED transition. We get this by calling GetStateSinceHeightFor, which
    // internally calls GetStateFor on earlier periods. Those calls could recurse back here
    // and call GetStateSinceHeightFor again, but the early return above prevents this:
    // the walk-back above guarantees all periods before pindexPrev are already cached,
    // and GetStateSinceHeightFor only walks backwards, so its GetStateFor calls always hit
    // the cache, have empty vToCompute, and return immediately via the early return.
    int activation_height = 0;
    if (state == ThresholdState::ACTIVE && active_duration < std::numeric_limits<int>::max()) {
        activation_height = GetStateSinceHeightFor(pindexPrev, params, cache);
    }

    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty()) {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        switch (state) {
            case ThresholdState::DEFINED: {
                if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                    stateNext = ThresholdState::STARTED;
                }
                break;
            }
            case ThresholdState::STARTED: {
                // We need to count
                const CBlockIndex* pindexCount = pindexPrev;
                int count = 0;
                for (int i = 0; i < nPeriod; i++) {
                    if (Condition(pindexCount, params)) {
                        count++;
                    }
                    pindexCount = pindexCount->pprev;
                }
                if (count >= nThreshold) {
                    // Normal BIP9 activation via signaling
                    stateNext = ThresholdState::LOCKED_IN;
                } else if (max_activation_height < std::numeric_limits<int>::max() && pindexPrev->nHeight + 1 >= max_activation_height - nPeriod) {
                    // Force LOCKED_IN one period before max_activation_height
                    // This ensures activation happens AT max_activation_height (not one period later)
                    // Overrides timeout to guarantee activation
                    stateNext = ThresholdState::LOCKED_IN;
                } else if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                    // Timeout without activation
                    stateNext = ThresholdState::FAILED;
                }
                break;
            }
            case ThresholdState::LOCKED_IN: {
                // Progresses into ACTIVE provided activation height will have been reached.
                if (pindexPrev->nHeight + 1 >= min_activation_height) {
                    stateNext = ThresholdState::ACTIVE;
                    if (active_duration < std::numeric_limits<int>::max()) {
                        activation_height = pindexPrev->nHeight + 1;
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE: {
                if (active_duration < std::numeric_limits<int>::max() &&
                    pindexPrev->nHeight + 1 >= activation_height + active_duration) {
                    stateNext = ThresholdState::EXPIRED;
                }
                break;
            }
            case ThresholdState::FAILED:
            case ThresholdState::EXPIRED: {
                // Nothing happens, these are terminal states.
                break;
            }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}
// NOLINTEND(misc-no-recursion)

BIP9Stats AbstractThresholdConditionChecker::GetStateStatisticsFor(const CBlockIndex* pindex, const Consensus::Params& params, std::vector<bool>* signalling_blocks) const
{
    BIP9Stats stats = {};

    stats.period = Period(params);
    stats.threshold = Threshold(params);

    if (pindex == nullptr) return stats;

    // Find how many blocks are in the current period
    int blocks_in_period = 1 + (pindex->nHeight % stats.period);

    // Reset signalling_blocks
    if (signalling_blocks) {
        signalling_blocks->assign(blocks_in_period, false);
    }

    // Count from current block to beginning of period
    int elapsed = 0;
    int count = 0;
    const CBlockIndex* currentIndex = pindex;
    do {
        ++elapsed;
        --blocks_in_period;
        if (Condition(currentIndex, params)) {
            ++count;
            if (signalling_blocks) signalling_blocks->at(blocks_in_period) = true;
        }
        currentIndex = currentIndex->pprev;
    } while(blocks_in_period > 0);

    stats.elapsed = elapsed;
    stats.count = count;
    stats.possible = (stats.period - stats.threshold ) >= (stats.elapsed - count);

    return stats;
}

// WARNING: This function is called from GetStateFor and calls GetStateFor in turn.
// The recursion is safe because this function calls GetStateFor first (which populates
// the cache), then only walks BACKWARDS through periods that are now cached. GetStateFor
// returns immediately for cached entries (via the early return when vToCompute is empty).
// If the backwards walk is ever changed to query uncached periods, infinite recursion
// will result.
// NOLINTBEGIN(misc-no-recursion)
int AbstractThresholdConditionChecker::GetStateSinceHeightFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    int64_t start_time = BeginTime(params);
    if (start_time == Consensus::BIP9Deployment::ALWAYS_ACTIVE || start_time == Consensus::BIP9Deployment::NEVER_ACTIVE) {
        return 0;
    }

    const ThresholdState initialState = GetStateFor(pindexPrev, params, cache);

    // BIP 9 about state DEFINED: "The genesis block is by definition in this state for each deployment."
    if (initialState == ThresholdState::DEFINED) {
        return 0;
    }

    const int nPeriod = Period(params);

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    // To ease understanding of the following height calculation, it helps to remember that
    // right now pindexPrev points to the block prior to the block that we are computing for, thus:
    // if we are computing for the last block of a period, then pindexPrev points to the second to last block of the period, and
    // if we are computing for the first block of a period, then pindexPrev points to the last block of the previous period.
    // The parent of the genesis block is represented by nullptr.
    pindexPrev = Assert(pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod)));

    const CBlockIndex* previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);

    while (previousPeriodParent != nullptr && GetStateFor(previousPeriodParent, params, cache) == initialState) {
        pindexPrev = previousPeriodParent;
        previousPeriodParent = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // Adjust the result because right now we point to the parent block.
    return pindexPrev->nHeight + 1;
}
// NOLINTEND(misc-no-recursion)

namespace
{
/**
 * Class to implement versionbits logic.
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker {
private:
    const Consensus::DeploymentPos id;

protected:
    int64_t BeginTime(const Consensus::Params& params) const override { return params.vDeployments[id].nStartTime; }
    int64_t EndTime(const Consensus::Params& params) const override { return params.vDeployments[id].nTimeout; }
    int MinActivationHeight(const Consensus::Params& params) const override { return params.vDeployments[id].min_activation_height; }
    int MaxActivationHeight(const Consensus::Params& params) const override { return params.vDeployments[id].max_activation_height; }
    int ActiveDuration(const Consensus::Params& params) const override { return params.vDeployments[id].active_duration; }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override {
        // Use per-deployment threshold if set, otherwise fall back to global
        int deploymentThreshold = params.vDeployments[id].threshold;
        return deploymentThreshold > 0 ? deploymentThreshold : params.nRuleChangeActivationThreshold;
    }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return (((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & Mask(params)) != 0);
    }

public:
    explicit VersionBitsConditionChecker(Consensus::DeploymentPos id_) : id(id_) {}
    uint32_t Mask(const Consensus::Params& params) const { return (uint32_t{1}) << params.vDeployments[id].bit; }
};

} // namespace

ThresholdState VersionBitsCache::State(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, m_caches[pos]);
}

BIP9Stats VersionBitsCache::Statistics(const CBlockIndex* pindex, const Consensus::Params& params, Consensus::DeploymentPos pos, std::vector<bool>* signalling_blocks)
{
    return VersionBitsConditionChecker(pos).GetStateStatisticsFor(pindex, params, signalling_blocks);
}

int VersionBitsCache::StateSinceHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(m_mutex);
    return VersionBitsConditionChecker(pos).GetStateSinceHeightFor(pindexPrev, params, m_caches[pos]);
}

uint32_t VersionBitsCache::Mask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).Mask(params);
}

int32_t VersionBitsCache::ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(m_mutex);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        Consensus::DeploymentPos pos = static_cast<Consensus::DeploymentPos>(i);
        ThresholdState state = VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, m_caches[pos]);
        if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
            nVersion |= Mask(params, pos);
        }
    }

    return nVersion;
}

void VersionBitsCache::Clear()
{
    LOCK(m_mutex);
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        m_caches[d].clear();
    }
}
