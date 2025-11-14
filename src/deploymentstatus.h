// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>

/** Determine if a deployment is active for the next block */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    const auto next_block_height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
    return next_block_height >= params.DeploymentHeight(dep) && next_block_height <= params.DeploymentHeightEnd(dep);
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (ThresholdState::ACTIVE != versionbitscache.State(pindexPrev, params, dep)) {
        return false;
    }
    // Check if temporary deployment has expired
    const auto& deployment = params.vDeployments[dep];
    if (deployment.active_duration > 0) {
        const int activation_height = versionbitscache.StateSinceHeight(pindexPrev, params, dep);
        const int next_block_height = (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1);
        if (next_block_height > activation_height + deployment.active_duration) {
            return false;
        }
    }
    return true;
}

/** Determine if a deployment is active for this block */
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= params.DeploymentHeight(dep) && index.nHeight <= params.DeploymentHeightEnd(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (ThresholdState::ACTIVE != versionbitscache.State(index.pprev, params, dep)) {
        return false;
    }
    // Check if temporary deployment has expired
    const auto& deployment = params.vDeployments[dep];
    if (deployment.active_duration > 0) {
        const int activation_height = versionbitscache.StateSinceHeight(index.pprev, params, dep);
        if (index.nHeight > activation_height + deployment.active_duration) {
            return false;
        }
    }
    return true;
}

/** Determine if a deployment is enabled (can ever be active) */
inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return params.DeploymentHeight(dep) != std::numeric_limits<int>::max();
}

inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    return params.vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
