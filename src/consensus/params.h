// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
    DEPLOYMENT_BLAKE2B,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_BLAKE2B; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /** Maximum height for activation. If less than INT_MAX, the deployment will activate
     *  at this height regardless of signaling (similar to BIP8 flag day).
     *  std::numeric_limits<int>::max() means no maximum (activation only via signaling). */
    int max_activation_height{std::numeric_limits<int>::max()};
    /** For temporary softforks: number of blocks the deployment remains active after activation.
     *  std::numeric_limits<int>::max() means permanent (never expires). */
    int active_duration{std::numeric_limits<int>::max()};
    /** Per-deployment activation threshold. If 0, uses the global nRuleChangeActivationThreshold.
     *  Otherwise, specifies the number of blocks required for this specific deployment. */
    int threshold{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Chainstate record of deployment enforcement.
 *
 * NOTE: Currently this only turns "valid" into "indeterminate" (and only
 * for ConnectBlock checks). It cannot turn "invalid" into "indeterminate"
 * and therefore is not safe to use for hardforks, only softforks.
 */
struct ChainstateRevalidationDeployment {
    /** Deployment name used for persisted state.
     *
     * Note that if enforcement isn't exactly the same (eg, an earlier
     * CoinbaseMaturityLongStartHeight), this must be changed.
     */
    std::string name;
    /**
     * First block height whose cached validation may be invalidated.
     *
     * The current revalidation framework only demotes cached validation back
     * to BLOCK_VALID_TRANSACTIONS. It is only appropriate for deployments
     * whose new checks are re-run by ConnectBlock() after that point. Rules
     * checked by CheckBlock() or ContextualCheckBlock() need additional block
     * index support before they can use this safely.
     */
    int start_height{std::numeric_limits<int>::max()};
    /** Last block height whose cached validation may be invalidated. */
    int stop_height{std::numeric_limits<int>::max()};
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Block height at which BLAKE2b hardfork becomes active */
    int Blake2bHeight{std::numeric_limits<int>::max()};
    std::vector<unsigned char> Blake2bHeadline;
    uint8_t Blake2bTargetShift{20};
    /**
     * RDTS (BIP110 ReducedData Temporary Softfork) deployment expiry.
     *
     * At the BLAKE2b hardfork RDTS stops using versionbits: its rules are
     * enforced for exactly the blocks from Blake2bHeight (see RdtsActiveAt)
     * until expiry. A block is past expiry when its parent's median-time-past
     * has reached RdtsExpiryTime, so the boundary is monotone along any chain
     * and the rules for the next block are knowable in advance.
     *
     * The default leaves the deployment unscheduled (expiry precedes every
     * median-time-past, and Blake2bHeight itself defaults to unscheduled), so
     * behaviour is unchanged on chains that do not set it.
     */
    int64_t RdtsExpiryTime{std::numeric_limits<int64_t>::min()};
    /**
     * One period of the long coinbase maturity schedule.
     *
     * Coinbases of height start_height or later, and below the next period,
     * stay unspendable until release_height. release_height of
     * std::numeric_limits<int>::max() means the period ends when the parent
     * block's median-time-past reaches CoinbaseMaturityLongReleaseTime.
     */
    struct CoinbaseMaturityPeriod {
        int start_height{std::numeric_limits<int>::max()};
        int release_height{std::numeric_limits<int>::max()};
    };
    /**
     * Long coinbase maturity temporary softfork. It extends RDTS: every RDTS
     * rule stays in force on its own schedule, and this rule adds coinbase
     * maturity periods that end at RDTS expiry. Mainnet has four.
     *
     * From CoinbaseMaturityLongEnforceHeight, a covered coinbase cannot be
     * spent at any depth until its period releases. Height releases are
     * monotone, and the last period releases when the parent block's
     * median-time-past reaches CoinbaseMaturityLongReleaseTime (the same
     * boundary as RdtsExpiryTime), so the rules for the next block are
     * knowable in advance. Reaching that time does not release a period
     * before the first period's release height: that height is the last
     * block the previous rule still held. Every coinbase the schedule does
     * not cover needs COINBASE_MATURITY as always.
     *
     * The defaults leave the rule unscheduled.
     */
    int CoinbaseMaturityLongStartHeight{std::numeric_limits<int>::max()};
    int CoinbaseMaturityLongEnforceHeight{std::numeric_limits<int>::max()};
    int64_t CoinbaseMaturityLongReleaseTime{std::numeric_limits<int64_t>::min()};
    std::vector<CoinbaseMaturityPeriod> coinbase_maturity_long_periods;
    bool CoinbaseMaturityLongScheduled() const
    {
        return !coinbase_maturity_long_periods.empty();
    }
    /** Earliest spending-block height at which a height-released period ends. */
    int CoinbaseMaturityLongFirstReleaseHeight() const
    {
        int first{std::numeric_limits<int>::max()};
        for (const CoinbaseMaturityPeriod& period : coinbase_maturity_long_periods) {
            if (period.release_height < first) first = period.release_height;
        }
        return first;
    }
    bool CoinbaseMaturityPeriodReleased(const CoinbaseMaturityPeriod& period, int spend_height, int64_t mtp_prev) const
    {
        if (period.release_height != std::numeric_limits<int>::max() && spend_height >= period.release_height) {
            return true;
        }
        if (mtp_prev < CoinbaseMaturityLongReleaseTime) return false;
        // No release height: this period ends at the RDTS expiry time.
        if (period.release_height == std::numeric_limits<int>::max()) return true;
        // RDTS expiry also ends an earlier period once the first release
        // height has passed. Releasing before that height would accept a
        // spend the previous rule still rejects.
        const int first_release{CoinbaseMaturityLongFirstReleaseHeight()};
        return first_release != std::numeric_limits<int>::max() && spend_height >= first_release;
    }
    /** Whether any period still holds coinbases in a block at this height whose parent has this median-time-past. */
    bool CoinbaseMaturityLongActiveAt(int height, int64_t mtp_prev) const
    {
        return CoinbaseMaturityLongHeldFrom(height, mtp_prev) != std::numeric_limits<int>::max();
    }
    /**
     * First coinbase height that cannot be spent in a block at the given
     * height whose parent has the given median-time-past, or
     * std::numeric_limits<int>::max() when the rule does not apply to it.
     */
    int CoinbaseMaturityLongHeldFrom(int height, int64_t mtp_prev) const
    {
        if (coinbase_maturity_long_periods.empty() || height < CoinbaseMaturityLongEnforceHeight) {
            return std::numeric_limits<int>::max();
        }
        int held{std::numeric_limits<int>::max()};
        for (const CoinbaseMaturityPeriod& period : coinbase_maturity_long_periods) {
            if (!CoinbaseMaturityPeriodReleased(period, height, mtp_prev) && period.start_height < held) {
                held = period.start_height;
            }
        }
        return held;
    }
    /**
     * Release height of the period covering coin_height, or false when the
     * schedule does not cover it. release_height_out is
     * std::numeric_limits<int>::max() when that period ends at
     * CoinbaseMaturityLongReleaseTime.
     */
    bool CoinbaseMaturityLongCovered(int coin_height, int& release_height_out) const
    {
        const CoinbaseMaturityPeriod* match{nullptr};
        for (const CoinbaseMaturityPeriod& period : coinbase_maturity_long_periods) {
            if (coin_height >= period.start_height) match = &period;
        }
        if (!match) return false;
        release_height_out = match->release_height;
        return true;
    }
    std::vector<ChainstateRevalidationDeployment> chainstate_revalidation_deployments;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        case DEPLOYMENT_BLAKE2B:
            return Blake2bHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }

    bool IsBlake2bHeight(int height) const
    {
        return height >= Blake2bHeight;
    }

    /** RDTS activates at the BLAKE2b hardfork; there is no separate schedule. */
    int RdtsActivationHeight() const { return Blake2bHeight; }

    /** Whether the RDTS rules apply to a block at the given height whose
     *  parent has the given median-time-past. */
    bool RdtsActiveAt(int height, int64_t mtp_prev) const
    {
        return IsBlake2bHeight(height) && mtp_prev < RdtsExpiryTime;
    }
};

/**
 * Last height at which a block can still have a parent median time past
 * below `until_mtp`, given a block at `anchor_height` whose median time
 * past is `anchor_mtp`.
 *
 * A block timestamp must be greater than the previous median time past, so
 * that median rises by at least one second every six blocks. The block at
 * the returned height can still see a parent median of `until_mtp - 1`.
 */
inline int LastHeightWithParentMtpBelow(int anchor_height, int64_t anchor_mtp, int64_t until_mtp)
{
    if (until_mtp <= anchor_mtp) return anchor_height;
    const int64_t seconds{until_mtp - anchor_mtp};
    constexpr int64_t blocks_per_second{6};
    if (seconds > (static_cast<int64_t>(std::numeric_limits<int>::max()) - anchor_height) / blocks_per_second) {
        return std::numeric_limits<int>::max();
    }
    return anchor_height + static_cast<int>(seconds * blocks_per_second);
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
